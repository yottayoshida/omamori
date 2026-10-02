//! Audit log retention and pruning.
//!
//! Whether a prune is due is checked every `PRUNE_CHECK_INTERVAL` entries
//! during `AuditLogger::append()`, once that append has released the log's
//! lock; one is due when the first entry is more than [`PRUNE_SLACK`] past the
//! retention period (#568). It builds the pruned log beside the real one
//! without holding that lock, and takes it only to rename the result into
//! place (ADR-0016, ADR-0017).

use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use super::AuditEvent;
use super::chain::{
    CHAIN_VERSION, compute_entry_hash_for_write, hmac_bytes, parse_line, prune_genesis_hash,
};
use super::secret::{
    Keyring, SigningKey, flock_exclusive, load_keyring, names_this_file, open_read_nofollow,
    secret_path_for, try_flock_exclusive,
};
use super::verify::{BreakCause, VerifyResult, Walk, keyring_failure, walk_lines};
use crate::atomic_file::{TempGuard, describe_file_type, fsync_parent};

pub(super) const PRUNE_CHECK_INTERVAL: u64 = 1000;
pub(super) const MIN_RETENTION_DAYS: u32 = 7;
pub(super) const MIN_RETAIN_ENTRIES: usize = 1000;
/// How far past the retention period the first entry in the log has to be
/// before a prune runs (#568).
///
/// A prune copies everything it keeps, however little it removes. Run whenever
/// a single entry had aged out, it ran at every check on a busy log — a
/// thousand appends apart, each time copying the whole log to drop the
/// thousand entries that had passed the period since the last one. With a day
/// of slack it runs when a day's worth has, about once a day, and the checks
/// in between read the log's first line and stop.
///
/// It moves *when* a prune runs, not *what* it removes: a prune that runs
/// still removes everything older than the period. So an entry can outlast the
/// period by this much, and by however long the next check takes to come.
///
/// Fixed rather than configured or scaled to the period: a day reads the same
/// against a period of seven days or ninety, and a setting can be added when
/// someone needs one.
pub(super) const PRUNE_SLACK: time::Duration = time::Duration::days(1);
pub(super) const PRUNE_COMMAND: &str = "_prune";
pub(super) const PRUNE_ACTION: &str = "retention";
pub(super) const PRUNE_RESULT: &str = "pruned";

/// Namespace for the findings record carried in a prune point's `rule_id`
/// (`#461`). A prefix rather than a bare list so a value that is *not* this
/// record — an entry that merely happens to sit where a prune point would —
/// is not read as one.
const FINDINGS_PREFIX: &str = "pruned:";

/// What `audit verify` would have reported about entries a prune removed
/// (`#461`).
///
/// A prune that removes a range containing entries the verifier could not
/// check used to leave nothing behind: `prune_point` carried an entry count
/// and nothing else, so a store that reported exit 4 before the prune
/// reported exit 0 after it, with no trace that anything had ever been
/// unverifiable. These counts are that trace.
///
/// **They are the verifier's own findings, not a second opinion** (`#539`,
/// `#540`, ADR-0015). The range is walked with [`walk_lines`] — the loop
/// `verify_chain` runs — and what that reports is what is written down.
/// Through 1.2.2 a separate keyless scan produced the counts, and the two
/// described one log differently: the scan never recomputed an `entry_hash`,
/// never checked the head against its anchor, and stopped without a word at
/// an entry naming a key the ring did not hold.
///
/// Two things follow from walking as the verifier does, and `SECURITY.md`
/// states them for operators:
///
/// - **It stops where the verifier stops.** A break ends the walk. Past a
///   halt — an unrecognised `chain_version`, a key the ring does not hold —
///   the verifier tallies lines without judging them (`verify.rs`: "nothing
///   about it — including its own seq/prev_hash — is trustworthy structural
///   signal"), so nothing behind either is counted. Only `unprotected` is a
///   true count, because it is the one state the verifier walks past.
/// - **A stop is one finding.** `unverifiable`, `legacy_splice`, `broken`,
///   `hash_mismatch` and `unchecked` are each `0` or `1` for one prune. They
///   exceed `1` only by being carried across prunes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrunedFindings {
    /// `1` when an entry declared a `chain_version` this build cannot hash
    /// (`audit verify` exit 4). `0` or `1`, not a tally: the verifier halts
    /// on the first one and reports only that one's position, so a count
    /// here would describe a range the verifier never judged.
    pub unverifiable: u64,
    /// Entries omamori itself wrote with no HMAC — `key_id` is the
    /// unresolved sentinel *and* `entry_hash` is the no-key sentinel, the
    /// two-piece evidence `#483` requires before believing it.
    pub unprotected: u64,
    /// `1` when an entry with no `chain_version` appeared after the chain
    /// had started. A legacy entry at the head of a log is ordinary history;
    /// one spliced into the middle is what `verify_chain` fails closed on —
    /// and because it stops there, so does this, which is why the value is
    /// `0` or `1` rather than a tally.
    pub legacy_splice: u64,
    /// `1` when the walk broke on a link: an adjacent pair failing
    /// `prev_hash`/`seq` continuity, a head that does not anchor, a prune-bind
    /// that does not hold, or the first retained entry not following the last
    /// removed one. `0` or `1` for the same reason as `legacy_splice`: the
    /// verifier breaks at the first one, and a single spliced line disturbs
    /// two pairs, so a tally here would describe one line as two findings.
    pub broken: u64,
    /// `1` when a removed entry's `entry_hash` did not match its contents —
    /// what `audit verify` reports as exit 1 and describes as possible
    /// tampering (`#540`). A key of its own rather than part of `broken`:
    /// releases since 1.0.5 read `broken` as "a break in prev_hash/seq
    /// continuity" and would describe a rewritten entry that way. One they do
    /// not know makes them say the record cannot be read, which is true.
    pub hash_mismatch: u64,
    /// Times a prune could not finish its check (`#539`). Either the walk
    /// halted inside the removed range — on an entry naming a key the ring
    /// does not hold, or because the ring could not be used at all — and
    /// everything behind that went unexamined; or the range walked clean and
    /// the first retained entry did not authenticate, so its link to the last
    /// removed line could not be checked. This is not a record of the missing
    /// key — restoring the key resolves that, and a permanent record of it
    /// would state a fault that may no longer exist. It records that entries
    /// were removed without the check completing, which stays true once the
    /// key is back. Without it a range halted at its first entry and a clean
    /// range both wrote all zeroes.
    pub unchecked: u64,
    /// Times a prune could not carry a previous prune point's record
    /// forward, because that prune point did not authenticate against the
    /// key it names. Counted rather than silently dropped: a record that
    /// vanishes and a record that says zero must not look the same.
    pub prior_lost: u64,
    /// A `pruned:` record was present and this build could not read all of
    /// it. Read-side only — `try_prune` turns an unreadable prior record into
    /// [`Self::prior_lost`], because from the writer's side that is what
    /// happened.
    pub record_unreadable: bool,
}

impl PrunedFindings {
    pub(super) fn merge(self, other: Self) -> Self {
        Self {
            unverifiable: self.unverifiable.saturating_add(other.unverifiable),
            unprotected: self.unprotected.saturating_add(other.unprotected),
            legacy_splice: self.legacy_splice.saturating_add(other.legacy_splice),
            broken: self.broken.saturating_add(other.broken),
            hash_mismatch: self.hash_mismatch.saturating_add(other.hash_mismatch),
            unchecked: self.unchecked.saturating_add(other.unchecked),
            prior_lost: self.prior_lost.saturating_add(other.prior_lost),
            record_unreadable: self.record_unreadable || other.record_unreadable,
        }
    }

    /// The `rule_id` value that records these counts, or `None` when there is
    /// nothing to record.
    ///
    /// `None` matters as much as the string: a prune that found nothing
    /// writes the same bytes it wrote before `#461`, so a log that never hits
    /// the condition is byte-identical to one produced by the previous
    /// release. Zero-valued keys are omitted for the same reason.
    ///
    /// The two keys `#539`/`#540` added sit after the ones 1.0.5 wrote, so a
    /// record holding only those reads as it always did.
    fn encode(self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut push = |name: &str, n: u64| {
            if n > 0 {
                parts.push(format!("{name}={n}"));
            }
        };
        push("unverifiable", self.unverifiable);
        push("unprotected", self.unprotected);
        push("legacy_splice", self.legacy_splice);
        push("broken", self.broken);
        push("hash_mismatch", self.hash_mismatch);
        push("unchecked", self.unchecked);
        push("prior_lost", self.prior_lost);
        if parts.is_empty() {
            None
        } else {
            Some(format!("{FINDINGS_PREFIX}{}", parts.join(";")))
        }
    }

    fn unreadable() -> Self {
        Self {
            record_unreadable: true,
            ..Self::default()
        }
    }

    /// One sentence naming what a prune removed, for the surfaces that report
    /// it.
    ///
    /// Returned rather than printed, and shared by `audit verify` and
    /// `doctor` rather than written twice: two surfaces describing one record
    /// in wording that drifts apart is the failure `#471 item 3` records, and
    /// the record is counts only, so there is nothing here for one surface to
    /// redact and the other not.
    ///
    /// No total is computed. Most of the counters are 0-or-1 and one of them
    /// — `broken` — describes a relationship between two lines rather than a
    /// line, so a sum would call a single spliced entry "2 entries" and undo
    /// the very thing keeping `broken` off a tally.
    ///
    /// `record_unreadable` is said *beside* whatever was read, not instead of
    /// it (`#539`). It used to replace the whole sentence, so two prune points
    /// merged by `verify_chain` — one legible, one not — told the operator to
    /// upgrade and dropped the counts that had been read.
    pub fn summary(self) -> String {
        const UNREADABLE: &str = "recorded findings in a form this build cannot read \
                                  — upgrade omamori and re-run";
        let mut parts: Vec<String> = Vec::new();
        if self.unverifiable > 0 {
            parts.push("an entry declaring an unrecognized chain_version".to_string());
        }
        if self.unprotected == 1 {
            parts.push("1 entry carrying no HMAC".to_string());
        } else if self.unprotected > 1 {
            parts.push(format!("{} entries carrying no HMAC", self.unprotected));
        }
        if self.legacy_splice > 0 {
            parts.push("a legacy entry spliced in after the chain had started".to_string());
        }
        if self.broken > 0 {
            parts.push("a break in prev_hash/seq continuity".to_string());
        }
        if self.hash_mismatch > 0 {
            parts.push("an entry whose HMAC did not match its contents".to_string());
        }
        // The wording `audit verify` uses for a halt it cannot explain away:
        // an attacker who rewrites an entry can also rename its key, which
        // turns what would have been `hash_mismatch` into this.
        if self.unchecked == 1 {
            parts.push(
                "a range whose check could not be completed (treat as possible tampering)"
                    .to_string(),
            );
        } else if self.unchecked > 1 {
            parts.push(format!(
                "{} ranges whose check could not be completed (treat as possible tampering)",
                self.unchecked
            ));
        }
        let lost = if self.prior_lost == 1 {
            ", and 1 earlier record could not be carried forward".to_string()
        } else if self.prior_lost > 1 {
            format!(
                ", and {} earlier records could not be carried forward",
                self.prior_lost
            )
        } else {
            String::new()
        };
        match (parts.is_empty(), self.record_unreadable) {
            // Not "nothing unverifiable": part of the record went unread.
            (true, true) => format!("a prune {UNREADABLE}{lost}"),
            (true, false) => {
                format!("a prune reported nothing unverifiable in what it removed{lost}")
            }
            (false, unreadable) => {
                let also = if unreadable {
                    format!("; a prune also {UNREADABLE}")
                } else {
                    String::new()
                };
                format!(
                    "a prune removed a range that did not fully verify: {}{lost}{also}",
                    parts.join(", ")
                )
            }
        }
    }
}

/// Read a prune point's findings record out of its `rule_id`.
///
/// `None` means there is no record — either the field is absent, or it holds
/// something that is not this record at all.
///
/// A key this build does not know sets `record_unreadable` and leaves the
/// counts it did read in place (`#539`). Both halves matter: a build that
/// quietly skipped the counter it did not recognise would report "nothing was
/// lost" about a range where something was, and one that threw the rest away
/// with it — which this did through 1.2.2 — told the operator to upgrade and
/// lost an `unverifiable=1` that was perfectly legible.
///
/// A part that is not `key=number`, or a key given twice, still yields
/// [`PrunedFindings::unreadable`] and nothing else: there it is the counts
/// themselves that cannot be trusted.
pub(super) fn decode_findings(rule_id: Option<&str>) -> Option<PrunedFindings> {
    let raw = rule_id?.strip_prefix(FINDINGS_PREFIX)?;
    let mut findings = PrunedFindings::default();
    let mut seen: Vec<&str> = Vec::new();
    for part in raw.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            return Some(PrunedFindings::unreadable());
        };
        let Ok(n) = value.parse::<u64>() else {
            return Some(PrunedFindings::unreadable());
        };
        // A repeated key is unreadable, not last-wins. `encode` cannot
        // produce one, so anything that arrives with a duplicate was built by
        // something else — and picking a winner there would be this function
        // deciding, on its own, which of two claims about a removed range to
        // believe.
        if seen.contains(&key) {
            return Some(PrunedFindings::unreadable());
        }
        seen.push(key);
        match key {
            "unverifiable" => findings.unverifiable = n,
            "unprotected" => findings.unprotected = n,
            "legacy_splice" => findings.legacy_splice = n,
            "broken" => findings.broken = n,
            "hash_mismatch" => findings.hash_mismatch = n,
            "unchecked" => findings.unchecked = n,
            "prior_lost" => findings.prior_lost = n,
            _ => findings.record_unreadable = true,
        }
    }
    Some(findings)
}

/// What `audit verify` would have said about the range a prune is about to
/// remove — found by walking it the way `audit verify` does (`#539`, `#540`).
///
/// `removed` runs from the head of the file, through the prune point already
/// standing there if one is, to the last line being removed. That is where a
/// walk has to start: the head is checked against a genesis or prune anchor,
/// and a prior prune point is authenticated and its prune-bind checked, by
/// the code that checks them in `verify_chain`.
///
/// `first_retained` is walked too, as a continuation of the same walk, and
/// for one question only: does it follow the last removed line. After the
/// prune a prune point stands between the two, the verifier allows a gap
/// there, and nothing can ask again. So the answer is one of three, and
/// "nothing to record" is given only when the entry authenticated:
///
/// - it authenticated, which covers its `seq` and `prev_hash`, and the link
///   holds: nothing is recorded;
/// - the link does not hold: `broken`;
/// - it did not authenticate — the walk halted on its key or its version, its
///   HMAC does not match, it carries none, or it is not an entry at all — so
///   the link could not be checked: `unchecked`. An entry's `seq` and
///   `prev_hash` say nothing while its hash does not hold. Recording nothing
///   here let a deletion at the end of the range be hidden by making this one
///   entry fail to authenticate until the prune had run and then putting it
///   back (review, P1).
///
/// What is wrong with that entry *itself* is still not what is recorded: it
/// stays in the log, and the next `audit verify` reports it for as long as it
/// is true.
///
/// There is no exception for a legacy line. One was written — "a legacy line
/// there, before any chain has started, is ordinary history, and the verifier
/// judges nothing about it" — and it was the same hole again (review, R2):
/// delete the head of a chain, put one old legacy line in its place, strip
/// `chain_version` from the next entry until the prune has run, and that
/// entry is counted as legacy and nothing is written. And the exception
/// protected no healthy store: a legacy line behind a prune point is what the
/// verifier fails closed on at the next `audit verify` anyway.
///
/// `removed` is an iterator, not a slice: a prune reads the range from the
/// file a line at a time (ADR-0016), and a read that fails is the caller's
/// error to report.
///
/// `head_naming_prune` is the first line when it carries `command:
/// "_prune"`. It decides only whether there was a prior record to lose.
///
/// `keyring` is `None` only where a test prunes with no store to load a ring
/// from. That is walked as the empty ring it is, so the first entry naming a
/// key halts it. A ring that cannot resolve any id — an unlistable key
/// directory, an unreadable epoch record — starts the walk the way
/// `verify_chain` starts over the same store, already halted: see
/// [`keyring_failure`].
///
/// `pub(super)` so the audit tests can hold the record to the answer written
/// beside each line (#556).
pub(super) fn findings_for_removed_range<S: AsRef<str>, E>(
    removed: impl Iterator<Item = Result<S, E>>,
    first_retained: Option<&str>,
    head_naming_prune: Option<&str>,
    keyring: Option<&Keyring>,
) -> Result<PrunedFindings, E> {
    let empty = Keyring::empty();
    let keyring = keyring.unwrap_or(&empty);
    let start = Walk::start(VerifyResult {
        key_store_failure: keyring_failure(keyring),
        ..VerifyResult::default()
    });

    let walk = walk_lines(removed, keyring, start)?;
    let result = &walk.result;

    let mut findings = PrunedFindings::default();
    if result.unknown_version_at.is_some() {
        findings.unverifiable = 1;
    }
    findings.unprotected = result.never_protected_entries;
    match walk.broke {
        Some(BreakCause::LegacySplice) => findings.legacy_splice = 1,
        Some(BreakCause::Hash) => findings.hash_mismatch = 1,
        Some(BreakCause::Link) => findings.broken = 1,
        None => {}
    }
    // Either way a key is why the walk stopped: one entry named a key the
    // ring does not hold, or the ring could resolve nothing and the walk
    // began halted.
    if result.key_unavailable_at.is_some() || result.key_store_failure.is_some() {
        findings.unchecked = 1;
    }
    findings = findings.merge(prior_record(head_naming_prune, result));

    // The trailing edge. Only a walk that is still judging can be continued:
    // a break has stopped for good, and past a halt the next line would only
    // be tallied. Either of those has already put something in the record.
    //
    // Added to what the prior record carried, not assigned over it.
    let still_judging = result.broken_at.is_none() && !result.halted();
    let authenticated = result.chain_entries;
    if still_judging && let Some(line) = first_retained {
        let after = walk_lines(std::iter::once(Ok::<_, E>(line)), keyring, walk)?;
        if after.broke == Some(BreakCause::Link) {
            findings.broken = findings.broken.saturating_add(1);
        } else if after.result.chain_entries == authenticated {
            // `chain_entries` moves only past the `entry_hash` comparison, so
            // this is every way of not authenticating at once — and the one
            // test that cannot be passed by editing the line.
            findings.unchecked = findings.unchecked.saturating_add(1);
        }
    }
    Ok(findings)
}

/// The record the prune point at the head of the removed range carried,
/// brought forward — or `prior_lost` when there was one to bring and it could
/// not be.
///
/// The record is tamper-evidence *about* the log held *in* the log, so it is
/// read only from an entry that authenticates against the key its own
/// `key_id` names — the rule `#461` set for anything taken back out of the
/// log. That check is the walk's: `pruned_findings` is
/// filled past the prune point's own `entry_hash` comparison, and `pruned` is
/// set there too. Every way of failing to get there produces `prior_lost`, so
/// a record that could not be carried is visible as a record that could not
/// be carried, rather than as an absence.
fn prior_record(head_naming_prune: Option<&str>, result: &VerifyResult) -> PrunedFindings {
    let lost = PrunedFindings {
        prior_lost: 1,
        ..PrunedFindings::default()
    };
    if let Some(prior) = result.pruned_findings {
        return if prior.record_unreadable {
            // What this build could read is carried; the part it could not is,
            // from the writer's side, a record it could not carry. The flag
            // itself is read-side only and is never written.
            PrunedFindings {
                record_unreadable: false,
                ..prior
            }
            .merge(lost)
        } else {
            prior
        };
    }
    if result.pruned {
        // Authenticated, and carrying nothing.
        return PrunedFindings::default();
    }
    // Nothing at the head authenticated as a prune point. Whether that lost a
    // record depends on whether a prune point was there to hold one —
    // `is_prune_point`'s three fields, not `command` alone: an ordinary entry
    // for a command that happens to be named `_prune` is not one, has no
    // record, and loses nothing.
    let Some(head) = head_naming_prune else {
        return PrunedFindings::default();
    };
    match parse_line::<AuditEvent>(head.trim()) {
        Ok(event) if !is_prune_point(&event) => PrunedFindings::default(),
        _ => lost,
    }
}

/// Where a prune builds the log that replaces the one it is pruning
/// (ADR-0016): beside it, under a name only a prune uses, so that whatever is
/// found there is a prune's own leftover and can be swept without asking whose
/// it is.
pub(super) fn prune_temp_path_for(audit_path: &Path) -> PathBuf {
    let mut temp = audit_path.as_os_str().to_owned();
    temp.push(".prune-tmp");
    PathBuf::from(temp)
}

/// Prune entries older than `retention_days`.
/// Called from `append()` once it has released the log's lock (ADR-0017).
/// Best-effort: the caller turns an error into a warning (prune is not critical path).
pub(super) fn try_prune(
    signing_key: &SigningKey,
    retention_days: u32,
    path: &Path,
    warnings: &mut Vec<String>,
) -> Result<u64, std::io::Error> {
    try_prune_at_collect(
        signing_key,
        retention_days,
        path,
        true,
        OffsetDateTime::now_utc(),
        warnings,
    )
}

/// Removes what an unfinished prune left under the temporary name, if this
/// process can show no prune is running. Called on the prune's own schedule
/// when retention is off, so a leftover does not outlive the setting, and by a
/// prune that will not run for want of a secret.
pub(super) fn sweep_leftover(path: &Path) {
    let temp = prune_temp_path_for(path);
    if fs::symlink_metadata(&temp).is_err() {
        return;
    }
    if let Ok(_prunes) = exclude_other_prunes(path) {
        let _ = clear_leftover(&temp);
    }
}

/// [`try_prune_at_collect`] with its warnings printed — the form the tests that
/// pin a prune at a fixed `now` call.
///
/// `file` is the handle those tests locked the log with, from when a prune ran
/// under its caller's lock. A prune takes the lock itself now, so that lock is
/// let go here and the handle is otherwise unused.
#[cfg(test)]
pub(super) fn try_prune_at(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    path: &Path,
    now: OffsetDateTime,
) -> Result<u64, std::io::Error> {
    unlock(file);
    let (result, warnings) = prune_collecting(signing_key, retention_days, path, true, now);
    super::print_warnings(&warnings);
    result
}

/// [`try_prune_at`] without loading the store's keyring: the range is walked
/// against an empty ring, so the first entry naming a key halts it. The shape
/// the oldest prune tests were written in, when a prune took no path at all.
#[cfg(test)]
pub(super) fn try_prune_at_no_ring(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    path: &Path,
    now: OffsetDateTime,
) -> Result<u64, std::io::Error> {
    unlock(file);
    let (result, warnings) = prune_collecting(signing_key, retention_days, path, false, now);
    super::print_warnings(&warnings);
    result
}

/// The prune with its warnings handed back, for the tests that read them.
#[cfg(test)]
pub(super) fn prune_collecting(
    signing_key: &SigningKey,
    retention_days: u32,
    path: &Path,
    load_ring: bool,
    now: OffsetDateTime,
) -> (Result<u64, std::io::Error>, Vec<String>) {
    let mut warnings = Vec::new();
    let result = try_prune_at_collect(
        signing_key,
        retention_days,
        path,
        load_ring,
        now,
        &mut warnings,
    );
    (result, warnings)
}

#[cfg(test)]
fn unlock(file: &fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

/// The prune itself. Its warnings are pushed onto `warnings` (ADR-0013).
///
/// Nothing here writes into the log (ADR-0016). The result is built in
/// [`prune_temp_path_for`] and renamed over it, so a prune that stops — a
/// full disk, a killed process, power — leaves the log as it was until the
/// rename and as pruned after it.
///
/// **And the log's lock is held only for that rename** (ADR-0017). The log
/// grows at its end and nowhere else; the one thing that changes its head is a
/// prune. So with prunes excluded from one another, everything before the
/// point the copy stopped at is the same bytes whenever it is read, and it is
/// read here without the lock. The lock is taken afterwards, for as long as it
/// takes to add what was appended meanwhile and rename. Until this, a prune
/// copied under `append`'s lock, and every `append` that arrived in those
/// seconds gave up after half of one and left no entry.
///
/// It reads only what it has to: the head as far as the first entry it keeps,
/// a thousand lines past that to know enough would remain, and the removed
/// range once more for the walk. The retained part is copied without being
/// looked at. A log whose first entry is not yet [`PRUNE_SLACK`] past the
/// period is left after a line or two.
///
/// `load_ring` is `false` only in [`try_prune_at_no_ring`].
fn try_prune_at_collect(
    signing_key: &SigningKey,
    retention_days: u32,
    path: &Path,
    load_ring: bool,
    now: OffsetDateTime,
    warnings: &mut Vec<String>,
) -> Result<u64, std::io::Error> {
    // `#461`: without a secret there is nothing to prune *with*. `hmac_bytes`
    // answers a `None` key with the fixed string `NO_HMAC_SECRET` (`chain.rs`),
    // so the prune point this would write carries a `target_hash` and an
    // `entry_hash` that any reader can reproduce — a prune-bind that binds
    // nothing, standing where the pruned range used to be. Keeping the entries
    // is the lesser loss: the condition that removed the key is usually
    // recoverable, and a later prune with the key in hand does the same work.
    if signing_key.secret().is_none() {
        warnings.push(
            "omamori warning: audit prune skipped — no HMAC secret is available, so the prune \
             point that replaces the removed entries could not be protected. The entries were \
             left in place; the log will keep growing until the key is readable again."
                .to_string(),
        );
        // No prune, but what an earlier one left unfinished still goes.
        sweep_leftover(path);
        return Ok(0);
    }

    // One prune at a time. Held until this function returns; the kernel lets
    // go of it if the process dies first.
    let _prunes = match exclude_other_prunes(path) {
        Ok(lock) => lock,
        Err(reason) => {
            warnings.push(format!("omamori warning: audit prune skipped — {reason}"));
            return Ok(0);
        }
    };
    // With that held, whatever stands under the temporary name is a leftover.
    let temp = prune_temp_path_for(path);
    clear_leftover(&temp)?;

    // --- Phase one: without the log's lock. ---
    //
    // Opened for reading and never created, and kept open to the end: the
    // lock in phase two is taken on this descriptor, and the comparisons made
    // under it are against this file, which cannot have been swapped for
    // another that reused its inode number while it is still open.
    let log = open_read_nofollow(path)?;

    // Read before anything else, so that what phase two compares the head
    // against is the head as it stood when this prune began.
    let head = first_line(&log)?;

    let cutoff = now - time::Duration::days(i64::from(retention_days));
    let boundary = find_boundary(&log, cutoff)?;

    // Adjust for existing prune_point: don't re-count it
    let prune_count = boundary
        .lines_before
        .saturating_sub(usize::from(boundary.head_prune.is_some())) as u64;
    if prune_count == 0 {
        #[cfg(test)]
        HEAD_READ.with(|slot| slot.set((&log).stream_position().ok()));
        return Ok(0);
    }

    // Check minimum retain count.
    //
    // This is also what makes the unlocked read above safe at the end of the
    // log, where an `append` may be partway through its line: a boundary
    // followed by a thousand whole lines is nowhere near a line still being
    // written. (Reading *at* such a line, `find_boundary` can count it as two
    // — `read_line` returns what is there, then the rest — and a prune that
    // close to the end stops here.)
    let (retain_count, first_retained) = retained_lines(&log, boundary.offset, MIN_RETAIN_ENTRIES)?;
    if retain_count < MIN_RETAIN_ENTRIES {
        return Ok(0);
    }

    // `#461`: the ring is loaded here, before the result is built, because the
    // range has to be walked — and the previous prune point's findings record
    // authenticated — before the prune point replacing them is written. The
    // key store's lock is taken and released inside; the log's is not held.
    let keyring = load_ring.then(|| load_keyring(&secret_path_for(path)));

    // `#461`: what the removed range would have cost the verifier. Asked
    // before the log is replaced, since afterwards those lines are gone —
    // which is the whole defect being closed.
    //
    // The range starts at line 0, prune point included. That prune point is
    // about to be discarded along with the range it covered, and the record
    // it carries would die with it — a trace with a lifetime of one prune,
    // about a day on a busy log —
    // so the walk authenticates it and the record is carried forward.
    //
    // Read from the file a line at a time rather than held: the range a first
    // prune removes from a log that was never pruned is most of that log.
    let mut reader = &log;
    reader.seek(SeekFrom::Start(0))?;
    let findings = findings_for_removed_range(
        BufReader::new(reader.take(boundary.offset)).lines(),
        first_retained.as_deref(),
        boundary.head_prune.as_deref(),
        keyring.as_ref(),
    )?;

    let prune_point = build_prune_point(
        signing_key,
        prune_count,
        &boundary.first_retained_hash,
        findings,
        now,
    );

    let mut out = create_prune_temp(&temp)?;
    let mut guard = TempGuard::new(&temp);
    keep_owner(&log, &out)?;
    let mut line =
        serde_json::to_string(&prune_point).expect("prune_point serialization cannot fail");
    line.push('\n');
    out.write_all(line.as_bytes())?;

    // Where the copy stops is fixed here and nowhere else: the boundary plus
    // the bytes actually copied. Phase two starts from exactly that point, so
    // nothing is added twice and nothing is left out, wherever it falls. The
    // one thing that must not happen is for the two to be reckoned apart —
    // the copy running on past the length taken here while phase two starts
    // from that length. The copy is bounded by it as well, which also shows a
    // log that became shorter.
    let length = log.metadata()?.len();
    let wanted = length.saturating_sub(boundary.offset);
    let mut reader = &log;
    reader.seek(SeekFrom::Start(boundary.offset))?;
    let copied = copy_retained(&mut reader, &mut out, wanted)?;
    if copied < wanted {
        return Err(std::io::Error::other(
            "the audit log became shorter while it was being pruned",
        ));
    }
    let copied_to = boundary.offset + copied;
    out.sync_all()?;

    #[cfg(test)]
    run_test_hook(&BETWEEN_PHASES);

    // --- Phase two: under the log's lock, for as long as it takes to publish. ---
    //
    // One bounded attempt. The process waiting here is often a `hook-check`
    // that has not printed its verdict, and what holds the lock for longer
    // than this waits — `audit verify`, for the length of its walk — holds it
    // for longer than any retry worth making. The next check starts over.
    if let Err(e) = flock_exclusive(&log) {
        // Two different things, and only the first is someone else's doing.
        warnings.push(if e.kind() == std::io::ErrorKind::WouldBlock {
            format!(
                "omamori warning: audit prune postponed — the log was in use for longer than \
                 a prune waits ({e}); it will be tried again"
            )
        } else {
            format!(
                "omamori warning: audit prune postponed — the log could not be locked to \
                 publish it ({e}); it will be tried again"
            )
        });
        return Ok(0);
    }
    if let Err(what) = still_as_read(path, &log, copied_to, &head) {
        warnings.push(format!(
            "omamori warning: audit prune abandoned — {what}; the log was left as it was"
        ));
        return Ok(0);
    }
    // The last thing standing between a failed exclusion and someone else's
    // half-written file becoming the log.
    if !names_this_file(&temp, &out) {
        guard.disarm();
        warnings.push(format!(
            "omamori warning: audit prune abandoned — {} is no longer the file this prune \
             wrote; the log was left as it was",
            temp.display()
        ));
        return Ok(0);
    }

    let mut reader = &log;
    reader.seek(SeekFrom::Start(copied_to))?;
    std::io::copy(&mut reader, &mut out)?;
    // What `append` does before it writes: a log whose last line was never
    // finished gets its newline, so the next entry starts on its own line.
    let mut last = [0u8; 1];
    reader.seek(SeekFrom::End(-1))?;
    reader.read_exact(&mut last)?;
    if last[0] != b'\n' {
        out.write_all(b"\n")?;
    }

    // `sync_all`, then `rename`, then the directory: the order `write_hwm`
    // and `atomic_file` publish in. Until the rename the log has not been
    // touched and the temporary file is removed on the way out; after it the
    // log is the pruned one, and the one step left changes no content.
    out.sync_all()?;
    drop(out);
    fs::rename(&temp, path)?;
    guard.disarm();
    fsync_parent(path);
    drop(log);

    // The high-water-mark is not touched (#568). `append` raises it to the
    // `seq` it has just written whenever that is above the mark, and a prune
    // removes from the head — the end of the chain is where it was. So where
    // `append` could write the mark, a recomputation here could only agree
    // with it, or disagree with one that sits *above* the chain: the state
    // `append` warns about as a possible truncation, and the one `audit
    // verify` reports as exit 3. Through 1.2.2 this function recomputed the
    // mark from what remained, which moved a mark above the chain down to the
    // new end of it, and the report went away.

    warnings.push(format!(
        "omamori: pruned {prune_count} audit entries older than {retention_days}d"
    ));
    Ok(prune_count)
}

/// Keeps every other prune of this log out, by an exclusive `flock` on the
/// directory the log is in (ADR-0017). One attempt: if it is held, a prune is
/// running, and a second one has nothing to add.
///
/// The directory rather than a lock file of its own: there is then nothing in
/// the data directory to own, to protect, or to remove as debris — and
/// removing a lock file while a prune holds it is how two would come to run
/// at once.
fn exclude_other_prunes(path: &Path) -> Result<fs::File, String> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let handle = fs::File::open(dir).map_err(|e| {
        format!(
            "{} could not be opened to keep other prunes out: {e}",
            dir.display()
        )
    })?;
    match try_flock_exclusive(&handle) {
        Ok(true) => Ok(handle),
        Ok(false) => Err(format!(
            "another process is pruning this log, or holds a lock on {}",
            dir.display()
        )),
        Err(e) => Err(format!(
            "{} could not be locked to keep other prunes out: {e}",
            dir.display()
        )),
    }
}

/// The first line of the log, newline included — what phase two compares
/// against to know the head was not rewritten in between.
fn first_line(log: &fs::File) -> std::io::Result<Vec<u8>> {
    let mut reader = log;
    reader.seek(SeekFrom::Start(0))?;
    let mut line = Vec::new();
    BufReader::new(reader).read_until(b'\n', &mut line)?;
    Ok(line)
}

/// Under the log's lock: is the log still what phase one read?
///
/// Three things, any of which ends the prune:
///
/// - the path names another file — a prune by a process that does not take the
///   directory lock, or anything else that replaced the log;
/// - the log is shorter than the point the copy reached;
/// - its first line is not the one phase one saw. This catches a head
///   rewritten *in the same file* after phase one read it, which is what a
///   release through 1.2.2 does when it prunes. It does not catch a rewrite
///   that finished before phase one began — there the log simply holds nothing
///   old enough, and the prune ended for that reason — nor two logs that open
///   with the same line.
fn still_as_read(
    path: &Path,
    log: &fs::File,
    copied_to: u64,
    head: &[u8],
) -> Result<(), &'static str> {
    if !names_this_file(path, log) {
        return Err("the log was replaced while it ran");
    }
    let length = log.metadata().map(|meta| meta.len()).unwrap_or(0);
    if length < copied_to {
        return Err("the log became shorter while it ran");
    }
    let mut reader = log;
    let mut now = vec![0u8; head.len()];
    let same = reader.seek(SeekFrom::Start(0)).is_ok()
        && reader.read_exact(&mut now).is_ok()
        && now == head;
    if !same {
        return Err("the head of the log changed while it ran");
    }
    Ok(())
}

/// Where the part of a log a prune keeps begins.
struct Boundary {
    /// Byte offset of the first line kept.
    offset: u64,
    /// How many lines stand before it, an existing prune point included.
    lines_before: usize,
    /// The first line, when it names the prune command: a prune point already
    /// standing at the head. Not counted among the entries pruned, and what
    /// [`prior_record`] is asked about.
    head_prune: Option<String>,
    /// `entry_hash` of the first entry at or past the cutoff, for the
    /// prune-bind. Empty when the log ended before one was found.
    first_retained_hash: String,
}

/// Reads the log from its head as far as the first entry at or past `cutoff`.
///
/// The boundary is that entry when there is one. When the log ends first, it
/// is the end of the last entry older than the cutoff — lines that carry no
/// readable timestamp are removed only when an entry that is kept follows
/// them, which is what the pass over the whole file this replaces did.
///
/// **Whether a prune is due at all is settled at the first entry** — the
/// first line carrying a readable timestamp, a prune point at the head
/// aside. If it is not yet [`PRUNE_SLACK`] past the cutoff, nothing is due and
/// the boundary handed back removes nothing. That is decided before the
/// search for the boundary and not after it, because on every check between
/// two prunes the head of the log holds up to a day of entries that are past
/// the period, and walking them to find out it is not yet time is what a
/// check must not cost.
fn find_boundary(file: &fs::File, cutoff: OffsetDateTime) -> std::io::Result<Boundary> {
    use time::format_description::well_known::Rfc3339;

    let mut log = file;
    log.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(log);

    let mut boundary = Boundary {
        offset: 0,
        lines_before: 0,
        head_prune: None,
        first_retained_hash: String::new(),
    };
    let mut line = String::new();
    let mut end = 0u64;
    let mut index = 0usize;
    let mut due = false;
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        let start = end;
        end += read as u64;
        let i = index;
        index += 1;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue; // torn line
        };

        // Skip existing prune_point at the start (don't count it as prunable)
        if i == 0 && val.get("command").and_then(|v| v.as_str()) == Some(PRUNE_COMMAND) {
            boundary.head_prune = Some(trimmed.to_string());
            continue;
        }

        let Some(ts_str) = val.get("timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ts) = OffsetDateTime::parse(ts_str, &Rfc3339) else {
            continue;
        };

        if !due {
            if ts >= cutoff - PRUNE_SLACK {
                return Ok(Boundary {
                    offset: 0,
                    lines_before: 0,
                    head_prune: boundary.head_prune,
                    first_retained_hash: String::new(),
                });
            }
            due = true;
        }

        if ts >= cutoff {
            boundary.offset = start;
            boundary.lines_before = i;
            boundary.first_retained_hash = val
                .get("entry_hash")
                .and_then(|h| h.as_str())
                .unwrap_or_default()
                .to_string();
            break;
        }
        // haven't found a keeper yet
        boundary.offset = end;
        boundary.lines_before = i + 1;
    }
    Ok(boundary)
}

/// Counts the lines from `offset` on, stopping at `enough`, and hands back the
/// first of them — the entry the removed range has to be shown to lead into.
fn retained_lines(
    file: &fs::File,
    offset: u64,
    enough: usize,
) -> std::io::Result<(usize, Option<String>)> {
    let mut log = file;
    log.seek(SeekFrom::Start(offset))?;
    let mut lines = BufReader::new(log).lines();
    let Some(first) = lines.next().transpose()? else {
        return Ok((0, None));
    };
    let mut count = 1;
    while count < enough {
        if lines.next().transpose()?.is_none() {
            break;
        }
        count += 1;
    }
    Ok((count, Some(first)))
}

/// Removes what a prune that did not finish left under the temporary name.
/// Called with other prunes excluded, so it is not a prune still running.
fn clear_leftover(temp: &Path) -> std::io::Result<()> {
    let Err(e) = fs::remove_file(temp) else {
        return Ok(());
    };
    if e.kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    // Not a leftover of ours — a prune only ever leaves a regular file — and
    // every prune will stop here until it is gone, so say what it is.
    let what = fs::symlink_metadata(temp)
        .map(|meta| describe_file_type(&meta))
        .unwrap_or("something that could not be examined");
    Err(std::io::Error::new(
        e.kind(),
        format!(
            "{} is in the way ({what}) and could not be removed: {e}",
            temp.display()
        ),
    ))
}

/// `0600`, the mode `write_hwm` gives the mark, rather than the log's own: a
/// permission someone widened would otherwise be carried across every prune.
fn create_prune_temp(temp: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    opts.open(temp)
}

/// Gives the pruned log the owner the log has.
///
/// The rewrite in place never changed who owned the log, because it never
/// made a new file. This does, and the process making it is not always the
/// log's owner: a command run through `sudo` is blocked and audited as root
/// (`shim.rs`), into the invoking user's log. A prune on that append would
/// otherwise publish a log owned by root with mode `0600`, and its owner could
/// no longer append to it or verify it (review, P1).
///
/// The owner is the part that decides who can open a `0600` file, so a prune
/// that cannot keep it does not happen. The group decides nothing at that
/// mode and is kept where it can be.
#[cfg(unix)]
fn keep_owner(log: &fs::File, out: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, fchown};
    let (was, now) = (log.metadata()?, out.metadata()?);
    if was.uid() != now.uid() {
        return fchown(out, Some(was.uid()), Some(was.gid())).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "the pruned log could not be given the log's owner (uid {}): {e}",
                    was.uid()
                ),
            )
        });
    }
    if was.gid() != now.gid() {
        let _ = fchown(out, None, Some(was.gid()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn keep_owner(_log: &fs::File, _out: &fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Copies `wanted` bytes of `log` into `out`, file to file, and says how many
/// it copied.
fn copy_retained(log: &mut &fs::File, out: &mut fs::File, wanted: u64) -> std::io::Result<u64> {
    #[cfg(test)]
    if let Some(limit) = COPY_FAILS_AFTER.with(std::cell::Cell::take) {
        std::io::copy(&mut Read::by_ref(log).take(limit.min(wanted)), out)?;
        return Err(std::io::Error::other("the copy was stopped (test)"));
    }
    #[cfg(test)]
    if let Some(hook) = DURING_COPY.with(|slot| slot.borrow_mut().take()) {
        let half = wanted / 2;
        let first = std::io::copy(&mut Read::by_ref(log).take(half), out)?;
        hook();
        let rest = std::io::copy(&mut Read::by_ref(log).take(wanted - half), out)?;
        return Ok(first + rest);
    }
    std::io::copy(&mut Read::by_ref(log).take(wanted), out)
}

#[cfg(test)]
pub(super) type TestHook = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
thread_local! {
    /// Makes the next prune on this thread fail after copying this many bytes
    /// of the retained part — a full disk, as far as the prune can tell.
    pub(super) static COPY_FAILS_AFTER: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    /// Run once, halfway through the next prune's copy on this thread — where
    /// another process's `append` lands while a prune is copying.
    pub(super) static DURING_COPY: TestHook = const { std::cell::RefCell::new(None) };
    /// How far into the log the last prune on this thread had read when it
    /// found nothing to remove.
    pub(super) static HEAD_READ: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    /// Run once, after the next prune on this thread has finished copying and
    /// before it takes the log's lock.
    pub(super) static BETWEEN_PHASES: TestHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_test_hook(hook: &'static std::thread::LocalKey<TestHook>) {
    // Taken before it runs, so whatever it calls does not run it again.
    let hook = hook.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

/// Build the prune point that replaces the pruned range.
///
/// #457 Bug 1: this used to take a bare secret and write `key_id: "default"`
/// unconditionally. After a rotation, `"default"` names the *epoch-1* key
/// (`secret::load_keyring`), so the entry was signed with one key and labelled
/// with another — the verifier then recomputed its hash with the wrong key and
/// reported the chain as tampered. Taking a `SigningKey` makes the two
/// impossible to disagree: the same value supplies both the bytes and the id.
///
/// `now` is a parameter rather than `OffsetDateTime::now_utc()` because the
/// enclosing `try_prune_at` already threads a deterministic clock through for
/// tests; leaving this one call non-deterministic made a byte-level golden
/// test of the prune point structurally impossible to write.
///
/// `findings` rides in `rule_id` (`#461`). Three properties made that the
/// field to use, and all three were checked rather than assumed:
///
/// - **It is already hashed.** `rule_id` sits in both `HashableEvent` and
///   `HashableEventV2` (`chain.rs`), so the value is covered by `entry_hash`
///   and cannot be edited without the key. No new field, and therefore no
///   `chain_version` bump — which matters because a prune point stands at the
///   head of the file, so bumping it would leave every existing release
///   unable to verify a single line of a pruned log.
/// - **A prune point's `rule_id` has no consumer.** `report`'s `by_rule`
///   tally runs inside `action == "block"`, and a prune point's action is
///   `retention`; `show` renders prune points as a separator, not a row. The
///   field already serialises as `null` on every entry, so the JSON shape
///   does not move either.
/// - **It is not already carrying something else on this entry**, which is
///   what ruled out `target_count` and `target_hash` — `SECURITY.md`'s
///   forensic semantics depend on both.
pub(super) fn build_prune_point(
    signing_key: &SigningKey,
    prune_count: u64,
    first_retained_hash: &str,
    findings: PrunedFindings,
    now: OffsetDateTime,
) -> AuditEvent {
    let secret = signing_key.secret();
    let target_hash = hmac_bytes(
        secret,
        format!("prune-bind:{prune_count}:{first_retained_hash}").as_bytes(),
    );

    let mut event = AuditEvent {
        timestamp: now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: "omamori".to_string(),
        command: PRUNE_COMMAND.to_string(),
        rule_id: findings.encode(),
        action: PRUNE_ACTION.to_string(),
        result: PRUNE_RESULT.to_string(),
        target_count: prune_count as usize,
        target_hash,
        detection_layer: None,
        unwrap_chain: None,
        raw_input_hash: None,
        chain_version: Some(CHAIN_VERSION),
        seq: Some(0),
        prev_hash: Some(prune_genesis_hash(secret)),
        key_id: Some(signing_key.id.clone()),
        entry_hash: None,
        pid: None,
        ppid: None,
        parent_process: None,
        cwd_hash: None,
        wrapper_kind: None,
    };
    event.entry_hash = Some(compute_entry_hash_for_write(secret, &event));
    event
}

pub(super) fn is_prune_point(event: &AuditEvent) -> bool {
    event.command == PRUNE_COMMAND && event.action == PRUNE_ACTION && event.result == PRUNE_RESULT
}
