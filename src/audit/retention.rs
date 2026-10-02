//! Audit log retention and pruning.
//!
//! Automatic prune is triggered every `PRUNE_CHECK_INTERVAL` entries during
//! `AuditLogger::append()`, under the same flock.

use std::convert::Infallible;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use time::OffsetDateTime;

use super::AuditEvent;
use super::chain::{
    CHAIN_VERSION, RecomputedHash, compute_entry_hash, compute_entry_hash_for_write, hmac_bytes,
    parse_line, prune_genesis_hash,
};
use super::secret::{Keyring, SigningKey, load_keyring, secret_path_for};
use super::verify::{BreakCause, VerifyResult, Walk, keyring_failure, walk_lines};
use super::{hwm_path_for, write_hwm};

pub(super) const PRUNE_CHECK_INTERVAL: u64 = 1000;
pub(super) const MIN_RETENTION_DAYS: u32 = 7;
pub(super) const MIN_RETAIN_ENTRIES: usize = 1000;
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
/// `head_names_prune` is the caller's `skip_existing_prune`: the first line
/// carries `command: "_prune"`. It decides only whether there was a prior
/// record to lose.
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
pub(super) fn findings_for_removed_range(
    removed: &[&str],
    first_retained: Option<&str>,
    head_names_prune: bool,
    keyring: Option<&Keyring>,
) -> PrunedFindings {
    let empty = Keyring::empty();
    let keyring = keyring.unwrap_or(&empty);
    let start = Walk::start(VerifyResult {
        key_store_failure: keyring_failure(keyring),
        ..VerifyResult::default()
    });

    // The lines are already in memory and cannot fail to be read, which is
    // what `Infallible` says and what makes these two patterns irrefutable.
    let Ok(walk) = walk_lines(removed.iter().map(Ok::<_, Infallible>), keyring, start);
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
    let head_naming_prune = removed.first().copied().filter(|_| head_names_prune);
    findings = findings.merge(prior_record(head_naming_prune, result));

    // The trailing edge. Only a walk that is still judging can be continued:
    // a break has stopped for good, and past a halt the next line would only
    // be tallied. Either of those has already put something in the record.
    //
    // Added to what the prior record carried, not assigned over it.
    let still_judging = result.broken_at.is_none() && !result.halted();
    let authenticated = result.chain_entries;
    if still_judging && let Some(line) = first_retained {
        let Ok(after) = walk_lines(std::iter::once(Ok::<_, Infallible>(line)), keyring, walk);
        if after.broke == Some(BreakCause::Link) {
            findings.broken = findings.broken.saturating_add(1);
        } else if after.result.chain_entries == authenticated {
            // `chain_entries` moves only past the `entry_hash` comparison, so
            // this is every way of not authenticating at once — and the one
            // test that cannot be passed by editing the line.
            findings.unchecked = findings.unchecked.saturating_add(1);
        }
    }
    findings
}

/// The record the prune point at the head of the removed range carried,
/// brought forward — or `prior_lost` when there was one to bring and it could
/// not be.
///
/// The record is tamper-evidence *about* the log held *in* the log, so it is
/// read only from an entry that authenticates against the key its own
/// `key_id` names — the same rule the post-prune high-water-mark follows
/// since `#461`'s first half. That check is the walk's: `pruned_findings` is
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

/// In-place prune of entries older than `retention_days`.
/// Called under flock_exclusive from append().
/// Best-effort: errors are silently ignored (prune is not critical path).
pub(super) fn try_prune(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
    warnings: &mut Vec<String>,
) -> Result<u64, std::io::Error> {
    try_prune_at_collect(
        file,
        signing_key,
        retention_days,
        audit_path,
        OffsetDateTime::now_utc(),
        warnings,
    )
}

/// [`try_prune_at_collect`] with its warnings printed — the form the tests that
/// pin a prune at a fixed `now` call.
#[cfg(test)]
pub(super) fn try_prune_at(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
    now: OffsetDateTime,
) -> Result<u64, std::io::Error> {
    let mut warnings = Vec::new();
    let result = try_prune_at_collect(
        file,
        signing_key,
        retention_days,
        audit_path,
        now,
        &mut warnings,
    );
    super::print_warnings(&warnings);
    result
}

/// The prune itself. Its warnings are pushed onto `warnings` (ADR-0013).
fn try_prune_at_collect(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
    now: OffsetDateTime,
    warnings: &mut Vec<String>,
) -> Result<u64, std::io::Error> {
    use time::format_description::well_known::Rfc3339;

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
        return Ok(0);
    }

    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let cutoff = now - time::Duration::days(i64::from(retention_days));

    // Partition lines: find the first line whose timestamp >= cutoff.
    // Also capture the first retained entry's hash (for prune-bind) in a single pass.
    let lines: Vec<&str> = content.lines().collect();
    let mut retain_from = 0usize;
    let mut skip_existing_prune = 0usize;
    let mut first_retained_hash = String::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue; // torn line
        };

        // Skip existing prune_point at the start (don't count it as prunable)
        if i == 0 && val.get("command").and_then(|v| v.as_str()) == Some(PRUNE_COMMAND) {
            skip_existing_prune = 1;
            continue;
        }

        let Some(ts_str) = val.get("timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ts) = OffsetDateTime::parse(ts_str, &Rfc3339) else {
            continue;
        };

        if ts >= cutoff {
            retain_from = i;
            first_retained_hash = val
                .get("entry_hash")
                .and_then(|h| h.as_str())
                .unwrap_or_default()
                .to_string();
            break;
        }
        retain_from = i + 1; // haven't found a keeper yet
    }

    // Adjust for existing prune_point: don't re-count it
    let prune_count = retain_from.saturating_sub(skip_existing_prune) as u64;
    if prune_count == 0 {
        return Ok(0);
    }

    // Check minimum retain count
    let retain_count = lines.len() - retain_from;
    if retain_count < MIN_RETAIN_ENTRIES {
        return Ok(0);
    }

    // `#461`: the ring is loaded here rather than after the rewrite, because
    // the range has to be walked — and the previous prune point's findings
    // record authenticated — before the prune point replacing them is built. The post-prune high-water-mark below reuses this
    // same ring. Lock order is unchanged — still one key-store acquisition,
    // inside the log's own flock, on a path that runs once per
    // `PRUNE_CHECK_INTERVAL` appends.
    let keyring = audit_path.map(|path| load_keyring(&secret_path_for(path)));

    // `#461`: what the removed range would have cost the verifier. Asked
    // before the rewrite, since afterwards those lines are gone — which is
    // the whole defect being closed.
    //
    // The range starts at line 0, prune point included. That prune point is
    // about to be discarded along with the range it covered, and the record
    // it carries would die with it — on a log pruning every
    // `PRUNE_CHECK_INTERVAL` appends, a trace with a lifetime of one prune —
    // so the walk authenticates it and the record is carried forward.
    let findings = findings_for_removed_range(
        &lines[..retain_from],
        lines.get(retain_from).copied(),
        skip_existing_prune == 1,
        keyring.as_ref(),
    );

    let prune_point = build_prune_point(
        signing_key,
        prune_count,
        &first_retained_hash,
        findings,
        now,
    );

    // In-place rewrite: prune_point + retained lines
    let estimated_size = content.len(); // upper bound; retained portion is smaller
    let mut new_content = String::with_capacity(estimated_size);
    let prune_json =
        serde_json::to_string(&prune_point).expect("prune_point serialization cannot fail");
    new_content.push_str(&prune_json);
    new_content.push('\n');
    for line in &lines[retain_from..] {
        new_content.push_str(line);
        new_content.push('\n');
    }

    file.seek(SeekFrom::Start(0))?;
    file.write_all(new_content.as_bytes())?;
    file.set_len(new_content.len() as u64)?;
    file.flush()?;

    // Reset the high-water-mark from the retained entries.
    //
    // `#461`: the mark used to be the largest `seq` among them, read straight
    // out of the JSON. That number is tamper-evidence *about* the log, and it
    // was being taken from the log without checking whether the line it came
    // from was written by omamori — so one planted line with a high `seq` put
    // the mark wherever its author chose. No key is needed to write that line:
    // this recomputation was the only thing that read the field back.
    //
    // What that buys an attacker is a false accusation, not concealment
    // (Codex review, R2 — an earlier version of this comment had the direction
    // backwards). `verify_chain` reports a truncated tail when the mark is
    // *above* the chain, so a raised mark makes it say the log was cut when
    // nothing was removed, and keeps saying it: prune is the only thing that
    // recomputes the mark, and it runs once per 1000 appends. Lowering it —
    // which is what would hide a removal — is not reachable this way, since the
    // mark is a maximum. The defect is that tamper-evidence about the log was
    // taken from the log, which is the same root `#456` closed on the append
    // side and named this half as still open.
    //
    // The mark now comes from an entry that authenticates against the key it
    // names. `#456` closed the append side of the same root — on-disk `seq`
    // values trusted without verification — and named this half as still open.
    if let (Some(audit_path), Some(keyring)) = (audit_path, keyring.as_ref()) {
        match authenticated_max_seq(&lines[retain_from..], keyring) {
            Some(seq) => {
                if let Err(e) = write_hwm(&hwm_path_for(audit_path), seq) {
                    warnings.push(format!(
                        "omamori warning: failed to update audit high-water-mark after prune: {e}"
                    ));
                }
            }
            None => {
                // Left where it was, deliberately. A mark below the chain reads
                // as nothing; a mark above it reads as truncation. Neither is a
                // claim this function can make right now, and the previous mark
                // was at least derived when a key was available.
                //
                // The two ways to get here are worth telling apart, because one
                // is a key-store fault the operator can fix and the other is a
                // statement about the entries themselves.
                let reason = match keyring.fatal_anomaly() {
                    Some(anomaly) => anomaly.describe(),
                    None => "no retained entry could be authenticated against the key it names"
                        .to_string(),
                };
                warnings.push(format!(
                    "omamori warning: audit high-water-mark left unchanged after prune — {reason}"
                ));
            }
        }
    }

    warnings.push(format!(
        "omamori: pruned {prune_count} audit entries older than {retention_days}d"
    ));
    Ok(prune_count)
}

/// The highest `seq` among `retained` lines that authenticate against the key
/// they name (`#461`).
///
/// Entries are tried in descending `seq` order and the first one that
/// authenticates wins, so the ordinary case costs one HMAC rather than one per
/// retained entry — and the answer is the same either way, since a lower `seq`
/// cannot raise the maximum.
///
/// `None` covers both "the keyring holds nothing usable" and "nothing retained
/// authenticated". They arrive here identically — an empty ring makes every
/// `keyring.get` miss — and the caller reports which one it was from the ring's
/// own anomalies. Kept as one path on purpose: a separate emptiness branch
/// would be a second place to keep in step with what `get` actually returns.
///
/// Prune points are excluded by [`is_prune_point`], which checks all three
/// fields, rather than by `command` alone as the code this replaced did. The
/// first draft kept the looser check and argued that a real prune point carries
/// `seq: 0`, so admitting one could only lower the mark. That argument holds
/// for a real prune point and says nothing about an ordinary entry that merely
/// *names* `_prune` — a user running a command by that name produces a signed
/// entry with a real `seq`, and dropping it lowered the mark by one whenever it
/// was the highest retained, leaving that one entry's removal undetectable
/// (Codex review, P3). The stricter check is right on both: it still excludes
/// the real prune point, whose `action`/`result` identify it.
fn authenticated_max_seq(retained: &[&str], keyring: &Keyring) -> Option<u64> {
    // `seq` is taken out here rather than checked in the loop, so the sort key
    // is a plain `u64` and an entry without one is simply not a candidate — it
    // could not anchor the mark in any case.
    let mut candidates: Vec<(u64, AuditEvent)> = retained
        .iter()
        .filter_map(|line| parse_line::<AuditEvent>(line.trim()).ok())
        .filter(|event| !is_prune_point(event))
        .filter_map(|event| event.seq.map(|seq| (seq, event)))
        .collect();
    candidates.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));

    for (seq, event) in &candidates {
        // `unwrap_or("default")` for the same reason `verify_chain` uses it: a
        // missing `key_id` is an entry from before the field existed, and
        // `"default"` is the id that epoch always carried.
        let key_id = event.key_id.as_deref().unwrap_or("default");
        let Some(secret) = keyring.get(key_id) else {
            continue;
        };
        let RecomputedHash::Hash(recomputed) = compute_entry_hash(Some(secret), event) else {
            // Legacy (no `chain_version`) or a version this build cannot hash.
            // Either way this entry is not something to anchor the mark on.
            continue;
        };
        if event.entry_hash.as_deref() == Some(recomputed.as_str()) {
            return Some(*seq);
        }
    }
    None
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
