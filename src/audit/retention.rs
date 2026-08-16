//! Audit log retention and pruning.
//!
//! Automatic prune is triggered every `PRUNE_CHECK_INTERVAL` entries during
//! `AuditLogger::append()`, under the same flock.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use time::OffsetDateTime;

use super::AuditEvent;
use super::chain::{
    CHAIN_VERSION, NO_HMAC_SECRET, RecomputedHash, compute_entry_hash,
    compute_entry_hash_for_write, hmac_bytes, is_supported_chain_version, parse_chain_version,
    prune_genesis_hash,
};
use super::secret::{Keyring, SigningKey, UNRESOLVED_KEY_ID, load_keyring, secret_path_for};
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
/// **These counts are not the verdict `verify_chain` reaches.** They are
/// taken from the pruned range alone, one line at a time plus its immediate
/// neighbour, with no key. Three limits follow, and `SECURITY.md` states
/// them for operators:
///
/// - **Narrower in reach.** A break between the range's first line and
///   whatever preceded it is not counted, and an entry whose HMAC simply
///   does not match its contents is not counted at all — that needs a hash
///   per removed line, tracked separately.
/// - **It stops where the verifier stops.** Every state `verify_chain` halts
///   on — an unrecognised `chain_version`, a `key_id` it cannot resolve, a
///   spliced legacy line, a broken link — ends this scan too. Past a halt
///   the verifier tallies lines without judging them (`verify.rs`: "nothing
///   about it — including its own seq/prev_hash — is trustworthy structural
///   signal"), so a scan that kept judging would assert findings the
///   verifier never reached. Only `unprotected` is a true count, because it
///   is the one state the verifier walks past and counts.
/// - **Deliberately not a re-derivation.** Reproducing the verifier's walk
///   here would be a second implementation of a 1.0-frozen surface, and the
///   two would drift with nothing to catch it.
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
    /// `1` when an adjacent pair inside the range failed `prev_hash`/`seq`
    /// continuity. `0` or `1` for the same reason as `legacy_splice`: the
    /// verifier breaks at the first one, and a single spliced line disturbs
    /// two pairs, so a tally here would describe one line as two findings.
    pub broken: u64,
    /// Times a prune could not carry a previous prune point's record
    /// forward, because that prune point did not authenticate against the
    /// key it names. Counted rather than silently dropped: a record that
    /// vanishes and a record that says zero must not look the same.
    pub prior_lost: u64,
    /// A `pruned:` record was present but this build could not read it.
    /// Read-side only — `try_prune` turns an unreadable prior record into
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
    /// No total is computed. Three of the four counters are 0-or-1 and one of
    /// them — `broken` — describes a relationship between two lines rather
    /// than a line, so a sum would call a single spliced entry "2 entries"
    /// and undo the very thing keeping `broken` off a tally.
    pub fn summary(self) -> String {
        if self.record_unreadable {
            return "a prune recorded findings in a form this build cannot read \
                    — upgrade omamori and re-run"
                .to_string();
        }
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
        if parts.is_empty() {
            return format!("a prune reported nothing unverifiable in what it removed{lost}");
        }
        format!(
            "a prune removed a range that did not fully verify: {}{lost}",
            parts.join(", ")
        )
    }
}

/// Read a prune point's findings record out of its `rule_id`.
///
/// `None` means there is no record — either the field is absent, or it holds
/// something that is not this record at all. An unknown key inside a
/// well-formed record yields [`PrunedFindings::unreadable`] rather than being
/// skipped: a build that quietly ignored the counter it did not recognise
/// would report "nothing was lost" about a range where something was.
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
            "prior_lost" => findings.prior_lost = n,
            _ => return Some(PrunedFindings::unreadable()),
        }
    }
    Some(findings)
}

/// Count the part of what `verify` would have said about the range about to
/// be removed that can be seen from the range alone, without a key.
///
/// Not all of it. The range's first line is compared against nothing — the
/// verifier checks it against a genesis or prune anchor, and this does not —
/// and no `entry_hash` is recomputed, so a `broken_at` the verifier would
/// have reached through either route is absent here. `PrunedFindings`'
/// own docs carry the full list.
///
/// `starts_after_prune_point` is whether a prune point stands in front of the
/// range. It decides one thing: whether a legacy entry at the range's first
/// line is ordinary head-of-log history or a splice. `verify_chain` makes the
/// same call from `entries_walked()`, and a prune point counts as walked
/// there, so a range that follows one begins already-started.
///
/// `keyring` is here to reproduce one halt, not to authenticate anything: an
/// entry naming a key the ring does not hold is where `verify_chain` stops
/// (`mark_key_unavailable_tail`), and a scan that walked past it would keep
/// judging structure through an entry whose authenticity is unknown. The
/// state itself is deliberately **not** counted — restoring the key resolves
/// it, so recording it would state a fault that may no longer exist.
fn scan_pruned_range(
    range: &[&str],
    starts_after_prune_point: bool,
    keyring: Option<&Keyring>,
) -> PrunedFindings {
    let mut findings = PrunedFindings::default();
    // A flag, not a tally: the only question asked of it is whether the chain
    // had started, which is the same question `verify_chain` asks its
    // `entries_walked()` count. Counting here would invite a reader to treat
    // the number as a finding.
    let mut walked = starts_after_prune_point;
    // The previous *chain* line's `(seq, entry_hash)`. Torn lines and lines
    // this build cannot hash leave it alone, matching `verify_chain`: it
    // counts them and walks on without moving the link it expects next, so
    // the following entry is compared against the last line that could hold
    // an expectation.
    let mut prev: Option<(u64, String)> = None;

    for line in range {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue; // torn line
        };

        // The version peek comes off the raw value and runs first, exactly as
        // in `verify_chain`: a future format might not parse as an
        // `AuditEvent` at all, and it must still be recognised as a version
        // this build does not know rather than dismissed as a torn line.
        if let Some(version) = parse_chain_version(&raw)
            && !is_supported_chain_version(version)
        {
            // Same precedence `verify_chain` uses — the version gate runs
            // before the key lookup — and the same stop. Nothing about this
            // line is trustworthy structural signal, including its own `seq`
            // and `prev_hash`, so judging the lines after it would produce
            // findings the verifier never reaches: past this point it only
            // tallies. A genuine future-format block whose successors link
            // to it correctly would otherwise be recorded as a break.
            findings.unverifiable = 1;
            break;
        }
        let Ok(event) = serde_json::from_str::<AuditEvent>(trimmed) else {
            // Not typeable and not a version this build knows about: torn, in
            // the same sense `verify_chain` means it, which counts such a line
            // and walks on without moving its link expectation.
            continue;
        };

        // Legacy is decided from the typed value, not from the raw peek. The
        // two disagree on a `chain_version` that is present but malformed —
        // `"garbage"`, or a value past `u32` — which `parse_chain_version`
        // reports as absent while `verify_chain` reaches it as a line it
        // could not type, and counts as torn. Deciding here keeps a single
        // corrupt field from ending the scan as a splice.
        if event.chain_version.is_none() {
            // Pre-chain history at the head of a log; a fail-closed break
            // anywhere after it. The verifier stops there, so the scan does
            // too, and the value is 0 or 1 rather than a tally.
            if walked {
                findings.legacy_splice = 1;
                break;
            }
            continue;
        }

        let seq = event.seq.unwrap_or(0);
        let entry_hash = event.entry_hash.clone().unwrap_or_default();
        let key_id = event.key_id.as_deref().unwrap_or("default");

        // `#483`'s two-piece evidence, both halves required. `entry_hash`
        // alone would take an entry whose hash was destroyed — evidence of
        // tampering — and file it as "was never protected".
        let unprotected =
            key_id == UNRESOLVED_KEY_ID && entry_hash == NO_HMAC_SECRET && !is_prune_point(&event);

        // The key lookup, in the position `verify_chain` puts it: after the
        // version gate, before the link check. An entry naming a key the ring
        // does not hold halts the verifier unless #483's evidence says the
        // entry was written unprotected, and the scan halts with it — every
        // line after it runs through an entry whose authenticity is unknown.
        if !unprotected && keyring.is_none_or(|ring| ring.get(key_id).is_none()) {
            break;
        }

        // Continuity is checked before the entry is classified, and it is
        // checked on unprotected entries too. `verify_chain` does the same
        // (`#483`): that entry's `prev_hash` holds the previous entry's real
        // hash whoever wrote the line, so checking it is what makes a
        // two-field forgery break the chain instead of passing as a coverage
        // gap. Classifying first and skipping the link would reopen exactly
        // that door here.
        if let Some((prev_seq, prev_hash)) = &prev {
            let links = event.prev_hash.as_deref() == Some(prev_hash.as_str());
            let follows = prev_seq.checked_add(1) == Some(seq);
            if !links || !follows {
                // One, and stop — the same shape as the splice above.
                // `verify_chain` sets `broken_at` and breaks, so counting
                // every disturbed pair would report a single spliced line as
                // two findings (its own broken link, and the next entry's
                // link to it) and disagree with the verifier about the log it
                // is describing.
                findings.broken = 1;
                break;
            }
        }
        if unprotected {
            findings.unprotected = findings.unprotected.saturating_add(1);
        }
        walked = true;
        // The next line's `prev_hash` names this line's hash field, sentinel
        // and all — the same advance `verify_chain` makes for an unprotected
        // entry, and what turns a forged pair into a break one line later.
        prev = Some((seq, entry_hash));
    }
    findings
}

/// Carry a previous prune point's record forward, after authenticating it.
///
/// The record is tamper-evidence *about* the log held *in* the log, so it is
/// read only from an entry that authenticates against the key its own
/// `key_id` names — the same rule the post-prune high-water-mark follows
/// since `#461`'s first half. Every way of failing to get there produces
/// `prior_lost`, so a record that could not be carried is visible as a
/// record that could not be carried, rather than as an absence.
fn carry_forward_findings(line: &str, keyring: Option<&Keyring>) -> PrunedFindings {
    let lost = PrunedFindings {
        prior_lost: 1,
        ..PrunedFindings::default()
    };
    let Ok(event) = serde_json::from_str::<AuditEvent>(line.trim()) else {
        return lost;
    };
    if !is_prune_point(&event) {
        // Not a prune point at all, so there is no prior record to carry and
        // nothing was lost.
        return PrunedFindings::default();
    }
    let Some(keyring) = keyring else {
        return lost;
    };
    let key_id = event.key_id.as_deref().unwrap_or("default");
    let Some(secret) = keyring.get(key_id) else {
        return lost;
    };
    let RecomputedHash::Hash(recomputed) = compute_entry_hash(Some(secret), &event) else {
        return lost;
    };
    if event.entry_hash.as_deref() != Some(recomputed.as_str()) {
        return lost;
    }
    match decode_findings(event.rule_id.as_deref()) {
        // A record this build cannot read is, from the writer's side, a
        // record it could not carry.
        Some(findings) if findings.record_unreadable => lost,
        Some(findings) => findings,
        None => PrunedFindings::default(),
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
) -> Result<u64, std::io::Error> {
    try_prune_at(
        file,
        signing_key,
        retention_days,
        audit_path,
        OffsetDateTime::now_utc(),
    )
}

pub(super) fn try_prune_at(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
    now: OffsetDateTime,
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
        eprintln!(
            "omamori warning: audit prune skipped — no HMAC secret is available, so the prune \
             point that replaces the removed entries could not be protected. The entries were \
             left in place; the log will keep growing until the key is readable again."
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
    // the previous prune point's findings record has to be authenticated
    // before it can be read, and that has to happen before the prune point
    // replacing it is built. The post-prune high-water-mark below reuses this
    // same ring. Lock order is unchanged — still one key-store acquisition,
    // inside the log's own flock, on a path that runs once per
    // `PRUNE_CHECK_INTERVAL` appends.
    let keyring = audit_path.map(|path| load_keyring(&secret_path_for(path)));

    // `#461`: what the removed range would have cost the verifier. Counted
    // before the rewrite, since afterwards those lines are gone — which is
    // the whole defect being closed.
    let mut findings = scan_pruned_range(
        &lines[skip_existing_prune..retain_from],
        skip_existing_prune == 1,
        keyring.as_ref(),
    );
    if skip_existing_prune == 1 {
        // The prune point standing at line 0 is about to be discarded along
        // with the range it covered. Without this, the record it carries dies
        // with it, and on a log pruning every `PRUNE_CHECK_INTERVAL` appends
        // that is a trace with a lifetime of one prune.
        findings = findings.merge(carry_forward_findings(lines[0], keyring.as_ref()));
    }

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
                    eprintln!(
                        "omamori warning: failed to update audit high-water-mark after prune: {e}"
                    );
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
                eprintln!(
                    "omamori warning: audit high-water-mark left unchanged after prune — {reason}"
                );
            }
        }
    }

    eprintln!("omamori: pruned {prune_count} audit entries older than {retention_days}d");
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
        .filter_map(|line| serde_json::from_str::<AuditEvent>(line.trim()).ok())
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
