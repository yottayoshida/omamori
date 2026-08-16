//! Report aggregation for audit log analysis.
//!
//! Provides `aggregate_report()` to summarize block events, unknown tool
//! fail-opens, and chain integrity over a given time window.
//!
//! Security invariants (SEC-R10/R11):
//! - Uses `open_read_nofollow` to prevent symlink attacks
//! - Shares reader discipline with verify.rs / secret.rs

use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::error::AuditError;
use super::retention::PrunedFindings;
use super::secret::open_read_nofollow;
use super::verify::{KeyStoreFailure, verify_chain};
use super::{AuditConfig, AuditEvent, resolved_audit_path};

/// Chain integrity status. Originally 3-state per SEC-R8; #177 B1 step 2
/// adds `Unverifiable` as a 4th, distinct from `Broken` — an entry
/// declaring a `chain_version` this binary doesn't recognize is not
/// evidence of tampering, it's evidence the binary predates the chain
/// format. Collapsing it into `Broken` would misreport "you've been
/// tampered with" for what may just be "upgrade omamori."
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
// #457 A5 adds a variant. `VerifyResult` already carries `#[non_exhaustive]`
// (verify.rs) on the same reasoning — a public type that will keep gaining
// cases should close the exhaustive-match door before 1.0, not after. Within
// this crate the compiler still checks every `match` for completeness, so this
// costs nothing internally.
#[non_exhaustive]
pub enum ChainStatus {
    Intact,
    Broken {
        #[serde(skip_serializing)]
        at_seq: u64,
    },
    Truncated,
    Unverifiable {
        #[serde(skip_serializing)]
        at_seq: u64,
        chain_version: u32,
    },
    /// #457 A5: an entry names a `key_id` that is not in the keyring. This is
    /// *not* tampering — the entry may be perfectly authentic and merely
    /// uncheckable, which is what happens when a retired key file is deleted,
    /// renamed, or made unreadable. Kept distinct from `Broken` so a missing
    /// file cannot masquerade as evidence of an attack, and from
    /// `Unverifiable` (an unrecognized `chain_version`) because the remedy is
    /// different: restore the key, not upgrade the binary.
    KeyUnavailable {
        #[serde(skip_serializing)]
        at_seq: u64,
        key_id: String,
    },
    /// #483: the chain's links are whole, and some of its entries carry no HMAC
    /// — omamori writes them that way when it cannot resolve a key.
    ///
    /// Kept out of `Intact`, which is where the first draft of #483 left this
    /// store, on the argument that the links really are intact. They are; that
    /// is not what this field answers. A consumer branching on `intact`
    /// concludes every entry was checked, `audit verify` exits 2 on the same
    /// store, and two surfaces then disagree about one log (review). It was also
    /// a silent contract change — before #483 these entries reached `--json` as
    /// `key_unavailable`.
    ///
    /// Kept out of `KeyUnavailable` as well: nothing is missing and no key would
    /// resolve them, so the remedy that status carries never applied to this
    /// state.
    Unprotected {
        /// How many entries carry no HMAC. A count, not a path, so unlike every
        /// other internal on this enum it is safe to serialize — and it is the
        /// whole of what a consumer can act on.
        entries: u64,
    },
    /// #457 (Codex Round 2): the key directory could not be listed, so *no*
    /// entry can be checked against the key it names.
    ///
    /// Kept out of `Unavailable` deliberately. `Unavailable` also covers "audit
    /// is switched off" and "there is no log", which `doctor` correctly treats
    /// as quiet — folding this in would make an actionable, recoverable fault
    /// disappear from the risk signals, and it used to surface (as `Broken`)
    /// before #457 made the verifier stop early. That would be a regression in
    /// the one surface an operator actually watches.
    KeyringUnusable {
        /// Human-facing text. Carries the directory path, so it is **not**
        /// serialized: `report --json` is the form most likely to be pasted
        /// into an issue, and the path contains the operator's home
        /// directory. Every other variant already keeps its internals out of
        /// the JSON (`at_seq` on both `Broken` and `KeyUnavailable`); this one
        /// shipped as the first to leak, which the reason-free `kind` below
        /// corrects.
        ///
        /// The line this draws is **machine-readable output stays path-free**,
        /// not "paths are secret". The same string reaches `doctor`'s stdout,
        /// `verify`'s stderr and `VerifyResult::keyring_warnings` with the path
        /// intact, and it has to: an operator diagnosing a directory needs to
        /// know which directory. Only the serialized form is redacted.
        #[serde(skip_serializing)]
        reason: String,
        /// The path-free classification, for machine consumers.
        kind: &'static str,
    },
    /// #471/#487: the store could not be read, and not because there is
    /// nothing in it yet.
    ///
    /// `Unavailable` used to absorb every failure that was not
    /// `KeyringUnusable` — a symlink on `audit.jsonl`, an interrupted key
    /// rotation, an unresolvable `HOME` — and `needs_attention()` treats
    /// `Unavailable` as healthy, correctly, because it also means "auditing is
    /// off" and "there is no log yet". The quiet reading was right for those
    /// two and wrong for everything else that shared the bucket.
    ///
    /// One variant rather than one per condition: `kind` carries the
    /// distinction, so a consumer branching on `chain_status` learns one new
    /// value instead of seven. Same split as `KeyringUnusable` — `reason` is
    /// human-facing and embeds the data directory's path, so it stays out of
    /// the JSON; `kind` is what `--json` consumers branch on.
    Inaccessible {
        #[serde(skip_serializing)]
        reason: String,
        kind: &'static str,
    },
    /// **There is nothing to check yet**, and nothing else. Reached from
    /// exactly two errors since #471: auditing is switched off, and a store
    /// whose log or first key has not been written. Anything that means
    /// omamori tried and could not is [`Self::Inaccessible`].
    Unavailable,
}

impl ChainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::Broken { .. } => "broken",
            Self::Truncated => "truncated",
            Self::Unverifiable { .. } => "unverifiable",
            // Underscore, not hyphen: the enum serializes with
            // `rename_all = "snake_case"`, so the JSON tag is
            // `key_unavailable`. Every pre-existing variant is a single word,
            // which is why this is the first place the two could disagree.
            Self::KeyUnavailable { .. } => "key_unavailable",
            Self::Unprotected { .. } => "unprotected",
            Self::KeyringUnusable { .. } => "keyring_unusable",
            Self::Inaccessible { .. } => "inaccessible",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether this status is worth putting in front of an operator — wider
    /// than tampering, and deliberately excluding `Unavailable`, which also
    /// means "audit is switched off" and "there is no log yet".
    ///
    /// #457 (`/simplify`, three reviewers converged): this list was
    /// hand-maintained as a `matches!` in both `doctor` and `report`, each
    /// carrying its own comment warning that `matches!` gets no exhaustiveness
    /// check. Warning about a hazard twice is not closing it. As an exhaustive
    /// `match` here the compiler closes it — `#[non_exhaustive]` constrains
    /// other crates, not this one — so a new variant cannot be silently
    /// treated as healthy. `doctor` had already been bitten by exactly that
    /// during this PR's review.
    pub fn needs_attention(&self) -> bool {
        match self {
            Self::Intact | Self::Unavailable => false,
            Self::Broken { .. }
            | Self::Truncated
            | Self::Unverifiable { .. }
            | Self::KeyUnavailable { .. }
            | Self::Unprotected { .. }
            | Self::KeyringUnusable { .. }
            | Self::Inaccessible { .. } => true,
        }
    }
}

/// Aggregated report data for `omamori report` output.
///
/// JSON output has 8 fields per SEC-R2:
/// period_days, actual_window_days, total_blocks, by_layer, by_provider,
/// by_rule, chain_status, unknown_tool_fail_opens
/// #471: `#[non_exhaustive]`, matching `VerifyResult`, `ChainStatus`,
/// `AuditError`, `RotationResult` and (in the PR before this one)
/// `AuditSummary`. This change adds a field, and a `pub` struct with `pub`
/// fields cannot gain one without breaking every struct literal outside the
/// crate. Zero known reverse dependencies on crates.io, re-measured for this
/// change rather than inherited from the earlier ones.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ReportAggregate {
    pub period_days: u32,
    pub actual_window_days: u32,
    pub total_blocks: u64,
    pub by_layer: HashMap<String, u64>,
    pub by_provider: HashMap<String, u64>,
    pub by_rule: HashMap<String, u64>,
    pub chain_status: ChainStatus,
    pub unknown_tool_fail_opens: u64,
    /// True when the audit high-water-mark sidecar was unreadable or
    /// symlinked (tamper evidence) rather than genuinely absent. Not part
    /// of the JSON output (SEC-R2: exactly 8 fields) — for `doctor`'s
    /// internal use only, reusing the `verify_chain()` call already made
    /// below instead of re-reading the HWM file a second time.
    #[serde(skip)]
    pub hwm_tampered: bool,
    /// #471 item 3: non-fatal keyring problems `verify_chain` reports and
    /// nothing else used to read — a truncated ring, or a file shaped like a
    /// retired key that could not be read. Verification still ran, so
    /// `chain_status` may well be `Intact`; what is incomplete is the coverage,
    /// and a shorter key set that verifies fewer entries looks identical to a
    /// complete one unless it is said out loud.
    ///
    /// Not part of the JSON output (SEC-R2: exactly 8 fields), same as
    /// `hwm_tampered` — and for a second reason here, since these strings carry
    /// paths.
    #[serde(skip)]
    pub keyring_warnings: Vec<String>,
    /// #506: the key material could not be used at all, **and** `chain_status`
    /// is carrying something else.
    ///
    /// `chain_status` holds one value, and exactly one other finding can be
    /// true at the same time as this one: a truncated tail. That pair is the
    /// whole point of #506 — making the key unreadable is precisely how an
    /// attacker used to get a deleted tail reported as "cannot verify" and
    /// nothing more — so the two must not compete for the slot. Truncation
    /// wins it, because it is the finding that was being hidden, and the key
    /// failure travels here.
    ///
    /// `None` when the failure *is* the `chain_status` (see
    /// `chain_status_for_key_store_failure`), so a surface can print this
    /// unconditionally without printing the same fault twice.
    ///
    /// Not part of the JSON output (SEC-R2: exactly 8 fields), same as the two
    /// fields above, and its `reason` carries the key directory's path.
    #[serde(skip)]
    pub key_store_failure: Option<KeyStoreFailure>,
    /// #483: entries omamori wrote with no HMAC, which the walk stepped over
    /// rather than halting on.
    ///
    /// `chain_status` is deliberately left alone. The links really are intact —
    /// their positions and `prev_hash` values were checked, and neither needs a
    /// key — and saying otherwise would be its own false statement. What is
    /// incomplete is the *coverage*, which is the same distinction
    /// `keyring_warnings` draws and the reason it also travels beside the status
    /// rather than inside it.
    ///
    /// Not part of the JSON output (SEC-R2: exactly 8 fields).
    #[serde(skip)]
    pub never_protected_entries: u64,
    /// #461: what a prune recorded about the entries it removed.
    ///
    /// `chain_status` is left alone for the same reason `never_protected_entries`
    /// above leaves it alone, and the reason is sharper here: this is a statement
    /// about a range that is *gone*. The links that remain really are intact, and
    /// the entries the record counts were removed by a prune that was entitled to
    /// remove them. What the operator needs to know is that the log once held
    /// something the verifier could not check — a fact about its history, not its
    /// current state, and `chain_status` answers the latter.
    ///
    /// Not part of the JSON output (SEC-R2: exactly 8 fields), same as the fields
    /// above. Unlike `keyring_warnings` and `key_store_failure` it carries no
    /// path — it is counts only — so the reason here is SEC-R2 alone. Widening
    /// that limit is its own decision and is tracked separately.
    #[serde(skip)]
    pub pruned_findings: Option<PrunedFindings>,
}

impl Default for ReportAggregate {
    fn default() -> Self {
        Self {
            period_days: 0,
            actual_window_days: 0,
            total_blocks: 0,
            by_layer: HashMap::new(),
            by_provider: HashMap::new(),
            by_rule: HashMap::new(),
            chain_status: ChainStatus::Unavailable,
            unknown_tool_fail_opens: 0,
            hwm_tampered: false,
            keyring_warnings: Vec::new(),
            key_store_failure: None,
            never_protected_entries: 0,
            pruned_findings: None,
        }
    }
}

/// The `ChainStatus` a store-level key failure maps to.
///
/// #506: these five states used to arrive as `AuditError`s, and this reproduces
/// the mapping `chain_status_for_error` gave them — deliberately. A given store
/// must report the same `chain_status` and the same `kind` after this change as
/// before it; what moved is only that the walk now gets far enough to *also*
/// notice a missing tail. The one value that does change is
/// `epoch_record_unreadable`, which used to be flattened into
/// `directory_unreadable` because the error carried no way to tell them apart.
///
/// The two families are told apart by asking the failure, not by matching its
/// `kind` string here: see `KeyStoreFailure::is_keyring_level`.
fn chain_status_for_key_store_failure(failure: &KeyStoreFailure) -> ChainStatus {
    if failure.is_keyring_level() {
        ChainStatus::KeyringUnusable {
            reason: failure.reason.clone(),
            kind: failure.kind,
        }
    } else {
        ChainStatus::Inaccessible {
            reason: failure.reason.clone(),
            kind: failure.kind,
        }
    }
}

/// How a `verify_chain` failure becomes a `ChainStatus`.
///
/// #471/#487: extracted so the mapping can be *tested*. The version inlined in
/// `aggregate_report` could not be: every arm but the two quiet ones needs a
/// store in a specific broken state to reach through `verify_chain`, and the
/// catch-all needs a variant `verify_chain` no longer produces at all. A
/// falsification probe that reverted the catch-all to `Unavailable` took down
/// no test — the thesis of this change was the one part of it nothing measured.
///
/// **The catch-all is inverted.** It used to be `Err(_) => Unavailable`, so
/// every failure this function did not name was reported as healthy — the
/// default for a security tool pointing the wrong way. Only the two errors that
/// genuinely mean "there is nothing to check yet" stay quiet, and they are
/// named; anything else, including a variant added later, is loud.
fn chain_status_for_error(e: AuditError) -> ChainStatus {
    match e {
        // Quiet, and the only two: a log that has not been written, and a store
        // whose first key has not been minted.
        AuditError::FileNotFound | AuditError::SecretUnavailable => ChainStatus::Unavailable,
        AuditError::StoreInaccessible { kind, reason } => {
            ChainStatus::Inaccessible { reason, kind }
        }
        // #457: an unusable keyring is not the same as "no audit log" —
        // mapping it to `Unavailable` would hide it from doctor's risk signals.
        AuditError::KeyringUnusable { reason, .. } => ChainStatus::KeyringUnusable {
            reason,
            // Still one kind, but no longer one producer: #477 added
            // `rotate_key`, which returns the raw scan reason rather than a
            // `KeyringAnomaly`. It does not reach here — `aggregate_report`
            // maps only `verify_chain`'s result — and both producers describe
            // the same condition, so a second kind would split a distinction
            // `--json` consumers cannot act on. Said out loud because this
            // field exists to be stable, and "one producer" was the reason
            // given for it being safe.
            kind: "directory_unreadable",
        },
        // `unclassified`, not `io`: this arm exists for variants that do not
        // exist yet, and naming them after one cause would tell a `--json`
        // consumer something specific and wrong (review).
        other => ChainStatus::Inaccessible {
            reason: other.to_string(),
            kind: "unclassified",
        },
    }
}

/// Aggregate audit events within the given time window.
///
/// Returns a default (zeros + Unavailable) on any read/parse failure.
/// This is a UX surface, not a security gate — doctor/report must never
/// error out because the audit log happened to be unreadable.
///
/// # Arguments
/// * `config` - Audit configuration (path, retention, enabled)
/// * `days` - Requested period in days (1-90 per SEC-R4)
///
/// # Security
/// - Uses `open_read_nofollow` (SEC-R10)
/// - Shares reader with verify_chain (SEC-R11)
pub fn aggregate_report(config: &AuditConfig, days: u32) -> ReportAggregate {
    let mut result = ReportAggregate {
        period_days: days,
        actual_window_days: days,
        ..Default::default()
    };

    if !config.enabled {
        return result;
    }

    let path = resolved_audit_path(config);

    // Chain status via existing verify_chain (SEC-R11: shared reader)
    let mut keyring_warnings = Vec::new();
    result.chain_status = match verify_chain(config) {
        Ok(verify_result) => {
            // #491: `hwm_unusable` replaced the bool this reads. Both states it
            // now covers were already folded into the old flag, so what `doctor`
            // is told does not move — and `doctor`'s own wording ("unreadable or
            // tampered") was already the honest disjunction, which is why it is
            // the one surface this change leaves alone.
            result.hwm_tampered = verify_result.hwm_unusable.is_some();
            // #483: unconditional, unlike `key_store_failure` below. It never
            // competes for the `chain_status` slot — an unprotected entry does
            // not stop the walk, so the status is whatever the links turned out
            // to be — so there is no arm for it to be redundant with.
            result.never_protected_entries = verify_result.never_protected_entries;
            // #461: unconditional for the same reason as the line above — a
            // pruned range's findings never compete for the `chain_status`
            // slot, since they say nothing about the links that are still
            // here.
            result.pruned_findings = verify_result.pruned_findings;
            keyring_warnings = verify_result.keyring_warnings.clone();
            // #470: `Truncated` is checked *above* the two halted states, not
            // below them. It used to sit last, which was invisible while
            // `verify_chain` suppressed the comparison during a halt — the two
            // could not both be set — and became load-bearing the moment it
            // stopped doing so. The order here has to match
            // `run_audit_verify`'s exit branch and, through `chain_status`,
            // what `doctor` prints: a verdict that changes with which surface
            // you look at is worse than either verdict.
            //
            // Nothing moves for a log that did not halt. `Unverifiable` and
            // `KeyUnavailable` are both `None` there, so `Truncated` was
            // already the next arm reached.
            if let Some(at_seq) = verify_result.broken_at {
                ChainStatus::Broken { at_seq }
            } else if verify_result.tail_truncated {
                // #506: truncation takes the slot, and a store-level key
                // failure — if there is one — travels beside it in
                // `key_store_failure`. The pair is not hypothetical: making the
                // key material unreadable is precisely how a deleted tail used
                // to come out as "cannot verify" and nothing more, so reporting
                // only one of the two findings would leave that substitution
                // half-working. This is the only arm that can be reached with a
                // key failure also set — the three below all require an entry
                // to have been read and classified, which cannot happen once
                // the walk is tallying every line.
                result.key_store_failure = verify_result.key_store_failure.clone();
                ChainStatus::Truncated
            } else if let (Some(at_seq), Some(chain_version)) = (
                verify_result.unknown_version_at,
                verify_result.unknown_chain_version,
            ) {
                ChainStatus::Unverifiable {
                    at_seq,
                    chain_version,
                }
            } else if let (Some(at_seq), Some(key_id)) = (
                verify_result.key_unavailable_at,
                verify_result.key_unavailable_id.clone(),
            ) {
                ChainStatus::KeyUnavailable { at_seq, key_id }
            } else if let Some(failure) = &verify_result.key_store_failure {
                // Above `Intact`, and that placement is the whole of the
                // regression this change had to avoid. An unusable key store
                // used to be an `Err`, so it could not reach `Ok` at all; with
                // the walk continuing, a store with an empty log and an
                // unlistable key directory now completes with nothing set —
                // zero entries, no halt point, no break — and would land on
                // `Intact`. `doctor` says nothing for `Intact`. Today it says
                // "cannot verify — cannot list …", and loud → silent is the
                // worst regression an audit tool can ship.
                chain_status_for_key_store_failure(failure)
            } else if verify_result.never_protected_entries > 0 {
                // Took the slot, so the parallel field is cleared — a surface
                // that prints both would report one fault twice.
                result.never_protected_entries = 0;
                ChainStatus::Unprotected {
                    entries: verify_result.never_protected_entries,
                }
            } else {
                ChainStatus::Intact
            }
        }
        Err(e) => chain_status_for_error(e),
    };
    // #471 item 3: `keyring_warnings` was built by `verify_chain` and read by
    // nobody. On a store where one retired key is unreadable but the entries it
    // signed are already pruned, `verify` printed a warning while `doctor` said
    // `quiet` and `report` said `intact` — and the two surfaces an operator
    // watches habitually are the ones that stayed silent. A damaged key file is
    // most useful to know about *before* it is needed.
    //
    // `chain_status` is deliberately left alone: the chain really is intact
    // there, and saying otherwise would be its own false statement. This
    // travels beside it, the way `hwm_tampered` already does.
    result.keyring_warnings = keyring_warnings;

    // Retention caveat: actual window may be smaller than requested
    if config.retention_days > 0 && config.retention_days < days {
        result.actual_window_days = config.retention_days;
    }

    // Aggregate events (no-op when HOME is unusable and no explicit path is set)
    if let Some(stats) = path.as_deref().and_then(|p| aggregate_events(p, days)) {
        result.total_blocks = stats.total_blocks;
        result.by_layer = stats.by_layer;
        result.by_provider = stats.by_provider;
        result.by_rule = stats.by_rule;
        result.unknown_tool_fail_opens = stats.unknown_tool_fail_opens;

        // Refine actual_window_days based on oldest event in window
        if let Some(oldest_days) = stats.oldest_event_days
            && oldest_days < result.actual_window_days
        {
            result.actual_window_days = oldest_days;
        }
    }

    result
}

struct EventStats {
    total_blocks: u64,
    by_layer: HashMap<String, u64>,
    by_provider: HashMap<String, u64>,
    by_rule: HashMap<String, u64>,
    unknown_tool_fail_opens: u64,
    oldest_event_days: Option<u32>,
}

fn aggregate_events(path: &Path, days: u32) -> Option<EventStats> {
    let file = open_read_nofollow(path).ok()?;
    let reader = std::io::BufReader::new(file);

    let now = OffsetDateTime::now_utc();
    let cutoff = now - time::Duration::days(i64::from(days));

    let mut stats = EventStats {
        total_blocks: 0,
        by_layer: HashMap::new(),
        by_provider: HashMap::new(),
        by_rule: HashMap::new(),
        unknown_tool_fail_opens: 0,
        oldest_event_days: None,
    };

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let ts = match OffsetDateTime::parse(&event.timestamp, &Rfc3339) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if ts < cutoff {
            continue;
        }

        // Track oldest event for actual_window_days calculation
        let event_age_days = ((now - ts).whole_days().max(0) as u32).saturating_add(1);
        match stats.oldest_event_days {
            None => stats.oldest_event_days = Some(event_age_days),
            Some(oldest) if event_age_days > oldest => {
                stats.oldest_event_days = Some(event_age_days);
            }
            _ => {}
        }

        // Count unknown_tool_fail_open
        if event.action == "unknown_tool_fail_open" {
            stats.unknown_tool_fail_opens += 1;
            continue;
        }

        // Count blocks (action = "block", written by rules.rs Block variant)
        if event.action == "block" {
            stats.total_blocks += 1;

            // by_layer: classify detection_layer into 3 buckets
            let layer_bucket = classify_layer(event.detection_layer.as_deref());
            *stats.by_layer.entry(layer_bucket).or_insert(0) += 1;

            // by_provider: aggregate by provider field (SEC-R1)
            let provider = if event.provider.is_empty() {
                "none".to_string()
            } else {
                event.provider.clone()
            };
            *stats.by_provider.entry(provider).or_insert(0) += 1;

            // by_rule: aggregate by rule_id
            let rule = event.rule_id.as_deref().unwrap_or("unknown").to_string();
            *stats.by_rule.entry(rule).or_insert(0) += 1;
        }
    }

    Some(stats)
}

/// Classify detection_layer into 3 buckets for by_layer aggregation.
///
/// - "layer1" → "layer1"
/// - "layer2:*" (any variant) → "layer2"
/// - "shape-routing" → "shape-routing"
/// - None / unknown → "unclassified" (qa V-010)
fn classify_layer(detection_layer: Option<&str>) -> String {
    match detection_layer {
        Some("layer1") => "layer1".to_string(),
        Some(dl) if dl == "layer2" || dl.starts_with("layer2:") => "layer2".to_string(),
        Some("shape-routing") => "shape-routing".to_string(),
        Some(dl) => dl.to_string(), // preserve unknown values
        None => "unclassified".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogger;

    #[test]
    fn test_classify_layer() {
        assert_eq!(classify_layer(Some("layer1")), "layer1");
        assert_eq!(classify_layer(Some("layer2:rule")), "layer2");
        assert_eq!(classify_layer(Some("layer2:meta-pattern")), "layer2");
        assert_eq!(classify_layer(Some("layer2:pipe-to-shell:sudo")), "layer2");
        assert_eq!(classify_layer(Some("layer2:structural")), "layer2");
        assert_eq!(classify_layer(Some("layer2")), "layer2");
        assert_eq!(classify_layer(Some("shape-routing")), "shape-routing");
        assert_eq!(classify_layer(None), "unclassified");
    }

    #[test]
    fn test_classify_layer_rejects_false_prefixes() {
        assert_eq!(classify_layer(Some("layer20")), "layer20");
        assert_eq!(classify_layer(Some("layer2evil")), "layer2evil");
        assert_eq!(classify_layer(Some("layer2/")), "layer2/");
        assert_eq!(classify_layer(Some("layer3")), "layer3");
    }

    /// #471/#487: the inversion itself, which nothing else measures.
    ///
    /// Every loud state reachable through `verify_chain` needs a store broken a
    /// particular way, so the fixtures covering them all land on named arms.
    /// The catch-all is reached only by a variant `verify_chain` does not
    /// produce — and a falsification probe that reverted it to `Unavailable`
    /// took no test down. Feeding the mapping directly is what makes the
    /// default checkable.
    #[test]
    fn every_failure_but_the_two_quiet_ones_needs_attention() {
        // Quiet, and exhaustively so: nothing has been written yet.
        for quiet in [AuditError::FileNotFound, AuditError::SecretUnavailable] {
            let status = chain_status_for_error(quiet);
            assert_eq!(status, ChainStatus::Unavailable);
            assert!(!status.needs_attention(), "got {status:?}");
        }

        // Loud, including the two the catch-all exists for.
        // `RotationInterrupted` is produced by `rotate_key` today and `Io` by
        // nothing in `verify_chain` since this change — which is the point: the
        // default a future failure inherits has to be the loud one.
        for loud in [
            AuditError::StoreInaccessible {
                kind: "log_symlink",
                reason: "symlink (possible attack)".to_string(),
            },
            AuditError::KeyringUnusable {
                reason: "cannot list".to_string(),
                remedy: String::new(),
            },
            AuditError::RotationInterrupted {
                retired_path: std::path::PathBuf::from("/tmp/audit-secret.1.retired"),
                source: std::io::Error::other("no space"),
            },
            AuditError::Io(std::io::Error::other("read failed")),
        ] {
            let status = chain_status_for_error(loud);
            assert!(
                status.needs_attention(),
                "a failure that is not one of the two quiet ones must reach the operator — \
                 got {status:?}"
            );
        }
    }

    #[test]
    fn test_chain_status_as_str() {
        assert_eq!(ChainStatus::Intact.as_str(), "intact");
        assert_eq!(ChainStatus::Broken { at_seq: 42 }.as_str(), "broken");
        assert_eq!(ChainStatus::Truncated.as_str(), "truncated");
        assert_eq!(ChainStatus::Unavailable.as_str(), "unavailable");
        // #457: distinct from "broken" on purpose — a missing key file is not
        // an allegation of tampering, and consumers keying on this string must
        // be able to tell the two apart.
        assert_eq!(
            ChainStatus::KeyUnavailable {
                at_seq: 7,
                key_id: "key-3".to_string(),
            }
            .as_str(),
            "key_unavailable"
        );
    }

    /// #457 (Codex Round 1 P3). The JSON shape of a new public variant is part
    /// of the `omamori report --json` surface, so it gets the same coverage the
    /// older variants have: `at_seq` stays internal (`skip_serializing`), the
    /// key id does not.
    #[test]
    fn key_unavailable_serializes_without_leaking_seq() {
        let value = serde_json::to_value(ChainStatus::KeyUnavailable {
            at_seq: 7,
            key_id: "key-3".to_string(),
        })
        .unwrap();
        assert_eq!(value["status"], "key_unavailable");
        assert_eq!(value["key_id"], "key-3");
        assert!(
            value.get("at_seq").is_none(),
            "at_seq is skip_serializing, matching Broken/Unverifiable"
        );
    }

    /// #457 (Codex Round 3 issue proposal, revised in Phase 8). Coverage
    /// symmetry with the variant above. The reason carries the key
    /// directory's absolute path — which includes the operator's home
    /// directory — so it must stay out of the JSON exactly as `at_seq` does,
    /// and the reason-free `kind` is what machine consumers get instead.
    /// The first version of this test asserted the opposite (`value["reason"]
    /// == "cannot list /x: …"`); it passed, and pinned the leak.
    #[test]
    fn keyring_unusable_serializes_its_kind_and_not_the_path() {
        let value = serde_json::to_value(ChainStatus::KeyringUnusable {
            reason: "cannot list /Users/someone/.local/share/omamori: Permission denied"
                .to_string(),
            kind: "directory_unreadable",
        })
        .unwrap();
        assert_eq!(value["status"], "keyring_unusable");
        assert_eq!(value["kind"], "directory_unreadable");
        assert!(
            value.get("reason").is_none(),
            "reason is skip_serializing — it embeds the key directory's path"
        );
        assert!(
            !serde_json::to_string(&value).unwrap().contains("someone"),
            "no part of the home path may reach the JSON surface"
        );
        assert_eq!(
            ChainStatus::KeyringUnusable {
                reason: String::new(),
                kind: "directory_unreadable",
            }
            .as_str(),
            "keyring_unusable"
        );
    }

    #[test]
    fn test_default_report_aggregate() {
        let report = ReportAggregate::default();
        assert_eq!(report.period_days, 0);
        assert_eq!(report.total_blocks, 0);
        assert!(report.by_layer.is_empty());
        assert!(report.by_provider.is_empty());
        assert!(report.by_rule.is_empty());
        assert_eq!(report.chain_status, ChainStatus::Unavailable);
    }

    fn make_event_line(
        action: &str,
        provider: &str,
        detection_layer: Option<&str>,
        minutes_ago: i64,
    ) -> String {
        let ts = OffsetDateTime::now_utc() - time::Duration::minutes(minutes_ago);
        let ts_str = ts.format(&Rfc3339).unwrap();
        let dl = match detection_layer {
            Some(v) => format!("\"{v}\""),
            None => "null".to_string(),
        };
        format!(
            r#"{{"timestamp":"{ts_str}","provider":"{provider}","command":"test","rule_id":null,"action":"{action}","result":"done","target_count":0,"target_hash":"","detection_layer":{dl}}}"#,
        )
    }

    fn make_event_line_with_rule(
        action: &str,
        provider: &str,
        detection_layer: Option<&str>,
        rule_id: Option<&str>,
        minutes_ago: i64,
    ) -> String {
        let ts = OffsetDateTime::now_utc() - time::Duration::minutes(minutes_ago);
        let ts_str = ts.format(&Rfc3339).unwrap();
        let dl = match detection_layer {
            Some(v) => format!("\"{v}\""),
            None => "null".to_string(),
        };
        let rid = match rule_id {
            Some(v) => format!("\"{v}\""),
            None => "null".to_string(),
        };
        format!(
            r#"{{"timestamp":"{ts_str}","provider":"{provider}","command":"test","rule_id":{rid},"action":"{action}","result":"done","target_count":0,"target_hash":"","detection_layer":{dl}}}"#,
        )
    }

    fn write_temp_audit(lines: &[String], tag: &str) -> std::path::PathBuf {
        // `temp_dir()`, not ambient `$HOME`: this file also carries a test
        // that mutates the process-global `HOME` env var (tagged
        // `serial(home_env)`), and reading `HOME` here without the same
        // tag would race it (#344-class flake).
        let path =
            std::env::temp_dir().join(format!("omamori-test-{}-{tag}.jsonl", std::process::id()));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    #[test]
    fn test_action_block_counted_deny_ignored() {
        let lines = vec![
            make_event_line("block", "claude-code", Some("layer1"), 10),
            make_event_line("block", "claude-code", Some("layer2:rule"), 20),
            make_event_line("deny", "claude-code", Some("layer1"), 30),
            make_event_line("allow", "claude-code", Some("layer1"), 40),
        ];
        let path = write_temp_audit(&lines, "action");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 2);
        assert_eq!(*stats.by_layer.get("layer1").unwrap_or(&0), 1);
        assert_eq!(*stats.by_layer.get("layer2").unwrap_or(&0), 1);
    }

    #[test]
    fn test_empty_provider_mapped_to_none() {
        let lines = vec![make_event_line("block", "", Some("layer1"), 10)];
        let path = write_temp_audit(&lines, "provider");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 1);
        assert_eq!(*stats.by_provider.get("none").unwrap_or(&0), 1);
        assert!(!stats.by_provider.contains_key(""));
    }

    #[test]
    fn test_unknown_tool_fail_open_isolation() {
        let lines = vec![
            make_event_line("unknown_tool_fail_open", "claude-code", Some("layer1"), 10),
            make_event_line("unknown_tool_fail_open", "codex", None, 20),
            make_event_line("block", "claude-code", Some("layer1"), 30),
        ];
        let path = write_temp_audit(&lines, "unknown");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.unknown_tool_fail_opens, 2);
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.by_layer.len(), 1);
        assert_eq!(stats.by_provider.len(), 1);
    }

    #[test]
    fn test_events_outside_window_excluded() {
        let lines = vec![
            make_event_line("block", "claude-code", Some("layer1"), 10),
            make_event_line("block", "claude-code", Some("layer1"), 60 * 24 * 8),
        ];
        let path = write_temp_audit(&lines, "window");
        let stats = aggregate_events(&path, 7).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 1);
    }

    #[test]
    fn test_by_rule_aggregation() {
        let lines = vec![
            make_event_line_with_rule("block", "claude-code", Some("layer1"), Some("rm-rf"), 10),
            make_event_line_with_rule("block", "claude-code", Some("layer1"), Some("rm-rf"), 20),
            make_event_line_with_rule(
                "block",
                "claude-code",
                Some("layer2:rule"),
                Some("mv-slash"),
                30,
            ),
        ];
        let path = write_temp_audit(&lines, "by-rule");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 3);
        assert_eq!(*stats.by_rule.get("rm-rf").unwrap_or(&0), 2);
        assert_eq!(*stats.by_rule.get("mv-slash").unwrap_or(&0), 1);
    }

    #[test]
    fn test_by_rule_none_maps_to_unknown() {
        let lines = vec![make_event_line("block", "claude-code", Some("layer1"), 10)];
        let path = write_temp_audit(&lines, "by-rule-none");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(*stats.by_rule.get("unknown").unwrap_or(&0), 1);
        assert!(!stats.by_rule.contains_key(""));
    }

    /// #177 B1 step 2: an entry declaring a `chain_version` this binary
    /// doesn't recognize must surface as `ChainStatus::Unverifiable`, not
    /// silently fold into `Broken` (tamper) or `Intact` (fine) — both are
    /// wrong, and `Broken` in particular would misreport "you've been
    /// tampered with" for what may just be "upgrade omamori."
    #[test]
    fn test_aggregate_report_surfaces_unverifiable_chain_version() {
        let dir = std::env::temp_dir().join(format!(
            "omamori-report-unverifiable-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config_for_test(&config).expect("audit enabled");
        logger
            .append(AuditEvent {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                provider: "test".to_string(),
                command: "cmd0".to_string(),
                rule_id: None,
                action: "block".to_string(),
                result: "blocked".to_string(),
                target_count: 1,
                target_hash: String::new(),
                detection_layer: None,
                unwrap_chain: None,
                raw_input_hash: None,
                chain_version: None,
                seq: None,
                prev_hash: None,
                key_id: None,
                entry_hash: None,
                pid: None,
                ppid: None,
                parent_process: None,
                cwd_hash: None,
                wrapper_kind: None,
            })
            .unwrap();

        // Hand-append an entry from an imagined future omamori version.
        // entry_hash/prev_hash content is inert: the verifier's version
        // dispatch fires before it ever reads those fields for a
        // chain_version it doesn't recognize.
        let future_entry = serde_json::json!({
            "timestamp": "2026-01-01T00:00:01Z",
            "provider": "test",
            "command": "cmd1",
            "action": "block",
            "result": "blocked",
            "target_count": 1,
            "target_hash": "",
            "chain_version": 999,
            "seq": 1,
            "prev_hash": "irrelevant",
            "key_id": "default",
            "entry_hash": "irrelevant",
        });
        let mut content = std::fs::read_to_string(&audit_path).unwrap();
        content.push_str(&serde_json::to_string(&future_entry).unwrap());
        content.push('\n');
        std::fs::write(&audit_path, content).unwrap();

        let report = aggregate_report(&config, 7);
        match report.chain_status {
            ChainStatus::Unverifiable {
                at_seq,
                chain_version,
            } => {
                assert_eq!(at_seq, 1);
                assert_eq!(chain_version, 999);
            }
            other => panic!("expected ChainStatus::Unverifiable, got {other:?}"),
        }
        assert_eq!(report.chain_status.as_str(), "unverifiable");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_aggregate_report_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let report = aggregate_report(&config, 7);
        assert_eq!(report.period_days, 7);
        assert_eq!(report.total_blocks, 0);
        assert_eq!(report.chain_status, ChainStatus::Unavailable);
    }

    /// `hwm_tampered` must be threaded through from the same `verify_chain()`
    /// call `chain_status` already comes from — no second read of the HWM
    /// file (this is what `doctor` relies on instead of a standalone check).
    #[test]
    fn test_aggregate_report_surfaces_hwm_tampered() {
        use super::super::{hwm_path_for, write_hwm};

        let dir = std::env::temp_dir().join(format!(
            "omamori-report-hwm-tampered-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        // No audit log / HWM yet: not tampered.
        let report = aggregate_report(&config, 7);
        assert!(!report.hwm_tampered);

        // Append one entry so verify_chain() has a chain to walk, then
        // corrupt the HWM the same way append() would have written it.
        let logger = AuditLogger::from_config_for_test(&config).expect("audit enabled");
        logger
            .append(AuditEvent {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                provider: "test".to_string(),
                command: "cmd0".to_string(),
                rule_id: None,
                action: "block".to_string(),
                result: "blocked".to_string(),
                target_count: 1,
                target_hash: String::new(),
                detection_layer: None,
                unwrap_chain: None,
                raw_input_hash: None,
                chain_version: None,
                seq: None,
                prev_hash: None,
                key_id: None,
                entry_hash: None,
                pid: None,
                ppid: None,
                parent_process: None,
                cwd_hash: None,
                wrapper_kind: None,
            })
            .unwrap();
        let hwm_file = hwm_path_for(&audit_path);
        write_hwm(&hwm_file, 0).unwrap();
        std::fs::write(&hwm_file, "not-a-number").unwrap();

        let report = aggregate_report(&config, 7);
        assert!(
            report.hwm_tampered,
            "tampered HWM must surface on ReportAggregate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn aggregate_report_degrades_gracefully_when_home_unusable() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let report = crate::test_support::with_home(Some(""), || aggregate_report(&config, 7));

        assert_eq!(report.total_blocks, 0, "no path to read events from");
        // #471: this used to assert `Unavailable`, i.e. quiet. An audit path
        // that cannot be resolved is a configuration fault — `status` has
        // always reported it as one — and it shared a variant with "there is no
        // log yet", so the louder of the two inherited the quieter one's
        // verdict. "Degrades gracefully" means it does not panic and reports
        // zero blocks, which the assertion above still pins; it does not mean
        // the operator hears nothing.
        assert_eq!(
            report.chain_status,
            ChainStatus::Inaccessible {
                reason: "HOME is unset, empty, or relative — cannot resolve audit path".to_string(),
                kind: "path_unresolved",
            }
        );
        assert!(report.chain_status.needs_attention());
    }
}
