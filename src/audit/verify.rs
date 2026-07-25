//! Audit chain verification, entry display, and summary for CLI commands.

use std::io::{BufRead, Write};

use super::chain::{
    CHAIN_VERSION, RecomputedHash, compute_entry_hash, genesis_hash, hmac_bytes, prune_genesis_hash,
};
use super::retention::is_prune_point;
use super::secret::{flock_shared, load_keyring, open_read_nofollow, read_secret, secret_path_for};
use super::{AuditConfig, AuditEvent, resolved_audit_path};
use super::{HwmState, hwm_path_for, read_hwm, write_hwm};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AuditError {
    SecretUnavailable,
    FileNotFound,
    Io(std::io::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretUnavailable => write!(f, "HMAC secret unavailable"),
            Self::FileNotFound => write!(f, "audit log not found"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

pub struct VerifyResult {
    pub chain_entries: u64,
    pub legacy_entries: u64,
    pub torn_lines: u64,
    pub broken_at: Option<u64>,
    pub pruned: bool,
    pub pruned_count: Option<u64>,
    pub tail_truncated: bool,
    pub hwm_missing: bool,
    pub hwm_tampered: bool,
    /// #177 B1 step 2: seq of the first entry whose `chain_version` this
    /// binary doesn't recognize. `None` means every entry encountered was
    /// either verifiable or legacy. Distinct from `broken_at` — this is not
    /// evidence of tampering, it's evidence the binary predates the chain
    /// format (or, less likely, that a downgrade happened after a newer
    /// entry was written).
    pub unknown_version_at: Option<u64>,
    /// The unsupported `chain_version` value found at `unknown_version_at`.
    pub unknown_chain_version: Option<u32>,
    /// Count of lines from `unknown_version_at` onward (inclusive) that
    /// could not be verified — once one entry's authenticity can't be
    /// confirmed, the `prev_hash` chain running through it means nothing
    /// after it can be trusted either, regardless of what those later
    /// lines individually claim.
    pub unverified_entries_after: u64,
}

pub struct ShowOptions {
    pub last: Option<usize>,
    pub rule: Option<String>,
    pub provider: Option<String>,
    pub json: bool,
    /// PR6 (#182): exact-match filter on `action`. Used by
    /// `omamori audit unknown` to surface the `unknown_tool_fail_open`
    /// events the hook layer records when a tool drifts past
    /// shape-based routing.
    pub action: Option<String>,
    /// PR1d (v0.10.3+, #240): when true, only entries whose
    /// `detection_layer` starts with `"layer2:relaxed:"` are shown.
    /// Used by `omamori audit show --relaxed` to forensically review
    /// commands that the data-context residual backstop allowed
    /// (DI-16 audit-relaxed-tag invariant).
    pub relaxed_only: bool,
}

pub struct AuditSummary {
    pub enabled: bool,
    pub entry_count: u64,
    pub secret_available: bool,
    pub retention_days: u32,
    pub path_error: Option<String>,
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

/// Records the point where an entry's `chain_version` became unverifiable
/// and switches `result` into its terminal "unverifiable tail" state —
/// `result.unknown_version_at.is_some()` *is* that state; the main loop
/// checks it directly rather than tracking a separate local flag that
/// could drift out of sync with it. Shared by both places `verify_chain`
/// can discover this — the fast path (a successfully-parsed `AuditEvent`
/// whose `chain_version` field is unsupported) and the raw-JSON fallback
/// (an entry whose *shape* a future `chain_version` changed enough that
/// `AuditEvent` can't even parse it).
fn mark_unverifiable_tail(result: &mut VerifyResult, seq: u64, chain_version: u32) {
    result.unknown_version_at = Some(seq);
    result.unknown_chain_version = Some(chain_version);
    result.unverified_entries_after = 1;
}

/// Minimal typed peek for the raw-JSON fallback (an entry whose full
/// `AuditEvent` parse already failed). Any JSON key not named here —
/// including an attacker-controlled arbitrarily large one — is skipped by
/// serde during deserialization rather than allocated, unlike a
/// `serde_json::Value` peek of the same line (see the fallback's comment
/// for the measured cost of that). Both fields are `Option` so a missing
/// or wrong-shaped `seq` degrades to the `expected_seq` fallback rather
/// than failing the whole peek — a type-mismatched `chain_version`
/// (rather than missing) still fails the peek, same as a
/// `serde_json::Value` peek would have failed to extract a `u32` from it.
#[derive(serde::Deserialize)]
struct ChainVersionSeqPeek {
    chain_version: Option<u32>,
    seq: Option<u64>,
}

pub fn verify_chain(config: &AuditConfig) -> Result<VerifyResult, AuditError> {
    let path = resolved_audit_path(config).ok_or(AuditError::FileNotFound)?;
    let secret_path = secret_path_for(&path);

    // Primary secret for genesis hash computation (always the active key).
    // Read before keyring to preserve ELOOP (symlink attack) error distinction.
    let secret = read_secret(&secret_path).map_err(|e| {
        if e.to_string().contains("symlink") {
            return AuditError::Io(e);
        }
        AuditError::SecretUnavailable
    })?;

    // Load keyring for multi-key verification (active + retired keys)
    let keyring = load_keyring(&secret_path);

    let file = open_read_nofollow(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::FileNotFound,
        _ => AuditError::Io(e),
    })?;
    flock_shared(&file)?;

    let reader = std::io::BufReader::new(&file);
    let genesis = genesis_hash(Some(&secret));
    let prune_genesis = prune_genesis_hash(Some(&secret));

    let mut result = VerifyResult {
        chain_entries: 0,
        legacy_entries: 0,
        torn_lines: 0,
        broken_at: None,
        pruned: false,
        pruned_count: None,
        tail_truncated: false,
        hwm_missing: false,
        hwm_tampered: false,
        unknown_version_at: None,
        unknown_chain_version: None,
        unverified_entries_after: 0,
    };
    let mut expected_prev = genesis;
    let mut expected_seq: u64 = 0;
    let mut last_was_prune = false;
    let mut prune_target_hash: Option<String> = None;
    let mut prune_target_count: Option<u64> = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // #177 B1 step 2: once an entry's chain_version can't be
        // authenticated, the prev_hash chain running through it means
        // nothing after it can be trusted either — every remaining line
        // just gets tallied, not verified.
        if result.unknown_version_at.is_some() {
            result.unverified_entries_after += 1;
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                // Codex Round 1 (#177 B1): a future chain_version might pair
                // with a JSON shape this binary's AuditEvent can't
                // deserialize at all. Before assuming genuine corruption
                // (torn line), peek the raw JSON for chain_version — if
                // it's present and unrecognized, this must read as
                // "unverifiable", not "torn". Torn-line handling resumes
                // verification against the pre-entry expected_prev/
                // expected_seq for whatever comes next, which would
                // misreport a real subsequent entry (chaining from this
                // one's unverified hash) as broken_at.
                // Security review (#177 B1): peeking via serde_json::Value here
                // (unlike chain.rs's read_chain_state, whose tail-window read is
                // already capped at 64 KB) materializes a full DOM for whatever
                // this *unbounded* per-line scan reads — measured ~5.7x memory
                // and ~25x CPU amplification on a single hostile ~50MB line vs.
                // the typed AuditEvent parse path it substitutes for. A typed
                // peek struct lets serde skip any field it doesn't name
                // (including large ones) without allocating it.
                if let Ok(peek) = serde_json::from_str::<ChainVersionSeqPeek>(trimmed)
                    && let Some(chain_version) = peek.chain_version
                    && chain_version != CHAIN_VERSION
                {
                    let seq = peek.seq.unwrap_or(expected_seq);
                    mark_unverifiable_tail(&mut result, seq, chain_version);
                    continue;
                }
                result.torn_lines += 1;
                continue;
            }
        };

        if event.chain_version.is_none() {
            // #177 B1 step 4: legacy (no chain_version) entries are only
            // legitimate at the head of the file — genuine pre-#164
            // history that predates chain tracking. A legacy-shaped entry
            // appearing AFTER real chain entries have started is fail-
            // closed, not silently skipped: it's either corruption, or an
            // attacker exploiting the fact that legacy entries never
            // participate in prev_hash/seq continuity tracking to splice
            // unaudited content into the middle of an otherwise-verified
            // chain without breaking the links around it.
            if result.chain_entries > 0 {
                result.broken_at = Some(expected_seq);
                break;
            }
            result.legacy_entries += 1;
            continue;
        }

        let seq = event.seq.unwrap_or(0);
        let prev_hash = event.prev_hash.as_deref().unwrap_or("");
        let recorded_hash = event.entry_hash.as_deref().unwrap_or("");
        let is_prune = is_prune_point(&event);

        // --- entry_hash HMAC verification (multi-key: lookup by key_id).
        // Also the version dispatch point: an entry whose chain_version
        // this binary doesn't recognize can't be authenticated at all, so
        // nothing about it — including its own seq/prev_hash — is
        // trustworthy structural signal. Check this before the prev_hash
        // check below, not after. ---
        let entry_key_id = event.key_id.as_deref().unwrap_or("default");
        let entry_secret = keyring.get(entry_key_id).unwrap_or(&secret);
        let recomputed = match compute_entry_hash(Some(entry_secret), &event) {
            RecomputedHash::Hash(h) => h,
            RecomputedHash::UnsupportedVersion(v) => {
                // Not evidence of tampering — evidence this binary
                // predates the chain format (or a downgrade happened).
                // Stop verifying; everything from here on is tallied,
                // not trusted. Codex Round 1 test-adversarial review:
                // report expected_seq (not the generic `seq` default of
                // 0 above) when this entry's own `seq` field is missing —
                // matches the raw-JSON fallback path below and avoids a
                // misleading "at entry #0" report for an unrecognized-
                // version entry appearing deep in an otherwise-verified
                // chain.
                let reported_seq = event.seq.unwrap_or(expected_seq);
                mark_unverifiable_tail(&mut result, reported_seq, v);
                continue;
            }
            RecomputedHash::Legacy => {
                unreachable!("event.chain_version.is_none() already filtered above")
            }
        };

        // --- prev_hash verification ---
        if result.chain_entries == 0 {
            // First chain entry: genesis or prune_genesis
            let expected = if is_prune {
                &prune_genesis
            } else {
                &expected_prev
            };
            if prev_hash != expected {
                result.broken_at = Some(seq);
                break;
            }
            if is_prune {
                // seq must be 0 for prune_point at head
                if seq != 0 {
                    result.broken_at = Some(seq);
                    break;
                }
            }
        } else if last_was_prune {
            // Prune gap: prev_hash won't match prune_point's entry_hash — allowed.
            // But verify the prune-bind: target_hash must bind this entry's hash.
            // (entry_hash verification below will confirm this entry is authentic)
        } else {
            // Normal chain link
            if seq != expected_seq {
                result.broken_at = Some(seq);
                break;
            }
            if prev_hash != expected_prev {
                result.broken_at = Some(seq);
                break;
            }
        }

        if recomputed != recorded_hash {
            result.broken_at = Some(seq);
            break;
        }

        // --- prune-bind verification (after prune gap, use entry's key) ---
        if last_was_prune
            && let (Some(saved_target), Some(saved_count)) =
                (&prune_target_hash, prune_target_count)
        {
            let expected_bind = hmac_bytes(
                Some(entry_secret),
                format!("prune-bind:{saved_count}:{recorded_hash}").as_bytes(),
            );
            if *saved_target != expected_bind {
                result.broken_at = Some(seq);
                break;
            }
        }

        // Track prune state
        if is_prune {
            result.pruned = true;
            result.pruned_count = Some(event.target_count as u64);
            prune_target_hash = Some(event.target_hash.clone());
            prune_target_count = Some(event.target_count as u64);
        }

        last_was_prune = is_prune;
        expected_prev = recorded_hash.to_string();
        expected_seq = seq + 1;
        result.chain_entries += 1;
    }

    // HWM check: detect tail truncation. Requires having actually reached
    // EOF (#177 B1 step 2) — an early stop on unknown_version_at means
    // expected_seq stopped advancing before the real end of file, so
    // writing/comparing the HWM here would compare against a false "end"
    // and could silently lower the high-water-mark on a later re-verify.
    if result.broken_at.is_none() && result.unknown_version_at.is_none() && result.chain_entries > 0
    {
        let hwm_file = hwm_path_for(&path);
        let max_verified_seq = expected_seq.saturating_sub(1);
        match read_hwm(&hwm_file) {
            HwmState::Valid(hwm) if max_verified_seq < hwm => {
                result.tail_truncated = true;
            }
            HwmState::Valid(_) => {}
            HwmState::Missing => {
                // Bootstrap: first verify on a chain without HWM
                result.hwm_missing = true;
                let _ = write_hwm(&hwm_file, max_verified_seq);
            }
            HwmState::Tampered => {
                // The HWM itself is unreadable or symlinked — this is tamper
                // evidence, not a fresh install. Surface it distinctly instead
                // of silently re-bootstrapping as if nothing happened.
                result.hwm_tampered = true;
                let _ = write_hwm(&hwm_file, max_verified_seq);
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// show_entries
// ---------------------------------------------------------------------------

pub fn show_entries(
    config: &AuditConfig,
    opts: &ShowOptions,
    out: &mut impl Write,
) -> Result<(), AuditError> {
    use std::collections::VecDeque;

    let path = resolved_audit_path(config).ok_or(AuditError::FileNotFound)?;
    let file = open_read_nofollow(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::FileNotFound,
        _ => AuditError::Io(e),
    })?;

    let reader = std::io::BufReader::new(&file);
    let capacity = opts.last.unwrap_or(usize::MAX);
    let mut entries: VecDeque<AuditEvent> = VecDeque::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(ref filter) = opts.rule {
            match &event.rule_id {
                Some(rule) if rule.contains(filter.as_str()) => {}
                _ => continue,
            }
        }
        if opts
            .provider
            .as_ref()
            .is_some_and(|f| !event.provider.contains(f.as_str()))
        {
            continue;
        }
        // PR6 (#182): action is an exact-match filter (not substring)
        // because action labels are a small closed enum; substring
        // would let `--action allow` match the `unknown_tool_fail_open`
        // result label and confuse users.
        if opts.action.as_ref().is_some_and(|f| event.action != *f) {
            continue;
        }
        // PR1d (v0.10.3+, #240): only entries whose `detection_layer`
        // starts with `"layer2:relaxed:"` (DI-16). Surface for
        // forensically reviewing which commands the data-context
        // residual backstop allowed.
        if opts.relaxed_only
            && !event
                .detection_layer
                .as_ref()
                .is_some_and(|s| s.starts_with("layer2:relaxed:"))
        {
            continue;
        }

        entries.push_back(event);
        if entries.len() > capacity {
            entries.pop_front();
        }
    }

    if entries.is_empty() {
        return Ok(());
    }

    if opts.json {
        for event in &entries {
            serde_json::to_writer(&mut *out, event).map_err(std::io::Error::from)?;
            writeln!(out)?;
        }
    } else {
        // COMMAND and ACTION columns were widened in v0.9.7 (#190 B-2).
        // PR6 reused the COMMAND column to carry `tool_name` (e.g. `NotebookEdit`,
        // `FuturePlanWriter`) and the ACTION column to carry `unknown_tool_fail_open`
        // (22 chars), both of which overflowed the original `{:<8}` / `{:<15}` widths
        // and pushed every later column out of alignment. v0.9.7 deny-path additions
        // (#181) similarly carry `block` plus `detection_layer` strings such as
        // `layer2:pipe-to-shell:env`. Widening to 24 / 24 keeps a single shared
        // format function across event classes; a per-class formatter remains an
        // option if a future event class outgrows 24.
        writeln!(
            out,
            "{:<20} {:<12} {:<24} {:<24} {:<8} RULE",
            "TIMESTAMP", "PROVIDER", "COMMAND", "ACTION", "RESULT"
        )?;
        for event in &entries {
            if is_prune_point(event) {
                let ts = display_timestamp(&event.timestamp);
                writeln!(
                    out,
                    "--- pruned {} entries before {ts} ---",
                    event.target_count
                )?;
                continue;
            }
            let rule = event.rule_id.as_deref().unwrap_or("\u{2014}");
            let ts = display_timestamp(&event.timestamp);
            writeln!(
                out,
                "{:<20} {:<12} {:<24} {:<24} {:<8} {rule}",
                ts, event.provider, event.command, event.action, event.result
            )?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// audit_summary
// ---------------------------------------------------------------------------

pub fn audit_summary(config: &AuditConfig) -> AuditSummary {
    if !config.enabled {
        return AuditSummary {
            enabled: false,
            entry_count: 0,
            secret_available: false,
            retention_days: 0,
            path_error: None,
        };
    }

    let Some(path) = resolved_audit_path(config) else {
        return AuditSummary {
            enabled: true,
            entry_count: 0,
            secret_available: false,
            retention_days: config.retention_days,
            path_error: Some(
                "HOME is unset, empty, or relative — cannot resolve audit path".to_string(),
            ),
        };
    };
    let secret_available = read_secret(&secret_path_for(&path)).is_ok();

    let (entry_count, path_error) = match open_read_nofollow(&path) {
        Ok(f) => {
            let count = std::io::BufReader::new(f)
                .lines()
                .filter(|l| l.as_ref().is_ok_and(|s| !s.trim().is_empty()))
                .count() as u64;
            (count, None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, None),
        Err(e) => (0, Some(e.to_string())),
    };

    AuditSummary {
        enabled: true,
        entry_count,
        secret_available,
        retention_days: config.retention_days,
        path_error,
    }
}

// ---------------------------------------------------------------------------
// PR6 (#182): unknown-tool fail-open observability
// ---------------------------------------------------------------------------

/// Count `unknown_tool_fail_open` audit events whose timestamp falls
/// within the last `days` days. Used by `omamori doctor` to surface
/// silent forward-compat fail-opens that drifted past structure-based
/// routing.
///
/// Returns 0 on any read/parse failure — this is a UX surface, not a
/// security gate, and doctor must never error out a healthy install
/// because the audit log happened to be unreadable.
pub fn count_unknown_tool_fail_opens_within(config: &AuditConfig, days: u32) -> u64 {
    if !config.enabled {
        return 0;
    }
    let Some(path) = resolved_audit_path(config) else {
        return 0;
    };
    let file = match open_read_nofollow(&path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(days));

    let reader = std::io::BufReader::new(file);
    let mut count: u64 = 0;
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
        if event.action != "unknown_tool_fail_open" {
            continue;
        }
        let ts = match OffsetDateTime::parse(&event.timestamp, &Rfc3339) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ts >= cutoff {
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn display_timestamp(ts: &str) -> String {
    // "2026-04-04T03:31:02.54814Z" → "2026-04-04T03:31:02Z"
    match ts.find('.') {
        Some(dot) => format!("{}Z", &ts[..dot]),
        None => ts.to_string(),
    }
}
