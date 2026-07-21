//! CLI handler for `omamori break-glass`.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};

use crate::AppError;
use crate::audit::AuditLogger;
use crate::audit::provenance::ProcessProvenance;
use crate::break_glass::{
    self, ActivationError, DEFAULT_DURATION_SECS, format_duration_human, format_remaining,
};
use crate::config;
use crate::engine::guard::guard_ai_config_modification;

pub(crate) fn run_break_glass_command(args: &[OsString]) -> Result<i32, AppError> {
    let args_str: Vec<String> = args
        .iter()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    // Parse flags
    if args_str.iter().any(|a| a == "--status") {
        return run_status();
    }
    if args_str.iter().any(|a| a == "--clear") {
        let rule = extract_flag_value(&args_str, "--rule");
        return run_clear(rule.as_deref());
    }

    let Some(rule_id) = extract_flag_value(&args_str, "--rule") else {
        eprintln!("Usage: omamori break-glass --rule <id> [--duration <dur>] [--reason <text>]");
        eprintln!("       omamori break-glass --status");
        eprintln!("       omamori break-glass --clear [--rule <id>]");
        return Ok(1);
    };

    let duration_str = extract_flag_value(&args_str, "--duration");
    let reason = extract_flag_value(&args_str, "--reason");

    run_activate(&rule_id, duration_str.as_deref(), reason)
}

fn run_activate(
    rule_id: &str,
    duration_str: Option<&str>,
    reason: Option<String>,
) -> Result<i32, AppError> {
    guard_ai_config_modification("break-glass")?;

    // Confirmation must come from a real interactive terminal. Piping an
    // answer in would let an AI agent self-approve a bypass without a human
    // ever seeing the prompt. Checked before any file I/O, state change, or
    // audit logging (mirrors setup.rs's "fail before any file I/O" discipline).
    if !io::stdin().is_terminal() {
        eprintln!("error: break-glass requires an interactive terminal.");
        eprintln!("  Confirmation cannot be read from a pipe or script — this is a");
        eprintln!("  deliberate safety gate so an AI agent cannot self-approve a bypass.");
        eprintln!("  Run this command directly in your terminal (not via AI, pipe, or script).");
        log_denied_activation(rule_id);
        return Ok(1);
    }

    let duration_secs = match duration_str {
        Some(s) => break_glass::parse_duration(s).map_err(AppError::Config)?,
        None => DEFAULT_DURATION_SECS,
    };

    // Show confirmation prompt
    let duration_human = format_duration_human(duration_secs);
    let now = time::OffsetDateTime::now_utc();
    let expires = now + time::Duration::seconds(duration_secs as i64);
    let expires_str = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());

    eprintln!();
    eprintln!("  Break-glass bypass for: {rule_id}");
    eprintln!("  Duration: {duration_human} (expires {expires_str})");
    eprintln!();
    eprintln!("  WARNING: Protection action (trash/stash/block) will be disabled.");
    eprintln!("  The original command executes WITHOUT safety measures.");
    eprintln!("  All bypassed executions will be logged to the audit chain.");
    eprintln!();

    eprint!("  Activate? [y/N] ");
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() || !input.trim().eq_ignore_ascii_case("y") {
        eprintln!("  Cancelled.");
        return Ok(1);
    }

    match break_glass::activate(rule_id, duration_secs, reason) {
        Ok((entry, expired)) => {
            // Audit-log activation
            if let Some(logger) = config::load_config(None)
                .ok()
                .and_then(|r| AuditLogger::from_config(&r.config.audit))
            {
                let event = create_activation_event(rule_id, &entry.expires_at);
                if let Err(e) = logger.append(event) {
                    eprintln!("omamori warning: failed to audit-log activation: {e}");
                }
                log_expired_observed_events(&logger, &expired);
            }

            eprintln!();
            eprintln!("  Break-glass activated for '{rule_id}'.");
            eprintln!("  Expires: {}", entry.expires_at);
            eprintln!("  To revoke early: omamori break-glass --clear --rule {rule_id}");
            Ok(0)
        }
        Err(ActivationError::Io(e)) => Err(AppError::Io(e)),
        Err(e) => {
            eprintln!("omamori: break-glass activation failed — {e}");
            Ok(1)
        }
    }
}

fn run_clear(rule_id: Option<&str>) -> Result<i32, AppError> {
    guard_ai_config_modification("break-glass clear")?;

    match rule_id {
        Some(id) => {
            let (removed, expired) = break_glass::clear_rule(id)?;
            if let Some(logger) = config::load_config(None)
                .ok()
                .and_then(|r| AuditLogger::from_config(&r.config.audit))
            {
                if removed {
                    let event = create_deactivation_event(id);
                    if let Err(e) = logger.append(event) {
                        eprintln!("omamori warning: failed to audit-log deactivation: {e}");
                    }
                }
                log_expired_observed_events(&logger, &expired);
            }
            if removed {
                eprintln!("Break-glass cleared for '{id}'.");
            } else {
                eprintln!("No active break-glass for '{id}'.");
            }
            Ok(0)
        }
        None => {
            let count = break_glass::clear_all()?;
            if count > 0 {
                eprintln!("Cleared {count} break-glass bypass(es).");
            } else {
                eprintln!("No active break-glass bypasses.");
            }
            Ok(0)
        }
    }
}

fn run_status() -> Result<i32, AppError> {
    let entries = break_glass::read_active_entries();
    if entries.is_empty() {
        eprintln!("No active break-glass bypasses.");
    } else {
        eprintln!("{} active break-glass bypass(es):", entries.len());
        for entry in &entries {
            let remaining = entry.remaining_secs().unwrap_or(0);
            eprintln!(
                "  {}: {} remaining (expires {})",
                entry.rule_id,
                format_remaining(remaining),
                entry.expires_at
            );
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Audit event helpers
// ---------------------------------------------------------------------------

/// Records a denied non-interactive activation attempt so the refusal is a
/// forensically observable event rather than a silent stderr-only message.
fn log_denied_activation(rule_id: &str) {
    if let Some(logger) = config::load_config(None)
        .ok()
        .and_then(|r| AuditLogger::from_config(&r.config.audit))
    {
        let event = create_denied_activation_event(rule_id);
        if let Err(e) = logger.append(event) {
            eprintln!("omamori warning: failed to audit-log denied activation: {e}");
        }
    }
}

/// Shared field layout for break-glass audit events; only `provider`,
/// `command`, `action`, and `result` vary per event kind.
fn build_break_glass_event(
    rule_id: &str,
    provider: &str,
    command: String,
    action: &str,
    result: String,
) -> crate::audit::AuditEvent {
    crate::audit::AuditEvent {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: provider.to_string(),
        command,
        rule_id: Some(rule_id.to_string()),
        action: action.to_string(),
        result,
        target_count: 0,
        target_hash: String::new(),
        detection_layer: Some("break-glass".to_string()),
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
    }
}

/// Distinct from `create_activation_event`'s `provider: "human"` — a denied
/// non-interactive attempt must never be attributed to a human confirmation
/// that never happened.
fn create_denied_activation_event(rule_id: &str) -> crate::audit::AuditEvent {
    build_break_glass_event(
        rule_id,
        "non-interactive",
        format!("break-glass --rule {rule_id}"),
        "break-glass-activate-denied",
        "denied (non-interactive stdin)".to_string(),
    )
}

fn create_activation_event(rule_id: &str, expires_at: &str) -> crate::audit::AuditEvent {
    build_break_glass_event(
        rule_id,
        "human",
        format!("break-glass --rule {rule_id}"),
        "break-glass-activate",
        format!("activated (expires {expires_at})"),
    )
}

fn create_deactivation_event(rule_id: &str) -> crate::audit::AuditEvent {
    build_break_glass_event(
        rule_id,
        "human",
        format!("break-glass --clear --rule {rule_id}"),
        "break-glass-deactivate",
        "deactivated".to_string(),
    )
}

// ---------------------------------------------------------------------------
// #324: expired-observed audit event
// ---------------------------------------------------------------------------

/// Best-effort audit logging for entries `break_glass::prune_expired_entries`
/// removed from state during `activate`/`clear_rule` (state-first,
/// audit-best-effort: called only after the state write that actually
/// removed the entry already succeeded — a failure here just means this
/// particular expiry goes unrecorded, not that the state write is undone).
fn log_expired_observed_events(logger: &AuditLogger, expired: &[break_glass::BreakGlassEntry]) {
    for entry in expired {
        let Some(event) = create_expired_observed_event(entry) else {
            continue;
        };
        if let Err(e) = logger.append(event) {
            eprintln!(
                "omamori warning: failed to audit-log break-glass-expired-observed for '{}': {e}",
                entry.rule_id
            );
        }
    }
}

/// break-glass state carries no HMAC (#323), so a corrupted or forged
/// entry could otherwise produce a chain-legitimate-looking audit event
/// for a rule that was never actually activated (Codex② sanity-check
/// requirement). Reject entries whose `rule_id` isn't a known core rule
/// rather than logging them as-is; note the state-derived `expires_at` as
/// unauthenticated in the result text rather than presenting it as a
/// verified fact.
fn create_expired_observed_event(
    entry: &break_glass::BreakGlassEntry,
) -> Option<crate::audit::AuditEvent> {
    // DI-13 non-bypassable rules (omamori-*) can never actually reach the
    // state file — `activate()` rejects them before an entry is created
    // (see `is_non_bypassable` check). An entry claiming one of these
    // rule_ids is therefore forged/corrupted by construction, not merely
    // "unrecognized" — reject it the same way as an unknown rule_id
    // (Codex R1 finding).
    let known = config::core_rule_names();
    let is_known_bypassable =
        known.contains(&entry.rule_id.as_str()) && !break_glass::is_non_bypassable(&entry.rule_id);
    if !is_known_bypassable {
        eprintln!(
            "omamori warning: skipping expired-observed audit event for unrecognized rule '{}' \
             — break-glass state is unauthenticated; this may indicate tampering",
            entry.rule_id
        );
        return None;
    }
    let result = if time::OffsetDateTime::parse(
        &entry.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .is_ok()
    {
        format!(
            "expired (per state: active until {} — unauthenticated, see state file)",
            entry.expires_at
        )
    } else {
        "expired (state expires_at was unparseable)".to_string()
    };
    Some(build_break_glass_event(
        &entry.rule_id,
        "omamori",
        "break-glass (auto-pruned expired entry)".to_string(),
        "break-glass-expired-observed",
        result,
    ))
}

// ---------------------------------------------------------------------------
// Audit event for bypass (used by shim and hook)
// ---------------------------------------------------------------------------

/// `provenance` is best-effort process context (#420). Layer 1 (shim) call
/// sites pass real data; Layer 2 (hook) call sites deliberately pass `None`
/// — out of scope for #420 (the motivating incident had zero Layer 2
/// events). Unlike the other `AuditEvent` builders in this file (CLI-only
/// events where provenance is meaningless), this one IS in scope on the
/// Layer 1 path, so it does not simply hardcode `None`.
///
/// `secret` is the caller's `AuditLogger::secret_ref()` — needed to compute
/// `cwd_hash` (see `ProcessProvenance::as_audit_fields`). Pass it regardless
/// of what `provenance` is; only `provenance` being `None` should ever be
/// the reason the four fields come out empty.
pub(crate) fn create_bypass_event(
    rule_id: &str,
    command: &str,
    provider: &str,
    detection_layer: &str,
    provenance: Option<&ProcessProvenance>,
    secret: Option<&[u8; 32]>,
) -> crate::audit::AuditEvent {
    let (pid, ppid, parent_process, cwd_hash) =
        ProcessProvenance::as_audit_fields(provenance, secret);
    crate::audit::AuditEvent {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: provider.to_string(),
        command: command.to_string(),
        rule_id: Some(rule_id.to_string()),
        action: "break-glass-bypass".to_string(),
        result: "allow".to_string(),
        target_count: 0,
        target_hash: String::new(),
        detection_layer: Some(detection_layer.to_string()),
        unwrap_chain: None,
        raw_input_hash: None,
        chain_version: None,
        seq: None,
        prev_hash: None,
        key_id: None,
        entry_hash: None,
        pid,
        ppid,
        parent_process,
        cwd_hash,
    }
}

// ---------------------------------------------------------------------------
// Arg parsing helpers
// ---------------------------------------------------------------------------

fn extract_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
        if let Some(rest) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(rule_id: &str, expires_at: &str) -> break_glass::BreakGlassEntry {
        break_glass::BreakGlassEntry {
            rule_id: rule_id.to_string(),
            activated_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            reason: None,
        }
    }

    // -----------------------------------------------------------------
    // create_activation_event / create_deactivation_event (#375)
    //
    // Characterization tests pinning the exact field values before
    // migrating these two constructors onto the shared
    // `build_break_glass_event` helper. `build_break_glass_event`'s
    // signature has two adjacent `&str` params (`provider`, `action`) and
    // two adjacent `String` params (`command`, `result`) — a transposed
    // argument during migration would compile cleanly, would not change
    // the HMAC audit chain's internal consistency (it hashes whatever
    // values it's given), and would go undetected by any existing test.
    // These assertions are the only safety net.
    // -----------------------------------------------------------------

    #[test]
    fn activation_event_preserves_human_provenance_and_shape() {
        let event = create_activation_event("rm-recursive-to-trash", "2020-01-01T01:00:00Z");
        assert_eq!(event.provider, "human");
        assert_eq!(event.action, "break-glass-activate");
        assert_eq!(event.command, "break-glass --rule rm-recursive-to-trash");
        assert_eq!(event.rule_id.as_deref(), Some("rm-recursive-to-trash"));
        assert_eq!(event.result, "activated (expires 2020-01-01T01:00:00Z)");
        assert_eq!(event.detection_layer.as_deref(), Some("break-glass"));
        assert_eq!(event.target_count, 0);
        assert_eq!(event.target_hash, "");
        assert!(event.unwrap_chain.is_none());
        assert!(event.raw_input_hash.is_none());
        assert!(event.pid.is_none());
        assert!(event.ppid.is_none());
        assert!(event.parent_process.is_none());
        assert!(event.cwd_hash.is_none());
    }

    #[test]
    fn deactivation_event_preserves_human_provenance_and_shape() {
        let event = create_deactivation_event("rm-recursive-to-trash");
        assert_eq!(event.provider, "human");
        assert_eq!(event.action, "break-glass-deactivate");
        assert_eq!(
            event.command,
            "break-glass --clear --rule rm-recursive-to-trash"
        );
        assert_eq!(event.rule_id.as_deref(), Some("rm-recursive-to-trash"));
        assert_eq!(event.result, "deactivated");
        assert_eq!(event.detection_layer.as_deref(), Some("break-glass"));
        assert_eq!(event.target_count, 0);
        assert_eq!(event.target_hash, "");
        assert!(event.unwrap_chain.is_none());
        assert!(event.raw_input_hash.is_none());
        assert!(event.pid.is_none());
        assert!(event.ppid.is_none());
        assert!(event.parent_process.is_none());
        assert!(event.cwd_hash.is_none());
    }

    // -----------------------------------------------------------------
    // create_expired_observed_event (#324)
    // -----------------------------------------------------------------

    #[test]
    fn expired_observed_event_has_expected_shape_for_known_rule() {
        let e = entry("rm-recursive-to-trash", "2020-01-01T01:00:00Z");
        let event = create_expired_observed_event(&e).expect("known rule must produce an event");
        assert_eq!(event.action, "break-glass-expired-observed");
        assert_eq!(event.provider, "omamori");
        assert_eq!(event.rule_id.as_deref(), Some("rm-recursive-to-trash"));
        assert_eq!(event.detection_layer.as_deref(), Some("break-glass"));
        assert!(
            event.result.contains("2020-01-01T01:00:00Z"),
            "result must surface the state-derived expires_at: {}",
            event.result
        );
    }

    // -----------------------------------------------------------------
    // create_bypass_event provenance wiring (#420, M3 / Phase 5 finding)
    //
    // The compiler enforces that some value is passed for `provenance` at
    // every call site, but it cannot tell a deliberate `None` (hook.rs,
    // Layer 2, out of scope) from an accidental one (shim.rs, Layer 1,
    // should carry real data). These two tests pin the two directions
    // directly against `create_bypass_event`'s own behavior.
    // -----------------------------------------------------------------

    #[test]
    fn bypass_event_with_provenance_carries_real_fields() {
        let provenance = ProcessProvenance::collect();
        let event = create_bypass_event(
            "rm-recursive-to-trash",
            "rm -rf /tmp/x",
            "claude-code",
            "layer1:break-glass",
            Some(&provenance),
            None, // secret: absent is fine, only cwd_hash depends on it
        );
        // `ProcessProvenance`'s fields are `pub(super)` (audit-module-only),
        // so this test — living in `cli::break_glass_cmd` — derives its
        // expectations through the same public unpacking method the real
        // call site uses, rather than reaching into private fields.
        let (expected_pid, expected_ppid, expected_parent, _) =
            ProcessProvenance::as_audit_fields(Some(&provenance), None);
        assert_eq!(event.pid, expected_pid);
        assert_eq!(event.ppid, expected_ppid);
        // parent_process/cwd_hash are environment-dependent (may be None
        // if collection failed in this environment), but they must match
        // whatever collect() actually produced — not be silently dropped.
        assert_eq!(event.parent_process, expected_parent);
    }

    #[test]
    fn bypass_event_without_provenance_has_all_none_fields() {
        // Mirrors the two hook.rs call sites (Layer 2, out of scope).
        let event = create_bypass_event(
            "rm-recursive-to-trash",
            "rm -rf /tmp/x",
            "claude-code",
            "layer2:break-glass",
            None,
            None,
        );
        assert_eq!(event.pid, None);
        assert_eq!(event.ppid, None);
        assert_eq!(event.parent_process, None);
        assert_eq!(event.cwd_hash, None);
    }

    #[test]
    fn expired_observed_event_none_for_unknown_rule_id() {
        // break-glass state has no HMAC — a forged/corrupted rule_id must
        // not produce a chain-legitimate-looking event.
        let e = entry("totally-made-up-rule", "2020-01-01T01:00:00Z");
        assert!(
            create_expired_observed_event(&e).is_none(),
            "unrecognized rule_id must not produce an audit event"
        );
    }

    #[test]
    fn expired_observed_event_none_for_non_bypassable_rule_id() {
        // "omamori-config-modify-block" is a real entry in
        // config::core_rule_names(), but it's DI-13 non-bypassable —
        // activate() rejects it before any state entry could ever be
        // created. An entry claiming this rule_id is forged by
        // construction, not merely unrecognized (Codex R1 finding).
        let e = entry("omamori-config-modify-block", "2020-01-01T01:00:00Z");
        assert!(
            create_expired_observed_event(&e).is_none(),
            "non-bypassable rule_id must not produce an audit event, even though it's a known core rule name"
        );
    }

    #[test]
    fn expired_observed_event_notes_unparseable_expires_at_without_panicking() {
        let e = entry("rm-recursive-to-trash", "not-a-timestamp");
        let event =
            create_expired_observed_event(&e).expect("known rule must still produce an event");
        assert!(
            event.result.contains("unparseable"),
            "result must flag the unparseable expires_at rather than presenting it as valid: {}",
            event.result
        );
    }

    // -----------------------------------------------------------------
    // log_expired_observed_events (#324, Codex R1 P1): exercises the real
    // append path through a real AuditLogger, not just
    // create_expired_observed_event's return shape in isolation — this
    // would fail if append() were ever skipped or the event's action
    // field silently changed.
    // -----------------------------------------------------------------

    #[test]
    fn log_expired_observed_events_appends_to_chain() {
        let dir =
            std::env::temp_dir().join(format!("omamori-bg-cmd-expired-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let logger =
            crate::audit::AuditLogger::from_config(&audit_config).expect("should create logger");

        let expired = vec![
            entry("rm-recursive-to-trash", "2020-01-01T01:00:00Z"),
            entry("totally-made-up-rule", "2020-01-01T01:00:00Z"), // rejected, must not appear
        ];
        log_expired_observed_events(&logger, &expired);

        let content = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "only the known-rule entry should be appended, got: {content}"
        );
        assert!(lines[0].contains("\"action\":\"break-glass-expired-observed\""));
        assert!(lines[0].contains("\"rule_id\":\"rm-recursive-to-trash\""));
        assert!(!content.contains("totally-made-up-rule"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
