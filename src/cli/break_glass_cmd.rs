//! CLI handler for `omamori break-glass`.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};

use crate::AppError;
use crate::audit::AuditLogger;
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
        Ok(entry) => {
            // Audit-log activation
            if let Some(logger) = config::load_config(None)
                .ok()
                .and_then(|r| AuditLogger::from_config(&r.config.audit))
            {
                let event = create_activation_event(rule_id, &entry.expires_at);
                if let Err(e) = logger.append(event) {
                    eprintln!("omamori warning: failed to audit-log activation: {e}");
                }
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
            let removed = break_glass::clear_rule(id)?;
            if removed {
                if let Some(logger) = config::load_config(None)
                    .ok()
                    .and_then(|r| AuditLogger::from_config(&r.config.audit))
                {
                    let event = create_deactivation_event(id);
                    if let Err(e) = logger.append(event) {
                        eprintln!("omamori warning: failed to audit-log deactivation: {e}");
                    }
                }
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
/// `action`, and `result` vary per event kind.
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
    crate::audit::AuditEvent {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: "human".to_string(),
        command: format!("break-glass --rule {rule_id}"),
        rule_id: Some(rule_id.to_string()),
        action: "break-glass-activate".to_string(),
        result: format!("activated (expires {expires_at})"),
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
    }
}

fn create_deactivation_event(rule_id: &str) -> crate::audit::AuditEvent {
    crate::audit::AuditEvent {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: "human".to_string(),
        command: format!("break-glass --clear --rule {rule_id}"),
        rule_id: Some(rule_id.to_string()),
        action: "break-glass-deactivate".to_string(),
        result: "deactivated".to_string(),
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
    }
}

// ---------------------------------------------------------------------------
// Audit event for bypass (used by shim and hook)
// ---------------------------------------------------------------------------

pub(crate) fn create_bypass_event(
    rule_id: &str,
    command: &str,
    provider: &str,
    detection_layer: &str,
) -> crate::audit::AuditEvent {
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
