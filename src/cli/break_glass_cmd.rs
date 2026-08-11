//! CLI handler for `omamori break-glass`.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};

use crate::AppError;
use crate::audit::provenance::ProcessProvenance;
use crate::audit::{self, AppendOutlook, AuditLogger, AuditSummary, UnprotectedReason};
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

    // #492: the sentence below used to promise audit logging unconditionally,
    // printed here — fifteen lines before the first `load_config`, and so
    // before anything had checked whether auditing runs at all. With
    // `[audit] enabled = false` nothing was logged and the sentence that
    // obtained consent was simply untrue. It is an inducement, not a status
    // line: it is the reassurance that makes granting a bypass feel safe, so
    // it has to be answerable at the moment it is read.
    //
    // Asked through `audit_summary` rather than `AuditLogger::from_config`,
    // deliberately. The latter runs `load_signing_key`, which **mints a key
    // file** when none is there — a write, performed while asking a question,
    // before the operator has agreed to anything. `audit_summary` is the
    // read-only form of the same question and says so in its own doc.
    let audit = config::load_config(None)
        .map(|r| (audit::audit_summary(&r.config.audit), r.config.audit.strict))
        .ok();

    eprintln!();
    eprintln!("  Break-glass bypass for: {rule_id}");
    eprintln!("  Duration: {duration_human} (expires {expires_str})");
    eprintln!();
    eprintln!("  WARNING: Protection action (trash/stash/block) will be disabled.");
    eprintln!("  The original command executes WITHOUT safety measures.");
    eprintln!(
        "{}",
        format_audit_expectation(audit.as_ref().map(|(summary, strict)| AuditOutlook {
            summary,
            strict: *strict,
        }))
    );
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
            if let Some(logger) = config::load_config(None).ok().and_then(|r| {
                // #527: the verdict comes from the detector set this load
                // produced, not from the built-in list. Building the logger
                // can print a key-store warning, and that warning carries a
                // repair.
                let allow_repair = crate::detector::repair_gate_reporting(&r.config.detectors);
                AuditLogger::from_config(&r.config.audit, allow_repair)
            }) {
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

/// What `break-glass` knows about auditing at the moment it asks for consent.
///
/// `strict` travels beside the summary because it changes the *consequence* of
/// a failed append rather than its likelihood, and `AuditSummary` describes the
/// store rather than the policy applied to it.
struct AuditOutlook<'a> {
    summary: &'a AuditSummary,
    strict: bool,
}

/// Say what the audit chain will actually do with the bypasses this prompt is
/// about to authorise (#492).
///
/// Six outcomes. "Recorded", "verifiable afterwards" and "allowed to run at
/// all" are three separate promises and the operator is consenting to all of
/// them, so a state that differs in any one needs its own sentence — merging
/// two puts one of them under wording it does not deserve.
///
/// `None` means the config could not be read. That is not "auditing is off" —
/// it is "this command cannot tell", and saying either of the other answers
/// would be a guess presented as a fact.
fn format_audit_expectation(outlook: Option<AuditOutlook<'_>>) -> String {
    let Some(AuditOutlook { summary, strict }) = outlook else {
        return "  Audit logging: cannot tell — this command could not read the config."
            .to_string();
    };

    // No logger will be built, so nothing is attempted and nothing is refused.
    // `logger_available` rather than `enabled` because an audit path that does
    // not resolve lands here too with `enabled: true`, and rather than
    // `path_error` because that is also `Some` in the very different state
    // handled next.
    if !summary.logger_available {
        let mut out =
            "  Bypassed executions will NOT be logged — auditing is not running.".to_string();
        if let Some(err) = &summary.path_error {
            out.push_str(&format!("\n  ({err})"));
        }
        return out;
    }

    // A logger exists and the log cannot be read. Checked before the key,
    // because a write that cannot happen makes the signing story irrelevant —
    // and because these states co-occur: a symlinked or directory-shaped
    // `audit.jsonl` also reports `ActiveKeyMissing`, so the key arms below
    // would otherwise answer for it.
    //
    // Under `[audit] strict = true` the outcome is not "unrecorded" but
    // "refused": the failed append returns exit 2 from the hook
    // (`engine::hook`), so the bypass the operator is authorising will not run.
    // Saying "will not be logged" there would be a second false promise of the
    // exact kind #492 exists to remove.
    if let Some(err) = &summary.path_error {
        let consequence = if strict {
            "`[audit] strict = true` is set, so the bypass will be REFUSED rather than\n    \
             run unrecorded."
        } else {
            "the bypass will still run, unrecorded."
        };
        return format!(
            "  Bypassed executions will NOT be recorded — the audit log cannot be read:\n    \
             {err}\n    {consequence}"
        );
    }

    // #514: the log opens for reading and refuses writing. Every field checked
    // above passes here — `path_error` comes from an `O_RDONLY` open, so a log
    // at mode `0400` reports no error — and the sentence below would promise
    // exactly what cannot happen.
    //
    // Placed before the key arms for the reason the `path_error` arm above
    // gives: a write that cannot happen makes the signing story irrelevant. It
    // therefore also takes the two states where the key is missing or unusable,
    // where "omamori will try to create one on the next write" would describe a
    // write that never reaches the disk.
    match &summary.append_outlook {
        Some(AppendOutlook::NotWritable(err)) => {
            let consequence = if strict {
                "`[audit] strict = true` is set, so the bypass will be REFUSED rather than\n    \
                 run unrecorded."
            } else {
                "the bypass will still run, unrecorded."
            };
            return format!(
                "  Bypassed executions will NOT be recorded — the audit log cannot be \
                 written:\n    {err}\n    {consequence}"
            );
        }
        // No log yet. `append` creates one, together with its parent directory,
        // and whether that succeeds cannot be answered without performing it —
        // `#492`'s rule forbids resolving this by writing. So the uncertainty is
        // stated rather than guessed in either direction.
        Some(AppendOutlook::NoLogYet) => {
            let consequence = if strict {
                "if that fails, `[audit] strict = true` means the bypass is REFUSED."
            } else {
                "if that fails, the bypass still runs, unrecorded."
            };
            return format!(
                "  Bypassed executions will be logged once the audit log is created:\n    \
                 omamori writes it on the first append — {consequence}"
            );
        }
        _ => {}
    }

    if summary.secret_available {
        return "  All bypassed executions will be logged to the audit chain.".to_string();
    }

    // Recorded, but the signature is in doubt. Which sentence is honest here
    // depends on the reason, and the difference is not cosmetic:
    // `ActiveKeyMissing` is the one state where the *next* append often mints a
    // key and protects the very entry being asked about — measured, and
    // recorded in `UnprotectedReason::summary`'s own doc. Promising "cannot be
    // verified later" there would state the opposite of what usually happens.
    // `secret_available` is one-directional for exactly this reason (see
    // `AuditSummary`), so a single degraded sentence cannot be written.
    match &summary.unprotected_reason {
        Some(UnprotectedReason::ActiveKeyMissing) => {
            "  Bypassed executions will be logged, but the audit key is not in place:\n    \
             omamori will try to create one on the next write. If that succeeds these\n    \
             entries are signed as usual; if it fails they are recorded without a\n    \
             signature and cannot be verified afterwards."
                .to_string()
        }
        // ADR-0007 forbids rewriting an entry once written, so restoring the
        // key does not repair rows that were stamped without one.
        //
        // `None` is attached to *this* arm deliberately. It is unreachable
        // today — `audit_summary` derives `secret_available` from
        // `unprotected_reason.is_none()`, so within this branch a reason always
        // exists — but `AuditSummary` is `#[non_exhaustive]`, and a state added
        // later that reports "not protected" with no reason this build can name
        // should inherit the cautious sentence, not the reassuring one.
        Some(_) | None => {
            let reason = summary
                .unprotected_reason
                .as_ref()
                .map(|r| format!("\n    Reason: {}", r.summary()))
                .unwrap_or_default();
            format!(
                "  Bypassed executions will be logged, but NOT tamper-evident:\n    \
                 they are recorded without a signature, and restoring the key\n    \
                 afterwards does not make them verifiable.{reason}"
            )
        }
    }
}

fn run_clear(rule_id: Option<&str>) -> Result<i32, AppError> {
    guard_ai_config_modification("break-glass clear")?;

    match rule_id {
        Some(id) => {
            let (removed, expired) = break_glass::clear_rule(id)?;
            if let Some(logger) = config::load_config(None).ok().and_then(|r| {
                // #527: the verdict comes from the detector set this load
                // produced, not from the built-in list. Building the logger
                // can print a key-store warning, and that warning carries a
                // repair.
                let allow_repair = crate::detector::repair_gate_reporting(&r.config.detectors);
                AuditLogger::from_config(&r.config.audit, allow_repair)
            }) {
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
    if let Some(logger) = config::load_config(None).ok().and_then(|r| {
        // #527: see the sibling call sites — the verdict follows the
        // configuration this load produced.
        let allow_repair = crate::detector::repair_gate_reporting(&r.config.detectors);
        AuditLogger::from_config(&r.config.audit, allow_repair)
    }) {
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
        wrapper_kind: None,
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
        wrapper_kind: None,
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
    // format_audit_expectation (#492)
    //
    // The sentence this builds is an inducement: it is what makes granting a
    // bypass feel safe, and it used to be printed before anything had checked
    // whether auditing runs. Each state below is one the old unconditional
    // sentence got wrong.
    // -----------------------------------------------------------------

    fn summary(enabled: bool, secret_available: bool) -> AuditSummary {
        AuditSummary {
            enabled,
            // Every fixture here is past `from_config`'s two refusals unless it
            // says otherwise, which is what `enabled` used to imply on its own.
            logger_available: enabled,
            entry_count: 0,
            secret_available,
            unprotected_reason: None,
            retention_days: 90,
            path_error: None,
            // The existing fixtures all describe stores whose appends land; the
            // states where they do not get their own tests below (#514).
            append_outlook: Some(crate::audit::AppendOutlook::Writable),
        }
    }

    /// Default policy: `strict` off. The one test that needs it on says so.
    fn outlook(summary: &AuditSummary) -> Option<AuditOutlook<'_>> {
        Some(AuditOutlook {
            summary,
            strict: false,
        })
    }

    /// #514/#492: asking what a write would meet must not perform one.
    ///
    /// The probe added for `#514` is `open_audit_rw` minus `create`, and the
    /// missing flag is the whole point — the version with it would bring
    /// `audit.jsonl` into being as a side effect of rendering a consent prompt.
    /// `#492` found exactly this shape once already, where asking for status
    /// minted a key file.
    ///
    /// The directory listing is compared whole rather than just checking for
    /// `audit.jsonl`: the store also holds keys, an epoch record and a lock, and
    /// a side effect on any of them is the same defect.
    #[test]
    fn asking_what_a_write_would_meet_creates_nothing() {
        let dir =
            std::env::temp_dir().join(format!("omamori-bg-cmd-noprobe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };

        let listing = |d: &std::path::Path| {
            let mut names: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };

        let before = listing(&dir);
        assert!(
            before.is_empty(),
            "precondition: the store starts empty, so anything below is the probe's doing"
        );

        let summary = crate::audit::audit_summary(&audit_config);
        let _ = format_audit_expectation(outlook(&summary));

        assert_eq!(
            listing(&dir),
            before,
            "asking for status created something in the store"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #514: a log that opens for reading and refuses writing must not be
    /// promised as recorded — and the two neighbouring states must still say
    /// what they said.
    ///
    /// Driven through the real `audit_summary` on a real store rather than a
    /// hand-built `AuditSummary`. A fixture handing the formatter
    /// `NotWritable` would pass even if nothing ever produced that value, which
    /// is the half of this change that could silently not exist.
    ///
    /// All three states in one test on purpose: the defect was that `0400` and
    /// "no log yet" both reached the sentence `0600` deserves, so the cases only
    /// discriminate against each other.
    #[test]
    #[cfg(unix)]
    fn a_log_that_cannot_be_written_is_not_promised_as_recorded() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("omamori-bg-cmd-rofile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(log.clone()),
            retention_days: 0,
            strict: false,
        };

        // 1. No log yet. `append` would create one; whether that succeeds is the
        //    parent's question, so the sentence states the attempt.
        let absent = format_audit_expectation(outlook(&crate::audit::audit_summary(&audit_config)));
        assert!(
            absent.contains("once the audit log is created"),
            "with no log file, the prompt must say the log is yet to be written: {absent}"
        );

        // 2. Seed a real store, writable. This is the control: without it, an
        //    implementation that always warns would score full marks below.
        let logger = crate::audit::AuditLogger::from_config_for_test(&audit_config).unwrap();
        logger
            .append(create_activation_event(
                "rm-recursive-to-trash",
                "2030-01-01T00:00:00Z",
            ))
            .unwrap();
        let writable =
            format_audit_expectation(outlook(&crate::audit::audit_summary(&audit_config)));
        assert!(
            writable.contains("will be logged to the audit chain"),
            "control failed — a writable store must still reach the reassuring \
             sentence, or the assertion below is not about writability: {writable}"
        );

        // 3. The same store, readable but not writable.
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o400)).unwrap();
        let read_only =
            format_audit_expectation(outlook(&crate::audit::audit_summary(&audit_config)));
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(
            !read_only.contains("will be logged to the audit chain"),
            "a log that refuses writing must not be promised as recorded: {read_only}"
        );
        assert!(
            read_only.contains("cannot be written"),
            "and the prompt must say which way it is broken — reading still \
             works here, so 'cannot be read' would be wrong: {read_only}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_disabled_does_not_promise_logging() {
        let text = format_audit_expectation(outlook(&summary(false, false)));
        assert!(
            text.contains("NOT be logged"),
            "with `[audit] enabled = false` nothing is recorded, and this sentence \
             is what obtains consent: {text}"
        );
        assert!(
            !text.contains("will be logged to the audit chain"),
            "the reassuring sentence must not survive here: {text}"
        );
    }

    #[test]
    fn unresolvable_audit_path_does_not_promise_logging() {
        // `AuditLogger::from_config` returns `None` for this exactly as it does
        // for `enabled = false`, so no bypass is recorded — but `enabled` is
        // `true`, so a predicate that only read that flag would have printed
        // the reassuring sentence on a store that logs nothing.
        //
        // `logger_available: false` is the whole fixture. An earlier version of
        // this test set only `path_error` and left it `true`, which is not a
        // state `audit_summary` can produce — that combination is the *other*
        // `path_error` source (a resolved path whose log cannot be read), where
        // a logger does exist. The test passed anyway, because the code then
        // keyed on `path_error` and could not tell them apart either.
        let mut s = summary(true, false);
        s.logger_available = false;
        s.path_error = Some("HOME is unset, empty, or relative".to_string());
        let text = format_audit_expectation(outlook(&s));
        assert!(
            text.contains("NOT be logged"),
            "an unresolvable audit path records nothing: {text}"
        );
        assert!(
            text.contains("HOME is unset"),
            "the reason belongs in the prompt — the operator can act on it: {text}"
        );
    }

    /// `path_error` is `Some` in two unrelated states and only one of them
    /// means "nothing is written".
    ///
    /// Here the path resolved, auditing is on, and it is the **log file** that
    /// cannot be read — `AuditLogger::from_config` still returns a logger, so
    /// the append is attempted and fails. Answering this with "auditing is not
    /// running" names a cause the operator cannot act on, and the remedy is
    /// nothing like the other state's (`remove whatever was planted on your
    /// audit log`, not `turn auditing on`). This is the state `#471` was about,
    /// so it is not hypothetical.
    #[test]
    fn unreadable_log_is_not_reported_as_auditing_switched_off() {
        let mut s = summary(true, true);
        s.path_error =
            Some("audit path is a symlink (possible attack): /x/audit.jsonl".to_string());
        let text = format_audit_expectation(outlook(&s));
        assert!(
            !text.contains("auditing is not running"),
            "auditing IS running here — a logger exists and will attempt the append: {text}"
        );
        assert!(
            text.contains("cannot be read"),
            "the honest statement is about the log, not the switch: {text}"
        );
        assert!(
            text.contains("possible attack"),
            "and the reason has to survive — it is the actionable half: {text}"
        );
    }

    /// Under `[audit] strict = true` a failed append is not an unrecorded
    /// bypass, it is a **refused** one: the hook returns exit 2. Telling the
    /// operator the command will "still run, unrecorded" would be a second
    /// false promise of exactly the kind #492 exists to remove.
    #[test]
    fn strict_mode_says_the_bypass_is_refused_not_merely_unrecorded() {
        let mut s = summary(true, true);
        s.path_error = Some("is a directory, not a regular file".to_string());

        let lenient = format_audit_expectation(outlook(&s));
        assert!(
            lenient.contains("will still run"),
            "without strict the command does run: {lenient}"
        );

        let strict = format_audit_expectation(Some(AuditOutlook {
            summary: &s,
            strict: true,
        }));
        assert!(
            strict.contains("REFUSED"),
            "with strict the append failure blocks the command (exit 2): {strict}"
        );
        assert!(
            !strict.contains("will still run"),
            "and the lenient claim must not survive alongside it: {strict}"
        );
    }

    #[test]
    fn healthy_store_keeps_the_original_promise() {
        let text = format_audit_expectation(outlook(&summary(true, true)));
        assert_eq!(
            text.trim(),
            "All bypassed executions will be logged to the audit chain.",
            "the state the old unconditional sentence was written for must be \
             unchanged, or this change would be a regression for every healthy store"
        );
    }

    #[test]
    fn degraded_key_store_separates_logged_from_verifiable() {
        let mut s = summary(true, false);
        s.unprotected_reason = Some(UnprotectedReason::KeyDirUnlistable(
            "cannot list /x: Permission denied".to_string(),
        ));
        let text = format_audit_expectation(outlook(&s));
        assert!(
            text.contains("will be logged"),
            "entries ARE written in this state — claiming otherwise inverts what a \
             missing row means (SECURITY.md: absence implies Allow): {text}"
        );
        assert!(
            text.contains("NOT tamper-evident"),
            "and they carry no HMAC, which is the half the old sentence hid: {text}"
        );
        assert!(
            text.contains("key directory cannot be listed"),
            "the specific reason comes from `UnprotectedReason::summary`: {text}"
        );
    }

    #[test]
    fn missing_active_key_does_not_claim_the_entries_are_unverifiable() {
        // The one degraded state whose outcome is genuinely uncertain: the next
        // append tries to mint a key and often succeeds, protecting the very
        // entry being asked about (measured — see `UnprotectedReason::summary`).
        // A single "cannot be verified later" sentence would state the opposite
        // of what usually happens.
        let mut s = summary(true, false);
        s.unprotected_reason = Some(UnprotectedReason::ActiveKeyMissing);
        let text = format_audit_expectation(outlook(&s));
        assert!(
            text.contains("try to create one"),
            "the mint attempt is the whole difference from the other degraded \
             states and must be stated: {text}"
        );
        assert!(
            !text.contains("NOT tamper-evident"),
            "that verdict is not established here — the next write may well sign \
             these entries: {text}"
        );
    }

    /// The five tests above hand-build `AuditSummary`, so each one proves what
    /// the *formatter* does with a shape — not that `audit_summary` ever
    /// produces that shape. A branch keyed on a field combination the real
    /// function never returns would pass all five and be dead in production.
    ///
    /// This one runs the wiring: a real config, through the real
    /// `audit_summary`, into the formatter. The degraded arm is the one worth
    /// wiring — `mode 0o300` leaves the directory searchable but not listable,
    /// which is the permission state `key_store_outlook` refuses on while
    /// `read_secret` alone would still succeed. If the two ever stopped
    /// disagreeing there, the `KeyDirUnlistable` arm would become unreachable
    /// and only this test would notice.
    #[cfg(unix)]
    #[test]
    fn unlistable_key_dir_reaches_the_degraded_arm_through_audit_summary() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("omamori-bg-cmd-unlistable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };

        // Seed a real key so the store is healthy first — that establishes the
        // control: the reassuring sentence is reachable here, so the assertion
        // below is about the permission change and nothing else.
        let logger = crate::audit::AuditLogger::from_config_for_test(&audit_config).unwrap();
        logger
            .append(create_activation_event(
                "rm-recursive-to-trash",
                "2030-01-01T00:00:00Z",
            ))
            .unwrap();
        let healthy =
            format_audit_expectation(outlook(&crate::audit::audit_summary(&audit_config)));
        assert!(
            healthy.contains("will be logged to the audit chain"),
            "control failed — the healthy arm is not reachable in this fixture, so \
             the assertion below would not be measuring the permission change: {healthy}"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
        let degraded =
            format_audit_expectation(outlook(&crate::audit::audit_summary(&audit_config)));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            degraded.contains("NOT tamper-evident"),
            "an unlistable key directory must reach the degraded arm through the \
             real `audit_summary`, not just through a hand-built struct: {degraded}"
        );
        assert!(
            degraded.contains("key directory cannot be listed"),
            "and it must carry the reason `UnprotectedReason` actually returned: {degraded}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two `path_error` sources, told apart through the real
    /// `audit_summary` rather than by hand.
    ///
    /// A directory at the audit path is the reachable form of "the log cannot be
    /// read": the path resolves, so `logger_available` is true, and
    /// `open_read_nofollow` then fails with something other than `NotFound`.
    /// The hand-built tests above cannot prove this shape exists — only that the
    /// formatter would handle it if it did.
    #[test]
    fn directory_at_audit_path_reaches_the_unreadable_log_arm() {
        let dir =
            std::env::temp_dir().join(format!("omamori-bg-cmd-dirlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("audit.jsonl")).unwrap();
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };

        let summary = crate::audit::audit_summary(&audit_config);
        assert!(
            summary.logger_available,
            "the path resolved, so a logger exists — this is the half that \
             distinguishes this state from an unresolvable path"
        );
        assert!(
            summary.path_error.is_some(),
            "and the log itself could not be opened"
        );

        let text = format_audit_expectation(outlook(&summary));
        assert!(
            text.contains("cannot be read") && !text.contains("auditing is not running"),
            "so the message must be about the log, not the switch: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An absolute `audit.path` carrying control characters reaches the consent
    /// prompt (#492).
    ///
    /// `AuditConfig::validate` strips them only on the relative branch, where it
    /// discards the override anyway, so an absolute path goes through verbatim
    /// and lands in `path_error`. `ESC[2A` + `ESC[K` is cursor-up-two plus
    /// erase-line — enough to overwrite the two warning lines the operator is
    /// answering, on the one prompt whose honesty this change exists to
    /// establish. Sanitized in `audit_summary` so `status` is covered too.
    #[test]
    fn control_characters_in_the_audit_path_cannot_drive_the_terminal() {
        let dir = std::env::temp_dir().join(format!("omamori-bg-cmd-ansi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let planted = dir.join("\u{1b}[2A\u{1b}[Kaudit.jsonl");
        std::fs::create_dir_all(&planted).unwrap(); // a directory, so the read fails
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(planted),
            retention_days: 0,
            strict: false,
        };

        let summary = crate::audit::audit_summary(&audit_config);
        let err = summary
            .path_error
            .as_deref()
            .expect("a directory at the audit path must produce a path_error");
        assert!(
            !err.chars().any(char::is_control),
            "the escape sequence survived into path_error: {err:?}"
        );

        let text = format_audit_expectation(outlook(&summary));
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "and it must not reach the prompt: {text:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #515: the same route, for the characters `char::is_control` does not
    /// report.
    ///
    /// `U+202E` RIGHT-TO-LEFT OVERRIDE is category `Cf`, so the check the test
    /// above makes — "no control characters survived" — was true of a string
    /// that still rendered in an order the bytes do not have. On a prompt whose
    /// whole purpose is that the operator agrees to what the line says, the gap
    /// between displayed and actual is the thing being paid for.
    ///
    /// The second half is the one that makes this a test rather than a
    /// tautology: a path with Japanese and an emoji must come through
    /// **unchanged**. Widening the substitution until an operator cannot read
    /// the path they have to act on trades one failure for another, and an
    /// implementation that replaces everything non-ASCII passes the first
    /// assertion.
    #[test]
    fn bidi_overrides_in_the_audit_path_cannot_reorder_the_prompt() {
        let dir = std::env::temp_dir().join(format!("omamori-bg-cmd-bidi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let planted = dir.join("\u{202E}gnl.tidua\u{202C}");
        std::fs::create_dir_all(&planted).unwrap(); // a directory, so the read fails
        let audit_config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(planted),
            retention_days: 0,
            strict: false,
        };

        let summary = crate::audit::audit_summary(&audit_config);
        let err = summary
            .path_error
            .as_deref()
            .expect("a directory at the audit path must produce a path_error");
        assert!(
            !err.contains('\u{202E}') && !err.contains('\u{202C}'),
            "the override survived into path_error: {err:?}"
        );

        let text = format_audit_expectation(outlook(&summary));
        assert!(
            !text.contains('\u{202E}') && !text.contains('\u{202C}'),
            "and it must not reach the prompt: {text:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);

        // The control half of the pair: ordinary non-ASCII is not the threat and
        // must survive byte for byte.
        let legible = std::env::temp_dir().join(format!(
            "omamori-bg-cmd-ja-{}/監査ログ-\u{1F512}\u{FE0F}.jsonl",
            std::process::id()
        ));
        std::fs::create_dir_all(&legible).unwrap();
        let summary = crate::audit::audit_summary(&crate::audit::AuditConfig {
            enabled: true,
            path: Some(legible.clone()),
            retention_days: 0,
            strict: false,
        });
        let err = summary
            .path_error
            .as_deref()
            .expect("a directory at the audit path must produce a path_error");
        assert!(
            err.contains("監査ログ") && err.contains('\u{1F512}') && err.contains('\u{FE0F}'),
            "a legible path must come through intact, variation selector included: {err:?}"
        );
        let _ = std::fs::remove_dir_all(legible.parent().unwrap());
    }

    #[test]
    fn unreadable_config_says_so_rather_than_guessing() {
        let text = format_audit_expectation(None);
        assert!(
            text.contains("cannot tell"),
            "`None` means the config could not be read, which is neither of the \
             other two answers — printing one of them would be a guess presented \
             as a fact: {text}"
        );
        assert!(
            !text.contains("will be logged to the audit chain") && !text.contains("NOT be logged"),
            "and it must not borrow either verdict: {text}"
        );
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
    #[serial_test::serial(cwd)]
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
        let logger = crate::audit::AuditLogger::from_config_for_test(&audit_config)
            .expect("should create logger");

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
