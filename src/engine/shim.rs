//! PATH shim execution, command evaluation pipeline, and hook integrity.
//!
//! `run_command` is the core evaluation pipeline that orchestrates:
//! detector → rules → context → action → audit.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::AppError;
use crate::actions::{self, ActionExecutor, ActionOutcome, SystemOps};
use crate::audit::AuditLogger;
use crate::config::{ConfigLoadResult, load_config};
use crate::context;
use crate::detector::evaluate_detectors;
use crate::installer;
use crate::integrity;
use crate::rules::{self, CommandInvocation, RuleConfig, match_rule};
use time::OffsetDateTime;

use crate::util::{clone_lossy, resolve_real_command, should_block_for_sudo};

// ---------------------------------------------------------------------------
// Shim entry point
// ---------------------------------------------------------------------------

pub(crate) fn run_shim(program: &str, args: &[OsString]) -> Result<i32, AppError> {
    let base_dir = installer::default_base_dir();

    // Step 1: Lightweight integrity canary (stat + readlink, ~0.05ms)
    if let Some(warning) = integrity::canary(&base_dir, program) {
        eprintln!("omamori[health]: {warning}");
    }

    // Step 1a: Heartbeat — record shim activity (at most once per UTC day)
    touch_heartbeat();

    // Step 1b: v0.4 → v0.5 migration — create baseline if missing
    if !integrity::baseline_path(&base_dir).exists() && base_dir.join("shim").exists() {
        update_baseline_silent(&base_dir);
        eprintln!(
            "omamori[health]: integrity baseline created. Run `omamori status` for full check."
        );
    }

    // Step 2: Hook version + content hash check, regenerate if needed
    let hooks_regenerated = ensure_hooks_current();

    // Step 2b: Auto-setup Codex hooks if CODEX_CI detected but not configured
    let codex_setup = installer::auto_setup_codex_if_needed(&base_dir);

    // Step 2c: Re-merge ~/.claude/settings.json if version stale or matcher legacy (#196)
    let settings_synced = ensure_settings_current();

    // Step 3: If anything was regenerated, update baseline
    if hooks_regenerated || codex_setup || settings_synced {
        update_baseline_silent(&base_dir);
    }

    // Step 4: Run the actual command
    run_command(program.to_string(), args, None)
}

// ---------------------------------------------------------------------------
// Heartbeat — passive shim activity recording (once per UTC day)
// ---------------------------------------------------------------------------

pub(crate) fn heartbeat_path() -> Option<PathBuf> {
    context::data_dir().map(|d| d.join("heartbeat"))
}

fn touch_heartbeat() {
    if let Some(path) = heartbeat_path() {
        touch_heartbeat_at(&path);
    }
}

fn touch_heartbeat_at(path: &Path) {
    let _ = touch_heartbeat_inner(path);
}

fn touch_heartbeat_inner(path: &Path) -> Option<()> {
    let now = OffsetDateTime::now_utc();
    let today_jd = now.date().to_julian_day();

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return None;
        }
        let mtime = meta.modified().ok()?;
        let secs = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        let mtime_jd = OffsetDateTime::from_unix_timestamp(secs as i64)
            .ok()?
            .date()
            .to_julian_day();
        if mtime_jd == today_jd {
            return Some(());
        }
    }

    write_heartbeat_file(path, &now)
}

/// Writes via `atomic_file::atomic_write_with_mode` (#322: closes the
/// pre-creation race the old predictable-temp-name + `create(true)`
/// implementation had). The caller (`touch_heartbeat_inner`) already checked
/// that `path` isn't a non-regular-file entry before reaching here, so no
/// symlink check is duplicated at this layer.
fn write_heartbeat_file(path: &Path, now: &OffsetDateTime) -> Option<()> {
    let parent = path.parent()?;
    std::fs::create_dir_all(parent).ok()?;

    let content = now
        .format(&time::format_description::well_known::Rfc3339)
        .ok()?;

    crate::atomic_file::atomic_write_with_mode(path, content.as_bytes(), 0o600).ok()
}

// ---------------------------------------------------------------------------
// Hook integrity checking
// ---------------------------------------------------------------------------

/// Check if hooks are current; if not, regenerate them.
fn ensure_hooks_current() -> bool {
    ensure_hooks_current_at(&installer::default_base_dir())
}

/// Testable version that accepts a base directory.
///
/// Two-level check:
/// 1. Version mismatch → regenerate
/// 2. Version match but content hash mismatch → regenerate (T2 attack detection)
pub(crate) fn ensure_hooks_current_at(base_dir: &Path) -> bool {
    ensure_hooks_current_at_with_verifier_and_exe(base_dir, installer::verify_hook_contract, None)
}

/// Sentinel used to throttle repeated hook regeneration attempts (#349 code
/// review): `run_shim()` calls `ensure_hooks_current_at()` on every single
/// shimmed command, and without this, a persistently-failing resolved exe
/// would make every `rm`/`git`/etc. re-spawn the contract probe (up to
/// `HOOK_CONTRACT_TIMEOUT`, 2s) indefinitely until the user runs
/// `install --hooks`. Mirrors `should_emit_audit_warning_at`'s mtime-sentinel
/// pattern below.
fn hook_verify_throttle_path(base_dir: &Path) -> PathBuf {
    base_dir.join(".hook_verify_failed_at")
}

fn hook_verify_recently_failed_at(path: &Path) -> bool {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_file()
        && let Ok(mtime) = meta.modified()
        && let Ok(elapsed) = mtime.elapsed()
    {
        return elapsed.as_secs() < 300;
    }
    false
}

fn touch_hook_verify_throttle(base_dir: &Path) {
    let path = hook_verify_throttle_path(base_dir);
    let _ = crate::atomic_file::atomic_write_with_mode(&path, b"", 0o600);
}

fn clear_hook_verify_throttle(base_dir: &Path) {
    let _ = std::fs::remove_file(hook_verify_throttle_path(base_dir));
}

/// `ensure_hooks_current_at()` with an injectable contract verifier (#349)
/// and resolved exe path (#354), so tests can exercise the version/hash-
/// mismatch → regen path without the production verifier rejecting the test
/// binary as a non-omamori exe, and without the #354 dev-build check
/// rejecting the test binary's own `current_exe()` (always a
/// `target/debug`/`target/release` path under `cargo test`) before a test
/// gets to what it's actually exercising. `exe_override: None` is production
/// behavior (real `current_exe()` resolution); `Some(path)` lets tests
/// substitute a stable synthetic path.
fn ensure_hooks_current_at_with_verifier_and_exe(
    base_dir: &Path,
    verify: installer::HookVerifier,
    exe_override: Option<&Path>,
) -> bool {
    let hook_path = base_dir.join("hooks/claude-pretooluse.sh");

    let content = match std::fs::read_to_string(&hook_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let regen = |base_dir: &Path| -> Result<installer::HookOutcome, std::io::Error> {
        match exe_override {
            Some(exe) => installer::regenerate_hooks_for_exe(base_dir, exe, verify),
            None => installer::regenerate_hooks_with_verifier(base_dir, verify),
        }
    };

    let hook_version = installer::parse_hook_version(&content);
    let version_matches = hook_version == Some(env!("CARGO_PKG_VERSION"));

    if !version_matches {
        if hook_verify_recently_failed_at(&hook_verify_throttle_path(base_dir)) {
            return false;
        }

        let current = hook_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match regen(base_dir) {
            Ok(installer::HookOutcome::Written) => {
                clear_hook_verify_throttle(base_dir);
                eprintln!(
                    "omamori: hooks updated ({} → {})",
                    current,
                    env!("CARGO_PKG_VERSION")
                );
                return true;
            }
            Ok(installer::HookOutcome::KeptExisting(_)) => {
                // regenerate_hooks_with_verifier already printed a warning
                // distinguishing the specific reason; nothing more to say here.
                touch_hook_verify_throttle(base_dir);
            }
            Err(e) => {
                touch_hook_verify_throttle(base_dir);
                eprintln!(
                    "omamori: failed to update hooks ({}). Run: omamori install --hooks",
                    e
                );
            }
        }
        return false;
    }

    // Level 2: content hash check (T2 attack detection)
    let omamori_exe = match exe_override {
        Some(exe) => exe.to_path_buf(),
        None => match installer::resolved_current_omamori_exe() {
            Ok(exe) => exe,
            Err(_) => {
                // Cannot resolve exe — skip hash check rather than falling back to bare name
                return false;
            }
        },
    };
    let expected = installer::render_hook_script(&omamori_exe);
    let expected_hash = installer::hook_content_hash(&expected);
    let actual_hash = installer::hook_content_hash(&content);

    if expected_hash != actual_hash {
        if hook_verify_recently_failed_at(&hook_verify_throttle_path(base_dir)) {
            return false;
        }

        match regen(base_dir) {
            Ok(installer::HookOutcome::Written) => {
                clear_hook_verify_throttle(base_dir);
                eprintln!("omamori: hooks content mismatch detected — regenerated");
                return true;
            }
            Ok(installer::HookOutcome::KeptExisting(_)) => {
                // regenerate_hooks_with_verifier already printed a warning
                // distinguishing the specific reason; nothing more to say here.
                touch_hook_verify_throttle(base_dir);
            }
            Err(e) => {
                touch_hook_verify_throttle(base_dir);
                eprintln!(
                    "omamori: failed to regenerate hooks ({}). Run: omamori install --hooks",
                    e
                );
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Claude Code settings.json auto-sync (#196, UX R3)
// ---------------------------------------------------------------------------

/// Check if `~/.claude/settings.json` is current; if not, re-merge omamori entry.
fn ensure_settings_current() -> bool {
    ensure_settings_current_at(&installer::default_base_dir())
}

/// Testable version that accepts a base directory.
///
/// Two re-sync triggers:
/// 1. omamori entry's `x-omamori-version` field != current omamori version
///    (set when the schema or hook semantics change between releases)
/// 2. omamori entry's `matcher` is in legacy form (silently rejected by the
///    current Claude Code parser — would leave Layer 2 dormant)
///
/// On either trigger, calls `merge_claude_settings()` to re-merge the entry
/// in the current schema (UX R3: brew-upgrade auto-sync).
///
/// Returns `true` only when a re-merge was performed and produced an outcome
/// other than `AlreadyPresent`. Read errors, parse errors, and "Claude Code
/// not installed" all return `false` — recovery is the install command's
/// responsibility, not the shim's.
pub(crate) fn ensure_settings_current_at(base_dir: &Path) -> bool {
    let Some(claude_dir) = installer::claude_home_dir() else {
        return false; // HOME unset — Claude Code not detected
    };
    ensure_settings_current_for(base_dir, &claude_dir)
}

/// Inner implementation that takes `claude_dir` explicitly. Test entry point.
pub(crate) fn ensure_settings_current_for(base_dir: &Path, claude_dir: &Path) -> bool {
    if !installer::is_real_directory(claude_dir) {
        return false;
    }
    let settings_path = claude_dir.join("settings.json");
    let raw = match std::fs::read_to_string(&settings_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Determine resync need:
    //   1. omamori entry missing → resync
    //   2. entry present but version stale or matcher legacy → resync
    //   3. multiple omamori entries (stale accumulation) → resync
    //   4. entry present and current, exactly 1 → no-op
    let needs_resync = match doc.pointer("/hooks/PreToolUse").and_then(|v| v.as_array()) {
        Some(arr) => {
            let omamori_entries: Vec<&serde_json::Value> = arr
                .iter()
                .filter(|e| installer::is_omamori_entry_any_root(e, base_dir))
                .collect();
            match omamori_entries.len() {
                0 => true,
                1 => {
                    let e = omamori_entries[0];
                    let version = e
                        .get("x-omamori-version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let matcher = e.get("matcher").and_then(|v| v.as_str()).unwrap_or("");
                    let expected_script = base_dir.join("hooks/claude-pretooluse.sh");
                    let path_current = installer::entry_is_omamori_managed(e, base_dir)
                        || e.get("hooks")
                            .and_then(|v| v.as_array())
                            .into_iter()
                            .flatten()
                            .filter_map(|h| h.get("command").and_then(|v| v.as_str()))
                            .any(|c| {
                                let u = c.trim_matches('\'').trim_matches('"');
                                Path::new(u) == expected_script
                            });
                    version != env!("CARGO_PKG_VERSION") || matcher != "Bash" || !path_current
                }
                _ => true, // multiple entries → stale accumulation, force cleanup
            }
        }
        None => true,
    };

    if !needs_resync {
        return false;
    }

    let script_path = base_dir.join("hooks/claude-pretooluse.sh");
    match installer::merge_claude_settings(claude_dir, &script_path) {
        Ok(installer::ClaudeSettingsOutcome::AlreadyPresent) => false,
        Ok(installer::ClaudeSettingsOutcome::Skipped(reason)) => {
            eprintln!("omamori: failed to auto-sync Claude settings ({reason})");
            false
        }
        Ok(installer::ClaudeSettingsOutcome::StaleEntriesCleaned(n)) => {
            eprintln!("omamori: cleaned {n} stale hook(s) from Claude settings");
            true
        }
        Ok(_) => {
            eprintln!(
                "omamori: Claude settings auto-synced to v{}",
                env!("CARGO_PKG_VERSION")
            );
            true
        }
        Err(e) => {
            eprintln!("omamori: failed to auto-sync Claude settings ({e})");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Audit append helper
// ---------------------------------------------------------------------------

/// Lives under the base dir (`~/.omamori`), not the audit data dir
/// (`~/.local/share/omamori`) — the warning this throttles fires precisely
/// when the audit data dir is unwritable, so co-locating the sentinel there
/// would make the sentinel itself unwritable in the same failure and the
/// warning would repeat on every shimmed command. Resolves independently of
/// `installer::default_base_dir()` (which still has a `.` CWD fallback,
/// out of scope for this PR) so an unusable `HOME` skips the FS sentinel
/// entirely rather than writing to the CWD.
fn audit_warn_sentinel_path() -> Option<PathBuf> {
    let home = context::home_dir()?;
    Some(home.join(".omamori").join("audit-warn-throttle"))
}

fn should_emit_audit_warning() -> bool {
    match audit_warn_sentinel_path() {
        Some(p) => should_emit_audit_warning_at(&p),
        None => true,
    }
}

fn should_emit_audit_warning_at(path: &Path) -> bool {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return true;
        }
        if let Ok(mtime) = meta.modified()
            && let Ok(elapsed) = mtime.elapsed()
            && elapsed.as_secs() < 300
        {
            return false;
        }
    }

    touch_audit_warn_sentinel(path);
    true
}

/// Writes via `atomic_file::atomic_write_with_mode` (#322-class: this sentinel
/// had the same predictable-temp-name + `create(true)` race as the heartbeat
/// writer before #307). Content is empty — only the mtime matters
/// (`should_emit_audit_warning_at` reads it, never the bytes).
fn touch_audit_warn_sentinel(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let _ = std::fs::create_dir_all(parent);
    let _ = crate::atomic_file::atomic_write_with_mode(path, b"", 0o600);
}

/// Attempt to append an audit event. On failure:
/// - In strict mode, always emits error + returns `Some(1)` to block
/// - In non-strict mode, emits a 1-line warning at most once per 5 minutes
pub(crate) fn try_audit_append(
    logger: &AuditLogger,
    event: crate::audit::AuditEvent,
    strict: bool,
) -> Option<i32> {
    if let Err(e) = logger.append(event) {
        if strict {
            eprintln!("omamori error: audit strict mode — blocking because audit log is required");
            eprintln!("  audit log write failed: {e}");
            return Some(1);
        }
        if should_emit_audit_warning() {
            eprintln!("omamori warning: audit log write failed — run 'omamori doctor' to diagnose");
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Baseline helper
// ---------------------------------------------------------------------------

/// Silently update integrity baseline. Used after hook regen or config changes.
pub(crate) fn update_baseline_silent(base_dir: &Path) {
    match integrity::generate_baseline(base_dir) {
        Ok(baseline) => {
            if let Err(e) = integrity::write_baseline(base_dir, &baseline) {
                eprintln!("omamori[health]: failed to update baseline: {e}");
            }
        }
        Err(e) => {
            eprintln!("omamori[health]: failed to generate baseline: {e}");
        }
    }
}

pub(crate) fn emit_config_warnings(load_result: &ConfigLoadResult) {
    for warning in &load_result.warnings {
        eprintln!("omamori warning: {warning}");
    }
}

// ---------------------------------------------------------------------------
// Core command execution pipeline
// ---------------------------------------------------------------------------

pub(crate) fn run_command(
    program: String,
    args: &[OsString],
    config_path: Option<&Path>,
) -> Result<i32, AppError> {
    let load_result = load_config(config_path)?;
    emit_config_warnings(&load_result);

    // Collect process provenance (#420) as early as possible, before any
    // child process runs — the real parent (the AI CLI or shell that
    // invoked this shim) is only guaranteed to still be alive at this
    // point; a dead parent can be reparented to launchd (ppid=1) by the
    // time a later call site would otherwise collect it. Gated on audit
    // being enabled: when it's off, every guarded command on the machine
    // would otherwise pay the collection syscalls for no benefit.
    let provenance = load_result
        .config
        .audit
        .enabled
        .then(crate::audit::provenance::ProcessProvenance::collect);

    let invocation =
        CommandInvocation::new(program.clone(), args.iter().map(clone_lossy).collect());
    let env_pairs = env::vars().collect::<Vec<_>>();
    let detection = evaluate_detectors(&load_result.config.detectors, &env_pairs);

    // Sudo check: always evaluated, regardless of AI detection.
    if should_block_for_sudo() {
        let outcome = ActionOutcome::Blocked {
            message:
                "omamori blocked this command because it was invoked via sudo/elevated privileges"
                    .to_string(),
        };
        eprintln!("{}", outcome.message());
        for warning in &detection.warnings {
            eprintln!("omamori warning: {warning}");
        }
        if let Some(logger) = AuditLogger::from_config(&load_result.config.audit) {
            let event = logger.create_event(
                &invocation,
                None,
                &detection.matched_detectors,
                &outcome,
                provenance.as_ref(),
            );
            if let Some(code) = try_audit_append(&logger, event, load_result.config.audit.strict) {
                return Ok(code);
            }
        }
        return Ok(outcome.exit_code());
    }

    // Non-protected fast path: no AI environment detected = human terminal.
    if !detection.protected {
        let resolved = resolve_real_command(&program)?;
        let status = std::process::Command::new(&resolved)
            .args(&invocation.args)
            .status()?;
        let exit_code = actions::exit_code_from_status(status);
        let outcome = ActionOutcome::PassedThrough { exit_code };
        for warning in &detection.warnings {
            eprintln!("omamori warning: {warning}");
        }
        if let Some(logger) = AuditLogger::from_config(&load_result.config.audit) {
            let event = logger.create_event(
                &invocation,
                None,
                &detection.matched_detectors,
                &outcome,
                provenance.as_ref(),
            );
            if let Some(code) = try_audit_append(&logger, event, load_result.config.audit.strict) {
                return Ok(code);
            }
        }
        return Ok(exit_code);
    }

    // --- Protected path: AI environment detected. Full evaluation. ---

    // Strict mode: block if audit HMAC secret is unavailable
    if load_result.config.audit.strict && load_result.config.audit.enabled {
        match AuditLogger::from_config(&load_result.config.audit) {
            Some(logger) if !logger.secret_available() => {
                eprintln!("omamori: audit strict mode — HMAC secret unavailable, blocking command");
                eprintln!(
                    "omamori: to fix, re-create the secret or set audit.strict = false in config.toml"
                );
                return Ok(1);
            }
            None => {
                eprintln!(
                    "omamori: audit strict mode — audit logger unavailable, blocking command"
                );
                return Ok(1);
            }
            _ => {}
        }
    }

    let matched_rule = match_rule(&load_result.config.rules, &invocation);
    let detector_env_keys: Vec<String> = load_result
        .config
        .detectors
        .iter()
        .map(|d| d.env_key.clone())
        .filter(|k| !k.is_empty() && !k.contains('='))
        .collect();

    // Context-aware evaluation
    let context_override: Option<RuleConfig> = if let (Some(rule), Some(ctx_config)) =
        (matched_rule, &load_result.config.context)
    {
        // Tier 1: path-based evaluation
        let ctx = context::evaluate_context(&invocation, rule, ctx_config);
        let tier1_override = if let Some(override_action) = ctx.action_override {
            eprintln!(
                "omamori: {} {} → {} ({}, original: {})",
                invocation.program,
                invocation.target_args().join(" "),
                override_action.as_str(),
                ctx.reason,
                rule.action.as_str(),
            );
            let mut overridden = rule.clone();
            overridden.message = Some(override_action.context_message(&ctx.reason));
            overridden.action = override_action;
            Some(overridden)
        } else {
            if !ctx.reason.contains("no target paths") && !ctx.reason.contains("no context pattern")
            {
                eprintln!("omamori warning: {}", ctx.reason);
            }
            None
        };

        // Tier 2: git-aware evaluation
        let is_escalated = tier1_override
            .as_ref()
            .is_some_and(|r| matches!(r.action, rules::ActionKind::Block));

        if !is_escalated {
            if let Some(git_ctx) =
                context::evaluate_git_context(&invocation, &ctx_config.git, &detector_env_keys)
            {
                if let Some(git_action) = git_ctx.action_override {
                    eprintln!(
                        "omamori: {} {} → {} ({}, original: {})",
                        invocation.program,
                        invocation.args.join(" "),
                        git_action.as_str(),
                        git_ctx.reason,
                        rule.action.as_str(),
                    );
                    let mut overridden = rule.clone();
                    overridden.message = Some(git_action.context_message(&git_ctx.reason));
                    overridden.action = git_action;
                    Some(overridden)
                } else {
                    if !git_ctx.reason.contains("skipping") {
                        eprintln!("omamori: {}", git_ctx.reason);
                    }
                    tier1_override
                }
            } else {
                tier1_override
            }
        } else {
            tier1_override
        }
    } else {
        None
    };

    let effective_rule = match (&context_override, matched_rule) {
        (Some(overridden), _) => Some(overridden),
        (None, Some(rule)) => Some(rule),
        _ => None,
    };

    let resolved_program = resolve_real_command(&program)?;
    let mut executor =
        ActionExecutor::new(SystemOps::new(resolved_program, detector_env_keys.clone()));

    let outcome = if let Some(rule) = effective_rule {
        // Break-glass: if rule is bypassed, skip enforcement and pass through
        if crate::break_glass::is_bypassed(&rule.name) {
            eprintln!(
                "omamori: break-glass bypass active for '{}' — executing without protection",
                rule.name
            );
            // Audit the bypass
            if let Some(logger) = AuditLogger::from_config(&load_result.config.audit) {
                let provider = detection
                    .matched_detectors
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "none".to_string());
                let event = crate::cli::break_glass_cmd::create_bypass_event(
                    &rule.name,
                    &invocation.program,
                    &provider,
                    "layer1:break-glass",
                    provenance.as_ref(),
                    logger.secret_ref(),
                );
                if let Some(code) =
                    try_audit_append(&logger, event, load_result.config.audit.strict)
                {
                    return Ok(code);
                }
            }
            executor.exec_passthrough(&invocation)?
        } else {
            let outcome = executor.execute(&invocation, rule)?;
            match &outcome {
                ActionOutcome::Blocked { .. } | ActionOutcome::Failed { .. } => {
                    eprintln!("{}", outcome.message());
                    let explain_cmd = format_explain_hint(&invocation);
                    eprintln!("  hint: run `{explain_cmd}` for details");
                    eprintln!(
                        "  hint: false positive? run `omamori break-glass --rule {}` to bypass for 1h",
                        rule.name
                    );
                }
                ActionOutcome::Trashed { message, .. } | ActionOutcome::MovedTo { message, .. } => {
                    eprintln!("{message}");
                }
                _ => {}
            }
            outcome
        }
    } else {
        executor.exec_passthrough(&invocation)?
    };

    for warning in &detection.warnings {
        eprintln!("omamori warning: {warning}");
    }

    if let Some(logger) = AuditLogger::from_config(&load_result.config.audit) {
        let event = logger.create_event(
            &invocation,
            effective_rule,
            &detection.matched_detectors,
            &outcome,
            provenance.as_ref(),
        );
        if let Some(code) = try_audit_append(&logger, event, load_result.config.audit.strict) {
            return Ok(code);
        }
    }

    Ok(outcome.exit_code())
}

/// Format `omamori explain -- <program> <args...>` hint for block messages.
fn format_explain_hint(invocation: &CommandInvocation) -> String {
    let args_str = if invocation.args.is_empty() {
        String::new()
    } else {
        format!(" {}", shell_words::join(&invocation.args))
    };
    format!("omamori explain -- {}{}", invocation.program, args_str)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn setup_hooks_dir(base_dir: &Path) -> PathBuf {
        let hooks_dir = base_dir.join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        hooks_dir
    }

    /// A stable, non-dev-build synthetic exe path for `exe_override` (#354).
    /// The test binary's own `current_exe()` is itself always a
    /// `target/debug`/`target/release` path under `cargo test`, which would
    /// trip the #354 rejection before these tests get to what they're
    /// actually exercising (version/hash-mismatch regen, throttling, etc.).
    fn fake_stable_exe() -> PathBuf {
        PathBuf::from("/opt/homebrew/bin/omamori")
    }

    // --- G-02: ensure_hooks_current_at ---

    #[test]
    fn hooks_current_old_version_triggers_regen() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        // #349: the test binary is never a genuine omamori binary, so the
        // production verifier would always reject it — inject a passing stub
        // to exercise the version-mismatch → regen path in isolation.
        // #354: also inject a stable exe path — the test binary's own
        // current_exe() would otherwise trip the dev-build rejection.
        let result = ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            |_, _| installer::HookContractStatus::Ok,
            Some(&fake_stable_exe()),
        );
        assert!(result, "should regenerate hooks for old version");

        let content = std::fs::read_to_string(hooks_dir.join("claude-pretooluse.sh")).unwrap();
        assert_eq!(
            installer::parse_hook_version(&content),
            Some(env!("CARGO_PKG_VERSION"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_old_version_not_reported_as_updated_when_verification_fails() {
        // #349 Codex Round 1 P0: `regenerate_hooks_with_verifier`'s `Ok(())`
        // covers both "regenerated" and "verification failed, kept the old
        // hook" — this must not be reported as a successful update.
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-1b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        let result = ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            |_, _| installer::HookContractStatus::ExitNonZero(1),
            Some(&fake_stable_exe()),
        );
        assert!(
            !result,
            "must not report success when the resolved exe fails verification"
        );

        let content = std::fs::read_to_string(hooks_dir.join("claude-pretooluse.sh")).unwrap();
        assert_eq!(
            content, old_hook,
            "old hook must be left untouched when verification fails"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_throttles_repeated_verification_after_recent_failure() {
        // #349 code review: a persistently-failing resolved exe must not
        // force every subsequent shimmed command to re-pay the probe's cost.
        // A verifier that increments a counter on every call lets us assert
        // the second `ensure_hooks_current_at_with_verifier_and_exe` call
        // within the throttle window skips the expensive path entirely.
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn counting_failing_verifier(
            _exe: &Path,
            _timeout: std::time::Duration,
        ) -> installer::HookContractStatus {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            installer::HookContractStatus::ExitNonZero(1)
        }

        let dir =
            std::env::temp_dir().join(format!("omamori-hooks-throttle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);
        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        assert!(!ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            counting_failing_verifier,
            Some(&fake_stable_exe())
        ));
        assert_eq!(
            CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "first call must invoke the verifier"
        );

        assert!(!ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            counting_failing_verifier,
            Some(&fake_stable_exe())
        ));
        assert_eq!(
            CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second call within the throttle window must NOT invoke the verifier again"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_hash_mismatch_triggers_regen() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let tampered = format!(
            "#!/bin/sh\n# omamori hook v{}\nset -eu\nexit 0\n",
            env!("CARGO_PKG_VERSION")
        );
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), tampered).unwrap();

        // #349/#354: see comment in hooks_current_old_version_triggers_regen.
        let result = ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            |_, _| installer::HookContractStatus::Ok,
            Some(&fake_stable_exe()),
        );
        assert!(result, "should regenerate hooks for hash mismatch (T2)");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_hash_mismatch_not_reported_as_updated_when_verification_fails() {
        // #349 Codex Round 1 P0 (hash-mismatch branch counterpart).
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-2b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let tampered = format!(
            "#!/bin/sh\n# omamori hook v{}\nset -eu\nexit 0\n",
            env!("CARGO_PKG_VERSION")
        );
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), &tampered).unwrap();

        let result = ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            |_, _| installer::HookContractStatus::ExitNonZero(1),
            Some(&fake_stable_exe()),
        );
        assert!(
            !result,
            "must not report success when the resolved exe fails verification"
        );

        let content = std::fs::read_to_string(hooks_dir.join("claude-pretooluse.sh")).unwrap();
        assert_eq!(
            content, tampered,
            "existing (tampered) hook must be left untouched when verification fails"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_correct_returns_false() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let omamori_exe = installer::resolved_current_omamori_exe().unwrap();
        let expected = installer::render_hook_script(&omamori_exe);
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), expected).unwrap();

        let result = ensure_hooks_current_at(&dir);
        assert!(!result, "should return false when hooks are current");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_missing_returns_false() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let result = ensure_hooks_current_at(&dir);
        assert!(!result, "should return false when no hooks file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_readonly_dir_regen_fails_returns_false() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hooks_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        // #349/#354: inject a passing verifier and a stable exe path so the
        // failure this test exercises is the readonly-dir I/O error, not
        // contract verification or the dev-build-path rejection.
        let result = ensure_hooks_current_at_with_verifier_and_exe(
            &dir,
            |_, _| installer::HookContractStatus::Ok,
            Some(&fake_stable_exe()),
        );
        assert!(!result, "should return false when regen fails");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hooks_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ADV-01: hooks symlink attack ---

    #[test]
    fn hooks_symlink_attack_triggers_regen() {
        let dir = std::env::temp_dir().join(format!("omamori-adv01-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        #[cfg(unix)]
        {
            let malicious = dir.join("malicious.sh");
            std::fs::write(
                &malicious,
                format!(
                    "#!/bin/sh\n# omamori hook v{}\nexit 0\n",
                    env!("CARGO_PKG_VERSION")
                ),
            )
            .unwrap();

            let hook_path = hooks_dir.join("claude-pretooluse.sh");
            std::os::unix::fs::symlink(&malicious, &hook_path).unwrap();

            // #349/#354: see comment in hooks_current_old_version_triggers_regen.
            let result = ensure_hooks_current_at_with_verifier_and_exe(
                &dir,
                |_, _| installer::HookContractStatus::Ok,
                Some(&fake_stable_exe()),
            );
            assert!(
                result,
                "symlink hook should trigger regeneration due to hash mismatch"
            );

            let content = std::fs::read_to_string(&hook_path).unwrap();
            let expected = installer::render_hook_script(&fake_stable_exe());
            assert_eq!(
                installer::hook_content_hash(&content),
                installer::hook_content_hash(&expected),
                "regenerated hook should match expected content"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- GR-008: try_audit_append strict/non-strict ---

    #[test]
    fn try_audit_append_strict_returns_exit_code_on_failure() {
        let logger = AuditLogger::from_config(&crate::audit::AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("/nonexistent/dir/audit.jsonl")),
            retention_days: 0,
            strict: true,
        });
        if let Some(logger) = logger {
            let event = logger.create_event(
                &CommandInvocation::new("test".to_string(), vec![]),
                None,
                &[],
                &ActionOutcome::PassedThrough { exit_code: 0 },
                None,
            );
            let result = try_audit_append(&logger, event, true);
            assert_eq!(
                result,
                Some(1),
                "strict mode should return Some(1) on append failure"
            );
        }
    }

    #[test]
    fn try_audit_append_non_strict_returns_none_on_failure() {
        let logger = AuditLogger::from_config(&crate::audit::AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("/nonexistent/dir/audit.jsonl")),
            retention_days: 0,
            strict: false,
        });
        if let Some(logger) = logger {
            let event = logger.create_event(
                &CommandInvocation::new("test".to_string(), vec![]),
                None,
                &[],
                &ActionOutcome::PassedThrough { exit_code: 0 },
                None,
            );
            let result = try_audit_append(&logger, event, false);
            assert_eq!(
                result, None,
                "non-strict mode should return None on append failure"
            );
        }
    }

    // --- Audit warning throttle tests (#334) ---

    #[test]
    fn should_emit_first_call_returns_true() {
        let dir =
            std::env::temp_dir().join(format!("omamori-throttle-first-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("audit-warn-throttle");

        assert!(
            should_emit_audit_warning_at(&sentinel),
            "first call should return true (no sentinel)"
        );
        assert!(
            sentinel.exists(),
            "sentinel should be created after first call"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_emit_second_call_within_window_returns_false() {
        let dir =
            std::env::temp_dir().join(format!("omamori-throttle-second-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("audit-warn-throttle");

        let first = should_emit_audit_warning_at(&sentinel);
        assert!(first, "first call should emit");

        let second = should_emit_audit_warning_at(&sentinel);
        assert!(
            !second,
            "second call within 5min window should be suppressed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn throttle_sentinel_symlink_degrades_open() {
        let dir = std::env::temp_dir().join(format!("omamori-throttle-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sentinel = dir.join("audit-warn-throttle");
        let target = dir.join("evil-target");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &sentinel).unwrap();
            assert!(
                should_emit_audit_warning_at(&sentinel),
                "symlink sentinel must degrade-open (return true = emit warning)"
            );
            assert!(
                !target.exists(),
                "symlink attack: target file must not be created"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn audit_warn_sentinel_path_none_when_home_unusable() {
        assert_eq!(
            crate::test_support::with_home(Some(""), audit_warn_sentinel_path),
            None
        );
        assert_eq!(
            crate::test_support::with_home(Some("relative/path"), audit_warn_sentinel_path),
            None
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn audit_warn_sentinel_path_lives_under_base_dir_not_data_dir() {
        let path = crate::test_support::with_home(
            Some("/tmp/omamori-sentinel-base-dir-test"),
            audit_warn_sentinel_path,
        )
        .expect("absolute HOME must resolve");
        assert_eq!(
            path,
            PathBuf::from("/tmp/omamori-sentinel-base-dir-test/.omamori/audit-warn-throttle")
        );
    }

    #[test]
    fn audit_warn_sentinel_and_hook_verify_throttle_filenames_do_not_collide() {
        let base_dir = std::path::Path::new("/tmp/irrelevant-base");
        let hook_verify_path = hook_verify_throttle_path(base_dir);
        assert_ne!(
            hook_verify_path.file_name(),
            Some(std::ffi::OsStr::new("audit-warn-throttle")),
            "sentinel filenames sharing a directory must not collide"
        );
    }

    // ---------------------------------------------------------------------
    // ensure_settings_current_for tests (#196 UX R3)
    // ---------------------------------------------------------------------

    #[test]
    fn ensure_settings_skips_when_claude_dir_missing() {
        let dir =
            std::env::temp_dir().join(format!("omamori-shim-no-claude-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let claude_dir = dir.join("does-not-exist");
        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(!result);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ensure_settings_skips_when_settings_missing() {
        let dir =
            std::env::temp_dir().join(format!("omamori-shim-no-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(!result);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn ensure_settings_resyncs_on_legacy_matcher() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        std::fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let stale = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": omamori_cmd}]
                }]
            }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();

        // The shim resolves script_path from <base_dir>/hooks/...
        let base_hooks = dir.join("hooks");
        std::fs::create_dir_all(&base_hooks).unwrap();
        std::fs::write(
            base_hooks.join("claude-pretooluse.sh"),
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(result, "should re-sync when matcher is legacy");

        let raw = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse/0/matcher")
                .and_then(|v| v.as_str()),
            Some("Bash")
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn ensure_settings_resyncs_when_entry_missing() {
        // P1-1 (Codex R1): if settings.json exists with user hooks but no
        // omamori entry, the shim must merge one in, not silently no-op.
        let dir = std::env::temp_dir().join(format!("omamori-shim-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join("hooks");
        std::fs::create_dir_all(&omamori_hooks).unwrap();
        std::fs::write(
            omamori_hooks.join("claude-pretooluse.sh"),
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();

        // settings.json exists with only a user hook (no omamori)
        let user_doc = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Edit",
                    "hooks": [{ "type": "command", "command": "/usr/local/bin/userhook" }]
                }]
            }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&user_doc).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        // base_dir = dir, so omamori install root used by entry detection is `dir`
        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(result, "must resync when omamori entry is missing");

        // Verify the omamori entry was added (and user entry preserved)
        let raw = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2, "user entry + new omamori entry");

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn ensure_settings_returns_false_on_skipped() {
        // P1-3 (Codex R1): merge result Skipped (e.g. symlink target) must NOT
        // be reported as a successful re-sync.
        let dir = std::env::temp_dir().join(format!("omamori-shim-skipped-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Symlink settings.json — merge_claude_settings will return Skipped
        let real = dir.join("real-settings.json");
        // Stale entry to trigger needs_resync
        let stale = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "*",
                    "hooks": [{ "type": "command", "command": format!("{}/hooks/x.sh", dir.display()) }]
                }]
            }
        });
        std::fs::write(&real, serde_json::to_string_pretty(&stale).unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, claude_dir.join("settings.json")).unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(!result, "Skipped outcome must return false (not success)");

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn ensure_settings_no_op_when_current() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-current-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        std::fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let current = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": omamori_cmd}],
                    "x-omamori-version": env!("CARGO_PKG_VERSION")
                }]
            }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&current).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(!result, "should be a no-op when settings are current");

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // V-006: Shim resyncs when multiple omamori entries exist (stale accumulation)
    #[test]
    #[serial_test::serial(home_env)]
    fn ensure_settings_resyncs_when_multiple_entries() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-multi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join("hooks");
        std::fs::create_dir_all(&omamori_hooks).unwrap();
        std::fs::write(
            omamori_hooks.join("claude-pretooluse.sh"),
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();

        let current_entry =
            installer::claude_settings_entry(&omamori_hooks.join("claude-pretooluse.sh"));
        let stale_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/old/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [current_entry, stale_entry] }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let result = ensure_settings_current_for(&dir, &claude_dir);
        assert!(result, "must resync when multiple omamori entries exist");

        let raw = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let after: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            arr.len(),
            1,
            "only canonical entry should remain after cleanup"
        );
        let remaining = &arr[0];
        let remaining_ver = remaining
            .get("x-omamori-version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            remaining_ver,
            env!("CARGO_PKG_VERSION"),
            "surviving entry must be current version"
        );
        let remaining_cmd = remaining
            .pointer("/hooks/0/command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            remaining_cmd.contains(&dir.display().to_string()),
            "surviving entry must point to current base_dir, got: {remaining_cmd}"
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // --- Heartbeat ---

    fn heartbeat_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omamori-hb-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn heartbeat_path_points_to_data_dir() {
        // Reads ambient HOME directly — tagged so it can't observe a
        // torn/transient value from a concurrent HOME-mutating test
        // elsewhere in this file (#344-class flake).
        let path = heartbeat_path().expect("HOME should be set in test environment");
        let home = env::var("HOME").unwrap();
        let expected_suffix = ".local/share/omamori/heartbeat";
        assert!(path.starts_with(&home), "heartbeat should be under HOME");
        assert!(
            path.ends_with(expected_suffix),
            "heartbeat path should end with {expected_suffix}, got {}",
            path.display()
        );
    }

    #[test]
    fn heartbeat_creates_file_with_permissions() {
        let dir = heartbeat_test_dir("create");
        let path = dir.join("heartbeat");

        touch_heartbeat_at(&path);

        assert!(path.exists(), "heartbeat file should be created");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "heartbeat should have 0600 permissions");
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed =
            time::OffsetDateTime::parse(&content, &time::format_description::well_known::Rfc3339);
        assert!(parsed.is_ok(), "content must be valid RFC 3339: {content}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_skips_same_utc_day() {
        let dir = heartbeat_test_dir("skip");
        let path = dir.join("heartbeat");

        touch_heartbeat_at(&path);
        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        touch_heartbeat_at(&path);
        let mtime2 = std::fs::metadata(&path).unwrap().modified().unwrap();

        assert_eq!(mtime1, mtime2, "mtime should not change on same UTC day");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn heartbeat_rejects_symlink() {
        let dir = heartbeat_test_dir("symlink");
        let target = dir.join("decoy");
        std::fs::write(&target, "original").unwrap();
        let path = dir.join("heartbeat");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        touch_heartbeat_at(&path);

        assert!(
            path.symlink_metadata().unwrap().file_type().is_symlink(),
            "symlink must still exist (not replaced by regular file)"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "symlink target must not be overwritten"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_overwrites_future_mtime() {
        use std::fs::FileTimes;

        let dir = heartbeat_test_dir("future");
        let path = dir.join("heartbeat");

        touch_heartbeat_at(&path);

        let future =
            std::time::SystemTime::now() + std::time::Duration::from_secs(86400 * 365 * 10);
        let times = FileTimes::new().set_modified(future);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        touch_heartbeat_at(&path);

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_ne!(
            mtime_before, mtime_after,
            "future mtime should trigger overwrite"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_overwrites_old_mtime() {
        use std::fs::FileTimes;

        let dir = heartbeat_test_dir("old");
        let path = dir.join("heartbeat");

        touch_heartbeat_at(&path);

        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(86400 * 5);
        let times = FileTimes::new().set_modified(past);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        touch_heartbeat_at(&path);

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_ne!(
            mtime_before, mtime_after,
            "old mtime should trigger overwrite"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn heartbeat_silent_on_read_only_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = heartbeat_test_dir("readonly");
        let ro_dir = dir.join("ro");
        std::fs::create_dir_all(&ro_dir).unwrap();
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let path = ro_dir.join("heartbeat");
        touch_heartbeat_at(&path);

        assert!(!path.exists(), "should not create file in read-only dir");

        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_skips_directory_at_path() {
        let dir = heartbeat_test_dir("isdir");
        let path = dir.join("heartbeat");
        std::fs::create_dir_all(&path).unwrap();

        touch_heartbeat_at(&path);

        assert!(path.is_dir(), "directory should remain a directory");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_handles_corrupt_content() {
        let dir = heartbeat_test_dir("corrupt");
        let path = dir.join("heartbeat");

        std::fs::create_dir_all(dir.as_path()).unwrap();
        std::fs::write(&path, "not-a-date").unwrap();

        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(86400 * 2);
        let times = std::fs::FileTimes::new().set_modified(past);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        touch_heartbeat_at(&path);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("T"),
            "corrupt content with old mtime should be overwritten"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- #420: process provenance actually reaches the audit log ---
    //
    // Every other provenance test in this codebase exercises create_event /
    // create_bypass_event directly — none of them drive run_command() itself,
    // so none of them can catch a dropped `provenance.as_ref()` at one of its
    // four real call sites (a proxy adversarial review flagged this: silently
    // changing shim.rs's Layer 1 block-path call site to pass `None` left
    // every other test in the suite green). These tests close that gap by
    // running the real end-to-end pipeline and reading back audit.jsonl.

    /// Shared setup for the two provenance-wiring tests below: writes a
    /// 0600 config.toml with audit enabled under `dir` (load_config()
    /// silently falls back to Config::default() — dropping the `[audit]`
    /// section entirely — for anything looser than 0600), points `HOME` at
    /// `dir`, sets or clears `CLAUDECODE` per `ai_detected` to select
    /// run_command's protected vs. fast path, runs it, restores both env
    /// vars, and returns the last audit.jsonl entry.
    fn run_command_and_read_last_audit_event(
        dir: &Path,
        ai_detected: bool,
        program: &str,
        args: &[OsString],
    ) -> serde_json::Value {
        let audit_path = dir.join("audit.jsonl");
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[audit]\nenabled = true\npath = \"{}\"\n",
                audit_path.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        let saved_home = std::env::var_os("HOME");
        let saved_claudecode = std::env::var_os("CLAUDECODE");
        unsafe {
            std::env::set_var("HOME", dir);
            if ai_detected {
                std::env::set_var("CLAUDECODE", "1");
            } else {
                std::env::remove_var("CLAUDECODE");
            }
        }

        let result = run_command(program.to_string(), args, Some(&config_path));

        match saved_home {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match saved_claudecode {
            Some(v) => unsafe { std::env::set_var("CLAUDECODE", v) },
            None => unsafe { std::env::remove_var("CLAUDECODE") },
        }

        assert!(result.is_ok(), "run_command must not error: {result:?}");

        let content = std::fs::read_to_string(&audit_path)
            .expect("run_command must have appended an audit entry");
        let last_line = content
            .lines()
            .next_back()
            .expect("audit log must have at least one entry");
        serde_json::from_str(last_line).unwrap()
    }

    #[test]
    #[serial_test::serial(home_env, ai_env)]
    fn run_command_wires_provenance_into_the_layer1_block_audit_event() {
        let dir = std::env::temp_dir().join(format!(
            "omamori-shim-provenance-wiring-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // `rm -rf /` matches a default core rule and is Blocked — the
        // executor never spawns a real process for a Blocked outcome, so
        // this is safe to actually run through run_command(). AI-detected
        // env drives the protected path (shim.rs:741) — the one this
        // incident's #420 fields actually matter for.
        let event = run_command_and_read_last_audit_event(
            &dir,
            true,
            "rm",
            &[OsString::from("-rf"), OsString::from("/")],
        );

        // Sanity: confirm this really is the blocked rm event, not some
        // unrelated entry, before trusting its provenance fields.
        // `AuditEvent.command` stores only the program name, not argv.
        assert_eq!(event["command"], "rm");
        assert!(
            event.get("rule_id").and_then(|v| v.as_str()).is_some(),
            "expected a matched core rule (blocked outcome), got: {event}"
        );
        assert!(
            event.get("pid").and_then(|v| v.as_u64()).is_some(),
            "Layer 1 audit event must carry real process provenance (pid) \
             — got: {event}"
        );
        assert!(
            event.get("ppid").is_some(),
            "Layer 1 audit event must carry the ppid field (key present, \
             even if the OS call happens to return null) — got: {event}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex proxy review Round 1 (P1): the block-path test above only
    /// covers shim.rs:741 (protected path). shim.rs:564 (the non-protected
    /// "human terminal" fast path — a distinct `create_event` call site
    /// with its own `provenance.as_ref()`) had no positive test either.
    #[test]
    #[serial_test::serial(home_env, ai_env)]
    fn run_command_wires_provenance_into_the_layer1_fast_path_audit_event() {
        let dir = std::env::temp_dir().join(format!(
            "omamori-shim-provenance-fastpath-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // `true` always exits 0 and is safe to actually run. No AI CLI
        // detected drives the fast (non-protected) path (shim.rs:564).
        let event = run_command_and_read_last_audit_event(&dir, false, "true", &[]);

        assert_eq!(event["command"], "true");
        assert_eq!(
            event["action"], "passthrough",
            "sanity: the non-protected fast path always passes through, got: {event}"
        );
        assert!(
            event.get("pid").and_then(|v| v.as_u64()).is_some(),
            "Layer 1 fast-path audit event must carry real process provenance (pid) \
             — got: {event}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
