//! PATH shim execution, command evaluation pipeline, and hook integrity.
//!
//! `run_command` is the core evaluation pipeline that orchestrates:
//! detector → rules → context → action → audit.

use std::env;
use std::ffi::OsString;
use std::path::Path;

use crate::AppError;
use crate::actions::{self, ActionExecutor, ActionOutcome, SystemOps};
use crate::audit::AuditLogger;
use crate::config::{ConfigLoadResult, load_config};
use crate::context;
use crate::detector::evaluate_detectors;
use crate::installer;
use crate::integrity;
use crate::rules::{self, CommandInvocation, RuleConfig, match_rule};
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

    // Step 3: If hooks were regenerated or Codex was set up, update baseline
    if hooks_regenerated || codex_setup {
        update_baseline_silent(&base_dir);
    }

    // Step 4: Run the actual command
    run_command(program.to_string(), args, None)
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
    let hook_path = base_dir.join("hooks/claude-pretooluse.sh");

    let content = match std::fs::read_to_string(&hook_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let hook_version = installer::parse_hook_version(&content);
    let version_matches = hook_version == Some(env!("CARGO_PKG_VERSION"));

    if !version_matches {
        let current = hook_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match installer::regenerate_hooks(base_dir) {
            Ok(()) => {
                eprintln!(
                    "omamori: hooks updated ({} → {})",
                    current,
                    env!("CARGO_PKG_VERSION")
                );
                return true;
            }
            Err(e) => {
                eprintln!(
                    "omamori: failed to update hooks ({}). Run: omamori install --hooks",
                    e
                );
            }
        }
        return false;
    }

    // Level 2: content hash check (T2 attack detection)
    let expected = installer::render_hook_script();
    let expected_hash = installer::hook_content_hash(&expected);
    let actual_hash = installer::hook_content_hash(&content);

    if expected_hash != actual_hash {
        match installer::regenerate_hooks(base_dir) {
            Ok(()) => {
                eprintln!("omamori: hooks content mismatch detected — regenerated");
                return true;
            }
            Err(e) => {
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
// Audit append helper
// ---------------------------------------------------------------------------

/// Attempt to append an audit event. On failure:
/// - Always emits a WARNING to stderr
/// - In strict mode, returns `Some(1)` to signal the caller should exit
/// - In non-strict mode, returns `None` (command execution is not affected)
pub(crate) fn try_audit_append(
    logger: &AuditLogger,
    event: crate::audit::AuditEvent,
    strict: bool,
) -> Option<i32> {
    if let Err(e) = logger.append(event) {
        eprintln!("omamori warning: audit log write failed: {e}");
        eprintln!("  Command execution was not affected — this is a logging issue only.");
        eprintln!(
            "  To fix: check permissions on ~/.local/share/omamori/ or run omamori install --hooks"
        );
        if strict {
            eprintln!("omamori error: audit strict mode — blocking because audit log is required");
            return Some(1);
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
            let event =
                logger.create_event(&invocation, None, &detection.matched_detectors, &outcome);
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
            let event =
                logger.create_event(&invocation, None, &detection.matched_detectors, &outcome);
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
        let outcome = executor.execute(&invocation, rule)?;
        match &outcome {
            ActionOutcome::Blocked { .. } | ActionOutcome::Failed { .. } => {
                eprintln!("{}", outcome.message());
                let explain_cmd = format_explain_hint(&invocation);
                eprintln!("  hint: run `{explain_cmd}` for details");
            }
            ActionOutcome::Trashed { message, .. } | ActionOutcome::MovedTo { message, .. } => {
                eprintln!("{message}");
            }
            _ => {}
        }
        outcome
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

    // --- G-02: ensure_hooks_current_at ---

    #[test]
    fn hooks_current_old_version_triggers_regen() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        let result = ensure_hooks_current_at(&dir);
        assert!(result, "should regenerate hooks for old version");

        let content = std::fs::read_to_string(hooks_dir.join("claude-pretooluse.sh")).unwrap();
        assert_eq!(
            installer::parse_hook_version(&content),
            Some(env!("CARGO_PKG_VERSION"))
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

        let result = ensure_hooks_current_at(&dir);
        assert!(result, "should regenerate hooks for hash mismatch (T2)");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_correct_returns_false() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        let expected = installer::render_hook_script();
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

        let result = ensure_hooks_current_at(&dir);
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

            let result = ensure_hooks_current_at(&dir);
            assert!(
                result,
                "symlink hook should trigger regeneration due to hash mismatch"
            );

            let content = std::fs::read_to_string(&hook_path).unwrap();
            let expected = installer::render_hook_script();
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
            );
            let result = try_audit_append(&logger, event, false);
            assert_eq!(
                result, None,
                "non-strict mode should return None on append failure"
            );
        }
    }
}
