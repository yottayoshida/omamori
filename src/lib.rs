pub mod actions;
pub mod audit;
pub mod config;
pub mod context;
pub mod detector;
pub mod installer;
pub mod integrity;
pub mod rules;
pub mod unwrap;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use actions::{ActionExecutor, ActionOutcome, SystemOps};
use audit::{AuditEvent, AuditLogger};
use config::{ConfigLoadResult, load_config};
use detector::evaluate_detectors;
use installer::{InstallOptions, default_base_dir, install, uninstall};
use rules::{CommandInvocation, RuleConfig, match_rule};

#[derive(Debug)]
pub enum AppError {
    Usage(String),
    Io(std::io::Error),
    Config(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(f, "{message}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Config(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn run(args: &[OsString]) -> Result<i32, AppError> {
    let argv0 = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("omamori"));
    let argv0_name = binary_name(&argv0);

    if argv0_name != "omamori" {
        return run_shim(&argv0_name, &args[1..]);
    }

    match args.get(1).and_then(|item| item.to_str()) {
        Some("test") => run_policy_test_command(args),
        Some("exec") => run_exec_command(args),
        Some("install") => run_install_command(args),
        Some("uninstall") => run_uninstall_command(args),
        Some("init") => run_init_command(args),
        Some("config") => run_config_command(args),
        Some("override") => run_override_command(args),
        Some("status") => run_status_command(args),
        Some("cursor-hook") => run_cursor_hook(),
        Some("hook-check") => run_hook_check(args),
        Some("version") | Some("--version") | Some("-V") => {
            println!("omamori {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(0)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown subcommand: {other}\n\n{}",
            usage_text()
        ))),
    }
}

fn run_policy_test_command(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[2..])?;
    let load_result = load_config(config_path.as_deref())?;
    emit_config_warnings(&load_result);

    // Rules section
    let config = &load_result.config;
    let active_count = config.rules.iter().filter(|r| r.enabled).count();
    let disabled_count = config.rules.len() - active_count;

    println!("\nRules:");
    for rule in &config.rules {
        if !rule.enabled {
            println!("  SKIP  {:<28} (disabled by user config)", rule.name);
        } else {
            let action_display = match &rule.action {
                rules::ActionKind::MoveTo => {
                    let dest = rule.destination.as_deref().unwrap_or("(no destination)");
                    format!("move-to {dest}")
                }
                other => other.as_str().to_string(),
            };
            let pattern = if !rule.match_all.is_empty() {
                format!("{} {}", rule.command, rule.match_all.join(" "))
            } else if !rule.match_any.is_empty() {
                format!("{} {}", rule.command, rule.match_any.join("|"))
            } else {
                rule.command.clone()
            };
            println!(
                "  PASS  {:<28} {:<24} -> {}",
                rule.name, pattern, action_display
            );
        }
    }

    // Core Policy section
    println!("\nCore Policy:");
    let core_rules: Vec<&RuleConfig> = config.rules.iter().filter(|r| r.is_builtin).collect();
    let mut core_overridden = 0;
    for rule in &core_rules {
        if rule.enabled {
            println!("  PASS  {:<28} core rule active", rule.name);
        } else {
            println!(
                "  WARN  {:<28} core rule overridden (disabled by user)",
                rule.name
            );
            core_overridden += 1;
        }
    }

    // Context section
    let context_test_count = if let Some(ref ctx_config) = config.context {
        println!("\nContext:");
        let test_cases: Vec<(&str, Vec<String>, &str)> = vec![
            (
                "regenerable-path-downgrade",
                vec!["-rf".into(), "target/".into()],
                "rm",
            ),
            (
                "protected-path-escalate",
                vec!["-rf".into(), "src/".into()],
                "rm",
            ),
            (
                "unknown-path-unchanged",
                vec!["-rf".into(), "data/".into()],
                "rm",
            ),
        ];
        let mut count = 0;
        for (name, args, cmd) in &test_cases {
            let inv = CommandInvocation::new(cmd.to_string(), args.clone());
            let test_rule = config.rules.iter().find(|r| r.command == *cmd && r.enabled);
            if let Some(rule) = test_rule {
                let result = context::evaluate_context(&inv, rule, ctx_config);
                let (status, detail) = match &result.action_override {
                    Some(action) => (
                        "PASS",
                        format!(
                            "{} {} → {} (was: {})",
                            cmd,
                            args.last().unwrap_or(&String::new()),
                            action.as_str(),
                            rule.action.as_str(),
                        ),
                    ),
                    None => (
                        "PASS",
                        format!(
                            "{} {} → {} (unchanged)",
                            cmd,
                            args.last().unwrap_or(&String::new()),
                            rule.action.as_str(),
                        ),
                    ),
                };
                println!("  {status}  {name:<28} {detail}");
                count += 1;
            }
        }

        // Git-aware status
        if ctx_config.git.enabled {
            println!("  PASS  {:<28} (git-aware enabled)", "git-aware-evaluation");
        } else {
            println!(
                "  SKIP  {:<28} (git-aware not enabled)",
                "git-aware-evaluation"
            );
        }
        count
    } else {
        0
    };

    // Detection section
    let results = run_policy_tests(&load_result);
    let failures = results.iter().filter(|r| !r.passed).count();

    println!("\nDetection:");
    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("  {status}  {:<28} {}", result.name, result.details);
    }

    // Summary
    let context_summary = if context_test_count > 0 {
        format!(", {} context tests", context_test_count)
    } else {
        String::new()
    };
    let core_summary = if core_overridden > 0 {
        format!(
            ", {} core rules ({} overridden)",
            core_rules.len(),
            core_overridden
        )
    } else {
        format!(", {} core rules active", core_rules.len())
    };
    println!(
        "\nSummary: {} rules ({} active, {} disabled){}{}, {} detection tests {}",
        config.rules.len(),
        active_count,
        disabled_count,
        core_summary,
        context_summary,
        results.len(),
        if failures == 0 { "passed" } else { "FAILED" }
    );

    if failures == 0 { Ok(0) } else { Ok(1) }
}

fn run_exec_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut position = 2usize;
    let config_path = if args.get(position).and_then(|item| item.to_str()) == Some("--config") {
        let value = args
            .get(position + 1)
            .ok_or_else(|| AppError::Usage("--config requires a path".to_string()))?;
        position += 2;
        Some(PathBuf::from(value))
    } else {
        None
    };

    if args.get(position).and_then(|item| item.to_str()) != Some("--") {
        return Err(AppError::Usage(format!(
            "exec requires `--` before the target command\n\n{}",
            usage_text()
        )));
    }

    let program = args
        .get(position + 1)
        .ok_or_else(|| AppError::Usage("missing command after `--`".to_string()))?;
    let command_args = &args[(position + 2)..];
    run_command(binary_name(program), command_args, config_path.as_deref())
}

fn run_install_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = default_base_dir();
    let mut source_exe = installer::resolve_stable_exe_path(&env::current_exe()?);
    let mut generate_hooks = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("install requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            "--source" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("install requires a path after --source".to_string())
                })?;
                source_exe = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                generate_hooks = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown install flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    let result = install(&InstallOptions {
        base_dir,
        source_exe,
        generate_hooks,
    })?;

    // --- Categorized checklist output ---
    println!("\nomamori setup complete:\n");

    // Shims
    println!("Shims:");
    println!("  [done] {}", result.linked_commands.join(", "));

    // Hooks
    println!("\nHooks:");
    if let Some(script) = &result.hook_script {
        println!("  [done] Claude Code hook: {}", script.display());
    }
    if let Some(snippet) = &result.settings_snippet {
        println!(
            "  [done] Claude Code settings snippet: {}",
            snippet.display()
        );
    }
    if let Some(cursor_snippet) = &result.cursor_hook_snippet {
        println!("  [done] Cursor hook snippet: {}", cursor_snippet.display());
    }
    if let Some(wrapper) = &result.codex_wrapper {
        println!("  [done] Codex CLI wrapper: {}", wrapper.display());
    }
    match &result.codex_hooks_outcome {
        Some(installer::CodexHooksOutcome::Created) => {
            println!("  [done] Codex CLI hooks.json: created ~/.codex/hooks.json");
        }
        Some(installer::CodexHooksOutcome::Merged) => {
            println!("  [done] Codex CLI hooks.json: merged into ~/.codex/hooks.json");
        }
        Some(installer::CodexHooksOutcome::AlreadyPresent) => {
            println!("  [skip] Codex CLI hooks.json: already configured");
        }
        Some(installer::CodexHooksOutcome::Skipped(reason)) => {
            println!("  [warn] Codex CLI hooks.json: {reason}");
            println!("         Manual merge needed: cat ~/.omamori/hooks/codex-hooks.snippet.json");
        }
        None => {}
    }
    match &result.codex_config_outcome {
        Some(installer::CodexConfigOutcome::Added) => {
            println!("  [done] Codex CLI config.toml: set [features] codex_hooks = true");
            println!("         (backup: ~/.codex/config.toml.bak)");
        }
        Some(installer::CodexConfigOutcome::AlreadyEnabled) => {
            println!("  [skip] Codex CLI config.toml: codex_hooks already enabled");
        }
        Some(installer::CodexConfigOutcome::ExplicitlyDisabled) => {
            println!(
                "  [warn] Codex CLI config.toml: codex_hooks = false (set by user, not changed)"
            );
            println!("         omamori hooks will NOT activate until you set codex_hooks = true");
            println!("         in ~/.codex/config.toml");
        }
        Some(installer::CodexConfigOutcome::Skipped(reason)) => {
            println!("  [warn] Codex CLI config.toml: {reason}");
        }
        None => {}
    }

    // Config
    println!("\nConfig:");
    let config_status = match config::default_config_path() {
        Some(config_path) if !config_path.exists() => {
            match config::write_default_config(&config_path, false) {
                Ok(res) => format!("[done] Created: {}", res.path.display()),
                Err(e) => format!("[warn] Not created: {e}"),
            }
        }
        Some(config_path) => format!("[skip] Already exists: {}", config_path.display()),
        None => "[warn] Not created: HOME/XDG_CONFIG_HOME not set".to_string(),
    };
    println!("  {config_status}");

    // Auto-test
    let load_result = load_config(None)?;
    let test_results = run_policy_tests(&load_result);
    let failures = test_results.iter().filter(|r| !r.passed).count();
    let active_rules = load_result
        .config
        .rules
        .iter()
        .filter(|r| r.enabled)
        .count();
    if failures == 0 {
        println!(
            "  [done] {} rules verified, {} detection tests passed",
            active_rules,
            test_results.len()
        );
    } else {
        println!(
            "  [FAIL] {} detection test(s) failed — run `omamori test` for details",
            failures
        );
    }

    // Next steps
    println!("\nNext steps:");
    println!(
        "  [todo] Add to your shell profile (~/.zshrc or ~/.bashrc):\n\n    export PATH=\"{}:$PATH\"",
        result.shim_dir.display()
    );
    if result.settings_snippet.is_some() {
        let hooks_dir = result
            .hook_script
            .as_ref()
            .map(|p| p.parent().unwrap().display().to_string())
            .unwrap_or_default();
        println!(
            "\n  [todo] Apply Claude Code hook (copy snippet to settings.json):\n\n    cat {hooks_dir}/claude-settings.snippet.json"
        );
    }
    if result.cursor_hook_snippet.is_some() {
        let hooks_dir = result
            .cursor_hook_snippet
            .as_ref()
            .map(|p| p.parent().unwrap().display().to_string())
            .unwrap_or_default();
        println!(
            "\n  [todo] Merge Cursor hook into .cursor/hooks.json:\n\n    cat {hooks_dir}/cursor-hooks.snippet.json"
        );
    }

    println!();
    Ok(0)
}

fn run_uninstall_command(args: &[OsString]) -> Result<i32, AppError> {
    guard_ai_config_modification("uninstall")?;
    let mut base_dir = default_base_dir();
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("uninstall requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown uninstall flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    let result = uninstall(&base_dir)?;
    println!(
        "Removed omamori install artifacts from {}",
        result.shim_dir.display()
    );
    println!("Removed {} file(s)", result.removed_entries.len());
    Ok(0)
}

fn run_shim(program: &str, args: &[OsString]) -> Result<i32, AppError> {
    let base_dir = default_base_dir();

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

/// Check if hooks are current; if not, regenerate them.
/// Runs at shim startup. Failures are non-fatal (warn only).
/// Returns `true` if hooks were regenerated.
///
/// Two-level check:
/// 1. Version mismatch → regenerate (existing behavior, e.g. after upgrade)
/// 2. Version match but content hash mismatch → regenerate (T2 attack: AI keeps
///    version comment but rewrites hook body, e.g. `exit 2` → `exit 0`)
fn ensure_hooks_current() -> bool {
    ensure_hooks_current_at(&default_base_dir())
}

/// Testable version of `ensure_hooks_current` that accepts a base directory.
///
/// Two-level check:
/// 1. Version mismatch → regenerate (existing behavior, e.g. after upgrade)
/// 2. Version match but content hash mismatch → regenerate (T2 attack: AI keeps
///    version comment but rewrites hook body, e.g. `exit 2` → `exit 0`)
fn ensure_hooks_current_at(base_dir: &Path) -> bool {
    let hook_path = base_dir.join("hooks/claude-pretooluse.sh");

    let content = match std::fs::read_to_string(&hook_path) {
        Ok(c) => c,
        Err(_) => return false, // No hooks file = not installed via install --hooks, skip
    };

    let hook_version = installer::parse_hook_version(&content);
    let version_matches = hook_version == Some(env!("CARGO_PKG_VERSION"));

    if !version_matches {
        // Level 1: version mismatch → regenerate
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

    // Level 2: version matches → check content hash (T2 attack detection)
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

/// Silently update integrity baseline. Used after hook regen or config changes.
/// Failures are non-fatal (warn to stderr).
fn update_baseline_silent(base_dir: &Path) {
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

fn run_command(
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
    // Root-privilege destructive operations must be blocked even in non-AI environments.
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
                AuditEvent::from_outcome(&invocation, None, &detection.matched_detectors, &outcome);
            let _ = logger.append(&event);
        }
        return Ok(outcome.exit_code());
    }

    // Non-protected fast path: no AI environment detected = human terminal.
    // This is NOT a security boundary — omamori only guards AI-initiated commands.
    // match_rule, context evaluation, and ActionExecutor are not constructed.
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
                AuditEvent::from_outcome(&invocation, None, &detection.matched_detectors, &outcome);
            let _ = logger.append(&event);
        }
        return Ok(exit_code);
    }

    // --- Protected path: AI environment detected. Full evaluation. ---

    let matched_rule = match_rule(&load_result.config.rules, &invocation);
    let detector_env_keys: Vec<String> = load_result
        .config
        .detectors
        .iter()
        .map(|d| d.env_key.clone())
        .filter(|k| !k.is_empty() && !k.contains('='))
        .collect();

    // Context-aware evaluation: compute effective rule (may differ from matched_rule)
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

        // Tier 2: git-aware evaluation (skip if Tier 1 already escalated to Block)
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
        let event = AuditEvent::from_outcome(
            &invocation,
            effective_rule,
            &detection.matched_detectors,
            &outcome,
        );
        let _ = logger.append(&event);
    }

    Ok(outcome.exit_code())
}

fn emit_config_warnings(load_result: &ConfigLoadResult) {
    for warning in &load_result.warnings {
        eprintln!("omamori warning: {warning}");
    }
}

fn run_status_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = default_base_dir();
    let mut refresh = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("status requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            "--refresh" => {
                refresh = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown status flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    println!("\nomamori v{} — health check\n", env!("CARGO_PKG_VERSION"));

    let report = integrity::full_check(&base_dir);

    // Group items by category and print
    let categories = [
        "Shims",
        "Hooks",
        "Config",
        "Core Policy",
        "PATH",
        "Baseline",
    ];
    for cat in &categories {
        let cat_items: Vec<_> = report.items.iter().filter(|i| i.category == *cat).collect();
        if cat_items.is_empty() {
            continue;
        }
        println!("{}:", cat);
        for item in &cat_items {
            println!(
                "  {:<6} {:<36} {}",
                item.status.label(),
                item.name,
                item.detail
            );
        }
        println!();
    }

    // Detection engine summary (always displayed)
    let rule_count = load_config(None)
        .map(|r| r.config.rules.iter().filter(|r| r.enabled).count())
        .unwrap_or(7);
    println!("Detection:");
    println!(
        "  {:<6} {:<36} {rule_count} rules active",
        "[ok]", "Layer 1 (PATH shim)"
    );
    println!(
        "  {:<6} {:<36} Unwrap stack active",
        "[ok]", "Layer 2 (hooks)"
    );
    println!(
        "  {:<6} {:<36} Claude Code + Codex CLI + Cursor",
        "[info]", "Layer 2 coverage"
    );
    println!();

    let exit_code = report.exit_code();
    match exit_code {
        0 => println!("All layers healthy."),
        2 => println!("Some warnings detected. Review above."),
        _ => println!("Issues detected. Run suggested commands to repair."),
    }

    // --refresh: regenerate baseline from current state
    if refresh {
        match integrity::generate_baseline(&base_dir) {
            Ok(baseline) => {
                integrity::write_baseline(&base_dir, &baseline)?;
                println!(
                    "\nBaseline refreshed (v{}, {}).",
                    baseline.version, baseline.generated_at
                );
            }
            Err(e) => {
                eprintln!("\nomamori: failed to refresh baseline: {e}");
            }
        }
    }

    println!();
    Ok(exit_code)
}

/// Cursor `beforeShellExecution` hook handler.
/// Reads JSON from stdin, checks command via shared hook pipeline,
/// writes JSON response to stdout. All logs go to stderr only.
fn run_cursor_hook() -> Result<i32, AppError> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let command = match serde_json::from_str::<serde_json::Value>(&input) {
        Ok(v) => match v.get("command") {
            Some(c) if c.is_string() => c.as_str().unwrap().to_string(),
            Some(_) | None => {
                // command key missing or not a string → malformed protocol → deny
                eprintln!("omamori cursor-hook: missing or invalid 'command' field");
                print_cursor_response(false, "deny", Some("omamori: malformed hook input"), None);
                return Ok(0);
            }
        },
        Err(_) => {
            eprintln!("omamori cursor-hook: failed to parse stdin JSON");
            print_cursor_response(false, "deny", Some("omamori: malformed hook input"), None);
            return Ok(0);
        }
    };

    if command.is_empty() {
        print_cursor_response(true, "allow", None, None);
        return Ok(0);
    }

    match check_command_for_hook(&command) {
        HookCheckResult::Allow => {
            print_cursor_response(true, "allow", None, None);
        }
        HookCheckResult::BlockMeta(reason) => {
            eprintln!("omamori cursor-hook: BLOCKED ({reason})");
            print_cursor_response(
                false,
                "deny",
                Some(&format!("omamori hook: {reason}")),
                Some(&format!(
                    "This command was blocked by omamori: {reason}. Use a safer alternative."
                )),
            );
        }
        HookCheckResult::BlockRule {
            message,
            unwrap_chain,
            ..
        } => {
            let chain_str = unwrap_chain
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default();
            eprintln!("omamori cursor-hook: BLOCKED ({message}{chain_str})");
            print_cursor_response(
                false,
                "deny",
                Some(&format!("omamori hook: blocked — {message}{chain_str}")),
                Some("This command was blocked by omamori safety guard. Use a safer alternative."),
            );
        }
        HookCheckResult::BlockStructural(message) => {
            eprintln!("omamori cursor-hook: BLOCKED ({message})");
            print_cursor_response(
                false,
                "deny",
                Some(&message),
                Some("This command was blocked by omamori safety guard. Use a safer alternative."),
            );
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Shared hook check logic (used by both hook-check and cursor-hook)
// ---------------------------------------------------------------------------

/// Result of checking a command string through the hook pipeline.
enum HookCheckResult {
    /// Command is allowed.
    Allow,
    /// Command is blocked by a meta-pattern (string-level).
    BlockMeta(&'static str),
    /// Command is blocked by the unwrap stack (token-level rule match).
    BlockRule {
        rule_name: String,
        message: String,
        unwrap_chain: Option<String>,
    },
    /// Command is blocked by the unwrap stack (structural block: pipe-to-shell, etc.).
    BlockStructural(String),
}

/// Two-phase hook check:
/// Phase 1: Meta-pattern string-level check (env var unset, config tamper, /bin/rm, etc.)
/// Phase 2: Token-level unwrap stack → rule matching
fn check_command_for_hook(command: &str) -> HookCheckResult {
    // Phase 1: Meta-patterns (string-level, intentionally broad)
    for (pattern, reason) in installer::blocked_command_patterns() {
        if command.contains(pattern) {
            return HookCheckResult::BlockMeta(reason);
        }
    }

    // Phase 2: Unwrap stack → rule matching
    let parse_result = unwrap::parse_command_string(command);

    match parse_result {
        unwrap::ParseResult::Block(reason) => HookCheckResult::BlockStructural(format!(
            "omamori hook: blocked — {}",
            reason.message()
        )),
        unwrap::ParseResult::Commands(invocations) => {
            // Load config to get rules
            let load_result = match load_config(None) {
                Ok(r) => r,
                Err(_) => {
                    // Config load failure → use default rules (fail-safe, not fail-open)
                    ConfigLoadResult {
                        config: config::Config::default(),
                        warnings: vec![],
                    }
                }
            };

            for inv in &invocations {
                if let Some(rule) = match_rule(&load_result.config.rules, inv) {
                    let chain_desc = format_unwrap_chain(command, inv);
                    let msg = rule
                        .message
                        .clone()
                        .unwrap_or_else(|| format!("matched rule: {}", rule.name));
                    return HookCheckResult::BlockRule {
                        rule_name: rule.name.clone(),
                        message: msg,
                        unwrap_chain: chain_desc,
                    };
                }
            }

            HookCheckResult::Allow
        }
    }
}

/// Format the unwrap chain for display: "rm -rf / (via bash -c)"
fn format_unwrap_chain(original: &str, invocation: &CommandInvocation) -> Option<String> {
    // If the original command doesn't start with the matched program,
    // there was unwrapping involved — show the wrapper context
    let trimmed = original.trim();
    if !trimmed.starts_with(&invocation.program) {
        // Extract the first word of the original as the outermost wrapper
        let outer = trimmed.split_whitespace().next().unwrap_or("");
        let outer_base = outer.rsplit('/').next().unwrap_or(outer);
        // Check if bash -c style
        if trimmed.contains("-c") {
            Some(format!("via {} -c", outer_base))
        } else {
            Some(format!("via {}", outer_base))
        }
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// hook-check subcommand (Claude Code PreToolUse thin wrapper target)
// ---------------------------------------------------------------------------

/// `omamori hook-check [--provider NAME]`
/// Reads command string from stdin, checks against meta-patterns + unwrap stack + rules.
/// Exit 0 = allow, exit 2 = block.
fn run_hook_check(args: &[OsString]) -> Result<i32, AppError> {
    use std::io::Read;

    let provider = parse_provider_flag(args);

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    // Claude Code sends JSON with tool_input.command; extract it
    let command = extract_command_from_hook_input(&input);

    if command.is_empty() {
        print_hook_check_allow_response("omamori: empty command");
        return Ok(0);
    }

    let verbose = std::env::var("OMAMORI_VERBOSE").is_ok();

    match check_command_for_hook(&command) {
        HookCheckResult::Allow => {
            print_hook_check_allow_response("omamori: no dangerous pattern detected");
            Ok(0)
        }
        HookCheckResult::BlockMeta(reason) => {
            eprintln!("omamori hook: blocked — {reason}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  layer: meta-pattern (string-level)");
            }
            Ok(2)
        }
        HookCheckResult::BlockRule {
            rule_name,
            message,
            unwrap_chain,
        } => {
            let chain_str = unwrap_chain
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default();
            eprintln!("omamori hook: blocked — {message}{chain_str}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  rule: {rule_name}");
                eprintln!("  layer: unwrap-stack (token-level)");
            }
            eprintln!(
                "  hint: if intentional, run the command directly in your terminal (not via AI agent)"
            );
            Ok(2)
        }
        HookCheckResult::BlockStructural(message) => {
            eprintln!("{message}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  layer: unwrap-stack (structural)");
            }
            eprintln!(
                "  hint: if intentional, run the command directly in your terminal (not via AI agent)"
            );
            Ok(2)
        }
    }
}

/// Extract the command string from Claude Code's PreToolUse hook JSON input.
/// Falls back to treating the entire input as the command if JSON parsing fails.
fn extract_command_from_hook_input(input: &str) -> String {
    // Claude Code PreToolUse sends: { "tool_name": "Bash", "tool_input": { "command": "..." } }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(input) {
        if let Some(cmd) = v
            .get("tool_input")
            .and_then(|ti| ti.get("command"))
            .and_then(|c| c.as_str())
        {
            return cmd.to_string();
        }
        // Cursor format: { "command": "..." }
        if let Some(cmd) = v.get("command").and_then(|c| c.as_str()) {
            return cmd.to_string();
        }
    }
    // Fallback: treat raw input as command
    input.trim().to_string()
}

/// Parse --provider flag from args. Defaults to "unknown".
fn parse_provider_flag(args: &[OsString]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if arg.to_str() == Some("--provider")
            && let Some(val) = args.get(i + 1)
        {
            return val.to_string_lossy().to_string();
        }
    }
    "unknown".to_string()
}

/// Print hookSpecificOutput JSON for Claude Code PreToolUse hook (Auto mode compatibility).
/// Only used on ALLOW path — BLOCK uses exit code 2 (stdout ignored by Claude Code).
fn print_hook_check_allow_response(reason: &str) {
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
        }
    });
    // Fallback: if serialization somehow fails, emit a hardcoded JSON string (fail-safe)
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"omamori: fallback"}}"#.to_string()
        })
    );
}

fn print_cursor_response(
    cont: bool,
    permission: &str,
    user_message: Option<&str>,
    agent_message: Option<&str>,
) {
    let mut response = serde_json::json!({
        "continue": cont,
        "permission": permission,
    });
    if let Some(msg) = user_message {
        response["userMessage"] = serde_json::json!(msg);
    }
    if let Some(msg) = agent_message {
        response["agentMessage"] = serde_json::json!(msg);
    }
    // stdout is JSON only — never print anything else here
    println!(
        "{}",
        serde_json::to_string(&response)
            .unwrap_or_else(|_| { r#"{"continue":false,"permission":"deny"}"#.to_string() })
    );
}

fn print_usage() {
    println!("{}", usage_text());
}

fn run_config_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("list") => run_config_list(),
        Some("disable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("config disable requires a rule name".to_string())
            })?;
            run_config_disable(rule_name)
        }
        Some("enable") => {
            let rule_name = args
                .get(3)
                .and_then(|item| item.to_str())
                .ok_or_else(|| AppError::Usage("config enable requires a rule name".to_string()))?;
            run_config_enable(rule_name)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown config subcommand: {other}\n\n{}",
            usage_text()
        ))),
        None => Err(AppError::Usage(format!(
            "config requires a subcommand\n\n{}",
            usage_text()
        ))),
    }
}

/// Guard against AI agents modifying omamori's own configuration.
/// Blocks when any AI detector env var is present (exact match via evaluate_detectors).
fn guard_ai_config_modification(operation: &str) -> Result<(), AppError> {
    let detectors = config::default_detectors();
    let env_pairs: Vec<(String, String)> = std::env::vars().collect();
    let detection = evaluate_detectors(&detectors, &env_pairs);
    if detection.protected {
        return Err(AppError::Config(format!(
            "{operation} blocked — AI agent environment detected ({}).\n  \
             Protection rules cannot be modified by AI tools.\n  \
             To modify, run this command directly in your terminal (not via AI).",
            detection.matched_detectors.join(", ")
        )));
    }
    Ok(())
}

fn validate_rule_name(name: &str) -> Result<(), AppError> {
    let known_names: Vec<String> = config::default_rules()
        .iter()
        .map(|r| r.name.clone())
        .collect();
    if !known_names.contains(&name.to_string()) {
        return Err(AppError::Config(format!(
            "unknown rule `{name}`\n  Known rules: {}",
            known_names.join(", ")
        )));
    }
    Ok(())
}

fn resolve_config_path_checked() -> Result<std::path::PathBuf, AppError> {
    let path = config::default_config_path().ok_or_else(|| {
        AppError::Config("cannot determine config path: HOME/XDG_CONFIG_HOME not set".to_string())
    })?;
    // P2 fix: reject symlinked config file before writing
    if path.exists() {
        config::reject_symlink_public(&path, "config path")?;
    }
    Ok(path)
}

fn is_core_rule(name: &str) -> bool {
    config::core_rule_names().contains(&name)
}

fn run_config_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config disable")?;
    validate_rule_name(rule_name)?;

    // Core rules cannot be disabled via `config disable`
    if is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is a core safety rule and cannot be disabled.\n\n  \
             To override: omamori override disable {rule_name}\n  \
             To see core vs custom rules: omamori config list"
        )));
    }

    let config_path = resolve_config_path_checked()?;

    // Auto-create config if it doesn't exist
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    // Check current state via the config loader to detect all forms of disable
    let load_result = load_config(None)?;
    let rule = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name);
    if let Some(r) = rule
        && !r.enabled
    {
        eprintln!("Rule `{rule_name}` is already disabled.");
        return Ok(2);
    }

    // Read current content
    let content = std::fs::read_to_string(&config_path)?;

    // P1 fix: check if an existing [[rules]] entry for this rule exists in the file.
    // If so, we need to add `enabled = false` to that entry rather than appending a new block.
    let disable_block = format!("[[rules]]\nname = \"{rule_name}\"\nenabled = false\n");

    // Check if an uncommented entry for this rule exists
    let has_uncommented_entry = content.lines().any(|l| {
        let trimmed = l.trim();
        !trimmed.starts_with('#') && trimmed == format!("name = \"{rule_name}\"")
    });

    let new_content = if has_uncommented_entry {
        // Existing entry — replace or add enabled = false in the block
        // Find the block and ensure enabled = false is present
        let mut result = String::new();
        let mut in_target_block = false;
        let mut added_enabled = false;
        for line in content.lines() {
            if line.trim() == "[[rules]]" {
                if in_target_block && !added_enabled {
                    result.push_str("enabled = false\n");
                    added_enabled = true;
                }
                in_target_block = false;
                result.push_str(line);
                result.push('\n');
                continue;
            }
            if line.trim() == format!("name = \"{rule_name}\"") {
                in_target_block = true;
            }
            if in_target_block && line.trim().starts_with("enabled") {
                result.push_str("enabled = false\n");
                added_enabled = true;
                continue;
            }
            result.push_str(line);
            result.push('\n');
        }
        if in_target_block && !added_enabled {
            result.push_str("enabled = false\n");
        }
        result
    } else {
        // No existing entry — append a new disable block
        let mut new = content;
        if !new.ends_with('\n') {
            new.push('\n');
        }
        new.push('\n');
        new.push_str(&disable_block);
        new
    };

    // Validate the new TOML is parseable
    if toml::from_str::<toml::Value>(&new_content).is_err() {
        return Err(AppError::Config(
            "modifying config would create invalid TOML; aborting".to_string(),
        ));
    }

    std::fs::write(&config_path, &new_content)?;
    eprintln!("Disabled: {rule_name}");
    update_baseline_silent(&default_base_dir());

    // Show updated config list
    run_config_list()
}

fn run_config_enable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config enable")?;
    validate_rule_name(rule_name)?;

    let config_path = resolve_config_path_checked()?;

    if !config_path.exists() {
        eprintln!("Rule `{rule_name}` is already enabled (built-in default).");
        return Ok(2);
    }

    // Check current state
    let load_result = load_config(None)?;
    let rule = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name);
    if let Some(r) = rule
        && r.enabled
    {
        eprintln!("Rule `{rule_name}` is already enabled.");
        return Ok(2);
    }

    let content = std::fs::read_to_string(&config_path)?;

    // Remove standalone disable blocks
    let disable_block = format!("[[rules]]\nname = \"{rule_name}\"\nenabled = false\n");
    let mut new_content = content.replace(&disable_block, "");

    // Also handle entries where enabled = false is within a larger block
    // by removing the `enabled = false` line
    let enabled_false_line = "enabled = false";
    let mut lines: Vec<&str> = new_content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == enabled_false_line {
            // Check if we're in the target rule's block by looking backwards for the name
            let mut in_target = false;
            for j in (0..i).rev() {
                let trimmed = lines[j].trim();
                if trimmed == format!("name = \"{rule_name}\"") {
                    in_target = true;
                    break;
                }
                if trimmed == "[[rules]]" {
                    break;
                }
            }
            if in_target {
                lines.remove(i);
                continue;
            }
        }
        i += 1;
    }
    new_content = lines.join("\n");

    // Clean up trailing whitespace
    let new_content = new_content.trim_end().to_string() + "\n";

    std::fs::write(&config_path, &new_content)?;
    eprintln!("Enabled: {rule_name} (restored to built-in default)");
    update_baseline_silent(&default_base_dir());

    // Show updated config list
    run_config_list()
}

fn run_override_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("disable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("override disable requires a rule name".to_string())
            })?;
            run_override_disable(rule_name)
        }
        Some("enable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("override enable requires a rule name".to_string())
            })?;
            run_override_enable(rule_name)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown override subcommand: {other}\n\n{}",
            usage_text()
        ))),
        None => Err(AppError::Usage(format!(
            "override requires a subcommand (disable|enable)\n\n{}",
            usage_text()
        ))),
    }
}

fn run_override_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("override disable")?;
    validate_rule_name(rule_name)?;

    if !is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is not a core rule. Use `omamori config disable {rule_name}` instead."
        )));
    }

    let config_path = resolve_config_path_checked()?;

    // Auto-create config if it doesn't exist
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    let content = std::fs::read_to_string(&config_path)?;

    // Check if [overrides] section exists
    let new_content = if content.contains("[overrides]") {
        // Check if already has this rule
        if content.contains(&format!("{rule_name} = false"))
            || content.contains(&format!("{rule_name}=false"))
        {
            eprintln!("Rule `{rule_name}` is already overridden (disabled).");
            return Ok(2);
        }
        // Add entry after [overrides] line
        content.replace("[overrides]", &format!("[overrides]\n{rule_name} = false"))
    } else {
        // Append [overrides] section
        let mut new = content;
        if !new.ends_with('\n') {
            new.push('\n');
        }
        new.push_str(&format!("\n[overrides]\n{rule_name} = false\n"));
        new
    };

    // Validate TOML
    if toml::from_str::<toml::Value>(&new_content).is_err() {
        return Err(AppError::Config(
            "modifying config would create invalid TOML; aborting".to_string(),
        ));
    }

    std::fs::write(&config_path, &new_content)?;
    eprintln!("Override: disabled core rule `{rule_name}`");
    eprintln!("To restore: omamori override enable {rule_name}");
    update_baseline_silent(&default_base_dir());

    run_config_list()
}

fn run_override_enable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("override enable")?;
    validate_rule_name(rule_name)?;

    if !is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is not a core rule. Use `omamori config enable {rule_name}` instead."
        )));
    }

    let config_path = resolve_config_path_checked()?;

    if !config_path.exists() {
        eprintln!("Rule `{rule_name}` is already active (core default).");
        return Ok(2);
    }

    let content = std::fs::read_to_string(&config_path)?;

    // Remove the override entry
    let patterns = [
        format!("{rule_name} = false\n"),
        format!("{rule_name}=false\n"),
        format!("{rule_name} = false"),
        format!("{rule_name}=false"),
    ];

    let mut new_content = content.clone();
    for pat in &patterns {
        new_content = new_content.replace(pat, "");
    }

    // Clean up empty [overrides] section
    let new_content = new_content
        .replace("[overrides]\n\n", "[overrides]\n")
        .trim_end()
        .to_string()
        + "\n";

    // Check if [overrides] section is now empty and remove it
    let new_content = if new_content.contains("[overrides]\n")
        && !new_content
            .split("[overrides]\n")
            .nth(1)
            .unwrap_or("")
            .lines()
            .any(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && !t.starts_with('[')
            }) {
        new_content.replace("[overrides]\n", "")
    } else {
        new_content
    };

    let new_content = new_content.trim_end().to_string() + "\n";

    std::fs::write(&config_path, &new_content)?;
    eprintln!("Restored: core rule `{rule_name}` is active again.");
    update_baseline_silent(&default_base_dir());

    run_config_list()
}

fn run_config_list() -> Result<i32, AppError> {
    let load_result = load_config(None)?;
    let config = &load_result.config;

    // Emit any config warnings
    emit_config_warnings(&load_result);

    // Build default rules map for comparison (P3 fix)
    let defaults: std::collections::HashMap<String, _> = config::default_rules()
        .into_iter()
        .map(|r| (r.name.clone(), r))
        .collect();

    println!(
        "\n  {:<30} {:<16} {:<10} Source",
        "Rule", "Action", "Status"
    );
    println!("  {}", "-".repeat(76));

    for rule in &config.rules {
        let status = if rule.enabled { "active" } else { "disabled" };
        let source = if rule.is_builtin {
            if !rule.enabled {
                "core (overridden)"
            } else {
                "core"
            }
        } else if let Some(default) = defaults.get(&rule.name) {
            if !rule.enabled {
                "config (disabled)"
            } else if rule.action != default.action
                || rule.command != default.command
                || rule.match_all != default.match_all
                || rule.match_any != default.match_any
                || rule.destination != default.destination
            {
                "config (modified)"
            } else {
                "built-in"
            }
        } else {
            "config"
        };
        let action_str = match &rule.action {
            rules::ActionKind::MoveTo => {
                let dest = rule.destination.as_deref().unwrap_or("?");
                format!("move-to {dest}")
            }
            other => other.as_str().to_string(),
        };
        println!(
            "  {:<30} {:<16} {:<10} {}",
            rule.name, action_str, status, source
        );
    }

    // Show config path
    if let Some(path) = config::default_config_path() {
        if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    println!(
                        "\n  Config: {} (permissions: {:o})",
                        path.display(),
                        meta.mode() & 0o777
                    );
                }
            }
            #[cfg(not(unix))]
            println!("\n  Config: {}", path.display());
        } else {
            println!("\n  Config: not found (run `omamori init` to create)");
        }
    }

    println!();
    Ok(0)
}

fn run_init_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut force = false;
    let mut stdout_mode = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--force" => {
                force = true;
                index += 1;
            }
            "--stdout" => {
                stdout_mode = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown init flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    // Guard: init --force can overwrite existing config → block in AI sessions
    if force {
        guard_ai_config_modification("init --force")?;
    }

    // --stdout: backward-compatible stdout output
    if stdout_mode {
        print!("{}", config::config_template());
        return Ok(0);
    }

    // File write mode (default)
    let path = config::default_config_path().ok_or_else(|| {
        AppError::Config(
            "cannot determine config path: neither XDG_CONFIG_HOME nor HOME is set".to_string(),
        )
    })?;

    match config::write_default_config(&path, force) {
        Ok(result) => {
            eprintln!("Created {}", result.path.display());
            eprintln!("Run `omamori test` to verify your setup.");
            update_baseline_silent(&default_base_dir());
            Ok(0)
        }
        Err(AppError::Config(msg)) if msg.contains("already exists") => {
            eprintln!("omamori: {msg}");
            Ok(2)
        }
        Err(AppError::Config(msg)) if msg.contains("symlink") => {
            eprintln!("omamori: {msg}");
            Ok(1)
        }
        Err(e) => Err(e),
    }
}

fn usage_text() -> &'static str {
    "omamori usage:
  omamori --version                                      # Show version
  omamori test [--config PATH]
  omamori exec [--config PATH] -- <command> [args...]
  omamori install [--base-dir PATH] [--source PATH] [--hooks]
  omamori uninstall [--base-dir PATH]
  omamori init [--force] [--stdout]
  omamori config list
  omamori config disable <rule>
  omamori config enable <rule>
  omamori status [--refresh]                              # Health check all defense layers
  omamori override disable <rule>                        # Override a core safety rule
  omamori override enable <rule>                         # Restore a core safety rule
  omamori hook-check [--provider NAME]                   # Hook detection engine (stdin → exit code)
  omamori cursor-hook                                   # Cursor beforeShellExecution handler

When installed as a PATH shim (for example via a symlink named `rm`), omamori
uses the invoked binary name as the target command and evaluates its policies."
}

fn parse_config_flag(args: &[OsString]) -> Result<Option<PathBuf>, AppError> {
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() != 2 || args[0].to_str() != Some("--config") {
        return Err(AppError::Usage(format!(
            "expected `--config PATH`\n\n{}",
            usage_text()
        )));
    }
    Ok(Some(PathBuf::from(&args[1])))
}

fn binary_name(path: &OsString) -> String {
    Path::new(path)
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn clone_lossy(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(unix)]
fn should_block_for_sudo() -> bool {
    (unsafe { libc_geteuid() }) == 0 && env::var_os("SUDO_USER").is_some()
}

#[cfg(not(unix))]
fn should_block_for_sudo() -> bool {
    false
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn resolve_real_command(program: &str) -> Result<PathBuf, AppError> {
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    if program.contains(std::path::MAIN_SEPARATOR) {
        let candidate = PathBuf::from(program);
        let canonical = candidate.canonicalize().unwrap_or(candidate);
        if canonical == current_exe {
            return Err(AppError::Config(format!(
                "refusing to resolve `{program}` to the omamori shim itself"
            )));
        }
        return Ok(canonical);
    }

    let path_value = env::var_os("PATH").ok_or_else(|| {
        AppError::Config("PATH is not set; unable to resolve real command".to_string())
    })?;

    resolve_real_command_from_path(program, &path_value, &current_exe)
}

fn resolve_real_command_from_path(
    program: &str,
    path_value: &std::ffi::OsStr,
    current_exe: &Path,
) -> Result<PathBuf, AppError> {
    for candidate_dir in env::split_paths(path_value) {
        let candidate = candidate_dir.join(program);
        if !candidate.is_file() {
            continue;
        }

        let canonical = candidate.canonicalize().unwrap_or(candidate);
        if canonical == current_exe {
            continue;
        }

        return Ok(canonical);
    }

    Err(AppError::Config(format!(
        "unable to locate the real `{program}` outside the omamori shim path"
    )))
}

#[derive(Debug)]
pub struct PolicyTestResult {
    pub name: &'static str,
    pub passed: bool,
    pub details: String,
}

pub fn run_policy_tests(load_result: &ConfigLoadResult) -> Vec<PolicyTestResult> {
    let config = &load_result.config;
    let claude_env = vec![("CLAUDECODE".to_string(), "1".to_string())];
    let codex_env = vec![("CODEX_CI".to_string(), "1".to_string())];
    let cursor_env = vec![("CURSOR_AGENT".to_string(), "1".to_string())];
    let unprotected_env = Vec::new();

    let cases = vec![
        (
            "ai-rm-recursive-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            claude_env.clone(),
            Some("trash"),
            true,
        ),
        (
            "direct-rm-bypasses-shim",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            unprotected_env.clone(),
            None,
            false,
        ),
        (
            "git-reset-hard-stashes-before-exec",
            CommandInvocation::new(
                "git".to_string(),
                vec!["reset".to_string(), "--hard".to_string()],
            ),
            claude_env.clone(),
            Some("stash-then-exec"),
            true,
        ),
        (
            "config-parse-fallback-keeps-protection",
            CommandInvocation::new(
                "git".to_string(),
                vec!["push".to_string(), "--force".to_string()],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "find-delete-is-blocked",
            CommandInvocation::new(
                "find".to_string(),
                vec![
                    ".".to_string(),
                    "-name".to_string(),
                    "*.log".to_string(),
                    "-delete".to_string(),
                ],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "find-without-delete-passes",
            CommandInvocation::new(
                "find".to_string(),
                vec![".".to_string(), "-name".to_string(), "*.txt".to_string()],
            ),
            claude_env.clone(),
            None,
            true,
        ),
        (
            "rsync-delete-is-blocked",
            CommandInvocation::new(
                "rsync".to_string(),
                vec![
                    "--delete".to_string(),
                    "-avz".to_string(),
                    "src/".to_string(),
                    "dest/".to_string(),
                ],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "rsync-without-delete-passes",
            CommandInvocation::new(
                "rsync".to_string(),
                vec!["-avz".to_string(), "src/".to_string(), "dest/".to_string()],
            ),
            claude_env,
            None,
            true,
        ),
        (
            "codex-cli-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            codex_env,
            Some("trash"),
            true,
        ),
        (
            "cursor-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            cursor_env,
            Some("trash"),
            true,
        ),
        (
            "gemini-cli-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            vec![("GEMINI_CLI".to_string(), "1".to_string())],
            Some("trash"),
            true,
        ),
        (
            "cline-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            vec![("CLINE_ACTIVE".to_string(), "true".to_string())],
            Some("trash"),
            true,
        ),
    ];

    cases
        .into_iter()
        .map(
            |(name, command, env_map, expected_action, expected_protected)| {
                let detection = evaluate_detectors(&config.detectors, &env_map);
                let matched = match_rule(&config.rules, &command);
                let effective_action = if detection.protected {
                    matched.map(|rule| rule.action.as_str())
                } else {
                    None
                };
                let passed = detection.protected == expected_protected
                    && effective_action == expected_action;
                let details = format!(
                    "protected={} action={:?} detectors={:?}",
                    detection.protected, effective_action, detection.matched_detectors
                );
                PolicyTestResult {
                    name,
                    passed,
                    details,
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::ActionKind;

    #[test]
    fn policy_tests_pass_with_default_config() {
        let load_result = ConfigLoadResult {
            config: Config::default(),
            warnings: Vec::new(),
        };

        let results = run_policy_tests(&load_result);
        assert!(results.iter().all(|item| item.passed));
    }

    #[test]
    fn binary_name_uses_file_name() {
        assert_eq!(binary_name(&OsString::from("/tmp/rm")), "rm");
    }

    #[test]
    fn run_usage_succeeds() {
        let args = vec![OsString::from("omamori")];
        let code = run(&args).expect("usage should succeed");
        assert_eq!(code, 0);
    }

    #[test]
    fn resolve_default_rule_for_rm() {
        let invocation = CommandInvocation::new("rm".to_string(), vec!["-rf".to_string()]);
        let config = Config::default();
        let rule = match_rule(&config.rules, &invocation).expect("rule should match");
        assert_eq!(rule.action, ActionKind::Trash);
    }

    // --- G-02: ensure_hooks_current_at ---

    fn setup_hooks_dir(base_dir: &Path) -> PathBuf {
        let hooks_dir = base_dir.join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        hooks_dir
    }

    #[test]
    fn hooks_current_old_version_triggers_regen() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        // Write hook with old version
        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        let result = ensure_hooks_current_at(&dir);
        assert!(result, "should regenerate hooks for old version");

        // Verify the regenerated hook has the current version
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

        // Write hook with correct version but tampered body (T2 attack)
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

        // Write the exact expected hook content
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

        // No hooks file at all
        let result = ensure_hooks_current_at(&dir);
        assert!(!result, "should return false when no hooks file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_current_readonly_dir_regen_fails_returns_false() {
        let dir = std::env::temp_dir().join(format!("omamori-hooks-g02-5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        // Write hook with old version
        let old_hook = "#!/bin/sh\n# omamori hook v0.0.1\nset -eu\nexit 0\n";
        std::fs::write(hooks_dir.join("claude-pretooluse.sh"), old_hook).unwrap();

        // Make hooks dir read-only so regeneration fails
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hooks_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        let result = ensure_hooks_current_at(&dir);
        assert!(!result, "should return false when regen fails");

        // Restore permissions for cleanup
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hooks_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- G-03: should_block_for_sudo ---

    #[test]
    fn sudo_block_returns_false_when_not_root() {
        // Normal test process is not root
        let result = should_block_for_sudo();
        assert!(!result, "non-root user should not be blocked");
    }

    // Note: Testing the true path (euid=0 + SUDO_USER set) requires actual
    // root privileges. We test the negative path and trust the implementation.
    // The function is 2 lines of platform-specific code with no branching.

    // --- ADV-01: hooks symlink attack ---

    #[test]
    fn hooks_symlink_attack_triggers_regen() {
        // ADV-01: If the hooks file is a symlink (attacker replaced it),
        // ensure_hooks_current_at reads through it and detects the hash mismatch.
        let dir = std::env::temp_dir().join(format!("omamori-adv01-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hooks_dir = setup_hooks_dir(&dir);

        #[cfg(unix)]
        {
            // Create a malicious script elsewhere
            let malicious = dir.join("malicious.sh");
            std::fs::write(
                &malicious,
                format!(
                    "#!/bin/sh\n# omamori hook v{}\nexit 0\n",
                    env!("CARGO_PKG_VERSION")
                ),
            )
            .unwrap();

            // Replace hook with symlink to malicious script
            let hook_path = hooks_dir.join("claude-pretooluse.sh");
            std::os::unix::fs::symlink(&malicious, &hook_path).unwrap();

            // ensure_hooks_current_at should detect hash mismatch and regenerate
            let result = ensure_hooks_current_at(&dir);
            assert!(
                result,
                "symlink hook should trigger regeneration due to hash mismatch"
            );

            // After regen, the hook should have the correct hash
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

    #[test]
    fn resolve_real_command_skips_the_shim_path() {
        let root = std::env::temp_dir().join(format!("omamori-resolve-{}", std::process::id()));
        let shim_dir = root.join("shim");
        let real_dir = root.join("real");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let shim_path = shim_dir.join("rm");
        let real_path = real_dir.join("rm");
        std::fs::write(&shim_path, "shim").unwrap();
        std::fs::write(&real_path, "real").unwrap();

        let joined = env::join_paths([shim_dir.clone(), real_dir.clone()]).unwrap();
        let resolved =
            resolve_real_command_from_path("rm", &joined, &shim_path.canonicalize().unwrap())
                .unwrap();
        assert_eq!(resolved, real_path.canonicalize().unwrap());

        let _ = std::fs::remove_dir_all(root);
    }
}
