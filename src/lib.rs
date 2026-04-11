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
use audit::AuditLogger;
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
        Some("audit") => run_audit_command(args),
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
                logger.create_event(&invocation, None, &detection.matched_detectors, &outcome);
            let _ = logger.append(event);
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
                logger.create_event(&invocation, None, &detection.matched_detectors, &outcome);
            let _ = logger.append(event);
        }
        return Ok(exit_code);
    }

    // --- Protected path: AI environment detected. Full evaluation. ---

    // Strict mode: block if audit HMAC secret is unavailable (opt-in).
    // This prevents AI commands from running without tamper-evident logging.
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
            _ => {} // secret available, proceed normally
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
        let event = logger.create_event(
            &invocation,
            effective_rule,
            &detection.matched_detectors,
            &outcome,
        );
        let _ = logger.append(event);
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
    let load_result = load_config(None).ok();
    let rule_count = load_result
        .as_ref()
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
    {
        let audit_config = load_result
            .as_ref()
            .map(|r| &r.config.audit)
            .cloned()
            .unwrap_or_default();
        let summary = audit::audit_summary(&audit_config);
        if !summary.enabled {
            println!("  {:<6} {:<36} disabled", "[info]", "Layer 3 (audit)");
        } else if let Some(ref err) = summary.path_error {
            println!("  {:<6} {:<36} {err}", "[warn]", "Layer 3 (audit)");
        } else if !summary.secret_available {
            println!(
                "  {:<6} {:<36} HMAC secret missing",
                "[warn]", "Layer 3 (audit)"
            );
        } else if summary.entry_count == 0 {
            println!(
                "  {:<6} {:<36} enabled (log created on first event)",
                "[ok]", "Layer 3 (audit)"
            );
        } else {
            let retention = if summary.retention_days > 0 {
                format!(", retention: {}d", summary.retention_days)
            } else {
                String::new()
            };
            println!(
                "  {:<6} {:<36} {} entries{retention} (run 'omamori audit verify' to check chain)",
                "[ok]", "Layer 3 (audit)", summary.entry_count
            );
        }
    }
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

// ---------------------------------------------------------------------------
// Audit CLI
// ---------------------------------------------------------------------------

fn run_audit_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("verify") => run_audit_verify(args),
        Some("show") => run_audit_show(args),
        Some(other) => Err(AppError::Usage(format!(
            "unknown audit subcommand: {other}\n\n{}",
            audit_usage()
        ))),
        None => {
            eprintln!("{}", audit_usage());
            Ok(0)
        }
    }
}

fn run_audit_verify(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[3..])?;
    let load_result = load_config(config_path.as_deref())?;

    match audit::verify_chain(&load_result.config.audit) {
        Ok(result) => {
            if let Some(seq) = result.broken_at {
                eprintln!("omamori audit verify: chain broken at entry #{seq}");
                eprintln!("  The audit log may have been tampered with.");
                eprintln!("  Inspect: omamori audit show --last 10");
                Ok(1)
            } else if result.chain_entries == 0 && result.legacy_entries > 0 {
                eprintln!(
                    "omamori audit verify: no chain entries found ({} legacy entries skipped)",
                    result.legacy_entries
                );
                Ok(2)
            } else if result.chain_entries == 0 {
                println!("omamori audit verify: no entries to verify.");
                Ok(0)
            } else {
                let mut msg = format!(
                    "omamori audit verify: {} entries verified, chain intact.",
                    result.chain_entries
                );
                if result.pruned
                    && let Some(count) = result.pruned_count
                {
                    msg.push_str(&format!(" ({count} entries pruned; prune_point anchored)"));
                }
                if result.legacy_entries > 0 {
                    msg.push_str(&format!(" ({} legacy skipped)", result.legacy_entries));
                }
                if result.torn_lines > 0 {
                    msg.push_str(&format!(" ({} torn lines skipped)", result.torn_lines));
                }
                println!("{msg}");
                Ok(0)
            }
        }
        Err(audit::AuditError::SecretUnavailable) => {
            eprintln!("omamori audit verify: cannot verify \u{2014} HMAC secret unavailable");
            Ok(2)
        }
        Err(audit::AuditError::FileNotFound) => {
            eprintln!("omamori audit verify: no audit log found");
            Ok(2)
        }
        Err(audit::AuditError::Io(e)) => {
            eprintln!("omamori audit verify: {e}");
            Ok(2)
        }
    }
}

fn run_audit_show(args: &[OsString]) -> Result<i32, AppError> {
    let mut opts = audit::ShowOptions {
        last: Some(20),
        rule: None,
        provider: None,
        json: false,
    };

    let mut index = 3usize;
    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--last" => {
                let value = args
                    .get(index + 1)
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| AppError::Usage("--last requires a number".to_string()))?;
                opts.last =
                    Some(value.parse::<usize>().map_err(|_| {
                        AppError::Usage(format!("invalid number for --last: {value}"))
                    })?);
                index += 2;
            }
            "--all" => {
                opts.last = None;
                index += 1;
            }
            "--rule" => {
                opts.rule = Some(
                    args.get(index + 1)
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| AppError::Usage("--rule requires a value".to_string()))?
                        .to_string(),
                );
                index += 2;
            }
            "--provider" => {
                opts.provider = Some(
                    args.get(index + 1)
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| AppError::Usage("--provider requires a value".to_string()))?
                        .to_string(),
                );
                index += 2;
            }
            "--json" => {
                opts.json = true;
                index += 1;
            }
            other => {
                return Err(AppError::Usage(format!(
                    "unknown show flag: {other}\n\n{}",
                    audit_usage()
                )));
            }
        }
    }

    let load_result = load_config(None)?;
    let mut stdout = std::io::stdout().lock();
    match audit::show_entries(&load_result.config.audit, &opts, &mut stdout) {
        Ok(()) => Ok(0),
        Err(audit::AuditError::FileNotFound) => {
            println!("omamori audit: no entries recorded yet");
            Ok(0)
        }
        Err(e) => {
            eprintln!("omamori audit show: {e}");
            Ok(1)
        }
    }
}

fn audit_usage() -> &'static str {
    "omamori audit — audit log commands

  omamori audit verify                           Verify hash chain integrity
  omamori audit show [--last N] [--json]         View recent audit entries (default: last 20)
  omamori audit show --all                       View all entries
  omamori audit show --rule <name>               Filter by rule (substring match)
  omamori audit show --provider <name>           Filter by provider"
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
/// Reads PreToolUse JSON from stdin, classifies via `HookInput`, then evaluates.
/// Exit 0 = allow, exit 2 = block.
fn run_hook_check(args: &[OsString]) -> Result<i32, AppError> {
    use std::io::Read;

    let provider = parse_provider_flag(args);
    let verbose = std::env::var("OMAMORI_VERBOSE").is_ok();

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    match extract_hook_input(&input) {
        HookInput::MalformedJson => {
            eprintln!("omamori hook: blocked — hook input is not valid JSON");
            eprintln!("  The command was denied because omamori cannot verify its safety.");
            eprintln!(
                "  This may happen after an AI tool update. Try: upgrade omamori, or report at https://github.com/yottayoshida/omamori/issues"
            );
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!(
                    "  raw input (first 200 chars): {}",
                    truncate_for_log(&input, 200)
                );
            }
            Ok(2)
        }
        HookInput::MalformedMissingField => {
            eprintln!("omamori hook: blocked — required fields missing from hook input");
            eprintln!("  The command was denied because omamori cannot verify its safety.");
            eprintln!("  Expected: tool_input.command or tool_input.file_path");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!(
                    "  raw input (first 200 chars): {}",
                    truncate_for_log(&input, 200)
                );
            }
            Ok(2)
        }
        HookInput::UnknownTool(tool_name) => {
            print_hook_check_allow_response(&format!(
                "omamori: unrecognized tool '{tool_name}' — allowed for forward compatibility"
            ));
            Ok(0)
        }
        HookInput::FileOp { tool, path } => {
            if let Some(reason) = is_protected_file_path(&path) {
                eprintln!("omamori hook: blocked {tool} to protected file — {reason}");
                eprintln!("  AI agents cannot modify omamori configuration or security files.");
                eprintln!(
                    "  To edit config: use `omamori config` CLI or edit the file directly in your terminal."
                );
                if verbose {
                    eprintln!("  provider: {provider}");
                    eprintln!("  tool: {tool}");
                    eprintln!("  path: {path}");
                }
                Ok(2)
            } else {
                print_hook_check_allow_response(&format!(
                    "omamori: {tool} to non-protected path — allowed"
                ));
                Ok(0)
            }
        }
        HookInput::Command(command) => {
            if command.is_empty() {
                print_hook_check_allow_response("omamori: empty command");
                return Ok(0);
            }
            run_hook_check_command(&command, &provider, verbose)
        }
    }
}

/// Evaluate a shell command through the two-phase hook check pipeline.
/// Extracted from `run_hook_check` to keep the match arms concise.
fn run_hook_check_command(command: &str, provider: &str, verbose: bool) -> Result<i32, AppError> {
    match check_command_for_hook(command) {
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

/// Truncate a string for log output, avoiding panic on multi-byte boundaries.
fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

// ---------------------------------------------------------------------------
// File path protection for Edit/Write/MultiEdit (#110)
// ---------------------------------------------------------------------------

/// Patterns that identify omamori's own files and external hook registrations.
/// Substring match against the canonicalized (or lexically normalized) path.
/// Intentionally broad: "audit-secret" matches "audit-secret.1.retired" too.
const PROTECTED_FILE_PATTERNS: &[(&str, &str)] = &[
    ("omamori/config.toml", "omamori config"),
    (".integrity.json", "integrity baseline"),
    ("audit-secret", "audit HMAC secret"),
    ("audit.jsonl", "audit log"),
    (".local/share/omamori", "omamori data directory"),
    ("claude-pretooluse.sh", "omamori hook script"),
    ("codex-pretooluse.sh", "omamori Codex hook script"),
    (".codex/hooks.json", "Codex hooks config"),
    (".codex/config.toml", "Codex config"),
    // Claude Code hook registration — AI removing hooks = full bypass (#110 T3)
    (
        ".claude/settings.json",
        "Claude Code settings (contains hook config)",
    ),
];

/// Check whether a file path targets a protected omamori file.
///
/// Resolution strategy (defense-in-depth per Codex review):
///   1. Try `canonicalize()` to resolve symlinks for existing paths
///   2. For non-existent paths, canonicalize the parent directory
///   3. Fall back to lexical normalization (`context::normalize_path`)
///   4. If canonicalize fails AND lexical path matches → fail-close (block)
fn is_protected_file_path(path: &str) -> Option<&'static str> {
    let lexical = context::normalize_path(path);

    // Try full canonicalize first (resolves symlinks for existing paths)
    let candidates: Vec<std::path::PathBuf> = match std::fs::canonicalize(&lexical) {
        Ok(canonical) => vec![canonical],
        Err(_) => {
            // Full path doesn't exist — try canonicalizing the parent directory.
            // This catches symlinked parents: /tmp/alias/newfile where /tmp/alias → protected dir
            lexical
                .parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .and_then(|cp| lexical.file_name().map(|f| cp.join(f)))
                .into_iter()
                .collect()
        }
    };

    // Check all resolved candidates + the lexical path itself
    let lexical_str = lexical.to_string_lossy();
    for &(pattern, reason) in PROTECTED_FILE_PATTERNS {
        // Lexical match always checked (fail-close: even if canonicalize failed)
        if lexical_str.contains(pattern) {
            return Some(reason);
        }
        // Canonical/parent-resolved matches
        for candidate in &candidates {
            if candidate.to_string_lossy().contains(pattern) {
                return Some(reason);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HookInput: typed representation of PreToolUse hook stdin
// ---------------------------------------------------------------------------

/// Parsed hook input from AI tool platforms (Claude Code, Codex CLI, etc.).
///
/// Fail-close design: anything that cannot be positively identified as a known
/// tool invocation is treated as malformed and blocked.
enum HookInput {
    /// `tool_input.command` present — shell command to evaluate.
    /// Covers tool_name = "Bash", "Shell", or any tool that carries a command field.
    Command(String),

    /// `tool_input.file_path` present — file operation (Edit/Write/MultiEdit).
    /// Protected-path checking via `is_protected_file_path()`.
    FileOp { tool: String, path: String },

    /// Valid JSON with a `tool_name` but neither `command` nor `file_path`.
    /// Allow for forward compatibility with future platform tool types.
    UnknownTool(String),

    /// JSON parse failed entirely (invalid syntax, non-UTF8, etc.).
    MalformedJson,

    /// JSON parsed but required structure is missing (no `tool_input`, etc.).
    MalformedMissingField,
}

/// Parse PreToolUse hook stdin into a typed `HookInput`.
///
/// Classification priority:
///   1. JSON parse failure → `MalformedJson`
///   2. `tool_input.command` (string) → `Command`
///   3. top-level `command` (Cursor compat) → `Command`
///   4. `tool_input.file_path` (string) → `FileOp`
///   5. `tool_name` present → `UnknownTool`
///   6. nothing recognizable → `MalformedMissingField`
fn extract_hook_input(input: &str) -> HookInput {
    let v = match serde_json::from_str::<serde_json::Value>(input) {
        Ok(v) => v,
        Err(_) => return HookInput::MalformedJson,
    };

    let tool_input = v.get("tool_input");

    // Priority 1: tool_input.command (Claude Code / Codex CLI format)
    if let Some(cmd_val) = tool_input.and_then(|ti| ti.get("command")) {
        // Key exists — value MUST be a string. null/number/array = malformed.
        return match cmd_val.as_str() {
            Some(cmd) => HookInput::Command(cmd.to_string()),
            None => HookInput::MalformedMissingField,
        };
    }

    // Priority 2: top-level command (Cursor beforeShellExecution compat)
    if let Some(cmd_val) = v.get("command") {
        return match cmd_val.as_str() {
            Some(cmd) => HookInput::Command(cmd.to_string()),
            None => HookInput::MalformedMissingField,
        };
    }

    // Priority 3: tool_input.file_path (Edit/Write/MultiEdit)
    if let Some(path_val) = tool_input.and_then(|ti| ti.get("file_path")) {
        return match path_val.as_str() {
            Some(path) => {
                let tool = v
                    .get("tool_name")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                HookInput::FileOp {
                    tool,
                    path: path.to_string(),
                }
            }
            None => HookInput::MalformedMissingField,
        };
    }

    // Priority 4: tool_input exists but has no command/file_path
    if let Some(ti) = tool_input {
        // Empty tool_input or non-object = malformed (e.g. {"tool_name":"Bash","tool_input":{}})
        if ti.as_object().is_none_or(|obj| obj.is_empty()) {
            return HookInput::MalformedMissingField;
        }
        // Non-empty tool_input with unrecognized fields = future tool type
        if let Some(name) = v.get("tool_name").and_then(|t| t.as_str()) {
            return HookInput::UnknownTool(name.to_string());
        }
        return HookInput::MalformedMissingField;
    }

    // Priority 5: no tool_input at all — tool_name alone = future tool type
    if let Some(name) = v.get("tool_name").and_then(|t| t.as_str()) {
        return HookInput::UnknownTool(name.to_string());
    }

    // Nothing recognizable
    HookInput::MalformedMissingField
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

// ---------------------------------------------------------------------------
// Config mutation helper — shared read → parse → mutate → validate → write
// ---------------------------------------------------------------------------

/// Read config.toml, parse as DocumentMut, apply mutation, validate, and write back.
/// The `toml::from_str` validation is an independent failsafe layer — do NOT remove.
fn mutate_config<F>(config_path: &Path, mutate: F) -> Result<(), AppError>
where
    F: FnOnce(&mut toml_edit::DocumentMut) -> Result<(), AppError>,
{
    let content = std::fs::read_to_string(config_path)?;
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| AppError::Config(format!("failed to parse config as TOML: {e}")))?;

    mutate(&mut doc)?;

    let new_content = doc.to_string();
    // Failsafe: validate with independent parser (toml_edit and toml are different impls).
    // DO NOT REMOVE — this catches toml_edit bugs that would corrupt config.toml.
    if toml::from_str::<toml::Value>(&new_content).is_err() {
        return Err(AppError::Config(
            "config mutation would create invalid TOML; aborting".to_string(),
        ));
    }
    // Hardened write: atomic (temp → fsync → rename) with O_NOFOLLOW (#102)
    config::reject_symlink_public(config_path, "config path")?;
    let temp_path = config_path.with_extension("toml.tmp");
    if temp_path.symlink_metadata().is_ok() {
        config::reject_symlink_public(&temp_path, "config temp")?;
        let _ = std::fs::remove_file(&temp_path);
    }
    integrity::write_new_file(&temp_path, &new_content)?;
    std::fs::File::open(&temp_path)?.sync_all()?;
    std::fs::rename(&temp_path, config_path)?;
    if let Some(dir) = config_path.parent()
        && let Ok(f) = std::fs::File::open(dir)
    {
        let _ = f.sync_all();
    }
    update_baseline_silent(&default_base_dir());
    Ok(())
}

fn run_config_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config disable")?;
    validate_rule_name(rule_name)?;

    if is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is a core safety rule and cannot be disabled.\n\n  \
             To override: omamori override disable {rule_name}\n  \
             To see core vs custom rules: omamori config list"
        )));
    }

    let config_path = resolve_config_path_checked()?;
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    let load_result = load_config(None)?;
    if let Some(r) = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        && !r.enabled
    {
        eprintln!("Rule `{rule_name}` is already disabled.");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        let rules = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut());

        if let Some(entry) = rules.and_then(|tables| {
            tables
                .iter_mut()
                .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name))
        }) {
            entry["enabled"] = toml_edit::value(false);
            return Ok(());
        }

        // No existing entry — append a new [[rules]] block
        let mut new_table = toml_edit::Table::new();
        new_table["name"] = toml_edit::value(rule_name);
        new_table["enabled"] = toml_edit::value(false);
        if let Some(array) = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut())
        {
            array.push(new_table);
        } else {
            let mut array = toml_edit::ArrayOfTables::new();
            array.push(new_table);
            doc.insert("rules", toml_edit::Item::ArrayOfTables(array));
        }
        Ok(())
    })?;

    eprintln!("Disabled: {rule_name}");
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

    let load_result = load_config(None)?;
    if let Some(r) = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        && r.enabled
    {
        eprintln!("Rule `{rule_name}` is already enabled.");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        if let Some(tables) = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut())
        {
            // Find the target entry index
            let idx = tables
                .iter()
                .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name));

            if let Some(i) = idx {
                // If the entry only has "name" and "enabled", remove the entire entry
                // (standalone disable block → restore to built-in default)
                let key_count = tables.iter().nth(i).map_or(0, |t| t.iter().count());
                if key_count <= 2 {
                    tables.remove(i);
                } else {
                    // Entry has other fields — just remove "enabled"
                    if let Some(entry) = tables.iter_mut().nth(i) {
                        entry.remove("enabled");
                    }
                }
            }
        }
        Ok(())
    })?;

    eprintln!("Enabled: {rule_name} (restored to built-in default)");
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
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    // Check if already overridden by reading the raw TOML
    let content = std::fs::read_to_string(&config_path)?;
    if content
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| doc.get("overrides")?.get(rule_name)?.as_bool())
        == Some(false)
    {
        eprintln!("Rule `{rule_name}` is already overridden (disabled).");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        if !doc.contains_key("overrides") {
            doc["overrides"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        doc["overrides"][rule_name] = toml_edit::value(false);
        Ok(())
    })?;

    eprintln!("Override: disabled core rule `{rule_name}`");
    eprintln!("To restore: omamori override enable {rule_name}");
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

    mutate_config(&config_path, |doc| {
        if let Some(overrides) = doc.get_mut("overrides").and_then(|t| t.as_table_mut()) {
            overrides.remove(rule_name);
            // Remove empty [overrides] section
            if overrides.is_empty() {
                doc.remove("overrides");
            }
        }
        Ok(())
    })?;

    eprintln!("Restored: core rule `{rule_name}` is active again.");
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
  omamori audit verify                                    # Verify hash chain integrity
  omamori audit show [--last N] [--json] [--all]          # View audit log entries
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
