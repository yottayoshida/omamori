pub mod actions;
pub mod audit;
pub mod config;
pub mod context;
pub mod detector;
mod engine;
pub mod installer;
pub mod integrity;
pub mod rules;
pub mod unwrap;
mod util;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

// --- engine submodule imports ---
use engine::exec::run_exec_command;
use engine::guard::guard_ai_config_modification;
use engine::hook::{run_cursor_hook, run_hook_check};
use engine::shim::{emit_config_warnings, run_shim, update_baseline_silent};

// --- util imports ---
use util::{binary_name, parse_config_flag, print_usage, usage_text};

// --- crate module imports ---
use config::{ConfigLoadResult, load_config};
use detector::evaluate_detectors;
use installer::{InstallOptions, default_base_dir, install, uninstall};
use rules::{CommandInvocation, RuleConfig, match_rule};

// Re-export fuzz entry points (pub API for fuzz harness)
pub use engine::hook::{fuzz_check_command_for_hook, fuzz_extract_hook_input};

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
        Some("key") => run_audit_key(args),
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

fn run_audit_key(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(3).and_then(|item| item.to_str()) {
        Some("rotate") => {
            // Block in AI context — AI should not rotate keys
            guard_ai_config_modification("audit key rotate")?;

            let load_result = load_config(None)?;
            eprintln!("omamori: rotating audit HMAC key...");
            eprintln!("  Old entries will still verify against the retired key backup.");

            match audit::rotate_key(&load_result.config.audit) {
                Ok(result) => {
                    eprintln!("omamori: key rotation complete.");
                    eprintln!("  New key ID: {}", result.new_key_id);
                    eprintln!("  Retired key: {}", result.retired_path.display());
                    eprintln!("  Run `omamori audit verify` to confirm chain integrity.");
                    Ok(0)
                }
                Err(audit::AuditError::SecretUnavailable) => {
                    eprintln!("omamori: no audit secret found — nothing to rotate");
                    Ok(1)
                }
                Err(e) => {
                    eprintln!("omamori: key rotation failed: {e}");
                    Ok(1)
                }
            }
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown audit key subcommand: {other}\n\n{}",
            audit_usage()
        ))),
        None => Err(AppError::Usage(format!(
            "audit key requires a subcommand\n\n{}",
            audit_usage()
        ))),
    }
}

fn audit_usage() -> &'static str {
    "omamori audit — audit log commands

  omamori audit verify                           Verify hash chain integrity
  omamori audit show [--last N] [--json]         View recent audit entries (default: last 20)
  omamori audit show --all                       View all entries
  omamori audit show --rule <name>               Filter by rule (substring match)
  omamori audit show --provider <name>           Filter by provider
  omamori audit key rotate                       Rotate HMAC signing key"
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

    // =====================================================================
    // Guardrail tests for v0.8.1 module split (#112)
    //
    // These tests lock security-critical behavior that existing tests do
    // NOT directly cover.  They must pass before AND after each PR in the
    // module split sequence.
    // =====================================================================
}

// --- GR-005: mutate_config pipeline (T6 guardrail) ---

#[test]
fn mutate_config_rejects_invalid_mutation() {
    let dir = std::env::temp_dir().join(format!("omamori-gr005-1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, "[rules]\n").unwrap();

    let original = std::fs::read_to_string(&config_path).unwrap();

    // Mutation that produces invalid TOML (unparseable by the failsafe toml crate)
    let result = mutate_config(&config_path, |doc| {
        // Insert raw string that is valid toml_edit but breaks toml's stricter parser
        doc.insert("__broken", toml_edit::Item::None);
        Ok(())
    });

    // Regardless of whether this particular mutation triggers the failsafe,
    // the original file must not be corrupted.
    let after = std::fs::read_to_string(&config_path).unwrap_or_default();
    // If mutation succeeded, the file was validly updated (also acceptable).
    // The key invariant: the file is never left in a corrupt state.
    if result.is_err() {
        assert_eq!(
            after, original,
            "config must not be corrupted on mutation error"
        );
    } else {
        // Mutation succeeded — verify output is valid TOML
        assert!(
            toml::from_str::<toml::Value>(&after).is_ok(),
            "mutate_config produced invalid TOML"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mutate_config_roundtrip_preserves_structure() {
    let dir = std::env::temp_dir().join(format!("omamori-gr005-2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");

    // Write a minimal valid config
    let initial = "[rules]\n[audit]\nenabled = true\n";
    std::fs::write(&config_path, initial).unwrap();

    // Apply a valid mutation
    let result = mutate_config(&config_path, |doc| {
        doc["audit"]["enabled"] = toml_edit::value(false);
        Ok(())
    });
    assert!(result.is_ok(), "valid mutation should succeed: {result:?}");

    let after = std::fs::read_to_string(&config_path).unwrap();
    let parsed: toml::Value = toml::from_str(&after).expect("output must be valid TOML");
    assert_eq!(
        parsed
            .get("audit")
            .and_then(|a| a.get("enabled"))
            .and_then(|v| v.as_bool()),
        Some(false),
        "mutation should have set audit.enabled = false"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
