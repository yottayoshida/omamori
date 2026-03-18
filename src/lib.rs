pub mod actions;
pub mod audit;
pub mod config;
pub mod detector;
pub mod installer;
pub mod rules;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use actions::{ActionExecutor, ActionOutcome, SystemOps};
use audit::{AuditEvent, AuditLogger};
use config::{ConfigLoadResult, load_config};
use detector::evaluate_detectors;
use installer::{InstallOptions, default_base_dir, install, uninstall};
use rules::{CommandInvocation, match_rule};

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
        Some("cursor-hook") => run_cursor_hook(),
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

    // Detection section
    let results = run_policy_tests(&load_result);
    let failures = results.iter().filter(|r| !r.passed).count();

    println!("\nDetection:");
    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("  {status}  {:<28} {}", result.name, result.details);
    }

    // Summary
    println!(
        "\nSummary: {} rules ({} active, {} disabled), {} detection tests {}",
        config.rules.len(),
        active_count,
        disabled_count,
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
    let mut source_exe = env::current_exe()?;
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
    run_command(program.to_string(), args, None)
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
    let matched_rule = match_rule(&load_result.config.rules, &invocation);

    let resolved_program = resolve_real_command(&program)?;
    let detector_env_keys: Vec<String> = load_result
        .config
        .detectors
        .iter()
        .map(|d| d.env_key.clone())
        .filter(|k| !k.is_empty() && !k.contains('='))
        .collect();
    let mut executor = ActionExecutor::new(SystemOps::new(resolved_program, detector_env_keys));
    let audit_logger = AuditLogger::from_config(&load_result.config.audit);

    let outcome = if should_block_for_sudo() {
        let blocked = ActionOutcome::Blocked {
            message:
                "omamori blocked this command because it was invoked via sudo/elevated privileges"
                    .to_string(),
        };
        eprintln!("{}", blocked.message());
        blocked
    } else if !detection.protected {
        executor.exec_passthrough(&invocation)?
    } else if let Some(rule) = matched_rule {
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

    if let Some(logger) = audit_logger {
        let event = AuditEvent::from_outcome(
            &invocation,
            matched_rule,
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

/// Cursor `beforeShellExecution` hook handler.
/// Reads JSON from stdin, checks command against blocked patterns,
/// writes JSON response to stdout. All logs go to stderr only.
fn run_cursor_hook() -> Result<i32, AppError> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    // Extract "command" field from JSON input
    let command = match serde_json::from_str::<serde_json::Value>(&input) {
        Ok(v) => v
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        Err(_) => {
            // Can't parse → allow (don't block on malformed input)
            eprintln!("omamori cursor-hook: failed to parse stdin JSON");
            print_cursor_response(true, "allow", None, None);
            return Ok(0);
        }
    };

    eprintln!("omamori cursor-hook: command={command}");

    // Check against shared blocked patterns
    for (pattern, reason) in installer::blocked_command_patterns() {
        if command.contains(pattern) {
            eprintln!("omamori cursor-hook: BLOCKED ({reason})");
            print_cursor_response(
                false,
                "deny",
                Some(&format!("omamori hook: {reason}")),
                Some(&format!(
                    "This command was blocked by omamori safety guard: {reason}. Use a safer alternative."
                )),
            );
            return Ok(0);
        }
    }

    // Check for interpreter patterns (warn only, don't block)
    let interpreter_patterns = [
        ("shutil.rmtree", "python shutil.rmtree detected"),
        ("os.remove", "python os.remove detected"),
        ("os.rmdir", "python os.rmdir detected"),
        ("rmSync", "node rmSync detected"),
        ("unlinkSync", "node unlinkSync detected"),
    ];
    // Only check if command involves an interpreter with -c/-e flag
    if (command.contains("python") && command.contains("-c"))
        || (command.contains("node") && command.contains("-e"))
        || (command.contains("bash") && command.contains("-c"))
        || (command.contains("sh") && command.contains("-c"))
    {
        for (pattern, reason) in interpreter_patterns {
            if command.contains(pattern) {
                eprintln!("omamori cursor-hook: WARNING ({reason})");
                print_cursor_response(
                    true,
                    "ask",
                    Some(&format!("omamori warning: {reason}")),
                    Some("This interpreter command may be destructive. Review before proceeding."),
                );
                return Ok(0);
            }
        }
        // bash/sh -c "rm -rf" pattern
        if command.contains("rm -rf") || command.contains("rm -r ") {
            eprintln!("omamori cursor-hook: WARNING (shell rm -rf via interpreter)");
            print_cursor_response(
                true,
                "ask",
                Some("omamori warning: shell rm -rf via interpreter"),
                Some("This interpreter command may be destructive. Review before proceeding."),
            );
            return Ok(0);
        }
    }

    // Allow
    print_cursor_response(true, "allow", None, None);
    Ok(0)
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
            .unwrap_or_else(|_| { r#"{"continue":true,"permission":"allow"}"#.to_string() })
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

fn run_config_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config disable")?;
    validate_rule_name(rule_name)?;

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

    // Show updated config list
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
        let source = if let Some(default) = defaults.get(&rule.name) {
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
