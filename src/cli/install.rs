//! `omamori install` and `omamori uninstall` subcommands.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use super::policy_test::run_policy_tests;
use crate::AppError;
use crate::config::{self, load_config};
use crate::engine::guard::guard_ai_config_modification;
use crate::installer::{self, InstallOptions, default_base_dir, install, uninstall};
use crate::util::USAGE_HINT;

pub(crate) fn run_install_command(args: &[OsString]) -> Result<i32, AppError> {
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
                    USAGE_HINT
                )));
            }
        }
    }

    let result = install(&InstallOptions {
        base_dir,
        source_exe,
        generate_hooks,
    })?;

    // --- Summary banner ---
    println!("\nomamori setup complete:\n");

    // Layer 1 (PATH shims)
    println!(
        "  \u{2713} Layer 1 (PATH shims): {}/{} installed",
        result.linked_commands.len(),
        installer::SHIM_COMMANDS.len()
    );

    // Layer 2 (hooks) — aggregate tool statuses
    let mut layer2_warnings: Vec<String> = Vec::new();
    if generate_hooks {
        let l2 = aggregate_layer2_status(&result);
        let layer2_symbol = if l2.warnings.is_empty() {
            "\u{2713}"
        } else {
            "!"
        };
        let layer2_summary = if l2.tools.is_empty() {
            "no tools detected".to_string()
        } else {
            l2.tools.join(", ")
        };
        println!("  {layer2_symbol} Layer 2 (hooks):      {layer2_summary}");
        layer2_warnings = l2.warnings;
    } else {
        println!("  - Layer 2 (hooks):      not requested (run with --hooks)");
    }

    // Config (side effect: auto-create if missing)
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
    println!("  \u{2713} Config:               {config_status}");

    // Policy (auto-test)
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
            "  \u{2713} Policy:               {} rules verified, {} tests passed",
            active_rules,
            test_results.len()
        );
    } else {
        println!(
            "  \u{2717} Policy:               {} test(s) failed \u{2014} run `omamori test` for details",
            failures
        );
    }

    // Warnings (collected from Layer 2)
    if !layer2_warnings.is_empty() {
        println!();
        for w in &layer2_warnings {
            if w.starts_with("  ") {
                println!("    {w}");
            } else {
                println!("  ! {w}");
            }
        }
    }

    // Next steps
    println!("\nNext steps:");
    println!(
        "  Add to ~/.zshrc:  export PATH=\"{}:$PATH\"",
        result.shim_dir.display()
    );
    println!("  Verify:           omamori doctor");
    println!("  Dry-run:          omamori test");

    println!();
    Ok(0)
}

#[derive(Debug)]
struct Layer2Status {
    tools: Vec<String>,
    warnings: Vec<String>,
}

fn aggregate_layer2_status(result: &installer::InstallResult) -> Layer2Status {
    let mut tools = Vec::new();
    let mut warnings = Vec::new();

    // Claude Code
    match &result.claude_settings_outcome {
        Some(installer::ClaudeSettingsOutcome::Skipped(reason)) => {
            warnings.push(format!("Claude Code: {reason}"));
            if result.settings_snippet.is_some() {
                warnings.push("  cat ~/.omamori/hooks/claude-settings.snippet.json".to_string());
            }
        }
        Some(_) => tools.push("Claude Code".to_string()),
        None => {}
    }

    // Codex CLI — both hooks AND config must be OK
    let codex_hooks_ok = matches!(
        &result.codex_hooks_outcome,
        Some(
            installer::CodexHooksOutcome::Created
                | installer::CodexHooksOutcome::Merged
                | installer::CodexHooksOutcome::AlreadyPresent
        )
    );
    let codex_config_disabled = matches!(
        &result.codex_config_outcome,
        Some(installer::CodexConfigOutcome::ExplicitlyDisabled)
    );
    if codex_hooks_ok && !codex_config_disabled {
        tools.push("Codex CLI".to_string());
    } else if codex_hooks_ok && codex_config_disabled {
        warnings.push("Codex CLI: codex_hooks = false (set by user)".to_string());
        warnings.push("  set codex_hooks = true in ~/.codex/config.toml".to_string());
    } else if let Some(installer::CodexHooksOutcome::Skipped(reason)) = &result.codex_hooks_outcome
    {
        warnings.push(format!("Codex CLI: {reason}"));
    }
    if let Some(installer::CodexConfigOutcome::Skipped(reason)) = &result.codex_config_outcome {
        warnings.push(format!("Codex CLI config: {reason}"));
    }

    // Cursor — always manual merge
    if result.cursor_hook_snippet.is_some() {
        warnings.push("Cursor: manual merge needed".to_string());
        warnings.push("  cat ~/.omamori/hooks/cursor-hooks.snippet.json".to_string());
    }

    Layer2Status { tools, warnings }
}

pub(crate) fn run_uninstall_command(args: &[OsString]) -> Result<i32, AppError> {
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
                    USAGE_HINT
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn empty_result() -> installer::InstallResult {
        installer::InstallResult {
            shim_dir: PathBuf::from("/tmp/shim"),
            linked_commands: vec![],
            hook_script: None,
            settings_snippet: None,
            cursor_hook_snippet: None,
            codex_wrapper: None,
            codex_hooks_outcome: None,
            codex_config_outcome: None,
            claude_settings_outcome: None,
        }
    }

    #[test]
    fn all_success_no_cursor() {
        let mut r = empty_result();
        r.claude_settings_outcome = Some(installer::ClaudeSettingsOutcome::Created);
        r.codex_hooks_outcome = Some(installer::CodexHooksOutcome::Created);
        r.codex_config_outcome = Some(installer::CodexConfigOutcome::Added);

        let l2 = aggregate_layer2_status(&r);
        assert_eq!(l2.tools, vec!["Claude Code", "Codex CLI"]);
        assert!(l2.warnings.is_empty());
    }

    #[test]
    fn codex_hooks_ok_but_config_disabled_is_warn() {
        let mut r = empty_result();
        r.claude_settings_outcome = Some(installer::ClaudeSettingsOutcome::Merged);
        r.codex_hooks_outcome = Some(installer::CodexHooksOutcome::Created);
        r.codex_config_outcome = Some(installer::CodexConfigOutcome::ExplicitlyDisabled);

        let l2 = aggregate_layer2_status(&r);
        assert_eq!(l2.tools, vec!["Claude Code"]);
        assert!(
            l2.warnings
                .iter()
                .any(|w| w.contains("codex_hooks = false"))
        );
    }

    #[test]
    fn all_none_no_tools() {
        let r = empty_result();
        let l2 = aggregate_layer2_status(&r);
        assert!(l2.tools.is_empty());
        assert!(l2.warnings.is_empty());
    }

    #[test]
    fn claude_ok_codex_skipped_mixed() {
        let mut r = empty_result();
        r.claude_settings_outcome = Some(installer::ClaudeSettingsOutcome::AlreadyPresent);
        r.codex_hooks_outcome = Some(installer::CodexHooksOutcome::Skipped(
            "not installed".to_string(),
        ));

        let l2 = aggregate_layer2_status(&r);
        assert_eq!(l2.tools, vec!["Claude Code"]);
        assert!(l2.warnings.iter().any(|w| w.contains("not installed")));
    }

    #[test]
    fn cursor_always_warns() {
        let mut r = empty_result();
        r.claude_settings_outcome = Some(installer::ClaudeSettingsOutcome::Created);
        r.cursor_hook_snippet = Some(PathBuf::from("/tmp/cursor-hooks.snippet.json"));

        let l2 = aggregate_layer2_status(&r);
        assert_eq!(l2.tools, vec!["Claude Code"]);
        assert!(l2.warnings.iter().any(|w| w.contains("Cursor")));
    }
}
