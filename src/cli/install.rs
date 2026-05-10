//! `omamori install` and `omamori uninstall` subcommands.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use super::policy_test::run_policy_tests;
use crate::AppError;
use crate::config::{self, load_config};
use crate::engine::guard::guard_ai_config_modification;
use crate::installer::{self, InstallOptions, default_base_dir, install, uninstall};
use crate::util::usage_text;

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
    match &result.claude_settings_outcome {
        Some(installer::ClaudeSettingsOutcome::Created) => {
            println!("  [done] Claude Code settings.json: created ~/.claude/settings.json");
        }
        Some(installer::ClaudeSettingsOutcome::Merged) => {
            println!("  [done] Claude Code settings.json: merged into ~/.claude/settings.json");
        }
        Some(installer::ClaudeSettingsOutcome::AlreadyPresent) => {
            println!("  [skip] Claude Code settings.json: already configured");
        }
        Some(installer::ClaudeSettingsOutcome::MatcherMigrated) => {
            println!(
                "  [migrated] Claude Code settings.json: matcher migrated to current spec (\"Bash\")"
            );
        }
        Some(installer::ClaudeSettingsOutcome::StaleEntriesCleaned(n)) => {
            println!(
                "  [done] Claude Code settings.json: cleaned {n} stale hook(s), merged current entry"
            );
        }
        Some(installer::ClaudeSettingsOutcome::Skipped(reason)) => {
            println!("  [warn] Claude Code settings.json: {reason}");
            println!(
                "         Manual merge needed: cat ~/.omamori/hooks/claude-settings.snippet.json"
            );
        }
        None => {}
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
