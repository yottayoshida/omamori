//! `omamori setup` — one-command interactive onboarding.
//!
//! Orchestrates: install (shims + hooks) → shell profile → doctor verification.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::AppError;
use crate::config;
use crate::installer::{self, InstallOptions, SHIM_COMMANDS};
use crate::integrity::{self, CheckStatus};
use crate::util::USAGE_HINT;

use super::doctor::is_ai_environment;

const MARKER: &str = "# Added by omamori setup";

#[derive(Debug, Clone, Copy)]
enum ShellKind {
    Zsh,
    Bash,
}

impl ShellKind {
    fn name(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Bash => "bash",
        }
    }
}

pub(crate) fn run_setup_command(args: &[OsString]) -> Result<i32, AppError> {
    // --- Preflight: determine execution mode BEFORE any mutations ---
    let mut dry_run = false;
    let mut non_interactive = false;
    let mut base_dir: Option<PathBuf> = None;
    let mut source_override: Option<PathBuf> = None;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--dry-run" => {
                dry_run = true;
                index += 1;
            }
            "--non-interactive" => {
                non_interactive = true;
                index += 1;
            }
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("setup requires a path after --base-dir".to_string())
                })?;
                base_dir = Some(PathBuf::from(value));
                index += 2;
            }
            "--source" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("setup requires a path after --source".to_string())
                })?;
                source_override = Some(PathBuf::from(value));
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown setup flag: {arg}\n\n{USAGE_HINT}"
                )));
            }
        }
    }

    let custom_base = base_dir.is_some();
    let base_dir = base_dir.unwrap_or_else(installer::default_base_dir);
    let ai_env = is_ai_environment();

    if ai_env {
        non_interactive = true;
    }

    // Non-TTY stdin without --non-interactive: fail BEFORE any file I/O
    if !non_interactive && !dry_run && !io::stdin().is_terminal() {
        eprintln!("error: stdin is not a terminal");
        eprintln!("Use --non-interactive to run without prompts.");
        return Ok(1);
    }

    let shell = detect_shell();
    let profile = shell.and_then(detect_profile_path);

    if dry_run {
        return print_dry_run(&base_dir, shell, profile.as_deref(), custom_base, ai_env);
    }

    // --- [1/3] Install shims and hooks ---
    println!("\nomamori setup \u{2014} one-command installation\n");
    println!("  [1/3] Installing shims and hooks...");

    let (source_exe, source_is_explicit) = match source_override {
        Some(path) => (path, true),
        None => (
            installer::resolve_stable_exe_path(&env::current_exe()?),
            false,
        ),
    };
    let result = installer::install(&InstallOptions {
        base_dir: base_dir.clone(),
        source_exe,
        generate_hooks: true,
        source_is_explicit,
        ..Default::default()
    })?;

    println!(
        "  \u{2713} Layer 1 (PATH shims): {}/{} installed",
        result.linked_commands.len(),
        SHIM_COMMANDS.len()
    );

    let l2_tools = layer2_tool_names(&result);
    let l2_label = if l2_tools.is_empty() {
        "no tools detected".to_string()
    } else {
        l2_tools.join(", ")
    };
    println!("  \u{2713} Layer 2 (hooks):      {l2_label}");

    match config::default_config_path() {
        Some(p) if !p.exists() => match config::write_default_config(&p, false) {
            Ok(_) => println!("  \u{2713} Config:               {}", p.display()),
            Err(e) => println!("  ! Config:               not created: {e}"),
        },
        Some(p) => println!("  \u{2713} Config:               {}", p.display()),
        None => println!("  ! Config:               HOME/XDG_CONFIG_HOME not set"),
    };

    // --- [2/3] Shell profile ---
    println!("\n  [2/3] Shell profile");

    let profile_done = if ai_env {
        println!("  - AI environment detected; skipping profile modification.");
        print_manual_path_instructions(&result.shim_dir);
        false
    } else if custom_base {
        println!("  - Custom --base-dir; add PATH manually:");
        print_manual_path_instructions(&result.shim_dir);
        false
    } else if let (Some(s), Some(profile_path)) = (shell, &profile) {
        handle_profile(profile_path, &result.shim_dir, s, non_interactive)?
    } else if shell.is_none() {
        println!("  - Unknown shell; add PATH manually:");
        print_manual_path_instructions(&result.shim_dir);
        false
    } else {
        println!("  - Shell profile not found; add PATH manually:");
        print_manual_path_instructions(&result.shim_dir);
        false
    };

    // --- [3/3] Verification ---
    println!("\n  [3/3] Verification");
    let report = integrity::full_check(&base_dir);
    let (mut ok_count, mut fail_count, mut warn_count) = (0, 0, 0);
    for item in &report.items {
        match item.status {
            CheckStatus::Ok => ok_count += 1,
            CheckStatus::Fail => fail_count += 1,
            CheckStatus::Warn => warn_count += 1,
        }
    }

    if fail_count == 0 && warn_count == 0 {
        println!("  \u{2713} doctor: OK ({ok_count} checks passed)");
    } else if fail_count == 0 {
        println!("  ! doctor: {ok_count} OK, {warn_count} warning(s)");
    } else {
        println!("  \u{2717} doctor: {fail_count} failed, {warn_count} warning(s)");
    }

    // --- Summary ---
    println!("\n  Setup complete!\n");
    println!("    Protected commands: {}", SHIM_COMMANDS.join(", "));
    if profile_done && let Some(ref p) = profile {
        println!("    \u{25b8} Activate now:  source {}", p.display());
        println!("      (or open a new terminal tab)");
    }
    println!("    Verify anytime:  omamori doctor");
    println!();

    if fail_count > 0 {
        Ok(1)
    } else if profile_done {
        Ok(0)
    } else {
        Ok(2)
    }
}

fn handle_profile(
    profile_path: &Path,
    shim_dir: &Path,
    shell: ShellKind,
    non_interactive: bool,
) -> Result<bool, AppError> {
    // Reject broken symlinks before any read
    if fs::symlink_metadata(profile_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
        && !profile_path.exists()
    {
        eprintln!(
            "  ! {} is a broken symlink; skipping.",
            profile_path.display()
        );
        print_manual_path_instructions(shim_dir);
        return Ok(false);
    }

    // Reject non-regular files (directory, device, etc.) before any read
    if profile_path.exists() && !profile_path.is_file() {
        eprintln!(
            "  ! {} is not a regular file; skipping.",
            profile_path.display()
        );
        print_manual_path_instructions(shim_dir);
        return Ok(false);
    }

    if path_already_configured(profile_path)? {
        println!("  \u{2713} Already in PATH");
        return Ok(true);
    }

    println!("  Detected: {} ({})", shell.name(), profile_path.display());
    println!("  Will add:  export PATH=\"$HOME/.omamori/shim:$PATH\"");

    let should_append = if non_interactive {
        true
    } else {
        println!(
            "  This is safe to undo \u{2014} just delete the last line of {}.",
            profile_path.display()
        );
        prompt_yes_no("  Add to shell profile? [Y/n]: ")
    };

    if !should_append {
        println!("  - Skipped. Add manually:");
        print_manual_path_instructions(shim_dir);
        return Ok(false);
    }

    append_path_to_profile(profile_path)?;
    println!("  \u{2713} Added to {}", profile_path.display());
    Ok(true)
}

fn detect_shell() -> Option<ShellKind> {
    let shell_var = env::var("SHELL").ok()?;
    let basename = Path::new(&shell_var).file_name()?.to_str()?;
    match basename {
        "zsh" => Some(ShellKind::Zsh),
        "bash" => Some(ShellKind::Bash),
        _ => None,
    }
}

fn detect_profile_path(shell: ShellKind) -> Option<PathBuf> {
    let home = PathBuf::from(env::var("HOME").ok()?);
    match shell {
        ShellKind::Zsh => Some(home.join(".zshrc")),
        ShellKind::Bash => {
            let bash_profile = home.join(".bash_profile");
            if bash_profile.exists() {
                Some(bash_profile)
            } else {
                Some(home.join(".bashrc"))
            }
        }
    }
}

fn path_already_configured(profile: &Path) -> Result<bool, AppError> {
    if !profile.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(profile)?;
    Ok(content.contains(MARKER) || content.contains(".omamori/shim"))
}

fn append_path_to_profile(profile: &Path) -> Result<(), AppError> {
    if let Some(parent) = profile.parent() {
        fs::create_dir_all(parent)?;
    }

    let block = format!(
        "\n{MARKER} (v{})\nexport PATH=\"$HOME/.omamori/shim:$PATH\"\n",
        env!("CARGO_PKG_VERSION"),
    );

    let mut file = OpenOptions::new().create(true).append(true).open(profile)?;
    file.write_all(block.as_bytes())?;
    Ok(())
}

fn prompt_yes_no(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    match io::stdin().lock().read_line(&mut input) {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            let trimmed = input.trim();
            trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("y")
                || trimmed.eq_ignore_ascii_case("yes")
        }
    }
}

fn layer2_tool_names(result: &installer::InstallResult) -> Vec<String> {
    let mut tools = Vec::new();
    if matches!(
        &result.claude_settings_outcome,
        Some(
            installer::ClaudeSettingsOutcome::Created
                | installer::ClaudeSettingsOutcome::Merged
                | installer::ClaudeSettingsOutcome::AlreadyPresent
                | installer::ClaudeSettingsOutcome::MatcherMigrated
                | installer::ClaudeSettingsOutcome::StaleEntriesCleaned(_)
        )
    ) {
        tools.push("Claude Code".to_string());
    }
    if matches!(
        &result.codex_hooks_outcome,
        Some(
            installer::CodexHooksOutcome::Created
                | installer::CodexHooksOutcome::Merged
                | installer::CodexHooksOutcome::AlreadyPresent
        )
    ) && !matches!(
        &result.codex_config_outcome,
        Some(installer::CodexConfigOutcome::ExplicitlyDisabled)
    ) {
        tools.push("Codex CLI".to_string());
    }
    tools
}

fn print_manual_path_instructions(shim_dir: &Path) {
    println!("    export PATH=\"{}:$PATH\"", shim_dir.display());
}

fn print_dry_run(
    base_dir: &Path,
    shell: Option<ShellKind>,
    profile: Option<&Path>,
    custom_base: bool,
    ai_env: bool,
) -> Result<i32, AppError> {
    println!("\nomamori setup --dry-run (preview only, no changes)\n");

    println!("  [1/3] Would install shims and hooks");
    println!("    Base dir:  {}", base_dir.display());
    println!("    Shims:     {}", SHIM_COMMANDS.join(", "));
    println!("    Hooks:     enabled");

    println!("\n  [2/3] Shell profile");
    if ai_env {
        println!("    Would skip: AI environment detected");
    } else if custom_base {
        println!("    Would skip: custom --base-dir");
    } else if shell.is_none() {
        println!("    Would skip: unknown shell");
    } else if let Some(p) = profile {
        let already = path_already_configured(p).unwrap_or(false);
        if already {
            println!("    Target:    {}", p.display());
            println!("    Status:    already configured");
        } else {
            println!("    Target:    {}", p.display());
            println!("    Would add: export PATH=\"$HOME/.omamori/shim:$PATH\"");
        }
    } else {
        println!("    Would skip: shell profile not found");
    }

    println!("\n  [3/3] Would run doctor verification");
    println!("\nNo changes made.");
    Ok(0)
}
