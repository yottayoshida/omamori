use std::fs;
use std::path::{Path, PathBuf};

use crate::AppError;

const SHIM_COMMANDS: &[&str] = &["rm", "git", "chmod"];

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub base_dir: PathBuf,
    pub source_exe: PathBuf,
    pub generate_hooks: bool,
}

#[derive(Debug, Clone)]
pub struct InstallResult {
    pub shim_dir: PathBuf,
    pub linked_commands: Vec<String>,
    pub hook_script: Option<PathBuf>,
    pub settings_snippet: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct UninstallResult {
    pub shim_dir: PathBuf,
    pub removed_entries: Vec<PathBuf>,
}

pub fn install(options: &InstallOptions) -> Result<InstallResult, AppError> {
    let shim_dir = options.base_dir.join("shim");
    fs::create_dir_all(&shim_dir)?;

    let source_exe = options
        .source_exe
        .canonicalize()
        .unwrap_or_else(|_| options.source_exe.clone());
    let mut linked_commands = Vec::new();

    for command in SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        recreate_symlink(&source_exe, &link_path)?;
        linked_commands.push((*command).to_string());
    }

    let (hook_script, settings_snippet) = if options.generate_hooks {
        let hooks_dir = options.base_dir.join("hooks");
        fs::create_dir_all(&hooks_dir)?;

        let script_path = hooks_dir.join("claude-pretooluse.sh");
        fs::write(&script_path, render_hook_script())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        let snippet_path = hooks_dir.join("claude-settings.snippet.json");
        fs::write(&snippet_path, render_settings_snippet(&script_path))?;

        (Some(script_path), Some(snippet_path))
    } else {
        (None, None)
    };

    Ok(InstallResult {
        shim_dir,
        linked_commands,
        hook_script,
        settings_snippet,
    })
}

pub fn uninstall(base_dir: &Path) -> Result<UninstallResult, AppError> {
    let shim_dir = base_dir.join("shim");
    let hooks_dir = base_dir.join("hooks");
    let mut removed_entries = Vec::new();

    for command in SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        if link_path.exists() || link_path.is_symlink() {
            fs::remove_file(&link_path)?;
            removed_entries.push(link_path);
        }
    }

    for path in [
        hooks_dir.join("claude-pretooluse.sh"),
        hooks_dir.join("claude-settings.snippet.json"),
    ] {
        if path.exists() {
            fs::remove_file(&path)?;
            removed_entries.push(path);
        }
    }

    remove_dir_if_empty(&hooks_dir)?;
    remove_dir_if_empty(&shim_dir)?;
    remove_dir_if_empty(base_dir)?;

    Ok(UninstallResult {
        shim_dir,
        removed_entries,
    })
}

pub fn default_base_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".omamori")
}

fn recreate_symlink(source: &Path, link_path: &Path) -> Result<(), AppError> {
    if link_path.exists() || link_path.is_symlink() {
        fs::remove_file(link_path)?;
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(source, link_path)?;

    #[cfg(not(unix))]
    std::os::windows::fs::symlink_file(source, link_path)?;

    Ok(())
}

fn remove_dir_if_empty(path: &Path) -> Result<(), AppError> {
    if path.is_dir() && fs::read_dir(path)?.next().is_none() {
        fs::remove_dir(path)?;
    }

    Ok(())
}

fn render_hook_script() -> String {
    r#"#!/bin/sh
set -eu

INPUT="$(cat)"

case "$INPUT" in
  *"/bin/rm"*|*"/usr/bin/rm"*)
    echo "omamori hook: blocked direct rm path that bypasses PATH shim" >&2
    exit 2
    ;;
  *"unset CLAUDECODE"*|*"env -u CLAUDECODE"*|*"CLAUDECODE="*)
    echo "omamori hook: blocked attempt to unset the Claude detector env var" >&2
    exit 2
    ;;
  *)
    exit 0
    ;;
esac
"#
    .to_string()
}

fn render_settings_snippet(script_path: &Path) -> String {
    format!(
        "{{\n  \"hooks\": {{\n    \"PreToolUse\": [{{\n      \"matcher\": \"*\",\n      \"command\": \"{}\"\n    }}]\n  }}\n}}\n",
        script_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_creates_shims_and_hook_templates() {
        let root = std::env::temp_dir().join(format!("omamori-install-{}", std::process::id()));
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();

        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source_exe: source.clone(),
            generate_hooks: true,
        })
        .unwrap();

        assert!(result.shim_dir.join("rm").exists());
        assert!(result.hook_script.unwrap().exists());
        assert!(result.settings_snippet.unwrap().exists());

        let _ = fs::remove_dir_all(root);
    }
}
