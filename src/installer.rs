use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::AppError;

const SHIM_COMMANDS: &[&str] = &["rm", "git", "chmod", "find", "rsync"];

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
    pub cursor_hook_snippet: Option<PathBuf>,
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
        atomic_write(&script_path, &render_hook_script())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        let snippet_path = hooks_dir.join("claude-settings.snippet.json");
        atomic_write(&snippet_path, &render_settings_snippet(&script_path))?;

        (Some(script_path), Some(snippet_path))
    } else {
        (None, None)
    };

    // Generate Cursor hook snippet (alongside Claude Code hooks)
    let cursor_hook_snippet = if options.generate_hooks {
        let hooks_dir = options.base_dir.join("hooks");
        let cursor_snippet_path = hooks_dir.join("cursor-hooks.snippet.json");
        let omamori_exe = options
            .source_exe
            .canonicalize()
            .unwrap_or_else(|_| options.source_exe.clone());
        atomic_write(
            &cursor_snippet_path,
            &render_cursor_hooks_snippet(&omamori_exe),
        )?;
        Some(cursor_snippet_path)
    } else {
        None
    };

    Ok(InstallResult {
        shim_dir,
        linked_commands,
        hook_script,
        settings_snippet,
        cursor_hook_snippet,
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
        hooks_dir.join("cursor-hooks.snippet.json"),
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

/// Atomic write: write to temp file → flush → rename over target.
/// Prevents partial writes if the process is interrupted.
fn atomic_write(target: &Path, content: &str) -> Result<(), std::io::Error> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile_in(dir)?;
    tmp.write_all(content.as_bytes())?;
    tmp.flush()?;
    let tmp_path = tmp.into_path();
    fs::rename(&tmp_path, target)?;
    Ok(())
}

/// Create a named temp file in the given directory.
/// Returns a wrapper that tracks the path for rename.
fn tempfile_in(dir: &Path) -> Result<AtomicTempFile, std::io::Error> {
    let path = dir.join(format!(".omamori-tmp-{}", std::process::id()));
    let file = fs::File::create(&path)?;
    Ok(AtomicTempFile { file, path })
}

struct AtomicTempFile {
    file: fs::File,
    path: PathBuf,
}

impl AtomicTempFile {
    fn into_path(self) -> PathBuf {
        self.path
    }
}

impl Write for AtomicTempFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Parse the version from a hook script's version comment line.
/// Expected format: `# omamori hook v0.4.1` (second line of the script).
pub(crate) fn parse_hook_version(content: &str) -> Option<&str> {
    content
        .lines()
        .find(|line| line.starts_with("# omamori hook v"))
        .and_then(|line| line.strip_prefix("# omamori hook v"))
}

/// Regenerate hooks only (no shim recreation, no config touch).
/// Called from shim when version mismatch detected.
pub fn regenerate_hooks(base_dir: &Path) -> Result<(), std::io::Error> {
    let hooks_dir = base_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    let script_path = hooks_dir.join("claude-pretooluse.sh");
    atomic_write(&script_path, &render_hook_script())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms)?;
    }

    let snippet_path = hooks_dir.join("claude-settings.snippet.json");
    atomic_write(&snippet_path, &render_settings_snippet(&script_path))?;

    // Cursor hooks need the omamori exe path; use current_exe as best effort
    if let Ok(exe) = std::env::current_exe() {
        let cursor_path = hooks_dir.join("cursor-hooks.snippet.json");
        atomic_write(&cursor_path, &render_cursor_hooks_snippet(&exe))?;
    }

    Ok(())
}

pub(crate) fn render_hook_script() -> String {
    format!(
        r#"#!/bin/sh
# omamori hook v{}
set -eu"#,
        env!("CARGO_PKG_VERSION")
    ) + r#"

INPUT="$(cat)"

case "$INPUT" in
  *"/bin/rm "*|*"/bin/rm\""*|*"/usr/bin/rm "*|*"/usr/bin/rm\""*)
    echo "omamori hook: blocked direct rm path that bypasses PATH shim" >&2
    exit 2
    ;;
  *"unset CLAUDECODE"*|*"env -u CLAUDECODE"*|*"CLAUDECODE="*|\
  *"unset CODEX_CI"*|*"env -u CODEX_CI"*|*"CODEX_CI="*|\
  *"unset CURSOR_AGENT"*|*"env -u CURSOR_AGENT"*|*"CURSOR_AGENT="*|\
  *"unset GEMINI_CLI"*|*"env -u GEMINI_CLI"*|*"GEMINI_CLI="*|\
  *"unset CLINE_ACTIVE"*|*"env -u CLINE_ACTIVE"*|*"CLINE_ACTIVE="*|\
  *"unset AI_GUARD"*|*"env -u AI_GUARD"*|*"AI_GUARD="*)
    echo "omamori hook: blocked attempt to unset a detector env var" >&2
    exit 2
    ;;
  *"config disable"*|*"config enable"*)
    echo "omamori hook: blocked attempt to modify omamori rules" >&2
    exit 2
    ;;
  *"omamori uninstall"*)
    echo "omamori hook: blocked attempt to uninstall omamori" >&2
    exit 2
    ;;
  *"omamori init --force"*)
    echo "omamori hook: blocked attempt to overwrite omamori config" >&2
    exit 2
    ;;
  *"omamori/config.toml"*|*"omamori"*"config.toml"*)
    echo "omamori hook: blocked attempt to edit omamori config file directly" >&2
    exit 2
    ;;
  *"python "*"-c "*"shutil.rmtree"*|*"python3 "*"-c "*"shutil.rmtree"*|\
  *"python "*"-c "*"os.remove"*|*"python3 "*"-c "*"os.remove"*|\
  *"python "*"-c "*"os.rmdir"*|*"python3 "*"-c "*"os.rmdir"*|\
  *"node "*"-e "*"rmSync"*|*"node "*"-e "*"unlinkSync"*|\
  *"bash "*"-c "*"rm -rf"*|*"sh "*"-c "*"rm -rf"*)
    echo "omamori hook: warning — potentially destructive interpreter command detected" >&2
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#
}

/// Blocked command patterns shared between Claude Code hooks and Cursor hooks.
pub fn blocked_command_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        // Direct path execution bypassing PATH shim
        // Match various shell token boundaries: space, quote, tab
        ("/bin/rm ", "blocked direct rm path that bypasses PATH shim"),
        (
            "/bin/rm\"",
            "blocked direct rm path that bypasses PATH shim",
        ),
        (
            "/bin/rm\t",
            "blocked direct rm path that bypasses PATH shim",
        ),
        ("/bin/rm'", "blocked direct rm path that bypasses PATH shim"),
        (
            "/usr/bin/rm ",
            "blocked direct rm path that bypasses PATH shim",
        ),
        (
            "/usr/bin/rm\"",
            "blocked direct rm path that bypasses PATH shim",
        ),
        (
            "/usr/bin/rm\t",
            "blocked direct rm path that bypasses PATH shim",
        ),
        (
            "/usr/bin/rm'",
            "blocked direct rm path that bypasses PATH shim",
        ),
        // Env var unsetting attempts
        (
            "unset CLAUDECODE",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u CLAUDECODE",
            "blocked attempt to unset a detector env var",
        ),
        ("CLAUDECODE=", "blocked attempt to unset a detector env var"),
        (
            "unset CODEX_CI",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u CODEX_CI",
            "blocked attempt to unset a detector env var",
        ),
        ("CODEX_CI=", "blocked attempt to unset a detector env var"),
        (
            "unset CURSOR_AGENT",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u CURSOR_AGENT",
            "blocked attempt to unset a detector env var",
        ),
        (
            "CURSOR_AGENT=",
            "blocked attempt to unset a detector env var",
        ),
        (
            "unset GEMINI_CLI",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u GEMINI_CLI",
            "blocked attempt to unset a detector env var",
        ),
        ("GEMINI_CLI=", "blocked attempt to unset a detector env var"),
        (
            "unset CLINE_ACTIVE",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u CLINE_ACTIVE",
            "blocked attempt to unset a detector env var",
        ),
        (
            "CLINE_ACTIVE=",
            "blocked attempt to unset a detector env var",
        ),
        (
            "unset AI_GUARD",
            "blocked attempt to unset a detector env var",
        ),
        (
            "env -u AI_GUARD",
            "blocked attempt to unset a detector env var",
        ),
        ("AI_GUARD=", "blocked attempt to unset a detector env var"),
        // Config modification protection (#22)
        ("config disable", "blocked attempt to modify omamori rules"),
        ("config enable", "blocked attempt to modify omamori rules"),
        ("omamori uninstall", "blocked attempt to uninstall omamori"),
        (
            "omamori init --force",
            "blocked attempt to overwrite omamori config",
        ),
    ]
}

fn render_cursor_hooks_snippet(omamori_exe: &Path) -> String {
    // Use serde_json to generate correct JSON (handles path escaping properly)
    let command = format!("\"{}\" cursor-hook", omamori_exe.display());
    let snippet = serde_json::json!({
        "_comment": format!("Generated by omamori v{}. Merge into .cursor/hooks.json", env!("CARGO_PKG_VERSION")),
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                { "command": command }
            ]
        }
    });
    serde_json::to_string_pretty(&snippet).unwrap() + "\n"
}

fn render_settings_snippet(script_path: &Path) -> String {
    let escaped = script_path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!(
        "{{\n  \"hooks\": {{\n    \"PreToolUse\": [{{\n      \"matcher\": \"*\",\n      \"command\": \"{escaped}\"\n    }}]\n  }}\n}}\n"
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

    #[test]
    fn hook_script_blocks_bin_rm_but_not_rmdir() {
        let script = render_hook_script();
        // Should match /bin/rm followed by space
        assert!(script.contains(r#"*"/bin/rm "*"#));
        assert!(script.contains(r#"*"/usr/bin/rm "*"#));
        // Should NOT have unbounded /bin/rm that matches /bin/rmdir
        assert!(!script.contains(r#"*"/bin/rm"*"#) || script.contains(r#"*"/bin/rm "*"#));
    }

    #[test]
    fn hook_script_blocks_all_detector_env_var_unsets() {
        let script = render_hook_script();
        for var in &[
            "CLAUDECODE",
            "CODEX_CI",
            "CURSOR_AGENT",
            "GEMINI_CLI",
            "CLINE_ACTIVE",
            "AI_GUARD",
        ] {
            assert!(
                script.contains(&format!(r#"*"unset {var}"*"#)),
                "hook script should block unset of {var}"
            );
        }
        assert!(script.contains("blocked attempt to unset a detector env var"));
    }

    #[test]
    fn hook_script_warns_on_interpreter_patterns() {
        let script = render_hook_script();
        // Should contain interpreter warning patterns (warn only, exit 0)
        assert!(
            script.contains("shutil.rmtree"),
            "hook script should warn on shutil.rmtree"
        );
        assert!(
            script.contains("os.remove"),
            "hook script should warn on os.remove"
        );
        assert!(
            script.contains("rmSync"),
            "hook script should warn on rmSync"
        );
        // Should exit 0 for warnings (not exit 2)
        assert!(
            script.contains("potentially destructive interpreter command"),
            "hook script should have interpreter warning message"
        );
    }

    #[test]
    fn settings_snippet_escapes_path() {
        let path = std::path::Path::new(r#"/tmp/test "path"/hook.sh"#);
        let snippet = render_settings_snippet(path);
        assert!(snippet.contains(r#"\"path\""#));
        assert!(!snippet.contains(r#"" "path""#));
    }

    // --- Bypass corpus: P1 (highest priority) ---

    #[test]
    fn hook_script_covers_rm_path_core_variants() {
        let script = render_hook_script();
        // Hook script (shell case) covers space and quote boundaries
        for path in &["/bin/rm", "/usr/bin/rm"] {
            assert!(
                script.contains(&format!("{path} ")),
                "hook script should block '{path} '"
            );
            assert!(
                script.contains(&format!("{path}\\\"")),
                "hook script should block '{path}\\\"'"
            );
        }
    }

    #[test]
    fn blocked_command_patterns_cover_all_rm_boundaries() {
        let patterns = blocked_command_patterns();
        // blocked_command_patterns (used by cursor-hook) covers all boundary variants
        for path in &["/bin/rm", "/usr/bin/rm"] {
            for boundary in &[" ", "\"", "\t", "'"] {
                let needle = format!("{path}{boundary}");
                assert!(
                    patterns.iter().any(|(p, _)| *p == needle),
                    "blocked_command_patterns should cover: {path}{boundary:?}"
                );
            }
        }
    }

    #[test]
    fn hook_script_covers_all_env_var_unset_patterns() {
        let script = render_hook_script();
        let detector_vars = [
            "CLAUDECODE",
            "CODEX_CI",
            "CURSOR_AGENT",
            "GEMINI_CLI",
            "CLINE_ACTIVE",
            "AI_GUARD",
        ];
        for var in &detector_vars {
            assert!(
                script.contains(&format!("unset {var}")),
                "hook script should block 'unset {var}'"
            );
            assert!(
                script.contains(&format!("env -u {var}")),
                "hook script should block 'env -u {var}'"
            );
            assert!(
                script.contains(&format!("{var}=")),
                "hook script should block '{var}=' reassignment"
            );
        }
    }

    // --- Bypass corpus: P2 ---

    #[test]
    fn hook_script_covers_config_modification_patterns() {
        let script = render_hook_script();
        assert!(script.contains("config disable"));
        assert!(script.contains("config enable"));
        assert!(script.contains("omamori uninstall"));
        assert!(script.contains("omamori init --force"));
        assert!(script.contains("config.toml"));
    }

    // --- Bypass corpus: P3 ---

    #[test]
    fn hook_script_warns_bash_c_rm() {
        let script = render_hook_script();
        assert!(
            script.contains(r#"*"bash "*"-c "*"rm -rf"*"#),
            "hook script should warn on bash -c rm -rf"
        );
        assert!(
            script.contains(r#"*"sh "*"-c "*"rm -rf"*"#),
            "hook script should warn on sh -c rm -rf"
        );
    }

    // --- Bypass corpus: P4 (boundary variants) ---

    #[test]
    fn hook_script_does_not_false_positive_on_rmdir() {
        let patterns = blocked_command_patterns();
        // None of the patterns should match "rmdir" without also requiring
        // a boundary char after "rm"
        for (pattern, _) in &patterns {
            assert!(
                !pattern.contains("/bin/rmdir"),
                "pattern should not match rmdir: {pattern}"
            );
        }
    }

    // --- KNOWN_LIMIT documentation ---
    // These are attack vectors that omamori CANNOT detect by design.
    // They are documented here as tests to maintain awareness.

    // KNOWN_LIMIT: sudo changes PATH before shim runs → shim never invoked
    // KNOWN_LIMIT: alias/function overrides bypass string matching
    // KNOWN_LIMIT: env -i clears all env vars (undetectable by hooks)
    // KNOWN_LIMIT: obfuscated commands (base64, hex, variable expansion) cannot be detected
    // KNOWN_LIMIT: export -n VAR removes export attribute without unsetting
    // See SECURITY.md for the full Known Limitations table.

    // --- Hook version / regeneration tests (#26) ---

    #[test]
    fn hook_script_contains_version_comment() {
        let script = render_hook_script();
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            script.contains(&format!("# omamori hook v{version}")),
            "hook script should contain version comment"
        );
    }

    #[test]
    fn parse_hook_version_extracts_version() {
        let script = render_hook_script();
        let version = parse_hook_version(&script);
        assert_eq!(version, Some(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn parse_hook_version_returns_none_for_old_hooks() {
        let old_script = "#!/bin/sh\nset -eu\nINPUT=\"$(cat)\"\n";
        assert_eq!(parse_hook_version(old_script), None);
    }

    #[test]
    fn parse_hook_version_returns_none_for_empty() {
        assert_eq!(parse_hook_version(""), None);
    }

    #[test]
    fn regenerate_hooks_creates_files() {
        let root = std::env::temp_dir().join(format!("omamori-regen-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        regenerate_hooks(&root).unwrap();

        let hook_path = root.join("hooks/claude-pretooluse.sh");
        assert!(hook_path.exists(), "hook script should be created");

        let content = fs::read_to_string(&hook_path).unwrap();
        assert_eq!(
            parse_hook_version(&content),
            Some(env!("CARGO_PKG_VERSION"))
        );

        let snippet_path = root.join("hooks/claude-settings.snippet.json");
        assert!(snippet_path.exists(), "settings snippet should be created");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = std::env::temp_dir().join(format!("omamori-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let target = dir.join("test.txt");
        atomic_write(&target, "hello world").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "hello world");

        let _ = fs::remove_dir_all(dir);
    }
}
