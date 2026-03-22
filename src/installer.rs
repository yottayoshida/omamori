use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::AppError;

pub const SHIM_COMMANDS: &[&str] = &["rm", "git", "chmod", "find", "rsync"];

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

    // Use the source path as-is (do not canonicalize). When installed via
    // Homebrew, the source path is a stable symlink like /opt/homebrew/bin/omamori.
    // Canonicalizing resolves it to /opt/homebrew/Cellar/omamori/<version>/bin/omamori,
    // which breaks after `brew upgrade` + `brew cleanup` removes the old version (#42).
    let source_exe = options.source_exe.clone();
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
        let omamori_exe = options.source_exe.clone();
        atomic_write(
            &cursor_snippet_path,
            &render_cursor_hooks_snippet(&omamori_exe),
        )?;
        Some(cursor_snippet_path)
    } else {
        None
    };

    // Generate integrity baseline after install
    if let Err(e) = generate_install_baseline(&options.base_dir) {
        eprintln!("omamori: warning — failed to generate integrity baseline: {e}");
    }

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

    // Remove integrity baseline
    let integrity_path = base_dir.join(".integrity.json");
    if integrity_path.exists() {
        fs::remove_file(&integrity_path)?;
        removed_entries.push(integrity_path);
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

/// Compute SHA-256 hash of the given content and return as hex string.
/// Used to detect hook content tampering (T2 attack: version comment preserved but body changed).
pub fn hook_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Parse the version from a hook script's version comment line.
/// Expected format: `# omamori hook v0.4.1` (second line of the script).
pub fn parse_hook_version(content: &str) -> Option<&str> {
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

pub fn render_hook_script() -> String {
    format!(
        r#"#!/bin/sh
# omamori hook v{version}
# Thin wrapper: delegates all detection to `omamori hook-check`
set -eu
cat | omamori hook-check --provider claude-code
exit $?
"#,
        version = env!("CARGO_PKG_VERSION")
    )
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
        (
            "omamori override",
            "blocked attempt to override omamori core rules",
        ),
        // Integrity baseline protection
        (
            ".integrity.json",
            "blocked attempt to edit integrity baseline",
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

/// Generate integrity baseline after install. Non-fatal on failure.
fn generate_install_baseline(base_dir: &Path) -> Result<(), crate::AppError> {
    let baseline = crate::integrity::generate_baseline(base_dir)?;
    crate::integrity::write_baseline(base_dir, &baseline)?;
    Ok(())
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
    fn hook_script_is_thin_wrapper() {
        let script = render_hook_script();
        assert!(
            script.contains("omamori hook-check"),
            "hook script should delegate to omamori hook-check"
        );
        // Thin wrapper should NOT contain case statements
        assert!(
            !script.contains("case \"$INPUT\""),
            "hook script should not contain case statements (now a thin wrapper)"
        );
    }

    #[test]
    fn settings_snippet_escapes_path() {
        let path = std::path::Path::new(r#"/tmp/test "path"/hook.sh"#);
        let snippet = render_settings_snippet(path);
        assert!(snippet.contains(r#"\"path\""#));
        assert!(!snippet.contains(r#"" "path""#));
    }

    // --- Meta-pattern tests (blocked_command_patterns, Phase 1) ---

    #[test]
    fn meta_patterns_cover_rm_path_boundaries() {
        let patterns = blocked_command_patterns();
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
    fn meta_patterns_cover_all_detector_env_vars() {
        let patterns = blocked_command_patterns();
        for var in &[
            "CLAUDECODE",
            "CODEX_CI",
            "CURSOR_AGENT",
            "GEMINI_CLI",
            "CLINE_ACTIVE",
            "AI_GUARD",
        ] {
            assert!(
                patterns
                    .iter()
                    .any(|(p, _)| p.contains(&format!("unset {var}"))),
                "should block unset {var}"
            );
            assert!(
                patterns
                    .iter()
                    .any(|(p, _)| p.contains(&format!("env -u {var}"))),
                "should block env -u {var}"
            );
            assert!(
                patterns.iter().any(|(p, _)| p.contains(&format!("{var}="))),
                "should block {var}= reassignment"
            );
        }
    }

    #[test]
    fn meta_patterns_cover_config_modification() {
        let patterns = blocked_command_patterns();
        for keyword in &[
            "config disable",
            "config enable",
            "omamori uninstall",
            "omamori init --force",
        ] {
            assert!(
                patterns.iter().any(|(p, _)| p.contains(keyword)),
                "should block: {keyword}"
            );
        }
    }

    #[test]
    fn meta_patterns_do_not_false_positive_on_rmdir() {
        let patterns = blocked_command_patterns();
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

    // --- Hook content hash tests (T2 attack detection) ---

    #[test]
    fn hook_content_hash_is_deterministic() {
        let content = "#!/bin/sh\necho hello\n";
        let hash1 = hook_content_hash(content);
        let hash2 = hook_content_hash(content);
        assert_eq!(hash1, hash2, "same content should produce same hash");
    }

    #[test]
    fn hook_content_hash_differs_for_different_content() {
        let hash1 = hook_content_hash("exit 2");
        let hash2 = hook_content_hash("exit 0");
        assert_ne!(
            hash1, hash2,
            "different content should produce different hash"
        );
    }

    #[test]
    fn render_hook_script_produces_stable_hash() {
        let script1 = render_hook_script();
        let script2 = render_hook_script();
        let hash1 = hook_content_hash(&script1);
        let hash2 = hook_content_hash(&script2);
        assert_eq!(hash1, hash2, "render_hook_script() should be deterministic");
    }

    #[test]
    fn t2_attack_version_preserved_content_changed_hash_differs() {
        let original = render_hook_script();
        let original_hash = hook_content_hash(&original);

        // Simulate T2 attack: keep version comment but bypass hook-check
        let tampered = original.replace("omamori hook-check", "true");
        let tampered_hash = hook_content_hash(&tampered);

        assert_ne!(
            original_hash, tampered_hash,
            "T2 attack (hook-check → true) should be detected by hash mismatch"
        );

        // Verify version comment is still intact (attacker preserved it)
        assert_eq!(
            parse_hook_version(&tampered),
            parse_hook_version(&original),
            "T2 attack preserves version comment"
        );
    }

    #[test]
    fn hook_content_hash_returns_hex_string() {
        let hash = hook_content_hash("test");
        // SHA-256 produces 64 hex chars
        assert_eq!(hash.len(), 64, "SHA-256 hex string should be 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should contain only hex characters"
        );
    }

    // --- omamori override block pattern tests ---

    #[test]
    fn meta_patterns_block_omamori_override() {
        let patterns = blocked_command_patterns();
        assert!(
            patterns.iter().any(|(p, _)| p.contains("omamori override")),
            "meta-patterns should block 'omamori override'"
        );
    }

    #[test]
    fn blocked_command_patterns_include_omamori_override() {
        let patterns = blocked_command_patterns();
        assert!(
            patterns.iter().any(|(p, _)| *p == "omamori override"),
            "blocked_command_patterns should include 'omamori override'"
        );
    }
}
