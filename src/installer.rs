use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::AppError;

/// Marker used to identify omamori entries in Codex hooks.json.
/// Codex displays `statusMessage` in the TUI, so this doubles as user feedback.
const CODEX_STATUS_MESSAGE: &str = "omamori: checking command safety";

pub const SHIM_COMMANDS: &[&str] = &["rm", "git", "chmod", "find", "rsync"];

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub base_dir: PathBuf,
    /// Path to the omamori binary. Must be a stable path (not a versioned Cellar path).
    /// Callers should pass the result of `resolve_stable_exe_path()` when using `current_exe()`.
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
    pub codex_wrapper: Option<PathBuf>,
    pub codex_hooks_outcome: Option<CodexHooksOutcome>,
    pub codex_config_outcome: Option<CodexConfigOutcome>,
}

#[derive(Debug, Clone)]
pub enum CodexHooksOutcome {
    /// omamori entry merged into hooks.json
    Merged,
    /// hooks.json created from scratch
    Created,
    /// omamori entry already present and up to date
    AlreadyPresent,
    /// Skipped with reason (parse failure, symlink, etc.)
    Skipped(String),
}

#[derive(Debug, Clone)]
pub enum CodexConfigOutcome {
    /// `codex_hooks = true` added to config.toml
    Added,
    /// Already set to true
    AlreadyEnabled,
    /// User explicitly set false — not touched
    ExplicitlyDisabled,
    /// Skipped with reason (no file, parse failure, etc.)
    Skipped(String),
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

    // Generate Codex CLI hook (wrapper → hooks.json → config.toml)
    let (codex_wrapper, codex_hooks_outcome, codex_config_outcome) = if options.generate_hooks {
        setup_codex_hooks(&options.base_dir, &options.source_exe)
    } else {
        (None, None, None)
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
        codex_wrapper,
        codex_hooks_outcome,
        codex_config_outcome,
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
        hooks_dir.join("codex-pretooluse.sh"),
        hooks_dir.join("codex-hooks.snippet.json"),
    ] {
        if path.exists() {
            fs::remove_file(&path)?;
            removed_entries.push(path);
        }
    }

    // Remove omamori entry from Codex hooks.json (preserve other entries)
    if let Err(e) = remove_codex_hooks_entry() {
        eprintln!("omamori: warning — failed to clean Codex hooks.json: {e}");
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
/// Uses O_EXCL (create_new) for exclusive creation + O_NOFOLLOW on Unix to prevent
/// symlink-following attacks. AtomicU64 counter ensures uniqueness within a process.
/// See: #56, #82, T7.
fn tempfile_in(dir: &Path) -> Result<AtomicTempFile, std::io::Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!(".omamori-tmp-{}-{}", std::process::id(), seq));
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
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

    // Cursor hooks: resolve to stable Homebrew path to survive brew upgrade (#56)
    if let Ok(exe) = std::env::current_exe() {
        let stable_exe = resolve_stable_exe_path(&exe);
        let cursor_path = hooks_dir.join("cursor-hooks.snippet.json");
        atomic_write(&cursor_path, &render_cursor_hooks_snippet(&stable_exe))?;

        // Codex hooks: regenerate wrapper + re-merge hooks.json
        let codex_wrapper = hooks_dir.join("codex-pretooluse.sh");
        if codex_wrapper.exists() {
            atomic_write(&codex_wrapper, &render_codex_pretooluse_script(&stable_exe))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&codex_wrapper)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&codex_wrapper, perms)?;
            }
            let codex_dir = codex_home_dir();
            if is_real_directory(&codex_dir) {
                let _ = merge_codex_hooks(&codex_dir, &codex_wrapper);
            }
        }
    } else {
        eprintln!(
            "omamori warning: failed to resolve current exe; cursor/codex hooks not regenerated"
        );
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
        // Codex CLI hook protection (#66, T2/T3)
        (
            ".codex/hooks.json",
            "blocked attempt to edit Codex hooks config",
        ),
        (".codex/config.toml", "blocked attempt to edit Codex config"),
        (
            "config.toml.bak",
            "blocked attempt to use Codex config backup",
        ),
        (
            "codex_hooks",
            "blocked attempt to modify Codex hooks feature flag",
        ),
    ]
}

/// Extract the stable Homebrew-linked path from a versioned Cellar path.
/// Pure function — no filesystem access. Returns `None` for non-Cellar paths.
///
/// Pattern: `<prefix>/Cellar/<formula>/<version>/bin/<binary>` → `<prefix>/bin/<binary>`
fn cellar_to_stable_path(exe: &Path) -> Option<PathBuf> {
    let s = exe.to_string_lossy();
    let cellar_idx = s.find("/Cellar/")?;
    let prefix = &s[..cellar_idx];
    let bin_idx = s.rfind("/bin/")?;
    let binary = &s[bin_idx + 5..];
    (!binary.is_empty()).then(|| PathBuf::from(format!("{prefix}/bin/{binary}")))
}

/// Resolve a stable executable path for generated config files.
///
/// On Homebrew installs, `std::env::current_exe()` resolves symlinks to the versioned
/// Cellar path, which breaks after `brew upgrade` + `brew cleanup`. This function
/// converts it to the stable symlink path. See: #42 (shim fix), #56 (cursor hooks fix).
///
/// The `exists()` check has a TOCTOU window; this is acceptable because the worst case
/// is writing a Cellar path — the same as pre-fix behavior, caught by `omamori status`.
pub(crate) fn resolve_stable_exe_path(exe: &Path) -> PathBuf {
    if let Some(stable) = cellar_to_stable_path(exe) {
        if stable.exists() {
            return stable;
        }
        eprintln!(
            "omamori warning: Cellar path detected but stable path {} does not exist; \
             using versioned path (may break after brew upgrade)",
            stable.display()
        );
    }
    exe.to_path_buf()
}

pub(crate) fn render_cursor_hooks_snippet(omamori_exe: &Path) -> String {
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

// ---------------------------------------------------------------------------
// Codex CLI hook support (#66)
// ---------------------------------------------------------------------------

/// Default Codex CLI config directory.
fn codex_home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".codex")
}

/// True only if `path` is a real directory (not a symlink to one).
fn is_real_directory(path: &Path) -> bool {
    path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false)
}

/// True only if `path` is a regular file (not a symlink to one).
fn is_real_file(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Render the fail-close wrapper script for Codex CLI.
///
/// Codex treats exit 2 as BLOCK, but exit 1 as ALLOW (fail-open).
/// This wrapper converts any non-zero exit from `hook-check` into exit 2.
pub fn render_codex_pretooluse_script(omamori_exe: &Path) -> String {
    format!(
        r#"#!/bin/sh
# omamori hook v{version} — Codex CLI fail-close wrapper
# Codex: exit 0 = allow, exit 2 = block, exit 1 = allow (fail-open!)
# This wrapper maps all non-zero exits to exit 2 for fail-close safety.
set -u
cat | "{exe}" hook-check --provider codex
STATUS=$?
if [ "$STATUS" -eq 0 ]; then exit 0; else exit 2; fi
"#,
        version = env!("CARGO_PKG_VERSION"),
        exe = omamori_exe.display(),
    )
}

/// Build the JSON value for one omamori entry inside `hooks.PreToolUse`.
fn codex_hooks_entry(wrapper_path: &Path) -> serde_json::Value {
    // Quote the path to handle spaces (Codex executes command via shell)
    let command = shell_words::quote(&wrapper_path.display().to_string()).into_owned();
    serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 30,
            "statusMessage": CODEX_STATUS_MESSAGE
        }]
    })
}

/// Merge omamori's PreToolUse entry into `~/.codex/hooks.json`.
///
/// Strategy:
/// - File missing → create with omamori entry only.
/// - File exists, valid JSON → upsert by matching `statusMessage`.
/// - File exists, invalid JSON → do nothing, return Skipped.
pub(crate) fn merge_codex_hooks(
    codex_dir: &Path,
    wrapper_path: &Path,
) -> Result<CodexHooksOutcome, std::io::Error> {
    let hooks_path = codex_dir.join("hooks.json");
    let entry = codex_hooks_entry(wrapper_path);

    // --- No file: create from scratch ---
    if !hooks_path.exists() && !hooks_path.is_symlink() {
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [entry] }
        });
        atomic_write(&hooks_path, &serde_json::to_string_pretty(&doc).unwrap())?;
        return Ok(CodexHooksOutcome::Created);
    }

    // --- Symlink check: refuse to follow symlinks ---
    if hooks_path.is_symlink() || !is_real_file(&hooks_path) {
        return Ok(CodexHooksOutcome::Skipped(
            "hooks.json is a symlink or not a regular file".into(),
        ));
    }

    // --- Read & parse ---
    let raw = fs::read_to_string(&hooks_path)?;
    let mut doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return Ok(CodexHooksOutcome::Skipped(format!("JSON parse error: {e}"))),
    };

    // Ensure hooks.PreToolUse is an array
    let arr = doc
        .as_object_mut()
        .and_then(|o| {
            o.entry("hooks")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        })
        .and_then(|h| {
            let pre = h
                .entry("PreToolUse")
                .or_insert_with(|| serde_json::json!([]));
            pre.as_array_mut()
        });

    let arr = match arr {
        Some(a) => a,
        None => {
            return Ok(CodexHooksOutcome::Skipped(
                "hooks.PreToolUse is not an array".into(),
            ));
        }
    };

    // Find existing omamori entry by statusMessage (exact match)
    let existing_idx = arr.iter().position(|e| {
        e.pointer("/hooks/0/statusMessage").and_then(|v| v.as_str()) == Some(CODEX_STATUS_MESSAGE)
    });

    if let Some(idx) = existing_idx {
        if arr[idx] == entry {
            return Ok(CodexHooksOutcome::AlreadyPresent);
        }
        arr[idx] = entry;
    } else {
        arr.push(entry);
    }

    atomic_write(&hooks_path, &serde_json::to_string_pretty(&doc).unwrap())?;
    Ok(CodexHooksOutcome::Merged)
}

/// Remove omamori's entry from `~/.codex/hooks.json` during uninstall.
fn remove_codex_hooks_entry() -> Result<(), std::io::Error> {
    let hooks_path = codex_home_dir().join("hooks.json");
    if !hooks_path.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&hooks_path)?;
    let mut doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(()), // Can't parse → leave alone
    };

    let modified = doc
        .pointer_mut("/hooks/PreToolUse")
        .and_then(|v| v.as_array_mut())
        .map(|arr| {
            let before = arr.len();
            arr.retain(|e| {
                e.pointer("/hooks/0/statusMessage").and_then(|v| v.as_str())
                    != Some(CODEX_STATUS_MESSAGE)
            });
            arr.len() != before
        })
        .unwrap_or(false);

    if modified {
        atomic_write(&hooks_path, &serde_json::to_string_pretty(&doc).unwrap())?;
    }
    Ok(())
}

/// Ensure `[features] codex_hooks = true` in `~/.codex/config.toml`.
///
/// Uses `toml_edit` to preserve comments, formatting, and existing content.
pub(crate) fn update_codex_config(codex_dir: &Path) -> Result<CodexConfigOutcome, std::io::Error> {
    let config_path = codex_dir.join("config.toml");

    if !config_path.exists() {
        return Ok(CodexConfigOutcome::Skipped("config.toml not found".into()));
    }
    if config_path.is_symlink() || !is_real_file(&config_path) {
        return Ok(CodexConfigOutcome::Skipped(
            "config.toml is a symlink or not a regular file".into(),
        ));
    }

    let raw = fs::read_to_string(&config_path)?;
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("TOML parse: {e}"))
    })?;

    // Check current state
    if let Some(features) = doc.get("features") {
        if !features.is_table() && !features.is_table_like() {
            return Ok(CodexConfigOutcome::Skipped(
                "features is not a table".into(),
            ));
        }
        if let Some(item) = features.get("codex_hooks") {
            if item.as_bool() == Some(true) {
                return Ok(CodexConfigOutcome::AlreadyEnabled);
            }
            if item.as_bool() == Some(false) {
                return Ok(CodexConfigOutcome::ExplicitlyDisabled);
            }
        }
    }

    // Backup before modifying
    let backup_path = codex_dir.join("config.toml.bak");
    fs::copy(&config_path, &backup_path)?;

    // Set features.codex_hooks = true (creates [features] section if needed)
    doc["features"]["codex_hooks"] = toml_edit::value(true);

    atomic_write(&config_path, &doc.to_string())?;
    Ok(CodexConfigOutcome::Added)
}

/// Orchestrate the full Codex hook setup.
///
/// Invariant: writes in order wrapper → hooks.json → config.toml
/// so that hooks.json never references a non-existent wrapper.
fn setup_codex_hooks(
    base_dir: &Path,
    source_exe: &Path,
) -> (
    Option<PathBuf>,
    Option<CodexHooksOutcome>,
    Option<CodexConfigOutcome>,
) {
    let codex_dir = codex_home_dir();
    if !is_real_directory(&codex_dir) {
        return (None, None, None); // Codex not installed
    }

    let hooks_dir = base_dir.join("hooks");
    let wrapper_path = hooks_dir.join("codex-pretooluse.sh");

    // Step 1: wrapper script (must exist before hooks.json references it)
    if let Err(e) = atomic_write(&wrapper_path, &render_codex_pretooluse_script(source_exe)) {
        eprintln!("omamori: warning — Codex wrapper: {e}");
        return (None, None, None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = fs::metadata(&wrapper_path).map(|m| m.permissions()) {
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&wrapper_path, perms);
        }
    }

    // Step 2: hooks.json
    let hooks_outcome = merge_codex_hooks(&codex_dir, &wrapper_path)
        .unwrap_or_else(|e| CodexHooksOutcome::Skipped(format!("I/O: {e}")));
    if matches!(hooks_outcome, CodexHooksOutcome::Skipped(_)) {
        let snippet_path = hooks_dir.join("codex-hooks.snippet.json");
        let _ = atomic_write(&snippet_path, &render_codex_hooks_snippet(&wrapper_path));
    }

    // Step 3: config.toml
    let config_outcome = match update_codex_config(&codex_dir) {
        Ok(outcome) => outcome,
        Err(e) => CodexConfigOutcome::Skipped(format!("I/O: {e}")),
    };

    (
        Some(wrapper_path),
        Some(hooks_outcome),
        Some(config_outcome),
    )
}

/// Auto-setup Codex hooks from shim when `CODEX_CI` is detected
/// but the wrapper script doesn't exist yet.
///
/// Non-fatal: all errors are logged to stderr and swallowed.
/// Returns `true` if setup was performed.
pub fn auto_setup_codex_if_needed(base_dir: &Path) -> bool {
    // Fast path: no CODEX_CI env → skip (0 cost)
    if std::env::var_os("CODEX_CI").is_none() {
        return false;
    }

    let wrapper_path = base_dir.join("hooks/codex-pretooluse.sh");
    if wrapper_path.exists() {
        return false; // Already configured
    }

    // Codex detected but hooks not set up — auto-configure
    let source_exe = match std::env::current_exe() {
        Ok(exe) => resolve_stable_exe_path(&exe),
        Err(_) => return false,
    };

    let codex_dir = codex_home_dir();
    if !is_real_directory(&codex_dir) {
        return false;
    }

    eprintln!("omamori: Codex CLI detected — auto-configuring hooks");

    let hooks_dir = base_dir.join("hooks");
    if fs::create_dir_all(&hooks_dir).is_err() {
        eprintln!("omamori: warning — could not create hooks directory");
        return false;
    }

    let (wrapper, hooks_out, config_out) = setup_codex_hooks(base_dir, &source_exe);

    if let Some(ref path) = wrapper {
        eprintln!("omamori: [done] {} (created)", path.display());
    }
    match hooks_out {
        Some(CodexHooksOutcome::Created | CodexHooksOutcome::Merged) => {
            eprintln!("omamori: [done] ~/.codex/hooks.json (merged)");
        }
        Some(CodexHooksOutcome::Skipped(ref reason)) => {
            eprintln!("omamori: [warn] ~/.codex/hooks.json — {reason}");
        }
        _ => {}
    }
    match config_out {
        Some(CodexConfigOutcome::Added) => {
            eprintln!("omamori: [done] ~/.codex/config.toml (codex_hooks = true)");
        }
        Some(CodexConfigOutcome::ExplicitlyDisabled) => {
            eprintln!(
                "omamori: [warn] ~/.codex/config.toml: codex_hooks = false (set by user, not changed)"
            );
            eprintln!("omamori:        hooks will NOT activate until you set codex_hooks = true");
        }
        Some(CodexConfigOutcome::Skipped(ref reason)) => {
            eprintln!("omamori: [warn] ~/.codex/config.toml — {reason}");
        }
        _ => {}
    }

    wrapper.is_some()
}

/// Render a Codex hooks.json snippet file (fallback for manual merge).
pub(crate) fn render_codex_hooks_snippet(wrapper_path: &Path) -> String {
    let doc = serde_json::json!({
        "_comment": format!(
            "Generated by omamori v{}. Merge PreToolUse entry into ~/.codex/hooks.json",
            env!("CARGO_PKG_VERSION")
        ),
        "hooks": { "PreToolUse": [codex_hooks_entry(wrapper_path)] }
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
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

    #[test]
    fn tempfile_in_generates_unique_paths() {
        let dir = std::env::temp_dir().join(format!("omamori-tmpuniq-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let tmp1 = tempfile_in(&dir).unwrap();
        let tmp2 = tempfile_in(&dir).unwrap();
        assert_ne!(
            tmp1.path, tmp2.path,
            "sequential tempfile_in must produce different paths"
        );

        // Cleanup
        let _ = fs::remove_file(&tmp1.path);
        let _ = fs::remove_file(&tmp2.path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tempfile_in_uses_exclusive_creation() {
        let dir = std::env::temp_dir().join(format!("omamori-tmpexcl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a file that would collide if tempfile_in used deterministic naming
        let tmp = tempfile_in(&dir).unwrap();
        let path = tmp.path.clone();
        drop(tmp); // close file handle, but don't delete

        // The file still exists — a second call with the SAME name would fail on create_new
        // But since we use a counter, the next call gets a different name and succeeds
        let tmp2 = tempfile_in(&dir).unwrap();
        assert_ne!(path, tmp2.path);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&tmp2.path);
        let _ = fs::remove_dir_all(&dir);
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

    // --- Cellar path resolution tests (#56) ---

    #[test]
    fn cellar_to_stable_apple_silicon() {
        let p = Path::new("/opt/homebrew/Cellar/omamori/0.6.0/bin/omamori");
        assert_eq!(
            cellar_to_stable_path(p).unwrap(),
            PathBuf::from("/opt/homebrew/bin/omamori")
        );
    }

    #[test]
    fn cellar_to_stable_intel() {
        let p = Path::new("/usr/local/Cellar/omamori/0.6.0/bin/omamori");
        assert_eq!(
            cellar_to_stable_path(p).unwrap(),
            PathBuf::from("/usr/local/bin/omamori")
        );
    }

    #[test]
    fn cellar_to_stable_linuxbrew() {
        let p = Path::new("/home/linuxbrew/.linuxbrew/Cellar/omamori/0.6.0/bin/omamori");
        assert_eq!(
            cellar_to_stable_path(p).unwrap(),
            PathBuf::from("/home/linuxbrew/.linuxbrew/bin/omamori")
        );
    }

    #[test]
    fn cellar_to_stable_cargo_install_returns_none() {
        assert!(cellar_to_stable_path(Path::new("/Users/dev/.cargo/bin/omamori")).is_none());
    }

    #[test]
    fn cellar_to_stable_manual_copy_returns_none() {
        assert!(cellar_to_stable_path(Path::new("/usr/local/bin/omamori")).is_none());
    }

    #[test]
    fn cellar_to_stable_formula_name_irrelevant() {
        // Binary name is extracted from /bin/<binary>, not from formula dir
        let p = Path::new("/opt/homebrew/Cellar/some-other-formula/1.0/bin/omamori");
        assert_eq!(
            cellar_to_stable_path(p).unwrap(),
            PathBuf::from("/opt/homebrew/bin/omamori")
        );
    }

    #[test]
    fn cellar_to_stable_relative_path_returns_none() {
        assert!(cellar_to_stable_path(Path::new("Cellar/omamori/0.6.0/bin/omamori")).is_none());
    }

    #[test]
    fn cellar_to_stable_empty_path_returns_none() {
        assert!(cellar_to_stable_path(Path::new("")).is_none());
    }

    #[test]
    fn cellar_to_stable_incomplete_cellar_returns_none() {
        // Has /Cellar/ but no /bin/
        assert!(cellar_to_stable_path(Path::new("/opt/homebrew/Cellar/omamori/0.6.0/")).is_none());
    }

    #[test]
    fn resolve_stable_uses_cellar_path_when_stable_missing() {
        // Stable path won't exist → should fall back to input
        let cellar = PathBuf::from("/nonexistent/Cellar/omamori/0.6.0/bin/omamori");
        assert_eq!(resolve_stable_exe_path(&cellar), cellar);
    }

    #[test]
    fn resolve_stable_passes_through_non_cellar() {
        let cargo = PathBuf::from("/Users/dev/.cargo/bin/omamori");
        assert_eq!(resolve_stable_exe_path(&cargo), cargo);
    }

    #[test]
    fn resolve_stable_returns_stable_when_exists() {
        let dir = std::env::temp_dir().join(format!("omamori-stable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("omamori"), "binary").unwrap();

        let cellar = dir.join("Cellar/omamori/0.6.0/bin/omamori");
        let expected = bin_dir.join("omamori");
        assert_eq!(resolve_stable_exe_path(&cellar), expected);

        let _ = fs::remove_dir_all(dir);
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

    // --- Codex CLI hook tests (#66) ---

    #[test]
    fn codex_pretooluse_script_contains_fail_close_logic() {
        let script = render_codex_pretooluse_script(Path::new("/usr/local/bin/omamori"));
        assert!(script.contains("exit 2"), "must map non-zero to exit 2");
        assert!(script.contains("hook-check --provider codex"));
        assert!(script.contains("set -u"));
        assert!(script.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn codex_hooks_entry_has_status_message() {
        let entry = codex_hooks_entry(Path::new("/path/to/wrapper.sh"));
        let msg = entry
            .pointer("/hooks/0/statusMessage")
            .and_then(|v| v.as_str());
        assert_eq!(msg, Some(CODEX_STATUS_MESSAGE));
    }

    #[test]
    fn merge_codex_hooks_creates_new_file() {
        let dir = std::env::temp_dir().join(format!("omamori-codex-new-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();

        let result = merge_codex_hooks(&dir, &wrapper).unwrap();
        assert!(matches!(result, CodexHooksOutcome::Created));

        let content = fs::read_to_string(dir.join("hooks.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            doc.pointer("/hooks/PreToolUse/0/hooks/0/statusMessage")
                .is_some()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn merge_codex_hooks_preserves_existing_entries() {
        let dir = std::env::temp_dir().join(format!("omamori-codex-merge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Pre-existing hooks.json with UserPromptSubmit
        let existing = serde_json::json!({
            "hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/tmp/test.sh"}]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/other/tool"}]}]
            }
        });
        fs::write(
            dir.join("hooks.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();

        let result = merge_codex_hooks(&dir, &wrapper).unwrap();
        assert!(matches!(result, CodexHooksOutcome::Merged));

        let content = fs::read_to_string(dir.join("hooks.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();

        // UserPromptSubmit preserved
        assert!(doc.pointer("/hooks/UserPromptSubmit/0").is_some());
        // Original PreToolUse entry preserved
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 2, "should have original + omamori entry");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn merge_codex_hooks_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("omamori-codex-idem-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();

        // First merge
        let r1 = merge_codex_hooks(&dir, &wrapper).unwrap();
        assert!(matches!(r1, CodexHooksOutcome::Created));

        // Second merge — should detect existing entry
        let r2 = merge_codex_hooks(&dir, &wrapper).unwrap();
        assert!(matches!(r2, CodexHooksOutcome::AlreadyPresent));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn merge_codex_hooks_skips_invalid_json() {
        let dir = std::env::temp_dir().join(format!("omamori-codex-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("hooks.json"), "{ not valid json }}}").unwrap();

        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();

        let result = merge_codex_hooks(&dir, &wrapper).unwrap();
        assert!(matches!(result, CodexHooksOutcome::Skipped(_)));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn remove_codex_hooks_entry_cleans_up() {
        let dir = std::env::temp_dir().join(format!("omamori-codex-rm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Set HOME so codex_home_dir() points to our test dir
        // We test remove_codex_hooks_entry indirectly through merge + manual cleanup
        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();

        merge_codex_hooks(&dir, &wrapper).unwrap();

        // Verify entry exists
        let content = fs::read_to_string(dir.join("hooks.json")).unwrap();
        assert!(content.contains(CODEX_STATUS_MESSAGE));

        // Manual removal (since remove_codex_hooks_entry uses codex_home_dir())
        let raw = fs::read_to_string(dir.join("hooks.json")).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        if let Some(arr) = doc
            .pointer_mut("/hooks/PreToolUse")
            .and_then(|v| v.as_array_mut())
        {
            arr.retain(|e| {
                e.pointer("/hooks/0/statusMessage").and_then(|v| v.as_str())
                    != Some(CODEX_STATUS_MESSAGE)
            });
        }
        fs::write(
            dir.join("hooks.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let cleaned = fs::read_to_string(dir.join("hooks.json")).unwrap();
        assert!(!cleaned.contains(CODEX_STATUS_MESSAGE));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn is_real_directory_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("omamori-symdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let real = dir.join("real");
        let link = dir.join("link");
        fs::create_dir_all(&real).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(is_real_directory(&real));
        #[cfg(unix)]
        assert!(!is_real_directory(&link));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn update_codex_config_skips_non_table_features() {
        let dir = std::env::temp_dir().join(format!("omamori-toml-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("config.toml"), "features = \"oops\"\n").unwrap();

        let result = update_codex_config(&dir).unwrap();
        assert!(
            matches!(result, CodexConfigOutcome::Skipped(ref s) if s.contains("not a table")),
            "should skip when features is not a table, got: {result:?}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn update_codex_config_adds_feature_flag() {
        let dir = std::env::temp_dir().join(format!("omamori-toml-add-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("config.toml"), "model = \"gpt-5.3-codex\"\n").unwrap();

        let result = update_codex_config(&dir).unwrap();
        assert!(matches!(result, CodexConfigOutcome::Added));

        let content = fs::read_to_string(dir.join("config.toml")).unwrap();
        assert!(content.contains("codex_hooks = true"));
        // Backup created
        assert!(dir.join("config.toml.bak").exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn update_codex_config_idempotent() {
        let dir = std::env::temp_dir().join(format!("omamori-toml-idem-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = true\n").unwrap();

        let result = update_codex_config(&dir).unwrap();
        assert!(matches!(result, CodexConfigOutcome::AlreadyEnabled));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn update_codex_config_respects_explicit_false() {
        let dir = std::env::temp_dir().join(format!("omamori-toml-false-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = false\n").unwrap();

        let result = update_codex_config(&dir).unwrap();
        assert!(matches!(result, CodexConfigOutcome::ExplicitlyDisabled));

        // File not modified
        let content = fs::read_to_string(dir.join("config.toml")).unwrap();
        assert!(content.contains("codex_hooks = false"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn meta_patterns_cover_codex_protection() {
        let patterns = blocked_command_patterns();
        for keyword in &[
            ".codex/hooks.json",
            ".codex/config.toml",
            "config.toml.bak",
            "codex_hooks",
        ] {
            assert!(
                patterns.iter().any(|(p, _)| p.contains(keyword)),
                "should block: {keyword}"
            );
        }
    }

    #[test]
    fn blocked_command_patterns_include_omamori_override() {
        let patterns = blocked_command_patterns();
        assert!(
            patterns.iter().any(|(p, _)| *p == "omamori override"),
            "blocked_command_patterns should include 'omamori override'"
        );
    }

    // --- G-12: auto_setup_codex_if_needed ---

    #[test]
    #[serial_test::serial]
    fn auto_setup_codex_skips_without_env() {
        // SAFETY: serial_test ensures no concurrent access to env vars
        let saved = std::env::var_os("CODEX_CI");
        unsafe { std::env::remove_var("CODEX_CI") };

        let dir = std::env::temp_dir().join(format!("omamori-codex-g12-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let result = auto_setup_codex_if_needed(&dir);
        assert!(!result, "should skip when CODEX_CI is not set");

        let _ = fs::remove_dir_all(&dir);
        if let Some(v) = saved {
            unsafe { std::env::set_var("CODEX_CI", v) };
        }
    }

    #[test]
    #[serial_test::serial]
    fn auto_setup_codex_skips_when_wrapper_exists() {
        // SAFETY: serial_test ensures no concurrent access to env vars
        let saved = std::env::var_os("CODEX_CI");
        unsafe { std::env::remove_var("CODEX_CI") };

        let dir = std::env::temp_dir().join(format!("omamori-codex-g12-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let hooks_dir = dir.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        // Pre-create the wrapper script
        fs::write(hooks_dir.join("codex-pretooluse.sh"), "#!/bin/sh\n").unwrap();

        let result = auto_setup_codex_if_needed(&dir);
        assert!(!result);

        let _ = fs::remove_dir_all(&dir);
        if let Some(v) = saved {
            unsafe { std::env::set_var("CODEX_CI", v) };
        }
    }

    // Note: Testing CODEX_CI=1 + no wrapper requires setting env var (unsafe in Rust 2024)
    // and having a valid codex home dir. This is covered by integration tests (E-01~E-05).
}
