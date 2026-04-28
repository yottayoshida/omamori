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
    pub claude_settings_outcome: Option<ClaudeSettingsOutcome>,
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

/// Outcome of `merge_claude_settings` (#196). Maps to the print messages in
/// `cli/install.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeSettingsOutcome {
    /// `~/.claude/settings.json` did not exist; created with omamori entry only.
    Created,
    /// File existed and parsed; omamori entry was added or updated.
    Merged,
    /// File existed and already contained an up-to-date omamori entry.
    AlreadyPresent,
    /// File existed and contained an omamori-managed entry whose `matcher` was
    /// in legacy form (`"*"` or boolean string). Migrated to simple `"Bash"`
    /// (Q2=c partial migrate; user-managed entries are not touched).
    MatcherMigrated,
    /// Merge was not attempted; reason is provided. Caller surfaces this to
    /// the user with a manual-fallback hint.
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

    // Auto-merge omamori entry into ~/.claude/settings.json (#196).
    // Only attempt when Claude Code is installed (signal: ~/.claude/ exists
    // as a real directory). Mirrors the Codex CLI detection pattern below.
    let claude_settings_outcome = match (options.generate_hooks, hook_script.as_ref()) {
        (true, Some(script_path)) => {
            let claude_dir = claude_home_dir();
            if is_real_directory(&claude_dir) {
                Some(
                    merge_claude_settings(&claude_dir, script_path)
                        .unwrap_or_else(|e| ClaudeSettingsOutcome::Skipped(format!("I/O: {e}"))),
                )
            } else {
                Some(ClaudeSettingsOutcome::Skipped(
                    "Claude Code not detected (~/.claude not a directory)".into(),
                ))
            }
        }
        _ => None,
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
        claude_settings_outcome,
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

    // Remove omamori entry from Claude Code settings.json (preserve other entries) (#196)
    if let Err(e) = remove_claude_settings_entry(base_dir) {
        eprintln!("omamori: warning — failed to clean Claude settings: {e}");
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

/// Atomic write with explicit Unix file mode.
///
/// SEC-3: ensures `~/.claude/settings.json` is written with explicit `0o600`
/// (owner read/write only), independent of the caller's umask. The mode is set
/// at file creation via `OpenOptions::mode()`, so there is no TOCTOU window
/// where the file exists with a wider permission bit set.
///
/// On non-Unix platforms, `mode` is ignored and behavior matches `atomic_write`.
fn atomic_write_with_mode(target: &Path, content: &str, mode: u32) -> Result<(), std::io::Error> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile_in_with_mode(dir, mode)?;
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

/// Variant of `tempfile_in` that sets the file mode at creation time
/// (Unix only). On non-Unix platforms `mode` is ignored.
fn tempfile_in_with_mode(dir: &Path, mode: u32) -> Result<AtomicTempFile, std::io::Error> {
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
            .mode(mode)
            .open(&path)?
    };
    #[cfg(not(unix))]
    let _ = mode;
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

/// Protected AI environment detector variables.
/// Used by Phase 1B token-level env var tampering detection.
pub(crate) const PROTECTED_ENV_VARS: &[&str] = &[
    "CLAUDECODE",
    "CODEX_CI",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CLINE_ACTIVE",
    "AI_GUARD",
];

/// String-level blocked patterns (Phase 1A).
/// These are path-based, config, and uninstall patterns that don't require
/// whitespace normalization. Env var patterns (unset, env -u, export -n, VAR=)
/// are handled separately by token-level detection in hook.rs (Phase 1B).
pub fn blocked_string_patterns() -> Vec<(&'static str, &'static str)> {
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
        // Claude Code hook registration protection (#110 T3)
        (
            ".claude/settings.json",
            "blocked attempt to edit Claude Code settings (contains hook config)",
        ),
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
        // DI-9: doctor --fix and explain are blocked in AI environments (defense-in-depth)
        (
            "omamori doctor --fix",
            "blocked attempt to run doctor --fix via AI",
        ),
        (
            "omamori explain",
            "blocked attempt to run explain via AI (oracle attack prevention)",
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
        // Audit log protection (#29)
        ("audit.jsonl", "blocked attempt to modify audit log"),
        ("audit-secret", "blocked attempt to access audit secret"),
        // Config protection for retention settings (#29)
        (
            "omamori/config.toml",
            "blocked attempt to edit omamori config",
        ),
        // Data directory protection (#29)
        (
            ".local/share/omamori",
            "blocked attempt to modify omamori data directory",
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
    let exe_str = omamori_exe.display().to_string();
    let command = format!("{} cursor-hook", shell_words::quote(&exe_str));
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

/// Build the JSON value for one omamori entry inside Claude Code's
/// `hooks.PreToolUse` array.
///
/// Spec (current Claude Code, see https://code.claude.com/docs/en/hooks):
/// - `matcher`: simple string `"Bash"`. The legacy boolean form
///   `"tool == \"Bash\""` is silently rejected by the current parser (#195).
/// - `hooks`: nested array with `type: "command"`. The older flat `command`
///   field on the matcher object is deprecated.
/// - `x-omamori-version`: omamori version embed used by shim auto-sync to
///   detect schema migration. Claude Code ignores `x-` prefixed fields per the
///   JSON forward-compat convention.
pub(crate) fn claude_settings_entry(script_path: &Path) -> serde_json::Value {
    let command = shell_words::quote(&script_path.display().to_string()).into_owned();
    serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": command,
        }],
        "x-omamori-version": env!("CARGO_PKG_VERSION"),
    })
}

fn render_settings_snippet(script_path: &Path) -> String {
    let entry = claude_settings_entry(script_path);
    let snippet = serde_json::json!({
        "_comment": format!(
            "Generated by omamori v{}. Auto-merged into ~/.claude/settings.json by `omamori install --hooks`.",
            env!("CARGO_PKG_VERSION")
        ),
        "hooks": {
            "PreToolUse": [entry]
        }
    });
    serde_json::to_string_pretty(&snippet).unwrap() + "\n"
}

// ---------------------------------------------------------------------------
// Claude Code settings.json merge support (#196)
// ---------------------------------------------------------------------------

/// Default Claude Code config directory (`~/.claude`).
pub(crate) fn claude_home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
}

/// In-place merge of omamori's PreToolUse hook entry into
/// `~/.claude/settings.json`.
///
/// Identification of the omamori-managed entry uses the `command` field's
/// path containing `~/.omamori/`. User-managed entries with arbitrary
/// commands are preserved untouched.
///
/// Behavior:
/// - File missing → create with omamori entry only (`Created`).
/// - File is symlink / not a regular file → `Skipped`.
/// - Invalid JSON → `Skipped` with the parse error message.
/// - Existing omamori entry, identical → `AlreadyPresent`.
/// - Existing omamori entry, legacy matcher (`"*"` / boolean) → migrate to
///   simple `"Bash"` (`MatcherMigrated`). Q2=c: only entries identified as
///   omamori-managed are migrated.
/// - Existing omamori entry, otherwise stale → replace → `Merged`.
/// - No omamori entry → push new entry → `Merged`.
///
/// All writes use `atomic_write_with_mode(.., 0o600)` (SEC-3).
pub(crate) fn merge_claude_settings(
    claude_dir: &Path,
    script_path: &Path,
) -> Result<ClaudeSettingsOutcome, std::io::Error> {
    let settings_path = claude_dir.join("settings.json");
    let entry = claude_settings_entry(script_path);

    // --- No file: create from scratch with omamori entry only ---
    if !settings_path.exists() && !settings_path.is_symlink() {
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [entry] }
        });
        atomic_write_with_mode(
            &settings_path,
            &serde_json::to_string_pretty(&doc).unwrap(),
            0o600,
        )?;
        return Ok(ClaudeSettingsOutcome::Created);
    }

    // --- Symlink / non-regular: refuse ---
    if settings_path.is_symlink() || !is_real_file(&settings_path) {
        return Ok(ClaudeSettingsOutcome::Skipped(
            "settings.json is a symlink or not a regular file".into(),
        ));
    }

    // --- Read & parse ---
    let raw = fs::read_to_string(&settings_path)?;
    let mut doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Ok(ClaudeSettingsOutcome::Skipped(format!(
                "JSON parse error: {e}"
            )));
        }
    };

    // Ensure hooks.PreToolUse exists as an array
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
            return Ok(ClaudeSettingsOutcome::Skipped(
                "hooks.PreToolUse is not an array".into(),
            ));
        }
    };

    // Derive omamori install root from script_path: <base_dir>/hooks/<script>.
    // Using script_path (not $HOME/.omamori) makes identification work with
    // custom `--base-dir` installs as well.
    let install_root = script_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));
    let existing_idx = arr
        .iter()
        .position(|e| is_omamori_owned_entry(e, &install_root));

    if let Some(idx) = existing_idx {
        if arr[idx] == entry {
            return Ok(ClaudeSettingsOutcome::AlreadyPresent);
        }
        let was_legacy_matcher = arr[idx]
            .get("matcher")
            .and_then(|m| m.as_str())
            .map(is_legacy_matcher)
            .unwrap_or(false);
        arr[idx] = entry;
        let outcome = if was_legacy_matcher {
            ClaudeSettingsOutcome::MatcherMigrated
        } else {
            ClaudeSettingsOutcome::Merged
        };
        atomic_write_with_mode(
            &settings_path,
            &serde_json::to_string_pretty(&doc).unwrap(),
            0o600,
        )?;
        return Ok(outcome);
    }

    // No existing omamori entry → push new
    arr.push(entry);
    atomic_write_with_mode(
        &settings_path,
        &serde_json::to_string_pretty(&doc).unwrap(),
        0o600,
    )?;
    Ok(ClaudeSettingsOutcome::Merged)
}

/// Returns true if `entry` is an omamori-managed PreToolUse entry.
///
/// Identification: any `command` field inside this entry (whether in the
/// nested `hooks` array, or the legacy flat `command` field on the matcher
/// object itself) starts with `base_dir` (the omamori install root,
/// typically `~/.omamori`).
///
/// Walks the full `hooks` array (not just `hooks[0]`) so that an omamori
/// command sitting at index 1+ in a multi-hook entry is still detected.
/// Uses `Path::starts_with` (component-wise) instead of substring contains
/// so that, e.g., `~/.omamori-bak/...` does not match `~/.omamori`.
pub(crate) fn entry_is_omamori_managed(entry: &serde_json::Value, base_dir: &Path) -> bool {
    let mut commands: Vec<&str> = Vec::new();
    if let Some(arr) = entry.get("hooks").and_then(|v| v.as_array()) {
        for h in arr {
            if let Some(c) = h.get("command").and_then(|v| v.as_str()) {
                commands.push(c);
            }
        }
    }
    if let Some(c) = entry.get("command").and_then(|v| v.as_str()) {
        commands.push(c);
    }
    commands.iter().any(|c| {
        // Strip surrounding shell quoting that shell_words::quote may have applied.
        let unquoted = c.trim_matches('\'').trim_matches('"');
        Path::new(unquoted).starts_with(base_dir)
    })
}

/// Returns true if `entry` is OWNED by omamori — i.e., omamori has the right
/// to replace or remove the entire entry without losing user data.
///
/// Ownership criteria (all must hold):
/// 1. The entry contains an omamori command (`entry_is_omamori_managed`).
/// 2. The entry does NOT have any sibling user hooks. Specifically:
///    - the `hooks` array has at most 1 element, AND
///    - the legacy flat `command` field is not present alongside a non-empty
///      `hooks` array.
///
/// If a user has manually merged the omamori command into an entry that also
/// contains their own hook, that entry is NOT owned by omamori — replacing
/// or removing the whole entry would silently destroy the user's hook. Such
/// hybrid entries are left alone (omamori treats them as user territory).
pub(crate) fn is_omamori_owned_entry(entry: &serde_json::Value, base_dir: &Path) -> bool {
    if !entry_is_omamori_managed(entry, base_dir) {
        return false;
    }
    let hooks_size = entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let has_flat = entry.get("command").is_some();
    if hooks_size > 1 {
        return false; // sibling hook exists in `hooks` array
    }
    if has_flat && hooks_size > 0 {
        return false; // mixed legacy flat + new nested → user-merged shape
    }
    true
}

/// True if `matcher` is a legacy form that the current Claude Code parser
/// silently rejects: wildcard `"*"` or boolean expression
/// (`"tool == \"Bash\""` etc.). The modern parser accepts simple strings like
/// `"Bash"`, `"Edit"`, `"Read"`.
fn is_legacy_matcher(matcher: &str) -> bool {
    matcher == "*" || matcher.contains("==") || matcher.contains("&&") || matcher.contains("||")
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
pub(crate) fn is_real_directory(path: &Path) -> bool {
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
    let exe_str = omamori_exe.display().to_string();
    let quoted = shell_words::quote(&exe_str);
    format!(
        r#"#!/bin/sh
# omamori hook v{version} — Codex CLI fail-close wrapper
# Codex: exit 0 = allow, exit 2 = block, exit 1 = allow (fail-open!)
# This wrapper maps all non-zero exits to exit 2 for fail-close safety.
set -u
cat | {exe} hook-check --provider codex
STATUS=$?
if [ "$STATUS" -eq 0 ]; then exit 0; else exit 2; fi
"#,
        version = env!("CARGO_PKG_VERSION"),
        exe = quoted,
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

/// Remove omamori's entry from `~/.claude/settings.json` during uninstall.
/// Preserves the user's other hooks. Identifies the omamori entry by
/// `entry_is_omamori_managed(e, base_dir)`. Symlinks and parse errors
/// are skipped silently — the user can clean up manually if needed.
fn remove_claude_settings_entry(base_dir: &Path) -> Result<(), std::io::Error> {
    let settings_path = claude_home_dir().join("settings.json");
    if !settings_path.exists() {
        return Ok(());
    }
    if settings_path.is_symlink() || !is_real_file(&settings_path) {
        return Ok(());
    }
    let raw = fs::read_to_string(&settings_path)?;
    let mut doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let mut modified = false;

    if let Some(arr) = doc
        .pointer_mut("/hooks/PreToolUse")
        .and_then(|v| v.as_array_mut())
    {
        // Pass 1: drop entries owned by omamori (single-hook canonical entries).
        let before = arr.len();
        arr.retain(|e| !is_omamori_owned_entry(e, base_dir));
        if arr.len() != before {
            modified = true;
        }

        // Pass 2: surgical cleanup of hybrid entries.
        // For any remaining entry that still contains the omamori command as
        // a sibling alongside user hooks, remove just the omamori inner
        // hook(s) so the entry no longer points at a deleted script. User
        // sibling hooks are preserved.
        for entry in arr.iter_mut() {
            if !entry_is_omamori_managed(entry, base_dir) {
                continue;
            }
            if let Some(hooks_arr) = entry.get_mut("hooks").and_then(|v| v.as_array_mut()) {
                let h_before = hooks_arr.len();
                hooks_arr.retain(|h| {
                    let cmd = h.get("command").and_then(|v| v.as_str());
                    let is_omamori = cmd
                        .map(|c| {
                            let unquoted = c.trim_matches('\'').trim_matches('"');
                            Path::new(unquoted).starts_with(base_dir)
                        })
                        .unwrap_or(false);
                    !is_omamori
                });
                if hooks_arr.len() != h_before {
                    modified = true;
                }
            }
        }
    }

    if modified {
        atomic_write_with_mode(
            &settings_path,
            &serde_json::to_string_pretty(&doc).unwrap(),
            0o600,
        )?;
    }
    Ok(())
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
    fn cursor_snippet_quotes_path_with_spaces() {
        let snippet = render_cursor_hooks_snippet(Path::new("/Users/my user/bin/omamori"));
        let v: serde_json::Value = serde_json::from_str(snippet.trim()).unwrap();
        let cmd = v["hooks"]["beforeShellExecution"][0]["command"]
            .as_str()
            .unwrap();
        // shell_words::split should recover the original path
        let words = shell_words::split(cmd).unwrap();
        assert_eq!(words[0], "/Users/my user/bin/omamori");
        assert_eq!(words[1], "cursor-hook");
    }

    #[test]
    fn codex_pretooluse_script_quotes_path_with_spaces() {
        let script = render_codex_pretooluse_script(Path::new("/Users/my user/bin/omamori"));
        // The quoted path should appear in the script and be shell-safe
        assert!(script.contains("hook-check --provider codex"));
        assert!(!script.contains("\"\""));
    }

    #[test]
    fn settings_snippet_escapes_path() {
        let path = std::path::Path::new(r#"/tmp/test "path"/hook.sh"#);
        let snippet = render_settings_snippet(path);
        assert!(snippet.contains(r#"\"path\""#));
        assert!(!snippet.contains(r#"" "path""#));
    }

    // --- Meta-pattern tests (blocked_string_patterns, Phase 1) ---
    //
    // Behavioral coverage of `blocked_string_patterns()` now lives in
    // `tests/hook_integration.rs` (category 15a-15d of HOOK_DECISION_CASES)
    // as CLI exit-code assertions against `omamori hook-check`. That form
    // survives internal refactors of the pattern list (renames, grouping,
    // moving to a const table) and only fails when the attack surface
    // actually re-opens — which is what the test is there to protect
    // against. The previous array-shape assertions here tested the data
    // structure rather than the guarantee and were removed in PR #v096-pr4.

    #[test]
    fn protected_env_vars_constant_covers_all_detectors() {
        // Verify PROTECTED_ENV_VARS covers all expected detector variables.
        // Env var tampering detection is now handled by Phase 1B (token-level)
        // in hook.rs, not by string-level patterns.
        for var in &[
            "CLAUDECODE",
            "CODEX_CI",
            "CURSOR_AGENT",
            "GEMINI_CLI",
            "CLINE_ACTIVE",
            "AI_GUARD",
        ] {
            assert!(
                PROTECTED_ENV_VARS.contains(var),
                "PROTECTED_ENV_VARS should include {var}"
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
    // export -n VAR is now detected by Phase 1B token-level detection (v0.9.2)
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
        let patterns = blocked_string_patterns();
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

    // meta_patterns_cover_codex_protection was moved to
    // tests/hook_integration.rs as behavioral CLI exit-code assertions
    // (HOOK_DECISION_CASES category 15c). See the note above
    // `protected_env_vars_constant_covers_all_detectors` for rationale.

    #[test]
    fn blocked_string_patterns_include_omamori_override() {
        let patterns = blocked_string_patterns();
        assert!(
            patterns.iter().any(|(p, _)| *p == "omamori override"),
            "blocked_string_patterns should include 'omamori override'"
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

    // ---------------------------------------------------------------------
    // Claude Code settings.json merge tests (#196)
    //
    // V-001..V-013 verification IDs from the v0.9.7 plan:
    // V-001/010 file missing → Created   V-002 preserves user hooks
    // V-003 idempotent (AlreadyPresent)   V-004 boolean matcher migration
    // V-005 wildcard matcher migration    V-006 file mode 0o600 (Unix)
    // V-007 corrupted JSON → Skipped      V-008 large file handling
    // V-009 empty file → Skipped          V-011 symlink → Skipped
    // V-013 other legacy matcher forms
    //
    // ADV-196-1 (user-managed entry survival) is covered by V-002.
    // ADV-196-6 (deeply nested JSON) is covered by huge_json test.
    // ---------------------------------------------------------------------

    fn fresh_test_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("omamori-claude-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_script(dir: &Path) -> std::path::PathBuf {
        let omamori_root = dir.join(".omamori");
        let hooks_dir = omamori_root.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let script = hooks_dir.join("claude-pretooluse.sh");
        fs::write(&script, "#!/bin/sh\n# omamori hook v\nexit 0\n").unwrap();
        script
    }

    /// Compute the omamori prefix that `merge_claude_settings` expects.
    /// We point HOME-derived prefix at our test dir by passing the right script
    /// path. The merge function builds prefix from `HOME` env var, so for tests
    /// we ensure the script lives under `<HOME>/.omamori/...`.
    fn with_test_home<R>(home: &Path, f: impl FnOnce() -> R) -> R {
        let saved = std::env::var_os("HOME");
        // SAFETY: serial_test ensures no parallel test mutates HOME concurrently.
        unsafe { std::env::set_var("HOME", home) };
        let result = f();
        // Restore
        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        result
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_creates_when_missing() {
        let dir = fresh_test_dir("v001");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::Created));

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse/0/matcher")
                .and_then(|v| v.as_str()),
            Some("Bash")
        );
        assert_eq!(
            doc.pointer("/hooks/PreToolUse/0/x-omamori-version")
                .and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_preserves_user_hooks() {
        let dir = fresh_test_dir("v002");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let user_doc = serde_json::json!({
            "hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/usr/local/bin/userhook"}]}],
                "PreToolUse": [{
                    "matcher": "Edit",
                    "hooks": [{"type": "command", "command": "/usr/local/bin/another"}]
                }]
            },
            "theme": "dark"
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&user_doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::Merged));

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        // User's UserPromptSubmit preserved
        assert_eq!(
            doc.pointer("/hooks/UserPromptSubmit/0/hooks/0/command")
                .and_then(|v| v.as_str()),
            Some("/usr/local/bin/userhook")
        );
        // User's PreToolUse Edit entry preserved
        let pre = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(pre.len(), 2, "user entry + omamori entry");
        // Top-level "theme" preserved
        assert_eq!(doc.get("theme").and_then(|v| v.as_str()), Some("dark"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_is_idempotent() {
        let dir = fresh_test_dir("v003");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let r1 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(r1, ClaudeSettingsOutcome::Created));

        let r2 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(r2, ClaudeSettingsOutcome::AlreadyPresent));

        // Confirm only one entry exists after second merge
        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_migrates_legacy_boolean_matcher() {
        let dir = fresh_test_dir("v004");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // Pre-existing settings with omamori entry but legacy boolean matcher
        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let stale = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "tool == \"Bash\"",
                    "hooks": [{"type": "command", "command": omamori_cmd.clone()}]
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::MatcherMigrated));

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse/0/matcher")
                .and_then(|v| v.as_str()),
            Some("Bash"),
            "legacy boolean matcher must migrate to simple Bash"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_migrates_wildcard_matcher() {
        let dir = fresh_test_dir("v005");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // Older v0.9.6 snippet form: matcher = "*", flat command field
        let stale = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "*",
                    "command": script.display().to_string()
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::MatcherMigrated));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    #[cfg(unix)]
    fn merge_claude_writes_with_mode_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_test_dir("v006");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let _ = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });

        let mode = fs::metadata(claude_dir.join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "SEC-3: settings.json must be written with mode 0o600"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_skips_corrupted_json() {
        let dir = fresh_test_dir("v007");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(claude_dir.join("settings.json"), "{ not valid }}}").unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::Skipped(_)));

        // SEC-1: original file must not be overwritten
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        assert_eq!(raw, "{ not valid }}}", "must not overwrite on parse error");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_handles_large_settings_file() {
        let dir = fresh_test_dir("v008");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // Build a settings.json with many user entries
        let mut user_entries = Vec::new();
        for i in 0..500 {
            user_entries.push(serde_json::json!({
                "matcher": format!("Tool{i}"),
                "hooks": [{"type": "command", "command": format!("/path/{i}")}]
            }));
        }
        let user_doc = serde_json::json!({
            "hooks": { "PreToolUse": user_entries }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&user_doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::Merged));

        // 501 entries (500 user + 1 omamori)
        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(501)
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_handles_empty_file() {
        let dir = fresh_test_dir("v009");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(claude_dir.join("settings.json"), "").unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        // Empty file is a JSON parse error → Skipped (we don't blindly overwrite
        // because the file might be intentionally truncated by the user).
        assert!(matches!(result, ClaudeSettingsOutcome::Skipped(_)));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    #[cfg(unix)]
    fn merge_claude_skips_symlink() {
        let dir = fresh_test_dir("v011");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // Create a real file and symlink settings.json to it
        let real = dir.join("real-settings.json");
        fs::write(&real, "{}").unwrap();
        std::os::unix::fs::symlink(&real, claude_dir.join("settings.json")).unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(result, ClaudeSettingsOutcome::Skipped(_)));

        // SEC-2: real file must not be modified
        assert_eq!(fs::read_to_string(&real).unwrap(), "{}");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn is_legacy_matcher_classifies_correctly() {
        // V-013: legacy forms
        assert!(is_legacy_matcher("*"));
        assert!(is_legacy_matcher("tool == \"Bash\""));
        assert!(is_legacy_matcher("tool == \"Bash\" && tool == \"Edit\""));
        assert!(is_legacy_matcher("tool == \"Bash\" || tool == \"Edit\""));
        // Modern simple matchers
        assert!(!is_legacy_matcher("Bash"));
        assert!(!is_legacy_matcher("Edit"));
        assert!(!is_legacy_matcher("Read"));
    }

    #[test]
    fn claude_settings_entry_uses_current_spec() {
        let entry = claude_settings_entry(Path::new("/usr/local/.omamori/hooks/x.sh"));
        assert_eq!(
            entry.get("matcher").and_then(|v| v.as_str()),
            Some("Bash"),
            "matcher must be simple string"
        );
        assert!(
            entry.pointer("/hooks/0/type").is_some(),
            "must use nested hooks array with type field"
        );
        assert_eq!(
            entry.get("x-omamori-version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION")),
            "must embed omamori version"
        );
    }

    // ---------------------------------------------------------------------
    // R1 fix tests (Codex Round 1 findings)
    // ---------------------------------------------------------------------

    #[test]
    fn entry_is_omamori_managed_rejects_lookalike_dirs() {
        // P2-1 (Codex R1): substring contains was treating ~/.omamori-bak
        // as managed. Path::starts_with should reject it.
        let base = Path::new("/home/u/.omamori");
        let entry_bak = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "/home/u/.omamori-bak/hooks/x.sh" }]
        });
        let entry_real = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "/home/u/.omamori/hooks/x.sh" }]
        });
        assert!(!entry_is_omamori_managed(&entry_bak, base));
        assert!(entry_is_omamori_managed(&entry_real, base));
    }

    #[test]
    fn entry_is_omamori_managed_walks_full_hooks_array() {
        // P2-3 (Codex R1): hooks[1..] should be checked, not just hooks[0].
        let base = Path::new("/opt/omamori");
        let entry_at_idx1 = serde_json::json!({
            "matcher": "Bash",
            "hooks": [
                { "type": "command", "command": "/usr/local/bin/userhook" },
                { "type": "command", "command": "/opt/omamori/hooks/script.sh" }
            ]
        });
        assert!(entry_is_omamori_managed(&entry_at_idx1, base));
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_handles_custom_base_dir() {
        // P2-2 (Codex R1): identification must work for `--base-dir` installs,
        // not just the default ~/.omamori prefix.
        let dir = fresh_test_dir("p2-base");
        let custom_base = dir.join("custom-omamori");
        let hooks_dir = custom_base.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let script = hooks_dir.join("claude-pretooluse.sh");
        fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();

        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // First merge under custom base — should Create
        let r1 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(matches!(r1, ClaudeSettingsOutcome::Created));

        // Second merge — must recognise the existing entry as managed
        // (otherwise it would push a duplicate)
        let r2 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(r2, ClaudeSettingsOutcome::AlreadyPresent),
            "custom-base-dir managed entry must be recognised"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn remove_claude_surgically_removes_omamori_from_hybrid() {
        // R3 regression (Codex Round 3): uninstall must surgically remove
        // the omamori inner hook from a hybrid entry, even though the
        // entry as a whole is left intact (it carries a user sibling).
        // Otherwise, a dead pointer to the deleted script remains.
        let dir = fresh_test_dir("r3-hybrid-surgical");
        let script = fake_script(&dir);

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let hybrid = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "/usr/local/bin/userhook"},
                        {"type": "command", "command": omamori_cmd}
                    ]
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&hybrid).unwrap(),
        )
        .unwrap();

        let omamori_root = dir.join(".omamori");
        remove_claude_settings_entry(&omamori_root).unwrap();

        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 1, "hybrid entry must survive uninstall");

        // Inner hooks: only user hook remains, omamori inner hook removed
        let inner = arr[0].pointer("/hooks").and_then(|v| v.as_array()).unwrap();
        assert_eq!(inner.len(), 1, "only user hook should remain");
        assert_eq!(
            inner[0].get("command").and_then(|c| c.as_str()),
            Some("/usr/local/bin/userhook"),
            "user hook preserved"
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn merge_claude_does_not_replace_hybrid_entry() {
        // R2 regression (Codex Round 2): a "hybrid" entry — one that contains
        // BOTH the omamori command and a user-managed sibling hook — must NOT
        // be replaced wholesale, or the user's sibling hook is lost. Merge
        // should leave the hybrid alone and push a separate canonical entry.
        let dir = fresh_test_dir("r2-hybrid-merge");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let hybrid = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "/usr/local/bin/userhook"},
                        {"type": "command", "command": omamori_cmd}
                    ]
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&hybrid).unwrap(),
        )
        .unwrap();

        let _ = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });

        // After: hybrid still has both hooks (user hook survived), and a
        // separate canonical omamori entry was pushed.
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            arr.len(),
            2,
            "hybrid entry must be preserved + canonical pushed"
        );
        // The original hybrid entry retains both inner hooks
        let hybrid_entry = arr
            .iter()
            .find(|e| {
                e.pointer("/hooks")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len() == 2)
                    .unwrap_or(false)
            })
            .expect("hybrid entry must still have 2 inner hooks");
        let inner = hybrid_entry
            .pointer("/hooks")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(
            inner
                .iter()
                .any(|h| h.get("command").and_then(|c| c.as_str())
                    == Some("/usr/local/bin/userhook")),
            "user-managed sibling hook must survive"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn remove_claude_settings_entry_preserves_hybrid_entry() {
        // R2 regression (Codex Round 2): uninstall must not delete a hybrid
        // entry, because it contains a user hook. Only canonical (omamori-
        // owned) entries are removed.
        let dir = fresh_test_dir("r2-hybrid-uninstall");
        let script = fake_script(&dir);

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let hybrid_only = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "/usr/local/bin/userhook"},
                        {"type": "command", "command": omamori_cmd}
                    ]
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&hybrid_only).unwrap(),
        )
        .unwrap();

        let omamori_root = dir.join(".omamori");
        remove_claude_settings_entry(&omamori_root).unwrap();

        // Hybrid entry must survive intact
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 1, "hybrid entry must not be deleted");

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn remove_claude_settings_entry_preserves_user_hooks() {
        // P1-2 (Codex R1): uninstall must remove the omamori entry but leave
        // user-managed hooks intact.
        let dir = fresh_test_dir("p1-uninstall");
        let script = fake_script(&dir);

        // Set HOME so claude_home_dir() resolves to <dir>/.claude
        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // First, install the omamori entry alongside a user hook
        let user_doc = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Edit",
                    "hooks": [{ "type": "command", "command": "/usr/local/bin/userhook" }]
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&user_doc).unwrap(),
        )
        .unwrap();
        merge_claude_settings(&claude_dir, &script).unwrap();

        // Sanity: 2 entries
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            doc.pointer("/hooks/PreToolUse")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(2)
        );

        // Now run uninstall removal
        let omamori_root = dir.join(".omamori");
        remove_claude_settings_entry(&omamori_root).unwrap();

        // After: 1 entry, the user's
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 1, "user entry preserved, omamori removed");
        assert_eq!(
            arr[0].pointer("/hooks/0/command").and_then(|v| v.as_str()),
            Some("/usr/local/bin/userhook")
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }
}
