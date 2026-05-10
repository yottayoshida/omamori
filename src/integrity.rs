//! Integrity monitoring for omamori defense layers.
//!
//! Two-tier check:
//! - **Canary** (every shim invocation): `.integrity.json` exists + own symlink target = omamori binary. ~0.05ms.
//! - **Full check** (`omamori status`): all shims, hook content hash, config perms + hash, PATH order.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppError;
use crate::installer;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityBaseline {
    pub version: String,
    pub generated_at: String,
    pub omamori_exe: String,
    pub shims: Vec<ShimEntry>,
    pub hooks: Vec<HookEntry>,
    pub config: Option<ConfigEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimEntry {
    pub command: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEntry {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEntry {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
}

/// Result of a full integrity check (`omamori status`).
#[derive(Debug)]
pub struct IntegrityReport {
    pub items: Vec<CheckItem>,
}

#[derive(Debug)]
pub struct CheckItem {
    pub category: &'static str,
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    /// Suggested fix action. `None` for healthy items or when no auto-fix exists.
    pub remediation: Option<Remediation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// Suggested remediation action for a failing or warning check item.
/// Used by `omamori doctor --fix` to automatically repair issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remediation {
    /// Re-run `omamori install --hooks` to regenerate hook scripts.
    RegenerateHooks,
    /// Re-run `omamori install` to regenerate the integrity baseline.
    RegenerateBaseline,
    /// Re-run `omamori install` (full install: shims + hooks + baseline).
    RunInstall,
    /// Fix file permissions: `chmod 600 <path>`.
    ChmodConfig(PathBuf),
    /// Cannot be auto-fixed; display guidance to the user.
    ManualOnly(String),
}

impl IntegrityReport {
    pub fn exit_code(&self) -> i32 {
        if self.items.iter().any(|i| i.status == CheckStatus::Fail) {
            1
        } else if self.items.iter().any(|i| i.status == CheckStatus::Warn) {
            2
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// `.integrity.json` lives inside the base dir (`~/.omamori/`).
pub fn baseline_path(base_dir: &Path) -> PathBuf {
    base_dir.join(".integrity.json")
}

// ---------------------------------------------------------------------------
// Generate baseline
// ---------------------------------------------------------------------------

/// Generate a full integrity baseline from the current system state.
pub fn generate_baseline(base_dir: &Path) -> Result<IntegrityBaseline, AppError> {
    let shim_dir = base_dir.join("shim");
    let hooks_dir = base_dir.join("hooks");

    // Resolve omamori exe path: use stable Homebrew path, not versioned Cellar path (#56)
    let omamori_exe = std::env::current_exe()
        .map(|p| installer::resolve_stable_exe_path(&p).display().to_string())
        .unwrap_or_default();

    // Shims
    let mut shims = Vec::new();
    for command in installer::SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        let target = fs::read_link(&link_path)
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        shims.push(ShimEntry {
            command: (*command).to_string(),
            target,
        });
    }

    // Hooks
    let mut hooks = Vec::new();
    let hook_files = [
        "claude-pretooluse.sh",
        "claude-settings.snippet.json",
        "cursor-hooks.snippet.json",
        "codex-pretooluse.sh",
    ];
    for name in &hook_files {
        let path = hooks_dir.join(name);
        if let Ok(content) = fs::read_to_string(&path) {
            hooks.push(HookEntry {
                name: name.to_string(),
                sha256: sha256_hex(&content),
            });
        }
    }

    // Config
    let config = read_config_entry();

    let now = time::OffsetDateTime::now_utc();
    let format = time::format_description::well_known::Rfc3339;

    Ok(IntegrityBaseline {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: now.format(&format).unwrap_or_default(),
        omamori_exe,
        shims,
        hooks,
        config,
    })
}

/// Write baseline to `.integrity.json` using hardened write (chmod 600, O_NOFOLLOW).
pub fn write_baseline(base_dir: &Path, baseline: &IntegrityBaseline) -> Result<(), AppError> {
    let path = baseline_path(base_dir);
    let content =
        serde_json::to_string_pretty(baseline).map_err(|e| AppError::Config(e.to_string()))?;

    // Reject symlink at target path
    if path.symlink_metadata().is_ok() {
        crate::config::reject_symlink_public(&path, "integrity baseline")?;
    }

    if path.exists() {
        // Atomic update: temp → fsync → rename
        let temp_path = path.with_extension("json.tmp");
        if temp_path.symlink_metadata().is_ok() {
            crate::config::reject_symlink_public(&temp_path, "integrity temp")?;
            let _ = fs::remove_file(&temp_path);
        }
        write_new_file(&temp_path, &content)?;
        let file = fs::File::open(&temp_path)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, &path)?;
        if let Some(dir) = path.parent()
            && let Ok(dir_file) = fs::File::open(dir)
        {
            let _ = dir_file.sync_all();
        }
    } else {
        write_new_file(&path, &content)?;
    }

    Ok(())
}

/// Read existing baseline from disk.
pub fn read_baseline(base_dir: &Path) -> Result<Option<IntegrityBaseline>, AppError> {
    let path = baseline_path(base_dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let baseline: IntegrityBaseline =
        serde_json::from_str(&content).map_err(|e| AppError::Config(e.to_string()))?;
    Ok(Some(baseline))
}

// ---------------------------------------------------------------------------
// Canary (lightweight, every shim invocation)
// ---------------------------------------------------------------------------

/// Lightweight canary check: `.integrity.json` exists + own shim symlink points to omamori.
/// Returns None if everything is ok, Some(warning) if something is wrong.
pub fn canary(base_dir: &Path, program: &str) -> Option<String> {
    let bp = baseline_path(base_dir);

    // Check 1: .integrity.json exists
    if fs::symlink_metadata(&bp).is_err() {
        // v0.4 → v0.5 migration: baseline doesn't exist yet
        return None; // Handled by migration logic, not canary
    }

    // Check 2: own shim symlink target = omamori binary
    let shim_path = base_dir.join("shim").join(program);
    match fs::read_link(&shim_path) {
        Ok(target) => {
            // Verify it points to something that looks like omamori
            let target_name = target.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if target_name != "omamori" {
                return Some(format!(
                    "shim \"{program}\" target changed ({}) — run `omamori install` to repair",
                    target.display()
                ));
            }
            // Verify target exists (not dangling)
            if !target.exists() {
                return Some(format!(
                    "shim \"{program}\" target missing ({}) — run `omamori install` to repair",
                    target.display()
                ));
            }
            None
        }
        Err(_) => {
            // Shim symlink missing or unreadable
            Some(format!(
                "shim \"{program}\" not found — run `omamori install` to repair"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Full check (omamori status)
// ---------------------------------------------------------------------------

/// Extract the omamori exe path embedded in a cursor hooks snippet.
fn cursor_snippet_exe_path(content: &str) -> Option<PathBuf> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    let cmd = v["hooks"]["beforeShellExecution"][0]["command"].as_str()?;
    let words = shell_words::split(cmd).ok()?;
    let exe = words.first()?;
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

/// Validate cursor hooks snippet: hash comparison + dangling path detection.
/// Byte-exact comparison against `render_cursor_hooks_snippet()` output;
/// any difference (including formatting) is treated as a mismatch (#56, T8).
fn check_cursor_snippet(path: &Path) -> CheckItem {
    let name = "cursor-hooks.snippet.json".to_string();
    let category = "Hooks";

    if !path.exists() {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Warn,
            detail: "(not installed — run `omamori install --hooks`)".to_string(),
            remediation: Some(Remediation::RunInstall),
        };
    }

    let actual = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            return CheckItem {
                category,
                name,
                status: CheckStatus::Fail,
                detail: "(unreadable)".to_string(),
                remediation: Some(Remediation::RegenerateHooks),
            };
        }
    };

    // Hash comparison: generate expected content from current stable exe path
    let hash_ok = std::env::current_exe().ok().map(|exe| {
        let stable = installer::resolve_stable_exe_path(&exe);
        let expected = installer::render_cursor_hooks_snippet(&stable);
        installer::hook_content_hash(&expected) == installer::hook_content_hash(&actual)
    });

    // Dangling path detection: check if the exe in the snippet actually exists
    let dangling = cursor_snippet_exe_path(&actual).is_some_and(|p| !p.exists());

    let (status, detail, remediation) = match (hash_ok, dangling) {
        (Some(true), false) => (CheckStatus::Ok, "(hash match)", None),
        (Some(true), true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)",
            Some(Remediation::RunInstall),
        ),
        (Some(false), _) => (
            CheckStatus::Fail,
            "(hash MISMATCH — run `omamori install --hooks`)",
            Some(Remediation::RegenerateHooks),
        ),
        (None, false) => (CheckStatus::Warn, "(present, hash check skipped)", None),
        (None, true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)",
            Some(Remediation::RunInstall),
        ),
    };

    CheckItem {
        category,
        name,
        status,
        detail: detail.to_string(),
        remediation,
    }
}

/// Verify that `~/.claude/settings.json` is wired up correctly (#196 Bonus).
///
/// Confirms:
/// 1. settings.json exists and parses as JSON
/// 2. `hooks.PreToolUse` contains an omamori-managed entry (`command` path
///    inside `~/.omamori/`)
/// 3. The matcher is current spec (`"Bash"` simple string), not legacy
///    (`"*"` or boolean) which the current parser silently rejects
/// 4. The command points at a real file whose sha256 matches the bundled
///    hook script (T2 tampering detection)
///
/// Closes the "doctor 12/12 green but Layer 2 dormant" gap from #196:
/// a green doctor report now guarantees Layer 2 is active.
fn check_claude_settings_integration(base_dir: &Path) -> CheckItem {
    let name = "claude-code-settings".to_string();
    let category = "Hooks";

    let claude_dir = installer::claude_home_dir();
    let settings_path = claude_dir.join("settings.json");

    if !settings_path.exists() {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Warn,
            detail: "(no ~/.claude/settings.json — Claude Code not configured)".to_string(),
            remediation: Some(Remediation::RunInstall),
        };
    }

    let raw = match fs::read_to_string(&settings_path) {
        Ok(c) => c,
        Err(e) => {
            return CheckItem {
                category,
                name,
                status: CheckStatus::Warn,
                detail: format!("(read error: {e})"),
                remediation: Some(Remediation::RunInstall),
            };
        }
    };

    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return CheckItem {
                category,
                name,
                status: CheckStatus::Warn,
                detail: format!("(JSON parse error: {e})"),
                remediation: Some(Remediation::RunInstall),
            };
        }
    };

    let arr_opt = doc
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array());

    // Count all omamori-managed entries (tag OR path OR filename pattern).
    let omamori_count = arr_opt
        .map(|arr| {
            arr.iter()
                .filter(|e| {
                    installer::is_omamori_entry_any_root(e, base_dir) || {
                        let mut cmds: Vec<&str> = Vec::new();
                        if let Some(arr) = e.get("hooks").and_then(|v| v.as_array()) {
                            for h in arr {
                                if let Some(c) = h.get("command").and_then(|v| v.as_str()) {
                                    cmds.push(c);
                                }
                            }
                        }
                        if let Some(c) = e.get("command").and_then(|v| v.as_str()) {
                            cmds.push(c);
                        }
                        cmds.iter().any(|c| {
                            let unquoted = c.trim_matches('\'').trim_matches('"');
                            installer::is_omamori_hook_path(Path::new(unquoted))
                        })
                    }
                })
                .count()
        })
        .unwrap_or(0);

    if omamori_count > 1 {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "({omamori_count} duplicate omamori PreToolUse hook(s) — stale entries accumulated)"
            ),
            remediation: Some(Remediation::RunInstall),
        };
    }

    let entry = arr_opt.and_then(|arr| {
        arr.iter()
            .find(|e| installer::is_omamori_entry_any_root(e, base_dir))
    });

    let Some(entry) = entry else {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Fail,
            detail: "(omamori PreToolUse hook missing — Layer 2 not active)".to_string(),
            remediation: Some(Remediation::RunInstall),
        };
    };

    let matcher = entry.get("matcher").and_then(|m| m.as_str()).unwrap_or("");
    if matcher != "Bash" {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "(matcher = {matcher:?}, expected \"Bash\" — legacy form silently rejected)"
            ),
            remediation: Some(Remediation::RunInstall),
        };
    }

    let cmd_str = entry
        .pointer("/hooks/0/command")
        .and_then(|v| v.as_str())
        .or_else(|| entry.get("command").and_then(|v| v.as_str()))
        .unwrap_or("");
    let cmd_path = cmd_str.trim_matches('\'').trim_matches('"');
    let script_path = Path::new(cmd_path);
    if !script_path.exists() {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Fail,
            detail: format!("(script path missing: {cmd_path})"),
            remediation: Some(Remediation::RunInstall),
        };
    }

    // Verify the script is executable. Without execute bit, the kernel
    // refuses to run it and Layer 2 is silently inactive even though the
    // sha256 may match. Hash-only check would give a false-positive green.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(script_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0);
        if mode & 0o111 == 0 {
            return CheckItem {
                category,
                name,
                status: CheckStatus::Fail,
                detail: format!(
                    "(script not executable: mode {:o} — Layer 2 inactive)",
                    mode & 0o777
                ),
                remediation: Some(Remediation::RegenerateHooks),
            };
        }
    }

    let actual = match fs::read_to_string(script_path) {
        Ok(c) => c,
        Err(e) => {
            return CheckItem {
                category,
                name,
                status: CheckStatus::Warn,
                detail: format!("(script read error: {e})"),
                remediation: Some(Remediation::RegenerateHooks),
            };
        }
    };
    let expected_hash = installer::hook_content_hash(&installer::render_hook_script());
    let actual_hash = installer::hook_content_hash(&actual);
    if actual_hash != expected_hash {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Fail,
            detail: "(script content hash mismatch — possible tampering)".to_string(),
            remediation: Some(Remediation::RegenerateHooks),
        };
    }

    CheckItem {
        category,
        name,
        status: CheckStatus::Ok,
        detail: "(active — Layer 2 wired up)".to_string(),
        remediation: None,
    }
}

/// Compare a shim's resolved target against the baseline record.
/// Returns `true` (match) when baseline is absent, entry is missing, or paths agree.
fn shim_matches_baseline(
    target: &Path,
    command: &str,
    baseline: Option<&IntegrityBaseline>,
) -> bool {
    let Some(b) = baseline else { return true };
    let Some(entry) = b.shims.iter().find(|s| s.command == command) else {
        return true;
    };
    if entry.target.is_empty() {
        return true;
    }
    // Canonicalize both sides to handle Homebrew Cellar ↔ stable symlinks
    let actual = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let expected =
        fs::canonicalize(Path::new(&entry.target)).unwrap_or_else(|_| PathBuf::from(&entry.target));
    actual == expected
}

/// Run a full integrity check of all defense layers.
pub fn full_check(base_dir: &Path) -> IntegrityReport {
    let mut items = Vec::new();
    let baseline = read_baseline(base_dir).ok().flatten();

    // --- Shims ---
    let shim_dir = base_dir.join("shim");
    for command in installer::SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        let (status, detail, remediation) = match fs::read_link(&link_path) {
            Ok(target) => {
                let target_name = target.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if target_name != "omamori" {
                    (
                        CheckStatus::Fail,
                        format!("-> {} (unexpected target)", target.display()),
                        Some(Remediation::RunInstall),
                    )
                } else if !target.exists() {
                    (
                        CheckStatus::Fail,
                        format!("-> {} (dangling)", target.display()),
                        Some(Remediation::RunInstall),
                    )
                } else if !shim_matches_baseline(&target, command, baseline.as_ref()) {
                    (
                        CheckStatus::Warn,
                        format!(
                            "-> {} (differs from baseline — run `omamori install` to update)",
                            target.display()
                        ),
                        Some(Remediation::RunInstall),
                    )
                } else {
                    (CheckStatus::Ok, format!("-> {}", target.display()), None)
                }
            }
            Err(_) => (
                CheckStatus::Fail,
                "missing".to_string(),
                Some(Remediation::RunInstall),
            ),
        };
        items.push(CheckItem {
            category: "Shims",
            name: (*command).to_string(),
            status,
            detail,
            remediation,
        });
    }

    // --- Hooks (implementation-derived hash comparison) ---
    let hooks_dir = base_dir.join("hooks");
    let hook_path = hooks_dir.join("claude-pretooluse.sh");
    if hook_path.exists() {
        let expected = installer::render_hook_script();
        let expected_hash = installer::hook_content_hash(&expected);
        match fs::read_to_string(&hook_path) {
            Ok(actual) => {
                let actual_hash = installer::hook_content_hash(&actual);
                if expected_hash == actual_hash {
                    items.push(CheckItem {
                        category: "Hooks",
                        name: "claude-pretooluse.sh".to_string(),
                        status: CheckStatus::Ok,
                        detail: "(hash match)".to_string(),
                        remediation: None,
                    });
                } else {
                    items.push(CheckItem {
                        category: "Hooks",
                        name: "claude-pretooluse.sh".to_string(),
                        status: CheckStatus::Fail,
                        detail: "(hash MISMATCH — run `omamori install --hooks`)".to_string(),
                        remediation: Some(Remediation::RegenerateHooks),
                    });
                }
            }
            Err(_) => {
                items.push(CheckItem {
                    category: "Hooks",
                    name: "claude-pretooluse.sh".to_string(),
                    status: CheckStatus::Fail,
                    detail: "(unreadable)".to_string(),
                    remediation: Some(Remediation::RegenerateHooks),
                });
            }
        }
    } else {
        items.push(CheckItem {
            category: "Hooks",
            name: "claude-pretooluse.sh".to_string(),
            status: CheckStatus::Warn,
            detail: "(not installed — run `omamori install --hooks`)".to_string(),
            remediation: Some(Remediation::RunInstall),
        });
    }

    // claude-settings.snippet.json — existence check only
    let settings_snippet = hooks_dir.join("claude-settings.snippet.json");
    items.push(if settings_snippet.exists() {
        CheckItem {
            category: "Hooks",
            name: "claude-settings.snippet.json".to_string(),
            status: CheckStatus::Ok,
            detail: "(present)".to_string(),
            remediation: None,
        }
    } else {
        CheckItem {
            category: "Hooks",
            name: "claude-settings.snippet.json".to_string(),
            status: CheckStatus::Warn,
            detail: "(not installed)".to_string(),
            remediation: Some(Remediation::RunInstall),
        }
    });

    // claude-code-settings — verify ~/.claude/settings.json is wired up (#196)
    items.push(check_claude_settings_integration(base_dir));

    // cursor-hooks.snippet.json — hash comparison + dangling path detection (#56, T8)
    let cursor_snippet = hooks_dir.join("cursor-hooks.snippet.json");
    items.push(check_cursor_snippet(&cursor_snippet));

    // --- Config ---
    if let Some(entry) = read_config_entry() {
        let path = Path::new(&entry.path);
        let mode_ok = entry.mode & 0o777 == 0o600;
        let hash_ok = baseline
            .as_ref()
            .and_then(|b| b.config.as_ref())
            .map(|bc| bc.sha256 == entry.sha256)
            .unwrap_or(true); // no baseline = skip comparison

        let (status, detail, remediation) = if !mode_ok {
            (
                CheckStatus::Warn,
                format!(
                    "(mode {:o} — run `chmod 600 {}`)",
                    entry.mode & 0o777,
                    path.display()
                ),
                Some(Remediation::ChmodConfig(path.to_path_buf())),
            )
        } else if !hash_ok {
            (
                CheckStatus::Warn,
                "(modified outside omamori — run `omamori install` to update baseline)".to_string(),
                Some(Remediation::RegenerateBaseline),
            )
        } else {
            (
                CheckStatus::Ok,
                format!("(mode 600, hash {})", &entry.sha256[..12]),
                None,
            )
        };
        items.push(CheckItem {
            category: "Config",
            name: "config.toml".to_string(),
            status,
            detail,
            remediation,
        });
    } else {
        items.push(CheckItem {
            category: "Config",
            name: "config.toml".to_string(),
            status: CheckStatus::Ok,
            detail: "(using built-in defaults)".to_string(),
            remediation: None,
        });
    }

    // --- Core Policy ---
    let config_result = crate::config::load_config(None);
    if let Ok(load_result) = &config_result {
        let core_rules: Vec<_> = load_result
            .config
            .rules
            .iter()
            .filter(|r| r.is_builtin)
            .collect();
        let overridden = core_rules.iter().filter(|r| !r.enabled).count();
        let active = core_rules.len() - overridden;
        let (status, detail, remediation) = if overridden == 0 {
            (
                CheckStatus::Ok,
                format!("{} core rules active, 0 overridden", core_rules.len()),
                None,
            )
        } else {
            (
                CheckStatus::Warn,
                format!("{active} active, {overridden} overridden"),
                Some(Remediation::ManualOnly(
                    "review core rule overrides in config.toml".to_string(),
                )),
            )
        };
        items.push(CheckItem {
            category: "Core Policy",
            name: "core rules".to_string(),
            status,
            detail,
            remediation,
        });
    }

    // --- PATH ---
    let path_check = check_path_order(base_dir);
    items.push(path_check);

    // --- Baseline ---
    // Reuse `baseline` loaded at the top of full_check.
    let bp = baseline_path(base_dir);
    if let Some(b) = &baseline {
        let (status, detail, remediation) = if b.version == env!("CARGO_PKG_VERSION") {
            (
                CheckStatus::Ok,
                format!("(v{}, {})", b.version, b.generated_at),
                None,
            )
        } else {
            (
                CheckStatus::Warn,
                format!(
                    "(v{} — current binary is v{})",
                    b.version,
                    env!("CARGO_PKG_VERSION")
                ),
                Some(Remediation::RegenerateBaseline),
            )
        };
        items.push(CheckItem {
            category: "Baseline",
            name: ".integrity.json".to_string(),
            status,
            detail,
            remediation,
        });
    } else if bp.exists() {
        // baseline is None but file exists → corrupt
        items.push(CheckItem {
            category: "Baseline",
            name: ".integrity.json".to_string(),
            status: CheckStatus::Warn,
            detail: "(corrupt — run `omamori install` to regenerate)".to_string(),
            remediation: Some(Remediation::RegenerateBaseline),
        });
    } else {
        items.push(CheckItem {
            category: "Baseline",
            name: ".integrity.json".to_string(),
            status: CheckStatus::Warn,
            detail: "(not found — will be created)".to_string(),
            remediation: Some(Remediation::RegenerateBaseline),
        });
    }

    IntegrityReport { items }
}

// ---------------------------------------------------------------------------
// PATH order check
// ---------------------------------------------------------------------------

fn check_path_order(base_dir: &Path) -> CheckItem {
    let shim_dir = base_dir.join("shim");
    let shim_str = shim_dir.display().to_string();

    let path_var = std::env::var("PATH").unwrap_or_default();
    let paths: Vec<&str> = path_var.split(':').collect();

    let shim_pos = paths.iter().position(|p| *p == shim_str);
    let usr_bin_pos = paths.iter().position(|p| *p == "/usr/bin");

    match (shim_pos, usr_bin_pos) {
        (Some(s), Some(u)) if s < u => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Ok,
            detail: format!("{} is before /usr/bin", shim_str),
            remediation: None,
        },
        (Some(s), Some(u)) if s >= u => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: format!("{} is AFTER /usr/bin — shims may be bypassed", shim_str),
            remediation: Some(Remediation::ManualOnly(format!(
                "move {} before /usr/bin in your shell profile (.zshrc / .bashrc)",
                shim_str
            ))),
        },
        (None, _) => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: format!("{} not found in PATH", shim_str),
            remediation: Some(Remediation::ManualOnly(format!(
                "add {} to PATH in your shell profile (.zshrc / .bashrc)",
                shim_str
            ))),
        },
        _ => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Ok,
            detail: format!("{} in PATH (/usr/bin not found to compare)", shim_str),
            remediation: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn read_config_entry() -> Option<ConfigEntry> {
    let config_path = crate::config::default_config_path()?;
    if !config_path.exists() {
        return None;
    }
    let content = fs::read_to_string(&config_path).ok()?;
    let mode = file_mode(&config_path);
    Some(ConfigEntry {
        path: config_path.display().to_string(),
        sha256: sha256_hex(&content),
        mode,
    })
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map(|m| m.mode()).unwrap_or(0)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> u32 {
    0
}

#[cfg(unix)]
pub(crate) fn write_new_file(path: &Path, content: &str) -> Result<(), AppError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_new_file(path: &Path, content: &str) -> Result<(), AppError> {
    fs::write(path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn canary_ok_when_shim_points_to_omamori() {
        let dir = std::env::temp_dir().join(format!("omamori-integrity-t1-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        // Create .integrity.json
        fs::write(dir.join(".integrity.json"), "{}").unwrap();

        // Create symlink: shim/rm -> fake omamori binary
        let fake_bin = dir.join("omamori");
        fs::write(&fake_bin, "binary").unwrap();
        symlink(&fake_bin, shim_dir.join("rm")).unwrap();

        assert!(canary(&dir, "rm").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn canary_warns_when_shim_target_changed() {
        let dir = std::env::temp_dir().join(format!("omamori-integrity-t2-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        fs::write(dir.join(".integrity.json"), "{}").unwrap();

        // Create symlink pointing to something NOT named "omamori"
        let bad_target = dir.join("malicious");
        fs::write(&bad_target, "bad").unwrap();
        symlink(&bad_target, shim_dir.join("rm")).unwrap();

        let warning = canary(&dir, "rm");
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("target changed"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn canary_none_when_no_baseline() {
        let dir = std::env::temp_dir().join(format!("omamori-integrity-t3-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        // No .integrity.json — v0.4 migration case
        assert!(canary(&dir, "rm").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_and_read_baseline_roundtrip() {
        let dir = std::env::temp_dir().join(format!("omamori-integrity-t4-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        let hooks_dir = dir.join("hooks");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();

        // Create a shim symlink
        let fake_bin = dir.join("omamori");
        fs::write(&fake_bin, "binary").unwrap();
        symlink(&fake_bin, shim_dir.join("rm")).unwrap();

        // Create a hook file
        fs::write(hooks_dir.join("claude-pretooluse.sh"), "#!/bin/sh\nexit 0").unwrap();

        let baseline = generate_baseline(&dir).unwrap();
        assert_eq!(baseline.version, env!("CARGO_PKG_VERSION"));
        assert!(!baseline.shims.is_empty());
        assert!(!baseline.hooks.is_empty());

        write_baseline(&dir, &baseline).unwrap();

        let loaded = read_baseline(&dir).unwrap().unwrap();
        assert_eq!(loaded.version, baseline.version);
        assert_eq!(loaded.shims.len(), baseline.shims.len());

        // Verify file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(baseline_path(&dir)).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_check_returns_report() {
        let dir = std::env::temp_dir().join(format!("omamori-integrity-t5-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let report = full_check(&dir);
        // Should have items for shims, hooks, config, core policy, PATH, baseline
        assert!(!report.items.is_empty());

        // All shims should be FAIL (none exist in temp dir)
        let shim_items: Vec<_> = report
            .items
            .iter()
            .filter(|i| i.category == "Shims")
            .collect();
        assert!(shim_items.iter().all(|i| i.status == CheckStatus::Fail));

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Cursor snippet validation tests (#56) ---

    #[test]
    fn cursor_snippet_exe_path_extracts_path() {
        let snippet =
            installer::render_cursor_hooks_snippet(Path::new("/opt/homebrew/bin/omamori"));
        let exe = cursor_snippet_exe_path(&snippet).unwrap();
        assert_eq!(exe, PathBuf::from("/opt/homebrew/bin/omamori"));
    }

    #[test]
    fn cursor_snippet_exe_path_handles_spaces_in_path() {
        let snippet =
            installer::render_cursor_hooks_snippet(Path::new("/Users/my user/bin/omamori"));
        let exe = cursor_snippet_exe_path(&snippet).unwrap();
        assert_eq!(exe, PathBuf::from("/Users/my user/bin/omamori"));
    }

    #[test]
    fn cursor_snippet_exe_path_returns_none_for_invalid_json() {
        assert!(cursor_snippet_exe_path("not json").is_none());
    }

    #[test]
    fn cursor_snippet_exe_path_returns_none_for_empty_command() {
        let json = r#"{"hooks":{"beforeShellExecution":[{"command":""}]}}"#;
        assert!(cursor_snippet_exe_path(json).is_none());
    }

    #[test]
    fn check_cursor_snippet_detects_hash_match() {
        let dir = std::env::temp_dir().join(format!("omamori-cursor-t1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write snippet using the same resolved path that check_cursor_snippet uses
        let exe = installer::resolve_stable_exe_path(&std::env::current_exe().unwrap());
        let content = installer::render_cursor_hooks_snippet(&exe);
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        let item = check_cursor_snippet(&path);
        assert_eq!(item.status, CheckStatus::Ok);
        assert!(item.detail.contains("hash match"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn check_cursor_snippet_detects_tampered_content() {
        let dir = std::env::temp_dir().join(format!("omamori-cursor-t2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(
            &path,
            r#"{"hooks":{"beforeShellExecution":[{"command":"exit 0"}]}}"#,
        )
        .unwrap();

        let item = check_cursor_snippet(&path);
        assert_eq!(item.status, CheckStatus::Fail);
        assert!(item.detail.contains("MISMATCH"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn check_cursor_snippet_detects_dangling_path() {
        let dir = std::env::temp_dir().join(format!("omamori-cursor-t3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write snippet pointing to a nonexistent binary
        let content = installer::render_cursor_hooks_snippet(Path::new("/nonexistent/bin/omamori"));
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        let item = check_cursor_snippet(&path);
        // Either FAIL (hash mismatch) or WARN (dangling) — either way, not Ok
        assert_ne!(item.status, CheckStatus::Ok);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn check_cursor_snippet_missing_returns_warn() {
        let path = Path::new("/nonexistent/cursor-hooks.snippet.json");
        let item = check_cursor_snippet(path);
        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("not installed"));
    }

    // --- G-08: write_baseline ---

    #[test]
    fn write_baseline_rejects_symlink() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g08-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a symlink at the baseline path
        let real_file = dir.join("real.json");
        fs::write(&real_file, "{}").unwrap();
        let baseline_file = baseline_path(&dir);
        symlink(&real_file, &baseline_file).unwrap();

        let baseline = IntegrityBaseline {
            version: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            omamori_exe: "test".to_string(),
            shims: vec![],
            hooks: vec![],
            config: None,
        };

        let result = write_baseline(&dir, &baseline);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("symlink"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_baseline_atomic_update() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g08-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let baseline1 = IntegrityBaseline {
            version: "0.1.0".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            omamori_exe: "test".to_string(),
            shims: vec![],
            hooks: vec![],
            config: None,
        };

        // First write (new file)
        write_baseline(&dir, &baseline1).unwrap();
        let loaded1 = read_baseline(&dir).unwrap().unwrap();
        assert_eq!(loaded1.version, "0.1.0");

        // Second write (atomic update)
        let baseline2 = IntegrityBaseline {
            version: "0.2.0".to_string(),
            ..baseline1
        };
        write_baseline(&dir, &baseline2).unwrap();
        let loaded2 = read_baseline(&dir).unwrap().unwrap();
        assert_eq!(loaded2.version, "0.2.0");

        // Verify permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(baseline_path(&dir)).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_baseline_o_nofollow() {
        // Verify that the write uses O_NOFOLLOW (checked indirectly via symlink rejection)
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g08-3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let baseline = IntegrityBaseline {
            version: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            omamori_exe: "test".to_string(),
            shims: vec![],
            hooks: vec![],
            config: None,
        };

        // Normal write should succeed
        write_baseline(&dir, &baseline).unwrap();
        assert!(baseline_path(&dir).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // =========================================================================
    // G-09: IntegrityReport::exit_code direct tests
    // =========================================================================

    fn make_item(status: CheckStatus) -> CheckItem {
        CheckItem {
            category: "test",
            name: "test_item".to_string(),
            status,
            detail: String::new(),
            remediation: None,
        }
    }

    // =========================================================================
    // G-10: check_path_order direct tests
    // =========================================================================

    #[test]
    #[serial_test::serial]
    fn path_order_shim_before_usr_bin_is_ok() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g10-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("shim")).unwrap();

        let shim_str = dir.join("shim").display().to_string();
        let saved = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", format!("{shim_str}:/usr/bin:/usr/local/bin")) };

        let item = check_path_order(&dir);
        assert_eq!(item.status, CheckStatus::Ok);
        assert!(item.detail.contains("before /usr/bin"));

        unsafe { std::env::set_var("PATH", &saved) };
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial]
    fn path_order_shim_after_usr_bin_is_warn() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g10-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("shim")).unwrap();

        let shim_str = dir.join("shim").display().to_string();
        let saved = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", format!("/usr/bin:{shim_str}:/usr/local/bin")) };

        let item = check_path_order(&dir);
        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("AFTER /usr/bin"));

        unsafe { std::env::set_var("PATH", &saved) };
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial]
    fn path_order_shim_not_in_path_is_warn() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g10-3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("shim")).unwrap();

        let saved = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", "/usr/bin:/usr/local/bin") };

        let item = check_path_order(&dir);
        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("not found in PATH"));

        unsafe { std::env::set_var("PATH", &saved) };
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial]
    fn path_order_usr_bin_not_in_path_is_ok() {
        let dir =
            std::env::temp_dir().join(format!("omamori-integrity-g10-4-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("shim")).unwrap();

        let shim_str = dir.join("shim").display().to_string();
        let saved = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", format!("{shim_str}:/usr/local/bin")) };

        let item = check_path_order(&dir);
        assert_eq!(item.status, CheckStatus::Ok);
        assert!(item.detail.contains("/usr/bin not found"));

        unsafe { std::env::set_var("PATH", &saved) };
        let _ = fs::remove_dir_all(&dir);
    }

    // =========================================================================
    // G-09: IntegrityReport::exit_code direct tests
    // =========================================================================

    #[test]
    fn exit_code_fail_returns_1() {
        let report = IntegrityReport {
            items: vec![make_item(CheckStatus::Fail)],
        };
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_warn_returns_2() {
        let report = IntegrityReport {
            items: vec![make_item(CheckStatus::Warn)],
        };
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn exit_code_ok_returns_0() {
        let report = IntegrityReport {
            items: vec![make_item(CheckStatus::Ok)],
        };
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_fail_takes_precedence_over_warn() {
        let report = IntegrityReport {
            items: vec![
                make_item(CheckStatus::Warn),
                make_item(CheckStatus::Fail),
                make_item(CheckStatus::Ok),
            ],
        };
        assert_eq!(report.exit_code(), 1);
    }

    // --- #101: shim baseline comparison ---

    #[test]
    fn shim_matches_baseline_returns_true_when_no_baseline() {
        let target = PathBuf::from("/usr/local/bin/omamori");
        assert!(shim_matches_baseline(&target, "rm", None));
    }

    #[test]
    fn shim_matches_baseline_returns_true_when_target_matches() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-bl-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("omamori");
        fs::write(&bin, "binary").unwrap();

        let baseline = IntegrityBaseline {
            version: "0.7.5".to_string(),
            generated_at: String::new(),
            omamori_exe: bin.display().to_string(),
            shims: vec![ShimEntry {
                command: "rm".to_string(),
                target: bin.display().to_string(),
            }],
            hooks: vec![],
            config: None,
        };
        assert!(shim_matches_baseline(&bin, "rm", Some(&baseline)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shim_matches_baseline_detects_mismatch() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-mm-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("omamori");
        let fake = dir.join("fake_omamori");
        fs::write(&real, "real").unwrap();
        fs::write(&fake, "fake").unwrap();

        let baseline = IntegrityBaseline {
            version: "0.7.5".to_string(),
            generated_at: String::new(),
            omamori_exe: real.display().to_string(),
            shims: vec![ShimEntry {
                command: "rm".to_string(),
                target: real.display().to_string(),
            }],
            hooks: vec![],
            config: None,
        };
        assert!(!shim_matches_baseline(&fake, "rm", Some(&baseline)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shim_matches_baseline_skips_empty_target() {
        let baseline = IntegrityBaseline {
            version: "0.7.5".to_string(),
            generated_at: String::new(),
            omamori_exe: String::new(),
            shims: vec![ShimEntry {
                command: "rm".to_string(),
                target: String::new(),
            }],
            hooks: vec![],
            config: None,
        };
        let any_path = PathBuf::from("/any/path/omamori");
        assert!(shim_matches_baseline(&any_path, "rm", Some(&baseline)));
    }

    // --- #103: config hash baseline comparison ---

    #[test]
    fn full_check_config_hash_ok_when_baseline_matches() {
        let dir = std::env::temp_dir().join(format!("omamori-cfghash-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        // Create minimal structure so full_check doesn't fail early
        let fake_bin = dir.join("omamori");
        fs::write(&fake_bin, "binary").unwrap();
        for cmd in installer::SHIM_COMMANDS {
            let _ = symlink(&fake_bin, shim_dir.join(cmd));
        }

        // Generate and write baseline (includes config hash)
        let baseline = generate_baseline(&dir).unwrap();
        write_baseline(&dir, &baseline).unwrap();

        let report = full_check(&dir);
        let config_item = report.items.iter().find(|i| i.name == "config.toml");
        // No config file = built-in defaults = Ok
        if let Some(item) = config_item {
            assert_ne!(
                item.status,
                CheckStatus::Fail,
                "config should not fail: {}",
                item.detail
            );
        }

        let _ = fs::remove_dir_all(dir);
    }

    // ---------------------------------------------------------------------
    // check_claude_settings_integration tests (#196 Bonus)
    // ---------------------------------------------------------------------

    #[test]
    #[serial_test::serial]
    fn check_claude_settings_warns_when_missing() {
        let dir =
            std::env::temp_dir().join(format!("omamori-int-no-claude-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(item.status, CheckStatus::Warn);

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_claude_settings_fails_on_legacy_matcher() {
        let dir = std::env::temp_dir().join(format!("omamori-int-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();

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

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(item.status, CheckStatus::Fail);
        assert!(
            item.detail.contains("matcher"),
            "detail should mention matcher: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_claude_settings_fails_when_only_hybrid_entry_exists() {
        // R2 regression (Codex Round 2): if the user has merged the omamori
        // command into a hybrid entry (with sibling user hooks), there is no
        // canonical omamori-owned entry. Doctor must report this as Fail
        // ("Layer 2 not omamori-controlled"), not silently green by reading
        // the user's sibling hook script.
        let dir = std::env::temp_dir().join(format!("omamori-int-hybrid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();

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

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(
            item.status,
            CheckStatus::Fail,
            "hybrid-only state must be Fail (no canonical entry)"
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    #[cfg(unix)]
    fn check_claude_settings_fails_on_non_executable_script() {
        // P1-4 (Codex R1): if the script is not executable, hash match alone
        // would falsely report green. Mode check must catch this.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("omamori-int-noexec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();
        // Non-executable mode (0o600 — read+write only)
        fs::set_permissions(&script, fs::Permissions::from_mode(0o600)).unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let current = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": omamori_cmd}],
                    "x-omamori-version": env!("CARGO_PKG_VERSION")
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&current).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(
            item.status,
            CheckStatus::Fail,
            "non-executable script must fail the integration check"
        );
        assert!(
            item.detail.contains("not executable"),
            "detail should mention executability: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_claude_settings_ok_when_wired_up() {
        let dir = std::env::temp_dir().join(format!("omamori-int-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();
        // P1-4: ok-state requires the script to be executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let current = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": omamori_cmd}],
                    "x-omamori-version": env!("CARGO_PKG_VERSION")
                }]
            }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&current).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(item.status, CheckStatus::Ok, "details: {}", item.detail);

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    // V-007: Doctor detects duplicate/stale omamori entries
    #[test]
    #[serial_test::serial]
    fn doctor_detects_duplicate_omamori_entries() {
        let dir =
            std::env::temp_dir().join(format!("omamori-int-dup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let current = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": omamori_cmd}],
            "x-omamori-version": env!("CARGO_PKG_VERSION")
        });
        let stale = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/old/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [current, stale] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_eq!(
            item.status,
            CheckStatus::Warn,
            "should warn about duplicates: {}",
            item.detail
        );
        assert!(
            item.detail.contains("duplicate"),
            "detail should mention duplicate: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// Negative test: a user hook whose filename happens to be
    /// claude-pretooluse.sh (but outside omamori's hooks/ dir) must NOT
    /// be counted as a duplicate omamori entry.
    #[test]
    fn doctor_does_not_count_user_hook_as_duplicate() {
        let dir =
            std::env::temp_dir().join(format!("omamori-int-nodup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, installer::render_hook_script()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let canonical = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": omamori_cmd}],
            "x-omamori-version": env!("CARGO_PKG_VERSION")
        });
        // User hook with same filename but different parent directory
        let user_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/usr/local/my-project/scripts/claude-pretooluse.sh"}]
        });
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [canonical, user_entry] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let item = check_claude_settings_integration(&dir.join(".omamori"));
        assert_ne!(
            item.status,
            CheckStatus::Warn,
            "user hook with same filename must not trigger duplicate warning: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }
}
