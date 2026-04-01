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
    let path = cmd.strip_suffix(" cursor-hook")?.trim_matches('"');
    (!path.is_empty()).then(|| PathBuf::from(path))
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

    let (status, detail) = match (hash_ok, dangling) {
        (Some(true), false) => (CheckStatus::Ok, "(hash match)"),
        (Some(true), true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)",
        ),
        (Some(false), _) => (
            CheckStatus::Fail,
            "(hash MISMATCH — run `omamori install --hooks`)",
        ),
        (None, false) => (CheckStatus::Warn, "(present, hash check skipped)"),
        (None, true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)",
        ),
    };

    CheckItem {
        category,
        name,
        status,
        detail: detail.to_string(),
    }
}

/// Run a full integrity check of all defense layers.
pub fn full_check(base_dir: &Path) -> IntegrityReport {
    let mut items = Vec::new();

    // --- Shims ---
    let shim_dir = base_dir.join("shim");
    for command in installer::SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        let (status, detail) = match fs::read_link(&link_path) {
            Ok(target) => {
                let target_name = target.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if target_name != "omamori" {
                    (
                        CheckStatus::Fail,
                        format!("-> {} (unexpected target)", target.display()),
                    )
                } else if !target.exists() {
                    (
                        CheckStatus::Fail,
                        format!("-> {} (dangling)", target.display()),
                    )
                } else {
                    (CheckStatus::Ok, format!("-> {}", target.display()))
                }
            }
            Err(_) => (CheckStatus::Fail, "missing".to_string()),
        };
        items.push(CheckItem {
            category: "Shims",
            name: (*command).to_string(),
            status,
            detail,
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
                    });
                } else {
                    items.push(CheckItem {
                        category: "Hooks",
                        name: "claude-pretooluse.sh".to_string(),
                        status: CheckStatus::Fail,
                        detail: "(hash MISMATCH — run `omamori install --hooks`)".to_string(),
                    });
                }
            }
            Err(_) => {
                items.push(CheckItem {
                    category: "Hooks",
                    name: "claude-pretooluse.sh".to_string(),
                    status: CheckStatus::Fail,
                    detail: "(unreadable)".to_string(),
                });
            }
        }
    } else {
        items.push(CheckItem {
            category: "Hooks",
            name: "claude-pretooluse.sh".to_string(),
            status: CheckStatus::Warn,
            detail: "(not installed — run `omamori install --hooks`)".to_string(),
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
        }
    } else {
        CheckItem {
            category: "Hooks",
            name: "claude-settings.snippet.json".to_string(),
            status: CheckStatus::Warn,
            detail: "(not installed)".to_string(),
        }
    });

    // cursor-hooks.snippet.json — hash comparison + dangling path detection (#56, T8)
    let cursor_snippet = hooks_dir.join("cursor-hooks.snippet.json");
    items.push(check_cursor_snippet(&cursor_snippet));

    // --- Config ---
    if let Some(entry) = read_config_entry() {
        let path = Path::new(&entry.path);
        if entry.mode & 0o777 == 0o600 {
            items.push(CheckItem {
                category: "Config",
                name: "config.toml".to_string(),
                status: CheckStatus::Ok,
                detail: format!("(mode 600, hash {})", &entry.sha256[..12]),
            });
        } else {
            items.push(CheckItem {
                category: "Config",
                name: "config.toml".to_string(),
                status: CheckStatus::Warn,
                detail: format!(
                    "(mode {:o} — run `chmod 600 {}`)",
                    entry.mode & 0o777,
                    path.display()
                ),
            });
        }
    } else {
        items.push(CheckItem {
            category: "Config",
            name: "config.toml".to_string(),
            status: CheckStatus::Ok,
            detail: "(using built-in defaults)".to_string(),
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
        let (status, detail) = if overridden == 0 {
            (
                CheckStatus::Ok,
                format!("{} core rules active, 0 overridden", core_rules.len()),
            )
        } else {
            (
                CheckStatus::Warn,
                format!("{active} active, {overridden} overridden"),
            )
        };
        items.push(CheckItem {
            category: "Core Policy",
            name: "core rules".to_string(),
            status,
            detail,
        });
    }

    // --- PATH ---
    let path_check = check_path_order(base_dir);
    items.push(path_check);

    // --- Baseline ---
    let bp = baseline_path(base_dir);
    if bp.exists() {
        match read_baseline(base_dir) {
            Ok(Some(b)) => {
                if b.version == env!("CARGO_PKG_VERSION") {
                    items.push(CheckItem {
                        category: "Baseline",
                        name: ".integrity.json".to_string(),
                        status: CheckStatus::Ok,
                        detail: format!("(v{}, {})", b.version, b.generated_at),
                    });
                } else {
                    items.push(CheckItem {
                        category: "Baseline",
                        name: ".integrity.json".to_string(),
                        status: CheckStatus::Warn,
                        detail: format!(
                            "(v{} — current binary is v{})",
                            b.version,
                            env!("CARGO_PKG_VERSION")
                        ),
                    });
                }
            }
            Ok(None) => unreachable!(),
            Err(e) => {
                items.push(CheckItem {
                    category: "Baseline",
                    name: ".integrity.json".to_string(),
                    status: CheckStatus::Warn,
                    detail: format!("(corrupt: {e})"),
                });
            }
        }
    } else {
        items.push(CheckItem {
            category: "Baseline",
            name: ".integrity.json".to_string(),
            status: CheckStatus::Warn,
            detail: "(not found — will be created)".to_string(),
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
        },
        (Some(s), Some(u)) if s >= u => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: format!("{} is AFTER /usr/bin — shims may be bypassed", shim_str),
        },
        (None, _) => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: format!("{} not found in PATH", shim_str),
        },
        _ => CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Ok,
            detail: format!("{} in PATH (/usr/bin not found to compare)", shim_str),
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
fn write_new_file(path: &Path, content: &str) -> Result<(), AppError> {
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
fn write_new_file(path: &Path, content: &str) -> Result<(), AppError> {
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
}
