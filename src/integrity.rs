//! Integrity monitoring for omamori defense layers.
//!
//! Two-tier check:
//! - **Canary** (every shim invocation): `.integrity.json` exists + own symlink target = omamori binary. ~0.05ms.
//! - **Full check** (`omamori status`): all shims, hook content hash, config perms + hash, PATH order.

use std::fs;
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

/// Write baseline to `.integrity.json` via `atomic_file::atomic_write_with_mode`
/// (chmod 600, O_NOFOLLOW, fsync). `atomic_write_with_mode` always replaces
/// `path` via temp+rename regardless of whether it already exists, so the
/// former fresh-vs-existing branch (each hand-rolling its own temp+rename
/// around `write_new_file`) collapses to a single call.
pub fn write_baseline(base_dir: &Path, baseline: &IntegrityBaseline) -> Result<(), AppError> {
    let path = baseline_path(base_dir);
    let content =
        serde_json::to_string_pretty(baseline).map_err(|e| AppError::Config(e.to_string()))?;

    // Reject symlink at target path
    if path.symlink_metadata().is_ok() {
        crate::config::reject_symlink_public(&path, "integrity baseline")?;
    }

    write_new_file(&path, &content)
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

/// Extract the omamori exe path embedded in a Claude/Codex hook wrapper
/// script's `cat | <exe> hook-check ...` line (#349). Mirrors
/// `cursor_snippet_exe_path()`'s use of `shell_words::split`, adapted for the
/// shell-script format rather than the Cursor JSON snippet format.
fn hook_script_exe_path(content: &str) -> Option<PathBuf> {
    let line = content.lines().find(|l| l.contains("hook-check"))?;
    let words = shell_words::split(line).ok()?;
    let pipe_idx = words.iter().position(|w| w == "|")?;
    let exe = words.get(pipe_idx + 1)?;
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

/// Result of comparing an already-extracted "installed" version string
/// (shell hook comment or Cursor snippet `_comment`, #327/#381/#382) against
/// the running binary's version. An enum rather than `Option<String>` so
/// "versions agree" and "no comparable version found" can't be collapsed
/// into the same `None` and silently treated as "ok" — the plan invariant is
/// that missing/unparseable version comments never read as a false green.
/// `Missing` and `Rejected` are kept distinct (rather than one `Unknown`) so
/// the displayed message can say which happened: no comment at all reads
/// differently from one whose comment was specifically flagged as suspicious
/// (/code-review finding — the SEC-1 adversarial case deserves its own
/// message, not the same text as a pre-#327 legacy script).
enum HookVersionDrift {
    Matches,
    Missing,
    Rejected,
    Drift { installed: String },
}

/// Compares an already-extracted version string against `CARGO_PKG_VERSION`,
/// independent of exe resolution succeeding — deliberately so, since a
/// failed exe resolution (e.g. a broken Homebrew Cellar symlink) is exactly
/// the scenario that otherwise masks staleness (the motivating incident for
/// #327): the hash-comparison check that depends on exe resolution skips
/// entirely in that case, so this reads the hook's own embedded version
/// instead of needing a resolved exe to render an expected comparison.
/// `installed` is `None` when the caller found no version string at all
/// (file/field absent) and `Some(v)` when one was extracted — extraction
/// itself is format-specific and lives in the caller (`installer::parse_hook_version`
/// for the shell-comment format, `parse_cursor_snippet_version` for the JSON
/// `_comment` format, #381/#382).
fn detect_hook_version_drift(installed: Option<&str>) -> HookVersionDrift {
    match installed {
        None => HookVersionDrift::Missing,
        // An empty version string (malformed comment, e.g. `# omamori hook
        // v` with nothing after `v`, or a Cursor `_comment` reading
        // `"...omamori v. Merge..."`) is unparseable in practice even though
        // the caller's extractor returns `Some("")` for it — treat it the
        // same as a missing comment rather than displaying a blank version.
        Some("") => HookVersionDrift::Missing,
        // A hook file with a tampered version comment already fails the
        // hash comparison independently (that content differs from any
        // render), so this shape check isn't a security boundary — but
        // without it, `installed` (attacker-controlled once the file is
        // writable) flows unsanitized into a human-terminal tamper-warning
        // line. Reject anything that isn't a plausible version string
        // rather than echoing it (Phase 8 security review, SEC-1).
        Some(installed) if !is_plausible_version_string(installed) => HookVersionDrift::Rejected,
        Some(env!("CARGO_PKG_VERSION")) => HookVersionDrift::Matches,
        Some(installed) => HookVersionDrift::Drift {
            installed: installed.to_string(),
        },
    }
}

/// Whether `s` looks like a version string (digits, ASCII letters, `.`, `-`,
/// `+` — covers semver including pre-release/build metadata) rather than
/// control characters, ANSI escapes, or other terminal-hostile content.
fn is_plausible_version_string(s: &str) -> bool {
    s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// Formats `detect_hook_version_drift`'s result as a detail-string suffix:
/// empty when versions match, otherwise a bracketed clause naming both
/// versions (or noting why no comparison could be made). Advisory only —
/// this never changes a `CheckItem`'s status, only appends context to
/// whatever hash-comparison status was already decided; the sha256 baseline
/// stays the sole authority on tampering. `binary` is read directly at this
/// one call site rather than stored on `HookVersionDrift::Drift` — it's
/// always exactly `CARGO_PKG_VERSION`, a compile-time constant with no
/// independent value to carry through the enum (/code-review finding).
fn hook_version_drift_suffix(installed: Option<&str>) -> String {
    match detect_hook_version_drift(installed) {
        HookVersionDrift::Matches => String::new(),
        HookVersionDrift::Missing => {
            " [version drift: unknown \u{2014} no version metadata found]".to_string()
        }
        HookVersionDrift::Rejected => {
            " [version drift: unknown \u{2014} version metadata is unparseable]".to_string()
        }
        HookVersionDrift::Drift { installed } => format!(
            " [version drift: hooks rendered by v{installed}, binary is v{} \u{2014} run \
             `omamori install --hooks` (or `omamori doctor --fix`) to regenerate]",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

/// Extract the omamori exe path embedded in a cursor hooks snippet.
fn cursor_snippet_exe_path(content: &str) -> Option<PathBuf> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    let cmd = v["hooks"]["beforeShellExecution"][0]["command"].as_str()?;
    let words = shell_words::split(cmd).ok()?;
    let exe = words.first()?;
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

/// Extract the version from a Cursor hooks snippet's `_comment` field
/// (`render_cursor_hooks_snippet()` writes `"Generated by omamori v{X}. Merge
/// into .cursor/hooks.json"`, #382). The Cursor JSON format has no dedicated
/// version field — unlike the shell hooks' `# omamori hook v{X}` comment
/// line (`installer::parse_hook_version`) — so this mirrors that extractor's
/// role for the free-text `_comment` shape instead. Returns `None` for any
/// failure (invalid JSON, missing/non-string `_comment`, no `"omamori v"` or
/// `". "` boundary) rather than distinguishing them: all collapse to
/// `detect_hook_version_drift`'s `Missing` arm on the caller side, same as an
/// absent shell version comment.
fn parse_cursor_snippet_version(content: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    let comment = v.get("_comment")?.as_str()?;
    let after = comment.split_once("omamori v")?.1;
    let version = after.split_once(". ")?.0;
    Some(version.to_string())
}

/// Validate cursor hooks snippet: hash comparison + dangling path detection.
/// Byte-exact comparison against `render_cursor_hooks_snippet()` output;
/// any difference (including formatting) is treated as a mismatch (#56, T8).
/// `resolve_exe` is injectable (#382, mirroring `check_claude_hook_hash`'s
/// `ExeResolver` seam) so tests can drive the exe-resolution-failure branch
/// directly — previously this used an inline `std::env::current_exe()` call
/// that no test double could intercept, leaving that branch's version-drift
/// suffix (added below) unexercisable.
fn check_cursor_snippet(path: &Path, resolve_exe: ExeResolver) -> CheckItem {
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

    let installed = parse_cursor_snippet_version(&actual);

    // Hash comparison: generate expected content from the resolved omamori exe
    let hash_ok = resolve_exe().ok().map(|stable| {
        let expected = installer::render_cursor_hooks_snippet(&stable);
        installer::hook_content_hash(&expected) == installer::hook_content_hash(&actual)
    });

    // Dangling path detection: check if the exe in the snippet actually exists
    let dangling = cursor_snippet_exe_path(&actual).is_some_and(|p| !p.exists());

    // Drift suffix is injected on exactly the two branches where a stale
    // version is the likeliest explanation: exe resolution failing outright,
    // and a resolved-but-mismatching hash (the common post-upgrade case,
    // #382 Phase 5 Codex review P1 — an earlier draft only covered the
    // former, which meant the most common upgrade scenario never surfaced a
    // drift hint). The two dangling-priority branches deliberately omit it:
    // a dangling exe path is itself the more actionable diagnosis, and
    // `installed` there Missing/Rejected/Drift'ing over the underlying exe
    // problem would seed the empty commented case in Cursor as false noise
    // (#382 shape enumeration Δ6 — `_comment` is advisory-only, so users
    // deleting it is expected steady state, not an anomaly worth a suffix
    // once we already know the exe path is broken).
    let (status, detail, remediation) = match (hash_ok, dangling) {
        (Some(true), false) => (CheckStatus::Ok, "(hash match)".to_string(), None),
        (Some(true), true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)".to_string(),
            Some(Remediation::RunInstall),
        ),
        (Some(false), _) => {
            // Reuses `hash_mismatch_fail`'s message-building rather than
            // duplicating its literal + suffix format inline (#382
            // `/simplify` finding), then destructures back into this
            // match's tuple shape since the other arms don't build a full
            // `CheckItem` (they need `category`/`name` supplied once below).
            let item = hash_mismatch_fail(
                category,
                name.clone(),
                "(hash MISMATCH — run `omamori install --hooks`)",
                installed.as_deref(),
            );
            (item.status, item.detail, item.remediation)
        }
        (None, false) => (
            CheckStatus::Warn,
            exe_unresolved_detail(installed.as_deref()),
            Some(Remediation::RunInstall),
        ),
        (None, true) => (
            CheckStatus::Warn,
            "(path dangling — run `omamori install --hooks`)".to_string(),
            Some(Remediation::RunInstall),
        ),
    };

    CheckItem {
        category,
        name,
        status,
        detail,
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
    check_claude_settings_integration_with_verifier(
        base_dir,
        installer::verify_hook_contract,
        installer::resolved_current_omamori_exe,
    )
}

/// `check_claude_settings_integration()` with an injectable contract verifier
/// (#349) and exe resolver (#327), so tests can exercise the hash-match
/// "wired up" path without the production verifier rejecting the test binary
/// as a non-omamori exe, and can drive the "exe cannot be resolved" branch
/// directly.
fn check_claude_settings_integration_with_verifier(
    base_dir: &Path,
    verify: installer::HookVerifier,
    resolve_exe: ExeResolver,
) -> CheckItem {
    let name = "claude-code-settings".to_string();
    let category = "Hooks";

    let Some(claude_dir) = installer::claude_home_dir() else {
        return CheckItem {
            category,
            name,
            status: CheckStatus::Warn,
            detail: "(HOME unset — Claude Code not detected)".to_string(),
            remediation: Some(Remediation::RunInstall),
        };
    };
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

    let arr_opt = doc.pointer("/hooks/PreToolUse").and_then(|v| v.as_array());

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
    let installed = installer::parse_hook_version(&actual);
    let omamori_exe = match resolve_exe_or_warn(resolve_exe, category, name.clone(), installed) {
        Ok(exe) => exe,
        Err(item) => return item,
    };
    let expected_hash = installer::hook_content_hash(&installer::render_hook_script(&omamori_exe));
    let actual_hash = installer::hook_content_hash(&actual);
    if actual_hash != expected_hash {
        return hash_mismatch_fail(
            category,
            name,
            "(script content hash mismatch — possible tampering)",
            installed,
        );
    }

    // #349: hash match only proves the on-disk script mirrors what we'd
    // render for *some* previously-resolved exe — it says nothing about
    // whether that exe still works. A fresh re-resolution here (this doctor
    // process) would usually come out fine even when the file was written
    // with a since-vanished dev-build path, so we must probe the path
    // actually embedded in the file, not `omamori_exe` above.
    if let Some(embedded_exe) = hook_script_exe_path(&actual) {
        match verify(&embedded_exe, installer::HOOK_CONTRACT_TIMEOUT) {
            installer::HookContractStatus::Ok => {}
            status => {
                return CheckItem {
                    category,
                    name,
                    status: CheckStatus::Fail,
                    detail: format!(
                        "(hook points to {} but it fails the hook-check contract ({status:?}) — run: omamori install --hooks)",
                        embedded_exe.display()
                    ),
                    // RunInstall (not RegenerateHooks): `install()` fails
                    // loudly with a diagnostic message when verification
                    // fails, whereas `regenerate_hooks()` silently keeps the
                    // old hook (correct for its own background-self-repair
                    // caller, but doctor's --fix should surface the failure
                    // to the user, not report a silent no-op as "[fixed]").
                    remediation: Some(Remediation::RunInstall),
                };
            }
        }
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

/// A fn-pointer seam for resolving "the currently running omamori exe",
/// mirroring `HookVerifier`'s injection pattern so tests can drive the
/// "exe cannot be resolved" branch directly — the exact failure mode (e.g. a
/// broken Homebrew Cellar symlink) that #327's version-drift suffix exists to
/// surface instead of silently skipping.
type ExeResolver = fn() -> std::io::Result<PathBuf>;

/// The "(cannot resolve omamori exe — hash check skipped)" detail string
/// with drift suffix appended — shared by `resolve_exe_or_warn` (which
/// early-returns a `CheckItem` the moment resolution fails) and
/// `check_cursor_snippet` (which can't early-return here: it still needs to
/// compute `dangling` regardless of whether resolution succeeded, so it
/// builds this same detail inline for its `(None, false)` branch instead of
/// going through `resolve_exe_or_warn`'s `Result`-based control flow,
/// #382 `/simplify` finding).
fn exe_unresolved_detail(installed: Option<&str>) -> String {
    format!(
        "(cannot resolve omamori exe — hash check skipped){}",
        hook_version_drift_suffix(installed)
    )
}

/// Resolves the running omamori exe, or a fully-formed "(cannot resolve
/// omamori exe — hash check skipped)" `CheckItem` if resolution fails —
/// shared by `check_claude_hook_hash`, `check_codex_hook_hash`, and
/// `check_claude_settings_integration_with_verifier`, which all hit this
/// exact failure mode and message. `installed` is only read to compute the
/// version-drift suffix when resolution actually fails (#327's masked-skip
/// branch), not on the common path where resolution succeeds.
fn resolve_exe_or_warn(
    resolve_exe: ExeResolver,
    category: &'static str,
    name: String,
    installed: Option<&str>,
) -> Result<PathBuf, CheckItem> {
    resolve_exe().map_err(|_| CheckItem {
        category,
        name,
        status: CheckStatus::Warn,
        detail: exe_unresolved_detail(installed),
        remediation: Some(Remediation::RunInstall),
    })
}

/// Builds the `Fail`/`RegenerateHooks` `CheckItem` for a hash mismatch, with
/// the version-drift suffix appended — shared by `check_claude_hook_hash`,
/// `check_codex_hook_hash`, `check_claude_settings_integration_with_verifier`,
/// and `check_cursor_snippet` (the last destructures the result back into a
/// tuple, since it builds its `CheckItem` once at the end of a 5-way match
/// rather than early-returning), whose mismatch branches otherwise differ
/// only in `base_detail` (/code-review finding: this pair was left
/// duplicated while the parallel `resolve_exe_or_warn` case, one function
/// above, was deduped in the same diff).
fn hash_mismatch_fail(
    category: &'static str,
    name: String,
    base_detail: &str,
    installed: Option<&str>,
) -> CheckItem {
    CheckItem {
        category,
        name,
        status: CheckStatus::Fail,
        detail: format!("{base_detail}{}", hook_version_drift_suffix(installed)),
        remediation: Some(Remediation::RegenerateHooks),
    }
}

/// `full_check()`'s hash-comparison check for a shell-comment-versioned hook
/// wrapper (`claude-pretooluse.sh` / `codex-pretooluse.sh`, #381). Shared
/// body for `check_claude_hook_hash`/`check_codex_hook_hash`, which differ
/// only in which file they check and which `installer::render_*` function
/// produces the expected content — both scripts embed the same `# omamori
/// hook v{X}` comment line, so `installer::parse_hook_version` covers both.
/// `resolve_exe` is injectable so tests can swap in a failing stub.
fn check_hook_hash(
    hooks_dir: &Path,
    file_name: &str,
    render: fn(&Path) -> String,
    resolve_exe: ExeResolver,
) -> CheckItem {
    let name = file_name.to_string();
    let hook_path = hooks_dir.join(file_name);

    if !hook_path.exists() {
        return CheckItem {
            category: "Hooks",
            name,
            status: CheckStatus::Warn,
            detail: "(not installed — run `omamori install --hooks`)".to_string(),
            remediation: Some(Remediation::RunInstall),
        };
    }

    // Deliberately reads the file before attempting exe resolution — a
    // precedence decision, not an accident of refactoring. This means an
    // unreadable file now reports Fail/RegenerateHooks even if exe
    // resolution would *also* fail (previously, exe-resolution failure
    // always took priority and reported Warn/RunInstall, since the old
    // inline code never attempted the read in that branch). Read-first is
    // required for #327's core case (file readable, exe unresolvable) to
    // surface a drift suffix at all; for the rarer double-failure case, an
    // unreadable file is itself a concrete, actionable diagnosis (pinned by
    // `check_claude_hook_hash_unreadable_and_exe_both_fail_reports_unreadable`
    // below) rather than an untested side effect.
    let actual = match fs::read_to_string(&hook_path) {
        Ok(c) => c,
        Err(_) => {
            return CheckItem {
                category: "Hooks",
                name,
                status: CheckStatus::Fail,
                detail: "(unreadable)".to_string(),
                remediation: Some(Remediation::RegenerateHooks),
            };
        }
    };
    let installed = installer::parse_hook_version(&actual);
    let omamori_exe = match resolve_exe_or_warn(resolve_exe, "Hooks", name.clone(), installed) {
        Ok(exe) => exe,
        Err(item) => return item,
    };
    let expected = render(&omamori_exe);
    let expected_hash = installer::hook_content_hash(&expected);
    let actual_hash = installer::hook_content_hash(&actual);

    if expected_hash == actual_hash {
        CheckItem {
            category: "Hooks",
            name,
            status: CheckStatus::Ok,
            detail: "(hash match)".to_string(),
            remediation: None,
        }
    } else {
        hash_mismatch_fail(
            "Hooks",
            name,
            "(hash MISMATCH — run `omamori install --hooks`)",
            installed,
        )
    }
}

/// `full_check()`'s hash-comparison check for `claude-pretooluse.sh`.
fn check_claude_hook_hash(hooks_dir: &Path, resolve_exe: ExeResolver) -> CheckItem {
    check_hook_hash(
        hooks_dir,
        "claude-pretooluse.sh",
        installer::render_hook_script,
        resolve_exe,
    )
}

/// `full_check()`'s hash-comparison check for `codex-pretooluse.sh` (#381).
/// `check_hook_hash`'s not-installed branch fires unconditionally when the
/// file is absent from omamori's own hooks dir — independent of whether
/// Codex CLI itself is detected on the system, mirroring
/// `check_claude_hook_hash`'s CheckItem-presence behavior exactly. This
/// differs from `install --hooks`, which only *writes* the Codex wrapper
/// when `~/.codex` exists (`installer.rs`) — so a fresh install with no
/// `~/.codex` directory will show a permanent Warn here, not a false green.
fn check_codex_hook_hash(hooks_dir: &Path, resolve_exe: ExeResolver) -> CheckItem {
    check_hook_hash(
        hooks_dir,
        "codex-pretooluse.sh",
        installer::render_codex_pretooluse_script,
        resolve_exe,
    )
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
    items.push(check_claude_hook_hash(
        &hooks_dir,
        installer::resolved_current_omamori_exe,
    ));

    // codex-pretooluse.sh — hash comparison + version drift (#381)
    items.push(check_codex_hook_hash(
        &hooks_dir,
        installer::resolved_current_omamori_exe,
    ));

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

    // cursor-hooks.snippet.json — hash comparison + dangling path detection (#56, T8, #382)
    let cursor_snippet = hooks_dir.join("cursor-hooks.snippet.json");
    items.push(check_cursor_snippet(
        &cursor_snippet,
        installer::resolved_current_omamori_exe,
    ));

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

/// Shared by `write_baseline` and `config_cmd::mutate_config`. Before #307
/// this opened `path` directly with `create(true).truncate(true)` — the same
/// predictable-target, no-atomic-replace shape as the other #322-class sites
/// (mode never applied to a pre-existing file, no rename indirection).
pub(crate) fn write_new_file(path: &Path, content: &str) -> Result<(), AppError> {
    crate::atomic_file::atomic_write_with_mode(path, content.as_bytes(), 0o600)?;
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

    // --- hook_script_exe_path tests (#349) ---

    #[test]
    fn hook_script_exe_path_extracts_path_from_claude_script() {
        let script = installer::render_hook_script(Path::new("/opt/homebrew/bin/omamori"));
        let exe = hook_script_exe_path(&script).unwrap();
        assert_eq!(exe, PathBuf::from("/opt/homebrew/bin/omamori"));
    }

    #[test]
    fn hook_script_exe_path_extracts_path_from_codex_script() {
        let script =
            installer::render_codex_pretooluse_script(Path::new("/opt/homebrew/bin/omamori"));
        let exe = hook_script_exe_path(&script).unwrap();
        assert_eq!(exe, PathBuf::from("/opt/homebrew/bin/omamori"));
    }

    #[test]
    fn hook_script_exe_path_handles_spaces_in_path() {
        let script = installer::render_hook_script(Path::new("/Users/my user/bin/omamori"));
        let exe = hook_script_exe_path(&script).unwrap();
        assert_eq!(exe, PathBuf::from("/Users/my user/bin/omamori"));
    }

    #[test]
    fn hook_script_exe_path_returns_none_for_missing_hook_check_line() {
        let script = "#!/bin/sh\nset -eu\necho no hook-check here\n";
        assert!(hook_script_exe_path(script).is_none());
        assert!(hook_script_exe_path("").is_none());
    }

    #[test]
    fn hook_script_exe_path_returns_none_when_no_pipe_present() {
        let script = "#!/bin/sh\n/opt/homebrew/bin/omamori hook-check --provider claude-code\n";
        assert!(
            hook_script_exe_path(script).is_none(),
            "line without a `|` doesn't match the expected `cat | <exe> hook-check` shape"
        );
    }

    // --- hook version drift tests (#327) ---

    /// A syntactically valid hook script whose version comment names
    /// `fake_version` instead of the current binary's real version — content
    /// otherwise mirrors a real render, so hash comparisons against it behave
    /// like a genuinely stale on-disk script.
    fn script_with_version(fake_version: &str) -> String {
        let current = env!("CARGO_PKG_VERSION");
        let real = installer::render_hook_script(Path::new("/opt/homebrew/bin/omamori"));
        let replaced = real.replacen(
            &format!("# omamori hook v{current}"),
            &format!("# omamori hook v{fake_version}"),
            1,
        );
        assert_ne!(
            replaced, real,
            "fixture setup bug: version substitution did not change the script"
        );
        replaced
    }

    #[test]
    fn detect_hook_version_drift_matches_when_versions_agree() {
        let current = env!("CARGO_PKG_VERSION");
        let content = format!("#!/bin/sh\n# omamori hook v{current} — wrapper\nexit 0\n");
        assert!(matches!(
            detect_hook_version_drift(installer::parse_hook_version(&content)),
            HookVersionDrift::Matches
        ));
    }

    #[test]
    fn detect_hook_version_drift_flags_older_installed_version() {
        let content = "#!/bin/sh\n# omamori hook v0.0.1 — wrapper\nexit 0\n";
        match detect_hook_version_drift(installer::parse_hook_version(content)) {
            HookVersionDrift::Drift { installed } => assert_eq!(installed, "0.0.1"),
            _ => panic!("expected Drift, got a different shape"),
        }
    }

    #[test]
    fn detect_hook_version_drift_flags_newer_installed_version() {
        // A "future" version (e.g. binary was downgraded) must also be
        // flagged — drift is symmetric, not just staleness detection.
        let content = "#!/bin/sh\n# omamori hook v99.0.0 — wrapper\nexit 0\n";
        match detect_hook_version_drift(installer::parse_hook_version(content)) {
            HookVersionDrift::Drift { installed } => assert_eq!(installed, "99.0.0"),
            _ => panic!("expected Drift for a newer installed version"),
        }
    }

    #[test]
    fn detect_hook_version_drift_missing_when_comment_absent() {
        let content = "#!/bin/sh\nexit 0\n";
        assert!(matches!(
            detect_hook_version_drift(installer::parse_hook_version(content)),
            HookVersionDrift::Missing
        ));
    }

    #[test]
    fn detect_hook_version_drift_missing_when_comment_empty() {
        // `parse_hook_version` returns `Some("")` for `# omamori hook v` with
        // nothing after `v` — must not be displayed as a blank-version drift.
        let content = "#!/bin/sh\n# omamori hook v\nexit 0\n";
        assert!(matches!(
            detect_hook_version_drift(installer::parse_hook_version(content)),
            HookVersionDrift::Missing
        ));
    }

    #[test]
    fn detect_hook_version_drift_missing_when_installed_is_none() {
        // The JSON (Cursor) extraction path returns `None` — a distinct
        // origin from the shell path's `Some("")` above, but both must
        // collapse to the same `Missing` shape (#382 Mirror handoff Δ2,
        // shape enumeration V3/M1).
        assert!(matches!(
            detect_hook_version_drift(None),
            HookVersionDrift::Missing
        ));
    }

    #[test]
    fn detect_hook_version_drift_rejected_when_comment_has_control_chars() {
        // SEC-1 (Phase 8 security review): a tampered hook already fails the
        // hash comparison independently, but the version comment must not be
        // echoed unsanitized into a human-terminal tamper-warning line. ESC
        // + CR here would let an attacker visually cloak the "possible
        // tampering" message that follows it. Distinct from `Missing` so the
        // displayed message can say "unparseable" rather than "no comment at
        // all" — a legacy pre-#327 script and a specifically-flagged
        // suspicious one shouldn't read the same to a user (/code-review
        // finding).
        let content = "#!/bin/sh\n# omamori hook v0.0.1\x1b[31m\rCLOAKED\nexit 0\n";
        assert!(matches!(
            detect_hook_version_drift(installer::parse_hook_version(content)),
            HookVersionDrift::Rejected
        ));
    }

    #[test]
    fn detect_hook_version_drift_rejected_when_comment_too_long() {
        let content = format!("#!/bin/sh\n# omamori hook v{}\nexit 0\n", "9".repeat(64));
        assert!(matches!(
            detect_hook_version_drift(installer::parse_hook_version(&content)),
            HookVersionDrift::Rejected
        ));
    }

    #[test]
    fn detect_hook_version_drift_accepts_prerelease_and_build_metadata() {
        // Real semver shapes must not be rejected by the shape check.
        let content = "#!/bin/sh\n# omamori hook v1.2.3-beta.1+build.456\nexit 0\n";
        match detect_hook_version_drift(installer::parse_hook_version(content)) {
            HookVersionDrift::Drift { installed } => {
                assert_eq!(installed, "1.2.3-beta.1+build.456")
            }
            _ => panic!("expected Drift, got a different shape"),
        }
    }

    #[test]
    fn hook_version_drift_suffix_empty_when_matches() {
        let current = env!("CARGO_PKG_VERSION");
        let content = format!("#!/bin/sh\n# omamori hook v{current} — wrapper\nexit 0\n");
        assert_eq!(
            hook_version_drift_suffix(installer::parse_hook_version(&content)),
            ""
        );
    }

    #[test]
    fn hook_version_drift_suffix_names_both_versions_when_drift() {
        let content = "#!/bin/sh\n# omamori hook v0.0.1 — wrapper\nexit 0\n";
        let suffix = hook_version_drift_suffix(installer::parse_hook_version(content));
        assert!(suffix.contains("v0.0.1"), "suffix: {suffix}");
        assert!(
            suffix.contains(env!("CARGO_PKG_VERSION")),
            "suffix: {suffix}"
        );
        assert!(suffix.contains("version drift"), "suffix: {suffix}");
    }

    #[test]
    fn hook_version_drift_suffix_flags_unknown_when_comment_missing() {
        let suffix = hook_version_drift_suffix(installer::parse_hook_version("#!/bin/sh\nexit 0\n"));
        assert!(suffix.contains("unknown"), "suffix: {suffix}");
        // Neutralized wording (#382 Phase 5 Codex review P2): shared with the
        // JSON (Cursor) path now, so "hook script" language was replaced with
        // format-agnostic "version metadata".
        assert!(suffix.contains("no version metadata found"), "suffix: {suffix}");
    }

    #[test]
    fn hook_version_drift_suffix_distinguishes_rejected_from_missing() {
        // /code-review finding: a script with a version comment that was
        // specifically flagged as suspicious (SEC-1) must not read
        // identically to a legacy script with no comment at all.
        let missing = hook_version_drift_suffix(installer::parse_hook_version("#!/bin/sh\nexit 0\n"));
        let rejected = hook_version_drift_suffix(installer::parse_hook_version(
            "#!/bin/sh\n# omamori hook v0.0.1\x1b[31m\rCLOAKED\nexit 0\n",
        ));
        assert_ne!(missing, rejected);
        assert!(rejected.contains("unparseable"), "suffix: {rejected}");
    }

    // --- check_claude_hook_hash tests (#327) ---

    #[test]
    fn check_claude_hook_hash_reports_drift_when_exe_resolution_fails() {
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("claude-pretooluse.sh"),
            script_with_version("0.0.1"),
        )
        .unwrap();

        fn always_fails() -> std::io::Result<PathBuf> {
            Err(std::io::Error::other("simulated exe resolution failure"))
        }
        let item = check_claude_hook_hash(&dir, always_fails);

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(
            item.detail.contains("cannot resolve omamori exe"),
            "detail: {}",
            item.detail
        );
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);
        assert!(
            item.detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_claude_hook_hash_hash_mismatch_includes_drift_suffix() {
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("claude-pretooluse.sh"),
            script_with_version("0.0.1"),
        )
        .unwrap();

        let item = check_claude_hook_hash(&dir, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Fail);
        assert!(item.detail.contains("MISMATCH"), "detail: {}", item.detail);
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_claude_hook_hash_ok_when_hash_matches_no_drift_noise() {
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = installer::resolved_current_omamori_exe().unwrap();
        fs::write(
            dir.join("claude-pretooluse.sh"),
            installer::render_hook_script(&exe),
        )
        .unwrap();

        let item = check_claude_hook_hash(&dir, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Ok);
        assert_eq!(item.detail, "(hash match)");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_claude_hook_hash_not_installed_returns_warn() {
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t4-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let item = check_claude_hook_hash(&dir, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(
            item.detail.contains("not installed"),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_claude_hook_hash_unreadable_returns_fail() {
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t5-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // A directory at the expected script path exists but can't be
        // read as a file — triggers the "(unreadable)" branch.
        fs::create_dir_all(dir.join("claude-pretooluse.sh")).unwrap();

        let item = check_claude_hook_hash(&dir, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Fail);
        assert_eq!(item.detail, "(unreadable)");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_claude_hook_hash_unreadable_and_exe_both_fail_reports_unreadable() {
        // /code-review finding: extracting this function out of full_check
        // reversed the precedence between "file unreadable" and "exe cannot
        // be resolved" relative to the original inline code (which resolved
        // the exe first and never attempted the read on failure). Pins the
        // now-deliberate choice: an unreadable file wins even when exe
        // resolution would also fail, since read-first is what makes #327's
        // drift suffix reachable at all in the primary (file-readable) case.
        let dir = std::env::temp_dir().join(format!("omamori-hookdrift-t6-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("claude-pretooluse.sh")).unwrap();

        fn always_fails() -> std::io::Result<PathBuf> {
            Err(std::io::Error::other("simulated exe resolution failure"))
        }
        let item = check_claude_hook_hash(&dir, always_fails);

        assert_eq!(item.status, CheckStatus::Fail);
        assert_eq!(item.detail, "(unreadable)");
        assert_eq!(item.remediation, Some(Remediation::RegenerateHooks));

        let _ = fs::remove_dir_all(&dir);
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

        let item = check_cursor_snippet(&path, installer::resolved_current_omamori_exe);
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

        let item = check_cursor_snippet(&path, installer::resolved_current_omamori_exe);
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

        let item = check_cursor_snippet(&path, installer::resolved_current_omamori_exe);
        // Either FAIL (hash mismatch) or WARN (dangling) — either way, not Ok
        assert_ne!(item.status, CheckStatus::Ok);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn check_cursor_snippet_missing_returns_warn() {
        let path = Path::new("/nonexistent/cursor-hooks.snippet.json");
        let item = check_cursor_snippet(path, installer::resolved_current_omamori_exe);
        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("not installed"));
    }

    // --- check_codex_hook_hash tests (#381) ---
    //
    // `check_codex_hook_hash` is a thin wrapper around the shared
    // `check_hook_hash` body — its branch logic (hash match/mismatch, not
    // installed, exe-resolution-failure, unreadable) is exhaustively pinned
    // once already by `check_claude_hook_hash_*` above, since both wrappers
    // delegate to the identical shared function. Re-running all five
    // scenarios through the Codex wrapper would exercise no code path the
    // Claude-side tests don't already cover (#382 `/simplify` finding) — the
    // one thing genuinely specific to this wrapper is that it's wired to
    // the RIGHT filename and render function, which the hash-match test
    // below and `full_check_includes_codex_hook_check_item` together prove.

    #[test]
    fn check_codex_hook_hash_ok_when_hash_matches_no_drift_noise() {
        let dir = std::env::temp_dir().join(format!("omamori-codexdrift-t1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = installer::resolved_current_omamori_exe().unwrap();
        fs::write(
            dir.join("codex-pretooluse.sh"),
            installer::render_codex_pretooluse_script(&exe),
        )
        .unwrap();

        let item = check_codex_hook_hash(&dir, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Ok);
        assert_eq!(item.detail, "(hash match)");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_check_includes_codex_hook_check_item() {
        // V-006/V-006b: full_check wires check_codex_hook_hash in
        // unconditionally — a fresh dir with no codex-pretooluse.sh always
        // surfaces a Warn CheckItem for it, independent of whether Codex CLI
        // (or `~/.codex`) is present on this machine. `install --hooks` only
        // *writes* the wrapper when `~/.codex` is a real directory, so a
        // fresh install without it leaves this Warn permanently — mirroring
        // check_claude_hook_hash's CheckItem-presence behavior exactly.
        let dir = std::env::temp_dir().join(format!("omamori-codexdrift-t6-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let report = full_check(&dir);
        let codex_item = report
            .items
            .iter()
            .find(|i| i.name == "codex-pretooluse.sh")
            .expect("full_check should include a codex-pretooluse.sh CheckItem");
        assert_eq!(codex_item.status, CheckStatus::Warn);
        assert_eq!(codex_item.category, "Hooks");

        let _ = fs::remove_dir_all(&dir);
    }

    // --- parse_cursor_snippet_version tests (#382) ---

    /// Renders a real Cursor snippet (embedding `exe`) then substitutes the
    /// embedded version, mirroring `script_with_version()`'s approach for
    /// the shell format — there is no static fixture (#382 shape
    /// enumeration finding), the snippet is always generated at runtime.
    /// `exe` is caller-supplied rather than hardcoded (Codex Phase 6 review
    /// P1: a hardcoded `/opt/homebrew/bin/omamori` made the dangling-path
    /// check nondeterministic across runners — whether that path exists is
    /// environment-dependent, and dangling-detection tests specifically
    /// need control over it).
    fn cursor_snippet_with_version(exe: &Path, fake_version: &str) -> String {
        let current = env!("CARGO_PKG_VERSION");
        let real = installer::render_cursor_hooks_snippet(exe);
        let replaced = real.replacen(
            &format!("Generated by omamori v{current}."),
            &format!("Generated by omamori v{fake_version}."),
            1,
        );
        assert_ne!(
            replaced, real,
            "fixture setup bug: version substitution did not change the snippet"
        );
        replaced
    }

    #[test]
    fn parse_cursor_snippet_version_extracts_current() {
        // V-008
        let content = installer::render_cursor_hooks_snippet(Path::new("/opt/homebrew/bin/omamori"));
        assert_eq!(
            parse_cursor_snippet_version(&content).as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn parse_cursor_snippet_version_handles_prerelease() {
        // V-009
        let content = cursor_snippet_with_version(
            Path::new("/opt/homebrew/bin/omamori"),
            "1.2.3-beta.1+build.456",
        );
        assert_eq!(
            parse_cursor_snippet_version(&content).as_deref(),
            Some("1.2.3-beta.1+build.456")
        );
    }

    #[test]
    fn parse_cursor_snippet_version_returns_none_when_comment_absent() {
        // V-010 / V-012b origin 1: `_comment` field itself missing.
        let content = r#"{"hooks":{"beforeShellExecution":[{"command":"exit 0"}]}}"#;
        assert_eq!(parse_cursor_snippet_version(content), None);
    }

    #[test]
    fn parse_cursor_snippet_version_returns_none_when_comment_not_string() {
        // Phase 6 Codex review P2: `_comment` present but not a JSON string
        // (e.g. hand-edited to a number) — `.as_str()?` must reject it
        // gracefully rather than panicking.
        let content = r#"{"_comment": 123}"#;
        assert_eq!(parse_cursor_snippet_version(content), None);
    }

    #[test]
    fn parse_cursor_snippet_version_returns_none_when_marker_absent() {
        // Phase 6 Codex review P2: `_comment` is a well-formed string, but
        // not one omamori wrote (no "omamori v" marker at all) — distinct
        // from the "boundary present but incomplete" case below.
        let content = r#"{"_comment":"Generated by another tool"}"#;
        assert_eq!(parse_cursor_snippet_version(content), None);
    }

    #[test]
    fn parse_cursor_snippet_version_returns_none_when_json_broken() {
        // V-011 / V-012b origin 2: not valid JSON at all — no panic.
        let content = "{not valid json";
        assert_eq!(parse_cursor_snippet_version(content), None);
    }

    #[test]
    fn parse_cursor_snippet_version_returns_none_when_no_boundary() {
        // V-012b origin 3: `omamori v` marker present but no `". "` sentence
        // boundary to close the extraction.
        let content = r#"{"_comment":"Generated by omamori v1.2.3 without the expected boundary"}"#;
        assert_eq!(parse_cursor_snippet_version(content), None);
    }

    #[test]
    fn parse_cursor_snippet_version_returns_empty_when_version_blank() {
        // V-012b origin 4 (#382 shape enumeration V3): `_comment` present
        // with the `omamori v` marker but nothing before the `. ` boundary
        // — extracts as `Some("")`, which `detect_hook_version_drift` then
        // normalizes to Missing rather than a blank-version Drift.
        let content = r#"{"_comment":"Generated by omamori v. Merge into .cursor/hooks.json"}"#;
        assert_eq!(parse_cursor_snippet_version(content).as_deref(), Some(""));
        assert!(matches!(
            detect_hook_version_drift(parse_cursor_snippet_version(content).as_deref()),
            HookVersionDrift::Missing
        ));
    }

    #[test]
    fn parse_cursor_snippet_version_rejected_when_control_chars() {
        // V-012 (Critical, SEC-1 regression guard): the shared gate in
        // detect_hook_version_drift (not the extractor) is what rejects a
        // control-character version string — Shape A means this JSON path
        // gets the same is_plausible_version_string protection as the shell
        // path for free. Pins that the raw value round-trips through the
        // extractor unmodified so the shared gate is actually reached.
        // Uses JSON `\u` / `\r` escapes (not raw bytes) — raw unescaped
        // control characters inside a JSON string are themselves invalid
        // JSON, which would make this a `_comment`-is-not-valid-JSON test
        // instead of the intended is_plausible_version_string rejection.
        let content = r#"{"_comment":"Generated by omamori v0.0.1\u001b[31m\r. Merge"}"#;
        let extracted = parse_cursor_snippet_version(content);
        assert_eq!(extracted.as_deref(), Some("0.0.1\u{1b}[31m\r"));
        assert!(matches!(
            detect_hook_version_drift(extracted.as_deref()),
            HookVersionDrift::Rejected
        ));
    }

    // --- check_cursor_snippet ExeResolver + drift suffix tests (#382) ---

    #[test]
    fn check_cursor_snippet_reports_drift_when_exe_resolution_fails() {
        // V-007 (Critical): previously check_cursor_snippet resolved the exe
        // inline via std::env::current_exe(), a seam no test double could
        // intercept — this branch was undrivable before the ExeResolver
        // injection added in this PR.
        //
        // Must drive exactly the `(hash_ok=None, dangling=false)` branch —
        // embeds this test binary's own (guaranteed-existing) path rather
        // than a hardcoded `/opt/homebrew/bin/omamori` (Codex Phase 6 review
        // P1: that path doesn't exist on every runner, so `dangling` could
        // silently flip to `true` and this test would exercise the wrong
        // branch — see `cursor_snippet_with_version`'s doc comment).
        let dir = std::env::temp_dir().join(format!("omamori-cursordrift-t1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let existing_exe = std::env::current_exe().unwrap();
        let content = cursor_snippet_with_version(&existing_exe, "0.0.1");
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        fn always_fails() -> std::io::Result<PathBuf> {
            Err(std::io::Error::other("simulated exe resolution failure"))
        }
        let item = check_cursor_snippet(&path, always_fails);

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(
            item.detail.contains("cannot resolve omamori exe"),
            "detail: {}",
            item.detail
        );
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);
        assert!(
            item.detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_cursor_snippet_hash_mismatch_includes_drift_suffix() {
        // V-016 (Critical, Phase 5 Codex review P1): the most common
        // post-upgrade scenario — exe resolves fine but the on-disk snippet
        // is stale — must surface a drift suffix too, not just the
        // exe-resolution-failure branch above. An earlier draft only covered
        // that branch, silently missing this far more common case.
        let dir = std::env::temp_dir().join(format!("omamori-cursordrift-t2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Dangling status is irrelevant here — `(Some(false), _)` fires
        // regardless, since the resolved-exe path differs from this fixture
        // path either way (making the hash mismatch) — so an arbitrary path
        // is fine, unlike the exe-resolution-failure test above.
        let content = cursor_snippet_with_version(Path::new("/opt/homebrew/bin/omamori"), "0.0.1");
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        let item = check_cursor_snippet(&path, installer::resolved_current_omamori_exe);

        assert_eq!(item.status, CheckStatus::Fail);
        assert!(item.detail.contains("MISMATCH"), "detail: {}", item.detail);
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);
        assert!(
            item.detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_cursor_snippet_dangling_with_resolvable_exe_omits_drift_suffix() {
        // dangling-priority branch (Some(true), true): a snippet pointing at
        // a dangling exe path reports the dangling path, not a
        // version-drift suffix, even though hash comparison succeeded. The
        // resolve_exe stub deliberately returns the SAME nonexistent path
        // used to render the snippet, so the hash comparison matches (both
        // sides render from that path) while the embedded path itself is
        // dangling — the only way to reach `(Some(true), true)` without
        // `resolved_current_omamori_exe` (which never resolves to a path
        // that doesn't exist).
        let dir = std::env::temp_dir().join(format!("omamori-cursordrift-t3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let content = installer::render_cursor_hooks_snippet(Path::new("/nonexistent/bin/omamori"));
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        fn resolves_to_dangling_path() -> std::io::Result<PathBuf> {
            Ok(PathBuf::from("/nonexistent/bin/omamori"))
        }
        let item = check_cursor_snippet(&path, resolves_to_dangling_path);

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("dangling"), "detail: {}", item.detail);
        assert!(
            !item.detail.contains("version drift"),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_cursor_snippet_dangling_with_unresolvable_exe_omits_drift_suffix() {
        // V-016b (#382 shape enumeration finding): (None, true) — exe
        // resolution ALSO fails, but the dangling path already tells the
        // more actionable story than a version-drift hint would. Must not
        // be conflated with the (None, false) branch above, which DOES want
        // the suffix — this is the one dangling-priority combination that
        // wasn't previously pinned by its own test.
        let dir = std::env::temp_dir().join(format!("omamori-cursordrift-t4-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let content = installer::render_cursor_hooks_snippet(Path::new("/nonexistent/bin/omamori"));
        let path = dir.join("cursor-hooks.snippet.json");
        fs::write(&path, &content).unwrap();

        fn always_fails() -> std::io::Result<PathBuf> {
            Err(std::io::Error::other("simulated exe resolution failure"))
        }
        let item = check_cursor_snippet(&path, always_fails);

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(item.detail.contains("dangling"), "detail: {}", item.detail);
        assert!(
            !item.detail.contains("version drift"),
            "detail: {}",
            item.detail
        );
        assert!(
            !item.detail.contains("cannot resolve"),
            "detail: {}",
            item.detail
        );

        let _ = fs::remove_dir_all(&dir);
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
    fn check_claude_settings_warns_when_home_unset() {
        // #210: doctor must not panic when HOME is unset — it must fall
        // through to the same Warn outcome as "Claude Code not configured",
        // not `.unwrap()` the `Option<PathBuf>` from `claude_home_dir()`.
        let saved = std::env::var_os("HOME");
        unsafe { std::env::remove_var("HOME") };

        let item = check_claude_settings_integration(Path::new("/tmp/omamori-test-nonexistent"));

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        assert_eq!(item.status, CheckStatus::Warn);
        assert!(
            item.detail.contains("HOME unset"),
            "detail: {}",
            item.detail
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
    fn check_claude_settings_fails_on_legacy_matcher() {
        let dir = std::env::temp_dir().join(format!("omamori-int-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();

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
    #[serial_test::serial(home_env)]
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
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();

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
    #[serial_test::serial(home_env)]
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
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();
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
    #[serial_test::serial(home_env)]
    fn check_claude_settings_ok_when_wired_up() {
        let dir = std::env::temp_dir().join(format!("omamori-int-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();
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

        // #349: the test binary is never a genuine omamori binary, so the
        // production verifier would always reject the embedded exe path —
        // inject a passing stub to exercise the hash-match "wired up" path.
        let item = check_claude_settings_integration_with_verifier(
            &dir.join(".omamori"),
            |_, _| installer::HookContractStatus::Ok,
            installer::resolved_current_omamori_exe,
        );
        assert_eq!(item.status, CheckStatus::Ok, "details: {}", item.detail);
        // #327 test-adversarial finding: a matching-version fixture proves
        // `check_claude_hook_hash`'s OK path is drift-free, but says nothing
        // about *this* function's separate OK branch — assert directly.
        assert!(
            !item.detail.contains("version drift"),
            "OK path must not append drift noise: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn check_claude_settings_hash_mismatch_includes_drift_suffix() {
        // #327 test-adversarial finding: `check_claude_hook_hash`'s
        // hash-MISMATCH+drift combination has direct coverage, but this
        // function's own (separate) mismatch branch at integrity.rs:624 did
        // not — a bug that dropped the suffix here, or built it from the
        // wrong content, would have passed unnoticed.
        let dir = std::env::temp_dir().join(format!(
            "omamori-int-settingsmismatch-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        // Tampered version comment — same technique as
        // `check_claude_hook_hash_hash_mismatch_includes_drift_suffix` — this
        // also makes the content hash mismatch (verified below the resolver
        // never reaches `verify()`, since the mismatch branch returns first).
        fs::write(&script, script_with_version("0.0.1")).unwrap();
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

        // A verifier that panics if called proves the mismatch branch
        // returns before ever reaching `verify()` — i.e. `resolve_exe`
        // disagreeing with the embedded content can never smuggle a wrong
        // path into the contract probe (test-adversarial finding: this is
        // the actual safety property behind "does verify get the embedded
        // path, not resolve_exe's" — provable structurally, since the
        // mismatch check gates before `verify()` is reached at all).
        fn panics_if_called(_: &Path, _: std::time::Duration) -> installer::HookContractStatus {
            panic!("verify() must not be called when the hash comparison already failed")
        }
        let item = check_claude_settings_integration_with_verifier(
            &dir.join(".omamori"),
            panics_if_called,
            installer::resolved_current_omamori_exe,
        );
        assert_eq!(item.status, CheckStatus::Fail, "details: {}", item.detail);
        assert!(
            item.detail.contains("hash mismatch"),
            "detail: {}",
            item.detail
        );
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);
        assert!(
            item.detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn check_claude_settings_fails_when_embedded_exe_broken() {
        // #349: even when the on-disk script's content hash matches what we'd
        // render today (no tampering), the exe path baked into that content
        // may no longer be a working omamori binary (e.g. a since-vanished
        // dev build). This must be caught by probing the embedded path
        // directly — a fresh re-resolution inside this check would not
        // reproduce the staleness.
        let dir =
            std::env::temp_dir().join(format!("omamori-int-brokenexe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();
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

        let item = check_claude_settings_integration_with_verifier(
            &dir.join(".omamori"),
            |_, _| installer::HookContractStatus::ExitNonZero(1),
            installer::resolved_current_omamori_exe,
        );
        assert_eq!(item.status, CheckStatus::Fail, "details: {}", item.detail);
        assert!(
            item.detail.contains("hook-check contract"),
            "detail should explain the contract failure: {}",
            item.detail
        );
        assert!(
            item.detail.contains("omamori install --hooks"),
            "detail should point at the recovery command: {}",
            item.detail
        );
        // #349 Codex Round 1 P0: must route through the loud `install()` path
        // (RunInstall), not the silent `regenerate_hooks()` path
        // (RegenerateHooks) — the latter would let `doctor --fix` report
        // "[fixed]" even though nothing was actually written.
        assert_eq!(
            item.remediation,
            Some(Remediation::RunInstall),
            "must remediate via RunInstall, not RegenerateHooks"
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn check_claude_settings_reports_drift_when_exe_resolution_fails() {
        // #327: the settings-integration check's own exe-resolution-failure
        // branch (distinct from `check_claude_hook_hash`'s) must also surface
        // version drift instead of masking it — this is the same "hash check
        // depends on exe resolution succeeding" gap, at the second call site.
        let dir =
            std::env::temp_dir().join(format!("omamori-int-settingsdrift-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(&script, script_with_version("0.0.1")).unwrap();
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

        fn always_fails() -> std::io::Result<PathBuf> {
            Err(std::io::Error::other("simulated exe resolution failure"))
        }
        let item = check_claude_settings_integration_with_verifier(
            &dir.join(".omamori"),
            |_, _| installer::HookContractStatus::Ok,
            always_fails,
        );
        assert_eq!(item.status, CheckStatus::Warn, "details: {}", item.detail);
        assert!(
            item.detail.contains("cannot resolve omamori exe"),
            "detail: {}",
            item.detail
        );
        assert!(item.detail.contains("0.0.1"), "detail: {}", item.detail);
        assert!(
            item.detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {}",
            item.detail
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    // V-007: Doctor detects duplicate/stale omamori entries
    #[test]
    #[serial_test::serial(home_env)]
    fn doctor_detects_duplicate_omamori_entries() {
        let dir = std::env::temp_dir().join(format!("omamori-int-dup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();
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
    #[serial_test::serial(home_env)]
    fn doctor_does_not_count_user_hook_as_duplicate() {
        let dir = std::env::temp_dir().join(format!("omamori-int-nodup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let omamori_hooks = dir.join(".omamori").join("hooks");
        fs::create_dir_all(&omamori_hooks).unwrap();
        let script = omamori_hooks.join("claude-pretooluse.sh");
        fs::write(
            &script,
            installer::render_hook_script(&installer::resolved_current_omamori_exe().unwrap()),
        )
        .unwrap();
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
