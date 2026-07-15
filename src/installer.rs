use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::AppError;

/// Marker used to identify omamori entries in Codex hooks.json.
/// Codex displays `statusMessage` in the TUI, so this doubles as user feedback.
const CODEX_STATUS_MESSAGE: &str = "omamori: checking command safety";

pub const SHIM_COMMANDS: &[&str] = &["rm", "git", "chmod", "find", "rsync"];

/// The provenance of an install source path: whether the caller named it
/// explicitly (e.g. a `--source` flag) or it was implicitly resolved from
/// `current_exe()` (#354). Carrying the path and its provenance in one value
/// (rather than a separate `source_exe: PathBuf` + `source_is_explicit: bool`
/// pair, as this type replaced — #378) makes an implicitly-resolved path
/// with `Explicit` provenance unrepresentable by accident.
///
/// **Caller contract**: `Explicit` must only be constructed from a
/// caller-supplied `--source` flag (see `cli/setup.rs` and `cli/install.rs`).
/// Constructing it for a path derived from
/// `current_exe()`/`resolve_stable_exe_path()` without direct user input
/// reintroduces the implicit-resolution risk this type exists to prevent —
/// see the dev-build provenance check in `install()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceExe {
    /// Resolved without direct user input (`current_exe()` self-resolution).
    /// Subject to the dev-build provenance check in `install()`.
    Implicit(PathBuf),
    /// Named explicitly by the caller (a `--source` flag). The documented
    /// recovery path (e.g. developing omamori itself); bypasses the
    /// dev-build provenance check.
    Explicit(PathBuf),
}

impl SourceExe {
    /// Must be a stable path (not a versioned Cellar path). Callers
    /// constructing `Implicit` should pass the result of
    /// `resolve_stable_exe_path()` when starting from `current_exe()`.
    pub fn path(&self) -> &Path {
        match self {
            SourceExe::Implicit(p) | SourceExe::Explicit(p) => p,
        }
    }

    pub fn is_explicit(&self) -> bool {
        // Exhaustive match (no wildcard), matching `path()` above — a future
        // third variant must be handled here explicitly rather than silently
        // falling through `matches!`'s implicit `_ => false`.
        match self {
            SourceExe::Implicit(_) => false,
            SourceExe::Explicit(_) => true,
        }
    }
}

impl Default for SourceExe {
    /// Fail-close: a caller that forgets to set this field gets `Implicit`
    /// (subject to the dev-build gate), never `Explicit` (which bypasses it).
    fn default() -> Self {
        SourceExe::Implicit(PathBuf::new())
    }
}

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    pub base_dir: PathBuf,
    pub source: SourceExe,
    pub generate_hooks: bool,
    /// Override for the resolved `$HOME` used to locate `~/.claude` and
    /// `~/.codex`. `None` means production: resolve via `home_dir()`.
    /// `Some(dir)` pins both merge targets explicitly — used by in-process
    /// tests to guarantee the real `$HOME` is never reached (#210). This is
    /// a distinct `Option` layer from `home_dir()`'s own `None` (HOME unset)
    /// — field `None` defers resolution, env `None` means "not detected".
    pub home_override: Option<PathBuf>,
    /// Override for hook-contract verification (#349). `None` means
    /// production: verify by actually spawning `source_exe`. `Some(fn)` lets
    /// in-process tests substitute a fixed status without spawning a real
    /// binary (the test process's own exe is never a genuine omamori binary).
    pub verify_override: Option<HookVerifier>,
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
    /// Stale omamori entries (from different install roots or legacy formats)
    /// were cleaned up. The current canonical entry was merged or was already
    /// present after cleanup. The count is the number of stale entries removed.
    StaleEntriesCleaned(usize),
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
    // Resolve shim paths but do NOT canonicalize — Homebrew stable symlinks
    // like /opt/homebrew/bin/omamori must stay as-is (#42).
    let requested = options.source.path();
    let source_exe = shim_to_real_exe(requested).unwrap_or_else(|| requested.to_path_buf());

    // Layer 1 (PATH shims) has no dependency on hook verification — link it
    // unconditionally so a hook-contract failure below can't also block
    // shim repair (#349 code review: `install()` previously gated shim
    // creation on hook verification, so `omamori setup`'s first run and
    // `doctor --fix`'s shim-only RunInstall repairs would fail completely —
    // losing even Layer 1 protection — whenever verification failed for a
    // reason unrelated to shims).
    let shim_dir = options.base_dir.join("shim");
    fs::create_dir_all(&shim_dir)?;

    let mut linked_commands = Vec::new();

    for command in SHIM_COMMANDS {
        let link_path = shim_dir.join(command);
        recreate_symlink(&source_exe, &link_path)?;
        linked_commands.push((*command).to_string());
    }

    // #349: verify the resolved exe actually satisfies the hook-check contract
    // before writing any hook artifact. Unlike `regenerate_hooks()` (a silent
    // background self-repair), `install --hooks` is both an explicit command
    // and the documented recovery path from a fail-close lockout — silently
    // keeping old hooks while reporting success would mean the recovery
    // command lies about having recovered. Fail loud instead: no hook file is
    // written, so existing hooks (if any) are untouched and protection
    // continues under the previously installed binary. This gate is scoped to
    // hook artifacts only — it runs after Layer 1 is already linked above, so
    // a hook-contract failure never prevents shim repair.
    if options.generate_hooks {
        // #354: `source_exe` came from an implicit current-exe resolution
        // (setup/doctor's auto-repair, or `install` with no `--source`) unless
        // the caller explicitly marked it. An implicit dev-build path is
        // rejected here, before even probing the hook-check contract — a
        // fresh `cargo build` binary can be fully contract-compliant today
        // and still be the wrong thing to pin (see `is_dev_build_path`).
        if !options.source.is_explicit() && is_dev_build_path(&source_exe) {
            return Err(AppError::Config(format!(
                "could not update hooks — resolved binary at {} {DEV_BUILD_PATH_DESCRIPTION}\n\
                 Layer 1 (PATH shims) was still updated; existing hooks (if any) are kept and protection remains active with the previously installed binary\n\
                 if this is intentional (e.g. developing omamori itself), pass --source explicitly: `omamori install --hooks --source {}` or `omamori setup --source {}`",
                source_exe.display(),
                source_exe.display(),
                source_exe.display()
            )));
        }

        let verify = options.verify_override.unwrap_or(verify_hook_contract);
        match verify(&source_exe, HOOK_CONTRACT_TIMEOUT) {
            HookContractStatus::Ok => {}
            status => {
                return Err(AppError::Config(format!(
                    "could not update hooks — resolved binary at {} failed the hook-check contract ({status:?})\n\
                     Layer 1 (PATH shims) was still updated; existing hooks are kept and protection remains active with the previously installed binary\n\
                     if you ran this to recover from a blocked state, the currently running omamori binary may itself be the broken one — verify omamori is installed at a stable path, then retry",
                    source_exe.display()
                )));
            }
        }
    }

    let (hook_script, settings_snippet) = if options.generate_hooks {
        let hooks_dir = options.base_dir.join("hooks");
        fs::create_dir_all(&hooks_dir)?;

        let script_path = hooks_dir.join("claude-pretooluse.sh");
        atomic_write_script(&script_path, &render_hook_script(&source_exe))?;

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
        atomic_write(
            &cursor_snippet_path,
            &render_cursor_hooks_snippet(&source_exe),
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
            let claude_dir = options
                .home_override
                .clone()
                .map(|h| h.join(".claude"))
                .or_else(claude_home_dir);
            match claude_dir {
                Some(claude_dir) if is_real_directory(&claude_dir) => Some(
                    merge_claude_settings(&claude_dir, script_path)
                        .unwrap_or_else(|e| ClaudeSettingsOutcome::Skipped(format!("I/O: {e}"))),
                ),
                Some(_) => Some(ClaudeSettingsOutcome::Skipped(
                    "Claude Code not detected (~/.claude not a directory)".into(),
                )),
                None => Some(ClaudeSettingsOutcome::Skipped(
                    "HOME unset — Claude Code not detected".into(),
                )),
            }
        }
        _ => None,
    };

    // Generate Codex CLI hook (wrapper → hooks.json → config.toml)
    let (codex_wrapper, codex_hooks_outcome, codex_config_outcome) = if options.generate_hooks {
        setup_codex_hooks(
            &options.base_dir,
            &source_exe,
            options.home_override.clone(),
        )
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

/// Atomic write via the canonical `atomic_file::atomic_write_with_mode`
/// helper (#307 PR2). Fixed at `0o600` — every data-file call site in this
/// module already used this mode, either explicitly (the removed
/// `legacy_atomic_write_with_mode(.., 0o600)`) or, before this migration,
/// implicitly via umask (a user-visible permissions tightening for the
/// handful of sites that only ever called the mode-less `atomic_write`).
fn atomic_write(target: &Path, content: &str) -> Result<(), std::io::Error> {
    crate::atomic_file::atomic_write_with_mode(target, content.as_bytes(), 0o600)
}

/// Same as [`atomic_write`] but with executable (`0o755`) permissions, for
/// generated shell scripts (hook wrappers). Setting the mode at creation
/// time removes the window the old rename-then-`chmod` dance left open,
/// where the script briefly existed with default, non-executable
/// permissions.
fn atomic_write_script(target: &Path, content: &str) -> Result<(), std::io::Error> {
    crate::atomic_file::atomic_write_with_mode(target, content.as_bytes(), 0o755)
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
        .map(|rest| rest.split([' ', '\t']).next().unwrap_or(rest))
}

/// Whether `regenerate_hooks_with_verifier` actually rewrote the hook
/// scripts, or left the existing ones in place because the resolved exe
/// couldn't be trusted (#349). A bare `Result<(), io::Error>` conflates
/// "wrote" and "verification failed, kept the old file" — both are `Ok(())`
/// — forcing every caller that cares about the distinction to re-derive it
/// by re-reading and re-hashing the file. Returning it directly here removes
/// that duplication at all three call sites (`ensure_hooks_current_at`'s two
/// branches, `doctor`'s `RegenerateHooks` fix-loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HookOutcome {
    Written,
    KeptExisting(HookKeptReason),
}

/// Why `regenerate_hooks_with_verifier` kept the existing hook instead of
/// writing a new one — three unrelated causes that callers must not conflate
/// into one message (#349 code review): resolving the current exe can fail
/// for reasons that have nothing to do with the hook-check contract (e.g.
/// `std::env::current_exe()` failing in a restrictive container), in which
/// case the binary was never even probed. `NonDeploymentPath` (#354) is a
/// distinct third cause: the binary resolved and would likely pass contract
/// verification just fine, but its path is a transient `cargo build` output
/// directory rather than a stable install — persisting it would silently
/// repoint the hook at a path the next build can delete or replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HookKeptReason {
    ExeResolutionFailed,
    VerificationFailed(HookContractStatus),
    NonDeploymentPath,
}

/// True if `path` resolves through a Cargo build output directory
/// (`target/debug/...`, `target/release/...`, or the cross-compile layout
/// `target/<triple>/debug|release/...` produced by `cargo build --target`)
/// rather than a stable, deployed install (#354) — the signature of a
/// `cargo build`/`cargo test` artifact that the next build can delete or
/// overwrite out from under a persisted hook/shim reference.
///
/// Checked as whole path *components*, not a substring — `.contains("target/debug")`
/// would false-positive on `target/debugger/omamori` (V-018). `cargo install`
/// output lives under `~/.cargo/bin`, so it never matches. The cross-compile
/// case is checked with one arbitrary component allowed between `target` and
/// `debug`/`release` (matching Cargo's own two documented layouts, not an
/// open-ended "anywhere later" match, which would false-positive on
/// unrelated paths like `target/staging/release/...`).
fn is_dev_build_path(path: &Path) -> bool {
    let components: Vec<_> = path.components().collect();
    let is_target = |c: &std::path::Component| c.as_os_str() == "target";
    let is_profile_dir =
        |c: &std::path::Component| c.as_os_str() == "debug" || c.as_os_str() == "release";
    components
        .windows(2)
        .any(|pair| is_target(&pair[0]) && is_profile_dir(&pair[1]))
        || components
            .windows(3)
            .any(|triple| is_target(&triple[0]) && is_profile_dir(&triple[2]))
}

/// Diagnostic clause shared by every call site that rejects an implicitly
/// resolved dev-build path (`install()`, `regenerate_hooks_for_exe`,
/// `auto_setup_codex_if_needed`, and doctor.rs's `describe_regen_hooks_outcome`)
/// — kept as a single constant (/simplify review) so a future wording change
/// can't drift out of sync across the four sites.
pub(crate) const DEV_BUILD_PATH_DESCRIPTION: &str =
    "looks like a cargo build artifact (target/debug or target/release), not a stable install";

/// Regenerate hooks only (no shim recreation, no config touch).
/// Called from shim when version mismatch detected.
pub fn regenerate_hooks(base_dir: &Path) -> Result<(), std::io::Error> {
    regenerate_hooks_with_verifier(base_dir, verify_hook_contract).map(|_| ())
}

/// `regenerate_hooks()` with an injectable contract verifier, so tests can
/// substitute a fixed `HookContractStatus` instead of spawning a real binary
/// (the test process's own exe is never a genuine omamori binary, so the
/// production verifier would always reject it — see `regenerate_hooks_creates_files`).
pub(crate) fn regenerate_hooks_with_verifier(
    base_dir: &Path,
    verify: HookVerifier,
) -> Result<HookOutcome, std::io::Error> {
    // Resolve exe path once, shared by Claude/Cursor/Codex hooks.
    // Fail-close: if resolution fails, skip all hook regeneration rather than
    // falling back to bare `omamori` which would reintroduce PATH vulnerability (#315).
    let stable_exe = match resolved_current_omamori_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!(
                "omamori warning: failed to resolve current exe ({}); hooks not regenerated",
                e
            );
            return Ok(HookOutcome::KeptExisting(
                HookKeptReason::ExeResolutionFailed,
            ));
        }
    };

    regenerate_hooks_for_exe(base_dir, &stable_exe, verify)
}

/// `regenerate_hooks_with_verifier()` with the resolved exe path also
/// injectable, so tests can exercise the dev-build-path/contract-verification
/// logic against a synthetic path instead of the test binary's own
/// `current_exe()` — which is itself always a `target/debug`/`target/release`
/// path under `cargo test` and would otherwise trip the #354 check below
/// before the test even gets to what it's actually checking.
pub(crate) fn regenerate_hooks_for_exe(
    base_dir: &Path,
    stable_exe: &Path,
    verify: HookVerifier,
) -> Result<HookOutcome, std::io::Error> {
    let hooks_dir = base_dir.join("hooks");

    // #354: this path is always implicitly resolved (regenerate_hooks_with_verifier
    // has no caller-supplied "explicit source" concept — it's the shim's own
    // silent self-healing path). Reject dev-build artifacts before even probing
    // the contract: a fresh `cargo build` binary can be fully contract-compliant
    // today and still be the wrong thing to pin, since `target/debug`/`target/release`
    // gets overwritten or removed by the next build.
    if is_dev_build_path(stable_exe) {
        eprintln!(
            "omamori warning: resolved exe {} {DEV_BUILD_PATH_DESCRIPTION}; hooks not regenerated. Run: omamori install --hooks --source <stable-path> if this is intentional",
            stable_exe.display()
        );
        return Ok(HookOutcome::KeptExisting(HookKeptReason::NonDeploymentPath));
    }

    // #349: a resolved path that exists is not necessarily a working omamori
    // binary (e.g. a stale dev build from a `cargo build` mid-session). Verify
    // the hook-check contract actually works before persisting the path —
    // otherwise the hook silently repoints to a binary that fails at hook-run
    // time, fail-closing every subsequent Bash call.
    match verify(stable_exe, HOOK_CONTRACT_TIMEOUT) {
        HookContractStatus::Ok => {}
        status => {
            eprintln!(
                "omamori warning: resolved exe {} failed hook-check contract verification ({status:?}); hooks not regenerated. Run: omamori install --hooks",
                stable_exe.display()
            );
            return Ok(HookOutcome::KeptExisting(
                HookKeptReason::VerificationFailed(status),
            ));
        }
    }

    fs::create_dir_all(&hooks_dir)?;

    let script_path = hooks_dir.join("claude-pretooluse.sh");
    atomic_write_script(&script_path, &render_hook_script(stable_exe))?;

    let snippet_path = hooks_dir.join("claude-settings.snippet.json");
    atomic_write(&snippet_path, &render_settings_snippet(&script_path))?;

    // Cursor hooks
    let cursor_path = hooks_dir.join("cursor-hooks.snippet.json");
    atomic_write(&cursor_path, &render_cursor_hooks_snippet(stable_exe))?;

    // Codex hooks: regenerate wrapper + re-merge hooks.json
    let codex_wrapper = hooks_dir.join("codex-pretooluse.sh");
    if codex_wrapper.exists() {
        atomic_write_script(&codex_wrapper, &render_codex_pretooluse_script(stable_exe))?;
        if let Some(codex_dir) = codex_home_dir()
            && is_real_directory(&codex_dir)
        {
            let _ = merge_codex_hooks(&codex_dir, &codex_wrapper);
        }
    }

    Ok(HookOutcome::Written)
}

pub fn render_hook_script(omamori_exe: &Path) -> String {
    let exe_str = omamori_exe.display().to_string();
    let quoted = shell_words::quote(&exe_str);
    format!(
        r#"#!/bin/sh
# omamori hook v{version} — Claude Code fail-close wrapper
# Claude Code: exit 0 = allow, exit 2 = block, exit 1 = allow (fail-open!)
# This wrapper maps all non-zero exits to exit 2 for fail-close safety.
# exit 0 = allow, exit 2 = block(all reasons), other = infra failure (hint below).
set -u
cat | {exe} hook-check --provider claude-code
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
  exit 0
elif [ "$STATUS" -eq 2 ]; then
  exit 2
else
  echo "omamori: hook binary did not respond as expected — this is not a decision about your command." >&2
  echo "AI agent: do not retry this yourself. Tell the user to run this in a plain terminal (not via an AI agent):" >&2
  echo "  omamori install --hooks" >&2
  exit 2
fi
"#,
        version = env!("CARGO_PKG_VERSION"),
        exe = quoted,
    )
}

/// Outcome of probing whether an exe is a genuine, contract-compatible
/// omamori binary (#349). Distinguishes failure modes so callers can produce
/// useful diagnostics instead of a bare pass/fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookContractStatus {
    Ok,
    NotFound,
    PermissionDenied,
    ExitNonZero(i32),
    Timeout,
    SpawnError(String),
}

/// Signature shared by `verify_hook_contract` and its test doubles. Spelled
/// out once here rather than at each of its 4 call sites (`InstallOptions`,
/// `regenerate_hooks_with_verifier`, `ensure_hooks_current_at_with_verifier_and_exe`,
/// `check_claude_settings_integration_with_verifier`) so a signature change
/// is a one-site edit.
pub(crate) type HookVerifier = fn(&Path, Duration) -> HookContractStatus;

/// Stdin payload for the hook-check contract probe. Identical to the
/// guaranteed-ALLOW fixture used in `tests/cli.rs` (`pretooluse_bash_json`) —
/// reusing a real, test-verified payload avoids the false-fail risk of a
/// hand-rolled minimal payload (an empty/malformed payload can fail-close
/// even a correct binary).
const HOOK_CONTRACT_PROBE_PAYLOAD: &str =
    r#"{"tool_name":"Bash","tool_input":{"command":"ls /tmp"}}"#;

/// `hook-check` runs in well under 100ms normally; 2s leaves headroom for
/// cold-start/disk I/O without letting a hung probe stall the caller long.
pub(crate) const HOOK_CONTRACT_TIMEOUT: Duration = Duration::from_secs(2);

/// Best-effort random suffix for the probe's isolated HOME directory name
/// (defense in depth against path prediction — see `verify_hook_contract`).
/// Reuses `atomic_file`'s CSPRNG generator on unix; falls back to a fixed
/// suffix elsewhere rather than failing (the PID component still keeps the
/// path different per-process, and the config-permission/ownership checks
/// are the primary defense regardless).
#[cfg(unix)]
fn random_isolation_suffix() -> String {
    crate::atomic_file::random_hex_suffix().unwrap_or_default()
}

#[cfg(not(unix))]
fn random_isolation_suffix() -> String {
    String::new()
}

/// Verify that `exe` is a genuine, contract-compatible omamori binary by
/// actually invoking its hook-check contract with a known-benign payload.
/// A binary that merely exists and runs is not enough — an older/incompatible
/// binary can still accept `--version` while rejecting the `--provider` flag
/// the hook wrapper depends on, so the probe must exercise the real contract.
///
/// Spawns `exe` directly (never via shim, to avoid re-entrant regeneration).
/// No stdout/stderr pipes are opened, so there is nothing to drain and no
/// pipe-deadlock risk; timeout is enforced via `try_wait` polling + kill + reap.
pub(crate) fn verify_hook_contract(exe: &Path, timeout: Duration) -> HookContractStatus {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    // `hook-check` loads the real user's config and matches the probe command
    // against their live rules — a rule that happens to block `ls`/`/tmp`
    // would fail-close a perfectly good binary and misreport it as broken.
    // Point HOME/XDG_CONFIG_HOME at an isolated, nonexistent directory so
    // config loading falls back to built-in defaults (which allow this
    // fixture — it's the same payload `tests/cli.rs` asserts ALLOW for)
    // regardless of the real user's rules. This also keeps the probe from
    // writing audit-log entries into the user's real `~/.omamori`.
    //
    // A random suffix (reusing atomic_file's existing generator) is layered
    // on top of the PID so the path isn't purely predictable — defense in
    // depth against another same-user process pre-seeding a hostile config
    // at this path, on top of the config-permission/ownership checks that
    // already close that class of attack (see SECURITY.md).
    let isolated_home = std::env::temp_dir().join(format!(
        "omamori-hook-verify-home-{}-{}",
        std::process::id(),
        random_isolation_suffix()
    ));

    let mut cmd = Command::new(exe);
    cmd.args(["hook-check", "--provider", "claude-code"])
        .env("HOME", &isolated_home)
        .env("XDG_CONFIG_HOME", isolated_home.join(".config"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return match e.kind() {
                std::io::ErrorKind::NotFound => HookContractStatus::NotFound,
                std::io::ErrorKind::PermissionDenied => HookContractStatus::PermissionDenied,
                _ => HookContractStatus::SpawnError(e.to_string()),
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(HOOK_CONTRACT_PROBE_PAYLOAD.as_bytes());
        // stdin dropped here, closing the pipe so the child sees EOF.
    }

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return match status.code() {
                    Some(0) => HookContractStatus::Ok,
                    Some(code) => HookContractStatus::ExitNonZero(code),
                    None => HookContractStatus::ExitNonZero(-1), // terminated by signal
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait(); // reap
                return HookContractStatus::Timeout;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return HookContractStatus::SpawnError(format!("wait failed: {e}")),
        }
    }
}

/// Resolve the current omamori binary to a stable path.
///
/// Used by `regenerate_hooks()`, integrity checks, and shim verification
/// to ensure identical exe path resolution across generation and verification.
pub fn resolved_current_omamori_exe() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(resolve_stable_exe_path(&exe))
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

/// Resolve a shim symlink to the real omamori executable.
/// Returns `None` for non-shim paths or if resolution fails.
///
/// Pattern: `*/shim/<command>` where the symlink target's basename is `omamori`.
/// Uses `read_link` for symlinks, `canonicalize` fallback for non-symlink shims.
fn shim_to_real_exe(exe: &Path) -> Option<PathBuf> {
    let parent = exe.parent()?;
    if parent.file_name()?.to_str()? != "shim" {
        return None;
    }

    if let Ok(target) = fs::read_link(exe) {
        let resolved = if target.is_relative() {
            parent.join(&target)
        } else {
            target
        };
        let canonical = resolved.canonicalize().ok()?;
        if canonical.file_name()?.to_str()? != "omamori" {
            return None;
        }
        return Some(resolved);
    }

    let canonical = exe.canonicalize().ok()?;
    (canonical.file_name()?.to_str()? == "omamori").then_some(canonical)
}

/// Resolve a stable executable path for generated config files.
///
/// Handles two resolution layers:
/// 1. Shim paths (`~/.omamori/shim/<cmd>`) — follow symlink to real binary (#333/#315)
/// 2. Cellar paths (`/opt/homebrew/Cellar/...`) — convert to stable link (#42/#56)
///
/// The `exists()` check has a TOCTOU window; this is acceptable because the worst case
/// is writing a Cellar path — the same as pre-fix behavior, caught by `omamori status`.
pub(crate) fn resolve_stable_exe_path(exe: &Path) -> PathBuf {
    let resolved = shim_to_real_exe(exe).unwrap_or_else(|| exe.to_path_buf());

    if let Some(stable) = cellar_to_stable_path(&resolved) {
        if stable.exists() {
            return stable;
        }
        eprintln!(
            "omamori warning: Cellar path detected but stable path {} does not exist; \
             using versioned path (may break after brew upgrade)",
            stable.display()
        );
    }
    resolved
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

/// Resolves `$HOME`. Returns `None` when unset or empty — callers MUST
/// treat this as "not detected" and never fall back to a CWD-relative path
/// (#210: a `.` fallback here previously let test runs merge dead hook
/// paths into whatever `./.claude`/`./.codex` happened to exist in the
/// current working directory).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Default Claude Code config directory (`~/.claude`). See `home_dir` for
/// the `None` contract.
pub(crate) fn claude_home_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".claude"))
}

/// In-place merge of omamori's PreToolUse hook entry into
/// `~/.claude/settings.json`.
///
/// Identification uses `x-omamori-version` tag (primary, root-independent)
/// OR path-based `entry_is_omamori_managed` (secondary, for pre-v0.9.7
/// untagged entries). This union approach detects ALL omamori entries
/// regardless of which install root created them.
///
/// Behavior:
/// - File missing → create with omamori entry only (`Created`).
/// - File is symlink / not a regular file → `Skipped`.
/// - Invalid JSON → `Skipped` with the parse error message.
/// - Pass 1: `retain()` removes all omamori-only entries (via
///   `is_safe_to_remove`), keeping at most one that matches the new
///   canonical entry.
/// - Pass 2: surgical extraction of omamori inner hooks from hybrid
///   entries (user + omamori hooks coexisting). After extraction, the
///   `x-omamori-version` tag is stripped so the remaining user-only
///   entry is not misidentified on subsequent runs.
/// - Outcome priority: `MatcherMigrated` > `StaleEntriesCleaned` > `Merged`.
/// - `AlreadyPresent` when canonical entry already exists and no stale
///   entries were cleaned.
///
/// All writes use `atomic_write` (0o600, SEC-3).
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
        atomic_write(&settings_path, &serde_json::to_string_pretty(&doc).unwrap())?;
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

    let install_root = script_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));

    // --- Pass 1: remove stale non-hybrid omamori entries ---
    // Keep the first entry that exactly matches the new canonical entry (if any).
    // Remove all other omamori-managed entries that are safe to remove.
    let before_len = arr.len();
    let mut had_legacy_matcher = false;
    let mut kept_canonical = false;
    arr.retain(|e| {
        if !is_omamori_entry_any_root(e, &install_root) || !is_safe_to_remove(e) {
            return true; // not omamori or hybrid → keep
        }
        // This is an omamori non-hybrid entry. Keep exactly one if it matches
        // the canonical entry we're about to insert.
        if !kept_canonical && *e == entry {
            kept_canonical = true;
            return true; // keep the first canonical match
        }
        if e.get("matcher")
            .and_then(|m| m.as_str())
            .map(is_legacy_matcher)
            .unwrap_or(false)
        {
            had_legacy_matcher = true;
        }
        false // remove this stale entry
    });
    let pass1_removed = before_len - arr.len();

    // --- Pass 2: surgical extraction from hybrid entries ---
    // For hybrid entries (omamori-managed but not safe to remove as a whole),
    // remove only the inner hook(s) that match the omamori script path suffix.
    // After extraction, strip the x-omamori-version tag so the remaining
    // user-only entry is not misidentified as omamori-managed on future runs.
    let mut pass2_removed: usize = 0;
    for e in arr.iter_mut() {
        if !is_omamori_entry_any_root(e, &install_root) {
            continue;
        }
        if is_safe_to_remove(e) {
            continue; // non-hybrid entries already handled in Pass 1
        }
        if let Some(hooks_arr) = e.get_mut("hooks").and_then(|v| v.as_array_mut()) {
            let h_before = hooks_arr.len();
            hooks_arr.retain(|h| {
                let cmd = h.get("command").and_then(|v| v.as_str());
                let is_omamori_inner = cmd
                    .map(|c| {
                        let unquoted = c.trim_matches('\'').trim_matches('"');
                        is_omamori_hook_path(Path::new(unquoted))
                    })
                    .unwrap_or(false);
                !is_omamori_inner
            });
            let extracted = h_before - hooks_arr.len();
            if extracted > 0 {
                // Strip the tag so remaining user hooks are not misidentified
                if let Some(obj) = e.as_object_mut() {
                    obj.remove("x-omamori-version");
                }
            }
            pass2_removed += extracted;
        }
    }

    let stale_count = pass1_removed + pass2_removed;

    if kept_canonical {
        // Canonical entry was already present and kept. Any stale siblings removed.
        if stale_count > 0 {
            atomic_write(&settings_path, &serde_json::to_string_pretty(&doc).unwrap())?;
            return Ok(ClaudeSettingsOutcome::StaleEntriesCleaned(stale_count));
        }
        return Ok(ClaudeSettingsOutcome::AlreadyPresent);
    }

    // Canonical entry not present → push new
    arr.push(entry);
    atomic_write(&settings_path, &serde_json::to_string_pretty(&doc).unwrap())?;

    if had_legacy_matcher {
        return Ok(ClaudeSettingsOutcome::MatcherMigrated);
    }
    if stale_count > 0 {
        return Ok(ClaudeSettingsOutcome::StaleEntriesCleaned(stale_count));
    }
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

/// Returns true if `entry` carries the `x-omamori-version` tag.
/// Root-independent: catches all entries created since v0.9.7 (when
/// auto-merge was added), regardless of which install root was used.
pub(crate) fn has_omamori_version_tag(entry: &serde_json::Value) -> bool {
    entry.get("x-omamori-version").is_some()
}

/// Union identification: returns true if `entry` is an omamori-managed
/// PreToolUse entry from ANY install root.
///
/// Primary: `x-omamori-version` tag (root-independent, v0.9.7+).
/// Secondary: path-based `entry_is_omamori_managed` (for theoretical
/// pre-v0.9.7 untagged entries from the current `base_dir`).
pub(crate) fn is_omamori_entry_any_root(entry: &serde_json::Value, base_dir: &Path) -> bool {
    has_omamori_version_tag(entry) || entry_is_omamori_managed(entry, base_dir)
}

/// Structural safety check: returns true if the entry can be wholly removed
/// without destroying user hooks.
///
/// Safe when:
/// - `hooks` array has at most 1 element (no sibling user hooks), AND
/// - legacy flat `command` is not present alongside a non-empty `hooks` array
///   (no mixed legacy+nested user-merged shape).
pub(crate) fn is_safe_to_remove(entry: &serde_json::Value) -> bool {
    let hooks_size = entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let has_flat = entry.get("command").is_some();
    if hooks_size > 1 {
        return false;
    }
    if has_flat && hooks_size > 0 {
        return false;
    }
    true
}

/// Returns true if `path` looks like an omamori hook script.
/// Uses 2-component suffix match (`hooks/claude-pretooluse.sh`) to avoid
/// false positives on user scripts that happen to share the filename.
pub(crate) fn is_omamori_hook_path(path: &Path) -> bool {
    path.file_name().and_then(|f| f.to_str()) == Some("claude-pretooluse.sh")
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|d| d.to_str())
            == Some("hooks")
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

/// Default Codex CLI config directory (`~/.codex`). See `home_dir` for the
/// `None` contract.
fn codex_home_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".codex"))
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
# exit 0 = allow, exit 2 = block(all reasons), other = infra failure (hint below).
set -u
cat | {exe} hook-check --provider codex
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
  exit 0
elif [ "$STATUS" -eq 2 ]; then
  exit 2
else
  echo "omamori: hook binary did not respond as expected — this is not a decision about your command." >&2
  echo "AI agent: do not retry this yourself. Tell the user to run this in a plain terminal (not via an AI agent):" >&2
  echo "  omamori install --hooks" >&2
  exit 2
fi
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
    let Some(claude_dir) = claude_home_dir() else {
        return Ok(()); // HOME unset — nothing to clean up
    };
    let settings_path = claude_dir.join("settings.json");
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
        // Pass 1: drop all omamori entries (from any install root) that are
        // safe to remove (no sibling user hooks).
        let before = arr.len();
        arr.retain(|e| !(is_omamori_entry_any_root(e, base_dir) && is_safe_to_remove(e)));
        if arr.len() != before {
            modified = true;
        }

        // Pass 2: surgical cleanup of hybrid entries.
        // Uninstall requires BOTH base_dir prefix AND canonical filename to
        // avoid removing user hooks stored under base_dir (R4 regression)
        // or at paths like /project/hooks/claude-pretooluse.sh (R2 P1-1).
        for entry in arr.iter_mut() {
            if !is_omamori_entry_any_root(entry, base_dir) {
                continue;
            }
            if let Some(hooks_arr) = entry.get_mut("hooks").and_then(|v| v.as_array_mut()) {
                let h_before = hooks_arr.len();
                hooks_arr.retain(|h| {
                    let cmd = h.get("command").and_then(|v| v.as_str());
                    let is_omamori_inner = cmd
                        .map(|c| {
                            let unquoted = c.trim_matches('\'').trim_matches('"');
                            let p = Path::new(unquoted);
                            p.starts_with(base_dir) && is_omamori_hook_path(p)
                        })
                        .unwrap_or(false);
                    !is_omamori_inner
                });
                if hooks_arr.len() != h_before {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.remove("x-omamori-version");
                    }
                    modified = true;
                }
            }
        }
    }

    if modified {
        atomic_write(&settings_path, &serde_json::to_string_pretty(&doc).unwrap())?;
    }
    Ok(())
}

/// Remove omamori's entry from `~/.codex/hooks.json` during uninstall.
///
/// Symlinks and non-regular files are skipped silently — same policy as
/// `remove_claude_settings_entry` (#357). Without this guard, a hooks.json
/// that is a symlink to a real file would be read through (following the
/// link), then `atomic_write`'s rename would replace the symlink *entry*
/// itself with a plain file — destroying the symlink and leaving the real
/// target file untouched but orphaned from `~/.codex/hooks.json` (see
/// `atomic_file` module docs on rename not following the destination link).
fn remove_codex_hooks_entry() -> Result<(), std::io::Error> {
    let Some(codex_dir) = codex_home_dir() else {
        return Ok(()); // HOME unset — nothing to clean up
    };
    let hooks_path = codex_dir.join("hooks.json");
    if !hooks_path.exists() {
        return Ok(());
    }
    if hooks_path.is_symlink() || !is_real_file(&hooks_path) {
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
    atomic_write(&backup_path, &raw)?;

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
    home_override: Option<PathBuf>,
) -> (
    Option<PathBuf>,
    Option<CodexHooksOutcome>,
    Option<CodexConfigOutcome>,
) {
    let codex_dir = match home_override
        .map(|h| h.join(".codex"))
        .or_else(codex_home_dir)
    {
        Some(dir) => dir,
        None => return (None, None, None), // HOME unset — Codex not detected
    };
    if !is_real_directory(&codex_dir) {
        return (None, None, None); // Codex not installed
    }

    let hooks_dir = base_dir.join("hooks");
    let wrapper_path = hooks_dir.join("codex-pretooluse.sh");

    // Step 1: wrapper script (must exist before hooks.json references it)
    if let Err(e) = atomic_write_script(&wrapper_path, &render_codex_pretooluse_script(source_exe))
    {
        eprintln!("omamori: warning — Codex wrapper: {e}");
        return (None, None, None);
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

    let Some(codex_dir) = codex_home_dir() else {
        return false; // HOME unset — Codex not detected
    };
    if !is_real_directory(&codex_dir) {
        return false; // Codex not detected — nothing to warn about
    }

    // Codex detected but hooks not set up — auto-configure
    let source_exe = match std::env::current_exe() {
        Ok(exe) => resolve_stable_exe_path(&exe),
        Err(_) => return false,
    };

    // #354: this is the same silent shim self-heal entry point as
    // `ensure_hooks_current` (both are called back-to-back from `run_shim`),
    // resolving `current_exe()` implicitly with no caller-supplied
    // provenance. Without this check, a dev-build binary would get pinned
    // into the Codex wrapper (`hooks/codex-pretooluse.sh`) the moment
    // `CODEX_CI` is detected — the exact persistence this ADR exists to
    // prevent, just for Codex instead of Claude/Cursor. Checked after the
    // Codex-presence checks above so the warning only fires when there's
    // actually a Codex install to configure.
    if is_dev_build_path(&source_exe) {
        eprintln!(
            "omamori warning: resolved exe {} {DEV_BUILD_PATH_DESCRIPTION}; Codex hooks not auto-configured. Run: omamori install --hooks --source <stable-path> if this is intentional",
            source_exe.display()
        );
        return false;
    }

    eprintln!("omamori: Codex CLI detected — auto-configuring hooks");

    let hooks_dir = base_dir.join("hooks");
    if fs::create_dir_all(&hooks_dir).is_err() {
        eprintln!("omamori: warning — could not create hooks directory");
        return false;
    }

    let (wrapper, hooks_out, config_out) = setup_codex_hooks(base_dir, &source_exe, None);

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

    // --- is_dev_build_path tests (#354) ---

    #[test]
    fn is_dev_build_path_matches_target_debug() {
        assert!(is_dev_build_path(Path::new(
            "/Users/x/project/target/debug/omamori"
        )));
    }

    #[test]
    fn is_dev_build_path_matches_target_release() {
        assert!(is_dev_build_path(Path::new(
            "/Users/x/project/target/release/omamori"
        )));
    }

    #[test]
    fn is_dev_build_path_matches_nested_target_debug_deps() {
        // The actual shape of a `cargo test` harness binary's own current_exe().
        assert!(is_dev_build_path(Path::new(
            "/Users/x/project/target/debug/deps/omamori-abc123"
        )));
    }

    #[test]
    fn is_dev_build_path_does_not_match_debugger_lookalike() {
        // V-018: substring match on "target/debug" would false-positive here.
        assert!(!is_dev_build_path(Path::new(
            "/Users/x/project/target/debugger/omamori"
        )));
    }

    #[test]
    fn is_dev_build_path_does_not_match_stable_install() {
        assert!(!is_dev_build_path(Path::new("/opt/homebrew/bin/omamori")));
        assert!(!is_dev_build_path(Path::new("/Users/x/.cargo/bin/omamori")));
        assert!(!is_dev_build_path(Path::new("/Users/x/.omamori/shim/git")));
    }

    #[test]
    fn is_dev_build_path_does_not_match_unrelated_target_dir() {
        // A "target" directory not followed by debug/release must not match.
        assert!(!is_dev_build_path(Path::new(
            "/Users/x/target/config/omamori"
        )));
    }

    #[test]
    fn is_dev_build_path_matches_relative_target_debug() {
        // No leading "/" — a relative path is a real shape `current_exe()`
        // resolution can hand back (e.g. under some container/CI setups).
        assert!(is_dev_build_path(Path::new("target/debug/omamori")));
        assert!(is_dev_build_path(Path::new("./target/debug/omamori")));
    }

    #[test]
    fn is_dev_build_path_does_not_match_hidden_dot_target() {
        // #354 test-adversarial review: a hidden `.target` directory (as
        // used by some `CARGO_TARGET_DIR` conventions) is a known, accepted
        // evasion of the path-component check (documented in ADR-0004's
        // Consequences) — pinned here so a future edit doesn't "fix" this
        // boundary by accident and break the documented CARGO_TARGET_DIR
        // limitation's own reasoning.
        assert!(!is_dev_build_path(Path::new("/x/.target/debug/omamori")));
    }

    #[test]
    fn is_dev_build_path_matches_cross_compile_target_triple() {
        // Security review (Phase 8): `cargo build --target <triple>` produces
        // `target/<triple>/debug|release/...` — a standard, undocumented-limitation
        // Cargo layout the original adjacency-only check missed entirely.
        assert!(is_dev_build_path(Path::new(
            "/x/project/target/x86_64-apple-darwin/debug/omamori"
        )));
        assert!(is_dev_build_path(Path::new(
            "/x/project/target/aarch64-unknown-linux-gnu/release/omamori"
        )));
    }

    #[test]
    fn is_dev_build_path_three_component_window_is_component_exact() {
        // Components with a suffix/prefix ("target-notes", "debug-log") are
        // not the exact literal "target"/"debug"/"release", so the 3-component
        // window (added for the cross-compile triple case) does not loosen
        // the existing component-exact-match guarantee.
        assert!(!is_dev_build_path(Path::new(
            "/x/target-notes/staging/debug-log/omamori"
        )));

        // Accepted tradeoff, pinned deliberately: a literal `target/<anything>/release`
        // shape DOES match even when the middle component isn't a real Rust
        // target triple — the 3-component window can't distinguish "some
        // arbitrary directory happens to sit between target/ and release/"
        // from Cargo's own `target/<triple>/release/` layout. Narrower than
        // an open-ended substring/anywhere-later match (see the unrelated-
        // two-component test above), and a false positive here only means a
        // legitimate stable install gets asked to pass --source explicitly —
        // safety guard, not a security boundary (ADR-0004 Consequences).
        assert!(is_dev_build_path(Path::new(
            "/x/target/staging/release/omamori"
        )));
    }

    // --- regenerate_hooks_for_exe dev-build rejection (#354) ---

    #[test]
    fn regenerate_hooks_for_exe_rejects_dev_build_path() {
        let root =
            std::env::temp_dir().join(format!("omamori-regen-devbuild-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let dev_exe = Path::new("/Users/x/project/target/debug/omamori");
        let outcome = regenerate_hooks_for_exe(&root, dev_exe, |_, _| {
            panic!("verifier must not be called when the path is rejected as a dev build")
        })
        .unwrap();
        assert_eq!(
            outcome,
            HookOutcome::KeptExisting(HookKeptReason::NonDeploymentPath)
        );
        assert!(
            !root.join("hooks/claude-pretooluse.sh").exists(),
            "no hook script should be written for a rejected dev-build path"
        );

        let _ = fs::remove_dir_all(root);
    }

    // --- SourceExe (#378) ---

    #[test]
    fn source_exe_default_is_implicit() {
        // V-002: `InstallOptions` derives `Default`. `run_install_repair`
        // (cli/doctor.rs) now sets `source` explicitly, but any future
        // construction site that instead relies on `..Default::default()`
        // to fill in `source` must not silently get `Explicit` — that would
        // bypass the dev-build gate, a fail-open regression. Pin the exact
        // variant, not just `is_explicit()`, so a mutation that swaps the
        // variant but happens to also flip `is_explicit()`'s logic can't
        // slip through.
        assert_eq!(
            SourceExe::default(),
            SourceExe::Implicit(PathBuf::new()),
            "SourceExe::default() must be Implicit — Explicit would bypass the dev-build gate by default"
        );
        assert!(!SourceExe::default().is_explicit());
    }

    #[test]
    fn source_exe_path_and_is_explicit() {
        // Distinct paths per variant so a constant-return or swapped-arm bug
        // in the `Implicit(p) | Explicit(p) => p` binding can't slip through.
        let implicit_p = PathBuf::from("/opt/homebrew/bin/omamori");
        let explicit_p = PathBuf::from("/Users/dev/project/target/release/omamori");
        assert_eq!(SourceExe::Implicit(implicit_p.clone()).path(), implicit_p);
        assert_eq!(SourceExe::Explicit(explicit_p.clone()).path(), explicit_p);
        assert!(!SourceExe::Implicit(implicit_p).is_explicit());
        assert!(SourceExe::Explicit(explicit_p).is_explicit());
    }

    // --- install() dev-build rejection (#354) ---

    #[test]
    #[serial_test::serial(home_env)]
    fn install_rejects_implicit_dev_build_source() {
        let root =
            std::env::temp_dir().join(format!("omamori-install-devbuild-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::create_dir_all(root.join(".codex")).unwrap();

        let dev_exe = PathBuf::from("/Users/x/project/target/release/omamori");
        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Implicit(dev_exe.clone()),
            generate_hooks: true,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| {
                panic!("verifier must not be called when the path is rejected as a dev build")
            }),
        });

        let err = result.expect_err("install must reject an implicit dev-build source_exe");
        let message = err.to_string();
        assert!(
            message.contains("cargo build artifact"),
            "message should explain the rejection: {message}"
        );
        assert!(
            message.contains("Layer 1 (PATH shims) was still updated"),
            "message should state that shim repair was not blocked: {message}"
        );
        assert!(
            message.contains("--source"),
            "message should point at the explicit-source escape hatch: {message}"
        );
        // `.exists()` follows symlinks and would report `false` here since
        // the fake dev_exe target doesn't actually exist on disk — check the
        // symlink itself was created, not whether its (synthetic) target resolves.
        assert!(
            fs::symlink_metadata(root.join("shim").join("rm")).is_ok(),
            "shim must still be linked even when the hook-artifact write is rejected"
        );
        assert!(
            !root.join("hooks").join("claude-pretooluse.sh").exists(),
            "hook script must not be created for a rejected dev-build path"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn install_accepts_explicit_dev_build_source() {
        let root = std::env::temp_dir().join(format!(
            "omamori-install-devbuild-explicit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::create_dir_all(root.join(".codex")).unwrap();

        // Same dev-build-shaped path as the rejection test above, but this
        // time the caller explicitly named it — the documented recovery path
        // (e.g. developing omamori itself) must not be blocked.
        let dev_exe = PathBuf::from("/Users/x/project/target/release/omamori");
        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Explicit(dev_exe.clone()),
            generate_hooks: true,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| HookContractStatus::Ok),
        });

        result.expect("install must accept an explicit dev-build source_exe");
        assert!(
            root.join("hooks").join("claude-pretooluse.sh").exists(),
            "hook script must be created when the dev-build path was explicitly named"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn install_accepts_explicit_stable_source() {
        // Truth-table quadrant 4/4 (#378): explicit + non-dev-build path. The
        // dev-build gate's `!is_explicit()` short-circuit means this was
        // always accepted, but no test constructed this exact combination —
        // add it so all four `(is_explicit, is_dev_build_path)` quadrants are
        // pinned against `SourceExe` regressions, not just the two that
        // involve a dev-build-shaped path.
        let root = std::env::temp_dir().join(format!(
            "omamori-install-explicit-stable-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::create_dir_all(root.join(".codex")).unwrap();

        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Explicit(source.clone()),
            generate_hooks: true,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| HookContractStatus::Ok),
        });

        result.expect("install must accept an explicit non-dev-build source_exe");
        assert!(root.join("hooks").join("claude-pretooluse.sh").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn install_creates_shims_and_hook_templates() {
        let root = std::env::temp_dir().join(format!("omamori-install-{}", std::process::id()));
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();

        // #210: home_override pins the merge targets to a throwaway temp dir
        // instead of resolving the real $HOME. Without this, this in-process
        // test would merge dead hook paths into the developer's real
        // ~/.claude/settings.json and ~/.codex/hooks.json.
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::create_dir_all(root.join(".codex")).unwrap();

        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Implicit(source.clone()),
            generate_hooks: true,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| HookContractStatus::Ok),
        })
        .unwrap();

        assert!(result.shim_dir.join("rm").exists());
        let hook_script = result.hook_script.unwrap();
        assert!(hook_script.exists());
        assert!(result.settings_snippet.unwrap().exists());
        assert!(
            root.join(".claude/settings.json").exists(),
            "merge should target the injected home_override, not the real $HOME"
        );
        assert!(
            root.join(".codex/hooks.json").exists(),
            "merge should target the injected home_override, not the real $HOME"
        );

        // #307 PR2: hook scripts are written via `atomic_write_script` (mode set at
        // creation), replacing the old rename-then-`chmod(0o755)` dance. Assert the
        // resulting mode directly rather than only `.exists()` — a regression here
        // would silently disable Layer 2 (non-executable hook script).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&hook_script).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "hook script must be executable (0o755)");
        }

        let _ = fs::remove_dir_all(root);
    }

    const TEST_EXE: &str = "/usr/local/bin/omamori";

    #[test]
    fn hook_script_is_thin_wrapper() {
        let script = render_hook_script(Path::new(TEST_EXE));
        assert!(
            script.contains(&format!("| {TEST_EXE} hook-check --provider claude-code")),
            "hook script must pipe stdin through absolute exe path + hook-check"
        );
        assert!(
            !script.contains("| omamori hook-check"),
            "hook script must use absolute path, not bare omamori"
        );
        assert!(
            !script.contains("case \"$INPUT\""),
            "hook script should not contain case statements (now a thin wrapper)"
        );
    }

    #[test]
    fn hook_script_quotes_path_with_spaces() {
        let exe = "/Users/my user/bin/omamori";
        let script = render_hook_script(Path::new(exe));
        // shell_words::quote wraps entire path in single quotes
        assert!(
            script.contains(&format!("| '{exe}' hook-check --provider claude-code")),
            "path with spaces must be single-quoted in the pipe command"
        );
    }

    #[test]
    fn hook_script_quotes_path_with_apostrophe() {
        let exe = "/Users/o'brien/bin/omamori";
        let script = render_hook_script(Path::new(exe));
        assert!(
            script.contains("hook-check --provider claude-code"),
            "hook script must contain hook-check invocation"
        );
        let quoted = shell_words::quote(exe);
        assert!(
            script.contains(&*quoted),
            "path with apostrophe must be shell-safe: {quoted}"
        );
    }

    #[test]
    fn hook_script_quotes_path_with_dollar() {
        let exe = "/tmp/$HOME/bin/omamori";
        let script = render_hook_script(Path::new(exe));
        assert!(
            script.contains("hook-check --provider claude-code"),
            "hook script must contain hook-check invocation"
        );
        assert!(
            !script.contains("| /tmp/$HOME/bin/omamori"),
            "path with $ must be quoted to prevent shell expansion"
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

    #[test]
    fn protected_env_vars_constant_covers_all_detectors() {
        // Verify PROTECTED_ENV_VARS covers all expected detector variables.
        // Env var tampering detection is handled by Phase 1B (token-level)
        // in hook.rs.
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
        let script = render_hook_script(Path::new(TEST_EXE));
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            script.contains(&format!("# omamori hook v{version}")),
            "hook script should contain version comment"
        );
    }

    #[test]
    fn parse_hook_version_extracts_version() {
        let script = render_hook_script(Path::new(TEST_EXE));
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

        // Uses the exe-injectable DI seam, not the public `regenerate_hooks()`:
        // the test binary's own `current_exe()` is never a genuine omamori
        // binary (the production verifier would always reject it, #349) and
        // is itself always a `target/debug`/`target/release` path under
        // `cargo test`, which would trip the #354 dev-build check below
        // before this test gets to what it's actually checking.
        let fake_exe = root.join("omamori");
        fs::write(&fake_exe, "binary").unwrap();
        let outcome =
            regenerate_hooks_for_exe(&root, &fake_exe, |_, _| HookContractStatus::Ok).unwrap();
        assert_eq!(outcome, HookOutcome::Written);

        let hook_path = root.join("hooks/claude-pretooluse.sh");
        assert!(hook_path.exists(), "hook script should be created");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&hook_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o755,
                "regenerated hook script must be executable (0o755)"
            );
        }

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
    fn regenerate_hooks_keeps_existing_hook_on_verification_failure() {
        let root =
            std::env::temp_dir().join(format!("omamori-regen-verifyfail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let hooks_dir = root.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hook_path = hooks_dir.join("claude-pretooluse.sh");
        let existing_content = "#!/bin/sh\n# omamori hook v0.0.1 (pre-existing)\nexit 0\n";
        fs::write(&hook_path, existing_content).unwrap();

        // See `regenerate_hooks_creates_files` for why this uses the
        // exe-injectable seam rather than a `target/debug` test-binary path.
        let fake_exe = root.join("omamori");
        fs::write(&fake_exe, "binary").unwrap();
        let result =
            regenerate_hooks_for_exe(&root, &fake_exe, |_, _| HookContractStatus::ExitNonZero(1));
        assert_eq!(
            result.unwrap(),
            HookOutcome::KeptExisting(HookKeptReason::VerificationFailed(
                HookContractStatus::ExitNonZero(1)
            )),
            "verification failure must be reported as KeptExisting with the specific reason, not surfaced as an Err, from the background self-repair path"
        );

        let content_after = fs::read_to_string(&hook_path).unwrap();
        assert_eq!(
            content_after, existing_content,
            "existing hook must be left untouched when the resolved exe fails verification"
        );

        let _ = fs::remove_dir_all(root);
    }

    // --- verify_hook_contract tests (#349) ---

    #[test]
    fn verify_hook_contract_ok_on_exit_zero() {
        // `/usr/bin/true` ignores stdin/args and always exits 0 — this tests
        // the exit-code-0 -> Ok mapping without needing a real omamori binary.
        let status = verify_hook_contract(Path::new("/usr/bin/true"), Duration::from_secs(2));
        assert_eq!(status, HookContractStatus::Ok);
    }

    #[test]
    fn verify_hook_contract_exit_nonzero_on_exit_one() {
        // `/usr/bin/false` ignores stdin/args and always exits 1.
        let status = verify_hook_contract(Path::new("/usr/bin/false"), Duration::from_secs(2));
        assert_eq!(status, HookContractStatus::ExitNonZero(1));
    }

    #[test]
    fn verify_hook_contract_not_found_for_missing_path() {
        let status = verify_hook_contract(
            Path::new("/nonexistent/omamori-does-not-exist"),
            Duration::from_secs(2),
        );
        assert_eq!(status, HookContractStatus::NotFound);
    }

    #[test]
    #[cfg(unix)]
    fn verify_hook_contract_permission_denied_for_non_executable() {
        let path =
            std::env::temp_dir().join(format!("omamori-verify-noexec-{}", std::process::id()));
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let status = verify_hook_contract(&path, Duration::from_secs(2));
        assert_eq!(status, HookContractStatus::PermissionDenied);

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn verify_hook_contract_rejects_binary_reproducing_the_reported_349_symptom() {
        // #349 Codex Round 3 test review: the other verify_hook_contract
        // tests only prove the exit-code mapping works against a generic
        // exit-0/exit-1 binary — they don't prove the *actual reported bug*
        // is caught. This fixture reproduces it directly: an "old/dev-build"
        // binary that doesn't understand `--provider` and errors out the way
        // the original issue reported (`Unrecognized option: 'provider'`).
        let path =
            std::env::temp_dir().join(format!("omamori-verify-oldbinary-{}", std::process::id()));
        fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\necho \"Unrecognized option: 'provider'\" >&2\nexit 2\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let status = verify_hook_contract(&path, Duration::from_secs(2));
        assert_eq!(
            status,
            HookContractStatus::ExitNonZero(2),
            "a binary reproducing the exact reported #349 symptom must fail verification"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn verify_hook_contract_times_out_on_hung_binary() {
        let path = std::env::temp_dir().join(format!("omamori-verify-hang-{}", std::process::id()));
        fs::write(&path, "#!/bin/sh\nsleep 5\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let start = std::time::Instant::now();
        let status = verify_hook_contract(&path, Duration::from_millis(100));
        assert_eq!(status, HookContractStatus::Timeout);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout must not wait for the full sleep duration"
        );

        let _ = fs::remove_file(&path);
    }

    // Note: a test exercising `verify_hook_contract` against a hostile real
    // user config (#349 Codex Round 1 P0) needs a genuine, working omamori
    // binary to spawn — `std::env::current_exe()` inside a `--lib` unit test
    // resolves to the test harness, not the CLI. See
    // `tests/cli.rs::install_hooks_ignores_hostile_user_config_during_verification`,
    // which uses `env!("CARGO_BIN_EXE_omamori")` (only available to
    // integration tests) to cover this.

    #[test]
    #[cfg(unix)]
    fn verify_hook_contract_invokes_exe_directly_once() {
        // Regression guard for #349 V-005: the probe must invoke the resolved
        // path directly as argv0 (Command::new never shells out), not via a
        // shell wrapper — direct exec means there is no indirection through
        // which the omamori shim's own regeneration logic could re-enter.
        let dir =
            std::env::temp_dir().join(format!("omamori-verify-direct-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.sh");
        let marker = dir.join("invoked");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\ncat >/dev/null\necho x >> \"{}\"\nexit 0\n",
                marker.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let status = verify_hook_contract(&path, Duration::from_secs(2));
        assert_eq!(status, HookContractStatus::Ok);
        let invocations = fs::read_to_string(&marker).unwrap_or_default();
        assert_eq!(
            invocations.lines().count(),
            1,
            "probe script must be invoked exactly once, not recursively"
        );

        let _ = fs::remove_dir_all(&dir);
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

    // `tempfile_in`/`tempfile_in_with_mode`/`AtomicTempFile` were removed in
    // #307 PR2 (migrated onto `atomic_file::atomic_write_with_mode`). Coverage
    // moved to `atomic_file`'s own test suite: uniqueness/exclusivity of the
    // actual production suffix generator is `random_hex_suffix_produces_distinct_16_char_hex_strings`;
    // collision-retry logic (injecting a mock suffix generator to force
    // deterministic collisions) is `write_via_temp_retries_past_a_colliding_suffix`
    // / `write_via_temp_fails_closed_when_every_suffix_collides`.

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
        let script1 = render_hook_script(Path::new(TEST_EXE));
        let script2 = render_hook_script(Path::new(TEST_EXE));
        let hash1 = hook_content_hash(&script1);
        let hash2 = hook_content_hash(&script2);
        assert_eq!(hash1, hash2, "render_hook_script() should be deterministic");
    }

    #[test]
    fn t2_attack_version_preserved_content_changed_hash_differs() {
        let original = render_hook_script(Path::new(TEST_EXE));
        let original_hash = hook_content_hash(&original);

        // Simulate T2 attack: keep version comment but bypass hook-check
        let tampered = original.replace("hook-check", "true");
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

    // --- Shim path resolution tests (#333, #315) ---

    #[test]
    fn shim_to_real_exe_non_shim_returns_none() {
        assert!(shim_to_real_exe(Path::new("/usr/local/bin/omamori")).is_none());
        assert!(shim_to_real_exe(Path::new("/Users/dev/.cargo/bin/omamori")).is_none());
    }

    #[test]
    fn shim_to_real_exe_with_symlink() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let real_bin = dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real_bin, shim_dir.join("git")).unwrap();
            let result = shim_to_real_exe(&shim_dir.join("git"));
            assert!(result.is_some(), "should resolve shim symlink");
            let resolved = result.unwrap();
            assert_eq!(resolved, real_bin, "must return exact symlink target path");
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_stable_exe_path_of_shim_pointing_at_dev_build_is_flagged() {
        // #354 test-adversarial review: the composed chain that actually
        // matters end-to-end — a shim symlink resolving through to a
        // `target/debug`/`target/release` binary must be recognized by
        // `is_dev_build_path` on the *resolved* path, not just on a raw
        // synthetic path handed directly to the predicate.
        let dir =
            std::env::temp_dir().join(format!("omamori-shim-devbuild-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let target_debug = dir.join("target").join("debug");
        fs::create_dir_all(&target_debug).unwrap();
        let dev_bin = target_debug.join("omamori");
        fs::write(&dev_bin, "binary").unwrap();

        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();
        let shim_path = shim_dir.join("git");
        std::os::unix::fs::symlink(&dev_bin, &shim_path).unwrap();

        let resolved = resolve_stable_exe_path(&shim_path);
        assert_eq!(
            resolved, dev_bin,
            "shim should resolve to the dev-build binary"
        );
        assert!(
            is_dev_build_path(&resolved),
            "resolved shim target must be flagged as a dev-build path: {}",
            resolved.display()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn shim_to_real_exe_rejects_non_omamori_target() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-reject-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let evil_bin = dir.join("evil");
        fs::write(&evil_bin, "binary").unwrap();
        std::os::unix::fs::symlink(&evil_bin, shim_dir.join("git")).unwrap();

        assert!(
            shim_to_real_exe(&shim_dir.join("git")).is_none(),
            "must reject shim pointing to non-omamori binary"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn shim_to_real_resolves_nested_homebrew_symlinks() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-nested-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let cellar_dir = dir.join("Cellar/omamori/1.0/bin");
        fs::create_dir_all(&cellar_dir).unwrap();
        fs::write(cellar_dir.join("omamori"), "binary").unwrap();

        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        std::os::unix::fs::symlink(cellar_dir.join("omamori"), bin_dir.join("omamori")).unwrap();

        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();
        std::os::unix::fs::symlink(bin_dir.join("omamori"), shim_dir.join("git")).unwrap();

        let resolved = resolve_stable_exe_path(&shim_dir.join("git"));
        assert_eq!(
            resolved,
            bin_dir.join("omamori"),
            "nested shim→stable→Cellar must resolve to stable path"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn shim_to_real_exe_with_relative_symlink() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-rel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let real_bin = dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(Path::new("../omamori"), shim_dir.join("npm")).unwrap();
            let result = shim_to_real_exe(&shim_dir.join("npm"));
            assert!(result.is_some(), "should resolve relative shim symlink");
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn shim_to_real_exe_non_symlink_returns_none() {
        let dir = std::env::temp_dir().join(format!("omamori-shim-nosym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        fs::write(shim_dir.join("git"), "not a symlink").unwrap();
        let result = shim_to_real_exe(&shim_dir.join("git"));
        assert!(
            result.is_none(),
            "non-symlink shim with no canonicalize target"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_stable_resolves_shim_path() {
        let dir = std::env::temp_dir().join(format!("omamori-resolve-shim-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let real_bin = dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real_bin, shim_dir.join("git")).unwrap();
            let resolved = resolve_stable_exe_path(&shim_dir.join("git"));
            assert!(
                !resolved.to_string_lossy().contains("/shim/"),
                "resolved path must not contain /shim/: {}",
                resolved.display()
            );
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hook_script_never_contains_shim_path() {
        let script = render_hook_script(Path::new(TEST_EXE));
        assert!(
            !script.contains("/shim/"),
            "hook script must not embed a shim path"
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial(home_env)]
    fn install_with_shim_source_normalizes_hook_paths() {
        let dir = std::env::temp_dir().join(format!("omamori-install-shim-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();

        let real_bin = dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();
        std::os::unix::fs::symlink(&real_bin, shim_dir.join("git")).unwrap();

        let base = dir.join("base");
        let result = install(&InstallOptions {
            base_dir: base.clone(),
            source: SourceExe::Implicit(shim_dir.join("git")),
            generate_hooks: true,
            home_override: Some(dir.clone()),
            verify_override: Some(|_, _| HookContractStatus::Ok),
        })
        .unwrap();

        let hook_content = fs::read_to_string(result.hook_script.unwrap()).unwrap();
        assert!(
            !hook_content.contains("/shim/"),
            "install with shim source_exe must not embed shim path in Claude hook"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial(home_env)]
    fn install_rejects_implicit_dev_build_source_resolved_through_shim() {
        // V-003 (#378): the dev-build gate runs against `source_exe` *after*
        // `shim_to_real_exe` resolution (installer.rs:115), while provenance
        // comes from the `SourceExe` variant on the pre-resolution
        // `options.source`. A refactor bug that drops the variant during
        // this reassignment (e.g. always treating the resolved path as a
        // fresh, provenance-less value) would silently exempt a
        // shim-resolved dev-build path from the gate — this test fails if
        // that happens, unlike `install_with_shim_source_normalizes_hook_paths`
        // above, which resolves through the same shim but to a
        // non-dev-build-shaped target.
        let dir =
            std::env::temp_dir().join(format!("omamori-shim-devbuild-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let dev_dir = dir.join("project").join("target").join("release");
        fs::create_dir_all(&dev_dir).unwrap();
        let real_bin = dev_dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();

        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();
        std::os::unix::fs::symlink(&real_bin, shim_dir.join("git")).unwrap();

        let base = dir.join("base");
        let result = install(&InstallOptions {
            base_dir: base.clone(),
            source: SourceExe::Implicit(shim_dir.join("git")),
            generate_hooks: true,
            home_override: Some(dir.clone()),
            verify_override: Some(|_, _| {
                panic!("verifier must not be called when the path is rejected as a dev build")
            }),
        });

        let err = result.expect_err(
            "install must reject a dev-build path reached via shim resolution, not just one passed directly",
        );
        assert!(
            err.to_string().contains("cargo build artifact"),
            "message should explain the rejection: {err}"
        );
        assert!(
            !base.join("hooks").join("claude-pretooluse.sh").exists(),
            "hook script must not be created for a shim-resolved dev-build path"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial(home_env)]
    fn install_accepts_explicit_dev_build_source_resolved_through_shim() {
        // Sibling of `install_rejects_implicit_dev_build_source_resolved_through_shim`:
        // same shim-resolved dev-build-shaped target, but `Explicit` provenance.
        // Without this test, a refactor bug that loses `Explicit` provenance
        // specifically during shim resolution (while preserving it on the
        // direct-path `install_accepts_explicit_dev_build_source` test) would
        // go undetected (Codex test-adversarial review, Round 1).
        let dir = std::env::temp_dir().join(format!(
            "omamori-shim-devbuild-explicit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let dev_dir = dir.join("project").join("target").join("release");
        fs::create_dir_all(&dev_dir).unwrap();
        let real_bin = dev_dir.join("omamori");
        fs::write(&real_bin, "binary").unwrap();

        let shim_dir = dir.join("shim");
        fs::create_dir_all(&shim_dir).unwrap();
        std::os::unix::fs::symlink(&real_bin, shim_dir.join("git")).unwrap();

        let base = dir.join("base");
        let result = install(&InstallOptions {
            base_dir: base.clone(),
            source: SourceExe::Explicit(shim_dir.join("git")),
            generate_hooks: true,
            home_override: Some(dir.clone()),
            verify_override: Some(|_, _| HookContractStatus::Ok),
        });

        result.expect(
            "install must accept a shim-resolved dev-build path when explicitly named, mirroring the direct-path case",
        );
        assert!(base.join("hooks").join("claude-pretooluse.sh").exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn hook_wrapper_remaps_exit_1_to_exit_2() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("omamori-failclose-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let fake_exe = dir.join("omamori");
        fs::write(&fake_exe, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&fake_exe, fs::Permissions::from_mode(0o755)).unwrap();

        let hook_script = render_hook_script(&fake_exe);
        let hook_path = dir.join("hook.sh");
        fs::write(&hook_path, &hook_script).unwrap();
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

        let output = std::process::Command::new("/bin/sh")
            .arg(&hook_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(2),
            "hook wrapper must remap exit 1 → exit 2 (fail-close)"
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// #353 V-003/V-004: run a rendered wrapper (Claude or Codex, both use
    /// the same tail) around a stub inner "hook-check" and return
    /// (wrapper_exit_code, stderr). `inner` selects what the stub does:
    /// - `Some(script_body)`: a real, executable `#!/bin/sh` stub with that
    ///   body (used for exit 0/1/2 cases)
    /// - `None` with `executable = false`: exe exists but lacks +x (exit 126)
    /// - the exe path simply doesn't exist at all (exit 127) — caller just
    ///   never creates the file and passes a path under `dir`
    #[cfg(unix)]
    fn run_wrapper_around_stub(inner: Option<&str>, executable: bool, tag: &str) -> (i32, String) {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "omamori-wrapper-matrix-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let fake_exe = dir.join("omamori");
        if let Some(body) = inner {
            fs::write(&fake_exe, format!("#!/bin/sh\n{body}\n")).unwrap();
            let mode = if executable { 0o755 } else { 0o644 };
            fs::set_permissions(&fake_exe, fs::Permissions::from_mode(mode)).unwrap();
        }
        // inner=None && !fake_exe.exists() (the 127 case): leave it absent.

        let hook_script = render_hook_script(&fake_exe);
        let hook_path = dir.join("hook.sh");
        fs::write(&hook_path, &hook_script).unwrap();
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

        let output = std::process::Command::new("/bin/sh")
            .arg(&hook_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();

        let code = output.status.code().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = fs::remove_dir_all(dir);
        (code, stderr)
    }

    /// #353 exact recovery hint, one entry per `echo` line in the wrapper's
    /// else branch. Checked line-by-line (not just a single substring like
    /// "plain terminal") so a regression that drops or truncates any one
    /// line — e.g. losing the agent-facing "do not retry" instruction while
    /// keeping the human-facing line — is caught here, not just a partial
    /// match. Kept in sync with `render_hook_script`/
    /// `render_codex_pretooluse_script` by hand; `wrapper_tails_are_byte_identical_across_claude_and_codex`
    /// separately guarantees both wrappers emit the same lines as each other.
    const RECOVERY_HINT_LINES: [&str; 3] = [
        "omamori: hook binary did not respond as expected — this is not a decision about your command.",
        "AI agent: do not retry this yourself. Tell the user to run this in a plain terminal (not via an AI agent):",
        "  omamori install --hooks",
    ];

    #[cfg(unix)]
    #[test]
    fn wrapper_exit_code_matrix_v003_v004() {
        // (tag, inner script Some(body)/None-for-missing, executable, expected wrapper exit, hint expected)
        let cases: &[(&str, Option<&str>, bool, i32, bool)] = &[
            ("allow", Some("exit 0"), true, 0, false),
            ("legit-block", Some("exit 2"), true, 2, false), // V-004: no hint on real BLOCK
            ("internal-error", Some("exit 1"), true, 2, true),
            ("non-executable", Some("exit 0"), false, 2, true), // 126
            ("missing", None, true, 2, true),                   // 127
            // A Rust panic exits 101 by default (no unwind boundary reaches
            // main). This is not code-specific handling in the wrapper —
            // its `else` branch catches ANY status that isn't 0 or 2 — but
            // pinning 101 explicitly proves a hook-check panic is covered
            // without needing a separate catch_unwind in hook-check itself.
            ("panic-like", Some("exit 101"), true, 2, true),
        ];

        for (tag, inner, executable, expected_exit, expect_hint) in cases {
            let (code, stderr) = run_wrapper_around_stub(*inner, *executable, tag);
            assert_eq!(
                code, *expected_exit,
                "case '{tag}': wrapper exit code mismatch"
            );
            for line in RECOVERY_HINT_LINES {
                assert_eq!(
                    stderr.contains(line),
                    *expect_hint,
                    "case '{tag}': hint line presence mismatch for {line:?} (stderr: {stderr:?})"
                );
            }
            if *expect_hint {
                // Order matters: line 1 is agent-facing ("don't retry"),
                // line 2 hands the human-facing instruction. A regression
                // that keeps all 3 lines but scrambles their order would
                // pass the presence checks above but not this one.
                let positions: Vec<usize> = RECOVERY_HINT_LINES
                    .iter()
                    .map(|line| {
                        stderr
                            .find(line)
                            .unwrap_or_else(|| panic!("case '{tag}': line {line:?} missing"))
                    })
                    .collect();
                assert!(
                    positions.windows(2).all(|w| w[0] < w[1]),
                    "case '{tag}': recovery hint lines out of order (positions: {positions:?}, stderr: {stderr:?})"
                );
            }
        }
    }

    #[test]
    fn hook_script_contains_fail_close() {
        let script = render_hook_script(Path::new(TEST_EXE));
        // #353: the wrapper now has a 3-way branch (allow / legit block /
        // infra failure) instead of a single `else exit 2; fi`. The
        // fail-close guarantee this test pins is: any STATUS that is
        // neither 0 (allow) nor 2 (legit block) still exits 2.
        assert!(
            script.contains("elif [ \"$STATUS\" -eq 2 ]; then\n  exit 2\nelse"),
            "Claude Code hook must distinguish legit BLOCK (exit 2) from an else fallthrough"
        );
        assert!(
            script.trim_end().ends_with("exit 2\nfi"),
            "Claude Code hook's else (infra-failure) branch must still fail closed to exit 2"
        );
        assert!(
            !script.contains("exit $?"),
            "Claude Code hook must not use exit $? (fail-open on exit 1)"
        );
        assert!(
            !script.contains("set -eu"),
            "Claude Code hook must use set -u (not set -eu) to allow STATUS=$? capture"
        );
        assert!(
            script.contains("set -u\n"),
            "Claude Code hook must contain set -u (standalone, not set -eu)"
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

    /// #353/#356: render_hook_script and render_codex_pretooluse_script are
    /// deliberately NOT unified behind a shared helper (would break
    /// check-invariants.sh Invariant #7's per-function literal extraction —
    /// see plan). This test is the structural substitute: it pins that their
    /// fail-close tail (from `STATUS=$?` through the closing `fi`, i.e.
    /// everything except the provider-specific `hook-check --provider ...`
    /// line) stays byte-identical, so a future edit to one wrapper's
    /// 3-way branch without the other is caught here instead of silently
    /// drifting.
    #[test]
    fn wrapper_tails_are_byte_identical_across_claude_and_codex() {
        fn tail_from_status(script: &str) -> &str {
            // Anchor on the exact line, not a substring search — a future
            // comment mentioning "STATUS=$?" earlier in the script would
            // otherwise silently make `find()` match the wrong occurrence.
            let matches: Vec<usize> = script
                .match_indices("\nSTATUS=$?\n")
                .map(|(i, _)| i)
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "wrapper must contain the STATUS=$? assignment line exactly once, got {} occurrences",
                matches.len()
            );
            // +1 to skip the leading '\n' captured by the pattern, landing
            // exactly on "STATUS=$?".
            &script[matches[0] + 1..]
        }

        let claude = render_hook_script(Path::new(TEST_EXE));
        let codex = render_codex_pretooluse_script(Path::new(TEST_EXE));

        assert_eq!(
            tail_from_status(&claude),
            tail_from_status(&codex),
            "Claude and Codex wrapper fail-close tails (STATUS=$? onward) must be byte-identical"
        );
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

    // --- #357: remove_codex_hooks_entry symlink/non-regular-file guard ---
    // These call remove_codex_hooks_entry() directly via with_test_home,
    // unlike remove_codex_hooks_entry_cleans_up above (which predates
    // with_test_home and simulates removal manually).

    #[test]
    #[serial_test::serial(home_env)]
    fn remove_codex_hooks_entry_regular_file_removes_entry_preserves_others() {
        let dir = fresh_test_dir("codex-rm-regular");
        let codex_dir = dir.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();

        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();
        merge_codex_hooks(&codex_dir, &wrapper).unwrap();

        // Add a sibling entry that must survive uninstall.
        let raw = fs::read_to_string(codex_dir.join("hooks.json")).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        doc.pointer_mut("/hooks/PreToolUse")
            .and_then(|v| v.as_array_mut())
            .unwrap()
            .push(serde_json::json!({
                "matcher": "Edit",
                "hooks": [{"type": "command", "command": "/other/tool"}]
            }));
        fs::write(
            codex_dir.join("hooks.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        with_test_home(&dir, || remove_codex_hooks_entry().unwrap());

        let content = fs::read_to_string(codex_dir.join("hooks.json")).unwrap();
        assert!(
            !content.contains(CODEX_STATUS_MESSAGE),
            "omamori entry should be removed: {content}"
        );
        assert!(
            content.contains("/other/tool"),
            "sibling entry must be preserved: {content}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    #[cfg(unix)]
    fn remove_codex_hooks_entry_skips_symlink() {
        let dir = fresh_test_dir("codex-rm-symlink");
        let codex_dir = dir.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();

        // Real hooks.json with an omamori entry, living outside .codex/.
        let real = dir.join("real-hooks.json");
        let wrapper = dir.join("wrapper.sh");
        fs::write(&wrapper, "#!/bin/sh").unwrap();
        merge_codex_hooks(&dir, &wrapper).unwrap(); // writes dir/hooks.json
        fs::rename(dir.join("hooks.json"), &real).unwrap();
        std::os::unix::fs::symlink(&real, codex_dir.join("hooks.json")).unwrap();

        with_test_home(&dir, || remove_codex_hooks_entry().unwrap());

        assert!(
            codex_dir.join("hooks.json").is_symlink(),
            "symlink itself must be untouched"
        );
        let target_content = fs::read_to_string(&real).unwrap();
        assert!(
            target_content.contains(CODEX_STATUS_MESSAGE),
            "symlink target must not be modified: {target_content}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    #[cfg(unix)]
    fn remove_codex_hooks_entry_skips_dangling_symlink() {
        let dir = fresh_test_dir("codex-rm-dangling");
        let codex_dir = dir.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();
        std::os::unix::fs::symlink(dir.join("does-not-exist"), codex_dir.join("hooks.json"))
            .unwrap();

        // A dangling symlink must not be created, followed, or turned into a
        // regular file — remove_codex_hooks_entry must simply leave it alone.
        with_test_home(&dir, || remove_codex_hooks_entry().unwrap());

        let link_path = codex_dir.join("hooks.json");
        assert!(
            link_path.is_symlink(),
            "dangling symlink must remain untouched"
        );
        assert!(!link_path.exists(), "target must still not exist");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn remove_codex_hooks_entry_skips_directory() {
        let dir = fresh_test_dir("codex-rm-directory");
        let codex_dir = dir.join(".codex");
        // hooks.json is itself a directory — same is_real_file() rejection
        // path as a FIFO/socket, without requiring unsafe libc FFI in tests.
        fs::create_dir_all(codex_dir.join("hooks.json")).unwrap();

        with_test_home(&dir, || remove_codex_hooks_entry().unwrap());

        assert!(
            codex_dir.join("hooks.json").is_dir(),
            "directory must be left untouched, not read or replaced"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    #[cfg(unix)]
    fn remove_codex_hooks_entry_skips_fifo() {
        // A directory proves the same is_real_file() classification, but a
        // FIFO additionally proves the guard doesn't attempt to open it at
        // all — a stray read/write on an unopened-reader FIFO would hang
        // this test (Codex Round 1 adversarial review: directory read fails
        // fast, FIFO read blocks, so only a FIFO exercises that failure mode).
        let dir = fresh_test_dir("codex-rm-fifo");
        let codex_dir = dir.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();
        let fifo_path = codex_dir.join("hooks.json");
        let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        with_test_home(&dir, || remove_codex_hooks_entry().unwrap());

        use std::os::unix::fs::FileTypeExt;
        assert!(
            fifo_path.symlink_metadata().unwrap().file_type().is_fifo(),
            "FIFO must be left untouched, not read or replaced"
        );

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
    #[cfg(unix)]
    fn update_codex_config_bak_symlink_is_safe() {
        let dir = std::env::temp_dir().join(format!("omamori-toml-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let original = "model = \"gpt-5.3-codex\"\n";
        fs::write(dir.join("config.toml"), original).unwrap();

        // Place a symlink at config.toml.bak -> canary file
        let canary = dir.join("canary.txt");
        fs::write(&canary, "DO NOT OVERWRITE").unwrap();
        std::os::unix::fs::symlink(&canary, dir.join("config.toml.bak")).unwrap();

        let result = update_codex_config(&dir).unwrap();
        assert!(matches!(result, CodexConfigOutcome::Added));

        // Canary must be untouched (symlink target not followed)
        assert_eq!(fs::read_to_string(&canary).unwrap(), "DO NOT OVERWRITE");

        // Backup must be a regular file (symlink replaced by atomic_write rename)
        let bak = dir.join("config.toml.bak");
        assert!(!bak.is_symlink(), "backup must not be a symlink after fix");
        assert_eq!(fs::read_to_string(&bak).unwrap(), original);

        // Config must be updated
        let config = fs::read_to_string(dir.join("config.toml")).unwrap();
        assert!(config.contains("codex_hooks = true"));

        let _ = fs::remove_dir_all(dir);
    }

    // --- G-12: auto_setup_codex_if_needed ---

    #[test]
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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

    #[test]
    #[serial_test::serial(home_env)]
    fn auto_setup_codex_rejects_implicit_dev_build_source() {
        // #354: the test binary's own current_exe() is always a
        // target/debug (or target/release) path under `cargo test` — the
        // exact shape this check exists to reject, no injection needed.
        // SAFETY: serial_test ensures no concurrent access to env vars
        let saved = std::env::var_os("CODEX_CI");
        unsafe { std::env::set_var("CODEX_CI", "1") };

        let home =
            std::env::temp_dir().join(format!("omamori-codex-devbuild-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".codex")).unwrap();
        let _guard = HomeGuard::set(Some(home.as_os_str()));

        let dir = std::env::temp_dir().join(format!(
            "omamori-codex-devbuild-base-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let result = auto_setup_codex_if_needed(&dir);
        assert!(
            !result,
            "must reject an implicit dev-build source instead of auto-configuring"
        );
        assert!(
            !dir.join("hooks").join("codex-pretooluse.sh").exists(),
            "codex wrapper must not be written for an implicit dev-build source"
        );

        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&dir);
        if let Some(v) = saved {
            unsafe { std::env::set_var("CODEX_CI", v) };
        } else {
            unsafe { std::env::remove_var("CODEX_CI") };
        }
    }

    // Note: Testing CODEX_CI=1 + no wrapper + a genuine (non-dev-build) source
    // requires an injectable exe seam this function doesn't have. Covered by
    // manual verification only; see PR description.

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

    /// RAII guard that temporarily overrides `HOME`, restoring the original
    /// value (or absence) on drop — including when the guarded code panics,
    /// unlike a manual save/restore pair. Pass `None` to unset `HOME`
    /// entirely, or `Some("")` for the empty-string edge case. Callers must
    /// use `#[serial_test::serial(home_env)]` — no synchronization here.
    pub(crate) struct HomeGuard {
        saved: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        pub(crate) fn set(home: Option<&std::ffi::OsStr>) -> Self {
            let saved = std::env::var_os("HOME");
            // SAFETY: serial_test ensures no parallel test mutates HOME concurrently.
            match home {
                Some(v) => unsafe { std::env::set_var("HOME", v) },
                None => unsafe { std::env::remove_var("HOME") },
            }
            Self { saved }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.saved {
                Some(v) => unsafe { std::env::set_var("HOME", v) },
                None => unsafe { std::env::remove_var("HOME") },
            }
        }
    }

    /// Compute the omamori prefix that `merge_claude_settings` expects.
    /// We point HOME-derived prefix at our test dir by passing the right script
    /// path. The merge function builds prefix from `HOME` env var, so for tests
    /// we ensure the script lives under `<HOME>/.omamori/...`.
    fn with_test_home<R>(home: &Path, f: impl FnOnce() -> R) -> R {
        let _guard = HomeGuard::set(Some(home.as_os_str()));
        f()
    }

    // ---------------------------------------------------------------------
    // claude_home_dir / codex_home_dir Option<PathBuf> contract (#210)
    //
    // HOME unset or empty must resolve to None — never a `.` (CWD-relative)
    // fallback, which previously let test runs merge dead hook paths into
    // whatever `./.claude` happened to exist in the process's CWD.
    // ---------------------------------------------------------------------

    #[test]
    #[serial_test::serial(home_env)]
    fn claude_home_dir_is_none_when_home_unset() {
        let _guard = HomeGuard::set(None);

        assert_eq!(claude_home_dir(), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn claude_home_dir_is_none_when_home_empty() {
        let _guard = HomeGuard::set(Some(std::ffi::OsStr::new("")));

        assert_eq!(
            claude_home_dir(),
            None,
            "HOME=\"\" must normalize to the same None as HOME unset, not a relative './.claude'"
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn codex_home_dir_is_none_when_home_unset() {
        let _guard = HomeGuard::set(None);

        assert_eq!(codex_home_dir(), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn codex_home_dir_is_none_when_home_empty() {
        let _guard = HomeGuard::set(Some(std::ffi::OsStr::new("")));

        assert_eq!(codex_home_dir(), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn install_with_home_unset_succeeds_without_cwd_fallback() {
        let root =
            std::env::temp_dir().join(format!("omamori-install-nohome-{}", std::process::id()));
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();

        let cwd_claude = std::env::current_dir().unwrap().join(".claude");
        let cwd_claude_existed_before = cwd_claude.exists();

        let result = {
            let _guard = HomeGuard::set(None);
            install(&InstallOptions {
                base_dir: root.clone(),
                source: SourceExe::Implicit(source.clone()),
                generate_hooks: true,
                home_override: None,
                verify_override: Some(|_, _| HookContractStatus::Ok),
            })
        };

        let result = result.expect("install must succeed even when HOME is unset");
        assert!(matches!(
            result.claude_settings_outcome,
            Some(ClaudeSettingsOutcome::Skipped(_))
        ));
        assert_eq!(
            cwd_claude.exists(),
            cwd_claude_existed_before,
            "install with HOME unset must not create a CWD-relative ./.claude (#210 `.` fallback)"
        );

        let _ = fs::remove_dir_all(root);
    }

    // --- install() hook-contract verification tests (#349) ---

    #[test]
    fn install_fails_loudly_on_hooks_but_still_links_shims_when_verification_fails() {
        // #349 code review: Layer 1 (shims) has no dependency on hook
        // verification. A hook-contract failure must still fail the overall
        // command loudly (install --hooks doubles as the fail-close recovery
        // path and must not silently claim success), but it must not also
        // block Layer 1 repair — `omamori setup`'s first run and
        // `doctor --fix`'s shim-only RunInstall repairs depend on shims being
        // linked regardless of hook verification outcome.
        let root =
            std::env::temp_dir().join(format!("omamori-install-verifyfail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();

        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Implicit(source.clone()),
            generate_hooks: true,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| HookContractStatus::ExitNonZero(1)),
        });

        let err = result.expect_err("install must fail loudly when verification fails");
        let message = err.to_string();
        assert!(
            message.contains("could not update hooks"),
            "message should explain what happened: {message}"
        );
        assert!(
            message.contains("Layer 1 (PATH shims) was still updated"),
            "message should state that shim repair was not blocked: {message}"
        );
        assert!(
            message.contains("existing hooks are kept"),
            "message should state the current safe state for hooks: {message}"
        );
        assert!(
            message.contains("verify omamori is installed at a stable path"),
            "message should say what to do next: {message}"
        );

        // Shims must be linked despite the hook-contract failure...
        assert!(
            root.join("shim").join("rm").exists(),
            "shim must still be linked when only hook-contract verification fails"
        );
        // ...but no hook artifact should be written.
        assert!(
            !root.join("hooks").join("claude-pretooluse.sh").exists(),
            "hook script must not be created when hook-contract verification fails"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn install_skips_verification_when_hooks_not_requested() {
        // generate_hooks: false must not spawn a probe at all — a broken
        // verify_override here would fail the test if it were ever called.
        let root =
            std::env::temp_dir().join(format!("omamori-install-noverify-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let source = root.join("omamori");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, "binary").unwrap();

        let result = install(&InstallOptions {
            base_dir: root.clone(),
            source: SourceExe::Implicit(source.clone()),
            generate_hooks: false,
            home_override: Some(root.clone()),
            verify_override: Some(|_, _| {
                panic!("verifier must not be called when generate_hooks is false")
            }),
        });

        assert!(result.is_ok(), "install without --hooks must not verify");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn uninstall_succeeds_when_home_unset() {
        let root =
            std::env::temp_dir().join(format!("omamori-uninstall-nohome-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();

        let result = {
            let _guard = HomeGuard::set(None);
            uninstall(&root)
        };

        assert!(
            result.is_ok(),
            "uninstall must succeed (not panic) even when HOME is unset: {result:?}"
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
        // Legacy entry is removed as stale and replaced with canonical.
        // MatcherMigrated is returned when stale_count > 0 with legacy flag.
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
    fn remove_claude_does_not_touch_user_hook_inside_omamori_dir() {
        // R4 regression (Codex Round 4): the surgical pass must match the
        // CANONICAL omamori script path, not any path under base_dir.
        // A user who chooses to store their own hook script inside the omamori
        // base dir (e.g. for organizational convenience) must keep it intact.
        let dir = fresh_test_dir("r4-user-in-omamori");
        let script = fake_script(&dir);
        let user_inside = dir.join(".omamori").join("hooks").join("user-hook.sh");
        fs::write(&user_inside, "#!/bin/sh\nexit 0\n").unwrap();

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let omamori_cmd = shell_words::quote(&script.display().to_string()).into_owned();
        let user_cmd = shell_words::quote(&user_inside.display().to_string()).into_owned();
        let hybrid = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": user_cmd.clone()},
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
        assert_eq!(arr.len(), 1);
        let inner = arr[0].pointer("/hooks").and_then(|v| v.as_array()).unwrap();
        assert_eq!(
            inner.len(),
            1,
            "user hook stored inside omamori base dir must survive"
        );
        let surviving = inner[0].get("command").and_then(|c| c.as_str()).unwrap();
        assert!(
            surviving.contains("user-hook.sh"),
            "the surviving hook must be the user's, not the omamori canonical: {surviving}"
        );

        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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

        // After: hybrid entry has omamori inner hook surgically removed
        // (only user hook remains), and a canonical omamori entry was pushed.
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2, "hybrid (user-only now) + canonical pushed");
        // The hybrid entry should now have only the user hook (omamori extracted)
        assert_eq!(
            arr[0].pointer("/hooks/0/command").and_then(|v| v.as_str()),
            Some("/usr/local/bin/userhook"),
            "user-managed sibling hook must survive in hybrid"
        );
        assert_eq!(
            arr[0]
                .pointer("/hooks")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1),
            "hybrid should have only user hook after surgical extraction"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
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
    #[serial_test::serial(home_env)]
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

    // -----------------------------------------------------------------------
    // V-001: Cross-root stale cleanup (core #254 bug)
    // -----------------------------------------------------------------------
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_removes_all_stale_entries_from_different_roots() {
        let dir = fresh_test_dir("v001-stale");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let stale_entry_a = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/tmp1/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });
        let stale_entry_b = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/tmp2/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.8"
        });
        let user_entry = serde_json::json!({
            "matcher": "Edit",
            "hooks": [{"type": "command", "command": "/usr/local/bin/userhook"}]
        });

        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [stale_entry_a, user_entry.clone(), stale_entry_b] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(result, ClaudeSettingsOutcome::StaleEntriesCleaned(2)),
            "expected StaleEntriesCleaned(2), got {result:?}"
        );

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2, "user entry + new canonical entry");
        assert_eq!(
            arr[0].pointer("/hooks/0/command").and_then(|v| v.as_str()),
            Some("/usr/local/bin/userhook"),
            "user entry preserved at original position"
        );
        assert!(
            arr[1].get("x-omamori-version").is_some(),
            "new canonical entry has version tag"
        );

        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // V-002: Legacy entry cleanup (untagged, path-based fallback)
    // -----------------------------------------------------------------------
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_cleans_legacy_entry_without_version_tag() {
        let dir = fresh_test_dir("v002-legacy");
        let script = fake_script(&dir);
        let base_dir = dir.join(".omamori");
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let legacy_entry = serde_json::json!({
            "matcher": "*",
            "hooks": [{"type": "command", "command": format!("{}/hooks/claude-pretooluse.sh", base_dir.display())}]
        });

        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [legacy_entry] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        // Legacy wildcard matcher → MatcherMigrated takes priority over StaleEntriesCleaned
        assert!(
            matches!(result, ClaudeSettingsOutcome::MatcherMigrated),
            "expected MatcherMigrated, got {result:?}"
        );

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 1, "only new canonical entry");
        assert_eq!(
            arr[0].get("matcher").and_then(|v| v.as_str()),
            Some("Bash"),
            "canonical entry has current matcher"
        );

        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // V-004: Hybrid entry preservation with stale cleanup
    // -----------------------------------------------------------------------
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_preserves_hybrid_with_stale_cleanup() {
        let dir = fresh_test_dir("v004-hybrid");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let stale_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/old/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });
        let hybrid_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "/usr/local/bin/userhook"},
                {"type": "command", "command": "/var/folders/stale/hooks/claude-pretooluse.sh"}
            ],
            "x-omamori-version": "0.9.8"
        });

        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [stale_entry, hybrid_entry] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        // 1 whole stale entry removed + 1 inner hook surgically extracted = 2 total
        assert!(
            matches!(result, ClaudeSettingsOutcome::StaleEntriesCleaned(2)),
            "expected StaleEntriesCleaned(2), got {result:?}"
        );

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2, "hybrid (with user hook only) + new canonical");
        let hybrid = &arr[0];
        let hybrid_hooks = hybrid.get("hooks").and_then(|v| v.as_array()).unwrap();
        assert_eq!(hybrid_hooks.len(), 1, "only user hook remains in hybrid");
        assert_eq!(
            hybrid_hooks[0].get("command").and_then(|v| v.as_str()),
            Some("/usr/local/bin/userhook")
        );

        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // V-005: Uninstall cleans multiple stale entries
    // -----------------------------------------------------------------------
    #[test]
    #[serial_test::serial(home_env)]
    fn remove_claude_cleans_multiple_stale_entries() {
        let dir = fresh_test_dir("v005-rm-stale");
        let base_dir = dir.join(".omamori");
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::create_dir_all(base_dir.join("hooks")).unwrap();

        let stale_a = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/a/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });
        let stale_b = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/b/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.8"
        });
        let user_entry = serde_json::json!({
            "matcher": "Edit",
            "hooks": [{"type": "command", "command": "/usr/local/bin/userhook"}]
        });

        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [stale_a, user_entry.clone(), stale_b] }
        });

        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        remove_claude_settings_entry(&base_dir).unwrap();

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        let arr = doc
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 1, "only user entry remains");
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

    // -----------------------------------------------------------------------
    // V-008: Idempotency after stale cleanup
    // -----------------------------------------------------------------------
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_idempotent_after_stale_cleanup() {
        let dir = fresh_test_dir("v008-idem");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let stale_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/var/folders/old/hooks/claude-pretooluse.sh"}],
            "x-omamori-version": "0.9.7"
        });

        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [stale_entry] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        // First call: cleanup + merge
        let r1 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(r1, ClaudeSettingsOutcome::StaleEntriesCleaned(1)),
            "first call: {r1:?}"
        );

        // Second call: idempotent
        let r2 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(r2, ClaudeSettingsOutcome::AlreadyPresent),
            "second call should be AlreadyPresent, got {r2:?}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// P0 regression: after surgical extraction from a hybrid entry,
    /// `x-omamori-version` tag must be stripped. A second merge must NOT
    /// delete the remaining user hook.
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_hybrid_extraction_preserves_user_hook_on_rerun() {
        let dir = fresh_test_dir("p0-hybrid-rerun");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let hybrid = serde_json::json!({
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "/usr/local/bin/my-custom-hook"},
                {"type": "command", "command": "/old/root/hooks/claude-pretooluse.sh"}
            ],
            "x-omamori-version": "0.9.7"
        });
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [hybrid] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        // First merge: extract omamori inner hook, push canonical
        let r1 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(r1, ClaudeSettingsOutcome::StaleEntriesCleaned(_)),
            "first call: {r1:?}"
        );

        // Verify user hook survived and tag was stripped
        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let after: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        let user_entry = arr.iter().find(|e| {
            e.get("hooks")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter().any(|h| {
                        h.get("command").and_then(|v| v.as_str())
                            == Some("/usr/local/bin/my-custom-hook")
                    })
                })
                .unwrap_or(false)
        });
        assert!(user_entry.is_some(), "user hook entry must survive");
        assert!(
            user_entry.unwrap().get("x-omamori-version").is_none(),
            "tag must be stripped after extraction"
        );

        // Second merge: must NOT delete the user hook
        let r2 = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(r2, ClaudeSettingsOutcome::AlreadyPresent),
            "second call: {r2:?}"
        );

        let raw2 = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let after2: serde_json::Value = serde_json::from_str(&raw2).unwrap();
        let arr2 = after2
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        let user_still = arr2.iter().any(|e| {
            e.get("hooks")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter().any(|h| {
                        h.get("command").and_then(|v| v.as_str())
                            == Some("/usr/local/bin/my-custom-hook")
                    })
                })
                .unwrap_or(false)
        });
        assert!(user_still, "user hook must survive second merge");

        let _ = fs::remove_dir_all(dir);
    }

    /// Negative test: a user entry without tag and outside base_dir must
    /// survive merge even if it uses a similar filename.
    #[test]
    #[serial_test::serial(home_env)]
    fn merge_claude_does_not_delete_untagged_user_entry() {
        let dir = fresh_test_dir("no-del-user");
        let script = fake_script(&dir);
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let user_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/usr/local/my-project/hooks/claude-pretooluse.sh"}]
        });
        let doc = serde_json::json!({
            "hooks": { "PreToolUse": [user_entry] }
        });
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        let result = with_test_home(&dir, || {
            merge_claude_settings(&claude_dir, &script).unwrap()
        });
        assert!(
            matches!(result, ClaudeSettingsOutcome::Merged),
            "should merge (push new entry), got {result:?}"
        );

        let raw = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let after: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 2, "user entry + canonical must both exist");
        let user_survived = arr.iter().any(|e| {
            e.pointer("/hooks/0/command")
                .and_then(|v| v.as_str())
                .map(|c| c.contains("my-project"))
                .unwrap_or(false)
        });
        assert!(user_survived, "user entry must survive merge");

        let _ = fs::remove_dir_all(dir);
    }
}
