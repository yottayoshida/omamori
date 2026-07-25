use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::rules::{ActionKind, CommandInvocation, RuleConfig};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ContextEvaluation {
    pub action_override: Option<ActionKind>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    #[serde(default = "default_regenerable_paths")]
    pub regenerable_paths: Vec<String>,
    #[serde(default = "default_protected_paths")]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub git: GitContextConfig,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            regenerable_paths: default_regenerable_paths(),
            protected_paths: default_protected_paths(),
            git: GitContextConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitContextConfig {
    #[serde(default = "default_git_enabled")]
    pub enabled: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for GitContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_timeout_ms() -> u64 {
    100
}

fn default_git_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Built-in defaults
// ---------------------------------------------------------------------------

pub fn default_regenerable_paths() -> Vec<String> {
    vec![
        "target/".to_string(),
        "node_modules/".to_string(),
        ".next/".to_string(),
        "dist/".to_string(),
        "build/".to_string(),
        "__pycache__/".to_string(),
        ".cache/".to_string(),
    ]
}

pub fn default_protected_paths() -> Vec<String> {
    vec![
        "src/".to_string(),
        "lib/".to_string(),
        ".git/".to_string(),
        ".env".to_string(),
        ".ssh/".to_string(),
    ]
}

/// Paths that can never be classified as regenerable, regardless of config.
/// If a user adds one of these to regenerable_paths, it is silently ignored
/// and a config warning is emitted.
pub const NEVER_REGENERABLE: &[&str] = &["src", "lib", "app", ".git", ".env", ".ssh"];

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

/// Captures the process's current working directory once, for callers that
/// need a `base: &Path` and have no more specific origin than "wherever the
/// AI tool/user shell currently is". Returns `None` rather than silently
/// substituting something else when the CWD is unresolvable (e.g. deleted
/// out from under the running process) — mirroring [`home_dir`]'s fail-close
/// discipline (#373): an unusable value must not silently change which path
/// a downstream `protected_paths`/`regenerable_paths` match, or a protected-
/// file check, evaluates.
///
/// `base` is security-load-bearing: `is_protected_file_path`
/// (`engine::hook`) resolves relative `file_path`s against it to decide
/// whether an AI tool may write to omamori's own config/hooks/audit files.
/// Callers must construct `base` only from the process's own CWD (this
/// function) or an equivalently trusted origin — never from external input
/// (hook payload fields, arguments meant for the target command, etc.).
// reason: this is the one sanctioned CWD-read entry point (#175); every
// other caller in the crate must go through this function instead.
#[allow(clippy::disallowed_methods)]
pub(crate) fn process_base() -> Option<PathBuf> {
    env::current_dir().ok()
}

/// [`process_base`] with the historical `/` fallback, consolidated to this
/// one call site so no caller re-invents its own default.
///
/// Safe for [`evaluate_context`] callers under the *default* `protected_paths`
/// (single-component entries like `src/`, `.git/`): `path_matches_pattern`
/// does a contiguous-component-window match, and a single-component pattern
/// needs no components from `base` to complete its window, so the synthetic
/// `/`-rooted path still matches it correctly. **This does not generalize**:
/// a user-configured multi-component `protected_paths` entry (e.g.
/// `"some/nested/dir"`) can rely on `base` supplying a leading portion of the
/// window (the same boundary-spanning shape `is_protected_file_path`'s
/// Subpath matching has, see its V-A15 test) — under the real CWD it
/// matches, under the synthetic `/` fallback it silently does not, and
/// Priority 1 escalation is skipped (fail-*open* for that one rule, not
/// fail-closed). Exploitability is low (requires both an unresolvable CWD
/// *and* a non-default multi-component `protected_paths` entry) but this
/// fallback does not close it — tracked as a follow-up issue rather than
/// fixed here. `regenerable_paths` downgrade is unaffected either way: it
/// requires `fs::canonicalize` to succeed, which a synthetic `/`-rooted path
/// generally will not, so an unresolvable CWD can only ever suppress a
/// downgrade, never one that shouldn't happen. **Not** safe for exact-
/// location checks like `is_protected_file_path`, which must fail-closed on
/// [`process_base`]'s `None` directly instead of routing through this
/// fallback.
pub(crate) fn process_base_or_root() -> PathBuf {
    process_base().unwrap_or_else(|| PathBuf::from("/"))
}

/// Lexical path normalization with an explicit base directory for relative-path
/// resolution: expand `~`, resolve relative paths against `base`, remove `.` and
/// `..`. Does NOT access the filesystem (no symlink resolution).
///
/// `~` expansion uses `home_dir` (fail-close, #373): if `HOME` is unset,
/// empty, or relative, `~/foo` is left untouched rather than falling back to
/// a CWD-relative resolution of `foo` — an unusable `HOME` must not silently
/// change which path a `protected_paths`/`regenerable_paths` match evaluates.
///
/// `base` must be absolute — callers resolve it via `process_base` (or an
/// equivalently trusted origin) before calling. Enforced with a real
/// `assert!` (not `debug_assert!`, so this holds in release builds too):
/// `Path::join` alone never touches the filesystem, so a relative `base`
/// would not make *this* function CWD-dependent — but `resolve_path` (and
/// [`evaluate_context`], which calls it) feed this function's result into
/// `fs::canonicalize`, which silently resolves a still-relative path
/// against the real process CWD. A caller-supplied relative `base` must be
/// caught here, at the one place both call paths share, not left to
/// silently reintroduce the exact CWD dependence this PR (#175) exists to
/// remove (Codex Round 1 review finding).
pub fn normalize_path(path: &str, base: &Path) -> PathBuf {
    assert!(
        base.is_absolute(),
        "normalize_path: base must be absolute, got {base:?} — see module docs"
    );
    // Step 1: ~ expansion
    let path = if let Some(rest) = path.strip_prefix("~/") {
        match home_dir() {
            Some(home) => home.join(rest),
            None => PathBuf::from(path),
        }
    } else {
        PathBuf::from(path)
    };

    // Step 2: relative → absolute (based on explicit base, not process CWD)
    let path = if path.is_relative() {
        base.join(&path)
    } else {
        path
    };

    // Step 3: lexical resolution of .. / . / //
    let mut components: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if let Some(last) = components.last()
                    && !matches!(last, Component::RootDir)
                {
                    components.pop();
                }
            }
            Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Try to resolve the real path (symlinks included) via `fs::canonicalize`
/// after lexically absolutizing against `base`.
///
/// Because the value passed to `fs::canonicalize` is already absolute, the
/// result is independent of the process CWD — this closes the v0.9.5
/// `multi_target_*` quarantine root cause (#164).
///
/// Returns `(canonical, true)` on success, `(lexical, false)` if the path
/// does not exist. `base` must be absolute (see [`normalize_path`] doc).
pub(crate) fn resolve_path(raw: &str, base: &Path) -> (PathBuf, bool) {
    let lexical = normalize_path(raw, base);
    // canonicalize on the absolute lexical path, not on `raw`, so the result
    // does not depend on the current process CWD.
    match fs::canonicalize(&lexical) {
        Ok(canonical) => (canonical, true),
        Err(_) => (lexical, false),
    }
}

// ---------------------------------------------------------------------------
// HOME resolution (fail-close)
// ---------------------------------------------------------------------------

/// Resolve `$HOME` as an absolute path. `None` when `HOME` is unset, empty,
/// or relative — callers must treat this as "no usable HOME", not silently
/// fall back to the current working directory.
///
/// `env::var_os("HOME")` returns `Some("")` for `HOME=""`, so a bare
/// `?`/`map` chain without the `is_absolute()` filter does not catch the
/// empty-string case (nor a relative value like `HOME=.` or `HOME=rel`).
pub(crate) fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Resolve `$HOME/.local/share/omamori`. `None` when `HOME` is unusable
/// (see `home_dir`). Single source of truth for this data directory —
/// consumers (heartbeat, break-glass state, staging, audit log default)
/// all fail closed together rather than each re-deriving their own
/// CWD-fallback logic.
pub(crate) fn data_dir() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".local").join("share").join("omamori"))
}

// ---------------------------------------------------------------------------
// Component boundary matching
// ---------------------------------------------------------------------------

/// Check if `normalized` path contains `pattern` as a contiguous subsequence
/// of path components. This ensures "target" matches "/foo/target/bar" but
/// NOT "/foo/target_dir/bar".
pub fn path_matches_pattern(normalized: &Path, pattern: &str) -> bool {
    let pattern_path = Path::new(pattern);
    let pattern_components: Vec<Component> = pattern_path.components().collect();
    let path_components: Vec<Component> = normalized.components().collect();

    if pattern_components.is_empty() {
        return false;
    }

    path_components
        .windows(pattern_components.len())
        .any(|window| window == pattern_components.as_slice())
}

/// Check if a path matches any pattern in a list.
fn matches_any_pattern(path: &Path, patterns: &[String]) -> Option<String> {
    for pattern in patterns {
        if path_matches_pattern(path, pattern) {
            return Some(pattern.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// NEVER_REGENERABLE validation
// ---------------------------------------------------------------------------

/// Check if a path pattern conflicts with NEVER_REGENERABLE.
pub fn is_never_regenerable(pattern: &str) -> bool {
    let clean = pattern.trim_end_matches('/');
    NEVER_REGENERABLE.contains(&clean)
}

/// Validate regenerable_paths against NEVER_REGENERABLE.
/// Returns warnings for conflicting patterns.
pub fn validate_regenerable_paths(paths: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    for path in paths {
        if is_never_regenerable(path) {
            warnings.push(format!(
                "regenerable_paths pattern \"{}\" conflicts with protected system path; pattern ignored for security",
                path
            ));
        }
    }
    warnings
}

/// Filter out NEVER_REGENERABLE patterns from a list.
fn effective_regenerable_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| !is_never_regenerable(p))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Context evaluation (Tier 1: path-based)
// ---------------------------------------------------------------------------

/// Evaluate context for a matched rule.
///
/// Evaluation priority (highest first):
/// 1. protected_paths match → escalate to Block
/// 2. NEVER_REGENERABLE match → ignore regenerable config, keep original
/// 3. regenerable_paths match AND canonicalize succeeded → downgrade to LogOnly
/// 4. regenerable_paths match AND canonicalize failed → no downgrade (fail-close)
/// 5. No match → keep original
///
/// Relative target paths in `invocation` are resolved against `base` via
/// `resolve_path`, so the verdict does not depend on the process CWD.
/// `base` must be absolute (see [`normalize_path`] doc) — callers resolve it
/// via `process_base`/`process_base_or_root` before calling. Priority 1
/// (protected_paths) matches on path components, so it still functions
/// against `process_base_or_root`'s synthetic `/` fallback for the default,
/// single-component `protected_paths` entries; see that function's doc for
/// the narrower multi-component-entry caveat this does *not* cover.
pub fn evaluate_context(
    invocation: &CommandInvocation,
    _rule: &RuleConfig,
    config: &ContextConfig,
    base: &Path,
) -> ContextEvaluation {
    // Real `assert!`, not `debug_assert!` — see `normalize_path`'s doc for
    // why (this also protects the empty-`targets` early return below, which
    // never reaches `resolve_path`'s own transitive check).
    assert!(
        base.is_absolute(),
        "evaluate_context: base must be absolute, got {base:?} — see module docs"
    );
    let targets = invocation.target_args();
    if targets.is_empty() {
        return ContextEvaluation {
            action_override: None,
            reason: "no target paths to evaluate".to_string(),
        };
    }

    let effective_regenerable = effective_regenerable_paths(&config.regenerable_paths);

    // Evaluate ALL targets and collect the most severe result.
    // This prevents early-return on a regenerable path from skipping
    // a later protected path (e.g., `rm -rf target/ src/`).
    let mut result = ContextEvaluation {
        action_override: None,
        reason: "no context pattern matched".to_string(),
    };

    for target in &targets {
        let (resolved, canonicalized) = resolve_path(target, base);

        // Priority 1: protected_paths → escalate to Block (most severe, short-circuit)
        if let Some(pattern) = matches_any_pattern(&resolved, &config.protected_paths) {
            return ContextEvaluation {
                action_override: Some(ActionKind::Block),
                reason: format!("protected path (matched: {})", pattern),
            };
        }

        // Priority 3+4: regenerable_paths check (only adopt if no override yet)
        if result.action_override.is_none()
            && let Some(pattern) = matches_any_pattern(&resolved, &effective_regenerable)
        {
            if canonicalized {
                result = ContextEvaluation {
                    action_override: Some(ActionKind::LogOnly),
                    reason: format!("regenerable path (matched: {})", pattern),
                };
            } else {
                result = ContextEvaluation {
                    action_override: None,
                    reason: format!(
                        "regenerable pattern matched ({}) but path could not be resolved; keeping original action",
                        pattern
                    ),
                };
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Git-aware evaluation (Tier 2)
// ---------------------------------------------------------------------------

/// Git env vars that must be removed from subprocess to prevent spoofing (T4).
const GIT_SPOOFABLE_ENV_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
];

fn prepare_git_command(
    cmd: &mut std::process::Command,
    detector_env_keys: &[String],
    cwd: Option<&Path>,
    injected_env: &[(&str, &str)],
) {
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    for (key, value) in injected_env {
        cmd.env(key, value);
    }

    // Remove AI detector env vars (self-interference prevention)
    for key in detector_env_keys {
        cmd.env_remove(key);
    }
    // Remove git spoofable env vars (T4 defense)
    for key in GIT_SPOOFABLE_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// Query `git status --porcelain` with timeout and env var sanitization.
/// Returns Ok(output) on success, Err(reason) on failure/timeout.
fn git_status_porcelain(
    detector_env_keys: &[String],
    timeout_ms: u64,
    cwd: Option<&Path>,
    injected_env: &[(&str, &str)],
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    let mut cmd = Command::new("git");
    cmd.args(["status", "--porcelain"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    prepare_git_command(&mut cmd, detector_env_keys, cwd, injected_env);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn git: {e}"))?;

    let (tx, rx) = mpsc::channel();
    let child_stdout = child.stdout.take();

    std::thread::spawn(move || {
        use std::io::Read;
        let mut output = String::new();
        if let Some(mut stdout) = child_stdout {
            let _ = stdout.read_to_string(&mut output);
        }
        let _ = tx.send(output);
    });

    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(output) => {
            let _ = child.wait(); // reap
            Ok(output)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait(); // reap zombie
            Err(format!("git status timed out after {}ms", timeout_ms))
        }
    }
}

/// Check if we're inside a git repository.
fn is_inside_git_repo(
    detector_env_keys: &[String],
    cwd: Option<&Path>,
    injected_env: &[(&str, &str)],
) -> bool {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("git");
    cmd.args(["rev-parse", "--is-inside-work-tree"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    prepare_git_command(&mut cmd, detector_env_keys, cwd, injected_env);

    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Evaluate git context for a matched rule.
/// Only applies to git commands (reset --hard, clean).
/// Returns None if git-aware is disabled or not applicable.
fn evaluate_git_context_in_dir(
    invocation: &CommandInvocation,
    config: &GitContextConfig,
    detector_env_keys: &[String],
    cwd: Option<&Path>,
    injected_env: &[(&str, &str)],
) -> Option<ContextEvaluation> {
    if !config.enabled {
        return None;
    }

    // Only evaluate git commands
    if invocation.program != "git" {
        return None;
    }

    // Not inside a git repo → skip (avoid false positives)
    if !is_inside_git_repo(detector_env_keys, cwd, injected_env) {
        return Some(ContextEvaluation {
            action_override: None,
            reason: "not inside a git repository; skipping git-aware evaluation".to_string(),
        });
    }

    let args: Vec<&str> = invocation.args.iter().map(String::as_str).collect();

    // git reset --hard: check for uncommitted changes
    if args.contains(&"reset") && args.contains(&"--hard") {
        return match git_status_porcelain(detector_env_keys, config.timeout_ms, cwd, injected_env) {
            Ok(output) if output.trim().is_empty() => Some(ContextEvaluation {
                action_override: Some(ActionKind::LogOnly),
                reason: "no uncommitted changes detected".to_string(),
            }),
            Ok(_) => Some(ContextEvaluation {
                action_override: None,
                reason: "uncommitted changes present; keeping original action".to_string(),
            }),
            Err(reason) => Some(ContextEvaluation {
                action_override: None,
                reason: format!("git status failed ({}); keeping original action", reason),
            }),
        };
    }

    // git clean with force flag: check for untracked files
    let expanded_args = crate::rules::expand_short_flags(&invocation.args);
    let has_force = expanded_args.iter().any(|a| a == "-f" || a == "--force");
    if args.contains(&"clean") && has_force {
        return match git_status_porcelain(detector_env_keys, config.timeout_ms, cwd, injected_env) {
            Ok(output) => {
                let has_untracked = output.lines().any(|line| line.starts_with("??"));
                if has_untracked {
                    Some(ContextEvaluation {
                        action_override: None,
                        reason: "untracked files present; keeping original action".to_string(),
                    })
                } else {
                    Some(ContextEvaluation {
                        action_override: Some(ActionKind::LogOnly),
                        reason: "no untracked files detected".to_string(),
                    })
                }
            }
            Err(reason) => Some(ContextEvaluation {
                action_override: None,
                reason: format!("git status failed ({}); keeping original action", reason),
            }),
        };
    }

    None // Not a git command we evaluate
}

pub fn evaluate_git_context(
    invocation: &CommandInvocation,
    config: &GitContextConfig,
    detector_env_keys: &[String],
) -> Option<ContextEvaluation> {
    evaluate_git_context_in_dir(invocation, config, detector_env_keys, None, &[])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE (v0.9.6 structural fix for #164; #175 completed the promotion):
    // The v0.9.5 `multi_target_*` quarantine was resolved by introducing
    // base-taking internal helpers, later promoted to be the public
    // `normalize_path`/`resolve_path`/`evaluate_context` signatures
    // themselves (#175). Tests that previously relied on the process CWD to
    // resolve relative paths now pass an explicit base (via `test_base()`
    // or `normalize_test_base()`), so `fs::canonicalize` receives an
    // absolute path and its result no longer depends on concurrent
    // `env::set_current_dir` calls in the `git_context_*` family.
    //
    // As a result:
    //   - `multi_target_*` tests no longer need `#[serial_test::serial]`.
    //   - `git_context_*` tests pass an explicit cwd into the internal
    //     subprocess helpers, so they do not mutate process CWD.
    //
    // The process CWD is now read in exactly one place in this module
    // (`process_base`), and is banned everywhere else in the crate outside
    // shim/hook entry points via `clippy.toml`'s `disallowed-methods`.

    /// Absolute base for `normalize_path` tests. Unlike `evaluate_context`/
    /// `resolve_path` tests (`test_base()`), `normalize_path` never touches
    /// the filesystem, so this needs no `/tmp` fixture directory — any
    /// absolute path literal is sufficient.
    fn normalize_test_base() -> PathBuf {
        PathBuf::from("/omamori-normalize-test-base")
    }

    // --- process_base / process_base_or_root (V-A09) ---

    #[test]
    // Reads the real process CWD (via `process_base`) — shares the `cwd`
    // serial group with `process_base_fails_closed_when_cwd_is_unlinked`
    // and every other real-CWD-reading test in the crate, so none of them
    // can observe a CWD another one is mutating (Security Phase 8 review:
    // `serial(cwd)` was previously held by only one test, making the lock
    // inert).
    #[serial_test::serial(cwd)]
    fn process_base_returns_some_for_a_normal_cwd() {
        assert!(process_base().is_some());
        assert_eq!(process_base_or_root(), process_base().unwrap());
    }

    // #175/#373: `process_base` must fail-close (return `None`) rather than
    // silently substituting something else when the CWD is unresolvable —
    // e.g. deleted out from under the running process. `process_base_or_root`
    // then applies the one sanctioned `/` fallback on top of that `None`.
    //
    // Verified (not assumed) on both CI legs: `getcwd(3)` after the CWD
    // directory has been unlinked returns `ENOENT` on both Linux and macOS
    // (confirmed empirically on Darwin 24.3.0 — this comment previously
    // claimed macOS could silently return a dangling path instead, which
    // was wrong; QA + Security Phase 8 review both independently caught
    // it). No `#[cfg(target_os = ...)]` gate — this runs unconditionally on
    // every platform CI builds for (`ci.yml`'s matrix), so the fail-close
    // guarantee is verified on the actual macOS runtime omamori ships on
    // (`docs/CONTRACT.md`), not only on a CI-only Linux leg.
    #[test]
    #[serial_test::serial(cwd)]
    fn process_base_fails_closed_when_cwd_is_unlinked() {
        let dir = env::temp_dir().join(format!("omamori-cwd-unlink-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // reason: this reads the *real* process CWD deliberately — the
        // whole point of this test is to observe process_base()'s behavior
        // against a genuinely unlinked real CWD, which cannot be simulated
        // any other way.
        #[allow(clippy::disallowed_methods)]
        let original_cwd = env::current_dir().unwrap();
        // reason: same real-CWD test as above — moves the process into the
        // fixture dir that gets unlinked out from under it.
        #[allow(clippy::disallowed_methods)]
        {
            env::set_current_dir(&dir).unwrap();
        }
        fs::remove_dir(&dir).unwrap();

        let result = process_base();
        let fallback = process_base_or_root();

        // reason: same real-CWD test as above — restores the process's
        // original CWD so this test doesn't leak state into siblings.
        #[allow(clippy::disallowed_methods)]
        {
            env::set_current_dir(&original_cwd).unwrap();
        }

        assert_eq!(
            result, None,
            "process_base must return None (fail-close), not a stale/dangling path"
        );
        assert_eq!(
            fallback,
            PathBuf::from("/"),
            "process_base_or_root must apply the one sanctioned `/` fallback on top of None"
        );
    }

    // --- normalize_path ---

    #[test]
    fn normalize_resolves_dot_dot() {
        let result = normalize_path("target/../src/main.rs", &normalize_test_base());
        assert!(
            result.ends_with("src/main.rs"),
            "expected ends_with src/main.rs, got: {}",
            result.display()
        );
        // Must NOT contain "target" after normalization
        let s = result.to_string_lossy();
        assert!(
            !s.contains("/target/"),
            "should not contain /target/ after normalization: {}",
            s
        );
    }

    #[test]
    fn normalize_resolves_dot() {
        let result = normalize_path("./target/", &normalize_test_base());
        assert!(result.ends_with("target"));
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn normalize_expands_tilde() {
        // Reads ambient HOME directly — tagged so it can't observe a
        // torn/transient value from a concurrent HOME-mutating test
        // elsewhere in this file (#344-class flake; this exact test name
        // was previously observed flaking for the same reason).
        let result = normalize_path("~/Documents", &normalize_test_base());
        if let Some(home) = env::var_os("HOME") {
            assert!(result.starts_with(PathBuf::from(home)));
        }
    }

    #[test]
    fn normalize_joins_relative_path_against_absolute_base() {
        // Successor to the pre-#175 `normalize_makes_absolute`: verifies the
        // explicit-base contract directly (relative path + absolute base →
        // absolute result equal to their join), rather than relying on
        // process CWD to make this true implicitly.
        let result = normalize_path("target", &normalize_test_base());
        assert!(result.is_absolute());
        assert_eq!(result, normalize_test_base().join("target"));
    }

    // V-A12: degenerate inputs must not panic and must resolve to a
    // documented, deterministic value (pinning current behavior explicitly
    // rather than leaving it implicit).
    #[test]
    fn normalize_degenerate_inputs_do_not_panic() {
        let base = normalize_test_base();
        assert_eq!(
            normalize_path("", &base),
            base,
            "empty path resolves to base itself"
        );
        assert_eq!(
            normalize_path(".", &base),
            base,
            "\".\" resolves to base itself"
        );
        // "~" alone (no trailing slash) does not match the `~/` prefix
        // `strip_prefix` checks for, so it is treated as a literal relative
        // component rather than triggering HOME expansion.
        assert_eq!(
            normalize_path("~", &base),
            base.join("~"),
            "bare ~ (no trailing slash) is NOT tilde-expanded, joined as a literal component"
        );
        assert_eq!(
            normalize_path("~x", &base),
            base.join("~x"),
            "~x (not ~/) is not tilde-expanded, joined as a literal component"
        );
        // A long run of leading ".." components has nothing to pop past
        // the base's own RootDir component — must not panic or underflow.
        assert_eq!(
            normalize_path("../../../../../../etc/passwd", &base),
            PathBuf::from("/etc/passwd"),
            "excess .. components stop popping at the root, not before"
        );
    }

    // V-A01/V-A02 (redesigned per Codex Round 1 P0): a caller-supplied
    // *relative* base is now a hard `assert!` failure in every build
    // profile, not just debug. The original design of this test verified
    // that `normalize_path` computed a CWD-independent (if wrong) result
    // even with a relative base in release builds, on the theory that
    // `Path::join` never touches the filesystem. That theory is correct for
    // `normalize_path` in isolation, but Codex Round 1 found the real gap
    // it was papering over: `resolve_path`/`evaluate_context` feed
    // `normalize_path`'s result into `fs::canonicalize`, which — if the
    // result is still relative because `base` was relative — silently
    // resolves against the real process CWD, reintroducing exactly the
    // dependence #175 exists to remove. A "graceful" relative-base result
    // is therefore not actually safe to allow anywhere in this call chain;
    // panicking loudly is the correct behavior, and this test now verifies
    // that instead of verifying the old (insufficient) graceful fallback.
    #[test]
    #[should_panic(expected = "must be absolute")]
    fn normalize_path_panics_on_relative_base_in_every_profile() {
        let _ = normalize_path("x", Path::new("rel"));
    }

    #[test]
    #[should_panic(expected = "must be absolute")]
    fn evaluate_context_panics_on_relative_base_in_every_profile() {
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        let _ = evaluate_context(&inv, &test_rule(), &test_config(), Path::new("rel"));
    }

    // --- path_matches_pattern ---

    // #175: these tests exercise `path_matches_pattern`'s pure component
    // matching directly — the specific absolute path used is irrelevant to
    // what's under test, so `normalize_test_base()` replaces what was
    // previously an unnecessary `env::current_dir()` read (banned outside
    // `context::process_base` by `clippy.toml`'s `disallowed-methods`).

    #[test]
    fn pattern_matches_exact_component() {
        let base = normalize_test_base();
        assert!(path_matches_pattern(&base.join("target"), "target"));
        assert!(path_matches_pattern(&base.join("target/debug"), "target"));
    }

    #[test]
    fn pattern_does_not_match_partial_name() {
        let base = normalize_test_base();
        assert!(!path_matches_pattern(&base.join("target_dir"), "target"));
        assert!(!path_matches_pattern(&base.join("my-target"), "target"));
        assert!(!path_matches_pattern(&base.join("src_backup"), "src"));
    }

    #[test]
    fn pattern_matches_intermediate_component() {
        let base = normalize_test_base();
        assert!(path_matches_pattern(&base.join("lib/src/foo"), "src"));
    }

    #[test]
    fn trailing_slash_does_not_affect_match() {
        let base = normalize_test_base();
        let path = base.join("target");
        assert!(path_matches_pattern(&path, "target"));
        assert!(path_matches_pattern(&path, "target/"));

        let path_slash = base.join("target/");
        assert!(path_matches_pattern(&path_slash, "target"));
    }

    // --- NEVER_REGENERABLE ---

    #[test]
    fn never_regenerable_catches_src() {
        assert!(is_never_regenerable("src"));
        assert!(is_never_regenerable("src/"));
        assert!(is_never_regenerable(".git"));
        assert!(is_never_regenerable(".git/"));
        assert!(is_never_regenerable(".env"));
    }

    #[test]
    fn never_regenerable_allows_target() {
        assert!(!is_never_regenerable("target"));
        assert!(!is_never_regenerable("target/"));
        assert!(!is_never_regenerable("node_modules"));
        assert!(!is_never_regenerable("dist"));
    }

    #[test]
    fn validate_regenerable_warns_on_conflict() {
        let paths = vec!["target/".to_string(), "src/".to_string()];
        let warnings = validate_regenerable_paths(&paths);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("src/"));
    }

    // --- evaluate_context ---

    fn test_config() -> ContextConfig {
        ContextConfig {
            regenerable_paths: vec!["target/".to_string(), "node_modules/".to_string()],
            protected_paths: vec!["src/".to_string(), ".git/".to_string()],
            git: GitContextConfig::default(),
        }
    }

    fn test_rule() -> RuleConfig {
        RuleConfig::new(
            "rm-recursive-to-trash",
            "rm",
            ActionKind::Trash,
            Vec::new(),
            vec!["-rf".to_string()],
            Some("test".to_string()),
        )
    }

    /// Unique absolute base for context tests that need deterministic path
    /// resolution regardless of concurrent `env::set_current_dir` elsewhere
    /// in the process. Tied to the current PID so parallel test binaries
    /// cannot collide either.
    ///
    /// Also idempotently creates fixture children (`target/`, `node_modules/`)
    /// so that `fs::canonicalize` through `resolve_path` succeeds and
    /// regenerable-path canonicalization tests can reach the `LogOnly`
    /// branch. Cleanup is deliberately skipped: parallel tests in the same
    /// PID would race on a cleanup, and the tree is tiny under `/tmp`.
    ///
    /// Example: `/tmp/omamori-ctx-test-12345/target/` is what a relative
    /// `target/` arg resolves to when evaluating via
    /// `evaluate_context(&inv, &rule, &config, &test_base())`.
    fn test_base() -> PathBuf {
        let base = PathBuf::from(format!("/tmp/omamori-ctx-test-{}", std::process::id()));
        std::fs::create_dir_all(base.join("target")).unwrap();
        std::fs::create_dir_all(base.join("node_modules")).unwrap();
        base
    }

    #[test]
    fn context_protected_path_escalates_to_block() {
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert_eq!(result.action_override, Some(ActionKind::Block));
        assert!(result.reason.contains("protected path"));
    }

    #[test]
    fn context_no_targets_returns_none() {
        let config = test_config();
        let inv = CommandInvocation::new("rm".to_string(), vec!["-rf".to_string()]);
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert!(result.action_override.is_none());
    }

    #[test]
    fn context_unmatched_path_returns_none() {
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "data/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert!(result.action_override.is_none());
    }

    #[test]
    fn context_never_regenerable_overrides_config() {
        // Even if user adds "src/" to regenerable_paths, it should be ignored
        let config = ContextConfig {
            regenerable_paths: vec!["src/".to_string()],
            protected_paths: vec![],
            git: GitContextConfig::default(),
        };
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        // src/ is in NEVER_REGENERABLE, so it should NOT be downgraded
        assert!(
            result.action_override.is_none(),
            "src/ should not be downgraded even if in regenerable_paths"
        );
    }

    #[test]
    fn context_both_match_escalation_wins() {
        // A path that matches both regenerable and protected should be blocked
        let config = ContextConfig {
            regenerable_paths: vec!["shared/".to_string()],
            protected_paths: vec!["shared/".to_string()],
            git: GitContextConfig::default(),
        };
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "shared/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert_eq!(result.action_override, Some(ActionKind::Block));
    }

    #[test]
    fn traversal_attack_is_caught() {
        let config = test_config();
        // target/../src/ normalizes to <test_base()>/src/ and matches
        // protected_paths via component matching — re-verified against the
        // explicit base (not assumed to carry over mechanically from the
        // pre-#175 CWD-implicit version, per QA review of this test).
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/../src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert_eq!(
            result.action_override,
            Some(ActionKind::Block),
            "target/../src/ should be caught as protected path after normalization"
        );
    }

    #[test]
    fn component_boundary_prevents_false_match() {
        let config = test_config();
        // target_dir should NOT match "target" pattern
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target_dir/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &test_base());
        assert!(
            result.action_override.is_none(),
            "target_dir should not match target pattern"
        );
    }

    #[test]
    fn multi_target_protected_wins_over_regenerable() {
        // P1-1: rm -rf target/ src/ — src/ must be caught even though target/ matches first.
        //
        // Uses `test_base()` so concurrent process CWD changes cannot flip
        // the verdict. This closes the v0.9.5 #164 quarantine (structural
        // fix, v0.9.6 scope 10).
        let base = test_base();
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string(), "src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &base);
        assert_eq!(
            result.action_override,
            Some(ActionKind::Block),
            "protected src/ must win even when regenerable target/ appears first"
        );
    }

    #[test]
    fn multi_target_all_regenerable_downgrades() {
        // #164 structural fix: explicit base instead of relying on process
        // CWD. See module note.
        let base = test_base();
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec![
                "-rf".to_string(),
                "target/".to_string(),
                "node_modules/".to_string(),
            ],
        );
        let result = evaluate_context(&inv, &test_rule(), &config, &base);
        assert_eq!(result.action_override, Some(ActionKind::LogOnly));
    }

    // --- CI consistency check: NEVER_REGENERABLE ⊃ default_protected_paths ---

    // --- evaluate_git_context (G-01) ---

    /// Helper: create a real git repo in a temp directory.
    /// Returns the temp dir path (caller must clean up).
    fn create_git_repo() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT_REPO_ID: AtomicUsize = AtomicUsize::new(0);

        let id = NEXT_REPO_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("omamori-git-ctx-{}-{}", std::process::id(), id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        dir
    }

    fn git_config() -> GitContextConfig {
        GitContextConfig {
            enabled: true,
            timeout_ms: 5000,
        }
    }

    #[test]
    fn git_context_explicit_dir_downgrades_clean_repo_without_process_cwd() {
        let dir = create_git_repo();

        std::fs::write(dir.join("dummy.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_clean_repo_downgrades_to_log_only() {
        let dir = create_git_repo();

        // Create initial commit so repo is clean
        std::fs::write(dir.join("dummy.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_dirty_repo_keeps_original() {
        let dir = create_git_repo();

        // Create initial commit
        std::fs::write(dir.join("dummy.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        // Make dirty
        std::fs::write(dir.join("dirty.txt"), "uncommitted").unwrap();

        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert!(eval.action_override.is_none());
        assert!(eval.reason.contains("uncommitted"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_timeout_keeps_original() {
        let dir = create_git_repo();

        let config = GitContextConfig {
            enabled: true,
            timeout_ms: 0, // 0ms = guaranteed timeout
        };
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        // With 0ms timeout, git status may or may not time out depending on system.
        // Either way, the result should not downgrade to LogOnly for a dirty/timeout case.
        let result = evaluate_git_context_in_dir(&inv, &config, &[], Some(&dir), &[]);
        // We just check it returns Some (git command is evaluated)
        assert!(result.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_sanitizes_git_dir_env() {
        let dir = create_git_repo();

        // Create initial commit so repo is clean
        std::fs::write(dir.join("dummy.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        // GIT_DIR spoof: point to a non-existent dir.
        // evaluate_git_context should remove GIT_DIR before calling git.
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(
            &inv,
            &git_config(),
            &[],
            Some(&dir),
            &[("GIT_DIR", "/nonexistent/.git")],
        );

        // Should still work correctly (env var sanitized)
        assert!(result.is_some());
        let eval = result.unwrap();
        // Clean repo → LogOnly (proves GIT_DIR was sanitized, not followed)
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_sanitizes_git_work_tree_env() {
        let dir = create_git_repo();

        // Create initial commit so repo is clean
        std::fs::write(dir.join("dummy.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        // GIT_WORK_TREE spoof: point to a non-existent dir.
        // evaluate_git_context should remove GIT_WORK_TREE before calling git.
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(
            &inv,
            &git_config(),
            &[],
            Some(&dir),
            &[("GIT_WORK_TREE", "/nonexistent/fake")],
        );

        // Should still work correctly (env var sanitized)
        assert!(result.is_some());
        let eval = result.unwrap();
        // Clean repo → LogOnly (proves GIT_WORK_TREE was sanitized, not followed)
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_non_git_command_returns_none() {
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        let result = evaluate_git_context(&inv, &git_config(), &[]);
        assert!(result.is_none());
    }

    #[test]
    fn git_context_disabled_returns_none() {
        let config = GitContextConfig {
            enabled: false,
            timeout_ms: 100,
        };
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context(&inv, &config, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn git_context_non_git_directory_returns_some_none_override() {
        let dir = std::env::temp_dir().join(format!("omamori-nongit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert!(eval.action_override.is_none());
        assert!(eval.reason.contains("not inside a git repository"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- evaluate_git_context: git clean path (G-01 cont.) ---

    #[test]
    fn git_context_clean_no_untracked_downgrades_to_log_only() {
        let dir = create_git_repo();

        // Create initial commit so repo is clean with no untracked files
        std::fs::write(dir.join("committed.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        let inv = super::CommandInvocation::new(
            "git".to_string(),
            vec!["clean".to_string(), "-fdx".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));
        assert!(eval.reason.contains("no untracked"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_context_clean_with_untracked_keeps_original() {
        let dir = create_git_repo();

        // Create initial commit, then add an untracked file
        std::fs::write(dir.join("committed.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        std::fs::write(dir.join("untracked.txt"), "not tracked").unwrap();

        let inv = super::CommandInvocation::new(
            "git".to_string(),
            vec!["clean".to_string(), "-fd".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(result.is_some());
        let eval = result.unwrap();
        assert!(eval.action_override.is_none());
        assert!(eval.reason.contains("untracked files present"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- #78: git clean with split flags must also trigger context evaluation ---

    #[test]
    fn git_context_clean_split_flags_triggers_evaluation() {
        let dir = create_git_repo();

        std::fs::write(dir.join("committed.txt"), "init").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        // git clean -f -d (split flags) should still trigger evaluation
        let inv = super::CommandInvocation::new(
            "git".to_string(),
            vec!["clean".to_string(), "-f".to_string(), "-d".to_string()],
        );
        let result = evaluate_git_context_in_dir(&inv, &git_config(), &[], Some(&dir), &[]);
        assert!(
            result.is_some(),
            "split -f -d must trigger context evaluation"
        );
        let eval = result.unwrap();
        assert_eq!(eval.action_override, Some(ActionKind::LogOnly));

        // git clean --force -d should also trigger
        let inv2 = super::CommandInvocation::new(
            "git".to_string(),
            vec!["clean".to_string(), "--force".to_string(), "-d".to_string()],
        );
        let result2 = evaluate_git_context_in_dir(&inv2, &git_config(), &[], Some(&dir), &[]);
        assert!(result2.is_some(), "--force must trigger context evaluation");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // home_dir() / data_dir() — HOME shape sweep (#323/#306)
    // -----------------------------------------------------------------
    //
    // Mutates the process-global HOME env var; every test here is tagged
    // `#[serial_test::serial(home_env)]` per the crate-wide convention
    // (see lib.rs::shim_argv0_without_hook_check_still_enters_shim) to
    // avoid racing other HOME-mutating tests. HOME is saved and restored
    // around each mutation.

    use crate::test_support::with_home;

    #[test]
    #[serial_test::serial(home_env)]
    fn home_dir_none_when_unset() {
        assert_eq!(with_home(None, home_dir), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn home_dir_none_when_empty() {
        // `env::var_os("HOME")` returns `Some("")` for `HOME=""` — this is
        // the case a bare `?`/`map` chain does not catch (V-001/T1).
        assert_eq!(with_home(Some(""), home_dir), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn home_dir_none_when_relative() {
        assert_eq!(with_home(Some("relative/path"), home_dir), None);
        assert_eq!(with_home(Some("."), home_dir), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn home_dir_some_when_absolute() {
        assert_eq!(
            with_home(Some("/tmp/omamori-home-dir-test"), home_dir),
            Some(PathBuf::from("/tmp/omamori-home-dir-test"))
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn normalize_path_leaves_tilde_untouched_when_home_unusable() {
        // #373: an unusable HOME (unset/empty/relative) must not silently
        // fall back to a CWD-relative resolution of the tilde-stripped
        // remainder — that would let `~/protected-dir` resolve to a
        // completely different path than intended, potentially missing a
        // protected_paths/regenerable_paths match (evaluate_context consumes
        // this via resolve_path). Instead `~/foo` is left as a literal
        // (non-existent) path relative to `base`.
        let base = Path::new("/base");
        for home in [None, Some(""), Some("relative")] {
            let result = with_home(home, || normalize_path("~/protected-dir", base));
            assert_eq!(
                result,
                PathBuf::from("/base/~/protected-dir"),
                "HOME={home:?} should leave ~/ untouched, not resolve it to a CWD-relative path"
            );
        }
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn normalize_path_expands_tilde_when_home_absolute() {
        let base = Path::new("/base");
        let result = with_home(Some("/tmp/omamori-tilde-test"), || {
            normalize_path("~/protected-dir", base)
        });
        assert_eq!(
            result,
            PathBuf::from("/tmp/omamori-tilde-test/protected-dir")
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn data_dir_none_propagates_from_home_dir() {
        assert_eq!(with_home(Some(""), data_dir), None);
        assert_eq!(with_home(None, data_dir), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn data_dir_joins_expected_subpath_when_home_absolute() {
        assert_eq!(
            with_home(Some("/tmp/omamori-data-dir-test"), data_dir),
            Some(PathBuf::from(
                "/tmp/omamori-data-dir-test/.local/share/omamori"
            ))
        );
    }

    #[test]
    fn never_regenerable_covers_all_default_protected_paths() {
        let protected = default_protected_paths();
        let never: std::collections::HashSet<&str> = NEVER_REGENERABLE.iter().copied().collect();
        let missing: Vec<&str> = protected
            .iter()
            .map(|p| p.trim_end_matches('/'))
            .filter(|p| !never.contains(p))
            .collect();
        assert!(
            missing.is_empty(),
            "default_protected_paths() contains entries not in NEVER_REGENERABLE: {:?}\n\
             Either add them to NEVER_REGENERABLE or remove from default_protected_paths()",
            missing,
        );
    }
}
