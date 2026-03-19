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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitContextConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for GitContextConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_timeout_ms() -> u64 {
    100
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

/// Lexical path normalization: expand ~, resolve relative paths, remove . and ..
/// Does NOT access the filesystem (no symlink resolution).
pub fn normalize_path(path: &str) -> PathBuf {
    // Step 1: ~ expansion
    let path = if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            PathBuf::from(home).join(rest)
        } else {
            PathBuf::from(path)
        }
    } else {
        PathBuf::from(path)
    };

    // Step 2: relative → absolute (based on CWD)
    let path = if path.is_relative() {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(&path)
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

/// Try to resolve the real path (symlinks included) via canonicalize().
/// Returns Ok(canonical) if the path exists, Err(lexical) if it doesn't.
pub fn resolve_path(raw: &str) -> (PathBuf, bool) {
    let lexical = normalize_path(raw);
    match fs::canonicalize(raw) {
        Ok(canonical) => (canonical, true),
        Err(_) => (lexical, false),
    }
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

/// Evaluate context for a matched rule and return an optional action override.
///
/// Evaluation priority (highest first):
/// 1. protected_paths match → escalate to Block
/// 2. NEVER_REGENERABLE match → ignore regenerable config, keep original
/// 3. regenerable_paths match AND canonicalize succeeded → downgrade to LogOnly
/// 4. regenerable_paths match AND canonicalize failed → no downgrade (fail-close)
/// 5. No match → keep original
pub fn evaluate_context(
    invocation: &CommandInvocation,
    _rule: &RuleConfig,
    config: &ContextConfig,
) -> ContextEvaluation {
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
        let (resolved, canonicalized) = resolve_path(target);

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

/// Query `git status --porcelain` with timeout and env var sanitization.
/// Returns Ok(output) on success, Err(reason) on failure/timeout.
fn git_status_porcelain(detector_env_keys: &[String], timeout_ms: u64) -> Result<String, String> {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    let mut cmd = Command::new("git");
    cmd.args(["status", "--porcelain"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    // Remove AI detector env vars (self-interference prevention)
    for key in detector_env_keys {
        cmd.env_remove(key);
    }
    // Remove git spoofable env vars (T4 defense)
    for key in GIT_SPOOFABLE_ENV_VARS {
        cmd.env_remove(key);
    }

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
fn is_inside_git_repo(detector_env_keys: &[String]) -> bool {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("git");
    cmd.args(["rev-parse", "--is-inside-work-tree"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    for key in detector_env_keys {
        cmd.env_remove(key);
    }
    for key in GIT_SPOOFABLE_ENV_VARS {
        cmd.env_remove(key);
    }

    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Evaluate git context for a matched rule.
/// Only applies to git commands (reset --hard, clean).
/// Returns None if git-aware is disabled or not applicable.
pub fn evaluate_git_context(
    invocation: &CommandInvocation,
    config: &GitContextConfig,
    detector_env_keys: &[String],
) -> Option<ContextEvaluation> {
    if !config.enabled {
        return None;
    }

    // Only evaluate git commands
    if invocation.program != "git" {
        return None;
    }

    // Not inside a git repo → skip (avoid false positives)
    if !is_inside_git_repo(detector_env_keys) {
        return Some(ContextEvaluation {
            action_override: None,
            reason: "not inside a git repository; skipping git-aware evaluation".to_string(),
        });
    }

    let args: Vec<&str> = invocation.args.iter().map(String::as_str).collect();

    // git reset --hard: check for uncommitted changes
    if args.contains(&"reset") && args.contains(&"--hard") {
        return match git_status_porcelain(detector_env_keys, config.timeout_ms) {
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

    // git clean -fd/-fdx: check for untracked files
    if args.contains(&"clean") && (args.contains(&"-fd") || args.contains(&"-fdx")) {
        return match git_status_porcelain(detector_env_keys, config.timeout_ms) {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- normalize_path ---

    #[test]
    fn normalize_resolves_dot_dot() {
        let result = normalize_path("target/../src/main.rs");
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
        let result = normalize_path("./target/");
        assert!(result.ends_with("target"));
    }

    #[test]
    fn normalize_expands_tilde() {
        let result = normalize_path("~/Documents");
        if let Some(home) = env::var_os("HOME") {
            assert!(result.starts_with(PathBuf::from(home)));
        }
    }

    #[test]
    fn normalize_makes_absolute() {
        let result = normalize_path("target");
        assert!(result.is_absolute());
    }

    // --- path_matches_pattern ---

    #[test]
    fn pattern_matches_exact_component() {
        let cwd = env::current_dir().unwrap();
        assert!(path_matches_pattern(&cwd.join("target"), "target"));
        assert!(path_matches_pattern(&cwd.join("target/debug"), "target"));
    }

    #[test]
    fn pattern_does_not_match_partial_name() {
        let cwd = env::current_dir().unwrap();
        assert!(!path_matches_pattern(&cwd.join("target_dir"), "target"));
        assert!(!path_matches_pattern(&cwd.join("my-target"), "target"));
        assert!(!path_matches_pattern(&cwd.join("src_backup"), "src"));
    }

    #[test]
    fn pattern_matches_intermediate_component() {
        let cwd = env::current_dir().unwrap();
        assert!(path_matches_pattern(&cwd.join("lib/src/foo"), "src"));
    }

    #[test]
    fn trailing_slash_does_not_affect_match() {
        let cwd = env::current_dir().unwrap();
        let path = cwd.join("target");
        assert!(path_matches_pattern(&path, "target"));
        assert!(path_matches_pattern(&path, "target/"));

        let path_slash = cwd.join("target/");
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

    #[test]
    fn context_protected_path_escalates_to_block() {
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert_eq!(result.action_override, Some(ActionKind::Block));
        assert!(result.reason.contains("protected path"));
    }

    #[test]
    fn context_no_targets_returns_none() {
        let config = test_config();
        let inv = CommandInvocation::new("rm".to_string(), vec!["-rf".to_string()]);
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert!(result.action_override.is_none());
    }

    #[test]
    fn context_unmatched_path_returns_none() {
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "data/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config);
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
        let result = evaluate_context(&inv, &test_rule(), &config);
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
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert_eq!(result.action_override, Some(ActionKind::Block));
    }

    #[test]
    fn traversal_attack_is_caught() {
        let config = test_config();
        // target/../src/ should normalize to CWD/src/ and match protected_paths
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/../src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config);
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
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert!(
            result.action_override.is_none(),
            "target_dir should not match target pattern"
        );
    }

    #[test]
    fn multi_target_protected_wins_over_regenerable() {
        // P1-1: rm -rf target/ src/ — src/ must be caught even though target/ matches first
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string(), "src/".to_string()],
        );
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert_eq!(
            result.action_override,
            Some(ActionKind::Block),
            "protected src/ must win even when regenerable target/ appears first"
        );
    }

    #[test]
    fn multi_target_all_regenerable_downgrades() {
        let config = test_config();
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec![
                "-rf".to_string(),
                "target/".to_string(),
                "node_modules/".to_string(),
            ],
        );
        let result = evaluate_context(&inv, &test_rule(), &config);
        assert_eq!(result.action_override, Some(ActionKind::LogOnly));
    }

    // --- CI consistency check: NEVER_REGENERABLE ⊃ default_protected_paths ---

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
