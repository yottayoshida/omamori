//! Hook integration tests for v0.9.4 (#121).
//!
//! Spawns the installed hook script via `/bin/sh` with PATH injection so the
//! `omamori` binary in the generated shim dir is resolved at runtime. The
//! assertions compare only a coarse `Decision` enum (Allow / Block) — the
//! specific rule name or regex that caused the decision is intentionally kept
//! out of assertion strings so that test failures in CI logs do not leak
//! bypass-learning material (see SECURITY.md T11 mitigation).
//!
//! Category coverage (table-driven corpus):
//!   1. allow baseline
//!   2. direct-path bypass block
//!   3. env tampering block
//!   4. compound command block
//!   5. false-positive guard allow
//!   6. malformed stdin fail-close (separate test — different input shape)
//!   7. empty stdin behavior pin (separate test — different input shape)

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_omamori"))
}

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("omamori-hookint-{name}-{nanos}"))
}

/// Install omamori hooks into a fresh temp dir and return
/// (base_dir, hook_path, shim_dir).
fn setup_hook_env(case: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = unique_dir(case);
    let output = Command::new(binary())
        .arg("install")
        .arg("--base-dir")
        .arg(&base)
        .arg("--source")
        .arg(binary())
        .arg("--hooks")
        .output()
        .expect("failed to run omamori install");
    assert!(
        output.status.success(),
        "install failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hook_path = base.join("hooks/claude-pretooluse.sh");
    let shim_dir = base.join("shim");
    assert!(hook_path.exists(), "hook script not generated");
    assert!(shim_dir.exists(), "shim dir not generated");
    (base, hook_path, shim_dir)
}

/// Spawn the hook script via `/bin/sh` with two dirs prepended to PATH:
///   1. `shim_dir` — the installed shim path (rm/git/chmod/find/rsync symlinks).
///   2. `binary_dir` — the parent of the compiled test binary, so the wrapper's
///      bare `omamori hook-check` call resolves to *this* build. Without this,
///      a stale or missing `omamori` on the host PATH would silently change
///      behavior (CI fresh runners have no global install, so the shell would
///      otherwise fail with "command not found" and exit non-zero, making
///      every Allow-case look like Block).
fn run_hook_script(hook_path: &Path, shim_dir: &Path, input: &str) -> (String, String, i32) {
    let current_path = std::env::var("PATH").unwrap_or_default();
    let binary_dir = binary()
        .parent()
        .expect("omamori binary must have a parent dir")
        .to_path_buf();
    let injected_path = format!(
        "{}:{}:{}",
        shim_dir.display(),
        binary_dir.display(),
        current_path
    );

    let mut child = Command::new("/bin/sh")
        .arg(hook_path)
        .env("PATH", injected_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn /bin/sh hook_script");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn pretooluse_bash_json(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

#[derive(Debug, PartialEq)]
enum Decision {
    Allow,
    Block,
}

/// Map a hook-check exit code to the coarse decision enum.
///
/// Contract (from `omamori hook-check`):
///   exit 0 = allow (with hookSpecificOutput JSON on stdout)
///   exit 2 = block
///   other non-zero = fail-close (treated as Block here)
fn decision_from_exit(exit: i32) -> Decision {
    if exit == 0 {
        Decision::Allow
    } else {
        Decision::Block
    }
}

/// Corpus: (bash_command, expected_decision, category_label).
/// The `category_label` is used in assertion messages only — never a rule
/// name or regex (T11 mitigation).
const HOOK_DECISION_CASES: &[(&str, Decision, &str)] = &[
    // 1. allow baseline — typical safe command
    ("echo hello", Decision::Allow, "allow-baseline"),
    // 2. direct-path bypass — absolute path that bypasses PATH shim
    (
        "/bin/rm -rf /tmp/x",
        Decision::Block,
        "direct-path-bypass-block",
    ),
    // 3. env tampering — disable AI env detection variable
    (
        "unset CLAUDECODE && echo ok",
        Decision::Block,
        "env-tampering-block",
    ),
    // 4. compound command — semicolon separator hides dangerous tail
    (
        "echo ok;unset CLAUDECODE",
        Decision::Block,
        "compound-command-block",
    ),
    // 5. false-positive guard — text containing "unset" but not executing it
    (
        "printf 'unset CLAUDECODE'",
        Decision::Allow,
        "false-positive-guard-allow",
    ),
];

/// Cross-OS invariant: the same bash input must yield the same Decision on
/// every supported OS. Runs the entire corpus in one temp env to keep install
/// cost at one-per-test.
#[test]
fn hook_script_cross_os_invariant() {
    let (base, hook_path, shim_dir) = setup_hook_env("invariant");

    for (cmd, expected, category) in HOOK_DECISION_CASES {
        let json = pretooluse_bash_json(cmd);
        let (_, _, exit) = run_hook_script(&hook_path, &shim_dir, &json);
        let actual = decision_from_exit(exit);
        assert_eq!(
            &actual, expected,
            "hook decision divergence in category '{category}' (details redacted for T11)"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// Invariant: the corpus must include at least one Allow and one Block case.
/// If a future refactor accidentally removes one side, this test fails — a
/// complement to the structural invariant enforced by `check-invariants.sh`
/// (landing in PR2b).
#[test]
fn corpus_includes_both_decisions() {
    let has_allow = HOOK_DECISION_CASES
        .iter()
        .any(|(_, d, _)| *d == Decision::Allow);
    let has_block = HOOK_DECISION_CASES
        .iter()
        .any(|(_, d, _)| *d == Decision::Block);
    assert!(has_allow, "corpus must include at least one Allow case");
    assert!(has_block, "corpus must include at least one Block case");
}

/// Fail-close on malformed JSON stdin. The hook script feeds stdin as-is to
/// `omamori hook-check`, which must not treat an invalid payload as Allow.
#[test]
fn hook_script_malformed_json_is_not_allow() {
    let (base, hook_path, shim_dir) = setup_hook_env("malformed");
    let (_, _, exit) = run_hook_script(&hook_path, &shim_dir, "{not valid json");
    let _ = std::fs::remove_dir_all(&base);
    let decision = decision_from_exit(exit);
    assert_eq!(
        decision,
        Decision::Block,
        "malformed JSON must not produce Allow (fail-close)"
    );
}

/// Fail-close on empty stdin. Distinct from V-006 in tests/cli.rs, which
/// pins an empty *command* (a well-formed JSON payload with `command: ""`)
/// as Allow. An empty *stdin* here provides no payload at all, which the
/// hook layer treats as malformed and must not accept as Allow.
#[test]
fn hook_script_empty_stdin_is_not_allow() {
    let (base, hook_path, shim_dir) = setup_hook_env("empty");
    let (_, _, exit) = run_hook_script(&hook_path, &shim_dir, "");
    let _ = std::fs::remove_dir_all(&base);
    let decision = decision_from_exit(exit);
    assert_eq!(
        decision,
        Decision::Block,
        "empty stdin must fail-close (no payload = malformed)"
    );
}
