use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("omamori-{name}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("omamori-{name}-{nanos}.toml"))
}

fn binary() -> String {
    env!("CARGO_BIN_EXE_omamori").to_string()
}

/// Remove all AI detector env vars from a Command to prevent
/// guard_ai_config_modification() from blocking during tests.
fn clean_ai_env(cmd: &mut Command) -> &mut Command {
    cmd.env_remove("CLAUDECODE")
        .env_remove("CODEX_CI")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env_remove("CLINE_ACTIVE")
        .env_remove("AI_GUARD")
}

/// `omamori install --base-dir <base_dir> --source <this test binary> --hooks
/// --env HOME=<home> --env XDG_CONFIG_HOME=<home>/.config`, asserting success.
/// Shared by the Batch C PR-C1 doctor tests, which each need an identical
/// real install before exercising `doctor`/`doctor --fix` (/code-review
/// finding: this 12-line block was copy-pasted 3 times). `XDG_CONFIG_HOME`
/// is pinned alongside `HOME` — CI runners can have it set ambiently, which
/// would make `default_config_path()` resolve outside `home` entirely,
/// silently missing any config.toml a test plants there (caught by CI: the
/// initial version of this helper omitted this and passed locally but
/// failed on both CI runners, matching the isolation convention every other
/// config-touching test in this file already follows).
fn install_with_hooks(base_dir: &std::path::Path, home: &std::path::Path) {
    let mut install_cmd = Command::new(binary());
    clean_ai_env(&mut install_cmd);
    let install = install_cmd
        .arg("install")
        .arg("--base-dir")
        .arg(base_dir)
        .arg("--source")
        .arg(binary())
        .arg("--hooks")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori install");
    assert!(
        install.status.success(),
        "install should succeed. stderr: {}",
        String::from_utf8_lossy(&install.stderr)
    );
}

/// Writes a `config.toml` with a relative `[audit] path` under `config_dir`
/// (created if missing) and chmods it 0600. Shared by #439's relative-
/// audit-path tests (`/simplify` finding: this 7-line block was copy-pasted
/// across 4 tests; mirrors this file's own `install_with_hooks` precedent
/// for de-duplicating a repeated setup block).
fn write_relative_audit_path_config(config_dir: &std::path::Path) {
    fs::create_dir_all(config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(
        &config_path,
        "[audit]\nenabled = true\npath = \"audit.jsonl\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn omamori_test_command_succeeds_with_defaults() {
    let output = Command::new(binary())
        .arg("test")
        .output()
        .expect("failed to run omamori test");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("detection tests passed"),
        "stdout: {stdout}"
    );
}

#[test]
fn malformed_config_falls_back_to_defaults() {
    let path = unique_path("broken");
    fs::write(&path, "[[rules]\nname = ").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(binary())
        .arg("test")
        .arg("--config")
        .arg(&path)
        .output()
        .expect("failed to run omamori test");

    let _ = fs::remove_file(&path);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Built-in default rules are active"),
        "stderr should contain actionable warning: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// init tests
// ---------------------------------------------------------------------------

#[test]
fn init_stdout_mode_prints_template() {
    let output = Command::new(binary())
        .args(["init", "--stdout"])
        .output()
        .expect("failed to run omamori init --stdout");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# omamori config"));
    assert!(stdout.contains("rm-recursive-to-trash"));
    assert!(stdout.contains("git-push-force-block"));
}

#[test]
fn init_creates_config_file() {
    let dir = unique_dir("init-create");
    let config_path = dir.join("omamori").join("config.toml");

    let output = Command::new(binary())
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");

    assert!(
        output.status.success(),
        "exit={} stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(config_path.exists(), "config.toml should be created");

    // Verify content is the commented template
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("# omamori config"));
    assert!(content.contains("# [[rules]]"));
    // Should NOT contain uncommented [[rules]] (T4 safety)
    assert!(
        !content
            .lines()
            .any(|l| l.trim_start().starts_with("[[rules]]")),
        "config should have all rules commented out"
    );

    // Verify permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(&config_path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "config should be chmod 600, got {mode:o}");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn init_refuses_overwrite_without_force() {
    let dir = unique_dir("init-noforce");
    let config_dir = dir.join("omamori");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "# existing config\n").unwrap();

    let output = Command::new(binary())
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");

    // Should exit with code 2
    assert_eq!(output.status.code(), Some(2));

    // Existing file should be unchanged
    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, "# existing config\n");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn init_force_overwrites_existing() {
    let dir = unique_dir("init-force");
    let config_dir = dir.join("omamori");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "# old config\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["init", "--force"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init --force");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("# omamori config"),
        "should be new template"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn init_refuses_symlink_target() {
    let dir = unique_dir("init-symlink");
    let config_dir = dir.join("omamori");
    fs::create_dir_all(&config_dir).unwrap();

    let real_file = dir.join("real.toml");
    fs::write(&real_file, "# real\n").unwrap();

    let config_path = config_dir.join("config.toml");
    std::os::unix::fs::symlink(&real_file, &config_path).unwrap();

    let output = Command::new(binary())
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("symlink"),
        "should mention symlink: {stderr}"
    );

    // Real file should be unchanged
    let content = fs::read_to_string(&real_file).unwrap();
    assert_eq!(content, "# real\n");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn init_refuses_symlinked_parent_directory() {
    let dir = unique_dir("init-symlink-dir");
    let real_dir = dir.join("real_omamori");
    fs::create_dir_all(&real_dir).unwrap();

    // Make "omamori" a symlink to "real_omamori"
    let symlink_dir = dir.join("omamori");
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let output = Command::new(binary())
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("symlink"),
        "should mention symlink: {stderr}"
    );

    // No config.toml should be created in real_dir
    assert!(!real_dir.join("config.toml").exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn init_fails_without_home_and_xdg() {
    let output = Command::new(binary())
        .args(["init"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("XDG_CONFIG_HOME") || stderr.contains("HOME"),
        "should mention missing env: {stderr}"
    );
}

#[test]
fn init_written_config_loads_correctly() {
    let dir = unique_dir("init-roundtrip");
    let config_path = dir.join("omamori").join("config.toml");

    // Create config via init
    let output = Command::new(binary())
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");
    assert!(output.status.success());

    // Use the created config with omamori test
    let output = Command::new(binary())
        .args(["test", "--config"])
        .arg(&config_path)
        .output()
        .expect("failed to run omamori test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("detection tests passed"));

    // Should have no warnings (config exists and is valid)
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("warning"),
        "should have no warnings: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// warning message tests
// ---------------------------------------------------------------------------

#[test]
fn warning_config_not_found_is_actionable() {
    let nonexistent = unique_path("nonexistent");
    let output = Command::new(binary())
        .args(["test", "--config"])
        .arg(&nonexistent)
        .output()
        .expect("failed to run omamori test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("config not found"));
    assert!(
        stderr.contains("omamori init"),
        "warning should suggest omamori init: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn warning_bad_permissions_is_actionable() {
    let path = unique_path("badperms");
    fs::write(&path, "# ok\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let output = Command::new(binary())
        .args(["test", "--config"])
        .arg(&path)
        .output()
        .expect("failed to run omamori test");

    let _ = fs::remove_file(&path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("permissions are too open"));
    assert!(
        stderr.contains("chmod 600"),
        "warning should suggest chmod 600: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// cursor-hook tests
// ---------------------------------------------------------------------------

use std::io::Write;
use std::process::Stdio;

fn run_cursor_hook(input: &str) -> (String, String, bool) {
    let mut child = Command::new(binary())
        .args(["cursor-hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cursor-hook");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

#[test]
fn cursor_hook_blocks_bin_rm() {
    let (stdout, _, success) = run_cursor_hook(
        r#"{"command":"/bin/rm -rf /tmp/test","cwd":"/tmp","hook_event_name":"beforeShellExecution"}"#,
    );
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
    assert!(parsed["userMessage"].as_str().unwrap().contains("omamori"));
}

#[test]
fn cursor_hook_allows_safe_command() {
    let (stdout, _, success) = run_cursor_hook(
        r#"{"command":"ls /tmp","cwd":"/tmp","hook_event_name":"beforeShellExecution"}"#,
    );
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow");
}

#[test]
fn cursor_hook_blocks_env_unset() {
    let (stdout, _, success) = run_cursor_hook(
        r#"{"command":"unset CLAUDECODE && rm -rf /","cwd":"/tmp","hook_event_name":"beforeShellExecution"}"#,
    );
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

#[test]
fn cursor_hook_stdout_is_json_only() {
    let (stdout, _, _) = run_cursor_hook(
        r#"{"command":"echo hello","cwd":"/tmp","hook_event_name":"beforeShellExecution"}"#,
    );
    let trimmed = stdout.trim();
    assert!(
        serde_json::from_str::<serde_json::Value>(trimmed).is_ok(),
        "stdout must be valid JSON only, got: {trimmed}"
    );
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stdout must be exactly one JSON line, got: {trimmed}"
    );
}

#[test]
fn cursor_hook_denies_malformed_stdin() {
    let (stdout, _, success) = run_cursor_hook("not json at all");
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON even on bad input");
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

#[test]
fn cursor_hook_denies_null_command() {
    let (stdout, _, success) = run_cursor_hook(r#"{"command":null,"cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

#[test]
fn cursor_hook_denies_missing_command_key() {
    let (stdout, _, success) = run_cursor_hook(r#"{"foo":"bar","cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

#[test]
fn cursor_hook_allows_empty_command() {
    let (stdout, _, success) = run_cursor_hook(r#"{"command":"","cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow");
}

#[test]
fn cursor_hook_stderr_does_not_leak_command() {
    let (_, stderr, success) =
        run_cursor_hook(r#"{"command":"echo secret-token-12345","cwd":"/tmp"}"#);
    assert!(success);
    assert!(
        !stderr.contains("secret-token-12345"),
        "stderr must not contain the full command string"
    );
}

// ---------------------------------------------------------------------------
// cursor-hook interpreter warning tests
// ---------------------------------------------------------------------------

#[test]
fn cursor_hook_allows_python_rmtree() {
    // python interpreter patterns are not blocked by meta-patterns or unwrap stack.
    // The old warn-only (exit 0, ask) behavior was security theater.
    // Future: python -c detection via interpreter-aware unwrap.
    let (stdout, _, success) = run_cursor_hook(
        r#"{"command":"python3 -c \"import shutil; shutil.rmtree('/tmp/test')\"","cwd":"/tmp"}"#,
    );
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow");
}

#[test]
fn cursor_hook_no_warn_safe_python() {
    let (stdout, _, success) =
        run_cursor_hook(r#"{"command":"python3 -c \"print('hello')\"","cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow", "safe python should not warn");
}

#[test]
fn cursor_hook_allows_node_rmsync() {
    // node interpreter patterns are not blocked by meta-patterns or unwrap stack.
    // Future: node -e detection via interpreter-aware unwrap.
    let (stdout, _, success) = run_cursor_hook(
        r#"{"command":"node -e \"require('fs').rmSync('/tmp/test', {recursive: true})\"","cwd":"/tmp"}"#,
    );
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow");
}

// ---------------------------------------------------------------------------
// AI config bypass guard tests (#22)
// ---------------------------------------------------------------------------

#[test]
fn config_disable_blocked_in_ai_session() {
    let dir = unique_dir("guard-disable");

    // Init config first (no AI env var)
    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // Try config disable WITH AI env var → should be blocked
    let output = Command::new(binary())
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "should be blocked, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
    assert!(stderr.contains("CLAUDECODE") || stderr.contains("claude-code"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_enable_blocked_in_ai_session() {
    let output = Command::new(binary())
        .args(["config", "enable", "git-push-force-block"])
        .env("CODEX_CI", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
}

/// Security-review finding: the two tests above only exercise a *core*
/// rule name. #388 widened `config disable`/`enable` to accept custom
/// names too — confirm the AI-env guard blocks those identically (it's a
/// name-agnostic, unconditional first statement in both functions, so this
/// is a belt-and-suspenders regression pin, not a gap that was ever
/// actually exploitable).
#[test]
fn config_disable_enable_blocked_in_ai_session_for_custom_rule_name() {
    let dir = unique_dir("guard-disable-enable-custom");
    config_add_init(&dir);
    let add = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "my-guarded-custom-rule",
            "--command",
            "curl",
            "--action",
            "block",
            "--match-any",
            "x",
        ])
        .output()
        .unwrap();
    assert!(add.status.success());

    for subcommand in ["disable", "enable"] {
        let output = Command::new(binary())
            .args(["config", subcommand, "my-guarded-custom-rule"])
            .env("XDG_CONFIG_HOME", &dir)
            .env_remove("HOME")
            .env("CLAUDECODE", "1")
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "config {subcommand} on a custom name must still be blocked in an AI session"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("blocked"),
            "config {subcommand}: expected a blocked message, got: {stderr}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

/// V-007 (QA gap): every one of the 15 core rule ids must be rejected by
/// `config disable`, not just `git-push-force-block` (the one exercised by
/// `config_disable_blocked_in_ai_session`, which additionally only checks
/// the AI-guard path, not the actual core-rejection message).
#[test]
fn config_disable_rejects_all_core_rule_ids() {
    let dir = unique_dir("cfg-disable-core-all");
    config_add_init(&dir);
    let config_path = dir.join("omamori").join("config.toml");
    let before = fs::read_to_string(&config_path).unwrap();

    for id in CORE_RULE_IDS {
        let output = config_add_cmd(&dir)
            .args(["config", "disable", id])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "core id `{id}` must be rejected by config disable, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("core safety rule") && stderr.contains("override disable"),
            "id `{id}`: stderr should redirect to override disable: {stderr}"
        );
    }

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, before,
        "no rejected disable for a core id may have written anything to the file"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-007 companion: `config enable` on a fresh (never-disabled) core rule
/// must be a safe, non-crashing "already enabled" no-op for every one of
/// the 15 core ids — `enable` (unlike `disable`) does not unconditionally
/// reject core names, since it also has to clean up a hand-written raw
/// stub; this pins that every core id survives that path without error or
/// an unintended write.
#[test]
fn config_enable_is_safe_noop_for_all_core_rule_ids() {
    let dir = unique_dir("cfg-enable-core-all");
    config_add_init(&dir);
    let config_path = dir.join("omamori").join("config.toml");
    let before = fs::read_to_string(&config_path).unwrap();

    for id in CORE_RULE_IDS {
        let output = config_add_cmd(&dir)
            .args(["config", "enable", id])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("already enabled"),
            "id `{id}`: expected the idempotence message, got: {stderr}"
        );
    }

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, before,
        "no no-op enable for a core id may have written anything to the file"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn uninstall_blocked_in_ai_session() {
    let output = Command::new(binary())
        .args(["uninstall"])
        .env("CURSOR_AGENT", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
}

#[test]
fn init_force_blocked_in_ai_session() {
    let output = Command::new(binary())
        .args(["init", "--force"])
        .env("GEMINI_CLI", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
}

// --- GR-006: audit key rotate AI block (T3 guardrail) ---

#[test]
fn audit_key_rotate_blocked_in_ai_session() {
    let output = Command::new(binary())
        .args(["audit", "key", "rotate"])
        .env("CURSOR_AGENT", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("blocked"),
        "audit key rotate should be blocked in AI session, got: {stderr}"
    );
}

/// #371 (V-002): `run_audit_key`'s rotate arm must actually call
/// `resolved_audit_path` and branch on `None` — not just have the right
/// predicate logic somewhere in the codebase. `XDG_CONFIG_HOME` is pinned to
/// an isolated empty dir (not just removed) so an ambient value on the
/// runner/dev machine can't make `config.path` (loaded from a stray
/// config.toml) resolve to `Some` for the wrong reason — the exact hazard
/// `install_with_hooks`'s doc comment already documents for this file.
/// `XDG_DATA_HOME` is pinned alongside it defensively (`resolved_audit_path`
/// itself never reads it — only `HOME`, via `context::data_dir()` — but
/// pinning both keeps this test's isolation posture uniform with
/// `install_with_hooks`'s, per Phase 8 QA review). The sandboxed CWD is
/// checked for zero `audit-secret*` files afterward — the #210-class CWD
/// pollution this refactor closes. Shared by the two tests below (`HOME`
/// unset vs. `HOME=""`, `/simplify` review: Reuse and Simplification
/// independently flagged the pre-extraction copy-paste, following this
/// file's own `install_with_hooks` precedent for de-duplicating a
/// repeated assertion block).
fn assert_rotate_rejects_unresolvable_home(home: Option<&str>) {
    let sandbox = unique_dir("audit-rotate-nohome-cwd");
    let xdg = unique_dir("audit-rotate-nohome-xdg");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    cmd.args(["audit", "key", "rotate"])
        .current_dir(&sandbox)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_DATA_HOME", &xdg);
    match home {
        Some(v) => {
            cmd.env("HOME", v);
        }
        None => {
            cmd.env_remove("HOME");
        }
    }
    let output = cmd.output().expect("failed to run audit key rotate");

    assert!(
        !output.status.success(),
        "rotate must fail when HOME is unresolvable ({home:?}) and no audit.path override exists"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot resolve audit path")
            && stderr.contains("HOME is unset, empty, or relative")
            && stderr.contains("set audit.path explicitly"),
        "error must name the cause and the recovery options: {stderr}"
    );

    let entries: Vec<_> = fs::read_dir(&sandbox)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("audit-secret"))
        .collect();
    assert!(
        entries.is_empty(),
        "no audit-secret* file may be created in the CWD sandbox: {entries:?}"
    );

    let _ = fs::remove_dir_all(&sandbox);
    let _ = fs::remove_dir_all(&xdg);
}

#[test]
fn audit_key_rotate_errors_actionably_and_leaves_cwd_clean_when_home_unset() {
    assert_rotate_rejects_unresolvable_home(None);
}

/// `HOME=""` is a distinct failure shape from unset `HOME` — `context::home_dir()`'s
/// own unit tests flag this as historically hazardous (a bare `?`/`map` chain
/// would treat `Some("")` as usable). Pins the sibling case at the
/// CLI-integration layer instead of only at `context::home_dir()`'s unit-test
/// layer.
#[test]
fn audit_key_rotate_errors_actionably_when_home_is_empty_string() {
    assert_rotate_rejects_unresolvable_home(Some(""));
}

/// #371 Phase 6-B (test-adversarial-review blind spot, highest priority):
/// no test anywhere ran `omamori audit key rotate`'s success path through
/// the compiled binary before this — `provenance.rs`'s unit test calls
/// `rotate_key` directly, bypassing the CLI layer, `guard_ai_config_modification`,
/// and `resolved_audit_path` entirely. Seeds a real `audit-secret` file under
/// an isolated `HOME`, then verifies the CLI actually rotates it end-to-end:
/// exit 0, the new-key-id/retired-key confirmation message, and a
/// `audit-secret.1.retired` file landing next to the fresh `audit-secret`.
#[test]
fn audit_key_rotate_succeeds_end_to_end_with_absolute_home() {
    let home = unique_dir("audit-rotate-happy-home");
    let secret_dir = home.join(".local").join("share").join("omamori");
    fs::create_dir_all(&secret_dir).unwrap();
    let secret_path = secret_dir.join("audit-secret");
    fs::write(&secret_path, "0".repeat(64)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["audit", "key", "rotate"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run audit key rotate");

    assert!(
        output.status.success(),
        "rotate must succeed with an absolute HOME and an existing secret; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key rotation complete") && stderr.contains("New key ID:"),
        "stderr must confirm rotation: {stderr}"
    );
    assert!(
        secret_dir.join("audit-secret.1.retired").exists(),
        "the pre-rotation secret must be renamed to the retired slot"
    );
    assert!(
        secret_path.exists(),
        "a fresh secret must be generated at the active path"
    );

    let _ = fs::remove_dir_all(&home);
}

/// #371 Phase 8 QA finding (V-007): `rotate_key`'s missing-secret path
/// (`read_secret` fails before any `fs::rename`/`create_secret` mutation,
/// so `SecretUnavailable` propagates with zero filesystem side effects) was
/// previously verified only by code inspection, never through the compiled
/// binary. HOME resolves successfully here (unlike the sibling
/// HOME-unusable tests above) — the failure is specifically "no secret
/// exists yet", not "path unresolvable".
#[test]
fn audit_key_rotate_reports_missing_secret_without_partial_files() {
    let home = unique_dir("audit-rotate-nosecret-home");
    let secret_dir = home.join(".local").join("share").join("omamori");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["audit", "key", "rotate"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run audit key rotate");

    assert!(
        !output.status.success(),
        "rotate must fail when no secret exists yet"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no audit secret found"),
        "error must name the cause: {stderr}"
    );

    let leftover: Vec<_> = fs::read_dir(&secret_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        leftover.is_empty(),
        "no partial audit-secret* file may be left behind: {leftover:?}"
    );

    let _ = fs::remove_dir_all(&home);
}

/// #371 Phase 6-B blind spot: the HOME-unset error message tells the user
/// to "set audit.path explicitly in config.toml" as the recovery — but
/// nothing proved that recovery path actually works end-to-end through the
/// CLI. Seeds a config.toml with an explicit absolute `audit.path` (and a
/// matching secret), unsets HOME entirely, and confirms rotation succeeds.
#[test]
fn audit_key_rotate_succeeds_via_explicit_audit_path_when_home_unset() {
    let workdir = unique_dir("audit-rotate-explicit-path");
    let config_home = workdir.join("config-home");
    let audit_dir = workdir.join("audit-data");
    fs::create_dir_all(config_home.join("omamori")).unwrap();
    fs::create_dir_all(&audit_dir).unwrap();

    let audit_path = audit_dir.join("audit.jsonl");
    let secret_path = audit_dir.join("audit-secret");
    fs::write(&secret_path, "1".repeat(64)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let config_path = config_home.join("omamori").join("config.toml");
    fs::write(
        &config_path,
        format!(
            "[audit]\nenabled = true\npath = \"{}\"\n",
            audit_path.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["audit", "key", "rotate"])
        .env("XDG_CONFIG_HOME", &config_home)
        .env_remove("HOME")
        .output()
        .expect("failed to run audit key rotate");

    assert!(
        output.status.success(),
        "explicit audit.path must recover rotation even when HOME is unset; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        audit_dir.join("audit-secret.1.retired").exists(),
        "rotation must have used the explicit audit.path directory"
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// #439 (V-002b): a relative `[audit] path` in config.toml must not resolve
/// against the process CWD — the exact CWD-scatter hazard #371 closed for
/// the unset-path case, reintroduced through an explicit-but-unvalidated
/// override. Runs a real guarded command through the shim (symlink named
/// "rm" → omamori binary → `run_shim` → `run_command`, same wiring as
/// `shim_invocation_runs_canary_and_rule_evaluation` above) from a sandboxed
/// CWD distinct from `HOME`, with a relative `audit.path` configured, and
/// asserts the sandbox CWD ends up with zero `audit.jsonl`/`audit-secret*`
/// files — `AuditConfig::validate()` must have normalized the relative
/// override away before any audit I/O happened.
#[cfg(unix)]
#[test]
fn shim_ignores_relative_audit_path_and_does_not_scatter_into_cwd() {
    use std::os::unix::fs::symlink;

    let workdir = unique_dir("shim-relpath-audit");
    let fake_home = workdir.join("fakehome");
    let shim_dir = fake_home.join(".omamori").join("shim");
    fs::create_dir_all(&shim_dir).unwrap();

    write_relative_audit_path_config(&fake_home.join(".config").join("omamori"));

    // A sandbox CWD distinct from `fake_home` — this is where a relative
    // `audit.path` would scatter the log/secret if the hazard were still open.
    let sandbox = workdir.join("cwd-sandbox");
    fs::create_dir_all(&sandbox).unwrap();
    let target = sandbox.join("victim");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("file.txt"), "data").unwrap();

    let shim_rm = shim_dir.join("rm");
    symlink(binary(), &shim_rm).unwrap();

    let output = Command::new(&shim_rm)
        .args(["-rf", target.to_str().unwrap()])
        .current_dir(&sandbox)
        .env("HOME", &fake_home)
        // CI failure (post-merge Phase 9 discovery): an ambient `XDG_CONFIG_HOME`
        // on the runner (this file's own `install_with_hooks` doc comment already
        // documents this exact hazard) makes `default_config_path()` resolve
        // outside `fake_home` entirely, silently missing the config.toml this
        // test plants — the relative-path warning never fires because the
        // config never loads. Pin it explicitly, matching every other
        // config-planting test in this file.
        .env("XDG_CONFIG_HOME", fake_home.join(".config"))
        // `resolve_real_command`'s PATH search runs unconditionally (both the
        // fast path and the protected path), so an inherited PATH containing
        // a *real*, already-installed omamori shim directory (as on a
        // developer machine that dogfoods omamori for daily use) would
        // resolve "rm" to that production shim instead of the real `/bin/rm`
        // — a false "command failed" from unrelated recursion into a
        // different omamori install, not from anything this PR touches.
        // Pinned to the two directories the real `rm` can plausibly live in
        // on the CI matrix (macOS, Ubuntu) so this test is deterministic
        // regardless of what else is on the host's PATH.
        .env("PATH", "/bin:/usr/bin")
        .env_remove("CLAUDECODE")
        .env_remove("CODEX_CI")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env_remove("CLINE_ACTIVE")
        .env_remove("AI_GUARD")
        .output()
        .expect("failed to run shim");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit.path") && stderr.contains("is not an absolute path"),
        "relative audit.path warning must reach stderr via the shim's run_command hot path, got: {stderr}"
    );

    // Phase 6-B (test-adversarial-review): the warning alone only proves
    // `load_config`/`emit_config_warnings` ran, not that the guarded command
    // actually executed and reached the audit-append code path. No AI
    // detector env var is set, so this takes the non-protected fast path
    // (PassedThrough) and execs the real `/bin/rm` rather than evaluating
    // the Trash rule — still enough to prove the run continued past config
    // loading. Assert the command succeeded and the target is actually
    // gone, and that the HOME-derived default audit log was actually
    // written to (proving the audit append happened via the HOME fallback
    // rather than silently no-op'ing).
    assert!(
        output.status.success(),
        "shim rm must succeed, stderr: {stderr}"
    );
    assert!(
        !target.exists(),
        "victim dir must be gone after the guarded command ran, not left in place"
    );
    let home_audit_log = fake_home
        .join(".local")
        .join("share")
        .join("omamori")
        .join("audit.jsonl");
    assert!(
        home_audit_log.exists(),
        "audit append must have used the HOME-derived default, not silently no-op'd: expected {}",
        home_audit_log.display()
    );

    let scattered: Vec<_> = fs::read_dir(&sandbox)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("audit.jsonl") || name.starts_with("audit-secret"))
        .collect();
    assert!(
        scattered.is_empty(),
        "no audit.jsonl/audit-secret* file may be scattered into the CWD sandbox: {scattered:?}"
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// #439 (V-json): the relative-`audit.path` warning must reach stderr for
/// `audit show --json`, the exact JSON-output CLI surface issue #439 names,
/// without leaking into stdout (which callers may pipe into a JSON parser).
#[test]
fn audit_show_json_relative_path_warning_stays_on_stderr() {
    let workdir = unique_dir("audit-show-json-relpath");
    let config_home = workdir.join("config-home");
    write_relative_audit_path_config(&config_home.join("omamori"));
    let home = workdir.join("home");
    fs::create_dir_all(&home).unwrap();

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["audit", "show", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .output()
        .expect("failed to run audit show --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Phase 6-B: pin exit status too — without it, a command that failed
    // outright (empty stdout, warning still on stderr for an unrelated
    // reason) could pass the assertions below vacuously.
    assert!(
        output.status.success(),
        "audit show --json should exit 0 on an empty log, stderr: {stderr}"
    );
    assert!(
        stderr.contains("audit.path") && stderr.contains("is not an absolute path"),
        "relative audit.path warning must reach stderr for `audit show --json`, got: {stderr}"
    );
    assert!(
        !stdout.contains("omamori warning:"),
        "warning must not leak into stdout, got: {stdout}"
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// #439 (Phase 6-B blind spot): the `emit_config_warnings` wiring touches 5
/// separate call sites in `audit_cmd.rs` (`verify`/`show`/`unknown`/`key
/// rotate`/`hash-cwd`); the test above only exercised `show --json`.
/// Reverting the wiring on any single one of the other 4 would not have been
/// caught. Table-driven so all 5 are pinned in one place. `clean_ai_env` is
/// called unconditionally for every case — it only strips AI-detector env
/// vars, which `verify`/`show`/`unknown`/`hash-cwd` never read, so it's a
/// no-op for them and required only for `key rotate`'s AI-session guard
/// (`/simplify` finding: a per-case opt-in boolean added indirection for no
/// behavioral difference).
#[test]
fn audit_subcommands_all_warn_on_relative_audit_path() {
    let cases: [&[&str]; 5] = [
        &["audit", "verify"],
        &["audit", "show"],
        &["audit", "unknown"],
        &["audit", "key", "rotate"],
        &["audit", "hash-cwd", "/tmp/some/candidate"],
    ];

    for args in cases {
        let workdir = unique_dir("audit-allcmds-relpath");
        let config_home = workdir.join("config-home");
        write_relative_audit_path_config(&config_home.join("omamori"));
        let home = workdir.join("home");
        fs::create_dir_all(&home).unwrap();

        let mut cmd = Command::new(binary());
        clean_ai_env(&mut cmd);
        let output = cmd
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config_home)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {args:?}: {e}"));

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("audit.path") && stderr.contains("is not an absolute path"),
            "{args:?} must warn about the relative audit.path override, got stderr: {stderr}"
        );

        let _ = fs::remove_dir_all(&workdir);
    }
}

// `omamori audit show --relaxed` parser reachability (PR1d, DI-16 closure).
// Pins the gap between symbol-existence (DI-16 grep) and end-to-end CLI wiring.
#[test]
fn audit_show_relaxed_flag_reaches_parser() {
    let dir = unique_dir("audit-show-relaxed");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["audit", "show", "--relaxed"])
        .env("XDG_CONFIG_HOME", &dir)
        .env("XDG_DATA_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unknown show flag"),
        "--relaxed must reach the parser arm, got stderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "audit show --relaxed should exit 0 on empty log, got stderr: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_disable_core_rule_rejected() {
    let dir = unique_dir("guard-core-reject");

    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // `config disable` on a core rule should fail with actionable error
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "should be rejected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("core safety rule"),
        "should mention core safety rule: {stderr}"
    );
    assert!(
        stderr.contains("omamori override disable"),
        "should suggest override command: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// config validate tests
// ---------------------------------------------------------------------------

#[test]
fn config_validate_valid_exits_0() {
    let dir = unique_dir("cfg-validate-ok");

    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    let config_path = dir.join("omamori").join("config.toml");
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "validate", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "valid config should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("valid"), "should say valid: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_validate_broken_toml_exits_1() {
    let path = unique_path("cfg-validate-broken");
    fs::write(&path, "[[rules]\nname = ").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "validate", path.to_str().unwrap()])
        .output()
        .unwrap();

    let _ = fs::remove_file(&path);
    let code = output.status.code().unwrap();
    assert_eq!(code, 1, "broken TOML should exit 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid"), "should say invalid: {stderr}");
}

#[test]
fn config_validate_missing_exits_2() {
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "validate", "/tmp/nonexistent-omamori-config.toml"])
        .output()
        .unwrap();

    let code = output.status.code().unwrap();
    assert_eq!(code, 2, "missing config should exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "should say not found: {stderr}"
    );
}

#[test]
fn override_disable_core_rule_works() {
    let dir = unique_dir("override-allow");

    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // `override disable` on a core rule should succeed
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["override", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "should be allowed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Override"));

    // Config list should show the rule as overridden
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("core (overridden)"),
        "should show core (overridden) in config list: {stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn override_disable_blocked_in_ai_session() {
    let output = Command::new(binary())
        .args(["override", "disable", "git-push-force-block"])
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
}

#[test]
fn override_enable_restores_core_rule() {
    let dir = unique_dir("override-restore");

    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // First disable
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    cmd.args(["override", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // Then re-enable
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["override", "enable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "should be allowed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Restored"));

    // Config list should show the rule as core (active), not overridden
    let stdout = String::from_utf8_lossy(&output.stdout);
    let push_force_line = stdout
        .lines()
        .find(|l| l.contains("git-push-force-block"))
        .unwrap_or("");
    assert!(
        push_force_line.contains("core") && !push_force_line.contains("overridden"),
        "should show core (active): {push_force_line}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn any_single_ai_env_var_blocks() {
    // Even just CLINE_ACTIVE=true should block
    let output = Command::new(binary())
        .args(["config", "disable", "git-push-force-block"])
        .env_remove("CLAUDECODE")
        .env_remove("CODEX_CI")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env_remove("AI_GUARD")
        .env("CLINE_ACTIVE", "true")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"));
}

// ---------------------------------------------------------------------------
// --version subcommand
// ---------------------------------------------------------------------------

#[test]
fn version_flag_prints_version() {
    let output = Command::new(binary())
        .arg("--version")
        .output()
        .expect("failed to run omamori --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("omamori "),
        "expected 'omamori <version>', got: {stdout}"
    );
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version mismatch: {stdout}"
    );
}

#[test]
fn version_short_flag_works() {
    let output = Command::new(binary())
        .arg("-V")
        .output()
        .expect("failed to run omamori -V");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("omamori "));
}

#[test]
fn version_subcommand_works() {
    let output = Command::new(binary())
        .arg("version")
        .output()
        .expect("failed to run omamori version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("omamori "));
}

// ---------------------------------------------------------------------------
// Integrity monitoring / status tests
// ---------------------------------------------------------------------------

#[test]
fn status_command_outputs_health_check() {
    let output = Command::new(binary())
        .arg("status")
        .output()
        .expect("failed to run omamori status");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain the health check header and category sections
    assert!(
        stdout.contains("health check"),
        "stdout should contain health check header: {stdout}"
    );
    assert!(
        stdout.contains("Shims:"),
        "stdout should contain Shims section: {stdout}"
    );
    assert!(
        stdout.contains("Core Policy:"),
        "stdout should contain Core Policy section: {stdout}"
    );
}

#[test]
fn status_refresh_creates_baseline() {
    let dir = unique_dir("status-refresh");
    let shim_dir = dir.join("shim");
    fs::create_dir_all(&shim_dir).unwrap();

    // Create a fake shim symlink
    let fake_bin = dir.join("omamori");
    fs::write(&fake_bin, "binary").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&fake_bin, shim_dir.join("rm")).unwrap();

    let output = Command::new(binary())
        .arg("status")
        .arg("--base-dir")
        .arg(dir.to_str().unwrap())
        .arg("--refresh")
        .output()
        .expect("failed to run omamori status --refresh");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Baseline refreshed"),
        "stdout should confirm baseline refresh: {stdout}"
    );

    // Verify .integrity.json was created
    assert!(
        dir.join(".integrity.json").exists(),
        ".integrity.json should exist after --refresh"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn install_generates_integrity_baseline() {
    let dir = unique_dir("install-baseline");
    // #349: `--hooks` now verifies the source binary actually satisfies the
    // hook-check contract before persisting it, so a fake non-executable
    // stand-in (previously just `fs::write(&fake_bin, "binary")`) no longer
    // passes install — use the real compiled binary as the source instead.
    // #210: without a pinned HOME, this subprocess resolves the developer's
    // real ~/.claude and ~/.codex and merges a dead hook path (this `dir`
    // is removed at test end) into the real settings.
    let home = unique_dir("install-baseline-home");

    let output = Command::new(binary())
        .arg("install")
        .arg("--base-dir")
        .arg(dir.to_str().unwrap())
        .arg("--source")
        .arg(binary())
        .arg("--hooks")
        .env("HOME", &home)
        .output()
        .expect("failed to run omamori install");
    assert!(
        output.status.success(),
        "install should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        dir.join(".integrity.json").exists(),
        ".integrity.json should exist after install"
    );

    // Verify it's valid JSON
    let content = fs::read_to_string(dir.join(".integrity.json")).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(baseline.get("version").is_some());
    assert!(baseline.get("shims").is_some());
    assert!(baseline.get("hooks").is_some());

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// dev-build provenance rejection tests (#354)
// ---------------------------------------------------------------------------

#[test]
fn install_hooks_rejects_implicit_dev_build_source() {
    let dir = unique_dir("install-devbuild");
    let home = unique_dir("install-devbuild-home");

    // No --source: source_exe resolves implicitly to the running binary's
    // own current_exe(), which under `cargo test` IS a target/debug (or
    // target/release) path — exactly the shape #354 rejects.
    let output = Command::new(binary())
        .arg("install")
        .arg("--base-dir")
        .arg(dir.to_str().unwrap())
        .arg("--hooks")
        .env("HOME", &home)
        .output()
        .expect("failed to run omamori install");

    assert!(
        !output.status.success(),
        "install --hooks with an implicit dev-build source must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cargo build artifact"),
        "stderr should explain the rejection: {stderr}"
    );
    assert!(
        !dir.join("hooks").join("claude-pretooluse.sh").exists(),
        "hook script must not be written for an implicit dev-build source"
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn install_hooks_accepts_explicit_dev_build_source() {
    let dir = unique_dir("install-devbuild-explicit");
    let home = unique_dir("install-devbuild-explicit-home");

    // Same underlying binary as the implicit case above, but named via
    // --source — the documented recovery/dev-workflow path, must succeed.
    let output = Command::new(binary())
        .arg("install")
        .arg("--base-dir")
        .arg(dir.to_str().unwrap())
        .arg("--source")
        .arg(binary())
        .arg("--hooks")
        .env("HOME", &home)
        .output()
        .expect("failed to run omamori install");

    assert!(
        output.status.success(),
        "install --hooks --source <dev-build-path> must succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        dir.join("hooks").join("claude-pretooluse.sh").exists(),
        "hook script must be written when the dev-build path was explicitly named"
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_rejects_implicit_dev_build_source() {
    let home = unique_dir("setup-devbuild-home");

    // No --source flag at all here (mirrors real `cargo run -- setup` /
    // `omamori setup` invoked directly from a dev checkout).
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SHELL", "/bin/zsh")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup");

    assert!(
        !output.status.success(),
        "setup with an implicit dev-build source must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cargo build artifact"),
        "stderr should explain the rejection: {stderr}"
    );
    assert!(
        !home
            .join(".omamori")
            .join("hooks")
            .join("claude-pretooluse.sh")
            .exists(),
        "hook script must not be written for an implicit dev-build source"
    );

    let _ = fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// hook-check Auto mode compatibility tests (#62)
// ---------------------------------------------------------------------------

/// Run `omamori hook-check --provider claude-code` with given stdin input.
/// Returns (stdout, stderr, exit_code).
///
/// HOME / XDG isolation (PR6 R3 / Codex round 3 P3): the hook-check
/// path now writes audit events on the unknown-tool fail-open route
/// (`audit_log_unknown_tool_fail_open`). Without isolation, running
/// `cargo test --test cli` on a developer machine would append
/// synthetic `unknown_tool_fail_open` events for fixtures like
/// `FutureTool2027` to the user's real `~/.local/share/omamori/audit.jsonl`.
/// We point HOME and the XDG dirs at a per-test temp directory; the
/// hook-check binary inherits these env vars and resolves both
/// config and audit paths to the temp dir.
fn run_hook_check(input: &str) -> (String, String, i32) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_home = std::env::temp_dir().join(format!("omamori-cli-hookcheck-{nanos}"));
    let _ = std::fs::create_dir_all(&test_home);

    let mut child = Command::new(binary())
        .args(["hook-check", "--provider", "claude-code"])
        .env("HOME", &test_home)
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("XDG_DATA_HOME", test_home.join(".local/share"))
        .env("XDG_CACHE_HOME", test_home.join(".cache"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hook-check");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    let _ = std::fs::remove_dir_all(&test_home);
    (stdout, stderr, exit_code)
}

/// Build a Claude Code PreToolUse JSON input for a Bash command.
fn pretooluse_bash_json(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// V-001, V-002, V-003, V-007: ALLOW returns valid hookSpecificOutput JSON
#[test]
fn hook_check_allow_returns_permission_decision_json() {
    let (stdout, _, exit_code) = run_hook_check(&pretooluse_bash_json("ls /tmp"));
    assert_eq!(exit_code, 0);
    let trimmed = stdout.trim();
    // V-001: valid JSON, single line
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stdout must be exactly one JSON line"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).expect("stdout must be valid JSON");
    let hso = &parsed["hookSpecificOutput"];
    // V-003: hookEventName
    assert_eq!(hso["hookEventName"], "PreToolUse");
    // V-002: permissionDecision
    assert_eq!(hso["permissionDecision"], "allow");
    // V-007: reason contains "omamori"
    assert!(
        hso["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("omamori"),
        "reason must contain 'omamori'"
    );
}

/// V-004, V-005: BLOCK (rm -rf via Phase 2 rule) — stdout empty, exit code 2
#[test]
fn hook_check_block_rm_rf_has_empty_stdout_and_exit_2() {
    let (stdout, stderr, exit_code) =
        run_hook_check(&pretooluse_bash_json("/bin/rm -rf /tmp/test"));
    assert_eq!(exit_code, 2, "BLOCK must exit with code 2");
    assert!(stdout.trim().is_empty(), "BLOCK stdout must be empty");
    assert!(
        stderr.contains("omamori"),
        "BLOCK stderr must contain block reason"
    );
}

/// V-004, V-005: BLOCK (rule match) — stdout empty, exit code 2
#[test]
fn hook_check_block_rule_has_empty_stdout_and_exit_2() {
    let (stdout, _, exit_code) = run_hook_check(&pretooluse_bash_json("rm -rf /"));
    assert_eq!(exit_code, 2, "BLOCK must exit with code 2");
    assert!(stdout.trim().is_empty(), "BLOCK stdout must be empty");
}

/// V-004, V-005: BLOCK (env unset tamper) — stdout empty, exit code 2
#[test]
fn hook_check_block_env_unset_has_empty_stdout_and_exit_2() {
    let (stdout, _, exit_code) =
        run_hook_check(&pretooluse_bash_json("unset CLAUDECODE && echo pwned"));
    assert_eq!(exit_code, 2, "BLOCK must exit with code 2");
    assert!(stdout.trim().is_empty(), "BLOCK stdout must be empty");
}

/// V-006: Empty command returns ALLOW JSON
#[test]
fn hook_check_empty_command_returns_allow_json() {
    let (stdout, _, exit_code) = run_hook_check(&pretooluse_bash_json(""));
    assert_eq!(exit_code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("empty command must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// V-008: OMAMORI_VERBOSE=1 does not pollute stdout (必須回帰テスト)
#[test]
fn hook_check_verbose_does_not_pollute_stdout() {
    let mut child = Command::new(binary())
        .args(["hook-check", "--provider", "claude-code"])
        .env("OMAMORI_VERBOSE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hook-check");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(pretooluse_bash_json("ls /tmp").as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    assert_eq!(
        trimmed.lines().count(),
        1,
        "verbose mode must not add lines to stdout"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(trimmed).is_ok(),
        "stdout must remain valid JSON even in verbose mode"
    );
}

/// #111: Malformed (non-JSON) input is BLOCKED (fail-close).
/// Supersedes old V-010 which expected ALLOW — that was the fail-open vulnerability.
#[test]
fn hook_check_malformed_input_blocks_with_exit_2() {
    let (stdout, stderr, exit_code) = run_hook_check("this is not json at all");
    assert_eq!(exit_code, 2, "malformed input must be blocked (fail-close)");
    assert!(
        stdout.trim().is_empty(),
        "BLOCK stdout must be empty (exit 2)"
    );
    assert!(
        stderr.contains("not valid JSON"),
        "stderr must explain the parse failure"
    );
}

/// #111: Completely empty stdin is BLOCKED (fail-close).
/// Empty string is not valid JSON, so it triggers MalformedJson.
#[test]
fn hook_check_empty_stdin_blocks_with_exit_2() {
    let (stdout, stderr, exit_code) = run_hook_check("");
    assert_eq!(exit_code, 2, "empty stdin must be blocked (fail-close)");
    assert!(
        stdout.trim().is_empty(),
        "BLOCK stdout must be empty (exit 2)"
    );
    assert!(
        stderr.contains("not valid JSON"),
        "stderr must explain the parse failure"
    );
}

/// #111: JSON array (not an object) is BLOCKED — missing required fields.
#[test]
fn hook_check_json_array_blocks() {
    let (_, _, exit_code) = run_hook_check("[1, 2, 3]");
    assert_eq!(exit_code, 2, "JSON array must be blocked (no tool_input)");
}

/// #111: Valid JSON object but no tool_input and no command → MalformedMissingField.
#[test]
fn hook_check_json_no_tool_input_blocks() {
    let input = serde_json::json!({"unrelated": "data"}).to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "JSON without tool_input must be blocked");
    assert!(stderr.contains("required fields missing"));
}

/// #111: tool_input exists but command is null → MalformedMissingField.
#[test]
fn hook_check_null_command_blocks() {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": null }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "null command must be blocked");
    assert!(stderr.contains("required fields missing"));
}

/// #111: tool_input.command is a number (not string) → falls through to MalformedMissingField.
#[test]
fn hook_check_non_string_command_blocks() {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": 42 }
    })
    .to_string();
    let (_, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "non-string command must be blocked");
}

/// #111: Unknown tool_name with non-empty tool_input (no command/file_path) → allowed.
/// Forward compatibility: future tools may have different field names.
#[test]
fn hook_check_unknown_tool_with_payload_allowed() {
    let input = serde_json::json!({
        "tool_name": "FutureTool2027",
        "tool_input": { "query": "search term", "options": {} }
    })
    .to_string();
    let (stdout, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 0, "unknown tool with payload must be allowed");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// #111: Known tool_name with empty tool_input → blocked (malformed).
/// e.g. {"tool_name":"Bash","tool_input":{}} — Bash must have command field.
#[test]
fn hook_check_known_tool_empty_tool_input_blocks() {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {}
    })
    .to_string();
    let (_, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "empty tool_input must be blocked");
}

/// #111: tool_name only (no tool_input) → allowed (minimal future tool).
#[test]
fn hook_check_tool_name_only_allowed() {
    let input = serde_json::json!({
        "tool_name": "FutureTool2027"
    })
    .to_string();
    let (stdout, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 0, "tool_name-only must be allowed");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// #110: Edit to non-protected path → allowed.
#[test]
fn hook_check_edit_non_protected_path_allowed() {
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": "/tmp/test.txt", "old_string": "a", "new_string": "b" }
    })
    .to_string();
    let (stdout, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 0, "Edit to non-protected path must be allowed");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// #110 V-001: Edit to config.toml → blocked.
#[test]
fn hook_check_edit_config_toml_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.config/omamori/config.toml", home),
            "old_string": "enabled = true",
            "new_string": "enabled = false"
        }
    })
    .to_string();
    let (stdout, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Edit to config.toml must be blocked");
    assert!(stdout.trim().is_empty());
    assert!(stderr.contains("protected file"));
    assert!(stderr.contains("omamori config"));
}

/// #110 V-002: Write to .integrity.json → blocked.
#[test]
fn hook_check_write_integrity_json_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": format!("{}/.omamori/.integrity.json", home),
            "content": "{}"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Write to .integrity.json must be blocked");
    assert!(stderr.contains("integrity baseline"));
}

/// #110: Write to audit.jsonl → blocked.
#[test]
fn hook_check_write_audit_jsonl_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": format!("{}/.local/share/omamori/audit.jsonl", home),
            "content": ""
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Write to audit.jsonl must be blocked");
    assert!(stderr.contains("audit log"));
}

/// #110: Edit to audit-secret → blocked.
#[test]
fn hook_check_edit_audit_secret_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.local/share/omamori/audit-secret", home),
            "old_string": "old", "new_string": "new"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Edit to audit-secret must be blocked");
    assert!(stderr.contains("HMAC secret"));
}

/// #110 T3: Edit to .claude/settings.json → blocked (hook registration protection).
#[test]
fn hook_check_edit_claude_settings_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.claude/settings.json", home),
            "old_string": "hooks", "new_string": ""
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Edit to settings.json must be blocked");
    assert!(stderr.contains("Claude Code settings"));
}

/// #110: Edit to .codex/hooks.json → blocked.
#[test]
fn hook_check_edit_codex_hooks_json_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.codex/hooks.json", home),
            "old_string": "omamori", "new_string": ""
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Edit to .codex/hooks.json must be blocked");
    assert!(stderr.contains("Codex hooks"));
}

/// #110: Edit to hook script → blocked.
#[test]
fn hook_check_edit_hook_script_blocked() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.omamori/hooks/claude-pretooluse.sh", home),
            "old_string": "exit 2", "new_string": "exit 0"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "Edit to hook script must be blocked");
    assert!(stderr.contains("hook script"));
}

/// #110 V-006: Path traversal with .. → blocked.
#[test]
fn hook_check_edit_path_traversal_blocked() {
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/tmp/../../home/../tmp/../Users/nonexistent/.config/omamori/config.toml",
            "old_string": "a", "new_string": "b"
        }
    })
    .to_string();
    let (_, _, exit_code) = run_hook_check(&input);
    assert_eq!(
        exit_code, 2,
        "path traversal to config.toml must be blocked"
    );
}

/// #110: Tilde path ~ → blocked.
#[test]
fn hook_check_edit_tilde_path_blocked() {
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "~/.config/omamori/config.toml",
            "old_string": "a", "new_string": "b"
        }
    })
    .to_string();
    let (_, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2, "tilde path to config.toml must be blocked");
}

/// #110: Write to completely unrelated path → allowed.
#[test]
fn hook_check_write_unrelated_path_allowed() {
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/Users/someone/projects/myapp/src/main.rs",
            "content": "fn main() {}"
        }
    })
    .to_string();
    let (stdout, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 0, "Write to unrelated path must be allowed");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// #320: block message names the matched pattern and match-kind, so a
/// false positive is diagnosable from the message alone (self-recovery,
/// UX requirement). Uses `run_hook_check`'s isolated-HOME subprocess
/// wrapper so this exercises the real `eprintln!` output, not just the
/// `(pattern, kind, reason)` tuple `is_protected_file_path` returns.
#[test]
fn hook_check_write_block_message_names_matched_pattern_and_kind() {
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/whatever/.local/share/omamori/audit.jsonl.hwm.tmp",
            "content": "x"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2);
    assert!(
        stderr.contains("matched: filename ends with '.jsonl.hwm.tmp'"),
        "block message must name the matched pattern + kind for self-recovery, got: {stderr}"
    );
}

/// #110: Block message includes 3-layer structure and omamori config hint.
#[test]
fn hook_check_edit_block_message_has_3_layers() {
    let home = std::env::var("HOME").unwrap();
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": format!("{}/.config/omamori/config.toml", home),
            "old_string": "a", "new_string": "b"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 2);
    // Layer 1: what happened
    assert!(stderr.contains("blocked Edit to protected file"));
    // Layer 2: current state
    assert!(stderr.contains("AI agents cannot modify"));
    // Layer 3: what to do
    assert!(stderr.contains("omamori config"));
}

/// #110: Symlinked parent directory — canonicalize parent catches bypass.
#[cfg(unix)]
#[test]
fn hook_check_edit_symlinked_parent_blocked() {
    use std::os::unix::fs::symlink;

    let poc_dir = unique_dir("symlink-guard");
    std::fs::create_dir_all(&poc_dir).unwrap();

    // Create a symlink: poc_dir/alias -> ~/.local/share/omamori
    let home = std::env::var("HOME").unwrap();
    let target = format!("{home}/.local/share/omamori");
    let alias = poc_dir.join("alias");
    // Only test if the target directory exists
    if std::path::Path::new(&target).exists() {
        symlink(&target, &alias).unwrap();

        let fake_file = format!("{}/newfile.jsonl", alias.display());
        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": fake_file,
                "content": "injected"
            }
        })
        .to_string();
        let (_, _, exit_code) = run_hook_check(&input);
        assert_eq!(
            exit_code, 2,
            "symlinked parent to protected dir must be blocked"
        );
    }
    // Cleanup
    let _ = std::fs::remove_dir_all(&poc_dir);
}

/// #110 S2: Phase 1B env var tampering blocks unexport of detector env vars.
#[test]
fn hook_check_blocks_export_n_claudecode() {
    let (_, stderr, exit_code) =
        run_hook_check(&pretooluse_bash_json("export -n CLAUDECODE && echo hi"));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("unexport"));
}

/// #111: VERBOSE mode includes raw input in stderr for malformed input.
#[test]
fn hook_check_malformed_verbose_shows_raw_input() {
    let mut child = Command::new(binary())
        .args(["hook-check", "--provider", "claude-code"])
        .env("OMAMORI_VERBOSE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hook-check");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"broken json {{{")
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("raw input"), "verbose must show raw input");
}

// ---------------------------------------------------------------------------
// Codex CLI hook-check compatibility tests (#66)
// ---------------------------------------------------------------------------

/// Build a Codex CLI PreToolUse JSON input (includes extra fields vs Claude Code).
fn codex_pretooluse_json(command: &str) -> String {
    serde_json::json!({
        "session_id": "019d3c44-test",
        "turn_id": "019d3c45-test",
        "transcript_path": "/tmp/test-session.jsonl",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.4",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "call_test_001"
    })
    .to_string()
}

/// V-001 (Codex): safe command → ALLOW (exit 0)
#[test]
fn codex_hook_check_allow() {
    let (stdout, _, exit_code) = run_hook_check(&codex_pretooluse_json("ls /tmp"));
    assert_eq!(exit_code, 0, "safe command should exit 0");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// V-001 (Codex): dangerous command → BLOCK (exit 2)
#[test]
fn codex_hook_check_block_rm_rf() {
    let (stdout, stderr, exit_code) = run_hook_check(&codex_pretooluse_json("rm -rf /"));
    assert_eq!(exit_code, 2, "rm -rf should exit 2");
    assert!(
        stdout.trim().is_empty(),
        "block path should produce no stdout"
    );
    assert!(
        stderr.contains("blocked"),
        "stderr should contain 'blocked'"
    );
}

/// V-008: tool_name other than Bash still extracts command
#[test]
fn codex_hook_check_non_bash_tool_name() {
    let input = serde_json::json!({
        "session_id": "test",
        "tool_name": "Shell",
        "tool_input": { "command": "ls /tmp" },
        "tool_use_id": "test"
    })
    .to_string();
    let (_, _, exit_code) = run_hook_check(&input);
    assert_eq!(exit_code, 0, "non-Bash tool_name should still work");
}

/// V-009: --provider codex flag is accepted
#[test]
fn codex_hook_check_provider_flag() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let input = codex_pretooluse_json("ls /tmp");
    let mut child = std::process::Command::new(binary)
        .args(["hook-check", "--provider", "codex"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
}

// =========================================================================
// run_shim smoke integration test
// =========================================================================

/// Verify the shim invocation path works end-to-end:
/// symlink named "rm" → omamori binary → run_shim → canary + rule evaluation.
/// Uses HOME env override to isolate base_dir.
#[cfg(unix)]
#[test]
fn shim_invocation_runs_canary_and_rule_evaluation() {
    use std::os::unix::fs::symlink;

    let poc_dir = unique_dir("shim-smoke");
    let fake_home = poc_dir.join("fakehome");
    let shim_dir = fake_home.join(".omamori").join("shim");
    fs::create_dir_all(&shim_dir).unwrap();

    // Create target directory to be rm -rf'd via shim
    let target = poc_dir.join("victim");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("file.txt"), "data").unwrap();

    // Symlink: shim/rm -> omamori binary
    let shim_rm = shim_dir.join("rm");
    symlink(binary(), &shim_rm).unwrap();

    // Run: rm -rf <target> via shim with fake HOME
    let output = Command::new(&shim_rm)
        .args(["-rf", target.to_str().unwrap()])
        .env("HOME", &fake_home)
        .env_remove("CLAUDECODE")
        .env_remove("CODEX_CI")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env_remove("CLINE_ACTIVE")
        .env_remove("AI_GUARD")
        .output()
        .expect("failed to run shim");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify shim path was entered and rule evaluation occurred.
    // The shim should produce health/diagnostic messages on stderr.
    // At minimum, the baseline creation or Trash message should appear.
    let shim_entered = stderr.contains("omamori")
        || stderr.contains("Trash")
        || stderr.contains("integrity")
        || stderr.contains("health");

    assert!(
        shim_entered,
        "Expected shim stderr to contain omamori diagnostic output, got: {stderr}"
    );

    let _ = fs::remove_dir_all(&poc_dir);
}

// ---------------------------------------------------------------------------
// #76: basename normalization — path traversal must not bypass rules
// ---------------------------------------------------------------------------

#[test]
fn hook_check_blocks_path_traversal_rm() {
    // /bin/../bin/rm should normalize to rm and match rm-recursive-to-trash
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("/bin/../bin/rm -rf /tmp/test"));
    assert_eq!(exit_code, 2, "path traversal must be blocked");
}

#[test]
fn hook_check_blocks_dot_segment_rm() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("/usr/./bin/rm -rf /tmp/test"));
    assert_eq!(exit_code, 2, "dot segment must be blocked");
}

#[test]
fn hook_check_blocks_relative_path_rm() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("./rm -rf /tmp/test"));
    assert_eq!(exit_code, 2, "relative path must be blocked");
}

// ---------------------------------------------------------------------------
// #78: git clean rule expansion — split flags must also match
// ---------------------------------------------------------------------------

#[test]
fn hook_check_blocks_git_clean_split_flags() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("git clean -f -d"));
    assert_eq!(exit_code, 2, "git clean -f -d must be blocked");
}

#[test]
fn hook_check_blocks_git_clean_df() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("git clean -df"));
    assert_eq!(exit_code, 2, "git clean -df must be blocked");
}

#[test]
fn hook_check_blocks_git_clean_three_flags() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("git clean -d -f -x"));
    assert_eq!(exit_code, 2, "git clean -d -f -x must be blocked");
}

#[test]
fn hook_check_blocks_git_clean_long_force() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("git clean --force -d"));
    assert_eq!(exit_code, 2, "git clean --force must be blocked");
}

#[test]
fn hook_check_allows_git_clean_dry_run() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("git clean -n"));
    assert_eq!(exit_code, 0, "git clean -n (dry-run) must be allowed");
}

// ---------------------------------------------------------------------------
// #78: cursor-hook git clean regression
// ---------------------------------------------------------------------------

#[test]
fn cursor_hook_blocks_git_clean_split_flags() {
    let (stdout, _, success) = run_cursor_hook(r#"{"command":"git clean -f -d","cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

// ---------------------------------------------------------------------------
// #76: cursor-hook path traversal regression
// ---------------------------------------------------------------------------

#[test]
fn cursor_hook_blocks_path_traversal_rm() {
    let (stdout, _, success) =
        run_cursor_hook(r#"{"command":"/bin/../bin/rm -rf /tmp/test","cwd":"/tmp"}"#);
    assert!(success);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["continue"], false);
    assert_eq!(parsed["permission"], "deny");
}

// ===========================================================================
// #144: command separator bypass (newline + background operator)
// ===========================================================================

#[test]
fn hook_check_blocks_newline_separated_rm() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("echo ok\nrm -rf /"));
    assert_eq!(exit_code, 2, "newline-separated rm -rf must be blocked");
}

#[test]
fn hook_check_blocks_background_separated_rm() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("echo x & rm -rf /"));
    assert_eq!(exit_code, 2, "background-separated rm -rf must be blocked");
}

#[test]
fn hook_check_blocks_background_no_space_rm() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("echo x&rm -rf /"));
    assert_eq!(exit_code, 2, "no-space background rm -rf must be blocked");
}

#[test]
fn hook_check_allows_redirect_ampersand() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("echo err &>/dev/null"));
    assert_eq!(exit_code, 0, "&> redirect must be allowed (not split)");
}

#[test]
fn hook_check_allows_fd_redirect() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("ls -la 2>&1"));
    assert_eq!(exit_code, 0, "2>&1 redirect must be allowed (not split)");
}

// ===========================================================================
// #145: meta-pattern whitespace bypass (Phase 1B)
// ===========================================================================

#[test]
fn hook_check_blocks_unset_double_space() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("unset  CLAUDECODE"));
    assert_eq!(exit_code, 2, "double-space unset must be blocked");
}

#[test]
fn hook_check_blocks_env_u_combined() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("env -uCLAUDECODE bash"));
    assert_eq!(exit_code, 2, "combined env -uVAR must be blocked");
}

#[test]
fn hook_check_allows_echo_unset_not_command_position() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("echo unset CLAUDECODE"));
    assert_eq!(exit_code, 0, "echo unset (not command pos) must be allowed");
}

// ===========================================================================
// #146 P1-2: rm split flags
// ===========================================================================

#[test]
fn hook_check_blocks_rm_split_flags() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("rm -r -f /tmp/test"));
    assert_eq!(exit_code, 2, "rm -r -f (split flags) must be blocked");
}

#[test]
fn hook_check_blocks_rm_reversed_flags() {
    let (_, _, exit_code) = run_hook_check(&pretooluse_bash_json("rm -f -r /tmp/test"));
    assert_eq!(
        exit_code, 2,
        "rm -f -r (reversed split flags) must be blocked"
    );
}

// ---------------------------------------------------------------------------
// hook-check --json-error contract tests (PR1b of v0.10.3, Phase 6-B)
// ---------------------------------------------------------------------------
//
// These pin the SECURITY.md "hook-check --json-error schema" at the CLI
// boundary: stderr is a single parseable JSON object, layer/rule_id/
// matched_pattern/matched_position fields match the spec exactly.
// Codex review (Phase 6-B) flagged the previous internal-enum-only test
// as insufficient (mutation resistance weak, false confidence high).

fn run_hook_check_json_error_impl(input: &str, verbose: bool) -> (String, String, i32) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let suffix = if verbose { "-v" } else { "" };
    let test_home = std::env::temp_dir().join(format!("omamori-cli-jsonerr{suffix}-{nanos}"));
    let _ = std::fs::create_dir_all(&test_home);

    let mut cmd = Command::new(binary());
    cmd.args(["hook-check", "--provider", "claude-code", "--json-error"])
        .env("HOME", &test_home)
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("XDG_DATA_HOME", test_home.join(".local/share"))
        .env("XDG_CACHE_HOME", test_home.join(".cache"));
    if verbose {
        cmd.env("OMAMORI_VERBOSE", "1");
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hook-check --json-error");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    let _ = std::fs::remove_dir_all(&test_home);
    (stdout, stderr, exit_code)
}

/// Run `omamori hook-check --json-error --provider claude-code` with stdin.
fn run_hook_check_json_error(input: &str) -> (String, String, i32) {
    run_hook_check_json_error_impl(input, false)
}

/// Parse the stderr of `--json-error` mode as a single JSON object.
/// Asserts: stderr trims to exactly one JSON value (single-object contract).
fn parse_json_error_stderr(stderr: &str) -> serde_json::Value {
    let trimmed = stderr.trim();
    assert!(
        !trimmed.is_empty(),
        "stderr must not be empty in --json-error mode"
    );
    let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|e| {
        panic!("stderr must be a single parseable JSON object (got {trimmed:?}): {e}")
    });
    parsed
}

/// Phase 1B token-level detection (env tampering) emits null matched_pattern
/// and null matched_position per schema, since no single substring "pattern"
/// identifies the trigger.
#[test]
fn hook_check_json_error_phase1b_null_metadata() {
    let (stdout, stderr, exit_code) =
        run_hook_check_json_error(&pretooluse_bash_json("unset CLAUDECODE"));
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(
        json["layer"], "layer2:meta-pattern",
        "Phase 1B BlockMeta uses meta-pattern layer"
    );
    assert!(
        json["matched_pattern"].is_null(),
        "Phase 1B must report matched_pattern: null (got {:?})",
        json["matched_pattern"]
    );
    assert!(
        json["matched_position"].is_null(),
        "Phase 1B must report matched_position: null"
    );
}

/// BlockRule (token-level rule match) emits layer="layer2:rule" and
/// rule_id=<rule_name>. matched_pattern/position are null in PR1b
/// (PR1c will populate these for the token-level path).
#[test]
fn hook_check_json_error_blockrule_shape() {
    let (stdout, stderr, exit_code) =
        run_hook_check_json_error(&pretooluse_bash_json("rm -rf /tmp/test"));
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(json["layer"], "layer2:rule");
    // Mutation guard (Codex Phase 6-B R2): rule_id must be exact, not just
    // non-empty. A swap of rule_id <-> message would otherwise pass.
    assert_eq!(
        json["rule_id"], "rm-recursive-to-trash",
        "rule_id must be the exact rule name (not message)"
    );
    // PR1b: matched_pattern/position not yet populated for BlockRule.
    assert!(
        json["matched_pattern"].is_null(),
        "PR1b: BlockRule matched_pattern is null until PR1c"
    );
    assert!(
        json["matched_position"].is_null(),
        "PR1b: BlockRule matched_position is null until PR1c"
    );
}

/// BlockStructural (non-materializable blocks) emits layer with wrapper kind
/// and rule_id="structural".  Uses ObfuscatedExpansion because pipe-to-shell
/// is now materializable (exit 0) under default config (#299).
#[test]
fn hook_check_json_error_blockstructural_shape() {
    let (stdout, stderr, exit_code) =
        run_hook_check_json_error(&pretooluse_bash_json("$'rm' -rf /tmp"));
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(
        json["layer"], "layer2:obfuscated-expansion",
        "BlockStructural layer must encode the block kind exactly"
    );
    assert_eq!(
        json["rule_id"], "structural",
        "BlockStructural rule_id is the constant 'structural'"
    );
    assert!(
        json["matched_pattern"].is_null(),
        "BlockStructural matched_pattern is null per schema"
    );
    assert!(
        json["matched_position"].is_null(),
        "BlockStructural matched_position is null per schema"
    );
}

/// `--json-error` mode skips audit emission entirely (documented trade-off
/// in SECURITY.md). The stderr is a single JSON object with no audit
/// warning prefix even if the audit chain would have failed.
#[test]
fn hook_check_json_error_stderr_is_single_object() {
    let (_, stderr, exit_code) =
        run_hook_check_json_error(&pretooluse_bash_json("omamori uninstall"));
    assert_eq!(exit_code, 2);
    let trimmed = stderr.trim();
    // The stderr must parse as exactly one JSON value with no leading or
    // trailing free-form text. Mutation guard against text fall-through.
    let _: serde_json::Value = serde_json::from_str(trimmed)
        .expect("stderr must be a single parseable JSON object, not text + JSON");
    // Sanity: starts with `{` and ends with `}` (single object, not array).
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "stderr must be a single JSON object (got {trimmed:?})"
    );
}

// ---------------------------------------------------------------------------
// #249: --json-error for MalformedJson, MalformedMissingField, FileOp
// ---------------------------------------------------------------------------

#[test]
fn hook_check_json_error_malformed_json() {
    let (stdout, stderr, exit_code) = run_hook_check_json_error("this is not json at all");
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(json["layer"], "layer2:input-validation");
    assert_eq!(json["rule_id"], "invalid-input");
    assert_eq!(json["reason"], "hook input could not be validated");
    assert!(json["matched_pattern"].is_null());
    assert!(json["matched_position"].is_null());
    assert!(
        json["hint"].as_str().unwrap().starts_with("Tell the user:"),
        "hint must use Tell-the-user pattern"
    );
}

#[test]
fn hook_check_json_error_malformed_missing_field() {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {}
    })
    .to_string();
    let (stdout, stderr, exit_code) = run_hook_check_json_error(&input);
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(
        json["layer"], "layer2:input-validation",
        "MalformedMissingField uses same layer as MalformedJson (oracle minimization)"
    );
    assert_eq!(
        json["rule_id"], "invalid-input",
        "MalformedMissingField uses same rule_id as MalformedJson (oracle minimization)"
    );
    assert_eq!(json["reason"], "hook input could not be validated");
    assert!(json["matched_pattern"].is_null());
}

#[test]
fn hook_check_json_error_fileop_protected_file() {
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/home/user/.config/omamori/config.toml",
            "old_string": "x",
            "new_string": "y"
        }
    })
    .to_string();
    let (stdout, stderr, exit_code) = run_hook_check_json_error(&input);
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(json["layer"], "layer2:file-protection");
    assert_eq!(json["rule_id"], "protected-file");
    assert!(
        json["reason"].as_str().unwrap().contains("protected file"),
        "reason must mention protected file"
    );
    assert!(
        json["matched_pattern"].is_string(),
        "FileOp must report the matched pattern"
    );
    assert!(
        json["hint"].as_str().unwrap().starts_with("Tell the user:"),
        "hint must use Tell-the-user pattern"
    );
}

#[test]
fn hook_check_json_error_fileop_unknown_tool() {
    let input = serde_json::json!({
        "tool_name": "SomeEditor",
        "tool_input": {
            "file_path": "/home/user/.config/omamori/config.toml"
        }
    })
    .to_string();
    let (stdout, stderr, exit_code) = run_hook_check_json_error(&input);
    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    let json = parse_json_error_stderr(&stderr);
    assert_eq!(json["blocked"], serde_json::Value::Bool(true));
    assert_eq!(json["layer"], "layer2:file-protection");
    assert_eq!(json["rule_id"], "protected-file");
    assert!(
        json["matched_pattern"].is_string(),
        "FileOp via unknown tool must also report matched pattern"
    );
}

#[test]
fn hook_check_json_error_malformed_single_object_contract() {
    let (_, stderr, _) = run_hook_check_json_error("not json");
    let trimmed = stderr.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "MalformedJson stderr must be a single JSON object (got {trimmed:?})"
    );
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stderr must be exactly one line"
    );
}

#[test]
fn hook_check_json_error_fileop_single_object_contract() {
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/home/user/.config/omamori/config.toml",
            "content": "x"
        }
    })
    .to_string();
    let (_, stderr, _) = run_hook_check_json_error(&input);
    let trimmed = stderr.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "FileOp stderr must be a single JSON object (got {trimmed:?})"
    );
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stderr must be exactly one line"
    );
}

fn run_hook_check_json_error_verbose(input: &str) -> (String, String, i32) {
    run_hook_check_json_error_impl(input, true)
}

#[test]
fn hook_check_json_error_verbose_malformed_no_raw_input() {
    let (_, stderr, exit_code) = run_hook_check_json_error_verbose("this is not json at all");
    assert_eq!(exit_code, 2);
    let trimmed = stderr.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "verbose + json-error must still be single JSON (got {trimmed:?})"
    );
    assert!(
        !trimmed.contains("raw input"),
        "verbose raw-input must not leak in json-error mode"
    );
}

#[test]
fn hook_check_json_error_verbose_fileop_no_extra_lines() {
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/home/user/.config/omamori/config.toml",
            "old_string": "x",
            "new_string": "y"
        }
    })
    .to_string();
    let (_, stderr, exit_code) = run_hook_check_json_error_verbose(&input);
    assert_eq!(exit_code, 2);
    let trimmed = stderr.trim();
    assert_eq!(
        trimmed.lines().count(),
        1,
        "verbose + json-error FileOp must be single line (got {trimmed:?})"
    );
}

// ---------------------------------------------------------------------------
// setup command tests
// ---------------------------------------------------------------------------

#[test]
fn setup_dry_run_no_mutations() {
    let base = unique_dir("setup-dry");
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--dry-run", "--base-dir"])
        .arg(&base)
        .env("SHELL", "/bin/zsh")
        .output()
        .expect("failed to run setup --dry-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("dry-run"), "stdout: {stdout}");
    assert!(stdout.contains("No changes made"), "stdout: {stdout}");

    let shim_dir = base.join("shim");
    assert!(!shim_dir.exists(), "dry-run should not create shim dir");

    let _ = fs::remove_dir_all(&base);
}

// #380: `setup --dry-run` previews the #354 implicit-dev-build-path rejection
// instead of silently reporting "would install hooks" for a run that would
// actually be rejected.

#[test]
fn setup_dry_run_from_dev_build_warns_and_advises_without_source() {
    // The test binary itself (`CARGO_BIN_EXE_omamori`) is always a
    // `target/debug`/`target/release` path under `cargo test` — exactly the
    // implicit-dev-build shape #354 rejects. No `--source` is passed, so
    // `install()` would reject this at real-run time; the dry-run preview
    // must say so.
    let base = unique_dir("setup-dry-devbuild");
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--dry-run", "--base-dir"])
        .arg(&base)
        .env("SHELL", "/bin/zsh")
        .output()
        .expect("failed to run setup --dry-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "dry-run must keep exit 0 even when it would preview a rejection; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("WARNING")
            && stdout.contains("cargo build artifact")
            && stdout.contains("--source"),
        "expected a dev-build warning naming --source as the recovery path, stdout: {stdout}"
    );
    assert!(
        stdout.contains("steps below are shown for reference and would not be reached"),
        "expected the reachability advisory line, stdout: {stdout}"
    );
    assert!(
        stdout.contains("[2/3] Shell profile (not reached)")
            && stdout.contains("[3/3] Would run doctor verification (not reached)"),
        "expected each unreached section to be labeled, avoiding a preview that \
         says 'would not be reached' and then details those steps anyway, stdout: {stdout}"
    );

    let shim_dir = base.join("shim");
    assert!(!shim_dir.exists(), "dry-run should not create shim dir");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn setup_dry_run_with_explicit_source_suppresses_dev_build_warning() {
    // Deliberately a dev-build-*shaped* path (contains target/release), not a
    // stable-looking one — proving `--source` bypasses the gate rather than
    // merely observing that a stable path never triggers it in the first
    // place (Codex proxy Phase 6-B mutation testing: a stable-path fixture
    // here would pass even with the Explicit early-return deleted).
    let base = unique_dir("setup-dry-explicit-source");
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--dry-run", "--base-dir"])
        .arg(&base)
        .args(["--source", "/some/project/target/release/omamori"])
        .env("SHELL", "/bin/zsh")
        .output()
        .expect("failed to run setup --dry-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains("WARNING"),
        "explicit --source must bypass the dev-build gate with no warning, stdout: {stdout}"
    );
    assert!(
        !stdout.contains("steps below are shown for reference and would not be reached"),
        "explicit --source must not show the reachability advisory, stdout: {stdout}"
    );
    assert!(
        !stdout.contains("(not reached)"),
        "explicit --source must not label any section as unreached, stdout: {stdout}"
    );
    assert!(stdout.contains("Hooks:     enabled"), "stdout: {stdout}");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn setup_non_interactive_installs_and_appends() {
    let home = unique_dir("setup-ni-home");
    let profile = home.join(".zshrc");
    fs::write(&profile, "# existing content\n").unwrap();

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SHELL", "/bin/zsh")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup --non-interactive");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "exit={} stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("[1/3]"), "stdout: {stdout}");
    assert!(stdout.contains("Setup complete"), "stdout: {stdout}");

    // Shims installed under $HOME/.omamori/shim
    let shim_dir = home.join(".omamori").join("shim");
    assert!(shim_dir.join("rm").exists(), "rm shim missing");

    let content = fs::read_to_string(&profile).unwrap();
    assert!(
        content.contains("# Added by omamori setup"),
        "profile: {content}"
    );
    assert!(
        content.contains("export PATH=\""),
        "profile must contain export PATH line: {content}"
    );
    assert!(
        content.contains(".omamori/shim"),
        "export PATH must reference .omamori/shim: {content}"
    );
    assert!(
        content.starts_with("# existing content"),
        "existing content must be preserved"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_idempotent_no_duplicate_path() {
    let home = unique_dir("setup-idem-home");
    let profile = home.join(".zshrc");
    fs::write(&profile, "").unwrap();

    for _ in 0..2 {
        let mut cmd = Command::new(binary());
        clean_ai_env(&mut cmd);
        let output = cmd
            .args(["setup", "--non-interactive", "--source"])
            .arg(binary())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("SHELL", "/bin/zsh")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("failed to run setup");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let content = fs::read_to_string(&profile).unwrap();
    let marker_count = content.matches("# Added by omamori setup").count();
    assert_eq!(
        marker_count, 1,
        "marker should appear exactly once, got {marker_count}"
    );
    let export_count = content.matches("export PATH=").count();
    assert_eq!(
        export_count, 1,
        "export PATH should appear exactly once, got {export_count}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_unknown_shell_exits_2() {
    let home = unique_dir("setup-unk-sh-home");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("SHELL")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "unknown shell should exit 2");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Unknown shell"),
        "stdout should mention unknown shell: {stdout}"
    );

    // Shims should still be installed (only profile is skipped)
    assert!(
        home.join(".omamori").join("shim").join("rm").exists(),
        "shims should still be installed"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_ai_env_skips_profile() {
    let base = unique_dir("setup-ai");
    let home = unique_dir("setup-ai-home");
    let profile = home.join(".zshrc");
    fs::write(&profile, "").unwrap();

    let output = Command::new(binary())
        .args(["setup", "--base-dir"])
        .arg(&base)
        .args(["--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("SHELL", "/bin/zsh")
        .env("CLAUDECODE", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup in AI env");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "AI env should exit 2");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AI environment"),
        "should mention AI env: {stdout}"
    );

    let content = fs::read_to_string(&profile).unwrap();
    assert!(
        content.is_empty(),
        "AI env should not modify profile: {content}"
    );

    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_already_configured_exits_0() {
    let home = unique_dir("setup-already-home");
    let profile = home.join(".zshrc");
    fs::write(
        &profile,
        "# existing\n# Added by omamori setup (v0.10.0)\nexport PATH=\"/x:$PATH\"\n",
    )
    .unwrap();

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SHELL", "/bin/zsh")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "already configured should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Already in PATH"),
        "should say already in PATH: {stdout}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_non_tty_without_flag_exits_1() {
    let home = unique_dir("setup-nontty-home");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup"])
        .env("HOME", &home)
        .env("SHELL", "/bin/zsh")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "non-TTY without --non-interactive should exit 1");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a terminal"), "stderr: {stderr}");

    // No mutations should have occurred
    assert!(
        !home.join(".omamori").exists(),
        "no shims should be installed"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_bash_uses_bashrc() {
    let home = unique_dir("setup-bash-home");
    // No .bash_profile → should fall back to .bashrc
    let bashrc = home.join(".bashrc");
    fs::write(&bashrc, "").unwrap();

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SHELL", "/bin/bash")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup with bash");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = fs::read_to_string(&bashrc).unwrap();
    assert!(
        content.contains("# Added by omamori setup"),
        ".bashrc should be modified: {content}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_bash_prefers_bash_profile() {
    let home = unique_dir("setup-bashprof-home");
    let bash_profile = home.join(".bash_profile");
    let bashrc = home.join(".bashrc");
    fs::write(&bash_profile, "").unwrap();
    fs::write(&bashrc, "").unwrap();

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SHELL", "/bin/bash")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup with bash");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bp_content = fs::read_to_string(&bash_profile).unwrap();
    let rc_content = fs::read_to_string(&bashrc).unwrap();
    assert!(
        bp_content.contains("# Added by omamori setup"),
        ".bash_profile should be modified: {bp_content}"
    );
    assert!(
        !rc_content.contains("# Added by omamori setup"),
        ".bashrc should NOT be modified when .bash_profile exists: {rc_content}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn setup_unknown_flag_errors() {
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--bogus"])
        .output()
        .expect("failed to run setup");

    assert!(!output.status.success(), "unknown flag should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown setup flag"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// HOME resolver unification (#373, V-005/V-006)
// ---------------------------------------------------------------------------

#[test]
fn setup_non_interactive_with_explicit_base_dir_succeeds_when_home_unset() {
    // #373 V-005: --base-dir recovers from an unusable HOME (the arg-loop
    // override, checked after the loop, must win over the eager default).
    let base = unique_dir("setup-nohome-explicit-basedir");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--base-dir"])
        .arg(&base)
        .args(["--source"])
        .arg(binary())
        .env_remove("HOME")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup --non-interactive --base-dir");

    // Do not assert overall exit success: with HOME unset, the unrelated
    // [3/3] doctor verification step (integrity::full_check) legitimately
    // reports failures (no ~/.claude / ~/.codex to check), which yields
    // exit=1. What V-005 pins is that base_dir resolution itself does not
    // error — install must actually run and place shims under --base-dir.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("cannot resolve a base directory"),
        "explicit --base-dir must bypass the HOME resolution error entirely: {stderr}"
    );
    assert!(
        base.join("shim").join("rm").exists(),
        "shim must be installed under the explicit --base-dir; stderr: {stderr}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn setup_non_interactive_without_base_dir_errors_actionably_when_home_unset() {
    // #373 V-005/V-006: no --base-dir override and an unusable HOME must be
    // a loud, actionable error (not a silent CWD-relative install).
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["setup", "--non-interactive", "--source"])
        .arg(binary())
        .env_remove("HOME")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run setup --non-interactive");

    assert!(
        !output.status.success(),
        "setup without --base-dir must fail when HOME is unset"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("HOME is unset, empty, or relative") && stderr.contains("--base-dir"),
        "error must name the cause and the recovery flag: {stderr}"
    );

    let cwd_omamori = std::env::current_dir().unwrap().join(".omamori");
    assert!(
        !cwd_omamori.exists(),
        "must not fall back to a CWD-relative ./.omamori install"
    );
}

/// #373 V-006: runs `omamori <subcommand-args>` with `--base-dir` omitted and
/// `HOME` unset, asserting the shared "cannot resolve a base directory"
/// error fires before any base_dir-dependent work runs. Shared by
/// install/uninstall/doctor/status — all four resolve `base_dir` via the
/// identical `default_base_dir().ok_or_else(...)` pattern (see
/// src/cli/{install,doctor,status}.rs).
fn assert_base_dir_resolution_errors_when_home_unset(subcommand_args: &[&str]) {
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(subcommand_args)
        .env_remove("HOME")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("failed to run {subcommand_args:?}: {e}"));

    assert!(
        !output.status.success(),
        "{subcommand_args:?} without --base-dir must fail when HOME is unset"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot resolve a base directory")
            && stderr.contains("HOME is unset, empty, or relative")
            && stderr.contains("--base-dir"),
        "{subcommand_args:?} error must name cause + recovery flag: {stderr}"
    );
}

#[test]
fn install_without_base_dir_errors_actionably_when_home_unset() {
    assert_base_dir_resolution_errors_when_home_unset(&["install"]);
}

#[test]
fn uninstall_without_base_dir_errors_actionably_when_home_unset() {
    assert_base_dir_resolution_errors_when_home_unset(&["uninstall"]);
}

#[test]
fn doctor_without_base_dir_errors_actionably_when_home_unset() {
    assert_base_dir_resolution_errors_when_home_unset(&["doctor"]);
}

#[test]
fn status_without_base_dir_errors_actionably_when_home_unset() {
    assert_base_dir_resolution_errors_when_home_unset(&["status"]);
}

/// #373 adversarial review (test-adversarial-review agent, gap confirmed via
/// mutation testing: a deliberate `--base-dir`/`HOME` inversion in doctor.rs
/// went undetected by the V-006 error-path tests above — they only cover the
/// no-`--base-dir` direction). Explicit `--base-dir` must recover from an
/// unusable `HOME` for all 4 Class A commands, not just `setup` (which
/// already has this covered by
/// `setup_non_interactive_with_explicit_base_dir_succeeds_when_home_unset`).
/// Shared by `status`/`doctor` below — both exit non-zero when health checks
/// fail (expected for a bare base_dir with nothing installed); what matters
/// here is only that `--base-dir` resolution itself didn't error. (`install`
/// and `uninstall` need their own tests — extra `--source`/prior-install
/// steps make them not a byte-for-byte match with this shape.)
fn assert_explicit_base_dir_recovers_from_unset_home(subcommand: &str) {
    let base = unique_dir(&format!("{subcommand}-nohome-explicit-basedir"));

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args([subcommand, "--base-dir"])
        .arg(&base)
        .env_remove("HOME")
        .output()
        .unwrap_or_else(|e| panic!("failed to run {subcommand} --base-dir: {e}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("cannot resolve a base directory"),
        "{subcommand}: explicit --base-dir must bypass the HOME resolution error: {stderr}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn status_with_explicit_base_dir_succeeds_when_home_unset() {
    assert_explicit_base_dir_recovers_from_unset_home("status");
}

#[test]
fn doctor_with_explicit_base_dir_succeeds_when_home_unset() {
    assert_explicit_base_dir_recovers_from_unset_home("doctor");
}

#[test]
fn install_with_explicit_base_dir_succeeds_when_home_unset() {
    let base = unique_dir("install-nohome-explicit-basedir");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["install", "--base-dir"])
        .arg(&base)
        .args(["--source"])
        .arg(binary())
        .env_remove("HOME")
        .output()
        .expect("failed to run install --base-dir");

    assert!(
        output.status.success(),
        "install --base-dir must succeed despite unset HOME; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        base.join("shim").join("rm").exists(),
        "shim must be installed under the explicit --base-dir"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn uninstall_with_explicit_base_dir_succeeds_when_home_unset() {
    let base = unique_dir("uninstall-nohome-explicit-basedir");

    // Install first (needs a resolvable HOME for its own default_base_dir
    // eager-init path to be harmless either way — pin one for the install
    // step, then remove it for the uninstall step under test).
    let home = unique_dir("uninstall-nohome-explicit-basedir-home");
    install_with_hooks(&base, &home);

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["uninstall", "--base-dir"])
        .arg(&base)
        .env_remove("HOME")
        .output()
        .expect("failed to run uninstall --base-dir");

    assert!(
        output.status.success(),
        "uninstall --base-dir must succeed despite unset HOME; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn config_add_succeeds_when_home_unset_but_xdg_config_home_set() {
    // #373 V-007 (Class B): `config add`'s mutate_config path (line 241,
    // src/cli/config_cmd.rs) does a best-effort `default_base_dir()` baseline
    // update after the config write already succeeded via XDG_CONFIG_HOME
    // alone. An unusable HOME must silently skip that baseline update, NOT
    // fail the config mutation that already landed on disk. Also covers the
    // adversarial-review blind spot that `init`'s equivalent skip (line 135)
    // had no CWD non-pollution assertion, unlike install/run_shim's.
    let cwd_omamori = std::env::current_dir().unwrap().join(".omamori");
    let cwd_omamori_existed_before = cwd_omamori.exists();
    let dir = unique_dir("config-add-nohome");

    let mut init_cmd = Command::new(binary());
    clean_ai_env(&mut init_cmd);
    let init_output = init_cmd
        .args(["init"])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run omamori init");
    assert!(
        init_output.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&init_output.stderr)
    );
    assert_eq!(
        cwd_omamori.exists(),
        cwd_omamori_existed_before,
        "init's best-effort baseline skip must not create a CWD-relative ./.omamori"
    );

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .args([
            "config",
            "add",
            "my-nohome-rule",
            "--command",
            "curl",
            "--action",
            "block",
            "--match-any",
            "--insecure",
        ])
        .env("XDG_CONFIG_HOME", &dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run config add");

    assert!(
        output.status.success(),
        "config add must succeed on XDG_CONFIG_HOME alone despite unusable HOME; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("my-nohome-rule"),
        "add mutation must have landed on disk: {content}"
    );
    assert_eq!(
        cwd_omamori.exists(),
        cwd_omamori_existed_before,
        "config add's best-effort baseline skip must not create a CWD-relative ./.omamori"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// break-glass TTY tests (#319)
// ---------------------------------------------------------------------------

#[test]
fn break_glass_activate_rejects_piped_stdin() {
    let home = unique_dir("break-glass-pipe-home");

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let mut child = cmd
        .args(["break-glass", "--rule", "rm-rf"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn break-glass");

    // Reproduce the exact bypass attempt from issue #319:
    // `printf 'y\n' | omamori break-glass --rule <r>`.
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"y\n")
        .expect("failed to write to stdin");

    let output = child
        .wait_with_output()
        .expect("failed to wait on break-glass");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "piped 'y' must not activate break-glass; stderr: {stderr}"
    );
    assert!(
        stderr.contains("requires an interactive terminal"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("--yes") && !stderr.contains("--non-interactive"),
        "refusal must not advertise a bypass flag; stderr: {stderr}"
    );

    // Confirm the piped attempt did not actually activate anything.
    let mut status_cmd = Command::new(binary());
    clean_ai_env(&mut status_cmd);
    let status_output = status_cmd
        .args(["break-glass", "--status"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run break-glass --status");
    let status_stderr = String::from_utf8_lossy(&status_output.stderr);
    assert!(
        status_stderr.contains("No active break-glass bypasses"),
        "stderr: {status_stderr}"
    );

    // The refusal must still be forensically observable: the denied
    // activation attempt is audit-logged with a provider distinct from
    // "human" (which is reserved for genuine, confirmed activations).
    let audit_log = home.join(".local/share/omamori/audit.jsonl");
    let audit_content = fs::read_to_string(&audit_log).unwrap_or_else(|e| {
        panic!("expected denied activation to be audit-logged at {audit_log:?}: {e}")
    });
    assert!(
        audit_content.contains("\"action\":\"break-glass-activate-denied\""),
        "audit log missing denied-activation event: {audit_content}"
    );
    assert!(
        audit_content.contains("\"provider\":\"non-interactive\""),
        "denied event must not be attributed to provider \"human\": {audit_content}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn break_glass_status_and_clear_unaffected_by_tty_check() {
    let home = unique_dir("break-glass-status-home");

    for args in [["break-glass", "--status"], ["break-glass", "--clear"]] {
        let mut cmd = Command::new(binary());
        clean_ai_env(&mut cmd);
        let output = cmd
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap_or_else(|_| panic!("failed to run {args:?}"));
        assert!(
            output.status.success(),
            "{args:?} should succeed without a TTY; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = fs::remove_dir_all(&home);
}

/// #349 Codex Round 1 P0: `verify_hook_contract`'s probe (run internally by
/// `install --hooks`) must not be affected by the real user's rules — a
/// config that blocks `ls` targeting `/tmp` must not fail-close a perfectly
/// good binary. This can only be exercised against a genuine, working
/// omamori binary (unlike `src/installer.rs`'s unit tests, which resolve to
/// the test harness via `current_exe()`, not the real CLI), hence living
/// here where `CARGO_BIN_EXE_omamori` is available.
#[test]
fn install_hooks_ignores_hostile_user_config_during_verification() {
    let base_dir = unique_dir("install-hostile-base");
    let home = unique_dir("install-hostile-home");
    let config_dir = home.join(".config").join("omamori");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(
        &config_path,
        r#"[[rules]]
name = "block-ls-tmp-test"
command = "ls"
action = "block"
match_any = ["/tmp"]
message = "test: blocking ls /tmp"
"#,
    )
    .unwrap();
    // Config loading rejects world/group-readable config files as insecure
    // and silently falls back to defaults (see
    // `config::tests::load_config_rejects_insecure_permissions`) — without
    // this, the fixture below is not actually hostile and both the control
    // and the real assertion pass for the wrong reason.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Control: prove the fixture is actually hostile before trusting the
    // real test below (Codex Round 3 test review). A plain `hook-check`
    // using this exact HOME/XDG_CONFIG_HOME must BLOCK the probe payload —
    // otherwise "install still succeeds" would be true for the wrong reason
    // (a no-op config), not because verification's env isolation worked.
    let mut control = Command::new(binary());
    clean_ai_env(&mut control);
    let mut control_child = control
        .arg("hook-check")
        .arg("--provider")
        .arg("claude-code")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn control hook-check");
    control_child
        .stdin
        .take()
        .unwrap()
        .write_all(pretooluse_bash_json("ls /tmp").as_bytes())
        .unwrap();
    let control_status = control_child.wait().expect("control hook-check failed");
    assert_eq!(
        control_status.code(),
        Some(2),
        "control: the hostile config fixture must actually block `ls /tmp` for this test to be meaningful"
    );

    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    let output = cmd
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary())
        .arg("--hooks")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori install");

    assert!(
        output.status.success(),
        "install must succeed even when the real user config would block the probe payload; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// doctor display integration tests (Batch C PR-C1: #310/#309/#326/#327)
// ---------------------------------------------------------------------------

#[test]
fn doctor_awaiting_heartbeat_shows_hint_and_json_stays_unchanged() {
    let base_dir = unique_dir("doctor-awaiting-base");
    let home = unique_dir("doctor-awaiting-home");

    let mut human_cmd = Command::new(binary());
    clean_ai_env(&mut human_cmd);
    let human = human_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor");
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_stdout.contains("awaiting first invocation"),
        "stdout: {human_stdout}"
    );
    assert!(
        human_stdout.contains("hint:") && human_stdout.contains("git status"),
        "awaiting state should print the non-destructive hint: {human_stdout}"
    );
    // Plan V-012: hint must not steer the user toward a destructive command.
    // Scoped to the hint line itself — the shim inventory above it legitimately
    // lists a shim command literally named "rm", which would false-positive a
    // whole-stdout substring check.
    let hint_line = human_stdout
        .lines()
        .find(|line| line.contains("hint:"))
        .expect("already asserted a hint: line is present above");
    assert!(
        !hint_line.contains("rm "),
        "awaiting hint must not suggest a destructive command: {hint_line}"
    );
    // #310 test-adversarial finding: proves the heartbeat annotation is
    // actually wired through `section_annotations` at the Layer 1 slot, not
    // merely printed somewhere in the output — a test only checking
    // substring presence would still pass if the hardcoded
    // `if section == Layer1 { print_heartbeat_line() }` special case were
    // reintroduced (or moved to the wrong section) instead of going through
    // the table.
    let layer1_pos = human_stdout
        .find("[Layer 1]")
        .expect("stdout should contain [Layer 1] heading");
    let layer2_pos = human_stdout
        .find("[Layer 2]")
        .expect("stdout should contain [Layer 2] heading");
    let awaiting_pos = human_stdout
        .find("awaiting first invocation")
        .expect("already asserted present above");
    assert!(
        layer1_pos < awaiting_pos && awaiting_pos < layer2_pos,
        "heartbeat annotation must render between [Layer 1] and [Layer 2]: {human_stdout}"
    );

    let mut json_cmd = Command::new(binary());
    clean_ai_env(&mut json_cmd);
    let json_out = json_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--json")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor --json");
    let json: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("doctor --json must produce valid JSON");
    let shim_activity = &json["summary"]["shim_activity"];
    assert_eq!(shim_activity["status"], "awaiting_first_invocation");
    let mut keys: Vec<&String> = shim_activity.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["last_active_days_ago", "status"],
        "#326's hint is human-output only — shim_activity's JSON shape must stay exactly \
         {{last_active_days_ago, status}}, no new keys"
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_awaiting_heartbeat_hint_differs_in_ai_env() {
    // /code-review finding: the awaiting-state hint was the one doctor-output
    // string this PR didn't gate on ai_env, unlike remediation_hint and
    // print_break_glass_section. Confirms the human and AI phrasing actually
    // differ, and that the AI phrasing doesn't refer to "your AI tool" (which
    // reads as nonsensical when the reader IS the AI tool).
    let base_dir = unique_dir("doctor-awaiting-aihint-base");
    let home = unique_dir("doctor-awaiting-aihint-home");

    let mut human_cmd = Command::new(binary());
    clean_ai_env(&mut human_cmd);
    let human = human_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor (human)");
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    let human_hint = human_stdout
        .lines()
        .find(|line| line.contains("hint:"))
        .expect("human output should contain a hint line");
    assert!(
        human_hint.contains("your AI tool"),
        "human hint: {human_hint}"
    );

    let ai = Command::new(binary())
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("CLAUDECODE", "1")
        .output()
        .expect("failed to run omamori doctor (AI env)");
    let ai_stdout = String::from_utf8_lossy(&ai.stdout);
    let ai_hint = ai_stdout
        .lines()
        .find(|line| line.contains("hint:"))
        .expect("AI env output should contain a hint line");
    assert!(
        !ai_hint.contains("your AI tool"),
        "AI env hint must not refer to 'your AI tool': {ai_hint}"
    );
    assert!(
        ai_hint.contains("not via AI"),
        "AI env hint should follow the SEC-R5 'directly in your terminal (not via AI)' \
         convention: {ai_hint}"
    );
    assert_ne!(human_hint, ai_hint);

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_break_glass_detail_suppressed_in_ai_env() {
    let home = unique_dir("doctor-bg-home");
    let data_dir = home.join(".local").join("share").join("omamori");
    fs::create_dir_all(&data_dir).unwrap();
    let expires = time::OffsetDateTime::now_utc() + time::Duration::minutes(30);
    let state = serde_json::json!({
        "version": 1,
        "entries": [{
            "rule_id": "some-custom-rule-block",
            "activated_at": time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "expires_at": expires
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        }]
    });
    fs::write(
        data_dir.join("break-glass.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();

    let mut human_cmd = Command::new(binary());
    clean_ai_env(&mut human_cmd);
    let human = human_cmd
        .arg("doctor")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor (human)");
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_stdout.contains("some-custom-rule-block") && human_stdout.contains("remaining"),
        "non-AI env should show rule_id and remaining time: {human_stdout}"
    );

    let ai = Command::new(binary())
        .arg("doctor")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("CLAUDECODE", "1")
        .output()
        .expect("failed to run omamori doctor (AI env)");
    let ai_stdout = String::from_utf8_lossy(&ai.stdout);
    assert!(
        ai_stdout.contains("1 active bypass(es)"),
        "AI env should still show the count: {ai_stdout}"
    );
    assert!(
        !ai_stdout.contains("some-custom-rule-block") && !ai_stdout.contains("remaining"),
        "T8: AI env must not see which rule or how much time is left: {ai_stdout}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_fix_shows_shim_activity_footer_when_healthy() {
    let base_dir = unique_dir("doctor-fix-footer-base");
    let home = unique_dir("doctor-fix-footer-home");
    // `merge_claude_settings` only runs when `~/.claude` already exists as a
    // real directory (its signal for "Claude Code is installed") — without
    // this, `check_claude_settings_integration` stays WARN and `problems`
    // is never empty, so the "nothing to repair" fast path this test targets
    // would be unreachable.
    fs::create_dir_all(home.join(".claude")).unwrap();
    install_with_hooks(&base_dir, &home);

    // `check_path_order` reads the live `PATH` env var — the shim dir is
    // never actually on this test process's PATH, so without overriding it
    // here that check permanently WARNs and `problems` is never empty
    // either. Order it correctly (shim dir before /usr/bin) to reach the
    // fast path this test targets.
    let shim_dir = base_dir.join("shim");
    let healthy_path = format!("{}:/usr/bin:/bin", shim_dir.display());

    let mut fix_cmd = Command::new(binary());
    clean_ai_env(&mut fix_cmd);
    let fix = fix_cmd
        .arg("doctor")
        .arg("--fix")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", &healthy_path)
        .output()
        .expect("failed to run omamori doctor --fix");
    assert!(
        fix.status.success(),
        "doctor --fix should succeed on a healthy install. stderr: {}",
        String::from_utf8_lossy(&fix.stderr)
    );
    let fix_stdout = String::from_utf8_lossy(&fix.stdout);
    assert!(
        fix_stdout.contains("nothing to repair"),
        "stdout: {fix_stdout}"
    );
    assert!(
        fix_stdout.contains("[Shim activity]") && fix_stdout.contains("last active:"),
        "#309: --fix's own output must show shim activity even on the \
         nothing-to-repair fast path: {fix_stdout}"
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_fix_shows_shim_activity_footer_after_an_actual_repair() {
    // #309 test-adversarial finding: the "nothing to repair" fast path was
    // the only path covered — this exercises the footer print AFTER real
    // remediation work, not just on the early return. Uses a `ChmodConfig`
    // fixable issue specifically because it needs no exe resolution (unlike
    // `RunInstall`/`RegenerateHooks`, which would hit #354's dev-build-path
    // rejection here: this subprocess's own `current_exe()` under `cargo
    // test` IS a `target/debug` path).
    let base_dir = unique_dir("doctor-fix-repair-base");
    let home = unique_dir("doctor-fix-repair-home");
    fs::create_dir_all(home.join(".claude")).unwrap();
    install_with_hooks(&base_dir, &home);

    let config_dir = home.join(".config").join("omamori");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Wrong mode (world/group-readable) — the Config integrity check
        // wants exactly 0o600, triggering a `ChmodConfig` remediation.
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let shim_dir = base_dir.join("shim");
    let healthy_path = format!("{}:/usr/bin:/bin", shim_dir.display());

    let mut fix_cmd = Command::new(binary());
    clean_ai_env(&mut fix_cmd);
    let fix = fix_cmd
        .arg("doctor")
        .arg("--fix")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", &healthy_path)
        .output()
        .expect("failed to run omamori doctor --fix");
    assert!(
        fix.status.success(),
        "doctor --fix should succeed after a plain chmod repair. stderr: {}",
        String::from_utf8_lossy(&fix.stderr)
    );
    let fix_stdout = String::from_utf8_lossy(&fix.stdout);
    assert!(
        fix_stdout.contains("chmod 600") && fix_stdout.contains("[fixed]"),
        "control: fixture must actually trigger a repair for this test to be \
         meaningful: {fix_stdout}"
    );
    assert!(
        fix_stdout.contains("[Shim activity]") && fix_stdout.contains("last active:"),
        "#309: the footer must also appear after real repair work, not only \
         on the nothing-to-repair fast path: {fix_stdout}"
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn doctor_reports_hook_version_drift_in_human_and_json_output() {
    let base_dir = unique_dir("doctor-drift-base");
    let home = unique_dir("doctor-drift-home");
    install_with_hooks(&base_dir, &home);

    // Tamper only the version comment line — same technique #327's own unit
    // tests use (src/integrity.rs's `script_with_version` fixture) — this
    // also makes the content hash mismatch, exercising the real "hash
    // MISMATCH + drift suffix" combination a stale post-upgrade hook hits.
    let hook_path = base_dir.join("hooks").join("claude-pretooluse.sh");
    let current = fs::read_to_string(&hook_path).unwrap();
    let tampered = current.replacen(
        &format!("# omamori hook v{}", env!("CARGO_PKG_VERSION")),
        "# omamori hook v0.0.1",
        1,
    );
    assert_ne!(
        tampered, current,
        "fixture setup bug: version substitution did not change the installed hook script"
    );
    fs::write(&hook_path, &tampered).unwrap();

    let mut human_cmd = Command::new(binary());
    clean_ai_env(&mut human_cmd);
    let human = human_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor");
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_stdout.contains("version drift"),
        "stdout: {human_stdout}"
    );
    assert!(human_stdout.contains("v0.0.1"), "stdout: {human_stdout}");
    assert!(
        human_stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {human_stdout}"
    );

    let mut json_cmd = Command::new(binary());
    clean_ai_env(&mut json_cmd);
    let json_out = json_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--json")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .expect("failed to run omamori doctor --json");
    let json: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("doctor --json must produce valid JSON");
    let hook_item = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "claude-pretooluse.sh")
        .expect("claude-pretooluse.sh item must be present in JSON output");
    let detail = hook_item["detail"].as_str().unwrap();
    assert!(detail.contains("v0.0.1"), "detail: {detail}");
    assert!(
        detail.contains(env!("CARGO_PKG_VERSION")),
        "detail: {detail}"
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// config add tests (PR-C2, #325)
// ---------------------------------------------------------------------------

/// The 15 core (built-in) safety rule ids — mirrors `config::core_rule_names()`.
/// Hardcoded here (this file is a black-box binary test, no crate import) so a
/// future addition to that list is caught by drift between this constant and
/// the real one, not silently under-tested.
const CORE_RULE_IDS: &[&str] = &[
    "rm-recursive-to-trash",
    "git-reset-hard-stash",
    "git-push-force-block",
    "git-clean-force-block",
    "chmod-777-block",
    "find-delete-block",
    "rsync-delete-block",
    "omamori-config-modify-block",
    "omamori-uninstall-block",
    "omamori-init-force-block",
    "omamori-override-block",
    "omamori-doctor-fix-block",
    "omamori-explain-block",
    "omamori-break-glass-block",
    "omamori-audit-key-rotate-block",
];

fn config_add_cmd(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(binary());
    clean_ai_env(&mut cmd);
    cmd.env("XDG_CONFIG_HOME", dir).env_remove("HOME");
    cmd
}

fn config_add_init(dir: &std::path::Path) {
    let out = config_add_cmd(dir).args(["init"]).output().unwrap();
    assert!(
        out.status.success(),
        "init should succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// V-001: a rule created by `config add` loads cleanly and fires in `explain`.
#[test]
fn config_add_creates_rule_that_fires_in_explain() {
    let dir = unique_dir("cfg-add-fires");
    config_add_init(&dir);

    let add_out = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "my-ls-guard",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "--omamori-poc-target",
        ])
        .output()
        .unwrap();
    assert!(
        add_out.status.success(),
        "add should succeed, stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_stderr = String::from_utf8_lossy(&add_out.stderr);
    assert!(
        add_stderr.contains("Added rule `my-ls-guard`"),
        "stderr: {add_stderr}"
    );

    let validate_out = config_add_cmd(&dir)
        .args(["config", "validate"])
        .output()
        .unwrap();
    assert!(
        validate_out.status.success(),
        "config should load cleanly (degraded=false) after add, stderr: {}",
        String::from_utf8_lossy(&validate_out.stderr)
    );

    let explain_out = config_add_cmd(&dir)
        .args(["explain", "--", "ls", "--omamori-poc-target"])
        .output()
        .unwrap();
    assert!(
        explain_out.status.success() || explain_out.status.code() == Some(2),
        "explain should run to completion, stderr: {}",
        String::from_utf8_lossy(&explain_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&explain_out.stdout);
    assert!(
        stdout.contains("rule: my-ls-guard"),
        "explain should show the newly added rule matched: {stdout}"
    );
    assert!(stdout.contains("Verdict: BLOCK"), "stdout: {stdout}");

    let _ = fs::remove_dir_all(&dir);
}

/// /code-review R1 finding: a successful `add` must still surface an
/// unrelated pre-existing warning in the same file, matching `disable`/
/// `enable` (both end by calling `run_config_list()` -> `emit_config_warnings`).
/// Checking only `post.degraded` would silently swallow it.
#[test]
fn config_add_surfaces_unrelated_preexisting_warning() {
    let dir = unique_dir("cfg-add-unrelated-warning");
    config_add_init(&dir);

    // Hand-plant a malformed *different-named* rule: `merge_rules` skips it
    // with a warning (missing command/action) but does NOT degrade the file.
    let config_path = dir.join("omamori").join("config.toml");
    let mut content = fs::read_to_string(&config_path).unwrap();
    content.push_str("\n[[rules]]\nname = \"some-other-broken-rule\"\n");
    fs::write(&config_path, &content).unwrap();

    let add_out = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "unrelated-new-rule",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(
        add_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let stderr = String::from_utf8_lossy(&add_out.stderr);
    assert!(
        stderr.contains("some-other-broken-rule") && stderr.contains("missing"),
        "a successful add must still surface an unrelated pre-existing warning: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-002: `config add` is blocked when an AI detector env var is present,
/// same as `config disable`/`enable`.
#[test]
fn config_add_blocked_in_ai_session() {
    let dir = unique_dir("cfg-add-ai-block");
    config_add_init(&dir);

    let output = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "some-rule",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "should be blocked, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked"), "stderr: {stderr}");

    // The config file must be untouched — guard runs before any write.
    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        !content.contains("some-rule"),
        "blocked add must not write anything: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-004 (DI-13): every core rule id is rejected as a shadow target, not just
/// the one used in ad-hoc manual testing.
#[test]
fn config_add_rejects_all_core_rule_ids() {
    let dir = unique_dir("cfg-add-core-shadow");
    config_add_init(&dir);
    let config_path = dir.join("omamori").join("config.toml");
    let before = fs::read_to_string(&config_path).unwrap();

    for id in CORE_RULE_IDS {
        let output = config_add_cmd(&dir)
            .args([
                "config",
                "add",
                id,
                "--command",
                "ls",
                "--action",
                "log-only",
                "--match-any",
                "-l",
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "core id `{id}` must be rejected, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("core safety rule") && stderr.contains("DI-13"),
            "id `{id}`: stderr should explain the DI-13 rejection: {stderr}"
        );
    }

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, before,
        "no rejected add for a core id may have written anything to the file"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Cross-check `CORE_RULE_IDS` (hardcoded here since this is a black-box
/// binary test with no crate import) against the live core-rule count via
/// `omamori config list`'s "core"-sourced rows. If a future core rule is
/// added to `core_rule_names()` without updating `CORE_RULE_IDS`, this test
/// fails on a count mismatch instead of silently under-testing DI-13 shadow
/// rejection for the new rule (Codex adversarial review finding).
#[test]
fn core_rule_ids_constant_matches_live_core_rule_count() {
    let dir = unique_dir("cfg-core-count-check");
    config_add_init(&dir);

    let list_out = config_add_cmd(&dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let core_row_count = stdout
        .lines()
        .filter(|line| line.trim_end().ends_with("core"))
        .count();

    assert_eq!(
        core_row_count,
        CORE_RULE_IDS.len(),
        "CORE_RULE_IDS (len {}) is out of sync with the live core rule count ({core_row_count}). \
         Update the CORE_RULE_IDS constant in this file.\nfull output:\n{stdout}",
        CORE_RULE_IDS.len()
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-006 / AD1: adding a rule name that already exists (custom, not core) is
/// rejected rather than silently ignored by `merge_rules`' first-wins dedup.
#[test]
fn config_add_rejects_duplicate_rule_name() {
    let dir = unique_dir("cfg-add-dup");
    config_add_init(&dir);

    let first = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "dup-rule",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(first.status.success(), "first add should succeed");

    let config_path = dir.join("omamori").join("config.toml");
    let after_first = fs::read_to_string(&config_path).unwrap();

    let second = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "dup-rule",
            "--command",
            "ls",
            "--action",
            "trash",
            "--match-any",
            "-a",
        ])
        .output()
        .unwrap();
    assert!(
        !second.status.success(),
        "duplicate name must be rejected, stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("already exists"), "stderr: {stderr}");

    // The file must be byte-for-byte unchanged — not just "still exactly one
    // `dup-rule` name" (which a bug that mutates the existing entry's action/
    // message/match tokens before rejecting would still satisfy).
    let after_second = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after_second, after_first,
        "a rejected duplicate add must not modify the existing entry's fields"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Codex R1 P0: a pre-existing *malformed* raw entry (missing command/action,
/// so `merge_rules` skips it with only a warning — not `degraded`) sharing
/// the new rule's name must still be caught. Before the fix, the dup check
/// only consulted the *merged* rule set, which never contained the malformed
/// entry — so `add` would report success while claiming a name that
/// `merge_rules`'s first-name-wins semantics had already given away to the
/// broken entry, silently dropping the newly-added (valid) rule on next load.
#[test]
fn config_add_rejects_duplicate_name_against_malformed_raw_entry() {
    let dir = unique_dir("cfg-add-dup-malformed");
    config_add_init(&dir);

    let config_path = dir.join("omamori").join("config.toml");
    // Hand-plant a malformed entry (name only, no command/action) — this is
    // exactly what `merge_rules` skips-with-warning rather than `degraded`.
    let mut content = fs::read_to_string(&config_path).unwrap();
    content.push_str("\n[[rules]]\nname = \"shadowed-by-malformed\"\n");
    fs::write(&config_path, &content).unwrap();

    // Sanity: the file still loads as non-degraded (a skipped rule is just a
    // warning), confirming this really does bypass a merged-rule-set check.
    let validate_out = config_add_cmd(&dir)
        .args(["config", "validate"])
        .output()
        .unwrap();
    assert!(
        validate_out.status.success(),
        "a malformed custom rule alone must not degrade the config, stderr: {}",
        String::from_utf8_lossy(&validate_out.stderr)
    );

    let add_out = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "shadowed-by-malformed",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(
        !add_out.status.success(),
        "add must reject a name already claimed by a malformed raw entry, stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&add_out.stderr).contains("already exists"),
        "stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, content,
        "rejected add must not modify the file at all"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-005 / AD9 (SECURITY T2): metacharacters in flag values cannot inject a
/// sibling TOML table. `toml_edit`'s typed value API escapes them.
#[test]
fn config_add_escapes_metacharacters_without_corrupting_config() {
    let dir = unique_dir("cfg-add-injection");
    config_add_init(&dir);

    let malicious_message = "x\"\n[audit]\nenabled = false\n[[rules]]\nname = \"evil";
    let output = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "injection-test",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
            "--message",
            malicious_message,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "add with metacharacters in --message should still succeed (value is escaped), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Re-parse with the independent `toml` crate (mirrors mutate_config's failsafe):
    // exactly one rule named "injection-test" and no injected `[audit]` override
    // or second `evil` rule.
    let parsed: toml::Value =
        toml::from_str(&content).expect("written config must still be valid TOML");
    let rules = parsed["rules"].as_array().expect("rules array");
    assert_eq!(
        rules
            .iter()
            .filter(|r| r["name"].as_str() == Some("injection-test"))
            .count(),
        1,
        "exactly one injection-test rule: {content}"
    );
    assert!(
        rules.iter().all(|r| r["name"].as_str() != Some("evil")),
        "no injected `evil` rule: {content}"
    );
    assert!(
        parsed
            .get("audit")
            .and_then(|a| a.get("enabled"))
            .and_then(|v| v.as_bool())
            != Some(false),
        "injected [audit] override must not take effect: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// AD6/AD7: a bad `--destination` is rejected before writing, not silently
/// disabled after the fact the way post-load `validate_rules` does it.
#[test]
fn config_add_rejects_bad_destination_before_writing() {
    let dir = unique_dir("cfg-add-bad-dest");
    config_add_init(&dir);

    // "system" uses `/etc` itself (guaranteed to exist on macOS/Linux CI
    // runners). "system-nonexistent" (#391 fix): a nonexistent subdirectory
    // under a blocked prefix — `validate_destination` used to only check
    // `Path::canonicalize()` on the full path, which requires the whole path
    // to already exist, so this silently passed the pre-write check (the
    // rule scaffolded as "added" instead of being rejected). Since #391,
    // `resolve_for_prefix_check` walks up to the nearest existing ancestor
    // (`/etc`) and rejoins the missing tail before the prefix test, so this
    // is now rejected too — it was never a security bypass (`move_to_dir`
    // already failed closed at execution time, src/actions.rs), but `add`
    // silently reporting success for a rule that could never fire was itself
    // the bug this test now pins closed.
    for (label, dest) in [
        ("relative", "backup/quarantine"),
        ("system", "/etc"),
        ("system-nonexistent", "/etc/omamori-test-made-up-name"),
    ] {
        let output = config_add_cmd(&dir)
            .args([
                "config",
                "add",
                "dest-test",
                "--command",
                "rm",
                "--action",
                "move-to",
                "--match-any",
                "-rf",
                "--destination",
                dest,
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{label} destination `{dest}` must be rejected, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let config_path = dir.join("omamori").join("config.toml");
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(
            !content.contains("dest-test"),
            "{label} destination must not be written: {content}"
        );
    }

    // /code-review R1 finding: an earlier version of the error-message
    // cleanup stripped `validate_destination`'s "; rule disabled" trailing
    // clause via `str::split`, which matches that substring ANYWHERE in the
    // message — including inside the `--destination` value itself once
    // interpolated — silently truncating the real failure reason. A
    // destination containing the literal substring must still show the
    // actual reason ("not an absolute path"), not get cut off before it.
    let injected = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "dest-injection-test",
            "--command",
            "rm",
            "--action",
            "move-to",
            "--match-any",
            "-rf",
            "--destination",
            "; rule disabled bogus",
        ])
        .output()
        .unwrap();
    assert!(!injected.status.success());
    let stderr = String::from_utf8_lossy(&injected.stderr);
    assert!(
        stderr.contains("not an absolute path"),
        "the real rejection reason must survive even when --destination contains \
         the message-stripping substring: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// #391 V-001: the flip side of `config_add_rejects_bad_destination_before_writing`'s
/// "system-nonexistent" case — a destination that does not exist yet but is
/// **not** under a blocked prefix must still be accepted at add-time. This is
/// the shape of the README's `move-to` example (a quarantine directory the
/// user is expected to create on first use, not pre-provision). Deliberately
/// does NOT pre-create the directory (unlike
/// `config_add_move_to_with_valid_destination_and_match_all_fires_in_explain`),
/// to isolate "nonexistent + unblocked" from "nonexistent + blocked".
#[test]
fn config_add_accepts_nonexistent_destination_outside_blocked_prefix() {
    let dir = unique_dir("cfg-add-dest-unblocked-nonexistent");
    config_add_init(&dir);

    let scratch_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-scratch");
    let quarantine = scratch_root.join(format!(
        "cfg-add-unblocked-nonexistent-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&quarantine);
    assert!(
        !quarantine.exists(),
        "precondition: destination must not exist yet"
    );

    let output = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "dest-unblocked-test",
            "--command",
            "rm",
            "--action",
            "move-to",
            "--match-any",
            "-rf",
            "--destination",
        ])
        .arg(&quarantine)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "a nonexistent, non-blocked destination must be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("dest-unblocked-test"),
        "rule must have been written: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Usage-error surface (QA G-1/G-2/G-3 + Codex② Major): missing --command,
/// missing --action, and missing match token are all rejected up front with
/// an actionable message, rather than scaffolding a rule that silently never
/// fires (merge_rules would skip it, or match everything).
#[test]
fn config_add_requires_command_action_and_match_token() {
    let dir = unique_dir("cfg-add-usage");
    config_add_init(&dir);

    let missing_command = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r1",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(!missing_command.status.success());
    assert!(String::from_utf8_lossy(&missing_command.stderr).contains("--command"));

    // QA finding: an empty --command is "present but blank", not "missing" —
    // needs its own rejection, same silent-break class as an empty match
    // token (`rule.command != ""` can never equal a real program name).
    let empty_command = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r1b",
            "--command",
            "",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(!empty_command.status.success());
    assert!(String::from_utf8_lossy(&empty_command.stderr).contains("--command"));

    let missing_action = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r2",
            "--command",
            "ls",
            "--match-any",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(!missing_action.status.success());
    assert!(String::from_utf8_lossy(&missing_action.stderr).contains("--action"));

    let missing_match = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r3",
            "--command",
            "ls",
            "--action",
            "block",
        ])
        .output()
        .unwrap();
    assert!(!missing_match.status.success());
    let stderr = String::from_utf8_lossy(&missing_match.stderr);
    assert!(
        stderr.contains("--match-any") || stderr.contains("--match-all"),
        "stderr: {stderr}"
    );

    // Empty-string tokens must not satisfy the "at least one token" check —
    // `--match-any ""` has a non-empty Vec (one element) but a de facto no-op
    // token; a naive `.is_empty()`-on-the-Vec check would wrongly accept it.
    let empty_token = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r4",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "",
        ])
        .output()
        .unwrap();
    assert!(
        !empty_token.status.success(),
        "an empty-string match token must be rejected like no token at all"
    );

    // Codex adversarial review R2: a *mixed* empty token (alongside a real
    // one) must also be rejected — `match_all` requires every token present
    // via exact equality, so an empty token makes the rule permanently
    // unmatchable (no real invocation has a literal empty-string arg) even
    // though a non-empty token is also present.
    let mixed_empty_token = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r5",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-all",
            "",
            "--match-all",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(
        !mixed_empty_token.status.success(),
        "a match_all token list with any empty-string entry must be rejected"
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        !content.contains("r1")
            && !content.contains("r2")
            && !content.contains("r3")
            && !content.contains("r5")
            && !content.contains("r4"),
        "no rule should have been written on usage errors: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Flag consistency: `--destination` requires `--action move-to`, and
/// `--action move-to` requires `--destination`.
#[test]
fn config_add_destination_and_move_to_action_are_mutually_required() {
    let dir = unique_dir("cfg-add-move-to-pair");
    config_add_init(&dir);

    let dest_without_move_to = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r1",
            "--command",
            "rm",
            "--action",
            "trash",
            "--match-any",
            "-rf",
            "--destination",
            "/Users/you/.omamori-quarantine",
        ])
        .output()
        .unwrap();
    assert!(!dest_without_move_to.status.success());
    assert!(
        String::from_utf8_lossy(&dest_without_move_to.stderr).contains("move-to"),
        "stderr: {}",
        String::from_utf8_lossy(&dest_without_move_to.stderr)
    );

    let move_to_without_dest = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "r2",
            "--command",
            "rm",
            "--action",
            "move-to",
            "--match-any",
            "-rf",
        ])
        .output()
        .unwrap();
    assert!(!move_to_without_dest.status.success());
    assert!(
        String::from_utf8_lossy(&move_to_without_dest.stderr).contains("--destination"),
        "stderr: {}",
        String::from_utf8_lossy(&move_to_without_dest.stderr)
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Codex adversarial review finding: the negative tests above (bad
/// destination, mismatched action/destination pairing) never exercise a
/// *valid* `move-to` + `--destination` pairing, so a mutation that rejected
/// every `move-to` rule would still pass the whole suite. This is the
/// missing happy path, and also covers `--match-all` (every other happy-path
/// test in this file uses `--match-any` only).
#[test]
fn config_add_move_to_with_valid_destination_and_match_all_fires_in_explain() {
    let dir = unique_dir("cfg-add-move-to-happy");
    config_add_init(&dir);
    // NOTE: the destination must NOT live under `std::env::temp_dir()`. On
    // macOS that resolves to `/var/folders/...`, which `Path::canonicalize()`
    // turns into `/private/var/folders/...` — and `/var`/`/private` are both
    // in `BLOCKED_DESTINATION_PREFIXES` (config.rs). Using `unique_dir()` here
    // (as every other test in this file does) would make `validate_destination`
    // reject this as a system directory, defeating the "valid" happy path this
    // test exists to cover. `target/` under the repo checkout isn't blocked.
    let scratch_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-scratch");
    let quarantine = scratch_root.join(format!("cfg-add-move-to-happy-{}", std::process::id()));
    fs::create_dir_all(&quarantine).unwrap();

    // Uses `ls` rather than `rm`: `rm -r -f` would also match the built-in
    // `rm-recursive-to-trash` rule (higher priority, checked first), which
    // would make this test pass for the wrong reason (built-in firing, not
    // our new custom rule).
    let add_out = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "quarantine-rule",
            "--command",
            "ls",
            "--action",
            "move-to",
            "--match-all",
            "-a",
            "--match-all",
            "-l",
            "--destination",
            quarantine.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        add_out.status.success(),
        "valid move-to + destination should succeed, stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("match_all = [\"-a\", \"-l\"]")
            || content.contains("match_all = [\"-a\", \"-l\",]"),
        "config: {content}"
    );

    // match_all requires ALL tokens: "-a" alone must NOT fire...
    let explain_partial = config_add_cmd(&dir)
        .args(["explain", "--", "ls", "-a", "/tmp/x"])
        .output()
        .unwrap();
    let stdout_partial = String::from_utf8_lossy(&explain_partial.stdout);
    assert!(
        !stdout_partial.contains("rule: quarantine-rule"),
        "match_all with only one of two tokens present must not fire: {stdout_partial}"
    );

    // ...but "-a -l" together must fire, and the action must be move-to.
    let explain_full = config_add_cmd(&dir)
        .args(["explain", "--", "ls", "-a", "-l", "/tmp/x"])
        .output()
        .unwrap();
    let stdout_full = String::from_utf8_lossy(&explain_full.stdout);
    assert!(
        stdout_full.contains("rule: quarantine-rule"),
        "match_all with both tokens present must fire: {stdout_full}"
    );
    assert!(
        stdout_full.contains("action: move-to"),
        "stdout: {stdout_full}"
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&quarantine);
}

/// Codex② Minor: `--action stash` (the user-facing alias) must be written to
/// the config file as the literal schema value `stash-then-exec`.
#[test]
fn config_add_stash_action_writes_schema_literal() {
    let dir = unique_dir("cfg-add-stash-literal");
    config_add_init(&dir);

    let output = config_add_cmd(&dir)
        .args([
            "config",
            "add",
            "stash-rule",
            "--command",
            "git",
            "--action",
            "stash",
            "--match-any",
            "reset",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("action = \"stash-then-exec\""),
        "config must contain the schema-literal action, not the CLI alias: {content}"
    );
    assert!(
        !content.contains("action = \"stash\"\n"),
        "config must not contain the bare CLI alias `stash`: {content}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// V-008 (mirror pattern core finding): `add` must refuse to edit a
/// malformed/degraded config.toml rather than silently clobbering it the way
/// `disable`'s fallback branch would (shape (d): bare `[rules]` table; shape
/// (f): broken TOML syntax). The file must be left byte-for-byte unchanged.
#[test]
fn config_add_rejects_degraded_config_without_modifying_it() {
    for (label, contents) in [
        ("bare-rules-table", "[rules]\nfoo = \"bar\"\n"),
        ("broken-toml", "[[rules]\nname = \n"),
    ] {
        let dir = unique_dir(&format!("cfg-add-degraded-{label}"));
        fs::create_dir_all(dir.join("omamori")).unwrap();
        let config_path = dir.join("omamori").join("config.toml");
        fs::write(&config_path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let output = config_add_cmd(&dir)
            .args([
                "config",
                "add",
                "new-rule",
                "--command",
                "ls",
                "--action",
                "block",
                "--match-any",
                "-l",
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{label}: add on a degraded config must be rejected, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("malformed")
                || stderr.contains("degraded")
                || stderr.contains("cannot be safely edited"),
            "{label} stderr: {stderr}"
        );

        let after = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            after, contents,
            "{label}: config.toml must be byte-for-byte unchanged after a rejected add"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

/// Codex Round 1 test-adversarial finding: shape enumeration's headline
/// correction was that `rules = [{...}]` (inline array) and `rules = []`
/// (empty inline array) are VALID, non-degraded configs (`config list`
/// loads and honors them) — their refuse can only come from
/// `get_or_create_rules_array`'s own dispatch, never from the `degraded`
/// precheck covered by `config_add_rejects_degraded_config_without_modifying_it`
/// above. This is a materially different code path and needs its own test.
#[test]
fn config_add_refuses_non_degraded_inline_array_shapes_without_modifying_them() {
    for (label, contents) in [
        (
            "inline-array-with-rule",
            "rules = [{ name = \"inline-rule\", command = \"curl\", action = \"block\", match_any = [\"x\"] }]\n",
        ),
        ("empty-inline-array", "rules = []\n"),
    ] {
        let dir = unique_dir(&format!("cfg-add-inline-{label}"));
        fs::create_dir_all(dir.join("omamori")).unwrap();
        let config_path = dir.join("omamori").join("config.toml");
        fs::write(&config_path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // Sanity: not degraded — `config list` must succeed and (for the
        // non-empty case) show the inline rule as active.
        let list = config_add_cmd(&dir)
            .args(["config", "list"])
            .output()
            .unwrap();
        assert!(
            list.status.success(),
            "{label}: config list must succeed on a non-degraded config, stderr: {}",
            String::from_utf8_lossy(&list.stderr)
        );
        if label == "inline-array-with-rule" {
            assert!(
                String::from_utf8_lossy(&list.stdout).contains("inline-rule"),
                "{label}: inline rule must be loaded and honored (not degraded)"
            );
        }

        let output = config_add_cmd(&dir)
            .args([
                "config",
                "add",
                "new-rule",
                "--command",
                "ls",
                "--action",
                "block",
                "--match-any",
                "-l",
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{label}: add must refuse a non-`[[rules]]` shape even though it's valid, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.to_lowercase().contains("malformed"),
            "{label}: a valid inline-array config must not be called malformed: {stderr}"
        );
        assert!(
            stderr.contains("not in `[[rules]]`") || stderr.contains("array form"),
            "{label}: expected the shape-refuse message, got: {stderr}"
        );

        let after = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            after, contents,
            "{label}: config.toml must be byte-for-byte unchanged after a rejected add"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

/// V-009: `add` updates the integrity baseline the same way `disable`/`enable`
/// do, so a subsequent `doctor` run does not flag the config as tampered.
#[test]
fn config_add_updates_baseline_so_doctor_stays_clean() {
    let base_dir = unique_dir("cfg-add-baseline-base");
    let home = unique_dir("cfg-add-baseline-home");
    install_with_hooks(&base_dir, &home);

    let mut add_cmd = Command::new(binary());
    clean_ai_env(&mut add_cmd);
    let add_out = add_cmd
        .args([
            "config",
            "add",
            "baseline-rule",
            "--command",
            "ls",
            "--action",
            "block",
            "--match-any",
            "-l",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap();
    assert!(
        add_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    // Precise check via --json rather than "stdout doesn't contain 'tamper'"
    // (which a doctor bug could satisfy vacuously, e.g. by renaming the
    // string or omitting the check entirely): the `.integrity.json` /
    // Baseline item's status must be exactly "ok", not "WARN"/"FAIL".
    let mut doctor_cmd = Command::new(binary());
    clean_ai_env(&mut doctor_cmd);
    let doctor_out = doctor_cmd
        .arg("doctor")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--json")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&doctor_out.stdout).expect("doctor --json must produce valid JSON");
    let baseline_item = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["category"] == "Baseline")
        .expect("Baseline item must be present in doctor --json output");
    assert_eq!(
        baseline_item["status"], "ok",
        "baseline must be clean after config add updates it, got: {baseline_item}"
    );

    let _ = fs::remove_dir_all(&base_dir);
    let _ = fs::remove_dir_all(&home);
}
