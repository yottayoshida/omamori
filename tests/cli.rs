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
    let fake_bin = dir.join("omamori");
    fs::write(&fake_bin, "binary").unwrap();

    let output = Command::new(binary())
        .arg("install")
        .arg("--base-dir")
        .arg(dir.to_str().unwrap())
        .arg("--source")
        .arg(fake_bin.to_str().unwrap())
        .arg("--hooks")
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
}

// ---------------------------------------------------------------------------
// hook-check Auto mode compatibility tests (#62)
// ---------------------------------------------------------------------------

/// Run `omamori hook-check --provider claude-code` with given stdin input.
/// Returns (stdout, stderr, exit_code).
fn run_hook_check(input: &str) -> (String, String, i32) {
    let mut child = Command::new(binary())
        .args(["hook-check", "--provider", "claude-code"])
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

/// V-004, V-005: BLOCK (meta-pattern) — stdout empty, exit code 2
#[test]
fn hook_check_block_meta_has_empty_stdout_and_exit_2() {
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

/// #110 S2: export -n meta-pattern blocks unexport of detector env vars.
#[test]
fn hook_check_blocks_export_n_claudecode() {
    let (_, stderr, exit_code) =
        run_hook_check(&pretooluse_bash_json("export -n CLAUDECODE && echo hi"));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("unexport"));
}

/// #110 T3: Bash command editing settings.json is blocked by meta-pattern.
#[test]
fn hook_check_blocks_bash_settings_json_edit() {
    let (_, stderr, exit_code) = run_hook_check(&pretooluse_bash_json(
        "sed -i '' 's/omamori//' ~/.claude/settings.json",
    ));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("Claude Code settings"));
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
// hook-check meta-pattern tests (pre-existing)
// ---------------------------------------------------------------------------

#[test]
fn hook_check_blocks_integrity_json() {
    // Verify meta-patterns block .integrity.json editing
    // (previously checked in hook script, now delegated to hook-check via meta-patterns)
    let patterns = omamori::installer::blocked_command_patterns();
    assert!(
        patterns.iter().any(|(p, _)| p.contains(".integrity.json")),
        "meta-patterns should block .integrity.json editing"
    );
}

#[test]
fn blocked_patterns_include_integrity_json() {
    let patterns = omamori::installer::blocked_command_patterns();
    let has_integrity = patterns.iter().any(|(p, _)| p.contains(".integrity.json"));
    assert!(
        has_integrity,
        "blocked_command_patterns should include .integrity.json"
    );
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

/// V-001 (Codex): meta-pattern block (direct path bypass)
#[test]
fn codex_hook_check_block_meta_pattern() {
    let (_, stderr, exit_code) = run_hook_check(&codex_pretooluse_json("/bin/rm -rf /important"));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("blocked"));
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

/// Codex meta-pattern: block editing .codex/hooks.json
#[test]
fn codex_hook_check_blocks_hooks_json_edit() {
    let (_, stderr, exit_code) = run_hook_check(&codex_pretooluse_json(
        "sed -i '' 's/omamori/true/' ~/.codex/hooks.json",
    ));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("blocked"));
}

/// Codex meta-pattern: block editing .codex/config.toml
#[test]
fn codex_hook_check_blocks_config_toml_edit() {
    let (_, stderr, exit_code) = run_hook_check(&codex_pretooluse_json(
        "echo 'codex_hooks = false' > ~/.codex/config.toml",
    ));
    assert_eq!(exit_code, 2);
    assert!(stderr.contains("blocked"));
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
