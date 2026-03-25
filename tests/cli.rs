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
fn cursor_hook_handles_malformed_stdin() {
    let (stdout, _, success) = run_cursor_hook("not json at all");
    assert!(success);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON even on bad input");
    assert_eq!(parsed["continue"], true);
    assert_eq!(parsed["permission"], "allow");
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

/// V-010: Malformed (non-JSON) input still returns ALLOW JSON
#[test]
fn hook_check_malformed_input_returns_allow_json() {
    let (stdout, _, exit_code) = run_hook_check("this is not json at all");
    assert_eq!(exit_code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("malformed input must still return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
}

/// V-006 variant: Completely empty stdin returns ALLOW JSON
#[test]
fn hook_check_empty_stdin_returns_allow_json() {
    let (stdout, _, exit_code) = run_hook_check("");
    assert_eq!(exit_code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("empty stdin must return valid JSON");
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
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
