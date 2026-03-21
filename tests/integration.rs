use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn clean_ai_env(cmd: &mut Command) -> &mut Command {
    cmd.env_remove("CLAUDECODE")
        .env_remove("CODEX_CI")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env_remove("CLINE_ACTIVE")
        .env_remove("AI_GUARD")
}

fn unique_dir(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("omamori-{name}-{nanos}"))
}

#[test]
fn install_creates_shims_without_touching_shell_config() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .output()
        .expect("failed to run install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(base_dir.join("shim/rm").exists());
    assert!(base_dir.join("shim/git").exists());
    assert!(base_dir.join("hooks/claude-pretooluse.sh").exists());
    assert!(base_dir.join("hooks/claude-settings.snippet.json").exists());
    assert!(base_dir.join("hooks/cursor-hooks.snippet.json").exists());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[todo] Add to your shell profile"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Shims:"), "stdout: {stdout}");
    assert!(stdout.contains("Hooks:"), "stdout: {stdout}");
    assert!(stdout.contains("Cursor hook snippet"), "stdout: {stdout}");

    let _ = fs::remove_dir_all(base_dir);
}

#[test]
fn uninstall_removes_generated_artifacts() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("uninstall");

    let install_status = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .status()
        .expect("failed to run install");
    assert!(install_status.success());

    let mut uninstall_cmd = Command::new(binary);
    clean_ai_env(&mut uninstall_cmd);
    let uninstall_output = uninstall_cmd
        .arg("uninstall")
        .arg("--base-dir")
        .arg(&base_dir)
        .output()
        .expect("failed to run uninstall");

    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );
    assert!(!base_dir.join("shim/rm").exists());
    assert!(!base_dir.exists());
}

// ---------------------------------------------------------------------------
// install auto-config tests
// ---------------------------------------------------------------------------

#[test]
fn install_auto_creates_config_when_missing() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-autoconfig");
    let config_dir = unique_dir("install-autoconfig-xdg");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[done] Created"),
        "should auto-create config: {stdout}"
    );
    assert!(
        config_dir.join("omamori").join("config.toml").exists(),
        "config.toml should exist"
    );

    let _ = fs::remove_dir_all(base_dir);
    let _ = fs::remove_dir_all(config_dir);
}

#[test]
fn install_skips_existing_config() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-skipconfig");
    let config_dir = unique_dir("install-skipconfig-xdg");
    let omamori_dir = config_dir.join("omamori");
    fs::create_dir_all(&omamori_dir).unwrap();
    let config_path = omamori_dir.join("config.toml");
    fs::write(&config_path, "# my custom config\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run install");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[skip] Already exists"),
        "should skip existing config: {stdout}"
    );

    // Verify existing config wasn't modified
    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, "# my custom config\n");

    let _ = fs::remove_dir_all(base_dir);
    let _ = fs::remove_dir_all(config_dir);
}

#[test]
fn install_runs_auto_test() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-autotest");
    let config_dir = unique_dir("install-autotest-xdg");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run install");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rules verified"),
        "should show auto-test results: {stdout}"
    );

    let _ = fs::remove_dir_all(base_dir);
    let _ = fs::remove_dir_all(config_dir);
}

// ---------------------------------------------------------------------------
// config list tests
// ---------------------------------------------------------------------------

#[test]
fn config_list_shows_all_rules() {
    let binary = env!("CARGO_BIN_EXE_omamori");

    let output = Command::new(binary)
        .args(["config", "list"])
        .output()
        .expect("failed to run config list");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rm-recursive-to-trash"));
    assert!(stdout.contains("git-push-force-block"));
    assert!(stdout.contains("chmod-777-block"));
    assert!(stdout.contains("active"));
    assert!(stdout.contains("core"));
}

#[test]
fn config_list_shows_overridden_core_rule() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfglist-overridden");
    let omamori_dir = config_dir.join("omamori");
    fs::create_dir_all(&omamori_dir).unwrap();
    let config_path = omamori_dir.join("config.toml");
    // Core rule disabled via [overrides] section
    fs::write(&config_path, "[overrides]\ngit-push-force-block = false\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(binary)
        .args(["config", "list"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run config list");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("disabled"),
        "should show disabled: {stdout}"
    );
    assert!(
        stdout.contains("core (overridden)"),
        "source should be core (overridden): {stdout}"
    );

    let _ = fs::remove_dir_all(config_dir);
}

#[test]
fn config_list_ignores_core_rule_disabled_in_rules_section() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfglist-core-ignore");
    let omamori_dir = config_dir.join("omamori");
    fs::create_dir_all(&omamori_dir).unwrap();
    let config_path = omamori_dir.join("config.toml");
    // Core rule with enabled = false in [[rules]] but no [overrides] entry
    fs::write(
        &config_path,
        "[[rules]]\nname = \"git-push-force-block\"\nenabled = false\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(binary)
        .args(["config", "list"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to run config list");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Core rule should still show as active (immutability)
    let push_force_line = stdout
        .lines()
        .find(|l| l.contains("git-push-force-block"))
        .unwrap_or("");
    assert!(
        push_force_line.contains("active") && push_force_line.contains("core"),
        "core rule should stay active: {push_force_line}"
    );

    // Should have a warning about the ignored override
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("core safety rule"),
        "should warn about ignored override: {stderr}"
    );

    let _ = fs::remove_dir_all(config_dir);
}

// ---------------------------------------------------------------------------
// config disable/enable tests
// ---------------------------------------------------------------------------

#[test]
fn config_disable_core_rule_rejected_with_hint() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-core");

    let output = Command::new(binary)
        .args(["init"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Try to disable a core rule via `config disable` — should fail
    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "should be rejected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("core safety rule"));
    assert!(stderr.contains("omamori override disable"));

    let _ = fs::remove_dir_all(&config_dir);
}

#[test]
fn override_disable_then_enable_roundtrip() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-override-roundtrip");

    Command::new(binary)
        .args(["init"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // Override disable
    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["override", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify config has [overrides] section
    let config_path = config_dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("[overrides]") && content.contains("git-push-force-block = false"),
        "should have overrides section: {content}"
    );

    // Override enable (restore)
    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["override", "enable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Verify override entry is removed
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        !content.contains("git-push-force-block = false"),
        "override entry should be removed: {content}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

#[test]
fn config_disable_already_disabled_returns_error_for_core() {
    let binary = env!("CARGO_BIN_EXE_omamori");

    // For core rules, `config disable` always returns an error (not exit 2)
    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "disable", "git-push-force-block"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("core safety rule"));

    // No cleanup needed
}

#[test]
fn config_disable_unknown_rule_fails() {
    let binary = env!("CARGO_BIN_EXE_omamori");

    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    let output = cmd
        .args(["config", "disable", "nonexistent-rule"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown rule"));
}
