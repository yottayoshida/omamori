use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[todo] Add to your shell profile"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("[done] Shims installed"),
        "stdout: {stdout}"
    );

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

    let uninstall_output = Command::new(binary)
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
        stdout.contains("[done] Config created"),
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
        stdout.contains("[skip] Config already exists"),
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
        stdout.contains("[done] All rules verified"),
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
    assert!(stdout.contains("built-in"));
}

#[test]
fn config_list_shows_disabled_rule() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfglist-disabled");
    let omamori_dir = config_dir.join("omamori");
    fs::create_dir_all(&omamori_dir).unwrap();
    let config_path = omamori_dir.join("config.toml");
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
    assert!(
        stdout.contains("disabled"),
        "should show disabled: {stdout}"
    );
    assert!(
        stdout.contains("config (disabled)"),
        "source should be config (disabled): {stdout}"
    );

    let _ = fs::remove_dir_all(config_dir);
}

// ---------------------------------------------------------------------------
// config disable/enable tests
// ---------------------------------------------------------------------------

#[test]
fn config_disable_adds_block() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable");
    let config_path = config_dir.join("omamori").join("config.toml");

    // Init a fresh config
    let output = Command::new(binary)
        .args(["init"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(output.status.success());

    // Disable a rule
    let output = Command::new(binary)
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Disabled: git-push-force-block"));

    // Verify config file contains the disable block
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[[rules]]\nname = \"git-push-force-block\"\nenabled = false"));

    // config list should show disabled
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("disabled"));

    let _ = fs::remove_dir_all(&config_dir);
}

#[test]
fn config_enable_removes_block() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable");

    // Init + disable
    Command::new(binary)
        .args(["init"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    Command::new(binary)
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // Enable it back
    let output = Command::new(binary)
        .args(["config", "enable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Enabled: git-push-force-block"));

    // Verify the active disable block is removed (commented lines may still have "enabled = false")
    let config_path = config_dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        !content.contains("[[rules]]\nname = \"git-push-force-block\"\nenabled = false"),
        "disable block should be removed from config"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

#[test]
fn config_disable_already_disabled_returns_2() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-dup");

    Command::new(binary)
        .args(["init"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();
    Command::new(binary)
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    // Try to disable again
    let output = Command::new(binary)
        .args(["config", "disable", "git-push-force-block"])
        .env("XDG_CONFIG_HOME", &config_dir)
        .env_remove("HOME")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already disabled"));

    let _ = fs::remove_dir_all(&config_dir);
}

#[test]
fn config_disable_unknown_rule_fails() {
    let binary = env!("CARGO_BIN_EXE_omamori");

    let output = Command::new(binary)
        .args(["config", "disable", "nonexistent-rule"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown rule"));
}
