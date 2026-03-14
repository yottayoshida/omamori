use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("omamori-{name}-{nanos}.toml"))
}

#[test]
fn omamori_test_command_succeeds_with_defaults() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let output = Command::new(binary)
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
    let binary = env!("CARGO_BIN_EXE_omamori");
    let path = unique_path("broken");
    fs::write(&path, "[[rules]\nname = ").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = Command::new(binary)
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
    assert!(stderr.contains("using built-in default rules"));
}
