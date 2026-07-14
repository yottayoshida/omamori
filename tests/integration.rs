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

/// A throwaway `$HOME` for subprocess install/uninstall tests (#210).
///
/// Without pinning `HOME` here, the child process resolves the *developer's
/// real* `~/.claude` and `~/.codex` via `claude_home_dir()`/`codex_home_dir()`
/// and merges a hook entry pointing at this test's `--base-dir` — which is
/// deleted at the end of the test, leaving a dangling command path in the
/// developer's real settings.json/hooks.json.
fn isolated_home(name: &str) -> std::path::PathBuf {
    let dir = unique_dir(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn install_creates_shims_without_touching_shell_config() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install");
    let home = isolated_home("install-home");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("HOME", &home)
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
    assert!(stdout.contains("Add to"), "stdout: {stdout}");
    assert!(stdout.contains("Layer 1"), "stdout: {stdout}");
    assert!(stdout.contains("Layer 2"), "stdout: {stdout}");
    assert!(stdout.contains("Cursor"), "stdout: {stdout}");

    let _ = fs::remove_dir_all(base_dir);
    let _ = fs::remove_dir_all(home);
}

#[test]
fn uninstall_removes_generated_artifacts() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("uninstall");
    // Shared across install+uninstall: uninstall's remove_claude_settings_entry
    // must find (and only remove) the entry this test's install created —
    // not the developer's real canonical entry (#210 delete-path variant).
    // `.claude` is pre-created (unlike other isolated_home() uses) so the
    // merge/remove logic is actually exercised rather than short-circuiting
    // on "Claude Code not detected".
    let home = isolated_home("uninstall-home");
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    let install_status = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("HOME", &home)
        .status()
        .expect("failed to run install");
    assert!(install_status.success());
    assert!(
        claude_dir.join("settings.json").exists(),
        "install should have merged an entry into the isolated claude_dir"
    );

    let mut uninstall_cmd = Command::new(binary);
    clean_ai_env(&mut uninstall_cmd);
    let uninstall_output = uninstall_cmd
        .arg("uninstall")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .output()
        .expect("failed to run uninstall");

    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );
    assert!(!base_dir.join("shim/rm").exists());
    assert!(!base_dir.exists());

    let settings_content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
    assert!(
        !settings_content.contains("x-omamori-version"),
        "uninstall should have removed the omamori entry from the isolated claude_dir: {settings_content}"
    );

    let _ = fs::remove_dir_all(home);
}

/// #357 end-to-end: a symlinked `~/.codex/hooks.json` must survive
/// `omamori uninstall` untouched via the real CLI binary — the unit tests in
/// `installer.rs` cover `remove_codex_hooks_entry()` directly, but this
/// proves the guard is actually reached from the full uninstall command path.
#[test]
#[cfg(unix)]
fn uninstall_skips_symlinked_codex_hooks_json() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("uninstall-codex-symlink");
    let home = isolated_home("uninstall-codex-symlink-home");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();

    let mut install_cmd = Command::new(binary);
    clean_ai_env(&mut install_cmd);
    let install_status = install_cmd
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("HOME", &home)
        .status()
        .expect("failed to run install");
    assert!(install_status.success());
    let generated = codex_dir.join("hooks.json");
    assert!(generated.exists(), "install should have written hooks.json");

    // Swap the generated file for a symlink pointing at it under another name.
    let real = home.join("real-hooks.json");
    fs::rename(&generated, &real).unwrap();
    std::os::unix::fs::symlink(&real, &generated).unwrap();

    let mut uninstall_cmd = Command::new(binary);
    clean_ai_env(&mut uninstall_cmd);
    let uninstall_output = uninstall_cmd
        .arg("uninstall")
        .arg("--base-dir")
        .arg(&base_dir)
        .env("HOME", &home)
        .output()
        .expect("failed to run uninstall");
    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );

    assert!(
        generated
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "hooks.json symlink must survive uninstall untouched"
    );
    let real_content = fs::read_to_string(&real).unwrap();
    assert!(
        real_content.contains("omamori: checking command safety"),
        "symlink target content must be untouched by uninstall: {real_content}"
    );

    let _ = fs::remove_dir_all(base_dir);
    let _ = fs::remove_dir_all(home);
}

// ---------------------------------------------------------------------------
// install auto-config tests
// ---------------------------------------------------------------------------

#[test]
fn install_auto_creates_config_when_missing() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-autoconfig");
    let config_dir = unique_dir("install-autoconfig-xdg");
    // #210: this test's intent is "config resolution honors XDG_CONFIG_HOME",
    // not "behavior when HOME is unset". `env_remove("HOME")` previously hit
    // the `.` fallback in claude_home_dir()/codex_home_dir() and merged a
    // dead hook path into this process's CWD-relative `./.claude`. Pin HOME
    // to a throwaway dir instead — XDG_CONFIG_HOME still takes precedence
    // for config resolution (config.rs), so the assertion below is unaffected.
    let home = isolated_home("install-autoconfig-home");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env("HOME", &home)
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
    let _ = fs::remove_dir_all(home);
}

#[test]
fn install_skips_existing_config() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-skipconfig");
    let config_dir = unique_dir("install-skipconfig-xdg");
    let omamori_dir = config_dir.join("omamori");
    fs::create_dir_all(&omamori_dir).unwrap();
    let config_path = omamori_dir.join("config.toml");
    write_config(&config_path, "# my custom config\n");
    // #210: see install_auto_creates_config_when_missing for why HOME is
    // pinned rather than removed.
    let home = isolated_home("install-skipconfig-home");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env("HOME", &home)
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
    let _ = fs::remove_dir_all(home);
}

#[test]
fn install_runs_auto_test() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let base_dir = unique_dir("install-autotest");
    let config_dir = unique_dir("install-autotest-xdg");
    // #210: see install_auto_creates_config_when_missing for why HOME is
    // pinned rather than removed.
    let home = isolated_home("install-autotest-home");

    let output = Command::new(binary)
        .arg("install")
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--source")
        .arg(binary)
        .arg("--hooks")
        .env("XDG_CONFIG_HOME", &config_dir)
        .env("HOME", &home)
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
    let _ = fs::remove_dir_all(home);
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
    write_config(&config_path, "[overrides]\ngit-push-force-block = false\n");

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

// -----------------------------------------------------------------------
// #388/#389: custom rule toggling + shared get_or_create_rules_array
//
// `run_config_disable`'s mutate path was, until #388, unreachable from the
// CLI (any name that passed the old core-only `validate_rule_name` was
// always redirected to `override disable` immediately after) — so every
// row below is a first-ever execution of that code path, not a regression
// guard for something previously tested.
// -----------------------------------------------------------------------

fn omamori_cmd(binary: &str, config_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(binary);
    clean_ai_env(&mut cmd);
    cmd.env("XDG_CONFIG_HOME", config_dir).env_remove("HOME");
    cmd
}

/// Write `contents` to `path` and (on unix) chmod it 0600, matching the
/// permissions `omamori init`-created configs already have — several tests
/// below hand-write a config.toml directly to set up a specific TOML shape.
fn write_config(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Scope a config.toml assertion to one rule's own `[[rules]]` block —
/// `config_template()`'s commented-out `# [[rules]]` boilerplate for every
/// built-in would false-positive a whole-file substring check.
fn rule_block<'a>(content: &'a str, name: &str) -> &'a str {
    content
        .split("[[rules]]")
        .find(|block| block.contains(name))
        .unwrap_or_else(|| panic!("no [[rules]] block found for `{name}` in: {content}"))
}

/// #388 V-005: the core fix — a `config add`-created custom rule can now be
/// toggled off and back on via `config disable`/`config enable`, and the
/// rule body itself survives the round-trip (not deleted, not replaced with
/// a stub).
#[test]
fn config_add_disable_enable_roundtrip_for_custom_rule() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-custom-roundtrip");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let add = omamori_cmd(binary, &config_dir)
        .args([
            "config",
            "add",
            "my-custom-guard",
            "--command",
            "curl",
            "--action",
            "block",
            "--match-any",
            "evil.example",
        ])
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "add stderr: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // Was previously rejected as "unknown rule" (#388 bug).
    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "my-custom-guard"])
        .output()
        .unwrap();
    assert!(
        disable.status.success(),
        "custom rule must now be disable-able, stderr: {}",
        String::from_utf8_lossy(&disable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&disable.stderr).contains("restored to built-in default"),
        "a custom rule is not a built-in and must not claim to be restored to one"
    );

    let config_path = config_dir.join("omamori").join("config.toml");
    let after_disable = fs::read_to_string(&config_path).unwrap();
    // Scoped to the live `[[rules]]` block for this rule — the config
    // *template* separately contains commented-out `# # enabled = false`
    // boilerplate for every built-in, which would false-positive a
    // whole-file substring check for either half of this assertion.
    let disabled_block = rule_block(&after_disable, "my-custom-guard");
    assert!(
        disabled_block.contains("curl") && disabled_block.contains("enabled = false"),
        "rule body (command/action) must survive disable, only `enabled` should flip: {disabled_block}"
    );

    let list = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_out.contains("my-custom-guard") && list_out.contains("disabled"),
        "disabled custom rule must still be listed: {list_out}"
    );

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "my-custom-guard"])
        .output()
        .unwrap();
    assert!(
        enable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&enable.stderr).contains("restored to built-in default"),
        "custom-rule enable must not claim built-in restoration"
    );

    let after_enable = fs::read_to_string(&config_path).unwrap();
    assert!(
        after_enable.contains("my-custom-guard") && after_enable.contains("curl"),
        "rule body must survive enable too (not deleted by the core-rule stub-cleanup path): \
         {after_enable}"
    );
    // Scope the `enabled = false` check to the live `[[rules]]` block for
    // this rule specifically — the config *template* itself contains
    // commented-out `# # enabled = false` boilerplate for every built-in,
    // which would false-positive a whole-file substring check.
    let live_block = rule_block(&after_enable, "my-custom-guard");
    assert!(
        !live_block.contains("enabled = false"),
        "enabled=false must have been removed from my-custom-guard's own block: {live_block}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// #389: a hand-written bare `[rules]` table (not `[[rules]]`) with real
/// user data must be refused, not silently clobbered the way the old
/// `disable` else-branch did (`doc.insert("rules", ...)` overwrote whatever
/// was there).
#[test]
fn config_disable_refuses_bare_rules_table_without_clobbering() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-bare-table");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let hostile = "[rules]\nmy_setting = \"keep me\"\n";
    write_config(&config_path, hostile);

    // Codex Round 1 test-adversarial finding: use a name that is neither a
    // core rule nor a real custom rule ("totally-bogus-name"), not
    // "git-push-force-block". `reject_if_degraded` must run — and produce
    // its "malformed" message — *before* `validate_rule_name`/`is_core_rule`
    // are even reached; using a real core rule name here would make the
    // test pass even if a mutation reordered those checks (a core-rule
    // rejection and a malformed-config rejection are both "fails, file
    // unchanged", but for different reasons). Asserting the message content
    // below, not just failure + unchanged file, is what actually
    // distinguishes them.
    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "totally-bogus-name"])
        .output()
        .unwrap();
    assert!(
        !disable.status.success(),
        "must refuse rather than silently clobber: stdout={} stderr={}",
        String::from_utf8_lossy(&disable.stdout),
        String::from_utf8_lossy(&disable.stderr)
    );
    let stderr = String::from_utf8_lossy(&disable.stderr);
    assert!(
        stderr.contains("malformed"),
        "expected the malformed-config refuse message (proving reject_if_degraded fired \
         before any rule-name check), got: {stderr}"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, hostile,
        "config.toml must be byte-for-byte unchanged after a refused disable"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// #389 V-013 (shape enumeration correction): `rules = [{...}]` is a VALID,
/// working inline-array config (not malformed — `degraded` is `false`) —
/// its refuse can only come from `get_or_create_rules_array`'s own dispatch,
/// never from a `degraded` precheck. This is the one shape row the plan's
/// first draft got wrong before the shape-enumeration agent caught it.
#[test]
fn config_disable_refuses_inline_array_rules_without_degraded() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-inline-array");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let inline = "rules = [{ name = \"inline-rule\", command = \"curl\", action = \"block\", match_any = [\"x\"] }]\n";
    write_config(&config_path, inline);

    // Sanity: this config is NOT degraded — `config list` must show the
    // inline rule as active, proving omamori actually honors this shape.
    let list = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("inline-rule"),
        "inline-array rule must load and be honored (not degraded): {}",
        String::from_utf8_lossy(&list.stdout)
    );

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "inline-rule"])
        .output()
        .unwrap();
    assert!(
        !disable.status.success(),
        "must refuse — in-place `enabled` rewrite only works on `[[rules]]` form"
    );
    let stderr = String::from_utf8_lossy(&disable.stderr);
    assert!(
        !stderr.to_lowercase().contains("malformed"),
        "an inline-array config is valid and working — must not be called malformed: {stderr}"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, inline,
        "config.toml must be unchanged after the refusal"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// #389: a config with a type error (`enabled` as a string, not bool)
/// degrades the *whole* file — `disable` must refuse rather than silently
/// operating on the fallback-to-core-defaults state.
#[test]
fn config_disable_refuses_degraded_config() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-degraded");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let degraded = "[[rules]]\nname = \"bad-type\"\ncommand = \"curl\"\naction = \"block\"\nmatch_any = [\"x\"]\nenabled = \"false\"\n";
    write_config(&config_path, degraded);

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "git-push-force-block"])
        .output()
        .unwrap();
    assert!(!disable.status.success());
    let stderr = String::from_utf8_lossy(&disable.stderr);
    assert!(
        stderr.contains("malformed") || stderr.contains("config validate"),
        "expected the malformed-config refuse message, got: {stderr}"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, degraded,
        "config.toml must be unchanged after the refusal"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// #389 V-015: an in-place `enabled` rewrite only touches the *first*
/// `[[rules]]` entry matching a name — with a duplicate, `disable` must
/// refuse rather than silently rewriting one of the two and reporting
/// success.
#[test]
fn config_disable_refuses_duplicate_named_entries() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-dup");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let dup = "[[rules]]\nname = \"dup-rule\"\ncommand = \"curl\"\naction = \"block\"\nmatch_any = [\"x\"]\n\n\
               [[rules]]\nname = \"dup-rule\"\ncommand = \"wget\"\naction = \"block\"\nmatch_any = [\"y\"]\n";
    write_config(&config_path, dup);

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "dup-rule"])
        .output()
        .unwrap();
    assert!(
        !disable.status.success(),
        "must refuse rather than guess which duplicate to disable"
    );
    let stderr = String::from_utf8_lossy(&disable.stderr);
    assert!(
        stderr.contains("more than once"),
        "expected a duplicate-name message, got: {stderr}"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, dup,
        "config.toml must be unchanged after the refusal"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// Codex Round 1 finding: a rule can be effectively disabled by *validation*
/// (a `move-to` rule with a destination under a blocked prefix) while its
/// raw `[[rules]]` entry has no explicit `enabled = false`. `config disable`
/// must not read that merged/validated state as "already disabled" — doing
/// so would skip writing the raw `enabled = false`, and fixing the
/// destination later would silently reactivate the rule despite this
/// `disable` having reported success moments earlier.
#[test]
fn config_disable_writes_raw_enabled_even_when_validation_already_disables_it() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-validation-disabled");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    // No explicit `enabled` key — the rule is only effectively disabled by
    // validation, because `/etc/...` resolves under a blocked prefix.
    let effectively_disabled = "[[rules]]\nname = \"bad-dest-rule\"\ncommand = \"curl\"\naction = \"move-to\"\ndestination = \"/etc/omamori-test-validation-disabled\"\nmatch_any = [\"x\"]\n";
    write_config(&config_path, effectively_disabled);

    // Sanity: `config list` shows it as disabled (by validation, not by an
    // explicit raw toggle) before we ever run `config disable`.
    let list_before = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_before_out = String::from_utf8_lossy(&list_before.stdout);
    assert!(
        list_before_out.contains("bad-dest-rule") && list_before_out.contains("disabled"),
        "expected the rule to already show as disabled (by validation): {list_before_out}"
    );

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "bad-dest-rule"])
        .output()
        .unwrap();
    assert!(
        disable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&disable.stderr).contains("already disabled"),
        "must not treat validation-forced disable as \"already disabled\" — the raw \
         `enabled` key was never actually written"
    );

    let after_disable = fs::read_to_string(&config_path).unwrap();
    let block = rule_block(&after_disable, "bad-dest-rule");
    assert!(
        block.contains("enabled = false"),
        "the raw `enabled = false` must actually be written: {block}"
    );

    // Now fix the destination by hand (simulating the user resolving the
    // validation issue) and confirm the rule STAYS disabled — this is the
    // crux of the bug: without the raw write above, it would silently
    // reactivate here.
    let fixed = after_disable.replace(
        "/etc/omamori-test-validation-disabled",
        &config_dir.join("fixed-destination").display().to_string(),
    );
    fs::write(&config_path, &fixed).unwrap();

    let list_after_fix = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_after_fix_out = String::from_utf8_lossy(&list_after_fix.stdout);
    let rule_line = list_after_fix_out
        .lines()
        .find(|line| line.contains("bad-dest-rule"))
        .expect("bad-dest-rule must still be listed");
    assert!(
        rule_line.contains("disabled"),
        "rule must remain disabled after the destination is fixed — the explicit \
         disable must survive independent of the validation issue: {rule_line}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// #388: the "unknown rule" error must list existing custom rule names too
/// (previously only the 14 built-ins), so a typo'd name doesn't look like
/// the rule you just added was silently dropped.
#[test]
fn config_disable_unknown_rule_lists_custom_names_too() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-unknown-lists-custom");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();
    omamori_cmd(binary, &config_dir)
        .args([
            "config",
            "add",
            "my-listed-guard",
            "--command",
            "curl",
            "--action",
            "block",
            "--match-any",
            "x",
        ])
        .output()
        .unwrap();

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "typo-of-my-guard"])
        .output()
        .unwrap();
    assert!(!disable.status.success());
    let stderr = String::from_utf8_lossy(&disable.stderr);
    assert!(
        stderr.contains("unknown rule") && stderr.contains("my-listed-guard"),
        "expected the custom rule name in the known-rules list: {stderr}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

// -----------------------------------------------------------------------
// Codex Round 1 test-adversarial review: `enable`-side mirrors of the
// raw-vs-merged `enabled` state fix and the `is_builtin`/`key_count <= 2`
// boundary, which the original test pass only covered from the `disable`
// side.
// -----------------------------------------------------------------------

/// Mirror of `config_disable_writes_raw_enabled_even_when_validation_already_disables_it`:
/// a rule can be explicitly disabled (raw `enabled = false`) while ALSO
/// being effectively disabled by validation (a bad destination) for an
/// unrelated reason. `config enable` must still remove the raw `enabled =
/// false` (undoing the explicit disable), even though the rule correctly
/// remains disabled overall until the destination is separately fixed.
#[test]
fn config_enable_removes_raw_disable_independently_of_validation_state() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-validation-disabled");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let explicitly_and_validation_disabled = "[[rules]]\nname = \"bad-dest-rule-2\"\ncommand = \"curl\"\naction = \"move-to\"\ndestination = \"/etc/omamori-test-enable-validation-disabled\"\nmatch_any = [\"x\"]\nenabled = false\n";
    write_config(&config_path, explicitly_and_validation_disabled);

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "bad-dest-rule-2"])
        .output()
        .unwrap();
    assert!(
        enable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&enable.stderr).contains("already enabled"),
        "the raw `enabled = false` was never actually removed if this fires"
    );

    let after_enable = fs::read_to_string(&config_path).unwrap();
    let block = rule_block(&after_enable, "bad-dest-rule-2");
    assert!(
        !block.contains("enabled = false"),
        "the explicit raw disable must have been removed: {block}"
    );

    // The rule must still show as disabled overall — the destination issue
    // is a separate, still-unresolved problem `enable` cannot paper over.
    let list_still_disabled = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_out = String::from_utf8_lossy(&list_still_disabled.stdout);
    let rule_line = list_out
        .lines()
        .find(|line| line.contains("bad-dest-rule-2"))
        .expect("rule must still be listed");
    assert!(
        rule_line.contains("disabled"),
        "rule must remain effectively disabled (bad destination): {rule_line}"
    );

    // Now fix the destination — the rule should finally become active,
    // since both the raw disable AND the validation issue are resolved.
    // NOTE: must not be under `config_dir` (built from `unique_dir()`, i.e.
    // `std::env::temp_dir()` — `/var/folders/...` on macOS, itself under
    // the blocked `/var` prefix) or the "fix" would still resolve under a
    // blocked prefix and the rule would incorrectly stay disabled,
    // vacuously passing the assertion below for the wrong reason.
    // `target/test-scratch` under the repo checkout is never blocked.
    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-scratch")
        .join(format!(
            "cfg-enable-validation-fixed-{}",
            std::process::id()
        ));
    let fixed = after_enable.replace(
        "/etc/omamori-test-enable-validation-disabled",
        &scratch.display().to_string(),
    );
    fs::write(&config_path, &fixed).unwrap();
    let list_after_fix = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_after_fix_out = String::from_utf8_lossy(&list_after_fix.stdout);
    let rule_line_after_fix = list_after_fix_out
        .lines()
        .find(|line| line.contains("bad-dest-rule-2"))
        .expect("rule must still be listed");
    assert!(
        rule_line_after_fix.contains("active"),
        "rule must become active once both the raw disable and the destination \
         issue are resolved: {rule_line_after_fix}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// `enable`'s `is_builtin && key_count <= 2` cleanup branch must delete a
/// raw 2-key core-rule stub (`{name, enabled=false}`, as a hand-written
/// override or one that predates #388) entirely, restoring the built-in
/// default — proving the `<=` boundary (not e.g. `<`) and the `is_builtin`
/// gate both actually fire for this shape.
#[test]
fn config_enable_deletes_two_key_core_rule_stub_entirely() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-core-stub");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let stub = "[[rules]]\nname = \"git-push-force-block\"\nenabled = false\n";
    write_config(&config_path, stub);

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "git-push-force-block"])
        .output()
        .unwrap();
    assert!(
        enable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enable.stderr)
    );
    assert!(
        String::from_utf8_lossy(&enable.stderr).contains("restored to built-in default"),
        "a core rule's enable message must say restored-to-default"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert!(
        !after.contains("git-push-force-block"),
        "the 2-key stub must be deleted entirely, not left as an empty/partial block: {after}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// The `is_builtin` gate on the `key_count <= 2` deletion branch must never
/// apply to a custom rule, even a minimal 3-key one (name/command/action,
/// no match tokens — a legitimate, if unusual, well-formed rule per
/// `merge_rules`, whose empty `match_any`/`match_all` matches every
/// invocation of `command`). A mutation widening the boundary (`<= 2` to
/// `<= 3`) or dropping the `is_builtin` gate would delete this rule instead
/// of merely toggling its `enabled` key.
#[test]
fn config_enable_never_deletes_a_minimal_custom_rule() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-minimal-custom");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let minimal = "[[rules]]\nname = \"minimal-custom\"\ncommand = \"curl\"\naction = \"block\"\nenabled = false\n";
    write_config(&config_path, minimal);

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "minimal-custom"])
        .output()
        .unwrap();
    assert!(
        enable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&enable.stderr).contains("restored to built-in default"),
        "a custom rule is not a built-in"
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert!(
        after.contains("minimal-custom") && after.contains("curl") && after.contains("block"),
        "a 3-key custom rule must survive enable intact, not be deleted: {after}"
    );
    assert!(
        !after.contains("enabled = false"),
        "the `enabled` key must have been removed: {after}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

// -----------------------------------------------------------------------
// Second /code-review pass (10-angle fan-out): one more real bug fixed
// (below), and one near-miss where a fix attempt for a different finding
// was itself found to be a regression by a follow-up sweep pass and
// reverted — see `read_raw_rule_state`'s doc comment in src/config.rs for
// the full account. The reverted behavior (idempotence checked first,
// generically, regardless of `[[rules]]`-vs-inline-array TOML syntax) is
// pinned by the two tests below as the accepted, correct behavior.
// -----------------------------------------------------------------------

/// An inline-array rule (`rules = [{...}]`, valid, non-degraded) that is
/// ALREADY in the state `config disable` is asked to reach must report
/// "already disabled" — not attempt (and refuse) a write it doesn't need.
/// This is a deliberate, accepted behavior: idempotence is answerable from
/// content alone regardless of which TOML syntax wrote it, and no write
/// (so no incorrect file state) is ever at stake when the request was
/// already satisfied.
#[test]
fn config_disable_reports_already_disabled_for_inline_array_already_in_target_state() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-disable-inline-already-disabled");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let inline = "rules = [{ name = \"inline-rule\", command = \"curl\", action = \"block\", match_any = [\"x\"], enabled = false }]\n";
    write_config(&config_path, inline);

    let disable = omamori_cmd(binary, &config_dir)
        .args(["config", "disable", "inline-rule"])
        .output()
        .unwrap();
    // Idempotence no-ops exit 2 (not 0/"success" in `ExitStatus::success()`'s
    // strict sense), matching every other "already X" path in this CLI
    // (e.g. `config_disable_already_disabled_returns_error_for_core`) — the
    // meaningful assertion is that no error/refusal message was produced
    // and the file is untouched, checked below.
    assert!(
        String::from_utf8_lossy(&disable.stderr).contains("already disabled"),
        "expected the idempotence message, got: {}",
        String::from_utf8_lossy(&disable.stderr)
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        after, inline,
        "no-op must not touch the file (it was never going to write anyway)"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// Sweep-pass finding (the regression from the reverted fix mentioned
/// above): the presence of an unrelated inline-array custom rule anywhere
/// in `rules` must NOT block `config enable`/`config disable` on a
/// completely different, already-satisfied rule name — the shape of the
/// whole `rules` key is irrelevant when no write to it is actually needed.
#[test]
fn config_enable_on_unrelated_core_rule_ignores_unrelated_inline_array_shape() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-unrelated-inline-array");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    // `rules` is entirely inline-array form, but contains nothing related
    // to `git-push-force-block` (a core rule, enabled by default, needing
    // no raw entry and no write at all).
    let inline = "rules = [{ name = \"unrelated-custom-rule\", command = \"curl\", action = \"block\", match_any = [\"x\"] }]\n";
    write_config(&config_path, inline);

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "git-push-force-block"])
        .output()
        .unwrap();
    // Idempotence no-ops exit 2, not 0 — see the matching note above.
    assert!(
        String::from_utf8_lossy(&enable.stderr).contains("already enabled"),
        "an unrelated inline-array rule elsewhere in the file must not block this \
         no-op, got: {}",
        String::from_utf8_lossy(&enable.stderr)
    );

    let after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(after, inline, "no write should have happened at all");

    let _ = fs::remove_dir_all(&config_dir);
}

/// Rust-pitfall-specialist finding, reproduced empirically: a core rule
/// disabled via `omamori override disable` (writes to `[overrides]`, never
/// `[[rules]]`) must not be falsely reported as "already enabled" by
/// `config enable` — `config enable` only ever touches `[[rules]]`, so
/// without this check it silently no-ops while claiming success, and
/// `[overrides]` (the actually-effective mechanism) is left untouched.
#[test]
fn config_enable_redirects_when_rule_is_override_disabled() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-override-disabled");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let disable = omamori_cmd(binary, &config_dir)
        .args(["override", "disable", "rm-recursive-to-trash"])
        .output()
        .unwrap();
    assert!(
        disable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disable.stderr)
    );

    let list_before = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    let list_before_out = String::from_utf8_lossy(&list_before.stdout);
    let line_before = list_before_out
        .lines()
        .find(|line| line.contains("rm-recursive-to-trash"))
        .expect("rule must be listed");
    assert!(
        line_before.contains("overridden") || line_before.contains("disabled"),
        "expected the rule to show as overridden/disabled: {line_before}"
    );

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "rm-recursive-to-trash"])
        .output()
        .unwrap();
    assert!(
        !enable.status.success(),
        "`config enable` must refuse and redirect, not silently claim success \
         while leaving [overrides] untouched"
    );
    let stderr = String::from_utf8_lossy(&enable.stderr);
    assert!(
        stderr.contains("override enable"),
        "expected a redirect to `override enable`, got: {stderr}"
    );

    // Confirm the rule is STILL overridden — `config enable` must not have
    // silently no-op'd through to a false "Enabled" message.
    let config_path = config_dir.join("omamori").join("config.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("rm-recursive-to-trash = false"),
        "the [overrides] entry must survive the refused `config enable`: {content}"
    );

    // The actual fix — `override enable` — must still work correctly.
    let real_enable = omamori_cmd(binary, &config_dir)
        .args(["override", "enable", "rm-recursive-to-trash"])
        .output()
        .unwrap();
    assert!(
        real_enable.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&real_enable.stderr)
    );
    let content_after = fs::read_to_string(&config_path).unwrap();
    assert!(
        !content_after.contains("rm-recursive-to-trash = false"),
        "override enable must remove the [overrides] entry: {content_after}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// Angle-A follow-up finding: `config enable`'s "already enabled" message
/// (from the raw toggle) must not silently imply the rule is actually
/// active when validation independently keeps it disabled — otherwise the
/// user sees a "success"-looking no-op with no explanation for why
/// `config list` still shows it disabled.
#[test]
fn config_enable_notes_when_raw_enabled_but_validation_still_disables() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-enable-raw-ok-validation-bad");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    // No explicit `enabled` key (raw toggle defaults to enabled), but a
    // relative destination — validation forces this disabled regardless.
    let content = "[[rules]]\nname = \"diag-rule\"\ncommand = \"curl\"\naction = \"move-to\"\ndestination = \"relative/path\"\nmatch_any = [\"x\"]\n";
    write_config(&config_path, content);

    let enable = omamori_cmd(binary, &config_dir)
        .args(["config", "enable", "diag-rule"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&enable.stderr);
    assert!(
        stderr.contains("already enabled"),
        "expected the raw-toggle idempotence message, got: {stderr}"
    );
    assert!(
        stderr.contains("config list") && stderr.contains("separate validation issue"),
        "expected a note explaining the merged/raw state disagreement, got: {stderr}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}

/// UX-review finding: `config list`'s Action column used a fixed 16-char
/// width, which broke row alignment for any `move-to` rule whose
/// destination is longer than that — including this PR's own promoted
/// README example (`/Users/you/.omamori-quarantine/`, ~40 chars). Widened
/// to 40; this pins that a realistic long destination doesn't push
/// subsequent columns out of alignment with the header.
#[test]
fn config_list_keeps_columns_aligned_for_long_move_to_destination() {
    let binary = env!("CARGO_BIN_EXE_omamori");
    let config_dir = unique_dir("cfg-list-long-destination");
    omamori_cmd(binary, &config_dir)
        .args(["init"])
        .output()
        .unwrap();

    let config_path = config_dir.join("omamori").join("config.toml");
    let content = "[[rules]]\nname = \"rm-to-backup\"\ncommand = \"rm\"\naction = \"move-to\"\ndestination = \"/Users/you/.omamori-quarantine/\"\nmatch_any = [\"-rf\"]\n";
    write_config(&config_path, content);

    let list = omamori_cmd(binary, &config_dir)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let stdout = String::from_utf8_lossy(&list.stdout);

    let header = stdout
        .lines()
        .find(|line| line.contains("Rule") && line.contains("Status"))
        .expect("header row must exist");
    let status_col = header
        .find("Status")
        .expect("header must contain a Status column");

    let row = stdout
        .lines()
        .find(|line| line.contains("rm-to-backup"))
        .expect("rm-to-backup row must be listed");
    assert!(
        row.contains("active"),
        "row must show the rule as active: {row}"
    );
    let active_col = row
        .find("active")
        .expect("row must contain the active status");
    assert_eq!(
        active_col, status_col,
        "the Status value must align under the Status header even for a long \
         move-to destination — header: {header:?}, row: {row:?}"
    );

    let _ = fs::remove_dir_all(&config_dir);
}
