//! Shared test-only helpers for process-global env var manipulation
//! (#306/#323, extended for AI-detector env vars in #394).
//!
//! Every caller of `with_home`/`with_home_and_xdg` must be tagged
//! `#[serial_test::serial(home_env)]` — these mutate the process-global
//! `HOME` (and optionally `XDG_CONFIG_HOME`) env vars, which race across
//! threads without that tag (see MEMORY: #344-class flakes). Every caller of
//! `with_clean_ai_env` must be tagged `#[serial_test::serial(ai_env)]` — a
//! separate group, since it mutates a disjoint set of env vars.

/// Restores a single env var to its saved value on drop — including on
/// unwind, so a panicking `f()` inside `with_home`/`with_home_and_xdg`
/// still leaves the env var correctly restored for whatever test runs
/// next under the same `serial(home_env)` lock.
pub(crate) struct EnvVarGuard {
    key: &'static str,
    saved: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &'static str, value: Option<&str>) -> Self {
        let saved = std::env::var_os(key);
        // SAFETY: serialized by #[serial_test::serial(home_env)] on every caller.
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self { key, saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: see EnvVarGuard::set.
        unsafe {
            match &self.saved {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Temporarily set (or unset) `HOME` for the duration of `f`, restoring the
/// prior value afterward regardless of how `f` returns — including if `f`
/// panics.
pub(crate) fn with_home<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _guard = EnvVarGuard::set("HOME", value);
    f()
}

/// Like `with_home`, but also clears `XDG_CONFIG_HOME` for the duration of
/// `f` (for tests exercising `config::default_config_path`'s XDG-first
/// resolution, which would otherwise mask the HOME fallback under test).
pub(crate) fn with_home_and_xdg<T>(home: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _xdg_guard = EnvVarGuard::set("XDG_CONFIG_HOME", None);
    with_home(home, f)
}

/// Temporarily clears every AI-tool detector env var
/// (`default_detectors()`'s env-var list: `CLAUDECODE`, `CODEX_CI`,
/// `CURSOR_AGENT`, `GEMINI_CLI`, `CLINE_ACTIVE`, `AI_GUARD`) for the
/// duration of `f`, restoring prior values afterward. The in-process
/// equivalent of `tests/cli.rs`'s `clean_ai_env` (which only clears env for
/// a *spawned* `Command`, not the current process) — needed by any
/// in-process test that calls a `guard_ai_config_modification`-protected
/// function directly, since that guard reads the current process's
/// `std::env::vars()`. Without this, such a test would spuriously fail (or
/// spuriously pass a should-be-blocked case) depending on whether the
/// *test runner's own* environment happens to have one of these set — which
/// it does whenever `cargo test` itself runs inside an AI coding tool.
///
/// Callers must be tagged `#[serial_test::serial(ai_env)]` — a separate
/// serial group from `home_env`, since AI-detector env vars are an
/// independent concern from `HOME`/`XDG_CONFIG_HOME` and unnecessarily
/// coupling the two would over-serialize unrelated tests.
pub(crate) fn with_clean_ai_env<T>(f: impl FnOnce() -> T) -> T {
    let _guards: Vec<EnvVarGuard> = [
        "CLAUDECODE",
        "CODEX_CI",
        "CURSOR_AGENT",
        "GEMINI_CLI",
        "CLINE_ACTIVE",
        "AI_GUARD",
    ]
    .iter()
    .map(|key| EnvVarGuard::set(key, None))
    .collect();
    f()
}

/// A non-UTF8 `OsString` with no other structure — for tests pinning
/// "invalid UTF-8 is rejected/folded the same as a missing value" (#392/#377
/// Shape B). `/simplify` Reuse finding: this exact
/// `OsStringExt::from_vec(vec![0xff, 0xfe])` construction was copy-pasted
/// across util.rs/report.rs/audit_cmd.rs before being extracted here.
#[cfg(unix)]
pub(crate) fn non_utf8_osstring() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![0xff, 0xfe])
}

/// A non-UTF8 `OsString` shaped like a filesystem path (leading invalid
/// bytes followed by `/x`) — for tests pinning "a non-UTF8 path value is
/// accepted, not rejected" (#392/#377 Shape A escape hatch). Distinct from
/// `non_utf8_osstring` above since Shape A tests want something that reads
/// as path-like in failure messages, not just an arbitrary invalid byte
/// sequence.
#[cfg(unix)]
pub(crate) fn non_utf8_path_like() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![0xff, 0xfe, b'/', b'x'])
}

/// Create `path` holding `body` with permission bits `mode`, without this
/// process ever opening it for writing (#344).
///
/// Linux refuses to `execve` a file that any process has open for writing
/// (`ETXTBSY`, "Text file busy"). Every test thread shares one process, so a
/// fixture written here with `fs::write` and executed straight after loses a
/// race it cannot see: if another thread spawns a child while the write
/// descriptor is open, that child holds a copy until its own exec
/// (`O_CLOEXEC` closes it only then), and executing the fixture inside that
/// window fails. A short-lived `/bin/sh` writes the file instead, so no
/// descriptor on it ever exists in this process for a sibling's fork to copy.
///
/// The body travels as one argument, which is simpler than feeding a pipe.
/// An argument is capped (`MAX_ARG_STRLEN`, 128 KiB on Linux); a larger body
/// fails the spawn loudly rather than writing a truncated file.
/// `set_permissions` is `chmod(2)`, which opens nothing.
///
/// Use this for every fixture a test executes with its execute bit set —
/// directly, or through a script that runs it. A fixture that is only read,
/// or one expected to fail with `EACCES` (the permission check comes before
/// the busy check), can stay on `fs::write`.
#[cfg(unix)]
pub(crate) fn write_script(path: &std::path::Path, body: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", WRITE_SCRIPT_SH, "sh"])
        .arg(path)
        .arg(body)
        .status()
        .expect("spawn /bin/sh to write the fixture");
    assert!(
        status.success(),
        "writing {} failed: {status}",
        path.display()
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// `write_script`'s shell body: `$1` is the path, `$2` the content. `>|`, not
/// `>`: macOS's `/bin/sh` is bash, which takes `noclobber` from an exported
/// `SHELLOPTS` and would then refuse to replace a fixture an earlier run left.
#[cfg(unix)]
const WRITE_SCRIPT_SH: &str = "printf %s \"$2\" >| \"$1\"";

/// The five tests that rely on `write_script` would catch a body that stopped
/// arriving at all, but not one that arrived altered — a `%` or `\` taken as
/// a format, a dropped trailing newline — or a mode that drifted. This pins
/// both, over an existing longer file so a missing truncate shows too.
#[cfg(unix)]
#[test]
fn write_script_replaces_a_file_with_the_exact_body_and_mode() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!("omamori-write-script-{}", std::process::id()));
    std::fs::write(&path, "an earlier, longer fixture that must not survive\n").unwrap();
    let body = "#!/bin/sh\nprintf '%s\\n' \"$1\" 100% \\\n  && exit 0\n\n";

    write_script(&path, body, 0o751);

    let written = std::fs::read_to_string(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    let _ = std::fs::remove_file(&path);
    assert_eq!(written, body);
    assert_eq!(mode, 0o751);
}

/// The `>|` in `WRITE_SCRIPT_SH`, exercised the way it can fail: bash reads
/// `noclobber` from `SHELLOPTS` in its environment. Set on the child only, so
/// no process global is touched. On a `/bin/sh` that ignores `SHELLOPTS`
/// (dash) this passes either way, and so does the defect it guards against.
#[cfg(unix)]
#[test]
fn write_script_overwrites_even_when_the_shell_inherits_noclobber() {
    let path = std::env::temp_dir().join(format!(
        "omamori-write-script-noclobber-{}",
        std::process::id()
    ));
    std::fs::write(&path, "old").unwrap();

    let status = std::process::Command::new("/bin/sh")
        .args(["-c", WRITE_SCRIPT_SH, "sh"])
        .arg(&path)
        .arg("new")
        .env("SHELLOPTS", "noclobber")
        .status()
        .unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(status.success(), "the shell refused to overwrite: {status}");
    assert_eq!(written, "new");
}
