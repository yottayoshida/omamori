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
struct EnvVarGuard {
    key: &'static str,
    saved: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
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
