//! Shared test-only helpers for HOME env var manipulation (#306/#323).
//!
//! Every caller of `with_home`/`with_home_and_xdg` must be tagged
//! `#[serial_test::serial(home_env)]` — these mutate the process-global
//! `HOME` (and optionally `XDG_CONFIG_HOME`) env vars, which race across
//! threads without that tag (see MEMORY: #344-class flakes).

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
