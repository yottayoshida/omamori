//! Shared utility functions used across CLI subcommands.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::AppError;

// ---------------------------------------------------------------------------
// Usage text
// ---------------------------------------------------------------------------

pub(crate) const USAGE_HINT: &str = "Run `omamori --help` for usage.";

pub(crate) fn usage_text() -> &'static str {
    "\
omamori — AI tool safety guard

ESSENTIALS
  setup [--dry-run] [--non-interactive] [--source PATH] Install + shell profile + verify
  doctor                                                Check protection health
  test                                                  Verify policy rules match expected actions

DIAGNOSTICS
  report [--last <duration>] [--json] [--verbose] Aggregate audit summary
  explain [--json] [--config PATH] -- <cmd...>    Show what omamori would do for a command
  audit <verify|show> [options]                   Audit log operations
  status [--refresh]                              Show installed defense layers
  break-glass --rule <id> [--duration <dur>]      Time-limited bypass for false positives
  break-glass --status                            Show active bypasses
  break-glass --clear [--rule <id>]               Revoke bypass(es)

CONFIGURATION
  config <list|add|disable|enable|validate> [rule|path]  Rule management
  override <disable|enable> <rule>                Disable/restore core safety rules
  init [--force] [--stdout]                       Generate starter config template
  install [--base-dir PATH] [--source PATH] [--hooks]  Install PATH shims (and hooks)
  uninstall [--base-dir PATH]                     Remove PATH shims

FLAGS
  --version                                       Show version
  --help                                          Show this help
  --help-all                                      Show all commands including internal ones"
}

pub(crate) fn usage_text_full() -> &'static str {
    "\
omamori — AI tool safety guard

ESSENTIALS
  setup [--dry-run] [--non-interactive] [--source PATH] Install + shell profile + verify
  doctor                                                Check protection health
  test                                                  Verify policy rules match expected actions

DIAGNOSTICS
  report [--last <duration>] [--json] [--verbose] Aggregate audit summary
  explain [--json] [--config PATH] -- <cmd...>    Show what omamori would do for a command
  audit <verify|show> [options]                   Audit log operations
  status [--refresh]                              Show installed defense layers
  break-glass --rule <id> [--duration <dur>]      Time-limited bypass for false positives
  break-glass --status                            Show active bypasses
  break-glass --clear [--rule <id>]               Revoke bypass(es)

CONFIGURATION
  config <list|add|disable|enable|validate> [rule|path]  Rule management
  override <disable|enable> <rule>                Disable/restore core safety rules
  init [--force] [--stdout]                       Generate starter config template
  install [--base-dir PATH] [--source PATH] [--hooks]  Install PATH shims (and hooks)
  uninstall [--base-dir PATH]                     Remove PATH shims

INTERNAL (called by hooks, not intended for direct use)
  hook-check [--provider NAME] [--json-error]     Hook detection engine (stdin → exit code)
  cursor-hook                                     Cursor beforeShellExecution handler
  exec [--config PATH] -- <command> [args...]     Shim execution wrapper

FLAGS
  --version                                       Show version
  --help                                          Show this help
  --help-all                                      Show all commands including internal ones

When installed as a PATH shim (for example via a symlink named `rm`), omamori
uses the invoked binary name as the target command and evaluates its policies."
}

pub(crate) fn print_usage() {
    println!("{}", usage_text());
}

pub(crate) fn print_usage_full() {
    println!("{}", usage_text_full());
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

pub(crate) fn parse_config_flag(args: &[OsString]) -> Result<Option<PathBuf>, AppError> {
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() != 2 || args[0].to_str() != Some("--config") {
        return Err(AppError::Usage(format!(
            "expected `--config PATH`\n\n{USAGE_HINT}"
        )));
    }
    Ok(Some(PathBuf::from(&args[1])))
}

/// Reads `args[index + 1]` as this flag's value (as `&OsString`, preserving
/// non-UTF8 paths — Shape A: `install`/`setup`/`status`/`doctor`'s
/// `--base-dir`/`--source`), or returns `err()`'s message as a `Usage` error
/// if absent. Returns the value and the caller's next `index` as a tuple so
/// index advancement can't be forgotten or mis-added (#392/#377 — previously
/// each of 7 call sites hand-wrote `index += 2` after this check). Does not
/// validate the current arg itself; callers must only invoke this from
/// inside a matched flag arm.
pub(crate) fn flag_value(
    args: &[OsString],
    index: usize,
    err: impl FnOnce() -> String,
) -> Result<(&OsString, usize), AppError> {
    let value = args.get(index + 1).ok_or_else(|| AppError::Usage(err()))?;
    Ok((value, index + 2))
}

/// Like `flag_value`, but returns `&str` and folds "missing value" and
/// "value is not valid UTF-8" into the SAME error (Shape B: `audit`'s
/// `--last`/`--rule`/`--provider`/`--action`, `report`'s `--last` —
/// deliberate existing behavior, not something this refactor changes). A
/// single `flag_value` plus a caller-side `.to_str()` cannot preserve this
/// fold without either duplicating `err()`'s message or double-consuming the
/// `FnOnce` closure — this is why a dedicated variant exists rather than
/// composing `flag_value`.
pub(crate) fn flag_value_str(
    args: &[OsString],
    index: usize,
    err: impl FnOnce() -> String,
) -> Result<(&str, usize), AppError> {
    let value = args
        .get(index + 1)
        .and_then(|v| v.to_str())
        .ok_or_else(|| AppError::Usage(err()))?;
    Ok((value, index + 2))
}

// ---------------------------------------------------------------------------
// String / OsString utilities
// ---------------------------------------------------------------------------

pub(crate) fn binary_name(path: &OsString) -> String {
    Path::new(path)
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn clone_lossy(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Sudo detection (platform-specific)
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) fn should_block_for_sudo() -> bool {
    (unsafe { libc_geteuid() }) == 0 && env::var_os("SUDO_USER").is_some()
}

#[cfg(not(unix))]
pub(crate) fn should_block_for_sudo() -> bool {
    false
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

// ---------------------------------------------------------------------------
// PATH-based command resolution
// ---------------------------------------------------------------------------

pub(crate) fn resolve_real_command(program: &str) -> Result<PathBuf, AppError> {
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    if program.contains(std::path::MAIN_SEPARATOR) {
        let candidate = PathBuf::from(program);
        let canonical = candidate.canonicalize().unwrap_or(candidate);
        if canonical == current_exe {
            return Err(AppError::Config(format!(
                "refusing to resolve `{program}` to the omamori shim itself"
            )));
        }
        return Ok(canonical);
    }

    let path_value = env::var_os("PATH").ok_or_else(|| {
        AppError::Config("PATH is not set; unable to resolve real command".to_string())
    })?;

    resolve_real_command_from_path(program, &path_value, &current_exe)
}

pub(crate) fn resolve_real_command_from_path(
    program: &str,
    path_value: &std::ffi::OsStr,
    current_exe: &Path,
) -> Result<PathBuf, AppError> {
    for candidate_dir in env::split_paths(path_value) {
        let candidate = candidate_dir.join(program);
        if !candidate.is_file() {
            continue;
        }

        let canonical = candidate.canonicalize().unwrap_or(candidate);
        if canonical == current_exe {
            continue;
        }

        return Ok(canonical);
    }

    Err(AppError::Config(format!(
        "unable to locate the real `{program}` outside the omamori shim path"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_name_uses_file_name() {
        assert_eq!(binary_name(&OsString::from("/tmp/rm")), "rm");
    }

    // --- G-03: should_block_for_sudo ---

    #[test]
    fn sudo_block_returns_false_when_not_root() {
        // Normal test process is not root
        let result = should_block_for_sudo();
        assert!(!result, "non-root user should not be blocked");
    }

    // Note: Testing the true path (euid=0 + SUDO_USER set) requires actual
    // root privileges. We test the negative path and trust the implementation.
    // The function is 2 lines of platform-specific code with no branching.

    // --- V-001: --help shows category headers, hides internal commands ---

    #[test]
    fn help_contains_category_headers() {
        let text = usage_text();
        assert!(text.contains("ESSENTIALS"), "missing ESSENTIALS header");
        assert!(text.contains("DIAGNOSTICS"), "missing DIAGNOSTICS header");
        assert!(
            text.contains("CONFIGURATION"),
            "missing CONFIGURATION header"
        );
        assert!(text.contains("FLAGS"), "missing FLAGS header");
    }

    #[test]
    fn help_hides_internal_commands() {
        let text = usage_text();
        assert!(!text.contains("hook-check"), "hook-check should be hidden");
        assert!(
            !text.contains("cursor-hook"),
            "cursor-hook should be hidden"
        );
        assert!(
            !text.contains("exec [--config"),
            "exec should be hidden from default help"
        );
        assert!(
            !text.contains("INTERNAL"),
            "INTERNAL section should not appear in default help"
        );
    }

    // --- V-002: --help-all shows ALL commands including internal ---

    #[test]
    fn help_all_contains_internal_section() {
        let text = usage_text_full();
        assert!(text.contains("INTERNAL"), "missing INTERNAL header");
        assert!(text.contains("hook-check"), "missing hook-check");
        assert!(text.contains("cursor-hook"), "missing cursor-hook");
        assert!(text.contains("exec [--config"), "missing exec");
    }

    #[test]
    fn help_all_contains_all_categories() {
        let text = usage_text_full();
        assert!(text.contains("ESSENTIALS"));
        assert!(text.contains("DIAGNOSTICS"));
        assert!(text.contains("CONFIGURATION"));
        assert!(text.contains("INTERNAL"));
        assert!(text.contains("FLAGS"));
    }

    // --- V-003: error messages use short hint, not full usage ---

    #[test]
    fn usage_hint_is_concise() {
        assert!(
            USAGE_HINT.contains("--help"),
            "hint should reference --help"
        );
        assert!(
            !USAGE_HINT.contains("ESSENTIALS"),
            "hint should not contain full usage text"
        );
        assert!(USAGE_HINT.len() < 60, "hint should be a short one-liner");
    }

    // --- V-007: --help-all does NOT contain the "Use --help-all" footer ---

    #[test]
    fn help_all_no_self_referential_footer() {
        let text = usage_text_full();
        let has_footer = text.contains("--help-all")
            && text
                .lines()
                .any(|l| l.contains("--help-all") && !l.trim().starts_with("--help-all"));
        assert!(
            !has_footer,
            "--help-all should not suggest using --help-all"
        );
    }

    // --- V-008: --help contains "Use --help-all" pointer ---

    #[test]
    fn help_references_help_all() {
        let text = usage_text();
        assert!(
            text.contains("--help-all"),
            "--help should mention --help-all"
        );
    }

    // --- V-011: help inventory covers all routable commands ---

    #[test]
    fn help_inventory_covers_routable_commands() {
        let help = usage_text();
        let help_all = usage_text_full();

        let routable = [
            "test",
            "setup",
            "install",
            "uninstall",
            "init",
            "config",
            "override",
            "audit",
            "doctor",
            "explain",
            "report",
            "status",
        ];
        for cmd in &routable {
            assert!(
                help.contains(cmd),
                "routable command '{cmd}' missing from --help"
            );
        }

        let internal = ["hook-check", "cursor-hook", "exec"];
        for cmd in &internal {
            assert!(
                help_all.contains(cmd),
                "internal command '{cmd}' missing from --help-all"
            );
        }
    }

    #[test]
    fn resolve_real_command_skips_the_shim_path() {
        let root = std::env::temp_dir().join(format!("omamori-resolve-{}", std::process::id()));
        let shim_dir = root.join("shim");
        let real_dir = root.join("real");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let shim_path = shim_dir.join("rm");
        let real_path = real_dir.join("rm");
        std::fs::write(&shim_path, "shim").unwrap();
        std::fs::write(&real_path, "real").unwrap();

        let joined = env::join_paths([shim_dir.clone(), real_dir.clone()]).unwrap();
        let resolved =
            resolve_real_command_from_path("rm", &joined, &shim_path.canonicalize().unwrap())
                .unwrap();
        assert_eq!(resolved, real_path.canonicalize().unwrap());

        let _ = std::fs::remove_dir_all(root);
    }

    // --- flag_value / flag_value_str (#392/#377, V-HELPER-UNIT) ---

    #[test]
    fn flag_value_consumes_adjacent_flag_shaped_token_as_literal_value() {
        // Codex Phase 6-B: the call-site-level greedy-consumption test in
        // install.rs proves only a downstream side effect (an "unknown
        // flag" error further along); this pins the property directly at
        // the helper level — args[index+1] is returned as the value
        // unconditionally, even when it looks like another flag, with no
        // lookahead rejecting flag-shaped tokens.
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "install".into(),
            "--base-dir".into(),
            "--source".into(),
        ];
        let (value, next) = flag_value(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, &OsString::from("--source"));
        assert_eq!(next, 4);
    }

    #[test]
    fn flag_value_ok_returns_value_and_advances_index_by_two() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "install".into(),
            "--base-dir".into(),
            "/tmp".into(),
        ];
        let (value, next) = flag_value(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, &OsString::from("/tmp"));
        assert_eq!(next, 4);
    }

    #[test]
    fn flag_value_missing_returns_err_message() {
        let args: Vec<OsString> = vec!["omamori".into(), "install".into(), "--base-dir".into()];
        let err = flag_value(&args, 2, || "custom missing message".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "custom missing message");
    }

    #[test]
    fn flag_value_boundary_at_end_of_args_does_not_panic() {
        // index+1 pointing exactly past the end of args must error, not panic.
        let args: Vec<OsString> = vec!["omamori".into()];
        let err = flag_value(&args, 0, || "boundary".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "boundary");
    }

    #[test]
    fn flag_value_empty_string_value_is_not_missing() {
        // A present-but-blank value is a valid take, not a missing-value error.
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "install".into(),
            "--base-dir".into(),
            "".into(),
        ];
        let (value, next) = flag_value(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, &OsString::from(""));
        assert_eq!(next, 4);
    }

    #[test]
    #[cfg(unix)]
    fn flag_value_accepts_non_utf8_value() {
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "install".into(),
            "--base-dir".into(),
            non_utf8.clone(),
        ];
        let (value, next) = flag_value(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, &non_utf8);
        assert_eq!(next, 4);
    }

    #[test]
    fn flag_value_str_ok_returns_str_and_advances_index_by_two() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "--rule".into(),
            "my-rule".into(),
        ];
        let (value, next) = flag_value_str(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, "my-rule");
        assert_eq!(next, 4);
    }

    #[test]
    fn flag_value_str_missing_returns_err_message() {
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "--rule".into()];
        let err = flag_value_str(&args, 2, || "custom missing message".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "custom missing message");
    }

    #[test]
    fn flag_value_str_boundary_at_end_of_args_does_not_panic() {
        let args: Vec<OsString> = vec!["omamori".into()];
        let err = flag_value_str(&args, 0, || "boundary".to_string()).unwrap_err();
        assert_eq!(err.to_string(), "boundary");
    }

    #[test]
    fn flag_value_str_empty_string_value_is_not_missing() {
        let args: Vec<OsString> =
            vec!["omamori".into(), "audit".into(), "--rule".into(), "".into()];
        let (value, next) = flag_value_str(&args, 2, || "unreachable".to_string()).unwrap();
        assert_eq!(value, "");
        assert_eq!(next, 4);
    }

    #[test]
    #[cfg(unix)]
    fn flag_value_str_rejects_non_utf8_value_with_same_message_as_missing() {
        // The key behavioral difference from flag_value: a non-UTF8 value
        // must fold into the SAME error as a missing value, not a distinct
        // "invalid UTF-8" message — this is the entire reason flag_value_str
        // exists as a separate primitive rather than composing flag_value.
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "--rule".into(), non_utf8];
        let missing_args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "--rule".into()];

        let non_utf8_err =
            flag_value_str(&args, 2, || "--rule requires a value".to_string()).unwrap_err();
        let missing_err =
            flag_value_str(&missing_args, 2, || "--rule requires a value".to_string()).unwrap_err();
        // Codex Phase 6-B mirror-check finding: comparing the two errors to
        // each other alone would pass even if BOTH regressed to the same
        // wrong message — pin each to the hardcoded expected string too.
        assert_eq!(non_utf8_err.to_string(), "--rule requires a value");
        assert_eq!(missing_err.to_string(), "--rule requires a value");
        assert_eq!(non_utf8_err.to_string(), missing_err.to_string());
    }
}
