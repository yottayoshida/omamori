pub mod actions;
pub mod audit;
pub(crate) mod break_glass;
mod cli;
pub mod config;
pub mod context;
pub mod detector;
mod engine;
pub mod installer;
pub mod integrity;
pub mod rules;
pub mod unwrap;
mod util;

use std::ffi::OsString;

use cli::audit_cmd::run_audit_command;
use cli::break_glass_cmd::run_break_glass_command;
use cli::config_cmd::{run_config_command, run_init_command, run_override_command};
use cli::doctor::run_doctor_command;
use cli::explain::run_explain_command;
use cli::install::{run_install_command, run_uninstall_command};
use cli::policy_test::run_policy_test_command;
use cli::report::run_report_command;
use cli::setup::run_setup_command;
use cli::status::run_status_command;
use engine::exec::run_exec_command;
use engine::hook::{run_cursor_hook, run_hook_check};
use engine::shim::run_shim;
use util::{USAGE_HINT, binary_name, print_usage, print_usage_full};

// Re-export public API items
pub use cli::policy_test::{PolicyTestResult, run_policy_tests};
pub use engine::hook::{fuzz_check_command_for_hook, fuzz_extract_hook_input};

// Crate-internal property tests (cross-layer Layer 1 ⟹ Layer 2 invariant).
// Lives in-tree so it can call `pub(crate)` helpers like
// `check_command_for_hook_with_rules` without exposing a security-relevant
// helper to downstream crates. See `src/property_tests.rs` and
// `engine::hook::check_command_for_hook_with_rules` doc.
#[cfg(test)]
mod property_tests;

#[derive(Debug)]
pub enum AppError {
    Usage(String),
    Io(std::io::Error),
    Config(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(f, "{message}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Config(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn run(args: &[OsString]) -> Result<i32, AppError> {
    let argv0 = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("omamori"));
    let argv0_name = binary_name(&argv0);

    // Defense-in-depth: route hook-check even when invoked via shim (#333)
    if argv0_name != "omamori"
        && args.get(1).and_then(|a| a.to_str()) == Some("hook-check")
    {
        return run_hook_check(args);
    }

    if argv0_name != "omamori" {
        return run_shim(&argv0_name, &args[1..]);
    }

    match args.get(1).and_then(|item| item.to_str()) {
        Some("test") => run_policy_test_command(args),
        Some("exec") => run_exec_command(args),
        Some("install") => run_install_command(args),
        Some("uninstall") => run_uninstall_command(args),
        Some("init") => run_init_command(args),
        Some("config") => run_config_command(args),
        Some("override") => run_override_command(args),
        Some("audit") => run_audit_command(args),
        Some("break-glass") => run_break_glass_command(args),
        Some("doctor") => run_doctor_command(args),
        Some("setup") => run_setup_command(args),
        Some("explain") => run_explain_command(args),
        Some("report") => run_report_command(args),
        Some("status") => run_status_command(args),
        Some("cursor-hook") => run_cursor_hook(),
        Some("hook-check") => run_hook_check(args),
        Some("version") | Some("--version") | Some("-V") => {
            println!("omamori {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(0)
        }
        Some("--help-all") | Some("help-all") => {
            print_usage_full();
            Ok(0)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown subcommand: {other}\n\n{USAGE_HINT}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_usage_succeeds() {
        let args = vec![OsString::from("omamori")];
        let code = run(&args).expect("usage should succeed");
        assert_eq!(code, 0);
    }

    // V-004: `help` (no dashes) = same as `--help`
    #[test]
    fn run_help_succeeds() {
        let args = vec![OsString::from("omamori"), OsString::from("help")];
        let code = run(&args).expect("help should succeed");
        assert_eq!(code, 0);
    }

    // V-005: `-h` = same as `--help`
    #[test]
    fn run_dash_h_succeeds() {
        let args = vec![OsString::from("omamori"), OsString::from("-h")];
        let code = run(&args).expect("-h should succeed");
        assert_eq!(code, 0);
    }

    // V-006: no args = same as `--help`
    // (already covered by run_usage_succeeds)

    // V-010: exit code 0 for --help-all
    #[test]
    fn run_help_all_flag_succeeds() {
        let args = vec![OsString::from("omamori"), OsString::from("--help-all")];
        let code = run(&args).expect("--help-all should succeed");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_help_all_subcommand_succeeds() {
        let args = vec![OsString::from("omamori"), OsString::from("help-all")];
        let code = run(&args).expect("help-all should succeed");
        assert_eq!(code, 0);
    }

    // V-009: --version unaffected
    #[test]
    fn run_version_succeeds() {
        let args = vec![OsString::from("omamori"), OsString::from("--version")];
        let code = run(&args).expect("--version should succeed");
        assert_eq!(code, 0);
    }

    #[test]
    fn shim_argv0_with_hook_check_does_not_enter_shim_mode() {
        // Defense-in-depth: when argv0 is a shim name (e.g. "git") but
        // the subcommand is "hook-check", route to run_hook_check instead
        // of run_shim. run_hook_check reads from stdin; with empty stdin
        // it should return exit 2 (malformed input = fail-close).
        let args = vec![
            OsString::from("git"),
            OsString::from("hook-check"),
            OsString::from("--provider"),
            OsString::from("claude-code"),
        ];
        let code = run(&args).expect("hook-check via shim argv0 should not error");
        assert_eq!(code, 2, "empty stdin hook-check should fail-close with exit 2");
    }

    #[test]
    fn shim_argv0_without_hook_check_still_enters_shim() {
        // Mutation resistance: when argv0 is a shim name but subcommand
        // is NOT hook-check, must enter shim mode (not omamori dispatch).
        // "git status" via shim should not hit "unknown subcommand" error.
        let args = vec![
            OsString::from("git"),
            OsString::from("status"),
        ];
        let result = run(&args);
        // run_shim will try to execute real git; the important thing is
        // it does NOT return AppError::Usage("unknown subcommand: status")
        match &result {
            Err(AppError::Usage(msg)) => {
                panic!("shim argv0 with non-hook-check arg must not hit usage error: {msg}");
            }
            _ => {} // any other result (Ok or non-Usage error) is fine
        }
    }
}
