pub mod actions;
pub mod audit;
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
use cli::config_cmd::{run_config_command, run_init_command, run_override_command};
use cli::install::{run_install_command, run_uninstall_command};
use cli::policy_test::run_policy_test_command;
use cli::status::run_status_command;
use engine::exec::run_exec_command;
use engine::hook::{run_cursor_hook, run_hook_check};
use engine::shim::run_shim;
use util::{binary_name, print_usage, usage_text};

// Re-export public API items
pub use cli::policy_test::{PolicyTestResult, run_policy_tests};
pub use engine::hook::{fuzz_check_command_for_hook, fuzz_extract_hook_input};

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
        Some(other) => Err(AppError::Usage(format!(
            "unknown subcommand: {other}\n\n{}",
            usage_text()
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
}
