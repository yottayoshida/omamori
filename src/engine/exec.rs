//! `omamori exec [--config PATH] -- <command> [args...]` subcommand.

use std::ffi::OsString;
use std::path::PathBuf;

use super::shim::run_command;
use crate::AppError;
use crate::util::{binary_name, usage_text};

pub(crate) fn run_exec_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut position = 2usize;
    let config_path = if args.get(position).and_then(|item| item.to_str()) == Some("--config") {
        let value = args
            .get(position + 1)
            .ok_or_else(|| AppError::Usage("--config requires a path".to_string()))?;
        position += 2;
        Some(PathBuf::from(value))
    } else {
        None
    };

    if args.get(position).and_then(|item| item.to_str()) != Some("--") {
        return Err(AppError::Usage(format!(
            "exec requires `--` before the target command\n\n{}",
            usage_text()
        )));
    }

    let program = args
        .get(position + 1)
        .ok_or_else(|| AppError::Usage("missing command after `--`".to_string()))?;
    let command_args = &args[(position + 2)..];
    run_command(binary_name(program), command_args, config_path.as_deref())
}
