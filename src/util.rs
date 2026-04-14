//! Shared utility functions used across CLI subcommands.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::AppError;

// ---------------------------------------------------------------------------
// Usage text
// ---------------------------------------------------------------------------

pub(crate) fn usage_text() -> &'static str {
    "omamori usage:
  omamori --version                                      # Show version
  omamori test [--config PATH]
  omamori exec [--config PATH] -- <command> [args...]
  omamori install [--base-dir PATH] [--source PATH] [--hooks]
  omamori uninstall [--base-dir PATH]
  omamori init [--force] [--stdout]
  omamori config list
  omamori config disable <rule>
  omamori config enable <rule>
  omamori audit verify                                    # Verify hash chain integrity
  omamori audit show [--last N] [--json] [--all]          # View audit log entries
  omamori doctor [--fix] [--verbose] [--json]             # Diagnose and repair installation
  omamori explain [--json] [--config PATH] -- <cmd...>   # Explain what would happen to a command
  omamori status [--refresh]                              # Health check all defense layers
  omamori override disable <rule>                        # Override a core safety rule
  omamori override enable <rule>                         # Restore a core safety rule
  omamori hook-check [--provider NAME]                   # Hook detection engine (stdin → exit code)
  omamori cursor-hook                                   # Cursor beforeShellExecution handler

When installed as a PATH shim (for example via a symlink named `rm`), omamori
uses the invoked binary name as the target command and evaluates its policies."
}

pub(crate) fn print_usage() {
    println!("{}", usage_text());
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
            "expected `--config PATH`\n\n{}",
            usage_text()
        )));
    }
    Ok(Some(PathBuf::from(&args[1])))
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
}
