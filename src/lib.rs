pub mod actions;
pub mod audit;
pub mod config;
pub mod detector;
pub mod installer;
pub mod rules;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use actions::{ActionExecutor, ActionOutcome, SystemOps};
use audit::{AuditEvent, AuditLogger};
use config::{ConfigLoadResult, load_config};
use detector::evaluate_detectors;
use installer::{InstallOptions, default_base_dir, install, uninstall};
use rules::{CommandInvocation, match_rule};

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

fn run_policy_test_command(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[2..])?;
    let load_result = load_config(config_path.as_deref())?;
    emit_config_warnings(&load_result);

    let results = run_policy_tests(&load_result);
    let failures = results.iter().filter(|result| !result.passed).count();

    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("{status} {}", result.name);
        println!("  {}", result.details);
    }

    if failures == 0 {
        println!("policy tests passed: {}", results.len());
        Ok(0)
    } else {
        println!("policy tests failed: {failures}/{}", results.len());
        Ok(1)
    }
}

fn run_exec_command(args: &[OsString]) -> Result<i32, AppError> {
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

fn run_install_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = default_base_dir();
    let mut source_exe = env::current_exe()?;
    let mut generate_hooks = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("install requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            "--source" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("install requires a path after --source".to_string())
                })?;
                source_exe = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                generate_hooks = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown install flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    let result = install(&InstallOptions {
        base_dir,
        source_exe,
        generate_hooks,
    })?;

    println!("Installed omamori shims in {}", result.shim_dir.display());
    println!(
        "Add this directory to PATH manually:\n  export PATH=\"{}:$PATH\"",
        result.shim_dir.display()
    );
    if let Some(script) = result.hook_script {
        println!("Generated Claude Code hook script: {}", script.display());
    }
    if let Some(snippet) = result.settings_snippet {
        println!(
            "Generated Claude settings snippet (apply manually): {}",
            snippet.display()
        );
    }
    println!("Linked commands: {}", result.linked_commands.join(", "));

    Ok(0)
}

fn run_uninstall_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = default_base_dir();
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("uninstall requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown uninstall flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    let result = uninstall(&base_dir)?;
    println!(
        "Removed omamori install artifacts from {}",
        result.shim_dir.display()
    );
    println!("Removed {} file(s)", result.removed_entries.len());
    Ok(0)
}

fn run_shim(program: &str, args: &[OsString]) -> Result<i32, AppError> {
    run_command(program.to_string(), args, None)
}

fn run_command(
    program: String,
    args: &[OsString],
    config_path: Option<&Path>,
) -> Result<i32, AppError> {
    let load_result = load_config(config_path)?;
    emit_config_warnings(&load_result);

    let invocation =
        CommandInvocation::new(program.clone(), args.iter().map(clone_lossy).collect());
    let env_pairs = env::vars().collect::<Vec<_>>();
    let detection = evaluate_detectors(&load_result.config.detectors, &env_pairs);
    let matched_rule = match_rule(&load_result.config.rules, &invocation);

    let resolved_program = resolve_real_command(&program)?;
    let mut executor = ActionExecutor::new(SystemOps::new(resolved_program));
    let audit_logger = AuditLogger::from_config(&load_result.config.audit);

    let outcome = if should_block_for_sudo() {
        let blocked = ActionOutcome::Blocked {
            message:
                "omamori blocked this command because it was invoked via sudo/elevated privileges"
                    .to_string(),
        };
        eprintln!("{}", blocked.message());
        blocked
    } else if !detection.protected {
        executor.exec_passthrough(&invocation)?
    } else if let Some(rule) = matched_rule {
        let outcome = executor.execute(&invocation, rule)?;
        if matches!(
            outcome,
            ActionOutcome::Blocked { .. } | ActionOutcome::Failed { .. }
        ) {
            eprintln!("{}", outcome.message());
        }
        outcome
    } else {
        executor.exec_passthrough(&invocation)?
    };

    for warning in &detection.warnings {
        eprintln!("omamori warning: {warning}");
    }

    if let Some(logger) = audit_logger {
        let event = AuditEvent::from_outcome(
            &invocation,
            matched_rule,
            &detection.matched_detectors,
            &outcome,
        );
        let _ = logger.append(&event);
    }

    Ok(outcome.exit_code())
}

fn emit_config_warnings(load_result: &ConfigLoadResult) {
    for warning in &load_result.warnings {
        eprintln!("omamori warning: {warning}");
    }
}

fn print_usage() {
    println!("{}", usage_text());
}

fn usage_text() -> &'static str {
    "omamori usage:
  omamori test [--config PATH]
  omamori exec [--config PATH] -- <command> [args...]
  omamori install [--base-dir PATH] [--source PATH] [--hooks]
  omamori uninstall [--base-dir PATH]

When installed as a PATH shim (for example via a symlink named `rm`), omamori
uses the invoked binary name as the target command and evaluates its policies."
}

fn parse_config_flag(args: &[OsString]) -> Result<Option<PathBuf>, AppError> {
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

fn binary_name(path: &OsString) -> String {
    Path::new(path)
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn clone_lossy(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(unix)]
fn should_block_for_sudo() -> bool {
    (unsafe { libc_geteuid() }) == 0 && env::var_os("SUDO_USER").is_some()
}

#[cfg(not(unix))]
fn should_block_for_sudo() -> bool {
    false
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn resolve_real_command(program: &str) -> Result<PathBuf, AppError> {
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

fn resolve_real_command_from_path(
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

#[derive(Debug)]
pub struct PolicyTestResult {
    pub name: &'static str,
    pub passed: bool,
    pub details: String,
}

pub fn run_policy_tests(load_result: &ConfigLoadResult) -> Vec<PolicyTestResult> {
    let config = &load_result.config;
    let protected_env = vec![("CLAUDECODE".to_string(), "1".to_string())];
    let unprotected_env = Vec::new();

    let cases = vec![
        (
            "ai-rm-recursive-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            protected_env.clone(),
            Some("trash"),
            true,
        ),
        (
            "direct-rm-bypasses-shim",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            unprotected_env.clone(),
            None,
            false,
        ),
        (
            "git-reset-hard-stashes-before-exec",
            CommandInvocation::new(
                "git".to_string(),
                vec!["reset".to_string(), "--hard".to_string()],
            ),
            protected_env.clone(),
            Some("stash-then-exec"),
            true,
        ),
        (
            "config-parse-fallback-keeps-protection",
            CommandInvocation::new(
                "git".to_string(),
                vec!["push".to_string(), "--force".to_string()],
            ),
            protected_env,
            Some("block"),
            true,
        ),
    ];

    cases
        .into_iter()
        .map(
            |(name, command, env_map, expected_action, expected_protected)| {
                let detection = evaluate_detectors(&config.detectors, &env_map);
                let matched = match_rule(&config.rules, &command);
                let effective_action = if detection.protected {
                    matched.map(|rule| rule.action.as_str())
                } else {
                    None
                };
                let passed = detection.protected == expected_protected
                    && effective_action == expected_action;
                let details = format!(
                    "protected={} action={:?} detectors={:?}",
                    detection.protected, effective_action, detection.matched_detectors
                );
                PolicyTestResult {
                    name,
                    passed,
                    details,
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::ActionKind;

    #[test]
    fn policy_tests_pass_with_default_config() {
        let load_result = ConfigLoadResult {
            config: Config::default(),
            warnings: Vec::new(),
        };

        let results = run_policy_tests(&load_result);
        assert!(results.iter().all(|item| item.passed));
    }

    #[test]
    fn binary_name_uses_file_name() {
        assert_eq!(binary_name(&OsString::from("/tmp/rm")), "rm");
    }

    #[test]
    fn run_usage_succeeds() {
        let args = vec![OsString::from("omamori")];
        let code = run(&args).expect("usage should succeed");
        assert_eq!(code, 0);
    }

    #[test]
    fn resolve_default_rule_for_rm() {
        let invocation = CommandInvocation::new("rm".to_string(), vec!["-rf".to_string()]);
        let config = Config::default();
        let rule = match_rule(&config.rules, &invocation).expect("rule should match");
        assert_eq!(rule.action, ActionKind::Trash);
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
}
