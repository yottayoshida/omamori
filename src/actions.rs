use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::config::BLOCKED_DESTINATION_PREFIXES;
use crate::rules::{ActionKind, CommandInvocation, RuleConfig};

fn exit_code_from_status(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

#[derive(Debug, Clone)]
pub enum ActionOutcome {
    PassedThrough { exit_code: i32 },
    Trashed { exit_code: i32, message: String },
    ExecutedAfterStash { exit_code: i32, message: String },
    LoggedOnly { exit_code: i32, message: String },
    MovedTo { exit_code: i32, message: String },
    Blocked { message: String },
    Failed { message: String },
}

impl ActionOutcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PassedThrough { exit_code }
            | Self::Trashed { exit_code, .. }
            | Self::ExecutedAfterStash { exit_code, .. }
            | Self::LoggedOnly { exit_code, .. }
            | Self::MovedTo { exit_code, .. } => *exit_code,
            Self::Blocked { .. } | Self::Failed { .. } => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::PassedThrough { .. } => "omamori allowed the command to run unchanged",
            Self::Trashed { message, .. }
            | Self::ExecutedAfterStash { message, .. }
            | Self::LoggedOnly { message, .. }
            | Self::MovedTo { message, .. }
            | Self::Blocked { message }
            | Self::Failed { message } => message,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::PassedThrough { .. } => "passthrough",
            Self::Trashed { .. } => "trash",
            Self::ExecutedAfterStash { .. } => "stash-then-exec",
            Self::LoggedOnly { .. } => "log-only",
            Self::MovedTo { .. } => "move-to",
            Self::Blocked { .. } => "block",
            Self::Failed { .. } => "failed",
        }
    }
}

pub trait ExecOps {
    fn passthrough(&mut self, invocation: &CommandInvocation) -> io::Result<i32>;
    fn move_to_trash(&mut self, targets: &[String]) -> Result<(), String>;
    fn move_to_dir(&mut self, targets: &[String], destination: &Path) -> Result<usize, String>;
    fn git_stash(&mut self) -> Result<(), String>;
}

pub struct SystemOps {
    real_program: PathBuf,
    detector_env_keys: Vec<String>,
}

impl SystemOps {
    pub fn new(real_program: PathBuf, detector_env_keys: Vec<String>) -> Self {
        Self {
            real_program,
            detector_env_keys,
        }
    }
}

impl ExecOps for SystemOps {
    fn passthrough(&mut self, invocation: &CommandInvocation) -> io::Result<i32> {
        let status = Command::new(&self.real_program)
            .args(&invocation.args)
            .status()?;
        Ok(exit_code_from_status(status))
    }

    fn move_to_trash(&mut self, targets: &[String]) -> Result<(), String> {
        let paths = targets.iter().map(PathBuf::from).collect::<Vec<_>>();
        trash::delete_all(paths).map_err(|error| error.to_string())
    }

    fn move_to_dir(&mut self, targets: &[String], destination: &Path) -> Result<usize, String> {
        // Validate destination at execution time (fail-close)
        if !destination.exists() {
            return Err(format!(
                "move-to directory `{}` does not exist; refusing to run the original command",
                destination.display()
            ));
        }
        if !destination.is_dir() {
            return Err(format!(
                "move-to path `{}` is not a directory",
                destination.display()
            ));
        }

        // Check for symlink at execution time (TOCTOU mitigation)
        let meta = std::fs::symlink_metadata(destination).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "move-to directory `{}` is a symlink; refusing for security",
                destination.display()
            ));
        }

        // Re-check blocked prefixes at execution time (M1 fix: canonicalize may
        // have failed at config-load time if the directory didn't exist yet)
        if let Ok(canonical) = destination.canonicalize() {
            let canonical_str = canonical.to_string_lossy();
            for prefix in BLOCKED_DESTINATION_PREFIXES {
                if canonical_str.starts_with(prefix) {
                    return Err(format!(
                        "move-to directory `{}` resolves to blocked system path `{canonical_str}`",
                        destination.display()
                    ));
                }
            }
        }

        // Create timestamped subdirectory to avoid filename collisions
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sub_dir = destination.join(format!("{timestamp}"));
        std::fs::create_dir_all(&sub_dir)
            .map_err(|e| format!("failed to create subdirectory `{}`: {e}", sub_dir.display()))?;

        let mut moved = 0usize;
        let mut used_names = std::collections::HashSet::new();
        for target in targets {
            let src = PathBuf::from(target);
            let base_name = src
                .file_name()
                .unwrap_or(src.as_os_str())
                .to_string_lossy()
                .into_owned();
            // Deduplicate basenames: append _2, _3, etc. if collision
            let unique_name = if used_names.contains(&base_name) {
                let mut counter = 2u32;
                loop {
                    let candidate = format!("{base_name}_{counter}");
                    if !used_names.contains(&candidate) {
                        break candidate;
                    }
                    counter += 1;
                }
            } else {
                base_name.clone()
            };
            used_names.insert(unique_name.clone());
            let dest = sub_dir.join(&unique_name);

            std::fs::rename(&src, &dest).map_err(|e| {
                if e.raw_os_error() == Some(18) {
                    // EXDEV: cross-device link
                    format!(
                        "cannot move `{target}` to `{}`: cross-device move is not supported (use a destination on the same volume)",
                        destination.display()
                    )
                } else {
                    format!("failed to move `{target}` to `{}`: {e}", dest.display())
                }
            })?;
            moved += 1;
        }
        Ok(moved)
    }

    fn git_stash(&mut self) -> Result<(), String> {
        // Remove AI detector env vars so the internal git call does not
        // trigger omamori's own protection (self-interference prevention).
        let mut cmd = Command::new("git");
        cmd.arg("stash").arg("push").arg("--include-untracked");
        for key in &self.detector_env_keys {
            cmd.env_remove(key);
        }
        let status = cmd.status().map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git stash exited with status {:?}", status.code()))
        }
    }
}

pub struct ActionExecutor<T: ExecOps> {
    ops: T,
}

impl<T: ExecOps> ActionExecutor<T> {
    pub fn new(ops: T) -> Self {
        Self { ops }
    }

    pub fn exec_passthrough(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<ActionOutcome, io::Error> {
        let exit_code = self.ops.passthrough(invocation)?;
        Ok(ActionOutcome::PassedThrough { exit_code })
    }

    pub fn execute(
        &mut self,
        invocation: &CommandInvocation,
        rule: &RuleConfig,
    ) -> Result<ActionOutcome, io::Error> {
        let message = rule
            .message
            .clone()
            .unwrap_or_else(|| format!("omamori applied `{}`", rule.name));

        let outcome = match rule.action {
            ActionKind::Trash => {
                let targets: Vec<String> = invocation
                    .target_args()
                    .into_iter()
                    .map(String::from)
                    .collect();
                if targets.is_empty() {
                    ActionOutcome::Failed {
                        message: "omamori could not identify any rm targets to move to Trash"
                            .to_string(),
                    }
                } else {
                    match self.ops.move_to_trash(&targets) {
                        Ok(()) => ActionOutcome::Trashed {
                            exit_code: 0,
                            message,
                        },
                        Err(error) => ActionOutcome::Failed {
                            message: format!(
                                "omamori failed to move the targets to Trash and refused to run rm: {error}"
                            ),
                        },
                    }
                }
            }
            ActionKind::StashThenExec => match self.ops.git_stash() {
                Ok(()) => {
                    let exit_code = self.ops.passthrough(invocation)?;
                    ActionOutcome::ExecutedAfterStash { exit_code, message }
                }
                Err(error) => ActionOutcome::Failed {
                    message: format!(
                        "omamori could not create a git stash before execution: {error}"
                    ),
                },
            },
            ActionKind::MoveTo => {
                let destination = match &rule.destination {
                    Some(dest) => PathBuf::from(dest),
                    None => {
                        return Ok(ActionOutcome::Failed {
                            message: "omamori move-to rule has no destination configured"
                                .to_string(),
                        });
                    }
                };
                let targets: Vec<String> = invocation
                    .target_args()
                    .into_iter()
                    .map(String::from)
                    .collect();
                if targets.is_empty() {
                    ActionOutcome::Failed {
                        message: "omamori could not identify any targets to move".to_string(),
                    }
                } else {
                    match self.ops.move_to_dir(&targets, &destination) {
                        Ok(count) => ActionOutcome::MovedTo {
                            exit_code: 0,
                            message: format!(
                                "{message} ({count} target(s) moved to {})",
                                destination.display()
                            ),
                        },
                        Err(error) => ActionOutcome::Failed {
                            message: format!(
                                "omamori failed to move targets to `{}` and refused to run the original command: {error}",
                                destination.display()
                            ),
                        },
                    }
                }
            }
            ActionKind::Block => ActionOutcome::Blocked { message },
            ActionKind::LogOnly => {
                let exit_code = self.ops.passthrough(invocation)?;
                ActionOutcome::LoggedOnly { exit_code, message }
            }
        };

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleConfig;

    #[derive(Default)]
    struct FakeOps {
        passthrough_calls: usize,
        passthrough_status: i32,
        trash_error: Option<String>,
        move_to_dir_error: Option<String>,
        stash_error: Option<String>,
        last_trash_targets: Vec<String>,
        last_move_targets: Vec<String>,
        last_move_destination: Option<PathBuf>,
    }

    impl ExecOps for FakeOps {
        fn passthrough(&mut self, _invocation: &CommandInvocation) -> io::Result<i32> {
            self.passthrough_calls += 1;
            Ok(self.passthrough_status)
        }

        fn move_to_trash(&mut self, targets: &[String]) -> Result<(), String> {
            self.last_trash_targets = targets.to_vec();
            match &self.trash_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn move_to_dir(&mut self, targets: &[String], destination: &Path) -> Result<usize, String> {
            self.last_move_targets = targets.to_vec();
            self.last_move_destination = Some(destination.to_path_buf());
            match &self.move_to_dir_error {
                Some(error) => Err(error.clone()),
                None => Ok(targets.len()),
            }
        }

        fn git_stash(&mut self) -> Result<(), String> {
            match &self.stash_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }

    fn rule(action: ActionKind, command: &str) -> RuleConfig {
        RuleConfig::new(
            "test",
            command,
            action,
            Vec::new(),
            Vec::new(),
            Some("message".to_string()),
        )
    }

    #[test]
    fn trash_failure_does_not_fall_back_to_passthrough() {
        let mut executor = ActionExecutor::new(FakeOps {
            trash_error: Some("no trash".to_string()),
            ..Default::default()
        });
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "danger".to_string()],
        );
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::Trash, "rm"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Failed { .. }));
    }

    #[test]
    fn stash_then_exec_runs_both_steps() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::StashThenExec, "git"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::ExecutedAfterStash { .. }));
    }

    #[test]
    fn trash_with_double_dash_captures_dash_prefixed_targets() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec![
                "-rf".to_string(),
                "--".to_string(),
                "-dangerous.txt".to_string(),
            ],
        );
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::Trash, "rm"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Trashed { .. }));
        assert_eq!(executor.ops.last_trash_targets, vec!["-dangerous.txt"]);
    }

    #[test]
    fn move_to_succeeds_with_destination() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        let rule = RuleConfig::new(
            "rm-move",
            "rm",
            ActionKind::MoveTo,
            Vec::new(),
            Vec::new(),
            Some("moved".to_string()),
        )
        .with_destination("/tmp/backup".to_string());
        let outcome = executor.execute(&invocation, &rule).unwrap();
        assert!(matches!(outcome, ActionOutcome::MovedTo { .. }));
        assert_eq!(executor.ops.last_move_targets, vec!["target/"]);
    }

    #[test]
    fn move_to_without_destination_fails() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        let rule = RuleConfig::new(
            "rm-move",
            "rm",
            ActionKind::MoveTo,
            Vec::new(),
            Vec::new(),
            None,
        );
        let outcome = executor.execute(&invocation, &rule).unwrap();
        assert!(matches!(outcome, ActionOutcome::Failed { .. }));
    }

    #[test]
    fn move_to_failure_does_not_fall_back_to_passthrough() {
        let mut executor = ActionExecutor::new(FakeOps {
            move_to_dir_error: Some("disk full".to_string()),
            ..Default::default()
        });
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        let rule = RuleConfig::new(
            "rm-move",
            "rm",
            ActionKind::MoveTo,
            Vec::new(),
            Vec::new(),
            None,
        )
        .with_destination("/tmp/backup".to_string());
        let outcome = executor.execute(&invocation, &rule).unwrap();
        assert!(matches!(outcome, ActionOutcome::Failed { .. }));
        assert_eq!(executor.ops.passthrough_calls, 0);
    }

    #[test]
    fn trash_with_only_double_dash_fails() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation =
            CommandInvocation::new("rm".to_string(), vec!["-rf".to_string(), "--".to_string()]);
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::Trash, "rm"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Failed { .. }));
    }
}
