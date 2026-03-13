use std::io;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

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
    Blocked { message: String },
    Failed { message: String },
}

impl ActionOutcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PassedThrough { exit_code }
            | Self::Trashed { exit_code, .. }
            | Self::ExecutedAfterStash { exit_code, .. }
            | Self::LoggedOnly { exit_code, .. } => *exit_code,
            Self::Blocked { .. } | Self::Failed { .. } => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::PassedThrough { .. } => "omamori allowed the command to run unchanged",
            Self::Trashed { message, .. }
            | Self::ExecutedAfterStash { message, .. }
            | Self::LoggedOnly { message, .. }
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
            Self::Blocked { .. } => "block",
            Self::Failed { .. } => "failed",
        }
    }
}

pub trait ExecOps {
    fn passthrough(&mut self, invocation: &CommandInvocation) -> io::Result<i32>;
    fn move_to_trash(&mut self, targets: &[String]) -> Result<(), String>;
    fn git_stash(&mut self) -> Result<(), String>;
}

pub struct SystemOps {
    real_program: PathBuf,
}

impl SystemOps {
    pub fn new(real_program: PathBuf) -> Self {
        Self { real_program }
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

    fn git_stash(&mut self) -> Result<(), String> {
        // Remove AI detector env vars so the internal git call does not
        // trigger omamori's own protection (self-interference prevention).
        let status = Command::new("git")
            .arg("stash")
            .arg("push")
            .arg("--include-untracked")
            .env_remove("CLAUDECODE")
            .env_remove("AI_GUARD")
            .status()
            .map_err(|error| error.to_string())?;
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
        stash_error: Option<String>,
        last_trash_targets: Vec<String>,
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
            vec!["-rf".to_string(), "--".to_string(), "-dangerous.txt".to_string()],
        );
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::Trash, "rm"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Trashed { .. }));
        assert_eq!(executor.ops.last_trash_targets, vec!["-dangerous.txt"]);
    }

    #[test]
    fn trash_with_only_double_dash_fails() {
        let mut executor = ActionExecutor::new(FakeOps::default());
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "--".to_string()],
        );
        let outcome = executor
            .execute(&invocation, &rule(ActionKind::Trash, "rm"))
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Failed { .. }));
    }
}
