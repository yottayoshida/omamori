use std::io;
use std::path::PathBuf;
use std::process::Command;

use crate::rules::{ActionKind, CommandInvocation, RuleMatch};

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

    pub fn message(&self) -> String {
        match self {
            Self::PassedThrough { .. } => {
                "omamori allowed the command to run unchanged".to_string()
            }
            Self::Trashed { message, .. }
            | Self::ExecutedAfterStash { message, .. }
            | Self::LoggedOnly { message, .. }
            | Self::Blocked { message }
            | Self::Failed { message } => message.clone(),
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
        Ok(status.code().unwrap_or(1))
    }

    fn move_to_trash(&mut self, targets: &[String]) -> Result<(), String> {
        let paths = targets.iter().map(PathBuf::from).collect::<Vec<_>>();
        trash::delete_all(paths).map_err(|error| error.to_string())
    }

    fn git_stash(&mut self) -> Result<(), String> {
        let status = Command::new("git")
            .arg("stash")
            .arg("push")
            .arg("--include-untracked")
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
        rule_match: &RuleMatch,
    ) -> Result<ActionOutcome, io::Error> {
        let message = rule_match
            .rule
            .message
            .clone()
            .unwrap_or_else(|| format!("omamori applied `{}`", rule_match.rule.name));

        let outcome = match rule_match.rule.action {
            ActionKind::Trash => {
                let targets = invocation
                    .args
                    .iter()
                    .filter(|arg| !arg.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>();
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
    }

    impl ExecOps for FakeOps {
        fn passthrough(&mut self, _invocation: &CommandInvocation) -> io::Result<i32> {
            self.passthrough_calls += 1;
            Ok(self.passthrough_status)
        }

        fn move_to_trash(&mut self, _targets: &[String]) -> Result<(), String> {
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

    fn rule(action: ActionKind, command: &str) -> RuleMatch {
        RuleMatch {
            rule: RuleConfig::new(
                "test",
                command,
                action,
                Vec::new(),
                Vec::new(),
                Some("message".to_string()),
            ),
        }
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
}
