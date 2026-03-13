use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandInvocation {
    pub fn new(program: String, args: Vec<String>) -> Self {
        Self { program, args }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    Trash,
    StashThenExec,
    Block,
    LogOnly,
}

impl ActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trash => "trash",
            Self::StashThenExec => "stash-then-exec",
            Self::Block => "block",
            Self::LogOnly => "log-only",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    pub command: String,
    pub action: ActionKind,
    #[serde(default)]
    pub match_all: Vec<String>,
    #[serde(default)]
    pub match_any: Vec<String>,
    pub message: Option<String>,
}

impl RuleConfig {
    pub fn new(
        name: &str,
        command: &str,
        action: ActionKind,
        match_all: Vec<String>,
        match_any: Vec<String>,
        message: Option<String>,
    ) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            action,
            match_all,
            match_any,
            message,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: RuleConfig,
}

pub fn match_rule(rules: &[RuleConfig], invocation: &CommandInvocation) -> Option<RuleMatch> {
    rules
        .iter()
        .find(|rule| rule_matches(rule, invocation))
        .cloned()
        .map(|rule| RuleMatch { rule })
}

fn rule_matches(rule: &RuleConfig, invocation: &CommandInvocation) -> bool {
    if rule.command != invocation.program {
        return false;
    }

    if !rule
        .match_all
        .iter()
        .all(|needle| invocation.args.iter().any(|arg| arg == needle))
    {
        return false;
    }

    if rule.match_any.is_empty() {
        return true;
    }

    rule.match_any
        .iter()
        .any(|needle| invocation.args.iter().any(|arg| arg == needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_when_all_tokens_present() {
        let rule = RuleConfig::new(
            "git-reset",
            "git",
            ActionKind::StashThenExec,
            vec!["reset".to_string(), "--hard".to_string()],
            Vec::new(),
            None,
        );
        let invocation = CommandInvocation::new(
            "git".to_string(),
            vec!["reset".to_string(), "--hard".to_string()],
        );
        assert!(match_rule(&[rule], &invocation).is_some());
    }

    #[test]
    fn does_not_match_without_required_any_token() {
        let rule = RuleConfig::new(
            "git-push-force",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["-f".to_string(), "--force".to_string()],
            None,
        );
        let invocation = CommandInvocation::new("git".to_string(), vec!["push".to_string()]);
        assert!(match_rule(&[rule], &invocation).is_none());
    }
}
