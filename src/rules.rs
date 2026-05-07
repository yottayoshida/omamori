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

    /// Extract non-flag arguments (targets) from the command args.
    /// Respects the POSIX `--` separator: everything after `--` is a target,
    /// regardless of whether it starts with `-`.
    pub fn target_args(&self) -> Vec<&str> {
        if let Some(sep) = self.args.iter().position(|a| a == "--") {
            self.args[(sep + 1)..].iter().map(String::as_str).collect()
        } else {
            self.args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .map(String::as_str)
                .collect()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    Trash,
    StashThenExec,
    Block,
    LogOnly,
    MoveTo,
}

impl ActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trash => "trash",
            Self::StashThenExec => "stash-then-exec",
            Self::Block => "block",
            Self::LogOnly => "log-only",
            Self::MoveTo => "move-to",
        }
    }

    /// Defense level: higher = stronger protection.
    /// Used to prevent downgrade of core rules' action via config.
    pub fn defense_level(&self) -> u8 {
        match self {
            Self::LogOnly => 0,
            Self::Trash | Self::MoveTo | Self::StashThenExec => 1,
            Self::Block => 2,
        }
    }

    /// Generate a context-aware message that always matches the actual action.
    /// Used when context evaluation overrides the original rule's action,
    /// ensuring the user sees accurate feedback (e.g. "blocked" not "moved to Trash").
    pub fn context_message(&self, reason: &str) -> String {
        match self {
            Self::Block => format!("omamori blocked this command ({})", reason),
            Self::LogOnly => format!("omamori allowed this command ({})", reason),
            Self::Trash => format!("omamori moved targets to Trash ({})", reason),
            Self::StashThenExec => format!("omamori stashed changes first ({})", reason),
            Self::MoveTo => format!("omamori moved targets to backup ({})", reason),
        }
    }
}

fn default_true() -> bool {
    true
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
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub destination: Option<String>,
    /// Optional subcommand position constraint (v0.10.3+, DI-13).
    /// When `Some(s)`, the rule matches only when `args[0] == s`.
    /// Prevents false positives like `omamori exec -- echo disable config`
    /// matching a generic `match_any=["disable"]` builtin rule.
    /// Used by the 6 `omamori-*-block` self-protection rules.
    #[serde(default)]
    pub subcommand: Option<String>,
    /// True for the 13 built-in core safety rules. Cannot be injected via config.toml.
    #[serde(skip)]
    pub is_builtin: bool,
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
            enabled: true,
            destination: None,
            subcommand: None,
            is_builtin: false,
        }
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_destination(mut self, destination: String) -> Self {
        self.destination = Some(destination);
        self
    }

    pub fn with_subcommand(mut self, subcommand: &str) -> Self {
        self.subcommand = Some(subcommand.to_string());
        self
    }

    pub fn with_builtin(mut self, is_builtin: bool) -> Self {
        self.is_builtin = is_builtin;
        self
    }
}

pub fn match_rule<'a>(
    rules: &'a [RuleConfig],
    invocation: &CommandInvocation,
) -> Option<&'a RuleConfig> {
    rules
        .iter()
        .filter(|rule| rule.enabled)
        .find(|rule| rule_matches(rule, invocation))
}

/// Expand combined short flags like `-rfv` into individual flags
/// `["-rfv", "-r", "-f", "-v"]`, preserving the original.
/// Only expands when the flag chars are all ASCII alphabetic and there
/// are at least 2 chars after the leading `-`.
pub(crate) fn expand_short_flags(args: &[String]) -> Vec<String> {
    let mut expanded = Vec::with_capacity(args.len());
    // Track which single-letter flags have been emitted to avoid O(n²) contains() checks.
    // Index: 0-25 = a-z, 26-51 = A-Z.
    let mut seen = [false; 52];
    for arg in args {
        expanded.push(arg.clone());
        let bytes = arg.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'-'
            && bytes[1] != b'-'
            && bytes[1..].iter().all(|b| b.is_ascii_alphabetic())
        {
            for &ch in &bytes[1..] {
                let idx = match ch {
                    b'a'..=b'z' => (ch - b'a') as usize,
                    b'A'..=b'Z' => (ch - b'A') as usize + 26,
                    _ => continue,
                };
                if !seen[idx] {
                    seen[idx] = true;
                    expanded.push(format!("-{}", ch as char));
                }
            }
        }
    }
    expanded
}

fn rule_matches(rule: &RuleConfig, invocation: &CommandInvocation) -> bool {
    if rule.command != invocation.program {
        return false;
    }

    // DI-13: subcommand position constraint. When `Some`, args[0] must match exactly.
    // This prevents `omamori exec -- echo disable config` from matching a generic
    // `match_any=["disable"]` rule by ensuring the verb is at the subcommand position.
    if let Some(ref sub) = rule.subcommand {
        if invocation.args.first().map(String::as_str) != Some(sub.as_str()) {
            return false;
        }
    }

    let expanded = expand_short_flags(&invocation.args);

    if !rule
        .match_all
        .iter()
        .all(|needle| expanded.iter().any(|arg| arg == needle))
    {
        return false;
    }

    if rule.match_any.is_empty() {
        return true;
    }

    rule.match_any
        .iter()
        .any(|needle| expanded.iter().any(|arg| arg == needle))
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

    // --- target_args tests (Fix 1) ---

    #[test]
    fn target_args_respects_double_dash_separator() {
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec![
                "-rf".to_string(),
                "--".to_string(),
                "-dangerous.txt".to_string(),
            ],
        );
        assert_eq!(inv.target_args(), vec!["-dangerous.txt"]);
    }

    #[test]
    fn target_args_empty_after_double_dash() {
        let inv =
            CommandInvocation::new("rm".to_string(), vec!["-rf".to_string(), "--".to_string()]);
        assert!(inv.target_args().is_empty());
    }

    #[test]
    fn target_args_all_after_double_dash() {
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec![
                "--".to_string(),
                "-a".to_string(),
                "-b".to_string(),
                "-c".to_string(),
            ],
        );
        assert_eq!(inv.target_args(), vec!["-a", "-b", "-c"]);
    }

    #[test]
    fn target_args_no_separator_filters_flags() {
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "target/".to_string()],
        );
        assert_eq!(inv.target_args(), vec!["target/"]);
    }

    // --- expand_short_flags tests (Fix 2) ---

    #[test]
    fn expand_short_flags_splits_combined() {
        let args = vec!["-rfv".to_string()];
        let expanded = expand_short_flags(&args);
        assert!(expanded.contains(&"-rfv".to_string()));
        assert!(expanded.contains(&"-r".to_string()));
        assert!(expanded.contains(&"-f".to_string()));
        assert!(expanded.contains(&"-v".to_string()));
    }

    #[test]
    fn expand_short_flags_ignores_long_flags() {
        let args = vec!["--recursive".to_string()];
        let expanded = expand_short_flags(&args);
        assert_eq!(expanded, vec!["--recursive".to_string()]);
    }

    #[test]
    fn expand_short_flags_ignores_non_alpha() {
        let args = vec!["-C2".to_string(), "-1".to_string()];
        let expanded = expand_short_flags(&args);
        assert_eq!(expanded, vec!["-C2".to_string(), "-1".to_string()]);
    }

    #[test]
    fn expand_short_flags_single_char_not_expanded() {
        let args = vec!["-f".to_string()];
        let expanded = expand_short_flags(&args);
        assert_eq!(expanded, vec!["-f".to_string()]);
    }

    #[test]
    fn combined_flag_matches_rm_trash_rule() {
        let rule = RuleConfig::new(
            "rm-recursive",
            "rm",
            ActionKind::Trash,
            Vec::new(),
            vec![
                "-r".to_string(),
                "-rf".to_string(),
                "-fr".to_string(),
                "--recursive".to_string(),
            ],
            None,
        );
        // -rfv should match because it expands to include -r
        let inv = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rfv".to_string(), "target/".to_string()],
        );
        assert!(match_rule(&[rule], &inv).is_some());
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let rule = RuleConfig::new(
            "git-push-force",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["-f".to_string(), "--force".to_string()],
            None,
        )
        .with_enabled(false);
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["push".to_string(), "--force".to_string()],
        );
        assert!(match_rule(&[rule], &inv).is_none());
    }

    #[test]
    fn enabled_rule_still_matches() {
        let rule = RuleConfig::new(
            "git-push-force",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["-f".to_string(), "--force".to_string()],
            None,
        )
        .with_enabled(true);
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec!["push".to_string(), "--force".to_string()],
        );
        assert!(match_rule(&[rule], &inv).is_some());
    }

    #[test]
    fn move_to_action_serializes_correctly() {
        let rule = RuleConfig::new(
            "rm-to-backup",
            "rm",
            ActionKind::MoveTo,
            Vec::new(),
            vec!["-rf".to_string()],
            None,
        )
        .with_destination("/tmp/backup".to_string());
        assert_eq!(rule.action.as_str(), "move-to");
        assert_eq!(rule.destination.as_deref(), Some("/tmp/backup"));
    }

    #[test]
    fn git_push_dash_f_matches_block_rule() {
        let rule = RuleConfig::new(
            "git-push-force",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["-f".to_string(), "--force".to_string()],
            None,
        );
        let inv = CommandInvocation::new(
            "git".to_string(),
            vec![
                "push".to_string(),
                "-f".to_string(),
                "origin".to_string(),
                "main".to_string(),
            ],
        );
        assert!(match_rule(&[rule], &inv).is_some());
    }

    // --- context_message tests (#36) ---

    #[test]
    fn context_message_matches_action_kind() {
        let reason = "NEVER_REGENERABLE path";
        assert_eq!(
            ActionKind::Block.context_message(reason),
            "omamori blocked this command (NEVER_REGENERABLE path)"
        );
        assert_eq!(
            ActionKind::LogOnly.context_message(reason),
            "omamori allowed this command (NEVER_REGENERABLE path)"
        );
        assert_eq!(
            ActionKind::Trash.context_message(reason),
            "omamori moved targets to Trash (NEVER_REGENERABLE path)"
        );
        assert_eq!(
            ActionKind::StashThenExec.context_message(reason),
            "omamori stashed changes first (NEVER_REGENERABLE path)"
        );
        assert_eq!(
            ActionKind::MoveTo.context_message(reason),
            "omamori moved targets to backup (NEVER_REGENERABLE path)"
        );
    }

    #[test]
    fn context_message_includes_reason() {
        let msg = ActionKind::Block.context_message("git working tree has uncommitted changes");
        assert!(msg.contains("blocked"));
        assert!(msg.contains("git working tree has uncommitted changes"));
    }
}
