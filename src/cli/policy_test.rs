//! `omamori test` subcommand and policy test harness.

use std::ffi::OsString;

use crate::AppError;
use crate::config::{ConfigLoadResult, load_config};
use crate::context;
use crate::detector::evaluate_detectors;
use crate::engine::shim::emit_config_warnings;
use crate::rules::{self, CommandInvocation, RuleConfig, match_rule};
use crate::util::parse_config_flag;

pub(crate) fn run_policy_test_command(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[2..])?;
    let load_result = load_config(config_path.as_deref())?;
    emit_config_warnings(&load_result);

    // Rules section
    let config = &load_result.config;
    let active_count = config.rules.iter().filter(|r| r.enabled).count();
    let disabled_count = config.rules.len() - active_count;

    println!("\nRules:");
    for rule in &config.rules {
        if !rule.enabled {
            println!("  SKIP  {:<28} (disabled by user config)", rule.name);
        } else {
            let action_display = match &rule.action {
                rules::ActionKind::MoveTo => {
                    let dest = rule.destination.as_deref().unwrap_or("(no destination)");
                    format!("move-to {dest}")
                }
                other => other.as_str().to_string(),
            };
            let pattern = {
                let mut parts: Vec<String> = vec![rule.command.clone()];
                if let Some(ref sub) = rule.subcommand {
                    parts.push(sub.clone());
                }
                if !rule.match_all.is_empty() {
                    parts.push(rule.match_all.join(" "));
                } else if !rule.match_any.is_empty() {
                    parts.push(rule.match_any.join("|"));
                }
                parts.join(" ")
            };
            println!(
                "  PASS  {:<28} {:<24} -> {}",
                rule.name, pattern, action_display
            );
        }
    }

    // Core Policy section
    println!("\nCore Policy:");
    let core_rules: Vec<&RuleConfig> = config.rules.iter().filter(|r| r.is_builtin).collect();
    let mut core_overridden = 0;
    for rule in &core_rules {
        if rule.enabled {
            println!("  PASS  {:<28} core rule active", rule.name);
        } else {
            println!(
                "  WARN  {:<28} core rule overridden (disabled by user)",
                rule.name
            );
            core_overridden += 1;
        }
    }

    // Context section
    let context_test_count = if let Some(ref ctx_config) = config.context {
        println!("\nContext:");
        let test_cases: Vec<(&str, Vec<String>, &str)> = vec![
            (
                "regenerable-path-downgrade",
                vec!["-rf".into(), "target/".into()],
                "rm",
            ),
            (
                "protected-path-escalate",
                vec!["-rf".into(), "src/".into()],
                "rm",
            ),
            (
                "unknown-path-unchanged",
                vec!["-rf".into(), "data/".into()],
                "rm",
            ),
        ];
        let mut count = 0;
        for (name, args, cmd) in &test_cases {
            let inv = CommandInvocation::new(cmd.to_string(), args.clone());
            let test_rule = config.rules.iter().find(|r| r.command == *cmd && r.enabled);
            if let Some(rule) = test_rule {
                let result = context::evaluate_context(&inv, rule, ctx_config);
                let (status, detail) = match &result.action_override {
                    Some(action) => (
                        "PASS",
                        format!(
                            "{} {} → {} (was: {})",
                            cmd,
                            args.last().unwrap_or(&String::new()),
                            action.as_str(),
                            rule.action.as_str(),
                        ),
                    ),
                    None => (
                        "PASS",
                        format!(
                            "{} {} → {} (unchanged)",
                            cmd,
                            args.last().unwrap_or(&String::new()),
                            rule.action.as_str(),
                        ),
                    ),
                };
                println!("  {status}  {name:<28} {detail}");
                count += 1;
            }
        }

        if ctx_config.git.enabled {
            println!("  PASS  {:<28} (git-aware enabled)", "git-aware-evaluation");
        } else {
            println!(
                "  SKIP  {:<28} (git-aware not enabled)",
                "git-aware-evaluation"
            );
        }
        count
    } else {
        0
    };

    // Detection section
    let results = run_policy_tests(&load_result);
    let failures = results.iter().filter(|r| !r.passed).count();

    println!("\nDetection:");
    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("  {status}  {:<28} {}", result.name, result.details);
    }

    // Summary
    let context_summary = if context_test_count > 0 {
        format!(", {} context tests", context_test_count)
    } else {
        String::new()
    };
    let core_summary = if core_overridden > 0 {
        format!(
            ", {} core rules ({} overridden)",
            core_rules.len(),
            core_overridden
        )
    } else {
        format!(", {} core rules active", core_rules.len())
    };
    println!(
        "\nSummary: {} rules ({} active, {} disabled){}{}, {} detection tests {}",
        config.rules.len(),
        active_count,
        disabled_count,
        core_summary,
        context_summary,
        results.len(),
        if failures == 0 { "passed" } else { "FAILED" }
    );

    if failures == 0 { Ok(0) } else { Ok(1) }
}

// ---------------------------------------------------------------------------
// Policy test harness (pub API for install auto-test and fuzz)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PolicyTestResult {
    pub name: &'static str,
    pub passed: bool,
    pub details: String,
}

pub fn run_policy_tests(load_result: &ConfigLoadResult) -> Vec<PolicyTestResult> {
    let config = &load_result.config;
    let claude_env = vec![("CLAUDECODE".to_string(), "1".to_string())];
    let codex_env = vec![("CODEX_CI".to_string(), "1".to_string())];
    let cursor_env = vec![("CURSOR_AGENT".to_string(), "1".to_string())];
    let unprotected_env = Vec::new();

    let cases = vec![
        (
            "ai-rm-recursive-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            claude_env.clone(),
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
            claude_env.clone(),
            Some("stash-then-exec"),
            true,
        ),
        (
            "config-parse-fallback-keeps-protection",
            CommandInvocation::new(
                "git".to_string(),
                vec!["push".to_string(), "--force".to_string()],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "find-delete-is-blocked",
            CommandInvocation::new(
                "find".to_string(),
                vec![
                    ".".to_string(),
                    "-name".to_string(),
                    "*.log".to_string(),
                    "-delete".to_string(),
                ],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "find-without-delete-passes",
            CommandInvocation::new(
                "find".to_string(),
                vec![".".to_string(), "-name".to_string(), "*.txt".to_string()],
            ),
            claude_env.clone(),
            None,
            true,
        ),
        (
            "rsync-delete-is-blocked",
            CommandInvocation::new(
                "rsync".to_string(),
                vec![
                    "--delete".to_string(),
                    "-avz".to_string(),
                    "src/".to_string(),
                    "dest/".to_string(),
                ],
            ),
            claude_env.clone(),
            Some("block"),
            true,
        ),
        (
            "rsync-without-delete-passes",
            CommandInvocation::new(
                "rsync".to_string(),
                vec!["-avz".to_string(), "src/".to_string(), "dest/".to_string()],
            ),
            claude_env,
            None,
            true,
        ),
        (
            "codex-cli-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            codex_env,
            Some("trash"),
            true,
        ),
        (
            "cursor-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            cursor_env,
            Some("trash"),
            true,
        ),
        (
            "gemini-cli-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            vec![("GEMINI_CLI".to_string(), "1".to_string())],
            Some("trash"),
            true,
        ),
        (
            "cline-is-protected",
            CommandInvocation::new(
                "rm".to_string(),
                vec!["-rf".to_string(), "target".to_string()],
            ),
            vec![("CLINE_ACTIVE".to_string(), "true".to_string())],
            Some("trash"),
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
    fn resolve_default_rule_for_rm() {
        let invocation = CommandInvocation::new("rm".to_string(), vec!["-rf".to_string()]);
        let config = Config::default();
        let rule = match_rule(&config.rules, &invocation).expect("rule should match");
        assert_eq!(rule.action, ActionKind::Trash);
    }
}
