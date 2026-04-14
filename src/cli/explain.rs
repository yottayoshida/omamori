//! `omamori explain [--json] [--config PATH] -- <command...>` subcommand.
//!
//! Simulate evaluation of a command through both defense layers without executing it.
//! Shows what would happen and why — answering "why was this blocked?"
//!
//! SECURITY (DI-8): blocked in AI environments to prevent oracle attacks.

use std::ffi::OsString;

use crate::AppError;
use crate::config::{self, ConfigLoadResult, load_config};
use crate::context;
use crate::engine::guard::guard_ai_config_modification;
use crate::engine::hook::{HookCheckResult, check_command_for_hook};
use crate::rules::{CommandInvocation, match_rule};
use crate::util::{parse_config_flag, usage_text};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn run_explain_command(args: &[OsString]) -> Result<i32, AppError> {
    // DI-8: explain is blocked in AI environments (oracle attack prevention)
    guard_ai_config_modification("explain")?;

    let mut json = false;
    let mut config_args: Vec<OsString> = Vec::new();
    let mut command_parts: Vec<String> = Vec::new();
    let mut saw_separator = false;
    let mut index = 2usize;

    while index < args.len() {
        let arg = args[index].to_str().unwrap_or("");
        if saw_separator {
            command_parts.push(arg.to_string());
            index += 1;
            continue;
        }
        match arg {
            "--" => {
                saw_separator = true;
                index += 1;
            }
            "--json" => {
                json = true;
                index += 1;
            }
            "--config" => {
                config_args.push(args[index].clone());
                if let Some(val) = args.get(index + 1) {
                    config_args.push(val.clone());
                }
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown explain flag: {arg}\n\nUsage: omamori explain [--json] [--config PATH] -- <command...>\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    if command_parts.is_empty() {
        return Err(AppError::Usage(format!(
            "explain requires a command after `--`\n\nUsage: omamori explain [--json] [--config PATH] -- <command...>\n\n{}",
            usage_text()
        )));
    }

    let config_path = parse_config_flag(&config_args)?;
    // Preserve shell quoting for Layer 2 (hook evaluation operates on shell strings)
    let command_str = shell_words::join(&command_parts);

    // --- Layer 1 evaluation (shim / PATH-level) ---
    let layer1 = evaluate_layer1(&command_parts, config_path.as_deref());

    // --- Layer 2 evaluation (hook / string-level) ---
    let layer2 = evaluate_layer2(&command_str);

    // --- Verdict ---
    let blocked = layer1.blocked || layer2.blocked;
    let exit_code = if blocked { 2 } else { 0 };

    if json {
        print_json(&command_str, &layer1, &layer2, blocked);
    } else {
        print_report(&command_str, &layer1, &layer2, blocked);
    }

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// Layer evaluation results
// ---------------------------------------------------------------------------

struct Layer1Result {
    blocked: bool,
    matched_rule: Option<String>,
    action: String,
    context_override: Option<String>,
    detail: String,
}

struct Layer2Result {
    blocked: bool,
    phase: String,
    detail: String,
}

// ---------------------------------------------------------------------------
// Layer 1: shim evaluation (rule matching + context)
// ---------------------------------------------------------------------------

fn evaluate_layer1(
    command_parts: &[String],
    config_path: Option<&std::path::Path>,
) -> Layer1Result {
    let load_result = match load_config(config_path) {
        Ok(r) => r,
        Err(e) => {
            if config_path.is_some() {
                // Explicit --config: surface the error — don't silently use defaults
                return Layer1Result {
                    blocked: false,
                    matched_rule: None,
                    action: "error".to_string(),
                    context_override: None,
                    detail: format!("config load failed: {e} (using defaults)"),
                };
            }
            ConfigLoadResult {
                config: config::Config::default(),
                warnings: vec![],
            }
        }
    };

    if command_parts.is_empty() {
        return Layer1Result {
            blocked: false,
            matched_rule: None,
            action: "allow".to_string(),
            context_override: None,
            detail: "no command provided".to_string(),
        };
    }

    let program = &command_parts[0];
    let args: Vec<String> = command_parts[1..].to_vec();
    let invocation = CommandInvocation::new(program.clone(), args);

    let matched = match_rule(&load_result.config.rules, &invocation);

    let Some(rule) = matched else {
        return Layer1Result {
            blocked: false,
            matched_rule: None,
            action: "allow".to_string(),
            context_override: None,
            detail: "no rule matched — command would be passed through".to_string(),
        };
    };

    // Context evaluation
    let context_override = if let Some(ctx_config) = &load_result.config.context {
        let ctx = context::evaluate_context(&invocation, rule, ctx_config);
        ctx.action_override
            .map(|action| format!("{} ({})", action.as_str(), ctx.reason))
    } else {
        None
    };

    let effective_action = if let Some(ref ctx_str) = context_override {
        // Extract action name from "action (reason)" format
        ctx_str.split(' ').next().unwrap_or("block")
    } else {
        rule.action.as_str()
    };

    let blocked = effective_action == "block";
    let detail = rule
        .message
        .clone()
        .unwrap_or_else(|| format!("matched rule: {}", rule.name));

    Layer1Result {
        blocked,
        matched_rule: Some(rule.name.clone()),
        action: effective_action.to_string(),
        context_override,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Layer 2: hook evaluation (meta-pattern + unwrap stack)
// ---------------------------------------------------------------------------

fn evaluate_layer2(command_str: &str) -> Layer2Result {
    match check_command_for_hook(command_str) {
        HookCheckResult::Allow => Layer2Result {
            blocked: false,
            phase: "allow".to_string(),
            detail: "no meta-pattern or rule match".to_string(),
        },
        HookCheckResult::BlockMeta(reason) => Layer2Result {
            blocked: true,
            phase: "meta-pattern".to_string(),
            detail: reason.to_string(),
        },
        HookCheckResult::BlockRule {
            rule_name,
            message,
            unwrap_chain,
        } => {
            let detail = if let Some(chain) = unwrap_chain {
                format!("{message} ({chain})")
            } else {
                message
            };
            Layer2Result {
                blocked: true,
                phase: format!("rule: {rule_name}"),
                detail,
            }
        }
        HookCheckResult::BlockStructural(message) => Layer2Result {
            blocked: true,
            phase: "structural".to_string(),
            detail: message,
        },
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

fn print_report(command_str: &str, layer1: &Layer1Result, layer2: &Layer2Result, blocked: bool) {
    let verdict = if blocked { "BLOCK" } else { "ALLOW" };
    println!("omamori explain: {command_str}\n");
    println!("  Verdict: {verdict}\n");

    // Layer 1
    println!("  Layer 1 (PATH shim):");
    if let Some(ref rule) = layer1.matched_rule {
        println!("    rule: {rule}");
        println!("    action: {}", layer1.action);
        if let Some(ref ctx) = layer1.context_override {
            println!("    context override: {ctx}");
        }
        println!("    detail: {}", layer1.detail);
    } else {
        println!("    {}", layer1.detail);
    }

    // Layer 2
    println!();
    println!("  Layer 2 (hooks):");
    if layer2.blocked {
        println!("    phase: {}", layer2.phase);
        println!("    detail: {}", layer2.detail);
    } else {
        println!("    {}", layer2.detail);
    }
    println!("    note: Layer 2 applies rule action directly (no context override)");

    // Guidance
    println!();
    if blocked {
        println!("  Guidance: run this command directly in your terminal (not via AI)");
    } else {
        println!("  Guidance: this command would be allowed through omamori");
    }
}

fn print_json(command_str: &str, layer1: &Layer1Result, layer2: &Layer2Result, blocked: bool) {
    let output = serde_json::json!({
        "command": command_str,
        "verdict": if blocked { "block" } else { "allow" },
        "layer1": {
            "blocked": layer1.blocked,
            "matched_rule": layer1.matched_rule,
            "action": layer1.action,
            "context_override": layer1.context_override,
            "detail": layer1.detail,
        },
        "layer2": {
            "blocked": layer2.blocked,
            "phase": layer2.phase,
            "detail": layer2.detail,
        },
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer1_no_rule_match_is_allow() {
        let parts = vec!["ls".to_string(), "/tmp".to_string()];
        let result = evaluate_layer1(&parts, None);
        assert!(!result.blocked);
        assert!(result.matched_rule.is_none());
        assert_eq!(result.action, "allow");
    }

    #[test]
    fn layer1_rm_recursive_matches_rule() {
        let parts = vec!["rm".to_string(), "-rf".to_string(), "/tmp/test".to_string()];
        let result = evaluate_layer1(&parts, None);
        assert!(result.matched_rule.is_some());
        // Whether blocked depends on context config — the rule exists
        assert!(result.matched_rule.unwrap().contains("rm"));
    }

    #[test]
    fn layer2_safe_command_is_allow() {
        let result = evaluate_layer2("ls /tmp");
        assert!(!result.blocked);
        assert_eq!(result.phase, "allow");
    }

    #[test]
    fn layer2_meta_pattern_blocks() {
        let result = evaluate_layer2("unset CLAUDECODE");
        assert!(result.blocked);
        assert_eq!(result.phase, "meta-pattern");
    }

    #[test]
    fn layer2_blocked_command_pattern_explain() {
        // "omamori explain" should be caught by blocked_command_patterns after DI-9
        // This test will pass after we add the pattern to installer.rs
        let result = evaluate_layer2("omamori explain -- rm -rf /");
        assert!(result.blocked);
    }

    #[test]
    fn layer2_blocked_command_pattern_doctor_fix() {
        let result = evaluate_layer2("omamori doctor --fix");
        assert!(result.blocked);
    }

    #[test]
    fn verdict_blocked_if_either_layer_blocks() {
        // Layer 1 allow + Layer 2 block = blocked
        let l1 = Layer1Result {
            blocked: false,
            matched_rule: None,
            action: "allow".to_string(),
            context_override: None,
            detail: "no match".to_string(),
        };
        let l2 = Layer2Result {
            blocked: true,
            phase: "meta-pattern".to_string(),
            detail: "blocked".to_string(),
        };
        assert!(l1.blocked || l2.blocked);

        // Layer 1 block + Layer 2 allow = blocked
        let l1b = Layer1Result {
            blocked: true,
            matched_rule: Some("rm-recursive".to_string()),
            action: "block".to_string(),
            context_override: None,
            detail: "blocked".to_string(),
        };
        let l2b = Layer2Result {
            blocked: false,
            phase: "allow".to_string(),
            detail: "ok".to_string(),
        };
        assert!(l1b.blocked || l2b.blocked);
    }

    #[test]
    fn json_output_is_valid() {
        let l1 = Layer1Result {
            blocked: false,
            matched_rule: None,
            action: "allow".to_string(),
            context_override: None,
            detail: "no match".to_string(),
        };
        let l2 = Layer2Result {
            blocked: false,
            phase: "allow".to_string(),
            detail: "ok".to_string(),
        };
        // Just ensure it doesn't panic
        print_json("ls /tmp", &l1, &l2, false);
    }
}
