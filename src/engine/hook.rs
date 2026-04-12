//! Hook pipeline: input parsing, command checking, protected file detection.
//!
//! SECURITY: This module is the primary security gate for AI tool commands.
//! DO NOT SPLIT — the entire pipeline must be reviewable in one file.
//! See threat model T8 (DREAD 9.0): fail-close fallback in check_command_for_hook.

use std::ffi::OsString;

use crate::AppError;
use crate::config::{self, ConfigLoadResult, load_config};
use crate::installer;
use crate::rules::{CommandInvocation, match_rule};
use crate::unwrap;

// ---------------------------------------------------------------------------
// Shared hook check logic (used by both hook-check and cursor-hook)
// ---------------------------------------------------------------------------

/// Result of checking a command string through the hook pipeline.
pub(crate) enum HookCheckResult {
    /// Command is allowed.
    Allow,
    /// Command is blocked by a meta-pattern (string-level).
    BlockMeta(&'static str),
    /// Command is blocked by the unwrap stack (token-level rule match).
    BlockRule {
        rule_name: String,
        message: String,
        unwrap_chain: Option<String>,
    },
    /// Command is blocked by the unwrap stack (structural block: pipe-to-shell, etc.).
    BlockStructural(String),
}

/// Two-phase hook check:
/// Phase 1: Meta-pattern string-level check (env var unset, config tamper, /bin/rm, etc.)
/// Phase 2: Token-level unwrap stack → rule matching
///
/// SECURITY (T8): The `Config::default()` fallback on load_config failure is
/// intentional fail-safe behavior. DO NOT replace with `?` operator.
pub(crate) fn check_command_for_hook(command: &str) -> HookCheckResult {
    // Phase 1: Meta-patterns (string-level, intentionally broad)
    for (pattern, reason) in installer::blocked_command_patterns() {
        if command.contains(pattern) {
            return HookCheckResult::BlockMeta(reason);
        }
    }

    // Phase 2: Unwrap stack → rule matching
    let parse_result = unwrap::parse_command_string(command);

    match parse_result {
        unwrap::ParseResult::Block(reason) => HookCheckResult::BlockStructural(format!(
            "omamori hook: blocked — {}",
            reason.message()
        )),
        unwrap::ParseResult::Commands(invocations) => {
            // Load config to get rules
            // SECURITY (T8): fail-safe fallback — do NOT use ? here
            let load_result = match load_config(None) {
                Ok(r) => r,
                Err(_) => {
                    // Config load failure → use default rules (fail-safe, not fail-open)
                    ConfigLoadResult {
                        config: config::Config::default(),
                        warnings: vec![],
                    }
                }
            };

            for inv in &invocations {
                if let Some(rule) = match_rule(&load_result.config.rules, inv) {
                    let chain_desc = format_unwrap_chain(command, inv);
                    let msg = rule
                        .message
                        .clone()
                        .unwrap_or_else(|| format!("matched rule: {}", rule.name));
                    return HookCheckResult::BlockRule {
                        rule_name: rule.name.clone(),
                        message: msg,
                        unwrap_chain: chain_desc,
                    };
                }
            }

            HookCheckResult::Allow
        }
    }
}

/// Format the unwrap chain for display: "rm -rf / (via bash -c)"
fn format_unwrap_chain(original: &str, invocation: &CommandInvocation) -> Option<String> {
    let trimmed = original.trim();
    if !trimmed.starts_with(&invocation.program) {
        let outer = trimmed.split_whitespace().next().unwrap_or("");
        let outer_base = outer.rsplit('/').next().unwrap_or(outer);
        if trimmed.contains("-c") {
            Some(format!("via {} -c", outer_base))
        } else {
            Some(format!("via {}", outer_base))
        }
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// hook-check subcommand (Claude Code PreToolUse thin wrapper target)
// ---------------------------------------------------------------------------

/// `omamori hook-check [--provider NAME]`
/// Reads PreToolUse JSON from stdin, classifies via `HookInput`, then evaluates.
/// Exit 0 = allow, exit 2 = block.
pub(crate) fn run_hook_check(args: &[OsString]) -> Result<i32, AppError> {
    use std::io::Read;

    let provider = parse_provider_flag(args);
    let verbose = std::env::var("OMAMORI_VERBOSE").is_ok();

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    match extract_hook_input(&input) {
        HookInput::MalformedJson => {
            eprintln!("omamori hook: blocked — hook input is not valid JSON");
            eprintln!("  The command was denied because omamori cannot verify its safety.");
            eprintln!(
                "  This may happen after an AI tool update. Try: upgrade omamori, or report at https://github.com/yottayoshida/omamori/issues"
            );
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!(
                    "  raw input (first 200 chars): {}",
                    truncate_for_log(&input, 200)
                );
            }
            Ok(2)
        }
        HookInput::MalformedMissingField => {
            eprintln!("omamori hook: blocked — required fields missing from hook input");
            eprintln!("  The command was denied because omamori cannot verify its safety.");
            eprintln!("  Expected: tool_input.command or tool_input.file_path");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!(
                    "  raw input (first 200 chars): {}",
                    truncate_for_log(&input, 200)
                );
            }
            Ok(2)
        }
        HookInput::UnknownTool(tool_name) => {
            print_hook_check_allow_response(&format!(
                "omamori: unrecognized tool '{tool_name}' — allowed for forward compatibility"
            ));
            Ok(0)
        }
        HookInput::FileOp { tool, path } => {
            if let Some(reason) = is_protected_file_path(&path) {
                eprintln!("omamori hook: blocked {tool} to protected file — {reason}");
                eprintln!("  AI agents cannot modify omamori configuration or security files.");
                eprintln!(
                    "  To edit config: use `omamori config` CLI or edit the file directly in your terminal."
                );
                if verbose {
                    eprintln!("  provider: {provider}");
                    eprintln!("  tool: {tool}");
                    eprintln!("  path: {path}");
                }
                Ok(2)
            } else {
                print_hook_check_allow_response(&format!(
                    "omamori: {tool} to non-protected path — allowed"
                ));
                Ok(0)
            }
        }
        HookInput::Command(command) => {
            if command.is_empty() {
                print_hook_check_allow_response("omamori: empty command");
                return Ok(0);
            }
            run_hook_check_command(&command, &provider, verbose)
        }
    }
}

/// Evaluate a shell command through the two-phase hook check pipeline.
fn run_hook_check_command(command: &str, provider: &str, verbose: bool) -> Result<i32, AppError> {
    match check_command_for_hook(command) {
        HookCheckResult::Allow => {
            print_hook_check_allow_response("omamori: no dangerous pattern detected");
            Ok(0)
        }
        HookCheckResult::BlockMeta(reason) => {
            eprintln!("omamori hook: blocked — {reason}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  layer: meta-pattern (string-level)");
            }
            Ok(2)
        }
        HookCheckResult::BlockRule {
            rule_name,
            message,
            unwrap_chain,
        } => {
            let chain_str = unwrap_chain
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default();
            eprintln!("omamori hook: blocked — {message}{chain_str}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  rule: {rule_name}");
                eprintln!("  layer: unwrap-stack (token-level)");
            }
            eprintln!(
                "  hint: if intentional, run the command directly in your terminal (not via AI agent)"
            );
            Ok(2)
        }
        HookCheckResult::BlockStructural(message) => {
            eprintln!("{message}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  layer: unwrap-stack (structural)");
            }
            eprintln!(
                "  hint: if intentional, run the command directly in your terminal (not via AI agent)"
            );
            Ok(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor hook handler
// ---------------------------------------------------------------------------

/// Cursor `beforeShellExecution` hook handler.
pub(crate) fn run_cursor_hook() -> Result<i32, AppError> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let command = match serde_json::from_str::<serde_json::Value>(&input) {
        Ok(v) => match v.get("command") {
            Some(c) if c.is_string() => c.as_str().unwrap().to_string(),
            Some(_) | None => {
                eprintln!("omamori cursor-hook: missing or invalid 'command' field");
                print_cursor_response(false, "deny", Some("omamori: malformed hook input"), None);
                return Ok(0);
            }
        },
        Err(_) => {
            eprintln!("omamori cursor-hook: failed to parse stdin JSON");
            print_cursor_response(false, "deny", Some("omamori: malformed hook input"), None);
            return Ok(0);
        }
    };

    if command.is_empty() {
        print_cursor_response(true, "allow", None, None);
        return Ok(0);
    }

    match check_command_for_hook(&command) {
        HookCheckResult::Allow => {
            print_cursor_response(true, "allow", None, None);
        }
        HookCheckResult::BlockMeta(reason) => {
            eprintln!("omamori cursor-hook: BLOCKED ({reason})");
            print_cursor_response(
                false,
                "deny",
                Some(&format!("omamori hook: {reason}")),
                Some(&format!(
                    "This command was blocked by omamori: {reason}. Use a safer alternative."
                )),
            );
        }
        HookCheckResult::BlockRule {
            message,
            unwrap_chain,
            ..
        } => {
            let chain_str = unwrap_chain
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default();
            eprintln!("omamori cursor-hook: BLOCKED ({message}{chain_str})");
            print_cursor_response(
                false,
                "deny",
                Some(&format!("omamori hook: blocked — {message}{chain_str}")),
                Some("This command was blocked by omamori safety guard. Use a safer alternative."),
            );
        }
        HookCheckResult::BlockStructural(message) => {
            eprintln!("omamori cursor-hook: BLOCKED ({message})");
            print_cursor_response(
                false,
                "deny",
                Some(&message),
                Some("This command was blocked by omamori safety guard. Use a safer alternative."),
            );
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// File path protection for Edit/Write/MultiEdit (#110)
// ---------------------------------------------------------------------------

/// Patterns that identify omamori's own files and external hook registrations.
/// SECURITY: pub(crate) const, never pub const. See threat model T2.
pub(crate) const PROTECTED_FILE_PATTERNS: &[(&str, &str)] = &[
    ("omamori/config.toml", "omamori config"),
    (".integrity.json", "integrity baseline"),
    ("audit-secret", "audit HMAC secret"),
    ("audit.jsonl", "audit log"),
    (".local/share/omamori", "omamori data directory"),
    ("claude-pretooluse.sh", "omamori hook script"),
    ("codex-pretooluse.sh", "omamori Codex hook script"),
    (".codex/hooks.json", "Codex hooks config"),
    (".codex/config.toml", "Codex config"),
    (
        ".claude/settings.json",
        "Claude Code settings (contains hook config)",
    ),
];

/// Check whether a file path targets a protected omamori file.
fn is_protected_file_path(path: &str) -> Option<&'static str> {
    let lexical = crate::context::normalize_path(path);

    let candidates: Vec<std::path::PathBuf> = match std::fs::canonicalize(&lexical) {
        Ok(canonical) => vec![canonical],
        Err(_) => lexical
            .parent()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .and_then(|cp| lexical.file_name().map(|f| cp.join(f)))
            .into_iter()
            .collect(),
    };

    let lexical_str = lexical.to_string_lossy();
    for &(pattern, reason) in PROTECTED_FILE_PATTERNS {
        if lexical_str.contains(pattern) {
            return Some(reason);
        }
        for candidate in &candidates {
            if candidate.to_string_lossy().contains(pattern) {
                return Some(reason);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HookInput: typed representation of PreToolUse hook stdin
// ---------------------------------------------------------------------------

/// Parsed hook input from AI tool platforms (Claude Code, Codex CLI, etc.).
#[derive(Debug)]
enum HookInput {
    Command(String),
    FileOp { tool: String, path: String },
    UnknownTool(String),
    MalformedJson,
    MalformedMissingField,
}

/// Parse PreToolUse hook stdin into a typed `HookInput`.
fn extract_hook_input(input: &str) -> HookInput {
    let v = match serde_json::from_str::<serde_json::Value>(input) {
        Ok(v) => v,
        Err(_) => return HookInput::MalformedJson,
    };

    let tool_input = v.get("tool_input");

    if let Some(cmd_val) = tool_input.and_then(|ti| ti.get("command")) {
        return match cmd_val.as_str() {
            Some(cmd) => HookInput::Command(cmd.to_string()),
            None => HookInput::MalformedMissingField,
        };
    }

    if let Some(cmd_val) = v.get("command") {
        return match cmd_val.as_str() {
            Some(cmd) => HookInput::Command(cmd.to_string()),
            None => HookInput::MalformedMissingField,
        };
    }

    if let Some(path_val) = tool_input.and_then(|ti| ti.get("file_path")) {
        return match path_val.as_str() {
            Some(path) => {
                let tool = v
                    .get("tool_name")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                HookInput::FileOp {
                    tool,
                    path: path.to_string(),
                }
            }
            None => HookInput::MalformedMissingField,
        };
    }

    if let Some(ti) = tool_input {
        if ti.as_object().is_none_or(|obj| obj.is_empty()) {
            return HookInput::MalformedMissingField;
        }
        if let Some(name) = v.get("tool_name").and_then(|t| t.as_str()) {
            return HookInput::UnknownTool(name.to_string());
        }
        return HookInput::MalformedMissingField;
    }

    if let Some(name) = v.get("tool_name").and_then(|t| t.as_str()) {
        return HookInput::UnknownTool(name.to_string());
    }

    HookInput::MalformedMissingField
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

fn parse_provider_flag(args: &[OsString]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if arg.to_str() == Some("--provider")
            && let Some(val) = args.get(i + 1)
        {
            return val.to_string_lossy().to_string();
        }
    }
    "unknown".to_string()
}

fn print_hook_check_allow_response(reason: &str) {
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
        }
    });
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"omamori: fallback"}}"#.to_string()
        })
    );
}

fn print_cursor_response(
    cont: bool,
    permission: &str,
    user_message: Option<&str>,
    agent_message: Option<&str>,
) {
    let mut response = serde_json::json!({
        "continue": cont,
        "permission": permission,
    });
    if let Some(msg) = user_message {
        response["userMessage"] = serde_json::json!(msg);
    }
    if let Some(msg) = agent_message {
        response["agentMessage"] = serde_json::json!(msg);
    }
    println!(
        "{}",
        serde_json::to_string(&response)
            .unwrap_or_else(|_| { r#"{"continue":false,"permission":"deny"}"#.to_string() })
    );
}

// ---------------------------------------------------------------------------
// Fuzz entry points (pub for fuzz harness, re-exported from lib.rs)
// ---------------------------------------------------------------------------

pub fn fuzz_extract_hook_input(input: &str) {
    let _ = extract_hook_input(input);
}

pub fn fuzz_check_command_for_hook(command: &str) {
    let _ = check_command_for_hook(command);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- GR-001: fail-close config fallback (T8 guardrail, DREAD 9.0) ---

    /// Redirect config discovery to an empty temp dir so `load_config(None)`
    /// cannot find config.toml and falls back to `Config::default()`.
    ///
    /// # Safety
    /// Env-var mutation is guarded by `#[serial_test::serial]` on every caller.
    fn isolate_config() -> (Option<String>, Option<String>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("omamori-gr-iso-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let old_home = std::env::var("HOME").ok();
        // SAFETY: serialized by #[serial_test::serial] — no concurrent env reads.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.join("xdg"));
            std::env::set_var("HOME", &dir);
        }
        (old_xdg, old_home, dir)
    }

    fn restore_config(old_xdg: Option<String>, old_home: Option<String>, dir: PathBuf) {
        // SAFETY: serialized by #[serial_test::serial] — no concurrent env reads.
        unsafe {
            match old_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match old_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_command_for_hook_blocks_rm_rf_with_default_rules() {
        let (old_xdg, old_home, dir) = isolate_config();

        match check_command_for_hook("rm -rf /") {
            HookCheckResult::BlockRule { rule_name, .. } => {
                assert!(
                    rule_name.contains("rm"),
                    "expected rm-related rule, got: {rule_name}"
                );
            }
            HookCheckResult::BlockMeta(_) | HookCheckResult::BlockStructural(_) => {}
            HookCheckResult::Allow => {
                restore_config(old_xdg, old_home, dir);
                panic!("SECURITY: rm -rf / was ALLOWED — fail-close fallback is broken");
            }
        }
        restore_config(old_xdg, old_home, dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_command_for_hook_allows_safe_command() {
        let (old_xdg, old_home, dir) = isolate_config();

        match check_command_for_hook("ls /tmp") {
            HookCheckResult::Allow => {}
            other => {
                restore_config(old_xdg, old_home, dir);
                panic!(
                    "expected Allow for 'ls /tmp', got: {}",
                    match other {
                        HookCheckResult::BlockMeta(r) => format!("BlockMeta({r})"),
                        HookCheckResult::BlockRule { rule_name, .. } =>
                            format!("BlockRule({rule_name})"),
                        HookCheckResult::BlockStructural(r) => format!("BlockStructural({r})"),
                        HookCheckResult::Allow => unreachable!(),
                    }
                );
            }
        }
        restore_config(old_xdg, old_home, dir);
    }

    // --- GR-003: extract_hook_input 6-class unit tests ---

    #[test]
    fn extract_hook_input_command_from_tool_input() {
        let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "ls -la"),
            other => panic!("expected Command, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_command_from_top_level() {
        let input = r#"{"command":"echo hello"}"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "echo hello"),
            other => panic!("expected Command, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_file_op() {
        let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/x.rs"}}"#;
        match extract_hook_input(input) {
            HookInput::FileOp { tool, path } => {
                assert_eq!(tool, "Edit");
                assert_eq!(path, "/tmp/x.rs");
            }
            other => panic!("expected FileOp, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_unknown_tool() {
        let input = r#"{"tool_name":"FutureTool","tool_input":{"query":"something"}}"#;
        match extract_hook_input(input) {
            HookInput::UnknownTool(name) => assert_eq!(name, "FutureTool"),
            other => panic!("expected UnknownTool, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_malformed_json() {
        match extract_hook_input("not json at all") {
            HookInput::MalformedJson => {}
            other => panic!("expected MalformedJson, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_missing_field() {
        let input = r#"{"tool_name":"Bash","tool_input":{}}"#;
        match extract_hook_input(input) {
            HookInput::MalformedMissingField => {}
            other => panic!("expected MalformedMissingField, got: {other:?}"),
        }
    }

    // --- GR-004: is_protected_file_path ---

    #[test]
    fn protected_file_path_matches_config_toml() {
        let result = is_protected_file_path("/home/user/.config/omamori/config.toml");
        assert!(result.is_some(), "config.toml should be protected");
    }

    #[test]
    fn protected_file_path_rejects_unrelated() {
        let result = is_protected_file_path("/tmp/myfile.txt");
        assert!(result.is_none(), "/tmp/myfile.txt should not be protected");
    }

    #[test]
    fn protected_file_path_all_patterns_match() {
        let test_paths = [
            "/home/user/.config/omamori/config.toml",
            "/home/user/.local/share/omamori/.integrity.json",
            "/home/user/.local/share/omamori/audit-secret",
            "/home/user/.local/share/omamori/audit.jsonl",
            "/home/user/.local/share/omamori",
            "/home/user/.local/share/omamori/hooks/claude-pretooluse.sh",
            "/home/user/.local/share/omamori/hooks/codex-pretooluse.sh",
            "/home/user/.codex/hooks.json",
            "/home/user/.codex/config.toml",
            "/home/user/.claude/settings.json",
        ];
        for path in &test_paths {
            assert!(
                is_protected_file_path(path).is_some(),
                "PROTECTED_FILE_PATTERNS gap: {path} was not matched"
            );
        }
    }

    // --- GR-007: check_command_for_hook meta-pattern ---

    #[test]
    #[serial_test::serial]
    fn check_command_for_hook_blocks_meta_pattern() {
        let (old_xdg, old_home, dir) = isolate_config();

        match check_command_for_hook("unset CLAUDECODE") {
            HookCheckResult::BlockMeta(_) => {}
            HookCheckResult::BlockRule { .. } | HookCheckResult::BlockStructural(_) => {}
            HookCheckResult::Allow => {
                restore_config(old_xdg, old_home, dir);
                panic!("SECURITY: 'unset CLAUDECODE' was ALLOWED — meta-pattern is broken");
            }
        }
        restore_config(old_xdg, old_home, dir);
    }

    #[test]
    #[serial_test::serial]
    fn check_command_for_hook_allows_echo() {
        let (old_xdg, old_home, dir) = isolate_config();

        match check_command_for_hook("echo hello world") {
            HookCheckResult::Allow => {}
            _ => {
                restore_config(old_xdg, old_home, dir);
                panic!("'echo hello world' should be allowed");
            }
        }
        restore_config(old_xdg, old_home, dir);
    }
}
