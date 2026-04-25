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
///
/// Crate-internal: consumed by `run_hook_check_command` /
/// `run_cursor_hook` for stderr framing, and by the in-tree property test
/// (`crate::property_tests`, `#[cfg(test)]`) for cross-layer verdict
/// comparison. Not re-exported — downstream callers must invoke the AI-
/// tool hook entry point (`omamori hook-check`) instead, so phase
/// short-circuits and rule loading both run.
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

/// Check if token at `idx` is in command position (start of a segment).
/// Command position = index 0, immediately after an operator token,
/// or after a run of KEY=VAL assignment prefixes (e.g., FOO=1 unset VAR).
fn is_command_position(tokens: &[String], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let mut j = idx;
    while j > 0 {
        let prev = &tokens[j - 1];
        if matches!(prev.as_str(), "&&" | "||" | ";" | "|" | "&") {
            return true;
        }
        if unwrap::is_env_assignment(prev) {
            j -= 1;
            continue;
        }
        return false;
    }
    true // walked all the way to start
}

/// Detect env var tampering at the token level.
/// Only flags commands in command position to avoid false positives
/// on quoted strings and arguments (e.g., printf 'unset CLAUDECODE').
fn detect_env_var_tampering(tokens: &[String]) -> Option<&'static str> {
    let vars = installer::PROTECTED_ENV_VARS;

    // "unset VARNAME"
    for (i, w) in tokens.windows(2).enumerate() {
        if w[0] == "unset" && is_command_position(tokens, i) && vars.contains(&w[1].as_str()) {
            return Some("blocked attempt to unset a detector env var");
        }
    }

    for (i, w) in tokens.windows(2).enumerate() {
        if !is_command_position(tokens, i) {
            continue;
        }
        // "env -uVARNAME" (combined form)
        if w[0] == "env" && w[1].starts_with("-u") {
            let rest = &w[1][2..];
            if !rest.is_empty() && vars.contains(&rest) {
                return Some("blocked attempt to unset a detector env var");
            }
        }
        // "export -nVARNAME" (combined form)
        if w[0] == "export" && w[1].starts_with("-n") {
            let rest = &w[1][2..];
            if !rest.is_empty() && vars.contains(&rest) {
                return Some("blocked attempt to unexport detector env var");
            }
        }
    }

    // "env -u VARNAME" / "export -n VARNAME" (separated form)
    for (i, w) in tokens.windows(3).enumerate() {
        if !is_command_position(tokens, i) {
            continue;
        }
        if w[0] == "env" && w[1] == "-u" && vars.contains(&w[2].as_str()) {
            return Some("blocked attempt to unset a detector env var");
        }
        if w[0] == "export" && w[1] == "-n" && vars.contains(&w[2].as_str()) {
            return Some("blocked attempt to unexport detector env var");
        }
    }

    // "VARNAME=" or "VARNAME=value" — only in command position
    for (i, token) in tokens.iter().enumerate() {
        if is_command_position(tokens, i) {
            for var in vars {
                if token
                    .strip_prefix(var)
                    .is_some_and(|rest| rest.starts_with('='))
                {
                    return Some("blocked attempt to unset a detector env var");
                }
            }
        }
    }

    None
}

/// Phase 1A (meta-patterns), Phase 1B (env tampering), and the structural
/// branch of Phase 2 (parse-error / pipe-to-shell). Returns
/// `Err(verdict)` for any early-return case, or `Ok(invocations)` for the
/// caller to apply rule matching against a chosen rule slice.
///
/// Both `check_command_for_hook` and `check_command_for_hook_with_rules`
/// share this prefix so the production wrapper does not pay
/// `load_config(None)` when Phase 1A/1B/structural short-circuits the
/// verdict.
fn check_pre_phase_2(command: &str) -> Result<Vec<CommandInvocation>, HookCheckResult> {
    // Phase 1A: String-level meta-patterns (path/config/uninstall)
    for (pattern, reason) in installer::blocked_string_patterns() {
        if command.contains(pattern) {
            return Err(HookCheckResult::BlockMeta(reason));
        }
    }

    // Phase 1B: Token-level env var tampering detection.
    // normalize_compound_operators splits ;, &&, ||, |, &, \n into separate tokens,
    // then shell_words::split normalizes whitespace + parses quotes.
    // This ensures "echo ok;unset CLAUDECODE" is correctly tokenized as
    // ["echo", "ok", ";", "unset", "CLAUDECODE"] — without normalize,
    // shell_words would produce ["echo", "ok;unset", "CLAUDECODE"].
    // is_command_position() ensures only segment-initial verbs are flagged.
    //
    // DEFENSE BOUNDARY on shell_words::split failure:
    //   Phase 1A has already run. Phase 2 blocks malformed commands via
    //   ParseResult::Block(ParseError) — fail-close (unwrap.rs:77).
    let normalized = unwrap::normalize_compound_operators(command);
    if let Ok(tokens) = shell_words::split(&normalized)
        && let Some(reason) = detect_env_var_tampering(&tokens)
    {
        return Err(HookCheckResult::BlockMeta(reason));
    }

    // Phase 2 parse: structural block (parse error / pipe-to-shell etc.)
    match unwrap::parse_command_string(command) {
        unwrap::ParseResult::Block(reason) => Err(HookCheckResult::BlockStructural(format!(
            "omamori hook: blocked — {}",
            reason.message()
        ))),
        unwrap::ParseResult::Commands(invocations) => Ok(invocations),
    }
}

/// Apply Phase 2 rule matching against an explicit rule slice. Returns the
/// first matching rule's `BlockRule` verdict, or `Allow`.
fn match_invocations_against_rules(
    command: &str,
    invocations: &[CommandInvocation],
    rules: &[crate::rules::RuleConfig],
) -> HookCheckResult {
    for inv in invocations {
        if let Some(rule) = match_rule(rules, inv) {
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

/// Three-phase hook check, evaluating against rules loaded from on-disk
/// config with a `Config::default()` fail-safe fallback.
///
/// Phase 1A: String-level meta-patterns (path/config/uninstall)
/// Phase 1B: Token-level env var tampering detection (whitespace-resilient)
/// Phase 2: Token-level unwrap stack → rule matching
///
/// `load_config(None)` runs lazily — only when Phase 2 actually reaches
/// the rule-matching arm. Phase 1A/1B/structural short-circuits pay zero
/// disk I/O.
///
/// SECURITY (T8): The `Config::default()` fallback on `load_config` failure
/// is intentional fail-safe behavior, not fail-open.
pub(crate) fn check_command_for_hook(command: &str) -> HookCheckResult {
    let invocations = match check_pre_phase_2(command) {
        Ok(invs) => invs,
        Err(verdict) => return verdict,
    };
    // Phase 2 reached — load on-disk config now (fail-safe fallback per T8).
    let load_result = load_config(None).unwrap_or_else(|_| ConfigLoadResult {
        config: config::Config::default(),
        warnings: vec![],
    });
    match_invocations_against_rules(command, &invocations, &load_result.config.rules)
}

/// Three-phase hook check, evaluating Phase 2 rule matching against an
/// explicitly provided rule slice instead of loading config from disk.
///
/// Test-only (`#[cfg(test)]`). Production code paths call
/// [`check_command_for_hook`] so that the user's on-disk
/// `~/.config/omamori/config.toml` overrides take effect. Compiling this
/// helper out of the production binary makes the trust-boundary
/// guarantee structural: a downstream integration cannot call a
/// security-looking API with `Config::default().rules`, stale rules, or
/// an empty slice to silently skip user policy overrides, because the
/// symbol does not exist in the released binary.
///
/// The cross-layer property test (`crate::property_tests`) calls this
/// helper with `Config::default().rules` to keep both layers' verdicts
/// evaluated against the same canonical rule set, independent of any
/// ambient developer or CI config file.
#[cfg(test)]
pub(crate) fn check_command_for_hook_with_rules(
    command: &str,
    rules: &[crate::rules::RuleConfig],
) -> HookCheckResult {
    let invocations = match check_pre_phase_2(command) {
        Ok(invs) => invs,
        Err(verdict) => return verdict,
    };
    match_invocations_against_rules(command, &invocations, rules)
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
        HookInput::UnknownTool {
            tool_name,
            tool_input,
        } => run_hook_check_unknown_tool(&tool_name, &tool_input, &provider, verbose),
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
            eprintln!("  hint: run `omamori explain -- {}` for details", command);
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
            eprintln!("  hint: run `omamori explain -- {command}` for details");
            Ok(2)
        }
        HookCheckResult::BlockStructural(message) => {
            eprintln!("{message}");
            if verbose {
                eprintln!("  provider: {provider}");
                eprintln!("  layer: unwrap-stack (structural)");
            }
            eprintln!("  hint: run `omamori explain -- {command}` for details");
            Ok(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Unknown-tool routing (#182, v0.9.6 PR6)
// ---------------------------------------------------------------------------
//
// `HookInput::UnknownTool` was previously a forward-compat fail-open: any
// `tool_name` Claude Code added or renamed silently bypassed Layer 2.
// We now (1) re-classify the carried `tool_input` against `InputShape`
// in case an alias field (`cmd`/`path`) slipped past extract, (2) for
// truly unknown shapes, log to stderr and append a marked event to the
// audit chain so users can review what drifted past omamori. The final
// disposition stays *allow* — we preserve user workflow rather than
// start blocking unreviewed tools retroactively, but the silence is
// gone.
//
// **Scope and known noise (Known Limitation)**: legitimate Claude Code
// tools whose `tool_input` shape is not in our recognised set (e.g.
// NotebookEdit's `notebook_path`, Task's `subagent_type`, TodoWrite's
// `todos`, WebSearch's `query`) currently land in the unknown branch
// and emit fail-open events on every invocation. Counts surfaced via
// `omamori audit unknown` and `omamori doctor`'s 30-day line are an
// **upper bound on adversarial activity**, not a lower bound — they
// include this legitimate noise. An opt-in strict-mode that lets users
// choose between fail-open (today) and fail-closed (block) for
// unrecognised shapes is planned for a future omamori release. See
// `SECURITY.md` → "Scope: unknown / new tools" for the trade-off
// rationale.

fn run_hook_check_unknown_tool(
    tool_name: &str,
    tool_input: &serde_json::Value,
    provider: &str,
    verbose: bool,
) -> Result<i32, AppError> {
    match classify_input_shape(tool_input) {
        // Shell-shape and file-op-shape *should* have been resolved at
        // extract time. Re-routing here is the safety net for any future
        // refactor where extract_hook_input grows a fall-through path —
        // we re-enter the same checks rather than silently allowing.
        InputShape::ShellCommand(cmd) => {
            if cmd.is_empty() {
                print_hook_check_allow_response("omamori: empty command");
                return Ok(0);
            }
            run_hook_check_command(cmd, provider, verbose)
        }
        InputShape::FileOp(path) => {
            if let Some(reason) = is_protected_file_path(path) {
                eprintln!("omamori hook: blocked {tool_name} to protected file — {reason}");
                eprintln!("  AI agents cannot modify omamori configuration or security files.");
                eprintln!(
                    "  To edit config: use `omamori config` CLI or edit the file directly in your terminal."
                );
                if verbose {
                    eprintln!("  provider: {provider}");
                    eprintln!("  tool: {tool_name}");
                    eprintln!("  path: {path}");
                }
                Ok(2)
            } else {
                print_hook_check_allow_response(&format!(
                    "omamori: '{tool_name}' file op to non-protected path — allowed"
                ));
                Ok(0)
            }
        }
        InputShape::ReadOnlyUrl => {
            // url-shape inputs are read-only fetch tools (WebFetch,
            // WebSearch, …). Allow without hint — these are not the
            // class of fail-open we set out to make observable.
            print_hook_check_allow_response(&format!(
                "omamori: '{tool_name}' read-only url tool — allowed"
            ));
            Ok(0)
        }
        InputShape::Unknown => {
            // Observable fail-open: stderr hint + audit event + allow.
            // The allow keeps user workflow alive; the hint + audit
            // make the silence a thing of the past. One stderr line
            // per invocation — `omamori hook-check` is a short-lived
            // process (1 invocation = 1 dispatch), so a process-local
            // dedup guard would be dead code. If user noise becomes a
            // problem, session-level dedup is tracked for a future
            // release alongside opt-in strict-mode.
            eprintln!(
                "omamori: unknown tool '{tool_name}' routed as fail-open. \
                 Review via 'omamori audit unknown'"
            );
            audit_log_unknown_tool_fail_open(tool_name, tool_input, provider);
            print_hook_check_allow_response(&format!(
                "omamori: unknown tool '{tool_name}' routed as fail-open — allowed"
            ));
            Ok(0)
        }
    }
}

/// Append an `unknown_tool_fail_open` event to the audit chain.
///
/// Best-effort with respect to the hook *decision* (we already decided
/// to allow; an audit failure must never flip that), but **not silent**
/// with respect to observability. PR6 promises users that they can
/// review fail-opens via `omamori audit unknown`; if the append fails
/// the user must learn that the promise is unreliable for this event,
/// otherwise the stderr hint and the doctor count line both become
/// false advertising in the exact failure mode where they matter most
/// (broken audit log / missing HMAC secret / disk full / permissions).
/// Codex round 3 P2.
fn audit_log_unknown_tool_fail_open(
    tool_name: &str,
    tool_input: &serde_json::Value,
    provider: &str,
) {
    let load_result = match load_config(None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "omamori warning: could not record unknown_tool_fail_open event for '{tool_name}' \
                 — config load failed: {e}. The 'omamori audit unknown' review surface is \
                 incomplete for this event."
            );
            return;
        }
    };
    let logger = match crate::audit::AuditLogger::from_config(&load_result.config.audit) {
        Some(l) => l,
        None => {
            // Audit disabled in config — that's a user choice, not an
            // error, so stay quiet (the user opted out of the review
            // surface entirely).
            return;
        }
    };

    // Synthetic invocation: the "command" field of the audit event will
    // hold the tool_name; targets are the recognised top-level keys of
    // tool_input so analysts can spot which shape we saw.
    let invocation = CommandInvocation::new(tool_name.to_string(), Vec::new());
    let detectors = vec![provider.to_string()];
    let outcome = crate::actions::ActionOutcome::PassedThrough { exit_code: 0 };

    let mut event = logger.create_event(&invocation, None, &detectors, &outcome);
    // Override action label so `omamori audit unknown` (and SIEM filters)
    // can pick these out without parsing detection_layer. New string
    // value — old parsers treat it as opaque, no schema break, no
    // CHAIN_VERSION bump needed (Codex ② C-1 裁定維持).
    event.action = "unknown_tool_fail_open".to_string();
    event.result = "allow".to_string();
    // Override detection_layer: `create_event` defaults to "layer1"
    // because every existing caller is a Layer 1 / Layer 2 verdict.
    // Unknown-tool fail-open is neither — it's the shape-routing
    // dispatch deciding "no recognised shape, allow + record". A SIEM
    // counting "Layer 1 detector hits" would otherwise inflate with
    // these events. Like `action`, `detection_layer` is a string field
    // that older parsers treat as opaque — no schema break.
    event.detection_layer = Some("shape-routing".to_string());
    // target_count = number of recognised top-level keys in tool_input
    // (helps analysts see "shape we saw was empty" vs. "had keys we
    // didn't classify"). Note: this borrows the existing `target_count`
    // column with a different semantic for `unknown_tool_fail_open`
    // events specifically; downstream analytics that aggregate
    // `target_count` across action types will be skewed by these
    // events. A dedicated column is tracked for a future omamori
    // release.
    event.target_count = tool_input.as_object().map(|o| o.len()).unwrap_or(0);

    if let Err(e) = logger.append(event) {
        eprintln!(
            "omamori warning: failed to record unknown_tool_fail_open event for '{tool_name}': {e}. \
             The 'omamori audit unknown' review surface is incomplete for this event."
        );
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
    FileOp {
        tool: String,
        path: String,
    },
    /// A tool whose `tool_name` we don't recognise *and* whose `tool_input`
    /// shape did not match any known classifier (`command`/`cmd` →
    /// shell, `file_path`/`path` → file op, `url` → read-only).
    /// Carries the full `tool_input` so the routing layer can re-classify
    /// and so the audit/observability layer can record the shape we saw.
    UnknownTool {
        tool_name: String,
        tool_input: serde_json::Value,
    },
    MalformedJson,
    MalformedMissingField,
}

/// Classified shape of `tool_input` for routing.
///
/// **Forward-compat fail-open fix (#182, v0.9.6 PR6).** The previous
/// implementation dispatched `HookInput::UnknownTool` to an unconditional
/// allow; any provider-side rename of a write/exec tool would silently
/// bypass Layer 2. We now route by `tool_input` *structure* — independent
/// of `tool_name` — so a tool calling itself `FuturePlanWriter` but
/// carrying a `command` field still reaches the shell pipeline.
#[derive(Debug, PartialEq, Eq)]
enum InputShape<'a> {
    /// `tool_input.command` or `tool_input.cmd` is a string → route as Bash.
    ShellCommand(&'a str),
    /// `tool_input.file_path` or `tool_input.path` is a string → route as FileOp.
    FileOp(&'a str),
    /// `tool_input.url` is a string and no shell/file fields are present
    /// → read-only fetch, allow.
    ReadOnlyUrl,
    /// No recognised shape — observable fail-open (hint + audit + allow).
    Unknown,
}

/// Inspect `tool_input` and return its routed shape.
///
/// Order matters: shell command takes priority over file path takes
/// priority over url, so a malicious tool sending both `command` and
/// `url` cannot dodge into the read-only branch.
fn classify_input_shape(tool_input: &serde_json::Value) -> InputShape<'_> {
    if let Some(s) = tool_input.get("command").and_then(|v| v.as_str()) {
        return InputShape::ShellCommand(s);
    }
    if let Some(s) = tool_input.get("cmd").and_then(|v| v.as_str()) {
        return InputShape::ShellCommand(s);
    }
    if let Some(s) = tool_input.get("file_path").and_then(|v| v.as_str()) {
        return InputShape::FileOp(s);
    }
    if let Some(s) = tool_input.get("path").and_then(|v| v.as_str()) {
        return InputShape::FileOp(s);
    }
    if tool_input.get("url").and_then(|v| v.as_str()).is_some() {
        return InputShape::ReadOnlyUrl;
    }
    InputShape::Unknown
}

/// Whether a recognised routing field exists but with the wrong JSON type.
/// Such inputs must fail-close (MalformedMissingField), not silently fall
/// through to UnknownTool — otherwise an attacker can present a
/// `command: 42` payload and bypass shell checks.
fn has_routing_field_with_wrong_type(tool_input: &serde_json::Value) -> bool {
    for field in ["command", "cmd", "file_path", "path", "url"] {
        if let Some(val) = tool_input.get(field)
            && val.as_str().is_none()
        {
            return true;
        }
    }
    false
}

/// Parse PreToolUse hook stdin into a typed `HookInput`.
///
/// **Priority chain** — pre-PR6 ordering preserved + extended for v0.9.6:
///
/// 1. `tool_input.command` / `tool_input.cmd` (most-specific dangerous shape)
/// 2. top-level `command` (legacy Cursor-style fallback; *also* the
///    safety net for mixed Cursor-and-Claude-Code payloads where a
///    dangerous top-level command would otherwise be ignored if
///    `tool_input` happened to carry only a non-shell shape)
/// 3. `tool_input.file_path` / `tool_input.path` (FileOp routing)
/// 4. `tool_input.url` (ReadOnlyUrl)
/// 5. `tool_input` present but unrecognised shape → `UnknownTool`
///    (observable fail-open downstream)
/// 6. Bare `tool_name` with neither shape → `UnknownTool` with null input
///
/// Two regression-driven priority pins worth calling out:
///
/// - **PR6 R1 (Codex round 1)**: tool_input shell-command must beat
///   top-level command. Mixed payload `{"command":"echo ok",
///   "tool_input":{"command":"rm -rf /"}}` MUST route through the
///   inner command. An earlier draft inverted this and reopened the
///   very forward-compat fail-open this PR set out to close.
///
/// - **PR6 R2 (Codex round 2)**: top-level command must beat
///   tool_input non-shell shapes. Mixed payload
///   `{"command":"/bin/rm -rf /tmp/x","tool_name":"X","tool_input":
///   {"query":"x"}}` MUST route the top-level shell command, not
///   silently allow as UnknownTool. Pre-PR6 code did this; my round-1
///   fix collapsed steps 2–5 into one tool_input dispatch and lost
///   the middle priority. This priority chain restores all 6 steps.
fn extract_hook_input(input: &str) -> HookInput {
    let v = match serde_json::from_str::<serde_json::Value>(input) {
        Ok(v) => v,
        Err(_) => return HookInput::MalformedJson,
    };

    let tool_name = v.get("tool_name").and_then(|t| t.as_str());
    let ti = v.get("tool_input");

    // Pre-classify tool_input once so each priority gate can consult
    // the result without re-parsing. Type validation (wrong-type
    // routing fields → MalformedMissingField) happens here so that a
    // bad payload short-circuits before any priority gate.
    let ti_object_check = ti.map(|t| {
        let object_ok = matches!(t.as_object(), Some(obj) if !obj.is_empty());
        let wrong_type = has_routing_field_with_wrong_type(t);
        (t, object_ok, wrong_type)
    });

    if let Some((_, false, _)) = ti_object_check {
        return HookInput::MalformedMissingField;
    }
    if let Some((_, _, true)) = ti_object_check {
        return HookInput::MalformedMissingField;
    }

    let ti_shape = ti.map(classify_input_shape);

    // Priority 1: tool_input shell-command shape (highest danger surface).
    if let Some(InputShape::ShellCommand(cmd)) = ti_shape {
        return HookInput::Command(cmd.to_string());
    }

    // Priority 2: top-level `command` — legacy Cursor-style fallback,
    // also the safety net so a dangerous top-level command paired with
    // a benign `tool_input` (e.g. `{"query":"…"}`) cannot dodge into
    // UnknownTool fail-open.
    if let Some(cmd_val) = v.get("command") {
        return match cmd_val.as_str() {
            Some(cmd) => HookInput::Command(cmd.to_string()),
            None => HookInput::MalformedMissingField,
        };
    }

    // Priority 3-5: remaining tool_input shapes (FileOp / ReadOnlyUrl /
    // Unknown). Reached only when no shell-command surface fired.
    if let Some(shape) = ti_shape {
        return match shape {
            InputShape::ShellCommand(_) => unreachable!("handled at Priority 1"),
            InputShape::FileOp(path) => HookInput::FileOp {
                tool: tool_name.unwrap_or("unknown").to_string(),
                path: path.to_string(),
            },
            InputShape::ReadOnlyUrl | InputShape::Unknown => match tool_name {
                Some(name) => HookInput::UnknownTool {
                    tool_name: name.to_string(),
                    tool_input: ti.expect("ti_shape implies ti was Some").clone(),
                },
                None => HookInput::MalformedMissingField,
            },
        };
    }

    // Priority 6: bare tool_name with neither tool_input nor command.
    if let Some(name) = tool_name {
        return HookInput::UnknownTool {
            tool_name: name.to_string(),
            tool_input: serde_json::Value::Null,
        };
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
            HookInput::UnknownTool {
                tool_name,
                tool_input,
            } => {
                assert_eq!(tool_name, "FutureTool");
                assert_eq!(
                    tool_input.get("query").and_then(|v| v.as_str()),
                    Some("something"),
                    "tool_input must be carried through verbatim for routing"
                );
            }
            other => panic!("expected UnknownTool, got: {other:?}"),
        }
    }

    // --- PR6 (#182): structure-based routing for unknown tools ---

    #[test]
    fn extract_hook_input_unknown_tool_with_command_routes_to_command() {
        let input = r#"{"tool_name":"FuturePlanWriter","tool_input":{"command":"ls -la"}}"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "ls -la"),
            other => panic!(
                "expected Command (structure routing), got: {other:?} — \
                 PR6 fail-open fix means tool_input.command always routes \
                 to shell pipeline regardless of tool_name"
            ),
        }
    }

    #[test]
    fn extract_hook_input_unknown_tool_with_cmd_alias_routes_to_command() {
        let input = r#"{"tool_name":"FutureExec","tool_input":{"cmd":"echo hi"}}"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "echo hi"),
            other => panic!("expected Command via cmd alias, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_unknown_tool_with_path_alias_routes_to_file_op() {
        let input = r#"{"tool_name":"FutureEditor","tool_input":{"path":"/tmp/x"}}"#;
        match extract_hook_input(input) {
            HookInput::FileOp { tool, path } => {
                assert_eq!(tool, "FutureEditor");
                assert_eq!(path, "/tmp/x");
            }
            other => panic!("expected FileOp via path alias, got: {other:?}"),
        }
    }

    #[test]
    fn extract_hook_input_url_routes_to_unknown_tool_for_read_only() {
        let input = r#"{"tool_name":"FutureFetch","tool_input":{"url":"https://example.com"}}"#;
        match extract_hook_input(input) {
            HookInput::UnknownTool {
                tool_name,
                tool_input,
            } => {
                assert_eq!(tool_name, "FutureFetch");
                assert_eq!(classify_input_shape(&tool_input), InputShape::ReadOnlyUrl);
            }
            other => panic!(
                "expected UnknownTool carrying url-shape (router decides allow), got: {other:?}"
            ),
        }
    }

    #[test]
    fn extract_hook_input_wrong_type_command_fails_closed() {
        // Attacker payload: command is an integer to dodge string-based
        // routing. Must NOT fall through to UnknownTool fail-open.
        let input = r#"{"tool_name":"Bash","tool_input":{"command":42}}"#;
        match extract_hook_input(input) {
            HookInput::MalformedMissingField => {}
            other => panic!(
                "expected MalformedMissingField (fail-close on type mismatch), got: {other:?}"
            ),
        }
    }

    #[test]
    fn classify_input_shape_command_priority_over_url() {
        // Defence: a malicious tool sending both `command` and `url`
        // must be routed as ShellCommand, not ReadOnlyUrl.
        let v = serde_json::json!({
            "command": "rm -rf /",
            "url": "https://example.com",
        });
        assert_eq!(
            classify_input_shape(&v),
            InputShape::ShellCommand("rm -rf /")
        );
    }

    /// PR6 Codex round 1 regression guard: when a payload carries BOTH
    /// a top-level `command` (Cursor-style legacy) and a `tool_input`
    /// object, the dangerous `tool_input.command` MUST win — top-level
    /// `command` is only the fallback when `tool_input` is absent. An
    /// earlier draft inverted this and let `{"command":"safe",
    /// "tool_input":{"command":"rm -rf /tmp/x"}}` route through the
    /// safe top-level, reopening the very forward-compat fail-open
    /// this PR set out to close.
    #[test]
    fn extract_hook_input_mixed_payload_prefers_tool_input() {
        let input = r#"{
            "command": "echo ok",
            "tool_name": "Bash",
            "tool_input": { "command": "rm -rf /tmp/x" }
        }"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(
                cmd, "rm -rf /tmp/x",
                "tool_input.command must take priority over top-level command"
            ),
            other => panic!("expected Command from tool_input, got: {other:?}"),
        }
    }

    /// Same priority pin, but with an unknown tool_name and an alias
    /// `cmd` field. Mixed payload via the alias path must still prefer
    /// `tool_input`.
    #[test]
    fn extract_hook_input_mixed_payload_prefers_tool_input_alias() {
        let input = r#"{
            "command": "echo ok",
            "tool_name": "FutureExec",
            "tool_input": { "cmd": "/bin/rm -rf /tmp/x" }
        }"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "/bin/rm -rf /tmp/x"),
            other => panic!("expected Command from tool_input.cmd, got: {other:?}"),
        }
    }

    /// Counterpart pin: top-level `command` is consulted when
    /// `tool_input` is absent OR carries no shell-command shape.
    /// Without this pin a future refactor could silently drop the
    /// legacy Cursor-style fallback.
    #[test]
    fn extract_hook_input_top_level_command_used_when_tool_input_absent() {
        let input = r#"{"command":"ls -la"}"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "ls -la"),
            other => panic!("expected legacy top-level Command, got: {other:?}"),
        }
    }

    /// PR6 Codex round 2 regression guard: a mixed payload where the
    /// dangerous shell command sits at top-level and `tool_input`
    /// carries a benign non-shell shape (`query`, `text`, etc.) MUST
    /// route the top-level command. Round 1 fix collapsed all
    /// `tool_input`-present cases into the tool_input dispatch and
    /// silently turned this scenario into UnknownTool fail-open.
    #[test]
    fn extract_hook_input_top_level_command_wins_over_unknown_shape() {
        let input = r#"{
            "command": "/bin/rm -rf /tmp/x",
            "tool_name": "FutureSearch",
            "tool_input": { "query": "x" }
        }"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(
                cmd, "/bin/rm -rf /tmp/x",
                "top-level command must win over tool_input non-shell shape"
            ),
            other => panic!("expected top-level Command (R2 regression guard), got: {other:?}"),
        }
    }

    /// Variant: top-level command + `tool_input.url` (read-only fetch
    /// shape). The dangerous top-level command must still win — the
    /// read-only routing must not provide cover for shell commands.
    #[test]
    fn extract_hook_input_top_level_command_wins_over_url_shape() {
        let input = r#"{
            "command": "/bin/rm -rf /tmp/x",
            "tool_name": "FutureFetch",
            "tool_input": { "url": "https://example.com" }
        }"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "/bin/rm -rf /tmp/x"),
            other => panic!("expected top-level Command, got: {other:?}"),
        }
    }

    /// Variant: top-level command + `tool_input.file_path`. File-op
    /// routing must NOT shadow the dangerous shell command.
    #[test]
    fn extract_hook_input_top_level_command_wins_over_file_op_shape() {
        let input = r#"{
            "command": "/bin/rm -rf /tmp/x",
            "tool_name": "FutureEditor",
            "tool_input": { "file_path": "/tmp/x" }
        }"#;
        match extract_hook_input(input) {
            HookInput::Command(cmd) => assert_eq!(cmd, "/bin/rm -rf /tmp/x"),
            other => panic!("expected top-level Command, got: {other:?}"),
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

    // =========================================================================
    // Phase 1B: Token-level env var tampering tests (#145)
    // =========================================================================

    // --- Helper for concise block/allow assertions ---

    /// Assert that a command is blocked specifically by Phase 1B (BlockMeta).
    /// This ensures the test is exercising the token-level env var detection,
    /// not accidentally passing via Phase 2 rule matching.
    fn assert_blocks_meta(command: &str) {
        let (old_xdg, old_home, dir) = isolate_config();
        match check_command_for_hook(command) {
            HookCheckResult::BlockMeta(_) => {}
            HookCheckResult::Allow => {
                restore_config(old_xdg, old_home, dir);
                panic!("SECURITY: {command:?} was ALLOWED — should be BlockMeta");
            }
            other => {
                let desc = match other {
                    HookCheckResult::BlockRule { rule_name, .. } => {
                        format!("BlockRule({rule_name})")
                    }
                    HookCheckResult::BlockStructural(r) => format!("BlockStructural({r})"),
                    _ => unreachable!(),
                };
                restore_config(old_xdg, old_home, dir);
                panic!("{command:?} blocked by {desc}, expected BlockMeta (Phase 1B)");
            }
        }
        restore_config(old_xdg, old_home, dir);
    }

    fn assert_allows(command: &str) {
        let (old_xdg, old_home, dir) = isolate_config();
        match check_command_for_hook(command) {
            HookCheckResult::Allow => {}
            other => {
                let desc = match other {
                    HookCheckResult::BlockMeta(r) => format!("BlockMeta({r})"),
                    HookCheckResult::BlockRule { rule_name, .. } => {
                        format!("BlockRule({rule_name})")
                    }
                    HookCheckResult::BlockStructural(r) => format!("BlockStructural({r})"),
                    HookCheckResult::Allow => unreachable!(),
                };
                restore_config(old_xdg, old_home, dir);
                panic!("expected Allow for {command:?}, got: {desc}");
            }
        }
        restore_config(old_xdg, old_home, dir);
    }

    // --- BLOCK: whitespace bypass (#145) — all use assert_blocks_meta ---

    #[test]
    #[serial_test::serial]
    fn phase1b_unset_double_space() {
        assert_blocks_meta("unset  CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_unset_tab() {
        assert_blocks_meta("unset\tCLAUDECODE");
    }

    // --- BLOCK: VARNAME= assignment (Codex 6-B: missing test) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_var_assignment_empty() {
        assert_blocks_meta("CLAUDECODE=");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_var_assignment_value() {
        assert_blocks_meta("CLAUDECODE=fake");
    }

    // --- BLOCK: separator-adjacent (Codex 6-A regression fix) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_semicolon_adjacent_unset() {
        assert_blocks_meta("echo ok;unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_and_adjacent_export() {
        assert_blocks_meta("cmd&&export -nCLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_newline_adjacent_env_u() {
        assert_blocks_meta("echo ok\nenv -u CLAUDECODE bash");
    }

    // --- BLOCK: operator-after command position (Codex 6-B: missing boundary) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_after_semicolon() {
        assert_blocks_meta("echo ok ; unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_after_pipe() {
        assert_blocks_meta("cat /dev/null | unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_env_u_extra_spaces() {
        assert_blocks_meta("env  -u  CLAUDECODE bash");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_env_u_tabs() {
        assert_blocks_meta("env\t-u\tCLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_env_u_combined() {
        assert_blocks_meta("env -uCLAUDECODE bash");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_export_n_extra_space() {
        assert_blocks_meta("export  -n  CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_export_n_combined() {
        assert_blocks_meta("export -nCLAUDECODE");
    }

    // --- BLOCK: assignment prefix (#145) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_assignment_prefix_unset() {
        assert_blocks_meta("FOO=1 unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_assignment_prefix_env_u() {
        assert_blocks_meta("BAR=x env -uCLAUDECODE bash");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_multi_assignment_export() {
        assert_blocks_meta("X=1 Y=2 export -n CLAUDECODE");
    }

    // --- ALLOW: command position false positive prevention (#145) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_printf_unset_args() {
        assert_allows("printf '%s %s' unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_echo_unset() {
        assert_allows("echo unset CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_echo_env_u() {
        assert_allows("echo env -u CLAUDECODE");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_printf_var_assignment() {
        assert_allows("printf %s CLAUDECODE=test");
    }

    // --- ALLOW: quoted string false positive prevention (#145) ---

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_printf_unset_quoted() {
        assert_allows("printf 'unset  CLAUDECODE'");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_echo_env_u_quoted() {
        assert_allows("echo \"env  -u  CLAUDECODE\"");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_echo_newline_in_quotes() {
        assert_allows("echo 'line1\nline2'");
    }

    #[test]
    #[serial_test::serial]
    fn phase1b_benign_env_assignment_in_string() {
        assert_allows("echo 'CLAUDECODE=test'");
    }
}
