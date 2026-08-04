//! `omamori test` subcommand and policy test harness.

use std::ffi::OsString;
use std::path::Path;

use crate::AppError;
use crate::config::{Config, ConfigLoadResult, load_config};
use crate::context::{self, ContextConfig};
use crate::detector::evaluate_detectors;
use crate::engine::shim::emit_config_warnings;
use crate::rules::{self, ActionKind, CommandInvocation, RuleConfig, match_rule};
use crate::util::parse_config_flag;

pub(crate) fn run_policy_test_command(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[2..])?;
    let load_result = load_config(config_path.as_deref())?;
    emit_config_warnings(&load_result);
    // Captured once per invocation (#175) for the Context section below.
    let base = context::process_base_or_root();

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

    // Context section (#458). The rows carry their own verdicts; this block
    // only prints them, so there is one place that decides and one that
    // displays.
    let context_result: Vec<ContextRow> = match config.context {
        Some(ref ctx_config) => context_rows(config, ctx_config, &base),
        None => Vec::new(),
    };
    let context_failures = context_result
        .iter()
        .filter(|r| r.verdict == ContextVerdict::Fail)
        .count();
    let context_checked = context_result
        .iter()
        .filter(|r| !matches!(r.verdict, ContextVerdict::NotChecked(_)))
        .count();

    if !context_result.is_empty() {
        println!("\nContext:");
        for row in &context_result {
            let status = match row.verdict {
                ContextVerdict::Pass => "PASS",
                ContextVerdict::Fail => "FAIL",
                // Not `SKIP`: the row did run and observed something. What it
                // did not do is form an expectation to compare against.
                ContextVerdict::NotChecked(_) => "----",
            };
            let why = match row.verdict {
                ContextVerdict::NotChecked(why) => format!(" [not checked: {why}]"),
                _ => String::new(),
            };
            println!("  {status}  {:<28} {}{why}", row.name, row.detail);
        }
    }

    // Detection section
    let results = run_policy_tests(&load_result);
    let failures = results.iter().filter(|r| !r.passed).count();

    println!("\nDetection:");
    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("  {status}  {:<28} {}", result.name, result.details);
    }

    // Summary
    let context_summary = if context_result.is_empty() {
        String::new()
    } else {
        let not_checked = context_result.len() - context_checked;
        let mut s = format!(
            ", {context_checked} context check{}",
            if context_checked == 1 { "" } else { "s" }
        );
        if not_checked > 0 {
            s.push_str(&format!(" ({not_checked} not checked)"));
        }
        // Carried here rather than folded into the detection verdict below, so
        // neither phrase claims something about the other's tests.
        if context_failures > 0 {
            s.push_str(&format!(" — {context_failures} FAILED"));
        }
        s
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

    // #458: a Context row that formed an expectation and missed it now reaches
    // the exit code. Before this, the section could print nothing but `PASS`,
    // and even a real verdict would have been display-only — nothing consumed
    // it. Only `Fail` counts, so a row that could not form an expectation
    // cannot turn this red: the verdict does not depend on whether a directory
    // happens to exist on the machine running the command.
    if failures == 0 && context_failures == 0 {
        Ok(0)
    } else {
        Ok(1)
    }
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

// ---------------------------------------------------------------------------
// Context section (#458)
// ---------------------------------------------------------------------------

/// What a Context row can say about what it observed.
///
/// `#458`: the section used to print `PASS` from both arms of its match, so the
/// row could not fail whatever the evaluation returned. Restoring a real
/// verdict needs three states rather than two, because the three sample paths
/// are not equally decidable:
///
/// - a target naming a `protected_paths` entry escalates by component match
///   (`context::path_matches_pattern`), which needs no filesystem and no CWD;
/// - a target in neither list is decided by the lists;
/// - but a `regenerable_paths` match only downgrades when the path *resolves*
///   (`context::resolve_path` → `fs::canonicalize`). That is a fact about the
///   machine, not about the policy, so the honest row states what it saw.
///
/// Only `Fail` reaches the exit code. A row whose expectation could not be
/// formed must not be able to turn `omamori test` red — otherwise the verdict
/// depends on whether a directory happens to exist.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextVerdict {
    Pass,
    Fail,
    /// No expectation was formed; the payload says why.
    NotChecked(&'static str),
}

#[derive(Debug)]
pub(crate) struct ContextRow {
    pub name: &'static str,
    pub verdict: ContextVerdict,
    /// What was observed, already formatted. The printer does not decide
    /// anything — it prints the status word and this string.
    pub detail: String,
}

/// The path used for the "matches neither list" row. Kept as the section's
/// original sample so the row keeps meaning the same thing; the gate below is
/// what makes it honest for configs that do list it.
const UNKNOWN_PATH_SAMPLE: &str = "data/";

/// `#458`: evaluates the Context section's sample cases and returns what was
/// observed, without printing. Split out so the verdicts can be tested at all
/// — the section had no test before this, which is how both of its arms came to
/// hardcode the same status word.
///
/// Rows 1 and 3 take their target from the config's own first entry rather than
/// a literal, so the assertion is "the config declares this path, does the
/// evaluation honour that declaration" — the gate (is the list non-empty) and
/// the check (did the verdict follow) are then different questions. Row 2
/// cannot be built that way: deciding "this matches neither list" needs the
/// matching predicate itself, so that row's gate shares a predicate with what
/// it checks. Its remaining discriminating power is against the git-derived arm
/// of `evaluate_context` over-firing on a path no list names; it is not a
/// strong check and is not presented as one.
pub(crate) fn context_rows(
    config: &Config,
    ctx_config: &ContextConfig,
    base: &Path,
) -> Vec<ContextRow> {
    let mut rows = Vec::new();

    // `#458` covers the whole section, and this line had the same defect in a
    // quieter form: it printed `PASS` for a configuration readout, which is not
    // an evaluation that could have failed. It stays in the section because
    // whether git-aware evaluation is on changes how the rows above behave, but
    // it states that it is a readout.
    let git_row = || ContextRow {
        name: "git-aware-evaluation",
        verdict: ContextVerdict::NotChecked("this line reports configuration, not an evaluation"),
        detail: if ctx_config.git.enabled {
            "git-aware evaluation is enabled".to_string()
        } else {
            "git-aware evaluation is not enabled".to_string()
        },
    };

    // Every row evaluates an `rm` invocation, so the rule is resolved once. A
    // config with no enabled `rm` rule used to make the rows vanish silently;
    // they now say so.
    let rule = config.rules.iter().find(|r| r.command == "rm" && r.enabled);
    let Some(rule) = rule else {
        for name in [
            "regenerable-path-downgrade",
            "protected-path-escalate",
            "unknown-path-unchanged",
        ] {
            rows.push(ContextRow {
                name,
                verdict: ContextVerdict::NotChecked("no enabled rm rule in this config"),
                detail: "rm is disabled or absent, so context evaluation has nothing to act on"
                    .to_string(),
            });
        }
        rows.push(git_row());
        return rows;
    };

    let evaluate = |target: &str| {
        let inv = CommandInvocation::new("rm".to_string(), vec!["-rf".into(), target.into()]);
        context::evaluate_context(&inv, rule, ctx_config, base)
    };

    // --- Row 1: a declared regenerable path. Observation only. ---
    match ctx_config.regenerable_paths.first() {
        None => rows.push(ContextRow {
            name: "regenerable-path-downgrade",
            verdict: ContextVerdict::NotChecked("regenerable_paths is empty in this config"),
            detail: "no path is declared regenerable".to_string(),
        }),
        Some(target) => {
            let result = evaluate(target);
            let detail = match &result.action_override {
                Some(action) => format!(
                    "rm {target} → {} (was: {}) — {}",
                    action.as_str(),
                    rule.action.as_str(),
                    result.reason
                ),
                None => format!(
                    "rm {target} → {} (unchanged) — {}",
                    rule.action.as_str(),
                    result.reason
                ),
            };
            rows.push(ContextRow {
                name: "regenerable-path-downgrade",
                // Not a verdict: the downgrade requires the path to resolve on
                // this machine, so a fixed expectation would be wrong wherever
                // the directory is simply absent — which is most places
                // `omamori test` runs.
                verdict: ContextVerdict::NotChecked(
                    "the outcome depends on whether the path resolves here",
                ),
                detail,
            });
        }
    }

    // --- Row 2: a declared protected path. Decidable. ---
    match ctx_config.protected_paths.first() {
        None => rows.push(ContextRow {
            name: "protected-path-escalate",
            verdict: ContextVerdict::NotChecked("protected_paths is empty in this config"),
            detail: "no path is declared protected".to_string(),
        }),
        Some(target) => {
            let result = evaluate(target);
            let escalated = result.action_override == Some(ActionKind::Block);
            rows.push(ContextRow {
                name: "protected-path-escalate",
                verdict: if escalated {
                    ContextVerdict::Pass
                } else {
                    ContextVerdict::Fail
                },
                detail: if escalated {
                    format!(
                        "rm {target} → block (was: {}) — {}",
                        rule.action.as_str(),
                        result.reason
                    )
                } else {
                    format!(
                        "rm {target} → expected block, got {} — {}",
                        result
                            .action_override
                            .as_ref()
                            .map_or("no override", |a| a.as_str()),
                        result.reason
                    )
                },
            });
        }
    }

    // --- Row 3: a path no list names. Decidable behind a gate. ---
    let (resolved, _) = context::resolve_path(UNKNOWN_PATH_SAMPLE, base);
    let listed = ctx_config
        .protected_paths
        .iter()
        .chain(ctx_config.regenerable_paths.iter())
        .find(|pattern| context::path_matches_pattern(&resolved, pattern));
    match listed {
        Some(_) => rows.push(ContextRow {
            name: "unknown-path-unchanged",
            verdict: ContextVerdict::NotChecked("this config lists the sample path"),
            detail: format!(
                "{UNKNOWN_PATH_SAMPLE} is named by protected_paths or regenerable_paths here, so \
                 an override is the correct outcome"
            ),
        }),
        None => {
            let result = evaluate(UNKNOWN_PATH_SAMPLE);
            let unchanged = result.action_override.is_none();
            rows.push(ContextRow {
                name: "unknown-path-unchanged",
                verdict: if unchanged {
                    ContextVerdict::Pass
                } else {
                    ContextVerdict::Fail
                },
                detail: if unchanged {
                    format!(
                        "rm {UNKNOWN_PATH_SAMPLE} → {} (unchanged) — {}",
                        rule.action.as_str(),
                        result.reason
                    )
                } else {
                    format!(
                        "rm {UNKNOWN_PATH_SAMPLE} → expected no override, got {} — {}",
                        result
                            .action_override
                            .as_ref()
                            .map_or("no override", |a| a.as_str()),
                        result.reason
                    )
                },
            });
        }
    }

    rows.push(git_row());
    rows
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
            degraded: false,
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

    // --- Context section (#458) ---
    //
    // The section had no test at all before this, which is the direct
    // explanation for how both arms of its match came to print the same status
    // word. `base` is a path that does not exist, on purpose: the protected and
    // unknown rows must reach their verdicts without consulting the filesystem,
    // and passing a real directory would hide it if they did.

    fn absent_base() -> &'static Path {
        Path::new("/nonexistent-omamori-458-fixture")
    }

    fn row<'a>(rows: &'a [ContextRow], name: &str) -> &'a ContextRow {
        rows.iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("row {name} must be present"))
    }

    #[test]
    fn context_rows_check_what_can_be_decided_and_say_so_for_the_rest() {
        let config = Config::default();
        let ctx = config
            .context
            .clone()
            .expect("default config has [context]");
        let rows = context_rows(&config, &ctx, absent_base());

        assert_eq!(
            row(&rows, "protected-path-escalate").verdict,
            ContextVerdict::Pass,
            "a target naming the config's own first protected path must escalate, and that is \
             decidable without the filesystem"
        );
        assert_eq!(
            row(&rows, "unknown-path-unchanged").verdict,
            ContextVerdict::Pass,
            "a path neither list names must get no override"
        );
        assert!(
            matches!(
                row(&rows, "regenerable-path-downgrade").verdict,
                ContextVerdict::NotChecked(_)
            ),
            "the downgrade needs the path to resolve on this machine, so the row states its \
             observation instead of a verdict"
        );
        assert!(
            matches!(
                row(&rows, "git-aware-evaluation").verdict,
                ContextVerdict::NotChecked(_)
            ),
            "the git line reports configuration; it is not an evaluation that could fail"
        );
    }

    /// The `Fail` arm, and the reason it is worth having: `protected_paths = ["."]`
    /// is a config a user can write, and it can never match anything.
    /// `normalize_path` removes `.` from the resolved path, so the pattern's
    /// single `CurDir` component has nothing to match against. Before #458 this
    /// printed `PASS`.
    #[test]
    fn context_rows_fail_when_a_declared_protected_path_can_never_match() {
        let mut config = Config::default();
        let mut ctx = config.context.clone().unwrap();
        ctx.protected_paths = vec![".".to_string()];
        config.context = Some(ctx.clone());

        let rows = context_rows(&config, &ctx, absent_base());
        let protected = row(&rows, "protected-path-escalate");
        assert_eq!(
            protected.verdict,
            ContextVerdict::Fail,
            "a protected declaration that cannot match must not report success"
        );
        assert!(
            protected.detail.contains("expected block"),
            "the detail must say what was expected against what happened — got: {}",
            protected.detail
        );
    }

    /// Control for the test above: the same row passes on the default list, so
    /// the failure is attributable to the unmatchable entry rather than to the
    /// row being broken.
    #[test]
    fn context_rows_protected_row_passes_on_the_default_list() {
        let config = Config::default();
        let ctx = config.context.clone().unwrap();
        assert_eq!(
            row(
                &context_rows(&config, &ctx, absent_base()),
                "protected-path-escalate"
            )
            .verdict,
            ContextVerdict::Pass
        );
    }

    #[test]
    fn context_rows_do_not_check_a_row_whose_gate_is_unmet() {
        let config = Config::default();

        // An empty protected list: nothing to build the row's target from.
        let mut empty_protected = config.context.clone().unwrap();
        empty_protected.protected_paths = Vec::new();
        assert_eq!(
            row(
                &context_rows(&config, &empty_protected, absent_base()),
                "protected-path-escalate"
            )
            .verdict,
            ContextVerdict::NotChecked("protected_paths is empty in this config")
        );

        // A config that *does* name the unknown-row sample: an override is then
        // the correct outcome, so a fixed expectation of "unchanged" would be
        // wrong rather than useful.
        let mut lists_sample = config.context.clone().unwrap();
        lists_sample.regenerable_paths = vec![UNKNOWN_PATH_SAMPLE.to_string()];
        assert_eq!(
            row(
                &context_rows(&config, &lists_sample, absent_base()),
                "unknown-path-unchanged"
            )
            .verdict,
            ContextVerdict::NotChecked("this config lists the sample path")
        );
    }

    #[test]
    fn context_rows_say_why_when_no_rm_rule_is_enabled() {
        let mut config = Config::default();
        for rule in &mut config.rules {
            if rule.command == "rm" {
                rule.enabled = false;
            }
        }
        let ctx = config.context.clone().unwrap();
        let rows = context_rows(&config, &ctx, absent_base());

        // Previously these rows vanished from the output entirely.
        for name in [
            "regenerable-path-downgrade",
            "protected-path-escalate",
            "unknown-path-unchanged",
        ] {
            assert_eq!(
                row(&rows, name).verdict,
                ContextVerdict::NotChecked("no enabled rm rule in this config"),
                "row {name}"
            );
        }
        assert!(
            matches!(
                row(&rows, "git-aware-evaluation").verdict,
                ContextVerdict::NotChecked(_)
            ),
            "the git readout is independent of the rm rule and must still appear"
        );
    }

    /// The wiring, end to end: a failing Context row has to reach the exit code.
    /// Making the verdict real is not the whole fix — before this, nothing
    /// consumed it.
    #[test]
    fn omamori_test_exits_non_zero_when_a_context_row_fails() {
        let dir = std::env::temp_dir().join(format!(
            "omamori-458-exit-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");

        // The mode matters and cost real time to find: omamori refuses a config
        // whose permissions are too open and falls back to the built-in
        // defaults with a warning. A 0644 file — what `fs::write` produces —
        // makes this test read the *default* protected list, so the row passes
        // and the assertion below fails for a reason that has nothing to do
        // with the code under test.
        let write_config = |body: &str| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&config_path, body).unwrap();
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };

        write_config("[context]\nprotected_paths = [\".\"]\nregenerable_paths = [\"target/\"]\n");

        let args: Vec<OsString> = vec![
            "omamori".into(),
            "test".into(),
            "--config".into(),
            config_path.clone().into(),
        ];
        let code = run_policy_test_command(&args).expect("the command itself must not error");
        assert_eq!(
            code, 1,
            "an unmatchable protected declaration must make `omamori test` exit non-zero"
        );

        // Control: the same command on a config whose protected list is usable
        // exits 0, so the 1 above is the row's verdict and not the config file
        // merely being present.
        write_config(
            "[context]\nprotected_paths = [\"src/\"]\nregenerable_paths = [\"target/\"]\n",
        );
        let ok = run_policy_test_command(&args).expect("the command itself must not error");
        assert_eq!(ok, 0, "a usable protected declaration must exit 0");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
