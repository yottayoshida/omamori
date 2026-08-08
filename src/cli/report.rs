//! `omamori report [--last <duration>] [--json] [--verbose]` subcommand.
//!
//! Read-only aggregation viewer for audit log events.
//! No AI environment guard (SEC-R3: precedent with `audit show`).

use std::ffi::OsString;

use crate::AppError;
use crate::audit::report::{ChainStatus, ReportAggregate, aggregate_report};
use crate::config;
use crate::util::{USAGE_HINT, flag_value_str};

pub(crate) fn run_report_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut days: u32 = 7;
    let mut json = false;
    let mut verbose = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--json" => {
                json = true;
                index += 1;
            }
            "--verbose" => {
                verbose = true;
                index += 1;
            }
            "--last" => {
                let (value, next) = flag_value_str(args, index, || {
                    "report --last requires a duration (e.g. 7d)".to_string()
                })?;
                days = parse_duration(value)?;
                index = next;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown flag: {arg}\n\n{USAGE_HINT}"
                )));
            }
        }
    }

    let load_result = config::load_config(None)?;
    let report = aggregate_report(&load_result.config.audit, days);

    if json {
        print_json_report(&report);
    } else {
        print_human_report(&report, verbose);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Duration parser (SEC-R4: 1d–90d, case-insensitive)
// ---------------------------------------------------------------------------

fn parse_duration(s: &str) -> Result<u32, AppError> {
    let s = s.trim().to_lowercase();
    if !s.ends_with('d') {
        return Err(AppError::Usage(format!(
            "invalid duration \"{s}\": use format like 7d (1d–90d)"
        )));
    }
    let num_str = &s[..s.len() - 1];
    let n: u32 = num_str.parse().map_err(|_| {
        AppError::Usage(format!(
            "invalid duration \"{s}\": use format like 7d (1d–90d)"
        ))
    })?;
    if !(1..=90).contains(&n) {
        return Err(AppError::Usage(format!(
            "duration out of range: {n}d (allowed: 1d–90d)"
        )));
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

fn print_human_report(report: &ReportAggregate, verbose: bool) {
    println!("omamori report — last {} days", report.period_days);
    println!();

    // Retention caveat
    if report.actual_window_days < report.period_days {
        println!(
            "  Note: showing {} days of {} requested",
            report.actual_window_days, report.period_days
        );
        println!();
    }

    // Block events
    if report.total_blocks == 0 {
        println!("  Block events: none");
    } else {
        println!("  Block events: {}", report.total_blocks);
        print_breakdown("    by layer", &report.by_layer);
        print_breakdown("    by provider", &report.by_provider);
        print_breakdown("    by rule", &report.by_rule);
    }

    // Unknown tool fail-opens (SEC-R7: count only)
    if report.unknown_tool_fail_opens > 0 {
        println!(
            "  Unknown-tool fail-opens: {}",
            report.unknown_tool_fail_opens
        );
    }

    // Chain integrity (always shown; verbose adds seq detail)
    match &report.chain_status {
        ChainStatus::Intact => println!("  Audit log: intact"),
        // #471/#487: `reason` carries the data directory's path, so it is
        // printed only under `--verbose`, matching how the sibling arms treat
        // their own internals. The short form names `kind`, which is the same
        // value `--json` consumers branch on.
        ChainStatus::Inaccessible { reason, kind } => {
            if verbose {
                println!("  Audit log: cannot be read ({kind}) — {reason}");
            } else {
                println!("  Audit log: cannot be read ({kind})");
            }
        }
        ChainStatus::Broken { at_seq } => {
            if verbose {
                println!("  Audit log: broken at seq {at_seq}");
            } else {
                println!("  Audit log: broken");
            }
        }
        ChainStatus::Truncated => {
            println!("  Audit log: truncated (entries may have been removed)")
        }
        ChainStatus::Unverifiable {
            at_seq,
            chain_version,
        } => {
            if verbose {
                println!(
                    "  Audit log: unverifiable at seq {at_seq} — entry declares chain_version \
                     {chain_version}, which this omamori build does not recognize (not \
                     necessarily tampering — may mean this binary predates a newer chain format)"
                );
            } else {
                println!("  Audit log: unverifiable (unrecognized chain_version)");
            }
        }
        ChainStatus::KeyUnavailable { at_seq, key_id } => {
            if verbose {
                println!(
                    "  Audit log: cannot verify from seq {at_seq} — entry names key \
                     \"{key_id}\", which is not in the keyring (not tampering; the key \
                     file is missing, renamed, or unreadable)"
                );
            } else {
                println!("  Audit log: cannot verify (key \"{key_id}\" not in keyring)");
            }
        }
        // #483: the chain links verified; some entries in it carry no HMAC.
        ChainStatus::Unprotected { entries } => {
            println!("  Audit log: {entries} entries carry no HMAC and cannot be verified");
        }
        ChainStatus::KeyringUnusable { reason, .. } => {
            println!("  Audit log: cannot verify — {reason}");
        }
        ChainStatus::Unavailable => println!("  Audit log: unavailable"),
    }

    // #506: set only when `chain_status` is carrying something else, which in
    // practice means a truncated tail (see `ReportAggregate::key_store_failure`).
    // Without this line the store reports the missing tail and says nothing
    // about why nothing could be authenticated — and an unreadable key store is
    // how the missing tail was made hard to notice in the first place.
    if let Some(failure) = &report.key_store_failure {
        println!("  Audit keys: cannot verify — {}", failure.reason);
    }
    // #483: the chain status above is `intact` on this store and is right to be
    // — the links were checked. What it cannot say is that everything in the log
    // was authenticated, which is exactly the gap `keyring_warnings` below has
    // its own line for.
    if report.never_protected_entries > 0 {
        println!(
            "  Audit entries: {} carry no HMAC and cannot be verified",
            report.never_protected_entries
        );
    }

    // #471 item 3: `doctor` is not the only surface an operator watches, and
    // the comment in `aggregate_report` that motivated this said so — "the two
    // surfaces". Review caught that only one of them got the line, leaving
    // `report` printing `Audit log: intact` beside a damaged key. The chain
    // status is untouched, because it is genuinely intact.
    for warning in &report.keyring_warnings {
        println!("  {warning}");
    }

    // Follow-ups
    let mut follow_ups = Vec::new();
    if report.unknown_tool_fail_opens > 0 {
        follow_ups.push("review unknown tools: omamori audit unknown");
    }
    if report.chain_status.needs_attention() || !report.keyring_warnings.is_empty() {
        follow_ups.push("verify chain: omamori audit verify");
    }
    if !follow_ups.is_empty() {
        println!();
        println!("  Suggested follow-ups:");
        for f in &follow_ups {
            println!("    - {f}");
        }
    }
}

fn print_breakdown(label: &str, map: &std::collections::HashMap<String, u64>) {
    if map.is_empty() {
        return;
    }
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let parts: Vec<String> = entries.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    println!("{label}: {}", parts.join(", "));
}

// ---------------------------------------------------------------------------
// JSON output (SEC-R2: 7 fields via ReportAggregate Serialize)
// ---------------------------------------------------------------------------

fn print_json_report(report: &ReportAggregate) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_duration_valid() {
        assert_eq!(parse_duration("7d").unwrap(), 7);
        assert_eq!(parse_duration("1d").unwrap(), 1);
        assert_eq!(parse_duration("90d").unwrap(), 90);
        assert_eq!(parse_duration("30D").unwrap(), 30);
        assert_eq!(parse_duration(" 14d ").unwrap(), 14);
    }

    #[test]
    fn parse_duration_out_of_range() {
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("91d").is_err());
        assert!(parse_duration("100d").is_err());
    }

    #[test]
    fn parse_duration_invalid_format() {
        assert!(parse_duration("7").is_err());
        assert!(parse_duration("7h").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("d").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-1d").is_err());
    }

    #[test]
    fn json_output_has_eight_fields() {
        let report = ReportAggregate {
            period_days: 7,
            actual_window_days: 7,
            total_blocks: 3,
            by_layer: HashMap::from([("layer1".to_string(), 2), ("layer2".to_string(), 1)]),
            by_provider: HashMap::from([("claude-code".to_string(), 3)]),
            by_rule: HashMap::from([("rm-rf".to_string(), 2), ("mv-slash".to_string(), 1)]),
            chain_status: ChainStatus::Intact,
            unknown_tool_fail_opens: 1,
            hwm_tampered: false,
            // #471: non-empty on purpose. This test counts the JSON fields
            // (SEC-R2: exactly 8), and a field that is `skip`ped only while it
            // happens to be empty would pass here and leak in production.
            keyring_warnings: vec!["audit keyring: cannot read /tmp/k (denied)".to_string()],
            // #506: `Some`, for the reason `keyring_warnings` above is
            // non-empty. A `skip`ped field only ever tested while it is empty
            // proves nothing about what serializes when it is not — and this
            // one's `reason` carries the operator's home directory, which is
            // exactly what must not reach `--json`.
            key_store_failure: Some(crate::audit::KeyStoreFailure {
                kind: "directory_unreadable",
                reason: "audit keyring: cannot list /Users/someone/.local/share/omamori"
                    .to_string(),
                remedy: "To fix: make that directory listable again, then re-run.".to_string(),
            }),
            // #483: non-zero for the same reason the two above are non-empty.
            never_protected_entries: 2,
        };
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            !serde_json::to_string(&json).unwrap().contains("someone"),
            "no part of the key directory's path may reach the JSON surface"
        );

        assert_eq!(
            obj.len(),
            8,
            "SEC-R2: exactly 8 fields (hwm_tampered is #[serde(skip)], internal-only)"
        );
        assert!(obj.contains_key("period_days"));
        assert!(obj.contains_key("actual_window_days"));
        assert!(obj.contains_key("total_blocks"));
        assert!(obj.contains_key("by_layer"));
        assert!(obj.contains_key("by_provider"));
        assert!(obj.contains_key("by_rule"));
        assert!(obj.contains_key("chain_status"));
        assert!(obj.contains_key("unknown_tool_fail_opens"));
    }

    #[test]
    fn json_output_empty_report() {
        let report = ReportAggregate::default();
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.len(), 8);
        assert_eq!(json["total_blocks"], 0);
        assert_eq!(json["unknown_tool_fail_opens"], 0);
        assert_eq!(json["chain_status"]["status"], "unavailable");
    }

    #[test]
    fn run_command_default_succeeds() {
        let args: Vec<OsString> = vec!["omamori".into(), "report".into()];
        let code = run_report_command(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_command_with_last_flag() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "report".into(),
            "--last".into(),
            "30d".into(),
        ];
        let code = run_report_command(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_command_with_json_flag() {
        let args: Vec<OsString> = vec!["omamori".into(), "report".into(), "--json".into()];
        let code = run_report_command(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_command_invalid_duration_errors() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "report".into(),
            "--last".into(),
            "91d".into(),
        ];
        assert!(run_report_command(&args).is_err());
    }

    #[test]
    fn run_command_unknown_flag_errors() {
        let args: Vec<OsString> = vec!["omamori".into(), "report".into(), "--bogus".into()];
        assert!(run_report_command(&args).is_err());
    }

    #[test]
    fn json_chain_status_serialization() {
        let intact = serde_json::to_value(ChainStatus::Intact).unwrap();
        assert_eq!(intact["status"], "intact");

        let broken = serde_json::to_value(ChainStatus::Broken { at_seq: 42 }).unwrap();
        assert_eq!(broken["status"], "broken");
        assert!(broken.get("at_seq").is_none(), "SEC-R8: at_seq not in JSON");

        let truncated = serde_json::to_value(ChainStatus::Truncated).unwrap();
        assert_eq!(truncated["status"], "truncated");

        // #177 B1 step 2
        let unverifiable = serde_json::to_value(ChainStatus::Unverifiable {
            at_seq: 7,
            chain_version: 999,
        })
        .unwrap();
        assert_eq!(unverifiable["status"], "unverifiable");
        assert!(
            unverifiable.get("at_seq").is_none(),
            "SEC-R8: at_seq not in JSON (matches Broken's precedent)"
        );
        assert_eq!(
            unverifiable["chain_version"], 999,
            "chain_version IS meant to be JSON-visible (unlike at_seq) — it's the \
             actionable part of this status, not forensic detail"
        );

        let unavail = serde_json::to_value(ChainStatus::Unavailable).unwrap();
        assert_eq!(unavail["status"], "unavailable");
    }

    // --- Characterization tests (#392/#377): pin current --last error
    // wording before the shared-helper migration. Returns before any
    // filesystem I/O, so no config setup needed. ---

    #[test]
    fn report_last_missing_value_error_message() {
        let args: Vec<OsString> = vec!["omamori".into(), "report".into(), "--last".into()];
        let err = run_report_command(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "report --last requires a duration (e.g. 7d)"
        );
    }

    #[test]
    fn report_last_parse_failure_error_message() {
        // Distinct from the missing-value message above — parse_duration's
        // own error text, unchanged by this refactor (the helper covers
        // only the "get value or error" half).
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "report".into(),
            "--last".into(),
            "not-a-duration".into(),
        ];
        let err = run_report_command(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid duration \"not-a-duration\": use format like 7d (1d–90d)"
        );
    }

    #[test]
    #[cfg(unix)]
    fn report_last_rejects_non_utf8_value_same_as_missing() {
        // Shape B fold: non-UTF8 value → same message as missing value.
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> =
            vec!["omamori".into(), "report".into(), "--last".into(), non_utf8];
        let err = run_report_command(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "report --last requires a duration (e.g. 7d)"
        );
    }

    #[test]
    fn report_last_adjacent_flag_greedy_value_consumption() {
        // Codex Phase 6-B: strengthens V-ADJ coverage for Shape B — `--last
        // --json` must consume the literal string "--json" as --last's
        // value (parsed and rejected by parse_duration), not recognize
        // --json as a flag.
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "report".into(),
            "--last".into(),
            "--json".into(),
        ];
        let err = run_report_command(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid duration \"--json\": use format like 7d (1d–90d)"
        );
    }

    #[test]
    #[cfg(unix)]
    fn report_non_utf8_flag_name_silently_ends_parsing() {
        // #392/#377 V-NONUTF8-FLAG (Codex Phase 6-A finding during /plan,
        // Codex Phase 6-B adversarial review during /develop): the outer
        // loop `while let Some(arg) = args.get(index).and_then(|item|
        // item.to_str())` — shared verbatim across every migrated file, not
        // just report.rs — silently stops parsing (not an error) the moment
        // it hits a non-UTF8 token AT THE FLAG-NAME POSITION, distinct from
        // a non-UTF8 VALUE after a recognized flag (which the fold tests
        // above cover). A trailing `--last not-a-duration` after the
        // non-UTF8 token must never be reached, proving the loop actually
        // stopped rather than skipping past the bad token.
        let non_utf8_flag = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "report".into(),
            non_utf8_flag,
            "--last".into(),
            "not-a-duration".into(),
        ];
        // If the loop kept going past the non-UTF8 token, this would fail
        // on parse_duration("not-a-duration"). Success here proves parsing
        // stopped silently at the non-UTF8 flag-name position instead.
        let code = run_report_command(&args).unwrap();
        assert_eq!(code, 0);
    }
}
