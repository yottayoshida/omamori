//! `omamori report [--last <duration>] [--json] [--verbose]` subcommand.
//!
//! Read-only aggregation viewer for audit log events.
//! No AI environment guard (SEC-R3: precedent with `audit show`).

use std::ffi::OsString;

use crate::AppError;
use crate::audit::report::{ChainStatus, ReportAggregate, aggregate_report};
use crate::config;
use crate::util::usage_text;

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
                let value = args
                    .get(index + 1)
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| {
                        AppError::Usage("report --last requires a duration (e.g. 7d)".to_string())
                    })?;
                days = parse_duration(value)?;
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown flag: {arg}\n\n{}",
                    usage_text()
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
        ChainStatus::Broken { at_seq } => {
            if verbose {
                println!("  Audit log: broken at seq {at_seq}");
            } else {
                println!("  Audit log: broken");
            }
        }
        ChainStatus::Unavailable => println!("  Audit log: unavailable"),
    }

    // Follow-ups
    let mut follow_ups = Vec::new();
    if report.unknown_tool_fail_opens > 0 {
        follow_ups.push("review unknown tools: omamori audit unknown");
    }
    if matches!(report.chain_status, ChainStatus::Broken { .. }) {
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
    fn json_output_has_seven_fields() {
        let report = ReportAggregate {
            period_days: 7,
            actual_window_days: 7,
            total_blocks: 3,
            by_layer: HashMap::from([("layer1".to_string(), 2), ("layer2".to_string(), 1)]),
            by_provider: HashMap::from([("claude-code".to_string(), 3)]),
            chain_status: ChainStatus::Intact,
            unknown_tool_fail_opens: 1,
        };
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.len(), 7, "SEC-R2: exactly 7 fields");
        assert!(obj.contains_key("period_days"));
        assert!(obj.contains_key("actual_window_days"));
        assert!(obj.contains_key("total_blocks"));
        assert!(obj.contains_key("by_layer"));
        assert!(obj.contains_key("by_provider"));
        assert!(obj.contains_key("chain_status"));
        assert!(obj.contains_key("unknown_tool_fail_opens"));
    }

    #[test]
    fn json_output_empty_report() {
        let report = ReportAggregate::default();
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.len(), 7);
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

        let unavail = serde_json::to_value(ChainStatus::Unavailable).unwrap();
        assert_eq!(unavail["status"], "unavailable");
    }
}
