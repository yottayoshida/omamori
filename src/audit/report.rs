//! Report aggregation for audit log analysis.
//!
//! Provides `aggregate_report()` to summarize block events, unknown tool
//! fail-opens, and chain integrity over a given time window.
//!
//! Security invariants (SEC-R10/R11):
//! - Uses `open_read_nofollow` to prevent symlink attacks
//! - Shares reader discipline with verify.rs / secret.rs

use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::secret::{default_audit_path, open_read_nofollow};
use super::verify::verify_chain;
use super::{AuditConfig, AuditEvent};

/// Chain integrity status (3-state per SEC-R8).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChainStatus {
    Intact,
    Broken {
        #[serde(skip_serializing)]
        at_seq: u64,
    },
    Unavailable,
}

impl ChainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::Broken { .. } => "broken",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Aggregated report data for `omamori report` output.
///
/// JSON output is limited to 7 fields per SEC-R2:
/// period_days, actual_window_days, total_blocks, by_layer, by_provider,
/// chain_status, unknown_tool_fail_opens
#[derive(Debug, Clone, Serialize)]
pub struct ReportAggregate {
    pub period_days: u32,
    pub actual_window_days: u32,
    pub total_blocks: u64,
    pub by_layer: HashMap<String, u64>,
    pub by_provider: HashMap<String, u64>,
    pub chain_status: ChainStatus,
    pub unknown_tool_fail_opens: u64,
}

impl Default for ReportAggregate {
    fn default() -> Self {
        Self {
            period_days: 0,
            actual_window_days: 0,
            total_blocks: 0,
            by_layer: HashMap::new(),
            by_provider: HashMap::new(),
            chain_status: ChainStatus::Unavailable,
            unknown_tool_fail_opens: 0,
        }
    }
}

/// Aggregate audit events within the given time window.
///
/// Returns a default (zeros + Unavailable) on any read/parse failure.
/// This is a UX surface, not a security gate — doctor/report must never
/// error out because the audit log happened to be unreadable.
///
/// # Arguments
/// * `config` - Audit configuration (path, retention, enabled)
/// * `days` - Requested period in days (1-90 per SEC-R4)
///
/// # Security
/// - Uses `open_read_nofollow` (SEC-R10)
/// - Shares reader with verify_chain (SEC-R11)
pub fn aggregate_report(config: &AuditConfig, days: u32) -> ReportAggregate {
    let mut result = ReportAggregate {
        period_days: days,
        actual_window_days: days,
        ..Default::default()
    };

    if !config.enabled {
        return result;
    }

    let path = config.path.clone().unwrap_or_else(default_audit_path);

    // Chain status via existing verify_chain (SEC-R11: shared reader)
    result.chain_status = match verify_chain(config) {
        Ok(verify_result) => match verify_result.broken_at {
            Some(at_seq) => ChainStatus::Broken { at_seq },
            None => ChainStatus::Intact,
        },
        Err(_) => ChainStatus::Unavailable,
    };

    // Retention caveat: actual window may be smaller than requested
    if config.retention_days > 0 && config.retention_days < days {
        result.actual_window_days = config.retention_days;
    }

    // Aggregate events
    if let Some(stats) = aggregate_events(&path, days) {
        result.total_blocks = stats.total_blocks;
        result.by_layer = stats.by_layer;
        result.by_provider = stats.by_provider;
        result.unknown_tool_fail_opens = stats.unknown_tool_fail_opens;

        // Refine actual_window_days based on oldest event in window
        if let Some(oldest_days) = stats.oldest_event_days
            && oldest_days < result.actual_window_days
        {
            result.actual_window_days = oldest_days;
        }
    }

    result
}

struct EventStats {
    total_blocks: u64,
    by_layer: HashMap<String, u64>,
    by_provider: HashMap<String, u64>,
    unknown_tool_fail_opens: u64,
    oldest_event_days: Option<u32>,
}

fn aggregate_events(path: &Path, days: u32) -> Option<EventStats> {
    let file = open_read_nofollow(path).ok()?;
    let reader = std::io::BufReader::new(file);

    let now = OffsetDateTime::now_utc();
    let cutoff = now - time::Duration::days(i64::from(days));

    let mut stats = EventStats {
        total_blocks: 0,
        by_layer: HashMap::new(),
        by_provider: HashMap::new(),
        unknown_tool_fail_opens: 0,
        oldest_event_days: None,
    };

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let ts = match OffsetDateTime::parse(&event.timestamp, &Rfc3339) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if ts < cutoff {
            continue;
        }

        // Track oldest event for actual_window_days calculation
        let event_age_days = ((now - ts).whole_days().max(0) as u32).saturating_add(1);
        match stats.oldest_event_days {
            None => stats.oldest_event_days = Some(event_age_days),
            Some(oldest) if event_age_days > oldest => {
                stats.oldest_event_days = Some(event_age_days);
            }
            _ => {}
        }

        // Count unknown_tool_fail_open
        if event.action == "unknown_tool_fail_open" {
            stats.unknown_tool_fail_opens += 1;
            continue;
        }

        // Count blocks (action = "block", written by rules.rs Block variant)
        if event.action == "block" {
            stats.total_blocks += 1;

            // by_layer: classify detection_layer into 3 buckets
            let layer_bucket = classify_layer(event.detection_layer.as_deref());
            *stats.by_layer.entry(layer_bucket).or_insert(0) += 1;

            // by_provider: aggregate by provider field (SEC-R1)
            let provider = if event.provider.is_empty() {
                "none".to_string()
            } else {
                event.provider.clone()
            };
            *stats.by_provider.entry(provider).or_insert(0) += 1;
        }
    }

    Some(stats)
}

/// Classify detection_layer into 3 buckets for by_layer aggregation.
///
/// - "layer1" → "layer1"
/// - "layer2:*" (any variant) → "layer2"
/// - "shape-routing" → "shape-routing"
/// - None / unknown → "unclassified" (qa V-010)
fn classify_layer(detection_layer: Option<&str>) -> String {
    match detection_layer {
        Some("layer1") => "layer1".to_string(),
        Some(dl) if dl == "layer2" || dl.starts_with("layer2:") => "layer2".to_string(),
        Some("shape-routing") => "shape-routing".to_string(),
        Some(dl) => dl.to_string(), // preserve unknown values
        None => "unclassified".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_layer() {
        assert_eq!(classify_layer(Some("layer1")), "layer1");
        assert_eq!(classify_layer(Some("layer2:rule")), "layer2");
        assert_eq!(classify_layer(Some("layer2:meta-pattern")), "layer2");
        assert_eq!(classify_layer(Some("layer2:pipe-to-shell:sudo")), "layer2");
        assert_eq!(classify_layer(Some("layer2:structural")), "layer2");
        assert_eq!(classify_layer(Some("layer2")), "layer2");
        assert_eq!(classify_layer(Some("shape-routing")), "shape-routing");
        assert_eq!(classify_layer(None), "unclassified");
    }

    #[test]
    fn test_classify_layer_rejects_false_prefixes() {
        assert_eq!(classify_layer(Some("layer20")), "layer20");
        assert_eq!(classify_layer(Some("layer2evil")), "layer2evil");
        assert_eq!(classify_layer(Some("layer2/")), "layer2/");
        assert_eq!(classify_layer(Some("layer3")), "layer3");
    }

    #[test]
    fn test_chain_status_as_str() {
        assert_eq!(ChainStatus::Intact.as_str(), "intact");
        assert_eq!(ChainStatus::Broken { at_seq: 42 }.as_str(), "broken");
        assert_eq!(ChainStatus::Unavailable.as_str(), "unavailable");
    }

    #[test]
    fn test_default_report_aggregate() {
        let report = ReportAggregate::default();
        assert_eq!(report.period_days, 0);
        assert_eq!(report.total_blocks, 0);
        assert!(report.by_layer.is_empty());
        assert!(report.by_provider.is_empty());
        assert_eq!(report.chain_status, ChainStatus::Unavailable);
    }

    fn make_event_line(
        action: &str,
        provider: &str,
        detection_layer: Option<&str>,
        minutes_ago: i64,
    ) -> String {
        let ts = OffsetDateTime::now_utc() - time::Duration::minutes(minutes_ago);
        let ts_str = ts.format(&Rfc3339).unwrap();
        let dl = match detection_layer {
            Some(v) => format!("\"{v}\""),
            None => "null".to_string(),
        };
        format!(
            r#"{{"timestamp":"{ts_str}","provider":"{provider}","command":"test","rule_id":null,"action":"{action}","result":"done","target_count":0,"target_hash":"","detection_layer":{dl}}}"#,
        )
    }

    fn write_temp_audit(lines: &[String], tag: &str) -> std::path::PathBuf {
        let dir = std::env::var("HOME").unwrap();
        let path = std::path::PathBuf::from(dir)
            .join(format!(".omamori-test-{}-{tag}.jsonl", std::process::id()));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    #[test]
    fn test_action_block_counted_deny_ignored() {
        let lines = vec![
            make_event_line("block", "claude-code", Some("layer1"), 10),
            make_event_line("block", "claude-code", Some("layer2:rule"), 20),
            make_event_line("deny", "claude-code", Some("layer1"), 30),
            make_event_line("allow", "claude-code", Some("layer1"), 40),
        ];
        let path = write_temp_audit(&lines, "action");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 2);
        assert_eq!(*stats.by_layer.get("layer1").unwrap_or(&0), 1);
        assert_eq!(*stats.by_layer.get("layer2").unwrap_or(&0), 1);
    }

    #[test]
    fn test_empty_provider_mapped_to_none() {
        let lines = vec![make_event_line("block", "", Some("layer1"), 10)];
        let path = write_temp_audit(&lines, "provider");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 1);
        assert_eq!(*stats.by_provider.get("none").unwrap_or(&0), 1);
        assert!(!stats.by_provider.contains_key(""));
    }

    #[test]
    fn test_unknown_tool_fail_open_isolation() {
        let lines = vec![
            make_event_line("unknown_tool_fail_open", "claude-code", Some("layer1"), 10),
            make_event_line("unknown_tool_fail_open", "codex", None, 20),
            make_event_line("block", "claude-code", Some("layer1"), 30),
        ];
        let path = write_temp_audit(&lines, "unknown");
        let stats = aggregate_events(&path, 1).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.unknown_tool_fail_opens, 2);
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.by_layer.len(), 1);
        assert_eq!(stats.by_provider.len(), 1);
    }

    #[test]
    fn test_events_outside_window_excluded() {
        let lines = vec![
            make_event_line("block", "claude-code", Some("layer1"), 10),
            make_event_line("block", "claude-code", Some("layer1"), 60 * 24 * 8),
        ];
        let path = write_temp_audit(&lines, "window");
        let stats = aggregate_events(&path, 7).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(stats.total_blocks, 1);
    }

    #[test]
    fn test_aggregate_report_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let report = aggregate_report(&config, 7);
        assert_eq!(report.period_days, 7);
        assert_eq!(report.total_blocks, 0);
        assert_eq!(report.chain_status, ChainStatus::Unavailable);
    }
}
