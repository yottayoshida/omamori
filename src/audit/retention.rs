//! Audit log retention and pruning.
//!
//! Automatic prune is triggered every `PRUNE_CHECK_INTERVAL` entries during
//! `AuditLogger::append()`, under the same flock.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use time::OffsetDateTime;

use super::AuditEvent;
use super::chain::{CHAIN_VERSION, compute_entry_hash, hmac_bytes, prune_genesis_hash};

pub(super) const PRUNE_CHECK_INTERVAL: u64 = 1000;
pub(super) const MIN_RETENTION_DAYS: u32 = 7;
pub(super) const MIN_RETAIN_ENTRIES: usize = 1000;
pub(super) const PRUNE_COMMAND: &str = "_prune";
pub(super) const PRUNE_ACTION: &str = "retention";
pub(super) const PRUNE_RESULT: &str = "pruned";

/// In-place prune of entries older than `retention_days`.
/// Called under flock_exclusive from append().
/// Best-effort: errors are silently ignored (prune is not critical path).
pub(super) fn try_prune(
    file: &mut fs::File,
    secret: Option<&[u8; 32]>,
    retention_days: u32,
) -> Result<u64, std::io::Error> {
    use time::format_description::well_known::Rfc3339;

    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(retention_days));

    // Partition lines: find the first line whose timestamp >= cutoff.
    // Also capture the first retained entry's hash (for prune-bind) in a single pass.
    let lines: Vec<&str> = content.lines().collect();
    let mut retain_from = 0usize;
    let mut skip_existing_prune = 0usize;
    let mut first_retained_hash = String::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue; // torn line
        };

        // Skip existing prune_point at the start (don't count it as prunable)
        if i == 0 && val.get("command").and_then(|v| v.as_str()) == Some(PRUNE_COMMAND) {
            skip_existing_prune = 1;
            continue;
        }

        let Some(ts_str) = val.get("timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ts) = OffsetDateTime::parse(ts_str, &Rfc3339) else {
            continue;
        };

        if ts >= cutoff {
            retain_from = i;
            first_retained_hash = val
                .get("entry_hash")
                .and_then(|h| h.as_str())
                .unwrap_or_default()
                .to_string();
            break;
        }
        retain_from = i + 1; // haven't found a keeper yet
    }

    // Adjust for existing prune_point: don't re-count it
    let prune_count = retain_from.saturating_sub(skip_existing_prune) as u64;
    if prune_count == 0 {
        return Ok(0);
    }

    // Check minimum retain count
    let retain_count = lines.len() - retain_from;
    if retain_count < MIN_RETAIN_ENTRIES {
        return Ok(0);
    }

    let prune_point = build_prune_point(secret, prune_count, &first_retained_hash);

    // In-place rewrite: prune_point + retained lines
    let estimated_size = content.len(); // upper bound; retained portion is smaller
    let mut new_content = String::with_capacity(estimated_size);
    let prune_json =
        serde_json::to_string(&prune_point).expect("prune_point serialization cannot fail");
    new_content.push_str(&prune_json);
    new_content.push('\n');
    for line in &lines[retain_from..] {
        new_content.push_str(line);
        new_content.push('\n');
    }

    file.seek(SeekFrom::Start(0))?;
    file.write_all(new_content.as_bytes())?;
    file.set_len(new_content.len() as u64)?;
    file.flush()?;

    eprintln!("omamori: pruned {prune_count} audit entries older than {retention_days}d");
    Ok(prune_count)
}

pub(super) fn build_prune_point(
    secret: Option<&[u8; 32]>,
    prune_count: u64,
    first_retained_hash: &str,
) -> AuditEvent {
    let target_hash = hmac_bytes(
        secret,
        format!("prune-bind:{prune_count}:{first_retained_hash}").as_bytes(),
    );

    let mut event = AuditEvent {
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: "omamori".to_string(),
        command: PRUNE_COMMAND.to_string(),
        rule_id: None,
        action: PRUNE_ACTION.to_string(),
        result: PRUNE_RESULT.to_string(),
        target_count: prune_count as usize,
        target_hash,
        detection_layer: None,
        unwrap_chain: None,
        raw_input_hash: None,
        chain_version: Some(CHAIN_VERSION),
        seq: Some(0),
        prev_hash: Some(prune_genesis_hash(secret)),
        key_id: Some("default".to_string()),
        entry_hash: None,
    };
    event.entry_hash = Some(compute_entry_hash(secret, &event));
    event
}

pub(super) fn is_prune_point(event: &AuditEvent) -> bool {
    event.command == PRUNE_COMMAND && event.action == PRUNE_ACTION && event.result == PRUNE_RESULT
}
