//! Audit log retention and pruning.
//!
//! Automatic prune is triggered every `PRUNE_CHECK_INTERVAL` entries during
//! `AuditLogger::append()`, under the same flock.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use time::OffsetDateTime;

use super::AuditEvent;
use super::chain::{
    CHAIN_VERSION, RecomputedHash, compute_entry_hash, compute_entry_hash_for_write, hmac_bytes,
    prune_genesis_hash,
};
use super::secret::{Keyring, SigningKey, load_keyring, secret_path_for};
use super::{hwm_path_for, write_hwm};

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
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
) -> Result<u64, std::io::Error> {
    try_prune_at(
        file,
        signing_key,
        retention_days,
        audit_path,
        OffsetDateTime::now_utc(),
    )
}

pub(super) fn try_prune_at(
    file: &mut fs::File,
    signing_key: &SigningKey,
    retention_days: u32,
    audit_path: Option<&std::path::Path>,
    now: OffsetDateTime,
) -> Result<u64, std::io::Error> {
    use time::format_description::well_known::Rfc3339;

    // `#461`: without a secret there is nothing to prune *with*. `hmac_bytes`
    // answers a `None` key with the fixed string `NO_HMAC_SECRET` (`chain.rs`),
    // so the prune point this would write carries a `target_hash` and an
    // `entry_hash` that any reader can reproduce — a prune-bind that binds
    // nothing, standing where the pruned range used to be. Keeping the entries
    // is the lesser loss: the condition that removed the key is usually
    // recoverable, and a later prune with the key in hand does the same work.
    if signing_key.secret().is_none() {
        eprintln!(
            "omamori warning: audit prune skipped — no HMAC secret is available, so the prune \
             point that replaces the removed entries could not be protected. The entries were \
             left in place; the log will keep growing until the key is readable again."
        );
        return Ok(0);
    }

    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let cutoff = now - time::Duration::days(i64::from(retention_days));

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

    let prune_point = build_prune_point(signing_key, prune_count, &first_retained_hash, now);

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

    // Reset the high-water-mark from the retained entries.
    //
    // `#461`: the mark used to be the largest `seq` among them, read straight
    // out of the JSON. That number is tamper-evidence *about* the log, and it
    // was being taken from the log without checking whether the line it came
    // from was written by omamori — so one planted line with a high `seq` put
    // the mark wherever its author chose. No key is needed to write that line:
    // this recomputation was the only thing that read the field back.
    //
    // What that buys an attacker is a false accusation, not concealment
    // (Codex review, R2 — an earlier version of this comment had the direction
    // backwards). `verify_chain` reports a truncated tail when the mark is
    // *above* the chain, so a raised mark makes it say the log was cut when
    // nothing was removed, and keeps saying it: prune is the only thing that
    // recomputes the mark, and it runs once per 1000 appends. Lowering it —
    // which is what would hide a removal — is not reachable this way, since the
    // mark is a maximum. The defect is that tamper-evidence about the log was
    // taken from the log, which is the same root `#456` closed on the append
    // side and named this half as still open.
    //
    // The mark now comes from an entry that authenticates against the key it
    // names. `#456` closed the append side of the same root — on-disk `seq`
    // values trusted without verification — and named this half as still open.
    if let Some(audit_path) = audit_path {
        let keyring = load_keyring(&secret_path_for(audit_path));
        match authenticated_max_seq(&lines[retain_from..], &keyring) {
            Some(seq) => {
                if let Err(e) = write_hwm(&hwm_path_for(audit_path), seq) {
                    eprintln!(
                        "omamori warning: failed to update audit high-water-mark after prune: {e}"
                    );
                }
            }
            None => {
                // Left where it was, deliberately. A mark below the chain reads
                // as nothing; a mark above it reads as truncation. Neither is a
                // claim this function can make right now, and the previous mark
                // was at least derived when a key was available.
                //
                // The two ways to get here are worth telling apart, because one
                // is a key-store fault the operator can fix and the other is a
                // statement about the entries themselves.
                let reason = match keyring.fatal_anomaly() {
                    Some(anomaly) => anomaly.describe(),
                    None => "no retained entry could be authenticated against the key it names"
                        .to_string(),
                };
                eprintln!(
                    "omamori warning: audit high-water-mark left unchanged after prune — {reason}"
                );
            }
        }
    }

    eprintln!("omamori: pruned {prune_count} audit entries older than {retention_days}d");
    Ok(prune_count)
}

/// The highest `seq` among `retained` lines that authenticate against the key
/// they name (`#461`).
///
/// Entries are tried in descending `seq` order and the first one that
/// authenticates wins, so the ordinary case costs one HMAC rather than one per
/// retained entry — and the answer is the same either way, since a lower `seq`
/// cannot raise the maximum.
///
/// `None` covers both "the keyring holds nothing usable" and "nothing retained
/// authenticated". They arrive here identically — an empty ring makes every
/// `keyring.get` miss — and the caller reports which one it was from the ring's
/// own anomalies. Kept as one path on purpose: a separate emptiness branch
/// would be a second place to keep in step with what `get` actually returns.
///
/// Prune points are excluded by [`is_prune_point`], which checks all three
/// fields, rather than by `command` alone as the code this replaced did. The
/// first draft kept the looser check and argued that a real prune point carries
/// `seq: 0`, so admitting one could only lower the mark. That argument holds
/// for a real prune point and says nothing about an ordinary entry that merely
/// *names* `_prune` — a user running a command by that name produces a signed
/// entry with a real `seq`, and dropping it lowered the mark by one whenever it
/// was the highest retained, leaving that one entry's removal undetectable
/// (Codex review, P3). The stricter check is right on both: it still excludes
/// the real prune point, whose `action`/`result` identify it.
fn authenticated_max_seq(retained: &[&str], keyring: &Keyring) -> Option<u64> {
    // `seq` is taken out here rather than checked in the loop, so the sort key
    // is a plain `u64` and an entry without one is simply not a candidate — it
    // could not anchor the mark in any case.
    let mut candidates: Vec<(u64, AuditEvent)> = retained
        .iter()
        .filter_map(|line| serde_json::from_str::<AuditEvent>(line.trim()).ok())
        .filter(|event| !is_prune_point(event))
        .filter_map(|event| event.seq.map(|seq| (seq, event)))
        .collect();
    candidates.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));

    for (seq, event) in &candidates {
        // `unwrap_or("default")` for the same reason `verify_chain` uses it: a
        // missing `key_id` is an entry from before the field existed, and
        // `"default"` is the id that epoch always carried.
        let key_id = event.key_id.as_deref().unwrap_or("default");
        let Some(secret) = keyring.get(key_id) else {
            continue;
        };
        let RecomputedHash::Hash(recomputed) = compute_entry_hash(Some(secret), event) else {
            // Legacy (no `chain_version`) or a version this build cannot hash.
            // Either way this entry is not something to anchor the mark on.
            continue;
        };
        if event.entry_hash.as_deref() == Some(recomputed.as_str()) {
            return Some(*seq);
        }
    }
    None
}

/// Build the prune point that replaces the pruned range.
///
/// #457 Bug 1: this used to take a bare secret and write `key_id: "default"`
/// unconditionally. After a rotation, `"default"` names the *epoch-1* key
/// (`secret::load_keyring`), so the entry was signed with one key and labelled
/// with another — the verifier then recomputed its hash with the wrong key and
/// reported the chain as tampered. Taking a `SigningKey` makes the two
/// impossible to disagree: the same value supplies both the bytes and the id.
///
/// `now` is a parameter rather than `OffsetDateTime::now_utc()` because the
/// enclosing `try_prune_at` already threads a deterministic clock through for
/// tests; leaving this one call non-deterministic made a byte-level golden
/// test of the prune point structurally impossible to write.
pub(super) fn build_prune_point(
    signing_key: &SigningKey,
    prune_count: u64,
    first_retained_hash: &str,
    now: OffsetDateTime,
) -> AuditEvent {
    let secret = signing_key.secret();
    let target_hash = hmac_bytes(
        secret,
        format!("prune-bind:{prune_count}:{first_retained_hash}").as_bytes(),
    );

    let mut event = AuditEvent {
        timestamp: now
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
        key_id: Some(signing_key.id.clone()),
        entry_hash: None,
        pid: None,
        ppid: None,
        parent_process: None,
        cwd_hash: None,
        wrapper_kind: None,
    };
    event.entry_hash = Some(compute_entry_hash_for_write(secret, &event));
    event
}

pub(super) fn is_prune_point(event: &AuditEvent) -> bool {
    event.command == PRUNE_COMMAND && event.action == PRUNE_ACTION && event.result == PRUNE_RESULT
}
