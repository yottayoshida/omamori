//! Hash chain computation for audit log integrity.
//!
//! SECURITY: `HashableEvent` field order is locked by a golden test (GR-002).
//! DO NOT reorder fields without bumping `CHAIN_VERSION` and understanding the
//! chain compatibility impact on existing audit.jsonl files.

use std::fs;
use std::io::{Read, Seek, SeekFrom};

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use super::AuditEvent;

pub(super) type HmacSha256 = Hmac<Sha256>;

pub(super) const CHAIN_VERSION: u32 = 1;
pub(super) const GENESIS_SEED: &[u8] = b"omamori-genesis-v1";
pub(super) const PRUNE_GENESIS_SEED: &[u8] = b"omamori-prune-v1";

// ---------------------------------------------------------------------------
// HashableEvent — canonical representation for entry_hash computation
// ---------------------------------------------------------------------------

/// Canonical representation of an event for entry_hash computation.
/// All fields are non-optional and always serialized (no skip_serializing_if).
/// Field order is fixed by struct definition order (serde guarantee).
#[derive(Serialize)]
pub(super) struct HashableEvent {
    chain_version: u32,
    seq: u64,
    prev_hash: String,
    key_id: String,
    timestamp: String,
    provider: String,
    command: String,
    rule_id: Option<String>,
    action: String,
    result: String,
    target_count: usize,
    target_hash: String,
    detection_layer: Option<String>,
    unwrap_chain: Option<Vec<String>>,
    raw_input_hash: Option<String>,
}

impl HashableEvent {
    pub(super) fn from_event(event: &AuditEvent) -> Self {
        Self {
            chain_version: event.chain_version.unwrap_or(CHAIN_VERSION),
            seq: event.seq.unwrap_or(0),
            prev_hash: event.prev_hash.clone().unwrap_or_default(),
            key_id: event.key_id.clone().unwrap_or_default(),
            timestamp: event.timestamp.clone(),
            provider: event.provider.clone(),
            command: event.command.clone(),
            rule_id: event.rule_id.clone(),
            action: event.action.clone(),
            result: event.result.clone(),
            target_count: event.target_count,
            target_hash: event.target_hash.clone(),
            detection_layer: event.detection_layer.clone(),
            unwrap_chain: event.unwrap_chain.clone(),
            raw_input_hash: event.raw_input_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Hash functions
// ---------------------------------------------------------------------------

pub(super) fn genesis_hash(secret: Option<&[u8; 32]>) -> String {
    hmac_bytes(secret, GENESIS_SEED)
}

pub(super) fn prune_genesis_hash(secret: Option<&[u8; 32]>) -> String {
    hmac_bytes(secret, PRUNE_GENESIS_SEED)
}

pub(super) fn compute_entry_hash(secret: Option<&[u8; 32]>, event: &AuditEvent) -> String {
    let canonical = serde_json::to_string(&HashableEvent::from_event(event))
        .expect("AuditEvent serialization cannot fail");
    hmac_bytes(secret, canonical.as_bytes())
}

pub(super) fn hmac_bytes(secret: Option<&[u8; 32]>, data: &[u8]) -> String {
    let Some(key) = secret else {
        return "NO_HMAC_SECRET".to_string();
    };
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    mac.update(data);
    format!("{:x}", mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Chain state reading
// ---------------------------------------------------------------------------

pub(super) fn read_chain_state(
    file: &mut fs::File,
    secret: Option<&[u8; 32]>,
) -> (Option<u64>, String) {
    let genesis = genesis_hash(secret);

    let last_line = match read_last_valid_line(file) {
        Some(line) => line,
        None => return (None, genesis),
    };

    let parsed: serde_json::Value = match serde_json::from_str(&last_line) {
        Ok(v) => v,
        Err(_) => return (None, genesis),
    };

    // Chain entry has chain_version + seq + entry_hash
    match (
        parsed.get("chain_version"),
        parsed.get("seq"),
        parsed.get("entry_hash"),
    ) {
        (Some(_cv), Some(seq_val), Some(hash_val)) => {
            match (seq_val.as_u64(), hash_val.as_str()) {
                (Some(seq), Some(hash)) if !hash.is_empty() => (Some(seq), hash.to_string()),
                // Malformed chain entry → treat as corruption, restart from genesis
                _ => (None, genesis),
            }
        }
        // Legacy entry (no chain fields) → new chain from genesis
        _ => (None, genesis),
    }
}

/// Read the last valid JSON line from the file, skipping torn (partial) lines.
/// Uses reverse scanning: reads the tail in 4KB chunks, doubling up to 64KB.
fn read_last_valid_line(file: &mut fs::File) -> Option<String> {
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }

    let mut chunk_size = 4096u64;
    loop {
        let start = len.saturating_sub(chunk_size);
        file.seek(SeekFrom::Start(start)).ok()?;
        let read_len = (len - start) as usize;
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf).ok()?;

        let text = String::from_utf8_lossy(&buf);
        // Scan from the end: first valid JSON line wins
        for line in text.lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                // Only accept JSON objects (reject scalars/arrays from mid-line fragments)
                if val.is_object() {
                    return Some(trimmed.to_string());
                }
            }
            // Non-empty but invalid JSON = torn line, keep scanning
        }

        if chunk_size >= 65536 || start == 0 {
            return None;
        }
        chunk_size *= 2;
    }
}
