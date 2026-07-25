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

/// Result of recomputing an entry's `entry_hash` for verification. Distinct
/// from a bare `String` (#177 B1) so a verifier can tell "this entry isn't
/// part of a chain at all" (`Legacy`) apart from "this entry claims a
/// `chain_version` this binary doesn't know how to hash" (`UnsupportedVersion`)
/// apart from "successfully recomputed, compare it" (`Hash`) — collapsing the
/// first two into "just doesn't match" is exactly the forward-compatibility
/// gap #177 exists to close (a future `chain_version` a v1-era binary can't
/// verify must not silently read as tampered, nor silently read as fine).
#[derive(Debug, PartialEq)]
pub(super) enum RecomputedHash {
    Hash(String),
    Legacy,
    UnsupportedVersion(u32),
}

impl RecomputedHash {
    /// Test/writer convenience: unwrap the `Hash` variant, panicking with a
    /// descriptive message otherwise. Only valid where the caller has
    /// already guaranteed `event.chain_version == Some(CHAIN_VERSION)` (a
    /// freshly-constructed event about to be written, or a test fixture
    /// that set it explicitly) — production *verification* code must not
    /// use this and must instead match on all three variants, since an
    /// entry read back from disk can claim any `chain_version`.
    #[cfg(test)]
    pub(super) fn expect_hash(self, context: &str) -> String {
        match self {
            Self::Hash(h) => h,
            other => panic!("{context}: expected RecomputedHash::Hash, got {other:?}"),
        }
    }
}

/// Recompute `entry_hash` for verification. Dispatches on the event's own
/// `chain_version` rather than trusting the caller's expectation — an event
/// read back from disk can claim any version, including one this binary
/// predates.
pub(super) fn compute_entry_hash(secret: Option<&[u8; 32]>, event: &AuditEvent) -> RecomputedHash {
    match event.chain_version {
        None => RecomputedHash::Legacy,
        Some(CHAIN_VERSION) => RecomputedHash::Hash(hash_v1(secret, event)),
        Some(other) => RecomputedHash::UnsupportedVersion(other),
    }
}

/// Writer-side: compute `entry_hash` for an event this process is about to
/// append or write as a prune point. Callers set `event.chain_version =
/// Some(CHAIN_VERSION)` immediately before calling this (see `append` /
/// `build_prune_point`), so `compute_entry_hash` always resolves to `Hash`
/// here — this wrapper exists so write call sites get a plain `String`
/// instead of matching a case that cannot occur for a freshly-constructed
/// event.
pub(super) fn compute_entry_hash_for_write(
    secret: Option<&[u8; 32]>,
    event: &AuditEvent,
) -> String {
    debug_assert_eq!(
        event.chain_version,
        Some(CHAIN_VERSION),
        "compute_entry_hash_for_write is for writer call sites only — \
         event.chain_version must already be set to the current CHAIN_VERSION"
    );
    match compute_entry_hash(secret, event) {
        RecomputedHash::Hash(h) => h,
        RecomputedHash::Legacy | RecomputedHash::UnsupportedVersion(_) => unreachable!(
            "writer call sites always set chain_version = Some(CHAIN_VERSION) before hashing"
        ),
    }
}

fn hash_v1(secret: Option<&[u8; 32]>, event: &AuditEvent) -> String {
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

/// Where an append should resume from, based on the file's current tail
/// entry. `#177 B1 step 3`: distinguishes "safe to append" (`Fresh` /
/// `Ready`) from "this tail entry declares a `chain_version` this binary
/// doesn't recognize" (`UnsupportedVersion`) — the caller must refuse to
/// append after the latter rather than silently resuming seq numbering
/// past, or chaining `prev_hash` onto, an entry it never verified.
#[derive(Debug, PartialEq)]
pub(super) enum ChainTailState {
    /// No prior chain entries (empty file, or the tail is legacy/malformed)
    /// — safe to start a new chain from `genesis`.
    Fresh { genesis: String },
    /// Tail entry is a real, version-supported chain entry — safe to
    /// append with `seq = last_seq + 1`, `prev_hash = last_hash`.
    Ready { last_seq: u64, last_hash: String },
    /// Tail entry declares an unsupported `chain_version` — not safe to
    /// append after it.
    UnsupportedVersion { chain_version: u32 },
}

pub(super) fn read_chain_state(file: &mut fs::File, secret: Option<&[u8; 32]>) -> ChainTailState {
    let genesis = genesis_hash(secret);

    let last_line = match read_last_valid_line(file) {
        Some(line) => line,
        None => return ChainTailState::Fresh { genesis },
    };

    let parsed: serde_json::Value = match serde_json::from_str(&last_line) {
        Ok(v) => v,
        Err(_) => return ChainTailState::Fresh { genesis },
    };

    // Codex Round 1 (#177 B1): check chain_version FIRST, independent of
    // whether seq/entry_hash are also present. A future chain_version's
    // entry shape might structure those fields differently (or omit them
    // entirely) — that must still refuse to append (UnsupportedVersion),
    // not silently restart the chain from genesis. Restarting would fork a
    // second, disconnected chain in the same file with no record that the
    // original one continued past this point.
    match parsed.get("chain_version") {
        None => ChainTailState::Fresh { genesis }, // legacy entry
        Some(cv) => {
            let Some(chain_version) = cv.as_u64().and_then(|v| u32::try_from(v).ok()) else {
                // chain_version present but not a plausible u32 → treat as
                // corruption, restart from genesis (matches the existing
                // malformed-entry fallback below).
                return ChainTailState::Fresh { genesis };
            };
            if chain_version != CHAIN_VERSION {
                return ChainTailState::UnsupportedVersion { chain_version };
            }
            match (parsed.get("seq"), parsed.get("entry_hash")) {
                (Some(seq_val), Some(hash_val)) => match (seq_val.as_u64(), hash_val.as_str()) {
                    (Some(seq), Some(hash)) if !hash.is_empty() => ChainTailState::Ready {
                        last_seq: seq,
                        last_hash: hash.to_string(),
                    },
                    // Malformed chain entry → treat as corruption, restart from genesis
                    _ => ChainTailState::Fresh { genesis },
                },
                _ => ChainTailState::Fresh { genesis },
            }
        }
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
