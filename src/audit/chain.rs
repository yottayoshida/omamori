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

pub(super) const CHAIN_VERSION: u32 = 2;
pub(super) const GENESIS_SEED: &[u8] = b"omamori-genesis-v1";
pub(super) const PRUNE_GENESIS_SEED: &[u8] = b"omamori-prune-v1";

/// Every `chain_version` this binary can recompute a hash for. Shared by
/// `read_chain_state` (append-side tail check) and `verify_chain`'s
/// raw-JSON fallback peek (`verify.rs`) — before #177 B3 these two each
/// independently compared against the single `CHAIN_VERSION` constant, so
/// bumping it to `2` without this shared set would have required editing
/// both in lockstep with no compiler check that neither was missed.
///
/// `compute_entry_hash`'s `match` below is a THIRD place that must agree
/// with this array — its arms are literal (`Some(1) => hash_v1`, not
/// `Some(v) if is_supported_chain_version(v) => ...`) because each
/// supported version dispatches to a different hasher, which an array
/// membership check can't express. Adding a version to this array without
/// adding a matching arm there would let `read_chain_state`/`verify_chain`
/// treat the version as safe to append-after / worth authenticating, while
/// `compute_entry_hash` still reports `UnsupportedVersion` for it —
/// `all_supported_chain_versions_produce_a_hash` (mod.rs test) exists
/// specifically to catch that split at test time instead of in production.
///
/// `verify_chain`'s own `v1_entries`/`v2_entries` tally (`verify.rs`) is a
/// FOURTH place with the same literal-match shape, for the same reason
/// (each version increments a different counter). Security review (#177
/// B3): the two safety nets are asymmetric by construction —
/// `all_supported_chain_versions_produce_a_hash` catches a version added to
/// this array without a `compute_entry_hash` arm, but NOT the reverse (a
/// `compute_entry_hash` arm added without updating this array first) —
/// that entry would hash and verify successfully, then simply fall through
/// the tally `match`'s `_ => {}` arm uncounted rather than crash
/// verification (deliberately not `unreachable!()`, see that match's own
/// comment).
pub(super) const SUPPORTED_CHAIN_VERSIONS: [u32; 2] = [1, 2];

pub(super) fn is_supported_chain_version(v: u32) -> bool {
    SUPPORTED_CHAIN_VERSIONS.contains(&v)
}

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
    /// `chain_version` is hardcoded to `1`, not read from `event` (contrast
    /// `HashableEventV2::from_event` below, hardcoded to `2`) — #177 B3:
    /// `event.chain_version.unwrap_or(CHAIN_VERSION)` meant "trust the
    /// caller, default to whatever the current binary considers current."
    /// That default silently pointed at V2 the moment `CHAIN_VERSION`
    /// flipped, so a `None`-chain_version event handed to this V1 hasher
    /// (which cannot occur in production — `compute_entry_hash` routes
    /// `None` to `Legacy` first — but can occur from fixture/mutation-test
    /// code that constructs a `HashableEvent` directly) would silently hash
    /// as V2 dressed in V1's field set instead of failing loudly. Hardcoding
    /// removes the ambiguity structurally: this function only ever means V1.
    pub(super) fn from_event(event: &AuditEvent) -> Self {
        Self {
            chain_version: 1,
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

/// Canonical representation of a `chain_version: 2` event for `entry_hash`
/// computation (#177 B3). Extends `HashableEvent` (V1)'s 15 fields with the
/// 5 fields that were previously excluded from chain integrity by design
/// (ADR-0006's Design A for `pid`/`ppid`/`parent_process`/`cwd_hash`, and
/// `wrapper_kind`'s equivalent B2-era exclusion) — appended in the same
/// relative order they already appear in `AuditEvent`. Field order is fixed
/// by struct definition order (serde guarantee) and locked by golden test
/// GR-002-V2; unlike V1 fields, these 5 are pairwise same-typed
/// (`Option<u32>` × 2, `Option<String>` × 3), so a field-swap bug (e.g.
/// `ppid: event.pid`) would silently pass a golden fixture where all 5 are
/// `None` — the GR-002-V2 fixture therefore uses 5 distinct non-`None`
/// values, never all-`None`.
#[derive(Serialize)]
pub(super) struct HashableEventV2 {
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
    pid: Option<u32>,
    ppid: Option<u32>,
    parent_process: Option<String>,
    cwd_hash: Option<String>,
    wrapper_kind: Option<String>,
}

impl HashableEventV2 {
    pub(super) fn from_event(event: &AuditEvent) -> Self {
        Self {
            chain_version: 2,
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
            pid: event.pid,
            ppid: event.ppid,
            parent_process: event.parent_process.clone(),
            cwd_hash: event.cwd_hash.clone(),
            wrapper_kind: event.wrapper_kind.clone(),
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
        Some(1) => RecomputedHash::Hash(hash_v1(secret, event)),
        Some(2) => RecomputedHash::Hash(hash_v2(secret, event)),
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

fn hash_v2(secret: Option<&[u8; 32]>, event: &AuditEvent) -> String {
    let canonical = serde_json::to_string(&HashableEventV2::from_event(event))
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

/// Extract `chain_version` from a raw JSON value as a plausible `u32`.
/// `None` covers both "no `chain_version` key at all" (legacy entry) and
/// "present but not a valid `u32`" (corruption) — callers that need to
/// distinguish those two treat `None` as legacy/corrupt either way, so one
/// shared coercion is enough. `#177 B1`: `read_chain_state` (append-side
/// tail check) and `verify_chain`'s raw-JSON fallback (an entry whose
/// *shape* a future `chain_version` might break `AuditEvent`'s Deserialize
/// for) both need this same peek before trusting a typed parse — factored
/// out (Codex simplify pass) after both independently reimplemented it.
pub(super) fn parse_chain_version(raw: &serde_json::Value) -> Option<u32> {
    raw.get("chain_version")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
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
    match parse_chain_version(&parsed) {
        // Absent or malformed chain_version → legacy entry or corruption,
        // either way safe to restart from genesis.
        None => ChainTailState::Fresh { genesis },
        // #177 B3: any *supported* version's tail is safe to append after
        // — not just the current CHAIN_VERSION. A v1 tail must accept a v2
        // append (shape enumeration F-D, the single most common post-
        // upgrade shape) without being misclassified as unsupported.
        Some(chain_version) if !is_supported_chain_version(chain_version) => {
            ChainTailState::UnsupportedVersion { chain_version }
        }
        Some(_) => match (parsed.get("seq"), parsed.get("entry_hash")) {
            (Some(seq_val), Some(hash_val)) => match (seq_val.as_u64(), hash_val.as_str()) {
                (Some(seq), Some(hash)) if !hash.is_empty() => ChainTailState::Ready {
                    last_seq: seq,
                    last_hash: hash.to_string(),
                },
                // Malformed chain entry → treat as corruption, restart from genesis
                _ => ChainTailState::Fresh { genesis },
            },
            _ => ChainTailState::Fresh { genesis },
        },
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
