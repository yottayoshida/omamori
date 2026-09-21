//! Hash chain computation for audit log integrity.
//!
//! SECURITY: `HashableEvent` field order is locked by a golden test (GR-002).
//! DO NOT reorder fields without bumping `CHAIN_VERSION` and understanding the
//! chain compatibility impact on existing audit.jsonl files.

use std::fs;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use super::AuditEvent;

pub(super) type HmacSha256 = Hmac<Sha256>;

pub(super) const CHAIN_VERSION: u32 = 2;
pub(super) const GENESIS_SEED: &[u8] = b"omamori-genesis-v1";
pub(super) const PRUNE_GENESIS_SEED: &[u8] = b"omamori-prune-v1";

/// Every `chain_version` this binary can recompute a hash for. Shared by
/// `read_chain_state` (append-side tail check), `verify_chain`'s version
/// dispatch (`verify.rs`) and the prune scan (`retention.rs`) — before #177 B3
/// the first two each independently compared against the single
/// `CHAIN_VERSION` constant, so bumping it to `2` without this shared set
/// would have required editing both in lockstep with no compiler check that
/// neither was missed. All three read the version itself through
/// [`VersionPeek`] (#556).
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

/// The hash value written when there is no key to sign with.
///
/// #483 turned this from a display detail into a load-bearing one: it is one of
/// the two pieces of evidence the verifier requires before treating an entry as
/// never-protected rather than as unverifiable. Three sites produce it and now
/// a fourth compares against it, and a literal repeated four times is one edit
/// away from two of them disagreeing — where the failure mode is a store pinned
/// at cannot-verify permanently, which is the defect being closed.
pub(super) const NO_HMAC_SECRET: &str = "NO_HMAC_SECRET";

pub(super) fn hmac_bytes(secret: Option<&[u8; 32]>, data: &[u8]) -> String {
    let Some(key) = secret else {
        return NO_HMAC_SECRET.to_string();
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
///
/// `#456`: `Ready` carries the seq the next append must *use*, not the
/// tail's own seq. The increment happens here, beside the range check that
/// makes it valid, so no caller is left holding a number it still has to
/// add one to. The tail's seq is read off disk and is *unauthenticated* —
/// this function never verifies `entry_hash`, so any value can be planted
/// by writing one line — and `u64::MAX + 1` is not representable: without
/// `overflow-checks` it wraps to 0, where the wrapped seq reads as (or
/// masks) tail truncation against the high-water-mark; with
/// `overflow-checks` it panics. A tail that admits no successor is
/// reported as `SeqAtLimit` rather than incremented.
#[derive(Debug, PartialEq)]
pub(super) enum ChainTailState {
    /// The scan reached the start of the file, inside its limit, without
    /// finding a chain entry — safe to start a new chain from `genesis`.
    /// #465: this used to mean "the last line in the tail window was not a
    /// chain entry", which is now either a line read past or
    /// [`Self::NoEntryWithinLimit`].
    Fresh { genesis: String },
    /// Tail entry is a real, version-supported chain entry — safe to
    /// append with `seq = next_seq`, `prev_hash = last_hash`.
    Ready { next_seq: u64, last_hash: String },
    /// Tail entry declares an unsupported `chain_version` — not safe to
    /// append after it.
    UnsupportedVersion { chain_version: u32 },
    /// Tail entry's `seq` is the largest value a `u64` holds, so no
    /// successor number exists — not safe to append after it. Reaching this
    /// number by counting would take `u64::MAX` appends, so a chain that
    /// arrives here was not produced by appending alone. Note that omamori
    /// *will* write a `u64::MAX` entry itself if handed a tail numbered one
    /// below (the point being that the tail below it is equally unreachable),
    /// so this state does not identify who wrote the line.
    SeqAtLimit { seq: u64 },
    /// #465: no chain entry begins within the last `limit` bytes of the log —
    /// not safe to append. Reading past non-chain content has to stop
    /// somewhere: every byte read is time `hook-check` spends before it can
    /// print a deny, and past the host's hook timeout the deny is lost, which
    /// is the failure `flock_bounded` bounds lock acquisition to prevent.
    /// Stopping must not restart the chain either (that is the fork #465
    /// closes), so it refuses, like the two states above.
    NoEntryWithinLimit { limit: u64 },
}

/// Where an append should resume from: the state of the log's **last chain
/// entry**, however much non-chain content follows it.
///
/// #465: this used to be "the last line within a 64 KB tail window that
/// parses as a JSON object", and anything that window did not contain — or
/// contained but could not read as a chain entry — became `Fresh`, which
/// restarts the chain from genesis at `seq 0`. Four shapes reached that arm:
/// no parseable line in the window, a line without `chain_version`, a
/// chain-shaped line without `seq`, and one with an empty `entry_hash`. The
/// first is the padding #465 describes; the other three are one planted line
/// each (`{"pad":1}` was enough). And omamori itself writes lines larger than
/// any fixed window — the hook path records the whole command text, and an
/// input rejected as too large is recorded in full — so a window turns a
/// genuine long entry at the tail into the same fork, which `verify` then
/// reports as a broken chain.
///
/// Now the scan walks backwards one line at a time, up to
/// [`TAIL_SCAN_LIMIT`] bytes from the end, and stops at the first line that
/// carries a `chain_version`. Every other line — torn, foreign JSON,
/// legacy-shaped, chain-shaped but missing the fields omamori always writes —
/// is read past. `Fresh` is returned only when the start of the file is
/// reached within the limit without finding one: a log with no chain entry in
/// it at all. When the limit is reached first, the answer is
/// [`ChainTailState::NoEntryWithinLimit`] — a refusal, never `Fresh`.
///
/// The limit is on bytes, not lines, and a line that *starts* before it is
/// not examined, so a single line longer than the limit is refused too. The
/// shim path records a program name; the hook path records the command text,
/// and the longest line on the four-month log #465 was measured against was
/// 46 KB. Measured for #465 on a release build: 63 MiB of two-byte lines, the
/// costliest shape per byte, is read past in 1.3 s.
///
/// No line is assembled in memory. The scan reads the file in fixed-size
/// chunks to find newline offsets. A candidate line that lies wholly inside
/// the chunk in hand is parsed from that chunk, with no further I/O; only a
/// line longer than what the chunk holds is streamed from the file through a
/// bounded reader. A typed peek skips the fields it does not name rather than
/// allocating them (the same reasoning `verify_chain`'s version dispatch
/// records for the peeks it shares with this scan), so the only value a line
/// leaves behind is the
/// `entry_hash` of the entry the scan stops at — 64 hex characters on
/// anything omamori wrote, and whatever length someone else put there.
///
/// Cost: one read per chunk rather than one per line, and each line costs its
/// own bytes of I/O once per peek stage it reaches — one for a line with no
/// `chain_version`, two for a supported version with no readable `seq`, three
/// for one carrying both. The stages are separate because a typed struct fails
/// as a whole (see [`SeqPeek`]).
///
/// **What this does not do**: authenticate the line it stops at. A line
/// shaped like a supported chain entry is taken at its word, as it always was
/// (`entry_hash` is checked for presence, not recomputed), so a same-user
/// attacker who can write one well-formed line can still lift a refusal.
/// SECURITY.md records that as the residual.
///
/// Read failures are returned, not swallowed: an `Err` here becomes an
/// append failure like any other I/O error, rather than a chain restarted
/// from genesis because a read happened to fail partway.
pub(super) fn read_chain_state(
    file: &mut fs::File,
    secret: Option<&[u8; 32]>,
) -> io::Result<ChainTailState> {
    read_chain_state_bounded(file, secret, TAIL_SCAN_CHUNK, TAIL_SCAN_LIMIT)
}

/// How far back from the end of the log `append` looks for the last chain
/// entry. See [`read_chain_state`] for why there is a limit and how it was
/// sized, and [`ChainTailState::NoEntryWithinLimit`] for what happens at it.
pub(super) const TAIL_SCAN_LIMIT: u64 = 64 * 1024 * 1024;

/// Bytes read at a time while scanning backwards for line ends. Every byte
/// of the scanned region is read once; the value only bounds memory.
const TAIL_SCAN_CHUNK: usize = 64 * 1024;

/// [`read_chain_state`] with the chunk size and the limit exposed, so tests
/// can drive every line-boundary case through a chunk a few bytes wide and
/// every limit-boundary case through a limit a few bytes long.
pub(super) fn read_chain_state_bounded(
    file: &mut fs::File,
    secret: Option<&[u8; 32]>,
    chunk: usize,
    limit: u64,
) -> io::Result<ChainTailState> {
    let len = file.metadata()?.len();
    let mut newlines = ReverseNewlines::new(len, chunk, limit);
    let mut end = len;
    loop {
        let boundary = newlines.previous(file, end)?;
        let start = match boundary {
            Boundary::Newline(n) => n + 1,
            Boundary::StartOfFile => 0,
            Boundary::BeyondLimit => return Ok(ChainTailState::NoEntryWithinLimit { limit }),
        };
        if start < end {
            let line = match newlines.slice(start, end) {
                Some(bytes) => Line::Buffered(bytes),
                None => Line::OnDisk { start, end },
            };
            if let Some(state) = classify_line(file, &line)? {
                return Ok(state);
            }
        }
        match boundary {
            Boundary::Newline(n) => end = n,
            // The genesis hash is computed here rather than up front: it is
            // needed only by this arm, and `append` runs for every guarded
            // command.
            Boundary::StartOfFile => {
                return Ok(ChainTailState::Fresh {
                    genesis: genesis_hash(secret),
                });
            }
            // Returned above, before the line is classified. Spelled out
            // rather than folded into the arm above it: sharing that arm would
            // make the limit answer `Fresh` — a chain restarted from genesis
            // behind whatever filled those 64 MiB — the moment the early
            // return moved (review, P2).
            Boundary::BeyondLimit => return Ok(ChainTailState::NoEntryWithinLimit { limit }),
        }
    }
}

/// Stage one of the peek: only `chain_version`. Kept separate from
/// [`SeqPeek`] and [`HashPeek`] on purpose — a typed struct fails as a whole
/// when any field it names has the wrong type, and #177 B1 requires an entry
/// from a future format to be refused *whatever* shape its `seq` or
/// `entry_hash` take (or whether it has them). Peeking all three at once would
/// let such a line fail the peek, be read past, and fork the chain behind it —
/// the hole the refusal exists to close.
///
/// #556: `append`, `verify_chain` and the prune scan all decide whether a line
/// declares a chain version this build does not recognize through this peek,
/// before they read the line as an `AuditEvent`, so they cannot disagree about
/// a line the way they did through 1.2.0 — `verify_chain` read
/// `chain_version` and `seq` through one struct, and a `seq` of the wrong type
/// made it count as torn a line this scan refused to write behind.
#[derive(serde::Deserialize)]
pub(super) struct VersionPeek {
    pub(super) chain_version: Option<u32>,
}

/// Read one audit-log line as `T`, provided the line is a JSON object.
///
/// #556: every reader of `audit.jsonl` that types a line goes through here —
/// or through [`ObjectOnly`] directly, for the append scan's streamed lines —
/// so a line `verify_chain` counts as torn is never one `audit show`, `report`
/// or the prune scan reads as an event. The one exception is the loop in
/// `try_prune_at_collect` that finds where the retained range starts: it reads
/// `timestamp`, `command` and `entry_hash` off a `serde_json::Value`, whose
/// `get` is `None` on anything but an object, so an array is not a keeper there
/// either. A derived `Deserialize` also accepts a JSON array,
/// positionally: `[999]` read as `chain_version: 999`, and a whole entry
/// written as an array read as that entry. omamori never writes an array, and
/// through 1.2.0 the readers disagreed about them — `append` refused behind
/// `[999]` while `verify_chain` counted it torn.
pub(super) fn parse_line<T: serde::de::DeserializeOwned>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str::<ObjectOnly<T>>(line).map(|ObjectOnly(value)| value)
}

/// `T`, deserialized only from a JSON object. See [`parse_line`].
///
/// `T`'s own `Deserialize` still does the reading — a derived one keeps
/// refusing duplicate keys, skipping fields it does not name without
/// materializing them, and reading an absent `Option` as `None`. This only
/// decides which JSON values reach it: serde_json answers `deserialize_map`
/// with a type error for anything but `{`, where `deserialize_struct` (what a
/// derive calls) also accepts `[`.
pub(super) struct ObjectOnly<T>(pub(super) T);

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for ObjectOnly<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = ObjectOnly<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(ObjectOnly)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}

/// Stage two: `seq` alone, read only after stage one found a version. Alone
/// for the reason [`VersionPeek`] is alone, one field further in: #456 decides
/// whether a successor exists from `seq` and *before* `entry_hash`'s shape,
/// and a typed struct naming both fields fails as a whole — an `entry_hash` of
/// the wrong JSON type took the `seq` decision down with it, so a tail at
/// `u64::MAX` was read past instead of refused (#465 review, P1).
///
/// `verify_chain` reads it for the position of an unrecognized-version entry
/// (#556) and for the end the lines past a halt state (#470). A `seq` that
/// does not read as a `u64` is `None` there too: no position is stated.
#[derive(serde::Deserialize)]
pub(super) struct SeqPeek {
    pub(super) seq: Option<u64>,
}

/// Stage three: `entry_hash` alone, read only once a successor number exists.
#[derive(serde::Deserialize)]
struct HashPeek {
    entry_hash: Option<String>,
}

/// Where a candidate line's bytes are.
enum Line<'a> {
    /// Wholly inside the chunk the scan is holding: parsed with no I/O.
    Buffered(&'a [u8]),
    /// Extends past that chunk: streamed from `[start, end)` of the file.
    OnDisk { start: u64, end: u64 },
}

/// Decide what one line says about where the chain ends. `None` means "not a
/// chain entry omamori would have written — keep scanning".
fn classify_line(file: &mut fs::File, line: &Line<'_>) -> io::Result<Option<ChainTailState>> {
    // Absent, `null`, wrong JSON type, beyond `u32`, not an object, not JSON
    // at all: none of these is a chain entry here. `verify_chain` reads most
    // of them as torn lines, and a full `AuditEvent` whose `chain_version` is
    // absent or `null` as legacy — which it fails closed on once the chain has
    // started. The two do not classify identically; what matters is the
    // direction: a line this reads past is never one `verify_chain` counts as
    // an authenticated entry.
    let Some(VersionPeek {
        chain_version: Some(version),
    }) = peek::<VersionPeek>(file, line)?
    else {
        return Ok(None);
    };
    // #177 B1 step 3: decided before anything else about the line is read.
    // Restarting from genesis here would fork a second, disconnected chain in
    // the same file with no record that the original continued past this
    // point; chaining onto an earlier entry would do the same.
    if !is_supported_chain_version(version) {
        return Ok(Some(ChainTailState::UnsupportedVersion {
            chain_version: version,
        }));
    }
    let Some(SeqPeek { seq: Some(seq) }) = peek::<SeqPeek>(file, line)? else {
        // A supported version with no readable `seq` is not something omamori
        // writes (every writer sets it); the line is read past.
        return Ok(None);
    };
    // #456: the successor is computed here, and *before* `entry_hash` is read
    // at all — `checked_add` stays the single arbiter of whether a successor
    // exists, and a tail at the limit is refused whatever its hash looks like,
    // including a hash that is not a string.
    let Some(next_seq) = seq.checked_add(1) else {
        return Ok(Some(ChainTailState::SeqAtLimit { seq }));
    };
    // #465: an `entry_hash` that is missing, empty, or not a string used to
    // restart the chain from genesis. omamori never writes one (an entry it
    // could not sign carries the `NO_HMAC_SECRET` sentinel, which is not
    // empty), so this is read past like any other foreign line.
    let Some(HashPeek {
        entry_hash: Some(hash),
    }) = peek::<HashPeek>(file, line)?
    else {
        return Ok(None);
    };
    Ok((!hash.is_empty()).then_some(ChainTailState::Ready {
        next_seq,
        last_hash: hash,
    }))
}

/// Deserialize `T` from one line. `Ok(None)` is a parse failure (the line is
/// not `T`-shaped); `Err` is an I/O failure, which the caller must not mistake
/// for the former. The two sources must classify a line identically — the
/// scan's answer cannot depend on where a chunk boundary happened to fall, and
/// `tail_scan_tests` drives every case through both.
fn peek<T: serde::de::DeserializeOwned>(
    file: &mut fs::File,
    line: &Line<'_>,
) -> io::Result<Option<T>> {
    // `ObjectOnly`, like every other reader of the log (see `parse_line`).
    let parsed = match *line {
        Line::Buffered(bytes) => serde_json::from_slice::<ObjectOnly<T>>(bytes),
        Line::OnDisk { start, end } => {
            file.seek(SeekFrom::Start(start))?;
            serde_json::from_reader::<_, ObjectOnly<T>>(BufReader::new(
                file.by_ref().take(end - start),
            ))
        }
    };
    match parsed {
        Ok(ObjectOnly(value)) => Ok(Some(value)),
        Err(e) => match e.io_error_kind() {
            Some(kind) => Err(io::Error::new(kind, e)),
            None => Ok(None),
        },
    }
}

/// What precedes a line, walking backwards.
enum Boundary {
    /// A `\n` at this offset; the line starts just after it.
    Newline(u64),
    /// The start of the file, within the limit; the line starts at 0.
    StartOfFile,
    /// The line starts before the limit's floor and is not examined.
    BeyondLimit,
}

/// Walks a file backwards looking for `\n`, keeping one chunk in memory and
/// never reading below `limit` bytes from the end (plus the one byte that says
/// whether a line starts exactly at that floor).
///
/// `previous(before)` finds the last newline strictly before `before`. Calls
/// must pass non-increasing `before` values (each the offset the previous call
/// returned), which is how the caller walks lines from the end: the window
/// only ever moves towards the start of the file, and each byte is read once.
struct ReverseNewlines {
    /// File offset of `buf[0]`.
    win_start: u64,
    buf: Vec<u8>,
    chunk: usize,
    /// The first offset a line may start at and still be examined.
    floor: u64,
    /// The lowest offset read: one below `floor`, so a `\n` there — a line
    /// starting exactly at the floor — is seen.
    lowest: u64,
}

impl ReverseNewlines {
    fn new(len: u64, chunk: usize, limit: u64) -> Self {
        let floor = len.saturating_sub(limit);
        Self {
            win_start: len,
            buf: Vec::new(),
            chunk: chunk.max(1),
            floor,
            lowest: floor.saturating_sub(1),
        }
    }

    fn previous(&mut self, file: &mut fs::File, before: u64) -> io::Result<Boundary> {
        let mut hi = before;
        loop {
            let win_end = self.win_start + self.buf.len() as u64;
            if hi > self.win_start && hi <= win_end {
                let rel = (hi - self.win_start) as usize;
                if let Some(i) = self.buf[..rel].iter().rposition(|&b| b == b'\n') {
                    return Ok(Boundary::Newline(self.win_start + i as u64));
                }
            }
            if self.win_start <= self.lowest {
                return Ok(if self.floor == 0 {
                    Boundary::StartOfFile
                } else {
                    Boundary::BeyondLimit
                });
            }
            let new_start = self
                .win_start
                .saturating_sub(self.chunk as u64)
                .max(self.lowest);
            let read_len = (self.win_start - new_start) as usize;
            self.buf.resize(read_len, 0);
            file.seek(SeekFrom::Start(new_start))?;
            file.read_exact(&mut self.buf)?;
            hi = self.win_start;
            self.win_start = new_start;
        }
    }

    /// The bytes `[start, end)`, if the chunk in hand holds all of them.
    fn slice(&self, start: u64, end: u64) -> Option<&[u8]> {
        let win_end = self.win_start + self.buf.len() as u64;
        (start >= self.win_start && end <= win_end)
            .then(|| &self.buf[(start - self.win_start) as usize..(end - self.win_start) as usize])
    }
}

#[cfg(test)]
mod tail_scan_tests {
    use super::*;
    use std::io::Write;

    const SECRET: [u8; 32] = [0x42u8; 32];

    /// One directory per fixture name, as `mod.rs`'s `test_dir` does — the
    /// #344 invariant wants the name built at exactly one site.
    fn scan_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("omamori-tail-scan-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file_with(name: &str, content: &[u8]) -> fs::File {
        let path = scan_dir(name).join("audit.jsonl");
        fs::write(&path, content).unwrap();
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap()
    }

    fn entry(seq: u64, hash: &str) -> String {
        format!(r#"{{"chain_version":{CHAIN_VERSION},"seq":{seq},"entry_hash":"{hash}"}}"#)
    }

    fn ready(seq: u64, hash: &str) -> ChainTailState {
        ChainTailState::Ready {
            next_seq: seq + 1,
            last_hash: hash.to_string(),
        }
    }

    /// Every chunk size from 1 byte up must give the same answer: the scan's
    /// correctness cannot depend on where the chunk boundaries fall.
    fn for_all_chunks(name: &str, content: &[u8], expected: &ChainTailState) {
        for chunk in [1usize, 2, 3, 5, 7, 64, 4096, TAIL_SCAN_CHUNK] {
            let mut file = file_with(name, content);
            let got = read_chain_state_bounded(&mut file, Some(&SECRET), chunk, u64::MAX).unwrap();
            assert_eq!(&got, expected, "{name}: chunk={chunk}");
        }
        let _ = fs::remove_dir_all(scan_dir(name));
    }

    #[test]
    fn last_line_is_the_entry_with_and_without_a_trailing_newline() {
        let e = entry(4, "h4");
        for_all_chunks(
            "trailing-nl",
            format!("junk\n{e}\n").as_bytes(),
            &ready(4, "h4"),
        );
        for_all_chunks(
            "no-trailing-nl",
            format!("junk\n{e}").as_bytes(),
            &ready(4, "h4"),
        );
    }

    #[test]
    fn the_entry_on_the_first_line_is_found_behind_non_chain_lines() {
        let e = entry(0, "h0");
        let content = format!("{e}\n\n{{\"pad\":1}}\nnot json\n\r\n[1,2]\n5\n");
        for_all_chunks("first-line", content.as_bytes(), &ready(0, "h0"));
    }

    #[test]
    fn crlf_line_endings_are_read_past_and_the_entry_still_parses() {
        let e = entry(2, "h2");
        let content = format!("{e}\r\njunk\r\n{{\"pad\":1}}\r\n");
        for_all_chunks("crlf", content.as_bytes(), &ready(2, "h2"));
    }

    #[test]
    fn a_file_with_no_chain_entry_is_fresh_however_much_it_holds() {
        let genesis = ChainTailState::Fresh {
            genesis: genesis_hash(Some(&SECRET)),
        };
        for_all_chunks("empty", b"", &genesis);
        for_all_chunks("only-newlines", b"\n\n\n", &genesis);
        for_all_chunks(
            "only-junk",
            b"a\nbb\n{\"pad\":1}\n{\"chain_version\":null}\n",
            &genesis,
        );
        let legacy = r#"{"timestamp":"t","provider":"p","command":"c","action":"a","result":"r","target_count":0,"target_hash":"h"}"#;
        for_all_chunks(
            "legacy-only",
            format!("{legacy}\n{legacy}\n").as_bytes(),
            &genesis,
        );
    }

    #[test]
    fn a_line_far_longer_than_the_chunk_is_read_through_not_assembled() {
        // A 300 KB command in the entry, then 200 KB of one unbroken junk line.
        let big = "x".repeat(300 * 1024);
        let e = format!(
            r#"{{"chain_version":{CHAIN_VERSION},"command":"{big}","seq":9,"entry_hash":"h9"}}"#
        );
        let content = format!("{e}\n{}\n", "y".repeat(200 * 1024));
        for chunk in [3usize, 4096, TAIL_SCAN_CHUNK] {
            let mut file = file_with("long-lines", content.as_bytes());
            let got = read_chain_state_bounded(&mut file, Some(&SECRET), chunk, u64::MAX).unwrap();
            assert_eq!(got, ready(9, "h9"), "chunk={chunk}");
        }
        let _ = fs::remove_dir_all(scan_dir("long-lines"));
    }

    #[test]
    fn an_unknown_version_refuses_whatever_shape_its_other_fields_take() {
        // #177 B1 via #465 review: the version is decided before `seq` or
        // `entry_hash` are read, so a future format that changed their shape
        // is still refused rather than read past.
        let real = entry(1, "h1");
        let future = r#"{"chain_version":999,"seq":"seven","entry_hash":{"nested":true}}"#;
        let content = format!("{real}\n{future}\n");
        for_all_chunks(
            "future-odd-shape",
            content.as_bytes(),
            &ChainTailState::UnsupportedVersion { chain_version: 999 },
        );
    }

    #[test]
    fn chain_shaped_lines_omamori_never_writes_are_read_past() {
        let real = entry(3, "h3");
        for (name, planted) in [
            (
                "no-seq",
                format!(r#"{{"chain_version":{CHAIN_VERSION},"entry_hash":"x"}}"#),
            ),
            (
                "empty-hash",
                format!(r#"{{"chain_version":{CHAIN_VERSION},"seq":7,"entry_hash":""}}"#),
            ),
            (
                "no-hash",
                format!(r#"{{"chain_version":{CHAIN_VERSION},"seq":7}}"#),
            ),
            (
                "seq-wrong-type",
                format!(r#"{{"chain_version":{CHAIN_VERSION},"seq":"7","entry_hash":"x"}}"#),
            ),
            (
                "version-wrong-type",
                r#"{"chain_version":"2","seq":7,"entry_hash":"x"}"#.to_string(),
            ),
            (
                "version-beyond-u32",
                r#"{"chain_version":99999999999,"seq":7,"entry_hash":"x"}"#.to_string(),
            ),
            (
                "version-null",
                r#"{"chain_version":null,"seq":7,"entry_hash":"x"}"#.to_string(),
            ),
            ("trailing-garbage", format!("{} trailing", entry(7, "x"))),
            (
                "duplicate-version-key",
                r#"{"chain_version":2,"chain_version":2,"seq":7,"entry_hash":"x"}"#.to_string(),
            ),
        ] {
            let content = format!("{real}\n{planted}\n");
            for_all_chunks(name, content.as_bytes(), &ready(3, "h3"));
        }
    }

    /// `chunk = 1` streams every line from the file; `TAIL_SCAN_CHUNK` parses
    /// every short line from memory. serde_json's slice and reader front ends
    /// are separate code, so the inputs where they could plausibly diverge —
    /// bytes that are not UTF-8, inside an ignored string and inside a key; a
    /// lone surrogate escape; leading whitespace and a BOM; a NUL; a line that
    /// is only a prefix of an object — are run through both, and each must
    /// agree with the other whatever that answer is.
    #[test]
    fn buffered_and_streamed_lines_are_classified_alike() {
        let real = entry(3, "h3");
        let odd: Vec<Vec<u8>> = vec![
            [
                &br#"{"chain_version":2,"command":""#[..],
                &[0xff, 0xfe],
                &br#"","seq":7,"entry_hash":"x"}"#[..],
            ]
            .concat(),
            [
                &br#"{"chain_"#[..],
                &[0xff],
                &br#"version":999,"seq":7,"entry_hash":"x"}"#[..],
            ]
            .concat(),
            br#"{"chain_version":2,"command":"\ud800","seq":7,"entry_hash":"x"}"#.to_vec(),
            br#"   {"chain_version":2,"seq":7,"entry_hash":"x"}   "#.to_vec(),
            [
                &[0xef, 0xbb, 0xbf][..],
                &br#"{"chain_version":999,"seq":7,"entry_hash":"x"}"#[..],
            ]
            .concat(),
            [
                &br#"{"chain_version":2,"seq":7,"entry_hash":"x"#[..],
                &[0x00],
                &br#""}"#[..],
            ]
            .concat(),
            br#"{"chain_version":999,"seq":7"#.to_vec(),
            br#"{"chain_version":999,"seq":7,"entry_hash":"x"}"#.to_vec(),
        ];
        for (i, planted) in odd.iter().enumerate() {
            let content = [real.as_bytes(), b"\n", planted, b"\n"].concat();
            let name = format!("alike-{i}");
            let mut file = file_with(&name, &content);
            let buffered =
                read_chain_state_bounded(&mut file, Some(&SECRET), TAIL_SCAN_CHUNK, u64::MAX)
                    .unwrap();
            let mut file = file_with(&name, &content);
            let streamed = read_chain_state_bounded(&mut file, Some(&SECRET), 1, u64::MAX).unwrap();
            assert_eq!(buffered, streamed, "case {i}: the two sources disagree");
            let _ = fs::remove_dir_all(scan_dir(&name));
        }
    }

    /// The limit counts back from the end of the file, and a line is examined
    /// only if it *starts* within it. Each case is one byte either side of an
    /// edge, run through every chunk size.
    #[test]
    fn a_chain_entry_is_found_only_if_it_starts_within_the_limit() {
        let fresh = || ChainTailState::Fresh {
            genesis: genesis_hash(Some(&SECRET)),
        };
        let refused = |limit| ChainTailState::NoEntryWithinLimit { limit };
        let e = entry(5, "h5");
        let junk = "j\n{\"pad\":1}\nzz\n";

        // Entry on the first line (starts at 0).
        let content = format!("{e}\n{junk}");
        let len = content.len() as u64;
        let cases: Vec<(&str, String, u64, ChainTailState)> = vec![
            (
                "first-line-limit-eq-len",
                content.clone(),
                len,
                ready(5, "h5"),
            ),
            (
                "first-line-limit-len-minus-1",
                content.clone(),
                len - 1,
                refused(len - 1),
            ),
            // Entry starting at offset 2, after "x\n".
            ("at-floor", format!("x\n{e}\n{junk}"), len, ready(5, "h5")),
            (
                "one-below-floor",
                format!("x\n{e}\n{junk}"),
                len - 1,
                refused(len - 1),
            ),
            // No chain entry at all.
            (
                "no-entry-shorter-than-limit",
                junk.to_string(),
                junk.len() as u64 + 1,
                fresh(),
            ),
            (
                "no-entry-limit-eq-len",
                junk.to_string(),
                junk.len() as u64,
                fresh(),
            ),
            (
                "no-entry-longer-than-limit",
                junk.to_string(),
                junk.len() as u64 - 1,
                refused(junk.len() as u64 - 1),
            ),
            // One unbroken line longer than the limit: no newline is found
            // within it, and nothing below the floor is read.
            (
                "unbroken-line-past-the-limit",
                format!("{e}\n{}", "y".repeat(40)),
                30,
                refused(30),
            ),
        ];
        for (name, content, limit, expected) in cases {
            for chunk in [1usize, 2, 3, 5, 7, 64, 4096, TAIL_SCAN_CHUNK] {
                let mut file = file_with(name, content.as_bytes());
                let got = read_chain_state_bounded(&mut file, Some(&SECRET), chunk, limit).unwrap();
                assert_eq!(got, expected, "{name}: chunk={chunk} limit={limit}");
            }
            let _ = fs::remove_dir_all(scan_dir(name));
        }
    }

    /// #456's order — `seq` decides, `entry_hash` is looked at afterwards —
    /// has to hold for every shape the hash can take, including shapes that do
    /// not deserialize as a string. Pairing the two fields in one peek made
    /// the hash's type able to suppress the refusal (#465 review, P1).
    #[test]
    fn the_seq_limit_is_refused_whatever_the_entry_hash_looks_like() {
        for (name, hash) in [
            ("empty", r#""""#),
            ("absent-and-trailing-comma-free", "null"),
            ("number", "0"),
            ("object", r#"{"nested":true}"#),
            ("array", "[1]"),
            ("valid", r#""h""#),
        ] {
            let content = format!(
                r#"{{"chain_version":{CHAIN_VERSION},"seq":{},"entry_hash":{hash}}}"#,
                u64::MAX
            );
            for_all_chunks(
                &format!("seq-limit-{name}"),
                format!("{content}\n").as_bytes(),
                &ChainTailState::SeqAtLimit { seq: u64::MAX },
            );
        }
        // Without `seq` at the limit, the same hashes are read past instead —
        // the control that keeps the test above from passing for the wrong
        // reason (a peek that fails is not a refusal).
        let real = entry(3, "h3");
        for (name, hash) in [("number", "0"), ("object", r#"{"nested":true}"#)] {
            let planted =
                format!(r#"{{"chain_version":{CHAIN_VERSION},"seq":7,"entry_hash":{hash}}}"#);
            for_all_chunks(
                &format!("hash-shape-{name}"),
                format!("{real}\n{planted}\n").as_bytes(),
                &ready(3, "h3"),
            );
        }
    }

    #[test]
    fn a_read_failure_is_an_error_not_a_fresh_chain() {
        // A handle opened write-only can be stat'ed but not read: the first
        // chunk read fails, and that must surface rather than become `Fresh`.
        let dir = scan_dir("write-only");
        let path = dir.join("audit.jsonl");
        let mut w = fs::File::create(&path).unwrap();
        writeln!(w, "{}", entry(0, "h0")).unwrap();
        drop(w);
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let err = read_chain_state_bounded(&mut file, Some(&SECRET), 4096, u64::MAX)
            .expect_err("a read that fails must not be reported as an empty log");
        assert_ne!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
