//! Audit logging with HMAC hash chain integrity.
//!
//! Split into focused submodules for v0.8.1 (#112):
//! - `chain`: Hash chain computation (HashableEvent, HMAC, genesis)
//! - `retention`: Automatic pruning of old entries
//! - `secret`: HMAC key management, symlink-safe I/O, key rotation
//! - `verify`: Chain verification, entry display, summary for CLI
//! - `report`: Aggregation for `omamori report` (v0.10.0, #221)

pub mod chain;
pub mod report;
pub mod retention;
pub mod secret;
pub mod verify;

// --- Public re-exports (maintain `omamori::audit::*` API paths) ---
pub use report::{ChainStatus, ReportAggregate, aggregate_report};
pub use secret::{RotationResult, rotate_key};
pub use verify::{
    AuditError, AuditSummary, ShowOptions, VerifyResult, audit_summary,
    count_unknown_tool_fail_opens_within, show_entries, verify_chain,
};

// --- Internal imports from submodules (used by AuditLogger + tests) ---
use chain::{CHAIN_VERSION, compute_entry_hash, read_chain_state};
use retention::{PRUNE_CHECK_INTERVAL, try_prune};
use secret::{
    current_key_id, default_audit_path, flock_exclusive, hmac_targets, load_or_create_secret,
    open_audit_rw, secret_path_for,
};

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actions::ActionOutcome;
use crate::rules::{CommandInvocation, RuleConfig};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub retention_days: u32,
    #[serde(default)]
    pub strict: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        }
    }
}

impl AuditConfig {
    /// Validate and clamp retention_days. Returns warnings if adjusted.
    pub fn validate(&self) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut config = self.clone();
        if config.retention_days > 0 && config.retention_days < retention::MIN_RETENTION_DAYS {
            warnings.push(format!(
                "audit.retention_days {} is below minimum {}; clamped to {}",
                config.retention_days,
                retention::MIN_RETENTION_DAYS,
                retention::MIN_RETENTION_DAYS
            ));
            config.retention_days = retention::MIN_RETENTION_DAYS;
        }
        (config, warnings)
    }
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

pub struct AuditLogger {
    pub(super) path: PathBuf,
    pub(super) secret: Option<[u8; 32]>,
    pub(super) retention_days: u32,
    pub(super) key_id: String,
}

impl AuditLogger {
    pub fn secret_available(&self) -> bool {
        self.secret.is_some()
    }

    pub fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let (validated, _warnings) = config.validate();
        let path = validated.path.clone().unwrap_or_else(default_audit_path);
        let secret = load_or_create_secret(&secret_path_for(&path));
        let key_id = current_key_id(&secret_path_for(&path));
        Some(Self {
            path,
            secret,
            retention_days: validated.retention_days,
            key_id,
        })
    }

    pub fn create_event(
        &self,
        invocation: &CommandInvocation,
        matched_rule: Option<&RuleConfig>,
        matched_detectors: &[String],
        outcome: &ActionOutcome,
    ) -> AuditEvent {
        let targets = invocation.target_args();
        AuditEvent {
            timestamp: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
            provider: matched_detectors
                .first()
                .cloned()
                .unwrap_or_else(|| "none".to_string()),
            command: invocation.program.clone(),
            rule_id: matched_rule.map(|rule| rule.name.clone()),
            action: matched_rule
                .map(|rule| rule.action.as_str().to_string())
                .unwrap_or_else(|| "passthrough".to_string()),
            result: outcome.label().to_string(),
            target_count: targets.len(),
            target_hash: hmac_targets(self.secret.as_ref(), &targets),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: None,
            seq: None,
            prev_hash: None,
            key_id: None,
            entry_hash: None,
        }
    }

    /// Append an event with hash-chain integrity.
    ///
    /// Takes ownership of the event to set chain fields (seq, prev_hash, entry_hash).
    /// Uses flock for concurrent-append safety.
    pub fn append(&self, mut event: AuditEvent) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // read+write+create without truncate: we read the tail for chain state, then append.
        #[allow(clippy::suspicious_open_options)]
        let mut file = open_audit_rw(&self.path)?;

        flock_exclusive(&file)?;

        // Read chain state under lock (another process may have appended since our open)
        let (last_seq, last_hash) = read_chain_state(&mut file, self.secret.as_ref());
        let seq = last_seq.map_or(0, |s| s + 1);

        // Set chain fields
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(seq);
        event.prev_hash = Some(last_hash);
        event.key_id = Some(self.key_id.clone());
        event.entry_hash = Some(compute_entry_hash(self.secret.as_ref(), &event));

        // Ensure new entry starts on its own line (torn lines may lack trailing newline)
        let len = file.seek(SeekFrom::End(0))?;
        if len > 0 {
            file.seek(SeekFrom::End(-1))?;
            let mut last_byte = [0u8; 1];
            file.read_exact(&mut last_byte)?;
            if last_byte[0] != b'\n' {
                file.seek(SeekFrom::End(0))?;
                writeln!(file)?;
            } else {
                file.seek(SeekFrom::End(0))?;
            }
        }

        serde_json::to_writer(&mut file, &event)?;
        writeln!(file)?;
        file.flush()?;

        // Auto-prune under the same flock (no extra I/O when not triggered)
        if self.retention_days > 0
            && seq > 0
            && seq % PRUNE_CHECK_INTERVAL == 0
            && let Err(e) = try_prune(&mut file, self.secret.as_ref(), self.retention_days)
        {
            eprintln!("omamori warning: audit prune failed: {e}");
        }

        // flock released on file drop
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub provider: String,
    pub command: String,
    pub rule_id: Option<String>,
    pub action: String,
    pub result: String,
    pub target_count: usize,
    pub target_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_input_hash: Option<String>,
    // --- Chain fields (None for legacy entries) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests — kept in mod.rs because test helpers and cross-submodule assertions
// need access to all submodule items via `use super::*`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{ActionKind, RuleConfig};
    use std::fs::OpenOptions;
    use std::path::Path;

    // Also import submodule internals needed by tests
    use chain::{HashableEvent, genesis_hash, prune_genesis_hash};
    use retention::{MIN_RETENTION_DAYS, build_prune_point, try_prune};
    use secret::{create_secret, decode_hex_secret, flock_exclusive, read_secret};
    use verify::{AuditError, display_timestamp};

    const TEST_SECRET: [u8; 32] = [0x42u8; 32];

    fn test_logger(dir: &Path) -> AuditLogger {
        let path = dir.join("audit.jsonl");

        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        AuditLogger {
            path,
            secret: Some(TEST_SECRET),
            retention_days: 0,
            key_id: "default".to_string(),
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omamori-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_event(command: &str) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: command.to_string(),
            rule_id: None,
            action: "passthrough".to_string(),
            result: "passthrough".to_string(),
            target_count: 0,
            target_hash: "hmac-sha256:test".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: None,
            seq: None,
            prev_hash: None,
            key_id: None,
            entry_hash: None,
        }
    }

    fn read_events(path: &Path) -> Vec<serde_json::Value> {
        let content = fs::read_to_string(path).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    // --- AuditLogger: from_config ---

    #[test]
    fn from_config_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        assert!(AuditLogger::from_config(&config).is_none());
    }

    #[test]
    fn from_config_enabled_creates_secret() {
        let dir = test_dir("from-config");
        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let logger = AuditLogger::from_config(&config).expect("should create logger");
        assert!(logger.secret.is_some());
        assert!(dir.join("audit-secret").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial]
    fn from_config_default_path() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let logger = AuditLogger::from_config(&config);
        assert!(logger.is_some(), "should create logger with default path");
    }

    // --- Hash chain: append builds chain ---

    #[test]
    fn chain_three_entries() {
        let dir = test_dir("chain3");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Verify monotonic seq
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event["seq"], i as u64);
        }
        // Verify prev_hash chain
        let genesis = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(events[0]["prev_hash"], genesis);
        assert_eq!(events[1]["prev_hash"], events[0]["entry_hash"]);
        assert_eq!(events[2]["prev_hash"], events[1]["entry_hash"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_genesis_hash_is_deterministic() {
        let a = genesis_hash(Some(&TEST_SECRET));
        let b = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(a, b);
    }

    #[test]
    fn chain_genesis_differs_by_secret() {
        let other = [0x99u8; 32];
        assert_ne!(genesis_hash(Some(&TEST_SECRET)), genesis_hash(Some(&other)));
    }

    #[test]
    fn chain_entry_hash_is_deterministic() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let h1 = compute_entry_hash(Some(&TEST_SECRET), &event);
        let h2 = compute_entry_hash(Some(&TEST_SECRET), &event);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_entry_hash_changes_on_tamper() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let h_orig = compute_entry_hash(Some(&TEST_SECRET), &event);
        event.result = "tampered".to_string();
        let h_tampered = compute_entry_hash(Some(&TEST_SECRET), &event);
        assert_ne!(h_orig, h_tampered);
    }

    #[test]
    fn chain_no_secret_uses_marker() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let hash = compute_entry_hash(None, &event);
        assert_eq!(hash, "NO_HMAC_SECRET");
    }

    // --- Legacy migration ---

    #[test]
    fn chain_after_legacy_entries() {
        let dir = test_dir("chain-legacy");
        let logger = test_logger(&dir);

        // Write a legacy entry (no chain fields) directly
        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old-cmd",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(&logger.path, serde_json::to_string(&legacy).unwrap() + "\n").unwrap();

        // Append new entry — should start chain from genesis (ignore legacy)
        logger.append(make_event("new-cmd")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);
        assert!(events[0]["chain_version"].is_null(), "legacy has no chain");
        assert_eq!(events[1]["seq"], 0, "new chain starts at seq 0");
        assert_eq!(events[1]["prev_hash"], genesis_hash(Some(&TEST_SECRET)));

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Torn line handling ---

    #[test]
    fn chain_after_torn_line() {
        let dir = test_dir("chain-torn");
        let logger = test_logger(&dir);

        // Append one entry
        logger.append(make_event("first")).unwrap();
        let events_before = read_events(&logger.path);

        // Append a torn line (partial JSON)
        let mut file = OpenOptions::new().append(true).open(&logger.path).unwrap();
        writeln!(file, r#"{{"timestamp":"2026-01-0"#).unwrap();
        drop(file);

        // Append another entry — should continue chain from "first", ignoring torn line
        logger.append(make_event("second")).unwrap();

        let events = read_events(&logger.path);
        // first + second (torn line is not valid JSON so read_events skips it)
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["prev_hash"], events_before[0]["entry_hash"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_empty_file() {
        let dir = test_dir("chain-empty");
        let logger = test_logger(&dir);

        // Create empty file
        fs::write(&logger.path, "").unwrap();

        logger.append(make_event("first")).unwrap();
        let events = read_events(&logger.path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["seq"], 0);
        assert_eq!(events[0]["prev_hash"], genesis_hash(Some(&TEST_SECRET)));

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Golden hex vectors (PR #v096-pr4) ---
    //
    // WHY golden vectors (not a self-verifying helper):
    //   The previous form recomputed `compute_entry_hash` inside the test
    //   and compared it against the recorded `entry_hash`. Since both sides
    //   flow through the same function, an algorithm-level regression
    //   (HMAC key derivation change, field order change, genesis marker
    //   change) would produce a matching pair on both sides and the test
    //   would silently pass. Goldens break that symmetry by pinning the
    //   exact bytes a v0.9.x reader must accept.
    //
    // All inputs the goldens depend on (change any and the hex must be
    // regenerated). PR #186 proxy review P3 — earlier comment only listed
    // timestamp; these additional inputs also feed the HMAC:
    //   - `TEST_SECRET = [0x42u8; 32]`
    //   - `test_logger` defaults: `key_id: "default"`,
    //     `retention_days: 0`, path under temp dir
    //   - `make_event` defaults: `timestamp: "2026-01-01T00:00:00Z"`,
    //     `provider: "test"`, `action/result: "passthrough"`,
    //     `target_count: 0`, `target_hash: "hmac-sha256:test"`,
    //     `detection_layer: Some("layer1")`, all optional chain fields None
    //   - `AuditLogger::append` populates `chain_version`, `seq`,
    //     `prev_hash`, `key_id`, `entry_hash` on each event before write
    //     and does NOT overwrite `timestamp`
    //   - `compute_entry_hash` via `HashableEvent::from_event`
    //     (see `src/audit/chain.rs` — the field order of `HashableEvent`
    //     is additionally SECURITY-pinned by golden test GR-002; reordering
    //     fields invalidates these entry-hash goldens even if the HMAC
    //     algorithm itself is unchanged)
    //
    // How to regenerate (if a deliberate algorithm change lands):
    //   Run `chain_integrity_verification` with a temporary
    //   `println!("{events:#?}");` inserted after `read_events(&logger.path)`.
    //   Read the printed `entry_hash` and `prev_hash` fields
    //   (events[0].prev_hash == genesis). Paste below and delete the
    //   `println!`. Do NOT regenerate by calling `compute_entry_hash`
    //   directly on a `make_event(...)` result — the chain fields
    //   (seq / prev_hash / key_id) would be `None` and the digest would
    //   diverge from what `append` writes. Changing `test_logger` defaults
    //   (key_id, retention_days, etc.) also invalidates these goldens.
    const GOLDEN_GENESIS: &str = "d9c14c4fc7dbc19fce81268a054a22fa092e4946cc762823bd641e156233030b";
    const GOLDEN_ENTRY_HASHES: [&str; 5] = [
        // seq=0, command="cmd0"
        "ff8d28e58ca55a781c908beb827387f22418350d8b7399b2fdecae1a1f805bf2",
        // seq=1, command="cmd1"
        "23473c102da2cc4b56081e1bd9746628feba3c0daf566bb4ecdc7170b085f81f",
        // seq=2, command="cmd2"
        "c1c2d820311b47c2b16acbca62dd7b2be7951045bd7514130f3ea22031d8bf6d",
        // seq=3, command="cmd3"
        "bd394c8964cf47715e2ad67d78184f7a5cf5be21eb651c885d791c2885d075b3",
        // seq=4, command="cmd4"
        "3554f31aac0e3a9ea21afb2f572e09e343c841c21faf2ebf2208f89fc687d165",
    ];

    #[test]
    fn chain_integrity_verification() {
        let dir = test_dir("chain-verify");
        let logger = test_logger(&dir);

        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 5);

        // Pin genesis against the golden: if the HMAC marker changes
        // (e.g. key_id derivation, domain separator), this fails first.
        assert_eq!(
            events[0]["prev_hash"].as_str().unwrap(),
            GOLDEN_GENESIS,
            "genesis hash divergence — HMAC key or domain-separator changed?"
        );

        // Pin each entry's recorded entry_hash + prev_hash chain against
        // the golden. Using hardcoded hex breaks the symmetry of the old
        // self-verifying helper (compute_entry_hash on both sides).
        for (i, expected) in GOLDEN_ENTRY_HASHES.iter().enumerate() {
            assert_eq!(
                events[i]["entry_hash"].as_str().unwrap(),
                *expected,
                "entry_hash at seq={i} drifted from golden — algorithm change?"
            );
            let expected_prev = if i == 0 {
                GOLDEN_GENESIS
            } else {
                GOLDEN_ENTRY_HASHES[i - 1]
            };
            assert_eq!(
                events[i]["prev_hash"].as_str().unwrap(),
                expected_prev,
                "prev_hash at seq={i} broke chain linkage from golden"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_tamper_detected() {
        let dir = test_dir("chain-tamper");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // Tamper: change command in second entry on disk.
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen("cmd1", "HACKED", 1);
        fs::write(&logger.path, tampered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Tamper detection contract:
        //   (a) The *recorded* entry_hash on the tampered line is still the
        //       pre-tamper golden (attacker only flipped a payload byte).
        //   (b) Recomputing the hash from the post-tamper payload yields a
        //       different digest. That divergence is the detection signal.
        // Pinning both sides against goldens (not against each other) ensures
        // a future algorithm change can't paper over a real tamper.
        let parsed_seq1: AuditEvent = serde_json::from_value(events[1].clone()).unwrap();
        let recomputed_seq1 = compute_entry_hash(Some(&TEST_SECRET), &parsed_seq1);

        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[1],
            "tampered line should still carry the pre-tamper recorded hash"
        );
        assert_ne!(
            recomputed_seq1, GOLDEN_ENTRY_HASHES[1],
            "recomputed hash over tampered payload must diverge from golden — \
             this is the tamper signal"
        );
        assert_ne!(
            recomputed_seq1,
            events[1]["entry_hash"].as_str().unwrap(),
            "recomputed vs. recorded divergence is the end-to-end detection test"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: physical reorder of two adjacent on-disk events. Each
    /// event still carries its original (unchanged) entry_hash, but the
    /// hash-chain linkage between adjacent on-disk entries breaks because
    /// each `prev_hash` references the predecessor of its *original*
    /// position, not the predecessor at its new physical position.
    #[test]
    fn chain_tamper_reorder_detected() {
        let dir = test_dir("chain-tamper-reorder");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        // Swap on-disk positions of seq=1 and seq=2 lines.
        let reordered = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
        fs::write(&logger.path, reordered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // After reorder:
        //   on-disk position 0 = original seq=0 (entry_hash = GOLDEN[0])
        //   on-disk position 1 = original seq=2 (entry_hash = GOLDEN[2])
        //   on-disk position 2 = original seq=1 (entry_hash = GOLDEN[1])
        // Detection: position-1's recorded prev_hash references GOLDEN[1]
        // (its original predecessor seq=1's hash), but its on-disk
        // predecessor is position-0 whose entry_hash is GOLDEN[0]. The
        // adjacent-pair linkage breaks.
        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[2],
            "reordered position 1 carries original seq=2's entry_hash (unchanged by reorder)"
        );
        assert_eq!(
            events[1]["prev_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[1],
            "position 1's prev_hash still references its original predecessor (seq=1)"
        );
        assert_ne!(
            events[1]["prev_hash"].as_str().unwrap(),
            events[0]["entry_hash"].as_str().unwrap(),
            "after reorder, prev_hash linkage between adjacent on-disk entries breaks — \
             this is the reorder tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): the underlying signal
        // is necessary but not sufficient — `verify_chain` is what the omamori
        // CLI actually invokes to surface tamper, so a future regression in
        // `verify_chain`'s prev_hash-linkage check would silently flip every
        // chain_tamper_* test back to passing without detection. Pin both
        // layers (raw signal + detector E2E).
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after on-disk reorder; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: physical deletion of a middle event (seq=1). After
    /// deletion, the surviving seq=2 entry sits at on-disk position 1
    /// but its `prev_hash` still references the deleted seq=1's hash.
    /// The on-disk predecessor (seq=0) carries a different entry_hash,
    /// so the chain breaks at the deletion point.
    #[test]
    fn chain_tamper_middle_deletion_detected() {
        let dir = test_dir("chain-tamper-middle-deletion");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        // Drop the middle line (original seq=1).
        let truncated = format!("{}\n{}\n", lines[0], lines[2]);
        fs::write(&logger.path, truncated).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);

        // Surviving on-disk position 1 = original seq=2.
        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[2],
            "surviving position 1 carries original seq=2's entry_hash"
        );
        assert_eq!(
            events[1]["prev_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[1],
            "surviving position 1 still references the deleted seq=1's hash"
        );
        assert_ne!(
            events[1]["prev_hash"].as_str().unwrap(),
            events[0]["entry_hash"].as_str().unwrap(),
            "after middle-deletion, prev_hash points to a vanished hash — \
             this is the deletion tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): see
        // `chain_tamper_reorder_detected` for the rationale on pinning
        // `verify_chain` in addition to the raw on-disk signal.
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after middle-deletion; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: overwrite `prev_hash` on the genesis event (seq=0).
    /// Without the HMAC secret an attacker cannot forge a valid prev_hash
    /// — genesis is HMAC(secret, "omamori-genesis-v1"). Any overwrite
    /// produces a value != GOLDEN_GENESIS. The recorded entry_hash on
    /// seq=0 stays at GOLDEN[0] (attacker only flipped prev_hash bytes),
    /// but recomputing the entry_hash over the post-tamper payload now
    /// diverges from GOLDEN[0]. Both signals fire.
    #[test]
    fn chain_tamper_genesis_rewrite_detected() {
        let dir = test_dir("chain-tamper-genesis-rewrite");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let forged = "0000000000000000000000000000000000000000000000000000000000000000";
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen(GOLDEN_GENESIS, forged, 1);
        fs::write(&logger.path, tampered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Signal 1: genesis prev_hash diverges from golden.
        assert_ne!(
            events[0]["prev_hash"].as_str().unwrap(),
            GOLDEN_GENESIS,
            "genesis-rewrite must surface as prev_hash divergence from golden genesis"
        );
        assert_eq!(
            events[0]["prev_hash"].as_str().unwrap(),
            forged,
            "tampered prev_hash value is observable as the rewritten content"
        );

        // Signal 2: recorded entry_hash stays at golden (only prev_hash bytes
        // were touched), but recomputing entry_hash over the post-tamper
        // payload diverges from golden — same end-to-end signal as
        // chain_tamper_detected above, applied to the genesis event.
        assert_eq!(
            events[0]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES[0],
            "attacker only flipped prev_hash bytes; entry_hash byte sequence unchanged"
        );
        let parsed_seq0: AuditEvent = serde_json::from_value(events[0].clone()).unwrap();
        let recomputed_seq0 = compute_entry_hash(Some(&TEST_SECRET), &parsed_seq0);
        assert_ne!(
            recomputed_seq0, GOLDEN_ENTRY_HASHES[0],
            "recomputed entry_hash over tampered (prev_hash-rewritten) genesis payload \
             diverges from golden — this is the genesis-rewrite tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): see
        // `chain_tamper_reorder_detected` for the rationale on pinning
        // `verify_chain` in addition to the raw on-disk signal.
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after genesis-rewrite; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // --- create_event ---

    #[test]
    fn create_event_hides_argument_values() {
        let dir = test_dir("event-hide-args");
        let logger = test_logger(&dir);
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "/secret/dir".to_string()],
        );
        let rule = RuleConfig {
            name: "rm-recursive".to_string(),
            command: "rm".to_string(),
            action: ActionKind::Trash,
            match_all: vec![],
            match_any: vec![],
            message: None,
            enabled: true,
            destination: None,
            subcommand: None,
            is_builtin: false,
        };
        let outcome = ActionOutcome::Blocked {
            message: "blocked".to_string(),
        };
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string()],
            &outcome,
        );

        // target_hash should be present but target args should not appear in the event
        assert!(event.target_hash.starts_with("hmac-sha256:"));
        assert_eq!(event.command, "rm");
        // The actual paths are NOT stored — only their HMAC
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("/secret/dir"),
            "target paths should not appear in event JSON"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_all_fields() {
        let dir = test_dir("event-all-fields");
        let logger = test_logger(&dir);
        let invocation = CommandInvocation::new(
            "git".to_string(),
            vec!["push".to_string(), "--force".to_string()],
        );
        let rule = RuleConfig {
            name: "git-push-force".to_string(),
            command: "git".to_string(),
            action: ActionKind::Block,
            match_all: vec![],
            match_any: vec!["push.*--force".to_string()],
            message: Some("blocked push --force".to_string()),
            enabled: true,
            destination: None,
            subcommand: None,
            is_builtin: false,
        };
        let outcome = ActionOutcome::Blocked {
            message: "blocked push --force".to_string(),
        };
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string(), "cursor".to_string()],
            &outcome,
        );

        assert_eq!(event.provider, "claude-code"); // first detector
        assert_eq!(event.command, "git");
        assert_eq!(event.rule_id.as_deref(), Some("git-push-force"));
        assert_eq!(event.action, "block");
        assert_eq!(event.result, "block");
        assert_eq!(event.target_count, 1); // "push" (--force is filtered as flag)
        assert!(event.target_hash.starts_with("hmac-sha256:"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_without_secret() {
        let dir = test_dir("event-no-secret");
        let logger = AuditLogger {
            path: dir.join("audit.jsonl"),
            secret: None,
            retention_days: 0,
            key_id: "default".to_string(),
        };
        let invocation = CommandInvocation::new("ls".to_string(), vec![]);
        let outcome = ActionOutcome::PassedThrough { exit_code: 0 };
        let event = logger.create_event(&invocation, None, &[], &outcome);

        assert_eq!(event.target_hash, "NO_HMAC_SECRET");

        let _ = fs::remove_dir_all(&dir);
    }

    // --- HMAC ---

    #[test]
    fn hmac_targets_deterministic() {
        let targets = &["a", "b"];
        let h1 = hmac_targets(Some(&TEST_SECRET), targets);
        let h2 = hmac_targets(Some(&TEST_SECRET), targets);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hmac_targets_different_secrets() {
        let other = [0x99u8; 32];
        let targets = &["a"];
        assert_ne!(
            hmac_targets(Some(&TEST_SECRET), targets),
            hmac_targets(Some(&other), targets)
        );
    }

    #[test]
    fn hmac_targets_no_secret() {
        assert_eq!(hmac_targets(None, &["a"]), "NO_HMAC_SECRET");
    }

    // --- Secret management ---

    #[test]
    fn secret_roundtrip() {
        let dir = test_dir("secret-roundtrip");
        let path = dir.join("audit-secret");
        let secret = create_secret(&path).unwrap();
        let loaded = read_secret(&path).unwrap();
        assert_eq!(secret, loaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("secret-perms");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_create_new_prevents_overwrite() {
        let dir = test_dir("secret-overwrite");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();
        assert!(create_secret(&path).is_err(), "should not overwrite");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_creates_when_missing() {
        let dir = test_dir("secret-create");
        let path = dir.join("audit-secret");
        let secret = load_or_create_secret(&path);
        assert!(secret.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_reads_existing() {
        let dir = test_dir("secret-read");
        let path = dir.join("audit-secret");
        let created = create_secret(&path).unwrap();
        let loaded = load_or_create_secret(&path).unwrap();
        assert_eq!(created, loaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_hex_secret_rejects_short() {
        assert!(decode_hex_secret("abcd").is_err());
    }

    #[test]
    fn decode_hex_secret_rejects_invalid_hex() {
        assert!(decode_hex_secret(&"zz".repeat(32)).is_err());
    }

    // --- JSONL special chars ---

    #[test]
    fn jsonl_special_chars() {
        let dir = test_dir("jsonl-special");
        let logger = test_logger(&dir);

        // Create events with special characters
        let mut event = make_event("echo");
        event.command = "echo \"hello\nworld\"".to_string();
        logger.append(event).unwrap();

        let mut event2 = make_event("echo");
        event2.command = "echo 'café'".to_string();
        logger.append(event2).unwrap();

        // Read back — each event should be on its own line
        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "should be 2 JSONL lines");

        // Both should parse as valid JSON
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_path_derives_from_audit_path() {
        let audit = PathBuf::from("/tmp/omamori/audit.jsonl");
        let secret = secret_path_for(&audit);
        assert_eq!(secret, PathBuf::from("/tmp/omamori/audit-secret"));
    }

    // --- append IO error ---

    #[test]
    fn append_io_error() {
        let logger = AuditLogger {
            path: PathBuf::from("/nonexistent/dir/audit.jsonl"),
            secret: Some(TEST_SECRET),
            retention_days: 0,
            key_id: "default".to_string(),
        };
        assert!(logger.append(make_event("ls")).is_err());
    }

    // --- verify_chain ---

    fn verify_config(dir: &Path) -> AuditConfig {
        AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        }
    }

    #[test]
    fn verify_clean_chain() {
        let dir = test_dir("verify-clean");
        let logger = test_logger(&dir);
        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 5);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_tampered_chain() {
        let dir = test_dir("verify-tampered");
        let logger = test_logger(&dir);
        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // Tamper with second entry
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen("cmd2", "HACKED", 1);
        fs::write(&logger.path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_then_chain() {
        let dir = test_dir("verify-legacy-chain");
        let logger = test_logger(&dir);

        // Write legacy entry
        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(&logger.path, serde_json::to_string(&legacy).unwrap() + "\n").unwrap();

        logger.append(make_event("new")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.legacy_entries, 1);
        assert_eq!(result.chain_entries, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_only() {
        let dir = test_dir("verify-legacy-only");
        test_logger(&dir); // create secret

        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(
            dir.join("audit.jsonl"),
            serde_json::to_string(&legacy).unwrap() + "\n",
        )
        .unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.legacy_entries, 1);
        assert_eq!(result.chain_entries, 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_empty_file() {
        let dir = test_dir("verify-empty");
        test_logger(&dir);
        fs::write(dir.join("audit.jsonl"), "").unwrap();
        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_torn_line() {
        let dir = test_dir("verify-torn");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        // Append torn line
        let mut file = OpenOptions::new().append(true).open(&logger.path).unwrap();
        writeln!(file, r#"{{"broken"#).unwrap();
        drop(file);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 1);
        assert_eq!(result.torn_lines, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_no_secret() {
        let dir = test_dir("verify-no-secret");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let result = verify_chain(&verify_config(&dir));
        assert!(matches!(result, Err(AuditError::SecretUnavailable)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_no_file() {
        let dir = test_dir("verify-no-file");
        test_logger(&dir); // create secret but no audit.jsonl

        let result = verify_chain(&verify_config(&dir));
        assert!(matches!(result, Err(AuditError::FileNotFound)));
        let _ = fs::remove_dir_all(&dir);
    }

    // --- show_entries ---

    #[test]
    fn show_last_n() {
        let dir = test_dir("show-last");
        let logger = test_logger(&dir);
        for i in 0..10 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let opts = ShowOptions {
            last: Some(3),
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        // 1 header + 3 data lines
        assert_eq!(
            lines.len(),
            4,
            "expected header + 3 entries, got:\n{output}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_filter_rule() {
        let dir = test_dir("show-filter-rule");
        let logger = test_logger(&dir);

        let mut e1 = make_event("rm");
        e1.rule_id = Some("rm-recursive".to_string());
        logger.append(e1).unwrap();

        let mut e2 = make_event("git");
        e2.rule_id = Some("git-push-force".to_string());
        logger.append(e2).unwrap();

        let mut e3 = make_event("rm");
        e3.rule_id = Some("rm-recursive".to_string());
        logger.append(e3).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: Some("rm".to_string()),
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let data_lines = output.lines().skip(1).count(); // skip header
        assert_eq!(data_lines, 2, "expected 2 rm entries");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_json_includes_chain_fields() {
        let dir = test_dir("show-json");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: true,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert!(
            parsed.get("entry_hash").is_some(),
            "json should include entry_hash"
        );
        assert!(
            parsed.get("chain_version").is_some(),
            "json should include chain_version"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// v0.9.7 #190 B-2 regression: column alignment must survive PR6
    /// `unknown_tool_fail_open` events without overflow. The pre-v0.9.7
    /// format `{:<8}` (COMMAND) / `{:<15}` (ACTION) overflowed when
    /// `tool_name` exceeded 8 chars or when `action == "unknown_tool_fail_open"`
    /// (22 chars). v0.9.7 widened to `{:<24}` / `{:<24}`. This test pins
    /// the byte position of every column boundary so a silent reversion to
    /// the legacy widths fails CI before it reaches an operator's
    /// `audit show` output.
    #[test]
    fn show_pr6_unknown_tool_fail_open_keeps_columns_aligned() {
        let dir = test_dir("show-pr6-alignment");
        let logger = test_logger(&dir);

        let mut event = make_event("FuturePlanWriter"); // 16-char tool_name (PR6)
        event.action = "unknown_tool_fail_open".to_string(); // 22-char label (PR6)
        event.result = "allow".to_string();
        event.detection_layer = Some("shape-routing".to_string());
        logger.append(event).unwrap();

        let opts = ShowOptions {
            last: Some(1),
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "header + 1 row, got:\n{output}");
        let header = lines[0];
        let row = lines[1];

        // Format string: "{:<20} {:<12} {:<24} {:<24} {:<8} RULE"
        // Column starts (in bytes): 0 / 21 / 34 / 59 / 84 / 93
        assert_eq!(header.find("TIMESTAMP"), Some(0));
        assert_eq!(header.find("PROVIDER"), Some(21));
        assert_eq!(header.find("COMMAND"), Some(34));
        assert_eq!(header.find("ACTION"), Some(59));
        assert_eq!(header.find("RESULT"), Some(84));
        assert_eq!(header.find("RULE"), Some(93));

        // Body row: 16-char tool_name fills bytes 34..50, then padding to 58.
        assert_eq!(&row[34..50], "FuturePlanWriter");
        // 22-char action label fills bytes 59..81, then padding to 83.
        assert_eq!(&row[59..81], "unknown_tool_fail_open");
        // RESULT column at byte 84 ("allow" = 5 chars, padded to 8).
        assert_eq!(&row[84..89], "allow");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_table_hides_hashes() {
        let dir = test_dir("show-hides");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("hmac-sha256:"),
            "table should not show hashes"
        );
        assert!(
            !output.contains("entry_hash"),
            "table should not show entry_hash"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_empty_file() {
        let dir = test_dir("show-empty");
        test_logger(&dir);
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        assert!(buf.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- audit_summary ---

    #[test]
    fn summary_with_entries() {
        let dir = test_dir("summary");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("rm")).unwrap();

        let summary = audit_summary(&verify_config(&dir));
        assert!(summary.enabled);
        assert_eq!(summary.entry_count, 2);
        assert!(summary.secret_available);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let summary = audit_summary(&config);
        assert!(!summary.enabled);
    }

    // --- display_timestamp ---

    #[test]
    fn timestamp_truncation() {
        assert_eq!(
            display_timestamp("2026-04-04T03:31:02.54814Z"),
            "2026-04-04T03:31:02Z"
        );
        assert_eq!(
            display_timestamp("2026-04-04T03:31:02Z"),
            "2026-04-04T03:31:02Z"
        );
    }

    // --- Retention / Prune ---

    fn make_event_with_timestamp(command: &str, ts: &str) -> AuditEvent {
        let mut event = make_event(command);
        event.timestamp = ts.to_string();
        event
    }

    fn test_logger_with_retention(dir: &Path, retention_days: u32) -> AuditLogger {
        let path = dir.join("audit.jsonl");
        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();
        AuditLogger {
            path,
            secret: Some(TEST_SECRET),
            retention_days,
            key_id: "default".to_string(),
        }
    }

    /// Write chain entries directly with given timestamps (bypass append to control timestamps).
    fn write_chain_entries(path: &Path, secret: &[u8; 32], entries: &[(&str, &str)]) {
        let genesis = genesis_hash(Some(secret));
        let mut prev_hash = genesis;
        let mut content = String::new();

        for (seq, (command, timestamp)) in entries.iter().enumerate() {
            let mut event = make_event_with_timestamp(command, timestamp);
            event.chain_version = Some(CHAIN_VERSION);
            event.seq = Some(seq as u64);
            event.prev_hash = Some(prev_hash.clone());
            event.key_id = Some("default".to_string());
            event.entry_hash = Some(compute_entry_hash(Some(secret), &event));
            prev_hash = event.entry_hash.clone().unwrap();
            content.push_str(&serde_json::to_string(&event).unwrap());
            content.push('\n');
        }

        fs::write(path, content).unwrap();
    }

    #[test]
    fn prune_genesis_hash_is_distinct() {
        let genesis = genesis_hash(Some(&TEST_SECRET));
        let prune = prune_genesis_hash(Some(&TEST_SECRET));
        assert_ne!(genesis, prune);
    }

    #[test]
    fn prune_genesis_hash_is_deterministic() {
        let a = prune_genesis_hash(Some(&TEST_SECRET));
        let b = prune_genesis_hash(Some(&TEST_SECRET));
        assert_eq!(a, b);
    }

    #[test]
    fn try_prune_removes_old_entries() {
        let dir = test_dir("prune-old");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-09-18T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }

        let refs: Vec<(&str, &str)> = entries.to_vec();
        write_chain_entries(&path, &TEST_SECRET, &refs);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned, 100, "should prune 100 old entries");

        drop(file);
        let events = read_events(&path);
        assert_eq!(events.len(), 1101, "prune_point + 1100 retained");
        assert_eq!(events[0]["command"], "_prune");
        assert_eq!(events[0]["target_count"], 100);
        assert_eq!(events[0]["action"], "retention");
        assert_eq!(events[0]["result"], "pruned");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_nothing_to_prune() {
        let dir = test_dir("prune-nothing");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let new_ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..1100).map(|_| ("cmd", new_ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned, 0, "nothing should be pruned");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_min_retain_prevents_prune() {
        let dir = test_dir("prune-min-retain");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..500 {
            entries.push(("old", old_ts));
        }
        for _ in 0..500 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned, 0, "min retain should prevent prune");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_retention_days_zero_is_noop() {
        let dir = test_dir("prune-zero");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2020-01-01T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..100).map(|_| ("cmd", old_ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 36500).unwrap();
        assert_eq!(pruned, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_pruned_chain_intact() {
        let dir = test_dir("verify-pruned");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned, 100);
        drop(file);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_none(), "pruned chain should verify OK");
        assert!(result.pruned, "should detect prune_point");
        assert_eq!(result.pruned_count, Some(100));
        assert_eq!(result.chain_entries, 1101);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_forged_prune_point() {
        let dir = test_dir("verify-forged-prune");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..10).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let events = read_events(&path);
        let retained = &events[5..];

        let bad_secret = [0x99u8; 32];
        let first_retained_hash = retained[0]["entry_hash"].as_str().unwrap();
        let forged = build_prune_point(Some(&bad_secret), 5, first_retained_hash);

        let mut content = serde_json::to_string(&forged).unwrap();
        content.push('\n');
        for ev in retained {
            content.push_str(&serde_json::to_string(ev).unwrap());
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "forged prune_point should be detected"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_extra_deletion_after_prune() {
        let dir = test_dir("verify-extra-delete");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        drop(file);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut tampered = String::new();
        tampered.push_str(lines[0]);
        tampered.push('\n');
        for line in &lines[2..] {
            tampered.push_str(line);
            tampered.push('\n');
        }
        fs::write(&path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "extra deletion after prune should be detected via target_hash binding"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_prune_replaces_existing_prune_point() {
        let dir = test_dir("re-prune");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let mid_ts = "2025-10-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..50 {
            entries.push(("old", old_ts));
        }
        for _ in 0..50 {
            entries.push(("mid", mid_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned1 = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned1, 100, "should prune 50 old + 50 mid");
        drop(file);

        let result1 = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result1.broken_at.is_none(),
            "first prune chain should be intact"
        );
        assert!(result1.pruned);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned2 = try_prune(&mut file, Some(&TEST_SECRET), 1).unwrap();
        assert!(pruned2 <= 100, "second prune should respect min retain");
        drop(file);

        let result2 = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result2.broken_at.is_none(),
            "re-pruned chain should still be intact"
        );
        assert!(result2.pruned);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_prune_point_only() {
        let dir = test_dir("verify-prune-only");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let prune = build_prune_point(Some(&TEST_SECRET), 50, "");
        let content = serde_json::to_string(&prune).unwrap() + "\n";
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_none(), "prune_point alone should be OK");
        assert!(result.pruned);
        assert_eq!(result.chain_entries, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_head_deletion_without_prune_point() {
        let dir = test_dir("verify-head-delete");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..5).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let tampered = lines[1..].join("\n") + "\n";
        fs::write(&path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "head deletion without prune_point = chain broken"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_prune_separator() {
        let dir = test_dir("show-prune-sep");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let prune = build_prune_point(Some(&TEST_SECRET), 42, "hash123");
        let mut content = serde_json::to_string(&prune).unwrap() + "\n";

        let ts = "2026-04-04T00:00:00Z";
        let refs: Vec<(&str, &str)> = vec![("ls", ts), ("cat", ts)];
        let genesis = genesis_hash(Some(&TEST_SECRET));
        let mut prev_hash = genesis;
        for (seq, (cmd, ts)) in refs.iter().enumerate() {
            let mut event = make_event_with_timestamp(cmd, ts);
            event.chain_version = Some(CHAIN_VERSION);
            event.seq = Some(seq as u64);
            event.prev_hash = Some(prev_hash.clone());
            event.key_id = Some("default".to_string());
            event.entry_hash = Some(compute_entry_hash(Some(&TEST_SECRET), &event));
            prev_hash = event.entry_hash.clone().unwrap();
            content.push_str(&serde_json::to_string(&event).unwrap());
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("--- pruned 42 entries"),
            "should show prune separator, got:\n{output}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_validate_clamps_retention() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 3,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, MIN_RETENTION_DAYS);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn config_validate_zero_unchanged() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, 0);
        assert!(warnings.is_empty());
    }

    #[test]
    fn config_validate_valid_retention_unchanged() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 90,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, 90);
        assert!(warnings.is_empty());
    }

    #[test]
    fn summary_includes_retention() {
        let dir = test_dir("summary-retention");
        let logger = test_logger_with_retention(&dir, 90);
        logger.append(make_event("ls")).unwrap();

        let mut config = verify_config(&dir);
        config.retention_days = 90;
        let summary = audit_summary(&config);
        assert_eq!(summary.retention_days, 90);
        let _ = fs::remove_dir_all(&dir);
    }

    // --- O_NOFOLLOW: symlink rejection ---

    #[cfg(unix)]
    #[test]
    fn append_rejects_symlink_audit_log() {
        let dir = test_dir("symlink-audit-log");
        let real_path = dir.join("real-audit.jsonl");
        fs::write(&real_path, "").unwrap();
        let symlink_path = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        let logger = AuditLogger {
            path: symlink_path,
            secret: Some(TEST_SECRET),
            retention_days: 0,
            key_id: "default".to_string(),
        };
        let err = logger.append(make_event("ls")).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_rejects_symlink() {
        let dir = test_dir("symlink-secret-read");
        let real_secret = dir.join("real-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&real_secret, &hex).unwrap();
        let symlink_secret = dir.join("audit-secret");
        std::os::unix::fs::symlink(&real_secret, &symlink_secret).unwrap();

        let err = read_secret(&symlink_secret).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_secret_rejects_existing_symlink() {
        let dir = test_dir("symlink-secret-create");
        let real_secret = dir.join("real-secret");
        fs::write(&real_secret, "placeholder").unwrap();
        let symlink_secret = dir.join("audit-secret");
        std::os::unix::fs::symlink(&real_secret, &symlink_secret).unwrap();

        let err = create_secret(&symlink_secret).unwrap_err();
        assert!(
            err.to_string().contains("symlink") || err.kind() == std::io::ErrorKind::AlreadyExists,
            "expected symlink or AlreadyExists error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn verify_chain_rejects_symlink() {
        let dir = test_dir("symlink-verify");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        match verify_chain(&config) {
            Err(AuditError::Io(e)) => assert!(
                e.to_string().contains("symlink"),
                "expected symlink error, got: {e}"
            ),
            Err(other) => panic!("expected Io error, got: {other}"),
            Ok(_) => panic!("expected error for symlink path"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn show_entries_rejects_symlink() {
        let dir = test_dir("symlink-show");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        let err = show_entries(&config, &opts, &mut buf).unwrap_err();
        match err {
            AuditError::Io(e) => assert!(
                e.to_string().contains("symlink"),
                "expected symlink error, got: {e}"
            ),
            other => panic!("expected Io error, got: {other}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn audit_summary_symlink_sets_path_error() {
        let dir = test_dir("symlink-summary");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        let summary = audit_summary(&config);
        assert_eq!(summary.entry_count, 0);
        assert!(
            summary
                .path_error
                .as_ref()
                .is_some_and(|e| e.contains("symlink")),
            "expected path_error with 'symlink', got: {:?}",
            summary.path_error
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_summary_no_file_no_path_error() {
        let dir = test_dir("summary-nofile");
        let config = verify_config(&dir);
        let summary = audit_summary(&config);
        assert_eq!(summary.entry_count, 0);
        assert!(summary.path_error.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- O_NOFOLLOW: normal (non-symlink) paths still work ---

    #[test]
    fn normal_path_append_works_with_nofollow() {
        let dir = test_dir("nofollow-normal");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("cat")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn normal_path_verify_works_with_nofollow() {
        let dir = test_dir("nofollow-verify");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let config = verify_config(&dir);
        let result = verify_chain(&config).unwrap();
        assert_eq!(result.chain_entries, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- strict mode: secret_available ---

    #[test]
    fn secret_available_true_when_secret_present() {
        let dir = test_dir("strict-avail-true");
        let logger = test_logger(&dir);
        assert!(logger.secret_available());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_available_false_when_secret_absent() {
        let dir = test_dir("strict-avail-false");
        let logger = AuditLogger {
            path: dir.join("audit.jsonl"),
            secret: None,
            retention_days: 0,
            key_id: "default".to_string(),
        };
        assert!(!logger.secret_available());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn strict_config_parses_from_default() {
        let config = AuditConfig::default();
        assert!(!config.strict, "strict should default to false");
    }

    #[test]
    fn strict_config_deserializes_true() {
        let toml_str = r#"
            enabled = true
            strict = true
        "#;
        let config: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(config.strict);
    }

    #[test]
    fn strict_config_deserializes_absent_as_false() {
        let toml_str = r#"
            enabled = true
        "#;
        let config: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.strict);
    }

    // --- verify_chain: secret symlink ELOOP propagation ---

    #[cfg(unix)]
    #[test]
    fn verify_chain_secret_symlink_returns_io_error() {
        let dir = test_dir("verify-secret-symlink");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_secret = dir.join("real-secret");
        let secret_path = dir.join("audit-secret");
        fs::rename(&secret_path, &real_secret).unwrap();
        std::os::unix::fs::symlink(&real_secret, &secret_path).unwrap();

        let config = verify_config(&dir);
        match verify_chain(&config) {
            Err(AuditError::Io(e)) => assert!(
                e.to_string().contains("symlink"),
                "expected symlink error, got: {e}"
            ),
            Err(other) => panic!("expected Io error, got: {other}"),
            Ok(_) => panic!("expected error for symlink secret"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // --- GR-002: HashableEvent serialization order golden test (T9 guardrail) ---

    #[test]
    fn hashable_event_serialization_order_is_stable() {
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test-provider".to_string(),
            command: "rm -rf /".to_string(),
            rule_id: Some("test-rule".to_string()),
            action: "block".to_string(),
            result: "blocked".to_string(),
            target_count: 1,
            target_hash: "abc123".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: Some(1),
            seq: Some(42),
            prev_hash: Some("prev000".to_string()),
            key_id: Some("default".to_string()),
            entry_hash: None,
        };
        let json = serde_json::to_string(&HashableEvent::from_event(&event)).unwrap();

        let expected = concat!(
            r#"{"chain_version":1,"seq":42,"prev_hash":"prev000","key_id":"default","#,
            r#""timestamp":"2026-01-01T00:00:00Z","provider":"test-provider","#,
            r#""command":"rm -rf /","rule_id":"test-rule","action":"block","#,
            r#""result":"blocked","target_count":1,"target_hash":"abc123","#,
            r#""detection_layer":"layer1","unwrap_chain":null,"raw_input_hash":null}"#,
        );
        assert_eq!(
            json, expected,
            "HashableEvent field order has changed! \
            This WILL break verify_chain on all existing audit.jsonl files. \
            If this is intentional (new chain_version), update this test and bump CHAIN_VERSION."
        );
    }
}
