use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actions::ActionOutcome;
use crate::rules::{CommandInvocation, RuleConfig};

type HmacSha256 = Hmac<Sha256>;

const CHAIN_VERSION: u32 = 1;
const GENESIS_SEED: &[u8] = b"omamori-genesis-v1";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

pub struct AuditLogger {
    path: PathBuf,
    secret: Option<[u8; 32]>,
}

impl AuditLogger {
    pub fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let path = config.path.clone().unwrap_or_else(default_audit_path);
        let secret = load_or_create_secret(&secret_path_for(&path));
        Some(Self { path, secret })
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
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.path)?;

        flock_exclusive(&file)?;

        // Read chain state under lock (another process may have appended since our open)
        let (last_seq, last_hash) = read_chain_state(&mut file, self.secret.as_ref());
        let seq = last_seq.map_or(0, |s| s + 1);

        // Set chain fields
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(seq);
        event.prev_hash = Some(last_hash);
        event.key_id = Some("default".to_string());
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
// Hash chain
// ---------------------------------------------------------------------------

/// Canonical representation of an event for entry_hash computation.
/// All fields are non-optional and always serialized (no skip_serializing_if).
/// Field order is fixed by struct definition order (serde guarantee).
#[derive(Serialize)]
struct HashableEvent {
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
    fn from_event(event: &AuditEvent) -> Self {
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

fn genesis_hash(secret: Option<&[u8; 32]>) -> String {
    hmac_bytes(secret, GENESIS_SEED)
}

fn compute_entry_hash(secret: Option<&[u8; 32]>, event: &AuditEvent) -> String {
    let canonical = serde_json::to_string(&HashableEvent::from_event(event))
        .expect("AuditEvent serialization cannot fail");
    hmac_bytes(secret, canonical.as_bytes())
}

fn hmac_bytes(secret: Option<&[u8; 32]>, data: &[u8]) -> String {
    let Some(key) = secret else {
        return "NO_HMAC_SECRET".to_string();
    };
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    mac.update(data);
    format!("{:x}", mac.finalize().into_bytes())
}

fn read_chain_state(file: &mut fs::File, secret: Option<&[u8; 32]>) -> (Option<u64>, String) {
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

// ---------------------------------------------------------------------------
// File locking
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn flock_exclusive(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn flock_exclusive(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(()) // No-op on non-Unix (omamori is Unix-only, but keeps compilation clean)
}

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

fn hmac_targets(secret: Option<&[u8; 32]>, targets: &[&str]) -> String {
    let Some(key) = secret else {
        return "NO_HMAC_SECRET".to_string();
    };
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    for target in targets {
        mac.update(target.as_bytes());
        mac.update(&[0]); // null separator between targets
    }
    format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Secret management
// ---------------------------------------------------------------------------

fn secret_path_for(audit_path: &Path) -> PathBuf {
    audit_path.with_file_name("audit-secret")
}

fn load_or_create_secret(path: &Path) -> Option<[u8; 32]> {
    if let Ok(secret) = read_secret(path) {
        return Some(secret);
    }
    match create_secret(path) {
        Ok(secret) => Some(secret),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match read_secret(path) {
            Ok(secret) => Some(secret),
            Err(e) => {
                eprintln!("omamori warning: audit secret race: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("omamori warning: audit secret unavailable: {e}");
            None
        }
    }
}

fn read_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let hex = fs::read_to_string(path)?;
    decode_hex_secret(hex.trim())
}

fn create_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let mut secret = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(hex.as_bytes())?;

    Ok(secret)
}

fn decode_hex_secret(hex: &str) -> Result<[u8; 32], std::io::Error> {
    if hex.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit secret must be exactly 64 hex characters",
        ));
    }
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hex in audit secret",
            )
        })?;
    }
    Ok(secret)
}

fn default_audit_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("omamori")
        .join("audit.jsonl")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{ActionKind, RuleConfig};

    const TEST_SECRET: [u8; 32] = [0x42u8; 32];

    fn test_logger(dir: &Path) -> AuditLogger {
        let path = dir.join("audit.jsonl");

        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        AuditLogger {
            path,
            secret: Some(TEST_SECRET),
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
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    // --- AuditLogger: from_config ---

    #[test]
    fn from_config_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
        };
        assert!(AuditLogger::from_config(&config).is_none());
    }

    #[test]
    fn from_config_enabled_creates_secret() {
        let dir = test_dir("from-config");
        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
        };
        let logger = AuditLogger::from_config(&config).expect("should create logger");
        assert!(logger.secret.is_some());

        let secret_file = dir.join("audit-secret");
        assert!(secret_file.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial]
    fn from_config_default_path() {
        let config = AuditConfig {
            enabled: true,
            path: None,
        };
        let logger = AuditLogger::from_config(&config);
        assert!(logger.is_some());
    }

    // --- Hash chain: append builds chain ---

    #[test]
    fn chain_three_entries() {
        let dir = test_dir("chain-three");
        let logger = test_logger(&dir);

        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("cat")).unwrap();
        logger.append(make_event("echo")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // seq must be monotonic 0, 1, 2
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev["seq"], i as u64, "seq mismatch at entry {i}");
            assert_eq!(ev["chain_version"], CHAIN_VERSION);
            assert_eq!(ev["key_id"], "default");
            assert!(ev["entry_hash"].is_string());
            assert!(ev["prev_hash"].is_string());
        }

        // prev_hash chain: entry[n].prev_hash == entry[n-1].entry_hash
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
        assert!(!a.is_empty());
        assert_ne!(a, "NO_HMAC_SECRET");
    }

    #[test]
    fn chain_genesis_differs_by_secret() {
        let a = genesis_hash(Some(&[0x01; 32]));
        let b = genesis_hash(Some(&[0x02; 32]));
        assert_ne!(a, b);
    }

    #[test]
    fn chain_entry_hash_is_deterministic() {
        let mut event = make_event("rm");
        event.chain_version = Some(1);
        event.seq = Some(0);
        event.prev_hash = Some("abc".to_string());
        event.key_id = Some("default".to_string());

        let a = compute_entry_hash(Some(&TEST_SECRET), &event);
        let b = compute_entry_hash(Some(&TEST_SECRET), &event);
        assert_eq!(a, b);
    }

    #[test]
    fn chain_entry_hash_changes_on_tamper() {
        let mut event = make_event("rm");
        event.chain_version = Some(1);
        event.seq = Some(0);
        event.prev_hash = Some("abc".to_string());
        event.key_id = Some("default".to_string());

        let original = compute_entry_hash(Some(&TEST_SECRET), &event);
        event.action = "blocked".to_string(); // tamper
        let tampered = compute_entry_hash(Some(&TEST_SECRET), &event);
        assert_ne!(original, tampered);
    }

    #[test]
    fn chain_no_secret_uses_marker() {
        assert_eq!(genesis_hash(None), "NO_HMAC_SECRET");
        assert_eq!(
            compute_entry_hash(None, &make_event("ls")),
            "NO_HMAC_SECRET"
        );
    }

    // --- Legacy migration ---

    #[test]
    fn chain_after_legacy_entries() {
        let dir = test_dir("legacy-migration");
        let logger = test_logger(&dir);

        // Write a legacy entry (no chain fields) directly
        let legacy = r#"{"timestamp":"2026-01-01T00:00:00Z","provider":"test","command":"old","rule_id":null,"action":"passthrough","result":"passthrough","target_count":0,"target_hash":"sha256:old"}"#;
        fs::write(&logger.path, format!("{legacy}\n")).unwrap();

        // Append a new chain entry
        logger.append(make_event("new")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);

        // First entry: legacy (no chain fields)
        assert!(events[0].get("seq").is_none());

        // Second entry: chain starts from genesis (seq=0)
        assert_eq!(events[1]["seq"], 0);
        let genesis = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(events[1]["prev_hash"], genesis);

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Torn line handling ---

    #[test]
    fn chain_after_torn_line() {
        let dir = test_dir("torn-line");
        let logger = test_logger(&dir);

        // Write one valid entry, then a torn line
        logger.append(make_event("first")).unwrap();
        let mut file = OpenOptions::new().append(true).open(&logger.path).unwrap();
        write!(file, "{{\"broken\":tru").unwrap(); // torn JSON, no newline

        // Append should skip torn line and chain from the valid entry
        logger.append(make_event("second")).unwrap();

        let content = fs::read_to_string(&logger.path).unwrap();
        let valid_lines: Vec<serde_json::Value> = content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        assert_eq!(valid_lines.len(), 2);
        assert_eq!(valid_lines[0]["seq"], 0);
        assert_eq!(valid_lines[1]["seq"], 1);
        assert_eq!(valid_lines[1]["prev_hash"], valid_lines[0]["entry_hash"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_empty_file() {
        let dir = test_dir("empty-file");
        let logger = test_logger(&dir);

        // Create empty file
        fs::write(&logger.path, "").unwrap();

        logger.append(make_event("first")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["seq"], 0);
        let genesis = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(events[0]["prev_hash"], genesis);

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Verify chain integrity (helper for tests) ---

    fn verify_chain(events: &[serde_json::Value], secret: Option<&[u8; 32]>) -> bool {
        let genesis = genesis_hash(secret);
        let mut expected_prev = genesis;

        for (i, ev) in events.iter().enumerate() {
            // Check seq
            if ev["seq"] != i as u64 {
                return false;
            }
            // Check prev_hash
            if ev["prev_hash"] != expected_prev {
                return false;
            }
            // Recompute entry_hash
            let event: AuditEvent = serde_json::from_value(ev.clone()).unwrap();
            let mut for_hash = event.clone();
            for_hash.entry_hash = None;
            let recomputed = compute_entry_hash(secret, &for_hash);
            if ev["entry_hash"] != recomputed {
                return false;
            }
            expected_prev = ev["entry_hash"].as_str().unwrap().to_string();
        }
        true
    }

    #[test]
    fn chain_integrity_verification() {
        let dir = test_dir("verify");
        let logger = test_logger(&dir);

        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("cat")).unwrap();
        logger.append(make_event("echo")).unwrap();

        let events = read_events(&logger.path);
        assert!(verify_chain(&events, Some(&TEST_SECRET)));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_tamper_detected() {
        let dir = test_dir("tamper");
        let logger = test_logger(&dir);

        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("rm")).unwrap();
        logger.append(make_event("cat")).unwrap();

        // Tamper: change action of middle entry
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen("\"passthrough\"", "\"blocked\"", 1);
        fs::write(&logger.path, tampered).unwrap();

        let events = read_events(&logger.path);
        assert!(
            !verify_chain(&events, Some(&TEST_SECRET)),
            "tamper should be detected"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // --- create_event ---

    #[test]
    fn create_event_hides_argument_values() {
        let dir = test_dir("hides-args");
        let logger = test_logger(&dir);

        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["secret.txt".to_string(), "another.txt".to_string()],
        );
        let rule = RuleConfig::new(
            "rm-recursive",
            "rm",
            ActionKind::Trash,
            Vec::new(),
            Vec::new(),
            None,
        );
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string()],
            &ActionOutcome::Trashed {
                exit_code: 0,
                message: "ok".to_string(),
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("secret.txt"), "raw path must not appear");
        assert!(json.contains("\"target_hash\":\"hmac-sha256:"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_all_fields() {
        let dir = test_dir("all-fields");
        let logger = test_logger(&dir);

        let invocation = CommandInvocation::new(
            "git".to_string(),
            vec!["push".to_string(), "origin".to_string()],
        );
        let rule = RuleConfig::new(
            "git-push",
            "git",
            ActionKind::LogOnly,
            Vec::new(),
            Vec::new(),
            None,
        );
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string()],
            &ActionOutcome::LoggedOnly {
                exit_code: 0,
                message: "ok".to_string(),
            },
        );

        assert_eq!(event.command, "git");
        assert_eq!(event.rule_id, Some("git-push".to_string()));
        assert_eq!(event.provider, "claude-code");
        assert!(event.target_hash.starts_with("hmac-sha256:"));
        // Chain fields are None before append
        assert!(event.chain_version.is_none());
        assert!(event.seq.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_without_secret() {
        let logger = AuditLogger {
            path: PathBuf::from("/tmp/dummy.jsonl"),
            secret: None,
        };
        let invocation = CommandInvocation::new("ls".to_string(), vec![]);
        let event = logger.create_event(
            &invocation,
            None,
            &["test".to_string()],
            &ActionOutcome::PassedThrough { exit_code: 0 },
        );
        assert_eq!(event.target_hash, "NO_HMAC_SECRET");
    }

    // --- HMAC ---

    #[test]
    fn hmac_targets_deterministic() {
        let secret = [0xABu8; 32];
        let a = hmac_targets(Some(&secret), &["file.txt"]);
        let b = hmac_targets(Some(&secret), &["file.txt"]);
        assert_eq!(a, b);
        assert!(a.starts_with("hmac-sha256:"));
    }

    #[test]
    fn hmac_targets_different_secrets() {
        let a = hmac_targets(Some(&[0x01; 32]), &["file.txt"]);
        let b = hmac_targets(Some(&[0x02; 32]), &["file.txt"]);
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_targets_no_secret() {
        assert_eq!(hmac_targets(None, &["file.txt"]), "NO_HMAC_SECRET");
    }

    // --- Secret management ---

    #[test]
    fn secret_roundtrip() {
        let dir = test_dir("secret-roundtrip");
        let path = dir.join("audit-secret");

        let created = create_secret(&path).unwrap();
        let loaded = read_secret(&path).unwrap();
        assert_eq!(created, loaded);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_file_permissions() {
        let dir = test_dir("secret-perms");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_create_new_prevents_overwrite() {
        let dir = test_dir("secret-no-overwrite");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();
        assert!(create_secret(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_creates_when_missing() {
        let dir = test_dir("load-or-create");
        let path = dir.join("audit-secret");
        assert!(load_or_create_secret(&path).is_some());
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_reads_existing() {
        let dir = test_dir("load-existing");
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
        let dir = test_dir("special-chars");
        let logger = test_logger(&dir);

        let invocation = CommandInvocation::new(
            "echo".to_string(),
            vec!["hello\nworld".to_string(), "it's \"quoted\"".to_string()],
        );
        let event = logger.create_event(
            &invocation,
            None,
            &["test\u{1F680}".to_string()],
            &ActionOutcome::PassedThrough { exit_code: 0 },
        );
        logger.append(event).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 1);
        assert!(events[0]["entry_hash"].is_string());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_path_derives_from_audit_path() {
        let audit = PathBuf::from("/home/user/.local/share/omamori/audit.jsonl");
        assert_eq!(
            secret_path_for(&audit),
            PathBuf::from("/home/user/.local/share/omamori/audit-secret")
        );
    }

    // --- append IO error ---

    #[test]
    fn append_io_error() {
        let logger = AuditLogger {
            path: PathBuf::from("/nonexistent/dir/audit.jsonl"),
            secret: Some([0u8; 32]),
        };
        assert!(logger.append(make_event("rm")).is_err());
    }
}
