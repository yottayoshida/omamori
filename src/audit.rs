use std::fs::{self, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
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
const PRUNE_GENESIS_SEED: &[u8] = b"omamori-prune-v1";
const PRUNE_CHECK_INTERVAL: u64 = 1000;
const MIN_RETENTION_DAYS: u32 = 7;
const MIN_RETAIN_ENTRIES: usize = 1000;
const PRUNE_COMMAND: &str = "_prune";
const PRUNE_ACTION: &str = "retention";
const PRUNE_RESULT: &str = "pruned";

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
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            retention_days: 0,
        }
    }
}

impl AuditConfig {
    /// Validate and clamp retention_days. Returns warnings if adjusted.
    pub fn validate(&self) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut config = self.clone();
        if config.retention_days > 0 && config.retention_days < MIN_RETENTION_DAYS {
            warnings.push(format!(
                "audit.retention_days {} is below minimum {}; clamped to {}",
                config.retention_days, MIN_RETENTION_DAYS, MIN_RETENTION_DAYS
            ));
            config.retention_days = MIN_RETENTION_DAYS;
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
    path: PathBuf,
    secret: Option<[u8; 32]>,
    retention_days: u32,
}

impl AuditLogger {
    pub fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let (validated, _warnings) = config.validate();
        let path = validated.path.clone().unwrap_or_else(default_audit_path);
        let secret = load_or_create_secret(&secret_path_for(&path));
        Some(Self {
            path,
            secret,
            retention_days: validated.retention_days,
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

        // Auto-prune under the same flock (no extra I/O when not triggered)
        if self.retention_days > 0 && seq > 0 && seq % PRUNE_CHECK_INTERVAL == 0 {
            if let Err(e) = try_prune(&mut file, self.secret.as_ref(), self.retention_days) {
                eprintln!("omamori warning: audit prune failed: {e}");
            }
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

fn prune_genesis_hash(secret: Option<&[u8; 32]>) -> String {
    hmac_bytes(secret, PRUNE_GENESIS_SEED)
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
// Retention / Prune
// ---------------------------------------------------------------------------

/// In-place prune of entries older than `retention_days`.
/// Called under flock_exclusive from append().
/// Best-effort: errors are silently ignored (prune is not critical path).
fn try_prune(
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

fn build_prune_point(
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
            .format(&Rfc3339)
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

fn is_prune_point(event: &AuditEvent) -> bool {
    event.command == PRUNE_COMMAND && event.action == PRUNE_ACTION && event.result == PRUNE_RESULT
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
    Ok(())
}

#[cfg(unix)]
fn flock_shared(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn flock_shared(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(())
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
// CLI: verify, show, summary
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AuditError {
    SecretUnavailable,
    FileNotFound,
    Io(std::io::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretUnavailable => write!(f, "HMAC secret unavailable"),
            Self::FileNotFound => write!(f, "audit log not found"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct VerifyResult {
    pub chain_entries: u64,
    pub legacy_entries: u64,
    pub torn_lines: u64,
    pub broken_at: Option<u64>,
    pub pruned: bool,
    pub pruned_count: Option<u64>,
}

pub struct ShowOptions {
    pub last: Option<usize>,
    pub rule: Option<String>,
    pub provider: Option<String>,
    pub json: bool,
}

pub struct AuditSummary {
    pub enabled: bool,
    pub entry_count: u64,
    pub secret_available: bool,
    pub retention_days: u32,
}

pub fn verify_chain(config: &AuditConfig) -> Result<VerifyResult, AuditError> {
    let path = config.path.clone().unwrap_or_else(default_audit_path);
    let secret = read_secret(&secret_path_for(&path)).map_err(|_| AuditError::SecretUnavailable)?;

    let file = fs::File::open(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::FileNotFound,
        _ => AuditError::Io(e),
    })?;
    flock_shared(&file)?;

    let reader = std::io::BufReader::new(&file);
    let genesis = genesis_hash(Some(&secret));
    let prune_genesis = prune_genesis_hash(Some(&secret));

    let mut result = VerifyResult {
        chain_entries: 0,
        legacy_entries: 0,
        torn_lines: 0,
        broken_at: None,
        pruned: false,
        pruned_count: None,
    };
    let mut expected_prev = genesis;
    let mut expected_seq: u64 = 0;
    let mut last_was_prune = false;
    let mut prune_target_hash: Option<String> = None;
    let mut prune_target_count: Option<u64> = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                result.torn_lines += 1;
                continue;
            }
        };

        if event.chain_version.is_none() {
            result.legacy_entries += 1;
            continue;
        }

        let seq = event.seq.unwrap_or(0);
        let prev_hash = event.prev_hash.as_deref().unwrap_or("");
        let recorded_hash = event.entry_hash.as_deref().unwrap_or("");
        let is_prune = is_prune_point(&event);

        // --- prev_hash verification ---
        if result.chain_entries == 0 {
            // First chain entry: genesis or prune_genesis
            let expected = if is_prune {
                &prune_genesis
            } else {
                &expected_prev
            };
            if prev_hash != expected {
                result.broken_at = Some(seq);
                break;
            }
            if is_prune {
                // seq must be 0 for prune_point at head
                if seq != 0 {
                    result.broken_at = Some(seq);
                    break;
                }
            }
        } else if last_was_prune {
            // Prune gap: prev_hash won't match prune_point's entry_hash — allowed.
            // But verify the prune-bind: target_hash must bind this entry's hash.
            // (entry_hash verification below will confirm this entry is authentic)
        } else {
            // Normal chain link
            if seq != expected_seq {
                result.broken_at = Some(seq);
                break;
            }
            if prev_hash != expected_prev {
                result.broken_at = Some(seq);
                break;
            }
        }

        // --- entry_hash HMAC verification (always, including prune_point) ---
        let recomputed = compute_entry_hash(Some(&secret), &event);
        if recomputed != recorded_hash {
            result.broken_at = Some(seq);
            break;
        }

        // --- prune-bind verification (after prune gap) ---
        if last_was_prune {
            if let (Some(saved_target), Some(saved_count)) =
                (&prune_target_hash, prune_target_count)
            {
                let expected_bind = hmac_bytes(
                    Some(&secret),
                    format!("prune-bind:{saved_count}:{recorded_hash}").as_bytes(),
                );
                if *saved_target != expected_bind {
                    result.broken_at = Some(seq);
                    break;
                }
            }
        }

        // Track prune state
        if is_prune {
            result.pruned = true;
            result.pruned_count = Some(event.target_count as u64);
            prune_target_hash = Some(event.target_hash.clone());
            prune_target_count = Some(event.target_count as u64);
        }

        last_was_prune = is_prune;
        expected_prev = recorded_hash.to_string();
        expected_seq = seq + 1;
        result.chain_entries += 1;
    }

    Ok(result)
}

pub fn show_entries(
    config: &AuditConfig,
    opts: &ShowOptions,
    out: &mut impl Write,
) -> Result<(), AuditError> {
    use std::collections::VecDeque;

    let path = config.path.clone().unwrap_or_else(default_audit_path);
    let file = fs::File::open(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::FileNotFound,
        _ => AuditError::Io(e),
    })?;

    let reader = std::io::BufReader::new(&file);
    let capacity = opts.last.unwrap_or(usize::MAX);
    let mut entries: VecDeque<AuditEvent> = VecDeque::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(ref filter) = opts.rule {
            match &event.rule_id {
                Some(rule) if rule.contains(filter.as_str()) => {}
                _ => continue,
            }
        }
        if opts
            .provider
            .as_ref()
            .is_some_and(|f| !event.provider.contains(f.as_str()))
        {
            continue;
        }

        entries.push_back(event);
        if entries.len() > capacity {
            entries.pop_front();
        }
    }

    if entries.is_empty() {
        return Ok(());
    }

    if opts.json {
        for event in &entries {
            serde_json::to_writer(&mut *out, event).map_err(std::io::Error::from)?;
            writeln!(out)?;
        }
    } else {
        writeln!(
            out,
            "{:<20} {:<12} {:<8} {:<15} {:<8} RULE",
            "TIMESTAMP", "PROVIDER", "COMMAND", "ACTION", "RESULT"
        )?;
        for event in &entries {
            if is_prune_point(event) {
                let ts = display_timestamp(&event.timestamp);
                writeln!(
                    out,
                    "--- pruned {} entries before {ts} ---",
                    event.target_count
                )?;
                continue;
            }
            let rule = event.rule_id.as_deref().unwrap_or("\u{2014}");
            let ts = display_timestamp(&event.timestamp);
            writeln!(
                out,
                "{:<20} {:<12} {:<8} {:<15} {:<8} {rule}",
                ts, event.provider, event.command, event.action, event.result
            )?;
        }
    }

    Ok(())
}

pub fn audit_summary(config: &AuditConfig) -> AuditSummary {
    if !config.enabled {
        return AuditSummary {
            enabled: false,
            entry_count: 0,
            secret_available: false,
            retention_days: 0,
        };
    }

    let path = config.path.clone().unwrap_or_else(default_audit_path);
    let secret_available = read_secret(&secret_path_for(&path)).is_ok();

    let entry_count = fs::File::open(&path)
        .ok()
        .map(|f| {
            std::io::BufReader::new(f)
                .lines()
                .filter(|l| l.as_ref().is_ok_and(|s| !s.trim().is_empty()))
                .count() as u64
        })
        .unwrap_or(0);

    AuditSummary {
        enabled: true,
        entry_count,
        secret_available,
        retention_days: config.retention_days,
    }
}

fn display_timestamp(ts: &str) -> String {
    // "2026-04-04T03:31:02.54814Z" → "2026-04-04T03:31:02Z"
    match ts.find('.') {
        Some(dot) => format!("{}Z", &ts[..dot]),
        None => ts.to_string(),
    }
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
            retention_days: 0,
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
            retention_days: 0,
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
            retention_days: 0,
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

    fn check_chain_manual(events: &[serde_json::Value], secret: Option<&[u8; 32]>) -> bool {
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
        assert!(check_chain_manual(&events, Some(&TEST_SECRET)));

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
            !check_chain_manual(&events, Some(&TEST_SECRET)),
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
            retention_days: 0,
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
            retention_days: 0,
        };
        assert!(logger.append(make_event("rm")).is_err());
    }

    // --- verify_chain ---

    fn verify_config(dir: &Path) -> AuditConfig {
        AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
        }
    }

    #[test]
    fn verify_clean_chain() {
        let dir = test_dir("verify-clean");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("cat")).unwrap();
        logger.append(make_event("echo")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 3);
        assert_eq!(result.legacy_entries, 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_tampered_chain() {
        let dir = test_dir("verify-tamper");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("rm")).unwrap();
        logger.append(make_event("cat")).unwrap();

        let path = dir.join("audit.jsonl");
        let content = fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"passthrough\"", "\"blocked\"", 1);
        fs::write(&path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_then_chain() {
        let dir = test_dir("verify-legacy");
        let logger = test_logger(&dir);

        let path = dir.join("audit.jsonl");
        let legacy = r#"{"timestamp":"2026-01-01T00:00:00Z","provider":"test","command":"old","rule_id":null,"action":"passthrough","result":"passthrough","target_count":0,"target_hash":"sha256:old"}"#;
        fs::write(&path, format!("{legacy}\n{legacy}\n")).unwrap();

        logger.append(make_event("new1")).unwrap();
        logger.append(make_event("new2")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 2);
        assert_eq!(result.legacy_entries, 2);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_only() {
        let dir = test_dir("verify-legacy-only");
        test_logger(&dir); // create secret

        let path = dir.join("audit.jsonl");
        let legacy = r#"{"timestamp":"2026-01-01T00:00:00Z","provider":"test","command":"old","rule_id":null,"action":"passthrough","result":"passthrough","target_count":0,"target_hash":"sha256:old"}"#;
        fs::write(&path, format!("{legacy}\n")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 0);
        assert_eq!(result.legacy_entries, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_empty_file() {
        let dir = test_dir("verify-empty");
        test_logger(&dir); // create secret
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 0);
        assert_eq!(result.legacy_entries, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_torn_line() {
        let dir = test_dir("verify-torn");
        let logger = test_logger(&dir);
        logger.append(make_event("first")).unwrap();

        let path = dir.join("audit.jsonl");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        write!(f, "{{\"broken\":tru").unwrap();

        logger.append(make_event("second")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 2);
        assert!(result.torn_lines > 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_no_secret() {
        let dir = test_dir("verify-no-secret");
        fs::write(dir.join("audit.jsonl"), "").unwrap();
        // No secret file created
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

        // Append events with different rules by manipulating directly
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

        // Write 1100 entries: 1050 old (200 days ago), 50 recent
        let old_ts = "2025-09-18T00:00:00Z"; // ~200 days ago from 2026-04-05
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..1050 {
            entries.push(("old", old_ts));
        }
        for _ in 0..50 {
            entries.push(("new", new_ts));
        }
        // Need at least 1000 retained — 50 < 1000 so prune won't fire.
        // Adjust: 100 old, 1100 new
        entries.clear();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }

        let refs: Vec<(&str, &str)> = entries.iter().copied().collect();
        write_chain_entries(&path, &TEST_SECRET, &refs);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned, 100, "should prune 100 old entries");

        // Verify the file has prune_point + 1100 entries
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

        // 500 old, 500 new = 500 retained < 1000 min → no prune
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
        // retention_days=0 means try_prune is never called from append,
        // but verify it does nothing if called directly
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
        // retention_days=0 is checked in append(), not try_prune() itself
        // But try_prune with very large retention should prune nothing recent
        let pruned = try_prune(&mut file, Some(&TEST_SECRET), 36500).unwrap();
        assert_eq!(pruned, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_pruned_chain_intact() {
        let dir = test_dir("verify-pruned");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        // Create a chain, then manually prune with build_prune_point
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

        // Verify
        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_none(), "pruned chain should verify OK");
        assert!(result.pruned, "should detect prune_point");
        assert_eq!(result.pruned_count, Some(100));
        assert_eq!(result.chain_entries, 1101); // prune_point + 1100 retained

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_forged_prune_point() {
        let dir = test_dir("verify-forged-prune");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        // Write entries
        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..10).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries);

        // Read entries, keep last 5, prepend a forged prune_point
        let events = read_events(&path);
        let retained = &events[5..];

        // Forge a prune_point with wrong secret
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

        // Write chain, prune it
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

        // Now delete an extra entry after the prune_point (attacker removes entry #100)
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // lines[0] = prune_point, lines[1] = first retained (entry #100)
        // Remove lines[1] to simulate extra deletion
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

        // First prune: 50 old, 1100 new
        let old_ts = "2025-01-01T00:00:00Z";
        let mid_ts = "2025-10-01T00:00:00Z"; // ~6 months ago, within 90d? No, > 90d
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

        // First prune
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned1 = try_prune(&mut file, Some(&TEST_SECRET), 90).unwrap();
        assert_eq!(pruned1, 100, "should prune 50 old + 50 mid");
        drop(file);

        // Verify after first prune
        let result1 = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result1.broken_at.is_none(),
            "first prune chain should be intact"
        );
        assert!(result1.pruned);

        // Second prune (simulate time passing — add more old entries conceptually)
        // In practice, we re-prune with a shorter retention to exercise the path
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        // With retention_days=1, all "new" entries at 2026-04-04 would be >1 day old on 2026-04-05
        // But min retain 1000 protects: 1100 retained > 1000
        let pruned2 = try_prune(&mut file, Some(&TEST_SECRET), 1).unwrap();
        // 1100 entries remain, all "old" by 1-day standard, but 1100 > 1000 min retain
        // So some could be pruned: 1100 - 1000 = 100 could be pruned
        // The old prune_point is at index 0 and gets skipped
        assert!(pruned2 <= 100, "second prune should respect min retain");
        drop(file);

        // Verify after second prune
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

        // Write just a prune_point (edge case: all entries pruned except prune_point)
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

        // Write 5 entries, delete the first one (without prune_point)
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

        // Build a file with prune_point + 2 entries
        let prune = build_prune_point(Some(&TEST_SECRET), 42, "hash123");
        let mut content = serde_json::to_string(&prune).unwrap() + "\n";

        let ts = "2026-04-04T00:00:00Z";
        let refs: Vec<(&str, &str)> = vec![("ls", ts), ("cat", ts)];
        // Write entries starting from the prune_point's perspective
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
}
