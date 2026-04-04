use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actions::ActionOutcome;
use crate::rules::{CommandInvocation, RuleConfig};

type HmacSha256 = Hmac<Sha256>;

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
        }
    }

    pub fn append(&self, event: &AuditEvent) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, event)?;
        writeln!(file)?;
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
    /// Detection layer: "layer1" (PATH shim) or "layer2" (hook).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_layer: Option<String>,
    /// Unwrap chain showing how the command was extracted (e.g., ["sudo", "bash -c", "rm -rf /"]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_chain: Option<Vec<String>>,
    /// SHA-256 hash of the raw hook input (before parsing), for non-repudiation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_input_hash: Option<String>,
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
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created it between our read and create attempt.
            match read_secret(path) {
                Ok(secret) => Some(secret),
                Err(e) => {
                    eprintln!("omamori warning: audit secret race: {e}");
                    None
                }
            }
        }
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
    use std::io::Read;

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

    /// Create a logger with a fixed test secret for deterministic assertions.
    fn test_logger(dir: &Path) -> AuditLogger {
        let path = dir.join("audit.jsonl");
        let secret = [0x42u8; 32];

        // Write secret file so from_config-based tests can also read it
        let secret_file = dir.join("audit-secret");
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        AuditLogger {
            path,
            secret: Some(secret),
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omamori-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
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
        assert!(logger.secret.is_some(), "secret should be generated");

        let secret_file = dir.join("audit-secret");
        assert!(secret_file.exists(), "secret file should be created");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secret file should be mode 0600");
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
        // Just verify it doesn't panic; actual secret creation goes to default path
        let logger = AuditLogger::from_config(&config);
        assert!(logger.is_some());
    }

    // --- AuditLogger: append ---

    #[test]
    fn append_writes_jsonl() {
        let dir = test_dir("append");
        let logger = test_logger(&dir);

        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: "rm".to_string(),
            rule_id: Some("test-rule".to_string()),
            action: "trash".to_string(),
            result: "trashed".to_string(),
            target_count: 1,
            target_hash: "hmac-sha256:abc".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
        };

        logger.append(&event).unwrap();
        logger.append(&event).unwrap();

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["command"], "rm");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_io_error() {
        let logger = AuditLogger {
            path: PathBuf::from("/nonexistent/dir/audit.jsonl"),
            secret: Some([0u8; 32]),
        };
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: "rm".to_string(),
            rule_id: None,
            action: "trash".to_string(),
            result: "trashed".to_string(),
            target_count: 0,
            target_hash: "hmac-sha256:empty".to_string(),
            detection_layer: None,
            unwrap_chain: None,
            raw_input_hash: None,
        };
        assert!(logger.append(&event).is_err());
    }

    // --- AuditLogger: create_event ---

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
        assert!(json.contains("\"provider\":\"claude-code\""));
        assert!(json.contains("\"target_count\":2"));
        assert!(
            json.contains("\"target_hash\":\"hmac-sha256:"),
            "target_hash should use hmac-sha256 prefix"
        );

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
        assert_eq!(event.detection_layer, Some("layer1".to_string()));
        assert!(event.unwrap_chain.is_none());
        assert!(event.raw_input_hash.is_none());
        assert_eq!(event.target_count, 2);
        assert!(event.target_hash.starts_with("hmac-sha256:"));

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
        assert_eq!(a, b, "same inputs should produce same hash");
        assert!(a.starts_with("hmac-sha256:"));
    }

    #[test]
    fn hmac_targets_different_secrets() {
        let a = hmac_targets(Some(&[0x01; 32]), &["file.txt"]);
        let b = hmac_targets(Some(&[0x02; 32]), &["file.txt"]);
        assert_ne!(a, b, "different secrets should produce different hashes");
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
        let result = create_secret(&path);
        assert!(result.is_err(), "create_new should prevent overwrite");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_creates_when_missing() {
        let dir = test_dir("load-or-create");
        let path = dir.join("audit-secret");

        let secret = load_or_create_secret(&path);
        assert!(secret.is_some());
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
        let bad = "zz".repeat(32);
        assert!(decode_hex_secret(&bad).is_err());
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
        logger.append(&event).unwrap();
        logger.append(&event).unwrap();

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line must be valid JSON");
            assert!(parsed.get("command").is_some());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- secret_path_for ---

    #[test]
    fn secret_path_derives_from_audit_path() {
        let audit = PathBuf::from("/home/user/.local/share/omamori/audit.jsonl");
        assert_eq!(
            secret_path_for(&audit),
            PathBuf::from("/home/user/.local/share/omamori/audit-secret")
        );
    }
}
