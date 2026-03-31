use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actions::ActionOutcome;
use crate::rules::{CommandInvocation, RuleConfig};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default)]
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            path: config.path.clone().unwrap_or_else(default_audit_path),
        })
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

impl AuditEvent {
    pub fn from_outcome(
        invocation: &CommandInvocation,
        matched_rule: Option<&RuleConfig>,
        matched_detectors: &[String],
        outcome: &ActionOutcome,
    ) -> Self {
        let targets = invocation.target_args();
        Self {
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
            target_hash: hash_targets(&targets),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
        }
    }
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

fn hash_targets(targets: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for target in targets {
        hasher.update(target.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{ActionKind, RuleConfig};

    // --- G-07: AuditLogger ---

    #[test]
    fn audit_logger_from_config_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
        };
        assert!(AuditLogger::from_config(&config).is_none());
    }

    #[test]
    fn audit_logger_from_config_enabled() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("/tmp/test-audit.jsonl")),
        };
        assert!(AuditLogger::from_config(&config).is_some());
    }

    #[test]
    fn audit_logger_append_writes_jsonl() {
        let dir = std::env::temp_dir().join(format!("omamori-audit-g07-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = dir.join("audit.jsonl");
        let logger = AuditLogger { path: path.clone() };

        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: "rm".to_string(),
            rule_id: Some("test-rule".to_string()),
            action: "trash".to_string(),
            result: "trashed".to_string(),
            target_count: 1,
            target_hash: "sha256:abc".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
        };

        logger.append(&event).unwrap();
        logger.append(&event).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "should have 2 JSONL lines");

        // Each line should be valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["command"], "rm");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_logger_append_io_error() {
        // Write to a path that can't be created
        let logger = AuditLogger {
            path: PathBuf::from("/nonexistent/dir/audit.jsonl"),
        };

        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: "rm".to_string(),
            rule_id: None,
            action: "trash".to_string(),
            result: "trashed".to_string(),
            target_count: 0,
            target_hash: "sha256:empty".to_string(),
            detection_layer: None,
            unwrap_chain: None,
            raw_input_hash: None,
        };

        let result = logger.append(&event);
        assert!(result.is_err());
    }

    #[test]
    fn audit_event_hides_argument_values() {
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
        let event = AuditEvent::from_outcome(
            &invocation,
            Some(&rule),
            &["claude-code".to_string()],
            &ActionOutcome::Trashed {
                exit_code: 0,
                message: "ok".to_string(),
            },
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("secret.txt"));
        assert!(json.contains("\"provider\":\"claude-code\""));
        assert!(json.contains("\"target_count\":2"));
        assert!(json.contains("\"target_hash\":\"sha256:"));
    }

    // --- G-07 cont.: additional coverage ---

    #[test]
    #[serial_test::serial]
    fn audit_logger_from_config_default_path() {
        let config = AuditConfig {
            enabled: true,
            path: None,
        };
        let logger = AuditLogger::from_config(&config).expect("should create logger");
        // default_audit_path() uses HOME env
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let expected = home
            .join(".local")
            .join("share")
            .join("omamori")
            .join("audit.jsonl");
        assert_eq!(logger.path, expected);
    }

    #[test]
    fn audit_event_from_outcome_all_fields() {
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
        let event = AuditEvent::from_outcome(
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
        assert!(!event.target_hash.is_empty());
    }

    #[test]
    fn audit_logger_jsonl_special_chars() {
        let dir = std::env::temp_dir().join(format!("omamori-audit-g07-sc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("test.jsonl");

        let logger = AuditLogger {
            path: log_path.clone(),
        };

        // Event with special characters in fields
        let invocation = CommandInvocation::new(
            "echo".to_string(),
            vec!["hello\nworld".to_string(), "it's \"quoted\"".to_string()],
        );
        let event = AuditEvent::from_outcome(
            &invocation,
            None,
            &["test\u{1F680}".to_string()], // rocket emoji
            &ActionOutcome::PassedThrough { exit_code: 0 },
        );
        logger.append(&event).unwrap();

        // Append a second event to verify multi-line JSONL
        logger.append(&event).unwrap();

        // Read back and verify each line is valid JSON
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 JSONL lines");
        for line in &lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line must be valid JSON");
            assert!(parsed.get("command").is_some());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
