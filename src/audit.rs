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
}
