use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub detector_type: DetectorType,
    pub env_key: String,
    pub env_value: String,
}

impl DetectorConfig {
    pub fn env_var(name: &str, env_key: &str, env_value: &str) -> Self {
        Self {
            name: name.to_string(),
            detector_type: DetectorType::EnvVar,
            env_key: env_key.to_string(),
            env_value: env_value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    EnvVar,
}

pub trait DetectorProvider {
    fn detect(&self, env_map: &HashMap<String, String>) -> Result<bool, String>;
}

impl DetectorProvider for DetectorConfig {
    fn detect(&self, env_map: &HashMap<String, String>) -> Result<bool, String> {
        match self.detector_type {
            DetectorType::EnvVar => {
                if self.env_key.trim().is_empty() {
                    return Err(format!("detector `{}` is missing env_key", self.name));
                }
                Ok(env_map.get(&self.env_key) == Some(&self.env_value))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectionDecision {
    pub protected: bool,
    pub matched_detectors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn evaluate_detectors(
    detectors: &[DetectorConfig],
    env_pairs: &[(String, String)],
) -> DetectionDecision {
    let env_map: HashMap<String, String> = env_pairs.iter().cloned().collect();
    let mut protected = false;
    let mut matched_detectors = Vec::new();
    let mut warnings = Vec::new();

    for detector in detectors {
        match detector.detect(&env_map) {
            Ok(true) => {
                protected = true;
                matched_detectors.push(detector.name.clone());
            }
            Ok(false) => {}
            Err(error) => {
                protected = true;
                warnings.push(error);
            }
        }
    }

    DetectionDecision {
        protected,
        matched_detectors,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_detector_matches_expected_value() {
        let detectors = vec![DetectorConfig::env_var("claude-code", "CLAUDECODE", "1")];
        let env_pairs = vec![("CLAUDECODE".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["claude-code".to_string()]);
    }

    #[test]
    fn malformed_detector_fails_closed() {
        let detectors = vec![DetectorConfig {
            name: "broken".to_string(),
            detector_type: DetectorType::EnvVar,
            env_key: String::new(),
            env_value: "1".to_string(),
        }];
        let result = evaluate_detectors(&detectors, &[]);
        assert!(result.protected);
        assert_eq!(result.warnings.len(), 1);
    }
}
