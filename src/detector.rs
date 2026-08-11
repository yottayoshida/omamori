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

/// Whether literal repair instructions may be printed into this invocation's
/// output (SEC-R5).
///
/// Distinct from [`DetectionDecision::protected`] only in what it is *for*.
/// `protected` drives **enforcement** — whether omamori interposes at all — and
/// `engine::guard` deliberately answers that from the built-in list, because an
/// agent that can narrow the operator's list must not thereby unlock the guard
/// that stops it from narrowing the list. **Disclosure** runs the other way: the
/// operator is the only party who knows which tools they run, so the detector
/// set they declared is authoritative (ADR-0009).
#[derive(Debug, Clone)]
pub struct RepairGate {
    /// `false` when a detector matched. The *condition* is still reported in
    /// every case — withholding the observation would hide a degraded store
    /// from its reader, which inverts what the gate is for. What is withheld is
    /// the sentence that names a file and says what to do to it.
    pub allow_repair: bool,
    /// Detector-evaluation warnings, carried out rather than printed here.
    ///
    /// Two reasons. This stays a pure function, and the caller knows where its
    /// other warnings go. It matters more than it looks: an invalid detector
    /// fails closed in [`evaluate_detectors`] (`protected = true`), so
    /// `allow_repair` is `false` and **the reason for it is only visible if the
    /// caller prints these** — otherwise a typo in `config.toml` silently
    /// withholds every repair with nothing on screen to explain it.
    pub warnings: Vec<String>,
}

/// Decide [`RepairGate`] from a detector set and an explicit environment.
///
/// `env_pairs` is a parameter for the same reason [`evaluate_detectors`] takes
/// one: a test that had to set a process-wide variable to reach this decision
/// would race its neighbours *and* answer differently depending on who ran
/// `cargo test` — under Claude Code `CLAUDECODE=1` is already set, and that is
/// one of the built-in detectors.
pub fn repair_gate(detectors: &[DetectorConfig], env_pairs: &[(String, String)]) -> RepairGate {
    let decision = evaluate_detectors(detectors, env_pairs);
    RepairGate {
        allow_repair: !decision.protected,
        warnings: decision.warnings,
    }
}

/// [`repair_gate`] against the current process environment.
///
/// Private on purpose. Returning the whole gate to a caller means the caller can
/// take `allow_repair` and drop `warnings`, which review found at three call
/// sites before this was closed — and a rule that has to be remembered at every
/// new call site is the kind of rule that gets forgotten. Callers go through
/// [`repair_gate_reporting`], which cannot be used wrongly in that way.
/// [`repair_gate`] itself stays public and parameterised so tests can decide a
/// verdict without touching the real environment.
fn repair_gate_from_env(detectors: &[DetectorConfig]) -> RepairGate {
    let env_pairs: Vec<(String, String)> = std::env::vars().collect();
    repair_gate(detectors, &env_pairs)
}

/// [`repair_gate_from_env`], reduced to the verdict, with the warnings printed.
///
/// For call sites whose own job is something else — appending an event, logging
/// a bypass — and which therefore have no other place to put the reasons. The
/// verdict alone is not safe to take: an unevaluable detector fails closed, so
/// dropping the warnings turns a typo in `config.toml` into every repair going
/// quiet with nothing on screen to act on. Returning `bool` makes that the
/// convenient path rather than the one a caller has to remember.
pub fn repair_gate_reporting(detectors: &[DetectorConfig]) -> bool {
    let gate = repair_gate_from_env(detectors);
    for warning in &gate.warnings {
        eprintln!("omamori warning: {warning}");
    }
    gate.allow_repair
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #527 review (P1): no call site may take the verdict and drop the reasons.
    ///
    /// Review found three files doing `repair_gate_from_env(..).allow_repair`,
    /// which throws away the warning explaining why an unevaluable detector
    /// withheld every repair — the exact failure `RepairGate::warnings`
    /// documents. `repair_gate_reporting` is the fix; this keeps the shape from
    /// coming back.
    ///
    /// Source-level on purpose. The defect is the *absence* of a print at a call
    /// site, and no runtime assertion can observe code that was never written.
    ///
    /// Privacy already makes the shape unreachable from outside this module —
    /// this is the second lock, and the one that says why in a failure message.
    #[test]
    fn no_call_site_takes_the_verdict_without_the_warnings() {
        for (name, src) in [
            ("cli/config_cmd.rs", include_str!("cli/config_cmd.rs")),
            (
                "cli/break_glass_cmd.rs",
                include_str!("cli/break_glass_cmd.rs"),
            ),
            ("engine/hook.rs", include_str!("engine/hook.rs")),
            ("engine/shim.rs", include_str!("engine/shim.rs")),
            ("cli/audit_cmd.rs", include_str!("cli/audit_cmd.rs")),
        ] {
            assert!(
                !src.contains("repair_gate_from_env"),
                "{name} calls repair_gate_from_env directly. Use repair_gate_reporting, or the \
                 reason a repair was withheld never reaches the operator (#527 review P1)."
            );
        }

        // Control: the replacement is genuinely in use. Without this the loop
        // above would also pass on a tree where neither name appears at all —
        // "no bad call sites" and "no call sites" are the same string search.
        assert!(
            include_str!("cli/audit_cmd.rs").contains("repair_gate_reporting"),
            "audit_cmd should be reaching the gate through the reporting form"
        );
    }

    #[test]
    fn env_detector_matches_expected_value() {
        let detectors = vec![DetectorConfig::env_var("claude-code", "CLAUDECODE", "1")];
        let env_pairs = vec![("CLAUDECODE".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["claude-code".to_string()]);
    }

    #[test]
    fn codex_detector_matches() {
        let detectors = vec![DetectorConfig::env_var("codex-cli", "CODEX_CI", "1")];
        let env_pairs = vec![("CODEX_CI".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["codex-cli"]);
    }

    #[test]
    fn cursor_detector_matches() {
        let detectors = vec![DetectorConfig::env_var("cursor", "CURSOR_AGENT", "1")];
        let env_pairs = vec![("CURSOR_AGENT".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["cursor"]);
    }

    #[test]
    fn ai_guard_fallback_matches() {
        let detectors = vec![DetectorConfig::env_var(
            "ai-guard-fallback",
            "AI_GUARD",
            "1",
        )];
        let env_pairs = vec![("AI_GUARD".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["ai-guard-fallback"]);
    }

    #[test]
    fn no_env_vars_means_unprotected() {
        let detectors = vec![
            DetectorConfig::env_var("claude-code", "CLAUDECODE", "1"),
            DetectorConfig::env_var("codex-cli", "CODEX_CI", "1"),
            DetectorConfig::env_var("cursor", "CURSOR_AGENT", "1"),
        ];
        let result = evaluate_detectors(&detectors, &[]);
        assert!(!result.protected);
        assert!(result.matched_detectors.is_empty());
    }

    #[test]
    fn wrong_value_means_unprotected() {
        let detectors = vec![DetectorConfig::env_var("cursor", "CURSOR_AGENT", "1")];
        let env_pairs = vec![("CURSOR_AGENT".to_string(), "0".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(!result.protected);
    }

    #[test]
    fn claude_code_regression_guard() {
        let detectors = vec![DetectorConfig::env_var("claude-code", "CLAUDECODE", "1")];
        let env_pairs = vec![("CLAUDECODE".to_string(), "1".to_string())];
        let result = evaluate_detectors(&detectors, &env_pairs);
        assert!(result.protected);
        assert_eq!(result.matched_detectors, vec!["claude-code"]);
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
