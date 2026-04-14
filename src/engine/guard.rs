//! AI environment guard for config-mutating operations.
//!
//! SECURITY (T3): `guard_ai_config_modification` must be called on every
//! config-mutating code path (9 call sites as of v0.9.0).

use crate::AppError;
use crate::config;
use crate::detector::evaluate_detectors;

/// Guard against AI agents modifying omamori's own configuration.
/// Blocks when any AI detector env var is present (exact match via evaluate_detectors).
pub(crate) fn guard_ai_config_modification(operation: &str) -> Result<(), AppError> {
    let detectors = config::default_detectors();
    let env_pairs: Vec<(String, String)> = std::env::vars().collect();
    let detection = evaluate_detectors(&detectors, &env_pairs);
    if detection.protected {
        return Err(AppError::Config(format!(
            "{operation} blocked — AI agent environment detected ({}).\n  \
             Protection rules cannot be modified by AI tools.\n  \
             To modify, run this command directly in your terminal (not via AI).",
            detection.matched_detectors.join(", ")
        )));
    }
    Ok(())
}
