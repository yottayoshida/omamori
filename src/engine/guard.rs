//! AI environment guard for config-mutating operations.
//!
//! SECURITY (T3): `guard_ai_config_modification` must be called on every
//! config-mutating code path. (A call-site *count* used to be pinned here,
//! but it went stale at least twice as new mutating subcommands were added
//! without updating it — /code-review R1 finding. Grep for
//! `guard_ai_config_modification(` to see the current call sites instead of
//! trusting a number in this comment.)

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
