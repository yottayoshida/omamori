//! Break-glass: time-limited, audited bypass for specific rules.
//!
//! State file: `~/.local/share/omamori/break-glass.json`
//! Already protected from AI writes by PROTECTED_FILE_PATTERNS.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STATE_FILE_NAME: &str = "break-glass.json";
const STATE_VERSION: u32 = 1;
pub(crate) const MAX_CONCURRENT: usize = 3;
pub(crate) const DEFAULT_DURATION_SECS: u64 = 3600; // 1h
const MIN_DURATION_SECS: u64 = 300; // 5m
const MAX_DURATION_SECS: u64 = 86400; // 24h

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BreakGlassState {
    pub version: u32,
    pub entries: Vec<BreakGlassEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BreakGlassEntry {
    pub rule_id: String,
    pub activated_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl BreakGlassEntry {
    pub fn is_expired(&self) -> bool {
        let Ok(expires) = OffsetDateTime::parse(&self.expires_at, &Rfc3339) else {
            return true; // unparseable = expired (fail-closed)
        };
        OffsetDateTime::now_utc() >= expires
    }

    pub fn remaining_secs(&self) -> Option<i64> {
        let expires = OffsetDateTime::parse(&self.expires_at, &Rfc3339).ok()?;
        let remaining = (expires - OffsetDateTime::now_utc()).whole_seconds();
        Some(remaining.max(0))
    }
}

// ---------------------------------------------------------------------------
// Non-bypassable rules (DI-13 self-protection)
// ---------------------------------------------------------------------------

pub(crate) fn non_bypassable_rules() -> &'static [&'static str] {
    &[
        "omamori-config-modify-block",
        "omamori-uninstall-block",
        "omamori-init-force-block",
        "omamori-override-block",
        "omamori-doctor-fix-block",
        "omamori-explain-block",
        "omamori-break-glass-block",
    ]
}

pub(crate) fn is_non_bypassable(rule_id: &str) -> bool {
    non_bypassable_rules().contains(&rule_id)
}

// ---------------------------------------------------------------------------
// Core: is_bypassed()
// ---------------------------------------------------------------------------

/// Check if a rule is currently bypassed by break-glass.
///
/// All failure modes return `false` (fail-closed).
pub(crate) fn is_bypassed(rule_id: &str) -> bool {
    if is_non_bypassable(rule_id) {
        return false;
    }
    is_bypassed_inner(rule_id, &state_file_path())
}

fn is_bypassed_inner(rule_id: &str, path: &Path) -> bool {
    // Single syscall fast path: no file = no bypass
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Symlink rejection
    if meta.file_type().is_symlink() {
        return false;
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let state: BreakGlassState = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if state.version != STATE_VERSION {
        return false;
    }

    state
        .entries
        .iter()
        .any(|e| e.rule_id == rule_id && !e.is_expired())
}

/// Return bypass info for a rule (for audit/display purposes).
pub(crate) fn bypass_info(rule_id: &str) -> Option<BreakGlassEntry> {
    if is_non_bypassable(rule_id) {
        return None;
    }
    let path = state_file_path();
    let state = read_state(&path)?;
    state
        .entries
        .into_iter()
        .find(|e| e.rule_id == rule_id && !e.is_expired())
}

// ---------------------------------------------------------------------------
// State file I/O
// ---------------------------------------------------------------------------

pub(crate) fn state_file_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".local")
        .join("share")
        .join("omamori")
        .join(STATE_FILE_NAME)
}

fn read_state(path: &Path) -> Option<BreakGlassState> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let state: BreakGlassState = serde_json::from_str(&content).ok()?;
    if state.version != STATE_VERSION {
        return None;
    }
    Some(state)
}

pub(crate) fn read_active_entries() -> Vec<BreakGlassEntry> {
    let path = state_file_path();
    read_state(&path)
        .map(|s| s.entries.into_iter().filter(|e| !e.is_expired()).collect())
        .unwrap_or_default()
}

/// Atomic write via `atomic_file::atomic_write_with_mode`. Before #307 this
/// hand-rolled a fixed-name temp file with no `O_NOFOLLOW` and set
/// permissions *after* opening — the only one of the atomic-write sites
/// lacking both protections. Both close here: mode is set at creation, and
/// the random temp name makes the old "reject if tmp path is a symlink"
/// pre-check moot (an attacker can no longer predict the path to plant a
/// symlink at).
pub(crate) fn write_state(state: &BreakGlassState) -> Result<(), std::io::Error> {
    let path = state_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut content = serde_json::to_vec_pretty(state)?;
    content.push(b'\n');

    crate::atomic_file::atomic_write_with_mode(&path, &content, 0o600)
}

pub(crate) fn remove_state_file() -> Result<(), std::io::Error> {
    let path = state_file_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Activation / Deactivation
// ---------------------------------------------------------------------------

pub(crate) fn activate(
    rule_id: &str,
    duration_secs: u64,
    reason: Option<String>,
) -> Result<BreakGlassEntry, ActivationError> {
    // Validate rule_id is known
    let known = config::core_rule_names();
    if !known.contains(&rule_id) {
        return Err(ActivationError::UnknownRule(rule_id.to_string()));
    }

    // DI-13 check
    if is_non_bypassable(rule_id) {
        return Err(ActivationError::NonBypassable(rule_id.to_string()));
    }

    let path = state_file_path();
    let mut state = read_state(&path).unwrap_or(BreakGlassState {
        version: STATE_VERSION,
        entries: Vec::new(),
    });

    // Prune expired
    state.entries.retain(|e| !e.is_expired());

    // Check if already active for this rule
    if state.entries.iter().any(|e| e.rule_id == rule_id) {
        return Err(ActivationError::AlreadyActive(rule_id.to_string()));
    }

    // Max concurrent check
    if state.entries.len() >= MAX_CONCURRENT {
        return Err(ActivationError::MaxConcurrent);
    }

    let now = OffsetDateTime::now_utc();
    let expires = now + time::Duration::seconds(duration_secs as i64);

    let entry = BreakGlassEntry {
        rule_id: rule_id.to_string(),
        activated_at: now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        expires_at: expires
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        reason,
    };

    state.entries.push(entry.clone());
    write_state(&state).map_err(ActivationError::Io)?;

    Ok(entry)
}

pub(crate) fn clear_rule(rule_id: &str) -> Result<bool, std::io::Error> {
    let path = state_file_path();
    let Some(mut state) = read_state(&path) else {
        return Ok(false);
    };
    let before = state.entries.len();
    state.entries.retain(|e| e.rule_id != rule_id);
    if state.entries.len() == before {
        return Ok(false);
    }
    if state.entries.is_empty() {
        remove_state_file()?;
    } else {
        write_state(&state)?;
    }
    Ok(true)
}

pub(crate) fn clear_all() -> Result<usize, std::io::Error> {
    let path = state_file_path();
    let Some(state) = read_state(&path) else {
        return Ok(0);
    };
    let count = state.entries.iter().filter(|e| !e.is_expired()).count();
    remove_state_file()?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let (num_str, unit) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        (s, 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number: {num_str}"))?;
    let secs = num.checked_mul(unit).ok_or("duration overflow")?;

    if secs < MIN_DURATION_SECS {
        return Err(format!(
            "duration too short: minimum is {}m",
            MIN_DURATION_SECS / 60
        ));
    }
    if secs > MAX_DURATION_SECS {
        return Err(format!(
            "duration too long: maximum is {}h",
            MAX_DURATION_SECS / 3600
        ));
    }

    Ok(secs)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) enum ActivationError {
    UnknownRule(String),
    NonBypassable(String),
    AlreadyActive(String),
    MaxConcurrent,
    Io(std::io::Error),
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRule(r) => write!(f, "unknown rule: {r}"),
            Self::NonBypassable(r) => {
                write!(
                    f,
                    "rule '{r}' is a DI-13 self-protection rule and cannot be bypassed"
                )
            }
            Self::AlreadyActive(r) => write!(f, "break-glass already active for rule: {r}"),
            Self::MaxConcurrent => write!(
                f,
                "maximum {} concurrent bypasses reached — clear one first",
                MAX_CONCURRENT
            ),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

pub(crate) fn format_remaining(secs: i64) -> String {
    if secs <= 0 {
        return "expired".to_string();
    }
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    if hours > 0 {
        format!("{hours}h{mins:02}m")
    } else {
        format!("{mins}m")
    }
}

pub(crate) fn format_duration_human(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    if hours > 0 && mins > 0 {
        format!("{hours} hour(s) {mins} minute(s)")
    } else if hours > 0 {
        format!("{hours} hour(s)")
    } else {
        format!("{mins} minute(s)")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn setup_temp_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = PathBuf::from(home).join(format!(".omamori-test-{pid}-{id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn is_bypassed_no_file_returns_false() {
        let dir = setup_temp_dir();
        let path = dir.join("nonexistent.json");
        assert!(!is_bypassed_inner("rm-recursive-to-trash", &path));
        cleanup(&dir);
    }

    #[test]
    fn is_bypassed_corrupted_json_returns_false() {
        let dir = setup_temp_dir();
        let path = dir.join("break-glass.json");
        fs::write(&path, "not valid json!!!").unwrap();
        assert!(!is_bypassed_inner("rm-recursive-to-trash", &path));
        cleanup(&dir);
    }

    #[test]
    fn is_bypassed_wrong_version_returns_false() {
        let dir = setup_temp_dir();
        let path = dir.join("break-glass.json");
        let state = r#"{"version": 999, "entries": []}"#;
        fs::write(&path, state).unwrap();
        assert!(!is_bypassed_inner("rm-recursive-to-trash", &path));
        cleanup(&dir);
    }

    #[test]
    fn is_bypassed_expired_entry_returns_false() {
        let dir = setup_temp_dir();
        let path = dir.join("break-glass.json");
        let state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![BreakGlassEntry {
                rule_id: "rm-recursive-to-trash".to_string(),
                activated_at: "2020-01-01T00:00:00Z".to_string(),
                expires_at: "2020-01-01T01:00:00Z".to_string(),
                reason: None,
            }],
        };
        fs::write(&path, serde_json::to_string(&state).unwrap()).unwrap();
        assert!(!is_bypassed_inner("rm-recursive-to-trash", &path));
        cleanup(&dir);
    }

    #[test]
    fn is_bypassed_active_entry_returns_true() {
        let dir = setup_temp_dir();
        let path = dir.join("break-glass.json");
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(1);
        let state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![BreakGlassEntry {
                rule_id: "rm-recursive-to-trash".to_string(),
                activated_at: now.format(&Rfc3339).unwrap(),
                expires_at: expires.format(&Rfc3339).unwrap(),
                reason: None,
            }],
        };
        fs::write(&path, serde_json::to_string(&state).unwrap()).unwrap();
        assert!(is_bypassed_inner("rm-recursive-to-trash", &path));
        cleanup(&dir);
    }

    #[test]
    fn is_bypassed_non_bypassable_always_false() {
        for rule in non_bypassable_rules() {
            assert!(
                !is_bypassed(rule),
                "non-bypassable rule {rule} must never return true"
            );
        }
    }

    #[test]
    fn is_bypassed_wrong_rule_returns_false() {
        let dir = setup_temp_dir();
        let path = dir.join("break-glass.json");
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(1);
        let state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![BreakGlassEntry {
                rule_id: "rm-recursive-to-trash".to_string(),
                activated_at: now.format(&Rfc3339).unwrap(),
                expires_at: expires.format(&Rfc3339).unwrap(),
                reason: None,
            }],
        };
        fs::write(&path, serde_json::to_string(&state).unwrap()).unwrap();
        assert!(!is_bypassed_inner("git-push-force-block", &path));
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn is_bypassed_symlink_returns_false() {
        let dir = setup_temp_dir();
        let target = dir.join("real.json");
        let link = dir.join("break-glass.json");
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(1);
        let state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![BreakGlassEntry {
                rule_id: "rm-recursive-to-trash".to_string(),
                activated_at: now.format(&Rfc3339).unwrap(),
                expires_at: expires.format(&Rfc3339).unwrap(),
                reason: None,
            }],
        };
        fs::write(&target, serde_json::to_string(&state).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!is_bypassed_inner("rm-recursive-to-trash", &link));
        cleanup(&dir);
    }

    #[test]
    fn parse_duration_valid() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("24h").unwrap(), 86400);
        assert_eq!(parse_duration("300s").unwrap(), 300);
        assert_eq!(parse_duration("300").unwrap(), 300);
    }

    #[test]
    fn parse_duration_too_short() {
        assert!(parse_duration("1m").is_err());
        assert!(parse_duration("4m").is_err());
    }

    #[test]
    fn parse_duration_too_long() {
        assert!(parse_duration("25h").is_err());
        assert!(parse_duration("100h").is_err());
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn non_bypassable_covers_all_omamori_core_rules() {
        let core = crate::config::core_rule_names();
        let deny = non_bypassable_rules();
        for name in &core {
            if name.starts_with("omamori-") {
                assert!(
                    deny.contains(name),
                    "DI-13 rule '{name}' missing from non_bypassable_rules() — \
                     every omamori-* core rule must be non-bypassable"
                );
            }
        }
    }

    #[test]
    fn format_remaining_display() {
        assert_eq!(format_remaining(3661), "1h01m");
        assert_eq!(format_remaining(300), "5m");
        assert_eq!(format_remaining(0), "expired");
        assert_eq!(format_remaining(-10), "expired");
    }
}
