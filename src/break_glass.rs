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
        self.is_expired_at(OffsetDateTime::now_utc())
    }

    /// `is_expired()` with an injectable "now", so the inclusive boundary
    /// (`now >= expires`, not `now > expires`) is deterministically
    /// testable — a real clock reading has always advanced by the time a
    /// test can compare it to itself, so both operators would agree by
    /// coincidence rather than by the comparison actually being exercised.
    fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        let Ok(expires) = OffsetDateTime::parse(&self.expires_at, &Rfc3339) else {
            return true; // unparseable = expired (fail-closed)
        };
        now >= expires
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
    let Some(path) = state_file_path() else {
        // HOME is unset, empty, or relative — no usable state path, so no
        // bypass can be in effect (fail-closed).
        return false;
    };
    is_bypassed_inner(rule_id, &path)
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
    let path = state_file_path()?;
    let state = read_state(&path)?;
    state
        .entries
        .into_iter()
        .find(|e| e.rule_id == rule_id && !e.is_expired())
}

// ---------------------------------------------------------------------------
// State file I/O
// ---------------------------------------------------------------------------

/// `None` when `HOME` is unusable (unset/empty/relative) — see
/// `context::data_dir`. Every caller treats `None` as "no state
/// reachable", which for break-glass means fail-closed: no bypass can be
/// read, activated, or cleared without a resolvable state path.
pub(crate) fn state_file_path() -> Option<PathBuf> {
    crate::context::data_dir().map(|d| d.join(STATE_FILE_NAME))
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
    let Some(path) = state_file_path() else {
        return Vec::new();
    };
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
    let path = state_file_path().ok_or_else(|| {
        std::io::Error::other(
            "HOME is unset, empty, or relative — cannot resolve break-glass state path",
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut content = serde_json::to_vec_pretty(state)?;
    content.push(b'\n');

    crate::atomic_file::atomic_write_with_mode(&path, &content, 0o600)
}

/// Removes expired entries from `state.entries` in place, returning them.
///
/// This is the single place expiry is discovered as a *state transition*
/// (as opposed to `is_expired()`, which is a stateless per-entry check
/// used everywhere on the read path). `activate()` and `clear_rule()` are
/// the two callers that persist state afterward — each is a record point
/// for #324's `break-glass-expired-observed` audit event, and each pruned
/// entry is returned to the caller exactly once, only when the state that
/// no longer contains it has actually been written (see call sites: the
/// return value is discarded on any early-return path that doesn't reach
/// `write_state`, so a pruned-but-never-persisted entry is never reported
/// as having "left" the state — because on disk, it hasn't).
///
/// There is no daemon, so this can't fire at the instant an entry expires
/// — only the next time something calls `activate()`/`clear_rule()` (or
/// never, if neither is called again for that rule). This is a structural
/// limitation of the zero-daemon design, not a bug.
pub(crate) fn prune_expired_entries(state: &mut BreakGlassState) -> Vec<BreakGlassEntry> {
    let mut expired = Vec::new();
    state.entries.retain(|e| {
        if e.is_expired() {
            expired.push(e.clone());
            false
        } else {
            true
        }
    });
    expired
}

pub(crate) fn remove_state_file() -> Result<(), std::io::Error> {
    let Some(path) = state_file_path() else {
        return Ok(()); // no usable HOME → nothing could have been written
    };
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Activation / Deactivation
// ---------------------------------------------------------------------------

/// On success, also returns any entries `prune_expired_entries` removed
/// during this call — the caller (CLI layer) audit-logs each as
/// `break-glass-expired-observed` (#324). Only ever returned alongside
/// `Ok`: every early-return path below (`UnknownRule`/`NonBypassable`/
/// `AlreadyActive`/`MaxConcurrent`) exits before `write_state` runs, so a
/// pruned-in-memory entry that was never actually persisted is never
/// reported as expired-and-removed.
pub(crate) fn activate(
    rule_id: &str,
    duration_secs: u64,
    reason: Option<String>,
) -> Result<(BreakGlassEntry, Vec<BreakGlassEntry>), ActivationError> {
    // Validate rule_id is known
    let known = config::core_rule_names();
    if !known.contains(&rule_id) {
        return Err(ActivationError::UnknownRule(rule_id.to_string()));
    }

    // DI-13 check
    if is_non_bypassable(rule_id) {
        return Err(ActivationError::NonBypassable(rule_id.to_string()));
    }

    let path = state_file_path().ok_or_else(|| {
        ActivationError::Io(std::io::Error::other(
            "HOME is unset, empty, or relative — cannot resolve break-glass state path",
        ))
    })?;
    let mut state = read_state(&path).unwrap_or(BreakGlassState {
        version: STATE_VERSION,
        entries: Vec::new(),
    });

    let expired = prune_expired_entries(&mut state);

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

    Ok((entry, expired))
}

/// Returns `(rule_removed, expired)`: `rule_removed` is `true` only if
/// `rule_id` specifically was found and removed (unchanged CLI-facing
/// semantics — "was the requested rule cleared"). `expired` is any
/// entries `prune_expired_entries` removed during this call, regardless
/// of whether `rule_id` itself was found — pruning and the requested
/// removal are independent state changes that share this one write
/// (#324 V-013: this is the second of the two record points, alongside
/// `activate`).
pub(crate) fn clear_rule(rule_id: &str) -> Result<(bool, Vec<BreakGlassEntry>), std::io::Error> {
    let Some(path) = state_file_path() else {
        return Ok((false, Vec::new()));
    };
    let Some(mut state) = read_state(&path) else {
        return Ok((false, Vec::new()));
    };
    let expired = prune_expired_entries(&mut state);
    let before = state.entries.len();
    state.entries.retain(|e| e.rule_id != rule_id);
    let rule_removed = state.entries.len() != before;

    if !rule_removed && expired.is_empty() {
        // Nothing changed — avoid a no-op state write.
        return Ok((false, Vec::new()));
    }

    if state.entries.is_empty() {
        remove_state_file()?;
    } else {
        write_state(&state)?;
    }
    Ok((rule_removed, expired))
}

/// Note (#324 scope): unlike `activate`/`clear_rule`, this does not report
/// pruned-expired entries for audit recording. It destroys the whole
/// state file in one step rather than selectively pruning, and the
/// existing `break-glass-deactivate` event this call's caller already
/// logs covers the operator-initiated clear as a single action — plan
/// scoped #324's expired-observed event to the two selective-prune call
/// sites only.
pub(crate) fn clear_all() -> Result<usize, std::io::Error> {
    let Some(path) = state_file_path() else {
        return Ok(0);
    };
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
        // `temp_dir()`, not ambient `$HOME`: this file also carries tests
        // that mutate the process-global `HOME` env var (tagged
        // `serial(home_env)`), and reading `HOME` here without the same
        // tag would race them (#344-class flake).
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("omamori-test-{pid}-{id}"));
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

    // -----------------------------------------------------------------
    // HOME-unusable fail-close (#323): state_file_path() → None must
    // propagate as "no bypass possible", not silently resolve against CWD.
    // -----------------------------------------------------------------

    use crate::test_support::with_home;

    #[test]
    #[serial_test::serial(home_env)]
    fn state_file_path_none_when_home_empty() {
        assert_eq!(with_home(Some(""), state_file_path), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn state_file_path_none_when_home_relative() {
        assert_eq!(with_home(Some("relative"), state_file_path), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn state_file_path_matches_data_dir_when_home_absolute() {
        // Happy-path pin: guards against `state_file_path` accidentally
        // being wired to `context::home_dir()` directly instead of
        // `context::data_dir()`, which would move break-glass state from
        // `~/.local/share/omamori/break-glass.json` to `~/break-glass.json`.
        let result = with_home(Some("/tmp/omamori-state-file-path-test"), state_file_path);
        assert_eq!(
            result,
            Some(PathBuf::from(
                "/tmp/omamori-state-file-path-test/.local/share/omamori/break-glass.json"
            ))
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn is_bypassed_ignores_entry_activated_before_home_became_unusable() {
        // An active entry written while HOME was fine must not somehow
        // still be observed once HOME breaks — is_bypassed() re-resolves
        // state_file_path() fresh on every call, so once HOME breaks there
        // is no stale path to fall back to.
        let home =
            std::env::temp_dir().join(format!("omamori-bg-stale-entry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();

        with_home(Some(home.to_str().unwrap()), || {
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
            write_state(&state).unwrap();
            assert!(
                is_bypassed("rm-recursive-to-trash"),
                "entry should be active while HOME is valid"
            );
        });

        // HOME is now unusable — the entry written above still exists on
        // disk at the old (now-unreachable) path, but is_bypassed() must
        // not somehow still find it.
        assert!(!with_home(Some(""), || is_bypassed(
            "rm-recursive-to-trash"
        )));

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn is_bypassed_false_when_home_unusable() {
        // Even a non-bypassable check aside, a usable rule must fail closed
        // when the state path cannot be resolved at all.
        assert!(!with_home(Some(""), || is_bypassed(
            "rm-recursive-to-trash"
        )));
        assert!(!with_home(None, || is_bypassed("rm-recursive-to-trash")));
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn bypass_info_none_when_home_unusable() {
        assert!(with_home(Some(""), || bypass_info("rm-recursive-to-trash")).is_none());
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn read_active_entries_empty_when_home_unusable() {
        assert!(with_home(Some(""), read_active_entries).is_empty());
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn activate_errors_when_home_unusable() {
        let result = with_home(Some(""), || {
            activate("rm-recursive-to-trash", DEFAULT_DURATION_SECS, None)
        });
        assert!(
            matches!(result, Err(ActivationError::Io(_))),
            "activate() must fail closed (Io error), not silently write to CWD; got {result:?}"
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn clear_rule_returns_false_when_home_unusable() {
        let result = with_home(Some(""), || clear_rule("rm-recursive-to-trash"));
        let (rule_removed, expired) = result.unwrap();
        assert!(!rule_removed);
        assert!(expired.is_empty());
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn clear_all_returns_zero_when_home_unusable() {
        let result = with_home(Some(""), clear_all);
        assert_eq!(result.unwrap(), 0);
    }

    // -----------------------------------------------------------------
    // prune_expired_entries (#324)
    // -----------------------------------------------------------------

    fn entry(rule_id: &str, expires_at: &str) -> BreakGlassEntry {
        BreakGlassEntry {
            rule_id: rule_id.to_string(),
            activated_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            reason: None,
        }
    }

    fn expired_entry(rule_id: &str) -> BreakGlassEntry {
        entry(rule_id, "2020-01-01T01:00:00Z") // long past
    }

    fn active_entry(rule_id: &str) -> BreakGlassEntry {
        let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
        entry(rule_id, &expires.format(&Rfc3339).unwrap())
    }

    #[test]
    fn prune_expired_entries_removes_expired_keeps_active() {
        let mut state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![
                expired_entry("rm-recursive-to-trash"),
                active_entry("git-reset-hard-stash"),
            ],
        };
        let pruned = prune_expired_entries(&mut state);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].rule_id, "rm-recursive-to-trash");
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].rule_id, "git-reset-hard-stash");
    }

    #[test]
    fn prune_expired_entries_empty_state_returns_empty() {
        let mut state = BreakGlassState {
            version: STATE_VERSION,
            entries: Vec::new(),
        };
        assert!(prune_expired_entries(&mut state).is_empty());
    }

    #[test]
    fn prune_expired_entries_all_active_returns_empty() {
        let mut state = BreakGlassState {
            version: STATE_VERSION,
            entries: vec![active_entry("rm-recursive-to-trash")],
        };
        assert!(prune_expired_entries(&mut state).is_empty());
        assert_eq!(state.entries.len(), 1);
    }

    #[test]
    fn is_expired_at_boundary_is_inclusive() {
        // `is_expired_at` uses `now >= expires`, not `>` — an entry whose
        // expiry is exactly "now" must count as expired (Codex
        // test-adversarial review: a real clock reading can't distinguish
        // `>` from `>=` since time has always moved on by the time of
        // comparison, so this needs the injectable-`now` seam).
        let now = OffsetDateTime::now_utc();
        let e = entry("rm-recursive-to-trash", &now.format(&Rfc3339).unwrap());
        assert!(
            e.is_expired_at(now),
            "an entry expiring at exactly `now` must be considered expired"
        );
        assert!(
            !e.is_expired_at(now - time::Duration::seconds(1)),
            "an entry must not be considered expired one second before its expiry"
        );
    }

    // -----------------------------------------------------------------
    // activate()/clear_rule() surfacing pruned entries (#324, end-to-end
    // through the real HOME-resolved state file)
    // -----------------------------------------------------------------

    /// Shared HOME temp-dir lifecycle for the tests below: create a fresh
    /// throwaway HOME, run `f` with it active, clean up afterward. Extracted
    /// (`/simplify`) since all 6 callers repeated this dance verbatim,
    /// differing only in state seeding (left to each test via
    /// `entry`/`expired_entry`/`active_entry`, not folded in here).
    fn with_temp_home<T>(label: &str, f: impl FnOnce() -> T) -> T {
        let home = std::env::temp_dir().join(format!("omamori-bg-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let result = with_home(Some(home.to_str().unwrap()), f);
        let _ = fs::remove_dir_all(&home);
        result
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn activate_returns_pruned_expired_entries_on_success() {
        with_temp_home("activate-prune", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![
                    expired_entry("rm-recursive-to-trash"),
                    active_entry("git-reset-hard-stash"),
                ],
            };
            write_state(&seed).unwrap();

            let (new_entry, expired) =
                activate("git-push-force-block", DEFAULT_DURATION_SECS, None).unwrap();
            assert_eq!(new_entry.rule_id, "git-push-force-block");
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].rule_id, "rm-recursive-to-trash");

            // Persisted state: expired entry gone, active + new entry remain.
            let on_disk = read_state(&state_file_path().unwrap()).unwrap();
            let rule_ids: Vec<&str> = on_disk.entries.iter().map(|e| e.rule_id.as_str()).collect();
            assert!(!rule_ids.contains(&"rm-recursive-to-trash"));
            assert!(rule_ids.contains(&"git-reset-hard-stash"));
            assert!(rule_ids.contains(&"git-push-force-block"));
        });
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn activate_does_not_report_pruned_entries_on_early_return() {
        // AlreadyActive short-circuits before write_state — the pruned
        // expired entry must not be reported as removed, because on disk
        // it wasn't (see prune_expired_entries doc).
        with_temp_home("activate-noprune", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![
                    expired_entry("rm-recursive-to-trash"),
                    active_entry("git-reset-hard-stash"),
                ],
            };
            write_state(&seed).unwrap();
            let bytes_before = fs::read(state_file_path().unwrap()).unwrap();

            let result = activate("git-reset-hard-stash", DEFAULT_DURATION_SECS, None);
            assert!(matches!(result, Err(ActivationError::AlreadyActive(_))));

            // State on disk must be byte-for-byte unaffected by the
            // discarded in-memory prune — a raw byte comparison, not just
            // a parsed-content check (Codex test-adversarial review: a
            // parsed comparison wouldn't catch a spurious no-op rewrite).
            let bytes_after = fs::read(state_file_path().unwrap()).unwrap();
            assert_eq!(
                bytes_before, bytes_after,
                "a failed activate() must never touch the state file at all"
            );
        });
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn activate_reports_each_expired_entry_at_most_once_across_sequential_calls() {
        // Single-process guarantee (plan: concurrent-process duplication
        // is accepted, but a given entry must not be re-reported by a
        // second, sequential call once it has already left the state).
        with_temp_home("activate-once", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![expired_entry("rm-recursive-to-trash")],
            };
            write_state(&seed).unwrap();

            let (_, first_pruned) =
                activate("git-push-force-block", DEFAULT_DURATION_SECS, None).unwrap();
            assert_eq!(first_pruned.len(), 1, "first call observes the expiry");

            let (_, second_pruned) =
                activate("git-clean-force-block", DEFAULT_DURATION_SECS, None).unwrap();
            assert!(
                second_pruned.is_empty(),
                "the same expired entry must not be reported a second time — it already left the state"
            );
        });
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn clear_rule_returns_pruned_entries_even_when_target_rule_not_found() {
        with_temp_home("clear-prune", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![
                    expired_entry("rm-recursive-to-trash"),
                    active_entry("git-reset-hard-stash"),
                ],
            };
            write_state(&seed).unwrap();

            // "git-push-force-block" was never activated — clear_rule
            // must still prune+persist the expired sibling entry.
            let (rule_removed, expired) = clear_rule("git-push-force-block").unwrap();
            assert!(!rule_removed, "target rule was never active");
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].rule_id, "rm-recursive-to-trash");

            let on_disk = read_state(&state_file_path().unwrap()).unwrap();
            assert_eq!(on_disk.entries.len(), 1);
            assert_eq!(on_disk.entries[0].rule_id, "git-reset-hard-stash");
        });
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn clear_rule_no_write_when_nothing_changes() {
        with_temp_home("clear-nochange", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![active_entry("git-reset-hard-stash")],
            };
            write_state(&seed).unwrap();

            let (rule_removed, expired) = clear_rule("git-push-force-block").unwrap();
            assert!(!rule_removed);
            assert!(expired.is_empty());

            let on_disk = read_state(&state_file_path().unwrap()).unwrap();
            assert_eq!(on_disk.entries.len(), 1);
            assert_eq!(on_disk.entries[0].rule_id, "git-reset-hard-stash");
        });
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn clear_rule_then_clear_all_does_not_double_count_pruned_entry() {
        // #324 scope boundary check (Codex test-adversarial review):
        // clear_rule() prunes+reports an unrelated expired entry, then a
        // later clear_all() must count only what's genuinely still active
        // — not re-observe the entry clear_rule() already removed.
        with_temp_home("clear-then-clearall", || {
            let seed = BreakGlassState {
                version: STATE_VERSION,
                entries: vec![
                    expired_entry("rm-recursive-to-trash"),
                    active_entry("git-reset-hard-stash"),
                ],
            };
            write_state(&seed).unwrap();

            let (_, expired) = clear_rule("git-push-force-block").unwrap();
            assert_eq!(expired.len(), 1, "clear_rule prunes the expired sibling");

            // Only the one still-active entry remains for clear_all to count.
            let count = clear_all().unwrap();
            assert_eq!(
                count, 1,
                "clear_all must count exactly the remaining active entry, \
                 not re-count the entry clear_rule already pruned"
            );
        });
    }
}
