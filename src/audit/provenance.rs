//! Process provenance collection for layer1 audit events (#420).
//!
//! Best-effort forensic hints — pid, ppid, parent exec path, cwd — attached
//! to layer1 audit events so a future incident's actor can be identified
//! from the audit log alone. Collection never fails the calling command:
//! every field is independently optional, and any syscall/FFI failure
//! degrades that field to `None` rather than propagating an error.
//!
//! Deliberately excluded from `HashableEvent` (chain.rs) — Design A, see
//! ADR-0006. These fields are advisory forensic hints, not tamper-evident:
//! a same-user attacker who can write audit.jsonl can alter them without
//! breaking the hash chain. Folding them into the chain's integrity
//! envelope is tracked by issue #177 (CHAIN_VERSION 1→2).
//!
//! `parent_process` is sourced from `proc_pidpath` (the kernel's record of
//! the parent's resolved exec path), never `argv[0]` — on Darwin, `argv[0]`
//! is fully attacker-controlled at exec time.
//!
//! Limitation (document, don't over-claim): this is forensic best-effort,
//! not an authenticated identity. A shell hop (`sh -c ...`), deliberate
//! orphaning, a double-fork, or a crafted binary name can each launder or
//! defeat it. `None` means "collection failed or was skipped" — it is never
//! evidence of anything, and should not be read as such.

use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::chain::hmac_bytes;

/// Domain separator for cwd hashing — keeps `cwd_hash` values disjoint from
/// `target_hash` (`secret::hmac_targets`) even when the underlying bytes are
/// identical (e.g. a command whose sole target argument equals its cwd).
/// Without this, a keyless log reader could use `cwd_hash == target_hash`
/// as an equality oracle between the two columns.
const CWD_DOMAIN_TAG: &[u8] = b"omamori-cwd-v1\0";

/// Cap on `parent_process` length before storage — bounds log growth from
/// an attacker-influenced field (a crafted, very long binary path) without
/// affecting the common case.
const PARENT_PROCESS_MAX_LEN: usize = 1024;

/// Snapshot of a process's identity at a point in time. Forensic best-effort
/// only — see module docs for the same-user-model limitations.
///
/// `cwd` is intentionally stored raw (unhashed) here: hashing needs an HMAC
/// secret, which may not be resolvable at the point in the guarded command's
/// lifecycle where collection must happen (see `collect`'s doc comment).
/// Hashing is deferred to `as_audit_fields`, called once a secret is
/// available — this is safe because, unlike `ppid`/`parent_process`, the
/// process's cwd does not change based on whether a child process has run.
#[derive(Debug, Clone)]
pub struct ProcessProvenance {
    pub(super) pid: u32,
    pub(super) ppid: Option<u32>,
    pub(super) parent_process: Option<String>,
    pub(super) cwd: Option<PathBuf>,
}

impl ProcessProvenance {
    /// Collect a snapshot of the current process's provenance. Call once, as
    /// early as possible in the guarded command's lifecycle — specifically,
    /// before any child process runs. The parent (the AI CLI or shell that
    /// launched this shim) is only guaranteed to still be alive at that
    /// point; after a wrapped child exits, a dead parent can be reparented
    /// to launchd (`ppid == 1`), losing the real launcher's identity.
    ///
    /// No HMAC secret is needed here (see the struct doc comment on why
    /// `cwd` is deferred).
    pub fn collect() -> Self {
        let pid = std::process::id();
        let ppid = get_ppid();
        let parent_process = ppid.and_then(proc_pidpath).map(|p| sanitize(&p));
        let cwd = env::current_dir().ok();
        Self {
            pid,
            ppid,
            parent_process,
            cwd,
        }
    }

    /// Unpack into the four `AuditEvent` fields provenance maps to,
    /// computing `cwd_hash` with the given secret. Shared by every
    /// `AuditEvent`/bypass-event builder so the field layout and hashing
    /// logic live in exactly one place. `provenance` may be `None` (e.g.
    /// Layer 2 call sites, deliberately out of scope for #420), in which
    /// case all four fields become `None`. `secret` follows the same
    /// `NO_HMAC_SECRET`-on-`None` convention as `target_hash`.
    pub fn as_audit_fields(
        provenance: Option<&ProcessProvenance>,
        secret: Option<&[u8; 32]>,
    ) -> (Option<u32>, Option<u32>, Option<String>, Option<String>) {
        let cwd_hash = provenance
            .and_then(|p| p.cwd.as_deref())
            .map(|cwd| hmac_cwd(secret, cwd.as_os_str()));
        (
            provenance.map(|p| p.pid),
            provenance.and_then(|p| p.ppid),
            provenance.and_then(|p| p.parent_process.clone()),
            cwd_hash,
        )
    }
}

/// Domain-separated HMAC over a raw path (any `OsStr`, no lossy
/// conversion). See `CWD_DOMAIN_TAG` docs for why this must not reuse
/// `secret::hmac_targets`'s preimage scheme.
pub fn hmac_cwd(secret: Option<&[u8; 32]>, cwd: &OsStr) -> String {
    if secret.is_none() {
        return "NO_HMAC_SECRET".to_string();
    }

    #[cfg(unix)]
    let raw: &[u8] = {
        use std::os::unix::ffi::OsStrExt;
        cwd.as_bytes()
    };
    #[cfg(not(unix))]
    let raw: &[u8] = cwd.to_str().map(str::as_bytes).unwrap_or(&[]);

    let mut preimage = Vec::with_capacity(CWD_DOMAIN_TAG.len() + raw.len());
    preimage.extend_from_slice(CWD_DOMAIN_TAG);
    preimage.extend_from_slice(raw);
    format!("hmac-cwd:{}", hmac_bytes(secret, &preimage))
}

/// Compute every candidate `cwd_hash` for a path an investigator supplies,
/// so they can grep the audit log for a match without knowing which HMAC
/// key was active when the entry was written, and without having to guess
/// whether the stored value used the raw or symlink-resolved form of the
/// path.
///
/// `std::env::current_dir()` (used at collection time) returns an already
/// symlink-resolved path (e.g. macOS `/tmp` → `/private/tmp`), so an
/// investigator's hand-typed candidate — typically NOT resolved — needs
/// both forms tried, or a real match is silently missed.
///
/// Returns `None` if no HMAC key (active or retired) is available.
pub fn hash_cwd_candidates(
    audit_config: &super::AuditConfig,
    candidate: &std::path::Path,
) -> Option<Vec<(String, &'static str, String)>> {
    let audit_path = super::resolved_audit_path(audit_config)?;
    let secret_path = super::secret::secret_path_for(&audit_path);
    let mut keyring: Vec<(String, [u8; 32])> = super::secret::load_keyring(&secret_path)
        .into_iter()
        .collect();
    if keyring.is_empty() {
        return None;
    }
    keyring.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic output order

    let mut forms: Vec<(&'static str, std::ffi::OsString)> =
        vec![("raw", candidate.as_os_str().to_owned())];
    if let Ok(canonical) = candidate.canonicalize()
        && canonical.as_os_str() != candidate.as_os_str()
    {
        forms.push(("canonical", canonical.into_os_string()));
    }

    let mut out = Vec::with_capacity(keyring.len() * forms.len());
    for (key_id, secret) in &keyring {
        for (label, form) in &forms {
            out.push((key_id.clone(), *label, hmac_cwd(Some(secret), form)));
        }
    }
    Some(out)
}

/// Best-effort ppid lookup. `getppid()` is documented as always succeeding
/// on POSIX systems, but the boundary is still treated defensively rather
/// than assuming libc contracts hold forever.
#[cfg(unix)]
fn get_ppid() -> Option<u32> {
    let ppid = unsafe { libc::getppid() };
    if ppid > 0 { Some(ppid as u32) } else { None }
}

#[cfg(not(unix))]
fn get_ppid() -> Option<u32> {
    None
}

/// Resolve a pid's exec path via `proc_pidpath` — a Darwin-only libproc
/// call, not part of POSIX or Linux's libc. Returns `None` on any failure
/// (invalid pid, permission denied, process already exited) — never
/// panics, matching the fail-open collection contract. PID reuse between
/// the `getppid()` call and this lookup is an inherent race in the
/// same-process-tree model; snapshotting as early as possible (see
/// `collect`'s doc comment) minimizes but cannot eliminate the window.
#[cfg(target_os = "macos")]
fn proc_pidpath(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::pid_t,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..ret as usize]).into_owned())
}

/// Linux equivalent of the macOS `proc_pidpath` lookup above: `/proc/<pid>/exe`
/// is a symlink the kernel maintains to the process's resolved exec path.
/// Reading it never requires the target process's cooperation and fails
/// cleanly (`None`) if the pid is invalid, already exited, or unreadable —
/// same fail-open contract as the macOS path. omamori itself only ships for
/// macOS (see SECURITY.md / README); this exists so the crate still builds
/// and tests pass in CI's Linux job, not as a supported deployment target.
#[cfg(target_os = "linux")]
fn proc_pidpath(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn proc_pidpath(_pid: u32) -> Option<String> {
    None
}

/// Strip ASCII/Unicode control characters and cap length. Applied once at
/// collection time so every downstream consumer (`--json`, a future display
/// table, any tool that pipes the log through `jq -r`) is safe by
/// construction, rather than requiring each display site to sanitize
/// separately.
///
/// Residual risk (documented, not closed by this function): under Design A
/// the field is outside the hash chain, so a same-user attacker with direct
/// write access to audit.jsonl can hand-craft a line with raw control bytes
/// in this field regardless of what omamori's own collection path does —
/// see SECURITY.md.
fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .take(PARENT_PROCESS_MAX_LEN)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditConfig, AuditLogger, rotate_key};

    const TEST_SECRET: [u8; 32] = [0x42; 32];

    /// Isolated per-test directory. Mirrors `audit::tests::test_dir` (which
    /// is private to that module and can't be reused here) — `$TMPDIR`
    /// rather than `$HOME` because these are pure filesystem/HMAC operations
    /// with no guarded-command execution in the path, same as the existing
    /// `audit::tests::test_dir` and `benches/audit_append.rs` precedent.
    fn hash_cwd_test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("omamori-hashcwd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hmac_cwd_no_secret_uses_marker() {
        assert_eq!(hmac_cwd(None, OsStr::new("/tmp/x")), "NO_HMAC_SECRET");
    }

    #[test]
    fn hmac_cwd_deterministic() {
        let h1 = hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/x"));
        let h2 = hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/x"));
        assert_eq!(h1, h2);
    }

    #[test]
    fn hmac_cwd_different_paths_differ() {
        let a = hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/x"));
        let b = hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/y"));
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_cwd_has_distinct_prefix_from_target_hash() {
        let cwd_hash = hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/x"));
        let target_hash = crate::audit::secret::hmac_targets(Some(&TEST_SECRET), &["/tmp/x"]);
        assert!(cwd_hash.starts_with("hmac-cwd:"));
        assert!(target_hash.starts_with("hmac-sha256:"));
        // Different prefixes alone guarantee the two can never collide as
        // strings, regardless of preimage construction — belt and suspenders
        // on top of the domain tag.
        assert_ne!(cwd_hash, target_hash);
    }

    #[test]
    fn sanitize_strips_control_chars() {
        let dirty = "\x1b[31mCLOAKED\rmalicious\x07bell";
        let clean = sanitize(dirty);
        assert!(!clean.chars().any(|c| c.is_control()));
        assert!(clean.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(PARENT_PROCESS_MAX_LEN + 500);
        assert_eq!(sanitize(&long).chars().count(), PARENT_PROCESS_MAX_LEN);
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        let normal = "/Applications/Cursor.app/Contents/Frameworks/node";
        assert_eq!(sanitize(normal), normal);
    }

    /// Proxy adversarial review finding: `sanitize_strips_control_chars`
    /// only pins the standalone function; nothing proved the sanitized
    /// value stays clean once it goes through the JSON encode/decode a real
    /// `audit.jsonl` line — and `--json` consumers (see SECURITY.md's
    /// residual-exposure note) — actually go through.
    #[test]
    fn sanitized_parent_process_survives_json_round_trip() {
        let dirty = "\x1b[31mCLOAKED\rmalicious\x07bell";
        let sanitized = sanitize(dirty);
        assert!(!sanitized.chars().any(|c| c.is_control()));

        let json = serde_json::to_string(&sanitized).unwrap();
        let round_tripped: String = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped, sanitized);
        assert!(
            !round_tripped.chars().any(|c| c.is_control()),
            "round-tripping through JSON must not reintroduce raw control bytes"
        );
    }

    #[test]
    fn proc_pidpath_invalid_pid_returns_none() {
        assert!(proc_pidpath(999_999).is_none());
    }

    #[test]
    fn get_ppid_returns_some_for_real_process() {
        // Every real process has a valid ppid (reparented to launchd=1 at
        // worst) — this asserts the FFI call itself doesn't fail/panic in
        // the test environment.
        assert!(get_ppid().is_some());
    }

    #[test]
    fn collect_never_panics_and_populates_pid() {
        let prov = ProcessProvenance::collect();
        assert!(prov.pid > 0);
    }

    #[test]
    fn as_audit_fields_without_secret_degrades_cwd_hash_to_marker() {
        let prov = ProcessProvenance::collect();
        let (_, _, _, cwd_hash) = ProcessProvenance::as_audit_fields(Some(&prov), None);
        // cwd resolution can still fail independently of the secret, but if
        // it succeeds the marker must be the no-secret sentinel, never a
        // panic or an empty string.
        if let Some(hash) = cwd_hash {
            assert_eq!(hash, "NO_HMAC_SECRET");
        }
    }

    #[test]
    fn as_audit_fields_none_provenance_yields_all_none() {
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(None, Some(&TEST_SECRET));
        assert_eq!(pid, None);
        assert_eq!(ppid, None);
        assert_eq!(parent_process, None);
        assert_eq!(cwd_hash, None);
    }

    #[test]
    fn as_audit_fields_some_provenance_populates_pid_and_cwd_hash() {
        let prov = ProcessProvenance::collect();
        let (pid, _, _, cwd_hash) =
            ProcessProvenance::as_audit_fields(Some(&prov), Some(&TEST_SECRET));
        assert_eq!(pid, Some(prov.pid));
        if prov.cwd.is_some() {
            assert!(cwd_hash.unwrap().starts_with("hmac-cwd:"));
        }
    }

    /// Proxy adversarial review finding: the test above (and
    /// `bypass_event_with_provenance_carries_real_fields` in
    /// break_glass_cmd.rs) both re-derive their expected values by calling
    /// `collect()`/`as_audit_fields()` themselves — a mirror that can't
    /// catch `as_audit_fields` silently dropping `ppid` or `parent_process`
    /// from its return tuple, because both sides of the assertion would
    /// agree on the (wrong) `None`. This test builds a `ProcessProvenance`
    /// from known constants instead (its `pub(super)` fields are directly
    /// constructible from this descendant module), so every one of the four
    /// output fields is checked against a value fixed independently of the
    /// code under test.
    #[test]
    fn as_audit_fields_preserves_all_four_fields_independently() {
        let prov = ProcessProvenance {
            pid: 4242,
            ppid: Some(1111),
            parent_process: Some("/usr/bin/known-launcher".to_string()),
            cwd: Some(PathBuf::from("/tmp/known-cwd")),
        };
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(Some(&prov), Some(&TEST_SECRET));
        assert_eq!(pid, Some(4242));
        assert_eq!(ppid, Some(1111));
        assert_eq!(parent_process, Some("/usr/bin/known-launcher".to_string()));
        assert_eq!(
            cwd_hash,
            Some(hmac_cwd(Some(&TEST_SECRET), OsStr::new("/tmp/known-cwd")))
        );
    }

    /// Proxy adversarial review finding: the module doc claims every field
    /// is "independently optional" (fail-open per-field, not all-or-nothing),
    /// but no prior test proved `cwd` failing independently of `pid`/`ppid`
    /// actually degrades only `cwd_hash` — direct construction is needed
    /// since `collect()` cannot itself force `cwd: None` on a real system.
    #[test]
    fn as_audit_fields_degrades_only_cwd_hash_when_cwd_collection_failed() {
        let prov = ProcessProvenance {
            pid: 99,
            ppid: Some(88),
            parent_process: Some("/bin/sh".to_string()),
            cwd: None, // simulates current_dir() failing independently
        };
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(Some(&prov), Some(&TEST_SECRET));
        assert_eq!(pid, Some(99));
        assert_eq!(ppid, Some(88));
        assert_eq!(parent_process, Some("/bin/sh".to_string()));
        assert_eq!(
            cwd_hash, None,
            "only cwd_hash should degrade when cwd collection alone failed"
        );
    }

    #[test]
    fn hash_cwd_candidates_returns_none_when_no_keyring_exists() {
        let dir = hash_cwd_test_dir("no-keyring");
        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        // Deliberately no AuditLogger::from_config call — no secret file
        // has ever been created in this dir, so the keyring is empty.
        let result = hash_cwd_candidates(&config, &dir);
        assert!(
            result.is_none(),
            "no keyring exists yet — hash_cwd_candidates must return None, not an empty Vec"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hash_cwd_candidates_falls_back_to_raw_only_when_candidate_does_not_exist() {
        let dir = hash_cwd_test_dir("nonexistent-candidate");
        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        // Establish a real keyring on disk (contents don't matter here,
        // only that `load_keyring` finds at least one key).
        let _logger = AuditLogger::from_config(&config).expect("logger constructs");

        let nonexistent = dir.join("does-not-exist");
        let candidates = hash_cwd_candidates(&config, &nonexistent)
            .expect("keyring exists — hash_cwd_candidates must return Some");

        let forms: std::collections::HashSet<&str> =
            candidates.iter().map(|(_, form, _)| *form).collect();
        assert_eq!(
            forms,
            std::collections::HashSet::from(["raw"]),
            "canonicalize() fails for a nonexistent path — only the raw \
             form should be present, never a phantom 'canonical' entry"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // hash_cwd_candidates (M5/M6, Phase 3 adversarial review findings)
    // -----------------------------------------------------------------

    #[test]
    fn hash_cwd_candidates_covers_active_and_retired_keys_after_rotation() {
        let dir = hash_cwd_test_dir("rotation");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger_before =
            AuditLogger::from_config(&config).expect("logger constructs in a writable temp dir");
        let original_secret = *logger_before
            .secret_ref()
            .expect("from_config must create a secret in a fresh dir");
        let original_key_id = logger_before.key_id.clone();

        let rotation =
            rotate_key(&audit_path).expect("rotation succeeds against an existing secret");
        assert_ne!(
            rotation.new_key_id, original_key_id,
            "rotation must mint a new active key id distinct from the pre-rotation one"
        );

        let candidates = hash_cwd_candidates(&config, &dir)
            .expect("keyring must be non-empty — both the retired and new active key exist");

        let key_ids: std::collections::HashSet<&str> =
            candidates.iter().map(|(id, _, _)| id.as_str()).collect();
        assert!(
            key_ids.contains(original_key_id.as_str()),
            "a log entry written before rotation used the now-retired key \
             — it must remain a hash candidate (M5)"
        );
        assert!(
            key_ids.contains(rotation.new_key_id.as_str()),
            "the new active key must also be a hash candidate"
        );

        // Not just "the key id shows up" — the retired key's candidate hash
        // must equal what that key's actual secret bytes would produce.
        let raw_form = dir.as_os_str();
        let expected_retired_hash = hmac_cwd(Some(&original_secret), raw_form);
        let retired_entry = candidates
            .iter()
            .find(|(id, form, _)| id == &original_key_id && *form == "raw")
            .expect("retired key + raw form combination must be present");
        assert_eq!(retired_entry.2, expected_retired_hash);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hash_cwd_candidates_covers_raw_and_canonical_forms() {
        let dir = hash_cwd_test_dir("symlink");
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let symlink_dir = dir.join("symlink");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let logger =
            AuditLogger::from_config(&config).expect("logger constructs in a writable temp dir");
        let secret = *logger
            .secret_ref()
            .expect("from_config must create a secret in a fresh dir");

        let candidates = hash_cwd_candidates(&config, &symlink_dir)
            .expect("keyring must be non-empty after from_config");

        let forms: std::collections::HashSet<&str> =
            candidates.iter().map(|(_, form, _)| *form).collect();
        assert!(
            forms.contains("raw"),
            "the investigator's literal (symlink) path must be one candidate form"
        );
        assert!(
            forms.contains("canonical"),
            "the resolved real path must also be a candidate — cwd_hash was \
             computed from an already-resolved path at collection time (M6)"
        );

        let expected_raw_hash = hmac_cwd(Some(&secret), symlink_dir.as_os_str());
        let raw_entry = candidates
            .iter()
            .find(|(_, form, _)| *form == "raw")
            .expect("raw form must be present");
        assert_eq!(raw_entry.2, expected_raw_hash);

        let canonical_path = symlink_dir.canonicalize().expect("symlink resolves");
        let expected_canonical_hash = hmac_cwd(Some(&secret), canonical_path.as_os_str());
        let canonical_entry = candidates
            .iter()
            .find(|(_, form, _)| *form == "canonical")
            .expect("canonical form must be present");
        assert_eq!(canonical_entry.2, expected_canonical_hash);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
