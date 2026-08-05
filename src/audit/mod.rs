//! Audit logging with HMAC hash chain integrity.
//!
//! Split into focused submodules for v0.8.1 (#112):
//! - `chain`: Hash chain computation (HashableEvent, HMAC, genesis)
//! - `retention`: Automatic pruning of old entries
//! - `secret`: HMAC key management, symlink-safe I/O, key rotation
//! - `verify`: Chain verification, entry display, summary for CLI
//! - `report`: Aggregation for `omamori report` (since v0.10.0, #221)

pub mod chain;
pub mod provenance;
pub mod report;
pub mod retention;
pub mod secret;
pub mod verify;

// --- Public re-exports (maintain `omamori::audit::*` API paths) ---
pub use provenance::hash_cwd_candidates;
pub use report::{ChainStatus, ReportAggregate, aggregate_report};
pub use secret::{RotationResult, UnprotectedReason, rotate_key};
pub use verify::{
    AuditError, AuditSummary, KeyUnavailableKind, ShowOptions, VerifyResult, audit_summary,
    count_unknown_tool_fail_opens_within, show_entries, verify_chain,
};

// --- Internal imports from submodules (used by AuditLogger + tests) ---
use chain::{CHAIN_VERSION, ChainTailState, compute_entry_hash_for_write, read_chain_state};
use provenance::ProcessProvenance;
use retention::{PRUNE_CHECK_INTERVAL, try_prune};
use secret::{
    SigningKey, flock_exclusive, hmac_targets, load_signing_key, open_audit_rw, secret_path_for,
};

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actions::ActionOutcome;
use crate::rules::{CommandInvocation, RuleConfig};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub retention_days: u32,
    #[serde(default)]
    pub strict: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        }
    }
}

impl AuditConfig {
    /// Validate and normalize the audit config. Clamps `retention_days` and
    /// neutralizes a relative `path` override. Returns warnings if adjusted.
    ///
    /// A relative `audit.path` (e.g. `path = "audit.jsonl"`) would make every
    /// audit operation resolve against the process CWD — the same #210-class
    /// CWD-scatter hazard #371 closed for the `path = None` case, reintroduced
    /// through an explicit override `resolved_audit_path()` never validated.
    /// We drop it to `None` here so the resolver falls through to the
    /// HOME-derived default (or fails closed when HOME is unusable too),
    /// mirroring the `is_absolute()` filter `context::home_dir()` applies to
    /// HOME and the warn-and-disable policy `config::validate_destination`
    /// applies to a rule's relative `destination`.
    pub fn validate(&self) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut config = self.clone();
        if config.retention_days > 0 && config.retention_days < retention::MIN_RETENTION_DAYS {
            warnings.push(format!(
                "audit.retention_days {} is below minimum {}; clamped to {}",
                config.retention_days,
                retention::MIN_RETENTION_DAYS,
                retention::MIN_RETENTION_DAYS
            ));
            config.retention_days = retention::MIN_RETENTION_DAYS;
        }
        if let Some(ref path) = config.path
            && !path.is_absolute()
        {
            // Phase 8 QA+UX (independently converged) + Security findings:
            // (a) an empty `path = ""` rendered as confusing empty
            // backticks — special-cased to `<empty>`; (b) `config.path` is
            // attacker-controlled (config.toml is explicitly AI-editable
            // per this issue's own threat model) and was interpolated
            // unsanitized into a terminal warning, allowing ANSI/control-
            // character injection — stripped here, mirroring the same
            // control-character sanitization `provenance::sanitize`
            // already applies to `parent_process` before it reaches a
            // terminal or `--json` output.
            let shown = if path.as_os_str().is_empty() {
                "<empty>".to_string()
            } else {
                path.display()
                    .to_string()
                    .chars()
                    .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                    .collect()
            };
            warnings.push(format!(
                "audit.path `{shown}` is not an absolute path; ignoring the override — set an absolute path to use a custom audit log location"
            ));
            config.path = None;
        }
        (config, warnings)
    }
}

fn default_true() -> bool {
    true
}

/// Resolve the effective audit log path: an explicit config override
/// (honored only when absolute), or the default under
/// `$HOME/.local/share/omamori/audit.jsonl`. `None` when neither is
/// available — no absolute override and `HOME` is unusable (unset/empty/
/// relative) — callers must treat audit logging as unavailable rather than
/// falling back to a CWD-relative path.
///
/// Historical note (#306/#371): `secret.rs` used to have its own
/// `default_audit_path()` with a CWD fallback (`AuditConfig.path` defaults
/// to `None`, so that fallback fired on every default install where `HOME`
/// happened to be unusable, scattering the audit log and its HMAC secret
/// into the process's working directory). #371 deleted it and routed
/// `rotate_key` through this fail-close resolver instead — this is now the
/// sole path-resolution function in the audit subsystem.
///
/// A non-absolute `config.path` is already normalized to `None` by
/// `AuditConfig::validate()` (#439) — every caller is expected to pass a
/// validated config. The `.filter()` below is a second, silent
/// defense-in-depth layer against a future caller that constructs an
/// `AuditConfig` without going through `validate()`.
pub(crate) fn resolved_audit_path(config: &AuditConfig) -> Option<PathBuf> {
    config
        .path
        .clone()
        .filter(|p| p.is_absolute())
        .or_else(|| crate::context::data_dir().map(|d| d.join("audit.jsonl")))
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

pub struct AuditLogger {
    pub(super) path: PathBuf,
    /// #457: the signing key and the `key_id` that names it are one value, not
    /// two fields that call sites can pair up incorrectly. Private rather than
    /// `pub(super)` — reaching the bytes goes through `secret_ref()` and the
    /// label through `key_id()`, so no caller outside this impl can hold one
    /// without the other. (`mod tests` is a child module and can still build
    /// the struct directly, which is what the fixtures need.)
    signing_key: SigningKey,
    pub(super) retention_days: u32,
}

impl AuditLogger {
    pub fn secret_available(&self) -> bool {
        self.signing_key.secret().is_some()
    }

    /// Narrow crate-internal accessor for computing provenance fields
    /// outside the `audit` module — currently only
    /// `cli::break_glass_cmd::create_bypass_event`, which builds its own
    /// `AuditEvent` rather than going through `create_event`. Not part of
    /// the public API: intentionally `pub(crate)`, not `pub`.
    pub(crate) fn secret_ref(&self) -> Option<&[u8; 32]> {
        self.signing_key.secret()
    }

    /// The `key_id` this logger labels its entries with. Reading it through
    /// the `SigningKey` rather than a standalone field is the point of #457's
    /// A1 — there is no way to get the label without going through the value
    /// that also holds the bytes.
    pub(super) fn key_id(&self) -> &str {
        &self.signing_key.id
    }

    pub fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let (validated, _warnings) = config.validate();
        let path = resolved_audit_path(&validated)?;
        let signing_key = load_signing_key(&secret_path_for(&path));
        Some(Self {
            path,
            signing_key,
            retention_days: validated.retention_days,
        })
    }

    /// `provenance` is best-effort process context (#420) — pass `None` for
    /// call sites where it is intentionally not collected (Layer 2 hook
    /// events are out of scope; see `engine::hook`) or was unavailable at
    /// the call site.
    pub fn create_event(
        &self,
        invocation: &CommandInvocation,
        matched_rule: Option<&RuleConfig>,
        matched_detectors: &[String],
        outcome: &ActionOutcome,
        provenance: Option<&ProcessProvenance>,
    ) -> AuditEvent {
        let targets = invocation.target_args();
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(provenance, self.signing_key.secret());
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
            target_hash: hmac_targets(self.signing_key.secret(), &targets),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: None,
            seq: None,
            prev_hash: None,
            key_id: None,
            entry_hash: None,
            pid,
            ppid,
            parent_process,
            cwd_hash,
            wrapper_kind: None,
        }
    }

    /// Append an event with hash-chain integrity.
    ///
    /// Takes ownership of the event to set chain fields (seq, prev_hash, entry_hash).
    /// Uses flock for concurrent-append safety.
    pub fn append(&self, mut event: AuditEvent) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // read+write+create without truncate: we read the tail for chain state, then append.
        #[allow(clippy::suspicious_open_options)]
        let mut file = open_audit_rw(&self.path)?;

        flock_exclusive(&file)?;

        // Read chain state under lock (another process may have appended since our open).
        // #177 B1 step 3: when the last valid JSON line within read_chain_state's tail
        // window declares an unsupported chain_version, we can't safely resume seq
        // numbering or chain prev_hash onto it — refuse to append. This returns Err,
        // like every other append failure (disk full,
        // permissions, secret unavailable) — QA Phase 8 finding F-001: the two call
        // sites that already implement strict-mode enforcement (shim.rs's
        // try_audit_append, hook.rs's break-glass bypass path) only escalate to
        // blocking on Err, and strict mode's documented contract ("no receipt is a
        // reason not to allow") applies here exactly as it does to any other
        // recording failure. G-2's best-effort *default* is unaffected: every call
        // site's existing Err handling already treats a non-strict Err as a warning,
        // not a block — Err doesn't change that, it only makes strict mode able to
        // see this case at all.
        let (seq, prev_hash) = match read_chain_state(&mut file, self.signing_key.secret()) {
            ChainTailState::UnsupportedVersion { chain_version } => {
                return Err(std::io::Error::other(format!(
                    "audit log tail declares chain_version {chain_version}, which this \
                     omamori build does not recognize \u{2014} refusing to append (this \
                     event was not recorded; not necessarily tampering \u{2014} may mean \
                     this binary predates a newer chain format)"
                )));
            }
            // #456: the same refusal shape as the arm above, for the same
            // reason — the tail is something this build cannot number after.
            // States only what was observed, the number on the line: nothing
            // here authenticated it (`read_chain_state` does not check
            // `entry_hash`), so it is not called tampering.
            ChainTailState::SeqAtLimit { seq } => {
                return Err(std::io::Error::other(format!(
                    "audit log tail is numbered {seq}, the largest sequence number the \
                     format can hold, so there is no number left to give the next entry \
                     \u{2014} refusing to append (this event was not recorded; not \
                     necessarily tampering \u{2014} counting a chain up to this number is \
                     not physically reachable, so the tail line or something before it did \
                     not come from omamori's own counting)"
                )));
            }
            ChainTailState::Fresh { genesis } => (0, genesis),
            // #456: no arithmetic here. `next_seq` is already the number this
            // entry takes — `read_chain_state` incremented it where the range
            // check lives, so there is nothing left at this call site that
            // could wrap.
            ChainTailState::Ready {
                next_seq,
                last_hash,
            } => (next_seq, last_hash),
        };

        // Set chain fields
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(seq);
        event.prev_hash = Some(prev_hash);
        event.key_id = Some(self.key_id().to_string());
        event.entry_hash = Some(compute_entry_hash_for_write(
            self.signing_key.secret(),
            &event,
        ));

        // Ensure new entry starts on its own line (torn lines may lack trailing newline)
        let len = file.seek(SeekFrom::End(0))?;
        if len > 0 {
            file.seek(SeekFrom::End(-1))?;
            let mut last_byte = [0u8; 1];
            file.read_exact(&mut last_byte)?;
            if last_byte[0] != b'\n' {
                file.seek(SeekFrom::End(0))?;
                writeln!(file)?;
            } else {
                file.seek(SeekFrom::End(0))?;
            }
        }

        serde_json::to_writer(&mut file, &event)?;
        writeln!(file)?;
        file.flush()?;

        // HWM update: detect truncation on append + advance high-water-mark
        let hwm_file = hwm_path_for(&self.path);
        let advance_hwm = match read_hwm(&hwm_file) {
            HwmState::Valid(h) if seq < h => {
                eprintln!(
                    "omamori warning: audit log tail may have been truncated \
                     (seq {seq} < high-water-mark {h})"
                );
                false
            }
            HwmState::Valid(h) => seq > h,
            HwmState::Missing => true,
            HwmState::Tampered => {
                // Same-user tamper on the tamper-evidence sidecar itself: don't
                // silently re-bootstrap as if this were a fresh install.
                eprintln!(
                    "omamori warning: audit high-water-mark is unreadable or has been \
                     tampered with (expected a plain integer, found a symlink or \
                     invalid content). Run `omamori audit verify` to investigate."
                );
                true
            }
        };
        if advance_hwm && let Err(e) = write_hwm(&hwm_file, seq) {
            eprintln!("omamori warning: failed to update audit high-water-mark: {e}");
        }

        // Auto-prune under the same flock (no extra I/O when not triggered)
        if self.retention_days > 0
            && seq > 0
            && seq % PRUNE_CHECK_INTERVAL == 0
            && let Err(e) = try_prune(
                &mut file,
                &self.signing_key,
                self.retention_days,
                Some(&self.path),
            )
        {
            eprintln!("omamori warning: audit prune failed: {e}");
        }

        // flock released on file drop
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditEvent {
    pub timestamp: String,
    pub provider: String,
    pub command: String,
    pub rule_id: Option<String>,
    pub action: String,
    pub result: String,
    pub target_count: usize,
    pub target_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_input_hash: Option<String>,
    // --- Chain fields (None for legacy entries) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    // --- Process provenance fields (#420) ---
    // Absent from `HashableEvent` (V1 preimage, chain.rs) — Design A, see
    // ADR-0006 and SECURITY.md's "Process Provenance" section. Included in
    // `HashableEventV2` (#177 B3) — hash-protected on `chain_version: 2`
    // entries, permanently unprotected on `chain_version: 1` entries
    // (existing bytes are never rewritten, ADR-0007).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd_hash: Option<String>,
    // --- Structural block classification (#177 B2) ---
    // Promotes the wrapper name (e.g. "env", "sudo") that was previously
    // only embedded inside the detection_layer string
    // ("layer2:pipe-to-shell:{wrapper}") to its own field, alongside — not
    // instead of — that suffix (see #459 for its later, separate sunset).
    // `None` for every block/allow path except BlockStructural's
    // PipeToShell origin and the materialize path derived from it.
    // `String`, not `&'static str`: AuditEvent round-trips through
    // `Deserialize` when reading audit.jsonl back (verify/report/show),
    // which requires owned data — a borrowed field can't satisfy the
    // `'static` bound serde's derive needs against a non-'static input.
    // Absent from `HashableEvent` (V1 preimage) — like the process-provenance
    // fields above. Included in `HashableEventV2` (#177 B3), with the same
    // v1/v2 hash-protection split.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper_kind: Option<String>,
}

// ---------------------------------------------------------------------------
// High-water-mark (HWM) helpers
// ---------------------------------------------------------------------------

/// Derive HWM file path from the audit log path.
/// e.g. `~/.local/share/omamori/audit.jsonl` → `~/.local/share/omamori/audit.jsonl.hwm`
pub(crate) fn hwm_path_for(audit_path: &std::path::Path) -> PathBuf {
    let mut hwm = audit_path.as_os_str().to_owned();
    hwm.push(".hwm");
    PathBuf::from(hwm)
}

/// Result of reading the HWM sidecar file.
///
/// `Missing` (genuinely absent, e.g. first run) is distinct from `Tampered`
/// (a filesystem entry exists at the path but is a symlink or does not
/// contain a valid sequence number) so callers can avoid silently treating
/// tamper evidence as a fresh install.
pub(crate) enum HwmState {
    Valid(u64),
    Missing,
    Tampered,
}

/// The HWM file holds one decimal integer. 64 bytes is far past `u64::MAX`'s
/// 20 digits and still small enough that a hostile file cannot be read into
/// memory in bulk.
const MAX_HWM_FILE_BYTES: u64 = 64;

fn read_hwm(hwm_path: &std::path::Path) -> HwmState {
    // #468: this used to `symlink_metadata` and then `fs::read_to_string`,
    // which handled symlinks and nothing else. A FIFO here made
    // `read_to_string` block forever — measured as an indefinite hang of
    // `verify`, `exec`, `doctor`, `report` and `hook-check`, the last of
    // those before it printed its deny verdict. It survived the round of
    // fixes that closed the same hole on `audit.jsonl` because it never went
    // through the shared open helper.
    //
    // `Tampered` is the right bucket for the shapes this now rejects: a
    // FIFO, directory or symlink at this path is not a file omamori wrote,
    // which is exactly what the symlink arm already said.
    let file = match crate::atomic_file::open_read_regular(hwm_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HwmState::Missing,
        Err(_) => return HwmState::Tampered,
    };
    let mut content = String::new();
    if std::io::BufReader::new(file)
        .take(MAX_HWM_FILE_BYTES)
        .read_to_string(&mut content)
        .is_err()
    {
        return HwmState::Tampered;
    }
    match content.trim().parse::<u64>() {
        Ok(v) => HwmState::Valid(v),
        Err(_) => HwmState::Tampered,
    }
}

fn write_hwm(hwm_path: &std::path::Path, seq: u64) -> Result<(), std::io::Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    // Rejects a symlinked path in a single stat call; returns whether a
    // (non-symlink) file exists there so callers don't need a second stat
    // just to check existence.
    let reject_symlink = |path: &std::path::Path, which: &str| -> Result<bool, std::io::Error> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "HWM {which} path `{}` is a symlink; refusing to write",
                    path.display()
                ),
            )),
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    };
    reject_symlink(hwm_path, "final")?;

    let mut temp_path = hwm_path.as_os_str().to_owned();
    temp_path.push(".tmp");
    let temp_path = PathBuf::from(temp_path);
    if reject_symlink(&temp_path, "temp")? {
        // Stale temp file from a prior crash between create and rename.
        fs::remove_file(&temp_path)?;
    }

    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)?;
        write!(file, "{seq}")?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, hwm_path)?;
    if let Some(dir) = hwm_path.parent()
        && let Ok(dir_file) = fs::File::open(dir)
    {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — kept in mod.rs because test helpers and cross-submodule assertions
// need access to all submodule items via `use super::*`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::chain::compute_entry_hash;
    use super::*;
    use crate::rules::{ActionKind, RuleConfig};
    use std::fs::OpenOptions;
    use std::path::Path;

    // Also import submodule internals needed by tests
    use chain::{
        HashableEvent, HashableEventV2, RecomputedHash, SUPPORTED_CHAIN_VERSIONS, genesis_hash,
        prune_genesis_hash,
    };
    use retention::{MIN_RETENTION_DAYS, PRUNE_COMMAND, build_prune_point, try_prune_at};
    use secret::{
        KeyringAnomaly, MAX_KEYRING_KEYS, UNRESOLVED_KEY_ID, create_secret, decode_hex_secret,
        expected_key_file, flock_exclusive, is_writer_emitted_key_id, load_keyring,
        load_or_create_secret, load_signing_key, open_read_nofollow, read_secret,
    };
    use verify::{AuditError, KeyUnavailableKind, display_timestamp};

    /// Run `f` on a worker thread and fail the test if it has not finished
    /// within `limit`.
    ///
    /// The defects these guard against (`flock` without `LOCK_NB`, `open`
    /// without `O_NONBLOCK`) fail by *not returning*, and a test that simply
    /// calls them would hang rather than fail — indistinguishable from a slow
    /// machine, and it takes the whole test binary with it. Timing out into an
    /// assertion turns "it blocks forever" into an ordinary red test.
    fn must_finish_within<T: Send + 'static>(
        limit: std::time::Duration,
        what: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(limit) {
            Ok(value) => value,
            Err(_) => panic!("{what} did not return within {limit:?} — it blocked"),
        }
    }

    const TEST_SECRET: [u8; 32] = [0x42u8; 32];

    fn test_logger(dir: &Path) -> AuditLogger {
        let path = dir.join("audit.jsonl");

        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        AuditLogger {
            path,
            signing_key: SigningKey::for_test("default", Some(TEST_SECRET)),
            retention_days: 0,
        }
    }

    /// #457 A2: `try_prune_at` / `build_prune_point` take the key and the
    /// `key_id` that names it as one value. Most fixtures only care about the
    /// bytes, so this wraps `TEST_SECRET` under the id an unrotated store
    /// would carry. Fixtures that exercise rotation build their own.
    fn test_signing_key() -> SigningKey {
        SigningKey::for_test("default", Some(TEST_SECRET))
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omamori-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Unwraps a `Valid` HWM read, panicking with the actual state otherwise.
    fn expect_hwm(hwm_path: &Path) -> u64 {
        match read_hwm(hwm_path) {
            HwmState::Valid(v) => v,
            HwmState::Missing => panic!("expected HWM to be Valid, but it was Missing"),
            HwmState::Tampered => panic!("expected HWM to be Valid, but it was Tampered"),
        }
    }

    fn make_event(command: &str) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test".to_string(),
            command: command.to_string(),
            rule_id: None,
            action: "passthrough".to_string(),
            result: "passthrough".to_string(),
            target_count: 0,
            target_hash: "hmac-sha256:test".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: None,
            seq: None,
            prev_hash: None,
            key_id: None,
            entry_hash: None,
            pid: None,
            ppid: None,
            parent_process: None,
            cwd_hash: None,
            wrapper_kind: None,
        }
    }

    fn read_events(path: &Path) -> Vec<serde_json::Value> {
        let content = fs::read_to_string(path).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    // --- AuditLogger: from_config ---

    #[test]
    fn from_config_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        assert!(AuditLogger::from_config(&config).is_none());
    }

    #[test]
    fn from_config_enabled_creates_secret() {
        let dir = test_dir("from-config");
        let config = AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let logger = AuditLogger::from_config(&config).expect("should create logger");
        assert!(logger.secret_available());
        assert!(dir.join("audit-secret").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn from_config_default_path() {
        // Uses ambient HOME (via resolved_audit_path → context::data_dir)
        // — must share the `home_env` lock with tests elsewhere in this
        // file that mutate HOME, or it can observe a torn value (#344-class
        // flake; the bare `#[serial_test::serial]` this carried previously
        // used a different, non-overlapping lock group).
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let logger = AuditLogger::from_config(&config);
        assert!(logger.is_some(), "should create logger with default path");
    }

    // --- Hash chain: append builds chain ---

    #[test]
    fn chain_three_entries() {
        let dir = test_dir("chain3");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Verify monotonic seq
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event["seq"], i as u64);
        }
        // Verify prev_hash chain
        let genesis = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(events[0]["prev_hash"], genesis);
        assert_eq!(events[1]["prev_hash"], events[0]["entry_hash"]);
        assert_eq!(events[2]["prev_hash"], events[1]["entry_hash"]);

        let _ = fs::remove_dir_all(&dir);
    }

    // #420 (Design A): provenance fields are outside `HashableEvent`, so
    // an entry written before this feature (no provenance keys in the JSON
    // at all) and one written after (real provenance data) must both
    // verify cleanly in the *same* chain — this is the load-bearing claim
    // behind "CHAIN_VERSION stays 1, existing chains are unaffected".
    #[test]
    fn verify_chain_mixes_pre_420_and_post_420_entries() {
        let dir = test_dir("verify-mixed-420");
        let logger = test_logger(&dir);

        // Pre-#420 shaped entry: `make_event`'s provenance fields are all
        // `None`, so `skip_serializing_if` omits the JSON keys entirely —
        // indistinguishable from a real pre-#420 log line.
        logger.append(make_event("pre-420-cmd")).unwrap();

        // Post-#420 shaped entry: real provenance data present.
        let provenance = ProcessProvenance::collect();
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(Some(&provenance), Some(&TEST_SECRET));
        let mut post_event = make_event("post-420-cmd");
        post_event.pid = pid;
        post_event.ppid = ppid;
        post_event.parent_process = parent_process;
        post_event.cwd_hash = cwd_hash;
        logger.append(post_event).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at, None,
            "mixed pre/post-#420 chain must verify cleanly"
        );
        assert_eq!(result.chain_entries, 2);

        // Confirm the on-disk JSON actually differs in shape — otherwise
        // this test would not be exercising the mixed-shape scenario at all.
        let events = read_events(&logger.path);
        assert!(
            events[0].get("pid").is_none(),
            "pre-420 entry must omit provenance keys entirely, not just be null"
        );
        assert!(
            events[1].get("pid").is_some(),
            "post-420 entry must carry provenance keys"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // #420 Design A's accepted cost, made concrete rather than left as a
    // documentation claim: provenance fields sit outside `HashableEvent`,
    // so *semantic* tampering (same JSON shape, different value) is
    // chain-silent — verify_chain has no way to see it (ADR-0006). *Syntactic*
    // corruption (breaks the JSON shape entirely) is a different failure
    // mode: the line fails `AuditEvent` deserialization, is counted as
    // torn, and the *next* line's prev_hash check then fails because
    // `expected_prev` was never advanced past the torn line (see
    // verify.rs's `serde_json::from_str` -> `torn_lines += 1; continue`
    // path). This pair of tests pins that asymmetry directly.
    fn provenance_tamper_fixture(dir: &Path) -> AuditLogger {
        let logger = test_logger(dir);
        let provenance = ProcessProvenance::collect();
        let (pid, ppid, parent_process, cwd_hash) =
            ProcessProvenance::as_audit_fields(Some(&provenance), Some(&TEST_SECRET));
        let mut first_event = make_event("first-cmd");
        first_event.pid = pid;
        first_event.ppid = ppid;
        first_event.parent_process = parent_process;
        first_event.cwd_hash = cwd_hash;
        logger.append(first_event).unwrap();
        logger.append(make_event("second-cmd")).unwrap();
        logger
    }

    /// #177 B3: `logger.append()` now writes `chain_version: 2`, so a
    /// tamper against its output exercises the *detected* side of the
    /// v1/v2 asymmetry (shape enumeration §5). `_remains_silent_on_v1_entries`
    /// below covers the still-undetectable v1 side.
    #[test]
    fn provenance_value_tampering_is_detected_on_v2_entries() {
        let dir = test_dir("tamper-semantic-420-v2");
        let logger = provenance_tamper_fixture(&dir);

        let content = fs::read_to_string(&logger.path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        assert_eq!(lines.len(), 2);

        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            first.get("pid").is_some(),
            "precondition: first line must actually carry a pid value to tamper with"
        );
        assert_eq!(
            first.get("chain_version").and_then(|v| v.as_u64()),
            Some(2),
            "precondition: logger.append() must write the current (v2) chain_version"
        );
        first["pid"] = serde_json::json!(999_999);
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&logger.path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at,
            Some(0),
            "#177 B3: pid is now part of HashableEventV2 — a value-only edit to a v2 entry's \
             provenance field MUST be detected via the hash chain"
        );
        assert_eq!(result.torn_lines, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B2/B3: mirrors `provenance_value_tampering_is_detected_on_v2_entries`
    /// above for `wrapper_kind`, the second field HashableEventV2 newly
    /// protects.
    #[test]
    fn wrapper_kind_tampering_is_detected_on_v2_entries() {
        let dir = test_dir("tamper-wrapper-kind-177b3-v2");
        let logger = test_logger(&dir);
        let mut first_event = make_event("first-cmd");
        first_event.wrapper_kind = Some("env".to_string());
        logger.append(first_event).unwrap();
        logger.append(make_event("second-cmd")).unwrap();

        let content = fs::read_to_string(&logger.path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        assert_eq!(lines.len(), 2);

        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(
            first.get("wrapper_kind").and_then(|v| v.as_str()),
            Some("env"),
            "precondition: first line must actually carry a wrapper_kind value to tamper with"
        );
        assert_eq!(
            first.get("chain_version").and_then(|v| v.as_u64()),
            Some(2),
            "precondition: logger.append() must write the current (v2) chain_version"
        );
        first["wrapper_kind"] = serde_json::json!("sudo");
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&logger.path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at,
            Some(0),
            "#177 B3: wrapper_kind is now part of HashableEventV2 — a value-only edit to a v2 \
             entry's wrapper_kind MUST be detected via the hash chain"
        );
        assert_eq!(result.torn_lines, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B3: writes a 2-entry V1-tagged chain directly (not via
    /// `logger.append()`, which now writes v2) — the first entry carries
    /// fixed `pid`/`wrapper_kind` values to tamper with. Fixed, not
    /// `ProcessProvenance::collect()`'s real environment values (unlike
    /// `provenance_tamper_fixture` above): this fixture isn't golden-hex
    /// pinned, but determinism still matters for readable failure output.
    fn v1_provenance_and_wrapper_tamper_fixture(dir: &Path) -> PathBuf {
        test_logger(dir); // secret file only; audit.jsonl written below
        let path = dir.join("audit.jsonl");
        let genesis = genesis_hash(Some(&TEST_SECRET));

        let mut first = make_event("first-cmd");
        first.chain_version = Some(1);
        first.seq = Some(0);
        first.prev_hash = Some(genesis);
        first.key_id = Some("default".to_string());
        first.pid = Some(4242);
        first.wrapper_kind = Some("env".to_string());
        first.entry_hash = Some(
            compute_entry_hash(Some(&TEST_SECRET), &first)
                .expect_hash("v1_provenance_and_wrapper_tamper_fixture: first"),
        );

        let mut second = make_event("second-cmd");
        second.chain_version = Some(1);
        second.seq = Some(1);
        second.prev_hash = first.entry_hash.clone();
        second.key_id = Some("default".to_string());
        second.entry_hash = Some(
            compute_entry_hash(Some(&TEST_SECRET), &second)
                .expect_hash("v1_provenance_and_wrapper_tamper_fixture: second"),
        );

        let content = format!(
            "{}\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
        );
        fs::write(&path, content).unwrap();
        path
    }

    /// #177 B3: the permanent, non-negotiable half of the v1/v2 asymmetry
    /// (shape enumeration §5, A-4) — a v1 entry's provenance was never
    /// hash-protected and B3 does not retroactively protect it (existing
    /// audit.jsonl bytes are never rewritten). If this test ever starts
    /// failing (`broken_at` becoming `Some`), that means V1 hashing
    /// changed, which would break every existing user's audit.jsonl.
    #[test]
    fn provenance_value_tampering_remains_silent_on_v1_entries() {
        let dir = test_dir("tamper-semantic-420-v1");
        let path = v1_provenance_and_wrapper_tamper_fixture(&dir);

        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first["pid"], serde_json::json!(4242));
        first["pid"] = serde_json::json!(999_999);
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at, None,
            "Design A, permanent for v1: a value-only edit to a v1 entry's provenance field \
             must never be detectable via the hash chain — existing audit.jsonl bytes are \
             never rewritten, so this is not a bug to fix"
        );
        assert_eq!(result.torn_lines, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B3: mirrors `provenance_value_tampering_remains_silent_on_v1_entries`
    /// for `wrapper_kind`.
    #[test]
    fn wrapper_kind_tampering_remains_silent_on_v1_entries() {
        let dir = test_dir("tamper-wrapper-kind-177b3-v1");
        let path = v1_provenance_and_wrapper_tamper_fixture(&dir);

        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first["wrapper_kind"], serde_json::json!("env"));
        first["wrapper_kind"] = serde_json::json!("sudo");
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at, None,
            "Design A, permanent for v1: a value-only edit to a v1 entry's wrapper_kind must \
             never be detectable via the hash chain — existing audit.jsonl bytes are never \
             rewritten, so this is not a bug to fix"
        );
        assert_eq!(result.torn_lines, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B3: the single most important tampering test in this module
    /// (shape enumeration §5.2). A chain with v1 entries followed by v2
    /// entries — the exact shape every existing user's log takes on
    /// upgrade — proves per-entry, stateless dispatch rather than a
    /// degenerate file-level version check: tampering the v1 portion stays
    /// silent (all 4 entries still verify), but the SAME dispatch applied
    /// to the v2 portion of the SAME chain detects tampering. Splitting
    /// this into two single-version files (as the 4 tests above do) could
    /// only ever show "v1 files behave differently from v2 files" — never
    /// that a single chain switches behavior mid-stream at the version
    /// boundary, which is what #177 B3 actually implements.
    /// The v1 portion (seq 0-1) is built directly, the same structural
    /// necessity as `hash_v1_algorithm_is_frozen` above (`logger.append()`
    /// can only ever write the current `CHAIN_VERSION`, now 2). The v2
    /// portion (seq 2-3) is appended through the REAL `AuditLogger::append`
    /// (Codex Phase 6-B): the original version of this fixture built both
    /// halves through the same direct `compute_entry_hash` call, which
    /// couldn't distinguish a bug in `compute_entry_hash` itself from a bug
    /// in `append()`'s own wiring onto an existing tail — routing the v2
    /// half through the production writer closes that gap for exactly the
    /// entries this test's Part 2 assertion (tampering the v2 side) relies
    /// on.
    fn write_mixed_v1_v2_provenance_fixture(dir: &Path) -> PathBuf {
        // `test_logger`'s own return value is the logger this fixture needs
        // for its v2 (real-append) half below — keep it instead of
        // discarding it and rebuilding an identical one later (/simplify).
        let logger = test_logger(dir);
        let path = logger.path.clone();
        let genesis = genesis_hash(Some(&TEST_SECRET));
        let mut prev_hash = genesis;
        let mut lines = Vec::new();

        for i in 0..2u64 {
            let mut event = make_event(&format!("cmd{i}"));
            event.chain_version = Some(1);
            event.seq = Some(i);
            event.prev_hash = Some(prev_hash.clone());
            event.key_id = Some("default".to_string());
            event.pid = Some(4242);
            event.entry_hash = Some(
                compute_entry_hash(Some(&TEST_SECRET), &event)
                    .expect_hash("write_mixed_v1_v2_provenance_fixture: v1"),
            );
            prev_hash = event.entry_hash.clone().unwrap();
            lines.push(serde_json::to_string(&event).unwrap());
        }
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        for i in 2..4u64 {
            let mut event = make_event(&format!("cmd{i}"));
            event.pid = Some(4242);
            logger.append(event).unwrap();
        }

        path
    }

    #[test]
    fn v1_and_v2_tamper_asymmetry_within_one_chain() {
        // Part 1: tamper the v1 portion (seq=0) of a v1→v2 chain — must
        // stay silent, and verification must still reach and confirm all
        // 4 entries (the v2 tail included), not just stop quietly.
        let dir_v1 = test_dir("tamper-asymmetry-v1-side");
        let path_v1 = write_mixed_v1_v2_provenance_fixture(&dir_v1);
        let content = fs::read_to_string(&path_v1).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut seq0: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(seq0["chain_version"], serde_json::json!(1));
        seq0["pid"] = serde_json::json!(999_999);
        lines[0] = serde_json::to_string(&seq0).unwrap();
        fs::write(&path_v1, lines.join("\n") + "\n").unwrap();

        let result_v1_tamper = verify_chain(&verify_config(&dir_v1)).unwrap();
        assert_eq!(
            result_v1_tamper.broken_at, None,
            "tampering the v1 (seq=0) portion of a mixed v1→v2 chain must stay silent"
        );
        assert_eq!(
            result_v1_tamper.chain_entries, 4,
            "all 4 entries (v1 and v2) must still verify — the v1 tamper doesn't just get \
             silently skipped, the rest of the chain genuinely checks out"
        );
        assert_eq!(result_v1_tamper.v1_entries, 2);
        assert_eq!(result_v1_tamper.v2_entries, 2);
        let _ = fs::remove_dir_all(&dir_v1);

        // Part 2: fresh copy of the same mixed chain, tamper the v2 portion
        // (seq=2) instead — same per-entry dispatch, opposite outcome.
        let dir_v2 = test_dir("tamper-asymmetry-v2-side");
        let path_v2 = write_mixed_v1_v2_provenance_fixture(&dir_v2);
        let content = fs::read_to_string(&path_v2).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut seq2: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        assert_eq!(seq2["chain_version"], serde_json::json!(2));
        seq2["pid"] = serde_json::json!(999_999);
        lines[2] = serde_json::to_string(&seq2).unwrap();
        fs::write(&path_v2, lines.join("\n") + "\n").unwrap();

        let result_v2_tamper = verify_chain(&verify_config(&dir_v2)).unwrap();
        assert_eq!(
            result_v2_tamper.broken_at,
            Some(2),
            "tampering the v2 (seq=2) portion of the SAME mixed chain shape must be detected \
             — proving per-entry dispatch, not a degenerate file-level version check"
        );
        let _ = fs::remove_dir_all(&dir_v2);
    }

    /// #177 B3 (Codex Round 1 P1): shape-enumeration release blocker T-09
    /// (`read_chain_state` accepting a v1 tail as safe-to-append-after) was
    /// otherwise only exercised indirectly, through hand-built fixtures
    /// that never touch `AuditLogger::append()` itself. This test drives
    /// the real production writer path starting from a genuine v1 tail,
    /// proving `append()` — not just `verify_chain`'s dispatch — correctly
    /// continues a v1 chain with a new v2 entry.
    #[test]
    fn append_continues_a_v1_tail_with_a_v2_entry() {
        let dir = test_dir("append-v1-tail-v2-continue");
        let logger = test_logger(&dir); // audit.jsonl written below
        let path = logger.path.clone();
        let ts = "2026-01-01T00:00:00Z";
        let entries: [(&str, &str); 2] = [("cmd0", ts), ("cmd1", ts)];
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let before = read_events(&path);
        assert_eq!(before.len(), 2);
        assert_eq!(before[1]["chain_version"], serde_json::json!(1));
        let last_v1_seq = before[1]["seq"].as_u64().unwrap();
        let last_v1_hash = before[1]["entry_hash"].as_str().unwrap().to_string();

        logger.append(make_event("cmd2")).unwrap();

        let after = read_events(&path);
        assert_eq!(after.len(), 3);
        assert_eq!(
            after[2]["chain_version"],
            serde_json::json!(2),
            "append() must write the current CHAIN_VERSION (2) onto a v1 tail"
        );
        assert_eq!(
            after[2]["seq"].as_u64().unwrap(),
            last_v1_seq + 1,
            "seq must continue from the v1 tail's last seq, not restart"
        );
        assert_eq!(
            after[2]["prev_hash"].as_str().unwrap(),
            last_v1_hash,
            "prev_hash must chain onto the v1 tail's entry_hash"
        );

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at, None,
            "a v1 tail continued by a real append()'d v2 entry must verify intact"
        );
        assert_eq!(result.chain_entries, 3);
        assert_eq!(result.v1_entries, 2);
        assert_eq!(result.v2_entries, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B3 (Codex Round 1 P1): shape-enumeration release blocker T-08
    /// (`verify_chain`'s raw-JSON fallback peek must not misreport a
    /// genuinely corrupted but *supported*-version entry as "unrecognized
    /// version"). Corrupts `pid`'s type (not `chain_version`/`seq`, which
    /// the fallback peek itself reads) on a v1 entry — `AuditEvent`
    /// deserialization fails entirely, but the peek still succeeds and
    /// finds `chain_version: 1`, a supported value, so this must fall
    /// through to `torn_lines`, not get classified as an unrecognized
    /// version and tell the operator to upgrade omamori for what is
    /// actually plain corruption on an already-current binary.
    #[test]
    fn verify_v1_corruption_is_torn_not_unrecognized_version() {
        let dir = test_dir("verify-v1-corruption-torn");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");
        let entries: [(&str, &str); 1] = [("cmd0", "2026-01-01T00:00:00Z")];
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let content = fs::read_to_string(&path).unwrap();
        let mut event: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(event["chain_version"], serde_json::json!(1));
        event["pid"] = serde_json::json!("not-a-number");
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.torn_lines, 1,
            "type-corrupted v1 line must fail AuditEvent deserialization and count as torn"
        );
        assert_eq!(
            result.unknown_version_at, None,
            "a corrupted-but-SUPPORTED (v1) chain_version must never be reported as an \
             unrecognized version — T-08"
        );
        assert_eq!(result.chain_entries, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B3 (Codex Phase 6-B, Finding 5): the shape-enumeration report's
    /// F-I shape ("legacy → v1 → v2", the longest-lived possible log) —
    /// no existing test combined all three eras in one file. Legacy is
    /// hand-written (no `chain_version` key, genuine pre-#164 history), v1
    /// is hand-built (`logger.append()` can't produce it post-flip), and v2
    /// is appended through the real production writer, continuing the v1
    /// tail — proving `legacy_entries`/`v1_entries`/`v2_entries` are each
    /// counted correctly and the whole chain verifies intact end to end.
    #[test]
    fn verify_legacy_then_v1_then_v2_chain() {
        let dir = test_dir("verify-legacy-v1-v2");
        let logger = test_logger(&dir);
        let path = logger.path.clone();

        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(&path, serde_json::to_string(&legacy).unwrap() + "\n").unwrap();

        let genesis = genesis_hash(Some(&TEST_SECRET));
        let mut v1_event = make_event("cmd-v1");
        v1_event.chain_version = Some(1);
        v1_event.seq = Some(0);
        v1_event.prev_hash = Some(genesis);
        v1_event.key_id = Some("default".to_string());
        v1_event.entry_hash = Some(
            compute_entry_hash(Some(&TEST_SECRET), &v1_event)
                .expect_hash("verify_legacy_then_v1_then_v2_chain: v1"),
        );
        let mut content = fs::read_to_string(&path).unwrap();
        content.push_str(&serde_json::to_string(&v1_event).unwrap());
        content.push('\n');
        fs::write(&path, content).unwrap();

        logger.append(make_event("cmd-v2-a")).unwrap();
        logger.append(make_event("cmd-v2-b")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_none(),
            "legacy -> v1 -> v2 chain must verify intact end to end"
        );
        assert_eq!(result.legacy_entries, 1);
        assert_eq!(result.chain_entries, 3);
        assert_eq!(result.v1_entries, 1);
        assert_eq!(result.v2_entries, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provenance_type_corruption_causes_downstream_chain_break() {
        let dir = test_dir("tamper-syntactic-420");
        let logger = provenance_tamper_fixture(&dir);

        let content = fs::read_to_string(&logger.path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        assert_eq!(lines.len(), 2);

        // Valid JSON syntax, but wrong type for `pid` (u32) — AuditEvent
        // deserialization fails on this line entirely.
        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        first["pid"] = serde_json::json!("not-a-number");
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&logger.path, lines.join("\n") + "\n").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.torn_lines, 1,
            "the type-corrupted line must fail AuditEvent deserialization entirely"
        );
        assert!(
            result.broken_at.is_some(),
            "corruption surfaces downstream: the torn line is skipped without \
             advancing expected_prev, so the next entry's prev_hash check fails \
             — this is NOT silent, unlike the value-only tamper above"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_genesis_hash_is_deterministic() {
        let a = genesis_hash(Some(&TEST_SECRET));
        let b = genesis_hash(Some(&TEST_SECRET));
        assert_eq!(a, b);
    }

    #[test]
    fn chain_genesis_differs_by_secret() {
        let other = [0x99u8; 32];
        assert_ne!(genesis_hash(Some(&TEST_SECRET)), genesis_hash(Some(&other)));
    }

    #[test]
    fn chain_entry_hash_is_deterministic() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let h1 = compute_entry_hash_for_write(Some(&TEST_SECRET), &event);
        let h2 = compute_entry_hash_for_write(Some(&TEST_SECRET), &event);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_entry_hash_changes_on_tamper() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let h_orig = compute_entry_hash_for_write(Some(&TEST_SECRET), &event);
        event.result = "tampered".to_string();
        let h_tampered = compute_entry_hash_for_write(Some(&TEST_SECRET), &event);
        assert_ne!(h_orig, h_tampered);
    }

    #[test]
    fn chain_no_secret_uses_marker() {
        let mut event = make_event("ls");
        event.chain_version = Some(CHAIN_VERSION);
        event.seq = Some(0);
        event.prev_hash = Some("genesis".to_string());
        event.key_id = Some("default".to_string());

        let hash = compute_entry_hash_for_write(None, &event);
        assert_eq!(hash, "NO_HMAC_SECRET");
    }

    // --- Legacy migration ---

    #[test]
    fn chain_after_legacy_entries() {
        let dir = test_dir("chain-legacy");
        let logger = test_logger(&dir);

        // Write a legacy entry (no chain fields) directly
        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old-cmd",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(&logger.path, serde_json::to_string(&legacy).unwrap() + "\n").unwrap();

        // Append new entry — should start chain from genesis (ignore legacy)
        logger.append(make_event("new-cmd")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);
        assert!(events[0]["chain_version"].is_null(), "legacy has no chain");
        assert_eq!(events[1]["seq"], 0, "new chain starts at seq 0");
        assert_eq!(events[1]["prev_hash"], genesis_hash(Some(&TEST_SECRET)));

        let _ = fs::remove_dir_all(&dir);
    }

    // --- #177 B1 step 3: append refuses an unsupported-version tail ---

    #[test]
    fn append_refuses_after_unknown_chain_version_tail() {
        let dir = test_dir("append-unknown-version-refuse");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();
        append_unknown_version_line(&logger.path, 1);

        let before = fs::read_to_string(&logger.path).unwrap();
        let before_line_count = before.lines().filter(|l| !l.trim().is_empty()).count();

        let result = logger.append(make_event("cmd1-should-not-be-recorded"));
        assert!(
            result.is_err(),
            "append must return Err — QA Phase 8 F-001: strict mode's 'no receipt = don't \
             allow' contract only escalates on Err. G-2's best-effort default is preserved \
             by the caller's own Err handling (a warning, not a block in non-strict mode), \
             not by append() itself claiming success."
        );

        let after = fs::read_to_string(&logger.path).unwrap();
        let after_line_count = after.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(
            before_line_count, after_line_count,
            "append must refuse to write after an unsupported-chain_version tail — \
             the file's entry count must be unchanged"
        );
        assert!(
            !after.contains("cmd1-should-not-be-recorded"),
            "the refused event must not appear anywhere in the file"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// QA Phase 8 F-001 (#177 B1): `try_audit_append` is the seam every
    /// non-hook call site (`exec`, sudo-block, non-protected passthrough)
    /// routes audit logging through, and it's `strict`-aware. Before the
    /// append() Err fix, an unsupported-version tail returned `Ok(())`,
    /// so `try_audit_append`'s `if let Err(e) = logger.append(event)`
    /// never fired — strict mode's documented "no receipt = don't allow"
    /// contract silently didn't apply to this one failure mode, creating
    /// a permanent, silent audit blackout that `[audit] strict = true`
    /// exists specifically to prevent.
    #[test]
    fn try_audit_append_strict_blocks_on_unknown_chain_version_tail() {
        let dir = test_dir("try-audit-append-strict-unknown-version");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();
        append_unknown_version_line(&logger.path, 1);

        let strict_logger = AuditLogger {
            path: logger.path.clone(),
            signing_key: SigningKey::for_test(logger.key_id(), logger.secret_ref().copied()),
            retention_days: logger.retention_days,
        };
        let event = strict_logger.create_event(
            &CommandInvocation::new("cmd1".to_string(), vec![]),
            None,
            &[],
            &ActionOutcome::PassedThrough { exit_code: 0 },
            None,
        );
        let result = crate::engine::shim::try_audit_append(&strict_logger, event, true);
        assert_eq!(
            result,
            Some(1),
            "strict mode must block when the audit tail has an unrecognized chain_version, \
             the same as it blocks on any other append failure"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex Round 1 (#177 B1): a future-version tail entry that doesn't
    /// carry `seq`/`entry_hash` in a form the old code recognized fell
    /// through to `Fresh` (silently restart the chain from genesis)
    /// instead of refusing to append — forking a second, disconnected
    /// chain in the same file with no record that the original continued.
    #[test]
    fn append_refuses_after_unknown_chain_version_tail_missing_seq_and_hash() {
        let dir = test_dir("append-unknown-version-refuse-bad-shape");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();

        let future_tail = serde_json::json!({
            "chain_version": 999,
            "some_future_field": "whatever a v999 tail entry looks like"
        });
        let mut content = fs::read_to_string(&logger.path).unwrap();
        content.push_str(&serde_json::to_string(&future_tail).unwrap());
        content.push('\n');
        fs::write(&logger.path, &content).unwrap();
        let before_line_count = content.lines().filter(|l| !l.trim().is_empty()).count();

        let result = logger.append(make_event("cmd1-should-not-be-recorded"));
        assert!(
            result.is_err(),
            "must return Err (QA Phase 8 F-001: strict mode)"
        );

        let after = fs::read_to_string(&logger.path).unwrap();
        let after_line_count = after.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(
            before_line_count, after_line_count,
            "must refuse to append, not silently fork a new chain from genesis"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #456: the tail's `seq` is read off disk and never authenticated
    /// (`read_chain_state` accepts any non-empty `entry_hash`), so one
    /// planted line can set it to `u64::MAX`. `append()` used to compute
    /// `last_seq + 1` from it, which wraps to 0 in a release build without
    /// `overflow-checks` — the next entry is numbered 0, and the
    /// high-water-mark check reads that as tail truncation. Refusing is the
    /// same answer this function already gives an unsupported
    /// `chain_version` tail.
    #[test]
    fn append_refuses_when_the_tail_seq_admits_no_successor() {
        let dir = test_dir("append-seq-at-limit-refuse");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();
        append_seq_at_limit_line(&logger.path);

        let hwm_file = hwm_path_for(&logger.path);
        let hwm_before = expect_hwm(&hwm_file);
        let content = fs::read_to_string(&logger.path).unwrap();

        let err = logger
            .append(make_event("cmd1-should-not-be-recorded"))
            .expect_err("append must return Err, not wrap the seq to 0 and record the entry");
        let msg = err.to_string();

        // Assert on the diagnostic sentence, not on a word the fixture also
        // supplies (#488): the number below comes from the planted line, so a
        // `contains`-on-the-number alone would be satisfied by any message
        // that quotes the tail.
        assert!(
            msg.contains("the largest sequence number the format can hold"),
            "the refusal must say why there is no successor — got: {msg}"
        );
        assert!(
            msg.contains("refusing to append") && msg.contains("was not recorded"),
            "the refusal must reuse the existing shape (refused, nothing written) — got: {msg}"
        );
        assert!(
            msg.contains("18446744073709551615"),
            "the refusal must quote the number the operator can check against the file — \
             got: {msg}"
        );
        // Nothing here authenticated the tail, so the message must not make
        // the accusation `broken_at` makes.
        assert!(
            !msg.contains("may have been tampered with"),
            "must not use the tamper-claim phrasing for a line nothing authenticated — \
             got: {msg}"
        );

        let after = fs::read_to_string(&logger.path).unwrap();
        // The legible assertion first, then the total one: a byte-equality
        // failure prints the whole file, which is unreadable as a first
        // signal (Codex review, R1 P3 asked for the byte comparison — the
        // claim is "nothing was written", and a line count does not say that).
        assert!(
            !after.contains("cmd1-should-not-be-recorded"),
            "the refused event must not appear anywhere in the file"
        );
        assert_eq!(
            after, content,
            "a refused append must leave the file byte-for-byte unchanged"
        );
        assert_eq!(
            expect_hwm(&hwm_file),
            hwm_before,
            "a refused append must not move the high-water-mark — a wrapped seq of 0 \
             would either raise a false truncation warning or (on a Tampered sidecar) \
             rewrite the mark to 0 and hide later truncation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex review R1 P1: the refusal has to be decided from `seq` before
    /// `entry_hash`'s shape is looked at. A malformed entry is answered by
    /// restarting from genesis — which numbers the next entry `0` — so this
    /// shape reached the very outcome the refusal exists to prevent while
    /// never passing through the increment. The wrap was not the only road to
    /// `seq: 0`; the fork was the other.
    #[test]
    fn append_refuses_at_the_seq_limit_even_when_the_tail_entry_hash_is_malformed() {
        let dir = test_dir("append-seq-at-limit-empty-hash");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();

        // `entry_hash: ""` is what makes this distinct from
        // `append_seq_at_limit_line`: an empty string fails the shape check,
        // so before the fix this line took the genesis-restart arm.
        let mut content = fs::read_to_string(&logger.path).unwrap();
        content.push_str(
            r#"{"timestamp":"2026-01-01T00:00:01Z","provider":"test","command":"planted-cmd","action":"passthrough","result":"passthrough","target_count":0,"target_hash":"irrelevant","chain_version":2,"seq":18446744073709551615,"prev_hash":"irrelevant","key_id":"default","entry_hash":""}"#,
        );
        content.push('\n');
        fs::write(&logger.path, &content).unwrap();

        let err = logger
            .append(make_event("cmd1-should-not-be-recorded"))
            .expect_err("a tail at the limit must be refused whatever shape entry_hash is in");
        assert!(
            err.to_string()
                .contains("the largest sequence number the format can hold"),
            "must give the seq-limit refusal, not fall through to a genesis restart — \
             got: {err}"
        );

        let after = fs::read_to_string(&logger.path).unwrap();
        assert!(
            !after.contains("cmd1-should-not-be-recorded"),
            "the refused event must not appear anywhere in the file"
        );
        assert_eq!(
            after, content,
            "a refused append must leave the file byte-for-byte unchanged"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Control for the test above: the same malformed `entry_hash` on a tail
    /// that is *not* at the limit still restarts the chain from genesis. This
    /// pins that the fix reordered one decision rather than turning every
    /// malformed tail into a refusal — which would be a much larger behavior
    /// change than #456 asks for, and would break the pre-existing
    /// corruption-recovery path.
    #[test]
    fn a_malformed_tail_below_the_limit_still_restarts_from_genesis() {
        let dir = test_dir("append-malformed-hash-below-limit");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();

        let mut content = fs::read_to_string(&logger.path).unwrap();
        content.push_str(
            r#"{"timestamp":"2026-01-01T00:00:01Z","provider":"test","command":"planted-cmd","action":"passthrough","result":"passthrough","target_count":0,"target_hash":"irrelevant","chain_version":2,"seq":7,"prev_hash":"irrelevant","key_id":"default","entry_hash":""}"#,
        );
        content.push('\n');
        fs::write(&logger.path, &content).unwrap();

        logger
            .append(make_event("cmd1-should-be-recorded"))
            .expect("a malformed tail below the limit keeps the pre-existing behavior");

        let events = read_events(&logger.path);
        let last = events.last().unwrap();
        assert_eq!(last["command"], "cmd1-should-be-recorded");
        assert_eq!(
            last["seq"].as_u64(),
            Some(0),
            "the pre-existing answer to a malformed tail is a fresh chain at seq 0"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Control for `append_refuses_when_the_tail_seq_admits_no_successor`:
    /// one below the limit still appends, and takes `u64::MAX` as its own
    /// seq. Without this, the refusal test passes for the wrong reasons — an
    /// implementation that rejected every large seq, or every hand-planted
    /// tail, would satisfy it just as well.
    #[test]
    fn append_still_succeeds_one_below_the_seq_limit() {
        let dir = test_dir("append-seq-one-below-limit");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();
        append_chain_version_line(
            &logger.path,
            CHAIN_VERSION,
            Some(u64::MAX - 1),
            "planted-cmd",
            "passthrough",
            "passthrough",
        );

        logger
            .append(make_event("cmd1-should-be-recorded"))
            .expect("a tail one below the limit still has a successor");

        let events = read_events(&logger.path);
        let last = events.last().unwrap();
        assert_eq!(
            last["command"], "cmd1-should-be-recorded",
            "the event must have been recorded"
        );
        assert_eq!(
            last["seq"].as_u64(),
            Some(u64::MAX),
            "the successor of u64::MAX - 1 is u64::MAX, and it is representable"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #456, mirroring `try_audit_append_strict_blocks_on_unknown_chain_version_tail`:
    /// the refusal must reach strict mode through the same seam as every
    /// other append failure. `try_audit_append` only escalates on `Err`, so
    /// a wrap that returned `Ok(())` left strict mode's "no receipt = don't
    /// allow" contract silently inapplicable to this failure.
    #[test]
    fn try_audit_append_strict_blocks_when_tail_seq_admits_no_successor() {
        let dir = test_dir("try-audit-append-strict-seq-at-limit");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();
        append_seq_at_limit_line(&logger.path);

        let strict_logger = AuditLogger {
            path: logger.path.clone(),
            signing_key: SigningKey::for_test(logger.key_id(), logger.secret_ref().copied()),
            retention_days: logger.retention_days,
        };
        let event = strict_logger.create_event(
            &CommandInvocation::new("cmd1".to_string(), vec![]),
            None,
            &[],
            &ActionOutcome::PassedThrough { exit_code: 0 },
            None,
        );
        let result = crate::engine::shim::try_audit_append(&strict_logger, event, true);
        assert_eq!(
            result,
            Some(1),
            "strict mode must block when the audit tail admits no successor seq, \
             the same as it blocks on any other append failure"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Torn line handling ---

    #[test]
    fn chain_after_torn_line() {
        let dir = test_dir("chain-torn");
        let logger = test_logger(&dir);

        // Append one entry
        logger.append(make_event("first")).unwrap();
        let events_before = read_events(&logger.path);

        // Append a torn line (partial JSON)
        let mut file = OpenOptions::new().append(true).open(&logger.path).unwrap();
        writeln!(file, r#"{{"timestamp":"2026-01-0"#).unwrap();
        drop(file);

        // Append another entry — should continue chain from "first", ignoring torn line
        logger.append(make_event("second")).unwrap();

        let events = read_events(&logger.path);
        // first + second (torn line is not valid JSON so read_events skips it)
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["prev_hash"], events_before[0]["entry_hash"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_empty_file() {
        let dir = test_dir("chain-empty");
        let logger = test_logger(&dir);

        // Create empty file
        fs::write(&logger.path, "").unwrap();

        logger.append(make_event("first")).unwrap();
        let events = read_events(&logger.path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["seq"], 0);
        assert_eq!(events[0]["prev_hash"], genesis_hash(Some(&TEST_SECRET)));

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Golden hex vectors (PR #v096-pr4) ---
    //
    // WHY golden vectors (not a self-verifying helper):
    //   The previous form recomputed `compute_entry_hash` inside the test
    //   and compared it against the recorded `entry_hash`. Since both sides
    //   flow through the same function, an algorithm-level regression
    //   (HMAC key derivation change, field order change, genesis marker
    //   change) would produce a matching pair on both sides and the test
    //   would silently pass. Goldens break that symmetry by pinning the
    //   exact bytes a v0.9.x reader must accept.
    //
    // All inputs the goldens depend on (change any and the hex must be
    // regenerated). PR #186 proxy review P3 — earlier comment only listed
    // timestamp; these additional inputs also feed the HMAC:
    //   - `TEST_SECRET = [0x42u8; 32]`
    //   - `test_logger` defaults: `key_id: "default"`,
    //     `retention_days: 0`, path under temp dir
    //   - `make_event` defaults: `timestamp: "2026-01-01T00:00:00Z"`,
    //     `provider: "test"`, `action/result: "passthrough"`,
    //     `target_count: 0`, `target_hash: "hmac-sha256:test"`,
    //     `detection_layer: Some("layer1")`, all optional chain fields None
    //   - `AuditLogger::append` populates `chain_version`, `seq`,
    //     `prev_hash`, `key_id`, `entry_hash` on each event before write
    //     and does NOT overwrite `timestamp`
    //   - `compute_entry_hash` via `HashableEvent::from_event`
    //     (see `src/audit/chain.rs` — the field order of `HashableEvent`
    //     is additionally SECURITY-pinned by golden test GR-002; reordering
    //     fields invalidates these entry-hash goldens even if the HMAC
    //     algorithm itself is unchanged)
    //
    // #177 B3: this golden set is FROZEN. `GOLDEN_ENTRY_HASHES_V1`'s 5
    // values were captured before CHAIN_VERSION ever left `1` and must
    // NEVER be regenerated — they are the only remaining byte-level proof
    // that V1 hashing is unchanged after V2 was introduced. The "how to
    // regenerate" recipe that used to live here (run
    // `chain_integrity_verification` with a temporary `println!`, since it
    // used the real `AuditLogger::append()` writer path) is GONE on
    // purpose: `append()` now writes whatever CHAIN_VERSION currently is
    // (v2), so running that recipe today would silently produce V2 hashes
    // and, if pasted here by mistake, permanently destroy the V1 proof.
    // V1-hashing regression coverage lives in `hash_v1_algorithm_is_frozen`
    // below, which builds a V1-tagged fixture directly (not via `append()`)
    // and re-derives these exact literals from it.
    //
    // If GOLDEN_ENTRY_HASHES_V1 ever needs to change, that is not a
    // "regeneration" — it is a NEW chain_version (3) with its own
    // GOLDEN_ENTRY_HASHES_V3 database. Never edit these 5 values in place.
    const GOLDEN_GENESIS: &str = "d9c14c4fc7dbc19fce81268a054a22fa092e4946cc762823bd641e156233030b";
    const GOLDEN_ENTRY_HASHES_V1: [&str; 5] = [
        // seq=0, command="cmd0"
        "ff8d28e58ca55a781c908beb827387f22418350d8b7399b2fdecae1a1f805bf2",
        // seq=1, command="cmd1"
        "23473c102da2cc4b56081e1bd9746628feba3c0daf566bb4ecdc7170b085f81f",
        // seq=2, command="cmd2"
        "c1c2d820311b47c2b16acbca62dd7b2be7951045bd7514130f3ea22031d8bf6d",
        // seq=3, command="cmd3"
        "bd394c8964cf47715e2ad67d78184f7a5cf5be21eb651c885d791c2885d075b3",
        // seq=4, command="cmd4"
        "3554f31aac0e3a9ea21afb2f572e09e343c841c21faf2ebf2208f89fc687d165",
    ];

    /// #177 B3: `chain_integrity_verification` and the `chain_tamper_*`
    /// tests below all build their fixtures via `logger.append()` — the
    /// real production writer path (see "WHY golden vectors" above), which
    /// writes whatever `CHAIN_VERSION` currently is. That is now `2`, so
    /// these are the V2 goldens, captured once via `append()` immediately
    /// after the version flip (same one-time-capture discipline as V1 had
    /// before it was frozen). If `CHAIN_VERSION` ever moves to `3`, these
    /// 5 values freeze in turn and a `GOLDEN_ENTRY_HASHES_V3` set takes
    /// over the tests below — do not edit these in place either.
    const GOLDEN_ENTRY_HASHES_V2: [&str; 5] = [
        // seq=0, command="cmd0"
        "5a058a41787911477162e2ec1630527bbb68cabd989628f5ca5d0973ad7ffeb4",
        // seq=1, command="cmd1"
        "d0d0de2d965fe5c8ea3bbae211da6890d54af5ed4a35fc88900ce08bf4a9e11c",
        // seq=2, command="cmd2"
        "0b607702134d38ef8f0631af11c0fcb8eacedac17a0af76ef38b1a1914f2a358",
        // seq=3, command="cmd3"
        "bf80f841b96df92a8fb789896f8809e8158ba4dff9c84d8a298bebc83b97321a",
        // seq=4, command="cmd4"
        "25880d3a375eecd6d0873b548ea73dee044edb00784bbfc73d849dca69fcb8f5",
    ];

    /// #177 B3: `chain_integrity_verification` below moved to testing V2
    /// (it uses `logger.append()`, the real writer, which now produces V2)
    /// — this is what keeps `GOLDEN_ENTRY_HASHES_V1` from becoming
    /// unreachable dead weight. Builds a V1-tagged fixture directly via
    /// `write_chain_entries(.., 1)` (bypassing the current-version-only
    /// writer path) and re-derives the exact frozen literals, proving V1
    /// hashing is byte-for-byte unchanged after V2 was introduced.
    #[test]
    fn hash_v1_algorithm_is_frozen() {
        let dir = test_dir("hash-v1-algorithm-is-frozen");
        let path = dir.join("audit.jsonl");
        // Fixed timestamp for every entry, matching `make_event`'s default
        // (not per-index) — `GOLDEN_ENTRY_HASHES_V1` was originally captured
        // via `make_event(&format!("cmd{i}"))`, whose timestamp field is a
        // constant regardless of `i`. `write_chain_entries` goes through
        // `make_event_with_timestamp`, which only differs from `make_event`
        // if given a different timestamp — passing this same constant
        // reproduces the identical fixture.
        let ts = "2026-01-01T00:00:00Z";
        let entries: [(&str, &str); 5] = [
            ("cmd0", ts),
            ("cmd1", ts),
            ("cmd2", ts),
            ("cmd3", ts),
            ("cmd4", ts),
        ];
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let events = read_events(&path);
        assert_eq!(events.len(), 5);

        assert_eq!(
            events[0]["prev_hash"].as_str().unwrap(),
            GOLDEN_GENESIS,
            "V1 genesis hash must remain byte-identical — this is the frozen proof, \
             never regenerate this value"
        );
        for (i, expected) in GOLDEN_ENTRY_HASHES_V1.iter().enumerate() {
            assert_eq!(
                events[i]["entry_hash"].as_str().unwrap(),
                *expected,
                "V1 entry_hash at seq={i} drifted — GOLDEN_ENTRY_HASHES_V1 must be frozen; \
                 if this fails, V1 hashing changed and every existing user's audit.jsonl \
                 will fail verification"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_integrity_verification() {
        let dir = test_dir("chain-verify");
        let logger = test_logger(&dir);

        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 5);

        // Pin genesis against the golden: if the HMAC marker changes
        // (e.g. key_id derivation, domain separator), this fails first.
        assert_eq!(
            events[0]["prev_hash"].as_str().unwrap(),
            GOLDEN_GENESIS,
            "genesis hash divergence — HMAC key or domain-separator changed?"
        );

        // Pin each entry's recorded entry_hash + prev_hash chain against
        // the golden. Using hardcoded hex breaks the symmetry of the old
        // self-verifying helper (compute_entry_hash on both sides).
        for (i, expected) in GOLDEN_ENTRY_HASHES_V2.iter().enumerate() {
            assert_eq!(
                events[i]["entry_hash"].as_str().unwrap(),
                *expected,
                "entry_hash at seq={i} drifted from golden — algorithm change?"
            );
            let expected_prev = if i == 0 {
                GOLDEN_GENESIS
            } else {
                GOLDEN_ENTRY_HASHES_V2[i - 1]
            };
            assert_eq!(
                events[i]["prev_hash"].as_str().unwrap(),
                expected_prev,
                "prev_hash at seq={i} broke chain linkage from golden"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_tamper_detected() {
        let dir = test_dir("chain-tamper");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // Tamper: change command in second entry on disk.
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen("cmd1", "HACKED", 1);
        fs::write(&logger.path, tampered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Tamper detection contract:
        //   (a) The *recorded* entry_hash on the tampered line is still the
        //       pre-tamper golden (attacker only flipped a payload byte).
        //   (b) Recomputing the hash from the post-tamper payload yields a
        //       different digest. That divergence is the detection signal.
        // Pinning both sides against goldens (not against each other) ensures
        // a future algorithm change can't paper over a real tamper.
        let parsed_seq1: AuditEvent = serde_json::from_value(events[1].clone()).unwrap();
        let recomputed_seq1 = compute_entry_hash(Some(&TEST_SECRET), &parsed_seq1)
            .expect_hash("chain_tamper_detected: seq=1 is a real v2 entry");

        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[1],
            "tampered line should still carry the pre-tamper recorded hash"
        );
        assert_ne!(
            recomputed_seq1, GOLDEN_ENTRY_HASHES_V2[1],
            "recomputed hash over tampered payload must diverge from golden — \
             this is the tamper signal"
        );
        assert_ne!(
            recomputed_seq1,
            events[1]["entry_hash"].as_str().unwrap(),
            "recomputed vs. recorded divergence is the end-to-end detection test"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: physical reorder of two adjacent on-disk events. Each
    /// event still carries its original (unchanged) entry_hash, but the
    /// hash-chain linkage between adjacent on-disk entries breaks because
    /// each `prev_hash` references the predecessor of its *original*
    /// position, not the predecessor at its new physical position.
    #[test]
    fn chain_tamper_reorder_detected() {
        let dir = test_dir("chain-tamper-reorder");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        // Swap on-disk positions of seq=1 and seq=2 lines.
        let reordered = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
        fs::write(&logger.path, reordered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // After reorder:
        //   on-disk position 0 = original seq=0 (entry_hash = GOLDEN[0])
        //   on-disk position 1 = original seq=2 (entry_hash = GOLDEN[2])
        //   on-disk position 2 = original seq=1 (entry_hash = GOLDEN[1])
        // Detection: position-1's recorded prev_hash references GOLDEN[1]
        // (its original predecessor seq=1's hash), but its on-disk
        // predecessor is position-0 whose entry_hash is GOLDEN[0]. The
        // adjacent-pair linkage breaks.
        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[2],
            "reordered position 1 carries original seq=2's entry_hash (unchanged by reorder)"
        );
        assert_eq!(
            events[1]["prev_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[1],
            "position 1's prev_hash still references its original predecessor (seq=1)"
        );
        assert_ne!(
            events[1]["prev_hash"].as_str().unwrap(),
            events[0]["entry_hash"].as_str().unwrap(),
            "after reorder, prev_hash linkage between adjacent on-disk entries breaks — \
             this is the reorder tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): the underlying signal
        // is necessary but not sufficient — `verify_chain` is what the omamori
        // CLI actually invokes to surface tamper, so a future regression in
        // `verify_chain`'s prev_hash-linkage check would silently flip every
        // chain_tamper_* test back to passing without detection. Pin both
        // layers (raw signal + detector E2E).
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after on-disk reorder; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: physical deletion of a middle event (seq=1). After
    /// deletion, the surviving seq=2 entry sits at on-disk position 1
    /// but its `prev_hash` still references the deleted seq=1's hash.
    /// The on-disk predecessor (seq=0) carries a different entry_hash,
    /// so the chain breaks at the deletion point.
    #[test]
    fn chain_tamper_middle_deletion_detected() {
        let dir = test_dir("chain-tamper-middle-deletion");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        // Drop the middle line (original seq=1).
        let truncated = format!("{}\n{}\n", lines[0], lines[2]);
        fs::write(&logger.path, truncated).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);

        // Surviving on-disk position 1 = original seq=2.
        assert_eq!(
            events[1]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[2],
            "surviving position 1 carries original seq=2's entry_hash"
        );
        assert_eq!(
            events[1]["prev_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[1],
            "surviving position 1 still references the deleted seq=1's hash"
        );
        assert_ne!(
            events[1]["prev_hash"].as_str().unwrap(),
            events[0]["entry_hash"].as_str().unwrap(),
            "after middle-deletion, prev_hash points to a vanished hash — \
             this is the deletion tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): see
        // `chain_tamper_reorder_detected` for the rationale on pinning
        // `verify_chain` in addition to the raw on-disk signal.
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after middle-deletion; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #314 baseline: tail truncation is NOT detected by verify_chain().
    ///
    /// Forward-only chain walk has no external sequence anchor, so removing
    /// the last K entries produces a valid (shorter) chain. This test
    /// documents the structural limitation. If future work adds detection
    /// High-water-mark detects tail truncation: the chain itself is valid
    /// (forward-only walk sees a valid shorter chain) but HWM reveals
    /// that higher seq entries once existed.
    #[test]
    fn chain_tail_truncation_detected_by_hwm() {
        let dir = test_dir("chain-tail-truncation-hwm");
        let logger = test_logger(&dir);

        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // HWM should be at seq 4 after appending 5 entries
        let hwm_file = hwm_path_for(&logger.path);
        assert!(hwm_file.exists(), "HWM file should exist after appends");
        let hwm_val = expect_hwm(&hwm_file);
        assert_eq!(hwm_val, 4, "HWM should be 4 after 5 entries (seq 0-4)");

        // Truncate: keep only first 3 entries (seq 0-2)
        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        let truncated = format!("{}\n{}\n{}\n", lines[0], lines[1], lines[2]);
        fs::write(&logger.path, truncated).unwrap();

        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must succeed on truncated chain");
        assert!(
            verify_result.broken_at.is_none(),
            "chain itself is valid (forward-only walk succeeds)"
        );
        assert!(
            verify_result.tail_truncated,
            "HWM detects that entries are missing (chain ends at seq 2, HWM is 4)"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR #187 item 4 / PR #186 proxy R4 P3-5 deferred.
    ///
    /// Tamper class: overwrite `prev_hash` on the genesis event (seq=0).
    /// Without the HMAC secret an attacker cannot forge a valid prev_hash
    /// — genesis is HMAC(secret, "omamori-genesis-v1"). Any overwrite
    /// produces a value != GOLDEN_GENESIS. The recorded entry_hash on
    /// seq=0 stays at GOLDEN[0] (attacker only flipped prev_hash bytes),
    /// but recomputing the entry_hash over the post-tamper payload now
    /// diverges from GOLDEN[0]. Both signals fire.
    #[test]
    fn chain_tamper_genesis_rewrite_detected() {
        let dir = test_dir("chain-tamper-genesis-rewrite");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let forged = "0000000000000000000000000000000000000000000000000000000000000000";
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen(GOLDEN_GENESIS, forged, 1);
        fs::write(&logger.path, tampered).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 3);

        // Signal 1: genesis prev_hash diverges from golden.
        assert_ne!(
            events[0]["prev_hash"].as_str().unwrap(),
            GOLDEN_GENESIS,
            "genesis-rewrite must surface as prev_hash divergence from golden genesis"
        );
        assert_eq!(
            events[0]["prev_hash"].as_str().unwrap(),
            forged,
            "tampered prev_hash value is observable as the rewritten content"
        );

        // Signal 2: recorded entry_hash stays at golden (only prev_hash bytes
        // were touched), but recomputing entry_hash over the post-tamper
        // payload diverges from golden — same end-to-end signal as
        // chain_tamper_detected above, applied to the genesis event.
        assert_eq!(
            events[0]["entry_hash"].as_str().unwrap(),
            GOLDEN_ENTRY_HASHES_V2[0],
            "attacker only flipped prev_hash bytes; entry_hash byte sequence unchanged"
        );
        let parsed_seq0: AuditEvent = serde_json::from_value(events[0].clone()).unwrap();
        let recomputed_seq0 = compute_entry_hash(Some(&TEST_SECRET), &parsed_seq0)
            .expect_hash("chain_tamper_genesis_rewrite_detected: seq=0 is a real v2 entry");
        assert_ne!(
            recomputed_seq0, GOLDEN_ENTRY_HASHES_V2[0],
            "recomputed entry_hash over tampered (prev_hash-rewritten) genesis payload \
             diverges from golden — this is the genesis-rewrite tamper signal"
        );

        // End-to-end detector check (Codex Round 1 P0): see
        // `chain_tamper_reorder_detected` for the rationale on pinning
        // `verify_chain` in addition to the raw on-disk signal.
        let verify_result = verify::verify_chain(&verify_config(&dir))
            .expect("verify_chain must run on a non-symlink test dir");
        assert!(
            verify_result.broken_at.is_some(),
            "verify_chain must report broken_at = Some(_) after genesis-rewrite; got None"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // --- create_event ---

    #[test]
    fn create_event_hides_argument_values() {
        let dir = test_dir("event-hide-args");
        let logger = test_logger(&dir);
        let invocation = CommandInvocation::new(
            "rm".to_string(),
            vec!["-rf".to_string(), "/secret/dir".to_string()],
        );
        let rule = RuleConfig {
            name: "rm-recursive".to_string(),
            command: "rm".to_string(),
            action: ActionKind::Trash,
            match_all: vec![],
            match_any: vec![],
            message: None,
            enabled: true,
            destination: None,
            subcommand: None,
            is_builtin: false,
        };
        let outcome = ActionOutcome::Blocked {
            message: "blocked".to_string(),
        };
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string()],
            &outcome,
            None,
        );

        // target_hash should be present but target args should not appear in the event
        assert!(event.target_hash.starts_with("hmac-sha256:"));
        assert_eq!(event.command, "rm");
        // The actual paths are NOT stored — only their HMAC
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("/secret/dir"),
            "target paths should not appear in event JSON"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_all_fields() {
        let dir = test_dir("event-all-fields");
        let logger = test_logger(&dir);
        let invocation = CommandInvocation::new(
            "git".to_string(),
            vec!["push".to_string(), "--force".to_string()],
        );
        let rule = RuleConfig {
            name: "git-push-force".to_string(),
            command: "git".to_string(),
            action: ActionKind::Block,
            match_all: vec![],
            match_any: vec!["push.*--force".to_string()],
            message: Some("blocked push --force".to_string()),
            enabled: true,
            destination: None,
            subcommand: None,
            is_builtin: false,
        };
        let outcome = ActionOutcome::Blocked {
            message: "blocked push --force".to_string(),
        };
        let event = logger.create_event(
            &invocation,
            Some(&rule),
            &["claude-code".to_string(), "cursor".to_string()],
            &outcome,
            None,
        );

        assert_eq!(event.provider, "claude-code"); // first detector
        assert_eq!(event.command, "git");
        assert_eq!(event.rule_id.as_deref(), Some("git-push-force"));
        assert_eq!(event.action, "block");
        assert_eq!(event.result, "block");
        assert_eq!(event.target_count, 1); // "push" (--force is filtered as flag)
        assert!(event.target_hash.starts_with("hmac-sha256:"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_event_without_secret() {
        let dir = test_dir("event-no-secret");
        let logger = AuditLogger {
            path: dir.join("audit.jsonl"),
            signing_key: SigningKey::for_test("default", None),
            retention_days: 0,
        };
        let invocation = CommandInvocation::new("ls".to_string(), vec![]);
        let outcome = ActionOutcome::PassedThrough { exit_code: 0 };
        let event = logger.create_event(&invocation, None, &[], &outcome, None);

        assert_eq!(event.target_hash, "NO_HMAC_SECRET");

        let _ = fs::remove_dir_all(&dir);
    }

    // --- HMAC ---

    #[test]
    fn hmac_targets_deterministic() {
        let targets = &["a", "b"];
        let h1 = hmac_targets(Some(&TEST_SECRET), targets);
        let h2 = hmac_targets(Some(&TEST_SECRET), targets);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hmac_targets_different_secrets() {
        let other = [0x99u8; 32];
        let targets = &["a"];
        assert_ne!(
            hmac_targets(Some(&TEST_SECRET), targets),
            hmac_targets(Some(&other), targets)
        );
    }

    #[test]
    fn hmac_targets_no_secret() {
        assert_eq!(hmac_targets(None, &["a"]), "NO_HMAC_SECRET");
    }

    // --- Secret management ---

    #[test]
    fn secret_roundtrip() {
        let dir = test_dir("secret-roundtrip");
        let path = dir.join("audit-secret");
        let secret = create_secret(&path).unwrap();
        let loaded = read_secret(&path).unwrap();
        assert_eq!(secret, loaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("secret-perms");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_create_new_prevents_overwrite() {
        let dir = test_dir("secret-overwrite");
        let path = dir.join("audit-secret");
        create_secret(&path).unwrap();
        assert!(create_secret(&path).is_err(), "should not overwrite");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_creates_when_missing() {
        let dir = test_dir("secret-create");
        let path = dir.join("audit-secret");
        let secret = load_or_create_secret(&path);
        assert!(secret.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_secret_reads_existing() {
        let dir = test_dir("secret-read");
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
        assert!(decode_hex_secret(&"zz".repeat(32)).is_err());
    }

    // --- JSONL special chars ---

    #[test]
    fn jsonl_special_chars() {
        let dir = test_dir("jsonl-special");
        let logger = test_logger(&dir);

        // Create events with special characters
        let mut event = make_event("echo");
        event.command = "echo \"hello\nworld\"".to_string();
        logger.append(event).unwrap();

        let mut event2 = make_event("echo");
        event2.command = "echo 'café'".to_string();
        logger.append(event2).unwrap();

        // Read back — each event should be on its own line
        let content = fs::read_to_string(&logger.path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "should be 2 JSONL lines");

        // Both should parse as valid JSON
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_path_derives_from_audit_path() {
        let audit = PathBuf::from("/tmp/omamori/audit.jsonl");
        let secret = secret_path_for(&audit);
        assert_eq!(secret, PathBuf::from("/tmp/omamori/audit-secret"));
    }

    // --- append IO error ---

    #[test]
    fn append_io_error() {
        let logger = AuditLogger {
            path: PathBuf::from("/nonexistent/dir/audit.jsonl"),
            signing_key: SigningKey::for_test("default", Some(TEST_SECRET)),
            retention_days: 0,
        };
        assert!(logger.append(make_event("ls")).is_err());
    }

    // --- verify_chain ---

    fn verify_config(dir: &Path) -> AuditConfig {
        AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        }
    }

    /// Hand-crafts and appends a single JSON line with the given
    /// `chain_version`/`command`/`action`/`result`, simulating an entry
    /// written by a possibly-future, possibly-corrupt omamori version.
    /// `entry_hash`/`prev_hash`/`target_hash` content is deliberately
    /// arbitrary: for any `chain_version` != `CHAIN_VERSION`, the
    /// verifier's version dispatch (`RecomputedHash::UnsupportedVersion`)
    /// fires *before* it ever reads those fields, so their exact values
    /// are inert. `seq: None` omits the `seq` key entirely, simulating a
    /// shape the current binary can't extract a seq from.
    fn append_chain_version_line(
        path: &Path,
        chain_version: u32,
        seq: Option<u64>,
        command: &str,
        action: &str,
        result: &str,
    ) {
        let mut event = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": command,
            "action": action,
            "result": result,
            "target_count": 0,
            "target_hash": "irrelevant",
            "chain_version": chain_version,
            "prev_hash": "irrelevant",
            "key_id": "default",
            "entry_hash": "irrelevant",
        });
        if let Some(seq) = seq {
            event["seq"] = serde_json::json!(seq);
        }
        let mut content = fs::read_to_string(path).unwrap_or_default();
        content.push_str(&serde_json::to_string(&event).unwrap());
        content.push('\n');
        fs::write(path, content).unwrap();
    }

    /// Convenience wrapper for the common case: a future entry
    /// (`chain_version: 999`) with an ordinary (non-prune) command shape
    /// and `seq` present.
    fn append_unknown_version_line(path: &Path, seq: u64) {
        append_chain_version_line(
            path,
            999,
            Some(seq),
            "future-cmd",
            "passthrough",
            "passthrough",
        );
    }

    /// #456: a tail on a *supported* `chain_version` whose `seq` leaves no
    /// successor. The version is the current one on purpose — the refusal
    /// under test is about the number, not the format.
    ///
    /// Note what `append_chain_version_line` writes for `entry_hash`:
    /// `"irrelevant"`. That is the premise of #456 rather than a shortcut in
    /// the fixture — `read_chain_state` only checks that the field is a
    /// non-empty string, so planting this tail needs no HMAC key.
    fn append_seq_at_limit_line(path: &Path) {
        append_chain_version_line(
            path,
            CHAIN_VERSION,
            Some(u64::MAX),
            "planted-cmd",
            "passthrough",
            "passthrough",
        );
    }

    #[test]
    fn verify_clean_chain() {
        let dir = test_dir("verify-clean");
        let logger = test_logger(&dir);
        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 5);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_tampered_chain() {
        let dir = test_dir("verify-tampered");
        let logger = test_logger(&dir);
        for i in 0..5 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // Tamper with second entry
        let content = fs::read_to_string(&logger.path).unwrap();
        let tampered = content.replacen("cmd2", "HACKED", 1);
        fs::write(&logger.path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- #177 B1 step 2: forward-unknown chain_version handling ---

    #[test]
    fn verify_unknown_chain_version_reports_unverifiable_not_broken() {
        let dir = test_dir("verify-unknown-version");
        let logger = test_logger(&dir);
        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        append_unknown_version_line(&logger.path, 3);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_none(),
            "an unrecognized chain_version is not tamper evidence"
        );
        assert_eq!(result.unknown_version_at, Some(3));
        assert_eq!(result.unknown_chain_version, Some(999));
        assert_eq!(result.chain_entries, 3);
        assert_eq!(result.unverified_entries_after, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex Round 1 (#177 B1): a future chain_version might pair with a
    /// JSON shape this binary's AuditEvent can't deserialize at all — the
    /// original implementation fell through to "torn line" handling for
    /// this case, which resumes verification against the pre-entry
    /// expected_prev/expected_seq for whatever comes next (risking a false
    /// broken_at on a real subsequent entry chaining from this one's
    /// unverified hash).
    #[test]
    fn verify_unknown_chain_version_with_incompatible_shape_still_reports_unverifiable() {
        let dir = test_dir("verify-unknown-version-bad-shape");
        let logger = test_logger(&dir);
        for i in 0..2 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        // Missing every field AuditEvent requires (timestamp/provider/
        // command/action/result/target_count/target_hash) except
        // chain_version/seq — simulating a future entry shape this binary
        // genuinely cannot parse.
        let malformed_future = serde_json::json!({
            "chain_version": 999,
            "seq": 2,
            "some_future_field": "whatever a v999 entry looks like"
        });
        let mut content = fs::read_to_string(&logger.path).unwrap();
        content.push_str(&serde_json::to_string(&malformed_future).unwrap());
        content.push('\n');
        fs::write(&logger.path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.torn_lines, 0,
            "an unrecognized-version entry must not be miscounted as a torn line, \
             even when its shape can't be deserialized as AuditEvent"
        );
        assert_eq!(result.unknown_version_at, Some(2));
        assert_eq!(result.unknown_chain_version, Some(999));
        assert_eq!(result.chain_entries, 2);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex Round 1 test-adversarial review: a *parsed* (AuditEvent-shape-
    /// compatible) unknown-version entry with no `seq` field previously
    /// reported `unknown_version_at = Some(0)` (the generic `seq` default),
    /// misleadingly pointing at entry #0 regardless of how deep in the
    /// chain it actually appeared. Must report `expected_seq` instead,
    /// matching the raw-JSON fallback path's behavior.
    #[test]
    fn verify_unknown_chain_version_missing_seq_reports_expected_seq() {
        let dir = test_dir("verify-unknown-version-missing-seq");
        let logger = test_logger(&dir);
        for i in 0..2 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        // Fully AuditEvent-parseable (all required fields present) but no
        // `seq` — chain_version alone must still trigger the dispatch.
        append_chain_version_line(&logger.path, 999, None, "future-cmd", "block", "blocked");

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.unknown_version_at,
            Some(2),
            "must report expected_seq (2 real entries verified so far), not 0"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex Round 1 test-adversarial review: `chain_version: 0` must not
    /// be silently accepted as "current" (a `>` vs `!=` mutation on the
    /// version comparison would let this slip through, since 0 < 1 rather
    /// than > 1) nor confused with a legacy entry (chain_version present,
    /// just not a value this binary hashes).
    #[test]
    fn verify_chain_version_zero_is_unverifiable_not_current() {
        let dir = test_dir("verify-chain-version-zero");
        let logger = test_logger(&dir);
        logger.append(make_event("cmd0")).unwrap();

        append_chain_version_line(&logger.path, 0, Some(1), "future-cmd", "block", "blocked");

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.unknown_chain_version,
            Some(0),
            "chain_version: 0 must be treated as an unsupported version, not silently \
             accepted as current or folded into legacy handling"
        );
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex Round 1 test-adversarial review: an entry that looks like a
    /// prune point (`command`/`action`/`result` match `is_prune_point`)
    /// but declares an unsupported `chain_version` must be treated as
    /// unverifiable, not specially recognized as a real prune point —
    /// version dispatch must win regardless of what the entry's other
    /// fields claim to be.
    #[test]
    fn verify_unknown_version_prune_shaped_entry_is_unverifiable_not_pruned() {
        let dir = test_dir("verify-unknown-version-prune-shaped");
        let logger = test_logger(&dir);
        for i in 0..2 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        append_chain_version_line(&logger.path, 999, Some(2), "_prune", "retention", "pruned");

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.unknown_version_at, Some(2));
        assert!(
            !result.pruned,
            "a prune-shaped entry with an unsupported chain_version must not be \
             recognized as a real prune point"
        );
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_unknown_chain_version_distrusts_everything_after_it() {
        let dir = test_dir("verify-unknown-version-tail");
        let logger = test_logger(&dir);
        for i in 0..2 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }
        append_unknown_version_line(&logger.path, 2);
        // Two more lines after the unknown-version entry, shaped like
        // ordinary v1 chain entries. Even though they claim chain_version
        // 1, nothing after an unauthenticated entry is trustworthy — the
        // prev_hash chain running through it can't be validated — so these
        // must be tallied as unverified, not silently re-admitted as
        // verified chain_entries.
        let mut content = fs::read_to_string(&logger.path).unwrap();
        for seq in 3..5u64 {
            let fake_v1 = serde_json::json!({
                "timestamp": "2026-01-01T00:00:00Z",
                "provider": "test",
                "command": "later-cmd",
                "action": "passthrough",
                "result": "passthrough",
                "target_count": 0,
                "target_hash": "irrelevant",
                "chain_version": 1,
                "seq": seq,
                "prev_hash": "irrelevant",
                "key_id": "default",
                "entry_hash": "irrelevant",
            });
            content.push_str(&serde_json::to_string(&fake_v1).unwrap());
            content.push('\n');
        }
        fs::write(&logger.path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.chain_entries, 2,
            "entries after the unknown version must not be counted as verified"
        );
        assert_eq!(
            result.unverified_entries_after, 3,
            "the unknown-version entry itself plus the 2 fake-v1 lines after it"
        );
        // #177 B3 (Codex Phase 6-B): the 2 entries before the cutoff were
        // written by logger.append() — the current writer, chain_version 2
        // — and must be the only ones counted. The 2 fake-v1 lines after
        // unknown_version_at claim chain_version 1 but were never verified
        // (VerifyResult's own doc comment: entries at or after
        // unknown_version_at are excluded from v1_entries/v2_entries,
        // since counting them would assert a version for unverified data).
        assert_eq!(result.v1_entries, 0);
        assert_eq!(result.v2_entries, 2);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_unknown_chain_version_does_not_bootstrap_hwm() {
        // #177 B1 step 2 / plan risk V-B50-equivalent: bootstrapping the
        // HWM off an early stop at unknown_version_at would permanently
        // cap future truncation detection below the chain's true length —
        // a poison-pill unknown-version entry could mask deletion of
        // everything after it. The HWM must only ever be touched when
        // verification actually reached EOF.
        //
        // Entries are written via `write_chain_entries` (direct disk
        // write), not `logger.append()` — `append()` bootstraps its own
        // HWM as a side effect of every call, which would make this the
        // *second* time the HWM is set and mask the bug this test exists
        // to catch. This models a freshly-arrived audit.jsonl being
        // verified for the very first time (`HwmState::Missing`).
        let dir = test_dir("verify-unknown-version-hwm-guard");
        let _ = test_logger(&dir); // secret file only
        let path = dir.join("audit.jsonl");
        write_chain_entries(
            &path,
            &TEST_SECRET,
            &[
                ("cmd0", "2026-01-01T00:00:00Z"),
                ("cmd1", "2026-01-01T00:00:01Z"),
                ("cmd2", "2026-01-01T00:00:02Z"),
            ],
            1,
        );
        append_unknown_version_line(&path, 3);

        assert!(
            matches!(read_hwm(&hwm_path_for(&path)), HwmState::Missing),
            "sanity: HWM must be Missing before the first-ever verify"
        );

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.unknown_version_at, Some(3));
        assert!(
            !result.tail_truncated,
            "must not compare against an HWM bootstrap that never happened"
        );
        // #470 reversed this assertion, deliberately. It used to read
        // `!result.hwm_missing`, on the reasoning that the guard "skips the
        // bootstrap entirely — it must not run it and then discard the result".
        // The bootstrap is still skipped, which is what the file assertion
        // below pins; what changed is that the *absence of a mark* is now
        // reported rather than swallowed. An operator reading exit 4 needs to
        // know that truncation was not merely un-detected but uncheckable —
        // there was nothing to compare against — because otherwise a halted
        // run that stays silent about the tail is indistinguishable from one
        // that checked it and found it whole.
        assert!(
            result.hwm_missing,
            "the missing mark must be reported even though it is not created"
        );

        assert!(
            matches!(read_hwm(&hwm_path_for(&path)), HwmState::Missing),
            "HWM must remain Missing — bootstrapping it off an early stop would permanently \
             cap future truncation detection below the chain's true (unknown) length"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // #470: a halt stops authentication. It must not take the tail-truncation
    // comparison down with it — that comparison needs no key.
    // -----------------------------------------------------------------------

    /// Rewrites the `key_id` of the line at `index` to an epoch this store has
    /// no key file for. This is the whole of #470's first step: `key_id` is an
    /// ordinary field of the log, so planting it needs no key and leaves every
    /// hash on the line byte-for-byte intact.
    fn plant_unresolvable_key_id(path: &Path, index: usize) {
        let content = fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let mut event: serde_json::Value = serde_json::from_str(&lines[index]).unwrap();
        event["key_id"] = serde_json::Value::String("key-7".to_string());
        lines[index] = serde_json::to_string(&event).unwrap();
        fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    /// Drops the last `n` lines — #470's second step.
    fn remove_tail_lines(path: &Path, n: usize) {
        let content = fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let kept = &lines[..lines.len() - n];
        fs::write(path, format!("{}\n", kept.join("\n"))).unwrap();
    }

    /// Where the halt sits relative to the file that is finally verified.
    #[derive(Clone, Copy, Debug)]
    enum HaltAt {
        Head,
        Middle,
        Tail,
    }

    /// Six genuine entries (seq 0..=5), a mark at the real end, optionally the
    /// last two lines removed, and one surviving line's `key_id` made
    /// unresolvable. Deleting before planting rather than after is the same
    /// file either way — the index is computed against what remains, so the
    /// planted line always survives.
    fn halted_store(name: &str, halt_at: HaltAt, delete_tail: bool) -> PathBuf {
        let dir = test_dir(name);
        let _ = test_logger(&dir); // secret file only
        let path = dir.join("audit.jsonl");
        write_chain_entries(
            &path,
            &TEST_SECRET,
            &[
                ("cmd0", "2026-01-01T00:00:00Z"),
                ("cmd1", "2026-01-01T00:00:01Z"),
                ("cmd2", "2026-01-01T00:00:02Z"),
                ("cmd3", "2026-01-01T00:00:03Z"),
                ("cmd4", "2026-01-01T00:00:04Z"),
                ("cmd5", "2026-01-01T00:00:05Z"),
            ],
            CHAIN_VERSION,
        );
        // The mark an honest run of appends would have left behind.
        write_hwm(&hwm_path_for(&path), 5).unwrap();
        if delete_tail {
            remove_tail_lines(&path, 2);
        }
        let surviving = if delete_tail { 4 } else { 6 };
        let index = match halt_at {
            HaltAt::Head => 0,
            HaltAt::Middle => 2,
            HaltAt::Tail => surviving - 1,
        };
        plant_unresolvable_key_id(&path, index);
        dir
    }

    /// C-1: the grid. Six cells — halt at the head, the middle and the tail,
    /// each with and without a deleted tail.
    ///
    /// Both halves are load-bearing and neither alone would do. The three
    /// *deleted* cells are what the fix buys: on `73b76a7` all six report
    /// nothing, so those three are the regression. The three *undeleted* cells
    /// rule out the implementation that passes the first three for the wrong
    /// reason — comparing against `last_verified_seq`, which stops at the halt
    /// and is therefore behind the mark whenever the halt is not at the very
    /// end. That is not a hypothetical: it is what #470's own text proposes.
    ///
    /// `key_unavailable_at` is asserted in every cell because without it the
    /// deleted cells pass whether or not the planting worked — a store that
    /// never halted also has a chain shorter than its mark.
    #[test]
    fn verify_reports_a_removed_tail_even_when_a_halt_stopped_authentication() {
        for (halt_at, deleted, expect_truncated) in [
            (HaltAt::Head, false, false),
            (HaltAt::Head, true, true),
            (HaltAt::Middle, false, false),
            (HaltAt::Middle, true, true),
            (HaltAt::Tail, false, false),
            (HaltAt::Tail, true, true),
        ] {
            let name = format!("verify-470-{halt_at:?}-{deleted}").to_lowercase();
            let dir = halted_store(&name, halt_at, deleted);
            let result = verify_chain(&verify_config(&dir)).unwrap();

            assert!(
                result.key_unavailable_at.is_some(),
                "{halt_at:?}/deleted={deleted}: the planted key_id must actually halt \
                 verification, or this cell proves nothing"
            );
            assert!(
                result.broken_at.is_none(),
                "{halt_at:?}/deleted={deleted}: an unresolvable key_id is not a broken chain"
            );
            assert_eq!(
                result.tail_truncated, expect_truncated,
                "{halt_at:?}/deleted={deleted}: expected tail_truncated={expect_truncated}"
            );
            assert_eq!(
                expect_hwm(&hwm_path_for(&dir.join("audit.jsonl"))),
                5,
                "{halt_at:?}/deleted={deleted}: a halted run may read the mark but never \
                 move it"
            );

            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// C-1, third surface: the same store has to produce the same verdict
    /// through `aggregate_report`, which is also what `doctor` renders. A fix
    /// applied to the CLI's exit branch alone would leave `--json` consumers
    /// reading `key_unavailable` for a store whose tail is gone.
    #[test]
    fn report_prefers_truncated_over_the_halt_that_was_planted_to_hide_it() {
        let dir = halted_store("report-470-truncated", HaltAt::Middle, true);
        let report = aggregate_report(&verify_config(&dir), 30);
        assert_eq!(
            report.chain_status,
            report::ChainStatus::Truncated,
            "the removed tail outranks the halt that was planted to conceal it"
        );

        let _ = fs::remove_dir_all(&dir);

        // Control: without the deletion the same store must still report the
        // halt. Hoisting `Truncated` above the halted arms must not turn into
        // "report Truncated whenever a halt happened".
        let intact = halted_store("report-470-halt-only", HaltAt::Middle, false);
        let report = aggregate_report(&verify_config(&intact), 30);
        assert!(
            matches!(
                report.chain_status,
                report::ChainStatus::KeyUnavailable { .. }
            ),
            "nothing was removed — the verdict is still the unresolvable key, got {:?}",
            report.chain_status
        );

        let _ = fs::remove_dir_all(&intact);
    }

    /// C-2: a halted run reads the mark's *state* and reports it, and writes
    /// nothing. Both halves are required — reporting without the second half
    /// would be #177 B1's silent-lowering bug back again, and the second half
    /// without the first is the suppression #470 is about.
    #[test]
    fn a_halted_run_reports_a_tampered_mark_without_resetting_it() {
        let dir = halted_store("verify-470-hwm-tampered", HaltAt::Middle, false);
        let hwm_file = hwm_path_for(&dir.join("audit.jsonl"));
        fs::write(&hwm_file, "not-a-number").unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.key_unavailable_at.is_some(), "sanity: it halted");
        assert!(
            result.hwm_tampered,
            "an unreadable sidecar is a fact about the sidecar — a halt in the log does \
             not make it unknowable"
        );
        assert!(
            !result.tail_truncated,
            "a Tampered mark yields no comparison at all, so nothing may be claimed \
             about the tail"
        );
        assert_eq!(
            fs::read_to_string(&hwm_file).unwrap(),
            "not-a-number",
            "the re-bootstrap must stay withheld: this run could not authenticate the \
             chain end, so it has no value it is entitled to write"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #470, Codex R1 P1 — **the fallback position is not an end.**
    ///
    /// `mark_*` reports a halting line that states no `seq` at the position it
    /// *should* have occupied, which is one past the last verified entry. A
    /// first draft fed that number into the comparison, and it is behind the
    /// mark for every halt that is not at the very end of the file — so a log
    /// written by a future omamori that renamed or dropped `seq` would be
    /// reported as truncated with nothing removed. That is the "compare against
    /// a false end" failure the pre-#470 `!halted()` gate existed to prevent,
    /// re-entering by a different door.
    ///
    /// Nothing at or after the halt states a `seq` here, so there is no end to
    /// compare and the comparison is skipped.
    #[test]
    fn a_halt_that_states_no_seq_yields_no_end_to_compare() {
        let dir = test_dir("verify-470-no-stated-seq");
        let _ = test_logger(&dir);
        let path = dir.join("audit.jsonl");
        write_chain_entries(
            &path,
            &TEST_SECRET,
            &[
                ("cmd0", "2026-01-01T00:00:00Z"),
                ("cmd1", "2026-01-01T00:00:01Z"),
            ],
            CHAIN_VERSION,
        );
        // Four entries from a format this build cannot read, none stating a
        // `seq`. The mark is where six honest appends would have left it.
        for _ in 0..4 {
            append_chain_version_line(&path, 999, None, "future-cmd", "passthrough", "passthrough");
        }
        write_hwm(&hwm_path_for(&path), 5).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.unknown_version_at.is_some(), "sanity: it halted");
        assert!(
            !result.tail_truncated,
            "no line at or after the halt states a seq, so the file's end is unknown — \
             reporting truncation here accuses a log nothing was removed from"
        );
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            5,
            "and the mark is still not written from a halted run"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #470, Codex R1 P1 — **the last stated `seq`, not the largest.**
    ///
    /// A max lets any single planted line stand in for the file's end, so
    /// concealing a deletion would cost an insertion in the middle rather than
    /// a rewrite of the surviving tail — weaker than what SECURITY.md claims.
    /// Here the largest surviving `seq` reaches the mark and the last one does
    /// not, which is exactly the gap between the two rules.
    #[test]
    fn the_end_is_the_last_stated_seq_not_the_largest() {
        let dir = test_dir("verify-470-last-not-max");
        let _ = test_logger(&dir);
        let path = dir.join("audit.jsonl");
        write_chain_entries(
            &path,
            &TEST_SECRET,
            &[
                ("cmd0", "2026-01-01T00:00:00Z"),
                ("cmd1", "2026-01-01T00:00:01Z"),
                ("cmd2", "2026-01-01T00:00:02Z"),
            ],
            CHAIN_VERSION,
        );
        write_hwm(&hwm_path_for(&path), 5).unwrap();
        plant_unresolvable_key_id(&path, 2);
        // Past the halt: one line claiming the mark's own number, then the
        // file's real last lines, below it.
        for seq in [5u64, 3, 4] {
            append_chain_version_line(
                &path,
                999,
                Some(seq),
                "future-cmd",
                "passthrough",
                "passthrough",
            );
        }

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.key_unavailable_at.is_some(), "sanity: it halted");
        assert!(
            result.tail_truncated,
            "the file ends on a line stating seq 4, below the mark of 5 — a planted 5 \
             earlier in the remainder must not answer for the end"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The `broken_at` gate is deliberately kept. A broken chain `break`s out
    /// of the loop, so the structural end sits at the break rather than at the
    /// end of file — and exit 1 is already the strongest thing this command
    /// says. Pinned because "let the comparison through a halt" reads like it
    /// should apply here too.
    #[test]
    fn a_broken_chain_still_suppresses_the_truncation_comparison() {
        let dir = test_dir("verify-470-broken-plus-tail");
        let _ = test_logger(&dir);
        let path = dir.join("audit.jsonl");
        write_chain_entries(
            &path,
            &TEST_SECRET,
            &[
                ("cmd0", "2026-01-01T00:00:00Z"),
                ("cmd1", "2026-01-01T00:00:01Z"),
                ("cmd2", "2026-01-01T00:00:02Z"),
                ("cmd3", "2026-01-01T00:00:03Z"),
            ],
            CHAIN_VERSION,
        );
        write_hwm(&hwm_path_for(&path), 3).unwrap();

        // Edit an entry's payload without recomputing its hash, then remove the
        // tail: both findings are available, and exit 1 must win.
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let mut event: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        event["command"] = serde_json::Value::String("tampered".to_string());
        lines[1] = serde_json::to_string(&event).unwrap();
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        remove_tail_lines(&path, 1);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at,
            Some(1),
            "the edited payload must break the chain"
        );
        assert!(
            !result.tail_truncated,
            "broken_at keeps its own gate — the loop broke early, so the end it would \
             compare is the break, not the end of the file"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #456: the high-water-mark reported after verification is the seq that
    /// was verified, not one derived from "the seq expected next". The
    /// derivation (`expected_seq - 1`) is short by one at the top of the range,
    /// and a mark one short is *behind* the chain — which is exactly the shape
    /// `tail_truncated` looks for. The mark here is what an append would have
    /// left, so the file and the mark agree and nothing was removed.
    #[test]
    fn verify_does_not_report_truncation_when_the_chain_ends_at_the_seq_limit() {
        let dir = test_dir("verify-seq-limit-no-false-truncation");
        let _ = test_logger(&dir); // secret file only
        let path = dir.join("audit.jsonl");
        write_chain_entries_at_seqs(
            &path,
            &TEST_SECRET,
            &[(u64::MAX, "cmd-at-limit", "2026-01-01T00:00:00Z")],
            CHAIN_VERSION,
        );
        write_hwm(&hwm_path_for(&path), u64::MAX).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_none(),
            "the entry is authentic and anchors to genesis — nothing is broken"
        );
        assert_eq!(result.chain_entries, 1);
        assert!(
            !result.tail_truncated,
            "the chain verified up to u64::MAX and the mark is u64::MAX, so the mark is not \
             ahead of the chain — reporting truncation here is a false accusation about a \
             file nothing was removed from"
        );
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            u64::MAX,
            "an unchanged mark must stay unchanged"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Companion to the test above, for the bootstrap arm: the first verify of
    /// a chain that has no mark yet must write the seq it verified. Writing one
    /// less would plant the false-truncation state rather than merely report
    /// it, and it would persist.
    #[test]
    fn verify_bootstraps_the_mark_to_the_seq_it_verified_at_the_limit() {
        let dir = test_dir("verify-seq-limit-bootstrap");
        let _ = test_logger(&dir);
        let path = dir.join("audit.jsonl");
        write_chain_entries_at_seqs(
            &path,
            &TEST_SECRET,
            &[(u64::MAX, "cmd-at-limit", "2026-01-01T00:00:00Z")],
            CHAIN_VERSION,
        );
        assert!(
            matches!(read_hwm(&hwm_path_for(&path)), HwmState::Missing),
            "sanity: no mark before the first verify"
        );

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.hwm_missing, "the bootstrap arm must have run");
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            u64::MAX,
            "the bootstrapped mark must be the verified seq"
        );

        // The persistence is the point: a mark one short makes the *next*
        // verify of an unchanged file report a truncated tail.
        let again = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            !again.tail_truncated,
            "re-verifying an unchanged file must not report truncation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #456: nothing can legitimately follow an entry numbered `u64::MAX`, and
    /// the verifier says so. This is the case a saturating advance would have
    /// admitted — `expected_seq` would have stayed at `u64::MAX`, so a second
    /// entry carrying the same number satisfies the equality check. Both
    /// entries here are genuinely signed, so nothing but the seq continuity is
    /// available to reject the second one.
    #[test]
    fn verify_rejects_a_second_entry_numbered_at_the_seq_limit() {
        let dir = test_dir("verify-seq-limit-no-successor");
        let _ = test_logger(&dir);
        let path = dir.join("audit.jsonl");
        write_chain_entries_at_seqs(
            &path,
            &TEST_SECRET,
            &[
                (u64::MAX, "cmd-at-limit", "2026-01-01T00:00:00Z"),
                (u64::MAX, "cmd-after-limit", "2026-01-01T00:00:01Z"),
            ],
            CHAIN_VERSION,
        );

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at,
            Some(u64::MAX),
            "the second entry has no valid position, so the chain breaks at it"
        );
        assert_eq!(
            result.chain_entries, 1,
            "only the head counts as verified — the break stops the scan"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_chain_accepts_break_glass_expired_observed_action() {
        // #324: confirms the plan's "no CHAIN_VERSION bump needed" claim —
        // a new `action` string is just data to the HMAC chain, not part
        // of any schema chain verification depends on.
        let dir = test_dir("verify-expired-observed");
        let logger = test_logger(&dir);
        let mut event = make_event("break-glass (auto-pruned expired entry)");
        event.provider = "omamori".to_string();
        event.rule_id = Some("rm-recursive-to-trash".to_string());
        event.action = "break-glass-expired-observed".to_string();
        event.result = "expired (per state: active until 2020-01-01T01:00:00Z)".to_string();
        event.detection_layer = Some("break-glass".to_string());
        logger.append(event).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_then_chain() {
        let dir = test_dir("verify-legacy-chain");
        let logger = test_logger(&dir);

        // Write legacy entry
        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(&logger.path, serde_json::to_string(&legacy).unwrap() + "\n").unwrap();

        logger.append(make_event("new")).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.legacy_entries, 1);
        assert_eq!(result.chain_entries, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// #177 B1 step 4: a legacy-shaped (no chain_version) entry appearing
    /// AFTER real chain entries have started must fail-close (broken_at),
    /// not silently count as benign pre-#164 history. Legacy entries never
    /// participate in prev_hash/seq continuity tracking, so without this
    /// check an attacker could splice unaudited content into the middle of
    /// an otherwise-verified chain and have it counted as "legacy skipped"
    /// rather than flagged.
    #[test]
    fn verify_mid_chain_legacy_fails_closed() {
        let dir = test_dir("verify-mid-chain-legacy");
        let logger = test_logger(&dir);

        logger.append(make_event("cmd0")).unwrap();

        let injected_legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:01Z",
            "provider": "test",
            "command": "injected",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        let mut content = fs::read_to_string(&logger.path).unwrap();
        content.push_str(&serde_json::to_string(&injected_legacy).unwrap());
        content.push('\n');
        fs::write(&logger.path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "a legacy entry after a real chain entry must fail-close"
        );
        assert_eq!(
            result.chain_entries, 1,
            "the one real entry before the injected legacy line is still counted"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_only() {
        let dir = test_dir("verify-legacy-only");
        test_logger(&dir); // create secret

        let legacy = serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "provider": "test",
            "command": "old",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "legacy"
        });
        fs::write(
            dir.join("audit.jsonl"),
            serde_json::to_string(&legacy).unwrap() + "\n",
        )
        .unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.legacy_entries, 1);
        assert_eq!(result.chain_entries, 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_empty_file() {
        let dir = test_dir("verify-empty");
        test_logger(&dir);
        fs::write(dir.join("audit.jsonl"), "").unwrap();
        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 0);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_torn_line() {
        let dir = test_dir("verify-torn");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        // Append torn line
        let mut file = OpenOptions::new().append(true).open(&logger.path).unwrap();
        writeln!(file, r#"{{"broken"#).unwrap();
        drop(file);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(result.chain_entries, 1);
        assert_eq!(result.torn_lines, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_no_secret() {
        let dir = test_dir("verify-no-secret");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let result = verify_chain(&verify_config(&dir));
        assert!(matches!(result, Err(AuditError::SecretUnavailable)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_no_file() {
        let dir = test_dir("verify-no-file");
        test_logger(&dir); // create secret but no audit.jsonl

        let result = verify_chain(&verify_config(&dir));
        assert!(matches!(result, Err(AuditError::FileNotFound)));
        let _ = fs::remove_dir_all(&dir);
    }

    // --- show_entries ---

    #[test]
    fn show_last_n() {
        let dir = test_dir("show-last");
        let logger = test_logger(&dir);
        for i in 0..10 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let opts = ShowOptions {
            last: Some(3),
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        // 1 header + 3 data lines
        assert_eq!(
            lines.len(),
            4,
            "expected header + 3 entries, got:\n{output}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_filter_rule() {
        let dir = test_dir("show-filter-rule");
        let logger = test_logger(&dir);

        let mut e1 = make_event("rm");
        e1.rule_id = Some("rm-recursive".to_string());
        logger.append(e1).unwrap();

        let mut e2 = make_event("git");
        e2.rule_id = Some("git-push-force".to_string());
        logger.append(e2).unwrap();

        let mut e3 = make_event("rm");
        e3.rule_id = Some("rm-recursive".to_string());
        logger.append(e3).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: Some("rm".to_string()),
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let data_lines = output.lines().skip(1).count(); // skip header
        assert_eq!(data_lines, 2, "expected 2 rm entries");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_json_includes_chain_fields() {
        let dir = test_dir("show-json");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: true,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert!(
            parsed.get("entry_hash").is_some(),
            "json should include entry_hash"
        );
        assert!(
            parsed.get("chain_version").is_some(),
            "json should include chain_version"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// v0.9.7 #190 B-2 regression: column alignment must survive PR6
    /// `unknown_tool_fail_open` events without overflow. The pre-v0.9.7
    /// format `{:<8}` (COMMAND) / `{:<15}` (ACTION) overflowed when
    /// `tool_name` exceeded 8 chars or when `action == "unknown_tool_fail_open"`
    /// (22 chars). v0.9.7 widened to `{:<24}` / `{:<24}`. This test pins
    /// the byte position of every column boundary so a silent reversion to
    /// the legacy widths fails CI before it reaches an operator's
    /// `audit show` output.
    #[test]
    fn show_pr6_unknown_tool_fail_open_keeps_columns_aligned() {
        let dir = test_dir("show-pr6-alignment");
        let logger = test_logger(&dir);

        let mut event = make_event("FuturePlanWriter"); // 16-char tool_name (PR6)
        event.action = "unknown_tool_fail_open".to_string(); // 22-char label (PR6)
        event.result = "allow".to_string();
        event.detection_layer = Some("shape-routing".to_string());
        logger.append(event).unwrap();

        let opts = ShowOptions {
            last: Some(1),
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "header + 1 row, got:\n{output}");
        let header = lines[0];
        let row = lines[1];

        // Format string: "{:<20} {:<12} {:<24} {:<24} {:<8} RULE"
        // Column starts (in bytes): 0 / 21 / 34 / 59 / 84 / 93
        assert_eq!(header.find("TIMESTAMP"), Some(0));
        assert_eq!(header.find("PROVIDER"), Some(21));
        assert_eq!(header.find("COMMAND"), Some(34));
        assert_eq!(header.find("ACTION"), Some(59));
        assert_eq!(header.find("RESULT"), Some(84));
        assert_eq!(header.find("RULE"), Some(93));

        // Body row: 16-char tool_name fills bytes 34..50, then padding to 58.
        assert_eq!(&row[34..50], "FuturePlanWriter");
        // 22-char action label fills bytes 59..81, then padding to 83.
        assert_eq!(&row[59..81], "unknown_tool_fail_open");
        // RESULT column at byte 84 ("allow" = 5 chars, padded to 8).
        assert_eq!(&row[84..89], "allow");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_table_hides_hashes() {
        let dir = test_dir("show-hides");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("hmac-sha256:"),
            "table should not show hashes"
        );
        assert!(
            !output.contains("entry_hash"),
            "table should not show entry_hash"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_empty_file() {
        let dir = test_dir("show-empty");
        test_logger(&dir);
        fs::write(dir.join("audit.jsonl"), "").unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        assert!(buf.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- audit_summary ---

    #[test]
    fn summary_with_entries() {
        let dir = test_dir("summary");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("rm")).unwrap();

        let summary = audit_summary(&verify_config(&dir));
        assert!(summary.enabled);
        assert_eq!(summary.entry_count, 2);
        assert!(summary.secret_available);
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // #471 / #487: `ChainStatus::Unavailable` means "there is nothing to check
    // yet" and nothing else.
    // -----------------------------------------------------------------------

    /// The inventory, both halves.
    ///
    /// The loud half is the regression: on `23b882c` every one of these reached
    /// `doctor` as `Unavailable`, which `needs_attention()` calls healthy. The
    /// quiet half is what stops the fix being "make `Unavailable` loud" — that
    /// implementation passes every loud cell and turns a store with auditing
    /// switched off into a permanent warning. Neither half proves anything on
    /// its own.
    #[test]
    fn only_a_store_with_nothing_to_check_yet_stays_quiet() {
        use std::os::unix::fs::PermissionsExt;

        // (case, expect `needs_attention`, expect `as_str`, expect `kind`)
        //
        // `kind` is asserted per cell, not just `as_str`. Review caught that
        // the version without it — plus a separate test that checked one kind —
        // was satisfied by an implementation returning the same `kind` for
        // every fault, which is exactly what the `--json` contract must not do.
        for (case, expect_loud, expect_status, expect_kind) in [
            ("disabled", false, "unavailable", ""),
            ("no-log-yet", false, "unavailable", ""),
            ("never-written-no-key", false, "unavailable", ""),
            // The two the first draft of this change left quiet, both measured
            // on a release build before they were closed.
            (
                "log-deleted-after-writes",
                true,
                "inaccessible",
                "log_missing",
            ),
            (
                "key-deleted-after-writes",
                true,
                "inaccessible",
                "active_key_missing",
            ),
            ("secret-symlink", true, "inaccessible", "secret_symlink"),
            ("log-symlink", true, "inaccessible", "log_symlink"),
            (
                "rotation-interrupted",
                true,
                "inaccessible",
                "rotation_interrupted",
            ),
            (
                "secret-unreadable",
                true,
                "inaccessible",
                "secret_unreadable",
            ),
        ] {
            let dir = test_dir(&format!("chain-status-471-{case}"));
            let logger = test_logger(&dir);
            let secret_file = dir.join("audit-secret");
            let log = dir.join("audit.jsonl");
            // `never-written-no-key` must mean exactly that. The first draft
            // appended first and then removed the key, called it
            // "fresh-store-no-key", and pinned the resulting silence as
            // correct — a fixture whose name disagreed with its contents,
            // certifying the very hole review then found.
            if !matches!(case, "no-log-yet" | "never-written-no-key") {
                logger.append(make_event("seed")).unwrap();
            }

            match case {
                "never-written-no-key" => fs::remove_file(&secret_file).unwrap(),
                "log-deleted-after-writes" => fs::remove_file(&log).unwrap(),
                "key-deleted-after-writes" => fs::remove_file(&secret_file).unwrap(),
                "secret-symlink" => {
                    let real = dir.join("real-secret");
                    fs::rename(&secret_file, &real).unwrap();
                    std::os::unix::fs::symlink(&real, &secret_file).unwrap();
                }
                "log-symlink" => {
                    let real = dir.join("real-audit.jsonl");
                    fs::rename(&log, &real).unwrap();
                    std::os::unix::fs::symlink(&real, &log).unwrap();
                }
                "rotation-interrupted" => {
                    // The store this leaves: retired keys present, nothing at
                    // the active path. `rotate` has named it since #487's A/C
                    // half; the verifier had not.
                    fs::rename(&secret_file, dir.join("audit-secret.1.retired")).unwrap();
                }
                "secret-unreadable" => {
                    fs::write(&secret_file, "not-hex").unwrap();
                    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => {}
            }

            let mut config = verify_config(&dir);
            if case == "disabled" {
                config.enabled = false;
            }
            let report = aggregate_report(&config, 30);

            assert_eq!(
                report.chain_status.as_str(),
                expect_status,
                "{case}: chain_status (got {:?})",
                report.chain_status
            );
            assert_eq!(
                report.chain_status.needs_attention(),
                expect_loud,
                "{case}: needs_attention"
            );
            if !expect_kind.is_empty() {
                match &report.chain_status {
                    report::ChainStatus::Inaccessible { kind, .. } => {
                        assert_eq!(*kind, expect_kind, "{case}: kind")
                    }
                    other => panic!("{case}: expected Inaccessible, got {other:?}"),
                }
            }

            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// `reason` carries the data directory and must not reach the serialized
    /// form — the line this repo draws is "machine-readable output stays
    /// path-free". The grid above pins the `kind`s; this pins what travels
    /// beside them.
    #[test]
    fn an_inaccessible_reason_never_reaches_the_json() {
        let dir = test_dir("chain-status-471-kinds");
        let logger = test_logger(&dir);
        logger.append(make_event("seed")).unwrap();
        let real = dir.join("real-audit.jsonl");
        fs::rename(dir.join("audit.jsonl"), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("audit.jsonl")).unwrap();

        let report = aggregate_report(&verify_config(&dir), 30);
        match report.chain_status {
            report::ChainStatus::Inaccessible { kind, ref reason } => {
                assert_eq!(kind, "log_symlink");
                assert!(
                    reason.contains("possible attack"),
                    "a symlinked log is an attack shape, not a generic I/O error — got: {reason}"
                );
                assert!(
                    reason.contains(&dir.display().to_string()),
                    "precondition: the reason really does embed the store path"
                );
            }
            ref other => panic!("expected Inaccessible, got {other:?}"),
        }
        let json = serde_json::to_string(&report.chain_status).unwrap();
        assert!(
            !json.contains(&dir.display().to_string()),
            "the serialized form must stay path-free — got: {json}"
        );
        assert!(
            json.contains("log_symlink"),
            "and must still carry the kind a consumer branches on — got: {json}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #471 item 3: the chain can be `intact` while the keyring is damaged, so
    /// this travels beside `chain_status` rather than inside it — and it has to
    /// travel, because `verify` printed it and the two surfaces an operator
    /// watches habitually did not.
    #[test]
    fn a_damaged_retired_key_reaches_the_report_without_moving_chain_status() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("chain-status-471-keyring-warning");
        let _ = test_logger(&dir); // creates audit-secret
        // Retire that key and make it unreadable **before** anything is
        // written, so the epoch the entries name is the *next* one. This is the
        // issue's own scenario — a damaged retired key whose entries are
        // already gone — and getting it wrong is instructive: filing the damage
        // under `.1.retired` *after* seeding makes the seeded entry's own
        // `key_id: "default"` resolve to it (index 1 is the epoch `"default"`
        // names), so the chain legitimately reports `key_unavailable` and the
        // fixture proves the opposite of what it set out to.
        let retired = dir.join("audit-secret.1.retired");
        fs::rename(dir.join("audit-secret"), &retired).unwrap();
        fs::set_permissions(&retired, fs::Permissions::from_mode(0o000)).unwrap();

        let config = verify_config(&dir);
        let writer = AuditLogger::from_config(&config).expect("audit is enabled");
        writer.append(make_event("seed")).unwrap();

        let report = aggregate_report(&config, 30);
        let restored = fs::set_permissions(&retired, fs::Permissions::from_mode(0o600));

        assert!(
            !report.keyring_warnings.is_empty(),
            "the damaged key must reach the report"
        );
        assert!(
            report.keyring_warnings[0].contains("audit-secret.1.retired"),
            "and must name the file — got: {:?}",
            report.keyring_warnings
        );
        assert_eq!(
            report.chain_status.as_str(),
            "intact",
            "the chain really is intact; saying otherwise would be its own false statement"
        );

        restored.unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// #471: `status`'s judgement and the writer's must be the same judgement.
    ///
    /// Comparing `secret_available` against a second copy of the same condition
    /// would pass on any implementation that keeps the two in step while both
    /// are wrong — which is the state this fixes. So each cell appends through
    /// the **real writer** (`AuditLogger::from_config`, so `load_signing_key`
    /// runs) and then asks what that entry actually carries.
    ///
    /// `0o300`, not `0o100`: write permission keeps `audit-secret.lock`
    /// creatable and the append itself possible, so the listing is the only
    /// thing that fails — the same reason the keyring fixtures in this module
    /// give. At `0o100` the append would fail too and there would be nothing
    /// left to inspect.
    #[test]
    fn summary_agrees_with_the_writer_about_whether_an_append_is_protected() {
        use crate::audit::chain::hmac_bytes;
        use std::os::unix::fs::PermissionsExt;

        // (case, expect `secret_available`, expect the entry to carry an HMAC)
        for (case, expect_available, expect_protected) in [
            ("healthy", true, true),
            // The regression: readable by name, unlistable as a directory. The
            // writer refuses; before #471 `status` said `[ok]`.
            ("unlistable", false, false),
            // Something is at the active path that cannot be read as a key, so
            // the mint cannot replace it either.
            ("bad-secret", false, false),
            // The one direction that is deliberately *not* symmetric: a store
            // with no active key yet warns, and the writer then mints one and
            // protects the entry. Pinned so the asymmetry is a recorded
            // decision rather than something rediscovered as a bug — the
            // guarantee is one-directional (`[ok]` implies protected), and
            // erring toward `[warn]` is the safe side of it.
            ("no-active-key", false, true),
        ] {
            let dir = test_dir(&format!("summary-471-{case}"));
            let logger = test_logger(&dir);
            logger.append(make_event("seed")).unwrap();
            let secret_file = dir.join("audit-secret");

            match case {
                "unlistable" => {
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();
                }
                "bad-secret" => fs::write(&secret_file, "not-hex").unwrap(),
                "no-active-key" => {
                    fs::rename(&secret_file, dir.join("audit-secret.moved")).unwrap()
                }
                _ => {}
            }

            let config = verify_config(&dir);
            let summary = audit_summary(&config);
            let writer = AuditLogger::from_config(&config).expect("audit is enabled");
            let _ = writer.append(make_event("probe"));

            let last = fs::read_to_string(dir.join("audit.jsonl"))
                .unwrap()
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .expect("the probe append must have produced a line")
                .to_string();
            let probe: serde_json::Value = serde_json::from_str(&last).unwrap();
            // Derived, not spelled out: `hmac_bytes` with no key *is* the
            // sentinel, so this cannot drift from what the writer stamps.
            let sentinel = hmac_bytes(None, b"whatever");
            let protected = probe["entry_hash"] != serde_json::json!(sentinel);

            // Restore before asserting: at 0o300 the directory cannot be
            // removed, so a failing assertion would leave it behind.
            let restored = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

            assert_eq!(
                summary.secret_available, expect_available,
                "{case}: secret_available"
            );
            // Scoped to this fixture: audit is enabled and the path resolves,
            // so a reason must exist whenever protection does not. The two
            // early returns in `audit_summary` report `false` with no reason
            // and are covered by their own tests.
            assert_eq!(
                summary.unprotected_reason.is_none(),
                summary.secret_available,
                "{case}: a reason must be present exactly when protection is not"
            );
            assert_eq!(
                protected, expect_protected,
                "{case}: the entry the writer actually produced (line: {last})"
            );
            if summary.secret_available {
                assert!(
                    protected,
                    "{case}: `[ok]` was printed for an entry with no HMAC — the direction \
                     this test exists to forbid"
                );
            }
            // The reason may not describe an outcome opposite to the one the
            // writer produced. A shared "entries are recorded without HMAC
            // protection" suffix did exactly that in the `no-active-key` cell,
            // where the append mints a key and the entry is protected — caught
            // by review and confirmed on a release build before this assertion
            // existed.
            if let Some(reason) = &summary.unprotected_reason
                && protected
            {
                assert!(
                    !reason.summary().contains("without HMAC protection"),
                    "{case}: the reason claims entries go unprotected, but the entry this \
                     writer just produced carries an HMAC — got: {}",
                    reason.summary()
                );
            }

            restored.unwrap();
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// The reason is the one the *writer* would give, not a phrase assembled at
    /// the display surface. `HMAC secret missing` was wrong at `0o300` in both
    /// halves: nothing is missing, and the cause is the directory.
    #[test]
    fn summary_names_the_unlistable_directory_rather_than_a_missing_secret() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("summary-471-reason");
        let logger = test_logger(&dir);
        logger.append(make_event("seed")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();

        let summary = audit_summary(&verify_config(&dir));
        let restored = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

        let reason = summary
            .unprotected_reason
            .expect("an unlistable key directory is not protected");
        assert!(
            matches!(reason, UnprotectedReason::KeyDirUnlistable(_)),
            "got {reason:?}"
        );
        assert!(
            !reason.summary().contains("missing"),
            "the key is present and readable here — got: {}",
            reason.summary()
        );
        assert!(
            reason.summary().contains("without HMAC protection"),
            "the consequence is what the operator needs — got: {}",
            reason.summary()
        );

        restored.unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_disabled() {
        let config = AuditConfig {
            enabled: false,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let summary = audit_summary(&config);
        assert!(!summary.enabled);
    }

    // --- display_timestamp ---

    #[test]
    fn timestamp_truncation() {
        assert_eq!(
            display_timestamp("2026-04-04T03:31:02.54814Z"),
            "2026-04-04T03:31:02Z"
        );
        assert_eq!(
            display_timestamp("2026-04-04T03:31:02Z"),
            "2026-04-04T03:31:02Z"
        );
    }

    // --- Retention / Prune ---

    fn make_event_with_timestamp(command: &str, ts: &str) -> AuditEvent {
        let mut event = make_event(command);
        event.timestamp = ts.to_string();
        event
    }

    fn test_logger_with_retention(dir: &Path, retention_days: u32) -> AuditLogger {
        let path = dir.join("audit.jsonl");
        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();
        AuditLogger {
            path,
            signing_key: SigningKey::for_test("default", Some(TEST_SECRET)),
            retention_days,
        }
    }

    fn retention_test_now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-04-04T12:00:00Z", &Rfc3339).unwrap()
    }

    /// Write chain entries directly with given timestamps (bypass append to control timestamps).
    /// `version` is explicit, not `CHAIN_VERSION` (#177 B3, shape
    /// enumeration T-01): before B3 this always meant "the current
    /// version" because only one existed. Once `CHAIN_VERSION` can flip,
    /// defaulting to it here would silently rewrite every one of this
    /// helper's ~10 call sites (mostly prune/retention fixtures) to whatever
    /// version happens to be current, erasing their v1-specific coverage
    /// with no signal that anything changed. Uses `compute_entry_hash`
    /// directly (not `compute_entry_hash_for_write`, T-06): the writer-only
    /// helper's `debug_assert_eq!(chain_version, CHAIN_VERSION)` exists to
    /// catch production writer bugs, and would wrongly panic here whenever
    /// this fixture helper is asked for a non-current version on purpose.
    /// #456: like `write_chain_entries`, but each entry's `seq` is stated by
    /// the caller instead of taken from its index. The top of the `u64` range
    /// is not reachable by counting, so it cannot be reached by indexing
    /// either — and the entries still have to be genuinely signed, because the
    /// behaviour under test happens *after* an entry verifies.
    fn write_chain_entries_at_seqs(
        path: &Path,
        secret: &[u8; 32],
        entries: &[(u64, &str, &str)],
        version: u32,
    ) {
        let mut prev_hash = genesis_hash(Some(secret));
        let mut content = String::new();

        for (seq, command, timestamp) in entries {
            let mut event = make_event_with_timestamp(command, timestamp);
            event.chain_version = Some(version);
            event.seq = Some(*seq);
            event.prev_hash = Some(prev_hash.clone());
            event.key_id = Some("default".to_string());
            event.entry_hash = Some(
                compute_entry_hash(Some(secret), &event).expect_hash("write_chain_entries_at_seqs"),
            );
            prev_hash = event.entry_hash.clone().unwrap();
            content.push_str(&serde_json::to_string(&event).unwrap());
            content.push('\n');
        }

        fs::write(path, content).unwrap();
    }

    fn write_chain_entries(path: &Path, secret: &[u8; 32], entries: &[(&str, &str)], version: u32) {
        let with_seqs: Vec<(u64, &str, &str)> = entries
            .iter()
            .enumerate()
            .map(|(i, (command, timestamp))| (i as u64, *command, *timestamp))
            .collect();
        write_chain_entries_at_seqs(path, secret, &with_seqs, version);
    }

    #[test]
    fn prune_genesis_hash_is_distinct() {
        let genesis = genesis_hash(Some(&TEST_SECRET));
        let prune = prune_genesis_hash(Some(&TEST_SECRET));
        assert_ne!(genesis, prune);
    }

    #[test]
    fn prune_genesis_hash_is_deterministic() {
        let a = prune_genesis_hash(Some(&TEST_SECRET));
        let b = prune_genesis_hash(Some(&TEST_SECRET));
        assert_eq!(a, b);
    }

    // #177 B1 step 5 / V-B31: `prune_genesis_hash_is_deterministic` and
    // `_is_distinct` above compare the function against itself or against
    // an unrelated hash — neither pins the *value*. `PRUNE_GENESIS_SEED`
    // (chain.rs) could be edited and both tests would stay green, silently
    // invalidating the prev_hash anchor every already-pruned audit.jsonl on
    // disk links against. This pins the literal value, same pattern as
    // GOLDEN_GENESIS above.
    //
    // Regenerating: this value must NEVER be edited to make a change pass.
    // If PRUNE_GENESIS_SEED changes intentionally, every existing pruned
    // chain becomes unverifiable — that's a breaking, `CHAIN_VERSION`-class
    // decision, not a test update.
    const GOLDEN_PRUNE_GENESIS: &str =
        "c1af069504c38b0fd648e34f5577a0107b3f3bd8e704f179ebc73928e0d59b50";

    #[test]
    fn prune_genesis_hash_matches_golden() {
        assert_eq!(
            prune_genesis_hash(Some(&TEST_SECRET)),
            GOLDEN_PRUNE_GENESIS,
            "PRUNE_GENESIS_SEED (or the HMAC domain separator) changed — every already-pruned \
             audit.jsonl's prune_point anchor is now unverifiable. This is not a test to fix by \
             updating the golden; see the comment above GOLDEN_PRUNE_GENESIS."
        );
    }

    #[test]
    fn try_prune_removes_old_entries() {
        let dir = test_dir("prune-old");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-09-18T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }

        let refs: Vec<(&str, &str)> = entries.to_vec();
        write_chain_entries(&path, &TEST_SECRET, &refs, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned, 100, "should prune 100 old entries");

        drop(file);
        let events = read_events(&path);
        assert_eq!(events.len(), 1101, "prune_point + 1100 retained");
        assert_eq!(events[0]["command"], "_prune");
        assert_eq!(events[0]["target_count"], 100);
        assert_eq!(events[0]["action"], "retention");
        assert_eq!(events[0]["result"], "pruned");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_nothing_to_prune() {
        let dir = test_dir("prune-nothing");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let new_ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..1100).map(|_| ("cmd", new_ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned, 0, "nothing should be pruned");
        let _ = fs::remove_dir_all(&dir);
    }

    // --- #461: the post-prune high-water-mark ---
    //
    // The mark used to be the largest `seq` among the retained lines, read
    // straight out of the JSON with nothing checking who wrote it. **No test
    // covered the recomputation at all**: every prune test above passes
    // `audit_path: None`, which skips the block entirely. So these are the
    // first tests to enter it, and the reason a "never update the mark"
    // implementation would have gone unnoticed.

    /// A store a prune will act on: 100 entries old enough to remove, 1100
    /// young enough to keep (`MIN_RETAIN_ENTRIES` is 1000). `seq` is the index,
    /// so the highest retained one is [`PRUNE_HWM_TOP_SEQ`].
    ///
    /// `version` is the literal `2`, not `CHAIN_VERSION`, for the reason
    /// `write_chain_entries`' own doc gives: these tests are not about which
    /// version is current, and pinning it stops a future flip from silently
    /// rewriting what they exercise.
    fn prune_hwm_fixture(dir: &Path, secret: &[u8; 32]) -> PathBuf {
        let path = dir.join("audit.jsonl");
        let old_ts = "2025-09-18T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, secret, &entries, 2);
        path
    }

    const PRUNE_HWM_TOP_SEQ: u64 = 1199;

    /// Appends a line nothing signed, timestamped inside the retained window.
    /// `entry_hash` is a placeholder on purpose — that it does not authenticate
    /// is the whole point, and writing it needs no key, since until `#461` this
    /// function's output was the only thing that read the field back.
    fn plant_unauthenticated_line(path: &Path, seq: u64) {
        let event = serde_json::json!({
            "timestamp": "2026-04-04T00:00:01Z",
            "provider": "planted",
            "command": "planted-cmd",
            "action": "passthrough",
            "result": "passthrough",
            "target_count": 0,
            "target_hash": "irrelevant",
            "chain_version": 2,
            "seq": seq,
            "prev_hash": "irrelevant",
            "key_id": "default",
            "entry_hash": "irrelevant",
        });
        let mut content = fs::read_to_string(path).unwrap();
        content.push_str(&serde_json::to_string(&event).unwrap());
        content.push('\n');
        fs::write(path, content).unwrap();
    }

    /// Runs the prune with `audit_path` supplied, so the high-water-mark block
    /// actually executes.
    fn prune_reaching_the_hwm(path: &Path, signing_key: &SigningKey) -> u64 {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned =
            try_prune_at(&mut file, signing_key, 90, Some(path), retention_test_now()).unwrap();
        drop(file);
        pruned
    }

    /// #461: the planted line carries the highest `seq` in the file and no
    /// valid `entry_hash`. The mark must not follow it — a mark above the chain
    /// is what tail-truncation detection reads as a removal, so moving it up
    /// hides the removal of everything below.
    #[test]
    fn prune_hwm_ignores_a_retained_entry_that_does_not_authenticate() {
        let dir = test_dir("prune-hwm-unauthenticated");
        test_logger(&dir);
        let path = prune_hwm_fixture(&dir, &TEST_SECRET);
        plant_unauthenticated_line(&path, 9_999_999);
        write_hwm(&hwm_path_for(&path), 0).unwrap();

        let pruned = prune_reaching_the_hwm(&path, &test_signing_key());
        assert_eq!(pruned, 100, "sanity: the prune itself must have run");
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            PRUNE_HWM_TOP_SEQ,
            "the mark must come from the highest authenticated seq, not from the planted line"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Control for the test above. Without it, an implementation that never
    /// writes the mark satisfies that assertion too — the planted value would
    /// simply never be reached. Here the mark starts at 0 and has to advance.
    #[test]
    fn prune_hwm_advances_to_the_highest_authenticated_seq() {
        let dir = test_dir("prune-hwm-advances");
        test_logger(&dir);
        let path = prune_hwm_fixture(&dir, &TEST_SECRET);
        write_hwm(&hwm_path_for(&path), 0).unwrap();

        let pruned = prune_reaching_the_hwm(&path, &test_signing_key());
        assert_eq!(pruned, 100);
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            PRUNE_HWM_TOP_SEQ,
            "with nothing planted the mark must still reach the top retained seq — otherwise \
             the test above passes for an implementation that never writes it"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Second control, on the axis the plan's first draft got wrong: the
    /// retained entries here are signed with the key that rotation *retires*,
    /// so authenticating against the active key alone would find nothing and
    /// leave the mark at 0. The keyring holds both, which is why the entry
    /// still authenticates. Uses production `rotate_key`, not a hand-built
    /// store.
    #[test]
    fn prune_hwm_authenticates_a_retained_entry_signed_with_a_retired_key() {
        let dir = test_dir("prune-hwm-retired-key");
        let secret_path = dir.join("audit-secret");
        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key is created");
        let path = prune_hwm_fixture(&dir, &epoch1);

        let rotation = super::rotate_key(&path).expect("rotation succeeds");
        assert_eq!(rotation.new_key_id, "key-2");
        let active = load_signing_key(&secret_path);
        assert_eq!(
            active.id, "key-2",
            "the prune must run under the post-rotation key, or this fixture is not \
             exercising the retired-key path"
        );
        write_hwm(&hwm_path_for(&path), 0).unwrap();

        let pruned = prune_reaching_the_hwm(&path, &active);
        assert_eq!(pruned, 100);
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            PRUNE_HWM_TOP_SEQ,
            "an entry signed with a retired key must still authenticate — the keyring holds it, \
             and only an active-key-only implementation would miss it"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex review P3: `_prune` is a command name a user can run, and such an
    /// entry is signed and carries a real `seq` — it is not the prune point.
    /// Excluding it by `command` alone dropped the highest retained entry from
    /// the mark whenever it happened to have that name, leaving that entry's
    /// removal undetectable. The three-field [`is_prune_point`] check keeps the
    /// real prune point out and lets this one in.
    #[test]
    fn prune_hwm_counts_a_signed_entry_that_only_shares_the_prune_command_name() {
        let dir = test_dir("prune-hwm-prune-named-entry");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");
        let old_ts = "2025-09-18T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1099 {
            entries.push(("new", new_ts));
        }
        // seq 1199, signed, `action`/`result` are the ordinary ones — so it
        // shares only the name with a prune point.
        entries.push((PRUNE_COMMAND, new_ts));
        write_chain_entries(&path, &TEST_SECRET, &entries, 2);
        write_hwm(&hwm_path_for(&path), 0).unwrap();

        let pruned = prune_reaching_the_hwm(&path, &test_signing_key());
        assert_eq!(pruned, 100);
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            PRUNE_HWM_TOP_SEQ,
            "an entry that merely names `_prune` is an ordinary signed entry — excluding it \
             would put the mark one below the chain, and a mark below the chain cannot detect \
             the removal of the entry above it"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #461: with no secret the prune does not run. `hmac_bytes(None, ..)`
    /// returns the fixed string `NO_HMAC_SECRET`, so the prune point standing
    /// where the removed entries used to be would carry a `target_hash` and an
    /// `entry_hash` any reader can reproduce — a prune-bind binding nothing.
    #[test]
    fn prune_does_not_run_without_a_secret() {
        let dir = test_dir("prune-no-secret");
        test_logger(&dir);
        let path = prune_hwm_fixture(&dir, &TEST_SECRET);
        let before = fs::read_to_string(&path).unwrap();
        write_hwm(&hwm_path_for(&path), 7).unwrap();

        let pruned = prune_reaching_the_hwm(&path, &SigningKey::for_test("default", None));
        assert_eq!(pruned, 0, "the prune must not run at all");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "the log must be byte-for-byte unchanged"
        );
        assert_eq!(
            expect_hwm(&hwm_path_for(&path)),
            7,
            "and the mark must not move either"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_min_retain_prevents_prune() {
        let dir = test_dir("prune-min-retain");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..500 {
            entries.push(("old", old_ts));
        }
        for _ in 0..500 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned, 0, "min retain should prevent prune");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_prune_retention_days_zero_is_noop() {
        let dir = test_dir("prune-zero");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2020-01-01T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..100).map(|_| ("cmd", old_ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(
            &mut file,
            &test_signing_key(),
            36500,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_pruned_chain_intact() {
        let dir = test_dir("verify-pruned");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned, 100);
        drop(file);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_none(), "pruned chain should verify OK");
        assert!(result.pruned, "should detect prune_point");
        assert_eq!(result.pruned_count, Some(100));
        assert_eq!(result.chain_entries, 1101);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_forged_prune_point() {
        let dir = test_dir("verify-forged-prune");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..10).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let events = read_events(&path);
        let retained = &events[5..];

        let bad_secret = [0x99u8; 32];
        let first_retained_hash = retained[0]["entry_hash"].as_str().unwrap();
        // The forging key is not in the keyring at all — that is what makes
        // this test discriminating, and #457's fix must not change it.
        let forged = build_prune_point(
            &SigningKey::for_test("default", Some(bad_secret)),
            5,
            first_retained_hash,
            retention_test_now(),
        );

        let mut content = serde_json::to_string(&forged).unwrap();
        content.push('\n');
        for ev in retained {
            content.push_str(&serde_json::to_string(ev).unwrap());
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "forged prune_point should be detected"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // #457: key rotation × chain verification
    // -----------------------------------------------------------------

    /// Build a 1200-entry chain under the store's first key, rotate with the
    /// **production** `rotate_key`, and prune the 100 oldest under the
    /// post-rotation key resolved by the **production** `load_signing_key`.
    /// This is the sequence a user hits when `[audit] retention_days > 0` and
    /// the 1000-entry prune trigger fires after a rotation.
    ///
    /// An earlier version reimplemented rotation locally (rename + write,
    /// mirroring `rotate_key`'s steps) and hand-built the post-rotation
    /// `SigningKey`. Codex flagged it as a mirror helper: a fixture that
    /// reimplements the thing under test stops being evidence the moment the
    /// two drift. Both halves now go through production code.
    ///
    /// Returns the log path and both epoch keys, which callers need in order
    /// to recompute hashes independently.
    fn pruned_across_rotation_fixture(dir: &Path) -> (std::path::PathBuf, [u8; 32], [u8; 32]) {
        let path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key is created");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &epoch1, &entries, 2);

        let rotation = super::rotate_key(&path).expect("rotation succeeds");
        assert_eq!(rotation.new_key_id, "key-2");
        let epoch2 = read_secret(&secret_path).expect("the new active key is readable");

        let signing_key = load_signing_key(&secret_path);
        assert_eq!(
            signing_key.id, "key-2",
            "the writer must resolve the post-rotation epoch, or this fixture \
             is not exercising what the prune path actually does"
        );

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(&mut file, &signing_key, 90, None, retention_test_now()).unwrap();
        assert_eq!(pruned, 100, "the 100 old-timestamped entries are prunable");
        drop(file);

        (path, epoch1, epoch2)
    }

    /// #457 Bug 1 + Bug 1b (V-010). The whole chain must verify after a prune
    /// that ran under a rotated key. Two independent defects sit on this path:
    ///
    /// - **Bug 1** — `build_prune_point` wrote `key_id: "default"` while
    ///   signing with the active secret; after a rotation `"default"` names
    ///   the *epoch-1* key, so the prune point failed at seq 0.
    /// - **Bug 1b** — the prune-bind `target_hash` is computed by the writer
    ///   with the key active at prune time (`retention.rs`) but recomputed by
    ///   the verifier with the key of the *first retained entry*
    ///   (`verify.rs`). Different epochs, so it fails at the first retained
    ///   entry (seq 100 in this fixture), not at the prune point.
    ///
    /// The break moving from seq 0 to seq 100 as A2 lands is the evidence that
    /// these are two defects and not one symptom seen twice.
    #[test]
    fn prune_point_written_after_rotation_verifies() {
        let dir = test_dir("457-prune-after-rotation");
        pruned_across_rotation_fixture(&dir);

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_none(),
            "a prune point written after a key rotation must verify; \
             broken_at = {:?}",
            result.broken_at
        );
        assert!(result.pruned, "the prune point must still be recognized");
        assert_eq!(result.pruned_count, Some(100));

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 Bug 1 (V-011), asserted at the writer rather than through
    /// `verify_chain`. `build_prune_point` must stamp the id of the key it
    /// actually signed with — after a rotation that is `key-2`, not the
    /// hardcoded `"default"` the old code wrote.
    ///
    /// Separating this from `prune_point_written_after_rotation_verifies`
    /// keeps the two defects independently observable: reverting A2 turns this
    /// test red on its own, while reverting A4 leaves it green and only turns
    /// the whole-chain test red.
    #[test]
    fn prune_point_is_labelled_with_the_key_that_signed_it() {
        let dir = test_dir("457-prune-point-label");
        let (path, _epoch1, epoch2) = pruned_across_rotation_fixture(&dir);

        let events = read_events(&path);
        assert_eq!(
            events[0]["key_id"].as_str(),
            Some("key-2"),
            "the prune point must name the post-rotation active key"
        );

        // Not just the label: the entry must actually authenticate under the
        // key it names. A writer that stamped the right id while signing with
        // a different key would pass the assertion above.
        let prune_point: AuditEvent = serde_json::from_value(events[0].clone()).unwrap();
        let recorded = prune_point.entry_hash.clone().unwrap();
        assert_eq!(
            compute_entry_hash(Some(&epoch2), &prune_point).expect_hash("prune point"),
            recorded,
            "the prune point must authenticate under the key its key_id names"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 (V-003). A chain that continues across a real rotation, exercised
    /// end to end through the production writer and the production
    /// `rotate_key` — no hand-built fixture, no simulated rotation.
    ///
    /// The first version of this test wrote *both* halves with the pre-rotation
    /// key and labelled them all `"default"`, a state no writer can produce. It
    /// passed, and it did catch the anchor mutation, but what it actually
    /// exercised was "a head naming a retired key is accepted" — not "a chain
    /// spanning a rotation verifies". Both Codex reviews flagged it
    /// independently (Round 1 P1, test review #1).
    ///
    /// Going through `AuditLogger` also pins the labels the writer really
    /// stamps, which a fixture can only assert about itself.
    #[test]
    fn chain_spanning_a_real_rotation_verifies_end_to_end() {
        let dir = test_dir("457-real-rotation");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        assert_eq!(
            logger.key_id(),
            "default",
            "an unrotated store signs under epoch 1"
        );
        logger.append(make_event("before-rotation")).unwrap();
        drop(logger);

        super::rotate_key(&audit_path).expect("rotation succeeds");

        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        assert_eq!(
            logger.key_id(),
            "key-2",
            "after one rotation the writer must stamp the new epoch"
        );
        logger.append(make_event("after-rotation")).unwrap();
        drop(logger);

        let events = read_events(&audit_path);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["key_id"].as_str(), Some("default"));
        assert_eq!(
            events[1]["key_id"].as_str(),
            Some("key-2"),
            "the two halves must be labelled with different epochs, or this \
             fixture is not exercising a rotation at all"
        );

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "a chain spanning a rotation must verify; broken_at = {:?}",
            result.broken_at
        );
        assert!(
            result.key_unavailable_at.is_none(),
            "both keys are present; nothing should be unresolvable"
        );
        assert_eq!(result.chain_entries, 2);
        // V-003: both epochs must be counted as one verified chain, not
        // silently dropped from the tally. `broken_at.is_none()` alone would
        // also hold for a verifier that stopped early without saying so.
        assert_eq!(
            result.v2_entries, 2,
            "both entries are chain_version 2 and both must be counted"
        );
        assert_eq!(result.legacy_entries, 0);
        assert_eq!(result.unverified_entries_after, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-005. Two rotations, log started in epoch 1. The head names
    /// `"default"`, so the anchor must come from the oldest retired key.
    ///
    /// **Its unique-kill set is empty** — measured, not assumed. `/simplify`
    /// ran five anchor-resolution mutations against the suite; every one this
    /// test kills is also killed by seven or eight others, and the two that
    /// isolate a single test both point at V-006, not here. Kept anyway: it is
    /// a named item in the plan's V-ID table, and it states a property the
    /// others do not say out loud — that after *two* rotations `"default"`
    /// still means epoch 1, not "whatever was retired most recently".
    ///
    /// If test runtime ever needs trimming, this is the first candidate, and
    /// V-006's doc comment already carries the contrast that makes it
    /// redundant.
    #[test]
    fn head_anchor_after_two_rotations_uses_the_epoch_the_head_names() {
        let dir = test_dir("457-two-rotations");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("first")).unwrap();
        logger.append(make_event("second")).unwrap();
        drop(logger);

        super::rotate_key(&audit_path).expect("rotation 1");
        super::rotate_key(&audit_path).expect("rotation 2");

        let events = read_events(&audit_path);
        assert_eq!(
            events[0]["key_id"].as_str(),
            Some("default"),
            "precondition: the head belongs to epoch 1"
        );

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "broken_at = {:?}",
            result.broken_at
        );
        assert_eq!(result.chain_entries, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-006 (and V-004: this is the "log started after a rotation" shape
    /// — rotate, discard the log, start fresh — which no other fixture covers)
    /// — the discriminating case QA called the strongest cell.
    ///
    /// Three rotations, but the log starts in **epoch 2**. The head names
    /// `key-2`, while the oldest retired key is `key-1` and the most recently
    /// retired is `key-3`. A fix that reached for either the oldest or the
    /// newest retired key would pass V-005 and fail here.
    #[test]
    fn head_anchor_after_three_rotations_uses_a_middle_epoch() {
        let dir = test_dir("457-three-rotations");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        // Epoch 1: write and discard, so the surviving log starts later.
        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1-discarded")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation 1");
        fs::remove_file(&audit_path).unwrap();
        let _ = fs::remove_file(hwm_path_for(&audit_path));

        // Epoch 2: this is the log that survives, so its head names `key-2`.
        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        assert_eq!(logger.key_id(), "key-2");
        logger.append(make_event("epoch-2-head")).unwrap();
        drop(logger);

        super::rotate_key(&audit_path).expect("rotation 2");
        super::rotate_key(&audit_path).expect("rotation 3");

        let events = read_events(&audit_path);
        assert_eq!(
            events[0]["key_id"].as_str(),
            Some("key-2"),
            "precondition: the head is neither the oldest nor the newest epoch"
        );

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "the anchor must come from key-2 — not key-1 (oldest) and not key-3 \
             (most recently retired); broken_at = {:?}",
            result.broken_at
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-007. `verify.rs` computes two anchors on adjacent lines —
    /// `genesis` and `prune_genesis`. A fix that converts only one of them
    /// passes every other test in this file.
    ///
    /// The reason is fixture ordering. `pruned_across_rotation_fixture` prunes
    /// *after* rotating, so the prune point is signed by the key that is also
    /// active at verification time — exactly where the old active-key-anchored
    /// code happens to agree with the correct answer. Pruning *before*
    /// rotating separates them: the prune point is anchored to the retired
    /// key's `prune_genesis`, and computing that from the active key fails.
    ///
    /// Mutation-verified. Reverting `prune_genesis_hash(Some(entry_secret))` to
    /// the active secret produced exactly one failure — this test:
    ///
    /// ```text
    /// prune_genesis_is_resolved_from_the_prune_points_own_key ... FAILED
    /// prune_point_written_after_rotation_verifies             ... ok
    /// prune_point_is_labelled_with_the_key_that_signed_it     ... ok
    /// verify_pruned_chain_intact                              ... ok
    /// ```
    ///
    /// Without it, a fix that converted `genesis` and left `prune_genesis`
    /// anchored to the active key would have shipped green.
    #[test]
    fn prune_genesis_is_resolved_from_the_prune_points_own_key() {
        let dir = test_dir("457-prune-then-rotate");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&audit_path, &epoch1, &entries, 2);

        // Prune while epoch 1 is still active: the prune point is signed by
        // epoch 1 and labelled `"default"`.
        let signing_key = load_signing_key(&secret_path);
        assert_eq!(signing_key.id, "default", "still unrotated at prune time");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&audit_path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned = try_prune_at(&mut file, &signing_key, 90, None, retention_test_now()).unwrap();
        assert_eq!(pruned, 100);
        drop(file);

        // Only now rotate. `"default"` from here on names the retired key.
        super::rotate_key(&audit_path).expect("rotation succeeds");

        let events = read_events(&audit_path);
        assert_eq!(
            events[0]["key_id"].as_str(),
            Some("default"),
            "precondition: the prune point belongs to epoch 1"
        );

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "the prune point's anchor must be computed from the key it names, \
             not from whichever key is active now; broken_at = {:?}",
            result.broken_at
        );
        assert!(result.pruned);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-018. The forged-prune-point test must keep discriminating once a
    /// keyring holds several keys — a fix that widened key resolution too far
    /// would let a forgery find *some* key that validates it.
    ///
    /// The forging key (`[0x99; 32]`) is in no keyring, so the only way this
    /// passes is if verification still refuses keys it was not given.
    #[test]
    fn forged_prune_point_is_still_rejected_with_several_keys_in_the_ring() {
        let dir = test_dir("457-forged-multikey");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");

        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key");
        for _ in 0..3 {
            super::rotate_key(&audit_path).expect("rotation succeeds");
        }
        let ring = load_keyring(&secret_path);
        assert!(
            ring.get("key-1").is_some() && ring.get("key-4").is_some(),
            "precondition: several epochs are present"
        );

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..10).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&audit_path, &epoch1, &entries, 2);

        let events = read_events(&audit_path);
        let retained = &events[5..];
        let bad_secret = [0x99u8; 32];
        let forged = build_prune_point(
            &SigningKey::for_test("default", Some(bad_secret)),
            5,
            retained[0]["entry_hash"].as_str().unwrap(),
            retention_test_now(),
        );

        let mut content = serde_json::to_string(&forged).unwrap();
        content.push('\n');
        for ev in retained {
            content.push_str(&serde_json::to_string(ev).unwrap());
            content.push('\n');
        }
        fs::write(&audit_path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "a prune point forged with a key outside the ring must be rejected \
             no matter how many keys the ring holds"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-019 — pins the acceptance widening that ADR-0008 §7 records as a
    /// deliberate cost. **This is the test ADR-0008 and CHANGELOG refer to when
    /// they say the widening cannot change silently.**
    ///
    /// Anchoring on the key the head entry names means a chain whose head was
    /// signed by a *retired* key is accepted. Before #457 the anchor came from
    /// the active key, so such a head was rejected — incidentally, as a side
    /// effect of the defect, not by design. An attacker holding only a retired
    /// key can therefore now forge a chain head as well as the non-head entries
    /// they could already forge (no epoch-monotonicity check exists).
    ///
    /// The assertion is deliberately `broken_at.is_none()`: it asserts that
    /// forged-with-a-retired-key **verifies**. If a later change tightens this,
    /// the test fails and whoever tightened it has to decide consciously
    /// whether ADR-0008 §7 still holds.
    #[test]
    fn a_chain_forged_with_only_a_retired_key_is_accepted_documented_tradeoff() {
        let dir = test_dir("457-retired-key-forgery");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        // Establish epoch 1 and rotate, so epoch-1 becomes the retired key.
        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key");
        super::rotate_key(&audit_path).expect("rotation succeeds");
        let epoch2 = read_secret(&secret_path).expect("epoch-2 is active");
        assert_ne!(epoch1, epoch2);

        // An attacker who exfiltrated only the retired key writes a whole
        // chain with it, labelling it `"default"` — which is what that key is
        // called. No part of this uses the active key.
        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..3).map(|_| ("forged", ts)).collect();
        write_chain_entries(&audit_path, &epoch1, &entries, 2);

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "ADR-0008 §7 accepts this: anchoring on the named key means a \
             retired-key forgery verifies. broken_at = {:?}",
            result.broken_at
        );
        assert_eq!(result.chain_entries, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-032 — the machine check behind CHANGELOG's "needs no re-audit".
    ///
    /// The claim being verified: v0.16.0 reporting `chain broken` on a rotated
    /// log was a **false positive**, not a missed detection. That only holds if
    /// the fixed verifier still catches real tampering on exactly the kind of
    /// chain that used to fail spuriously.
    ///
    /// A BASE comparison cannot establish this — v0.16.0 returns `broken` for a
    /// rotated chain whether or not it was altered, so it cannot distinguish
    /// the two. What has to be shown is that the *fixed* verifier does.
    #[test]
    fn tampering_is_still_detected_on_a_chain_that_spans_a_rotation() {
        let dir = test_dir("457-tamper-across-rotation");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("before")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation succeeds");
        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        logger.append(make_event("after")).unwrap();
        logger.append(make_event("after-2")).unwrap();
        drop(logger);

        let clean = fs::read_to_string(&audit_path).unwrap();
        assert!(
            verify_chain(&config).unwrap().broken_at.is_none(),
            "control: the unaltered rotated chain must verify"
        );

        // Alter an entry on the far side of the rotation boundary.
        let mut events = read_events(&audit_path);
        events[1]["command"] = serde_json::Value::String("TAMPERED".to_string());
        let altered: String = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        fs::write(&audit_path, altered).unwrap();

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_some(),
            "tampering on a rotated chain must still be detected — this is what \
             makes v0.16.0's report a false positive rather than a missed \
             detection, and it is what CHANGELOG's \"needs no re-audit\" rests on"
        );

        // Restoring must clear it: a verifier that always says "broken" would
        // satisfy the assertion above while proving nothing.
        fs::write(&audit_path, clean).unwrap();
        assert!(
            verify_chain(&config).unwrap().broken_at.is_none(),
            "restoring the original bytes must clear the verdict"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-024 — pins the property ADR-0008 and SECURITY.md describe as
    /// *not* guaranteed, so that "we deferred this" cannot quietly become "we
    /// fixed this" or "we broke this further" without a test changing.
    ///
    /// `verify_chain` performs no check that key epochs advance monotonically
    /// along the chain. An entry naming an older epoch after entries naming a
    /// newer one verifies fine, provided each authenticates under the key it
    /// names.
    #[test]
    fn key_epochs_are_not_checked_for_monotonicity_documented_gap() {
        let dir = test_dir("457-epoch-monotonicity");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let epoch1 = load_or_create_secret(&secret_path).expect("epoch-1 key");
        super::rotate_key(&audit_path).expect("rotation succeeds");
        let epoch2 = read_secret(&secret_path).expect("epoch-2 is active");

        // Build a chain that goes epoch-2, epoch-2, then *back* to epoch-1.
        let ts = "2026-04-04T00:00:00Z";
        let mut prev = genesis_hash(Some(&epoch2));
        let mut content = String::new();
        for (seq, (key, key_id)) in [(&epoch2, "key-2"), (&epoch2, "key-2"), (&epoch1, "default")]
            .iter()
            .enumerate()
        {
            let mut event = make_event_with_timestamp("cmd", ts);
            event.chain_version = Some(2);
            event.seq = Some(seq as u64);
            event.prev_hash = Some(prev.clone());
            event.key_id = Some((*key_id).to_string());
            event.entry_hash =
                Some(compute_entry_hash(Some(*key), &event).expect_hash("epoch-mix"));
            prev = event.entry_hash.clone().unwrap();
            content.push_str(&serde_json::to_string(&event).unwrap());
            content.push('\n');
        }
        fs::write(&audit_path, content).unwrap();

        let result = verify_chain(&config).unwrap();
        assert!(
            result.broken_at.is_none(),
            "documented gap: epochs going backwards along the chain is not \
             checked. If this starts failing, rotation gained forward security \
             — update ADR-0008 §7 and SECURITY.md's \"What rotation does not \
             guarantee\" rather than just fixing the test"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 V-020. `hmac_bytes(None, ..)` returns the literal `NO_HMAC_SECRET`.
    /// An attacker who writes that string into `entry_hash` must not have it
    /// accepted as a valid hash by any path.
    #[test]
    fn no_hmac_secret_sentinel_is_never_accepted_as_a_hash() {
        let dir = test_dir("457-sentinel");
        let path = dir.join("audit.jsonl");
        test_logger(&dir);

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..3).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 2);

        let mut events = read_events(&path);
        events[1]["entry_hash"] = serde_json::Value::String("NO_HMAC_SECRET".to_string());
        let content: String = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert_eq!(
            result.broken_at,
            Some(1),
            "the sentinel must fail the hash comparison like any other wrong value"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C02) — the deliberate improvement the limitation this replaces
    /// asked for by name.
    ///
    /// Deleting the last retired key used to read as **tampering**. With no
    /// `.retired` files left the store was indistinguishable from one that
    /// never rotated, so `"default"` resolved to the *active* key: an id that
    /// exists, holding the wrong bytes. `key_unavailable` could not fire — the
    /// id resolved — and the entry failed its hash, so `verify` produced the
    /// product's strongest accusation, permanently (`ADR-0007` forbids
    /// rewriting the entry), from an operator tidying up a directory.
    ///
    /// `audit-secret.epoch` is what tells the two apart. The store recorded
    /// epoch 2 when it rotated, so removing `.1.retired` no longer lowers the
    /// active epoch to 1: `"default"` is not aliased onto the epoch-2 key, the
    /// epoch-1 entry resolves to nothing, and it lands in cannot-verify —
    /// which is what actually became of it.
    ///
    /// The old test's own closing note set this bar: "If a later change makes
    /// this report cannot-verify instead, that is an improvement — but it must
    /// be a deliberate one, with this test updated to say so." Renamed rather
    /// than edited in place, because the name was the part that stated the
    /// verdict.
    #[test]
    fn deleting_the_last_retired_key_reads_as_cannot_verify() {
        let dir = test_dir("457-deleted-retired");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);

        super::rotate_key(&audit_path).expect("rotation succeeds");
        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        logger.append(make_event("epoch-2")).unwrap();
        drop(logger);

        // Sanity: both keys present, chain verifies. Without this the
        // assertions below could pass on a chain that was already broken.
        assert!(verify_chain(&config).unwrap().broken_at.is_none());

        fs::remove_file(dir.join("audit-secret.1.retired")).unwrap();

        let result = verify_chain(&config).unwrap();
        assert_eq!(
            result.broken_at, None,
            "the record holds the active epoch at 2, so \"default\" is not \
             aliased onto the epoch-2 key and no entry is checked against \
             bytes that never signed it"
        );
        assert_eq!(
            result.key_unavailable_at,
            Some(0),
            "the epoch-1 entry names a key that is genuinely gone: cannot \
             verify (exit 2), not tampering (exit 1)"
        );

        // The control, and the reason this test discriminates: take the record
        // away and the epoch comes from the retired slots again, which is the
        // pre-PR-C1 reading — accusation included. Without this the assertions
        // above would also pass on a build that stopped aliasing `"default"`
        // for some entirely unrelated reason.
        fs::remove_file(dir.join("audit-secret.epoch")).unwrap();
        let derived = verify_chain(&config).unwrap();
        assert_eq!(
            derived.broken_at,
            Some(0),
            "control: with no record the store derives epoch 1 for the active \
             key, and the old misreading comes back"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 A5 (V-028), category D — BASE green, FIXED non-zero.
    ///
    /// An entry that names a `key_id` absent from the keyring is *not*
    /// evidence of tampering: the entry may be entirely authentic and merely
    /// uncheckable. Before #457, `keyring.get(id).unwrap_or(&secret)` quietly
    /// checked such an entry against the **active** key. When that happened to
    /// be the signing key — which is the common case, since a stray
    /// `audit-secret.bak.retired` inflates `retired_key_count` and shifts
    /// every new entry's label without changing which key signs them — the
    /// entry passed. The verifier reported "chain intact" about an entry it
    /// had not actually authenticated under the key the entry named.
    ///
    /// This test therefore does not go red on BASE. It pins the *new*
    /// contract: name a key we do not hold and verification stops and says so.
    #[test]
    fn entry_naming_an_absent_key_is_unverifiable_not_tampered() {
        let dir = test_dir("457-absent-key");
        let path = dir.join("audit.jsonl");
        test_logger(&dir);

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..4).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 2);

        // Relabel entry #2 to name a key that does not exist, and re-sign it
        // with the *real* key. The entry is authentic in every sense except
        // that its label points at nothing — exactly the shape a stray
        // `.retired` file produces.
        let events = read_events(&path);
        let mut relabelled: AuditEvent = serde_json::from_value(events[2].clone()).unwrap();
        relabelled.key_id = Some("key-99".to_string());
        // `entry_hash` is left for the relink pass below, which re-signs every
        // entry from #1 onward with the real key.

        // Re-signing entry #2 changed its hash, so every later entry's
        // `prev_hash` now points at a value that no longer exists. Relink them
        // — otherwise the fixture carries a second, unrelated defect (a broken
        // chain link) and the test would pass for the wrong reason: the
        // verifier stops at #2 and never reaches the damage at #3. Measured
        // against the BASE binary, the un-relinked fixture reported
        // "chain broken at entry #3", which is not the property under test.
        let mut rebuilt: Vec<AuditEvent> = Vec::with_capacity(events.len());
        let mut prev = String::new();
        for (i, ev) in events.iter().enumerate() {
            let mut event: AuditEvent = if i == 2 {
                relabelled.clone()
            } else {
                serde_json::from_value(ev.clone()).unwrap()
            };
            if i > 0 {
                event.prev_hash = Some(prev.clone());
                event.entry_hash = None;
                event.entry_hash = Some(
                    compute_entry_hash(Some(&TEST_SECRET), &event).expect_hash("relinked entry"),
                );
            }
            prev = event.entry_hash.clone().unwrap();
            rebuilt.push(event);
        }

        let mut content = String::new();
        for event in &rebuilt {
            content.push_str(&serde_json::to_string(event).unwrap());
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();

        assert!(
            result.broken_at.is_none(),
            "an absent key must not be reported as tampering; broken_at = {:?}",
            result.broken_at
        );
        assert_eq!(
            result.key_unavailable_at,
            Some(2),
            "verification must stop at the entry whose key is missing"
        );
        assert_eq!(result.key_unavailable_id.as_deref(), Some("key-99"));
        assert_eq!(
            result.chain_entries, 2,
            "the two entries before it were verified"
        );
        assert_eq!(
            result.unverified_entries_after, 2,
            "the naming entry and everything after it are tallied, not trusted"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // #457 P4: key-directory scanning
    // -----------------------------------------------------------------

    fn write_key_file(path: &Path, secret: &[u8; 32]) {
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(path, hex).unwrap();
    }

    /// #457 P4-a (V-014). Taking a backup of the active key must not change
    /// which epoch the writer thinks it is in.
    ///
    /// The old `retired_key_count` counted every name matching
    /// `audit-secret.*.retired` without parsing the index, so
    /// `audit-secret.bak.retired` — a name an operator produces by following
    /// the rotation command's own output, which prints the retired key's path
    /// — silently incremented the count. Every entry written afterwards was
    /// labelled `key-2` while still being signed by the same key, and the next
    /// real rotation skipped to `.2.retired`, leaving `load_keyring`'s
    /// sequential probe to stop at the missing `.1` and lose epoch 1 entirely.
    #[test]
    fn stray_backup_file_does_not_shift_key_ids() {
        let dir = test_dir("457-stray-backup");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.bak.retired"), &[0x77u8; 32]);
        write_key_file(&dir.join("audit-secret.old.retired"), &[0x88u8; 32]);

        assert_eq!(
            load_signing_key(&secret_path).id,
            "default",
            "non-numeric suffixes are not rotations and must not shift the key id"
        );

        let ring = load_keyring(&secret_path);
        assert!(
            ring.get("key-2").is_none(),
            "a backup file must not materialize an epoch that never happened"
        );
        assert!(
            ring.get("default").is_some(),
            "the active key is still epoch 1"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-b. On a case-insensitive filesystem (APFS default) the old code
    /// built `audit-secret.1.retired` and opened it — which **succeeds** for a
    /// file actually named `audit-secret.1.RETIRED`. `retired_key_count`, which
    /// matched names literally, never saw that file. The two disagreed, and one
    /// stray file was enough to make a never-rotated host report a broken chain.
    ///
    /// Enumerating with `read_dir` and matching the name as it is removes the
    /// disagreement: the file is simply not a retired key.
    ///
    /// **Limitation** (Codex test review #2): on a *case-sensitive* filesystem
    /// this test is non-discriminating — reverting to constructed-path probing
    /// would still pass, because `audit-secret.1.retired` genuinely does not
    /// open `audit-secret.1.RETIRED` there. It discriminates on macOS (APFS
    /// default) and on any case-insensitive mount, which is where the defect
    /// was found. The `read_dir` behaviour it pins is filesystem-independent;
    /// only this test's ability to catch a regression is not.
    #[test]
    fn case_variant_retired_file_is_not_treated_as_a_rotation() {
        let dir = test_dir("457-case-variant");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.1.RETIRED"), &[0x99u8; 32]);

        assert_eq!(
            load_signing_key(&secret_path).id,
            "default",
            "an upper-case suffix is not the retired-key name"
        );

        let ring = load_keyring(&secret_path);
        assert_eq!(
            ring.get("default"),
            Some(&TEST_SECRET),
            "\"default\" must still resolve to the real active key, not the decoy"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-a (test review #3). The canonical-decimal guard had no test, so
    /// deleting `index.to_string() == middle` from `scan_key_dir` went
    /// unnoticed by the suite.
    ///
    /// Each decoy below parses as a number but is not the canonical spelling of
    /// a usable epoch. Admitting any of them either shifts every subsequent
    /// `key_id` (the "backup file" failure) or makes which file wins depend on
    /// `read_dir` order (`01` and `1` mapping to the same index).
    #[test]
    fn only_canonical_decimal_indices_count_as_rotations() {
        let dir = test_dir("457-canonical-index");
        let secret_path = dir.join("audit-secret");
        let real = [0x11u8; 32];
        let decoy = [0xEEu8; 32];
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.1.retired"), &real);
        write_key_file(&dir.join("audit-secret.01.retired"), &decoy);
        write_key_file(&dir.join("audit-secret.+1.retired"), &decoy);
        write_key_file(&dir.join("audit-secret.0.retired"), &decoy);
        write_key_file(&dir.join("audit-secret.4294967295.retired"), &decoy);

        let ring = load_keyring(&secret_path);
        assert_eq!(
            ring.get("key-1"),
            Some(&real),
            "the canonically-named .1 must be the one that loads"
        );
        assert_eq!(
            ring.get("default"),
            Some(&real),
            "\"default\" aliases epoch 1, so it must resolve to the same bytes"
        );
        assert!(
            ring.get("key-0").is_none(),
            "epochs start at 1 — a key-0 is an id no writer can produce"
        );
        assert!(
            ring.get("key-4294967295").is_none(),
            "the u32 ceiling is excluded because the next epoch would overflow"
        );
        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-2",
            "only .1 counts as a rotation, so the next epoch is 2 — if any \
             decoy were admitted this would be higher"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-e — pins the **residual**, which is what the plan asked for and
    /// what `SECURITY.md`'s "omamori warns when it sees this" needs behind it.
    ///
    /// #478 (V-B01) → PR-C1 (V-C05). A completed rotation that afterwards lost
    /// its key — which is what this fixture builds, and no longer what #478
    /// called S1.
    ///
    /// **The record changed which state this is.** `rotate_key` writes the new
    /// epoch between the rename and the mint, so a store that rotated and then
    /// lost `audit-secret` carries a record naming an epoch no key answers to.
    /// Whether that epoch ever signed anything is not recoverable from the key
    /// store — the record precedes the key — so the store stops guessing and
    /// stops reusing the number. Handing out epoch 2 a second time is what put
    /// two secrets under one id; handing out 3 costs a gap in the numbering,
    /// which costs nothing.
    ///
    /// **This is still the evidence for minting at all.** The alternative
    /// weighed for #478 — fail closed whenever retired keys exist with no
    /// active key — was rejected because it breaks a store that recovers on its
    /// own, and this shows the recovery still happens and still verifies.
    ///
    /// The sibling below drives the same fixture with an entry written under
    /// the lost epoch and gets a different verdict for it: that entry is
    /// reported as unauthenticatable rather than as tampering.
    /// `an_interrupted_rotation_before_the_record_uses_the_derived_epoch`
    /// covers the window that is still genuinely S1 — rename done, record not
    /// yet written — which only a hand-built store can reach.
    #[test]
    fn an_interrupted_rotation_does_not_reuse_the_recorded_epoch() {
        let dir = test_dir("478-interrupted-before-handout");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation succeeds");

        // The crash window, entered before the new epoch signed anything.
        fs::remove_file(&secret_path).unwrap();

        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        assert_eq!(
            logger.key_id(),
            "key-3",
            "epoch 2 is recorded, so the replacement takes the next number \
             instead of the one the rotation already claimed"
        );
        // The number and the record move together or not at all. Asserting the
        // observable id alone would pass on an implementation that hands out 3
        // and leaves the file saying 2 — after which the next command derives
        // 2 again and the same bytes answer to two ids.
        assert_eq!(
            fs::read_to_string(dir.join("audit-secret.epoch"))
                .expect("the record survives the mint"),
            "3",
            "the record states the epoch that was handed out, byte for byte"
        );
        logger.append(make_event("after-recovery")).unwrap();
        drop(logger);

        let result = verify_chain(&config).unwrap();
        assert_eq!(
            result.broken_at, None,
            "nothing was signed under key-2 and key-3 is a fresh label, so no \
             entry resolves to the wrong bytes"
        );
        assert_eq!(
            result.key_unavailable_at, None,
            "and every id in the log resolves: epoch 1 to .1.retired, key-3 to \
             the replacement"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C05) — the residual this replaces, resolved.
    ///
    /// A rotation whose key is lost afterwards used to have its number handed
    /// out a second time: the next append minted a fresh secret under the same
    /// `key-{N+1}` label, two secrets shared one id, and no verifier-side
    /// repair could untangle it — the id resolved, the bytes were simply wrong,
    /// so even the cannot-verify path could not fire. `verify` reported
    /// tampering, permanently.
    ///
    /// The old test's closing note set the terms: "If this starts passing, the
    /// epoch-recording fix landed — update ADR-0008 and SECURITY.md rather than
    /// just the assertion." Both are updated in this change.
    ///
    /// What the record buys is not detection but prevention: `key-3` is a label
    /// no earlier entry can hold, so nothing is ever checked against bytes that
    /// did not sign it. The epoch-2 entry is not rescued — its key is gone —
    /// but it is now reported as unauthenticatable rather than as evidence of
    /// an attack, and those are different exit codes and different actions.
    #[test]
    fn an_interrupted_rotation_no_longer_puts_two_secrets_under_one_id() {
        let dir = test_dir("457-interrupted-rotation");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation succeeds");

        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        assert_eq!(logger.key_id(), "key-2");
        logger.append(make_event("epoch-2")).unwrap();
        drop(logger);
        assert!(
            verify_chain(&config).unwrap().broken_at.is_none(),
            "control: the completed rotation verifies"
        );

        // Simulate the crash window: the retired key is in place, the active
        // key is not.
        let epoch2 = read_secret(&secret_path).unwrap();
        fs::remove_file(&secret_path).unwrap();

        // The next resolution warns (stderr) and mints a replacement — under
        // the same id the interrupted rotation had already used.
        let replacement = load_signing_key(&secret_path);
        assert_eq!(
            replacement.id, "key-3",
            "the record already holds epoch 2, so the replacement is a \
             generation the log cannot already contain"
        );
        assert_ne!(
            replacement.secret(),
            Some(&epoch2),
            "it is a different secret, not a recovery of the old one"
        );

        // Consequence: the epoch-2 entry names a key that is gone, and says so.
        let result = verify_chain(&config).unwrap();
        assert_eq!(
            result.broken_at, None,
            "no entry is checked against bytes that did not sign it, because \
             no two keys share an id any more"
        );
        assert_eq!(
            result.key_unavailable_at,
            Some(1),
            "the epoch-2 entry is unauthenticatable — cannot verify (exit 2) — \
             rather than evidence of an attack (exit 1)"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Create a FIFO, for the shapes that must not be read as a missing key.
    #[cfg(unix)]
    fn mkfifo_at(path: &Path) {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// PR-C1 (V-C01). The window that is still genuinely S1: the rename
    /// happened, the record did not.
    ///
    /// `rotate_key` writes the record between the rename and the mint, so in
    /// production this window is a few instructions wide and only a hand-built
    /// store can be parked in it. What it has to do here is *nothing new* — a
    /// record at or below the retired slots leaves the derivation in charge,
    /// which is what makes the record additive rather than a migration.
    #[test]
    fn an_interrupted_rotation_before_the_record_uses_the_derived_epoch() {
        let dir = test_dir("c1-before-record");
        let secret_path = dir.join("audit-secret");
        let record_path = dir.join("audit-secret.epoch");
        write_key_file(&dir.join("audit-secret.1.retired"), &[7u8; 32]);

        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-2",
            "with no record the epoch comes from the slots, exactly as before"
        );
        assert!(
            !record_path.exists(),
            "and a mint does not create one — only rotation records an epoch \
             (yotta 判断15), which is what keeps record-less stores in the \
             population the BASE comparison draws from"
        );

        // The same answer from a record the slots have already caught up with,
        // which is the state a crash between `rename` and `write_epoch_record`
        // leaves behind.
        fs::remove_file(&secret_path).unwrap();
        fs::write(&record_path, "1").unwrap();
        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-2",
            "a record at or below the highest slot does not raise the epoch"
        );
        assert_eq!(
            fs::read_to_string(&record_path).unwrap(),
            "1",
            "and this mint does not advance it either: the number handed out \
             is the derived one, which the next command derives again"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C03) — the shape QA called mandatory, because nothing
    /// observable distinguishes it.
    ///
    /// `read_secret` rejects an active key in more ways than one, and only
    /// `NotFound` means the key is *gone*. #478 removed the same fold from the
    /// interrupted-rotation warning, where its cost was a wrong sentence. Here
    /// the cost is worse and silent: a store whose key is present but
    /// unreachable — one `chmod` — would be read as having lost a generation,
    /// the record would advance, and the advance is durable. The observable id
    /// is identical either way (the mint fails under every shape below, since
    /// `create_new` finds the path occupied), so only the record's bytes can
    /// tell a correct build from a broken one.
    #[test]
    #[cfg(unix)]
    fn an_unreadable_active_key_does_not_advance_the_record() {
        use std::os::unix::fs::PermissionsExt;

        for shape in [
            "unreadable-mode",
            "bad-hex",
            "too-short",
            "a-directory",
            "a-fifo",
        ] {
            let dir = test_dir(&format!("c3-{shape}"));
            let secret_path = dir.join("audit-secret");
            let record_path = dir.join("audit-secret.epoch");
            write_key_file(&dir.join("audit-secret.1.retired"), &[7u8; 32]);
            fs::write(&record_path, "5").unwrap();
            match shape {
                "unreadable-mode" => {
                    write_key_file(&secret_path, &[1u8; 32]);
                    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o000)).unwrap();
                }
                "bad-hex" => fs::write(&secret_path, "z".repeat(64)).unwrap(),
                "too-short" => fs::write(&secret_path, "a".repeat(63)).unwrap(),
                "a-directory" => fs::create_dir(&secret_path).unwrap(),
                "a-fifo" => mkfifo_at(&secret_path),
                other => unreachable!("unhandled shape {other}"),
            }

            let id = load_signing_key(&secret_path).id;
            assert_eq!(
                fs::read_to_string(&record_path).unwrap(),
                "5",
                "{shape}: the record must not move for a key that is present \
                 and unreadable — only `NotFound` says a generation is gone"
            );
            assert_eq!(
                id, "key-5",
                "{shape}: and the label stays on the recorded epoch"
            );

            let _ = fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600));
            let _ = fs::remove_dir_all(&dir);
        }

        // The control. Without it every assertion above would also hold on a
        // build that never advances the record at all, which is a different
        // bug wearing the same green.
        let dir = test_dir("c3-control-notfound");
        let secret_path = dir.join("audit-secret");
        let record_path = dir.join("audit-secret.epoch");
        write_key_file(&dir.join("audit-secret.1.retired"), &[7u8; 32]);
        fs::write(&record_path, "5").unwrap();

        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-6",
            "control: an absent active key is the one shape that does move the \
             epoch on"
        );
        assert_eq!(
            fs::read_to_string(&record_path).unwrap(),
            "6",
            "control: and the record moves with it"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (Codex Round 1, P1). The record only ever moves up.
    ///
    /// The recovery path runs under a **shared** lock, so two processes can both
    /// observe the same missing key. If one of them has since advanced the
    /// record and minted a key for the new epoch, the other must not write its
    /// own lower number back: the next `create_secret` fails `AlreadyExists`,
    /// reads the newer key, and labels it with the older epoch — a key
    /// travelling under another epoch's name, which is the shape this whole
    /// change removes, reappearing through the fix for it.
    ///
    /// Returning the number actually on disk is the other half. Skipping the
    /// write while still letting the caller name its own number leaves exactly
    /// the same mismatch, just without the file to show for it.
    #[test]
    fn the_epoch_record_only_moves_up() {
        let dir = test_dir("c1-monotonic");
        let secret_path = dir.join("audit-secret");
        let record_path = dir.join("audit-secret.epoch");

        assert_eq!(
            secret::write_epoch_record(&secret_path, 4).expect("first write"),
            4,
            "an absent record takes whatever it is given"
        );
        assert_eq!(
            secret::write_epoch_record(&secret_path, 5).expect("higher write"),
            5,
            "and moves up"
        );
        assert_eq!(
            secret::write_epoch_record(&secret_path, 3).expect("stale write"),
            5,
            "a stale caller is told the number the store is on, not the one it \
             asked for — naming 3 while the key belongs to epoch 5 is the \
             defect this guards"
        );
        assert_eq!(
            fs::read_to_string(&record_path).unwrap(),
            "5",
            "and the file is not walked back"
        );
        assert_eq!(
            secret::write_epoch_record(&secret_path, 5).expect("equal write"),
            5,
            "equal is not an advance either"
        );

        // A record that cannot be parsed is not overwritten. This is the one
        // path that could destroy it silently, and an operator diagnosing a
        // fail-closed store needs the bytes to still be there.
        fs::write(&record_path, "not-an-epoch").unwrap();
        let err = secret::write_epoch_record(&secret_path, 9)
            .expect_err("an unreadable record fails closed here too");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read_to_string(&record_path).unwrap(),
            "not-an-epoch",
            "and the bytes survive for the operator to look at"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C04). A record above the slots is followed by all three
    /// consumers, not only whichever one reads it first.
    ///
    /// #477 exists because one of the three took a number the other two would
    /// have refused. The record adds a second input to the same computation, so
    /// the same question has to be asked again of each: the writer that labels
    /// entries, the keyring that resolves those labels, and rotation, which
    /// picks the slot the current key is filed into.
    #[test]
    fn every_consumer_follows_a_record_above_the_retired_slots() {
        let dir = test_dir("c4-all-consumers");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        write_key_file(&dir.join("audit-secret.1.retired"), &[7u8; 32]);
        write_key_file(&secret_path, &[9u8; 32]);
        fs::write(dir.join("audit-secret.epoch"), "5").unwrap();

        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-5",
            "the writer labels entries with the recorded epoch, not with \
             max_retired + 1 (which would be key-2)"
        );

        let ring = load_keyring(&secret_path);
        assert_eq!(
            ring.get("key-5"),
            Some(&[9u8; 32]),
            "the keyring registers the active key under the same epoch"
        );
        assert!(
            ring.get("key-2").is_none(),
            "and not under the derived one, which nothing signed"
        );
        assert_eq!(
            ring.get("default"),
            Some(&[7u8; 32]),
            "epoch 1 keeps its alias: the record moves the active epoch, not \
             the meaning of the oldest one"
        );

        let result = super::rotate_key(&audit_path).expect("rotation succeeds");
        assert_eq!(
            result.retired_key_id, "key-5",
            "rotation ends the epoch the record named"
        );
        assert_eq!(result.new_key_id, "key-6", "and allocates the next one");
        assert!(
            dir.join("audit-secret.5.retired").exists(),
            "the slot follows the epoch too — filing epoch 5's key into \
             .2.retired is what made a later rotation overwrite a live key"
        );
        assert_eq!(
            fs::read_to_string(dir.join("audit-secret.epoch")).unwrap(),
            "6",
            "and the record states the epoch that was just handed out"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C06). Removing the *newest* retired key must not walk the
    /// active label backwards.
    ///
    /// Not in the plan's table of three defects — it is a fourth instance of
    /// the same shape, found while writing these. Deleting `.2.retired` on a
    /// store at epoch 3 drops `max_retired` to 1, and the derivation then calls
    /// the *current* key epoch 2. Every entry written afterwards would be
    /// labelled `key-2` while signed with epoch 3's bytes, and `.2.retired` is
    /// exactly the file the next rotation would then try to create.
    #[test]
    fn deleting_the_newest_retired_key_does_not_walk_the_active_label_back() {
        let dir = test_dir("c6-newest-retired-gone");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("first rotation");
        super::rotate_key(&audit_path).expect("second rotation");
        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-3",
            "precondition: two rotations put the store at epoch 3"
        );

        fs::remove_file(dir.join("audit-secret.2.retired")).unwrap();

        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-3",
            "the active key did not change, so neither does its label — \
             deriving from the slots would call it key-2 here"
        );

        // The control, and the reason this is a fourth defect rather than a
        // restatement: without the record the same deletion moves the label.
        fs::remove_file(dir.join("audit-secret.epoch")).unwrap();
        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-2",
            "control: with the record gone the label walks back, which is the \
             behaviour this test exists to rule out"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C09) + PR-C2 (V-C24). Neither of the two files omamori keeps
    /// beside the keys is a retired key, on this version or any other.
    ///
    /// Both sit under the `audit-secret` prefix so the AI write block covers
    /// them, which puts each one `strip_suffix` away from being counted as a
    /// slot. If either ever were, every epoch in the store would shift — and
    /// the versions that predate them apply the same suffix rule, so this holds
    /// for those too.
    ///
    /// The pending slot is also checked to be *reported*, not merely ignored.
    /// Rotation needs to know it is there, and it must learn that from the
    /// listing rather than from an `exists()` on a path it built itself: on a
    /// case-insensitive filesystem those two disagree, and rotation deletes
    /// what it is told about.
    #[test]
    fn neither_the_record_nor_the_pending_slot_is_a_retired_key() {
        use std::ffi::OsString;

        let dir = test_dir("c9-record-is-not-a-slot");
        fs::write(dir.join("audit-secret.epoch"), "3").unwrap();

        let scan = secret::fold_key_dir_entries(
            &dir,
            vec![
                Ok(OsString::from("audit-secret.epoch")),
                Ok(OsString::from("audit-secret.pending")),
                Ok(OsString::from("audit-secret.1.retired")),
            ]
            .into_iter(),
        );
        let secret::KeyDirScan::Listed {
            retired,
            epoch,
            pending,
        } = &scan
        else {
            panic!("a complete listing must list")
        };
        assert_eq!(
            secret::max_retired_index(retired),
            1,
            "neither file may count as a slot"
        );
        assert_eq!(
            retired.len(),
            1,
            "and neither may appear in the retired map under any index"
        );
        assert_eq!(
            epoch.recorded().expect("the record reads"),
            3,
            "the record is read as the epoch record instead"
        );
        assert_eq!(
            pending.as_deref(),
            Some(dir.join("audit-secret.pending").as_path()),
            "and the pending slot is handed to rotation, from the listing"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C2 (V-C21, V-C23). What sits in the pending slot decides whether the
    /// rotation starts — and the decision lands before anything has moved.
    ///
    /// **The order is the change.** A rotation that could not build its
    /// replacement used to find that out *after* renaming the active key away,
    /// leaving a store the next command had to recover from. So the assertion
    /// worth making here is not "it failed" but "it failed and nothing moved":
    /// the active key is byte-identical, no slot was filled, no epoch was
    /// recorded, and re-running is the entire remedy.
    ///
    /// Three shapes omamori refuses to remove. The refusal is not the defence —
    /// `create_new` + `O_NOFOLLOW` is — it is what stops a rotation from
    /// deleting a file omamori did not write.
    #[test]
    #[cfg(unix)]
    fn what_sits_in_the_pending_slot_decides_before_anything_moves() {
        for shape in ["a-directory", "a-fifo", "a-symlink"] {
            let dir = test_dir(&format!("c21-{shape}"));
            let audit_path = dir.join("audit.jsonl");
            let secret_path = dir.join("audit-secret");
            let pending_path = dir.join("audit-secret.pending");
            let config = AuditConfig {
                enabled: true,
                path: Some(audit_path.clone()),
                retention_days: 0,
                strict: false,
            };

            let logger = AuditLogger::from_config(&config).expect("logger constructs");
            logger.append(make_event("epoch-1")).unwrap();
            drop(logger);
            let before = fs::read_to_string(&secret_path).expect("the active key exists");

            match shape {
                "a-directory" => fs::create_dir(&pending_path).unwrap(),
                "a-fifo" => mkfifo_at(&pending_path),
                "a-symlink" => std::os::unix::fs::symlink(&secret_path, &pending_path).unwrap(),
                other => unreachable!("unhandled shape {other}"),
            }

            let Err(e) = super::rotate_key(&audit_path) else {
                panic!("{shape}: rotation must refuse")
            };
            let msg = e.to_string();
            assert!(
                msg.contains("audit-secret.pending"),
                "{shape}: the message names the path to inspect: {msg}"
            );

            assert_eq!(
                fs::read_to_string(&secret_path).unwrap(),
                before,
                "{shape}: the active key did not move"
            );
            assert!(
                !dir.join("audit-secret.1.retired").exists(),
                "{shape}: nothing was retired — the refusal is ahead of the rename"
            );
            assert!(
                !dir.join("audit-secret.epoch").exists(),
                "{shape}: and no epoch was recorded"
            );
            assert!(
                fs::symlink_metadata(&pending_path).is_ok(),
                "{shape}: what was planted is left where the operator can see it"
            );

            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// PR-C2 (V-C21). A leftover the rotation itself wrote is cleared, and the
    /// rotation goes through.
    ///
    /// The control for the test above — same slot, different contents, opposite
    /// outcome. Without it, "rotation refuses when the slot is occupied" would
    /// also be satisfied by refusing unconditionally, which would make every
    /// store that crashed mid-rotation permanently un-rotatable.
    ///
    /// The leftover key is discarded rather than adopted. It was written by a
    /// rotation that never moved it into place, so no reader ever resolved it
    /// and no entry can name it; adopting it would be inheriting bytes with no
    /// record of where they came from.
    #[test]
    fn a_leftover_pending_key_is_cleared_and_the_rotation_goes_through() {
        let dir = test_dir("c21-leftover-cleared");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let pending_path = dir.join("audit-secret.pending");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);

        write_key_file(&pending_path, &[3u8; 32]);
        let leftover = fs::read_to_string(&pending_path).unwrap();

        let result = super::rotate_key(&audit_path).expect("rotation succeeds");
        assert_eq!(result.new_key_id, "key-2", "the rotation completed");
        assert!(
            !pending_path.exists(),
            "and the slot is empty again — the replacement was moved out of it"
        );
        assert_ne!(
            fs::read_to_string(&secret_path).unwrap(),
            leftover,
            "the leftover was discarded, not adopted"
        );
        assert_eq!(
            fs::read_to_string(dir.join("audit-secret.epoch")).unwrap(),
            "2",
            "and the epoch advanced as it would have without any leftover"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C2 (Codex Round 1, P1). A leftover is cleared only by a rotation that
    /// holds the key-store lock.
    ///
    /// "No reader resolves `.pending`" proves no *entry* can name the key it
    /// holds. It does not prove the file is unowned — and the lock is
    /// best-effort, so a second rotation reaches this point while the first is
    /// still inside `create_secret`. Deleting there strands the first at its
    /// final rename and leaves exactly the interrupted store this change exists
    /// to prevent, manufactured by the cleanup for it.
    ///
    /// The lock is made unavailable here by putting a directory at its path,
    /// which is one of the four ways `with_key_store_lock` reports `Unheld`.
    #[test]
    fn a_pending_slot_is_not_cleared_without_the_key_store_lock() {
        let dir = test_dir("c21-no-lock-no-delete");
        let audit_path = dir.join("audit.jsonl");
        let pending_path = dir.join("audit-secret.pending");
        let lock_path = dir.join("audit-secret.lock");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);

        write_key_file(&pending_path, &[3u8; 32]);
        let before = fs::read_to_string(&pending_path).unwrap();

        // A directory at the lock path: `with_key_store_lock` cannot open it,
        // so the rotation runs unlocked.
        let _ = fs::remove_file(&lock_path);
        fs::create_dir(&lock_path).unwrap();

        let Err(e) = super::rotate_key(&audit_path) else {
            panic!("an unlocked rotation must not decide a leftover is stale")
        };
        let msg = e.to_string();
        assert!(
            msg.contains("does not hold the key-store lock"),
            "and it must say why it refused rather than blaming the file: {msg}"
        );
        assert_eq!(
            fs::read_to_string(&pending_path).unwrap(),
            before,
            "the file another rotation may be writing is left alone"
        );
        assert!(
            !dir.join("audit-secret.1.retired").exists(),
            "and the refusal is ahead of the rename, so the store is untouched"
        );

        // The control: with the lock reachable, the same leftover is cleared
        // and the rotation completes. Without this the assertions above would
        // also hold for a build that never clears anything.
        fs::remove_dir(&lock_path).unwrap();
        super::rotate_key(&audit_path).expect("with the lock available it goes through");
        assert!(
            !pending_path.exists(),
            "control: the leftover is gone once exclusion was actually obtained"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// PR-C1 (V-C10, yotta 判断12). A record that states no epoch fails closed
    /// — and removing it puts the store back on the derivation.
    ///
    /// Failing closed has a price: one file makes `verify` stop. The mitigation
    /// is entirely in the message, so the recovery half of this test is the
    /// only evidence that the mitigation works. Deletion is reachable by a
    /// person and not by an agent — `PROTECTED_FILE_PATTERNS` covers the
    /// `audit-secret` prefix — so this is a remedy the threat model allows.
    #[test]
    fn a_record_that_states_no_epoch_fails_closed_and_recovers_when_removed() {
        let dir = test_dir("c10-bad-record");
        let audit_path = dir.join("audit.jsonl");
        let record_path = dir.join("audit-secret.epoch");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation succeeds");
        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        logger.append(make_event("epoch-2")).unwrap();
        drop(logger);
        assert!(
            verify_chain(&config).unwrap().broken_at.is_none(),
            "precondition: the rotated store verifies"
        );

        // Eleven shapes. Every one is a number this program does not write, and
        // the canonical-decimal pair (`01`, `+1`) is here for the reason
        // `fold_key_dir_entries` rejects the same two in a slot name: they
        // parse to an epoch that already has a spelling.
        for bad in [
            "0",
            "01",
            "+1",
            "abc",
            "",
            "   ",
            "-1",
            "1 2",
            "4294967296",
            "9".repeat(17).as_str(),
            "1\n2",
        ] {
            fs::write(&record_path, bad).unwrap();
            let Err(err) = verify_chain(&config) else {
                panic!(
                    "a record reading {bad:?} must stop verification, not be \
                     guessed past"
                )
            };
            let reason = err.to_string();
            assert!(
                matches!(err, AuditError::KeyringUnusable { .. }),
                "{bad:?}: cannot-verify, not tampering — got {reason}"
            );
            assert!(
                reason.contains("audit-secret.epoch"),
                "{bad:?}: the message must name the file to remove: {reason}"
            );

            let Err(refused) = super::rotate_key(&audit_path) else {
                panic!("{bad:?}: rotation must refuse too")
            };
            assert!(
                matches!(refused, AuditError::KeyringUnusable { .. }),
                "{bad:?}: rotation refuses on the same footing as verification \
                 — one invariant, one depth (#479). Got: {refused}"
            );
        }

        // A record that cannot be read at all, rather than one that reads as
        // the wrong thing. `Absent` is decided by the listing, so this must not
        // collapse into it.
        fs::remove_file(&record_path).unwrap();
        fs::create_dir(&record_path).unwrap();
        let Err(unreadable) = verify_chain(&config) else {
            panic!("a directory at the record path is not an absent record")
        };
        assert!(
            matches!(unreadable, AuditError::KeyringUnusable { .. }),
            "an unreadable record is not an absent one: {unreadable}"
        );
        fs::remove_dir(&record_path).unwrap();

        // Recovery: the derivation agrees with what the record said, so the
        // store verifies again.
        assert!(
            verify_chain(&config).unwrap().broken_at.is_none(),
            "removing the record restores verification — this is the whole of \
             the mitigation for failing closed"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 (Codex Round 2 follow-up). Failing closed on an unreadable key
    /// directory must not catch the case where the directory does not exist
    /// yet — that is every fresh install.
    ///
    /// The first version of that change returned a keyless `SigningKey` before
    /// `load_or_create_secret` could create the tree, so a new install recorded
    /// entries with no HMAC at all. Only an existing directory that cannot be
    /// listed is a fault; `NotFound` is just "nothing has happened yet".
    ///
    /// The regression was caught by an unrelated `hash-cwd` test. This one
    /// names the property directly.
    #[test]
    fn fresh_install_with_no_data_directory_still_gets_a_key() {
        let dir = test_dir("457-fresh-install");
        fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists(), "precondition: the directory must be absent");

        let secret_path = dir.join("audit-secret");
        let key = load_signing_key(&secret_path);

        assert!(
            key.secret().is_some(),
            "a fresh install must still receive an HMAC key — without one every \
             entry it writes is unprotected"
        );
        assert_eq!(key.id, "default", "a store with no rotations is epoch 1");
        assert!(secret_path.exists(), "the key must have been persisted");

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 (Codex Round 1 P0). An unlistable key directory is not "no
    /// rotations have happened". Treating it as such makes `"default"` resolve
    /// to the active key on a rotated store, and every entry then fails its
    /// hash — reporting a permissions problem as tampering.
    #[cfg(unix)]
    #[test]
    fn unlistable_key_directory_is_cannot_verify_not_tampering() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("457-unlistable-keydir");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("epoch-1")).unwrap();
        drop(logger);
        super::rotate_key(&audit_path).expect("rotation succeeds");
        let logger = AuditLogger::from_config(&config).expect("logger reconstructs");
        logger.append(make_event("epoch-2")).unwrap();
        drop(logger);
        assert!(verify_chain(&config).unwrap().broken_at.is_none());

        // Drop **read** on the directory but keep **execute**. On Unix these
        // are separate: `r` allows listing, `x` allows resolving a name inside
        // it. Removing both (e.g. 0o600) also makes the key files unopenable,
        // so `read_secret` fails first and the test measures
        // `SecretUnavailable` instead of the unlistable-directory path it is
        // supposed to be measuring.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o100)).unwrap();
        let outcome = verify_chain(&config);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        match outcome {
            Err(AuditError::KeyringUnusable { reason, .. }) => {
                assert!(
                    reason.contains("cannot list"),
                    "the error must name the real cause, got: {reason}"
                );
            }
            Err(other) => panic!("expected KeyringUnusable, got {other:?}"),
            Ok(result) => panic!(
                "an unlistable key directory must not produce a verdict; \
                 broken_at = {:?}",
                result.broken_at
            ),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457, Phase 8. Acquiring a held lock gives up instead of waiting.
    ///
    /// The first version called `flock(LOCK_EX)` with no `LOCK_NB`, which
    /// waits for as long as the holder likes. Measured: with an unrelated
    /// process holding the lock, `audit verify`, `doctor`, `report`,
    /// `exec -- true` and `hook-check` all stalled indefinitely — and the lock
    /// file was created world-readable, so a read-only descriptor was enough
    /// to take it. `hook-check` stalling is the serious one: it hangs before
    /// printing its deny verdict, leaving the outcome to the host's hook
    /// timeout rather than to omamori.
    #[test]
    #[cfg(unix)]
    fn a_held_lock_is_given_up_on_rather_than_waited_for() {
        let dir = test_dir("457-flock-bounded");
        let path = dir.join("locked");
        fs::write(&path, b"").unwrap();

        // flock is per open-file-description, so two opens in one process
        // contend exactly as two processes would.
        let holder = fs::File::open(&path).unwrap();
        flock_exclusive(&holder).expect("first acquisition succeeds");

        let contender = fs::File::open(&path).unwrap();
        let err = must_finish_within(
            std::time::Duration::from_secs(5),
            "flock_exclusive on a held lock",
            move || flock_exclusive(&contender).unwrap_err(),
        );
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::WouldBlock,
            "giving up must be distinguishable from a real I/O failure, got: {err}"
        );

        drop(holder);
        let after = fs::File::open(&path).unwrap();
        flock_exclusive(&after).expect("the lock is free again once released");

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457, Phase 8. The key store lock is best-effort in *both* directions.
    ///
    /// Creation failure was already documented as non-fatal; acquisition
    /// failure was not, and that asymmetry was the whole bug — a lock omamori
    /// cannot take must not stop it from resolving a key, or every guarded
    /// command stops with it.
    #[test]
    #[cfg(unix)]
    fn a_held_key_store_lock_does_not_stop_key_resolution() {
        let dir = test_dir("457-keystore-lock-held");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);

        let lock_path = dir.join("audit-secret.lock");
        fs::write(&lock_path, b"").unwrap();
        let holder = fs::File::open(&lock_path).unwrap();
        flock_exclusive(&holder).expect("holder takes the lock");

        let probe = secret_path.clone();
        let key = must_finish_within(
            std::time::Duration::from_secs(5),
            "load_signing_key with the key store lock held",
            move || load_signing_key(&probe),
        );
        assert_eq!(key.id, "default");
        assert_eq!(
            key.secret(),
            Some(&TEST_SECRET),
            "the key still resolves: an unavailable lock degrades to unlocked here \
             rather than blocking. Not because the exclusivity is optional — #477 \
             warns when rotation loses it — but because a caller that can hold this \
             lock forever must not be able to stall key resolution"
        );

        drop(holder);
        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-d / #468. `open` must not be the thing that blocks, and the
    /// rejection must not be the caller's job.
    ///
    /// Two properties, and the second replaced an earlier version of this
    /// test. `read_secret` used to reject a FIFO by stat'ing the path first,
    /// which is a TOCTOU window — swap the path for a FIFO between the stat
    /// and the open and the open hangs anyway, on a path omamori runs for
    /// every command. `O_NONBLOCK` closes that. But this test then asserted
    /// that the *helper* returned `Ok`, on the reasoning that "rejecting a
    /// FIFO is the caller's job" — which is the reasoning #468 exists to
    /// retire: a check that lives on callers does not reach the next caller,
    /// and it demonstrably did not.
    ///
    /// Without `O_NONBLOCK` this does not fail, it hangs, which is why it
    /// runs under a watchdog.
    #[test]
    #[cfg(unix)]
    fn opening_a_fifo_for_reading_is_refused_rather_than_waited_on() {
        let dir = test_dir("457-fifo-nonblock");
        let fifo = dir.join("fifo-secret");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) },
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let probe = fifo.clone();
        let err = must_finish_within(
            std::time::Duration::from_secs(5),
            "open_read_nofollow on a FIFO with no writer",
            move || open_read_nofollow(&probe).expect_err("a FIFO is not a readable file"),
        );
        assert!(
            err.to_string().contains("is a FIFO"),
            "the helper itself must refuse it, and name what it found so the \
             operator knows what to remove; got: {err}"
        );

        // And the caller inherits the refusal rather than restating it.
        let err = read_secret(&fifo).expect_err("a FIFO is not a secret file");
        assert!(
            err.to_string().contains("not a regular file"),
            "unexpected message: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457, Phase 8. Which explanations the verifier is entitled to give.
    ///
    /// `key_id` is an ordinary field of `audit.jsonl`. Before this, an
    /// unresolvable one produced a flat "This is not evidence of tampering",
    /// so editing one string moved an entry from exit 1 to exit 2 *and*
    /// bought an assertion of innocence — for free, with no key material.
    #[test]
    fn unresolvable_key_ids_are_classified_by_whether_a_writer_could_have_made_them() {
        assert!(is_writer_emitted_key_id("default"));
        assert!(is_writer_emitted_key_id("key-2"));
        assert!(is_writer_emitted_key_id("key-4294967295"));
        assert!(is_writer_emitted_key_id(UNRESOLVED_KEY_ID));

        // `key-1` is never written: epoch 1 is `"default"`.
        assert!(!is_writer_emitted_key_id("key-1"));
        assert!(!is_writer_emitted_key_id("key-0"));
        // Non-canonical decimals round-trip differently and are not ours.
        assert!(!is_writer_emitted_key_id("key-02"));
        assert!(!is_writer_emitted_key_id("key-2 "));
        assert!(!is_writer_emitted_key_id("key-+2"));
        assert!(!is_writer_emitted_key_id("key-99999999999999999999"));
        assert!(!is_writer_emitted_key_id(""));
        assert!(!is_writer_emitted_key_id("KEY-2"));

        // The remedy must name a file. There is no file called "default".
        let default_file = expected_key_file("default").expect("epoch 1 has a file");
        assert!(default_file.contains("audit-secret"));
        // #478: this used to pin `key-N` → `.{N-1}.retired`, which is the
        // defect, not the contract. `rotate_key_locked` renames the key it
        // displaces into `audit-secret.{max_retired + 1}.retired` and reports
        // it as `key-{max_retired + 1}`, so the two numbers are the same one.
        assert!(
            expected_key_file("key-3")
                .expect("epoch 3 has a file")
                .contains("audit-secret.3.retired"),
            "epoch N's key retires into slot N"
        );
        // Stated as an exclusion so the fix cannot be read as "any decimal now
        // gets a path": the slot below the one epoch 3 names must not appear.
        assert!(
            !expected_key_file("key-3")
                .expect("epoch 3 has a file")
                .contains("audit-secret.2.retired"),
            "epoch 3 must not be filed under epoch 2's slot"
        );
        // Agrees with `is_writer_emitted_key_id`, which rejects both: epoch 1
        // is `"default"`, and `.0.retired` is a slot the directory scan
        // refuses. A path here would name a file omamori would not read.
        assert!(expected_key_file("key-1").is_none());
        assert!(expected_key_file("key-0").is_none());
        assert!(expected_key_file("nonsense").is_none());
    }

    /// #457, Phase 8 QA. The writer-side sibling of the test above, and the
    /// one that was missing: that test only exercised the verifier, so the
    /// fail-closed branch on the *writing* side went out unmeasured.
    ///
    /// What it caught: the first version stamped `key_id: "default"` on
    /// entries written while the directory could not be listed, alongside
    /// `entry_hash: NO_HMAC_SECRET`. Once permissions came back, `"default"`
    /// resolved, the recomputed HMAC did not match the sentinel, and the entry
    /// read as **tampering** — permanently, since ADR-0007 forbids rewriting
    /// it. Measured against v0.16.0, which wrote a real HMAC here and reported
    /// `chain intact`: a regression, produced by the branch whose comment
    /// claimed it was avoiding exactly that outcome.
    ///
    /// `UNRESOLVED_KEY_ID` cannot be in any keyring, so the entry now lands in
    /// the cannot-verify terminal state with its real reason.
    #[test]
    #[cfg(unix)]
    fn an_unlistable_key_directory_does_not_make_the_writer_manufacture_tampering() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("457-unlistable-writer");
        let audit_path = dir.join("audit.jsonl");
        let config = AuditConfig {
            enabled: true,
            path: Some(audit_path.clone()),
            retention_days: 0,
            strict: false,
        };

        let logger = AuditLogger::from_config(&config).expect("logger constructs");
        logger.append(make_event("before")).unwrap();
        drop(logger);
        // Rotate first: on an unrotated store `"default"` and the active key
        // are the same bytes, so the mislabel would be invisible. The rotated
        // store is where `"default"` means `.1.retired` and the wrong label
        // becomes a tampering verdict.
        super::rotate_key(&audit_path).expect("rotation succeeds");

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o100)).unwrap();
        let blind = AuditLogger::from_config(&config).expect("logger still constructs");
        assert_eq!(
            blind.key_id(),
            UNRESOLVED_KEY_ID,
            "a key epoch that could not be determined must not be guessed at"
        );
        blind.append(make_event("written-blind")).unwrap();
        drop(blind);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let result = verify_chain(&config).expect("verification runs once the directory is back");
        assert!(
            result.broken_at.is_none(),
            "an entry omamori itself wrote without a key is not evidence of tampering; \
             broken_at = {:?}",
            result.broken_at
        );
        assert_eq!(
            result.key_unavailable_id.as_deref(),
            Some(UNRESOLVED_KEY_ID),
            "the entry must be reported under the id that says why it is unverifiable"
        );
        assert_eq!(
            result.key_unavailable_kind,
            Some(KeyUnavailableKind::NeverProtected),
            "and classified as never-protected, not as a key file the operator lost"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #477 (V-A16): a listing that stops partway is not a shorter listing —
    /// it is no listing at all.
    ///
    /// *Why* a partial listing is worse than a short one — what `std` does with
    /// a per-entry `Err`, and the 300-file measurement behind it — is on
    /// `fold_key_dir_entries`, next to the code it justifies. What this test
    /// adds is that it drives that seam directly rather than the filesystem: no
    /// condition producing a per-entry `Err` (removable volume, network
    /// filesystem, failing disk) can be provisioned by this suite, so without
    /// the seam the branch would ship untested.
    #[test]
    fn a_listing_that_stops_partway_is_unlistable_not_short() {
        use std::ffi::OsString;

        let dir = std::path::Path::new("/tmp/477-fold");
        let names =
            |v: Vec<std::io::Result<OsString>>| secret::fold_key_dir_entries(dir, v.into_iter());

        // Control: the same names, all `Ok`, list normally.
        let complete = names(vec![
            Ok(OsString::from("audit-secret.1.retired")),
            Ok(OsString::from("audit-secret.9.retired")),
        ]);
        let secret::KeyDirScan::Listed { retired, .. } = &complete else {
            panic!("a complete listing must list")
        };
        assert_eq!(
            secret::max_retired_index(retired),
            9,
            "a complete listing must report the highest epoch present"
        );

        // The same listing truncated before `.9` by an error. Pre-#477 this
        // reported 1, and rotation would have filed the current key into slot
        // 2 — while `.9.retired` sat unread on disk.
        let truncated = names(vec![
            Ok(OsString::from("audit-secret.1.retired")),
            Err(std::io::Error::from_raw_os_error(22)),
            Ok(OsString::from("audit-secret.9.retired")),
        ]);
        // Destructured rather than compared against a "no index" value: the
        // claim is that this is not a listing, and an assertion phrased as
        // `max_index() == None` would also pass for a listing that merely has
        // no retired keys in it.
        let secret::KeyDirScan::Unlistable(reason) = &truncated else {
            panic!("an interrupted listing must not be usable as a listing")
        };
        assert!(
            reason.contains("stopped after 1 entries"),
            "the reason must state where the listing stopped, not guess at why: {reason}"
        );

        // Failing on the first item is the same answer, not a special case:
        // "no entries were read" must still be unlistable rather than an empty
        // `Listed`, which is what a fresh install legitimately produces.
        let immediate = names(vec![Err(std::io::Error::from_raw_os_error(22))]);
        let secret::KeyDirScan::Unlistable(reason) = &immediate else {
            panic!("an error on the first entry is no listing either")
        };
        assert!(
            reason.contains("stopped after 0 entries"),
            "and it must not be confused with the empty directory a fresh install has"
        );
        // The errno is reported, never interpreted: the reachable macOS case is
        // EINVAL, not the EIO this was first predicted to be, and the two
        // platforms take different `ReadDir::next` bodies.
        assert!(
            !reason.contains("permission") && !reason.contains("Permission"),
            "the reason must not name a cause it did not observe: {reason}"
        );
    }

    /// #477 (V-A17): an unlistable directory yields an **empty** keyring, not a
    /// partial one.
    ///
    /// `verify` never observes this — `fatal_anomaly` stops it first — so
    /// `hash_cwd_candidates` is the only surface where the difference shows.
    /// Registering the active key here would mean naming it, and the only
    /// number available to name it with is the one the failed scan could not
    /// produce. An investigator would get candidates under a guessed epoch
    /// label, which is the forensic form of the mislabelling #457 closed for
    /// the writer.
    #[cfg(unix)]
    #[test]
    fn an_unlistable_key_directory_registers_no_keys_at_all() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("477-empty-ring");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.1.retired"), &[0x11u8; 32]);

        // Readable: both keys load, as a control for the assertion below.
        let ring = secret::load_keyring(&secret_path);
        assert!(!ring.is_empty(), "precondition: the ring loads normally");
        assert!(
            ring.fatal_anomaly().is_none(),
            "precondition: nothing is wrong yet"
        );

        // `0o300`, not the `0o100` the older unlistable fixtures in this module
        // use: write permission keeps `audit-secret.lock` creatable, so the
        // listing is the only thing that fails. At `0o100` the lock also fails
        // and there would be two conditions to tell apart.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();
        let ring = secret::load_keyring(&secret_path);
        let restored = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));

        assert!(
            ring.is_empty(),
            "an unlistable directory must not yield keys under a guessed epoch"
        );
        assert!(
            ring.fatal_anomaly().is_some(),
            "and it must still say why the ring is empty — an empty ring with no \
             anomaly is indistinguishable from a store with no keys"
        );
        restored.unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-b (V-016). A gap in the retired indices must not hide the keys
    /// beyond it. The old loop probed 1, 2, 3, … and stopped at the first
    /// miss, so a missing `.2` made `.3` unreachable — permanently
    /// unverifiable entries with the key sitting right there on disk.
    #[test]
    fn keyring_tolerates_a_gap_in_retired_indices() {
        let dir = test_dir("457-index-gap");
        let secret_path = dir.join("audit-secret");
        let epoch1 = [0x11u8; 32];
        let epoch3 = [0x33u8; 32];
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.1.retired"), &epoch1);
        write_key_file(&dir.join("audit-secret.3.retired"), &epoch3);

        let ring = load_keyring(&secret_path);
        assert_eq!(ring.get("key-1"), Some(&epoch1));
        assert_eq!(
            ring.get("key-3"),
            Some(&epoch3),
            "the key past the gap must still load"
        );
        assert_eq!(
            ring.get("default"),
            Some(&epoch1),
            "\"default\" is an alias for epoch 1, which is .1.retired once rotated"
        );
        assert_eq!(
            load_signing_key(&secret_path).id,
            "key-4",
            "the next id comes from the highest index, not from a count"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-a/P4-c (V-015). A gap in the indices used to make the next
    /// rotation destroy a key.
    ///
    /// With `.1` and `.3` present, the old count-based numbering said "two
    /// rotations so far, the next is `.3`" and `fs::rename` overwrote the
    /// existing `.3.retired` without a word. That key was the only copy; every
    /// entry from its epoch became permanently unverifiable, with nothing left
    /// on disk to explain why.
    ///
    /// Index-based numbering picks `.4` — above the highest present, so by
    /// construction free. The explicit `AlreadyExists` refusal in `rotate_key`
    /// remains as a backstop for a slot that becomes occupied between the scan
    /// and the rename.
    ///
    /// It used to be described as covering the failed-scan case as well, on the
    /// reasoning that a failed scan reads the highest index as 0 and reaches for
    /// `.1`. It never did: on a store missing its low epochs, `.1` is *free*, so
    /// the check passes and the guess lands. #477 closes that upstream instead —
    /// an unlistable directory is refused before any slot is chosen.
    #[test]
    fn rotation_after_a_gap_does_not_destroy_the_occupied_slot() {
        let dir = test_dir("457-gap-rotation");
        let audit_path = dir.join("audit.jsonl");
        let secret_path = dir.join("audit-secret");
        let epoch3 = [0x33u8; 32];
        write_key_file(&secret_path, &TEST_SECRET);
        write_key_file(&dir.join("audit-secret.1.retired"), &[0x11u8; 32]);
        write_key_file(&dir.join("audit-secret.3.retired"), &epoch3);

        let rotation = super::rotate_key(&audit_path).expect("rotation succeeds");

        assert_eq!(
            read_secret(&dir.join("audit-secret.3.retired")).unwrap(),
            epoch3,
            "the pre-existing retired key must survive the rotation"
        );
        assert_eq!(
            read_secret(&dir.join("audit-secret.4.retired")).unwrap(),
            TEST_SECRET,
            "the rotated-out key goes to the slot above the highest index"
        );
        assert_eq!(
            rotation.new_key_id, "key-5",
            "the new active key is named for the slot after the one just used"
        );

        // The freshly created active key must be a real, distinct key.
        let new_active = read_secret(&secret_path).expect("a new active key is created");
        assert_ne!(new_active, TEST_SECRET);

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-d. A FIFO at a key path makes `open(O_RDONLY)` block until
    /// someone writes to it — which would hang `verify` *and every hook
    /// append*, i.e. omamori silently stops protecting anything. The check is
    /// a `stat`, which never blocks.
    ///
    /// If this regresses, the test does not fail — it hangs. That is the
    /// failure mode being guarded, so there is no way to assert it more gently.
    #[test]
    fn fifo_at_a_key_path_is_rejected_instead_of_blocking() {
        let dir = test_dir("457-fifo");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);

        let fifo_path = dir.join("audit-secret.1.retired");
        let c_path = std::ffi::CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo must succeed for this test to mean anything");

        assert!(
            read_secret(&fifo_path).is_err(),
            "a FIFO is not a key file and must be rejected before opening"
        );

        // The ring still loads; the FIFO is reported rather than hung on.
        // Assert the anomaly *class* and the file it names — "non-empty" would
        // pass on any anomaly at all, including an unrelated one (test review
        // #5).
        let ring = load_keyring(&secret_path);
        let named: Vec<&str> = ring
            .anomalies()
            .iter()
            .filter_map(|a| match a {
                KeyringAnomaly::Unreadable { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        // #471: the full path, not the bare file name — `DirectoryUnreadable`
        // already named the directory it failed on, and the two read side by
        // side. Asserted as "absolute and ending in the name" rather than as a
        // literal, so the fixture's own temp path does not have to be spelled
        // out here.
        assert_eq!(named.len(), 1, "exactly one unreadable key file");
        assert!(
            named[0].starts_with('/') && named[0].ends_with("/audit-secret.1.retired"),
            "the FIFO must be reported as an unreadable key file, by full path — got: {named:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 (test review blind spot 5, shapes D19-D22). Every way a file can
    /// occupy a retired-key name without being a usable key must be reported
    /// rather than skipped: a directory, a file with the wrong content, and one
    /// the process cannot open. Each takes a different path out of
    /// `read_secret` (file-type check, hex decode, `open`), so a fix that
    /// covers one does not necessarily cover the others.
    #[cfg(unix)]
    #[test]
    fn unusable_retired_key_shapes_are_each_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("457-unusable-shapes");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);

        // D19: a directory where a key should be.
        fs::create_dir(dir.join("audit-secret.1.retired")).unwrap();
        // D21: right shape, wrong content.
        fs::write(dir.join("audit-secret.2.retired"), "not-hex").unwrap();
        // D22: unopenable.
        let unreadable = dir.join("audit-secret.3.retired");
        write_key_file(&unreadable, &[0x33u8; 32]);
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        // D20 (V-023): a symlink where a key should be. `read_secret` rejects
        // it before `open`, with the "possible attack" wording rather than the
        // generic not-a-regular-file one — a symlinked key is an attack shape,
        // not a mistake shape.
        let real = dir.join("real-key");
        write_key_file(&real, &[0x44u8; 32]);
        std::os::unix::fs::symlink(&real, dir.join("audit-secret.4.retired")).unwrap();

        let ring = load_keyring(&secret_path);
        let mut reported: Vec<&str> = ring
            .anomalies()
            .iter()
            .filter_map(|a| match a {
                KeyringAnomaly::Unreadable { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        reported.sort_unstable();
        // #471: full paths now (see the FIFO fixture above for why). Reduced to
        // file names here so the four-shape assertion stays readable — what it
        // pins is that none is dropped, and the path form is pinned once, over
        // there.
        let names: Vec<&str> = reported
            .iter()
            .map(|p| p.rsplit('/').next().unwrap_or(p))
            .collect();
        assert_eq!(
            names,
            vec![
                "audit-secret.1.retired",
                "audit-secret.2.retired",
                "audit-secret.3.retired",
                "audit-secret.4.retired",
            ],
            "all four unusable shapes must be named, not silently dropped"
        );
        assert!(
            reported.iter().all(|p| p.starts_with('/')),
            "and each must be named by full path — got: {reported:?}"
        );

        // The symlink specifically must carry the attack wording, not the
        // generic file-type rejection.
        let symlink_reason = ring
            .anomalies()
            .iter()
            .find_map(|a| match a {
                // #471: `name` is a full path now, so this selector matches on
                // the trailing component instead of the whole string.
                KeyringAnomaly::Unreadable { name, reason }
                    if name.ends_with("/audit-secret.4.retired") =>
                {
                    Some(reason.as_str())
                }
                _ => None,
            })
            .expect("the symlinked key must be reported");
        assert!(
            symlink_reason.contains("possible attack"),
            "a symlinked key file is an attack shape, not a mistake shape; got: {symlink_reason}"
        );

        // None of them registered a key, so nothing can be verified against a
        // partially-loaded ring while believing it is complete.
        assert!(ring.get("key-1").is_none());
        assert!(ring.get("key-2").is_none());
        assert!(ring.get("key-3").is_none());
        assert!(ring.get("key-4").is_none());

        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-d. `read_to_string` would materialize the whole file before the
    /// 64-character check could reject it.
    #[test]
    fn oversized_secret_file_is_rejected_before_reading() {
        let dir = test_dir("457-oversized");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);

        let big = dir.join("audit-secret.1.retired");
        fs::write(&big, "0".repeat(64 * 1024)).unwrap();

        let err = read_secret(&big).expect_err("an oversized file is not a key");
        assert!(
            format!("{err}").contains("expected at most"),
            "the error must name the limit, got: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #457 P4-b. Beyond the cap, the **newest** keys are the ones kept —
    /// dropping those would make the current epoch unverifiable, while the
    /// oldest keys are the ones whose entries are most likely already pruned.
    /// A `1..`-style loop that stopped at the cap would have done the reverse.
    #[test]
    fn keyring_cap_keeps_the_newest_keys_and_reports_the_truncation() {
        let dir = test_dir("457-keyring-cap");
        let secret_path = dir.join("audit-secret");
        write_key_file(&secret_path, &TEST_SECRET);

        let over = MAX_KEYRING_KEYS + 5;
        for n in 1..=over {
            let mut secret = [0u8; 32];
            secret[0] = (n % 251) as u8;
            secret[1] = (n / 251) as u8;
            write_key_file(&dir.join(format!("audit-secret.{n}.retired")), &secret);
        }

        let ring = load_keyring(&secret_path);
        assert!(
            ring.get(&format!("key-{over}")).is_some(),
            "the newest retired key must be loaded"
        );
        assert!(
            ring.get("key-1").is_none(),
            "the oldest keys are the ones dropped at the cap"
        );
        // Assert the class and its numbers, not just that *something* was
        // reported (test review #5).
        let truncation = ring
            .anomalies()
            .iter()
            .find_map(|a| match a {
                KeyringAnomaly::Truncated {
                    found,
                    loaded,
                    lowest_loaded_index,
                } => Some((*found, *loaded, *lowest_loaded_index)),
                _ => None,
            })
            .expect(
                "truncation must not be silent — a shorter keyring is a \
                 forensic false negative, not a smaller problem",
            );
        assert_eq!(truncation.0, over, "all retired keys are counted as found");
        assert_eq!(truncation.1, MAX_KEYRING_KEYS, "exactly the cap is loaded");
        assert_eq!(
            truncation.2,
            (over - MAX_KEYRING_KEYS + 1) as u32,
            "the lowest loaded index must be the oldest key that survived the cap"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_extra_deletion_after_prune() {
        let dir = test_dir("verify-extra-delete");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..100 {
            entries.push(("old", old_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        drop(file);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut tampered = String::new();
        tampered.push_str(lines[0]);
        tampered.push('\n');
        for line in &lines[2..] {
            tampered.push_str(line);
            tampered.push('\n');
        }
        fs::write(&path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "extra deletion after prune should be detected via target_hash binding"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_prune_replaces_existing_prune_point() {
        let dir = test_dir("re-prune");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let old_ts = "2025-01-01T00:00:00Z";
        let mid_ts = "2025-10-01T00:00:00Z";
        let new_ts = "2026-04-04T00:00:00Z";
        let mut entries: Vec<(&str, &str)> = Vec::new();
        for _ in 0..50 {
            entries.push(("old", old_ts));
        }
        for _ in 0..50 {
            entries.push(("mid", mid_ts));
        }
        for _ in 0..1100 {
            entries.push(("new", new_ts));
        }
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned1 = try_prune_at(
            &mut file,
            &test_signing_key(),
            90,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert_eq!(pruned1, 100, "should prune 50 old + 50 mid");
        drop(file);

        let result1 = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result1.broken_at.is_none(),
            "first prune chain should be intact"
        );
        assert!(result1.pruned);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock_exclusive(&file).unwrap();
        let pruned2 = try_prune_at(
            &mut file,
            &test_signing_key(),
            1,
            None,
            retention_test_now(),
        )
        .unwrap();
        assert!(pruned2 <= 100, "second prune should respect min retain");
        drop(file);

        let result2 = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result2.broken_at.is_none(),
            "re-pruned chain should still be intact"
        );
        assert!(result2.pruned);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_prune_point_only() {
        let dir = test_dir("verify-prune-only");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let prune = build_prune_point(&test_signing_key(), 50, "", retention_test_now());
        let content = serde_json::to_string(&prune).unwrap() + "\n";
        fs::write(&path, content).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(result.broken_at.is_none(), "prune_point alone should be OK");
        assert!(result.pruned);
        assert_eq!(result.chain_entries, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_head_deletion_without_prune_point() {
        let dir = test_dir("verify-head-delete");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let ts = "2026-04-04T00:00:00Z";
        let entries: Vec<(&str, &str)> = (0..5).map(|_| ("cmd", ts)).collect();
        write_chain_entries(&path, &TEST_SECRET, &entries, 1);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let tampered = lines[1..].join("\n") + "\n";
        fs::write(&path, tampered).unwrap();

        let result = verify_chain(&verify_config(&dir)).unwrap();
        assert!(
            result.broken_at.is_some(),
            "head deletion without prune_point = chain broken"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_prune_separator() {
        let dir = test_dir("show-prune-sep");
        test_logger(&dir);
        let path = dir.join("audit.jsonl");

        let prune = build_prune_point(&test_signing_key(), 42, "hash123", retention_test_now());
        let mut content = serde_json::to_string(&prune).unwrap() + "\n";

        let ts = "2026-04-04T00:00:00Z";
        let refs: Vec<(&str, &str)> = vec![("ls", ts), ("cat", ts)];
        let genesis = genesis_hash(Some(&TEST_SECRET));
        let mut prev_hash = genesis;
        for (seq, (cmd, ts)) in refs.iter().enumerate() {
            let mut event = make_event_with_timestamp(cmd, ts);
            event.chain_version = Some(CHAIN_VERSION);
            event.seq = Some(seq as u64);
            event.prev_hash = Some(prev_hash.clone());
            event.key_id = Some("default".to_string());
            event.entry_hash = Some(compute_entry_hash_for_write(Some(&TEST_SECRET), &event));
            prev_hash = event.entry_hash.clone().unwrap();
            content.push_str(&serde_json::to_string(&event).unwrap());
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        show_entries(&verify_config(&dir), &opts, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("--- pruned 42 entries"),
            "should show prune separator, got:\n{output}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_validate_clamps_retention() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 3,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, MIN_RETENTION_DAYS);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn config_validate_zero_unchanged() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, 0);
        assert!(warnings.is_empty());
    }

    #[test]
    fn config_validate_valid_retention_unchanged() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 90,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.retention_days, 90);
        assert!(warnings.is_empty());
    }

    // -----------------------------------------------------------------
    // AuditConfig::validate() — relative `audit.path` normalization (#439)
    // -----------------------------------------------------------------

    #[test]
    fn config_validate_keeps_absolute_path() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("/var/log/omamori/audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(
            validated.path,
            Some(PathBuf::from("/var/log/omamori/audit.jsonl"))
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn config_validate_empty_path_cleared_with_warning() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("")),
            retention_days: 0,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.path, None);
        // Phase 8 QA+UX (independently converged): must not render as
        // confusing empty backticks (`audit.path `` is not...`).
        assert!(
            warnings.iter().any(|w| w.contains("<empty>")),
            "empty path should render as `<empty>`, not blank backticks: {warnings:?}"
        );
    }

    #[test]
    fn config_validate_relative_path_control_chars_sanitized() {
        // Phase 8 Security finding: config.path is attacker-controlled
        // (config.toml is explicitly AI-editable) and must not be
        // interpolated raw into a terminal warning — an ANSI/control-
        // character payload must not survive into the warning text.
        let hostile = format!("\u{1b}[2Ksneaky{}payload", '\u{7}');
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from(&hostile)),
            retention_days: 0,
            strict: false,
        };
        let (validated, warnings) = config.validate();
        assert_eq!(validated.path, None);
        assert!(
            warnings
                .iter()
                .all(|w| !w.contains('\u{1b}') && !w.contains('\u{7}')),
            "warning must not carry raw control characters through: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("sneaky") && w.contains("payload")),
            "warning should still show the sanitized (non-control) parts of the value: {warnings:?}"
        );
    }

    #[test]
    fn config_validate_relative_boundary_paths_all_cleared() {
        // `/simplify` finding: this loop subsumes the single-case
        // `"audit.jsonl"` test that used to sit next to it — same
        // assertions (cleared + warning content), one fewer near-duplicate
        // test.
        for relative in [
            "audit.jsonl",
            ".",
            "..",
            "sub/x",
            "./audit.jsonl",
            "../audit.jsonl",
        ] {
            let config = AuditConfig {
                enabled: true,
                path: Some(PathBuf::from(relative)),
                retention_days: 0,
                strict: false,
            };
            let (validated, warnings) = config.validate();
            assert_eq!(validated.path, None, "expected `{relative}` to be cleared");
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains("audit.path") && w.contains("is not an absolute path")),
                "expected a warning naming audit.path for relative path `{relative}`, got: {warnings:?}"
            );
        }
    }

    #[test]
    fn config_validate_is_idempotent_on_already_normalized_path() {
        // A config that already went through validate() once (path == None)
        // must not re-warn or otherwise misbehave on a second pass — this is
        // what `AuditLogger::from_config`'s internal re-validate relies on.
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let (once, warnings_once) = config.validate();
        let (twice, warnings_twice) = once.validate();
        assert_eq!(twice.path, None);
        assert!(warnings_once.is_empty());
        assert!(warnings_twice.is_empty());
    }

    #[test]
    fn summary_includes_retention() {
        let dir = test_dir("summary-retention");
        let logger = test_logger_with_retention(&dir, 90);
        logger.append(make_event("ls")).unwrap();

        let mut config = verify_config(&dir);
        config.retention_days = 90;
        let summary = audit_summary(&config);
        assert_eq!(summary.retention_days, 90);
        let _ = fs::remove_dir_all(&dir);
    }

    // --- O_NOFOLLOW: symlink rejection ---

    #[cfg(unix)]
    #[test]
    fn append_rejects_symlink_audit_log() {
        let dir = test_dir("symlink-audit-log");
        let real_path = dir.join("real-audit.jsonl");
        fs::write(&real_path, "").unwrap();
        let symlink_path = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        let secret_file = dir.join("audit-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&secret_file, &hex).unwrap();

        let logger = AuditLogger {
            path: symlink_path,
            signing_key: SigningKey::for_test("default", Some(TEST_SECRET)),
            retention_days: 0,
        };
        let err = logger.append(make_event("ls")).unwrap_err();
        assert!(
            // See the note on the other symlink fixtures: the path is in the
            // message, so matching "symlink" would match the directory name.
            err.to_string().contains("possible attack"),
            "expected the symlink/possible-attack error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_rejects_symlink() {
        let dir = test_dir("symlink-secret-read");
        let real_secret = dir.join("real-secret");
        let hex: String = TEST_SECRET.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&real_secret, &hex).unwrap();
        let symlink_secret = dir.join("audit-secret");
        std::os::unix::fs::symlink(&real_secret, &symlink_secret).unwrap();

        let err = read_secret(&symlink_secret).unwrap_err();
        // Match on "possible attack", not on "symlink": the error text embeds
        // the path, and `test_dir("symlink-secret-read")` puts the word
        // "symlink" in that path — so a `contains("symlink")` assertion passes
        // no matter what the error actually says. It did exactly that when
        // #457's file-type pre-check briefly replaced this error with a
        // generic "not a regular file" (caught in Codex review, not by this
        // test). "possible attack" appears only in the intended message.
        assert!(
            err.to_string().contains("possible attack"),
            "expected the symlink/possible-attack error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_secret_rejects_existing_symlink() {
        let dir = test_dir("symlink-secret-create");
        let real_secret = dir.join("real-secret");
        fs::write(&real_secret, "placeholder").unwrap();
        let symlink_secret = dir.join("audit-secret");
        std::os::unix::fs::symlink(&real_secret, &symlink_secret).unwrap();

        let err = create_secret(&symlink_secret).unwrap_err();
        assert!(
            // `create_new(true)` may report `AlreadyExists` before the
            // O_NOFOLLOW path is reached, so both outcomes are legitimate here.
            // The text arm matches "possible attack" rather than "symlink" for
            // the same reason as the other fixtures — the directory name
            // contains "symlink".
            err.to_string().contains("possible attack")
                || err.kind() == std::io::ErrorKind::AlreadyExists,
            "expected the symlink/possible-attack or AlreadyExists error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn verify_chain_rejects_symlink() {
        let dir = test_dir("symlink-verify");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        // #471: this arrived as `AuditError::Io` before, which
        // `aggregate_report` mapped to `ChainStatus::Unavailable` — so the one
        // state here that is evidence of an attack was also the one `doctor`
        // said nothing about. The wording assertion is unchanged; what is new
        // is that the variant carries a `kind`, and that `kind` is what stops
        // this landing in the quiet bucket.
        match verify_chain(&config) {
            Err(AuditError::StoreInaccessible { kind, reason }) => {
                assert_eq!(kind, "log_symlink");
                assert!(
                    // "possible attack", not "symlink": these fixtures use
                    // `test_dir` names containing the word "symlink", and the
                    // error embeds the path — so `contains("symlink")` passes
                    // regardless of what the error says. Found by same-class
                    // scan after Codex Round 1 flagged the same defect in
                    // `read_secret_rejects_symlink` (#457).
                    reason.contains("possible attack"),
                    "expected the symlink/possible-attack error, got: {reason}"
                );
            }
            Err(other) => panic!("expected StoreInaccessible, got: {other}"),
            Ok(_) => panic!("expected error for symlink path"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn show_entries_rejects_symlink() {
        let dir = test_dir("symlink-show");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        let opts = ShowOptions {
            last: None,
            rule: None,
            provider: None,
            json: false,
            action: None,
            relaxed_only: false,
        };
        let mut buf = Vec::new();
        let err = show_entries(&config, &opts, &mut buf).unwrap_err();
        match err {
            AuditError::Io(e) => assert!(
                // "possible attack", not "symlink": these fixtures use
                // `test_dir` names containing the word "symlink", and the error
                // embeds the path — so `contains("symlink")` passes regardless
                // of what the error says. Found by same-class scan after Codex
                // Round 1 flagged the same defect in
                // `read_secret_rejects_symlink` (#457).
                e.to_string().contains("possible attack"),
                "expected the symlink/possible-attack error, got: {e}"
            ),
            other => panic!("expected Io error, got: {other}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn audit_summary_symlink_sets_path_error() {
        let dir = test_dir("symlink-summary");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_path = dir.join("real-audit.jsonl");
        fs::rename(&logger.path, &real_path).unwrap();
        std::os::unix::fs::symlink(&real_path, &logger.path).unwrap();

        let config = verify_config(&dir);
        let summary = audit_summary(&config);
        assert_eq!(summary.entry_count, 0);
        assert!(
            summary
                .path_error
                .as_ref()
                .is_some_and(|e| e.contains("symlink")),
            "expected path_error with 'symlink', got: {:?}",
            summary.path_error
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_summary_no_file_no_path_error() {
        let dir = test_dir("summary-nofile");
        let config = verify_config(&dir);
        let summary = audit_summary(&config);
        assert_eq!(summary.entry_count, 0);
        assert!(summary.path_error.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- O_NOFOLLOW: normal (non-symlink) paths still work ---

    #[test]
    fn normal_path_append_works_with_nofollow() {
        let dir = test_dir("nofollow-normal");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();
        logger.append(make_event("cat")).unwrap();

        let events = read_events(&logger.path);
        assert_eq!(events.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn normal_path_verify_works_with_nofollow() {
        let dir = test_dir("nofollow-verify");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let config = verify_config(&dir);
        let result = verify_chain(&config).unwrap();
        assert_eq!(result.chain_entries, 1);
        assert!(result.broken_at.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // --- strict mode: secret_available ---

    #[test]
    fn secret_available_true_when_secret_present() {
        let dir = test_dir("strict-avail-true");
        let logger = test_logger(&dir);
        assert!(logger.secret_available());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_available_false_when_secret_absent() {
        let dir = test_dir("strict-avail-false");
        let logger = AuditLogger {
            path: dir.join("audit.jsonl"),
            signing_key: SigningKey::for_test("default", None),
            retention_days: 0,
        };
        assert!(!logger.secret_available());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn strict_config_parses_from_default() {
        let config = AuditConfig::default();
        assert!(!config.strict, "strict should default to false");
    }

    #[test]
    fn strict_config_deserializes_true() {
        let toml_str = r#"
            enabled = true
            strict = true
        "#;
        let config: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(config.strict);
    }

    #[test]
    fn strict_config_deserializes_absent_as_false() {
        let toml_str = r#"
            enabled = true
        "#;
        let config: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.strict);
    }

    // --- verify_chain: secret symlink ELOOP propagation ---

    #[cfg(unix)]
    #[test]
    fn verify_chain_secret_symlink_is_reported_as_inaccessible() {
        let dir = test_dir("verify-secret-symlink");
        let logger = test_logger(&dir);
        logger.append(make_event("ls")).unwrap();

        let real_secret = dir.join("real-secret");
        let secret_path = dir.join("audit-secret");
        fs::rename(&secret_path, &real_secret).unwrap();
        std::os::unix::fs::symlink(&real_secret, &secret_path).unwrap();

        let config = verify_config(&dir);
        // #471: this arrived as `AuditError::Io` before, which
        // `aggregate_report` mapped to `ChainStatus::Unavailable` — so the one
        // state here that is evidence of an attack was also the one `doctor`
        // said nothing about. The wording assertion is unchanged; what is new
        // is that the variant carries a `kind`, and that `kind` is what stops
        // this landing in the quiet bucket.
        match verify_chain(&config) {
            Err(AuditError::StoreInaccessible { kind, reason }) => {
                assert_eq!(kind, "secret_symlink");
                assert!(
                    // "possible attack", not "symlink": these fixtures use
                    // `test_dir` names containing the word "symlink", and the
                    // error embeds the path — so `contains("symlink")` passes
                    // regardless of what the error says. Found by same-class
                    // scan after Codex Round 1 flagged the same defect in
                    // `read_secret_rejects_symlink` (#457).
                    reason.contains("possible attack"),
                    "expected the symlink/possible-attack error, got: {reason}"
                );
            }
            Err(other) => panic!("expected StoreInaccessible, got: {other}"),
            Ok(_) => panic!("expected error for symlink secret"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // --- GR-002: HashableEvent serialization order golden test (T9 guardrail) ---

    #[test]
    fn hashable_event_serialization_order_is_stable() {
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test-provider".to_string(),
            command: "rm -rf /".to_string(),
            rule_id: Some("test-rule".to_string()),
            action: "block".to_string(),
            result: "blocked".to_string(),
            target_count: 1,
            target_hash: "abc123".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: Some(1),
            seq: Some(42),
            prev_hash: Some("prev000".to_string()),
            key_id: Some("default".to_string()),
            entry_hash: None,
            pid: None,
            ppid: None,
            parent_process: None,
            cwd_hash: None,
            wrapper_kind: None,
        };
        let json = serde_json::to_string(&HashableEvent::from_event(&event)).unwrap();

        let expected = concat!(
            r#"{"chain_version":1,"seq":42,"prev_hash":"prev000","key_id":"default","#,
            r#""timestamp":"2026-01-01T00:00:00Z","provider":"test-provider","#,
            r#""command":"rm -rf /","rule_id":"test-rule","action":"block","#,
            r#""result":"blocked","target_count":1,"target_hash":"abc123","#,
            r#""detection_layer":"layer1","unwrap_chain":null,"raw_input_hash":null}"#,
        );
        assert_eq!(
            json, expected,
            "HashableEvent (V1) field order has changed! This WILL break verify_chain on all \
            existing audit.jsonl files. V1 is frozen — never edit this expectation. A new \
            chain_version gets a new HashableEventVn + its own golden test (see GR-002-V2)."
        );
    }

    // --- GR-002-V2: HashableEventV2 serialization order golden test (#177 B3) ---

    /// #177 B3: mirrors GR-002 above for `chain_version: 2`. The 5 new
    /// fields (`pid`/`ppid`/`parent_process`/`cwd_hash`/`wrapper_kind`) are
    /// pairwise same-typed (`Option<u32>` × 2, `Option<String>` × 3) —
    /// deliberately given 5 *distinct*, non-`None` values here (never all
    /// `None`) so a field-swap bug in `HashableEventV2::from_event` (e.g.
    /// `ppid: event.pid`) shows up as a JSON diff instead of silently
    /// passing (shape enumeration T-05, architect subagent finding).
    #[test]
    fn hashable_event_v2_serialization_order_is_stable() {
        let event = AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            provider: "test-provider".to_string(),
            command: "rm -rf /".to_string(),
            rule_id: Some("test-rule".to_string()),
            action: "block".to_string(),
            result: "blocked".to_string(),
            target_count: 1,
            target_hash: "abc123".to_string(),
            detection_layer: Some("layer1".to_string()),
            unwrap_chain: None,
            raw_input_hash: None,
            chain_version: Some(2),
            seq: Some(42),
            prev_hash: Some("prev000".to_string()),
            key_id: Some("default".to_string()),
            entry_hash: None,
            pid: Some(4242),
            ppid: Some(1717),
            parent_process: Some("/bin/parent".to_string()),
            cwd_hash: Some("cwdhash".to_string()),
            wrapper_kind: Some("env".to_string()),
        };
        let json = serde_json::to_string(&HashableEventV2::from_event(&event)).unwrap();

        let expected = concat!(
            r#"{"chain_version":2,"seq":42,"prev_hash":"prev000","key_id":"default","#,
            r#""timestamp":"2026-01-01T00:00:00Z","provider":"test-provider","#,
            r#""command":"rm -rf /","rule_id":"test-rule","action":"block","#,
            r#""result":"blocked","target_count":1,"target_hash":"abc123","#,
            r#""detection_layer":"layer1","unwrap_chain":null,"raw_input_hash":null,"#,
            r#""pid":4242,"ppid":1717,"parent_process":"/bin/parent","#,
            r#""cwd_hash":"cwdhash","wrapper_kind":"env"}"#,
        );
        assert_eq!(
            json, expected,
            "HashableEventV2 field order has changed! This WILL break verify_chain on all \
            existing v2 audit.jsonl entries. If intentional, this is itself a new \
            chain_version (3) and needs its own HashableEventV3 + golden test — never repurpose \
            this one."
        );
    }

    /// #177 B3: proves each of the 5 new V2-only fields is actually
    /// included in the hash — not just present in the struct definition.
    /// Mutation-tested by construction: for each field, two events that
    /// differ ONLY in that field must hash differently.
    #[test]
    fn hash_v2_includes_all_five_new_fields() {
        fn base_event() -> AuditEvent {
            let mut e = make_event("cmd0");
            e.chain_version = Some(2);
            e.seq = Some(0);
            e.prev_hash = Some("genesis".to_string());
            e.key_id = Some("default".to_string());
            e
        }

        let baseline = base_event();
        let baseline_hash = compute_entry_hash(Some(&TEST_SECRET), &baseline).expect_hash("base");

        let mut varied = base_event();
        varied.pid = Some(999);
        assert_ne!(
            compute_entry_hash(Some(&TEST_SECRET), &varied).expect_hash("pid"),
            baseline_hash,
            "pid must be part of the V2 hash"
        );

        let mut varied = base_event();
        varied.ppid = Some(999);
        assert_ne!(
            compute_entry_hash(Some(&TEST_SECRET), &varied).expect_hash("ppid"),
            baseline_hash,
            "ppid must be part of the V2 hash"
        );

        let mut varied = base_event();
        varied.parent_process = Some("/bin/other".to_string());
        assert_ne!(
            compute_entry_hash(Some(&TEST_SECRET), &varied).expect_hash("parent_process"),
            baseline_hash,
            "parent_process must be part of the V2 hash"
        );

        let mut varied = base_event();
        varied.cwd_hash = Some("other-cwd-hash".to_string());
        assert_ne!(
            compute_entry_hash(Some(&TEST_SECRET), &varied).expect_hash("cwd_hash"),
            baseline_hash,
            "cwd_hash must be part of the V2 hash"
        );

        let mut varied = base_event();
        varied.wrapper_kind = Some("sudo".to_string());
        assert_ne!(
            compute_entry_hash(Some(&TEST_SECRET), &varied).expect_hash("wrapper_kind"),
            baseline_hash,
            "wrapper_kind must be part of the V2 hash"
        );
    }

    /// #177 B3: `chain_version` sits first in both `HashableEvent` and
    /// `HashableEventV2`'s preimage, so a V1 and a V2 event that are
    /// otherwise identical (same seq/prev_hash/timestamp/etc., V2's 5 extra
    /// fields all `None`) must never hash to the same value — the version
    /// tag itself acts as a domain separator. Without this, a downgrade
    /// forgery (rewrite `chain_version: 2` to `1` on a real V2 entry, or
    /// vice versa) could theoretically collide.
    #[test]
    fn v1_and_v2_hashes_never_collide_for_equivalent_events() {
        let mut v1_event = make_event("cmd0");
        v1_event.chain_version = Some(1);
        v1_event.seq = Some(0);
        v1_event.prev_hash = Some("genesis".to_string());
        v1_event.key_id = Some("default".to_string());

        let mut v2_event = v1_event.clone();
        v2_event.chain_version = Some(2);

        let v1_hash = compute_entry_hash(Some(&TEST_SECRET), &v1_event).expect_hash("v1");
        let v2_hash = compute_entry_hash(Some(&TEST_SECRET), &v2_event).expect_hash("v2");
        assert_ne!(
            v1_hash, v2_hash,
            "V1 and V2 preimages must never collide even for field-identical events"
        );
    }

    /// #177 B3 (/simplify, 4-way convergent finding): `SUPPORTED_CHAIN_VERSIONS`
    /// (chain.rs) and `compute_entry_hash`'s literal `match` arms are two
    /// independently-maintained lists of the same versions — a future
    /// bump that adds a version to one without the other would let
    /// `read_chain_state`/`verify_chain` treat it as safe to
    /// append-after/authenticate while `compute_entry_hash` still reports
    /// `UnsupportedVersion`. Closes that split at test time: every version
    /// the array claims support for must actually produce a hash.
    #[test]
    fn all_supported_chain_versions_produce_a_hash() {
        for version in SUPPORTED_CHAIN_VERSIONS {
            let mut event = make_event("cmd0");
            event.chain_version = Some(version);
            event.seq = Some(0);
            event.prev_hash = Some("genesis".to_string());
            event.key_id = Some("default".to_string());
            match compute_entry_hash(Some(&TEST_SECRET), &event) {
                RecomputedHash::Hash(_) => {}
                other => panic!(
                    "SUPPORTED_CHAIN_VERSIONS claims {version} is supported, but \
                     compute_entry_hash returned {other:?} instead of Hash(_) — \
                     the array and the hasher match arms have drifted apart"
                ),
            }
        }
    }

    /// Codex test-adversarial review (#177 B2): `AuditEvent.wrapper_kind`
    /// was deliberately typed `Option<String>` rather than
    /// `Option<&'static str>` specifically so it can survive a real
    /// Serialize→Deserialize round trip (reading `audit.jsonl` back) —
    /// that specific claim had no test.
    #[test]
    fn wrapper_kind_survives_json_round_trip() {
        let mut event = make_event("cmd0");
        event.wrapper_kind = Some("env".to_string());

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains(r#""wrapper_kind":"env""#),
            "wrapper_kind must serialize as a plain string field — got: {json}"
        );

        let round_tripped: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(
            round_tripped.wrapper_kind,
            Some("env".to_string()),
            "wrapper_kind must survive a full Serialize -> Deserialize round trip"
        );
    }

    /// Codex test-adversarial review (#177 B2): `wrapper_kind: None` must
    /// be omitted from JSON entirely (`skip_serializing_if`), matching
    /// every other `Option` field on `AuditEvent`, and must round-trip
    /// back to `None` rather than an empty string or explicit null.
    #[test]
    fn wrapper_kind_none_is_omitted_and_round_trips_to_none() {
        let event = make_event("cmd0"); // wrapper_kind: None by default
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("wrapper_kind"),
            "wrapper_kind: None must be omitted from JSON, not serialized as null — got: {json}"
        );

        let round_tripped: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.wrapper_kind, None);
    }

    #[test]
    fn hwm_bootstrap_on_pre_hwm_chain() {
        let dir = test_dir("hwm-bootstrap");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        // Remove HWM to simulate a pre-HWM chain
        let hwm_file = hwm_path_for(&logger.path);
        let _ = fs::remove_file(&hwm_file);
        assert!(!hwm_file.exists());

        let result = verify::verify_chain(&verify_config(&dir)).expect("verify must succeed");
        assert!(!result.tail_truncated, "no truncation on bootstrap");
        assert!(result.hwm_missing, "hwm_missing flag should be set");

        // HWM should be bootstrapped
        assert!(hwm_file.exists(), "HWM bootstrapped by verify");
        let hwm = expect_hwm(&hwm_file);
        assert_eq!(hwm, 2, "bootstrapped to max seq");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Malformed HWM content is tamper evidence, not a fresh install — it
    /// must NOT be collapsed into the same `hwm_missing` bucket as a
    /// genuinely absent HWM file. The chain is still re-bootstrapped so the
    /// tool keeps functioning, but the distinction is surfaced separately.
    #[test]
    fn hwm_malformed_treated_as_tampered() {
        let dir = test_dir("hwm-malformed");
        let logger = test_logger(&dir);

        for i in 0..3 {
            logger.append(make_event(&format!("cmd{i}"))).unwrap();
        }

        let hwm_file = hwm_path_for(&logger.path);
        fs::write(&hwm_file, "not-a-number").unwrap();

        let result = verify::verify_chain(&verify_config(&dir)).expect("verify must succeed");
        assert!(!result.tail_truncated);
        assert!(
            !result.hwm_missing,
            "malformed HWM is tamper evidence, not a fresh install"
        );
        assert!(
            result.hwm_tampered,
            "malformed HWM should be flagged as tampered"
        );

        // Still re-bootstrapped so the tool keeps functioning.
        let hwm = expect_hwm(&hwm_file);
        assert_eq!(hwm, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    /// A symlinked HWM path must be rejected on write, not followed — an
    /// attacker-controlled symlink target must never be truncated/written.
    /// The append() path must distinguish tampered HWM from missing HWM,
    /// not just verify()'s self-heal — both call sites route through the
    /// same read_hwm(), so both must handle all three states.
    #[test]
    fn append_treats_malformed_hwm_as_tampered_and_rebootstraps() {
        let dir = test_dir("append-hwm-tampered");
        let logger = test_logger(&dir);

        logger.append(make_event("cmd0")).unwrap();

        let hwm_file = hwm_path_for(&logger.path);
        fs::write(&hwm_file, "not-a-number").unwrap();
        assert!(matches!(read_hwm(&hwm_file), HwmState::Tampered));

        // A subsequent append must re-bootstrap the HWM rather than error
        // or leave it tampered.
        logger.append(make_event("cmd1")).unwrap();

        match read_hwm(&hwm_file) {
            HwmState::Valid(v) => assert_eq!(v, 1, "HWM should advance to the new seq"),
            HwmState::Missing => panic!("HWM should not be Missing after append re-bootstraps it"),
            HwmState::Tampered => {
                panic!("HWM should not still be Tampered after append re-bootstraps it")
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_hwm_rejects_symlink() {
        let dir = test_dir("write-hwm-symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("attacker-target");
        fs::write(&target, "do-not-touch").unwrap();
        let hwm_file = dir.join("audit.jsonl.hwm");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &hwm_file).unwrap();

        let err = write_hwm(&hwm_file, 99).expect_err("write_hwm must reject a symlinked path");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "do-not-touch",
            "symlink target must not be modified"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Reading a symlinked HWM must report `Tampered`, not follow the link
    /// and return whatever value the attacker placed at the target.
    #[test]
    fn read_hwm_symlink_is_tampered() {
        let dir = test_dir("read-hwm-symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("forged-value");
        fs::write(&target, "999").unwrap();
        let hwm_file = dir.join("audit.jsonl.hwm");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &hwm_file).unwrap();

        assert!(matches!(read_hwm(&hwm_file), HwmState::Tampered));

        let _ = fs::remove_dir_all(&dir);
    }

    /// A stale `.tmp` file left over from a prior crash (create-then-crash
    /// before rename) must not permanently block future HWM writes.
    #[test]
    fn write_hwm_removes_stale_temp() {
        let dir = test_dir("write-hwm-stale-temp");
        fs::create_dir_all(&dir).unwrap();
        let hwm_file = dir.join("audit.jsonl.hwm");
        let temp_file = dir.join("audit.jsonl.hwm.tmp");
        fs::write(&temp_file, "leftover-from-a-crash").unwrap();

        write_hwm(&hwm_file, 7).expect("stale temp must not block a fresh write");
        assert!(matches!(read_hwm(&hwm_file), HwmState::Valid(7)));

        let _ = fs::remove_dir_all(&dir);
    }

    /// The HWM file must keep 0600 permissions through the temp+rename path.
    #[cfg(unix)]
    #[test]
    fn write_hwm_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("write-hwm-permissions");
        fs::create_dir_all(&dir).unwrap();
        let hwm_file = dir.join("audit.jsonl.hwm");

        write_hwm(&hwm_file, 1).unwrap();
        let mode = fs::metadata(&hwm_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    /// A torn write (crash between create and rename) must never leave an
    /// empty or partial HWM in place of a previously-valid one — the old
    /// value survives untouched because rename is atomic.
    #[test]
    fn write_hwm_atomic_no_partial_state() {
        let dir = test_dir("write-hwm-atomic");
        fs::create_dir_all(&dir).unwrap();
        let hwm_file = dir.join("audit.jsonl.hwm");

        write_hwm(&hwm_file, 1).unwrap();
        assert!(matches!(read_hwm(&hwm_file), HwmState::Valid(1)));

        // Simulate a crash after the temp file is created but before rename:
        // the temp exists, the real HWM path is untouched.
        let temp_file = dir.join("audit.jsonl.hwm.tmp");
        fs::write(&temp_file, "2").unwrap();
        assert!(
            matches!(read_hwm(&hwm_file), HwmState::Valid(1)),
            "old value must survive an interrupted write"
        );

        // A subsequent successful write cleans up the stale temp and publishes atomically.
        write_hwm(&hwm_file, 2).unwrap();
        assert!(matches!(read_hwm(&hwm_file), HwmState::Valid(2)));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_status_truncated_serialization() {
        let status = crate::audit::report::ChainStatus::Truncated;
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["status"], "truncated");
        assert_eq!(status.as_str(), "truncated");
    }

    // -----------------------------------------------------------------
    // resolved_audit_path() reroute (#306): explicit config.path always
    // wins; the default fires only through `context::data_dir()`, which
    // fails closed on an unusable HOME rather than falling back to CWD
    // (the pre-#371 `secret::default_audit_path()` CWD fallback this
    // reroute bypasses — that function has since been deleted entirely).
    // -----------------------------------------------------------------

    use crate::test_support::with_home;

    #[test]
    #[serial_test::serial(home_env)]
    fn resolved_audit_path_matches_data_dir_when_home_absolute() {
        // Happy-path pin: with an absolute HOME, the default resolves to
        // exactly `$HOME/.local/share/omamori/audit.jsonl` — the same
        // location the pre-#371 `secret::default_audit_path()` used before
        // this reroute existed (and before that function was deleted).
        // Guards against `resolved_audit_path` accidentally being wired to
        // `context::home_dir()` directly (which would move audit.jsonl for
        // every user with a normal, working HOME).
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let result = with_home(Some("/tmp/omamori-resolved-audit-path-test"), || {
            resolved_audit_path(&config)
        });
        assert_eq!(
            result,
            Some(PathBuf::from(
                "/tmp/omamori-resolved-audit-path-test/.local/share/omamori/audit.jsonl"
            ))
        );
    }

    #[test]
    fn resolved_audit_path_prefers_explicit_config_path() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("/explicit/audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert_eq!(
            resolved_audit_path(&config),
            Some(PathBuf::from("/explicit/audit.jsonl"))
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn resolved_audit_path_none_when_no_override_and_home_unusable() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        assert_eq!(with_home(Some(""), || resolved_audit_path(&config)), None);
        assert_eq!(with_home(None, || resolved_audit_path(&config)), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn from_config_none_when_no_override_and_home_unusable() {
        let config = AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        assert!(
            with_home(Some(""), || AuditLogger::from_config(&config)).is_none(),
            "logger creation must fail closed (unavailable), not write into CWD"
        );
    }

    // -----------------------------------------------------------------
    // Relative `audit.path` override — CWD-scatter hazard closure (#439)
    // -----------------------------------------------------------------

    #[test]
    #[serial_test::serial(home_env)]
    fn resolved_audit_path_ignores_relative_override_falls_through_to_home_default() {
        // The second-layer defense-in-depth filter in `resolved_audit_path`
        // itself: even an unvalidated config carrying a relative override
        // must not be honored verbatim — it must fall through to the same
        // HOME-derived default as an unset override.
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let result = with_home(Some("/tmp/omamori-relative-audit-path-test"), || {
            resolved_audit_path(&config)
        });
        assert_eq!(
            result,
            Some(PathBuf::from(
                "/tmp/omamori-relative-audit-path-test/.local/share/omamori/audit.jsonl"
            )),
            "relative override must be dropped and the HOME default used, not resolved against CWD"
        );
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn resolved_audit_path_none_when_relative_override_and_home_unusable() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert_eq!(with_home(Some(""), || resolved_audit_path(&config)), None);
        assert_eq!(with_home(None, || resolved_audit_path(&config)), None);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn from_config_relative_override_falls_through_to_home_default() {
        // End-to-end proof through the real choke point (`validate()` runs
        // inside `from_config`): a relative override must still produce a
        // working logger anchored under HOME, never under the process CWD.
        let home = test_dir("v439-relpath-home");
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        let logger = with_home(home.to_str(), || AuditLogger::from_config(&config))
            .expect("relative override + usable HOME must still produce a working logger");
        assert_eq!(logger.path, home.join(".local/share/omamori/audit.jsonl"));

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn from_config_none_when_relative_override_and_home_unusable() {
        let config = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert!(
            with_home(Some(""), || AuditLogger::from_config(&config)).is_none(),
            "relative override + unusable HOME must fail closed, not write into CWD"
        );
    }
}
