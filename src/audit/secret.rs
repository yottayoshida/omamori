//! Audit HMAC secret management, symlink-safe file I/O, and key rotation.
//!
//! SECURITY: Functions that touch raw key material (`[u8; 32]` secret bytes)
//! are `pub(super)` — they must NEVER be `pub(crate)` or `pub`. `rotate_key`
//! is the sole, intentional exception: it crosses the module boundary into
//! `cli::audit_cmd` as the sanctioned rotation entry point, but never returns
//! key bytes — only labels and paths — so it doesn't violate the invariant
//! above. Stated as the invariant rather than as an inventory of
//! `RotationResult`'s fields: the type is `#[non_exhaustive]` precisely
//! because that list is expected to grow, and a list is what goes stale.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::error::AuditError;

// ---------------------------------------------------------------------------
// File locking (platform-specific)
// ---------------------------------------------------------------------------

/// Ceiling on how long any single `flock` acquisition may take.
///
/// Acquisition is **never** allowed to block indefinitely. A plain `LOCK_EX`
/// waits for as long as the current holder wants, and every lock omamori takes
/// sits on a path that runs for every guarded command: the key store lock is
/// taken by `AuditLogger::from_config`, and `audit.jsonl`'s by `append` and
/// `verify_chain`. Any local process — including the AI agents omamori's
/// threat model assumes are present — can open one of those files and hold a
/// lock forever, which does not merely slow omamori down: `hook-check` stops
/// before it prints its deny verdict, and what happens next is the host's hook
/// timeout policy rather than omamori's. Bounding acquisition converts that
/// from a silent disable into a slow, loud failure.
///
/// 100 × 5 ms. Legitimate contention is a rotation or a concurrent append,
/// both of which finish in single-digit milliseconds; a budget this size is
/// slack for them and a hard ceiling for everyone else.
#[cfg(unix)]
const LOCK_ATTEMPTS: u32 = 100;
#[cfg(unix)]
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

/// Take an flock, giving up once [`LOCK_ATTEMPTS`] have been spent.
///
/// Returns [`std::io::ErrorKind::WouldBlock`] when the budget runs out, which
/// callers must handle explicitly: `with_key_store_lock` proceeds unlocked and
/// reports it, while `append` and `verify_chain` propagate it.
///
/// The difference is not that one is an optimisation — the key store's
/// exclusivity is a correctness property too, and #477 says so where rotation
/// warns about losing it. It is that refusing to rotate on an unheld lock
/// would let any local process stop rotation permanently, and that is the
/// larger harm. So rotation degrades deliberately and says what it observed.
#[cfg(unix)]
fn flock_bounded(file: &fs::File, exclusive: bool) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let op = (if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    }) | libc::LOCK_NB;
    for attempt in 0..LOCK_ATTEMPTS {
        if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // Anything other than "someone else holds it" is a real failure and
        // retrying cannot help.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(err);
        }
        if attempt + 1 < LOCK_ATTEMPTS {
            std::thread::sleep(LOCK_RETRY_DELAY);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "audit lock is held by another process",
    ))
}

#[cfg(unix)]
pub(super) fn flock_exclusive(file: &fs::File) -> Result<(), std::io::Error> {
    flock_bounded(file, true)
}

#[cfg(not(unix))]
pub(super) fn flock_exclusive(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn flock_shared(file: &fs::File) -> Result<(), std::io::Error> {
    flock_bounded(file, false)
}

#[cfg(not(unix))]
pub(super) fn flock_shared(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(())
}

// ---------------------------------------------------------------------------
// HMAC targets (event field hashing)
// ---------------------------------------------------------------------------

use super::chain::{HmacSha256, NO_HMAC_SECRET};
use hmac::Mac;

pub(super) fn hmac_targets(secret: Option<&[u8; 32]>, targets: &[&str]) -> String {
    let Some(key) = secret else {
        return NO_HMAC_SECRET.to_string();
    };
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    for target in targets {
        mac.update(target.as_bytes());
        mac.update(&[0]); // null separator between targets
    }
    format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Signing key
// ---------------------------------------------------------------------------

/// An audit HMAC key together with the `key_id` label that names it.
///
/// #457: these two used to travel as separate values — `AuditLogger` held an
/// `Option<[u8; 32]>` and a `String` side by side, and `from_config` resolved
/// them with two independent filesystem reads. Every defect in #457 is an
/// instance of one shape: **a value signed with one key while labelled as
/// another**. Binding them into a single type means a call site cannot name a
/// key it did not sign with, because it never holds the label apart from the
/// bytes.
///
/// `secret` is `Option` because an unwritable data directory leaves the logger
/// running without a key: events are still appended and still carry a
/// `key_id`, their HMAC fields just read `NO_HMAC_SECRET` (see `hmac_bytes`).
/// Making the bytes mandatory here would silently drop the label in that case
/// and change on-disk output for a failure mode unrelated to #457.
///
/// SECURITY: carries raw key material, so `pub(super)` per this module's
/// header invariant. Never widen it.
pub(super) struct SigningKey {
    pub(super) id: String,
    secret: Option<[u8; 32]>,
}

impl SigningKey {
    pub(super) fn secret(&self) -> Option<&[u8; 32]> {
        self.secret.as_ref()
    }

    /// `secret: None` models the unwritable-data-directory case, which several
    /// fixtures exercise — hence `Option` rather than two constructors.
    #[cfg(test)]
    pub(super) fn for_test(id: &str, secret: Option<[u8; 32]>) -> Self {
        Self {
            id: id.to_string(),
            secret,
        }
    }
}

/// What the attempt to take the key-store lock actually observed.
///
/// #477 gave rotation — the one caller that acts on this — a `bool`, which put
/// four different facts under one value: the lock file could not be opened (on
/// Unix that includes `O_NOFOLLOW` refusing a symlink planted at the path), it
/// was not a regular file, another process was holding it, or `flock` failed
/// some other way. The first two are the **only** signal the `O_NOFOLLOW` and
/// file-type guards can ever produce, since both discard their own error, so
/// collapsing them filed a tampering indicator as a benign concurrency note.
///
/// `Unheld` carries what was observed rather than a reading of it — the same
/// rule [`fold_key_dir_entries`] follows for a listing that stopped partway.
enum KeyStoreLock {
    Held,
    Unheld(String),
}

/// Serialize key-store observations against rotation.
///
/// #457 (Codex Round 1 P0): binding the key and its label into one type is not
/// enough on its own. `load_signing_key` still makes two observations — it
/// lists the directory, then reads the active secret — and `rotate_key` still
/// makes two mutations. A rotation landing between the two reads pairs the new
/// key's bytes with the old epoch's label, which is the same defect this PR
/// removes, just through a narrower window.
///
/// The lock file sits next to the secret. It is never a retired key
/// (`audit-secret.lock` does not end in `.retired`) so it cannot shift an
/// epoch.
///
/// **Best-effort, in both directions.** If the lock cannot be created *or*
/// cannot be acquired within [`LOCK_ATTEMPTS`], the operation proceeds
/// unlocked: refusing to record an audit event because a lock file could not
/// be made would trade a rare mislabel for a guaranteed hole in the record,
/// and a hole is worse.
///
/// Acquisition needs saying out loud, not just creation. The first version of
/// this function used a blocking `LOCK_EX`, which let any local process that
/// could open the lock file stall `verify`, `doctor`, `report`, every guarded
/// command and — the one that matters — `hook-check`, before it printed its
/// deny verdict (measured, Phase 8). The same argument that makes creation
/// failure non-fatal makes acquisition failure non-fatal: a rare mislabel is
/// the lesser harm.
/// #477: the non-fatal argument above is about *recording* — a hole in the log
/// is worse than a rare mislabel. Rotation is not recording. It is the only
/// caller that mutates the key store, and it asks for `exclusive` precisely so
/// that readers cannot observe the rename half-done. Establishing "do not
/// mutate on an observation you could not make" for the directory scan while
/// staying silent about an observation the lock could not protect would defend
/// one invariant at two different depths. So the outcome is handed to the
/// callback rather than dropped — reported, not enforced: an unheld lock is a
/// race window, while an unlistable directory is a certainty, and refusing to
/// rotate because a lock file could not be opened would hand any local process
/// a way to block rotation for good.
fn with_key_store_lock<T>(
    secret_path: &Path,
    exclusive: bool,
    f: impl FnOnce(&KeyStoreLock) -> T,
) -> T {
    let lock_path = secret_path.with_file_name("audit-secret.lock");
    // `O_NOFOLLOW` is not optional here. #457 added a file-type pre-check to
    // `read_secret` precisely because an `open` that blocks forever stops
    // `verify` *and every hook append* — and then opened this file without
    // any such protection, in the same change. A FIFO planted at the lock
    // path would hang the very path the pre-check was added to protect.
    //
    // The structural point (`/simplify`, Altitude): the check lives on callers,
    // so it did not reach a new caller added alongside it. The five call sites
    // that open `audit.jsonl` have the same gap and are tracked in #468.
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        // 0600 like every other file omamori creates in this directory
        // (`create_secret` sets the same). The lock holds no data, but a
        // world-readable lock file is enough to take the lock — `flock` works
        // on a read-only descriptor — so the mode is what decides who can
        // contend for it on a shared host.
        opts.mode(0o600);
    }
    let opened = match opts.open(&lock_path) {
        Ok(file) => match file.metadata() {
            Ok(m) if m.is_file() => Ok(file),
            // O_NONBLOCK stops a FIFO from blocking, but it does not make one
            // a usable lock target — reject anything that is not a regular
            // file.
            Ok(_) => Err(format!("{} is not a regular file", lock_path.display())),
            Err(e) => Err(format!("cannot stat {}: {e}", lock_path.display())),
        },
        Err(e) => Err(format!("cannot open {}: {e}", lock_path.display())),
    };
    let (lock, state) = match opened {
        Ok(file) => {
            let acquired = if exclusive {
                flock_exclusive(&file)
            } else {
                flock_shared(&file)
            };
            match acquired {
                Ok(()) => (Some(file), KeyStoreLock::Held),
                // Not "someone may be holding it": `flock_bounded` spent its
                // whole budget and this is the error it ended on.
                Err(e) => (
                    Some(file),
                    KeyStoreLock::Unheld(format!(
                        "cannot acquire {} after {LOCK_ATTEMPTS} attempts: {e}",
                        lock_path.display()
                    )),
                ),
            }
        }
        Err(reason) => (None, KeyStoreLock::Unheld(reason)),
    };
    let out = f(&state);
    drop(lock); // releases the flock
    out
}

/// What the store can say about an `audit-secret` that is not there.
///
/// #478 could only say "a rotation may have been interrupted" and had to cover
/// two readings in one sentence, because the key store held nothing that told
/// them apart. The epoch record does, for stores that have one — so each
/// variant is a different sentence, about different entries and different
/// keys, rather than one sentence hedged to cover both.
///
/// Reached only when `read_secret` returned `NotFound`. Every other failure
/// means the key is unreachable rather than absent (#478), and none of these
/// sentences would be true of it.
enum MissingActiveKey {
    /// No record, so the store cannot say whether the rotation that left this
    /// state got as far as handing its number out. Every store looked like
    /// this before the record existed, and one that has not rotated since
    /// still does.
    Ambiguous,
    /// The record does not reach past the retired slots. The rotation that left
    /// this state stopped before writing a new epoch, so — as far as the record
    /// goes — the number about to be minted has never named a key.
    BeforeHandout { recorded: u32 },
    /// The record names an epoch above every retired slot and no key answers to
    /// it.
    ///
    /// **Whether that epoch ever signed anything is not knowable here.** The
    /// record is written before the key is minted, so a crash between the two
    /// leaves this exact state with nothing handed out. What is certain is the
    /// number must not be handed out again: a second key under an id some entry
    /// already carries makes those entries read as tampered, permanently.
    Unbacked(u32),
}

impl MissingActiveKey {
    fn classify(recorded: u32, max_retired: u32) -> Option<Self> {
        if recorded > max_retired {
            // `recorded > max_retired >= 0`, so a record exists.
            return Some(Self::Unbacked(recorded));
        }
        if max_retired == 0 {
            // A fresh install: nothing retired, nothing recorded, no key yet.
            // Not an interrupted anything, and warning about one here is what
            // #478 measured as the false alarm on a healthy store.
            return None;
        }
        Some(if recorded == 0 {
            Self::Ambiguous
        } else {
            Self::BeforeHandout { recorded }
        })
    }

    /// The observation, for the branch where a key is now present.
    fn observed(&self, id: &str, max_retired: u32) -> String {
        match self {
            Self::Ambiguous => "retired audit keys are present and audit-secret was not — a key \
                 rotation may have been interrupted."
                .to_string(),
            Self::BeforeHandout { recorded } => format!(
                "retired audit keys are present and audit-secret was not — a key rotation may \
                 have been interrupted. {EPOCH_RECORD_NAME} records epoch {recorded}, which the \
                 retired keys already reach ({max_retired}), so that rotation stopped before \
                 recording a new epoch and the record shows nothing signed under {id}."
            ),
            Self::Unbacked(lost) => format!(
                "{EPOCH_RECORD_NAME} records epoch {lost} and no key answers to it — that \
                 rotation may have handed the epoch out before its key was lost, or may have \
                 stopped before creating one. Either way the number is not reused: entries \
                 labelled {}, if any exist, stay unverifiable.",
                key_id_for_epoch(*lost)
            ),
        }
    }

    /// The observation, for the branch where the replacement could not be
    /// created. Stated separately rather than composed from [`Self::observed`]:
    /// the two differ in the middle of the sentence, not at the end, and
    /// splicing "and a replacement could not be created" into a string built
    /// elsewhere is how the wording drifts apart.
    fn observed_without_mint(&self, max_retired: u32) -> String {
        match self {
            Self::Ambiguous => "retired audit keys are present, audit-secret was not, and a \
                 replacement could not be created — a key rotation may have been interrupted."
                .to_string(),
            Self::BeforeHandout { recorded } => format!(
                "retired audit keys are present, audit-secret was not, and a replacement could \
                 not be created — a key rotation may have been interrupted. \
                 {EPOCH_RECORD_NAME} records epoch {recorded} and the retired keys reach \
                 {max_retired}."
            ),
            Self::Unbacked(lost) => format!(
                "{EPOCH_RECORD_NAME} records epoch {lost}, no key answers to it, and a \
                 replacement could not be created."
            ),
        }
    }

    /// What becomes of the entries written while no key could be created.
    ///
    /// Two different fates, and the difference is whether the label can ever
    /// resolve. `Ambiguous` and `BeforeHandout` hand out a number the record
    /// does not hold, so clearing the fault mints a key under exactly that
    /// label and every entry written meanwhile fails against it — the outcome
    /// #478 documented. `Unbacked` cannot end that way: the record already
    /// holds this epoch, so the next attempt allocates past it and nothing is
    /// ever created under this id.
    ///
    /// **The `Unbacked` arm is not reachable from the test suite** (Codex Round
    /// 1, P2). Getting here needs the record to be writable while
    /// `create_secret` fails, and on every fixture that denies the mint — an
    /// unwritable directory — the record is denied first and the caller returns
    /// before this point. What is left is a missing `/dev/urandom` or `EMFILE`.
    /// Stated rather than left to be inferred from the other arm, because a
    /// sentence that is wrong only in an unreachable state is still a sentence
    /// this repository has now shipped twice.
    fn consequence_without_mint(&self, id: &str) -> String {
        match self {
            Self::Ambiguous | Self::BeforeHandout { .. } => format!(
                "They are still labelled {id}, so once a key exists under that label they will \
                 be checked against it, fail, and be reported as tampering — clearing the \
                 condition does not make them verifiable."
            ),
            Self::Unbacked(_) => format!(
                "They are still labelled {id}, and {EPOCH_RECORD_NAME} already holds that \
                 epoch — the next attempt allocates past it, so no key is ever created under \
                 {id} and these entries stay unverifiable rather than turning into a tampering \
                 report."
            ),
        }
    }

    /// The clause warning that earlier entries may already carry this id.
    ///
    /// Only [`Self::Ambiguous`] can say it, and saying it is not hedging: a
    /// store with no record genuinely cannot tell a rotation that stopped
    /// before handing out its number from one whose key was lost afterwards.
    /// The other two variants know which happened — `BeforeHandout` because the
    /// record is below the slots, `Unbacked` because the mint moved past the
    /// recorded number instead of reusing it — so for them the clause would
    /// describe a collision this call has just made impossible.
    fn overlap_clause(&self, id: &str) -> String {
        match self {
            Self::Ambiguous => format!(
                ", and entries written before this may carry {id} too, signed with different \
                 bytes"
            ),
            _ => String::new(),
        }
    }
}

/// Move the record past an epoch whose key is gone, returning the number the
/// caller may hand out.
///
/// yotta 判断11: the danger is not minting, it is reusing a number. Entries
/// signed under the lost epoch stay cannot-verify — exit 2, which is the honest
/// verdict — while entries signed from here carry a number no earlier entry
/// can hold.
///
/// **The record moves before the key exists, and never after.** Handing out
/// `lost + 1` while the file still says `lost` would put the next run back on
/// `lost`: the same bytes would answer to two ids, and everything written in
/// between would name an epoch no keyring can produce. That is the
/// key-and-label split #457 closed, reopened one generation wide.
///
/// `None` means the caller must not mint. A key created under a number the
/// store has not written down is a key the next run names differently.
///
/// Residual, and deliberate: if the record can be written but the mint cannot
/// run — a missing `/dev/urandom`, `EMFILE` — every later command repeats this
/// and the number climbs. Both failures usually share a cause (an unwritable
/// directory denies the record first, and then this returns `None` without
/// touching anything), and the alternative is minting under a number the record
/// does not hold. u32 gives 4.29e9 epochs; weekly rotation for two years
/// reaches 104.
fn claim_next_epoch(secret_path: &Path, lost: u32, policy: KeyWarnPolicy) -> Option<u32> {
    let Some(next) = lost.checked_add(1) else {
        if may_warn(policy, WARN_KIND_EPOCH_AT_LIMIT, secret_path) {
            eprintln!(
                "omamori warning: audit key epoch {lost} is at the representable limit, so no \
                 successor can be allocated and no replacement key was created. \
                 {ENTRIES_CARRY_NO_HMAC}"
            );
        }
        return None;
    };
    match write_epoch_record(secret_path, next) {
        // Not necessarily `next`: another process may have claimed further
        // while this one was deciding, and the number on disk is the one the
        // mint below will be named by.
        Ok(recorded) => Some(recorded),
        Err(e) => {
            if may_warn(policy, WARN_KIND_EPOCH_NOT_ADVANCED, secret_path) {
                eprintln!(
                    // "a replacement could not be created" is the wording #478 gave
                    // this outcome, and the outcome is the same one: no key exists at
                    // the active path when this returns. Kept verbatim so the operator
                    // reads one sentence for one state — the reason differs (the record
                    // stopped it before the mint was attempted) and the reason is what
                    // the rest of the sentence is for.
                    // "They stay unverifiable", not "they will be reported as
                    // tampering" — the consequence the *other* failed-mint branch has.
                    // The difference is the label: that branch returns a resolvable
                    // `key-{N}`, so clearing the fault mints a key under it and the
                    // entries written meanwhile fail against it. This one returns
                    // `UNRESOLVED_KEY_ID`, which no keyring can hold, so they stay in
                    // cannot-verify instead. Same words as the unlistable-directory
                    // site because the same thing happens there and for the same
                    // reason, checked rather than assumed (#478 Phase 8) — and written
                    // out rather than shared through a constant, so a third site
                    // cannot inherit a consequence nobody re-derived for it.
                    "omamori warning: the key for audit epoch {lost} is missing and a replacement could \
             not be created — {EPOCH_RECORD_NAME} could not be advanced to {next}: {e}. \
             Creating one under an epoch the store has not recorded is what puts two keys under \
             a single id. {ENTRIES_CARRY_NO_HMAC} They stay unverifiable; clearing the condition \
             protects later ones, not those."
                );
            }
            None
        }
    }
}

/// Throttle sentinel kinds. Named rather than inline so the invariant that
/// binds them — **no two messages with different content may share one** — has
/// something a test can hold onto. The bug this prevents does not fail to
/// compile: passing the same string at two sites is valid Rust that silently
/// lets one branch suppress the other (#473 review found exactly that between
/// the two rotation warnings, only one of which carries the prohibition).
pub(super) const WARN_KIND_KEYSTORE: &str = "keystore";
pub(super) const WARN_KIND_ROTATION_MINTED: &str = "rotation-minted";
pub(super) const WARN_KIND_ROTATION_UNMINTED: &str = "rotation-unminted";
/// #518: the four printers `load_signing_key_locked` reaches that #473 left
/// unthrottled. One kind each, not one shared kind — two messages behind one
/// sentinel means the first to fire silences the second, and the states these
/// four report do not resolve on their own, so the silenced one would stay
/// silenced for as long as the store is broken.
pub(super) const WARN_KIND_EPOCH_AT_LIMIT: &str = "epoch-at-limit";
pub(super) const WARN_KIND_EPOCH_NOT_ADVANCED: &str = "epoch-not-advanced";
pub(super) const WARN_KIND_SECRET_PATH_OCCUPIED: &str = "secret-path-occupied";
pub(super) const WARN_KIND_SECRET_UNREADABLE: &str = "secret-unreadable";

/// How loudly `load_signing_key` may talk about a degraded key store (#473).
///
/// The warnings below are produced where the key store is read, which is on
/// **every** guarded command via `AuditLogger::from_config`. Two existing
/// mechanisms exist for exactly that situation and neither reached here: the
/// 300-second stderr throttle (`#359`) and the SEC-R5 rule against printing
/// literal repair commands into an AI session.
///
/// The policy travels from the caller rather than being decided at the print
/// site, because the print site cannot tell an operator who typed a command
/// from a shim that fired because one was typed. Throttling at the print site
/// would let a background shim invocation silence the answer to a question a
/// person just asked — and `audit_cmd`'s rotation failure explicitly points at
/// "the condition reported above", which is this warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyWarnPolicy {
    /// Say it every time. The default, and what every interactive command uses.
    Always,
    /// At most once per throttle window, per warning kind, per store. Used by
    /// the PATH shim, matching the Layer 1 / Layer 2 asymmetry SECURITY.md
    /// already records for audit-append warnings.
    Throttled,
}

/// `load_signing_key_with(.., Always)`, kept for the tests that predate the
/// policy parameter (#473). Every production caller now states its policy.
#[cfg(test)]
pub(super) fn load_signing_key(secret_path: &Path) -> SigningKey {
    load_signing_key_with(secret_path, KeyWarnPolicy::Always)
}

/// Resolve the active signing key and its `key_id` together.
///
/// #457: the secret and its id used to be resolved by two separate calls, each
/// reading the key directory independently. A rotation landing between them
/// minted one entry signed with the old key but labelled with the new id — a
/// permanently unverifiable entry that no amount of verifier-side repair can
/// reclassify, because the id is present and only the bytes are wrong. The two
/// reads are now one value *and* one locked observation.
pub(super) fn load_signing_key_with(secret_path: &Path, policy: KeyWarnPolicy) -> SigningKey {
    with_key_store_lock(secret_path, false, |_lock| {
        load_signing_key_locked(secret_path, policy)
    })
}

/// `may_warn`, for the test that pins "the first occurrence is never throttled
/// away" (#518). Exposed rather than reached through a fixture because the
/// property is about this function and not about any one call site — the call
/// sites are pinned separately, by the sentinel each one leaves behind.
#[cfg(test)]
pub(super) fn may_warn_for_test(policy: KeyWarnPolicy, kind: &str, store: &Path) -> bool {
    may_warn(policy, kind, store)
}

/// Whether a warning of `kind` about `store` may be printed under `policy`.
fn may_warn(policy: KeyWarnPolicy, kind: &str, store: &Path) -> bool {
    match policy {
        KeyWarnPolicy::Always => true,
        KeyWarnPolicy::Throttled => {
            let name = crate::warn_throttle::sentinel_name_for_store(kind, store);
            match crate::warn_throttle::sentinel_path(&name) {
                Some(p) => crate::warn_throttle::should_emit_at(&p),
                // No resolvable base dir is not a reason to withhold.
                None => true,
            }
        }
    }
}

/// The warning for a key store that cannot say which epoch is active.
///
/// `with_repair` is SEC-R5's answer, not a formatting choice: exactly one of
/// the four reasons carries a repair, and that is the only text this flag can
/// remove. The condition itself is stated in every case — withholding the
/// observation would hide a degraded store from the reader, which inverts what
/// the gate is for.
pub(super) fn keystore_warning(reason: &UnprotectedReason, with_repair: bool) -> String {
    match reason {
        // Not "fix the condition and re-run to restore protection": the reason
        // is inline in this same sentence rather than above it, nothing here is
        // a command the operator ran, and "restore" reads as covering the
        // entries written meanwhile — which `verify`'s own `NeverProtected` arm
        // then denies.
        UnprotectedReason::KeyDirUnlistable(r) => format!(
            "omamori warning: {r} — cannot determine which key epoch is active, so no entry \
             written from here on can be HMAC-protected or labelled with a key epoch. \
             {ENTRIES_CARRY_NO_HMAC} They stay unverifiable; clearing the condition protects \
             later ones, not those."
        ),
        UnprotectedReason::EpochRecordUnreadable(r) => format!(
            "omamori warning: {r} — cannot determine which key epoch is active, so no entry \
             written from here on can be HMAC-protected or labelled with a key epoch. \
             {ENTRIES_CARRY_NO_HMAC} They stay unverifiable.{}",
            if with_repair {
                format!(" {}", epoch_record_remedy())
            } else {
                // A route, not a deletion. Every other SEC-R5 site in this
                // codebase substitutes "run it yourself, directly in your
                // terminal" rather than ending on the condition — `doctor`,
                // `explain`, `guard` and `break-glass` all do, and `cli.rs`
                // pins the wording for `doctor`. Leaving an agent with a
                // degraded key store and no sanctioned next step is what makes
                // it improvise one inside the audit directory, which is the
                // outcome the gate exists to prevent.
                " To see how to clear it, run 'omamori doctor' directly in your terminal \
                 (not via AI)."
                    .to_string()
            }
        ),
        // `key_store_outlook` decides from the listing alone and never reads the
        // active key, so it produces neither of these two. Listed rather than
        // caught by `_` so that a future refusal added there has to be given
        // wording here instead of silently inheriting somebody else's — which
        // the compiler enforced the moment `ActiveKeyMissing` was split out.
        //
        // Reaching either would mean this function returned before the code
        // below that decides whether to mint, so neither may promise one.
        UnprotectedReason::ActiveKeyUnusable(r) => {
            format!("omamori warning: {r} — {ENTRIES_CARRY_NO_HMAC} They stay unverifiable.")
        }
        UnprotectedReason::ActiveKeyMissing => format!(
            "omamori warning: no active audit key is present. {ENTRIES_CARRY_NO_HMAC} They stay \
             unverifiable."
        ),
    }
}

/// Whether literal repair instructions may be printed (SEC-R5).
///
/// The condition itself is always reported — suppressing the observation would
/// hide a degraded store, which is the opposite of the point. What is withheld
/// in an AI session is the part that names a key file and says what to do to
/// it, which is a recipe handed to the reader most likely to act on it
/// unsupervised.
fn may_print_repair() -> bool {
    !crate::cli::doctor::is_ai_environment()
}

/// Why an append made right now could not be HMAC-protected.
///
/// #471: `status` and the writer were asking different questions about one
/// store. `audit_summary` judged health with `read_secret(…).is_ok()`, which
/// opens by name and therefore needs only *search* permission on the directory
/// holding it; the writer goes through `scan_key_dir`, which needs to *list*
/// it. At mode `0300` the first succeeds and the second does not, so the writer
/// fell back to recording without HMAC protection while `status` printed
/// `[ok] Layer 3 (audit)`.
///
/// Carried as a reason rather than a `bool` so the caller does not assemble the
/// wording from a flag: at `0300` the key is present and readable, and the old
/// single message — "HMAC secret missing" — is simply false there.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnprotectedReason {
    /// The key directory could not be listed, so which epoch is active is
    /// unknown. Decidable from the listing alone.
    KeyDirUnlistable(String),
    /// The epoch record is present but states no epoch. Also from the listing.
    EpochRecordUnreadable(String),
    /// There is no active key at all. Held apart from the variant below
    /// because the consequence differs and only this one is uncertain: the
    /// writer's next append tries to *mint* a key here, and often succeeds.
    ActiveKeyMissing,
    /// Something is at the active key's path that cannot be read as a key —
    /// symlinked, a FIFO, the wrong size, bad hex. Not part of the
    /// listing-derived pair above, but the same `read_secret` call the writer
    /// makes.
    ActiveKeyUnusable(String),
}

impl UnprotectedReason {
    /// One clause for `status`'s single-line layer row.
    ///
    /// Each variant owns its whole sentence rather than sharing a suffix. A
    /// shared "entries are recorded without HMAC protection" was wrong for
    /// [`Self::ActiveKeyMissing`] — measured on a release build: with the
    /// active key moved aside, the next append minted a replacement and the
    /// entry it wrote *did* carry an HMAC. The line would have stated the
    /// opposite of what the very next command does. `[warn]` is still right
    /// there (the store is in a state an operator has to look at, and this run
    /// did not mint anything), but the reason may not predict a mint it has
    /// not performed.
    pub fn summary(&self) -> &'static str {
        match self {
            Self::KeyDirUnlistable(_) => {
                "key directory cannot be listed — entries are recorded without HMAC protection"
            }
            Self::EpochRecordUnreadable(_) => {
                "key epoch record states no epoch — entries are recorded without HMAC protection"
            }
            Self::ActiveKeyMissing => "no active HMAC key is present",
            Self::ActiveKeyUnusable(_) => {
                "HMAC secret cannot be read — entries are recorded without HMAC protection"
            }
        }
    }
}

/// The part of `load_signing_key_locked`'s decision that a reader can make
/// **without side effects**: the directory listing, and the two refusals
/// reachable from it alone.
///
/// The decision does not end here. Past this point the writer reads the active
/// key and, finding none, *creates* one — and a command that only reports state
/// must not do that. So this is where the shared predicate stops, and
/// `audit_summary` adds exactly one more observation of its own: the same
/// `read_secret` call, whose failure it reports as [`UnprotectedReason::ActiveKeyUnusable`].
/// What neither can see is a mint that fails after being attempted; that outcome
/// exists only inside the writer.
///
/// Shared rather than copied, for the reason `classify_secret_failure` gives one
/// file over: two commands disagreeing about one store is the defect being
/// closed, and a duplicated condition is one edit away from disagreeing again.
pub(super) enum KeyStoreOutlook {
    /// No append from here can be HMAC-protected, whatever the active key holds.
    Unprotected(UnprotectedReason),
    /// Nothing in the listing refuses. Carries what the writer needs next.
    Usable {
        retired: BTreeMap<u32, PathBuf>,
        recorded: u32,
        /// #471 (review): carried so the three observations `rotate_key_locked`
        /// makes about "has this store rotated?" are the same three every
        /// reader makes. Dropping it left the shared predicate answering a
        /// slightly different question than the command it was shared with —
        /// the exact shape this extraction exists to remove.
        pending: Option<PathBuf>,
    },
}

pub(super) fn key_store_outlook(secret_path: &Path) -> KeyStoreOutlook {
    let (retired, record, pending) = match scan_key_dir(secret_path) {
        KeyDirScan::Unlistable(reason) => {
            return KeyStoreOutlook::Unprotected(UnprotectedReason::KeyDirUnlistable(reason));
        }
        KeyDirScan::Listed {
            retired,
            epoch,
            pending,
        } => (retired, epoch, pending),
    };
    match record.recorded() {
        Ok(recorded) => KeyStoreOutlook::Usable {
            retired,
            recorded,
            pending,
        },
        Err(reason) => KeyStoreOutlook::Unprotected(UnprotectedReason::EpochRecordUnreadable(
            reason.to_string(),
        )),
    }
}

/// Does the store look like a rotation that stopped between filing the old key
/// and creating its replacement?
///
/// #487 B. **Observed under the key-store lock**, which is the whole reason this
/// lives here rather than being assembled by the caller. Review caught that
/// reading the active key and then listing the directory as two unsynchronised
/// steps admits a rotation completing in between: the reader then sees "no
/// active key" from before it and "retired keys exist" from after it, and
/// reports an interrupted rotation on a store that is perfectly healthy. This
/// change would have introduced that false alarm, since the state used to be
/// quiet. The mirror case is worse — a directory becoming unlistable between
/// the two steps would drop a `KeyringUnusable` verdict to a quiet one.
///
/// The three observations are `rotate_key_locked`'s three, not a subset:
/// retired keys, a recorded epoch, or a pending replacement.
pub(super) fn interrupted_rotation_evidence(secret_path: &Path) -> bool {
    with_key_store_lock(secret_path, false, |_lock| {
        // Re-read inside the lock. The caller's earlier read is what raised the
        // question; this is the one the answer is based on.
        if read_secret(secret_path).is_ok() {
            return false;
        }
        match key_store_outlook(secret_path) {
            KeyStoreOutlook::Usable {
                retired,
                recorded,
                pending,
            } => !retired.is_empty() || recorded >= 1 || pending.is_some(),
            // The directory stopped being listable. Not this function's verdict
            // to give — the caller's keyring check owns that one.
            KeyStoreOutlook::Unprotected(_) => false,
        }
    })
}

fn load_signing_key_locked(secret_path: &Path, policy: KeyWarnPolicy) -> SigningKey {
    // #457 (Codex Round 2): the verifier was made fail-closed for an unlistable
    // key directory, but this side was not — and it is the side that writes.
    // With execute-but-not-read permissions the active secret is still
    // readable, so appends would keep being signed while stamped `"default"`
    // from a scan that saw nothing. On a rotated store those entries are
    // mislabelled, and once permissions are restored `"default"` resolves to
    // `.1.retired` and they read as tampered.
    //
    // Recording without HMAC protection is the honest outcome: the existing
    // `NO_HMAC_SECRET` path already marks such entries, and `[audit] strict =
    // true` already blocks the command rather than proceeding unrecorded.
    //
    // The *label* took two tries to get right. The first version stamped
    // `"default"`, and the comment justifying it claimed the alternative
    // "would instead manufacture evidence of tampering later" — which is
    // exactly what `"default"` does. Measured against v0.16.0 (Phase 8): with
    // the data directory execute-only, v0.16.0 wrote a real HMAC and later
    // reported `chain intact`, while `"default"` + `NO_HMAC_SECRET` made the
    // same store report `chain broken … may have been tampered with`,
    // permanently, because ADR-0007 forbids rewriting the entry. A regression,
    // and one produced by the fail-closed branch itself.
    //
    // `UNRESOLVED_KEY_ID` is the fix: an id no keyring can ever hold, so the
    // entry lands in the cannot-verify terminal state (exit 2) with its actual
    // reason, instead of being checked against a key it was never signed with.
    // The distinction the original comment was reaching for — do not write a
    // label you cannot stand behind — is preserved by naming the absence
    // rather than guessing an epoch.
    // States the condition, not the consequence. This runs from
    // `AuditLogger::from_config`, i.e. before any caller has decided whether to
    // append at all — and two callers decide not to. `shim.rs`'s strict gate
    // builds a logger purely to test `secret_available()` and then blocks the
    // command without appending; `cli::audit_cmd`'s rotation record skips the
    // append on purpose. Asserting "this entry is recorded without HMAC
    // protection" told the operator, in both of those, that something was
    // written when nothing was.
    //
    // PR-C1 (yotta 判断12): a record that does not state an epoch is refused
    // here, in the verifier and in rotation alike. Falling back to the
    // derivation is the softer option and the wrong one — the record is
    // consulted precisely where the derivation is known to walk backwards, so
    // ignoring an unreadable one reinstates the defect on exactly the stores
    // that needed it. #479's rule, applied to a second file: one invariant,
    // guarded at one depth.
    //
    // #471: both refusals now come from `key_store_outlook`, which `status`
    // asks the same question of. Only the wording stays here — a reader of
    // state has no business printing an operator warning, and the two refusals
    // want different remedies.
    let (retired, recorded) = match key_store_outlook(secret_path) {
        KeyStoreOutlook::Unprotected(reason) => {
            // #473: this block runs from `AuditLogger::from_config`, i.e. on
            // every guarded command, and printed unconditionally. One sentinel
            // for the whole block: these four are one condition seen four ways
            // (the key store cannot answer), so reporting one and suppressing
            // the others for the window would be the sharing this change exists
            // to remove — between *kinds*, not within one.
            if may_warn(policy, WARN_KIND_KEYSTORE, secret_path) {
                eprintln!("{}", keystore_warning(&reason, may_print_repair()));
            }
            return SigningKey {
                id: UNRESOLVED_KEY_ID.to_string(),
                secret: None,
            };
        }
        KeyStoreOutlook::Usable {
            retired, recorded, ..
        } => (retired, recorded),
    };

    let max_retired = max_retired_index(&retired);
    let epoch = active_epoch(&retired, recorded);

    // #457 P4-e: a rotation that crashed between `rename` and `create_secret`
    // leaves retired keys with nothing at the active path. `load_or_create_secret`
    // below tries to mint one — under the *same* `key-{N+1}` label the crashed
    // rotation was heading for. If it succeeds and that rotation had already
    // handed out a key under that label, two different secrets share one id,
    // and no verifier-side repair can untangle that: the id resolves, the bytes
    // just do not match, so the entries read as tampered forever.
    //
    // #478: "tries to". A directory that can be read and searched but not
    // written denies the mint, and the branch below reports that case
    // separately rather than describing a key that was never created.
    //
    // Detecting it here does not fix it (the complete fix needs the key file
    // itself to record its epoch — deferred, see ADR-0008), but a warning at
    // the moment it happens is the difference between an operator who can
    // restore the interrupted rotation and one who discovers it months later
    // as an unexplained broken chain.
    // Read once and reuse. The warning check and `load_or_create_secret` both
    // needed the active key, so the pre-`/simplify` form read the same file
    // twice on every command in a rotated store (measured: +9.4 µs).
    let active = read_secret(secret_path);

    // #478: the condition is the error *kind*, not "produced no value".
    // `read_secret` rejects thirteen different ways — permission, symlink,
    // FIFO, directory, oversize, bad hex — and `.ok()` filed every one of them
    // as "the active key is missing". Only `NotFound` means that, and it is
    // only reachable with the directory searchable, which also makes it the
    // only one that says anything about a rotation. Measured: a data directory
    // at mode 0400 lists completely and denies every open inside it, so the old
    // condition announced an interrupted rotation on a store whose active key
    // was present, valid and untouched.
    // PR-C1: the same `NotFound` condition, now handed to the record to be
    // classified. `max_retired > 0` used to stand in for "a rotation happened
    // here" — it is the only signal a store without a record has, and it misses
    // the store whose retired keys were all removed.
    let missing = matches!(&active, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        .then(|| MissingActiveKey::classify(recorded, max_retired))
        .flatten();

    // PR-C1: `Unbacked` is the one state that may not hand out the epoch the
    // derivation produced, because that number is already written down. Moving
    // the record first is what makes the mint below name a generation the next
    // command will still name the same way.
    let epoch = match missing {
        Some(MissingActiveKey::Unbacked(lost)) => match claim_next_epoch(secret_path, lost, policy)
        {
            Some(next) => next,
            None => {
                return SigningKey {
                    id: UNRESOLVED_KEY_ID.to_string(),
                    secret: None,
                };
            }
        },
        _ => epoch,
    };

    // `load_or_create_secret` is only reached when the active key could not be
    // read — normally because this is a fresh install and it has to be created.
    let secret = match active {
        Ok(secret) => Some(secret),
        Err(_) => load_or_create_secret(secret_path, policy),
    };
    let id = key_id_for_epoch(epoch);

    // #478: printed *after* the mint, and about the store as it stands now.
    // The previous version ran before it and described what was about to
    // happen: it promised a new key the mint does not always manage, gave the
    // operator a window that this same call closes a few lines further down,
    // and offered as its reason a fact the mint falsified before anyone could
    // read it. The three withdrawn clauses are quoted verbatim in
    // `RETRACTED_CLAUSES` (`tests/hook_integration.rs`), which is also what
    // `check-invariants.sh` reads to keep them out of this file — quoting them
    // here would put the strings back into the code they were removed from.
    //
    // Following the old instruction was worse than ignoring it: copying a
    // retired key over `audit-secret` destroys the replacement's bytes while
    // `max_retired` stays put, so `{id}` resolves to the older key and `verify`
    // reports the product's strongest accusation — permanently, since ADR-0007
    // forbids rewriting the entries. Under the same-user threat model that
    // makes the instruction itself the payload.
    //
    // The first branch reports that an active key is present, not that a new
    // one was created: `Some` here can also be a concurrent writer's mint that
    // this call went on to read. The distinction does not change what the
    // operator must not do, and only the weaker claim is something this code
    // observed. Described rather than quoted — a paraphrase in quotation marks
    // is what a literal `grep` for the printed string will miss, and this repo
    // pins operator text with exactly that grep.
    //
    // "may carry" is the S1/S2 ambiguity, not hedging. A rotation that stopped
    // before minting wrote no entry under `{id}`; a store whose distributed key
    // was lost afterwards wrote several. The key store holds nothing that tells
    // the two apart — the difference is only in `audit.jsonl` — so the sentence
    // covers both. PR-C1's epoch record is what will separate them.
    // #473: throttled, but **not** withheld in an AI session, and the issue's
    // own description of this warning is why the distinction had to be checked
    // rather than assumed. It called this "a recovery procedure"; reading the
    // whole of what the three shapes produce, there is no procedure in it. The
    // parts are an observation, a consequence for the entries already written,
    // and one prohibition — do not copy a `.retired` file over `audit-secret`.
    //
    // SEC-R5 withholds recipes from the reader most likely to run them
    // unsupervised. A prohibition is the opposite artefact: suppressing it in
    // an AI session removes the sentence from the one reader it was written
    // for, and the action it forbids destroys the key its own newer entries
    // were signed with. Separate sentinel from the key-store block above,
    // because a store can be in both states and they need different remedies.
    //
    // The two branches take **separate** sentinels. Only the first carries the
    // prohibition, and the sequence that reaches the second and then the first
    // is the ordinary fix-and-retry: the directory is unwritable so the mint
    // fails (branch B, no prohibition, sentinel touched), the operator repairs
    // the permissions, the next command mints successfully — and branch A, the
    // one that says not to copy a `.retired` file over `audit-secret`, would be
    // suppressed for the rest of the window. That is the sharing this change
    // exists to remove, reached through the likely path rather than a contrived
    // one.
    if let Some(missing) = &missing {
        // The throttle check is nested inside each arm rather than folded into
        // the arm's own condition: `secret.is_some() && may_warn(..)` would send
        // a *suppressed* first branch into the `else`, printing the other
        // branch's message — which describes a store that failed to mint, on a
        // store that just did.
        if secret.is_some() {
            if may_warn(policy, WARN_KIND_ROTATION_MINTED, secret_path) {
                eprintln!(
                    "omamori warning: {} audit-secret now holds an \
                     active key; entries from here on are signed with it and labelled {id}{}. \
                     Do not copy a .retired file over audit-secret: that \
                     destroys the key the newer entries were signed with. See the audit \
                     chapter of omamori's FAQ.",
                    missing.observed(&id, max_retired),
                    missing.overlap_clause(&id)
                );
            }
        } else if may_warn(policy, WARN_KIND_ROTATION_UNMINTED, secret_path) {
            eprintln!(
                // "while this lasts", not "from here on" — the same bound the
                // unlistable-directory warning above uses, and for the same
                // reason. The condition is a permissions or storage fault the
                // operator can clear, after which later entries are protected
                // again; the unbounded phrasing described a store that never
                // recovers (Codex Round 1).
                "omamori warning: {} {ENTRIES_CARRY_NO_HMAC} {} See the audit chapter of \
                 omamori's FAQ.",
                missing.observed_without_mint(max_retired),
                missing.consequence_without_mint(&id)
            );
        }
    }

    SigningKey { id, secret }
}

// ---------------------------------------------------------------------------
// Secret path helpers
// ---------------------------------------------------------------------------

pub(super) fn secret_path_for(audit_path: &Path) -> PathBuf {
    audit_path.with_file_name("audit-secret")
}

/// Upper bound on how many keys `load_keyring` will hold.
///
/// #457 P4-b: the old `for n in 1..` loop had no bound at all. 256 is chosen
/// against the real cost — a measured 200-key ring adds ~26 ms to `verify` —
/// and against the most aggressive plausible schedule: weekly rotation for two
/// years is 104 keys, so a legitimate user does not reach it.
pub(super) const MAX_KEYRING_KEYS: usize = 256;

/// A secret file is 64 hex characters, optionally with trailing whitespace.
/// Anything meaningfully larger is not a key, and reading it would allocate
/// before the length check could reject it.
const MAX_SECRET_FILE_BYTES: u64 = 1024;

/// The opening words of the symlink rejection, shared by the one place that
/// builds it and the one place that classifies on it.
///
/// #478: `verify_chain` matched `"symlink"` *anywhere* in the message, and
/// every `read_secret` rejection ends with the path — so a store under
/// `~/symlink-tests/` made a FIFO at the secret path read as an attack.
/// `ErrorKind` cannot separate the two, because `symlink_attack_error` and the
/// "not a regular file" rejection are both `InvalidInput`; a prefix can,
/// because the path is always last. `read_secret`'s pre-check comment already
/// recorded this hazard — about a *test* that matched the same way — and the
/// production classifier had the same bug the whole time.
/// The one observation both no-HMAC warnings share.
///
/// **Only the observation.** An earlier version of this constant carried the
/// consequence too — "…and stay unverifiable; clearing the condition protects
/// later ones, not those" — and that half is a prognosis about a later `verify`
/// run, which the two sites do not share.
///
/// The unlistable-directory site returns [`UNRESOLVED_KEY_ID`], an id no
/// keyring can hold, so its entries do stay unverifiable. The failed-mint site
/// returns `key_id_for_index(max_retired)` — a resolvable `key-{N+1}` — with no
/// secret, so once the operator clears the fault and a key is minted under that
/// same label, those entries resolve, their `NO_HMAC_SECRET` hash fails to
/// match, and `verify` reports **tampering**, permanently (`ADR-0007`). The
/// shared sentence told that operator the opposite of what happens.
///
/// This is the mistake #477's Phase 8 recorded and named: what two sites may
/// share is the *observation*, never the *remedy or the prognosis*. It came
/// back here through a Codex Round 1 fix that aligned the second site's wording
/// with the first's, and a `/simplify` pass that then froze the alignment into
/// a constant. Each site now states its own consequence from its own facts.
const ENTRIES_CARRY_NO_HMAC: &str = "Entries written while this lasts carry no HMAC.";

/// What an operator can do about a record that does not state an epoch.
///
/// Shared by the writer, the verifier and rotation — and shared only after
/// checking each, because #478's Phase 8 shared a recovery line across four
/// sites and it was wrong at three of them. Here the action really is one
/// action: the record is advisory, all three consumers fall back to the same
/// derivation without it, and removing it is safe on every one. Each site
/// still states its own consequence; only the action is common.
///
/// Reachable by a person and not by an agent: the file sits under the
/// `audit-secret` prefix, so `PROTECTED_FILE_PATTERNS` blocks AI writes to it
/// while leaving an operator's `rm` alone. An instruction omamori's own threat
/// model lets the AI follow would be a payload, which is the mistake #478
/// found in the interrupted-rotation text.
///
/// A function rather than a `const` so the filename comes from
/// [`EPOCH_RECORD_NAME`]. A `const` cannot interpolate one, which would leave
/// the name spelled twice — and this is the one sentence that tells an operator
/// which file to delete, so a drift here sends them after a file that does not
/// exist. Cheaper to make the mistake impossible than to add a check for it.
fn epoch_record_remedy() -> String {
    format!(
        "Removing {EPOCH_RECORD_NAME} puts this store back on deriving the epoch from the \
         retired key files, which is what omamori did before the record existed."
    )
}

/// The opening words of the symlink rejection, shared by the one place that
/// builds it and the one place that classifies on it.
///
/// #478: `verify_chain` matched `"symlink"` *anywhere* in the message, and
/// every `read_secret` rejection ends with the path — so a store under
/// `~/symlink-tests/` made a FIFO at the secret path read as an attack.
/// `ErrorKind` cannot separate the two, because `symlink_attack_error` and the
/// "not a regular file" rejection are both `InvalidInput`; a prefix can,
/// because the path is always last. `read_secret`'s pre-check comment already
/// recorded this hazard — about a *test* that matched the same way — and the
/// production classifier had the same bug the whole time.
const SYMLINK_ATTACK_PREFIX: &str = "audit path is a symlink";

/// Whether a [`read_secret`] failure is the symlink rejection.
///
/// Next to the constructor rather than at the call site. `symlink_attack_error`
/// below is documented as the one place that rejection is *built*; until #478
/// the one place it was *recognised* sat in another module with the wording
/// copied across the boundary, which is the arrangement that comment exists to
/// prevent. Both halves now move together, and a later switch to a typed
/// payload is a change to this function rather than to its callers.
pub(super) fn is_symlink_attack(e: &std::io::Error) -> bool {
    e.to_string().starts_with(SYMLINK_ATTACK_PREFIX)
}

/// How a failed [`read_secret`] is reported once the key directory itself has
/// been listed successfully.
///
/// Shared by rotation and verification on purpose. #478 exists because the two
/// gave contradictory accounts of one store, and letting each classify the same
/// error independently is how that comes back: a future arm — a distinct
/// verdict for `PermissionDenied`, say — then lands in one and not the other.
/// `NotFound` is the only failure meaning the key is absent rather than
/// unreachable, so it is the only one that keeps its own name.
pub(super) fn classify_secret_failure(e: std::io::Error) -> AuditError {
    match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::SecretUnavailable,
        _ => AuditError::Io(e),
    }
}

/// The one place the symlink rejection is constructed.
///
/// #457 (`/simplify`): `verify_chain` classifies a symlinked secret path by
/// matching this phrase, which makes the wording load-bearing — and this change
/// briefly had two producers of it (`read_secret`'s pre-check and
/// `eloop_message`). Load-bearing text with two authors drifts.
fn symlink_attack_error(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{SYMLINK_ATTACK_PREFIX} (possible attack): {}",
            path.display()
        ),
    )
}

/// The result of enumerating the key directory — either a listing that is
/// known to be complete, or the reason it is not one.
///
/// **The discriminant is what enforces this**, not field privacy: Rust privacy
/// is module-scoped and all three consumers live in this file, so a private
/// field would protect nothing. What the discriminant buys is a change of
/// *kind*. Reaching the number without a listing goes from something a caller
/// can omit — #477 was exactly that omission, taking the index with no branch
/// above it — to something a caller has to write out. Nothing stops this
/// module from building `Listed(BTreeMap::new())` by hand, but stating a
/// listing that was never made is a different and much louder mistake than
/// forgetting to check one.
///
/// #457 (Codex Round 1, P0) established why collapsing "cannot list" into
/// "no retired keys" is not a harmless default: on a rotated store it makes
/// the writer label new entries `"default"` (naming epoch 1 while signing with
/// epoch N), and it makes the verifier resolve `"default"` to the active key
/// and report the mismatch as **tampering** — from nothing worse than an
/// unreadable directory. That fix reached the writer and the verifier.
///
/// #477 is the same hazard on the one consumer it missed, and the only one
/// that *mutates* the store.
pub(super) enum KeyDirScan {
    Listed {
        /// Parsed retired-key index → path, ordered by index.
        retired: BTreeMap<u32, PathBuf>,
        /// What the store says about the highest epoch it has handed out,
        /// read from this same listing.
        epoch: EpochRecord,
        /// Where [`PENDING_NAME`] sits, if the listing saw it.
        ///
        /// **Only rotation looks at this.** The two readers destructure with
        /// `..`, and that is the whole reason a half-finished rotation does not
        /// add a fourth state for them to classify: a key that has not been
        /// renamed into place has not been handed out, so nothing they resolve
        /// can name it. Which epoch is current is answered by the record, and
        /// only by the record.
        pending: Option<PathBuf>,
    },
    /// The listing could not be obtained, or could not be trusted to be whole.
    /// The string states what was observed, with no interpretation — callers
    /// wrap it in whatever their own context can actually claim.
    Unlistable(String),
}

/// The file recording the store's highest handed-out epoch.
///
/// Under the `audit-secret` prefix on purpose: `PROTECTED_FILE_PATTERNS`
/// (`engine/hook.rs`) matches that prefix against the file name, so this file
/// is covered by the AI write block from the moment it exists, with no second
/// entry to keep in step. Equally on purpose it does **not** end in
/// `.retired` — [`fold_key_dir_entries`] requires that suffix, so no version
/// of omamori, including ones that predate this file, can mistake the record
/// for a retired key and shift every epoch by one.
pub(super) const EPOCH_RECORD_NAME: &str = "audit-secret.epoch";

/// Where a rotation builds the replacement key before anything else moves.
///
/// Under the `audit-secret` prefix so `PROTECTED_FILE_PATTERNS` covers it, and
/// deliberately not ending in `.retired` so no version of omamori counts it as
/// an epoch — the same two constraints [`EPOCH_RECORD_NAME`] is named under.
///
/// A file here is a key **nobody has been given**. The readers never look at
/// this path, so no entry can name it, which is what makes a leftover safe to
/// delete — the opposite of a `.retired` file, where deleting one destroys the
/// only thing that can authenticate an epoch's entries.
pub(super) const PENDING_NAME: &str = "audit-secret.pending";

pub(super) fn pending_path_for(secret_path: &Path) -> PathBuf {
    secret_path.with_file_name(PENDING_NAME)
}

/// The record holds one decimal integer. 16 bytes is past `u32::MAX`'s ten
/// digits with room for a trailing newline, and small enough that a hostile
/// file cannot be read into memory in bulk.
const MAX_EPOCH_FILE_BYTES: u64 = 16;

pub(super) fn epoch_record_path(secret_path: &Path) -> PathBuf {
    secret_path.with_file_name(EPOCH_RECORD_NAME)
}

/// What the key store records about the highest epoch it has ever handed out.
///
/// Every defect this record closes is one shape: **an epoch inferred from
/// files that can be deleted**. `max_retired + 1` reads the current epoch off
/// the retired slots, so an operator tidying up after a prune moves the store
/// backwards, and the next rotation hands out a number that has already been
/// used — under which entries were already signed. Their keys are gone either
/// way; what the inference adds is that the store stops *knowing* they are
/// gone and reports the resulting mismatch as tampering, permanently
/// (`ADR-0007` forbids rewriting the entries).
///
/// A number the store wrote down cannot be lowered by deleting some other
/// file. That is the whole mechanism.
///
/// Not a per-key tag. ADR-0008 proposed one — each key file naming its own
/// epoch — and it cannot work: what has to be told apart is a *lost*
/// generation, and a file that is gone carries no tag.
pub(super) enum EpochRecord {
    /// The store states its highest handed-out epoch. Always ≥ 1;
    /// [`read_epoch_record`] rejects 0, which is not an epoch any writer emits.
    Recorded(u32),
    /// No record file. Epochs derive from the retired slots exactly as they did
    /// before this file existed (see [`active_epoch`]). **Not a fault** — a
    /// store that has not rotated since upgrading has nothing to record,
    /// because rotation is the only thing that writes one.
    Absent,
    /// A file is there but does not state an epoch this program wrote. Carries
    /// what was observed, with no interpretation — the rule
    /// [`KeyDirScan::Unlistable`] follows.
    Unreadable(String),
}

impl EpochRecord {
    /// The recorded number, or the reason the store cannot be trusted to
    /// answer.
    ///
    /// A `Result` rather than an `Option` with a default, because all three
    /// consumers have to refuse an unreadable record (`#479`: one invariant is
    /// not guarded at two depths) and none of them may fold it into "no
    /// record". That fold is the `.ok()` collapse #478 took out of
    /// `read_secret`, in a place where its consequence is not a wrong message
    /// but a silently lowered epoch.
    pub(super) fn recorded(&self) -> Result<u32, &str> {
        match self {
            Self::Recorded(n) => Ok(*n),
            Self::Absent => Ok(0),
            Self::Unreadable(reason) => Err(reason),
        }
    }
}

/// Read the record, classifying every way it can fail to state an epoch.
///
/// Fail-closed by construction: no arm returns [`EpochRecord::Absent`].
/// Absence is decided by the directory listing and only there — a
/// `PermissionDenied` on this path means the store *has* a record it cannot
/// show, which is the opposite of not having one.
fn read_epoch_record(path: &Path) -> EpochRecord {
    let content = match crate::atomic_file::read_to_string_capped(path, MAX_EPOCH_FILE_BYTES) {
        Ok(content) => content,
        Err(e) => return EpochRecord::Unreadable(format!("cannot read {}: {e}", path.display())),
    };
    match parse_epoch(path, &content) {
        Ok(n) => EpochRecord::Recorded(n),
        Err(reason) => EpochRecord::Unreadable(reason),
    }
}

/// Classify the *content* of a record.
///
/// Split from [`read_epoch_record`] because the two readers disagree about
/// exactly one thing: what an absent file means. That reader has the directory
/// listing behind it, so absence never reaches it and every error is a fault;
/// [`write_epoch_record`] has no listing, and for it an absent file is the
/// ordinary first write. Sharing the parse and not the open is what keeps the
/// two from drifting on the part they *do* agree about.
fn parse_epoch(path: &Path, content: &str) -> Result<u32, String> {
    let trimmed = content.trim();
    match trimmed.parse::<u32>() {
        // Canonical decimal, and at least 1: the two conditions
        // `fold_key_dir_entries` puts on a retired slot number, for the same
        // reasons. `01` and `+1` are not numbers this program writes, and
        // epoch 0 does not exist — epoch 1 is `"default"`.
        Ok(n) if n >= 1 && n.to_string() == trimmed => Ok(n),
        // The content is not quoted back. It is attacker-controlled bytes on a
        // path any local process can write, and the operator gains nothing
        // from it: the remedy is the same whatever it says.
        _ => Err(format!("{} does not hold a key epoch", path.display())),
    }
}

/// Record `epoch` as the highest this store has handed out, and return the
/// number the record holds afterwards.
///
/// **Monotonic.** The value is re-read here rather than taken from whatever the
/// caller scanned, because a caller can hold a stale observation: the recovery
/// path runs under a *shared* lock, so two processes can both see epoch 2
/// missing, and if one of them has meanwhile written 4 and minted a key for it,
/// a blind write of 3 walks the record backwards. The next `create_secret`
/// then fails `AlreadyExists`, reads the epoch-4 key, and labels it `key-3` —
/// a key travelling under another epoch's name, which is the shape this whole
/// change removes. Returning the number actually on disk is the other half:
/// skipping the write while still naming the caller's number would leave the
/// same mismatch (Codex Round 1, P1).
///
/// The read is still a TOCTOU against a concurrent writer. What it buys is a
/// direction — every write moves the number up — which is the property the
/// defect needs violated.
///
/// Durable before it returns for the write it does perform:
/// `atomic_write_with_mode` writes to a temp file, `sync_all`s it, renames, and
/// then asks the parent directory to sync. **The file sync is checked; the
/// parent's is best-effort** (`atomic_file::fsync_parent` swallows its error,
/// by a design decision that predates this file). So a record that has returned
/// `Ok` is durable to a process crash, and to a power loss only as far as the
/// directory entry made it — see ADR-0008's residual list.
pub(super) fn write_epoch_record(secret_path: &Path, epoch: u32) -> Result<u32, std::io::Error> {
    let path = epoch_record_path(secret_path);
    // Not `read_epoch_record`: that one has a directory listing behind it and
    // treats every failure as a fault, `NotFound` included. Here `NotFound` is
    // the ordinary first write — rotation creates this file, it is not shipped.
    match crate::atomic_file::read_to_string_capped(&path, MAX_EPOCH_FILE_BYTES) {
        Ok(content) => match parse_epoch(&path, &content) {
            // Already at or past this epoch: someone else claimed further, and
            // their number is the one the store is on.
            Ok(current) if current >= epoch => return Ok(current),
            Ok(_) => {}
            // Fail-closed, as the three readers do. Overwriting a record that
            // cannot be parsed would destroy the bytes an operator still has to
            // look at, and this is the only path that could do it silently.
            Err(reason) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, reason));
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Present and unreadable — a permission fault, a FIFO, a directory.
        // Refuse for the same reason as an unparseable one: what is there
        // might be a higher number.
        Err(e) => return Err(e),
    }
    crate::atomic_file::atomic_write_with_mode(&path, epoch.to_string().as_bytes(), 0o600)?;
    Ok(epoch)
}

/// Which epoch the key at `audit-secret` belongs to.
///
/// `max(recorded, max_retired + 1)`, and each side covers what the other
/// cannot:
///
/// - **`max_retired + 1`** is the derivation that predates the record, and it
///   is still right whenever the retired slots are intact. A store that has
///   never recorded an epoch passes `recorded` = 0 and gets exactly this
///   number — which is what makes the record a pure addition rather than a
///   migration.
/// - **`recorded`** covers the cases where the slots are not intact: a retired
///   key deleted, or a rotation that handed out a number and then lost the key
///   to it. Both lower `max_retired`; neither lowers what the store wrote down.
///
/// Taking the larger never walks an epoch backwards, and walking backwards is
/// what every defect here has in common.
pub(super) fn active_epoch(retired: &BTreeMap<u32, PathBuf>, recorded: u32) -> u32 {
    max_retired_index(retired).saturating_add(1).max(recorded)
}

/// Highest retired index present, or 0 when there are none. Replaces the old
/// count-based derivation: with a gap (`.1` and `.3`, no `.2`) the count said
/// 2 and named the next key `key-3`, colliding with the key `.3.retired`
/// already holds.
///
/// Takes the map, not the scan: there is no way to ask for this number without
/// first matching [`KeyDirScan::Listed`] to obtain one.
pub(super) fn max_retired_index(retired: &BTreeMap<u32, PathBuf>) -> u32 {
    retired.keys().next_back().copied().unwrap_or(0)
}

/// One `read_dir` pass over the key directory.
///
/// #457 P4-a/P4-b: three functions used to each answer "how many rotations
/// have there been?" differently — `retired_key_count` counted *name matches*
/// without parsing the index, `current_key_id` derived `count + 1`, and
/// `load_keyring` probed `audit-secret.{n}.retired` for n = 1, 2, … stopping
/// at the first gap. Reading the directory once and parsing indices as they
/// actually are collapses all three onto the same answer.
///
/// Probing a constructed path was independently unsafe: on a case-insensitive
/// filesystem (APFS default) `open("audit-secret.1.retired")` **succeeds** for
/// a file named `audit-secret.1.RETIRED`, which the name-matching count never
/// saw. Measured: one such file on a never-rotated host produced
/// `chain broken at #0`.
/// The one place a listing failure is put into words.
///
/// `symlink_attack_error` makes the argument 60 lines up and it applies here
/// unchanged: load-bearing text with two authors drifts. Five assertions and a
/// `report.rs` redaction fixture key on the `cannot list` prefix, so the two
/// failures state it once and differ only in what they actually observed —
/// whether the listing never started, or stopped at a known position.
fn unlistable(parent: &Path, stopped_after: Option<usize>, e: &std::io::Error) -> KeyDirScan {
    KeyDirScan::Unlistable(match stopped_after {
        None => format!("cannot list {}: {e}", parent.display()),
        Some(seen) => format!(
            "cannot list all of {} — the listing stopped after {seen} entries: {e}",
            parent.display()
        ),
    })
}

fn scan_key_dir(secret_path: &Path) -> KeyDirScan {
    // `parent()` returning `None` is structurally unreachable here: every call
    // site derives this path with `with_file_name`, which always appends a
    // component, and `resolved_audit_path` admits only absolute paths. Handled
    // as `Unlistable` rather than given its own variant, because a variant for
    // an unreachable state is a variant nothing can test.
    let Some(parent) = secret_path.parent() else {
        return KeyDirScan::Unlistable("audit secret path has no parent directory".to_string());
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        // A directory that does not exist yet genuinely means "no rotations
        // have happened" — this is every fresh install, before
        // `load_or_create_secret` creates the tree. Treating it as
        // "unreadable" made `load_signing_key` bail out before the secret was
        // ever created, so a new install wrote entries with no HMAC at all.
        // Only an *existing* directory we cannot look into is a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return KeyDirScan::Listed {
                retired: BTreeMap::new(),
                epoch: EpochRecord::Absent,
                pending: None,
            };
        }
        Err(e) => return unlistable(parent, None, &e),
    };

    fold_key_dir_entries(parent, entries.map(|e| e.map(|entry| entry.file_name())))
}

/// The listing half of [`scan_key_dir`], as a fold over names.
///
/// Split out because the failure this closes cannot be provoked through the
/// real syscall from a test: a per-entry `Err` needs a removable volume, a
/// network filesystem, or failing hardware. Taking an iterator instead of a
/// `ReadDir` makes the branch reachable from a unit test, and costs nothing —
/// `DirEntry::path()` is defined as `root.join(file_name)`, so rebuilding the
/// path from the parent is the same value.
///
/// **A per-entry `Err` fails the whole listing.** It is tempting to skip the
/// bad entry and keep the rest, which is what `filter_map(|e| e.ok())` did.
/// Measured: enumerating a 300-file directory while its volume was detached
/// returned 151 `Ok`s and then one `Err`, and `std` sets `end_of_stream` on
/// that error — so the remainder was never read. Skipping the error does not
/// drop one entry, it drops **everything after it, silently, as a listing that
/// looks complete**. For a store whose highest epochs sort last, that is
/// exactly the set that matters.
pub(super) fn fold_key_dir_entries(
    parent: &Path,
    entries: impl Iterator<Item = std::io::Result<std::ffi::OsString>>,
) -> KeyDirScan {
    let mut retired = BTreeMap::new();
    // Whether the record exists is answered by this listing, never by a
    // separate `exists()` probe on a constructed path. `scan_key_dir`'s header
    // records why: on a case-insensitive filesystem (APFS default) a probe
    // succeeds for `AUDIT-SECRET.EPOCH`, a name the listing does not consider a
    // record — so the two would disagree about which files are present, and a
    // store could read its own epoch off a file `rotate` will never update.
    let mut epoch_present = false;
    // Same rule as the record: the listing decides what exists, never a
    // constructed-path `exists()`. A probe on a case-insensitive filesystem
    // answers for `AUDIT-SECRET.PENDING` too, and rotation would then delete a
    // file its own `create_new` is about to collide with under a different
    // name.
    let mut pending = None;

    for (seen, entry) in entries.enumerate() {
        let file_name = match entry {
            Ok(name) => name,
            // Deliberately not interpreting the errno: the reachable macOS case
            // reports EINVAL, not the EIO the issue predicted, and the two
            // platforms take different `ReadDir::next` bodies. State the
            // position and the error; let the operator's context supply the
            // cause.
            Err(e) => return unlistable(parent, Some(seen), &e),
        };
        let name = file_name.to_string_lossy();
        if name == EPOCH_RECORD_NAME {
            epoch_present = true;
            continue;
        }
        if name == PENDING_NAME {
            pending = Some(parent.join(&file_name));
            continue;
        }
        let Some(middle) = name
            .strip_prefix("audit-secret.")
            .and_then(|rest| rest.strip_suffix(".retired"))
        else {
            continue;
        };
        // Three conditions, each closing a different way a name can look like
        // an epoch without being one:
        //
        // - **Canonical decimal.** `parse` alone accepts `01` and `+1`, mapping
        //   them onto the same index as `1` — which file wins would then depend
        //   on `read_dir` order.
        // - **`index >= 1`.** Epochs start at 1: `"default"` *is* epoch 1 and
        //   rotation creates `.1`, `.2`, … A `.0.retired` would register a
        //   `key-0` that no writer can produce (Codex Round 1 P1).
        // - **`index < u32::MAX`.** The next epoch is `index + 1`; admitting
        //   `u32::MAX` would overflow it here and in `rotate_key` (Codex Round
        //   1 P2).
        match middle.parse::<u32>() {
            Ok(index) if (1..u32::MAX).contains(&index) && index.to_string() == middle => {
                retired.insert(index, parent.join(&file_name));
            }
            // Anything else is not an epoch. **Ignored, not counted** — a user
            // taking a backup must not shift the `key_id` of every entry
            // written afterwards, which is the mechanism behind the "back up
            // your key and the log stops verifying" failure.
            _ => {}
        }
    }

    KeyDirScan::Listed {
        retired,
        // Read only when the listing saw it. An absent record and an
        // unreadable one are different states and the difference is not
        // recoverable from an error: `read_epoch_record` has no `Absent` arm
        // precisely so that this decision is made here, from the listing, and
        // nowhere else.
        epoch: if epoch_present {
            read_epoch_record(&parent.join(EPOCH_RECORD_NAME))
        } else {
            EpochRecord::Absent
        },
        pending,
    }
}

/// The `key_id` naming `epoch`. `"default"` for epoch 1, `key-{N}` above it.
///
/// Takes the epoch rather than the highest retired index, which is the whole
/// of PR-C1 at this level: the previous form derived the epoch itself, by
/// adding one to the single input that deleting a file can lower. Callers
/// compute it once through [`active_epoch`], where the record gets a say, and
/// name it here.
///
/// Every caller passes an [`active_epoch`] result, which is ≥ 1, so there is
/// no epoch 0 to name — the `key-0` that would fall out of the `else` is a
/// label [`is_writer_emitted_key_id`] rejects, and it stays unreachable
/// because the epoch has one producer.
fn key_id_for_epoch(epoch: u32) -> String {
    if epoch == 1 {
        "default".to_string()
    } else {
        format!("key-{epoch}")
    }
}

/// The `key_id` written when the key directory cannot be enumerated.
///
/// Deliberately not of the form any epoch takes, so `keyring.get` can never
/// resolve it: the entry was written with no HMAC at all, and pretending it
/// belongs to an epoch would make a later verify recompute a hash for a key
/// that never signed it and call the mismatch tampering.
pub(super) const UNRESOLVED_KEY_ID: &str = "unresolved";

/// Is `id` a label one of omamori's writers could have produced?
///
/// `"default"` (epoch 1), `key-{N}` in canonical decimal, and
/// [`UNRESOLVED_KEY_ID`]. Anything else did not come from this program.
///
/// The verifier uses this to decide how to describe an entry whose key it
/// cannot resolve. `key_id` is a plain field in `audit.jsonl` that anyone who
/// can write the file can edit, so "the key file must be missing" is a guess,
/// not a fact — and for an id no writer emits, it is a guess that is wrong.
/// Which file on disk holds the key `id` names.
///
/// The exit-2 remedy used to say `restore the key file for "default"`, and
/// there is no file called `default`: the operator had to know the id→filename
/// mapping to act on it, and that mapping lived only in ADR-0008 (Phase 8 UX).
/// Both branches are two-valued because an epoch's key sits in `audit-secret`
/// while it is current and moves to `audit-secret.{N}.retired` when the next
/// rotation displaces it — the entry does not record which of the two it was.
pub(super) fn expected_key_file(id: &str) -> Option<String> {
    if id == "default" {
        return Some(
            "audit-secret, or audit-secret.1.retired if this store has rotated".to_string(),
        );
    }
    let n: u32 = id.strip_prefix("key-")?.parse().ok()?;
    // #478: this branch said `.{n-1}.retired`. Epoch N retires into slot N —
    // `rotate_key_locked` renames the key it is displacing into
    // `audit-secret.{max_retired + 1}.retired` and labels it
    // `key_id_for_index(max_retired)`, i.e. `key-{max_retired + 1}`, so the
    // number in the id and the number in the filename are the same one. The
    // paragraph above this function said so, and the `"default"` branch (epoch
    // 1 → `.1.retired`) was already right; one line of code disagreed with all
    // of them.
    //
    // Not a harmless off-by-one. This string is only printed when the named
    // epoch is *below* the store's ceiling — the operator-tidying case — so on
    // a store holding `.1` and `.3`, an entry naming `key-2` sent the operator
    // to `audit-secret.1.retired`, a file that exists and holds a different
    // epoch's key. Restoring it is a worse outcome than finding nothing.
    //
    // `key-0` and `key-1` return `None`, for the reason
    // `is_writer_emitted_key_id` also rejects them: epoch 1 is `"default"`, and
    // `.0.retired` is a slot the directory scan refuses as one no writer can
    // produce. The old `checked_sub(1)` rejected only `key-0`, and by
    // arithmetic accident rather than by agreeing with anything.
    //
    // Agreeing *for the same reason* is not the same as agreeing everywhere,
    // and the two still part company on `key-02`: `is_writer_emitted_key_id`
    // requires canonical decimal and rejects it, `parse` here accepts it. The
    // one production caller (`classify_unavailable_key`) gates on the stricter
    // of the two first, so the difference is unreachable — but it is latent,
    // not absent, and a claim that they match would be the kind this change
    // exists to remove.
    if n < 2 {
        return None;
    }
    Some(format!(
        "audit-secret.{n}.retired, or audit-secret if epoch {n} is still the current key"
    ))
}

pub(super) fn is_writer_emitted_key_id(id: &str) -> bool {
    if id == "default" || id == UNRESOLVED_KEY_ID {
        return true;
    }
    match id.strip_prefix("key-") {
        // Canonical decimal only: `key-01` and `key-2 ` are not ids this
        // program writes, and the round-trip is what rejects them.
        Some(n) => n.parse::<u32>().is_ok_and(|v| v >= 2 && v.to_string() == n),
        None => false,
    }
}

/// What `load_keyring` could not do, so callers can report it instead of
/// silently verifying against a partial key set.
pub(super) enum KeyringAnomaly {
    /// More retired keys exist on disk than `MAX_KEYRING_KEYS` allows. The
    /// *highest* indices are kept: the oldest keys are the ones whose entries
    /// are most likely already pruned, and dropping the newest would make the
    /// current epoch unverifiable.
    Truncated {
        found: usize,
        loaded: usize,
        lowest_loaded_index: u32,
    },
    /// A file that is shaped like a retired key but could not be read.
    Unreadable { name: String, reason: String },
    /// The key directory itself could not be listed, so which epochs exist is
    /// unknown. Every id resolution below is a guess; callers must treat this
    /// as "cannot verify" rather than as an empty key set.
    DirectoryUnreadable { reason: String },
    /// The epoch record is there but does not state an epoch, so which id names
    /// the active key is unknown. Fatal for the reason `DirectoryUnreadable` is
    /// fatal: the fallback resolves `"default"` to the active key on a rotated
    /// store, and every entry then reads as altered.
    EpochRecordUnreadable { reason: String },
}

impl KeyringAnomaly {
    pub(super) fn describe(&self) -> String {
        match self {
            Self::Truncated {
                found,
                loaded,
                lowest_loaded_index,
            } => format!(
                "audit keyring holds {found} retired keys, above the {MAX_KEYRING_KEYS} limit \
                 — only the {loaded} newest were loaded (from key-{lowest_loaded_index}). \
                 Entries signed with older keys cannot be verified."
            ),
            Self::Unreadable { name, reason } => format!(
                "audit keyring: cannot read {name} ({reason}) — entries signed with that key \
                 cannot be verified."
            ),
            Self::DirectoryUnreadable { reason } => format!(
                "audit keyring: {reason} — which key epochs exist is unknown, so no entry can \
                 be authenticated against the key it names."
            ),
            Self::EpochRecordUnreadable { reason } => format!(
                "audit keyring: {reason} — which key epoch is active is unknown, so no entry \
                 can be authenticated against the key it names."
            ),
        }
    }

    /// What to do about it, for the surfaces that carry a repair.
    ///
    /// Separate from [`Self::describe`] because the two travel to different
    /// places. `describe` reaches `doctor`, whose whole job at that line is to
    /// name the cause and point at `omamori audit verify` — its siblings are
    /// one short clause each, and inlining a repair there took this branch's
    /// wording past 250 characters (pinned by `cli.rs`, and measured again
    /// when PR-C1 briefly put the remedy back into `describe`).
    ///
    /// Separate from the *caller*, too, for the reason #477 had to withdraw a
    /// caller-side remedy: the CLI arm knows it has an unusable keyring and not
    /// which of the two conditions produced one, so any sentence it adds is
    /// right for one of them at best.
    ///
    /// `None` for the two non-fatal anomalies. A truncated ring or one
    /// unreadable retired key still authenticates everything whose key did
    /// load, and what to do about the gap depends on whether those keys exist
    /// anywhere else — no single sentence covers it, and `fatal_anomaly` never
    /// selects them.
    pub(super) fn remedy(&self) -> Option<String> {
        match self {
            Self::DirectoryUnreadable { .. } => {
                Some("To fix: make that directory listable again, then re-run.".to_string())
            }
            Self::EpochRecordUnreadable { .. } => Some(epoch_record_remedy()),
            Self::Truncated { .. } | Self::Unreadable { .. } => None,
        }
    }

    /// The path-free classification machine consumers branch on.
    ///
    /// #506: the two fatal anomalies used to reach `report --json` as one
    /// `AuditError::KeyringUnusable`, and `chain_status_for_error` pinned
    /// `kind: "directory_unreadable"` on both — so a store whose directory was
    /// perfectly listable and whose epoch record simply stated no epoch
    /// reported the wrong cause to every consumer of that field. The field's
    /// own doc calls it stable, which is an argument for not changing it
    /// lightly and not one for it being right.
    ///
    /// Carrying the anomaly through the verifier meant carrying the mislabel
    /// with it. Splitting the two here is what stops that, and it is why this
    /// is a method on the anomaly rather than a literal at the call site.
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::DirectoryUnreadable { .. } => "directory_unreadable",
            Self::EpochRecordUnreadable { .. } => "epoch_record_unreadable",
            // Neither is fatal, so neither reaches `chain_status` today —
            // `fatal_anomaly` does not select them. Named rather than left to a
            // catch-all so that promoting one later is a compile-time question
            // about what to call it, not a silent inheritance of the label
            // above it.
            Self::Truncated { .. } => "keyring_truncated",
            Self::Unreadable { .. } => "retired_key_unreadable",
        }
    }
}

/// All keys this host can verify with, plus what went wrong assembling them.
pub(super) struct Keyring {
    keys: BTreeMap<String, [u8; 32]>,
    anomalies: Vec<KeyringAnomaly>,
}

impl Keyring {
    /// A ring holding nothing, for a caller that reached a verdict before one
    /// could be assembled.
    ///
    /// #506: `verify_chain` now records an unusable key store and keeps
    /// walking, and one of the states it records — a symlink planted on the
    /// secret path — is observed *before* the directory is listed, deliberately
    /// (at mode 0300 the directory is searchable but not listable, so scanning
    /// first would report "cannot list" and never mention the attack). There is
    /// no listing to build a ring from at that point, and the walk does not ask
    /// for one: every line is tallied rather than trusted once the failure is
    /// recorded. This is what it holds while that is true.
    pub(super) fn empty() -> Self {
        Self {
            keys: BTreeMap::new(),
            anomalies: Vec::new(),
        }
    }

    pub(super) fn get(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys.get(id)
    }

    /// Whether the ring holds no keys.
    ///
    /// Test-only on purpose. Production asks through [`Self::report_and_usable`]
    /// so that the emptiness check cannot end up ahead of the anomaly report;
    /// leaving a bare `is_empty` reachable would put that ordering back within
    /// reach of the next edit. Tests assert on the key count itself, which is
    /// the narrower claim.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &[u8; 32])> {
        self.keys.iter()
    }

    pub(super) fn anomalies(&self) -> &[KeyringAnomaly] {
        &self.anomalies
    }

    /// The highest epoch number this store currently shows any sign of.
    ///
    /// Used to tell "your key file went missing" apart from "this epoch has
    /// never been on this machine". It is deliberately phrased as *currently
    /// shows*: deleting a retired key file still lowers this number for the
    /// epoch that file held. What PR-C1 changed is the *active* epoch, which
    /// the record pins even with every retired key gone
    /// (`deleting_the_last_retired_key_reads_as_cannot_verify`). Either way
    /// this grounds an observation, never an accusation.
    pub(super) fn highest_known_epoch(&self) -> u32 {
        self.keys
            .keys()
            .filter_map(|id| match id.as_str() {
                "default" => Some(1),
                other => other.strip_prefix("key-")?.parse::<u32>().ok(),
            })
            .max()
            .unwrap_or(0)
    }

    /// Print every anomaly on stderr, then say whether this ring can answer at
    /// all.
    ///
    /// The two are one call because the order between them is load-bearing and
    /// was previously only a convention. #477 made an unlistable directory
    /// yield an *empty* ring, which put the emptiness check ahead of the
    /// reporting loop on a surface that has no exit code to spend
    /// (`hash_cwd_candidates`): it returned "nothing available" without ever
    /// saying why, and the caller's message for that names a missing secret —
    /// false, when the secret is readable and only the directory is not. A
    /// caller that cannot sequence the two cannot reintroduce it.
    pub(super) fn report_and_usable(&self) -> bool {
        for anomaly in &self.anomalies {
            eprintln!("omamori warning: {}", anomaly.describe());
        }
        !self.keys.is_empty()
    }

    /// The first anomaly that makes verification untrustworthy, if any.
    ///
    /// `DirectoryUnreadable` and `EpochRecordUnreadable` qualify: under either,
    /// `"default"` would resolve to the active key on a rotated store and every
    /// entry would read as tampered. A truncated ring or one unreadable file is
    /// bounded — the keys that did load still authenticate their own entries,
    /// and the gap is reported.
    pub(super) fn fatal_anomaly(&self) -> Option<&KeyringAnomaly> {
        self.anomalies.iter().find(|a| {
            matches!(
                a,
                KeyringAnomaly::DirectoryUnreadable { .. }
                    | KeyringAnomaly::EpochRecordUnreadable { .. }
            )
        })
    }
}

/// Load every key this host can verify with (active + retired).
///
/// #457 P4-b: returns a `Keyring` rather than a bare map so that "we could not
/// load everything" is a value the caller must look at, instead of being
/// indistinguishable from "there was nothing more to load".
pub(super) fn load_keyring(secret_path: &Path) -> Keyring {
    with_key_store_lock(secret_path, false, |_lock| load_keyring_locked(secret_path))
}

fn load_keyring_locked(secret_path: &Path) -> Keyring {
    let mut keys = BTreeMap::new();
    let mut anomalies = Vec::new();

    // An unlistable directory yields an **empty** ring, not a partial one.
    // Registering the active key here would have to name it, and the only
    // number available to name it with is the one the failed scan could not
    // produce. `verify` never observes the difference — `fatal_anomaly` stops
    // it first — but `hash_cwd_candidates` does not consult that, and handing
    // an investigator a candidate list under a guessed epoch label is the
    // forensic version of the same mislabelling #457 closed for the writer.
    let (retired, record) = match scan_key_dir(secret_path) {
        KeyDirScan::Unlistable(reason) => {
            anomalies.push(KeyringAnomaly::DirectoryUnreadable { reason });
            return Keyring { keys, anomalies };
        }
        KeyDirScan::Listed { retired, epoch, .. } => (retired, epoch),
    };
    // PR-C1 (yotta 判断12): fatal for the same reason the arm above is. Every
    // id resolved below would be resolved against an epoch the store did not
    // confirm, and the ring is what `verify` authenticates the whole log
    // against.
    let recorded = match record.recorded() {
        Ok(recorded) => recorded,
        Err(reason) => {
            anomalies.push(KeyringAnomaly::EpochRecordUnreadable {
                reason: reason.to_string(),
            });
            return Keyring { keys, anomalies };
        }
    };
    let epoch = active_epoch(&retired, recorded);

    // Active key → the id the writer is currently stamping.
    if let Ok(secret) = read_secret(secret_path) {
        keys.insert(key_id_for_epoch(epoch), secret);
        // Before any rotation the active key *is* epoch 1, which is what
        // `"default"` names. After a rotation `"default"` belongs to
        // `.1.retired` instead, registered below.
        //
        // PR-C1 (Codex Round 3, Minor-1): the condition is the *epoch*, not
        // `max_retired == 0`, and the difference is the whole of the
        // deleted-retired-key defect. On a store that recorded epoch 2 and then
        // had its only retired key removed, `max_retired` is 0 — so the old
        // condition aliased `"default"` onto the epoch-2 key, and every epoch-1
        // entry was checked against bytes that never signed it and reported as
        // tampering. With the record consulted, `"default"` resolves to nothing
        // and those entries land in cannot-verify, which is what actually
        // became of them.
        if epoch == 1 {
            keys.insert("default".to_string(), secret);
        }
    }

    let found = retired.len();
    let skip = found.saturating_sub(MAX_KEYRING_KEYS);
    let mut lowest_loaded_index = None;
    for (index, path) in retired.iter().skip(skip) {
        match read_secret(path) {
            Ok(secret) => {
                lowest_loaded_index.get_or_insert(*index);
                // Epoch 1 was written before rotation existed, so its entries
                // carry `"default"`. Registering both ids is an alias for one
                // key, not two distinct keys.
                if *index == 1 {
                    keys.insert("default".to_string(), secret);
                }
                keys.insert(format!("key-{index}"), secret);
            }
            // #471: the full path, not just the file name. `DirectoryUnreadable`
            // names the directory it failed on, and an operator reading the two
            // together had one that said where and one that said only which.
            // The file name alone is also ambiguous once more than one store
            // exists on a machine, which is exactly when a diagnostic gets read.
            Err(e) => anomalies.push(KeyringAnomaly::Unreadable {
                name: path.display().to_string(),
                reason: e.to_string(),
            }),
        }
    }
    if skip > 0 {
        anomalies.push(KeyringAnomaly::Truncated {
            found,
            loaded: found - skip,
            lowest_loaded_index: lowest_loaded_index.unwrap_or(0),
        });
    }

    Keyring { keys, anomalies }
}

// ---------------------------------------------------------------------------
// Secret I/O (symlink-safe)
// ---------------------------------------------------------------------------

pub(super) fn load_or_create_secret(path: &Path, policy: KeyWarnPolicy) -> Option<[u8; 32]> {
    if let Ok(secret) = read_secret(path) {
        return Some(secret);
    }
    match create_secret(path) {
        Ok(secret) => Some(secret),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match read_secret(path) {
            Ok(secret) => Some(secret),
            Err(e) => {
                // #478: not "race". `O_CREAT|O_EXCL` returning `AlreadyExists`
                // is a sound observation that something occupies the path —
                // measured: a dangling symlink, a live symlink, a FIFO, a
                // directory, a mode-000 file and a too-short key file all
                // produce it — and this second read is what says why it is not
                // usable. A concurrent writer is one way to arrive here and the
                // least likely one; the ordinary cause is a file that has been
                // there all along. Calling it a race filed a standing
                // permissions fault as transient contention, which is the
                // difference between an operator who runs `ls -l` and one who
                // retries.
                //
                // #518: throttled, and this is the site that made the case for
                // it — the file is still there on the next command, so this
                // repeated on every guarded one for as long as the store stayed
                // broken.
                if may_warn(policy, WARN_KIND_SECRET_PATH_OCCUPIED, path) {
                    eprintln!(
                        "omamori warning: something already occupies the audit secret path \
                         and cannot be read as a key: {e}"
                    );
                }
                None
            }
        },
        Err(e) => {
            if may_warn(policy, WARN_KIND_SECRET_UNREADABLE, path) {
                eprintln!("omamori warning: audit secret unavailable: {e}");
            }
            None
        }
    }
}

pub(super) fn read_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    // #457 P4-d: inspect the file before opening it. `symlink_metadata` is a
    // stat, which never blocks; `open` can.
    //
    // - A FIFO at this path makes `open(O_RDONLY)` block until someone writes.
    //   That would hang `verify` *and every hook append*, i.e. omamori stops
    //   protecting anything, from one `mkfifo` in the data directory.
    // - A multi-gigabyte regular file would be pulled into memory in full by
    //   `read_to_string` below, before `decode_hex_secret`'s length check
    //   could reject it.
    //
    // The stat is an early rejection with a precise message, **not** the
    // enforcement. Both hazards are re-checked after the open, because a stat
    // followed by an open is a TOCTOU window: swap the path for a FIFO in
    // between and the pre-check passes while the open blocks anyway. omamori
    // reads this file on every command, so an attacker gets unlimited retries
    // and the race is not a meaningful obstacle. `open_read_nofollow` passes
    // `O_NONBLOCK` so the open itself cannot hang, and the checks below act on
    // the file that was actually opened rather than on the name.
    let meta = fs::symlink_metadata(path)?;
    // A symlink must keep producing the existing "possible attack" wording.
    // `verify_chain` tells a symlinked secret path apart from an ordinary
    // missing one by matching that phrase, so folding symlinks into the
    // generic "not a regular file" case below would silently downgrade a
    // symlink attack to an unremarkable I/O error. (Codex Round 1: the
    // existing `read_secret_rejects_symlink` test did not catch this, because
    // it matched `contains("symlink")` against a message that embeds a path
    // whose directory name contains the word.)
    if meta.file_type().is_symlink() {
        return Err(symlink_attack_error(path));
    }
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "audit secret path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if meta.len() > MAX_SECRET_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "audit secret file is {} bytes, expected at most {MAX_SECRET_FILE_BYTES}: {}",
                meta.len(),
                path.display()
            ),
        ));
    }

    // The post-open re-check that used to sit here moved into
    // `atomic_file::open_read_regular` (#468): keeping it on this caller is
    // what let the next caller ship without one.
    let file = open_read_nofollow(path)?;
    let mut hex = String::new();
    // `take` bounds the read at the descriptor. The `meta.len()` check above
    // cannot: a file that passed it can be extended before this line runs.
    std::io::BufReader::new(file)
        .take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_string(&mut hex)?;
    if hex.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "audit secret file exceeds {MAX_SECRET_FILE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    decode_hex_secret(hex.trim())
}

pub(super) fn create_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let mut secret = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).map_err(|e| eloop_message(e, path))?;
    // C-F3: a `write_all` that dies partway — ENOSPC, EIO, a quota — used to
    // leave a short `audit-secret` behind that nothing ever removed.
    // `read_secret` then rejects it on its length and `create_secret` cannot
    // replace it (`create_new`), so the store has no usable key until a person
    // deletes the file by hand. Write and sync are one fallible step now, and
    // the file goes away if either half of it fails.
    //
    // The removal is best-effort of necessity: if it fails there is nothing
    // further to try, and the write error is the one worth reporting. What
    // changes is that the ordinary failure — a full disk — no longer bricks
    // the store.
    if let Err(e) = file
        .write_all(hex.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    drop(file);
    // The sync above makes the bytes durable; this makes the *name* durable.
    // Best-effort, like every other `fsync_parent` caller — see ADR-0008's
    // residual list.
    crate::atomic_file::fsync_parent(path);

    Ok(secret)
}

pub(super) fn decode_hex_secret(hex: &str) -> Result<[u8; 32], std::io::Error> {
    if hex.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit secret must be exactly 64 hex characters",
        ));
    }
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hex in audit secret",
            )
        })?;
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Symlink-safe open helpers (O_NOFOLLOW)
// ---------------------------------------------------------------------------

/// Open a file for reading, refusing symlinks on Unix and never blocking.
///
/// `O_NONBLOCK` matters for the same reason `O_NOFOLLOW` does: without it,
/// `open(O_RDONLY)` on a FIFO waits for a writer that may never come, and the
/// caller — `read_secret`, `audit_summary`, the audit-log readers — hangs
/// forever instead of reporting a bad path. On a regular file the flag has no
/// effect on read semantics, so it costs nothing in the normal case. Callers
/// that care must still confirm the opened descriptor is a regular file;
/// `O_NONBLOCK` stops the hang, it does not make a FIFO a valid input.
pub(super) fn open_read_nofollow(path: &Path) -> Result<fs::File, std::io::Error> {
    crate::atomic_file::open_read_regular(path).map_err(|e| eloop_message(e, path))
}

/// Open audit.jsonl for read+write+create, refusing symlinks on Unix and
/// never blocking.
///
/// `O_NONBLOCK` for the same reason as `open_read_nofollow`. It is belt and
/// braces here — POSIX leaves `O_RDWR` on a FIFO undefined and both Linux and
/// macOS return immediately — but "this open happens not to hang on the two
/// platforms we ship to" is a worse guarantee than one flag, on a path that
/// runs for every audited command.
pub(super) fn open_audit_rw(path: &Path) -> Result<fs::File, std::io::Error> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path).map_err(|e| eloop_message(e, path))?;
    // Cannot use `open_read_regular` (this one creates and writes), so it
    // shares the rule through `reject_non_regular` instead of restating it.
    // Without this, `append` writes audit entries *into a FIFO* — they leave
    // the process and land nowhere, and the log looks empty afterwards.
    crate::atomic_file::reject_non_regular(&file, path)?;
    Ok(file)
}

/// Convert ELOOP into a user-friendly error message.
fn eloop_message(e: std::io::Error, path: &Path) -> std::io::Error {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return symlink_attack_error(path);
    }
    e
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

/// Result of a key rotation operation.
///
/// `#[non_exhaustive]` so later fields are not a breaking change (the same
/// check and the same precedent as `AuditEvent`, `VerifyResult`, `ChainStatus`
/// and `AuditError`: zero reverse dependencies on crates.io).
#[non_exhaustive]
pub struct RotationResult {
    pub new_key_id: String,
    /// The id of the epoch this rotation ended — `"default"` when it was the
    /// store's first, `"key-{N}"` otherwise.
    ///
    /// Returned rather than left to the caller because it is derived from the
    /// retired slot number, which this function computes and does not
    /// otherwise expose. Recovering it from `retired_path` would mean
    /// deriving an id from a path, which is the shape #457 removed when it
    /// deleted `current_key_id`.
    ///
    /// #477: on a store whose directory could not be listed, this used to name
    /// the epoch the scan *could see* rather than the one that was actually
    /// active. Rotation now refuses instead, so a value here means a whole
    /// listing backed it — see [`KeyDirScan`].
    pub retired_key_id: String,
    pub retired_path: PathBuf,
}

/// Rotate the audit HMAC key.
///
/// `path` is the resolved audit log path (`audit.jsonl`), e.g. from
/// `super::resolved_audit_path` — this function never resolves a path
/// itself (#371: the old `config: &AuditConfig`-taking signature fell back
/// to a CWD-relative default when `HOME` was unusable; callers now must
/// resolve fail-closed before calling).
///
/// 1. Rename current secret to audit-secret.N.retired
/// 2. Generate a new secret at audit-secret
/// 3. New entries will use the new key_id
/// 4. verify_chain uses keyring to verify old entries with old key
pub fn rotate_key(path: &Path) -> Result<RotationResult, AuditError> {
    let secret_path = secret_path_for(path);
    // Exclusive: readers resolving a signing key or building a keyring must
    // not observe the store mid-rename (#457, Codex Round 1 P0).
    with_key_store_lock(&secret_path, true, |lock| {
        rotate_key_locked(&secret_path, lock)
    })
}

/// Clear the pending slot, or refuse if something omamori did not write is
/// sitting in it.
///
/// A leftover here is a rotation that stopped after creating the replacement
/// and before renaming it into place. **That key was never handed out** — the
/// readers do not resolve this path, so no entry can name it — which is what
/// makes removing it safe, and what separates it from a `.retired` file, where
/// deleting one destroys the only thing that authenticates an epoch.
///
/// Anything that is not a regular file is refused rather than removed. The
/// refusal happens before the rename, so the store is untouched: a symlink or
/// FIFO planted here costs a rotation, not a key. `create_secret`'s
/// `create_new` + `O_NOFOLLOW` is the enforcement — this is the message.
///
/// **Removal requires the key-store lock** (Codex Round 1, P1). "No reader
/// resolves this path" proves no *entry* can name the key — it says nothing
/// about whether another rotation is holding the file open right now. The lock
/// is best-effort: acquisition gives up after [`LOCK_ATTEMPTS`] and rotation
/// proceeds anyway, so a second rotation can reach this point while the first
/// is still inside `create_secret`. Deleting there would strand the first one
/// at its final rename and leave exactly the interrupted store this change
/// exists to prevent — produced by the cleanup for it.
///
/// Holding the lock does not make concurrency impossible (the other side may
/// also have given up on it), but it does confine an irreversible delete to the
/// caller that won the exclusion. The residual is in ADR-0008.
///
/// Takes the path the *listing* produced. A constructed path re-introduces the
/// probe `scan_key_dir` avoids: on a case-insensitive filesystem it answers for
/// a name the listing did not report, and this function deletes what it is
/// given.
fn take_pending_slot(seen: Option<&Path>, lock: &KeyStoreLock) -> Result<(), AuditError> {
    let Some(path) = seen else {
        return Ok(());
    };
    if let KeyStoreLock::Unheld(reason) = lock {
        return Err(AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!(
                "{} already exists and this rotation does not hold the key-store lock \
                 ({reason}), so it cannot tell a leftover from another rotation's replacement \
                 being written right now. No key file was renamed or created; re-run once the \
                 lock is available, or remove that file by hand if you know no rotation is in \
                 progress.",
                path.display()
            ),
        )));
    }
    match fs::symlink_metadata(path) {
        // Gone between the listing and now. Nothing to clear, and
        // `create_secret` below is the one that decides whether the slot is
        // really free.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AuditError::Io(e)),
        Ok(meta) if meta.is_file() => {
            fs::remove_file(path).map_err(AuditError::Io)?;
            eprintln!(
                "omamori warning: removed a leftover {PENDING_NAME} from an earlier rotation \
                 that stopped before moving it into place. It held a key no entry was ever \
                 signed with — nothing resolves that path."
            );
            Ok(())
        }
        Ok(_) => Err(AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} exists and is not a regular file. A rotation builds its replacement key \
                 there, and omamori will not remove something it did not write. No key file \
                 was renamed or created; inspect that path and clear it by hand.",
                path.display()
            ),
        ))),
    }
}

/// Which of the scan's observations say this store has rotated before.
///
/// Quoted into the refusal rather than summarised as "has rotated": the three
/// are left behind by different points in a rotation — the first rename, the
/// record, the replacement — and an operator standing in the directory can
/// check each one against what is actually there. A summary would be a claim
/// they cannot audit.
///
/// Never called with all three false; the caller's condition is the disjunction
/// of exactly these, so the joined string is never empty.
fn rotated_store_evidence(
    retired: &BTreeMap<u32, PathBuf>,
    recorded: u32,
    pending: bool,
) -> String {
    let mut seen = Vec::new();
    if !retired.is_empty() {
        seen.push(format!("{} retired key file(s) present", retired.len()));
    }
    if recorded >= 1 {
        seen.push(format!("{EPOCH_RECORD_NAME} records epoch {recorded}"));
    }
    if pending {
        seen.push(format!("a replacement is waiting in {PENDING_NAME}"));
    }
    seen.join("; ")
}

fn rotate_key_locked(
    secret_path: &Path,
    lock: &KeyStoreLock,
) -> Result<RotationResult, AuditError> {
    let secret_path = secret_path.to_path_buf();

    // #477: refuse before touching the key store when the directory cannot be
    // listed. (`with_key_store_lock` may already have created `audit-secret.lock`
    // by this point — it holds no key material and is not a retired key, which
    // is why the refusal test compares the listing against it rather than
    // against an empty directory.)
    //
    // Rotation is the only consumer of this scan that *mutates*, and it
    // was the only one that took the number without asking whether the listing
    // was real. On a store missing its low retired slots — an operator tidying
    // up after a prune — the failed scan reads as "never rotated", so the
    // current key is renamed into `.1.retired` and the new one is named after
    // an epoch that already exists. Once the directory is readable again those
    // entries resolve to the wrong bytes and `verify` reports tampering,
    // permanently, with no attacker involved (`ADR-0007` forbids rewriting).
    //
    // Ordered before `read_secret` deliberately: it makes the diagnosis right
    // when *both* are unreadable (mode 000). The other order reported "no audit
    // secret found — nothing to rotate", which is false — the secret is there.
    let (retired, record, pending) = match scan_key_dir(&secret_path) {
        // The rotation-specific half of the message is built here, next to the
        // condition, rather than by the CLI arm that prints it. That arm used
        // to add "make that directory listable and writable again" to every
        // `KeyringUnusable` — correct while an unusable keyring had one cause,
        // and wrong the moment the arm below gave it a second one, where the
        // directory is fine and a file is not. Same shape as the caller-side
        // remedy #477 had to withdraw, and it was found the same way: by
        // running the binary.
        KeyDirScan::Unlistable(reason) => {
            return Err(AuditError::KeyringUnusable {
                reason: format!(
                    "{reason} — rotating without a complete listing of the key directory would \
                     retire the current key under the wrong epoch number, and entries signed by \
                     it would later read as tampered."
                ),
                // "listable **and writable**": rotation renames and creates, so
                // a directory made merely readable still fails here — measured
                // at mode 0500, where both the rename and the create return
                // EACCES. And "no key file was renamed or created" rather than
                // "nothing changed": `with_key_store_lock` may have created
                // `audit-secret.lock` by now, which holds no key material and
                // is recreated on demand.
                remedy: "No key file was renamed or created. To fix: make that directory \
                         listable and writable again, then re-run."
                    .to_string(),
            });
        }
        KeyDirScan::Listed {
            retired,
            epoch,
            pending,
        } => (retired, epoch, pending),
    };

    // PR-C1 (yotta 判断12): refuse before touching the store, on the same
    // argument as the arm above. Rotation is the one consumer that mutates, and
    // the number it allocates is precisely what the record answers — proceeding
    // on a fallback here is how a number gets handed out twice.
    let recorded = match record.recorded() {
        Ok(recorded) => recorded,
        Err(reason) => {
            return Err(AuditError::KeyringUnusable {
                reason: format!(
                    "{reason} — which key epoch is active is unknown, so rotation cannot \
                     allocate the next one."
                ),
                remedy: format!(
                    "No key file was renamed or created. {}",
                    epoch_record_remedy()
                ),
            });
        }
    };

    // Verify current secret exists. The error body is kept rather than
    // flattened with `|_|`: `read_secret` distinguishes a missing secret from a
    // symlinked one ("possible attack") and from a non-regular file, and
    // `verify` classifies on that text. Rotation was erasing the distinction
    // and reporting all of them as "nothing to rotate".
    //
    // #487: and `NotFound` itself is two states, not one. On a store that has
    // rotated before it is the interrupted-rotation shape; the CLI arm for
    // `SecretUnavailable` describes the other one ("no audit secret found —
    // nothing to rotate"), which reads as an empty store and invites setting
    // one up again. The three observations that tell them apart were all
    // answered by the scan above and were being thrown away here.
    //
    // A fresh install has none of the three, so it keeps the old wording.
    if let Err(e) = read_secret(&secret_path) {
        if e.kind() == std::io::ErrorKind::NotFound
            && (!retired.is_empty() || recorded >= 1 || pending.is_some())
        {
            return Err(AuditError::KeyringUnusable {
                reason: format!(
                    "the active audit key is missing and this store has rotated before \
                     ({}) — a rotation that stopped between filing the old key and moving \
                     its replacement into place leaves exactly this.",
                    rotated_store_evidence(&retired, recorded, pending.is_some())
                ),
                // Written here rather than shared with
                // `rotation_interrupted_lines`. A recovery instruction with two
                // homes is one edit away from disagreeing with itself, and that
                // is the defect this change exists to remove — the other copy
                // went stale when `write_epoch_record` moved between the
                // renames. Says nothing about what the next command will
                // manage, for the reason #478 gives.
                // Hedged for the same reason `rotation_interrupted_lines` is:
                // this refusal is reached from both interrupted shapes, and
                // only one of them has the record advanced past the retired
                // slot. On the other, moving the file back really is a
                // recovery. What holds on both is that waiting works.
                remedy: "No key file was renamed or created. Leave the key files where they \
                         are; moving a .retired file to the active path can destroy the key \
                         its own epoch's entries were signed with, and waiting is safe either \
                         way. See the audit chapter of omamori's FAQ."
                    .to_string(),
            });
        }
        return Err(classify_secret_failure(e));
    }

    // Determine retired key number from the highest index present, not from a
    // count of matching names (#457 P4-a): with a gap (`.1`, `.3`) the count
    // said 2 and picked `.2`, while `key_id` derivation said `key-3` — the two
    // disagreed about which epoch was which.
    //
    // PR-C1: and not from the highest index alone either. The key being
    // displaced belongs to the *active epoch*, which the record can put above
    // `max_retired + 1` — a store that recorded epoch 5 and holds only `.2`
    // retires into `.5.retired`, because 5 is the epoch whose entries that key
    // signed. Deriving the slot from the slots is what let a rotation on a
    // tidied-up store name a key after an epoch that already existed.
    let epoch = active_epoch(&retired, recorded);
    // #457 (Codex Round 2): `scan_key_dir` rejects `u32::MAX` itself, so the
    // derived side of `active_epoch` cannot reach it — but the recorded side
    // is a number read off disk and can be anything. Unreachable in ordinary
    // use; refusing beats panicking.
    let Some(next_id) = epoch.checked_add(1) else {
        return Err(AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "audit key epoch {epoch} is at the representable limit; \
                 rotation cannot allocate a successor"
            ),
        )));
    };
    let retired_path = secret_path
        .parent()
        .unwrap()
        .join(format!("audit-secret.{epoch}.retired"));

    // #457 P4-c: `fs::rename` silently replaces its destination. `create_secret`
    // is already guarded with `create_new(true)`; the rename side was not, so a
    // gap in the numbering could make a rotation overwrite a retired key and
    // destroy it — every entry from that epoch becomes permanently
    // unverifiable, with nothing on disk left to say why.
    //
    // This is a check-then-act, not an atomic exclusive rename (`renamex_np`
    // with `RENAME_EXCL` on macOS, `renameat2` on Linux). Rotation is a manual,
    // human-initiated, AI-blocked operation, so the residual window is not
    // worth the platform-specific unsafe code; what matters is that the
    // ordinary case can no longer destroy a key.
    //
    // #486: asked through `symlink_metadata`, not `exists()`. The question is
    // whether the rename will replace something, and `exists()` answers a
    // different one — it follows the link, so a dangling symlink at that path
    // reads as free and the rename removes it. `take_pending_slot` already asks
    // it this way; this was the last place that did not.
    //
    // **The listing cannot answer it at all**, which is why the probe stays.
    // `active_epoch` returns `max(max_retired + 1, recorded)`, above every key
    // the scan reported, so `retired` never holds this epoch — comparing
    // against the listing would make the check vacuous rather than stricter.
    // What can be sitting there is exactly what the listing refuses to name: a
    // middle that is not a canonical decimal, or a spelling that differs only
    // in case on a case-insensitive filesystem (APFS by default).
    match fs::symlink_metadata(&retired_path) {
        // Nothing there — the one outcome that lets the rename proceed.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to overwrite an existing retired key: {} — the key-directory \
                     listing did not report this epoch, so whatever occupies that path was \
                     not filed there by a rotation. A name the listing rejects can still \
                     resolve to it: a spelling that is not a canonical decimal, or one that \
                     differs only in case on a case-insensitive filesystem.",
                    retired_path.display()
                ),
            )));
        }
        // Cannot tell. Refusing costs a rotation; proceeding lets `rename`
        // replace whatever is there, and it does that without a word.
        Err(e) => {
            return Err(AuditError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot tell whether {} is free: {e} — refusing rather than letting the \
                     rename replace what may be a retired key.",
                    retired_path.display()
                ),
            )));
        }
    }

    // Placed here, past every refusal, rather than at the top: a rotation that
    // is about to be declined has no window for anyone to observe, and warning
    // about one would describe a risk this run never takes.
    //
    // The reason is quoted, not summarised. Two of the four ways to reach
    // `Unheld` — the lock path is a symlink (`O_NOFOLLOW`) or is not a regular
    // file — are the file-type guards firing, and this is the only place they
    // can be heard; the previous wording named a concurrent reader, which is
    // one of the other two.
    // PR-C2 step 22: build the replacement first, at a path no reader looks
    // at, and move it into place last.
    //
    // The order is about **where the failures land**. Generating a key can fail
    // — no `/dev/urandom`, ENOSPC, EMFILE — and until now those failures
    // happened *after* the rename, leaving a store with retired keys and no
    // active one, which the next command then had to recover from. They now
    // happen before anything has moved, so the store is exactly as it was and
    // re-running is the whole remedy.
    //
    // What is left inside the window is rename → record → rename. What moved
    // out of it is every way *producing a key* can fail: no entropy source, no
    // free descriptor, no room for the 64 bytes.
    //
    // Not "the window cannot fail". Directory-entry changes are a smaller
    // surface, not an exempt one — `rename` returns `ENOSPC` when the target
    // directory cannot be extended — and a failure in there is still reported
    // as an interrupted rotation, naming the file that moved.
    let pending_path = pending_path_for(&secret_path);
    take_pending_slot(pending.as_deref(), lock)?;
    // `AuditError::Io`, not `RotationInterrupted`: nothing is interrupted yet.
    // This is still the refusal half of the function, where the store is
    // untouched and the operator's action is "fix the cause and re-run".
    create_secret(&pending_path).map_err(AuditError::Io)?;

    // Placed here, past every refusal, rather than at the top: a rotation that
    // is about to be declined has no window for anyone to observe, and warning
    // about one would describe a risk this run never takes. PR-C2 moved it
    // down again, because building the replacement became a refusal too —
    // `take_pending_slot` and `create_secret` both leave the store untouched
    // when they fail.
    //
    // The reason is quoted, not summarised. Two of the four ways to reach
    // `Unheld` — the lock path is a symlink (`O_NOFOLLOW`) or is not a regular
    // file — are the file-type guards firing, and this is the only place they
    // can be heard; the previous wording named a concurrent reader, which is
    // one of the other two.
    if let KeyStoreLock::Unheld(reason) = lock {
        eprintln!(
            "omamori warning: proceeding without the audit key-store lock — {reason}. \
             A reader resolving a key epoch during this rotation can pair the previous \
             label with the new key's bytes, which `audit verify` later reports as \
             tampering. omamori only ever puts a plain, empty file at that path."
        );
    }

    // Rename active → retired
    fs::rename(&secret_path, &retired_path).map_err(AuditError::Io)?;

    // Set restrictive permissions on retired key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&retired_path, fs::Permissions::from_mode(0o600));
    }

    // PR-C1 step 16: record the new epoch *before* a key exists to carry it.
    //
    // The order is the invariant, not an optimisation: a key minted under a
    // number the store has not written down is a key the next command names
    // differently. Recording first means the worst a crash can leave is a
    // number nobody used — epochs are allowed to have gaps, and skipping one
    // costs nothing, while reusing one puts two secrets under a single id and
    // `ADR-0007` forbids repairing the entries afterwards.
    //
    // Durable before it returns (Codex Round 3, Major-1) — see
    // `write_epoch_record`. A record that reached only the page cache would
    // come back as the old number after a crash, and this whole ordering would
    // buy nothing.
    //
    // yotta 判断16: a failure here stops the rotation rather than rolling the
    // rename back. The store is left in the interrupted state
    // `load_signing_key` already handles and recovers from on the next command;
    // an undo would add a failure path whose own failure has no handler. The
    // error names the record so the message does not read as if `create_secret`
    // was the step that failed.
    let next_id = match write_epoch_record(&secret_path, next_id) {
        // The record is monotonic, so this can come back *higher* than asked
        // for — a concurrent recovery under an unheld lock. Naming the number
        // that is on disk keeps `new_key_id` equal to what the next scan will
        // derive; naming the one this call wanted would not.
        Ok(recorded) => recorded,
        Err(e) => {
            return Err(AuditError::RotationInterrupted {
                retired_path,
                source: std::io::Error::new(
                    e.kind(),
                    format!("{EPOCH_RECORD_NAME} could not be advanced to epoch {next_id}: {e}"),
                ),
            });
        }
    };

    // Move the replacement into place — the last step that can fail, and now
    // the narrowest: a same-directory rename of a file this call created
    // moments ago, with its bytes already synced.
    //
    // #478: its own error, not the `Io` catch-all. Everything above the first
    // rename refuses without touching the key directory; from there on the
    // store is changed, and a failure leaves exactly the interrupted state
    // `load_signing_key` warns about. The operator needs to know which file
    // moved, and `key rotation failed: {e}` said neither.
    //
    // PR-C2 narrowed what can land here. It used to be `create_secret`, which
    // fails for a full disk, a missing `/dev/urandom` or an exhausted
    // descriptor table — all of them now happen before the first rename, with
    // the store untouched.
    if let Err(source) = fs::rename(&pending_path, &secret_path) {
        return Err(AuditError::RotationInterrupted {
            retired_path,
            source,
        });
    }
    // Two renames and a record, all of them directory-entry changes. This is
    // what makes them survive a power loss as a set rather than individually.
    // Best-effort, like every other `fsync_parent` caller — ADR-0008's residual
    // list says so.
    crate::atomic_file::fsync_parent(&secret_path);

    // The active epoch names the one this rotation just ended.
    // `key_id_for_epoch` owns the `"default"`-vs-`key-N` rule; restating it
    // here is what would let the two drift.
    //
    // `new_key_id` keeps its own `format!` so that `next_id` — which the
    // overflow check above exists to guard — still names a value something
    // reads.
    Ok(RotationResult {
        new_key_id: format!("key-{next_id}"),
        retired_key_id: key_id_for_epoch(epoch),
        retired_path,
    })
}
