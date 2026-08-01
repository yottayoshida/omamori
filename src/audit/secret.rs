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

use super::verify::AuditError;

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

use super::chain::HmacSha256;
use hmac::Mac;

pub(super) fn hmac_targets(secret: Option<&[u8; 32]>, targets: &[&str]) -> String {
    let Some(key) = secret else {
        return "NO_HMAC_SECRET".to_string();
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

/// Resolve the active signing key and its `key_id` together.
///
/// #457: the secret and its id used to be resolved by two separate calls, each
/// reading the key directory independently. A rotation landing between them
/// minted one entry signed with the old key but labelled with the new id — a
/// permanently unverifiable entry that no amount of verifier-side repair can
/// reclassify, because the id is present and only the bytes are wrong. The two
/// reads are now one value *and* one locked observation.
pub(super) fn load_signing_key(secret_path: &Path) -> SigningKey {
    with_key_store_lock(secret_path, false, |_lock| {
        load_signing_key_locked(secret_path)
    })
}

fn load_signing_key_locked(secret_path: &Path) -> SigningKey {
    let scan = scan_key_dir(secret_path);

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
    let retired = match scan {
        KeyDirScan::Unlistable(reason) => {
            eprintln!(
                // Not "fix the condition and re-run to restore protection":
                // the reason is inline in this same sentence rather than
                // above it, nothing here is a command the operator ran, and
                // "restore" reads as covering the entries written meanwhile —
                // which `verify`'s own `NeverProtected` arm then denies.
                "omamori warning: {reason} — cannot determine which key epoch is active, so no \
                 entry written from here on can be HMAC-protected or labelled with a key epoch. \
                 Entries written while this lasts carry no HMAC and stay unverifiable; clearing \
                 the condition protects later ones, not those."
            );
            return SigningKey {
                id: UNRESOLVED_KEY_ID.to_string(),
                secret: None,
            };
        }
        KeyDirScan::Listed(retired) => retired,
    };

    let max_retired = max_retired_index(&retired);

    // #457 P4-e: a rotation that crashed between `rename` and `create_secret`
    // leaves retired keys with no active key. `load_or_create_secret` below
    // will mint a fresh one — under the *same* `key-{N+1}` label the crashed
    // rotation was heading for. Two different secrets then share one id, and
    // no verifier-side repair can untangle that: the id resolves, the bytes
    // just do not match, so the entries read as tampered forever.
    //
    // Detecting it here does not fix it (the complete fix needs the key file
    // itself to record its epoch — deferred, see ADR-0008), but a warning at
    // the moment it happens is the difference between an operator who can
    // restore the interrupted rotation and one who discovers it months later
    // as an unexplained broken chain.
    // Read once and reuse. The warning check and `load_or_create_secret` both
    // needed the active key, so the pre-`/simplify` form read the same file
    // twice on every command in a rotated store (measured: +9.4 µs).
    let active = read_secret(secret_path).ok();
    if max_retired > 0 && active.is_none() {
        eprintln!(
            "omamori warning: retired audit keys exist but the active key is missing \
             or unreadable — a key rotation may have been interrupted. A new key will \
             be created under id key-{next}, which entries from the interrupted \
             rotation may also claim. To recover, copy audit-secret.{max_retired}.retired \
             back to audit-secret before anything appends — the rotation never got as \
             far as creating a new key, so the retired copy is the one those entries \
             were signed with.",
            next = max_retired + 1,
            max_retired = max_retired
        );
    }

    // `load_or_create_secret` is only reached when the active key could not be
    // read — normally because this is a fresh install and it has to be created.
    let secret = match active {
        Some(secret) => Some(secret),
        None => load_or_create_secret(secret_path),
    };
    SigningKey {
        id: key_id_for_index(max_retired),
        secret,
    }
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
            "audit path is a symlink (possible attack): {}",
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
    /// Parsed retired-key index → path, ordered by index.
    Listed(BTreeMap<u32, PathBuf>),
    /// The listing could not be obtained, or could not be trusted to be whole.
    /// The string states what was observed, with no interpretation — callers
    /// wrap it in whatever their own context can actually claim.
    Unlistable(String),
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
            return KeyDirScan::Listed(BTreeMap::new());
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

    KeyDirScan::Listed(retired)
}

/// The `key_id` for a store whose highest retired index is `max_retired`.
/// `"default"` when nothing has been retired yet; `"key-N"` otherwise.
///
/// Takes the index rather than a path so it cannot disagree with the scan the
/// caller already performed — the previous path-taking form re-read the
/// directory, which is how the writer's key and its label came apart.
fn key_id_for_index(max_retired: u32) -> String {
    if max_retired == 0 {
        "default".to_string()
    } else {
        format!("key-{}", max_retired + 1)
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
    let prev = n.checked_sub(1)?;
    Some(format!(
        "audit-secret.{prev}.retired, or audit-secret if epoch {n} is still the current key"
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
        }
    }
}

/// All keys this host can verify with, plus what went wrong assembling them.
pub(super) struct Keyring {
    keys: BTreeMap<String, [u8; 32]>,
    anomalies: Vec<KeyringAnomaly>,
}

impl Keyring {
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
    /// shows*: deleting retired key files lowers this number, because nothing
    /// on disk records the store's epoch history (the same limitation
    /// `deleting_the_last_retired_key_reads_as_tampering_known_limitation`
    /// pins). So it grounds an observation, never an accusation.
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
    /// Only `DirectoryUnreadable` qualifies: `"default"` would resolve to the
    /// active key on a rotated store and every entry would read as tampered.
    /// A truncated ring or one unreadable file is bounded — the keys that did
    /// load still authenticate their own entries, and the gap is reported.
    pub(super) fn fatal_anomaly(&self) -> Option<&KeyringAnomaly> {
        self.anomalies
            .iter()
            .find(|a| matches!(a, KeyringAnomaly::DirectoryUnreadable { .. }))
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
    let retired = match scan_key_dir(secret_path) {
        KeyDirScan::Unlistable(reason) => {
            anomalies.push(KeyringAnomaly::DirectoryUnreadable { reason });
            return Keyring { keys, anomalies };
        }
        KeyDirScan::Listed(retired) => retired,
    };
    let max_retired = max_retired_index(&retired);

    // Active key → the id the writer is currently stamping.
    if let Ok(secret) = read_secret(secret_path) {
        keys.insert(key_id_for_index(max_retired), secret);
        // Before any rotation the active key *is* epoch 1, which is what
        // `"default"` names. After a rotation `"default"` belongs to
        // `.1.retired` instead, registered below.
        if max_retired == 0 {
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
            Err(e) => anomalies.push(KeyringAnomaly::Unreadable {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
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

pub(super) fn load_or_create_secret(path: &Path) -> Option<[u8; 32]> {
    if let Ok(secret) = read_secret(path) {
        return Some(secret);
    }
    match create_secret(path) {
        Ok(secret) => Some(secret),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match read_secret(path) {
            Ok(secret) => Some(secret),
            Err(e) => {
                eprintln!("omamori warning: audit secret race: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("omamori warning: audit secret unavailable: {e}");
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
    file.write_all(hex.as_bytes())?;

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
    let retired = match scan_key_dir(&secret_path) {
        KeyDirScan::Unlistable(reason) => return Err(AuditError::KeyringUnusable(reason)),
        KeyDirScan::Listed(retired) => retired,
    };

    // Verify current secret exists. The error body is kept rather than
    // flattened with `|_|`: `read_secret` distinguishes a missing secret from a
    // symlinked one ("possible attack") and from a non-regular file, and
    // `verify` classifies on that text. Rotation was erasing the distinction
    // and reporting all of them as "nothing to rotate".
    read_secret(&secret_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::SecretUnavailable,
        _ => AuditError::Io(e),
    })?;

    // Determine retired key number from the highest index present, not from a
    // count of matching names (#457 P4-a): with a gap (`.1`, `.3`) the count
    // said 2 and picked `.2`, while `key_id` derivation said `key-3` — the two
    // disagreed about which epoch was which.
    let max_retired = max_retired_index(&retired);
    // #457 (Codex Round 2): `scan_key_dir` rejects `u32::MAX` itself, but
    // `u32::MAX - 1` is accepted — and the new key's id is `n + 1`, one past
    // the retired slot, so the arithmetic has to survive two increments, not
    // one. Unreachable in practice; refusing beats panicking.
    let (n, next_id) = match max_retired
        .checked_add(1)
        .and_then(|n| n.checked_add(1).map(|next| (n, next)))
    {
        Some(pair) => pair,
        None => {
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "audit key epoch {max_retired} is at the representable limit; \
                     rotation cannot allocate a successor"
                ),
            )));
        }
    };
    let retired_path = secret_path
        .parent()
        .unwrap()
        .join(format!("audit-secret.{n}.retired"));

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
    if retired_path.exists() {
        return Err(AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "refusing to overwrite an existing retired key: {}",
                retired_path.display()
            ),
        )));
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

    // Generate new secret
    create_secret(&secret_path).map_err(AuditError::Io)?;

    // The pre-rotation max index names the epoch this rotation just ended.
    // `key_id_for_index` owns the `"default"`-vs-`key-N` rule; restating it
    // here is what would let the two drift.
    //
    // `new_key_id` keeps its own `format!` so that `next_id` — which exists to
    // make the overflow check above cover *both* increments — still guards a
    // value something reads.
    Ok(RotationResult {
        new_key_id: format!("key-{next_id}"),
        retired_key_id: key_id_for_index(max_retired),
        retired_path,
    })
}
