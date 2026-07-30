//! Canonical atomic file write helper (#307, #311, #322).
//!
//! Two entry points, both enforcing `create_new` (`O_EXCL`) + `O_NOFOLLOW` +
//! creation-time mode + `fsync` + CSPRNG temp names — unconditionally, with
//! no caller-facing knob able to weaken any of it:
//!
//! - [`atomic_write_with_mode`] — temp file + rename, for sites where an
//!   existing target may legitimately be replaced.
//! - [`atomic_create_new`] — direct `create_new` on the target, no rename,
//!   for sites with a no-clobber contract (fail if the target already
//!   exists).
//!
//! See `docs/adr/0001-atomic-file-canonical-helper.md`.
//!
//! Neither entry point checks whether `target` itself is a symlink: `rename`
//! replaces whatever directory entry sits at the destination without
//! following it, and `create_new` fails outright if anything (including a
//! symlink) already exists there. A caller that wants a friendlier,
//! context-specific error message when `target` is a pre-existing symlink
//! must check before calling — that check stays caller-side by design so the
//! message can name the call site (e.g. "config path", "integrity baseline").
//! [`is_symlink`] is the shared primitive for that caller-side check (#311).

use std::io;
use std::path::Path;

const MAX_TEMP_RETRIES: u32 = 8;
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const TEMP_PREFIX: &str = ".omamori-tmp-";

/// Atomic write via temp file + rename. Replaces `target` if it already
/// exists, creates it otherwise.
#[cfg(unix)]
pub(crate) fn atomic_write_with_mode(target: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    write_via_temp(target, content, mode, random_hex_suffix)
}

#[cfg(not(unix))]
pub(crate) fn atomic_write_with_mode(target: &Path, content: &[u8], _mode: u32) -> io::Result<()> {
    use std::io::Write as _;

    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..MAX_TEMP_RETRIES {
        let temp_path = dir.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            fallback_suffix()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                file.write_all(content)?;
                std::fs::rename(&temp_path, target)?;
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temp name space exhausted",
    ))
}

/// Direct `create_new` on `target` — no rename, fails if `target` already
/// exists.
///
/// For call sites where "never overwrite an existing file" is the contract
/// itself (e.g. first-time config creation): routing this through the
/// rename-based path would turn a fail-closed race (`AlreadyExists`) into a
/// silent fail-open clobber, since `rename` cannot distinguish "target
/// appeared after my existence check" from "target was always absent".
///
/// Unlike [`atomic_write_with_mode`], there is no temp file and therefore no
/// `TempGuard`: if `write_all`/`sync_all` fails after `target` was already
/// created, a partial file is left at `target` (matching the pre-#307
/// behavior of `config::write_new_config`, which this replaces — not a
/// regression, but also not newly hardened).
#[cfg(unix)]
pub(crate) fn atomic_create_new(target: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(target)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    fsync_parent(target);
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn atomic_create_new(target: &Path, content: &[u8], _mode: u32) -> io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    file.write_all(content)?;
    Ok(())
}

/// Shared symlink-check primitive (#311). `false` on any I/O error (path
/// doesn't exist, permission denied, etc.) — callers that need fail-closed
/// behavior on error should not rely on this alone; it answers exactly one
/// question: "does a symlink sit at this path right now".
pub(crate) fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Canonical read side (#468)
// ---------------------------------------------------------------------------

/// Open `path` for reading, refusing symlinks and anything that is not a
/// regular file, and never blocking on the `open` itself.
///
/// Unlike the symlink check above, this is **not** caller-side by design. It
/// is the check whose absence #468 is about, and the reason it belongs here
/// is a measured one: `read_secret` had a per-caller version of it, and the
/// next caller added in the same change did not get one. A check that lives
/// on callers does not reach the next caller.
///
/// Three things, none of which is redundant:
///
/// - `O_NOFOLLOW` — a symlink at `path` is refused by the kernel rather than
///   followed to wherever it points.
/// - `O_NONBLOCK` — `open(O_RDONLY)` on a FIFO otherwise waits for a writer
///   that may never come. Measured on omamori: a FIFO at `audit.jsonl.hwm`
///   hung `verify`, `exec`, `doctor`, `report` **and `hook-check`** — the
///   last of those before it printed its deny verdict, which turns a local
///   `mkfifo` into a silent disabling of the enforcement path. On a regular
///   file the flag changes nothing about reads.
/// - `fstat` on the **opened descriptor** — `O_NONBLOCK` stops the hang, it
///   does not make a FIFO a valid input, and reads from one return
///   `EWOULDBLOCK`/`ENOTSUP` rather than an error naming the real problem.
///   Checking the descriptor rather than the path also closes the
///   check-then-act window that `symlink_metadata`-then-`open` leaves open.
pub(crate) fn open_read_regular(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    reject_non_regular(&file, path)?;
    Ok(file)
}

/// Fail unless `file` is a regular file. Split out so the read+write opens
/// that cannot use [`open_read_regular`] still share one definition of the
/// rule and one wording.
pub(crate) fn reject_non_regular(file: &std::fs::File, path: &Path) -> io::Result<()> {
    let meta = file.metadata()?;
    if meta.is_file() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} is {}, not a regular file",
            path.display(),
            describe_file_type(&meta)
        ),
    ))
}

/// Name the thing that was found, so the message says what to remove rather
/// than only what was expected.
fn describe_file_type(meta: &std::fs::Metadata) -> &'static str {
    let ft = meta.file_type();
    if ft.is_dir() {
        return "a directory";
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return "a FIFO";
        }
        if ft.is_socket() {
            return "a socket";
        }
        if ft.is_block_device() {
            return "a block device";
        }
        if ft.is_char_device() {
            return "a character device";
        }
    }
    "not a regular file"
}

/// Read a whole file as UTF-8, refusing non-regular files and bounding the
/// read at `max_bytes`.
///
/// The bound is applied to the descriptor via `take`, not to a prior `stat`:
/// a file that passed a size check can be extended before the read runs, and
/// omamori re-reads these paths on every command, so an attacker racing that
/// window gets unlimited attempts.
pub(crate) fn read_to_string_capped(path: &Path, max_bytes: u64) -> io::Result<String> {
    use std::io::Read;
    let file = open_read_regular(path)?;
    let mut buf = String::new();
    io::BufReader::new(file)
        .take(max_bytes.saturating_add(1))
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds {max_bytes} bytes", path.display()),
        ));
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internals (Unix)
// ---------------------------------------------------------------------------

/// `next_suffix` is injectable so tests can force deterministic name
/// collisions without controlling `/dev/urandom`; production callers only
/// ever reach this via [`atomic_write_with_mode`], which wires in
/// [`random_hex_suffix`].
#[cfg(unix)]
fn write_via_temp(
    target: &Path,
    content: &[u8],
    mode: u32,
    mut next_suffix: impl FnMut() -> io::Result<String>,
) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let mut last_err: Option<io::Error> = None;

    for _ in 0..MAX_TEMP_RETRIES {
        let suffix = next_suffix()?;
        let temp_path = dir.join(format!("{TEMP_PREFIX}{}-{}", std::process::id(), suffix));

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(&temp_path);

        let mut file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };

        // Armed until the rename below succeeds — any early return (write or
        // sync failure) drops this and removes the temp file. Closes the
        // leak in the pre-#307 installer `AtomicTempFile`, which had no
        // `Drop` impl at all.
        let mut guard = TempGuard::new(&temp_path);

        file.write_all(content)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&temp_path, target)?;
        guard.disarm();

        fsync_parent(target);
        gc_stale_temps(dir);
        return Ok(());
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AlreadyExists, "temp name space exhausted")
    }))
}

#[cfg(unix)]
pub(crate) fn random_hex_suffix() -> io::Result<String> {
    use std::io::Read as _;

    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

// Untestable by ordinary means: its only observable effect is crash
// durability (surviving a kernel panic / power loss between rename and the
// next fsync), which no test in this suite simulates. Best-effort by design
// (errors are swallowed) — a failure here can't turn a successful write into
// a lost one on a live process, only into a slightly-less-durable one.
fn fsync_parent(target: &Path) {
    if let Some(dir) = target.parent()
        && let Ok(dir_file) = std::fs::File::open(dir)
    {
        let _ = dir_file.sync_all();
    }
}

/// Best-effort cleanup of orphaned temp files left by a prior crash between
/// `create_new` and `rename`. Random temp names (unlike the fixed names they
/// replace) don't self-collide on the next write, so without this, orphans
/// would accumulate forever.
///
/// Three invariants, each load-bearing:
/// - strict `.omamori-tmp-` prefix match — never touches unrelated files
/// - age read via `DirEntry::metadata`, which uses `lstat` semantics (does
///   not follow symlinks) — an attacker-planted `.omamori-tmp-*` symlink is
///   skipped, not traversed
/// - any symlink entry is skipped outright, never handed to `remove_file`
fn gc_stale_temps(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(age) = modified.elapsed() else {
            continue;
        };
        if age > STALE_TEMP_AGE {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// RAII guard: removes the temp file at `path` unless [`disarm`](Self::disarm)
/// is called first.
struct TempGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl<'a> TempGuard<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Internals (non-Unix) — best-effort only: no O_NOFOLLOW, no forced mode, no
// fsync, no GC. Matches the pre-existing non-Unix behavior of every site
// migrated to this module (none of them hardened non-Unix writes either).
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
fn fallback_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{seq}")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn test_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("omamori-atomicfile-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Run `f` on a worker thread and fail if it has not finished in time.
    ///
    /// The defect these guard against (`open` without `O_NONBLOCK` on a FIFO)
    /// fails by *not returning*. A test that simply called it would hang and
    /// take the whole test binary with it, which is indistinguishable from a
    /// slow machine; timing out into an assertion makes it an ordinary red
    /// test.
    fn must_finish_within<T: Send + 'static>(
        what: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(v) => v,
            Err(_) => panic!("{what} did not return within 5s — it blocked"),
        }
    }

    fn mkfifo_at(path: &Path) {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo failed: {}",
            io::Error::last_os_error()
        );
    }

    // -----------------------------------------------------------------
    // open_read_regular / read_to_string_capped (#468)
    // -----------------------------------------------------------------

    /// The regression this helper exists for: `fs::read_to_string` on a FIFO
    /// waits for a writer forever. Measured before the fix, a FIFO at
    /// `audit.jsonl.hwm` hung `verify`, `exec`, `doctor`, `report` and
    /// `hook-check` — the last of those before it printed its deny verdict.
    #[test]
    fn a_fifo_is_refused_rather_than_waited_on() {
        let dir = test_dir("read-fifo");
        let fifo = dir.join("f");
        mkfifo_at(&fifo);

        let p = fifo.clone();
        let err = must_finish_within("read_to_string_capped on a FIFO", move || {
            read_to_string_capped(&p, 1024).expect_err("a FIFO is not a regular file")
        });
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("is a FIFO"),
            "the message must name what was found, not only what was expected: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every shape that is not a regular file, refused with its own name.
    /// A directory and a socket reach different `open` outcomes than a FIFO,
    /// so one case does not stand in for the others.
    #[test]
    fn every_non_regular_shape_is_refused_and_named() {
        let dir = test_dir("read-shapes");

        let subdir = dir.join("d");
        std::fs::create_dir(&subdir).unwrap();
        let err = open_read_regular(&subdir).expect_err("a directory is not a regular file");
        assert!(err.to_string().contains("a directory"), "{err}");

        // A symlink never reaches the file-type check: `O_NOFOLLOW` refuses
        // it at the kernel. Pinned so that a later refactor cannot quietly
        // start following links and then report on the *target's* type.
        let target = dir.join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("l");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open_read_regular(&link).expect_err("a symlink must not be followed");
        assert_ne!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "a symlink must fail at the open, not at the file-type check: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "x",
            "and the target must be untouched"
        );

        // A regular file still works.
        assert!(open_read_regular(&target).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cap is enforced, and enforced on the descriptor rather than on a
    /// prior `stat` — a file that grows after a size check cannot slip past
    /// one that never happened.
    ///
    /// **Measured limits of this test.** Reverting the `take(max + 1)` to an
    /// unbounded read leaves it green: the length check below still rejects
    /// the oversized file, because the bytes have already been read. `take`
    /// is what stops a hostile file being pulled into memory *in full* before
    /// the rejection, and that is not observable from here — the only tests
    /// that would discriminate it depend on allocating hundreds of megabytes
    /// and on timing, which is worse in CI than an honest note. Recorded
    /// rather than papered over.
    #[test]
    fn the_cap_is_enforced_without_a_prior_stat() {
        let dir = test_dir("read-cap");
        let path = dir.join("big");
        std::fs::write(&path, "x".repeat(2048)).unwrap();

        let err = read_to_string_capped(&path, 1024).expect_err("2048 bytes exceeds a 1024 cap");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds 1024 bytes"), "{err}");

        // Exactly at the cap is allowed; the +1 is only there to detect
        // overrun, not to shift the limit.
        std::fs::write(&path, "y".repeat(1024)).unwrap();
        assert_eq!(read_to_string_capped(&path, 1024).unwrap().len(), 1024);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // random_hex_suffix: the actual generator every production caller uses
    // (the collision-handling tests below inject a mock closure instead, to
    // deterministically force collisions — this test covers the generator
    // itself, which those tests don't exercise)
    // -----------------------------------------------------------------

    #[test]
    fn random_hex_suffix_produces_distinct_16_char_hex_strings() {
        let a = random_hex_suffix().unwrap();
        let b = random_hex_suffix().unwrap();
        assert_eq!(a.len(), 16, "8 bytes hex-encoded = 16 chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two consecutive calls must not collide");
    }

    // -----------------------------------------------------------------
    // atomic_write_with_mode: basic contract
    // -----------------------------------------------------------------

    #[test]
    fn write_with_mode_creates_new_file() {
        let dir = test_dir("create");
        let target = dir.join("out.txt");

        atomic_write_with_mode(&target, b"hello", 0o600).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        assert_eq!(mode_of(&target), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_with_mode_handles_empty_content() {
        // Production call site: `touch_audit_warn_sentinel` writes `b""` —
        // only the mtime matters for that sentinel, not the bytes.
        let dir = test_dir("empty");
        let target = dir.join("out.txt");

        atomic_write_with_mode(&target, b"", 0o600).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"");
        assert_eq!(mode_of(&target), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_with_mode_replaces_existing_file_content_and_mode() {
        let dir = test_dir("replace");
        let target = dir.join("out.txt");
        std::fs::write(&target, b"stale").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write_with_mode(&target, b"fresh", 0o600).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"fresh");
        assert_eq!(
            mode_of(&target),
            0o600,
            "mode must come from the new write, not the replaced file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_with_mode_replaces_symlink_target_without_following_it() {
        let dir = test_dir("symlink-target");
        let decoy = dir.join("decoy");
        std::fs::write(&decoy, b"original").unwrap();
        let target = dir.join("out.txt");
        std::os::unix::fs::symlink(&decoy, &target).unwrap();

        atomic_write_with_mode(&target, b"fresh", 0o600).unwrap();

        assert!(
            !target.symlink_metadata().unwrap().file_type().is_symlink(),
            "target symlink must be replaced by a regular file (rename semantics)"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"fresh");
        assert_eq!(
            std::fs::read(&decoy).unwrap(),
            b"original",
            "the symlink's old destination must be untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(umask)]
    fn write_with_mode_mode_is_exact_regardless_of_umask() {
        let dir = test_dir("umask");
        let target = dir.join("out.txt");

        // SAFETY: serialized against other `umask`-tagged tests; umask is
        // process-global.
        let previous = unsafe { libc::umask(0o077) };
        let result = atomic_write_with_mode(&target, b"x", 0o600);
        unsafe {
            libc::umask(previous);
        }
        result.unwrap();

        assert_eq!(mode_of(&target), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // AlreadyExists retry (deterministic via injected suffix generator)
    // -----------------------------------------------------------------

    #[test]
    fn write_via_temp_retries_past_a_colliding_suffix() {
        let dir = test_dir("retry-collide");
        let target = dir.join("out.txt");
        let colliding = dir.join(format!(".omamori-tmp-{}-collide", std::process::id()));
        std::fs::write(&colliding, b"attacker-planted").unwrap();

        let mut calls = 0u32;
        let next_suffix = move || {
            calls += 1;
            Ok(if calls == 1 {
                "collide".to_string()
            } else {
                "unique".to_string()
            })
        };

        write_via_temp(&target, b"payload", 0o600, next_suffix).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
        assert_eq!(
            std::fs::read(&colliding).unwrap(),
            b"attacker-planted",
            "the pre-existing colliding file must be untouched, not truncated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_via_temp_fails_closed_when_every_suffix_collides() {
        let dir = test_dir("retry-exhaust");
        let target = dir.join("out.txt");
        let fixed = dir.join(format!(".omamori-tmp-{}-stuck", std::process::id()));
        std::fs::write(&fixed, b"blocker").unwrap();

        let next_suffix = || Ok("stuck".to_string());

        let result = write_via_temp(&target, b"payload", 0o600, next_suffix);

        assert!(!target.exists(), "target must not be created on exhaustion");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::AlreadyExists,
            "must fail closed, not silently fall back to create(true) or remove+create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A planted symlink at the temp path is treated as a collision (retried,
    /// not followed). Note on mechanism: `create_new` (`O_EXCL`) alone already
    /// guarantees this — `open(O_CREAT|O_EXCL)` fails on *any* pre-existing
    /// directory entry, symlink or not, without resolving it. This test
    /// proves the useful end-to-end property (a planted symlink can't hijack
    /// the temp path), not that `O_NOFOLLOW` specifically is what causes it;
    /// `O_NOFOLLOW` is defense-in-depth here, not the load-bearing guard.
    #[test]
    fn write_via_temp_treats_a_pre_existing_symlink_at_the_temp_path_as_a_collision() {
        let dir = test_dir("retry-symlink-temp");
        let target = dir.join("out.txt");
        let decoy = dir.join("decoy");
        std::fs::write(&decoy, b"do-not-touch").unwrap();
        let colliding = dir.join(format!(".omamori-tmp-{}-collide", std::process::id()));
        std::os::unix::fs::symlink(&decoy, &colliding).unwrap();

        let mut calls = 0u32;
        let next_suffix = move || {
            calls += 1;
            Ok(if calls == 1 {
                "collide".to_string()
            } else {
                "unique".to_string()
            })
        };

        write_via_temp(&target, b"payload", 0o600, next_suffix).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
        assert_eq!(
            std::fs::read(&decoy).unwrap(),
            b"do-not-touch",
            "a planted symlink at the temp path must not be written through"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_via_temp_retries_exactly_up_to_max_then_succeeds() {
        let dir = test_dir("retry-max");
        let target = dir.join("out.txt");

        // Collide on the first (MAX_TEMP_RETRIES - 1) suffixes, succeed on the
        // last available attempt. Pins MAX_TEMP_RETRIES exactly: a lower
        // value would exhaust before reaching "final" and fail closed
        // instead of succeeding.
        for i in 0..MAX_TEMP_RETRIES - 1 {
            let blocker = dir.join(format!(".omamori-tmp-{}-slot{i}", std::process::id()));
            std::fs::write(&blocker, b"blocker").unwrap();
        }

        let mut calls = 0u32;
        let next_suffix = move || {
            let suffix = if calls < MAX_TEMP_RETRIES - 1 {
                format!("slot{calls}")
            } else {
                "final".to_string()
            };
            calls += 1;
            Ok(suffix)
        };

        write_via_temp(&target, b"payload", 0o600, next_suffix).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // Drop guard: temp cleanup on failure
    // -----------------------------------------------------------------

    #[test]
    fn write_with_mode_cleans_up_temp_when_rename_fails() {
        let dir = test_dir("rename-fail");
        // A directory at the target path makes the final `rename` fail
        // (can't rename a regular file onto a non-empty rename target type
        // mismatch), after the temp file has already been created+written.
        let target = dir.join("out.txt");
        std::fs::create_dir_all(&target).unwrap();

        let result = atomic_write_with_mode(&target, b"payload", 0o600);
        assert!(result.is_err());

        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(TEMP_PREFIX))
            .collect();
        assert!(
            leftover.is_empty(),
            "TempGuard must remove the temp file when rename fails, found: {leftover:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_guard_removes_file_when_a_panic_unwinds_through_it() {
        let dir = test_dir("guard-panic");
        let path = dir.join(".omamori-tmp-panic-test");
        std::fs::write(&path, b"x").unwrap();

        let path_for_panic = path.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = TempGuard::new(&path_for_panic);
            panic!("simulated failure while the guard is armed");
        }));

        assert!(result.is_err(), "the panic must have propagated");
        assert!(
            !path.exists(),
            "TempGuard::drop must run (and remove the file) even when unwinding from a panic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // Stale temp GC
    // -----------------------------------------------------------------

    #[test]
    fn gc_removes_old_temp_but_not_fresh_or_unrelated_or_symlinked() {
        let dir = test_dir("gc");
        let target = dir.join("out.txt");

        let old_temp = dir.join(format!("{TEMP_PREFIX}{}-old", std::process::id()));
        std::fs::write(&old_temp, b"orphan").unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 60 * 60);
        let file = std::fs::File::options()
            .write(true)
            .open(&old_temp)
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(past))
            .unwrap();
        drop(file);

        let unrelated = dir.join("not-a-temp-file.txt");
        std::fs::write(&unrelated, b"keep-me").unwrap();

        let old_symlink_name = dir.join(format!("{TEMP_PREFIX}{}-oldlink", std::process::id()));
        let decoy = dir.join("decoy");
        std::fs::write(&decoy, b"decoy-content").unwrap();
        std::os::unix::fs::symlink(&decoy, &old_symlink_name).unwrap();

        atomic_write_with_mode(&target, b"payload", 0o600).unwrap();

        assert!(!old_temp.exists(), "stale temp older than 24h must be GC'd");
        assert!(unrelated.exists(), "GC must not touch non-prefixed files");
        assert!(
            old_symlink_name.symlink_metadata().is_ok(),
            "GC must skip symlinked temp-named entries, not remove them"
        );
        assert!(decoy.exists(), "GC must never traverse through a symlink");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_age_boundary_is_strictly_greater_than() {
        let dir = test_dir("gc-boundary");
        let target = dir.join("out.txt");

        let set_age = |name: &str, age: std::time::Duration| {
            let path = dir.join(format!("{TEMP_PREFIX}{}-{name}", std::process::id()));
            std::fs::write(&path, b"x").unwrap();
            let file = std::fs::File::options().write(true).open(&path).unwrap();
            file.set_times(
                std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - age),
            )
            .unwrap();
            drop(file);
            path
        };

        let just_under = set_age("under", STALE_TEMP_AGE - std::time::Duration::from_secs(1));
        let just_over = set_age("over", STALE_TEMP_AGE + std::time::Duration::from_secs(1));

        atomic_write_with_mode(&target, b"payload", 0o600).unwrap();

        assert!(
            just_under.exists(),
            "a temp file 1s younger than the threshold must survive (boundary is strict `>`)"
        );
        assert!(
            !just_over.exists(),
            "a temp file 1s older than the threshold must be GC'd"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // atomic_create_new: no-clobber contract
    // -----------------------------------------------------------------

    #[test]
    fn create_new_creates_file_with_mode() {
        let dir = test_dir("create-new");
        let target = dir.join("config.toml");

        atomic_create_new(&target, b"[rules]\n", 0o600).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"[rules]\n");
        assert_eq!(mode_of(&target), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_new_fails_closed_when_target_already_exists() {
        let dir = test_dir("create-new-exists");
        let target = dir.join("config.toml");
        std::fs::write(&target, b"original").unwrap();

        let result = atomic_create_new(&target, b"attacker-payload", 0o600);

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"original",
            "no-clobber contract: existing content must survive a failed create_new"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_new_fails_closed_when_target_is_a_symlink() {
        let dir = test_dir("create-new-symlink");
        let decoy = dir.join("decoy");
        std::fs::write(&decoy, b"decoy").unwrap();
        let target = dir.join("config.toml");
        std::os::unix::fs::symlink(&decoy, &target).unwrap();

        let result = atomic_create_new(&target, b"attacker-payload", 0o600);

        assert!(
            result.is_err(),
            "create_new must not follow a symlinked target"
        );
        assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
