//! One-per-interval gating for repeated stderr warnings (#359, generalized in #473).
//!
//! A warning that fires from a code path the shim runs on every guarded command
//! is not information after the second time — it is noise that trains the
//! operator to skip it. The mechanism is an mtime sentinel: emit, touch the
//! file, and stay quiet for [`THROTTLE_SECS`] while its mtime is fresh.
//!
//! Two properties are load-bearing and easy to lose:
//!
//! **The sentinel lives under the base dir (`~/.omamori`), never the audit data
//! dir.** Every warning throttled here fires precisely when something about the
//! audit store is unreadable or unwritable, so a sentinel co-located with it
//! would be unwritable in the same failure — and the warning would repeat on
//! every command, which is the state this exists to prevent.
//!
//! **No two messages with different content may share a sentinel.** Sharing
//! lets the first silence the second for five minutes, and the two conditions
//! generally need different actions. [`sentinel_name_for_store`] is how a
//! caller gets a name that separates by warning kind *and* by store — the
//! second matters because `--config` can point anywhere, and because unit tests
//! in one process share a real home directory.
//!
//! Not every caller needs it. The audit-append warning (#359) predates this
//! module and uses a single fixed name, which is correct for it: it has one
//! message and one store per invocation. The separation is a tool offered here,
//! not an invariant this module can enforce on its callers — nothing stops two
//! call sites from passing the same kind, which is why
//! `audit::tests::throttle_kinds_are_distinct` exists.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Matches the interval `#359` established for the audit-append warning, which
/// is still the largest consumer.
const THROTTLE_SECS: u64 = 300;

/// Where a sentinel with this name lives.
///
/// `None` when the base dir cannot be resolved (HOME unset, empty or relative),
/// which callers must read as **do not throttle** — an unresolvable home is not
/// a reason to withhold a warning.
pub(crate) fn sentinel_path(name: &str) -> Option<PathBuf> {
    crate::installer::default_base_dir().map(|d| d.join(name))
}

/// A sentinel name that is distinct per warning kind *and* per store.
///
/// The store is folded in as a short digest of its path rather than the path
/// itself: paths contain separators and characters a filename cannot hold, and
/// the full path in a filename under `~/.omamori` would also put the operator's
/// directory layout somewhere it is not already written.
pub(crate) fn sentinel_name_for_store(kind: &str, store: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(store.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    // Rendered whole and then truncated, rather than byte by byte. `{:x}` on a
    // `u8` drops leading zeros, so the first version of this produced 5- to
    // 8-character names and was **not injective** — `[0x01,0x23,..]` and
    // `[0x12,0x03,..]` both became `123..`, giving two stores one sentinel and
    // undoing the separation this function exists to provide. On the digest as
    // a whole the same format is fixed-width, which is why the shape rather
    // than a per-byte width specifier is what keeps the property. Both other
    // SHA-256 renderings in this crate (`integrity::sha256_hex`,
    // `installer::hook_content_hash`) use this form; only the hand-rolled loop
    // had the hazard.
    //
    // Eight characters is a cache key, not a security boundary. A collision
    // costs one suppressed warning on one of two stores, and the input is not
    // attacker-chosen in any way that makes finding one worth the effort.
    format!("warn-{kind}-{}", &format!("{digest:x}")[..8])
}

/// The window for recording a tool whose input shape `hook-check` does not
/// recognise (ADR-0018): once per tool name per day.
pub(crate) const UNKNOWN_TOOL_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The sentinel name for an unrecognised-shape tool.
///
/// Digested for the reason [`sentinel_name_for_store`] is — a tool name is
/// whatever the agent platform sends, MCP names included, and has no business
/// becoming a path component as it stands.
pub(crate) fn unknown_tool_sentinel_name(tool_name: &str) -> String {
    let digest = Sha256::digest(tool_name.as_bytes());
    format!("unknown-tool-{}", &format!("{digest:x}")[..8])
}

/// Whether this warning should be printed now, touching the sentinel if so.
///
/// Fails open in every uncertain case: an unreadable sentinel, a non-file at
/// that path, a clock that will not answer. Withholding a warning because the
/// throttle itself is broken is the wrong direction for a tool whose product is
/// telling the operator what happened.
pub(crate) fn should_emit_at(path: &Path) -> bool {
    if is_fresh(path, THROTTLE_SECS) {
        return false;
    }
    mark(path);
    true
}

/// Whether the sentinel at `path` was touched within the last `window_secs`.
/// Every uncertain case — no file, a non-file, no mtime, a clock that will not
/// answer — is "not fresh", for the reason [`should_emit_at`] fails open.
pub(crate) fn is_fresh(path: &Path, window_secs: u64) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| {
        meta.file_type().is_file()
            && meta
                .modified()
                .ok()
                .and_then(|mtime| mtime.elapsed().ok())
                .is_some_and(|elapsed| elapsed.as_secs() < window_secs)
    })
}

/// Touch the sentinel at `path`. Separate from [`is_fresh`] for a caller that
/// marks only once the thing being throttled has actually happened (ADR-0018:
/// the unknown-tool record).
///
/// Writes via `atomic_file::atomic_write_with_mode` (#322-class: this sentinel
/// had the same predictable-temp-name + `create(true)` race as the heartbeat
/// writer before #307). Content is empty — only the mtime matters
/// ([`is_fresh`] reads it, never the bytes).
pub(crate) fn mark(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let _ = std::fs::create_dir_all(parent);
    let _ = crate::atomic_file::atomic_write_with_mode(path, b"", 0o600);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("omamori-warn-throttle-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name)
    }

    #[test]
    fn first_call_emits_and_second_is_suppressed() {
        let s = tmp("basic");
        let _ = std::fs::remove_file(&s);
        assert!(should_emit_at(&s), "nothing has been said yet");
        assert!(
            !should_emit_at(&s),
            "the same warning within the window is noise"
        );
        let _ = std::fs::remove_file(&s);
    }

    /// The property `#473` turns on: one warning must not silence another.
    ///
    /// Without distinct names, reporting "the key directory cannot be listed"
    /// would hide "a rotation was interrupted" for five minutes — two different
    /// conditions with two different remedies.
    #[test]
    fn different_kinds_do_not_suppress_each_other() {
        // A store path unique to this test. The sibling below derives names
        // from its own pair, and `tmp()` keys only on pid — sharing a store
        // path would put both tests on one file, in one process, at default
        // test parallelism. Which is the production hazard this pair exists to
        // pin, reproduced in the fixture.
        let store = Path::new("/tmp/omamori-kinds-fixture");
        let a = tmp(&sentinel_name_for_store("keystore", store));
        let b = tmp(&sentinel_name_for_store("rotation", store));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);

        assert_ne!(
            a, b,
            "two warning kinds on one store must not share a sentinel"
        );
        assert!(should_emit_at(&a));
        assert!(
            should_emit_at(&b),
            "the second kind has not been reported yet"
        );
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    /// And one store must not silence another — `--config` can point anywhere,
    /// and unit tests in one process share a real HOME.
    #[test]
    fn different_stores_do_not_suppress_each_other() {
        let a = tmp(&sentinel_name_for_store(
            "keystore",
            Path::new("/tmp/omamori-stores-fixture-a"),
        ));
        let b = tmp(&sentinel_name_for_store(
            "keystore",
            Path::new("/tmp/omamori-stores-fixture-b"),
        ));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);

        assert_ne!(a, b, "the store must be part of the name");
        assert!(should_emit_at(&a));
        assert!(should_emit_at(&b));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    /// The digest rendering must be fixed-width, or the separation the two
    /// tests above check does not hold in general.
    ///
    /// `{:x}` on a `u8` drops leading zeros, which makes the rendering
    /// non-injective: `[0x01,0x23,..]` and `[0x12,0x03,..]` both become
    /// `123..`, and two stores share a sentinel. The two tests above use fixed
    /// paths whose digests happen not to collide, so they would keep passing.
    /// This asserts the property they rely on.
    #[test]
    fn sentinel_names_are_fixed_width_and_injective_over_the_digest() {
        // Paths chosen only to be different; the property is about rendering,
        // so a spread of inputs is what is wanted rather than a crafted pair.
        let mut seen = std::collections::HashSet::new();
        for i in 0..512 {
            let name = sentinel_name_for_store("k", &PathBuf::from(format!("/s/{i}")));
            let hex = name.strip_prefix("warn-k-").expect("prefix");
            assert_eq!(
                hex.len(),
                8,
                "digest rendering must be 8 characters, got {name:?}"
            );
            assert!(
                seen.insert(name.clone()),
                "two distinct stores produced the same sentinel: {name:?}"
            );
        }
    }

    /// Fail open. A directory where the sentinel belongs cannot be read for an
    /// mtime, and the answer to "I cannot tell" is to speak, not to stay quiet.
    #[test]
    fn non_file_at_the_sentinel_path_does_not_suppress() {
        let s = tmp("as-a-directory");
        let _ = std::fs::remove_file(&s);
        std::fs::create_dir_all(&s).unwrap();
        assert!(should_emit_at(&s));
        assert!(
            should_emit_at(&s),
            "and it keeps failing open rather than latching"
        );
        let _ = std::fs::remove_dir_all(&s);
    }

    /// ADR-0018: one sentinel per tool name, fixed width, and no name of the
    /// tool itself in the file name (MCP names are whatever the platform
    /// sends).
    #[test]
    fn unknown_tool_sentinels_are_distinct_per_name() {
        let mut seen = std::collections::HashSet::new();
        for name in [
            "AskUserQuestion",
            "Agent",
            "mcp__notion__notion-search",
            "../x",
            "a/b",
        ] {
            let sentinel = unknown_tool_sentinel_name(name);
            let hex = sentinel.strip_prefix("unknown-tool-").expect("prefix");
            assert_eq!(hex.len(), 8, "{sentinel}");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{sentinel}");
            assert!(seen.insert(sentinel), "{name}");
        }
    }

    /// The window is the caller's: a day for unknown tools, where the default
    /// is five minutes. A sentinel touched just now suppresses within either,
    /// and one older than the window does not.
    #[test]
    fn the_window_is_the_callers() {
        let s = tmp("window");
        let _ = std::fs::remove_file(&s);
        assert!(!is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS));
        mark(&s);
        assert!(is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS));
        let an_hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&s)
            .unwrap()
            .set_modified(an_hour_ago)
            .unwrap();
        assert!(
            is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS),
            "an hour is inside a day"
        );
        std::fs::File::options()
            .write(true)
            .open(&s)
            .unwrap()
            .set_modified(an_hour_ago)
            .unwrap();
        assert!(should_emit_at(&s), "and outside five minutes");
        let _ = std::fs::remove_file(&s);
    }

    /// `is_fresh` only looks; `mark` is what makes it fresh.
    #[test]
    fn is_fresh_does_not_mark() {
        let s = tmp("look-only");
        let _ = std::fs::remove_file(&s);
        assert!(!is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS));
        assert!(
            !is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS),
            "looking twice changes nothing"
        );
        mark(&s);
        assert!(is_fresh(&s, UNKNOWN_TOOL_WINDOW_SECS));
        let _ = std::fs::remove_file(&s);
    }
}
