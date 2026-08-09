//! The audit subsystem's error type.
//!
//! #493: this lived in `verify.rs`, which made `secret.rs` import from
//! `verify.rs` while `verify.rs` imported from `secret.rs` — a mutual module
//! dependency that existed only because the type sat in the wrong file. The
//! type is the subsystem's, not verification's: `KeyringUnusable` gained a
//! second producer in #477 and `RotationInterrupted` is constructed by
//! `secret.rs` and can never be produced by `verify_chain`.
//!
//! `omamori::audit::verify::AuditError` is a path that resolves today, so
//! `verify.rs` keeps a `pub use` of this type. That re-export is a name, not a
//! dependency — nothing here reaches back into `verify.rs`.

// #457: gains a variant, so it closes the exhaustive-match door before 1.0 for
// the same reason `VerifyResult` and `ChainStatus` do.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    SecretUnavailable,
    FileNotFound,
    /// #457: the key directory could not be listed, so which epochs exist is
    /// unknown. Kept apart from `SecretUnavailable` (the active key itself is
    /// often readable in this state) and emphatically apart from a tampering
    /// verdict — resolving `"default"` to the active key on a rotated store
    /// would make every entry look altered.
    ///
    /// PR-C1 split the repair out of the reason. `Display` renders only
    /// `reason`, because the surface that shows it most often — `doctor`'s
    /// one-line risk signal — exists to name a cause and point at
    /// `omamori audit verify`, and a repair inlined there runs past what sits
    /// readably next to its one-clause siblings (pinned in `cli.rs`). The
    /// surfaces that *do* carry a repair print `remedy` on its own line.
    ///
    /// The remedy travels with the error rather than being added by the CLI
    /// arm, for the reason #477 had to withdraw a caller-side one: the arm
    /// knows the keyring is unusable and not which condition made it so, and
    /// the conditions need different actions — one is a directory that cannot
    /// be listed, another a record file that states no epoch while the
    /// directory is perfectly fine.
    ///
    /// **#487 added a third**: the active key is missing on a store that has
    /// rotated before. Same shape as the other two — the keyring cannot be
    /// resolved, and the arm cannot tell which condition made it so — and the
    /// action differs again. Here the operator is to leave the key files alone;
    /// nothing is broken that they can repair, and the `.retired` file the
    /// obvious repair reaches for is the only thing authenticating its own
    /// epoch's entries.
    ///
    /// **The last two are produced by `rotate_key` only, and `report --json`
    /// depends on it.** `aggregate_report` maps `verify_chain`'s result rather
    /// than rotation's, and pins `kind: "directory_unreadable"` on the
    /// `ChainStatus` it builds (`report.rs`). That value is honest exactly
    /// while `verify_chain` has one way to produce this variant. Giving the
    /// verifier a second one makes the field describe a condition that did not
    /// occur — the `kind` would have to grow with it, and it exists to be
    /// stable.
    ///
    /// Empty `remedy` is allowed and means "nothing beyond the reason".
    KeyringUnusable {
        reason: String,
        remedy: String,
    },
    /// #478: `rename` moved the key being replaced into its retired slot and
    /// this rotation did not create the replacement.
    ///
    /// Not "the store now has no active key" — `source` can be `AlreadyExists`,
    /// which says some other writer put a file at that path, possibly a usable
    /// key. What the variant carries is what this process did, which is also
    /// all the message built from it claims.
    ///
    /// Kept apart from `Io` because the store *changed*. The catch-all it came
    /// from covered five situations, four of which left the key directory
    /// exactly as they found it; reporting all five as `key rotation failed`
    /// told the operator nothing about which one they were in, and the one that
    /// matters is the one where the next append mints a second key under the id
    /// this rotation was heading for.
    RotationInterrupted {
        retired_path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// #471/#487: the store could not be read, and **not** because there is
    /// nothing in it yet.
    ///
    /// Every one of these used to arrive as `SecretUnavailable`, `FileNotFound`
    /// or `Io`, all of which `aggregate_report` mapped to
    /// `ChainStatus::Unavailable` — a status `needs_attention()` treats as
    /// healthy, because it also means "auditing is off" and "there is no log
    /// yet". So a symlink planted on `audit.jsonl`, an interrupted rotation,
    /// and an unreadable key all left `doctor` silent.
    ///
    /// `kind` is classified **at the call site**, where which file was being
    /// touched is still known — an `io::Error` on its own cannot say whether it
    /// came from the log or the key. It is path-free, for the reason
    /// `KeyringUnusable`'s is: `reason` carries the operator's home directory
    /// and must stay out of `report --json`.
    StoreInaccessible {
        kind: &'static str,
        reason: String,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretUnavailable => write!(f, "HMAC secret unavailable"),
            Self::FileNotFound => write!(f, "audit log not found"),
            Self::KeyringUnusable { reason, .. } => write!(f, "{reason}"),
            Self::RotationInterrupted {
                retired_path,
                source,
            } => write!(
                f,
                "the previous key was moved to {} and its replacement could not be created: {source}",
                retired_path.display()
            ),
            Self::StoreInaccessible { reason, .. } => write!(f, "{reason}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
