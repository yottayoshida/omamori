//! Audit chain verification, entry display, and summary for CLI commands.

use std::io::{BufRead, Write};

use super::chain::{
    NO_HMAC_SECRET, RecomputedHash, compute_entry_hash, genesis_hash, hmac_bytes,
    is_supported_chain_version, prune_genesis_hash,
};
use super::retention::is_prune_point;
use super::secret::{
    KeyStoreOutlook, Keyring, UNRESOLVED_KEY_ID, UnprotectedReason, classify_secret_failure,
    expected_key_file, flock_shared, interrupted_rotation_evidence, is_symlink_attack,
    is_writer_emitted_key_id, key_store_outlook, load_keyring, open_read_nofollow, read_secret,
    secret_path_for,
};
use super::{AuditConfig, AuditEvent, resolved_audit_path};
use super::{HwmState, hwm_path_for, read_hwm, write_hwm};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// #177 B3 (QA review): matches the precedent B2 set for `AuditEvent` when
// it added `wrapper_kind` — a public struct gaining new public fields
// gets `#[non_exhaustive]` in the same change, closing the exhaustive
// struct-literal/destructure two-way door before 1.0 rather than after
// (crates.io reverse dependencies verified at 0, same as B2's check).
/// Why an entry's `key_id` did not resolve to a key.
///
/// The three cases carry different amounts of information about whether the
/// log was attacked, and collapsing them is what made exit 2 exploitable
/// (Phase 8): `key_id` is an ordinary field of `audit.jsonl`, so anyone who
/// can write the file can move an entry from "tampered" to "cannot verify"
/// by editing one string — no key material, no re-signing. Measured against
/// v0.16.0: `exit 1  chain broken … may have been tampered with` became
/// `exit 2  … This is not evidence of tampering.` for a one-field edit.
///
/// The classification stays at exit 2 — an unresolvable key genuinely cannot
/// be checked, and calling that tampering is the false accusation #457 exists
/// to remove. What changes is that the *explanation* is now derived from
/// evidence rather than assumed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyUnavailableKind {
    /// The entry names [`UNRESOLVED_KEY_ID`]: omamori itself wrote it while
    /// the key directory could not be enumerated, so it was never
    /// HMAC-protected. Nothing is missing and nothing is restorable.
    NeverProtected,
    /// No omamori writer emits an id of this shape. The "a key file went
    /// missing" story is not merely unproven here, it is contradicted — so no
    /// reassurance is offered.
    NotWriterEmitted,
    /// A well-formed epoch id whose key file this host does not hold. A
    /// renamed, deleted or unreadable key file explains it; so does an edit.
    KeyFileAbsent {
        /// Where to look, in the directory holding `audit.jsonl`.
        expected_file: String,
        /// Set when the named epoch is higher than any this store currently
        /// shows — the epoch has no key file here to have lost. Carried as
        /// the observed maximum rather than as a verdict, because deleting
        /// retired key files lowers it too, and "you deleted old keys" and
        /// "someone edited this field" are not distinguishable from disk.
        beyond_known_epochs: Option<u32>,
    },
}

/// The key material could not be used at all, so **no** entry can be checked
/// against the key it names.
///
/// #506: these five states used to be `return Err(..)` before a single line was
/// read, and the high-water-mark comparison sits after the read loop. That
/// comparison needs no key — it asks whether the log still reaches the mark a
/// previous run recorded — so returning early suppressed tail-truncation
/// detection on exactly the stores where an attacker had already touched the
/// key material. Measured on a release build: a store with its tail deleted and
/// its key directory at mode 0300 reported `exit 2, cannot verify` and not one
/// word about the deletion, where the same deletion alone reported exit 3.
///
/// It is the substitution #470 closed for an edited `key_id`, reached through a
/// different door: make the key unreadable rather than unresolvable, and the
/// verifier stops before it can notice anything else.
///
/// Carried as a value so the walk continues. Being carried does not make it
/// mild — [`VerifyResult::halted`] includes it, so every line is tallied rather
/// than trusted, and the mark is never written from a run in this state. What
/// the walk buys is the checks that need no key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyStoreFailure {
    /// Path-free classification, for machine consumers.
    ///
    /// Deliberately the same values the `AuditError` this replaced carried, so
    /// that a given store reports the same `chain_status` and the same `kind`
    /// after this change as before it. The one value that moves is
    /// `epoch_record_unreadable`, which used to be mislabelled
    /// `directory_unreadable` — see `KeyringAnomaly::kind`.
    pub kind: &'static str,
    /// Human-facing text. Embeds the key directory's path, so it stays out of
    /// `report --json` exactly as `ChainStatus::KeyringUnusable`'s does.
    pub reason: String,
    /// What to do about it. Empty means "nothing beyond the reason" — the
    /// convention `AuditError::KeyringUnusable` already set.
    pub remedy: String,
}

impl KeyStoreFailure {
    /// Whether this failure is about the keyring as a whole rather than about
    /// the store being unreadable.
    ///
    /// It decides which `ChainStatus` the failure maps to, and the two families
    /// were previously distinguished by which `AuditError` variant arrived.
    /// Kept as one predicate here rather than as a `match` at the mapping site:
    /// the classification is a property of the failure, and spelling it out
    /// where it is consumed puts a typo one character away from silently
    /// re-filing a keyring fault as an inaccessible store.
    pub(crate) fn is_keyring_level(&self) -> bool {
        matches!(
            self.kind,
            "directory_unreadable" | "epoch_record_unreadable"
        )
    }

    /// The error this failure is reported as when there turns out to be no log
    /// to walk either.
    ///
    /// #506 keeps the walk going past an unusable key store, which helps only
    /// while a log can be read. One `chmod` takes both: at mode 0000 the
    /// directory loses its traverse bit, so the key listing *and* the log go
    /// with it. Reporting the log there would move that store from
    /// `keyring_unusable` to `log_unreadable` — undoing #478's judgement that
    /// the directory is what failed and the message must say so, silently, as a
    /// side effect of a change about something else. Naming the cause still
    /// beats naming the second symptom of it.
    fn into_error(self) -> AuditError {
        if self.is_keyring_level() {
            AuditError::KeyringUnusable {
                reason: self.reason,
                remedy: self.remedy,
            }
        } else {
            AuditError::StoreInaccessible {
                kind: self.kind,
                reason: self.reason,
            }
        }
    }
}

#[derive(Default)]
#[non_exhaustive]
pub struct VerifyResult {
    pub chain_entries: u64,
    /// #483: entries omamori itself wrote with no HMAC, walked past rather than
    /// halted on.
    ///
    /// Kept apart from `chain_entries` because they were **not** authenticated,
    /// and that field is the number this command reports as verified. Counted at
    /// all because the alternative is worse: a log made entirely of them would
    /// otherwise reach the `chain_entries == 0` arm, which prints "no entries to
    /// verify" and exits **0** — a clean bill of health for a log nothing could
    /// check.
    pub never_protected_entries: u64,
    pub legacy_entries: u64,
    pub torn_lines: u64,
    pub broken_at: Option<u64>,
    pub pruned: bool,
    pub pruned_count: Option<u64>,
    pub tail_truncated: bool,
    pub hwm_missing: bool,
    pub hwm_tampered: bool,
    /// Whether the high-water-mark comparison actually ran.
    ///
    /// #506: `audit verify`'s halted note ends by telling the operator that
    /// "the chain does reach the high-water-mark" whenever neither
    /// `hwm_missing` nor `hwm_tampered` is set. That inference held while the
    /// only way to halt was at some entry, which had usually stated a `seq` for
    /// the comparison to use. A store whose key material is unusable halts
    /// before the first line, so an empty log reaches the same note having
    /// compared nothing — and the note would claim it had. This is what tells
    /// "compared, and the chain was long enough" from "there was no end to
    /// compare with".
    pub hwm_compared: bool,
    /// #177 B1 step 2: seq of the first entry whose `chain_version` this
    /// binary doesn't recognize. `None` means every entry encountered was
    /// either verifiable or legacy. Distinct from `broken_at` — this is not
    /// evidence of tampering, it's evidence the binary predates the chain
    /// format (or, less likely, that a downgrade happened after a newer
    /// entry was written).
    pub unknown_version_at: Option<u64>,
    /// The unsupported `chain_version` value found at `unknown_version_at`.
    pub unknown_chain_version: Option<u32>,
    /// #457 A5: seq of the first entry whose `key_id` names a key that is not
    /// in the keyring. Like `unknown_version_at` this is *not* evidence of
    /// tampering — the entry may be perfectly authentic, we simply have no way
    /// to check it. Before #457 this case fell through to
    /// `keyring.get(id).unwrap_or(&secret)`, which checked the entry against
    /// the active key and reported the inevitable mismatch as "the audit log
    /// may have been tampered with" — a false accusation triggered by nothing
    /// more than a missing or renamed key file.
    pub key_unavailable_at: Option<u64>,
    /// The `key_id` named at `key_unavailable_at`.
    pub key_unavailable_id: Option<String>,
    /// Why that key could not be resolved — see [`KeyUnavailableKind`].
    pub key_unavailable_kind: Option<KeyUnavailableKind>,
    /// #457: non-fatal problems assembling the keyring — a truncated ring, or
    /// a file shaped like a retired key that could not be read. Verification
    /// still ran (the keys that loaded authenticate their own entries), but
    /// the coverage is incomplete and saying so is the whole point: a shorter
    /// key set that verifies fewer entries looks identical to a complete one
    /// unless it is reported.
    pub keyring_warnings: Vec<String>,
    /// #506: the key material could not be used at all — see
    /// [`KeyStoreFailure`]. The third terminal state, and the only one that is
    /// known before the first line is read, which is why nothing here is
    /// authenticated and `unverified_entries_after` counts from zero rather
    /// than from the halting entry.
    pub key_store_failure: Option<KeyStoreFailure>,
    /// Count of lines from `unknown_version_at` onward (inclusive) that
    /// could not be verified — once one entry's authenticity can't be
    /// confirmed, the `prev_hash` chain running through it means nothing
    /// after it can be trusted either, regardless of what those later
    /// lines individually claim.
    pub unverified_entries_after: u64,
    /// #177 B3: counts of *verified* chain entries by `chain_version`, for
    /// the mixed-chain counter `omamori audit verify` prints when a log
    /// spans the v1→v2 upgrade boundary. Legacy entries (no `chain_version`)
    /// are counted in `legacy_entries` above, not here. Entries at or after
    /// `unknown_version_at` are excluded — they were never verified, so
    /// asserting a version for them would be a claim about unverified data.
    pub v1_entries: u64,
    pub v2_entries: u64,
}

impl VerifyResult {
    /// Verification stopped at an entry it could not authenticate, and every
    /// line after that point is tallied rather than trusted.
    ///
    /// #457 (`/simplify`, three reviewers converged): the two terminal states
    /// were spelled out longhand in both places that gate on them — the read
    /// loop and the high-water-mark check. A third state would have to be
    /// added to both, and neither is compiler-checked. The HWM *write* is the
    /// expensive one to miss: recording the mark from a run that stopped early
    /// silently lowers it, which disables tail-truncation detection from then
    /// on, with no error and no failing test.
    ///
    /// `broken_at` is deliberately *not* included. A broken chain `break`s out
    /// of the loop entirely, and it must still reach the HWM check.
    ///
    /// #470: `pub(crate)`, because the three surfaces that render a verdict —
    /// the `audit verify` exit branch, `aggregate_report`, and `doctor` through
    /// it — have to distinguish "halted" from "halted *and* the tail is short",
    /// and the alternative was each of them re-spelling
    /// `unknown_version_at.is_some() || key_unavailable_at.is_some()`, which is
    /// the duplication this method exists to have removed. Crate-visible rather
    /// than `pub`: every caller is in this crate, and widening the library API
    /// for them would also put a `halted` method in scope for any consumer
    /// holding a `VerifyResult`, changing method resolution for one of their
    /// own traits (Codex R1, P2). Also note what it no longer means: halting
    /// stops *authentication*, not every check. The high-water-mark comparison
    /// runs regardless.
    ///
    /// #506 adds the third state, and it is the one the doc above was written
    /// for: a store whose key material is unusable now *reaches* this method
    /// instead of returning an error before the loop. Every line is tallied,
    /// the mark is not written, and the comparison — which needs no key — runs.
    pub(crate) fn halted(&self) -> bool {
        self.unknown_version_at.is_some()
            || self.key_unavailable_at.is_some()
            || self.key_store_failure.is_some()
    }

    /// Entries the walk has consumed as part of the chain — authenticated or
    /// not.
    ///
    /// #483: `chain_entries` answered this until now, because the two were the
    /// same number. A never-protected entry is walked past without being
    /// counted as verified, so the questions came apart, and the two sites that
    /// ask this one are asking *"has the chain started yet"*: the genesis
    /// anchor, and the fail-closed rule for a legacy-shaped line appearing
    /// mid-chain. Answering either with `chain_entries` would restart the chain
    /// at every unprotected entry — expecting a genesis hash where the previous
    /// line's hash belongs, and re-admitting spliced legacy entries after one.
    fn entries_walked(&self) -> u64 {
        self.chain_entries + self.never_protected_entries
    }

    /// Whether any line was walked past without being authenticated.
    ///
    /// Wider than [`Self::halted`], and the difference is what review caught.
    /// A never-protected entry does not stop verification — the entries after it
    /// are authenticated normally — but the end of the chain is still not
    /// something this run can vouch for, and **the append path advances the
    /// high-water-mark for every entry it writes, protected or not**. Measured:
    /// a store whose last entry was written while the key directory was
    /// unlistable reported `exit 3, audit log tail may have been truncated` on a
    /// log nothing had been removed from, because the mark had moved with the
    /// append while `last_verified_seq` deliberately had not.
    ///
    /// So the mark must not be written from such a run either — writing a
    /// lowered mark disables truncation detection from then on, silently, which
    /// is the failure `#177 B1` gated against in the first place.
    fn walked_past_unauthenticated(&self) -> bool {
        self.halted() || self.never_protected_entries > 0
    }
}

/// The three prune-point values the next entry's prune-bind check needs, which
/// are only meaningful together.
///
/// #457 (`/simplify`): A4 originally carried these as three parallel `Option`
/// locals plus a `last_was_prune` flag. That is the shape this whole change
/// exists to remove — `SigningKey`'s own doc argues that binding co-dependent
/// values into one type is what stops a call site from pairing them wrongly,
/// and then the prune path paired them by hand anyway. Concretely, the read
/// site checked two of the three and used the key unconditionally, so an edit
/// that set only two would have fed `hmac_bytes(None, ..)` — returning the
/// `NO_HMAC_SECRET` sentinel — into the comparison as the expected value.
struct PruneBind {
    target_hash: String,
    count: u64,
    key: [u8; 32],
}

pub struct ShowOptions {
    pub last: Option<usize>,
    pub rule: Option<String>,
    pub provider: Option<String>,
    pub json: bool,
    /// PR6 (#182): exact-match filter on `action`. Used by
    /// `omamori audit unknown` to surface the `unknown_tool_fail_open`
    /// events the hook layer records when a tool drifts past
    /// shape-based routing.
    pub action: Option<String>,
    /// PR1d (v0.10.3+, #240): when true, only entries whose
    /// `detection_layer` starts with `"layer2:relaxed:"` are shown.
    /// Used by `omamori audit show --relaxed` to forensically review
    /// commands that the data-context residual backstop allowed
    /// (DI-16 audit-relaxed-tag invariant).
    pub relaxed_only: bool,
}

/// #471: `#[non_exhaustive]`, matching `VerifyResult` and `ChainStatus`. This
/// change adds a field, and a `pub` struct with `pub` fields and no such
/// attribute cannot gain one without breaking every struct literal outside the
/// crate. The other two took that one-time cost before 1.0 on the reasoning
/// that a type which will keep gaining cases should close the door early; this
/// one was simply missed. Within the crate the compiler still checks nothing
/// away — `#[non_exhaustive]` constrains other crates only.
#[non_exhaustive]
pub struct AuditSummary {
    pub enabled: bool,
    /// Whether an append would be attempted at all — `AuditLogger::from_config`'s
    /// own predicate, mirrored here (#492).
    ///
    /// `enabled` alone does not answer it: `from_config` also returns `None`
    /// when the audit path does not resolve, and there `enabled` is `true`.
    /// Nor does `path_error`, which is `Some` in **two** unrelated states —
    /// that one, and a resolved path whose log file cannot be read. The second
    /// has a logger: appends are attempted and fail, which `[audit] strict`
    /// turns into a refused command rather than an unrecorded one. Telling
    /// "nothing will be written" from "the write will fail" needs this field.
    pub logger_available: bool,
    pub entry_count: u64,
    /// **One-directional**: `true` means an append made at this moment would
    /// be HMAC-protected. `false` does not mean the opposite — a store with no
    /// active key reports `false` and then mints one on the next append,
    /// protecting that entry (measured; pinned by a test). Erring toward
    /// "not protected" is the safe side, and closing the gap would mean
    /// creating a key file as a side effect of asking for status.
    ///
    /// #471: this used to be `read_secret(…).is_ok()`, which asks a narrower
    /// question than the writer does — see [`UnprotectedReason`]. It is now
    /// false in every state the writer refuses to sign in.
    pub secret_available: bool,
    /// Why not, so a caller never has to invent wording for a state it cannot
    /// name.
    ///
    /// `Some` exactly when `secret_available` is false **and** the store was
    /// far enough resolved to look: the two early returns — auditing disabled,
    /// and an audit path that does not resolve — report `false` with `None`
    /// here, because neither reached a key store to have an opinion about.
    /// `path_error` covers the second.
    pub unprotected_reason: Option<UnprotectedReason>,
    pub retention_days: u32,
    pub path_error: Option<String>,
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

/// Records the point where an entry's `chain_version` became unverifiable and
/// switches `result` into a terminal state. Shared by both places
/// `verify_chain` can discover this — the fast path (a successfully-parsed
/// `AuditEvent` whose `chain_version` field is unsupported) and the raw-JSON
/// fallback (an entry whose *shape* a future `chain_version` changed enough
/// that `AuditEvent` can't even parse it).
///
/// #457: this used to say "`unknown_version_at.is_some()` *is* that state",
/// which stopped being true the moment a second terminal state existed.
/// `VerifyResult::halted()` is now the single answer to "did verification
/// stop?", and each `mark_*` function owns the transition into one of them —
/// including `unverified_entries_after = 1`, which is what makes the count
/// mean "this entry plus everything after it".
/// #470 adds `structural_end` and `stated_seq` for the same reason `mark_*`
/// owns `unverified_entries_after`: the high-water-mark comparison now needs an
/// end for the *file*, the halting line is part of it, and a third terminal
/// state must not be able to forget that by construction.
///
/// **`stated_seq` is not `seq`.** `seq` carries a fallback — the position this
/// entry should have occupied — for a line that does not state one. That
/// fallback is one past the last verified entry, so using it as the file's end
/// compares the mark against the halt point rather than against the file, and
/// reports truncation on a log nothing was removed from. Exactly the "compare
/// against a false end" failure the old `!halted()` gate existed to prevent,
/// re-entering by a different door (Codex R1, P1). Only a stated `seq` counts;
/// when nothing at or after the halt states one, the comparison is skipped.
fn mark_unverifiable_tail(
    result: &mut VerifyResult,
    structural_end: &mut Option<u64>,
    stated_seq: Option<u64>,
    reported_position: u64,
    chain_version: u32,
) {
    result.unknown_version_at = Some(stated_seq.unwrap_or(reported_position));
    result.unknown_chain_version = Some(chain_version);
    result.unverified_entries_after = 1;
    if stated_seq.is_some() {
        *structural_end = stated_seq;
    }
}

/// The other terminal state (#457): an entry names a key the keyring does not
/// hold. Sibling of `mark_unverifiable_tail` — same shape, same ownership of
/// `unverified_entries_after`, different reason. Kept as a function rather
/// than three inline assignments so that adding a third terminal state means
/// writing a third `mark_*` and one arm in `halted()`, not finding every place
/// the transition was open-coded.
fn mark_key_unavailable_tail(
    result: &mut VerifyResult,
    structural_end: &mut Option<u64>,
    stated_seq: Option<u64>,
    reported_position: u64,
    key_id: &str,
    highest_known_epoch: u32,
) {
    result.key_unavailable_at = Some(stated_seq.unwrap_or(reported_position));
    result.key_unavailable_id = Some(key_id.to_string());
    result.key_unavailable_kind = Some(classify_unavailable_key(key_id, highest_known_epoch));
    result.unverified_entries_after = 1;
    // See `mark_unverifiable_tail` for why only a stated `seq` may count.
    if stated_seq.is_some() {
        *structural_end = stated_seq;
    }
}

/// Decide what can honestly be said about an unresolvable `key_id`.
///
/// Ordering matters: [`UNRESOLVED_KEY_ID`] is writer-emitted, so it has to be
/// matched before the general writer-shape test would fold it in with the
/// epochs.
fn classify_unavailable_key(key_id: &str, highest_known_epoch: u32) -> KeyUnavailableKind {
    if key_id == UNRESOLVED_KEY_ID {
        return KeyUnavailableKind::NeverProtected;
    }
    if !is_writer_emitted_key_id(key_id) {
        return KeyUnavailableKind::NotWriterEmitted;
    }
    match expected_key_file(key_id) {
        Some(expected_file) => {
            // Shape alone is a weak test: `key-99` looks exactly like an id a
            // writer emits, so an attacker picking a large number lands in
            // this arm and gets sent looking for `audit-secret.99.retired` —
            // a file that never existed. Saying so is worth more than the
            // path, and unlike the path it is checkable.
            let named = epoch_of(key_id);
            let beyond_known_epochs = match named {
                Some(n) if n > highest_known_epoch => Some(highest_known_epoch),
                _ => None,
            };
            KeyUnavailableKind::KeyFileAbsent {
                expected_file,
                beyond_known_epochs,
            }
        }
        // `is_writer_emitted_key_id` accepted it, so `expected_key_file`
        // returning None would mean the two disagree about what an epoch id
        // looks like. Treat the disagreement as "cannot substantiate the
        // missing-file story" rather than inventing a path.
        None => KeyUnavailableKind::NotWriterEmitted,
    }
}

/// The epoch number an id names: `"default"` is epoch 1, `key-N` is epoch N.
fn epoch_of(key_id: &str) -> Option<u32> {
    if key_id == "default" {
        return Some(1);
    }
    key_id.strip_prefix("key-")?.parse().ok()
}

/// Minimal typed peek for the raw-JSON fallback (an entry whose full
/// `AuditEvent` parse already failed). Any JSON key not named here —
/// including an attacker-controlled arbitrarily large one — is skipped by
/// serde during deserialization rather than allocated, unlike a
/// `serde_json::Value` peek of the same line (see the fallback's comment
/// for the measured cost of that). Both fields are `Option` so a missing
/// or wrong-shaped `seq` degrades to the `expected_seq` fallback rather
/// than failing the whole peek — a type-mismatched `chain_version`
/// (rather than missing) still fails the peek, same as a
/// `serde_json::Value` peek would have failed to extract a `u32` from it.
#[derive(serde::Deserialize)]
struct ChainVersionSeqPeek {
    chain_version: Option<u32>,
    seq: Option<u64>,
}

/// #470: `seq` alone, for lines past a halt, where nothing else about them is
/// being decided. Sharing `ChainVersionSeqPeek` here would have thrown away a
/// perfectly readable `seq` whenever the same line's `chain_version` had the
/// wrong JSON type — that peek fails as a whole in that case, by design, and
/// after a halt that would leave the file's end stuck at the halting line and
/// report truncation on a log nothing was removed from (Codex R1, P2).
#[derive(serde::Deserialize)]
struct SeqPeek {
    seq: Option<u64>,
}

/// Is this a store nothing has ever been written to?
///
/// #471 (review): the two quiet errors were named "there is no log yet" and
/// "the first key has not been minted", and neither checked. Measured on a
/// release build: **deleting `audit.jsonl` outright left `doctor` saying
/// `quiet`**, and so did deleting the active key of a store that already held
/// entries. An audit tool has no business being silent about either, and
/// `docs/CONTRACT.md` had already published the claim that only "nothing has
/// been written" stays quiet.
///
/// The evidence is on disk and costs two stats. `audit.jsonl.hwm` is created by
/// the first append and is not removed with the log, so a sidecar beside an
/// absent log says the log existed. A log with bytes in it says the same more
/// directly.
fn nothing_written_yet(path: &std::path::Path) -> bool {
    let log_has_content = std::fs::metadata(path).is_ok_and(|m| m.len() > 0);
    !log_has_content && !hwm_path_for(path).exists()
}

/// What the key material turned out to be, decided before a single line is
/// read.
///
/// #506: these outcomes were five `return`s inside `verify_chain`, four of
/// which left before the high-water-mark comparison — a comparison that needs
/// no key. Naming them as values is what lets the walk continue past the ones
/// that are not quiet, while keeping the one that *is* distinguishable from
/// them: that distinction is what #471 had to add, and losing it here would
/// turn a fresh install into a standing warning.
enum KeyStore {
    Usable(Keyring),
    /// Recorded on the result and walked past — see [`KeyStoreFailure`].
    Unusable(KeyStoreFailure),
    /// Nothing has ever been written here, so there is no tail to have lost
    /// either. The one key-material state that stays quiet.
    NothingWrittenYet,
}

/// Resolve the keys this run can verify with, or say why it cannot.
///
/// The order of the first two observations is load-bearing and predates this
/// change (#478): at mode 0300 the key directory is searchable but not
/// listable, so a symlink planted on the secret path is still observable, and
/// scanning first would report "cannot list" and never mention the attack. That
/// requirement was always about *report order* — #506 satisfies it by recording
/// the observation here, before anything walks the log, rather than by leaving
/// the function.
fn resolve_key_store(log_path: &std::path::Path, secret_path: &std::path::Path) -> KeyStore {
    // #457: the active secret is no longer used as a hash key — the anchor and
    // every entry are verified with the key each one names. The read stays for
    // two reasons that have nothing to do with hashing: it preserves the ELOOP
    // (symlink attack on the secret path) distinction, which must be reported
    // before anything else touches the directory, and a store with no readable
    // active secret is "cannot verify", not "chain intact".
    let secret_error = match read_secret(secret_path) {
        Ok(_) => None,
        // #471: classified rather than handed on as `Io`. `verify` already
        // preserved the "possible attack" wording here, but every non-
        // `KeyringUnusable` error reached `doctor` as `Unavailable`, so the one
        // state in this function that is *evidence of an attack* was also the
        // one `doctor` said nothing about.
        //
        // Matched on the prefix, not on `contains("symlink")`: every rejection
        // here ends with the path, so the old test made a FIFO under a
        // directory named `symlink-something` read as an attack. `ErrorKind`
        // cannot separate them — both are `InvalidInput`.
        //
        // #506: this is the state the threat model cares about most — a
        // symlinked secret plus a deleted tail — and it was the one early
        // return the first draft of this change overlooked.
        Err(e) if is_symlink_attack(&e) => {
            return KeyStore::Unusable(KeyStoreFailure {
                kind: "secret_symlink",
                reason: e.to_string(),
                remedy: String::new(),
            });
        }
        Err(e) => Some(e),
    };

    // #457: an unlistable key directory is not "no retired keys". Resolving ids
    // against it would make `"default"` mean the active key on a rotated store
    // and report every entry as tampered — a false accusation caused by a
    // permissions problem. Nothing consults the ring once this fires.
    let keyring = load_keyring(secret_path);
    if let Some(fatal) = keyring.fatal_anomaly() {
        return KeyStore::Unusable(KeyStoreFailure {
            // Not a literal: `fatal_anomaly` selects two conditions and they
            // are not the same fault. See `KeyringAnomaly::kind`.
            kind: fatal.kind(),
            reason: fatal.describe(),
            remedy: fatal.remedy().unwrap_or_default(),
        });
    }

    // Reached only with a listing in hand, which is what makes the secret's own
    // failure the whole story rather than a consequence of not having one.
    //
    // The error body is kept rather than flattened, through the same function
    // `rotate_key_locked` has used since #477: `read_secret` tells a missing
    // secret apart from a non-regular one and from an unreadable one, and
    // folding all of them into "HMAC secret unavailable" is the flattening this
    // change removes elsewhere. Shared rather than repeated because the two
    // commands disagreeing about one store is the defect being closed.
    let Some(e) = secret_error else {
        return KeyStore::Usable(keyring);
    };

    // #487 B: `SecretUnavailable` covers two states that could not be less
    // alike — a fresh store whose key has simply not been minted yet (quiet),
    // and a rotation that stopped between filing the old key and creating its
    // replacement (one append away from a permanent cannot-verify). `rotate`
    // has told them apart since #487's A/C half; the verifier had not, so
    // `doctor` stayed silent on the second.
    //
    // The distinction is asked of `interrupted_rotation_evidence`, which makes
    // it **under the key-store lock** and from the same three observations
    // `rotate_key_locked` uses. An earlier draft did it inline, reading the
    // outlook directly and comparing two of the three: review caught that the
    // absent key and the retired keys were then observed at different times, so
    // a rotation completing in between produced `rotation_interrupted` on a
    // perfectly healthy store — a false alarm that change would have
    // introduced, since the state used to be quiet. It is a second listing of a
    // directory this function already listed; `verify` is not a hot path, and
    // the alternative is a copy of `rotate`'s condition that can drift from it.
    if e.kind() == std::io::ErrorKind::NotFound && interrupted_rotation_evidence(secret_path) {
        return KeyStore::Unusable(KeyStoreFailure {
            kind: "rotation_interrupted",
            reason: "the active audit key is missing and this store has rotated before — \
                     a rotation that stopped between filing the old key and moving its \
                     replacement into place leaves exactly this"
                .to_string(),
            remedy: String::new(),
        });
    }
    match classify_secret_failure(e) {
        // #471 (review): quiet only while nothing has been written. A store
        // that already holds entries and has lost its active key is not a fresh
        // install — the next append mints a *different* secret under the same
        // id, and every existing entry then reads as tampered (#457 P4-e).
        // `status` warned about this already; `doctor` did not.
        AuditError::SecretUnavailable if nothing_written_yet(log_path) => {
            KeyStore::NothingWrittenYet
        }
        AuditError::SecretUnavailable => KeyStore::Unusable(KeyStoreFailure {
            kind: "active_key_missing",
            reason: "the active audit key is missing on a store that already holds \
                     entries — the next append mints a different key under the same id, \
                     after which those entries cannot be verified"
                .to_string(),
            remedy: String::new(),
        }),
        other => KeyStore::Unusable(KeyStoreFailure {
            kind: "secret_unreadable",
            reason: other.to_string(),
            remedy: String::new(),
        }),
    }
}

pub fn verify_chain(config: &AuditConfig) -> Result<VerifyResult, AuditError> {
    // #471: not `FileNotFound`. That variant means "there is no log yet", which
    // is a quiet state; this is a configuration that cannot name a log at all,
    // and `status` has always reported it as a fault. The two shared one
    // variant, so the louder of them inherited the quieter one's verdict.
    let path = resolved_audit_path(config).ok_or_else(|| AuditError::StoreInaccessible {
        kind: "path_unresolved",
        reason: "HOME is unset, empty, or relative — cannot resolve audit path".to_string(),
    })?;
    let secret_path = secret_path_for(&path);

    // #506: the key material is resolved into a *value* rather than into an
    // early return. `Unusable` still means nothing in this log can be
    // authenticated — it is the third terminal state, so every line below is
    // tallied and the mark is never written from this run — but the walk
    // continues, and the checks after the loop that need no key run on a store
    // whose keys were made unreadable. That was the whole of the gap: `chmod`
    // the key directory, delete the tail, and the deletion went unmentioned.
    //
    // Only one early return is left here, and it is the one #471 established:
    // "nothing has been written yet" is quiet, and everything else is not.
    let (keyring, key_store_failure) = match resolve_key_store(&path, &secret_path) {
        KeyStore::Usable(keyring) => (keyring, None),
        KeyStore::Unusable(failure) => (Keyring::empty(), Some(failure)),
        KeyStore::NothingWrittenYet => return Err(AuditError::SecretUnavailable),
    };

    // #471: the log itself was the half the first draft of this change missed
    // — review caught it. A symlink or a FIFO planted on `audit.jsonl` is the
    // same class of evidence as one planted on the key, and it landed in the
    // same quiet bucket. Only a genuinely absent log stays quiet.
    // `open_read_nofollow` routes ELOOP through `symlink_attack_error`, so the
    // attack shape is recognisable here without inspecting the message for
    // anything but that one prefix.
    let file = open_read_nofollow(&path).map_err(|e| {
        // #506: when the key store already failed, it is the better answer for
        // a store where the log cannot be opened either — one directory
        // permission causes both. See `KeyStoreFailure::into_error`.
        if let Some(failure) = key_store_failure.clone() {
            return failure.into_error();
        }
        match e.kind() {
            // Quiet only if nothing was ever written here. A missing log with a
            // high-water-mark sidecar still beside it is a log that was removed.
            std::io::ErrorKind::NotFound if nothing_written_yet(&path) => AuditError::FileNotFound,
            std::io::ErrorKind::NotFound => AuditError::StoreInaccessible {
                kind: "log_missing",
                reason: "the audit log is gone, but this store has written one before \
                     (its high-water-mark sidecar is still here)"
                    .to_string(),
            },
            _ if is_symlink_attack(&e) => AuditError::StoreInaccessible {
                kind: "log_symlink",
                reason: e.to_string(),
            },
            _ => AuditError::StoreInaccessible {
                kind: "log_unreadable",
                reason: e.to_string(),
            },
        }
    })?;
    flock_shared(&file).map_err(|e| AuditError::StoreInaccessible {
        kind: "log_lock",
        reason: e.to_string(),
    })?;

    let reader = std::io::BufReader::new(&file);

    let mut result = VerifyResult {
        keyring_warnings: keyring.anomalies().iter().map(|a| a.describe()).collect(),
        // #506: set before the first line is read, so `halted()` is already true
        // when the loop starts and every line takes the tally path — including
        // the one that keeps `last_structural_seq` moving, which is what the
        // high-water-mark comparison below then has an end to compare against.
        //
        // It is also why `unverified_entries_after` counts from zero in this
        // state where `mark_*` starts it at one: those two mark a *halting
        // entry* and count it, and this failure has no entry to be at.
        key_store_failure,
        ..Default::default()
    };
    // #457 A3: the chain's anchor is a function of the key, so it cannot be
    // computed up front from the active secret — a chain that started before a
    // rotation anchors to `genesis_hash(retired key)`. It is resolved in the
    // `chain_entries == 0` branch below, from the key the head entry names.
    // Only used from the second chain entry onward.
    let mut expected_prev = String::new();
    // #456: `None` means "no successor number exists" — the previous verified
    // entry was numbered `u64::MAX`. Held as an `Option` rather than a `u64`
    // so the advance below can be a checked increment: a `u64` would have to
    // wrap (or panic under `overflow-checks`) at the top of the range, and
    // saturating instead would let a second `u64::MAX` entry satisfy the
    // continuity check.
    let mut expected_seq: Option<u64> = Some(0);
    // #456: the highest seq actually verified, kept instead of deriving it
    // from `expected_seq - 1` for the high-water-mark below. The derivation
    // needed a `saturating_sub` to be safe, and reported `u64::MAX - 1` after
    // verifying an entry numbered `u64::MAX` — one short, which reads as tail
    // truncation against a mark that is correct.
    let mut last_verified_seq: Option<u64> = None;
    // #470: the last seq *stated* by a line at or after the one verification
    // halted on — that line included, written by `mark_*`. Unauthenticated by
    // construction, which is the point. `None` means no such line stated one,
    // and no end can be named. See the high-water-mark block after the loop for
    // what it is and is not allowed to decide.
    let mut last_structural_seq: Option<u64> = None;
    // #483 (review): the last seq stated by a line the walk *consumed as part of
    // the chain* — authenticated or unprotected. It exists because those two
    // ends stopped being the same number, and each is now used for exactly one
    // thing: this one for the high-water-mark comparison, `last_verified_seq`
    // for the write. Substituting either for the other reintroduces a measured
    // defect — using this to write lowers the mark from an unauthenticated end,
    // using `last_verified_seq` to compare reports a truncation that did not
    // happen. Not merged with `last_structural_seq`, which means something
    // narrower on purpose: only what lines *at or after a halt* stated, so that
    // a halt with nothing stating a seq skips the comparison rather than
    // comparing against the halt point (#470).
    let mut last_walked_seq: Option<u64> = None;
    // #457 A4: the prune-bind was written with the key active at prune time,
    // so it has to be recomputed with *that* key — not with the key of the
    // first retained entry, which belongs to whatever epoch that entry was
    // written in. `Some` iff the previous line was a prune point, which also
    // replaces the separate `last_was_prune` flag.
    let mut prev_prune: Option<PruneBind> = None;

    for line in reader.lines() {
        // #471: a read that fails partway through is not "there is no log"
        // either — the file exists and stopped being readable.
        let line = line.map_err(|e| AuditError::StoreInaccessible {
            kind: "log_read",
            reason: e.to_string(),
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // #177 B1 step 2: once an entry's chain_version can't be
        // authenticated, the prev_hash chain running through it means
        // nothing after it can be trusted either — every remaining line
        // just gets tallied, not verified.
        // #457 A5: `key_unavailable_at` is the second terminal state with the
        // same meaning — from here on, entries are tallied, not trusted.
        if result.halted() {
            result.unverified_entries_after += 1;
            // #470: the high-water-mark comparison after the loop needs an end
            // for the *file*, and `last_verified_seq` stopped advancing at the
            // halt. Take what these lines state, unauthenticated, because that
            // comparison needs no key — an attacker who halts verification by
            // editing one `key_id` must not thereby also get the tail deleted
            // unreported.
            //
            // A typed peek, like the torn-line path's: it names one field, so
            // serde skips the rest of a hostile line without materializing it
            // (the measured amplification a `serde_json::Value` peek would cost
            // is spelled out at that call site). A line that states no seq —
            // torn, legacy-shaped, or a future format that renamed the field —
            // simply does not move the end.
            //
            // **The last stated seq, not the largest.** A max lets one planted
            // line anywhere in the remainder stand in for the file's end, so
            // hiding a deletion would cost an insertion in the middle rather
            // than a rewrite of the surviving tail. Taking the last one keeps
            // the claim the docs make: the attacker has to renumber the line
            // the file actually ends on (Codex R1, P1).
            if let Ok(peek) = serde_json::from_str::<SeqPeek>(trimmed)
                && peek.seq.is_some()
            {
                last_structural_seq = peek.seq;
            }
            continue;
        }

        // #456: the position to report for an entry that does not state its
        // own `seq`. `expected_seq` is `None` only when the previous verified
        // entry was numbered `u64::MAX` — which is also the position being
        // reported — so that is what the fallback yields. Bound once per
        // iteration rather than at each of the five sites below: `expected_seq`
        // only changes at the end of the body, so this cannot drift from it,
        // and the reasoning lives in one place.
        let reported_position = expected_seq.unwrap_or(u64::MAX);

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                // Codex Round 1 (#177 B1): a future chain_version might pair
                // with a JSON shape this binary's AuditEvent can't
                // deserialize at all. Before assuming genuine corruption
                // (torn line), peek the raw JSON for chain_version — if
                // it's present and unrecognized, this must read as
                // "unverifiable", not "torn". Torn-line handling resumes
                // verification against the pre-entry expected_prev/
                // expected_seq for whatever comes next, which would
                // misreport a real subsequent entry (chaining from this
                // one's unverified hash) as broken_at.
                // Security review (#177 B1): peeking via serde_json::Value here
                // (unlike chain.rs's read_chain_state, whose tail-window read is
                // already capped at 64 KB) materializes a full DOM for whatever
                // this *unbounded* per-line scan reads — measured ~5.7x memory
                // and ~25x CPU amplification on a single hostile ~50MB line vs.
                // the typed AuditEvent parse path it substitutes for. A typed
                // peek struct lets serde skip any field it doesn't name
                // (including large ones) without allocating it.
                // #177 B3: a genuinely corrupted *supported*-version entry
                // (fails AuditEvent::deserialize but chain_version peeks as
                // 1 or 2) must fall through to torn_lines below, not be
                // misreported as "unrecognized version" — that would tell
                // an operator to upgrade omamori when the real problem is
                // file corruption on an already-current binary.
                if let Ok(peek) = serde_json::from_str::<ChainVersionSeqPeek>(trimmed)
                    && let Some(chain_version) = peek.chain_version
                    && !is_supported_chain_version(chain_version)
                {
                    mark_unverifiable_tail(
                        &mut result,
                        &mut last_structural_seq,
                        peek.seq,
                        reported_position,
                        chain_version,
                    );
                    continue;
                }
                result.torn_lines += 1;
                continue;
            }
        };

        if event.chain_version.is_none() {
            // #177 B1 step 4: legacy (no chain_version) entries are only
            // legitimate at the head of the file — genuine pre-#164
            // history that predates chain tracking. A legacy-shaped entry
            // appearing AFTER real chain entries have started is fail-
            // closed, not silently skipped: it's either corruption, or an
            // attacker exploiting the fact that legacy entries never
            // participate in prev_hash/seq continuity tracking to splice
            // unaudited content into the middle of an otherwise-verified
            // chain without breaking the links around it.
            // #483: `entries_walked`, not `chain_entries`. An unprotected entry
            // is still a chain entry that has been passed — treating the chain
            // as not-yet-started after one would re-open the splice this arm
            // exists to close, since a run of unprotected entries would then
            // admit legacy-shaped lines behind them.
            if result.entries_walked() > 0 {
                result.broken_at = Some(reported_position);
                break;
            }
            result.legacy_entries += 1;
            continue;
        }

        let seq = event.seq.unwrap_or(0);
        let prev_hash = event.prev_hash.as_deref().unwrap_or("");
        let recorded_hash = event.entry_hash.as_deref().unwrap_or("");
        let is_prune = is_prune_point(&event);

        // --- entry_hash HMAC verification (multi-key: lookup by key_id).
        // Also the version dispatch point: an entry whose chain_version
        // this binary doesn't recognize can't be authenticated at all, so
        // nothing about it — including its own seq/prev_hash — is
        // trustworthy structural signal. Check this before the prev_hash
        // check below, not after. ---
        // #457 (Codex Round 1 P1): version support is decided *before* the key
        // lookup. An entry from a future chain format that also names a key we
        // do not hold must report "upgrade omamori" (exit 4), not "restore the
        // key" (exit 2) — restoring the key would not make this binary able to
        // hash the entry. Resolving the key first inverted that precedence for
        // any future entry whose shape still parses as an `AuditEvent`.
        if let Some(version) = event.chain_version
            && !is_supported_chain_version(version)
        {
            mark_unverifiable_tail(
                &mut result,
                &mut last_structural_seq,
                event.seq,
                reported_position,
                version,
            );
            continue;
        }

        // `unwrap_or("default")` stays: a missing `key_id` field means an
        // entry from before the field existed, and `"default"` is the id that
        // epoch always carried. Only the *secret* fallback below is removed.
        let entry_key_id = event.key_id.as_deref().unwrap_or("default");
        let Some(entry_secret) = keyring.get(entry_key_id) else {
            // #483: **two** pieces of evidence before an entry is believed to
            // have been written unprotected, and they have to agree.
            //
            // `key_id == UNRESOLVED_KEY_ID` alone would not do. It is an
            // ordinary field of `audit.jsonl`, so relabelling one authenticated
            // entry would move it out of "tampered" and into a state that no
            // longer halts — the exit-2 exploit #457 closed, re-opened one door
            // along. Requiring the hash field to *also* read the no-key sentinel
            // means an attacker has to destroy the entry's own hash to get here,
            // and then the next line's `prev_hash` — compared against it below —
            // no longer matches, so the chain breaks at the line after.
            //
            // The final line of a log is the exception, and it is accepted:
            // nothing follows it to hold a `prev_hash`. That is what
            // `never_protected_entries` is for; it holds the command at exit 2
            // rather than letting the store come back clean.
            //
            // A prune point is excluded. Its own key is what the *next* entry's
            // prune-bind is checked with, and there is no key here to record.
            // Continuing would mean either dropping that check or feeding it
            // `hmac_bytes(None, ..)`, which returns the sentinel for any input
            // and so matches anything — the accident `PruneBind`'s own doc
            // records.
            if entry_key_id == UNRESOLVED_KEY_ID && recorded_hash == NO_HMAC_SECRET && !is_prune {
                // Everything below needs no key, which is the whole of what this
                // arm buys over halting: #470 established that an entry omamori
                // cannot authenticate must not also switch off the checks that
                // never depended on authentication.
                if result.entries_walked() == 0 {
                    // The head of the log. Its anchor cannot be *computed* —
                    // `genesis_hash` takes the key this entry does not have —
                    // but what omamori writes there is a constant, so it can be
                    // compared directly. Review caught that skipping this
                    // entirely let a whole log be replaced with unprotected
                    // lines carrying any seq and any prev_hash, landing on the
                    // coverage complaint instead of on a broken chain.
                    //
                    // `hmac_bytes(None, ..)` is deliberately **not** used to
                    // derive the expected value: it returns the sentinel for any
                    // input, so a comparison built on it matches anything. The
                    // constant is compared as a constant.
                    //
                    // `seq` is checked here where an authenticated head does not
                    // check it, and the asymmetry runs the right way: there the
                    // HMAC covers `seq`, here nothing does.
                    if seq != 0 || prev_hash != NO_HMAC_SECRET {
                        result.broken_at = Some(seq);
                        break;
                    }
                } else if prev_prune.is_none() {
                    if Some(seq) != expected_seq {
                        result.broken_at = Some(seq);
                        break;
                    }
                    // This field holds the previous entry's real hash whoever
                    // wrote the line, which is what makes a two-field forgery
                    // break the chain at the entry after it.
                    if prev_hash != expected_prev {
                        result.broken_at = Some(seq);
                        break;
                    }
                }
                // The prune-bind's key belongs to the prune point, not to this
                // entry, so it is in hand and the check runs.
                if let Some(bind) = &prev_prune {
                    let expected_bind = hmac_bytes(
                        Some(&bind.key),
                        format!("prune-bind:{}:{recorded_hash}", bind.count).as_bytes(),
                    );
                    if bind.target_hash != expected_bind {
                        result.broken_at = Some(seq);
                        break;
                    }
                }
                // Cleared, not carried. A bind left in place would be applied
                // again at the *next* entry, whose hash it does not describe,
                // and report `broken_at` on a chain nobody touched.
                prev_prune = None;
                // The next line's `prev_hash` names this line's hash field,
                // sentinel and all. Advancing it is what turns a forged pair
                // into `broken_at` one line later.
                expected_prev = recorded_hash.to_string();
                expected_seq = seq.checked_add(1);
                // The comparison end moves; the write end does not. See
                // `walked_past_unauthenticated` for the measurement behind that
                // split.
                last_walked_seq = Some(seq);
                // `last_verified_seq` and `chain_entries` deliberately do not
                // advance. The first is what the high-water-mark is written
                // from, and an unauthenticated end recorded there disables
                // truncation detection from that run on; the second is the count
                // this command prints as *verified*.
                result.never_protected_entries += 1;
                continue;
            }
            // #457 A5: the entry names a key we do not hold. Falling back to
            // the active secret here (the pre-#457 behaviour) guaranteed a
            // hash mismatch and reported it as tampering. Stop and say what is
            // actually true: this entry cannot be verified. Everything after
            // it inherits that — the prev_hash chain runs through an entry
            // whose authenticity is unknown.
            mark_key_unavailable_tail(
                &mut result,
                &mut last_structural_seq,
                event.seq,
                reported_position,
                entry_key_id,
                keyring.highest_known_epoch(),
            );
            continue;
        };
        let recomputed = match compute_entry_hash(Some(entry_secret), &event) {
            RecomputedHash::Hash(h) => h,
            // Unreachable as of #457 — the version gate above already
            // `continue`d on any unsupported version. Kept because
            // `compute_entry_hash` is the authority on which versions it can
            // hash, and a future version added there but not to
            // `SUPPORTED_CHAIN_VERSIONS` would arrive here rather than being
            // silently mis-tallied. Behaviour is identical either way.
            RecomputedHash::UnsupportedVersion(v) => {
                // Not evidence of tampering — evidence this binary
                // predates the chain format (or a downgrade happened).
                // Stop verifying; everything from here on is tallied,
                // not trusted. Codex Round 1 test-adversarial review:
                // report expected_seq (not the generic `seq` default of
                // 0 above) when this entry's own `seq` field is missing —
                // matches the raw-JSON fallback path below and avoids a
                // misleading "at entry #0" report for an unrecognized-
                // version entry appearing deep in an otherwise-verified
                // chain.
                mark_unverifiable_tail(
                    &mut result,
                    &mut last_structural_seq,
                    event.seq,
                    reported_position,
                    v,
                );
                continue;
            }
            RecomputedHash::Legacy => {
                unreachable!("event.chain_version.is_none() already filtered above")
            }
        };

        // --- prev_hash verification ---
        // #483: `entries_walked`, not `chain_entries`. When the head of the log
        // is unprotected, `chain_entries` stays 0 — so this arm would fire again
        // at the *next* entry and compare its `prev_hash` against a genesis
        // anchor, when what belongs there is the unprotected line's own hash.
        // That is a false `broken_at` on a store nobody touched.
        if result.entries_walked() == 0 {
            // First chain entry: genesis or prune_genesis.
            // #457 A3: computed from the key THIS entry names, not from the
            // active secret. `entry_secret` was already resolved above via
            // `key_id`, and `genesis_hash` is HMAC(key, GENESIS_SEED) — so a
            // chain whose head predates a rotation anchors to the retired
            // key's genesis, which is exactly what is on disk.
            let expected = if is_prune {
                prune_genesis_hash(Some(entry_secret))
            } else {
                genesis_hash(Some(entry_secret))
            };
            if prev_hash != expected.as_str() {
                result.broken_at = Some(seq);
                break;
            }
            if is_prune {
                // seq must be 0 for prune_point at head
                if seq != 0 {
                    result.broken_at = Some(seq);
                    break;
                }
            }
        } else if prev_prune.is_some() {
            // Prune gap: prev_hash won't match prune_point's entry_hash — allowed.
            // But verify the prune-bind: target_hash must bind this entry's hash.
            // (entry_hash verification below will confirm this entry is authentic)
        } else {
            // Normal chain link. #456: comparing `Some(seq)` means a `None`
            // expectation — the previous entry was numbered `u64::MAX`, so no
            // successor is possible — rejects this entry whatever its seq is,
            // including another `u64::MAX`. Saturating the advance instead
            // would have let that second one through here.
            if Some(seq) != expected_seq {
                result.broken_at = Some(seq);
                break;
            }
            if prev_hash != expected_prev {
                result.broken_at = Some(seq);
                break;
            }
        }

        if recomputed != recorded_hash {
            result.broken_at = Some(seq);
            break;
        }

        // --- prune-bind verification (after a prune gap, using the prune
        // point's own key — see `PruneBind`) ---
        if let Some(bind) = &prev_prune {
            let expected_bind = hmac_bytes(
                Some(&bind.key),
                format!("prune-bind:{}:{recorded_hash}", bind.count).as_bytes(),
            );
            if bind.target_hash != expected_bind {
                result.broken_at = Some(seq);
                break;
            }
        }

        // Track prune state
        if is_prune {
            result.pruned = true;
            result.pruned_count = Some(event.target_count as u64);
        }
        prev_prune = is_prune.then(|| PruneBind {
            target_hash: event.target_hash.clone(),
            count: event.target_count as u64,
            key: *entry_secret,
        });
        expected_prev = recorded_hash.to_string();
        last_verified_seq = Some(seq);
        // Same value as `last_verified_seq` on a log with nothing unprotected in
        // it, which is what keeps this change invisible to every store that has
        // none. They part company only once an unprotected entry has been walked
        // past.
        last_walked_seq = Some(seq);
        // #456: a checked increment, and `None` is kept as a state rather than
        // clamped. This entry verified, so the chain is intact up to here —
        // panicking or reporting `broken_at` would both be false. What is true
        // is that nothing can legitimately follow it, which is what the
        // continuity check above then enforces.
        expected_seq = seq.checked_add(1);
        result.chain_entries += 1;
        // #177 B3: `event.chain_version` is `Some` here — the `None`
        // (legacy) case already `continue`d above, and `compute_entry_hash`
        // (via `recomputed` above) already rejected any value outside
        // `SUPPORTED_CHAIN_VERSIONS`. A prune point is counted under its
        // own declared version, same as any other entry.
        //
        // Security review (#177 B3): this `match` is a FOURTH place that
        // must stay in sync with `SUPPORTED_CHAIN_VERSIONS` and
        // `compute_entry_hash`'s dispatch (chain.rs's doc comment on
        // `SUPPORTED_CHAIN_VERSIONS` names the other three) — and, unlike
        // those, a future version added to `compute_entry_hash` without a
        // matching arm added *here* would reach this point having already
        // verified successfully (`Hash(_)`, `recomputed == recorded_hash`
        // above), so panicking now would crash `omamori audit verify` on
        // an entry that just proved itself authentic. Deliberately no
        // panic: an unrecognized-but-successfully-hashed version is simply
        // left out of the v1/v2 breakdown (a display nicety) rather than
        // taking down verification of a chain that's otherwise intact.
        match event.chain_version {
            Some(1) => result.v1_entries += 1,
            Some(2) => result.v2_entries += 1,
            _ => {}
        }
    }

    // HWM check: detect tail truncation.
    //
    // #470: this whole block used to be gated on `!halted()` as well. The
    // reason behind that gate is real and still holds for half of it — a run
    // that stopped early cannot say where the chain ends, so writing the mark
    // from it silently lowers it and disables truncation detection from then
    // on, with no error and no failing test. But the gate applied that reason
    // to the *comparison* too, and the comparison needs no key. That made a
    // two-step attack free: edit one entry's `key_id` so verification halts,
    // then delete as much of the tail as you like. Measured on a release build
    // before this change — exit 2, "cannot verify from entry #1", and not one
    // word about the removal; deleting the same lines without the halt
    // reported exit 3.
    //
    // The two halves are now split by what each can honestly use:
    //
    // * The **comparison** uses the last `seq` *stated* by a line at or after
    //   the halt — the halting line itself, then anything past it. It is not
    //   authenticated, so an attacker who renumbers the line the file ends on
    //   can still hide the removal; that is strictly narrower than before,
    //   where changing one character was enough.
    // * The **write** still comes from `last_verified_seq`, and still only
    //   when nothing halted. #177 B1's judgement there is unchanged: an
    //   unauthenticated end must never become the mark, because the mark is
    //   what every later run compares against.
    //
    // When nothing at or after the halt states a `seq` — a future format that
    // renamed the field, say — there is no end to compare and the comparison
    // is skipped, exactly as before. Substituting `last_verified_seq` there
    // would compare the mark against the halt point instead of the file, which
    // is the "compare against a false end" failure the old gate prevented.
    //
    // `broken_at` keeps its own gate: it `break`s out of the loop, so any end
    // taken here would sit at the break rather than at the end of file, and
    // exit 1 is already the strongest thing this command can say.
    //
    // #456: the mark comes from the last seq actually verified, not from
    // `expected_seq - 1`. That derivation needed a `saturating_sub` to be safe
    // and reported `u64::MAX - 1` after verifying an entry numbered
    // `u64::MAX` — one short, which reads as tail truncation against a mark
    // that is correct.
    let structural_end = if result.halted() {
        last_structural_seq
    } else {
        // #483 (review): `last_walked_seq`, not `last_verified_seq`. The two are
        // the same number unless an unprotected entry was walked past, and where
        // they differ the mark has already moved with that entry's append —
        // comparing it against the last *authenticated* seq reported a deleted
        // tail on a whole log.
        last_walked_seq
    };
    if result.broken_at.is_none()
        && let Some(structural_end) = structural_end
    {
        let hwm_file = hwm_path_for(&path);
        // The only end this run is entitled to record. `None` while halted,
        // and `None` when nothing verified — both mean "do not touch the
        // mark", which is why the two arms below check it rather than the
        // counter.
        // #483 (review): `walked_past_unauthenticated`, not `halted`. An
        // unprotected entry does not halt, but a mark written from a run that
        // walked past one would still be an end this run could not authenticate
        // — and a mark is what every later run compares against.
        let writable_end = if result.walked_past_unauthenticated() {
            None
        } else {
            last_verified_seq
        };
        match read_hwm(&hwm_file) {
            HwmState::Valid(hwm) => {
                // #506: the two `Valid` arms were spelled as a guarded pair, and
                // both of them — and only them — are a comparison having
                // happened. `audit verify` tells the operator that "the chain
                // does reach the high-water-mark", which is a claim about a
                // comparison, so the fact that one ran has to be recorded
                // rather than inferred from two flags being unset.
                result.hwm_compared = true;
                if structural_end < hwm {
                    result.tail_truncated = true;
                }
            }
            HwmState::Missing => {
                // Bootstrap: first verify on a chain without HWM
                result.hwm_missing = true;
                if let Some(end) = writable_end {
                    let _ = write_hwm(&hwm_file, end);
                }
            }
            HwmState::Tampered => {
                // The HWM itself is unreadable or symlinked — this is tamper
                // evidence, not a fresh install. Surface it distinctly instead
                // of silently re-bootstrapping as if nothing happened.
                //
                // #470: reported during a halt too. That the sidecar is
                // unreadable is a fact about the sidecar, true or false
                // independently of whether the log could be authenticated, and
                // suppressing it handed an attacker a second thing one edited
                // `key_id` bought for free. Only the re-bootstrap is withheld —
                // so the operator-facing message must not claim the mark was
                // reset when it was not.
                result.hwm_tampered = true;
                if let Some(end) = writable_end {
                    let _ = write_hwm(&hwm_file, end);
                }
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// show_entries
// ---------------------------------------------------------------------------

pub fn show_entries(
    config: &AuditConfig,
    opts: &ShowOptions,
    out: &mut impl Write,
) -> Result<(), AuditError> {
    use std::collections::VecDeque;

    let path = resolved_audit_path(config).ok_or(AuditError::FileNotFound)?;
    let file = open_read_nofollow(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => AuditError::FileNotFound,
        _ => AuditError::Io(e),
    })?;

    let reader = std::io::BufReader::new(&file);
    let capacity = opts.last.unwrap_or(usize::MAX);
    let mut entries: VecDeque<AuditEvent> = VecDeque::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(ref filter) = opts.rule {
            match &event.rule_id {
                Some(rule) if rule.contains(filter.as_str()) => {}
                _ => continue,
            }
        }
        if opts
            .provider
            .as_ref()
            .is_some_and(|f| !event.provider.contains(f.as_str()))
        {
            continue;
        }
        // PR6 (#182): action is an exact-match filter (not substring)
        // because action labels are a small closed enum; substring
        // would let `--action allow` match the `unknown_tool_fail_open`
        // result label and confuse users.
        if opts.action.as_ref().is_some_and(|f| event.action != *f) {
            continue;
        }
        // PR1d (v0.10.3+, #240): only entries whose `detection_layer`
        // starts with `"layer2:relaxed:"` (DI-16). Surface for
        // forensically reviewing which commands the data-context
        // residual backstop allowed.
        if opts.relaxed_only
            && !event
                .detection_layer
                .as_ref()
                .is_some_and(|s| s.starts_with("layer2:relaxed:"))
        {
            continue;
        }

        entries.push_back(event);
        if entries.len() > capacity {
            entries.pop_front();
        }
    }

    if entries.is_empty() {
        return Ok(());
    }

    if opts.json {
        for event in &entries {
            serde_json::to_writer(&mut *out, event).map_err(std::io::Error::from)?;
            writeln!(out)?;
        }
    } else {
        // COMMAND and ACTION columns were widened in v0.9.7 (#190 B-2).
        // PR6 reused the COMMAND column to carry `tool_name` (e.g. `NotebookEdit`,
        // `FuturePlanWriter`) and the ACTION column to carry `unknown_tool_fail_open`
        // (22 chars), both of which overflowed the original `{:<8}` / `{:<15}` widths
        // and pushed every later column out of alignment. v0.9.7 deny-path additions
        // (#181) similarly carry `block` plus `detection_layer` strings such as
        // `layer2:pipe-to-shell:env`. Widening to 24 / 24 keeps a single shared
        // format function across event classes; a per-class formatter remains an
        // option if a future event class outgrows 24.
        writeln!(
            out,
            "{:<20} {:<12} {:<24} {:<24} {:<8} RULE",
            "TIMESTAMP", "PROVIDER", "COMMAND", "ACTION", "RESULT"
        )?;
        for event in &entries {
            if is_prune_point(event) {
                let ts = display_timestamp(&event.timestamp);
                writeln!(
                    out,
                    "--- pruned {} entries before {ts} ---",
                    event.target_count
                )?;
                continue;
            }
            let rule = event.rule_id.as_deref().unwrap_or("\u{2014}");
            let ts = display_timestamp(&event.timestamp);
            writeln!(
                out,
                "{:<20} {:<12} {:<24} {:<24} {:<8} {rule}",
                ts, event.provider, event.command, event.action, event.result
            )?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// audit_summary
// ---------------------------------------------------------------------------

pub fn audit_summary(config: &AuditConfig) -> AuditSummary {
    if !config.enabled {
        return AuditSummary {
            enabled: false,
            logger_available: false,
            entry_count: 0,
            secret_available: false,
            unprotected_reason: None,
            retention_days: 0,
            path_error: None,
        };
    }

    let Some(path) = resolved_audit_path(config) else {
        return AuditSummary {
            enabled: true,
            // #492: the other state `AuditLogger::from_config` returns `None`
            // for. `enabled` is `true` here, so a caller reading only that flag
            // concludes appends are happening when no log location exists.
            logger_available: false,
            entry_count: 0,
            secret_available: false,
            unprotected_reason: None,
            retention_days: config.retention_days,
            path_error: Some(
                "HOME is unset, empty, or relative — cannot resolve audit path".to_string(),
            ),
        };
    };
    // #471: the writer's own question, asked the writer's way. `read_secret`
    // alone opens by name and so needs only search permission on the directory;
    // `key_store_outlook` needs to list it, which is the observation the writer
    // refuses on. At mode 0300 the two disagree, and the writer is the one that
    // decides whether the entry carries an HMAC.
    //
    // No key-store lock is taken here, deliberately. `status` reports an
    // observation, not an atomic one: a rotation running concurrently can make
    // this stale between the read and the print. The invariant this restores is
    // **which question is asked**, not that the answer is simultaneous with the
    // writer's — and taking the lock in a status command would let an unrelated
    // writer block it.
    let secret_path = secret_path_for(&path);
    let unprotected_reason = match key_store_outlook(&secret_path) {
        KeyStoreOutlook::Unprotected(reason) => Some(reason),
        // The one observation past the shared predicate, made the same way the
        // writer makes it. What neither can see is a mint that is attempted and
        // fails; that outcome exists only inside `load_signing_key_locked`, and
        // reaching it from here would mean creating a key file as a side effect
        // of asking for status.
        KeyStoreOutlook::Usable { .. } => read_secret(&secret_path).err().map(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                UnprotectedReason::ActiveKeyMissing
            } else {
                UnprotectedReason::ActiveKeyUnusable(e.to_string())
            }
        }),
    };
    let secret_available = unprotected_reason.is_none();

    let (entry_count, path_error) = match open_read_nofollow(&path) {
        Ok(f) => {
            let count = std::io::BufReader::new(f)
                .lines()
                .filter(|l| l.as_ref().is_ok_and(|s| !s.trim().is_empty()))
                .count() as u64;
            (count, None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, None),
        // #492: sanitized here rather than at each display site. Every message
        // this arm can produce ends with the audit path, and an **absolute**
        // `audit.path` reaches this point verbatim — `AuditConfig::validate`
        // strips control characters only on the relative branch, where it
        // rejects the override anyway. So `config.toml`, which that same
        // function's comment calls attacker-controlled, can put ESC sequences
        // into a string that `status` prints and that `break-glass` now prints
        // two lines above its consent prompt. Cursor-up plus erase-line is
        // enough to overwrite the warning the operator is answering.
        //
        // Same treatment `provenance::sanitize` gives `parent_process`, minus
        // its length cap — that cap sizes a field written into every audit
        // entry, and truncating a filesystem error would cut the path the
        // operator needs.
        Err(e) => (0, Some(super::strip_control_chars(&e.to_string()))),
    };

    AuditSummary {
        enabled: true,
        // Reached only past the two early returns above, which are exactly the
        // two states `AuditLogger::from_config` refuses on.
        logger_available: true,
        entry_count,
        secret_available,
        unprotected_reason,
        retention_days: config.retention_days,
        path_error,
    }
}

// ---------------------------------------------------------------------------
// PR6 (#182): unknown-tool fail-open observability
// ---------------------------------------------------------------------------

/// Count `unknown_tool_fail_open` audit events whose timestamp falls
/// within the last `days` days. Used by `omamori doctor` to surface
/// silent forward-compat fail-opens that drifted past structure-based
/// routing.
///
/// Returns 0 on any read/parse failure — this is a UX surface, not a
/// security gate, and doctor must never error out a healthy install
/// because the audit log happened to be unreadable.
pub fn count_unknown_tool_fail_opens_within(config: &AuditConfig, days: u32) -> u64 {
    if !config.enabled {
        return 0;
    }
    let Some(path) = resolved_audit_path(config) else {
        return 0;
    };
    let file = match open_read_nofollow(&path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(days));

    let reader = std::io::BufReader::new(file);
    let mut count: u64 = 0;
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if event.action != "unknown_tool_fail_open" {
            continue;
        }
        let ts = match OffsetDateTime::parse(&event.timestamp, &Rfc3339) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ts >= cutoff {
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn display_timestamp(ts: &str) -> String {
    // "2026-04-04T03:31:02.54814Z" → "2026-04-04T03:31:02Z"
    match ts.find('.') {
        Some(dot) => format!("{}Z", &ts[..dot]),
        None => ts.to_string(),
    }
}
