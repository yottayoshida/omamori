# ADR-0008: Key resolution semantics for audit-chain verification

- **Status**: Accepted
- **Date**: 2026-07-30
- **Plan**: `.claude/plans/2026-07-30-omamori-457-key-rotation-verify.md`
- **Issue**: [#457](https://github.com/yottayoshida/omamori/issues/457)

## Context

`omamori audit key rotate` shipped in v0.8.0 (2026-04-11) alongside a changelog line reading
"Multi-key verification in `verify_chain()` — old entries verify against retired key". That
sentence was never true. Running the command once made `omamori audit verify` return exit 1
`chain broken at entry #0` from then on, with no way back: `ADR-0007` forbids rewriting existing
entries, no `unrotate` exists, and `docs/FAQ.md` has no entry for a broken chain. The only remedy
a user can reach on their own is deleting `audit.jsonl` — destroying the very record the tool
exists to protect.

The multi-key design itself was already in the codebase and already correct in places:
`verify_chain` resolved each entry's HMAC key through `keyring.get(entry.key_id)`, and
`provenance::hash_cwd_candidates` tried every key in the ring. What was missing was consistency.
Three values were still computed from whichever key happened to be active at verification time,
regardless of which key had actually produced them:

| Value | Written with | Verified with (before this ADR) |
|---|---|---|
| `genesis_hash` anchor of the first chain entry | the key active when the chain started | the key active *now* |
| `prune_genesis_hash` anchor of a prune point | the key active when the prune ran | the key active *now* |
| `prune-bind` `target_hash` | the key active when the prune ran | the key of the *first retained entry* |

Separately, `build_prune_point` stamped `key_id: "default"` unconditionally while signing with the
active secret, and `AuditLogger::from_config` resolved the secret and the `key_id` through two
independent directory reads. Every one of these is the same shape: **a value signed with one key
while labelled as, or checked against, another.**

## Decision

### 1. A value is verified with the key it names

`genesis_hash` and `prune_genesis_hash` are computed from the key named by the entry being
anchored, not from the active secret. `prune-bind` is recomputed with the key that authenticated
the prune point, carried forward alongside the target hash and count. Writers take a `SigningKey`
— one value holding both the bytes and the `key_id` — so a call site cannot name a key it did not
sign with.

### 2. `"default"` is an alias for epoch 1, not a wildcard

`"default"` names the first key a store ever had. Before any rotation that is the active key;
afterwards it is `audit-secret.1.retired`. Both registrations point at the same bytes. This was
already true in the code and is now stated explicitly, because a plausible-looking "fix" is to
renumber `"default"` to `"key-1"` — which would break unrotated stores, where `"key-1"` is not in
the ring at all.

### 3. A key we do not hold is *cannot verify*, not *tampered*

`keyring.get(id).unwrap_or(&active)` is removed. An entry naming an absent key stops verification
with exit **2** (cannot verify), the code already used for "secret unavailable / file missing /
legacy-only". Not exit 1: the entry may be entirely authentic and merely uncheckable, and
accusing an operator of tampering because a key file was renamed is a false alarm in the
strongest wording the product has. Not exit 4 either: that code's message tells the reader to
upgrade omamori, which does nothing for a missing key.

This also closes a **false negative**. The old fallback checked such an entry against the active
key; when that happened to be the signing key — the common case, since a stray
`audit-secret.bak.retired` shifted every new entry's label without changing which key signed them
— the entry passed and the verifier reported "chain intact" about an entry it had not
authenticated under the key the entry named. Measured against v0.16.0: exit 0.

### 4. Key epochs are derived from the highest index present, and the directory is enumerated

Retired keys are found by reading the directory once and parsing `audit-secret.{N}.retired` as a
canonical decimal. Non-numeric suffixes are ignored rather than counted; the next epoch is
`highest + 1` rather than `count + 1`; gaps do not hide the keys beyond them.

Building a path and opening it was independently unsafe: on a case-insensitive filesystem (APFS
default) `open("audit-secret.1.retired")` succeeds for a file named `audit-secret.1.RETIRED`,
which a literal name-match count never saw. One such file made a never-rotated host report
`chain broken at #0`.

### 5. The verifier does not search for a key the entry did not name

When an entry's declared key fails to authenticate it, verification stops. It does **not** try the
rest of the ring looking for a key that works.

Trying would recover some already-damaged logs — prune points written by the pre-fix writer, which
name `"default"` but were signed with the active key. It was rejected anyway, for a reason
unrelated to whether it works: it would make the verifier absorb the exact class of bug this
change exists to remove. A future writer that labelled entries wrongly would produce logs that
still verify, and nothing would report the drift. Verification would repair the symptom and
destroy the signal.

The population able to benefit is small by construction: it requires `[audit] retention_days > 0`
(default 0, absent from `config init`'s template) **and** a completed rotation **and** at least
1000 retained entries. If such a log ever turns up, the answer is an explicit repair command with
its own name and its own confirmation — not a verifier that quietly accepts mislabelled data.

### 6. What the verifier may *say* about a key it cannot resolve

§3 decides the classification. It does not license an explanation. `key_id` is an ordinary field of
`audit.jsonl`, so an entry naming an absent key is reached by two very different routes: a key file
that was renamed or deleted, and someone editing one string. Editing costs an attacker nothing —
no key material, no re-signing — so the first version of this change handed them something for
free: exit 1 `chain broken … The audit log may have been tampered with.` became exit 2 `… **This
is not evidence of tampering.** The key file for "key-99" is missing, renamed, or unreadable`
(measured against v0.16.0 on identical fixtures). omamori vouched for the log on the strength of a
field the attacker wrote.

The classification stands — an unresolvable entry genuinely cannot be checked, and calling that
tampering is the false accusation this ADR exists to remove. What the verifier may assert is
narrowed to what it can substantiate:

| Observation | What may be said |
|---|---|
| The id is the reserved `unresolved` | omamori wrote this itself with no key. Nothing is missing; restoring a file will not help |
| The id is of a shape no writer emits (`key-1`, `key-02`, `KEY-2`, anything non-decimal) | A missing key file does not explain it. The field has been altered |
| A well-formed epoch, within the epochs this store shows | The key file is the likely cause — name it — **and** an edit produces the same state |
| A well-formed epoch above them | No key file for that epoch is here to have gone missing. Either the field was altered or retired keys were deleted; nothing on disk distinguishes them |

The last row is stated as an observation, not a verdict, because deleting retired key files lowers
the observed maximum too — the same gap that makes deleting the last retired key read as tampering.
An accusation resting on it would be wrong for an operator who tidied their key directory.

Exit 2 also states that tail-truncation detection is suspended, which exit 4 already said for the
same reason. Omitting it made exit 2 the quieter of the two ways to reach a halt, and reaching it
is cheaper: forging a `chain_version` versus editing one label.

### 7. The accepted set widens by one entry, and that is deliberate

Deciding §1 has a cost. Before it, the head entry's anchor was computed from the active key, which
meant an attacker holding only a *retired* key could not forge a chain head — the forged anchor
would not match. After it, the head is anchored with whatever key it names, so such a forgery is
accepted.

This is accepted, for three reasons:

- The protection was **incidental, not designed**. Nothing in `SECURITY.md` or `docs/CONTRACT.md`
  claims it; it fell out of an implementation detail that this ADR is correcting.
- It covers **one entry**. `verify_chain` performs no monotonicity check on key epochs, so an
  attacker holding a retired key can already forge any *non-head* entry by naming that key
  (`SECURITY.md`, "Key rotation" section). The head was the sole exception.
- **There is no version of the fix that keeps it.** Verifying a rotation-spanning chain requires
  anchoring on the key the chain started with, and a forger can name that key too.

`prune_point_written_after_rotation_verifies` and the tests around it pin the intended behaviour;
a test also pins the widened acceptance itself, so that a later change cannot narrow or widen it
silently. Making rotation provide real forward security requires per-entry epoch monotonicity —
tracked separately, out of scope here.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| **Append a rotation marker to the chain and re-anchor there** | Does not address the prune-point defects at all, cannot help any log already written, and couples key management to log state — `rotate_key` would begin failing when the log's tail carries an unrecognized `chain_version`, and a crash between rename and append would leave the key rotated with no record of it. **What is rejected here is the *re-anchoring*, not the record.** A rotation event that `verify` does not special-case — no re-anchoring, no epoch inferred from it, no key-resolution decision consulting it, just an ordinary entry authenticated against the key its own `key_id` names — carries none of these costs, and was added separately (#457 PR2, see `SECURITY.md`'s "Key rotation events"). The last clause above still holds of it: a crash between the rename and the append leaves the rotation unrecorded, and the event is not evidence that no rotation occurred. |
| **Re-sign existing entries under the current key** | Forbidden by `ADR-0007` §"Never do this". Also self-defeating: re-signing requires holding every retired key, while the reason to rotate is that an old key may be compromised. |
| **Make `genesis_hash` key-independent** | Every existing chain head would stop matching — precisely the breaking change `docs/CONTRACT.md`'s audit-chain row exists to prevent. Gating it behind a new `chain_version` would mean a third format one release after the second. |
| **Renumber `"default"` to `"key-1"`** | Unrotated stores have no `"key-1"` in the ring, so every entry would fall through to an implicit fallback — replacing explicit resolution with the very thing §3 removes. |
| **Search the keyring on authentication failure (§5)** | See §5. |
| **Reorder rotation to temp-create → rename → rename** (create `audit-secret.pending`, rename the active key to `.N.retired`, then rename `.pending` into place) | **Not rejected — deferred, and cheaper than the option this ADR does defer.** It closes the interrupted-rotation window without adding any on-disk *format* element: the extra name is transient, does not end in `.retired`, and `write_hwm` already uses the same temp-plus-atomic-rename pattern. It is out of this change's scope only because rotation ordering is not what #457 is about. Recorded here so the next person to look at the interrupted-rotation residual sees three options rather than two. |

## Consequences

- A chain that spans one or more rotations verifies, with no file rewriting: the values on disk
  were always correct, only the verifier's choice of key was wrong.
- Entries written while the key directory could not be enumerated carry a reserved `key_id` that
  no keyring can hold, so they report as *cannot verify* with their real reason. The first version
  labelled them `"default"`, which on a rotated store resolved to `.1.retired` and made them read
  as tampering once permissions were restored — permanently, since ADR-0007 forbids rewriting
  them. Measured against v0.16.0, which wrote a real HMAC in that state and reported `intact`: a
  regression introduced by the fail-closed branch itself, and one its own comment claimed to be
  avoiding.
- No lock omamori takes waits indefinitely. `flock` works on a read-only descriptor, so a blocking
  `LOCK_EX` on a hot-path file let any local process stall every omamori surface — `verify`,
  `doctor`, `report`, every guarded command, and `hook-check` before it printed its deny verdict,
  which hands the outcome to the host's hook-timeout policy. Acquisition is bounded and then
  degrades to unlocked (key store) or reports contention (audit log). Read-side opens carry
  `O_NONBLOCK` for the same reason, and `read_secret` re-checks the file type and bounds the read
  on the opened descriptor: the `stat` pre-check it shipped with is a race, not a control.
- `omamori audit verify` gains no new exit code; exit 2 covers one more situation. `ChainStatus`
  gains a variant and `#[non_exhaustive]`, following the precedent `VerifyResult` set in #177 B3.
- A missing or unreadable key file now stops verification instead of being masked. Stores that
  reported "intact" while carrying entries nobody had actually checked will now say so — visible
  as a behaviour change, though what changed is the honesty of the report, not the data.
- `hash_cwd_candidates` warns when the keyring is truncated or partly unreadable. Silence there
  is a forensic false negative: a shorter candidate list with no sign that the matching key was
  never tried.
- Rotation can no longer overwrite a retired key. The numbering change already makes the next
  slot free; the explicit refusal remains as a backstop.

  **Corrected in #477.** The sentence above originally read "the explicit refusal remains for the
  case where the directory scan itself fails", which was not true of the code it described. The
  refusal is `retired_path.exists()`, so it only fires when the guessed slot is *occupied* — and a
  failed scan guesses slot 1, which on a store missing its low epochs is free. That is exactly the
  case the sentence claimed to cover, and the one where the guess does damage: the current key was
  filed under an epoch that already existed. #477 closes it upstream instead — rotation now refuses
  before any key file is renamed or created when the key directory cannot be listed — so the scan-failure
  case never reaches the slot check at all.
- An interrupted rotation (retired keys present, no active key) is reported when detected, and the
  residual is pinned by a test rather than left to be rediscovered. **#478 amends what "detected"
  means here.** The report is now made after the *attempt* to mint a replacement rather than
  before, and states which of the two outcomes it then observed; the earlier version predicted a
  mint that does not always succeed and offered a recovery step that, once one has, destroys the
  key the newest entries were signed with. The detection condition also narrowed from "the active
  key could not be read" to "there is no `audit-secret`": the wider form fired on stores whose key
  was present and intact behind a directory that merely denied `open`, and the recovery it printed
  would have overwritten that live key. Two ways to close the window properly
  are recorded in Alternatives: reordering rotation so the window does not exist (cheaper, no
  format change), and having each key file record its own epoch (more general, adds an on-disk
  element 1.0 would freeze). Note the asymmetry in that second one: **if 1.0 freezes on-disk
  elements, adding one afterwards is harder, not easier** — so "defer past 1.0" is the wrong frame
  for it. It is deferred because #457 is about key *resolution*, not key *storage*, and the
  reordering option closes the same window without touching storage at all.

**Update (PR-C1, 2026-08-03 — the deferred storage change landed, as neither of the two options
above)**: `audit-secret.epoch` now records **the highest epoch this store has ever handed out**,
as one decimal integer in a file next to the keys. Epochs are read as
`max(recorded, max_retired + 1)`, so a store without the file behaves exactly as before. Three
statements above did not hold; each is corrected here rather than edited away.

1. **"adds an on-disk element 1.0 would freeze" is not a property `docs/CONTRACT.md` has.** The
   breaking-change policy names three frozen surfaces — rule matching, the CLI, and audit-chain
   verification — and the key store's layout is in none of them; the same section puts
   `config.toml`'s format explicitly outside the contract. This cycle also added
   `audit-secret.lock` to that directory without treating it as breaking. The asymmetry argued
   above was right about the direction and wrong about the premise: there was no freeze to get
   ahead of.
2. **The `.pending` reordering does not close the same set.** Its reach is the
   interrupted-rotation window, which the Alternatives row states accurately. What reading it as
   "the cheaper of two equivalent fixes" adds — and the row does not claim — is the
   deleted-retired-key defect, which it cannot touch: the `"default"` alias condition looks at how
   many retired keys are *present*, not at how many epochs happened. `.pending` remains worth
   doing and is scoped as PR-C2; it is not a substitute for the record.
3. **"each key file records its own epoch" is the wrong shape.** What has to be told apart is a
   generation that is *gone*, and a file that is gone carries no tag. Tagging also leaves the mint
   stamping `max + 1`, so the numbering defects survive it. The record works precisely because it
   lives outside the keys: deleting a key lowers `max_retired` and changes nothing the store said.

The form is deliberately neither the key files nor the file *names*. A second line inside
`audit-secret` is rejected by v0.16.0's `hex.len() != 64` check, so every entry written under a
downgraded binary would carry `NO_HMAC_SECRET` beneath a real `key_id` — a permanent exit-1
tampering verdict on re-upgrade, unrepairable under ADR-0007. Encoding the epoch in the file name
hides `audit-secret` from older binaries entirely, and they then mint a second key in silence. A
separate file that older versions never look at is simply ignored by them.

Residual, recorded rather than closed:

- **A record is only as accurate as the listing that produced it.** If retired keys were already
  missing when the first record was written, the number it fixes is the low, derived one.
- **Downgrade is safe in general and conditional in one state.** v0.16.0 ignores the file. But a
  store that skipped an epoch — record above `max_retired + 1`, which happens when a generation is
  lost — mislabels its active key under v0.16.0, and entries written there can read as
  cannot-verify after upgrading again.
- **Deleting the record returns the store to the derivation.** It adds protection; it does not
  enforce it. `PROTECTED_FILE_PATTERNS` matches the `audit-secret` prefix, so this is an
  operator's action and not an agent's.
- **A record that cannot be parsed stops `verify` and refuses `rotate`.** One file can therefore
  halt verification, where a corrupt `.retired` file is only a non-fatal anomaly. That asymmetry
  is the accepted cost of not guessing; the mitigation is entirely in the message, which names the
  file and states that removing it restores the derivation.
- **Durability stops at the directory entry.** `atomic_write_with_mode` checks the temp file's own
  `sync_all` and then asks the parent directory to sync, but that second call's error is swallowed
  (`atomic_file::fsync_parent`, a decision that predates this record and is shared by every caller
  of the helper). A record that returned `Ok` therefore survives a process crash; against power
  loss it survives only as far as the rename reached the disk. Making the parent sync fallible
  would change every `atomic_file` call site and is not part of this change.
- **A store that can record but cannot mint climbs.** The recovery path writes the next epoch
  before creating the key, so if the write keeps succeeding while `create_secret` keeps failing,
  every later command advances the number again. The two failures normally share a cause — an
  unwritable directory denies the record first, and the recovery then does nothing at all — which
  leaves a missing `/dev/urandom` or `EMFILE`. The alternative is minting under a number the
  record does not hold, which is the defect itself; `u32` gives 4.29e9 epochs against 104 for
  weekly rotation over two years.
