# ADR-0007: Existing `audit.jsonl` entries are never rewritten in place

- **Status**: Accepted
- **Date**: 2026-07-26
- **Plan**: `.claude/plans/2026-07-25-omamori-pre-1.0-breaking-batch.md`

## Context

Issue #177's `CHAIN_VERSION` 1→2 flip (ADR-0006) means a log written before the upgrade has
`chain_version: 1` entries whose `pid`/`ppid`/`parent_process`/`cwd_hash`/`wrapper_kind` values
are permanently outside `entry_hash`'s HMAC protection (Design A), while entries written after
the upgrade have `chain_version: 2` and *do* get that protection. This is a real, visible gap
between what an old and a new entry in the same file guarantee.

The obvious-looking way to close that gap for existing entries would be a one-time migration
that reads every `chain_version: 1` entry, recomputes it as if it had always been `chain_version:
2` (with the newly-hashed fields carrying whatever value they happen to hold — `None` in most
cases, since v1 entries never had a slot to record them), and rewrites `audit.jsonl` in place with
the upgraded shape and a freshly-computed `entry_hash` for every line.

## Decision

**Never do this. No code path retroactively re-hashes or rewrites an existing entry's
`chain_version`, `entry_hash`, or any other field.** Upgrading only affects what gets written
*from that point forward* — the file before the upgrade instant and after it are the
concatenation of two regions whose entry content never changes, never a single region
reprocessed into a new shape.

**Carve-out (Security review, #177 B3): this is not a claim that `audit.jsonl` is literally
append-only at the file-descriptor level.** `retention::try_prune_at` already performs an
in-place file rewrite — `seek(0)` + `write_all` + `set_len` (`src/audit/retention.rs:110`,
documented as a deliberate design choice at SECURITY.md's "Design decision: In-place rewrite"
paragraph) — to drop aged-out entries below a `prune_point` anchor. What this ADR actually
guarantees is narrower and is the part that matters for the trap above: pruning **copies
retained entries verbatim**, byte-for-byte, into the rewritten file — it never recomputes an
`entry_hash`, reassigns a `chain_version`, or otherwise alters the *content* of an entry that
survives the prune. A `CHAIN_VERSION` migration that reprocessed every retained entry into a new
shape (the trap this ADR forbids) is categorically different from prune's file-level truncation,
which touches file layout, not entry content.

This was never seriously considered as an alternative in ADR-0006 and is recorded here, in its own
ADR, specifically because it is the kind of "obviously helpful" idea a well-intentioned future
change could reintroduce without realizing it defeats the product's core guarantee — the same
failure mode a positive-only design note (buried in prose elsewhere) is easy to miss.

## Why this is a trap, not a missed opportunity

`entry_hash` is a tamper-evidence mechanism: it lets `omamori audit verify` prove that what is on
disk today is exactly what omamori wrote at the time, with no code path — not even omamori's own
— able to alter it afterward without detection. A migration that rewrites `entry_hash` for
existing entries is, from the hash chain's own perspective, indistinguishable from an attacker's
tamper: both replace a recorded hash with a freshly-computed one over changed content. Doing this
"for a good reason" (closing the provenance-protection gap) does not change what the chain
mechanically proves — it proves that the *ability* to replace historical hashes exists in the
binary at all, which is the one thing the entire audit-chain design exists to rule out.

Concretely, an in-place rewrite would:

- **Destroy the exact byte-for-byte record an incident investigation depends on.** If a real
  incident occurred using the old shape, the migration overwrites the only copy of what was
  actually recorded at the time, replacing it with a reconstruction.
- **Require holding the HMAC secret at migration time**, for every historical entry, which is a
  strictly larger secret-exposure surface than the running append-only path (which only ever
  needs the *current* secret for the *next* entry) — every past secret and key rotation the chain
  ever spanned would need to be re-derivable and re-appliable in one pass.
- **Make "was this file ever rewritten" itself unanswerable.** Once in-place rewriting is a
  legitimate omamori operation, an investigator can no longer treat "every byte matches what
  `omamori audit verify` has always confirmed" as ground truth — the ground truth becomes "every
  byte matches what the *last* migration produced," which is a materially weaker claim.
- **Not actually close the gap it claims to.** A `pid`/`ppid`/etc. value re-hashed today still
  only proves "this is what the field held at migration time," not "this is what was true when
  the command that generated the entry originally ran" — the provenance data itself was never
  captured for pre-upgrade entries (see ADR-0006's Consequences), so there is nothing genuine to
  re-hash. The migration would be computing a real HMAC over a value that was never actually
  collected — `None` in the common case — manufacturing the *appearance* of protection without
  the substance.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Full in-place rewrite (recompute every v1 entry as v2) | See "Why this is a trap" above — defeats the tamper-evidence guarantee itself. |
| Partial rewrite (only re-hash entries that have real provenance data, e.g. `E-V1-prov` shape from #177 B3's shape enumeration) | Same objection at smaller scale — still replaces a historical `entry_hash` with a freshly-computed one, still requires the same-era secret, still makes "was this ever rewritten" unanswerable for the subset that was touched. Partial rewrite is not a smaller version of the trap; it is the same trap with better PR. |
| Sidecar "upgraded copy" of the log, original left untouched | Two files instead of one defeats the audit log's own success criterion (a single `audit.jsonl` an investigator can grep); the sidecar's protection is also fake for the same "nothing was actually collected" reason above. |

## Decision this legitimizes elsewhere

Per-entry, stateless `chain_version` dispatch (ADR-0006's update, #177 B1's `SUPPORTED_CHAIN_VERSIONS`
mechanism) is the *only* way #177's migration works without this trap: `compute_entry_hash` (and,
through it, `verify_chain`) recomputes a hash appropriate to *each entry's own declared version*,
on demand, forever, using the version-appropriate canonical struct (`HashableEvent` or
`HashableEventV2`) — never a one-time pass over the file, because there is no "upgraded" state for
the file to reach. `read_chain_state` (the append-side tail check) makes the complementary
decision without recomputing anything itself: it peeks the tail entry's declared `chain_version`
and accepts appending after it as long as that version is in `SUPPORTED_CHAIN_VERSIONS`, whatever
it is — the new entry gets hashed by `compute_entry_hash` at write time using the *current*
`CHAIN_VERSION`, chained onto whatever hash the tail already recorded. A mixed `chain_version: 1`
/ `chain_version: 2` file is not a transitional state that migration eventually resolves; it is
the **permanent, expected shape** of any log that existed before the upgrade instant.

## Consequences

- Every `chain_version: 1` entry's `pid`/`ppid`/`parent_process`/`cwd_hash`/`wrapper_kind` values
  remain outside HMAC protection **forever**, not just until some future migration runs. There is
  no future version of omamori that will close this gap for entries already on disk — only new
  entries, written after any given upgrade, get the protection available at write time.
- An investigator working a log that spans the v1→v2 boundary must treat `chain_version` as the
  signal for how much to trust an entry's provenance/`wrapper_kind` fields against tampering,
  entry by entry, for the life of that log file.
- Any future `CHAIN_VERSION` bump (3, 4, ...) inherits this same permanent split for entries
  written under every earlier version — the gap does not shrink over time by itself; it only
  grows to include one more permanently-frozen historical shape per bump.
