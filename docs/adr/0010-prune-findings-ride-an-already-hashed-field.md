# ADR-0010: A prune's findings ride an already-hashed field, not a new one

- **Status**: Accepted
- **Date**: 2026-08-16
- **Plan**: `.claude/plans/2026-08-16-omamori-461-prune-unverifiable-trace.md`

## Context

Issue #461's second half: a prune that removes a range containing entries `verify_chain` could
not check leaves no record that it did. `prune_point` carries an entry count and nothing about
what those entries were, so a store reporting exit 4 before the prune reports exit 0 after it —
the log's own history of having held something unverifiable is gone, and the tool whose whole
claim is "you cannot quietly remove evidence" removed some.

The first half of #461 closed in #505 (the post-prune high-water-mark no longer follows an
unauthenticated `seq`). That PR left this half open with a stated reason: recording it "needs a
field `AuditEvent` does not have, which makes it a `chain_version` question." Two shapes were
also rejected there and recorded so they would not be re-proposed — refusing to prune past an
unverifiable entry (one planted line then stops retention forever, and the log grows without
bound), and reusing `target_count` or `target_hash` (both already mean something specific on a
prune point, and SECURITY.md's forensic semantics depend on those meanings).

That left an apparent dead end: any new field is hash-coverage surface, hash-coverage surface is
`chain_version`, and a prune point is the **first line of the file**, so a prune point declaring
a `chain_version` no existing release recognises makes every existing release report exit 4 at
line 1 with `chain_entries = 0` — unable to verify a single line of a log it could fully verify
the day before.

## Decision

**Record the findings in `rule_id`, an existing field already inside both hash preimages, and do
not add a `chain_version`.**

The counts are written as `pruned:unverifiable=2;broken=1` — a prefixed, `key=value` list —
and are absent entirely (`rule_id: null`) when a prune finds nothing.

Three properties made `rule_id` the field, and each was checked against the source rather than
assumed:

1. **It is already hashed.** `rule_id` is a member of `HashableEvent` (V1 preimage) and
   `HashableEventV2` alike, and `from_event` copies the entry's own value into it. So the value
   is covered by `entry_hash`: editing the count without the key breaks the prune point's own
   hash, and `audit verify` reports exit 1.
2. **A prune point's `rule_id` has no consumer — after one exclusion this change had to add.**
   `report`'s `by_rule` tally runs inside `event.action == "block"`, and a prune point's action
   is `retention`, so that surface was already safe. `show` was **not**: its `--rule` filter is a
   substring match over `rule_id` and runs before the table decides to draw a prune point as a
   `--- pruned N entries ---` separator, so `--rule pruned --json` emitted the prune point as an
   object. The filter had been correct only because the field was always `None` on a prune point
   — a property that stops holding the moment it carries something — so it now excludes prune
   points explicitly (review caught this; the first draft of this ADR asserted the filter "cannot
   surface one", and it could). The field carries no `skip_serializing_if`, so it already
   serialises as `"rule_id": null` on every line — the JSON shape does not move.
3. **It is not already carrying something else on this entry**, which is the precise reason
   #505 rejected `target_count` and `target_hash`. That objection does not transfer here.

The premise this decision corrects is worth stating, because it is what made the dead end look
real: `entry_hash` is recomputed from the entry as it sits on disk, so **putting a value in a
field the preimage already contains does not break verification** — the writer and the reader
build the same preimage. Only changing the preimage's *shape* (adding a field, reordering one)
breaks it. #505's note, and the SECURITY.md paragraph derived from it, conflated the two.

## Why not a new field plus `CHAIN_VERSION` 3

Adding `pruned_unverifiable` to `AuditEvent` and to a new `HashableEventV3` is the shape that
looks principled — a dedicated field says what it means, and `chain_version` is exactly the
mechanism for evolving the schema. It was rejected on its cost, not its design:

- **A prune point is the head of the file.** ADR-0007 fixes that pruning copies retained entries
  verbatim and rewrites only file layout; the prune point it writes stands in front of them
  permanently. An older binary hits an unrecognised version on line 1, `mark_unverifiable_tail`
  fires, and every remaining line lands in `unverified_entries_after`. The honest message it
  prints — "this build does not recognise the format, upgrade" — is honest about *nothing else*:
  the run verified zero entries.
- **The gap being closed is smaller than the gap being opened.** #461's defect makes a specific
  historical fact disappear. Requiring a binary upgrade before a pruned log can be verified at
  all makes every fact about it unavailable until then.
- **ADR-0007's Consequences already state the ratchet**: each bump adds one more permanently
  frozen historical shape. Spending one on a single `Option<u64>` that is meaningful on one entry
  type sets the exchange rate badly for the next forensic counter, which would need v4.

A narrower variant — bump only the prune point, keeping `CHAIN_VERSION` at 2 — was also
considered and rejected: it splits the constant that four separate sites must already be kept in
step with (`chain.rs`'s own doc enumerates them), and buys nothing `rule_id` does not.

## Alternatives considered

| Option | Rejected because |
|---|---|
| New field + `CHAIN_VERSION` 3 (all entries) | Above. Every existing release loses the ability to verify any line of a pruned log. |
| New field + a prune-point-only version constant | Same cost at the head of the file, plus a fifth site to keep in step with the version dispatch. |
| Widen `target_hash`'s prune-bind preimage to cover the counts | The counts must be *readable*, and an HMAC is not; a plaintext field is needed regardless. Changing the preimage would then also make every older binary report `broken_at` on the prune point — a false accusation of tampering, the failure #457 spent a release correcting. |
| Change `result` from `pruned` to a second value | `is_prune_point` matches on all three of `command`/`action`/`result`, so an older binary stops recognising the entry as a prune point, compares its `prev_hash` against the ordinary genesis anchor, and reports `broken_at`. Same false accusation. |
| `target_count` / `target_hash` | Rejected in #505; both carry documented forensic meaning. |
| Refuse to prune past an unverifiable entry | Rejected in #505; one planted line halts retention permanently. |
| Record it in a sidecar | The `.hwm` sidecar is already documented as unauthenticated plaintext; a second one would hold tamper-evidence with no tamper-evidence. |

## Consequences

- **`rule_id` now has two meanings, discriminated by entry type.** On a block entry it names the
  rule that fired; on a prune point it carries a `pruned:`-prefixed findings record. The prefix
  is what keeps them apart, and `decode_findings` returns `None` for any value lacking it, so an
  ordinary rule id can never be read as a record. The reverse direction needed code, not just a
  prefix: any surface that filters or groups by `rule_id` must exclude prune points, which
  `show --rule` now does. A future surface that reads the field is inheriting this obligation.
- **A record this build cannot parse is reported, not skipped.** An unknown key inside a
  well-formed record yields `record_unreadable`, and `try_prune` turns an unreadable prior record
  into `prior_lost`. A future omamori that adds a counter will therefore be told about, rather
  than silently ignored by, an older reader — the reverse of the trap #177 B1 exists to close.
- **The counts are not the verdict `verify_chain` reaches**, and SECURITY.md says so: they are
  taken with no key from the removed range alone, `legacy_splice`/`broken` are 0-or-1 because the
  verifier fails closed on either, and an entry whose HMAC merely fails to match is not counted
  at all. A future change that makes the scan re-derive the verifier's walk should expect to be
  asked why the two are not one function instead.
- **A prune that finds nothing writes what the previous release wrote.** `rule_id` stays `null`,
  so no existing log changes shape and no existing binary sees anything new — which is what makes
  this decision reversible in practice: a later release could stop writing the record without
  stranding anything.
