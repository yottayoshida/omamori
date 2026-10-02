# ADR-0015: A prune's findings come from the verifier's own walk

- **Status**: Accepted
- **Date**: 2026-10-02
- **Plan**: `.claude/plans/2026-10-02-omamori-539-540-prune-record-from-verifier-walk.md`
- **Supersedes**: two Consequences of [ADR-0010](0010-prune-findings-ride-an-already-hashed-field.md)
  — the third ("the counts are not the verdict `verify_chain` reaches") in full, and of the second
  ("a record this build cannot parse is reported, not skipped") the part that discarded every count
  beside an unknown key. Where the record is stored — `rule_id`, no `chain_version` bump — is
  unchanged.

## Context

ADR-0010 put a prune's findings in the prune point's `rule_id` and produced them with
`scan_pruned_range`: a keyless, single-pass scan written beside `verify_chain` rather than from it.
It said why — reproducing the verifier's walk in `retention.rs` would be a second implementation of
a 1.0-frozen surface — and it said what would follow: "a future change that makes the scan
re-derive the verifier's walk should expect to be asked why the two are not one function instead."

That question has now been asked three times.

- **#556** found the scan and the verifier reading `chain_version` through different parsers, and
  disagreeing in both directions about which lines declare an unrecognized version.
- **#539** lists four more places where the record and the verifier would describe one log
  differently. One was already closed by #556; one is unreachable (a keyring cannot hold a key
  named `unresolved` — `load_keyring_locked` only ever inserts `default` and `key-N`); two are real:
  a scan that stops at an entry naming a missing key leaves an all-zero record, identical to a
  clean range, and `summary()` drops legible counts when a merged record is unreadable.
- **#540** is the one class the scan leaves out on purpose: an entry whose `entry_hash` does not
  match its contents. That is what `audit verify` reports as exit 1, "may have been tampered with",
  and it is the one finding a prune can erase without trace.

Closing #540 inside the scan means recomputing an HMAC per removed line with the key each line
names — which is the verifier's walk. The scan would stop being narrower than the verifier and
become a copy of it.

Review of the plan found a fourth gap neither issue names. After a prune, the verifier does not
check the first retained entry's `seq` or `prev_hash` — a prune gap is allowed there, and only the
prune-bind is checked. So a break between the last removed line and the first retained one is
visible to `audit verify` before the prune and to nothing after it.

The cost #540 asked to have measured first: on a release build, against a synthetic chain shaped
like a real four-gigabyte store (6.4 million signed entries, 656 bytes a line), walking the removed
range as the verifier does costs 3.6 µs per line and the scan 0.74 µs. Both apply to the removed
range only. A first prune removing 450,000 entries gains 1.3 s; a steady-state prune removing 1,000
gains 3 ms. The prune itself took 14 to 20 s on that store across fifteen runs with either build —
a spread larger than what the walk adds — and about seven tenths of it is recomputing the
high-water-mark from every retained entry. That is #568 and not this decision.

## Decision

**The loop in `verify_chain` becomes a function over lines and a keyring, and a prune walks the
range it is about to remove with that function. `scan_pruned_range` and `carry_forward_findings`
are removed.**

1. **One walk.** The verifier's per-line loop moves into `walk_lines` with its branches unchanged.
   `verify_chain` opens the log, calls it, and keeps the high-water-mark handling that follows.
   What the move adds is a function boundary; a `Walk` value holding everything the loop carries
   from one line to the next, so a walk can stop at a boundary and be continued; and a note of
   *why* a walk broke — a spliced legacy line, a link, or an HMAC — which the verifier does not
   report and the record needs.
2. **The range walked is `lines[..retain_from]`**: from the head of the file, through the existing
   prune point if there is one, to the last line being removed. A prune always removes from the
   head, so the walk's own assumptions hold — the genesis or prune anchor, the previous prune
   point's authentication, its prune-bind. The record is drawn from where that walk stands.
3. **The same walk is then continued over the first retained entry, for one question: does it
   follow the last removed line.** That link is checkable now and never again. The answer is taken
   as "yes" only from an entry that authenticates — an entry's `seq` and `prev_hash` say nothing
   while its hash does not hold. A link that does not hold is `broken`; an entry that does not
   authenticate leaves the link `unchecked`. What is wrong with that entry *itself* — its own HMAC,
   its key, its version — is still the next `audit verify`'s to report, because the entry stays in
   the log.

   The walk is continued rather than run once over range-plus-one because a single pass folds the
   retained entry into the totals (an entry legitimately written with no HMAC would be counted as
   removed), and taking it back out would mean `retention.rs` deciding what kind of line it was —
   the judgement this change removes.

   The first implementation recorded only a link failure there and nothing otherwise. Review of
   the diff showed what that left open: delete the end of the range, make the first retained entry
   fail to authenticate — rename its key, raise its version, or rewrite its `seq` and `prev_hash`
   to follow what is left — wait for the prune, and put the entry back. The prune-bind is taken
   from the entry's `entry_hash` field, which none of those edits touch, and the verifier allows a
   gap behind a prune point, so the log verified clean with entries gone. None of it needs the key.
   A second review found the same hole in the one exception the fix had kept — a legacy line
   before the chain has started, about which the verifier judges nothing: strip `chain_version`
   from the entry behind a deleted head and it reads as exactly that. The rule has no exceptions
   now. Nothing is recorded only when the entry was counted as authenticated, which is the one
   outcome that cannot be produced by editing the line.
4. **A ring that can resolve nothing starts the walk halted, as it does in `verify_chain`.** With
   an unlistable key directory or an unreadable epoch record the verifier judges no line; it
   tallies. A prune loading the same ring starts from the same `key_store_failure`, so it records
   `unchecked` and nothing else. Walked as a merely empty ring, it had judged the lines that need
   no key and recorded findings `audit verify` does not reach on that store.
5. **The record gains two keys and changes the meaning of none.**

   | Walk outcome | Record |
   |---|---|
   | unrecognized `chain_version` | `unverifiable=1` |
   | entries written with no HMAC, walked past | `unprotected=n` |
   | broke on a legacy line after the chain began | `legacy_splice=1` |
   | broke on a link: `seq`/`prev_hash`, the head anchor, a prune-bind | `broken=1` |
   | broke on an `entry_hash` that does not match its entry | **`hash_mismatch=1`** |
   | halted because of a key: an entry names one the ring lacks, or the ring is unusable | **`unchecked=1`** |
   | the first retained entry does not follow the last removed line | `broken` +1 |
   | the first retained entry did not authenticate, so that link could not be established | `unchecked` +1 |
   | the head prune point authenticated and carries a record | merged in |
   | the head is a prune point that did not authenticate, or its record is unreadable | `prior_lost=1` |

   `unchecked` says the check could not be completed. It stays true after the key comes back,
   which is what the scan's "do not record a fault that may no longer exist" was protecting; the
   missing key is still not what is recorded. It is not a weaker finding than `hash_mismatch` but
   an unknown one — whoever can rewrite an entry can rename the key it names — and the sentence
   printed for it says to treat it as possible tampering, as `audit verify` says of a halt.
6. **An unknown key inside an otherwise well-formed record no longer discards the counts beside
   it.** `decode_findings` keeps what it read and sets `record_unreadable`; `summary()` says both.
   A malformed part or a repeated key still yields nothing but `record_unreadable`.

## Why not the smaller changes

| Option | Rejected because |
|---|---|
| Add the HMAC comparison to `scan_pruned_range` | Leaves two implementations of one judgement. #556 and #539 are what that produces, and the head anchor, the prune-bind and whatever the verifier learns next would each need the same treatment again. |
| Leave #540 uncounted and documented | The findings that are counted are the weaker ones. Exit 1 is the one a prune erases. |
| Put HMAC mismatches under `broken` | `broken` reads "a break in prev_hash/seq continuity" in every release since 1.0.5, where the record first shipped, and those releases can read the key. They would describe a rewritten entry as a continuity break. A key they do not know makes them say "this build cannot read the record — upgrade", which is true. |
| Skip the prune when the walk halts on a key | One line with an invented `key_id` then stops retention for good and the log grows without bound — the shape ADR-0010 already rejected for an unverifiable entry. `secret().is_none()` skipping the prune is different: no line in the log can cause it. |
| Record the structural scan past a halt (`structural_break_at`, #470) | It is one-sided evidence from unauthenticated lines, reported beside a halt rather than as a verdict. A third new key for it is more vocabulary than it earns; SECURITY.md says it is not recorded. |
| Exclude the range's trailing edge and say so | It weakens the sentence the section opens with to cover a case that costs one more line of walking. |

## Consequences

- **Byte-identical stores can produce a different record, in both directions.** More: a rewritten
  entry, a head that does not anchor, a halt on a key, a gap before the first retained entry. Less:
  the scan walked past an HMAC mismatch and went on counting `unprotected` entries behind it, and
  it counted behind a prune point that failed to authenticate; the walk stops where the verifier
  stops, so those later counts are no longer written. `docs/CONTRACT.md`'s revision log lists each.
- **Releases 1.0.5 through 1.2.2 cannot read `hash_mismatch` or `unchecked`.** They report the
  record as unreadable, and one of them pruning such a log turns it into `prior_lost`. Releases
  before 1.0.5 do not read the record at all. That is ADR-0010's
  stated behaviour for a counter a reader does not know, and it is reachable on a machine where two
  installs take turns on one store. A prune that finds nothing still writes `rule_id: null`.
- **The prune holds the log's flock for longer** by the walk's cost over the removed range: 2.9 µs
  a line more than the scan.
- **`retention.rs` no longer judges a line.** What is left there is a mapping from the walk's
  outcome to the record, and a test of that mapping needs expectations written by hand — comparing
  the record against `verify_chain` on the same input would compare `walk_lines` with itself.
- **A surface that used to check three readers against each other now checks two readers and a
  mapping.** #556's agreement test called the scan directly. With the scan gone the verifier and
  the prune read a line through one function, and what the test's third check holds to its
  hand-written answer is the step from the walk's outcome to the record.
