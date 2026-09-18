# ADR-0014: `append()` chains only onto the log's last chain entry, within a bounded walk

- **Status**: Accepted (2026-09-17)
- **Date**: 2026-09-17
- **Issue**: [#465](https://github.com/yottayoshida/omamori/issues/465)

## Context

`AuditLogger::append` has to know where the chain ends before it can number the next entry and
link `prev_hash` to it. `read_chain_state` answered that by taking the last line within a 64 KB
tail window that parsed as a JSON object, and returning `Fresh` — restart from genesis at `seq 0` —
when there was no such line or when the line it found did not look like a chain entry. Four shapes
reached `Fresh`: nothing parseable in the window, a line with no `chain_version`, a chain-shaped
line with no `seq`, and one with an empty `entry_hash`.

#465 was filed for the first shape: enough non-JSON appended behind a planted entry with an
unrecognized `chain_version` pushed it out of the window, so the refusal that entry should cause
(#177 B1) stopped applying and appends resumed on a second chain. Review of the fix found the
other three, each reachable with one planted line (`{"pad":1}` suffices), and a case with no
attacker at all: on the hook path `command` holds the whole command text, an input rejected as too
large is recorded in full, and nothing truncates either, so a genuine entry longer than the window
at the tail made the next append fork at `seq 0` and `omamori audit verify` report a chain nobody
had touched as broken. The longest line on a real four-month log was already 46 KB.

`verify_chain` reads the whole file line by line and had none of these problems; the two sides
disagreed about what "the last valid line" means.

## Decision

`read_chain_state` walks the file backwards from its end, one line at a time, and stops at the
first line that carries a `chain_version`. Everything else — a torn fragment, foreign JSON, a
legacy-shaped line, a chain-shaped line missing the `seq` or non-empty `entry_hash` omamori always
writes — is read past.

The walk covers the last 64 MiB (`TAIL_SCAN_LIMIT`). A line is examined only if it *starts* within
that span, and no byte below it is read. When the span holds no chain entry the answer is
`ChainTailState::NoEntryWithinLimit`, which `append` turns into an error like its two existing
refusals; `Fresh` is returned only when the start of the file is reached within the span.

Mechanics: newline offsets are found in 64 KiB chunks; a candidate line wholly inside the chunk in
hand is parsed from memory, and only a line longer than that is streamed from the file through a
bounded reader, so memory stays at one chunk and reads stay at one per chunk. Each candidate is
peeked in three stages, one field each — `chain_version` first (an unrecognized version is refused
before `seq` or `entry_hash` are read, whatever shape they take, as #177 B1 requires), then `seq`
for a supported version (a tail at `u64::MAX` is refused here, before `entry_hash` is read at all,
as #456 requires), then `entry_hash`. A read that fails is returned as an error; it used to
become `Fresh`.

## Alternatives Considered

- **A larger window (8 MiB) and refusal beyond it, with nothing read past** — the first draft.
  Rejected in review: a planted `{"pad":1}` inside the window still reached `Fresh`, so the refusal
  was not a latch; and the window was sized from an input limit that does not bound what the writer
  records.
- **An unbounded walk** — the second draft, and what review approved. Rejected at the dry run.
  Reading past content costs time roughly per line, not per byte (measured on a release build: 1 GiB
  of two-byte lines took 22.5 s, a single 1 GiB line 1.2 s, both measured on that draft), and that
  time is spent under the log's
  lock before `hook-check` prints its deny. Past the host's hook timeout the deny is lost — the
  failure `flock_bounded` already bounds lock acquisition to prevent, reopened through the file's
  contents. The first unbounded implementation also issued a read per line (5 MiB of eight-byte
  lines took 0.7 s), which is why short lines are now parsed from the chunk in memory.
- **Consulting the high-water-mark before returning `Fresh`** (a populated mark contradicts "no
  chain here"). Not taken: it changes what `append` does on a log that was deleted while its sidecar
  survived — today it restarts and warns of truncation; this would refuse. A different promise
  about a different state.
- **Truncating what the writer records for an input rejected as too large**, which would bound
  genuine line length and let the limit be justified structurally rather than by measurement. Not
  taken by owner decision: it changes the content of an audit record. The limit is sized far above
  anything measured, and an entry past it is refused, not forked.
- **Authenticating the tail line in `append`** (recompute its HMAC against the keyring; refuse on
  mismatch). The only way to make a refusal survive a well-formed forged line. Not taken by owner
  decision: it has to settle behaviour across key rotation, entries written without a key (#483)
  and an unusable key store, which is a plan of its own. The residual is recorded in SECURITY.md.
- **One typed peek for all three fields.** Rejected in review: a typed struct fails as a whole when
  any field has the wrong type, so a future-format line with `seq` as a string would fail the peek,
  be read past, and fork the chain behind it — the hole #177 B1 closed. A second review found the
  same coupling one field further in: pairing `seq` with `entry_hash` let a hash of the wrong type
  suppress #456's refusal of a tail at `u64::MAX`. Hence one stage per field.

## Consequences

- Padding, a foreign JSON line, a legacy-shaped line or a malformed chain-shaped line behind the
  last chain entry no longer restarts the chain or lifts a refusal; inside the span it is read past
  and the next entry links to the last real one, beyond it the append is refused. `verify`'s
  verdict on each of those stores is unchanged.
- Measured on a release build: the costliest shape inside the span (63 MiB of two-byte lines) is
  read past in 1.3 s; 1 GiB of it is refused in 1.3 s; a single 1 GiB line is refused in 0.07 s.
  Memory stays near 5 MB. The cost persists until an operator removes the content, because the
  audit prune rewrites the head of the log and keeps its tail.
- Two logs that appended before now refuse: one whose last 64 MiB hold no chain entry (including a
  single entry longer than that), and a pre-v0.7.0 log holding more than 64 MiB of legacy entries
  and nothing else. `[audit] strict = true` blocks on them, as it does on a padded
  unrecognized-version store.
- Not closed: the tail is not authenticated, and the writer records over-large inputs in full.
