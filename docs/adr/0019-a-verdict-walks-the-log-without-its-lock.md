# ADR-0019: A verdict walks the log without holding its lock

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-503-577-579-shell-writes-verify-lock-poc.md` (PR-1)
- **Issue**: [#579](https://github.com/yottayoshida/omamori/issues/579)
- **Amends**: [ADR-0016](0016-a-prune-publishes-its-result-by-rename.md) Decision 4, where `verify_chain` holds the shared lock for its whole walk and reads the high-water-mark by path afterwards; and the two places in [ADR-0017](0017-a-prune-copies-outside-the-logs-lock.md) that say a prune cannot publish while `audit verify` walks.

## Context

`verify_chain` takes the audit log's shared lock and holds it to the end of the file. `audit verify`, `report`, `report --json`, `doctor` and `doctor --json` all compute their verdict through it. An `append()` that arrives meanwhile needs the exclusive lock, waits 0.5 s (`flock_bounded`) and gives up: the entry is not recorded, and under `[audit] strict = true` the guarded command is refused. The walk costs about 3.4 µs a line (measured during #568), so on a 6.4-million-line log every guarded command in a window of about 20 seconds loses its record — including the hook denies G-2 exists to keep.

The lock is there so that a walk is not compared against a log a prune has replaced (ADR-0016). Two facts make most of that unnecessary for the walk itself. An `append()` writes its line and raises the high-water-mark inside one exclusive lock, so a shared lock sees the two consistent with each other. And the log grows only at its end; the one thing that rewrites its head is a prune, which since 1.3.0 publishes by `rename` and never writes into the file a reader holds (ADR-0016).

## Decision

**`verify_chain` takes the shared lock to note where the log ends, walks without it, and takes it again to confirm and to write.**

1. Open and lock as today (`open_log_locked`, `Shared`). Under the lock, note the file's length `L`, the high-water-mark's state, and the first line. Release the lock; keep the descriptor.
2. Walk the first `L` bytes of that descriptor. What was appended after the note is outside this walk, as it would have been had the walk started a moment earlier.
3. Open the log again by path and take the shared lock. Confirm that the file walked — whether or not the path still names it, since a release through 1.2.2 can rewrite it in place and a later release rename another over it during one walk — is at least `L` long and begins with the line noted. If either fails, a release through 1.2.2 has pruned it in place during the walk, and what the walk read — or the error it stopped at — may be half of each: let the lock go and start verification over, reading the keys again before the lock is taken (never under it, the order a key rotation takes the two locks in) and holding it for the whole walk — the behaviour before this change. An error from the first walk is reported only after this confirmation. If the file walked holds and the path names another file, a prune has renamed one into place: the verdict stands for the file walked, and the mark is not written.
4. Compare the walk's end with the mark noted in step 1, never with the mark read afterwards. Write the mark — the re-bootstrap for a missing or unusable one — only under the lock of step 3, only when the path still names the file walked, and only when the file at the mark's path is the one noted (device, inode, modification time and length; every write of the mark renames a new file into place). When it is not written, `hwm_write` says so, and `audit verify` does not claim it was reset.
5. If the lock of step 3 cannot be had, the run reports `log_lock`, as a run that could not take the lock in step 1 does today.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Let an `append()` wait longer while a verdict is computed | Rejected in ADR-0017 for the prune: the process waiting is a `hook-check` that has not printed its verdict. |
| Release and retake the lock every N lines | Each retake needs the same confirmation as step 3, N times over, and the window an `append()` can fall into shrinks without closing. |
| Hold the lock and make the walk faster | The walk is proportional to the log; no constant factor removes a window that grows with it. |

## Consequences

- An `append()` arriving while a verdict is computed is recorded. The lock is held for two short spans: noting the end, and confirming it.
- A prune whose copy finishes during a walk can publish, where before it was thrown away (ADR-0017's phase two).
- The verdict describes the log as it stood when the walk began. An entry appended during the walk is checked by the next one.
- Where a release through 1.2.2 shares the store and prunes in place during the walk, the walk is repeated under the lock, and in that run an `append()` can still give up as before.
- A same-user edit made during the walk can at most produce a false exit 1 or 3, as it could before; a forged intact chain still needs the key.
