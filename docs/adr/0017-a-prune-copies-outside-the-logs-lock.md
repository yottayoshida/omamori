# ADR-0017: A prune copies outside the log's lock, and takes it only to publish

- **Status**: Accepted
- **Date**: 2026-10-02
- **Plan**: `.claude/plans/2026-10-02-omamori-568c-prune-copies-outside-the-lock.md`
- **Supersedes**, in [ADR-0016](0016-a-prune-publishes-its-result-by-rename.md): Decision 5 (the
  leftover is swept by the next `append`), the alternative "copy outside the lock" that it set
  aside, and the consequence "the time under the lock does not change". What ADR-0016 decided about
  *how* a prune publishes — a sibling file, `rename`, the check after the lock — stands.

## Context

ADR-0016 made a prune safe to interrupt and left its cost where it was: on a 4.2 GB log a prune
takes 4.0 to 4.6 s, almost all of it copying the retained part, and all of it under the exclusive
lock `append` holds. An `append` that arrives meanwhile waits 0.5 s (`flock_bounded`, 100 × 5 ms)
and gives up; its entry is not recorded, and under `[audit] strict = true` the command it belongs
to is blocked.

Measured on `524994d` through `hook-check`, 6.4 million entries: of twenty `hook-check` runs
started 0.2 s apart while another was pruning, four began during the prune, and all four failed to
record ("audit lock is held by another process").

ADR-0016 kept "copy outside the lock" as the route to take "if rare is not enough". The owner's
call was that an audit log should not lose entries to its own housekeeping at any frequency, and
that the first prune of a log that has never been pruned — the largest one it will ever run — is
exactly when it would lose the most.

## Decision

**A prune does its reading and copying without the log's lock, and takes the lock only to add what
was appended meanwhile and rename the result into place.**

What makes that sound: the log only grows at its end. The one thing that changes its head is a
prune. With prunes excluded from one another, the bytes before the boundary and the bytes up to
wherever the copy stopped do not change while they are being read; and appending, under the lock,
everything from that point on reproduces the log byte for byte — wherever that point falls, in the
middle of a line included.

1. **`append` releases the log's lock before the prune runs.** It writes its entry, advances the
   high-water-mark, drops the descriptor, and then calls the prune, which no longer takes a locked
   descriptor.
2. **Prunes exclude one another by `flock` on the log's directory.** One non-blocking attempt at
   an exclusive lock on the directory's descriptor; if it is held, a prune is already running, and
   this one says so in a warning and does nothing. Whoever holds it is the only one that creates,
   removes or renames `<log>.prune-tmp`. No file is added to the directory for this, so there is
   nothing to own, protect, or delete by mistake.
3. **Phase one, without the log's lock.** The log is opened for reading — never created — and that
   descriptor stays open until the prune is over, so the file it names cannot be confused with
   another that reused its inode number. The head is read, the range to remove is walked, the
   temporary file is created as ADR-0016 describes, and the retained part is copied. **Where the
   copy stopped is fixed in one place**: the boundary plus the number of bytes actually copied,
   bounded by the length the log had when the copy began. A copy that read less than that — the log
   shrank — ends the prune.
4. **Phase two, under the log's exclusive lock**, taken on the descriptor phase one already holds,
   in one bounded attempt. If it cannot be had — `audit verify` holds a shared lock for the length
   of its walk — the prune gives up, removes its temporary file, says so, and the next check tries
   again. Under the lock, four things are confirmed, and any one failing ends the prune with the
   log untouched:
   - the path still names the file phase one read;
   - the log is at least as long as the point the copy stopped at;
   - its first line is the one read when the prune began;
   - `<log>.prune-tmp` still names the file this prune wrote.
   Then everything from the stopping point on is appended to the temporary file, a missing final
   newline is added, and the result is synced and renamed as before.
5. **Leftovers are swept on the prune's own schedule**, by whoever holds the directory lock: at
   the start of a prune, and — retention on or off — on every append that reaches a multiple of
   `PRUNE_CHECK_INTERVAL` and finds one. ADR-0016 swept on every append and rejected exactly this
   schedule; that sweep assumed a prune only ever ran under `append`'s lock, and removing the file
   a running prune is writing is worse than a leftover lasting a thousand appends. This interval is
   the sweep's, and stays at a thousand appends however rarely prunes themselves come to run.

**What the first-line check stops, and what it does not.** It stops a head rewritten in the same
file after phase one read it — a release through 1.2.2, which prunes in place, running between the
two phases. It does not stop a rewrite that finished before phase one began; there the log simply
has nothing old enough left, and the prune ends for that reason. Nor does it tell apart two logs
that begin with the same line. The length check covers part of that; the rest is the documented
limit of a store someone is editing by hand.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Lower the frequency and keep copying under the lock | Entries are still lost, once a day instead of every few minutes, and most of all on a first prune. |
| Let an `append` wait longer while a prune's temporary file exists | The 0.5 s bound is what keeps a held lock from stalling every `hook-check`; a file whose presence lengthens it hands that stall to whoever can create the file. |
| A dedicated lock file, `<log>.prune-lock` | An empty file left lying in the data directory is something an operator removes as debris — and removing it while a prune runs lets a second one start. It also needs an owner, a protected pattern, and the checks against a symlink or a FIFO that the directory needs none of. |
| `flock` on the temporary file itself | Leaves a gap between creating it and locking it, and at the rename that file *becomes the log*. |
| Reuse the key store's lock | Held exclusively for seconds, it would make every command's key read wait 0.5 s and proceed unlocked. |
| Retry, or wait without bound, for the lock in phase two | The process waiting is a `hook-check` that has not printed its verdict. `audit verify` on a large log holds its lock for longer than any retry worth making. |
| Reopen the log in phase two | The writer's open creates the file. A log removed between the phases would be replaced by an empty one before the mismatch was noticed. |
| Run the prune in a detached process, so the command that triggered it does not wait | The host waits for the hook to exit either way; detaching means leaving a child behind, a different design. The wait is real and is stated; making prunes rare is the next change. |

## Consequences

- **An `append` is not refused while a prune copies.** The log's lock is held for the publish
  only.
- **The command whose append triggered the prune still waits for it** — the whole prune, before
  `hook-check` prints its verdict. That is unchanged, and is what the next #568 change makes rare.
- **A prune that cannot publish is thrown away.** While `audit verify` is walking the log, or if
  anything changed under it, the copy is discarded and the next check starts over.
- **A leftover temporary file lasts until the next multiple of a thousand appends**, not until the
  next append — and longer where the directory cannot be opened or its lock had, since that lock
  is what shows no prune is still writing the file.
- **`flock` is taken on a directory and on a descriptor opened for reading.** Local filesystems
  allow both. One that refuses either — some network filesystems want a descriptor opened for
  writing — leaves a prune unable to run, and saying so at each check. Not measured.
- **Every append is back to two `stat` calls** for ADR-0016's check; the `unlink` per append is
  gone.
- **A prune needs to open the log's directory for reading.** Where it cannot — a directory that
  is searchable but not listable — it says so and does not run. That is a change: it used to run
  there, with a keyring it could not load, and record the range it removed as `unchecked`. The
  range now stays, as it does when there is no secret to prune with. The unusable-keyring record
  itself is still reachable, through an epoch record that states no epoch.
- **A key rotation during phase one** leaves a prune point signed with the key that was active
  when the prune began. That key stays in the ring as a retired one, so the prune point should
  still verify; this was not exercised. The same window exists today, a few milliseconds wide.
- **Measured** on 6.4 million entries (4.2 GB), through `hook-check`: twenty runs started 0.2 s
  apart while another pruned. Before, four fell inside the prune and all four failed to record.
  After, seventeen fell inside it and all twenty-one appends were recorded. Measured separately,
  with nothing appended during the prune, the log's lock was held for 6 to 7 ms; it had been held
  for the whole prune, then 4.0 to 4.6 s (3.9 to 4.6 s as measured after this change).
