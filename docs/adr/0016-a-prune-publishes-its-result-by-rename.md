# ADR-0016: A prune publishes its result by rename, not in place

- **Status**: Accepted — Decision 5 (the leftover is swept by the next `append`), and with it
  the consequences that every append pays an `unlink` and that a remnant lasts until the next
  append, and the consequence that the time under the lock does not change, are superseded by
  ADR-0017; so is the reason Decision 2 gives for removing a leftover ("under the lock, nothing
  else is writing it" — the lock that shows it is now the one on the directory). See
  [ADR-0017](0017-a-prune-copies-outside-the-logs-lock.md), which also takes up the alternative
  "copy outside the lock" that this ADR set aside. Decision 4 lists `report` among the readers
  that take no lock; that holds for its tallies, not for its verdict, which `verify_chain`
  computes under the shared lock — as `doctor`'s does. The cost that decision names is paid
  there: see [#579](https://github.com/yottayoshida/omamori/issues/579).
- **Date**: 2026-10-02
- **Plan**: `.claude/plans/2026-10-02-omamori-568b-prune-publishes-by-rename.md`
- **Supersedes**: the *Design decision* paragraph of SECURITY.md → Audit Retention ("In-place
  rewrite (not tmpfile→rename)"), which was never an ADR. Its first reason — `rename` changes the
  inode, and another process may hold a lock on the old one — is answered here rather than
  dismissed. Its second — a crash mid-rewrite "produces torn lines handled by existing recovery" —
  was measured and is false. [ADR-0007](0007-no-in-place-rewrite-of-existing-audit-entries.md)'s carve-out
  cites that paragraph and the rewrite it described; what ADR-0007 guarantees — retained entries
  are copied byte for byte, never recomputed — is unchanged, and holds more literally than before.

## Context

A prune removes the oldest entries from the head of `audit.jsonl`. Through 1.2.2 it did so in
place: read the whole file into memory, build the replacement — a prune point followed by every
retained line — and write it back over the original with `seek(0)`, `write_all`, `set_len`. It
runs at the end of an `append`, under the exclusive `flock` that `append` holds, once every 1000
appends when `retention_days` is set.

Three things were measured on a 6.4-million-entry store (4.2 GB), the shape of the maintainer's own
log ([#568](https://github.com/yottayoshida/omamori/issues/568)):

- **A crash mid-rewrite does not leave torn lines.** Stopping the write at 10%, 50% or 90% leaves
  the new content's first part followed by the old content's remainder: two well-formed chains
  joined where the write stopped, with a duplicated stretch between them and no mark of where one
  ends. `audit verify` reports a broken chain from then on, and no later `append` repairs it. The
  Design decision's "handled by existing recovery" described a different failure.
- **The prune holds the whole log in memory twice.** Peak RSS went from 4.5 GB to 8.0 GB across
  the call: the file as a `String`, and the replacement as a second one.
- **A prune with nothing to remove still reads everything.** `read_to_string` runs before the
  `prune_count == 0` return.

After [#570](https://github.com/yottayoshida/omamori/pull/570) removed the high-water-mark
recomputation, the prune takes 2.7 to 5.0 s on that store: 0.5–1.2 s reading, 0.2–0.4 s finding
the cutoff, 0.5–1.9 s building the replacement, 1.3–2.0 s writing it.

## Decision

**A prune writes its result to a sibling file and publishes it with `rename`. It never writes into
the log it is pruning.**

1. **Only as much of the log is read as each question needs.** The head is read, as lines, as far
   as the first entry at or past the cutoff, which fixes the byte offset the retained part starts
   at; a log whose first entry is within the retention window is left after one or two lines. Up
   to `MIN_RETAIN_ENTRIES` lines past that offset are read, to know that enough would remain —
   before anything is created. The removed range is then read once more and handed to the
   verifier's walk (`walk_lines`, ADR-0015) a line at a time, so it is not held in memory. The
   retained part is never parsed.
2. **The result goes to `<log>.prune-tmp`, beside the log, under a fixed name** —
   `audit.jsonl.prune-tmp` for the default path. It is created with `create_new` and mode `0600`,
   the mode `write_hwm` uses, rather than the log's own, which would carry a widened permission
   across; a pruned log is therefore `0600` afterwards. If the name is already taken it is the
   remains of a prune that did not finish, and it is removed and recreated — under the lock,
   nothing else is writing it. If what stands there cannot be removed, the prune says what it
   found and does nothing. The prune point is written first, then the retained part is copied
   through `io::copy`, file to file; a final byte that is not a newline gets one, as `append`
   gives the log before writing.
3. **`sync_all`, then `rename`, then the directory is synced** — the order `write_hwm` and
   `atomic_file` already use. A failure before the `rename` removes the temporary file, and the
   log, which has not been written to, is as it was. After the `rename` the log is the pruned
   one; the only step left is the directory sync, and its failure changes no content.
4. **Whoever takes the log's lock checks, after taking it, that the file it holds is the file the
   path names.** `rename` gives `audit.jsonl` a new inode. A process that opened the
   log during a prune and waited for the lock holds, once it has it, an inode with no name. For
   `append`, a line written there is lost. For `verify_chain` the content is still the complete
   log as it stood before the rename — but a shared lock on the old inode does not hold off an
   `append` to the new one, and `verify_chain` reads the high-water-mark by path after its walk,
   so a mark raised meanwhile stands above the end it walked and the verdict is a false exit 3.
   So one helper opens the log, takes the lock asked for, compares the `(dev, ino)` of the
   descriptor with the `(dev, ino)` the path now has (by `lstat`; a path that is gone counts as a
   mismatch), and reopens on a mismatch, bounded at three attempts, after which it fails as a lock
   that could not be taken. The two places that lock the log go through it: `append` and
   `verify_chain`. Once the check has passed, no `rename` can happen while the lock is held: a
   prune runs only under the current inode's exclusive lock, and that cannot be taken while any
   lock on it, shared or exclusive, is held.

   **The readers that take no lock are left as they are** — `audit show`, the entry counts in
   `status` and `doctor`, `report`. A shared lock there would be held for as long as the read
   takes, seconds on a large log, and an `append` gives up after 0.5 s: adding the check to them
   would lose audit entries to fix a count. An unnamed old inode read without a lock is the
   complete log as it stood before the rename, which is harmless to count. A command that opens
   the log twice can see different entry counts if a prune runs between the two; that is true of
   the in-place rewrite as well, and an inode check does not change it.
5. **Leftovers are swept by the next `append`.** Having taken the lock *and passed the check
   above*, `append` removes `<log>.prune-tmp` if it is there — one `unlink` that fails with
   `NotFound` on every ordinary append. Before the check, the lock held may be on an old inode
   while a prune runs on the new one, and removing its temporary file would fail its `rename`.
   After it, the file cannot be one a running prune is writing. A remnant of an
   interrupted prune therefore lasts until the next append, whatever the retention setting and
   however often prunes run. Any other failure to remove it is silent here — a warning on every
   append would bury the hook's output — and is reported by the next prune that finds the name
   taken.
6. **`.prune-tmp` joins `PROTECTED_FILE_PATTERNS`.** `audit.path` is configurable, so the data
   directory's own entry does not cover it; a suffix including `.jsonl` would not cover a log
   named otherwise.
7. **`try_prune` requires the log's path.** A rename needs a destination; the `Option` that let
   tests prune a bare file handle is gone.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Keep the in-place rewrite and make the interrupted state recoverable | The interrupted state is two well-formed chains spliced together, not a torn line. Recovering it needs a record of where the write got to — a journal — which is what `rename` provides for free. |
| Copy outside the lock; inside it, copy only what was appended meanwhile and rename | Brings the locked interval down to tens of milliseconds. But `append` would take the lock twice, the gap between admits a second prune, and `hook-check` would spend the copy before printing its verdict. The locked interval is being addressed by frequency instead (the third #568 change), which makes a prune rare rather than fast. Kept as the route to take if rare is not enough. |
| Use `atomic_file`'s `.omamori-tmp-<pid>-<hex>` temporaries | `gc_stale_temps` would remove a remnant after 24 hours — a 4 GB file sitting for a day — and a prune cannot sweep that prefix itself at start, since an in-progress key-store write uses the same one. A name only the prune uses can be swept by the prune. |
| Sweep remnants only on the appends that check for a prune (every 1000th) | A remnant would last up to 1000 appends, and longer once prunes are made rarer. One `unlink` per append removes the timing question. |
| Put every reader of the log through the inode check, not only the two that lock it | The check means something only under a lock, and the unlocked readers would have to take one for the whole read — during which appends give up after 0.5 s. It would trade lost audit entries for a count that the check does not make consistent anyway. |
| Spare `verify_chain` the inode check, since it only reads | The content it reads is right either way; the high-water-mark it compares against is read by path, after a walk during which appends to the new inode are not held off. A false exit 3 is a wrong verdict, which is the one thing the verifier must not produce. |
| Give the temporary file the log's own mode | Copies a widened permission along with the data. The fixed `0600` is what every other file omamori publishes in this directory gets. |
| `sync_data` instead of `sync_all` | 0.02–0.09 s against 0.13–0.34 s on 4.2 GB. The saving is small and every other publish in this directory uses `sync_all`. |
| Platform copy primitives (`copyfile`, `copy_file_range`) | `io::copy` already uses `copy_file_range` on Linux. On macOS the 4.2 GB copy took 3.5–4.6 s through plain reads and writes, which is the disk's own write rate; a second code path would buy little. |
| Count the retained entries while copying, and discard a result below the minimum | Considered first. Reading up to `MIN_RETAIN_ENTRIES` lines before creating anything answers the same question for at most a thousand lines, and a prune that will not happen then creates no file at all. |

## Consequences

- **A prune interrupted at any point leaves the log either exactly as it was or exactly as
  pruned.** The property SECURITY.md now states in place of the old Design decision.
- **The prune's memory no longer grows with the log** — for lines of ordinary length; a single
  line with no newline is still read whole, as it is today — and a prune with nothing to remove
  reads one or two lines instead of the file.
- **A pruned log is `0600`.** Through 1.2.2 the log kept whatever mode it was created with
  (`0644` under the usual umask).
- **A pruned log keeps its owner.** The process that prunes is not always the log's owner: a
  command run through `sudo` is blocked and audited as root, into the invoking user's log. A new
  file made there is root's, and at `0600` the log's owner could no longer append to it or verify
  it. So the temporary file is given the log's owner before anything is copied into it, and a
  prune that cannot do that fails without touching the log. The group, which decides nothing at
  that mode, is kept where it can be. (Review, P1: the rewrite in place never had this problem,
  because it never made a new file.)
- **A pruned log is a new file.** Whatever holds the log open — `tail -f`, a log shipper — keeps
  the replaced one. Extended attributes, ACLs and hard links are not carried across. The
  directory has to be writable by the process that prunes.
- **Every append pays for the check and the sweep**: two `stat` calls and one `unlink`, whether
  or not retention is on.
- **Bytes are copied as they are.** The in-place rewrite split on `lines()` and rejoined with
  `\n`, which silently normalised a `\r\n` and a missing final newline; the copy preserves the
  former and only adds the latter. Bytes that are not UTF-8 stop a prune only where it reads —
  the removed range and the first thousand retained lines — not anywhere in the file.
- **The time under the lock does not change**: 4.0 to 4.6 s on the 4.2 GB store, almost all of it
  the copy, against 2.7 to 5.0 s before. Other appends still give up after 0.5 s while a prune
  runs. Making that rare is the third #568 change; making it fast is the alternative above.
- **During a prune the directory needs free space equal to the retained part of the log.**
- **A release through 1.2.2 sharing the store still prunes in place, and is exposed in two
  further ways.** Its `append` has no inode
  check, so one that opened the log in a prune's last 0.5 s and then took the lock writes to the
  unnamed inode and the entry is lost. And once two inodes exist, an old-release `append` on the
  old one and a new-release `append` on the new one run under different locks, and both publish
  the high-water-mark through the same fixed `.hwm.tmp` name, so one of the two writes fails or
  replaces the other's half-written file.
  Two installs sharing a store is a configuration SECURITY.md lists as supported, so both are
  stated there rather than left to be found.
- **`<log>.prune-tmp` can exist in the data directory**, for the duration of a prune or until the
  next append sweeps a remnant. It is protected from AI-mediated edits like the log itself.
  `.jsonl.hwm`'s protection still depends on the log's name ending in `.jsonl`; that is noted,
  not changed here.
