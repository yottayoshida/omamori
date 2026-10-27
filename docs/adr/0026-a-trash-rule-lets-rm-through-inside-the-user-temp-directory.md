# ADR-0026: A trash rule lets `rm` through inside the user's temporary directory

- **Status**: Accepted
- **Date**: 2026-10-27
- **Plan**: `.claude/plans/2026-10-27-rm-in-temp-dir-log-only.md`
- **Issues**: [#616](https://github.com/yottayoshida/omamori/issues/616)

## Context

Layer 1 decides that a command is AI-driven from environment variables alone (`CODEX_CI=1`,
`CLAUDECODE=1`, ...). A process started from inside an agent session keeps those variables for
its whole life. Two such processes filled the macOS Trash on one machine:

- Codex's `app-server daemon pid-update-loop`, started from a Codex session, checks for an update
  every hour in a `mktemp -d` directory and removes it with `rm -rf`. From 2026-10-21 the audit
  log holds two `trash` entries per hourly check from it, 130 in all; the Trash holds one
  such directory per check, containing only `codex-package_SHA256SUMS`.
- A test suite that passed `os.environ` to shell scripts, each of which removed its own
  `mktemp -d "${TMPDIR:-/tmp}/…"` directory.

Of the 55 Trash entries kept for inspection, 44 are directories of this kind. Every Codex process
on the machine has `TMPDIR` set to the per-user directory `/var/folders/<a>/<b>/T/`.

The existing context evaluation already lets an `rm` through as log-only when its targets are
regenerable (`target/`, `node_modules/`, ...). Reviewing it for this change found that the paths
it judged were not always the paths `rm` removes: it read only the arguments after `--`, skipped
a lone `-` and anything after the first operand that starts with `-`, folded `..` before resolving
links, and expanded `~` from `HOME`. One regenerable target let every other target through.

## Decision

1. The downgrade of a recursive `rm` is decided from the physical location of what `rm` would
   remove. Operands are counted the way macOS `rm`'s `getopt` counts them. For each operand, both
   the entry itself (`realpath` of its parent joined with its name) and what it resolves to
   (`realpath` of the operand as given, with no lexical folding and no `~` expansion) must qualify.
   Every operand must qualify; an operand whose entry does not exist removes nothing and is left out.
   An unresolvable working directory suppresses the downgrade.
2. A location qualifies when it is regenerable, as before, or — only for an `rm` rule whose action
   is trash — when it lies below the user's temporary directory.
3. The user's temporary directory is `confstr(_CS_DARWIN_USER_TEMP_DIR)`, used only when its
   canonical form is exactly `/private/var/folders/<one>/<one>/T`, a real directory, and owned by
   the current user. `TMPDIR` is not read. On other platforms there is none.

## Alternatives Considered

- **Judge by process ancestry.** The Codex daemon is the process that runs Codex's own commands,
  so ancestry cannot tell it apart from an agent.
- **Add the temporary directory to `regenerable_paths`' defaults.** A user-written list replaces the
  defaults, and the per-user path is only known at run time.
- **Include `/private/tmp`.** Nothing observed needs it, and it is shared between users and sessions.
- **Trust `TMPDIR`.** An agent sets it: `TMPDIR=$HOME rm -rf ~/proj`.
- **A setting to turn the temporary-directory downgrade off.** Not asked for; limiting it to trash
  rules keeps every `rm` rule a user wrote to block or move unchanged.

## Consequences

- An agent's `rm -r` below the user's temporary directory is removed for good instead of moved to
  Trash, and recorded in the audit log as log-only.
- Commands that were let through because one of their targets was regenerable now go to Trash.
- `git clean`, `chmod`, `rsync` and `find` keep the old regenerable downgrade; links make location an unreliable
  guide for them, which is left for a separate decision.
- A mount point placed inside the temporary directory, and a swap between the check and `rm`
  (T10), remain residual risks.
