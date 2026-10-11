# ADR-0024: A symlinked data directory is used, and protected where it points

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-463-475-486-fixture-and-key-store-decisions.md`
- **Issues**: [#486](https://github.com/yottayoshida/omamori/issues/486)

## Context

omamori keeps the audit log, its keys and its other state (`break-glass.json`, `staging/`) in
one data directory, `~/.local/share/omamori`. It guards the files in it: `read_secret` refuses a
symlinked key and calls it a possible attack, and `create_secret` creates with `create_new` +
`O_NOFOLLOW`. It did not decide what to do about the directory itself. `create_dir_all` follows
a link and `read_dir` takes no flags, so a data directory that is a symlink sends every key read
and write to wherever it points. #486 filed this, and SECURITY.md recorded it as "deliberately
left open" for a separate decision. This is that decision.

Measured on 1.4.0 with a disposable `HOME`, against a plain directory:

- **A symlink to a directory that exists**: appends, `audit verify` (exit 0, chain intact) and
  `doctor` behave as on the plain directory; `doctor`'s output is identical once paths are
  normalised. One surface differed: an agent's `Write` to `<target>/break-glass.json` was
  allowed (exit 0), while the same file named through `.local/share/omamori` was blocked
  (exit 2). The hook matched the data directory by its spelling, and `break-glass.json`,
  `staging/` and the heartbeat are protected only by that.
- **A dangling symlink**: the target is never created (`create_dir_all` returns
  `AlreadyExists`) and every append fails. The PATH shim says so once per five minutes and points
  at `omamori doctor`; `doctor` reported nothing, because its writability probe walked up past
  the link with `Path::exists()` — which follows it — and probed `~/.local/share` instead.

## Decision

A data directory that is a symlink is **used as it is, and treated as the data directory
wherever it points**: omamori does not refuse it or warn about it, and the hook protects the
location it points to the same way it protects `.local/share/omamori` — including when that
location does not exist yet (a dangling link, or `~/.local/share` itself a link and `omamori/`
not created yet), since a tool that creates missing parents would otherwise complete the link
with a file the agent wrote. While nothing exists there, nothing is recorded, and `doctor`
reports the audit log as unwritable.

The reason not to refuse rests on one premise: whoever can replace the entry
`~/.local/share/omamori` can also write `audit-secret` and the log directly. Replacing a
directory entry is an operation on its parent as the invoking user, and SECURITY.md's Defense
Boundary records direct operations by that user as **Not protected**, so a redirect gives them
nothing new. What the agent can reach through omamori's own hook is a different question, and
there the link must not change the answer.

Everything under the location the link points to is protected, as everything under a plain data
directory is. The link is expected to point at a directory used only by omamori; pointed at a
home directory or the root of a synced folder, it would block the agent's writes to all of it.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Refuse a symlinked data directory | People put `~/.local/share/omamori` (or its parent) elsewhere on purpose — another volume, a synced folder — and omamori would stop recording for them. Refusing by `lstat` before use leaves a swap window before every later open; closing it means opening the directory once and doing every key and log operation relative to that descriptor (`openat` and friends) across the whole store. The same user can still edit the key file in place. |
| Warn on every guarded command | Lands on every legitimate symlinked setup, on every command, and tells a user who could plant the link nothing they could not already do. |
| Report a working link in `doctor` | Seen only when someone runs `doctor`, and marks a legitimate setup as a finding permanently. Declined by the maintainer on 2026-10-11. A *dangling* link is reported, because nothing is being recorded. |
| Protect `break-glass.json` by file name | Would also block unrelated files of that name anywhere, and leaves `staging/` and the heartbeat, which are protected only by location. |

## Consequences

- SECURITY.md's #486 section states the decision and what an operator sees in each case; its
  Limitations row keeps the existing hook-layer caveat and points here.
- Tests pin it: appends through a link to an existing directory create the key at the target,
  verify intact and return no warnings; through a dangling link the append fails and the target
  is not created; `doctor`'s writability probe reports the dangling case; the hook blocks a
  `Write` to `<target>/break-glass.json` — also when `<target>` does not exist yet, through a
  dangling link or a linked `~/.local/share` — and not to a `break-glass.json` elsewhere. A change that
  starts refusing, creating, or matching by spelling again has to change those tests and this
  record together.
- On each write-side file-protection check the hook resolves both the data directory and the
  written path by following links one component at a time — an `lstat` per component and a
  `read_link` per link, joining the rest as spelled once a component does not exist. It does
  not use `canonicalize`, which fails for exactly the locations that do not exist yet. The part
  that exists is compared by device and inode, not by spelling: a macOS firmlink
  (`/System/Volumes/Data/...`) or a name in another Unicode normalization reaches the same
  directory without being a link, and a string comparison would let it through. Measured
  against the 1.4.0 binary on an allowed `Write` (debug builds, three alternating rounds of 60
  `hook-check` calls), the cost is inside the run-to-run spread: 6.8–8.7 ms per call before,
  7.0–10.3 ms after. A blocked write through this rule reports the existing token
  `.local/share/omamori` as its matched pattern, with the line `matched: inside the resolved
  location of '.local/share/omamori'` rather than one claiming the path contains that text.
- **Revisit when** the premise above stops holding — when something can replace the entry
  `~/.local/share/omamori` without also being able to write the key and the log directly. A
  sandbox that denies the agent writes to `~/.local/share` keeps the premise: it denies both.
