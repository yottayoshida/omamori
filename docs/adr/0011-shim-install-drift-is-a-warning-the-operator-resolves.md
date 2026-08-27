# ADR-0011: Shim install drift is a warning the operator resolves, not a repair

- **Status**: Accepted
- **Date**: 2026-08-27
- **Plan**: `.claude/plans/2026-08-27-omamori-doctor-shim-drift.md`

## Context

Issue #542. `doctor`'s Layer 1 compared each shim symlink against `.integrity.json` and nothing
else. That record is not an install log: `generate_baseline` reads `omamori_exe` and `version`
from whichever process is generating it and reads `shims` from the links as they currently are,
and three separate paths call it — `install`, `status --refresh`, and `doctor --fix`'s
`RegenerateBaseline` step. A shim left pointing at an older install therefore agreed with its own
record, and Layer 1 reported `6/6`.

This was found on the maintainer's machine while verifying the v1.0.5 release. Every shim pointed
at a `~/.cargo/bin` binary from v0.16.0 while a v1.0.4 Homebrew binary sat later on `PATH`. Layer
1 is what a plain `rm` in a terminal actually hits, so for nine days every rule decision came from
v0.16.0 and nothing in v1.0.0 through v1.0.4 was in force. Layer 2 named the same drift precisely
("hooks rendered by v0.16.0, binary is v1.0.5") because its check is implementation-derived: it
compares the hook file against what the *running* binary would render right now. Layer 1 had no
equivalent reference.

The state is reachable without doing anything unusual — `cargo install` and `brew install` both
being present is listed in SECURITY.md's v1.0 soak notes — and `install` writes the shim pointing
at whichever binary ran it, so the two installs simply drift apart.

## Decision

Layer 1 compares each shim's **resolved file** against the resolved file of the binary running the
check, and reports a mismatch as `Warn` with `Remediation::ManualOnly`.

Three consequences of that sentence are the actual decision, and each had a plausible alternative:

**The reference is the running binary, not the baseline.** It is the one input to the comparison
that cannot be rewritten from disk. Any baseline-derived answer is self-confirming — that is the
defect, not a way to fix it.

**The comparison is on canonicalized paths, and no version is named.** A symlink carries no
version metadata, and reading the target's version would mean executing a path the tool has not
otherwise decided to trust. Canonicalizing means a Homebrew stable path and the Cellar binary it
points at compare equal, so the normal case — `brew upgrade` relinks the stable path and the shims
follow it automatically — is not drift. It also means the message says only which two paths are
involved. `.integrity.json`'s `version` is not used as a stand-in: it records the process that
wrote the baseline, so "shims were installed by vX" would be false after any `status --refresh`.

**The remediation is `ManualOnly`, not `RunInstall`.** `doctor --fix`'s install repair re-links
every shim at `current_exe()`. Attaching that to this finding would silently discard a target the
operator pinned with `install --source` — which the README documents as the one way to make that
provenance judgement yourself. Which install should be in force is a decision, not a repair.
`doctor --fix` exits 2 while a manual item remains, so the finding does not disappear by being
ignored.

`Warn` rather than `Fail` for the same reason: Layer 1's existing `Fail` states are an unexpected
target, a dangling link, and a missing shim — each of them says nothing is running at all. Here
something is running.

**This check does not establish what that something is.** It compares two paths; it does not
execute the target, read it, or verify that it is omamori. The three branches that speak to the
target's identity run before it — the basename check, the existence check, and the baseline
comparison — so reaching this arm means all three agreed, and the only thing added is that the
target is not the install running the check. The neighbouring branch in the same loop ("differs
from baseline", which means somebody re-pointed a shim *after* install, a strictly more suspicious
event) is already `Warn`, so `Warn` here is the consistent verdict rather than a weaker one.

## Alternatives considered

**Execute the shim target and read `--version`.** Rejected. It would produce a real version
comparison, but running a binary at a path the tool reached by following a symlink is a larger
question than the one being answered, and #542 ruled it out when it was filed.

**Persist install provenance (whether `--source` was explicit) in the baseline and suppress the
warning for an explicit pin.** Rejected. Two of the three paths that regenerate the baseline
(`status --refresh`, `doctor --fix`) have no idea what the original install's provenance was, so
the field would need a carry-forward rule and would still be wrong after any hand-edit. The
`ManualOnly` remediation removes the harm the suppression was meant to prevent, at a fraction of
the cost.

**Treat `baseline.omamori_exe != shim target` as the signature of an explicit `--source` and
suppress on it.** Rejected. That is the same shape #542 itself produces after a baseline refresh,
so it would suppress exactly the case being detected.

**Add the check to the Integrity section instead, comparing baseline version to running version.**
Rejected. That check already exists (`.integrity.json` reports `Warn` when its recorded version
differs), and it is self-clearing: its remediation is `RegenerateBaseline`, and regenerating blesses
whatever the shims currently point at. It also leaves Layer 1's `6/6` — the thing that was read as
sound — untouched.

**Collapse the five shims into one finding.** Rejected. All five share a target today only because
`install` writes them in one loop; reporting per shim keeps a partially re-pointed set
representable, and matches the existing item model.

## Consequences

A machine with two installs now reports `Warn` where it reported `Ok`. Each drifting shim is its
own item, so Layer 1's pass count drops by one for each — normally all five, since `install` writes
them in a single loop from one source. On a machine with no other warning or failure that also
moves `doctor` from exit 0 to exit 2 and `--json`'s `protection_status` from `ok` to `warn`;
where something was already warning, only the counts move. `status` and `setup`'s
`[3/3] Verification` summary render the same items and move with them. The meaning of exit 2 does
not change — it has always meant warnings are present — so this is not one of the three surfaces
the 1.0 contract freezes; the move is recorded in `docs/CONTRACT.md`'s revision log alongside the
other verdict moves.

**An operator using `install --source` to pin a different binary sees a permanent warning.** This
is accepted. The statement is true — the shims are not the install running the check — and
`ManualOnly` means nothing is undone by it. The message names `install --hooks --source <target>`
as the way to make the two agree.

**Running `doctor` from the older binary reports no drift.** The comparison is relative to
whichever binary was invoked, so the stale install considers itself current. This is structural,
and it is the same limitation Layer 2's hash check has always had: a hook rendered by v0.16.0
matches when v0.16.0 renders it again. What the check buys is that a `doctor` run from the *new*
install — which is what happens after `brew upgrade`, and what happened in #542 — now says so.

**`doctor --fix` can still re-link the shims**, when some *other* finding carries `RunInstall`
(`run_fix` unions the remediations across all items before acting). That behaviour predates this
change and is unaffected by it; what is new is only that this finding does not add another trigger
for it.

`is_dev_build_path` suppresses the comparison when the check itself is running from a `cargo`
build artifact, so developing omamori does not produce five warnings on every `cargo run -- doctor`.
That predicate is a path-shape heuristic, not provenance: a `CARGO_TARGET_DIR` outside a directory
named `target` is not recognised (already documented in ADR-0004's Consequences), and a legitimate
install under a path that happens to contain `target/release` is suppressed. Because the suppression
cannot be relied on, `full_check_with_exe` takes the resolved exe as a parameter and the tests
supply it explicitly rather than depending on where the test harness happens to live.
