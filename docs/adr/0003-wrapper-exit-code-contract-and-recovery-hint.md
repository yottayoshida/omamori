# ADR-0003: Wrapper exit-code contract for the infra-failure recovery hint

- **Status**: Proposed
- **Date**: 2026-07-11
- **Plan**: `.claude/plans/2026-07-10-omamori-batch-a-lockout-safety.md`

## Context

The Claude/Codex hook wrappers (`render_hook_script`/`render_codex_pretooluse_script` in
`src/installer.rs`) previously mapped every non-zero exit from `omamori hook-check` to a bare
`exit 2`, with no way for the user (or the AI agent relaying the error) to distinguish "your
command was legitimately blocked" from "the hook binary is broken/missing" — the exact ambiguity
that made recovering from a stale exec path (#349) trial-and-error. #353 asked for a recovery hint
in the latter case.

The core design question: can the wrapper reliably tell the two cases apart using only the exit
code, without changing `hook-check`'s own contract?

## Decision

1. **`hook-check`'s exit-code contract is `0` = allow, `2` = block (all reasons), nothing else** —
   pinned in the doc comment on `run_hook_check` (`src/engine/hook.rs`). This was already true in
   practice (verified: every `run_hook_check` return path is `Ok(0)` or `Ok(2)`; an `Err` maps to
   exit 1 in `main.rs`), it just wasn't written down as an invariant other code could rely on.
2. **The wrapper adds a third branch**: `0` → allow, `2` → block (no hint — a legitimate BLOCK
   must not look like a malfunction), anything else → print a fixed-string recovery hint to
   stderr and still `exit 2` (fail-close preserved). "Anything else" covers `hook-check`'s own
   internal errors (exit 1) and cases where the shell can't even invoke the binary at all
   (exit 126 permission-denied, 127 not-found) — this second class is exactly what happens when
   the exec path is stale, and it's the one the wrapper script itself is best positioned to
   detect, since `hook-check` never even starts.
3. **The hint is a fixed string with no runtime interpolation** — no version number, no resolved
   exe path, nothing that could drift out of sync with a future release (see Consequences,
   snapshot-embedding risk). It names the durable, cross-version command `omamori install --hooks`
   only, split across two lines by audience: an AI-agent-facing line ("this is not a decision
   about your command, don't retry, tell the user") and a human-facing line ("run this in a plain
   terminal — not via an AI agent").
4. **The two wrappers are not unified behind a shared render helper.** `scripts/check-invariants.sh`
   Invariant #7 extracts `render_hook_script`'s function body via `awk` and greps for specific
   literal strings (`set -u`, `hook-check --provider claude-code`, `exit (0|2|$?)`, etc.) to catch
   drift in the wrapper contract. Delegating the shared tail to a helper function would move those
   literals out of `render_hook_script`'s own body, failing the gate that exists specifically to
   catch this class of regression. Instead:
   - Invariant #7 is extended with parallel checks (#7i–#7o) for
     `render_codex_pretooluse_script`, which previously had no invariant coverage of its own.
   - A new unit test (`wrapper_tails_are_byte_identical_across_claude_and_codex`) asserts the two
     wrappers' fail-close tail (everything from `STATUS=$?` onward) is byte-identical, so editing
     one without the other is caught structurally instead of relying on a human to remember to
     touch both.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Sentinel token: have `hook-check` print a version-stamped marker on every completed run, and have the wrapper treat its absence as "binary didn't actually run" | Adds `fd`-juggling complexity to the wrapper's fail-close hot path (every legitimate BLOCK would need its stderr captured and re-emitted to preserve the marker check) for a distinction the exit code already makes reliably enough in practice. No real evidence of an exit-2-returning "broken" binary exists (the closest test fixture, `verify_hook_contract_rejects_binary_reproducing_the_reported_349_symptom`, is a synthetic fixture for a *different* check — the install-time contract probe in #349 — not a wrapper runtime state). |
| A new reserved exit code from `hook-check` itself for infra failure (e.g. `3`) | Doesn't help: the wrapper's actual blind spot is the case where `hook-check` never runs at all (exec fails at the shell level, exit 126/127) — no exit code `hook-check` could return would ever surface, since the process never starts. A reserved code would only add complexity without closing the gap it's meant to close. |
| Capture the wrapper's own stderr and suppress the shell's raw error (`sh: /path: No such file or directory`) so *only* the fixed hint appears | Requires `set +e`/command-substitution around the inner pipeline, which risks losing exit-code fidelity and adds fragility to the fail-close hot path for a cosmetic improvement. The raw shell diagnostic is accurate and informative (it names the exact dead path) and doesn't compromise fail-close; verified in bash 3.2 and dash that this doesn't leak anything false. |

## Consequences

- The recovery hint text is now effectively part of the wrapper's stable contract (pinned by
  Invariant #7h/#7o and the exit-code matrix test `wrapper_exit_code_matrix_v003_v004`). Changing
  its wording requires updating those checks too.
- Because the hint is version-agnostic and path-agnostic by design, an `omamori` upgrade never
  needs to touch already-installed wrapper scripts for the hint to stay accurate — the "snapshot
  embedded in an old wrapper becomes wrong after upgrade" failure mode (`update-cadence` UX
  concern, U4) does not apply here.
- A legitimate BLOCK (exit 2 from a working `hook-check`) never shows the recovery hint — verified
  by `wrapper_exit_code_matrix_v003_v004`'s `legit-block` case. This matters because showing an
  "install --hooks to fix this" hint on every ordinary block would both be noise and a social
  engineering vector (repeatedly suggesting a user re-run install/reconfigure commands is exactly
  what an attacker prompting for policy relaxation would want to see suggested).
- `#355`'s isolated-HOME reproduction confirms the mechanism this hint targets: once the exec path
  is dead, *no* Bash command — including the recovery command itself, run by an AI agent — can get
  through the same broken wrapper. The hint's agent-facing line ("don't retry, tell the user") is
  not just a courtesy; retrying is provably useless from inside the same session.
