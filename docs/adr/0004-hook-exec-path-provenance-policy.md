# ADR-0004: Hook exec path provenance policy (reject implicit dev-build paths)

- **Status**: Proposed
- **Date**: 2026-07-11
- **Plan**: `.claude/plans/2026-07-11-omamori-batch-b-security-hardening.md`

## Context

`ensure_hooks_current`'s background self-repair (#349) resolves `current_exe()` and, once it
passes the hook-check contract probe, persists that path into the Claude/Cursor/Codex hook
artifacts and (via `install()`) the Layer 1 PATH shim symlinks. #349 already closed the gap where
a binary that merely *exists* at the resolved path could be non-functional — it now spawns the
binary and checks the real `hook-check --provider` contract before writing anything.

#349 does not close a distinct, narrower gap (#354): a `cargo build`/`cargo test` binary under
`target/debug` or `target/release` is frequently a **genuine, fully contract-compliant** omamori
binary — it just lives at a transient path the next build can delete or silently replace. If that
path gets pinned into `~/.omamori/hooks/*` or the PATH shim symlinks, the next `cargo build`
(overwriting the file) or `cargo clean`/branch switch (removing it) can leave the persisted
reference dangling or silently pointing at stale/different code, with no further signal to the
user. Investigation during implementation confirmed this is not hypothetical, though not via the
path first suspected: `ACCEPTANCE_TEST.md`'s documented pre-release procedure actually installs to
a stable path first (`cargo install --path . --force`, which places the binary under
`~/.cargo/bin`) *before* running `omamori install --force` — so that specific ritual does not
walk through this gap (a claim in an earlier draft of this ADR overstated this; corrected here
per Security Review during Phase 8). The real, verified evidence is narrower but solid: this
repository's own CI runs six `setup_*` subprocess tests (`tests/cli.rs`) that spawn the
just-built `CARGO_BIN_EXE_omamori` test binary — itself always a `target/debug`/`target/release`
path — directly through `omamori setup` with no override, on every push/PR, and until this PR
this was indistinguishable from a genuinely safe pattern.

The threat is symmetric with #349 in shape but distinct in mechanism: #349 is "is this binary
real", #354 is "is this binary's *path* durable". Both are pre-conditions for safely persisting a
hook/shim reference; neither implies the other.

## Decision

1. **A pure predicate, `is_dev_build_path(path) -> bool`** (`src/installer.rs`), true when `path`
   contains consecutive components `["target", "debug"]` or `["target", "release"]` anywhere in
   its component sequence. Checked as whole path *components*, not a substring — a substring check
   would false-positive on `target/debugger/omamori` (V-018) and never matches `cargo install`
   output (`~/.cargo/bin`) or Homebrew installs.
2. **Applied at every call site that resolves `source_exe` implicitly from `current_exe()` with no
   caller-supplied provenance**:
   - `regenerate_hooks_with_verifier` (the shim's silent self-heal path, #349's original scope) —
     checked before the contract probe, returns `HookOutcome::KeptExisting(HookKeptReason::NonDeploymentPath)`.
   - `auto_setup_codex_if_needed` — the shim's Codex-specific counterpart, called from the same
     silent self-heal entry point (`run_shim`) right alongside `ensure_hooks_current`. Checked
     immediately after its own `current_exe()` resolution, before `setup_codex_hooks` ever runs;
     returns `false` (no auto-configure) rather than persisting the path into the Codex wrapper.
   - `install()`, gated by a new `InstallOptions::source_is_explicit: bool` field — checked only
     when `false` (the default), returning `Err(AppError::Config(...))` with a message pointing at
     the `--source` escape hatch. `source_is_explicit: true` bypasses the check entirely.
   - Both `omamori install --hooks` (no `--source` given) and `omamori setup` (which gained a new
     `--source` flag, mirroring `install`'s existing one, precisely so this same explicit/implicit
     distinction is available to it) route through this shared gate.
3. **Explicit `--source` is the recovery/dev-workflow escape hatch, not a bypass to close.**
   Passing `--source <path>` (to `install` or the newly-added `setup --source`) sets
   `source_is_explicit: true` and skips the check unconditionally — a human who names a specific
   binary has already made the provenance judgment the check exists to make automatically. This
   mirrors #354's original design intent for `install()`'s pre-existing `--source` flag; the
   extension here is giving `setup` the same flag it previously lacked, rather than inventing a new
   bypass mechanism.
4. **No env-variable escape hatch.** Considered and rejected (see Alternatives). The distinction
   from `--source` is not "an AI agent can't invoke `--source`" — it plainly can, the same way it
   can pass any other flag. The distinction is *ambient vs. explicit*: a CLI flag is visible in the
   single invocation's argv, tied to that one command, and requires deliberately naming a specific
   path. An env var is invisible in the command line itself, can be set once and silently affect
   every subsequent invocation in a session/shell, and — critically — can be set by anything that
   controls the process environment (a wrapper script, a CI job, a prompt-injected shell command)
   without that control surfacing anywhere near the hook-persistence decision itself. That gap in
   auditability, not the mere fact that an agent could type it, is what makes an env-var knob a
   strictly larger attack surface than the footgun this ADR closes.
5. **`doctor --fix`'s automatic `RunInstall` repair path (`run_install_repair`) requires no code
   change.** It already resolves `source_exe` via `resolve_stable_exe_path(current_exe())` with
   `InstallOptions::source_is_explicit` left at its `Default` (`false`), so it is automatically
   subject to the same `install()` gate — the existing generic `Err(e) -> [FAILED] {e}` reporting
   in `doctor.rs`'s repair loop already surfaces the new rejection message without modification.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Env-variable escape (`OMAMORI_ALLOW_DEV_HOOK_PATH` or similar) | An AI agent operating in this threat model can set arbitrary env vars for its own subprocess invocations. A knob that lets the running process opt itself out of the provenance check is a persistent-hijack escalation path, not a legitimate developer convenience — the same reasoning that ruled out env escapes elsewhere in this batch (#321's provider taxonomy). |
| Reject unconditionally, including explicit `--source` | Breaks the documented recovery path (`omamori install --hooks --source <path>` is exactly how a user recovers from a fail-closed lockout, per #353/#355). Also breaks every existing integration test that legitimately passes `--source <CARGO_BIN_EXE_omamori>` to exercise install/setup against the freshly-built test binary. |
| Put the check inside `resolve_stable_exe_path`/`resolved_current_omamori_exe` directly | Blast radius too large — these are shared by `integrity` baseline generation and other consumers that have nothing to do with hook/shim persistence and should not be affected by a provenance policy scoped to exec-path persistence. |
| Leave `setup.rs`/`doctor.rs`'s implicit resolution out of scope (match the original, narrower plan) | Investigation found these are not equivalent-or-lesser risk to `regenerate_hooks_with_verifier`'s original scope — `setup` in particular is the single most-exercised implicit-resolution call site in this codebase's own CI (six subprocess tests spawn the freshly-built test binary through `setup` with no override), and is also the documented "one-command onboarding" flow most likely to be run directly from a dev checkout. Shipping #354 scoped only to the silent self-heal path while leaving `setup`/`doctor --fix` exposed would leave the PR's own stated thesis unmet for its two most realistic entry points. |
| Give `setup.rs` a test-only `#[cfg(test)]` override instead of a real `--source` flag | Doesn't work: the seven affected tests spawn `setup` as a genuine subprocess (`Command::new(binary())`), and `cfg(test)` gates compiled-in behavior for the unit-test binary, not the ordinary release/debug binary the subprocess tests actually invoke. A real, production `--source` flag was the only mechanism that could reach a spawned child process. |

## Consequences

- `omamori setup` gained a `--source PATH` flag it previously lacked. This is additive and
  backward compatible — omitting it preserves today's implicit-resolution behavior (now subject to
  the new check).
- Seven existing `setup_*` subprocess tests in `tests/cli.rs` were updated to pass
  `--source <CARGO_BIN_EXE_omamori>` explicitly, since their entire premise (spawn the just-built
  test binary and expect `setup` to succeed) is structurally the implicit-dev-build-path shape this
  ADR rejects by design. This is not a workaround for the tests specifically — it is the same
  escape hatch a real developer running `cargo run -- setup` from a checkout would need to use.
- `regenerate_hooks_with_verifier` was split into a thin exe-resolving wrapper plus an
  exe-injectable `regenerate_hooks_for_exe(base_dir, stable_exe, verify)`, and `shim.rs`'s
  `ensure_hooks_current_at_with_verifier_and_exe(base_dir, verify, exe_override)` gained the same
  exe-injection parameter directly (the old 2-arg `ensure_hooks_current_at_with_verifier` wrapper
  was removed as dead weight once every caller moved to the 3-arg form — /simplify review). Both
  changes exist because several pre-existing in-process unit tests rely on the *test harness's own*
  `current_exe()` as a stand-in "some working exe" — which is itself always a
  `target/debug`/`target/release` path under `cargo test`, and would otherwise trip this ADR's own
  check before those tests reach what they're actually exercising (version/hash-mismatch detection,
  verification-failure handling, throttling). This extends the *spirit* of #349's contract-verifier
  injection seam to the exe-path dimension, not its exact shape: across `InstallOptions.verify_override`
  (an `Option` struct field), `regenerate_hooks_for_exe`'s mandatory `stable_exe` parameter, and
  `..._and_exe`'s `Option<&Path>` parameter, this PR introduces two more DI conventions rather than
  reusing #349's exactly (/simplify reuse review) — noted as a real but non-blocking inconsistency;
  unifying all of them into one seam shape would be a larger refactor than this PR's scope.
- `CARGO_TARGET_DIR` customization (building outside the default `target/` directory name) is a
  known, accepted limitation — it evades the path-component check. This is a safety guard against
  the common case, not a hard security boundary; the actual security boundary (which binary a user
  trusts enough to explicitly name) is unaffected by this gap.
- **Fixed during Phase 8 Security Review**: the original adjacency-only check (`target` immediately
  followed by `debug`/`release`) missed `cargo build --target <triple>`'s standard cross-compile
  layout, `target/<triple>/debug|release/...` — a real, easily-reached Cargo behavior, not a
  hypothetical. `is_dev_build_path` now also checks a 3-component window (`target`, one arbitrary
  component, then `debug`/`release`), matching Cargo's two documented layouts without opening up to
  an unbounded "target anywhere, debug/release anywhere later" match. Accepted tradeoff: a
  non-Cargo path shaped like `target/<anything>/release/...` now also matches, which only means a
  legitimate stable install gets asked to pass `--source` explicitly — a safety-guard false
  positive, not a bypass.
- `omamori setup --dry-run` does not preview this check: the dry-run branch returns before
  `source_exe` resolution happens, so a dry run from a dev checkout (no `--source`) reports "would
  install hooks" even though the real run would be rejected. Known, accepted gap — fixing it would
  require resolving `source_exe` earlier in `run_setup_command` purely to annotate the preview
  output, adding real-path-resolution side effects to what is otherwise a pure preview path. Left
  as a follow-up if the discrepancy proves confusing in practice.
- `auto_setup_codex_if_needed` (the shim's Codex-specific auto-configure step, called alongside
  `ensure_hooks_current` from the same silent self-heal entry point) is also gated by the same
  `is_dev_build_path` check, for the same reason: it resolves `current_exe()` implicitly and would
  otherwise persist a dev-build path into the Codex hook wrapper the moment `CODEX_CI` is detected.
