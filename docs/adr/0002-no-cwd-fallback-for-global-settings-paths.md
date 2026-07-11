# ADR-0002: No CWD fallback for global settings paths; tests must be structurally unable to reach real HOME

- **Status**: Proposed
- **Date**: 2026-07-05
- **Plan**: `.claude/plans/2026-07-05-omamori-210-test-home-isolation.md`

## Context

omamori's own test suite corrupted the maintainer's real `~/.claude/settings.json` and
`~/.codex/hooks.json` on two consecutive days (2026-07-04, 2026-07-05). `install`/`uninstall`
resolve the merge target via `claude_home_dir()`/`codex_home_dir()`, which read `$HOME`. Eight
call sites (6 subprocess tests in `tests/integration.rs`/`tests/cli.rs`, 2 in-process tests in
`src/installer.rs`) invoke `install`/`uninstall` with a throwaway `--base-dir` but without
pinning `HOME`, so the merge target resolves to the developer's real `$HOME` — and the hook
entry it writes points at the temp `--base-dir`, which is deleted at test end, leaving a
dangling command path that fail-closes every subsequent Bash call in Claude Code.

Three of those eight sites additionally used `env_remove("HOME")` rather than leaving `HOME`
untouched. Combined with a `.` (CWD-relative) fallback in `claude_home_dir()`/`codex_home_dir()`,
this hit the repository's own `./.claude/settings.json` instead of the real `$HOME` — the same
class of bug via a second path. Issue #210 (opened 2026-04-30) diagnosed the first path and was
closed as "not planned": zero production impact, small contributor population, ~500-line
estimated fix. The recurrence rate — both incidents triggered by ordinary `cargo test` runs
inside dev worktrees — invalidated that cost/benefit call, and #210 was reopened.

## Decision

1. **Remove the `.` fallback.** `claude_home_dir()`/`codex_home_dir()` return `Option<PathBuf>`;
   `None` when `HOME` is unset *or empty* (`HOME=""` normalizes to the same `None`, not
   `PathBuf::from("").join(".claude")`). A CWD-relative path is never a correct resolution for a
   global settings file — the caller has no reliable way to know what `./.claude` means in an
   arbitrary process's working directory. All 8 callers (4 for claude, 4 for codex) treat `None`
   as "not detected" and skip the merge/remove/check, never falling through to a relative path.
   `doctor`'s equivalent check returns `Warn` (not `panic!`) on `None`, matching its existing
   "not configured" outcome.
2. **In-process tests get compile-time isolation, not env-var isolation.** `InstallOptions` gains
   a single `home_override: Option<PathBuf>` field — not separate `claude_dir`/`codex_dir` fields.
   `claude_home_dir()`/`codex_home_dir()` both derive from the same `$HOME`
   (`.join(".claude")`/`.join(".codex")` respectively), and every call site that needs an override
   needs it for both, so one field models the actual domain variable ("what `$HOME` should this
   resolve against") instead of two fields that always move together. Production callers pass
   `None` via `..Default::default()`, deferring to step 1's env resolution. Adding the field to a
   `pub` struct is a breaking change to any external `struct`-literal constructor — landed as part
   of the 0.12.0 bump. This is a second, independent layer from step 1: `field == None` means
   "resolve from environment", `env == None` means "not detected" — the two `None`s are not the
   same thing and both are documented as such.

   `regenerate_hooks()` and `auto_setup_codex_if_needed()` are sibling functions that also merge
   into `~/.codex/hooks.json` but aren't reached by `InstallOptions`, and neither is currently
   exercised by a test that reaches the merge branch (traced during review). An earlier revision
   of this PR added a matching override parameter to both, reasoning that leaving them on env-only
   resolution would be the same "isolation discipline can be forgotten" gap this ADR argues against
   for `install()` — just deferred to whoever writes the next test of the `doctor --fix`
   hook-repair path or the `CODEX_CI` auto-setup path. That reasoning doesn't actually transfer
   from a struct field to a plain function parameter: a struct field's preventive value comes from
   `Default`-literal enumeration forcing every *current* call site to be re-examined when the field
   is added; a function parameter has no such effect on call sites that don't yet exist — the
   *next* isolation discipline lapse would show up as a straightforward compile error when someone
   eventually adds the parameter for a real test, exactly as adding it today would have. Carrying an
   always-`None` parameter through 5+ production/test call sites in the meantime is speculative
   generalization for a test that doesn't exist, so the parameter was removed; the gap is noted
   here instead, to be closed with the same pattern if/when a test actually needs it.
3. **Subprocess tests get explicit `HOME` injection**, since they cross a process boundary DI
   cannot reach. All 6 sites pin `HOME` to a fresh temp dir instead of leaving it untouched or
   removing it. The 3 sites that previously used `env_remove("HOME")` to test XDG-based config
   resolution keep that intent — `XDG_CONFIG_HOME` still takes precedence over `HOME` in
   `config.rs`'s resolution order, so pinning `HOME` doesn't change what those tests verify.
4. **The uninstall delete-path is treated as equally severe as the install dangling-path.**
   `remove_claude_settings_entry`/`remove_codex_hooks_entry` resolving to the real `HOME` doesn't
   just leave a broken reference — it silently deletes the developer's real canonical hook entry,
   disabling Layer 2 with no error and no dangling-path symptom to notice. The uninstall test now
   pins the same injected `HOME` for both its install and uninstall subprocess calls.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Heuristic guard: reject `install`/merge when `base_dir` looks like a temp path (`/tmp`, `$TMPDIR` prefix) | Structurally unreliable — macOS real temp is `/var/folders/...` (not `/tmp`), CI runners use `$RUNNER_TEMP` at arbitrary paths, and any non-matching path (a legitimate `--base-dir` outside temp) bypasses it entirely. Confirmed independently by three investigation angles (QA, security, architecture) before being ruled out. |
| Runtime sentinel env var (e.g. `OMAMORI_TEST_SANDBOX`, panic if merge target falls outside it) | Adds a test-only branch to the production binary's control flow — a defense mechanism that only exists to compensate for test discipline, not a property of the tool itself. A CI-side canary check (see Consequences) achieves the same detection without touching `install`'s logic. |
| Keep the `.` fallback, just fix the 8 test sites | Doesn't remove the root cause — the *next* test someone writes without knowing this history reintroduces the bug. #210 was closed once already under this reasoning and reopened after two real incidents in as many days. |
| Env-var injection for the 2 in-process tests too (skip the `InstallOptions` DI fields) | `unsafe { std::env::set_var(...) }` in-process requires `#[serial_test::serial(home_env)]` and manual save/restore — a discipline that has already been forgotten at least twice in this codebase's history (see ADR-0001's "Incidental discovery" note). A typed `Option<PathBuf>` field makes "did I forget to isolate this" a compile-time question instead of a runtime one. |

## Consequences

- `InstallOptions` is no longer safely constructible with positional/partial struct literals that
  omit the new fields — call sites must use `..Default::default()` or name the fields explicitly.
  This is intentional: the compiler now enumerates every production call site whenever the struct
  gains a field, which is what surfaced 3 previously-unlisted call sites
  (`src/cli/doctor.rs`, `src/cli/install.rs`, `src/cli/setup.rs`) during this change.
- `default_base_dir()` (installer.rs) and `hook.rs`'s staging-dir resolution retain their own `.`
  fallback for `HOME` unset. These are deliberately out of scope: they resolve omamori's *own*
  install root, which is self-contained and doesn't merge into a file another tool (Claude Code,
  Codex CLI) owns — the failure mode this ADR closes (silent cross-tool corruption) doesn't apply.
- This PR does not add the CI-side canary check (pin `HOME` to a throwaway dir for the whole
  `cargo test` run, assert the real `~/.claude`/`~/.codex`/repo `./.claude` are byte-identical
  before and after) or the shared isolated-`Command` test helper. Both are deferred to a follow-up
  PR: a naive `sha256sum` diff on real files is a check that only fires if it fires — it needs to
  create files at all 3 target paths before the run to be a canary rather than a no-op on CI
  runners that don't have `~/.claude` in the first place. Bundling that into this PR would mix a
  behavior-preserving isolation fix with new CI infrastructure.

### Follow-up (#356): `scripts/test-isolation-canary.sh` landed

The CI-side canary deferred above shipped in #356. Design departs from the sketch above in two
ways learned from getting it actually working:

- **Sentinel placement, not a bare `sha256sum` diff on real files.** The canary creates its own
  fresh throwaway `HOME` (seeded with sentinel `.claude/settings.json`/`.codex/hooks.json`) and
  pins the wrapped command's `HOME`/`XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_CACHE_HOME` to it —
  it does not run the test suite against the developer's/runner's real `HOME` at all. The real
  `$HOME/.claude`, `$HOME/.codex`, and repo-local `./.claude` are still snapshotted (read-only,
  never created if absent — no-clobber) and re-checked after the run as defense-in-depth, but the
  primary detection mechanism is "did anything write into the throwaway HOME I handed the test
  suite", not "did the real HOME change". This sidesteps the "no-op on CI runners without
  `~/.claude`" problem entirely, since the throwaway HOME's sentinels always exist.
- **Wraps an arbitrary command (`test-isolation-canary.sh -- <cmd...>`), not just `cargo test`.**
  `ci.yml`'s `test`, `proptest-deep`, and `coverage` jobs each run a different underlying command
  (`cargo test --locked`, `cargo test --locked --lib property_tests::prop_ -- --nocapture`,
  `cargo tarpaulin --locked --out xml --skip-clean`); the wrapper takes the real invocation as its
  argument list instead of hardcoding one.
- **`--self-test` is a permanent CI job** (`test-isolation-canary-self-test`), not a one-off local
  check: it seeds the same throwaway sentinels, corrupts one directly (what a leaking test would
  do), and asserts the comparison logic reports it — proving the detection fires rather than
  vacuously always passing, on every CI run.
- **Building the canary found a real, then-undetected isolation gap**:
  `shim_argv0_without_hook_check_still_enters_shim` (`src/lib.rs`) calls `run()` in-process with
  argv0 `git`, which reaches `run_shim()` → `ensure_settings_current()` (`src/engine/shim.rs:53`)
  unconditionally, before executing the wrapped command — an ambient-`HOME`-resolving merge path
  this ADR's step 2 DI fields don't cover, because it isn't reached through `InstallOptions` at
  all. The test passed its own narrow assertion (only checked the error variant) while silently
  writing a re-synced `settings.json` into whatever `HOME` the test process happened to have —
  exactly the "future test forgets isolation, undetected because it still passes" scenario this
  ADR exists to prevent, caught here by the canary rather than by a third real-file incident.
  Fixed by pinning `HOME` to a throwaway dir for the duration of that one test
  (`#[serial_test::serial(home_env)]`, matching the existing convention), since `HomeGuard`
  (`src/installer.rs`) lives in a private `mod tests` and isn't reachable from `src/lib.rs`'s own
  test module.
- **Known limitations, unchanged from the original sketch**: only catches writes that resolve
  through `HOME`/`XDG_*` env vars (a test hardcoding an absolute path outside these would not be
  caught); a test that deletes a sentinel and recreates byte-identical content is not caught
  (content is compared, not mtime/existence-transition). This is a backstop for the #210 incident
  class specifically, not a general filesystem sandbox.
- **QA verification found a second, CI-specific gap the local Codex review rounds could not**:
  swapping `HOME` to an empty throwaway dir for the wrapped `cargo test`/`cargo tarpaulin`
  invocation risks breaking rustup-managed cargo installs (GitHub Actions runners install Rust via
  `actions-rust-lang/setup-rust-toolchain`, which is rustup-based) — rustup's proxy binaries
  resolve the active toolchain and registry/dependency cache via `RUSTUP_HOME`/`CARGO_HOME`,
  defaulting to `$HOME/.rustup`/`$HOME/.cargo` when unset. An unpinned `HOME` swap would make the
  wrapped `cargo` think no toolchain is installed, forcing a cold reinstall (or a hard failure) and
  bypassing the setup action's cache entirely. Fixed by resolving `CARGO_HOME`/`RUSTUP_HOME` to
  their real pre-swap locations (`${CARGO_HOME:-$HOME/.cargo}`, same for `RUSTUP_HOME`) and passing
  them through explicitly alongside the `HOME` override. This did not surface during local manual
  testing (repeated `cargo test`/`cargo tarpaulin` runs through the canary, all green) because the
  local development machine's `cargo` is a standalone Homebrew binary, not a rustup proxy — it
  doesn't consult either variable for toolchain resolution at all. Caught only by QA reasoning
  through the CI runner's actual toolchain-installation mechanism, not by execution; verified with
  a real CI run on the PR before merge (see PR for the confirming run) rather than trusted on
  static analysis alone.
- Two known, unrelated defects surfaced during shape enumeration and adversarial review are
  explicitly **not** fixed here, to keep this PR's scope to the HOME-isolation contract: Codex
  CLI's `merge_codex_hooks` orphans entries from prior install roots on multi-root duplication
  (existing behavior, no regression), and `remove_codex_hooks_entry` lacks the symlink guard
  `remove_claude_settings_entry` has. Both are candidates for follow-up issues.
