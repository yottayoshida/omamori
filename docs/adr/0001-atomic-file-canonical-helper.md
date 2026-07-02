# ADR-0001: atomic_file as the canonical atomic-write helper, no weakening knobs

- **Status**: Accepted
- **Date**: 2026-07-02
- **Plan**: `.claude/plans/2026-07-02-atomic-write-consolidation.md`

## Context

Eight independent implementations of the temp-file → write → fsync → rename pattern
existed across the codebase (heartbeat, audit-warn sentinel, break-glass state, config,
integrity baseline, config_cmd, installer, audit HWM/secret). Strength varied widely:
some had no `fsync`, some used predictable temp names vulnerable to pre-creation races
(#322), one (`break_glass::write_state`) lacked `O_NOFOLLOW` entirely. Issue #307
proposed consolidation; #311 proposed unifying symlink rejection; #322 identified the
pre-creation race in the heartbeat writer specifically, but investigation found the same
defect in four other sites.

## Decision

Introduce a single `pub(crate)` module `src/atomic_file.rs` as the canonical write path
for all content-replacement writes (excluding `audit::write_hwm` and `audit::secret`,
which are already at the target strength and sit on the audit hot path — deferred to a
follow-up issue). The helper exposes two entry points, landed incrementally across two
PRs so each PR ships only the code it actually uses:

- `atomic_write_with_mode` — temp file + rename, for sites where an existing target may
  legitimately be replaced. **Landed in PR1**, wired to the five call sites that had the
  #322-class pre-creation race: heartbeat, audit-warn sentinel, `break_glass::write_state`,
  and `integrity::write_new_file` — the last of which is itself called from both
  `integrity::write_baseline` and `config_cmd::mutate_config`, so migrating it alone
  covers the remaining two. **PR2** additionally migrated `config::write_default_config`'s
  force-overwrite branch and all 14 `installer.rs` call sites (replacing that module's own
  fsync-free, non-CSPRNG implementation).
- `atomic_create_new` — direct `create_new` on the target, no rename, for sites with a
  no-clobber contract. **Landed in PR2**, wired to `config::write_default_config`'s
  fresh-create branch — its only consumer.

Both enforce unconditionally: `create_new` (O_EXCL), `O_NOFOLLOW`, mode set at creation
time, CSPRNG-randomized temp names, `fsync` on the file and parent directory, and
Drop-based temp cleanup on error. No caller-supplied flag can weaken any of these —
mode is the only parameter.

`atomic_file::is_symlink` (#311) is the shared low-level primitive for the caller-side
target-symlink check described above; `config::reject_symlink` is a thin adapter over it
(PR2), keeping the public `reject_symlink_public(path, label) -> Result<(), AppError>`
signature — and all of its many call sites — unchanged.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Make `installer::atomic_write_with_mode` `pub(crate)` and reuse it | It has no fsync (weakest durability of the 8 sites); reusing it as-is would regress 4 sites that currently fsync |
| `durable()` / `fast()` presets (opt out of fsync per call site) | A knob is a lever an adversary or a future careless caller can pull; hot-path analysis showed no site needs the opt-out (heartbeat ≤1 write/day, audit-warn 5-min throttle, installer only on install/drift) |
| AlreadyExists fallback via `remove_file` + retry (mirrors `audit::write_hwm`) | Reintroduces a TOCTOU deletion window; CSPRNG-suffix retry achieves the same liveness without it |
| Single entry point (no `atomic_create_new` variant) | `write_new_config`'s fresh-create path is a no-clobber contract (config.rs:882); forcing it through the rename-based path turns a fail-closed race (AlreadyExists) into a fail-open one (silent clobber) |

## Consequences

- All 7 in-scope sites gained `O_NOFOLLOW` (break_glass previously lacked it) and CSPRNG
  temp names (closing the #322-class race for good, not just at the heartbeat) — 5 of
  the 7 in PR1, the remaining 2 (`config.rs`, `installer.rs`) in PR2.
- `fsync` was added to `installer.rs` in PR2 (all 18 call sites; previously none of them
  fsynced), a strict durability improvement with no measurable hot-path cost (the
  heartbeat/audit-warn sentinels already gained it in PR1).
- `installer.rs`'s 4 script-writing call sites (Claude/Codex hook wrappers) now set
  `0o755` at file creation instead of the old rename-then-`chmod` dance, closing the
  window where a freshly (re)generated hook script briefly existed non-executable.
  `installer.rs`'s other 10 data-writing call sites move from umask-derived permissions
  to a fixed `0o600` — a user-visible permissions tightening, to be noted in the
  `[0.11.9]` CHANGELOG entry at release time (per this repo's convention of writing
  CHANGELOG entries at the release-bump commit, not per-PR).
- Stale-temp self-recovery (relied on fixed temp names in the migrated sites) is
  replaced by an explicit best-effort GC inside the helper (age > 24h, strict
  `.omamori-tmp-` prefix, symlink-safe).
- `audit::write_hwm` / `audit::secret` remain on their own hand-rolled implementation
  until a follow-up issue migrates them; this is a deliberate, tracked residual, not an
  oversight.
- PR2 deleted `installer.rs`'s private `legacy_atomic_write_with_mode` /
  `atomic_write` / `tempfile_in[_with_mode]` / `AtomicTempFile` entirely — the module's
  `atomic_write(target, content)` and `atomic_write_script(target, content)` (new, 0o755)
  wrappers are now thin calls into the shared helper.
- **Incidental discovery during PR2, partially fixed**: two `installer.rs` tests that
  mutate the process-global `HOME` env var (`merge_claude_hybrid_extraction_preserves_user_hook_on_rerun`,
  `merge_claude_does_not_delete_untagged_user_entry`) were missing the
  `#[serial_test::serial(home_env)]` tag every sibling test uses — a genuine,
  pre-existing bug (confirmed present on `main` before this PR) — and are now fixed.
  However, **this does not close the whole flake class**: running the full suite
  repeatedly (30+ runs on `main` post-PR1, 30+ on this branch) reproduces low-frequency
  (~3-5%) failures in *other*, unrelated test groups on both — e.g.
  `context::tests::git_context_sanitizes_git_dir_env` (a `set_current_dir`-mutating
  test using the *default* `#[serial_test::serial]` group, not `home_env`) and
  `integrity::tests::check_claude_settings_fails_on_non_executable_script` (a
  `home_env`-tagged test failing with the same "hash mismatch" symptom this PR
  originally attributed to the two missing tags). Since these reproduce identically on
  `main` with none of this PR's changes present, they are **not caused by this PR** —
  tracked as a separate pre-existing test-suite stability issue (#344) rather than
  claimed as resolved here. A third instance (`installer::tests::merge_claude_cleans_legacy_entry_without_version_tag`,
  2/30 full-suite runs on this branch vs 0/30 on `main`) surfaced during review;
  running only the `merge_claude` test group in isolation 20/20 times found no
  failure, and every function on its assertion path is pure (explicit parameters
  only, no env/global state) — consistent with the same full-suite-only,
  system-contention-shaped flake #344 already tracks, not a distinct bug in this
  PR's migration logic. Logged as an additional data point on #344 rather than as
  a fourth issue.
