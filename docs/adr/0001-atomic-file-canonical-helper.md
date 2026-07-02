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
  covers the remaining two.
- `atomic_create_new` — direct `create_new` on the target, no rename, for sites with a
  no-clobber contract (`config::write_new_config` fresh-create path). **PR2**, landing
  alongside that call site's migration — adding it unused in PR1 would be dead code
  under `-D warnings`.

Both enforce unconditionally: `create_new` (O_EXCL), `O_NOFOLLOW`, mode set at creation
time, CSPRNG-randomized temp names, `fsync` on the file and parent directory, and
Drop-based temp cleanup on error. No caller-supplied flag can weaken any of these —
mode is the only parameter.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Make `installer::atomic_write_with_mode` `pub(crate)` and reuse it | It has no fsync (weakest durability of the 8 sites); reusing it as-is would regress 4 sites that currently fsync |
| `durable()` / `fast()` presets (opt out of fsync per call site) | A knob is a lever an adversary or a future careless caller can pull; hot-path analysis showed no site needs the opt-out (heartbeat ≤1 write/day, audit-warn 5-min throttle, installer only on install/drift) |
| AlreadyExists fallback via `remove_file` + retry (mirrors `audit::write_hwm`) | Reintroduces a TOCTOU deletion window; CSPRNG-suffix retry achieves the same liveness without it |
| Single entry point (no `atomic_create_new` variant) | `write_new_config`'s fresh-create path is a no-clobber contract (config.rs:882); forcing it through the rename-based path turns a fail-closed race (AlreadyExists) into a fail-open one (silent clobber) |

## Consequences

- All 7 in-scope sites will gain `O_NOFOLLOW` (break_glass currently lacks it) and
  CSPRNG temp names (closing the #322-class race for good, not just at the heartbeat) —
  5 of the 7 as of PR1, the remaining 2 (`config.rs`, `installer.rs`) in PR2.
- `fsync` will be added to `installer.rs` in PR2, a strict durability improvement with
  no measurable hot-path cost (already added to the heartbeat/audit-warn sentinels in
  PR1).
- Stale-temp self-recovery (relied on fixed temp names in the migrated sites) is
  replaced by an explicit best-effort GC inside the helper (age > 24h, strict
  `.omamori-tmp-` prefix, symlink-safe).
- `audit::write_hwm` / `audit::secret` remain on their own hand-rolled implementation
  until a follow-up issue migrates them; this is a deliberate, tracked residual, not an
  oversight.
- Until PR2 lands, `installer.rs` keeps its own private, differently-named
  `legacy_atomic_write_with_mode` (no fsync, non-CSPRNG counter-based temp suffix) —
  renamed in PR1 solely to avoid two functions sharing the name `atomic_write_with_mode`
  with different guarantees during the interim window.
