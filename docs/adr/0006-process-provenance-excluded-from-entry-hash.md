# ADR-0006: Process provenance fields are excluded from `entry_hash` (chain integrity)

- **Status**: Accepted
- **Date**: 2026-07-16
- **Plan**: `.claude/plans/vivid-petting-yeti.md`

## Context

Issue #420 adds `pid`/`ppid`/`parent_process`/`cwd_hash` to `AuditEvent`, following a real
incident (2026-07-16) where a repeating destructive command pair had to be traced using only
`target_hash`, with no way to correlate entries or identify the launching process. Whether these
new fields are folded into `HashableEvent` (the struct `entry_hash` is computed over — see
`chain.rs`) is a One-way Door decision: it determines whether every existing `audit.jsonl` chain
on every install remains verifiable without a version-aware verifier, and whether older omamori
binaries can still validate logs written by newer ones.

Three designs were considered:

1. **Design A**: keep provenance fields outside `HashableEvent`. `CHAIN_VERSION` stays at `1`.
2. **Design C**: bump `CHAIN_VERSION` from `1` to `2` now, folding provenance into the hashed
   struct as part of this PR.
3. **Design C′**: add the fields to `HashableEvent` via `skip_serializing_if`, without bumping
   `CHAIN_VERSION`.

Investigation surfaced that three independent reviewers (QA, UX, and the orchestrator itself)
converged on Design C′ before an architect subagent's direct read of `chain.rs::HashableEvent`
and issue #177 (which already charters a future `CHAIN_VERSION` 1→2 migration) revealed it to be
a trap — see Alternatives Considered.

## Decision

**Design A.** `CHAIN_VERSION` remains `1`. Provenance fields are added to `AuditEvent` only, via
the existing `Option<T>` + `#[serde(skip_serializing_if = "Option::is_none")]` pattern already
used for `chain_version`/`seq`/`prev_hash`/etc. — `chain.rs`'s `HashableEvent` and
`compute_entry_hash` are unchanged. Folding provenance into tamper-evidence is deferred to issue
#177's `CHAIN_VERSION` 1→2 migration.

This makes provenance the first `AuditEvent` payload in omamori's history that is *not*
hash-protected — see SECURITY.md's "Process Provenance" section for the full implication, and
note the explicit contrast drawn there with the v0.13.x config-mutation-events forward-compat
note (that note holds because it reuses *existing*, already-hashed fields for a new purpose;
provenance is the opposite case — genuinely new fields outside the hashed struct entirely).

## Alternatives Considered

| Option | Rejected because |
|---|---|
| (2) Bump `CHAIN_VERSION` to `2` now (Design C) | Implementation size: this would front-load issue #177's migration machinery (dual verifier dispatch across `chain_version` 1 and 2) — #177 itself flags this as its highest-risk, potentially product-killing component — for the sake of four forensic fields, well outside this PR's scope. |
| (3) `skip_serializing_if` inside `HashableEvent`, no version bump (Design C′) | Looks free (old entries with `provenance: None` serialize identically, so `GOLDEN_ENTRY_HASHES` and existing chains stay green) but is a trap: a *new* entry with real provenance data still reports `chain_version: 1`, yet its hashed content differs from what a v1 entry has always meant. An older omamori binary re-verifying that entry recomputes the v1 hash correctly but a downgrade or cross-version comparison scenario produces a hash mismatch that reads as tampering — a false positive. It also creates a third, undocumented state (`chain_version == 1` but provenance-hashed) that issue #177's planned v1/v2 verify dispatch cannot represent, breaking that migration before it ships. |
| Separate sidecar log for provenance | Correlating an incident would require joining two files instead of one, undermining the feature's own success criterion ("one grep, not a multi-file investigation"). |

## Consequences

- During the window before issue #177 lands, a same-user attacker with direct write access to
  `audit.jsonl` can alter `pid`/`ppid`/`parent_process`/`cwd_hash` on any entry without breaking
  the hash chain — `omamori audit verify` will not flag it. This is an accepted, scoped cost: the
  incident that motivated this feature involved no log tampering (all 16 entries verified clean),
  so chain-integrity coverage for these specific fields was not the priority.
- Protection for existing hashed fields (`command`, `target_hash`, `action`, etc.) is unchanged —
  this decision narrows what is *newly* unprotected, not what was already protected.
- Issue #177's current scope (titled around a `wrapper_kind` fold-in, targeting a stale
  "v0.10.0" milestone against a crate now at v0.13.0) does not yet mention
  `pid`/`ppid`/`parent_process`/`cwd_hash`. A fold-in request was added to #177 after this PR
  landed to keep the deferred work tracked rather than silently orphaned.

## Secondary Decision: `parent_process` granularity

Full path (`proc_pidpath`'s complete exec path) was adopted over basename-only (e.g. `node`).
Rationale: distinguishing which installed application a launcher actually was (e.g.
`/opt/homebrew/.../node` vs. an Electron app's bundled `node`) requires the full path — a
basename collapses exactly the distinction an investigator needs. This was weighed against the
risk of `/Users/<name>/...` exposure in a shared log and decided in favor of full-path
identifying power by yotta on 2026-07-16, informed by a prior real-world instance of pasting a
hash-bearing log excerpt into a public issue.
