# ADR-0013: Audit-layer warnings are returned; the caller decides where they go

- **Status**: Accepted (2026-09-11)
- **Date**: 2026-09-11
- **Issue**: [#494](https://github.com/yottayoshida/omamori/issues/494)

## Context

`hook-check --json-error` promises that every deny path writes a single JSON object to stderr
(SECURITY.md, "`hook-check --json-error` schema"). The audit layer printed operator warnings to
stderr from inside itself — while loading the signing key (`load_signing_key_locked`), while
appending (high-water-mark and prune messages in `AuditLogger::append`, the prune in
`retention.rs`), and around it in `engine::hook` (config-load failure, append failure, detector
warnings via `repair_gate_reporting`). Any of those lines ahead of the JSON object breaks the
contract.

PR1b (v0.10.3) resolved the conflict by not auditing at all in `--json-error` mode, and
SECURITY.md recorded it as a trade-off: a command blocked in a `--json-error` run left no row in
the audit chain. The contract was also already false elsewhere on the same path: a structural
block printed its config-load and degraded-config warnings ahead of the JSON, and a break-glass
bypass that could not be audited under `[audit] strict = true` blocked with text only.

The codebase already had the shape that removes the conflict, in one place:
`detector::repair_gate` returns its warnings, and `repair_gate_reporting` is the thin wrapper that
prints them — "the caller knows where its other warnings go".

## Decision

Functions that raise operator lines on the hook path push them onto a `&mut Vec<String>`; a
wrapper prints them for every caller that carries them nowhere else:

- `secret::load_signing_key_with` takes the collector (its test helper `load_signing_key`
  prints); `load_or_create_secret` is the collecting form's test-only printing wrapper
- `AuditLogger::from_config_collect` / `from_config`, `append_collect` / `append`;
  `from_config_throttled` prints what it collects
- `retention::try_prune` takes the collector; `try_prune_at`, used by tests, prints
- `detector::repair_gate_collect` / `repair_gate_reporting`, one spelling of the line for both
- in `engine::hook`: the Layer 2 block audit (`audit_log_hook_block_collect` /
  `audit_log_hook_block`), the materialize audit, the structural policy routing
  (`resolve_structural_block`), the break-glass branch, and `check_command_for_hook_inner`
  (its two wrappers print)

`run_hook_check_command` prints the collected lines first, in the order they were produced, for
every outcome except a `--json-error` block; a `--json-error` block appends its row and then emits
one JSON object carrying them in an optional `warnings` array, present only when non-empty. A
break-glass bypass is an allow unless its audit fails under `[audit] strict = true`; that block has
no row to append, and its branch emits the object carrying the lines it collected (under
`--json-error`) or prints them. Every existing entry point outside the hook keeps its signature and
prints as before.

`mod audit` denies `clippy::print_stderr` outside tests. `audit::print_warnings` — which every
printing wrapper calls — and three prints that are not on the hook path (`audit hash-cwd`'s
keyring report and two `audit key rotate` messages) carry an `#[allow]` with a `// reason:`
comment. A new `eprintln!` elsewhere in `mod audit` fails CI's `cargo clippy -- -D warnings`.

The lint's boundary is `mod audit`, not the contract's: the hook-side glue in `engine::hook` and
the structural routing are outside it, and are held by the tests in `tests/cli.rs` that parse
`--json-error`'s stderr as one object and pin text mode's output.

## Alternatives Considered

- **`SigningKey` carries warnings; each of the ~9 production callers of `from_config` decides
  where to print** (the shape #494 suggested). Covers the key-loading warnings only — the
  append-time warnings would still reach stderr in `--json-error` mode — and touches every caller.
- **Thread-local capture of stderr output.** No signature changes, but nothing in a function's
  type says its output can be redirected. The codebase passes such dependencies explicitly
  (e.g. `env_pairs` instead of `std::env::set_var`).
- **Drop the warnings in `--json-error` mode.** Makes a degraded key store silent in exactly the
  mode used by AI agents.

## Consequences

- A blocked shell command in a `--json-error` run is recorded in the audit chain, as in text mode.
  SECURITY.md's "audit gap" trade-off is removed.
- `--json-error` output gains an optional `warnings` field. It carries every line the block's
  handling would have printed, notes included: with a healthy store and configuration it is absent
  except on the run whose append triggers the audit log's periodic prune (`omamori: pruned N audit
  entries …`). An invalid detector entry in `config.toml` puts its warning there on every block.
- Deny paths that text mode does not audit either (malformed input, protected file operations)
  are unchanged.
- Text-mode output is unchanged: the wrappers print what they collected immediately, in the order
  it was produced.
