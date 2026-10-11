# ADR-0022: The audit log's `detection_layer` keeps its `:{wrapper}` suffix

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-393-395-459-hint-verb-position-wrapper-suffix.md`
- **Issues**: [#459](https://github.com/yottayoshida/omamori/issues/459) (closed by this decision); background [#177](https://github.com/yottayoshida/omamori/issues/177)

## Context

An audit row for a pipe-to-shell block that went through a transparent wrapper records the wrapper's basename twice: as the suffix of `detection_layer` (`layer2:pipe-to-shell:env`; `layer2:materialize:pipe-to-shell:env` on the materialize path) and as the standalone `AuditEvent.wrapper_kind` field. SECURITY.md documents the suffixed values in its `detection_layer` table.

#459 proposed retiring the suffix once `wrapper_kind` was a first-class, hash-protected field, so that the fact lived in one place. Its precondition — #177 B3, which folded `wrapper_kind` into `HashableEventV2` — shipped in 0.16.0, when `CHAIN_VERSION` became 2. On every `chain_version: 2` entry both carriers are now protected.

What the precondition did not change:

- **`chain_version: 1` entries are never rewritten** (ADR-0007). On those entries `wrapper_kind` is outside the hash and the suffix is the only protected copy of the attribution. Anyone reading a log started before 0.16.0 has to keep reading the suffix for as long as those entries exist, and without `retention_days` they exist indefinitely.
- **The suffixed values are documented**, and SIEM consumers may filter on them. Dropping the suffix from new rows would make such a filter stop matching without any signal.

## Decision

New audit rows keep writing the suffix. `wrapper_kind` remains the field to read on `chain_version: 2` entries; the suffix remains the value already documented and the only protected carrier on `chain_version: 1` entries. No sunset is scheduled.

This ADR covers the audit log. The `layer` field of `--json-error` output is documented to equal `detection_layer` exactly (SECURITY.md, `--json-error` schema), so it keeps the suffix as a consequence of that existing statement, not of this decision; changing `layer` on its own would be a separate decision that also has to revise that statement.

## Alternatives Considered

1. **Stop writing the suffix on new rows.** Removes nothing on the reading side — `chain_version: 1` entries still carry it and still need it — and gives every consumer a second shape to handle. Rejected: the cleanup does not simplify anything, it moves the redundancy into the consumers.
2. **Announce a deprecation now and remove the suffix later.** The reading-side argument above still holds after the removal, so the end state is the same two shapes, reached later. Rejected for the same reason.

## Consequences

- The redundancy is permanent and costs a few bytes per wrapped pipe-to-shell row. The two carriers agree because, at each of the two places that build an audit row for a structural verdict (the block path and the materialize path), both are derived from one `block_reason_wrapper_kind` result. Tests pin both paths — `hook_materialize_per_wrapper_format` and `hook_deny_blockstructural_pipe_to_shell_carries_wrapper_kind` assert the suffix and `wrapper_kind` together — and the `debug_assert_eq!` in `audit_log_hook_block_collect` checks the block path in debug builds.
- Removing the suffix later is a new decision: it needs a new ADR and a migration note for consumers of the documented values.
- SECURITY.md's "Channel separation" section and the source comments that pointed at #459 as a future sunset point here instead; ADR-0006 gets an update block saying so.
