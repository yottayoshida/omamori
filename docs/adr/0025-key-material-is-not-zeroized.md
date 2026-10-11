# ADR-0025: Key material is not zeroized

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-463-475-486-fixture-and-key-store-decisions.md`
- **Issues**: [#475](https://github.com/yottayoshida/omamori/issues/475)

## Context

Key bytes reach memory in several places and are dropped without being cleared: the keyring
held across a whole `verify_chain`, the signing key an `AuditLogger` carries for its lifetime,
the copy a prune point keeps while verifying, and the hex strings `read_secret` and
`create_secret` build. #475 proposed clearing them before 1.0, on the grounds that 1.0 would
freeze the types involved. SECURITY.md recorded the gap as a residual of the 1.0 gate and called
clearing them "worth doing as hardening".

Neither premise holds now. 1.0.0 shipped on 2026-08-08, and the types were never public:
`SigningKey` and `Keyring` are `pub(super)`. The public functions that take key bytes —
`audit::provenance::hmac_cwd` and `ProcessProvenance::as_audit_fields` — borrow them as
`Option<&[u8; 32]>`, which a buffer that clears itself could still lend. And clearing omamori's
own buffers would not clear memory of key material, because of the HMAC implementation:

- omamori uses `hmac` 0.12.1 and `sha2` 0.10.9 (`Cargo.lock`). `hmac_bytes`, `hmac_targets` and
  `hmac_cwd` construct an `HmacSha256` from the key on every call. Construction copies the key
  into a 64-byte block, XORs it with the inner and then the outer pad, feeds each into a fresh
  hash state, and drops the block — the key XOR a constant — without clearing it. None of
  `hmac` 0.12.1, `digest` 0.10.7, `sha2` 0.10.9 or `block-buffer` 0.10.4 clears on drop.
- The two hash states compute any HMAC without the key until the HMAC is finalized; with
  `hmac`'s `reset` feature off, as omamori builds it, finalizing updates them in place, so what
  is dropped at the end is no longer key-equivalent.
  Copies made while they were — wherever the value is moved, which depends on inlining — are not
  something a drop can reach.
- `hmac` 0.13.0 constructs the same way and leaves the 64-byte block uncleared too. Its
  `zeroize` feature only forwards to `digest`; clearing the hash states is `sha2` 0.11's own
  `zeroize` feature (`Drop for Sha256VarCore`), and it clears them only as they are when dropped.
- Moving any value in Rust copies its bytes; a buffer that clears itself on drop still leaves
  the bytes it was moved from.

## Decision

omamori does not clear key bytes from memory. Anything that can read another process's memory
as the same OS user can read `audit-secret` off the disk instead, which SECURITY.md's Defense
Boundary records as **Not protected**, so clearing would not move the boundary. And clearing
would not leave memory free of key-equivalent bytes, for the reasons above. A core dump taken
while omamori runs holds the key it is using whether or not buffers are cleared on drop.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Clear omamori's own types (`ZeroizeOnDrop` on `SigningKey`, `Keyring`, `PruneBind`; a wiped buffer for the hex strings) | The HMAC implementation still drops the key XOR a constant uncleared on every HMAC. A new dependency for a result that does not hold. |
| Upgrade to `hmac` 0.13 / `sha2` 0.11, enable `sha2`'s `zeroize`, and clear omamori's own types | The 64-byte block is still left behind, and the change moves the code that signs every audit entry and adds dependencies, with no change in what an attacker can reach. Declined by the maintainer on 2026-10-11. |
| Compute HMAC without the crate, or with another one, to control every buffer | Replaces the code that signs every audit entry to remove a residue the boundary already concedes, and moves of the key between frames would still copy it. |

## Consequences

- SECURITY.md's #475 paragraph states this as a decision, with the reason and what clearing
  would leave behind. The disclosure-side check ("no path reaches a log line or an error
  message") is unchanged.
- #475 is closed as not planned.
- **Revisit when** a copy of an omamori process's memory can reach someone who cannot read
  `audit-secret` — a crash report sent off the machine, say. Then what stays in memory becomes
  the question to answer first, starting with the HMAC implementation's key block.
