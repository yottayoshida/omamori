# omamori 1.0 Product Contract

> **What this document is**: the frozen set of guarantees omamori makes, what it explicitly does not guarantee, and how to verify each guarantee yourself. It exists so a reader can decide whether to depend on omamori without reading the full source tree.
>
> **What this document is not**: a restatement of [SECURITY.md](../SECURITY.md)'s defense-boundary detail. Where this contract needs to point at "everything we know can and cannot be caught," it links there instead of copying it — SECURITY.md is the single, living source for that detail and grows independently of this document.

| | |
|---|---|
| Contract version | v1 |
| Effective date | 2026-07-17 |
| Applies to | Current releases through `1.0.0` and beyond, governed by the [breaking-change policy](#breaking-change-policy) below |
| Revision policy | Revised only for (a) a breaking change to a guarantee — bumps this contract's version, (b) a wording clarification that changes no guarantee's scope — logged in the [revision log](#contract--crate-version-mapping--revision-log), no version bump, or (c) an expansion of a guarantee's scope (more is now verifiably true, nothing that previously verified stops verifying) — also logged in the revision log, no version bump; the [breaking-change policy](#breaking-change-policy) below already defines "adding new coverage" as non-breaking, so (c) makes that consequence explicit here rather than leaving expansions to be squeezed into (b)'s "wording only" framing |

---

## At a glance

Guarantees ([full list](#guarantees)):

- [G-1](#g-1-covered-destructive-command-classes-are-blocked-or-redirected) — covered destructive command classes are blocked or redirected
- [G-2](#g-2-a-recorded-hook-deny-event-is-protected-by-a-tamper-evident-audit-trail) — a recorded hook deny event is protected by a tamper-evident audit trail
- [G-3](#g-3-installed-defense-layers-can-be-checked-for-presence-and-integrity) — installed defense layers can be checked for presence and integrity
- [G-4](#g-4-hook-checks-are-local-and-deterministic) — hook checks are local and deterministic
- [G-5](#g-5-core-policy-cannot-be-disabled-by-an-ai-agent) — core policy cannot be disabled by an AI agent
- [G-6](#g-6-failure-inside-the-guard-fails-closed-observably) — failure inside the guard fails closed, observably

Also see: [Not guaranteed / 1.0 out-of-scope](#not-guaranteed--10-out-of-scope) · [Supported tier](#supported-tier) · [Breaking-change policy](#breaking-change-policy)

---

## Authority map

Different questions about omamori have different sources of truth. When two documents appear to disagree, use this table to resolve which one governs:

| Question | Governing document |
|---|---|
| What does omamori currently catch or not catch, in full detail? | [SECURITY.md's Defense Boundary Matrix](../SECURITY.md#defense-boundary-matrix-v0101) |
| How do I verify a specific claim right now? | [README's Verifiable Claims table](../README.md#verifiable-claims) |
| What is omamori committing not to break, and until when? | **This document** |
| Which tools is a guarantee contractually pinned to? | **This document** (see [Supported tier](#supported-tier)) — SECURITY.md's "supported" status describes *current test coverage*, not a contractual commitment |
| How do I recover from a false positive? | [docs/FAQ.md](FAQ.md) |
| Do I still need a sandbox if I use omamori (or vice versa)? | [docs/reference-architecture.md](reference-architecture.md) |
| How and when can I disclose a bypass I reported? | [SECURITY.md's Disclosure timeline](../SECURITY.md#disclosure-timeline) |

---

## Guarantees

Each guarantee below separates three things that are easy to conflate:

- **Mechanism** — where the underlying code actually runs. omamori's detectors key off environment variables, not tool identity, so a mechanism that fires "when an AI environment is detected" fires the same way regardless of which AI CLI set that variable.
- **Verification** — which tool's behavior is exercised by the acceptance test suite on every release.
- **Contract** — which tool this document commits to, i.e. what a regression here counts as *breaking* under the [breaking-change policy](#breaking-change-policy).

Today, verification and contract are both scoped to Claude Code only (see [Supported tier](#supported-tier)) — Codex CLI and Cursor are not held to a contractual commitment here even though the underlying mechanism runs the same way for any detected AI environment.

### G-1: Covered destructive command classes are blocked or redirected

For the destructive command classes SECURITY.md's Defense Boundary Matrix lists as caught, a command matching one of them is blocked or redirected (e.g. moved to Trash) rather than executed, when an AI environment is detected.

- **Mechanism**: fires for any environment variable pattern in `default_detectors()`, independent of which tool set it.
- **Verification**: Claude Code, on every release, via the acceptance test suite.
- **Contract**: Claude Code only.

**Verify:**
```bash
omamori test
```

**Boundary**: [SECURITY.md → Defense Boundary Matrix](../SECURITY.md#defense-boundary-matrix-v0101) for the exact command classes covered, and what is not covered by design or by structural limit.

### G-2: A recorded hook deny event is protected by a tamper-evident audit trail

When an event omamori's hook layer denies is successfully appended to the audit log, that entry becomes part of a hash-chained, HMAC-signed sequence — a same-user attacker who alters or removes a chained entry produces a detectable chain break.

This guarantee covers the entries that make it into the chain, not the completeness of appending itself: append is best-effort with respect to the underlying block decision — a failure to append (config load error, missing secret, disk full, permissions) does not flip the decision (the command stays blocked), but it does leave that specific event unrecorded, surfaced instead as a stderr warning at the time.

- **Mechanism**: `AuditLogger::append` on the Layer 1/2 deny paths. Layer 1 append-on-deny is tool-agnostic (fires for any detected AI environment). Layer 2 audit-chain integration is currently Claude Code / Codex CLI only — Cursor's Layer 2 denies are stderr-only today and do not reach the audit chain at all (see the Boundary link below).
- **Verification**: Claude Code.
- **Contract**: Claude Code only. Recorded events only — this does not extend to events an append failure kept out of the chain in the first place, nor, on a `chain_version: 1` entry specifically, to fields SECURITY.md documents as outside that entry's hash (process-provenance fields and `wrapper_kind`; see [SECURITY.md → Process Provenance](../SECURITY.md#process-provenance-v0131-420) and [SECURITY.md → Channel separation](../SECURITY.md#channel-separation-v095-invariant-maintained)). On a `chain_version: 2` entry, both are covered — see the `CHAIN_VERSION` 2 revision log entry below.

**Verify:**
```bash
omamori audit verify
```

**Boundary**: [SECURITY.md → Audit Log](../SECURITY.md#audit-log-v070) for schema, HMAC design, and what tampering the chain does and does not detect. See specifically [SECURITY.md → Audit-append failure semantics (SEC-7)](../SECURITY.md#audit-append-failure-semantics-sec-7) for the append-failure behavior this guarantee excludes, and [SECURITY.md → Forensic semantics](../SECURITY.md#forensic-semantics-v098) for the Cursor exclusion.

### G-3: Installed defense layers can be checked for presence and integrity

Whether the PATH shim, hooks, config, and core policy baseline are installed and unmodified since the last check is queryable on demand.

- **Mechanism**: file-presence and content-hash checks against the installed shim/hook/config paths.
- **Verification**: Claude Code.
- **Contract**: Claude Code only.

**Verify:**
```bash
omamori doctor
omamori status
```

**Boundary**: [SECURITY.md → Integrity Monitoring](../SECURITY.md#integrity-monitoring-v050) for what the two-tier check does and does not detect.

### G-4: Hook checks are local and deterministic

A hook decision is computed from the command text and static configuration only — no model inference, no network call, no non-deterministic input.

- **Mechanism**: `check_command_for_hook()` and its callees; this is a property of the code path itself, not of which tool invoked it.
- **Verification**: source inspection + CI (this guarantee has no single push-button command — see the scope note below).
- **Contract**: applies to the mechanism as a whole; not tool-scoped.

**Verify:** source inspection (`src/engine/hook.rs`, `src/unwrap.rs` — no external calls) and CI, which runs offline.

**Boundary**: none beyond the mechanism itself; this is a structural property, not a coverage claim.

### G-5: Core policy cannot be disabled by an AI agent

The built-in rule set cannot be turned off through `config.toml`, and self-modification commands (`config disable`, `uninstall`, hook/config file edits, environment-variable unsetting) are blocked while an AI environment is detected.

- **Mechanism**: Core Policy Immutability + Phase 2 self-protection rules, independent of which detected tool issues the command.
- **Verification**: Claude Code, via the acceptance test suite.
- **Contract**: Claude Code only.

**Verify:**
```bash
CLAUDECODE=1 omamori config disable rm-recursive-to-trash
```
Setting `CLAUDECODE=1` simulates an AI-tool environment; the rejection cites the detected AI tool (`claude-code`), not the core-rule id. Drop the env var and the same command is still rejected, but now citing a "core safety rule" instead — that always-on layer holds regardless of AI detection. `omamori override disable <rule>` is the only supported path to change core policy, and it's part of what gets blocked while an AI environment is detected — a deliberate human-initiated action, not something an AI agent's `config.toml` edit can trigger.

**Boundary**: [SECURITY.md → Core Policy Immutability](../SECURITY.md#core-policy-immutability-v050).

### G-6: Failure inside the guard fails closed, observably

When the guard itself fails (parse error, resource limit exceeded, unexpected internal error), the outcome is a block, not a silent pass-through — and that failure mode is one of a fixed, documented set, not an unbounded one.

- **Mechanism**: the failure-mode table in SECURITY.md's Fail-Close Guarantees; independent of which detected tool triggered the failing command.
- **Verification**: Claude Code, via hook integration tests.
- **Contract**: Claude Code only.

**Verify:** `omamori doctor` reports guard health; the fixed failure-mode set is enumerated in the boundary link below (there is no single command that forces every failure mode — this is a structural property, verified by inspection and CI, similar to G-4).

**Boundary**: [SECURITY.md → Fail-Close Guarantees](../SECURITY.md#fail-close-guarantees).

---

## Not guaranteed / 1.0 out-of-scope

### Not guaranteed (structural — see SECURITY.md for detail)

The following are **not** covered by any guarantee above. This list names categories only; for the specific bypass classes, structural limits, and rationale behind each, see the linked SECURITY.md sections — this document does not duplicate that catalogue.

- Commands and bypass techniques SECURITY.md documents as [not caught by design or by structural limit](../SECURITY.md#defense-boundary-matrix-v0101)
- `config.toml` schema and field compatibility — a `config.toml` written for one release is not guaranteed to parse identically on a future release (unlike the three surfaces the [breaking-change policy](#breaking-change-policy) does cover)
- Any tool or shell not listed in the [Supported tier](#supported-tier) below
- Complete mediation of destructive actions taken through means other than the shell commands omamori's rule set covers (native editor Write/Edit tools, non-shell APIs, etc.)

### 1.0 out-of-scope

Not planned for 1.0, independent of the guarantees above:

- Windows support
- LLM-based command classification (omamori is deterministic-only by design)
- Hierarchical policy packs (org/project/user layering)
- Exhaustive shallow multi-tool support / rule-count competition with other tools

---

## Supported tier

**Tier 1 — contractually guaranteed, verified on every release**: Claude Code, on macOS. This is the only tool the guarantees above are pinned to.

**Tier 2 — expected to work, not contractually guaranteed**: Codex CLI, Cursor. The detection mechanism is tool-agnostic (it keys off environment variables any of these tools can set), so the guarantees above are expected to hold in practice — but there is no continuous acceptance verification against these tools today, so a regression specific to one of them is not treated as a breaking change under this contract.

Tier membership is **not frozen by this contract** — which tools currently sit in which tier is a living fact, tracked in [README's Tool Compatibility table](../README.md#tool-compatibility), not pinned here. That table's `Supported (Tier 1)` / `Supported (Tier 2)` cells reference the tiering for convenience; the meaning of each tier — what it does and does not commit to — is defined here, not there, which is why README cross-references this section rather than the table cell alone being the last word on what "Tier 2" implies. What *is* frozen is the tier structure's meaning: moving a tool from Tier 1 to Tier 2 (removing a contractual commitment) is a breaking change; moving a tool from Tier 2 to Tier 1 (adding one, backed by verification) is not.

This tier structure applies only on macOS — omamori has no runtime behavior on any other platform.

---

## Breaking-change policy

Effective from `1.0.0` onward, a change is breaking (requires a major version bump) if it falls into one of these three surfaces:

| Surface | Breaking | Not breaking |
|---|---|---|
| Rule-matching behavior | A command class previously blocked or redirected under Tier 1 becomes unprotected (block → allow) | Adding new coverage; narrowing a false-positive |
| CLI | Removing a subcommand or flag, or changing what a documented exit code means | Adding a subcommand, flag, or exit code |
| Audit-chain verification | A chain written by an older release fails `omamori audit verify` on a newer release without an accompanying migration path | A schema addition that preserves verifiability of prior chains (e.g. a version-gated migration) |

`config.toml` schema compatibility is explicitly **not** one of these three surfaces (see [Not guaranteed](#not-guaranteed--10-out-of-scope) above).

Two changes were accounted for by this policy before 1.0, rather than treated as exceptions to it: [#175](https://github.com/yottayoshida/omamori/issues/175) (a `normalize_path` public API signature change) and [#177](https://github.com/yottayoshida/omamori/issues/177) (an audit-chain schema version bump — `CHAIN_VERSION` 1→2, shipped with a verification migration path that keeps every prior `chain_version: 1` entry verifiable unchanged). Neither required this contract's wording to change — the policy is written at the level of "does verification survive," not at the level of a specific schema value or function signature.

---

## Contract ↔ crate version mapping & revision log

| Contract version | Crate versions | Notes |
|---|---|---|
| v1 | `0.13.1` onward | Initial publication |
| v1 | `1.0.0` | [#423](https://github.com/yottayoshida/omamori/issues/423): SECURITY.md/RELEASE.md/README.md's Codex CLI language reconciled with the Tier 2 definition above ("expected to work, not contractually guaranteed"), closing the "Known inconsistency" this document previously disclosed. Wording clarification only — no guarantee's scope changed, no contract version bump. |
| v1 | `1.0.0` | [#177](https://github.com/yottayoshida/omamori/issues/177) B3: `CHAIN_VERSION` 1→2. G-2's hash-chain protection now additionally covers `wrapper_kind` and the four process-provenance fields (`pid`/`ppid`/`parent_process`/`cwd_hash`) on `chain_version: 2` entries — previously excluded by design (ADR-0006). Every existing `chain_version: 1` entry remains verifiable unchanged; those fields stay outside the hash on v1 entries permanently (existing bytes are never rewritten, ADR-0007). Revision policy category (c): a scope expansion, not a breaking change or a wording-only clarification — added to the revision policy line above by this same change. No contract version bump. |
| v1 | `1.0.0` | [#457](https://github.com/yottayoshida/omamori/issues/457): key rotation no longer breaks chain verification. **Neither (b) nor (c) — a defect fix restoring documented behaviour.** No guarantee's wording or scope changes. Recorded here because G-2's stated Verify command did not work on any store that had rotated its audit key since v0.8.0 (2026-04-11): it reported a broken chain unconditionally. That was a false positive — the cryptographic property G-2 asserts was never broken, and logs in that state need no re-audit. One narrow counter-direction: an entry naming a key absent from the keyring used to be checked against the active key and could pass, so a store that reported `intact` while holding such an entry now reports `cannot verify` (exit 2) instead. That is a correction of a false negative, not a withdrawn guarantee — the entry was never actually authenticated under the key it named. See ADR-0008 and SECURITY.md → Key Rotation. No contract version bump. |

| v1 | `1.0.0` | [#457](https://github.com/yottayoshida/omamori/issues/457) PR-C1: the audit key store records the highest key epoch it has handed out (`audit-secret.epoch`). **Neither (b) nor (c) — a defect fix, with one verdict moving.** No guarantee's wording or scope changes, and the key store's on-disk layout is not one of the three surfaces the breaking-change policy freezes. Recorded here because a store that lost every retired key used to report its earliest entries as *tampering* (exit 1) and now reports them as *cannot verify* (exit 2) — a correction in the same direction as #457's counter-direction note above, since those entries were never authenticated under the key they named. Two smaller changes go with it: a record that cannot be parsed stops verification (exit 2) instead of being guessed past, and removing that file returns the store to the previous derivation. Binaries that predate the record ignore it. See ADR-0008's Update block and SECURITY.md → Key Rotation. No contract version bump. |

| v1 | `1.0.0` | [#470](https://github.com/yottayoshida/omamori/issues/470): a verification halt no longer suppresses tail-truncation detection. **Category (c) — a scope expansion — with a verdict moving, and the move is a stronger one than the two #457 rows above.** Those corrected a verdict that was false (a rotated store reported as tampered; entries that were never authenticated reported as intact); this one *displaces* two verdicts that were each true as far as they went. A store that both halts verification and is missing its tail used to report `cannot verify` (exit 2) or `unrecognized chain_version` (exit 4) — accurate statements about authentication — and now reports the truncation instead (exit 3), on all three surfaces that render a verdict: the `audit verify` exit code, `report --json`'s `chain_status`, and `doctor`'s risk line. A consumer branching on the exit code therefore sees a different value for a byte-identical file, which is why this is logged rather than folded into a release note. Nothing that previously verified stops verifying, and no guarantee's wording changes: G-2's tamper-evidence now holds in a state where it silently did not, and the state was reachable by editing one plain field of the log. The compared chain end is not itself authenticated — see SECURITY.md → [Truncation Detection Across a Halt](../SECURITY.md#truncation-detection-across-a-halt-470) for what that does and does not buy. No contract version bump. |

| v1 | `1.0.0` | [#471](https://github.com/yottayoshida/omamori/issues/471) / [#487](https://github.com/yottayoshida/omamori/issues/487): `ChainStatus::Unavailable` now means only "there is nothing to check yet". **Category (c) — a scope expansion — with a verdict moving.** Every failure `verify_chain` can return was enumerated; the two that mean nothing has been written are named and stay quiet, and the rest — a symlinked audit log or key, an interrupted key rotation, an unreadable key, an unresolvable `HOME` — now surface as the new `chain_status` value `inaccessible` instead of `unavailable`, and reach `doctor`'s risk signals instead of being filed as healthy. **The catch-all is inverted**, so a failure added later inherits "loud" rather than "quiet". Exit codes do not move: `audit verify` reported cannot-verify for all of these already. A `--json` consumer branching on `chain_status` therefore sees a new value where it previously saw `unavailable` for the same store, which is why this is logged rather than folded into a release note; consumers already had to handle new values, since the enum has carried `#[non_exhaustive]` since #457. No guarantee's wording changes: G-2's tamper-evidence is unaltered, and what changes is which surfaces repeat what `verify` was already saying. No contract version bump. |

Revisions are appended below, never rewritten in place, so the history of what changed and why stays visible.

| Contract version | Crate versions | Notes |
|---|---|---|
| v1 | `1.0.0` | [#506](https://github.com/yottayoshida/omamori/issues/506) / [#483](https://github.com/yottayoshida/omamori/issues/483): an unusable key store no longer suppresses the checks that need no key, and an entry omamori wrote unprotected no longer pins the store at cannot-verify. **Category (c) — a scope expansion — with verdicts moving in both directions.** #506 is #470's finding reached through a second door: five key-material failures returned before the high-water-mark comparison, which needs no key, so a store with its tail deleted *and* its key directory unreadable reported `cannot verify` (exit 2) and said nothing about the deletion. It now reports the truncation (exit 3), exactly as #470 made a halted store do. #483 moves a verdict the other way: an entry omamori itself wrote with no HMAC — which happens when the key directory cannot be listed — used to halt verification permanently, since ADR-0007 forbids rewriting entries. Such an entry is now walked past when two fields agree, so a store held at exit 2 by a past permissions fault verifies its other entries again; it stays at exit 2 while any unprotected entry is present, because those entries are genuinely uncheckable. Three `--json` values move for a byte-identical store: `chain_status` gains `unprotected` where a log with such entries previously read `key_unavailable`, `KeyringUnusable`'s `kind` reports `epoch_record_unreadable` where both fatal keyring conditions were previously flattened to `directory_unreadable`, and a store whose keys are unreadable reports `inaccessible`/`keyring_unusable` alongside a truncation rather than instead of it. No guarantee's wording changes: G-2's tamper-evidence now holds in two states where it silently did not. The compared chain end is still not authenticated — see SECURITY.md → [Truncation Detection Across a Halt](../SECURITY.md#truncation-detection-across-a-halt-470). No contract version bump. |

---

## Recovery

If omamori blocks something you believe is a false positive:

- One-off: [`omamori break-glass`](FAQ.md#one-off--break-glass) (human-initiated, time-limited, audit-logged)
- Recurring: [adjust the ruleset](FAQ.md#recurring--adjust-the-ruleset)
- Full troubleshooting: [docs/FAQ.md](FAQ.md)
