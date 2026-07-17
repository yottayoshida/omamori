# omamori 1.0 Product Contract

> **What this document is**: the frozen set of guarantees omamori makes, what it explicitly does not guarantee, and how to verify each guarantee yourself. It exists so a reader can decide whether to depend on omamori without reading the full source tree.
>
> **What this document is not**: a restatement of [SECURITY.md](../SECURITY.md)'s defense-boundary detail. Where this contract needs to point at "everything we know can and cannot be caught," it links there instead of copying it — SECURITY.md is the single, living source for that detail and grows independently of this document.

| | |
|---|---|
| Contract version | v1 |
| Effective date | 2026-07-17 |
| Applies to | Current releases through `1.0.0` and beyond, governed by the [breaking-change policy](#breaking-change-policy) below |
| Revision policy | Revised only for (a) a breaking change to a guarantee — bumps this contract's version, or (b) a wording clarification that changes no guarantee's scope — logged in the [revision log](#contract--crate-version-mapping--revision-log), no version bump |

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
| Which tools is a guarantee contractually pinned to? | **This document** (see [Supported tier](#supported-tier)) — SECURITY.md's "supported" status describes *current test coverage*, not a contractual commitment; see the [known inconsistency note](#known-inconsistency-securitymd-releasemd-and-readmemd-vs-this-contract) below |
| How do I recover from a false positive? | [docs/FAQ.md](FAQ.md) |

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
- **Contract**: Claude Code only. Recorded events only — this does not extend to fields SECURITY.md documents as outside the hash chain (e.g. process-provenance fields, see [SECURITY.md → Process Provenance](../SECURITY.md#process-provenance-v0131-420)), nor to events an append failure kept out of the chain in the first place.

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
omamori --help
```
(the `override <disable|enable> <rule>` line it prints is the only supported path to change core policy — a deliberate human-initiated action, not something an AI agent's `config.toml` edit can trigger)

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

Tier membership is **not frozen by this contract** — which tools currently sit in which tier is a living fact, tracked in [README's Tool Compatibility table](../README.md#tool-compatibility), not pinned here. That table's `Supported` status describes active hook/shim integration, not a contractual commitment on its own — it does not distinguish Tier 1 from Tier 2 by itself, which is why README cross-references this section rather than the table alone being the last word on tiering. What *is* frozen is the tier structure's meaning: moving a tool from Tier 1 to Tier 2 (removing a contractual commitment) is a breaking change; moving a tool from Tier 2 to Tier 1 (adding one, backed by verification) is not.

This tier structure applies only on macOS — omamori has no runtime behavior on any other platform.

### Known inconsistency: SECURITY.md, RELEASE.md, and README.md vs. this contract

As of this contract's effective date, three other documents describe Codex CLI with more confidence than Tier 2 implies: SECURITY.md's status legend defines "supported" as "tested, expected to work" and lists several rows as `supported (Claude Code, Codex CLI)`; RELEASE.md's v1.0 release gate lists live-path acceptance for Codex CLI as a 1.0 shipping requirement; and README's Tool Compatibility table lists Codex CLI's Status as plain `Supported`, the same word it uses for Claude Code, without a tier distinction (README does cross-reference this section for the distinction — see [Supported tier](#supported-tier) above — but the table cell itself is unchanged). None of the three is rewritten by this PR. This is a known, tracked inconsistency — tracked in [#423](https://github.com/yottayoshida/omamori/issues/423) — the intent is to bring all three in line with the tiering above, not to silently let the gap stand.

---

## Breaking-change policy

Effective from `1.0.0` onward, a change is breaking (requires a major version bump) if it falls into one of these three surfaces:

| Surface | Breaking | Not breaking |
|---|---|---|
| Rule-matching behavior | A command class previously blocked or redirected under Tier 1 becomes unprotected (block → allow) | Adding new coverage; narrowing a false-positive |
| CLI | Removing a subcommand or flag, or changing what a documented exit code means | Adding a subcommand, flag, or exit code |
| Audit-chain verification | A chain written by an older release fails `omamori audit verify` on a newer release without an accompanying migration path | A schema addition that preserves verifiability of prior chains (e.g. a version-gated migration) |

`config.toml` schema compatibility is explicitly **not** one of these three surfaces (see [Not guaranteed](#not-guaranteed--10-out-of-scope) above).

Two changes are already planned before 1.0 and are accounted for by this policy rather than exceptions to it: [#177](https://github.com/yottayoshida/omamori/issues/177) (an audit-chain schema version bump, shipped with a verification migration path) and [#175](https://github.com/yottayoshida/omamori/issues/175) (a `normalize_path` public API signature change). Neither requires this contract's wording to change — the policy is written at the level of "does verification survive," not at the level of a specific schema value or function signature.

---

## Contract ↔ crate version mapping & revision log

| Contract version | Crate versions | Notes |
|---|---|---|
| v1 | `0.13.1` onward | Initial publication |

Revisions are appended below, never rewritten in place, so the history of what changed and why stays visible.

---

## Recovery

If omamori blocks something you believe is a false positive:

- One-off: [`omamori break-glass`](FAQ.md#one-off--break-glass) (human-initiated, time-limited, audit-logged)
- Recurring: [adjust the ruleset](FAQ.md#recurring--adjust-the-ruleset)
- Full troubleshooting: [docs/FAQ.md](FAQ.md)
