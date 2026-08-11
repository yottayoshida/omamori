# ADR-0009: Config-authoritative detection for disclosure, built-in detection for enforcement

- **Status**: Proposed
- **Date**: 2026-08-11
- **Plan**: `~/.claude/plans/prancy-seeking-axolotl.md`
- **Issue**: [#527](https://github.com/yottayoshida/omamori/issues/527), supersedes the scoping in
  [#519](https://github.com/yottayoshida/omamori/issues/519)

## Context

omamori asks "is an AI agent reading this session?" for two unrelated purposes, and until now both
questions were answered from the same list.

**Enforcement** — `guard_ai_config_modification` (`engine/guard.rs`) refuses config-mutating
subcommands when a detector matches. It reads `config::default_detectors()`, the built-in list.
Reading the operator's own `[[detectors]]` here would be self-defeating: an agent that can narrow
the list can unlock the guard that stops it from narrowing the list.

**Disclosure** — SEC-R5 withholds literal repair instructions (the sentence that names a file and
says what to do to it) from a session an agent is reading. The gate calls `is_ai_environment()`
(`cli/doctor.rs`), which also reads the built-in list.

The shim, meanwhile, decides whether to enter its protected path from
`load_result.config.detectors` (`engine/shim.rs`) — the merged configuration. `config.rs`'s
`build_merged_config` resolves `user.detectors.unwrap_or_else(default_detectors)`, so declaring a
single `[[detectors]]` entry **replaces** the built-in list outright rather than extending it.

The two answers therefore disagree in both directions:

| Operator's config | Shim's verdict | Gate's verdict | Result |
|---|---|---|---|
| adds a detector for a tool omamori does not ship with | protected (AI) | not AI | **the repair is printed into the session the gate exists to withhold it from** |
| narrows or replaces the defaults | not protected (human) | AI | the repair is withheld from a terminal the operator declared is not an AI session |

The first direction is a gate that reports success while not holding.

## Decision

**Disclosure decisions read the configuration the invocation actually loaded. Enforcement
decisions keep reading the built-in list.**

The asymmetry is deliberate, and it follows from what each decision protects:

- Enforcement answers "may this actor change omamori's own protection?" The actor is the party
  whose declaration would be consulted. A configuration-authoritative answer would let the subject
  of the rule write the rule.
- Disclosure answers "will this text be read by an agent?" The operator is the only party who
  knows which tools they run. omamori shipping a list of six env vars is a default, not a claim to
  know better than the person who configured the machine.

Concretely: the verdict travels from the caller that loaded the configuration, in the same way
`KeyWarnPolicy` already carries the throttle decision. `secret.rs` documents why that direction is
right — "the policy travels from the caller rather than being decided at the print site, because
the print site cannot tell an operator who typed a command from a shim that fired because one was
typed." A print site equally cannot tell which configuration produced the invocation it is
printing from.

### Scope of this ADR

This ADR settles which detector set is authoritative. It does not claim that every SEC-R5 call
site has been converted — `#527` converts the key-store repair path, and `doctor` / `explain` /
`setup` remain on `is_ai_environment()` under `#519`. Those conversions, when they happen, follow
this ADR rather than re-deciding it.

## Alternatives Considered

### Union of the built-in and configured lists — rejected

Matching either list would fail safe: narrowing `config.toml` could never unlock disclosure. It
was rejected because it honours the operator in one direction only. An operator who declares "this
is not an AI session" would still have repairs withheld, and the shim would take its human fast
path while the gate withheld — two parts of one invocation disagreeing about what the invocation
is, which is the defect this ADR exists to remove.

The safety argument for the union is also weaker than it looks. It protects against an operator
who narrows their own configuration, which is a configuration mistake, not an attack: an attacker
who can write `config.toml` can also add rules, remove rules, or point `audit.path` elsewhere.
Disclosure is not the surface that changes their position.

### Leaving the gate on the built-in list — rejected

This is the status quo. It leaves the first row of the table above intact: a detector added for a
tool omamori does not ship with puts the shim on its protected path while the gate answers "not an
AI session".

### `is_ai_environment()` loading the configuration itself — rejected

No threading required, but an invocation that passed `--config` would be judged against a
different file than the one it ran under. That is the same defect one level up.

### A process-global verdict set early in `main` — rejected

No signature churn, but any path that does not set it falls back to the old answer silently. The
property this ADR asks for is that the two answers *cannot* diverge; a global that callers may
forget to set preserves exactly the failure mode being removed.

## Consequences

- `AuditLogger::from_config` and `from_config_throttled` take the verdict as a parameter. This is a
  breaking change to a `pub` Rust API. `docs/CONTRACT.md` freezes rule matching, the CLI contract
  and audit-chain verifiability at 1.0; the Rust library API is explicitly outside that set.
- `config.toml` becomes a disclosure-control surface. It is covered by `PROTECTED_FILE_PATTERNS`
  and by `guard_ai_config_modification`, but neither stops a direct file write by the same OS
  user — `SECURITY.md` already records that trust level. The justification for this decision is
  that the operator's declaration is authoritative, **not** that the file is tamper-proof.
- Call sites that have no configuration in hand cannot make a disclosure decision. `setup` is the
  known case: `cli/setup.rs` decides before the point documented as failing ahead of any file I/O,
  so `load_config` cannot be placed there. Such sites stay on the built-in list and are recorded
  as residual risk rather than silently treated as converted.
- The enforcement guard keeps its own answer. A session that adds a detector gets its repairs
  withheld while still being able to run `omamori audit key rotate`, because the guard does not
  see the added detector. This is recorded in `SECURITY.md` as a residual risk; closing it means
  revisiting enforcement, which this ADR deliberately does not do.
