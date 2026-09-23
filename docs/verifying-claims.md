# Verifying the claims

The README's [Verifiable claims](../README.md#verifiable-claims) table, explained in full: how each row is checked and where CI cannot reach.

## How these are checked

Reproduce the machine-checkable rows locally with one command: `./scripts/verify-claims.sh` (claim 4's dependency and source tripwires, offline and deterministic) plus `./scripts/pre-pr-check.sh` (the full local claims/invariants pass, including the `omamori test` corpus behind claims 1/3/5). `omamori test` itself is a point-in-time check — it confirms the covered rules are present and evaluating as expected the moment you run it; the guarantee that a rule-matching *regression* turns CI red is enforced separately, by the `test` job's cargo test suite, plus claim 4's dedicated tripwire — not by re-running `omamori test` against a deliberately broken rule.

**Which cargo tests back claim 1:**

`policy_test.rs`, plus `property_tests.rs`'s `COVERED_DESTRUCTIVE_RULES` corpus for classes outside `omamori test`'s own set (e.g. `chmod-777-block` / `git-clean-force-block`).


Three claims carry an honest limitation instead of an unqualified "CI-enforced":

- **Claim 2** covers **Claude Code / Codex `hook-check` Layer 2 deny events only**. Cursor's Layer 2 denies are stderr-only and do not reach the audit chain — see [SECURITY.md → Forensic semantics](../SECURITY.md#forensic-semantics-v098). `omamori audit verify` on an empty log exits `0`; that is "nothing to verify," not "nothing was missed" — the write-side coverage (that the audit chain actually gets appended to, on every path that reaches it) is pinned by one cargo test per `HookCheckResult` variant that reaches the audit chain. A log that is *not* empty but whose entries were written while the key store could not be read is a different case and exits `2`: those entries carry no HMAC, so they are recorded but uncheckable, and the exit code says so rather than counting them as verified.

  **Which cargo tests back claim 2:**

  `hook_deny_blockmeta_creates_audit_entry` / `hook_deny_blockrule_creates_audit_entry` / `hook_deny_blockstructural_creates_audit_entry` for the three deny variants, plus `hook_materialize_pipe_to_shell_creates_audit_entry` for the one allow-but-observable variant (`action="materialize"`).

- **Claim 3**: the detection logic and an isolated install (`--base-dir`) are CI-tested. Verifying a **real user's `$HOME`** and shell profile — the actual installed state on your machine — is something only you can do, by running `omamori doctor` yourself; that is not a gap CI can close.
- **Claim 4** is a negative claim ("no network dependency, no model call") and has no single push-button command that proves an absence — this is the one claim in the table with no existing behavioral test to lean on, so `claims-check` adds a dependency allowlist (every `Cargo.lock` crate name must be pre-approved — a new network-client crate fails CI) and a source tripwire (no network-API identifier in the hook-decision-path source) as the machine-enforced evidence. CI running offline is corroborating, not sufficient on its own.

Core-policy immutability (claim 5) has two layers, and the README row's "AI-driven" wording refers specifically to the second one. The always-on layer needs no AI environment to trigger: writing `enabled = false` for a core rule directly in `config.toml` is ignored, and the CLI's own `omamori config disable <core-rule>` is rejected too, citing a "core safety rule" — a human typing the same command sees the identical rejection. The layer this claim is actually about is separate: any `config disable` / `config enable` / `override disable` attempt is blocked outright while an AI environment is detected, before the core-rule check above even runs — a deliberate human-only escape hatch (`override disable` is the only supported path to change core policy, and it's part of what gets blocked). Run `CLAUDECODE=1 omamori config disable rm-recursive-to-trash` yourself to see that layer directly: setting `CLAUDECODE=1` simulates an AI-tool environment, and the rejection now cites the detected AI tool (`claude-code`), not the core-rule id; drop the env var and you'll see the always-on "core safety rule" rejection instead. See [SECURITY.md → Core Policy Immutability](../SECURITY.md#core-policy-immutability-v050).

G-6 (failure inside the guard fails closed, observably) has no README row — it is a structural property with no single verify command; see [docs/CONTRACT.md → G-6](CONTRACT.md#g-6-failure-inside-the-guard-fails-closed-observably).
