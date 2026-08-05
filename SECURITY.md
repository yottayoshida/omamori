# SECURITY

## How to read this document

This document covers omamori's security model, threat analysis, and known limitations. Different readers want different things:

| If you are... | Read in this order |
|---|---|
| **An operator** evaluating omamori for your team | [Security Model](#security-model) → [What It Protects](#what-it-protects-v090) → [Defense Boundary Matrix](#defense-boundary-matrix-v0101) → [Structural Limits](#structural-limits) → [Safe Defaults](#safe-defaults) |
| **A security researcher** auditing the design, or reporting a bypass | [Reporting a Vulnerability](#reporting-a-vulnerability) → [Design Invariants](#design-invariants-v090) → [Bypass Corpus Testing](#bypass-corpus-testing-v041) → [Audit Log](#audit-log-v070) → [Integrity Monitoring](#integrity-monitoring-v050) |
| **A contributor** preparing a PR | [AI-assisted Contribution Invariants](#ai-assisted-contribution-invariants-v093) |

For end-user installation and CLI usage, see [README.md](README.md). For known limitations classified by closure status — closed in v0.9.x / decided out of scope / structural — jump to [Bypass Corpus Testing → Known limitations (KNOWN_LIMIT)](#known-limitations-known_limit).

---

## Reporting a Vulnerability

Found a way to bypass a guarantee this document claims omamori provides, or a way to defeat its self-defense (disabling or uninstalling it without the guard blocking that action)? Report it privately rather than filing a public issue.

**Channel**: [GitHub Private Vulnerability Reporting](https://github.com/yottayoshida/omamori/security/advisories/new) (GitHub Security Advisories, enabled on this repository).

**Response time**: omamori is a single-maintainer project. Response is best-effort; there is no fixed SLA.

**In scope**: a bypass of a guarantee documented in the [Defense Boundary Matrix](#defense-boundary-matrix-v0101) or the README's [Verifiable Claims](README.md#verifiable-claims) table; a way to circumvent omamori's self-defense.

**Out of scope**: anything already documented as a known-limit ([Structural Limits](#structural-limits), [Bypass Corpus Testing → Known limitations](#known-limitations-known_limit)) or a structural limit inherent to the PATH-shim + static-analysis approach (see README → [Scope and Limitations](README.md#scope-and-limitations)). These are welcome as regular GitHub issues, not private reports.

A report that leads to a fix follows the [Known-bypass-becomes-row rule](#known-bypass-becomes-row-rule): a new Defense Boundary Matrix row, a corpus test, and — if applicable — a new known-limit entry.

Please do not include exploit walkthroughs in public issues or PR descriptions; keep those in the private report.

> Verified against omamori **v0.13.1**. If a claim here disagrees with current repository state, trust the repository.

### Disclosure timeline

Pre-fix, a confirmed in-scope bypass stays private until a fix ships.

**Embargo upper bound**: 90 days from confirmation as an in-scope bypass. If 90 days pass with no fix, the reporter is free to disclose publicly.

The clock starts at confirmation, not at initial submission, so a low-quality or out-of-scope report does not start it. An interim acknowledgment or status update from the maintainer does not reset or extend the clock. This is the reporter's right to disclose, not a maintainer commitment to fix within 90 days; it does not change the best-effort, no-SLA posture stated above.

This right covers disclosing that the bypass exists, and how it was (or was not) mitigated — it is not an exception to this section's rule against exploit walkthroughs in public issues or PR descriptions: that rule applies regardless of embargo status, before and after the 90 days lapse.

A report can also be resolved by documenting the bypass as a structural limit (see [Known-bypass-becomes-row rule](#known-bypass-becomes-row-rule)) instead of shipping a fix. Documenting a limit is a valid resolution, not a stall — it starts the same post-fix disclosure path described below.

### Redaction policy

No discretionary redaction tier exists for omamori's own behavior. Once a bypass is resolved — by fix or by documenting it as a structural limit — it follows the [Known-bypass-becomes-row rule](#known-bypass-becomes-row-rule) in full: a Defense Boundary Matrix row, a corpus entry in `tests/hook_integration.rs`, and a known-limit entry where applicable. This is unchanged and remains full public.

**One narrow carve-out**: if a bypass is confirmed to chain through an unfixed third-party vulnerability (for example an unpatched OS or provider-sandbox flaw), the portion of the report that would disclose that third-party vulnerability is held until the third party ships a fix, or until the embargo above expires, whichever comes first. omamori's own mitigation, and the existence of the gap, are still disclosed on the normal timeline above — only the third-party exploit detail is withheld. Using this carve-out requires a known-limit entry recording the gap even while the detail is withheld, so the corpus stays honest about what it does not yet cover.

Payload and exploit-walkthrough detail is never published verbatim under this policy; the corpus test captures the class of the bypass, not attacker-ready reproduction steps.

### Corpus PR review criterion

A public pull request that adds a Defense Boundary Matrix row or a `tests/hook_integration.rs` corpus entry must not include exploit walkthroughs or step-by-step reproduction detail in its description, commit messages, or code comments — only the class of bypass and the fix. A reviewer may request changes to, or reject, a PR that violates this, citing this section.

---

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects (v0.9.0)

- recursive `rm` variants matched by the default rules
- `git reset --hard`
- force pushes
- destructive `git clean`
- `chmod 777`
- `find -delete` / `find --delete`
- `rsync --delete` and 7 variants (`--del`, `--delete-before`, `--delete-during`, `--delete-after`, `--delete-excluded`, `--delete-delay`, `--remove-source-files`)
- Custom rules defined via `config.toml`

### Defense Boundary Matrix (v0.10.1+)

<!-- boundary-matrix:start -->

What is caught, what is not, and why. Status values: **supported** (tested on Tier 1 — see [CONTRACT.md → Supported tier](docs/CONTRACT.md#supported-tier) — expected to work on Tier 2, since the underlying detection mechanism is tool-agnostic) · **partial** (covered in some but not all tool paths) · **not covered** (no protection at this layer, but another layer may cover it) · **not applicable** (this layer's mechanism does not apply to this surface) · **out of scope** (deliberate design decision) · **structural limit** (cannot be addressed by static analysis).

A machine-readable projection of this matrix (surface list + per-layer status, one object per row) is published at [`docs/defense-boundary.json`](docs/defense-boundary.json) (schema: [`docs/defense-boundary.schema.json`](docs/defense-boundary.schema.json)), kept row-for-row in sync by the `invariants-check` CI job. This is step 4 of the [Known-bypass-becomes-row rule](#known-bypass-becomes-row-rule).

#### Caught

| Surface | Layer 1 (shim) | Layer 2 (hook) | Verified by |
|---------|----------------|----------------|-------------|
| Destructive recursive removal (`rm -rf`) | supported | supported | `omamori test`, CI, hook integration |
| `git reset --hard` | supported | supported | `omamori test`, CI, hook integration |
| `git push --force` / `git clean -f` | supported | supported | `omamori test`, CI, hook integration |
| `chmod 777` | supported | supported | `omamori test`, CI, hook integration |
| `find -delete` / `rsync --delete` variants | supported | supported | `omamori test`, CI, hook integration |
| Full-path execution (`/bin/rm -rf`) | not covered | supported | Hook integration Phase 2 rule tests |
| Shell wrapper evasion (`sudo env bash -c "rm -rf"`) | not covered | supported | Hook integration unwrap tests |
| Pipe-to-shell (`curl URL \| bash` and wrapper variants) | not covered | supported | Hook integration pipe-to-shell corpus |
| Dynamic command generation (`bash -c "$(cmd)"`) | not covered | supported (fail-close) | Hook integration |
| PATH override bypass (`PATH=/usr/bin:$PATH rm`) | not covered | supported (v0.10.1) | Hook integration, acceptance test T-3' |
| Env-var tampering (`unset CLAUDECODE`, `export -n`) | not covered | supported | Hook integration env-tampering corpus |
| Self-disablement (`config disable`, `uninstall`) | supported (env guard) | supported (Phase 2 builtin rules) | Acceptance tests |
| Config/hook file editing (Edit/Write operations) | not applicable | supported (Claude Code Tier 1; Codex CLI Tier 2) | Hook integration file-protection tests |
| Static shell expansion obfuscation (`$'rm'`, `$"rm"`, `${IFS}rm`, `{rm,-rf,/}`, `r$'m'`) | not covered | supported (v0.10.2) | Hook integration `obfuscated-*`, unit tests |
| Self-modification commands in command context (`omamori config disable/enable/add`, `uninstall`, `init --force`, `override`, `doctor --fix`, `explain`, `break-glass`, `audit key rotate`) | supported (env guard) | supported (Phase 2 builtin rules `omamori-*-block`, v0.10.3+ DI-13) | `tests/config::omamori_self_protect_rules_match_via_phase2`, acceptance tests |

#### Not caught — by design

| Surface | Reason | Reference |
|---------|--------|-----------|
| Interpreter commands (`python -c "shutil.rmtree(...)"`) | Zero real-world incidents in target tools; protocol-level enforcement (MCP) is the right layer | [#74](https://github.com/yottayoshida/omamori/issues/74) |
| Commands outside the curated rule set | omamori guards a narrow set of known destructive patterns, not arbitrary commands | [Security Model](#security-model) |
| AI overwrites/destroys user source files via native Write/Edit tools | Command-guard scope: omamori observes Bash commands and protects its own files only; native editor-tool writes are outside the interception layer | Git hygiene (`git diff` before commit), AI tool file sandbox |

#### Not caught — structural limit

| Surface | Why | Mitigation |
|---------|-----|------------|
| Obfuscated commands (base64, hex, runtime variable indirection `X=rm; $X -rf`) | Static analysis cannot decode runtime-constructed commands. Note: *static* expansion (`$'rm'`, `${IFS}rm`, brace expansion) IS caught since v0.10.2; this row covers runtime-evaluated forms only | Sandbox isolation |
| Mid-word brace expansion at verb position (`r{m,}`) | `{` in mid-word is FP-prone (`file{.bak}`); prefix-only brace detection | Sandbox isolation |
| `bash -c "$VAR"` (variable set earlier in shell) | Requires runtime evaluation | Sandbox isolation |
| `alias rm='/bin/rm'` | Alias overrides bypass string matching | Layer 2 hooks cover AI tool paths |
| Heredoc / encoded payloads decoded at execution time | Static analysis boundary | Sandbox isolation |
| `source /dev/fd/N N<&0` (standalone fd-dup stdin alias) | Standalone: requires parsing `N<&0`-style redirections and fd equivalence tracking. However, when used after a pipe (e.g. `curl … \| bash -c 'source /dev/fd/3' 3<&0`), pipe-to-shell detection catches the `bash` launcher on the pipe RHS regardless of inner fd-dup content | Sandbox isolation (standalone); pipe-to-shell catches piped variant |

For per-tool hook coverage (Claude Code vs Codex CLI vs Cursor), see [Hook Coverage (Layer 2)](#hook-coverage-layer-2). For the full closure history, see [Known limitations (KNOWN_LIMIT)](#known-limitations-known_limit).

<!-- boundary-matrix:end -->

### Known-bypass-becomes-row rule

When a new bypass surfaces, the response is not just a code fix. It is also:

1. A row added to the Defense Boundary Matrix above.
2. A corpus entry added to `tests/hook_integration.rs`.
3. An entry in the [Known limitations](#known-limitations-known_limit) section (if closed) or Structural limits table (if not closable).
4. A mirrored entry in [`docs/defense-boundary.json`](docs/defense-boundary.json) (enforced by the `invariants-check` CI job).

This rule ensures that the boundary matrix and test corpus grow together and that bypass discovery is treated as a documentation event, not just a code event.

### v0.2.0 Security Changes

- **`enabled: false` and config.toml editing risk**: The `enabled` flag allows users to intentionally disable individual rules. This opens a new attack vector: an AI agent could attempt to edit `config.toml` to disable protection rules. Mitigations:
  - Config file requires `chmod 600` permissions (enforced at load time)
  - Violation of blocked destination paths **disables the rule** (enforcement, not just warning)
  - Users should not allow AI tools to edit `~/.config/omamori/config.toml`

- **`move-to` destination validation**: The `move-to` action validates destinations at two points:
  - **Config load time**: Absolute path required, blocked system prefixes checked via `canonicalize()`, symlinks rejected
  - **Runtime**: Directory existence, `is_dir()`, symlink re-check via `symlink_metadata()`, blocked prefixes re-checked via `canonicalize()` (catches paths created after config load)

- **Blocked destination prefixes**: `/usr`, `/etc`, `/System`, `/Library`, `/bin`, `/sbin`, `/var`, `/private`. Rules with blocked destinations are automatically disabled.

- **Basename collision avoidance**: When `move-to` processes multiple targets, a dedup suffix (`_2`, `_3`, ...) prevents same-named files from overwriting each other.

- **Cross-device move rejection**: `move-to` uses `rename(2)` which is atomic on the same filesystem. Cross-device moves (`EXDEV`) are rejected to avoid the TOCTOU window that copy+delete would introduce.

- **Staging subdirectory hardening against symlink planting (v0.13.x, #410)**: `move-to` quarantines targets into a timestamped subdirectory under the (already validated) destination. Prior to this hardening, that subdirectory was created non-exclusively (`create_dir_all`), so a symlink pre-planted at the predictable `<destination>/<unix-secs>` path would be followed, redirecting the quarantine `rename` to an attacker-controlled location. The subdirectory is now created exclusively (`create_dir`, which never follows a symlink at the target path and fails on any pre-existing entry) with a high-entropy random suffix; on a name collision the create is retried with a fresh random suffix (bounded, then fails closed) rather than a predictable sequential one, so an attacker cannot pre-occupy the whole candidate space. **Residual risk**: this closes pre-planted-symlink attacks only. A same-user active watcher process could still race between the exclusive create and the subsequent `rename` calls into it (delete-then-replant at the now-known real path); full closure would require fd-relative operations (`openat`/`renameat`), deferred as future hardening. This residual requires a local process with write access to the destination — at minimum the invoking user, who already has legitimate write access to wherever `move-to` is configured to point, watching the destination path closely enough to win that race window. World-writable, non-`sticky` destinations extend that requirement to any local user, not just the invoking one.

## Design Invariants (v0.9.0+)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DI-7 | `doctor --fix` is blocked in AI environments | `guard_ai_config_modification("doctor --fix")` — prevents baseline normalization to hide tampering |
| DI-8 | `explain` is blocked in AI environments | `guard_ai_config_modification("explain")` — prevents oracle attacks (probing which commands are blocked) |
| DI-9 | *(Retired in v0.10.4)* | Was: `doctor --fix` and `explain` in `blocked_string_patterns` (meta-pattern defense-in-depth). Protection now provided by Phase 2 builtin rules `omamori-doctor-fix-block` and `omamori-explain-block` (DI-13) |
| DI-10 | `doctor --fix` repair order: install → hooks → chmod → baseline (last) | Baseline must reflect the post-repair state, not the pre-repair state |
| DI-11 | Command separators `\n`, `\r`, `&` are normalized before tokenization | `normalize_compound_operators` treats unquoted newlines as `;` and space-separates `&` (excluding `&>`, `>&`, `2>&1` redirects) |
| DI-12 | Env var tampering detection is token-level, not string-level | Phase 1B `detect_env_var_tampering` uses `shell_words::split` after normalization, with `is_command_position()` to prevent false positives on quoted strings and arguments |
| DI-13 | Phase 2 builtin rules cover self-modification verbs (v0.10.3+, updated v0.10.4, updated for `config add` in v0.12.5, updated for `audit key rotate` in v0.13.x) | Eight `omamori-*-block` builtin rules in `default_rules()` block self-modification commands (`config disable/enable/add`, `uninstall`, `init --force`, `override`, `doctor --fix`, `explain`, `break-glass`, `audit key rotate`) via Phase 2 token-level rule matching. Each rule uses the `subcommand` field so `args[0]` must match exactly, preventing false positives like `omamori exec -- echo disable config`. Prior to v0.10.4 these served as defense-in-depth alongside Phase 1A meta-patterns; since v0.10.4 they are the primary Layer 2 defense for self-modification verbs. Enforced by unit tests `default_rules_includes_omamori_self_protect_eight_rules` + `omamori_self_protect_rules_skip_false_positive_data_args`. |
| DI-14 | *(Retired in v0.10.4)* | Was: data-context recognition via `strip_quoted_data` (v0.10.3). Removed with meta-pattern infrastructure — Phase 2 builtin rules use token-level matching that inherently distinguishes command context from data arguments via the `subcommand` field. |
| DI-15 | *(Retired in v0.10.4)* | Was: data-context substitution preservation via `subst_depth` tracking (v0.10.3). Removed with `strip_quoted_data` — no longer needed since meta-pattern substring matching is gone. |
| DI-16 | *(Retired in v0.10.4)* | Was: data-flag allow emits audit with `layer2:relaxed:*` tag (v0.10.3). Removed with the data-context heuristic — `relaxed_by` field is always `None`. |

### `hook-check --json-error` schema (v0.10.3+, extended in #249)

When `--json-error` is passed to `omamori hook-check`, **all deny paths** emit a single JSON object to **stderr** (in place of free-form text). Allow paths still emit the regular Claude Code hook response on stdout. AI agent integrations consume this for retry / approach-switch decisions.

**Scope**: the JSON contract applies to all deny paths — shell-command blocks (Phase 1B token detection / Phase 2 rule match / Phase 2 structural unwrap), malformed hook input, and file-op deny on protected paths. AI agents parse one format regardless of block reason.

**Schema**:

```json
{
  "blocked": true,
  "layer": "layer2:meta-pattern" | "layer2:rule" | "layer2:structural" | "layer2:pipe-to-shell:<wrapper>" | "layer2:obfuscated-expansion" | "layer2:input-validation" | "layer2:file-protection",
  "rule_id": "<rule_name or layer-specific identifier>",
  "reason": "<human-readable message>",
  "matched_pattern": "<pattern string>" | null,
  "matched_position": { "start": <usize>, "end": <usize> } | null,
  "hint": "<action guidance for AI agent>"
}
```

**Field semantics**:

- `blocked`: always `true` (allow path uses Claude Code hook response, not this schema)
- `layer`: forensic layer identifier prefixed with `layer2:` to match the audit log `detection_layer` field exactly. Stderr JSON `layer` and audit row `detection_layer` are interchangeable for correlation
- `rule_id`: for `BlockRule` it is the rule name (e.g. `omamori-config-modify-block`); for `BlockMeta` it is the reason string itself; for `BlockStructural` it is the constant string `"structural"`; for input validation it is `"invalid-input"`; for file protection it is `"protected-file"` when a `PROTECTED_FILE_PATTERNS` entry actually matched, or `"unresolvable-base"` (#175) when a *relative* `file_path` couldn't be evaluated at all because the process's working directory was unresolvable — see the `layer2:file-protection` row below
- `matched_pattern`: the protected pattern token when known. `null` for structural blocks, Phase 1B token-level detections, input validation errors, and the `"unresolvable-base"` fail-close case above (no pattern was ever evaluated, so none is reported)
- `matched_position`: byte range `[start, end)` of the match in the original command string when known; `null` when position tracking is not available for the layer
- `hint`: action guidance for the AI agent consumer. Shell-command blocks reference `omamori explain`; input validation and file protection blocks use a "Tell the user:" pattern directing the AI to inform the user and offer alternatives — the `"unresolvable-base"` case's hint explicitly says the file's protection status was never determined, not that it matched a protected pattern

**Layer values**:

| Layer | Deny path |
|-------|-----------|
| `layer2:meta-pattern` | Phase 1B token-level detection (env tampering, config commands) |
| `layer2:rule` | Phase 2 rule match (e.g. `rm-recursive-to-trash`) |
| `layer2:structural` | Phase 2 structural detection (no wrapper kind) |
| `layer2:pipe-to-shell:<wrapper>` | Phase 2 pipe-to-shell with wrapper (e.g. `env`, `bash`) |
| `layer2:obfuscated-expansion` | Phase 2 obfuscated expansion detection |
| `layer2:input-validation` | Malformed or incomplete hook input (JSON parse failure or missing fields) |
| `layer2:file-protection` | Protected file modification attempt (`rule_id: "protected-file"`), or a relative path that couldn't be evaluated because the working directory was unresolvable (`rule_id: "unresolvable-base"`, #175 — fail-closed, not necessarily a real match) |

**Security note — input validation errors**: `MalformedJson` and `MalformedMissingField` emit identical JSON (same layer, rule_id, reason) to minimize oracle exposure. Attackers cannot distinguish JSON parse failures from missing-field errors, preventing incremental input refinement. The reason string is static and never includes raw stdin content to prevent reflection attacks.

**Trade-off — audit gap in `--json-error` mode**:

When `--json-error` is active, the hook **skips audit log emission** for the blocked event. This trade-off keeps stderr a single parseable JSON object even in degraded audit environments (missing or unreadable audit secret, full disk, broken permissions) where `AuditLogger::from_config` would otherwise emit free-form warnings. AI agent integrations get a reliable contract; the cost is that `omamori audit show --action block` may miss events from `--json-error` invocations. Operators who need full audit coverage should not pass `--json-error`; the regular text-mode hook records the audit row even when it cannot print to stderr cleanly.

**Stability**: `blocked`, `layer`, `rule_id`, `reason`, `hint` are stable contract fields. Additional fields may be added in minor releases. AI agents should ignore unknown keys.

`guard_ai_config_modification` call sites: 9 (as of v0.9.0).

## Integrity Monitoring (v0.5.0+)

omamori verifies that its own defense layers are intact. This addresses the question: "who guards the guard?"

### Two-Tier Check

| Tier | When | What | Cost | Catches |
|------|------|------|------|---------|
| **Canary** | Every shim invocation | `.integrity.json` exists + own symlink target = omamori binary | ~0.05ms (stat + readlink) | Shim deletion/replacement |
| **Full check** (`omamori status`) | On-demand | All shims, hook content hash, config perms + hash, core policy, PATH order | ~5-10ms | All tampering including subtle hook edits |

### `.integrity.json` Baseline

- **Location**: `~/.omamori/.integrity.json`
- **Protection**: chmod 600, `O_NOFOLLOW`, atomic write (temp → fsync → rename), hook block list
- **Contents**: SHA-256 hashes of hooks and config, shim symlink targets, version, timestamp
- **Trusted transitions**: Auto-updates only from omamori-initiated operations (install, hook regen, config CLI). External edits produce WARN on next check, not auto-update

### Hook Content Hash (T2 fix, DREAD 9.0)

`ensure_hooks_current()` compares the SHA-256 of `render_hook_script()` (implementation-derived expected content) against the actual file on disk. This detects attacks where the version comment is preserved but the hook body is rewritten (e.g. `exit 2` → `exit 0`).

Using implementation-derived content as source of truth (not stored baseline) eliminates baseline tampering as an attack vector for hook verification.

### Hook Exec Path Contract Verification (#349, liveness only — accepted limitation)

Before persisting a resolved exec path into a hook script (`regenerate_hooks()`'s background self-repair, `install --hooks`), omamori spawns that path directly and confirms it actually satisfies the `hook-check --provider <provider>` CLI contract with a known-benign payload, in an environment isolated from the real user's `HOME`/`XDG_CONFIG_HOME` (so the probe's outcome doesn't depend on the user's own rules). This closes the class of bug where a stale/incompatible binary (e.g. a `cargo build` dev artifact resolved mid-session) gets silently baked into a hook, causing every subsequent Bash call to fail-close.

**This is a liveness check, not an authenticity check.** It confirms the resolved binary runs and responds to the expected CLI surface — it does not confirm the binary is the genuine, unmodified omamori release. A binary crafted to always return an ALLOW decision regardless of input would pass this verification unchanged. Detecting that class of tampering requires provenance/signature verification of the resolved binary, which is a separate, not-yet-implemented layer (tracked in #354). The exec-path resolution itself is also still subject to the TOCTOU window described below — verification narrows it but cannot close it, since the resolved path could in principle be swapped between the probe and the subsequent write (this requires write access to the resolved binary's path, which already implies the attacker controls what omamori itself would execute — a root-of-trust compromise, not a new privilege).

### TOCTOU Risk (accepted)

Canary checks point-in-time state. Tampering between checks is not detected until the next shim invocation. This is a structural limitation of the no-daemon design. A filesystem watcher or daemon would eliminate this gap but contradicts omamori's zero-daemon philosophy.

### Self-Defense for Baseline

| Attack | Protection |
|--------|-----------|
| AI edits `.integrity.json` (Claude Code Edit/Write) | Hook block pattern: `".integrity.json"` |
| AI edits `.integrity.json` (Cursor Bash) | `PROTECTED_FILE_PATTERNS` match |
| AI deletes `.integrity.json` | Canary detects missing file; auto-regenerates on next shim invocation |
| AI tampers baseline to match tampered state | Implementation-derived hook hash ignores baseline for hook verification |

## Core Policy Immutability (v0.5.0+)

The 7 built-in safety rules are structurally enforced in the binary. Config.toml cannot disable or weaken them.

### Immutability Scope

| Field | User can override? | Rationale |
|-------|-------------------|-----------|
| `enabled` | **No** | Core purpose of immutability |
| `action` | **No** (downgrade blocked; upgrade allowed) | `log-only` downgrade = effective disable |
| `command` | **No** | Changed command = rule never matches |
| `match_all` / `match_any` | **No** | Empty arrays = unexpected match behavior |
| `destination` | **No** | Tied to action semantics |
| `message` | **Yes** | Localization / customization. No security impact |

### Override Mechanism

For legitimate use cases (CI environments, solo developers), `omamori override disable <rule>`:
- Writes to `[overrides]` section in config.toml
- Blocked by `guard_ai_config_modification()` in AI context
- Blocked by hook patterns (`omamori override` string match)
- Restores with `omamori override enable <rule>`

### Design Decision: Structural > Detection

Core immutability uses structural enforcement (binary ignores config overrides for core rules) rather than detection-based approaches (HMAC signing of config). "Tampering is meaningless" is stronger than "tampering is detected."

## Structural Limits

- Full-path execution such as `/bin/rm` or `/usr/bin/git` can bypass the PATH shim. Mitigated by Layer 2 hooks (Claude Code + Cursor).
- `find -exec /bin/rm {} \;` bypasses both the find shim and the rm shim because rm is invoked via absolute path. Partially mitigated by Layer 2 hooks.
- `sudo` may change PATH before the shim runs.
- Interpreter commands (`python -c "shutil.rmtree(...)"`) are not detected by the unwrap stack (which handles bash/sh/zsh/dash/ksh only). [Decided out of scope per #74](https://github.com/yottayoshida/omamori/issues/74): zero real-world incidents in target tools (Claude Code, Cursor, Codex CLI).
- **Dynamic command generation** (`bash -c "$(cmd)"`, backtick substitution) inside shell launchers is **blocked** (fail-close) because the inner content cannot be statically analyzed.
- **Obfuscated commands** (base64 encoding, heredoc, variable indirection, string concatenation outside shell launchers) **cannot be detected**. This is a fundamental limitation of static analysis.
- **Bypass-by-substitution**: AI agents may attempt alternative commands (e.g., `rmdir`, `unlink`, `python os.rmdir()`) when their primary method is blocked. The unwrap stack partially mitigates this for shell launcher wrapping, but cannot prevent all substitution patterns. Protocol-level enforcement (#14 MCP) is the structural answer.
- Commands outside the curated default rules are not protected.
- Non-existent `destination` paths skip `canonicalize()` validation at config load time (caught at runtime via fail-close).
- macOS resolves `/etc` to `/private/etc` — the blocked prefix list includes `/private` to cover this.

## Environment Variable Detection

Detection uses **exact value matching**:
- `CLAUDECODE=1` is detected; `CLAUDECODE=true` or `CLAUDECODE=yes` is **not**
- `CLINE_ACTIVE=true` is detected; `CLINE_ACTIVE=1` is **not**

This is intentional: each detector's expected value is sourced from the actual tool implementation. If a tool changes its env var value in a future release, the detector must be updated.

## Hook Coverage (Layer 2)

### Recursive Unwrap Stack (v0.6.0+)

Layer 2 hooks use a **token-aware Recursive Unwrap Stack** implemented in Rust (`src/unwrap.rs`). The hook pipeline runs in two phases:

1. **Phase 1B — Token-level detectors**: `detect_env_var_tampering` (blocks `unset CLAUDECODE`, `export -n`, `env -u` on protected env vars) and `detect_path_shim_bypass` (blocks `PATH=/usr/bin:$PATH rm` and `env PATH=...` variants targeting shimmed commands). These run after `shell_words::split` for position-aware detection.

2. **Phase 2 — Unwrap Stack** (token-level): Tokenizes the command, strips shell wrappers, extracts inner commands from shell launchers, and evaluates each extracted command against the configured rules. Eight builtin `omamori-*-block` rules protect against self-modification commands.

**v0.10.4 meta-pattern removal**: Prior to v0.10.4, a Phase 1A substring-matching layer (`META_PATTERNS_PATH` with 18 entries and `META_PATTERNS_VERB` with 7 entries) ran before Phase 1B. This layer was removed in v0.10.4 because it caused 5-12 false-positive blocks per day on legitimate developer workflows (`grep` on config paths, commit messages mentioning protected files, etc.) and was bypassable via script file indirection. All protection previously provided by meta-patterns is now covered by Phase 1B token-level detectors (env var tampering, PATH override bypass), Phase 2 builtin rules (`omamori-*-block` for self-modification verbs), and `PROTECTED_FILE_PATTERNS` (Edit/Write tool gate). The `detection_layer` value `"layer2:meta-pattern"` is retained in the taxonomy for Phase 1B BlockMeta verdicts.

| Capability | Detection |
|-----------|-----------|
| Shell wrappers (`sudo`, `env`, `nohup`, `timeout`, `nice`, `exec`, `command`, `doas`, `pkexec`) | Stripped recursively to expose inner command |
| Shell launchers (`bash -c`, `sh -c`, `zsh -c`, `dash -c`, `ksh -c`) | Inner command extracted and recursively parsed |
| Full-path shells (`/usr/local/bin/bash -c`) | Recognized via basename matching |
| Combined flags (`bash -lc`) | Detected via flag suffix matching |
| Compound commands (`cmd1 && cmd2`) | Split and each segment checked independently |
| Pipe-to-shell (`curl url \| bash`) | **Blocked** unconditionally |
| Process substitution (`bash <(...)`) | **Blocked** |
| Dynamic generation (`bash -c "$(cmd)"`) | **Blocked** (fail-close) |
| `env KEY=VAL cmd` | KEY=VAL pairs skipped; actual command evaluated |
| PATH override bypass (`PATH=/usr/bin:$PATH rm`, `env PATH=/usr/bin rm`) | **Blocked** (v0.10.1). Inline assignment and `env` grammar variants detected via `detect_path_shim_bypass()` using `SHIM_COMMANDS` as single source of truth. See [#227](https://github.com/yottayoshida/omamori/issues/227). |

### Supported Shell List

`bash`, `sh`, `zsh`, `dash`, `ksh`. Detected by basename (full paths recognized). `fish` and `nushell` are not currently supported — they may be added based on real-world bypass reports (corpus-driven).

### Claude Code Hooks

The generated PreToolUse hook script is a thin wrapper that delegates to the omamori binary via its absolute path (resolved via `resolve_stable_exe_path()` at install and hook regeneration time):

```sh
cat | /usr/local/bin/omamori hook-check --provider claude-code
exit $?
```

### Cursor Hooks

The `omamori cursor-hook` subcommand uses the same `check_command_for_hook()` pipeline internally, with Cursor's JSON stdin/stdout protocol.

### Fail-Close Guarantees

| Failure mode | Behavior |
|-------------|----------|
| Parse error (unclosed quote, etc.) | BLOCK |
| Recursion depth > 5 | BLOCK |
| Token count > 1000 | BLOCK |
| Segment count > 20 | BLOCK |
| Input size > 1 MB | BLOCK |
| `$(...)` or backtick in shell launcher inner | BLOCK |
| OOM / panic | Process exit (hook failure = AI tool blocks) |

### Layer 2 Deny Coverage (v0.9.7+)

Pre-v0.9.7, Layer 2 hook deny verdicts (`BlockMeta` / `BlockRule` / `BlockStructural`) wrote to stderr but did not append to the HMAC audit chain. The marketed moat — tamper-evident audit chain that survives the AI agent itself — therefore covered Layer 1 (PATH shim) cleanly but had a structural gap at Layer 2. v0.9.7 closes that gap: every Layer 2 deny verdict appends an audit event with `action = "block"`, `result = "block"`, and `detection_layer` from the v0.9.7 taxonomy.

| Verdict | `detection_layer` value |
|---------|------------------------|
| `BlockMeta` (Phase 1B token-level: env-var tampering, PATH override bypass) | `"layer2:meta-pattern"` |
| `BlockRule` (token-level rule match) | `"layer2:rule"` (with `rule_id` carrying the matched rule name) |
| `BlockStructural` with transparent wrapper | `"layer2:pipe-to-shell:{wrapper}"` (e.g. `"layer2:pipe-to-shell:env"`, `"layer2:pipe-to-shell:sudo"`; wrapper basename comes from `unwrap::TRANSPARENT_WRAPPERS`) |
| `BlockStructural` without wrapper (parse error / depth / dynamic generation / process substitution / bare-shell pipe RHS) | `"layer2:structural"` |

#### Channel separation (v0.9.5 invariant maintained)

Wrapper kind flows into the audit log only. Block-reason **stderr** text remains the v0.9.5 fixed string (`"pipe to shell interpreter"` for all pipe-to-shell variants regardless of wrapper). The two channels are deliberately separated: an AI agent observing only stderr cannot iterate on wrapper variants (`env bash` blocked → try `sudo bash` → blocked → try `nice bash` → ...) because the block message is identical, while a forensic operator reading the audit log gets full attribution including the specific wrapper basename.

**Two carriers, both hashed on v2 entries (#177 B2/B3)**: the audit log records the wrapper basename twice — as the `:{wrapper}` suffix of `detection_layer` and as the standalone `AuditEvent.wrapper_kind` field. As of `CHAIN_VERSION` 2 (#177 B3), both carriers are part of `HashableEventV2` and are chain-protected on any entry that declares `chain_version: 2`. On a `chain_version: 1` entry, `wrapper_kind` is **not** hashed (`HashableEvent`, the v1 preimage, does not include it) — a same-user attacker can alter `wrapper_kind` on a v1 entry without breaking the hash chain, though `detection_layer`'s copy of the same fact remains chain-protected there too, since `detection_layer` has been part of the hashed struct since v1. This v1/v2 split is permanent: existing v1 audit.jsonl bytes are never rewritten (see ADR-0007), so v1 entries never retroactively gain `wrapper_kind` protection. Do not drop `detection_layer`'s `:{wrapper}` suffix (tracked separately for sunset in #459) while any v1 entries with a real wrapper attribution remain in a log — see #459 for the exact trigger condition.

#### Forensic semantics (v0.9.8+)

An audit row exists for every **Claude Code / Codex `hook-check` Layer 2 deny verdict** (`BlockMeta` / `BlockRule` / `BlockStructural`); the **absence** of a row in those provider paths implies `Allow` (or, in the limit, a missed-detection bypass). Provider scope is deliberate: Cursor hooks emit stderr-only deny messages without an audit-log append (see `### Cursor Hooks` above for the integration boundary), so absence in the audit log does NOT imply Cursor deny did not happen. HMAC chain integrity is not the same as forensic completeness — the chain protects against tampering with recorded events, not against under-recording. When investigating an incident or verifying coverage on the in-scope providers, treat audit-log absence and audit-log presence as orthogonal signals: HMAC `omamori audit verify` proves the recorded events are unforged, while `omamori hook-check --provider claude-code` dry-run on the same `tool_input.command` proves whether the structural pipeline reaches a deny at all. The two together close the gap; either alone is insufficient.

#### Audit-append failure semantics (SEC-7)

Layer 2 deny audit append is **best-effort with respect to the hook decision** but **not silent with respect to observability**: an append failure (config load error, audit secret missing, disk full, permissions) does not flip the block decision (the user's command stays blocked at exit code 2), but a stderr warning surfaces so the user knows the audit chain has a gap for that event. This mirrors the `audit_log_unknown_tool_fail_open` (PR6) pattern: fail-close on the safety-critical decision, fail-open on observability.

#### Schema migration note (parser developers)

This v0.9.7 change did not require a `CHAIN_VERSION` bump on its own (that came later, from #177 — see [Forward-Unknown Chain Versions](#forward-unknown-chain-versions-177)). The new `detection_layer` values follow the precedent set by v0.9.6's `"shape-routing"` value (PR6): they are added to the existing string field with no schema break, and parsers that do not recognise the new values must treat them as opaque. SIEM pipelines that filter on `detection_layer == "layer1"` only will silently exclude the new Layer 2 deny events; pipelines that want full Layer 2 coverage should match `detection_layer` values starting with `"layer2:"`.

`is_valid_detection_layer` (in `src/engine/hook.rs`) validates against a fixed taxonomy — static prefixes (`"layer1"`, `"shape-routing"`, `"layer2:meta-pattern"`, `"layer2:rule"`, `"layer2:structural"`) plus the `"layer2:pipe-to-shell:"` prefix paired with a wrapper basename from `unwrap::TRANSPARENT_WRAPPERS`. The `"layer2:meta-pattern"` value is retained for Phase 1B BlockMeta verdicts (env-var tampering, PATH override bypass). Adding a new transparent wrapper to that constant automatically becomes a valid detection_layer extension; adding a new top-level layer category requires an explicit constant update.

#### What is *not* covered

- **Cursor hooks** (`run_cursor_hook` in `src/engine/hook.rs`) still emit deny verdicts to stderr only. Audit-chain integration for the Cursor path will follow in a separate PR; the protection guarantee for Cursor is unchanged but observability remains stderr-only for that provider in v0.9.7.
- **Layer 2 allow events** (every `omamori hook-check` that returns 0) are not appended. The chain captures deny narrative end-to-end, not full traffic.

### Scope: unknown / new tools (v0.9.6+)

AI tool platforms ship new tools and rename existing ones on their own cadence; omamori is locally installed and updated on the user's cadence. A `tool_name` allowlist baked into the binary would always be slightly behind reality, so we route by **payload shape** instead of by name. See `README.md` → "How omamori handles new / renamed tools" for the full table.

The threat we care about: a provider-side rename of a write/exec tool silently bypasses Layer 2. Pre-v0.9.6, `HookInput::UnknownTool` short-circuited to allow regardless of the carried `tool_input`. Codex adversarial-review ② A-2 (2026-04-23, critical) flagged this as a forward-compat fail-open, and v0.9.6 closes it: a payload like `{"tool_name":"FuturePlanWriter","tool_input":{"command":"/bin/rm -rf /"}}` now reaches the full shell pipeline (Phase 1B detectors, Phase 2 rules, unwrap stack) on the strength of the `command` field alone. Wrong-type routing fields (`command: 42`) fail closed.

The residual risk is `tool_input` shapes we don't recognise at all (no `command`/`cmd`/`file_path`/`path`/`url`). That's still **Allow**, on purpose: starting to block unreviewed payload shapes would break user workflow on every legitimate AI tool update. But the silence is gone — the call is recorded as an `unknown_tool_fail_open` event in the audit chain, stderr carries a one-line hint, and `omamori doctor` surfaces a 30-day count. Users review the events with `omamori audit unknown`.

The 30-day count assumes a roughly correct, monotonic OS clock. The cutoff is computed as `now_utc() - 30 days` and applied as a `>=` filter on the per-event RFC 3339 timestamp, so significant NTP rewinds or other clock anomalies move the cutoff window and silently shrink or zero the count. Treat the surfaced number as a drift indicator, not a forensic counter — investigate spikes via `omamori audit unknown` and HMAC-verify suspicious windows with `omamori audit verify` rather than relying on the doctor count alone.

This is a **trade-off, not a complete mitigation**. Threat-model implications:

- An adversary aware of this scope could intentionally craft a `tool_input` shape that matches none of our known fields — say `{"prompt":"...","payload":"..."}` — to land in the observable fail-open branch. The damage they can do that way is limited (whatever the AI tool itself ends up doing with that payload is outside omamori's enforcement layer), and the call leaves a trail in `audit unknown`.
- Stricter posture (block-by-default-on-unrecognised-shape) is tracked as opt-in `strict-mode` for a follow-up release, for users who would rather break workflow than allow an unobserved tool.
- Audit log integrity: events use the existing `action` field with a new value (`"unknown_tool_fail_open"`) and the existing `detection_layer` field with a new value (`"shape-routing"`); no `CHAIN_VERSION` bump, no schema break, parsers that don't recognise the values treat them as opaque.

#### Known limitations carried into v0.9.6

The shape catalogue is intentionally narrow in v0.9.6 and several known-good Claude Code tools land in the unknown branch — `NotebookEdit` (`notebook_path`), `Task` (`subagent_type`/`prompt`), `TodoWrite` (`todos`), `WebSearch` (`query`), and similar. Operationally:

| Surface | Behavior in v0.9.6 | Honest read |
|---|---|---|
| **Protection** (does the dangerous shape reach the unwrap stack?) | Routes correctly: `command`/`cmd`/`file_path`/`path` always reach the full pipeline regardless of `tool_name` | Effective. The forward-compat fail-open Codex ② A-2 flagged is closed for the dangerous-shape class. |
| **Observability** (`audit unknown` count, `doctor` 30-day line) | Includes legitimate-tool noise on every `Glob` / `Task` / `TodoWrite` / `WebSearch` invocation | **Upper bound on adversarial activity, not a lower bound**. A baseline of routine fail-opens is expected; spikes or unfamiliar tool names are the actionable signal. |
| **Audit schema borrowing** | `target_count` re-used to record `tool_input` top-level key count for `unknown_tool_fail_open` events; `command` field re-used to carry `tool_name` | Downstream analytics that aggregate these columns across action types will see skewed distributions. Use `action == "unknown_tool_fail_open"` as the filter, not field semantics. |
| **stderr dedup** (per the original release-blocker UX wording) | One stderr line per hook-check invocation; no in-process dedup — `omamori hook-check` is short-lived (1 process = 1 dispatch), so a process-local guard would be dead code | Each fail-open emits one line. If user noise becomes a problem, session-level dedup will land alongside strict-mode. |

A future omamori release will address these by (1) widening the shape catalogue to cover known legitimate tool fields, (2) adding dedicated audit columns so `unknown_tool_fail_open` events do not borrow `target_count` / `command` semantics, (3) opt-in `strict-mode` so users can fail-closed on unrecognised shapes, and (4) session-level stderr dedup.

### Hook Limitations

The unwrap stack is a static analyzer, not a shell interpreter. It cannot detect:
- Obfuscated commands (base64 encoding, hex encoding)
- Variable indirection (`CMD=rm; $CMD -rf /`)
- Commands constructed at runtime by interpreters (`python -c`, `node -e`)
- Heredoc content
- Encoded payloads decoded at execution time
- **Standalone redirection-dup stdin aliases** (`source /dev/fd/N N<&0` without a pipe): shell redirection creates a synthetic file descriptor that points at stdin, then `source /dev/fd/N` reads from it. Detection would require parsing `N<&0`-style redirections and tracking fd equivalence to `/dev/stdin`. Note that when fd-dup appears after a pipe (e.g. `curl … | bash -c 'source /dev/fd/3' 3<&0`), pipe-to-shell detection catches the `bash` launcher on the pipe RHS regardless of inner fd content — the residual is standalone invocations without a pipe context.
- **GNU env `-S STRING` attack surface is closed by a coarse rule**: any `env -S` invocation on the RHS of a pipe is blocked unconditionally, regardless of STRING contents. The rule covers all known evasion angles (leading `KEY=VAL` assignments, leading env flags `-i`/`-u`/`-C`, trailing argv, `--` terminator, nested `-S`, and the full GNU escape vocabulary `\_`/`\n`/`\t`/`\v`/`\c`/`${VAR}`). This is strictly stronger than the finer-grained `string_head_is_shell` predicate used in earlier PR2 iterations, which repeatedly leaked one angle at a time (Codex Phase 6-A Rounds 1–3). Legitimate `env -S` use is concentrated in shebang lines (`#!/usr/bin/env -S prog args`), which are resolved by the kernel before an omamori hook sees the command — no regression to shebang-based workflows.

## Hook Auto-Sync (v0.4.1+)

After `brew upgrade omamori`, the binary is updated but hook scripts remain at the old version. The shim now detects this on startup and auto-regenerates hooks.

### How it works

1. Hook scripts embed a version comment: `# omamori hook v0.4.1`
2. On each shim invocation, `ensure_hooks_current()` reads the first line of the hook script
3. If the version doesn't match `CARGO_PKG_VERSION`, `regenerate_hooks()` rewrites all hook files
4. After regeneration, versions match — no further checks until the next upgrade

### Safety properties

- **Non-blocking**: Version check reads ~50 bytes; adds < 0.1ms to normal invocations
- **One-time**: Regeneration fires once per upgrade (version match prevents re-triggers)
- **Fail-safe**: If regeneration fails, old hooks continue to function. A fallback command (`omamori install --hooks`) is printed to stderr
- **Atomic writes**: All hook file writes use temp + flush + rename to prevent partial writes

### Residual risk

Custom edits to generated hook scripts are overwritten during regeneration. Hook scripts are treated as generated artifacts, not user-editable files. A managed-block approach (preserving custom sections) may be added in a future version if demand exists.

## Bypass Corpus Testing (v0.4.1+)

omamori maintains a bypass corpus — a set of tests that verify both "what we block" and "what we cannot block." This ensures honesty about the tool's limitations.

### Test coverage by priority

| Priority | Pattern | Verified by |
|----------|---------|-------------|
| P1 | `/bin/rm` + `/usr/bin/rm` path variants | Phase 2 rule tests in `hook_integration.rs` |
| P1 | All 6 detector env vars × 3 unset patterns | Phase 1B `detect_env_var_tampering` tests |
| P2 | `config disable/enable`, `uninstall`, `init --force` | Phase 2 builtin rule tests (`omamori-*-block`) |
| P3 | `bash -c "rm -rf"`, `sudo env bash -c "rm -rf"` | `unwrap::tests::bash_c_*`, `unwrap::tests::chained_wrappers` |
| P3 | Pipe-to-shell (`curl \| bash`) | `unwrap::tests::curl_pipe_bash` |
| P3 | Dynamic generation (`bash -c "$(cmd)"`) | `unwrap::tests::dollar_paren_*` |
| P4 | False positive: `echo "rm -rf"`, `env NODE_ENV=production npm start` | `unwrap::tests::echo_with_dangerous_string`, `unwrap::tests::env_production_start` |
| P4 | `/bin/rmdir` false-positive regression | Phase 2 rule tests (rmdir not matched) |

### Known limitations (KNOWN_LIMIT)

These cover everything omamori does *not* protect against, separated by why. (A) closures that landed in the v0.9.x series, (B) out-of-scope decisions, and (C) structural / parser-level limits the current static-analysis approach cannot bridge without product-level changes. Test source comments use the `KNOWN_LIMIT` label.

#### A. Closed in v0.9.x series

| Attack vector | Closed in | Notes |
|---------------|-----------|-------|
| `export -n CLAUDECODE` | v0.9.2 | Phase 1B token detection. `export -n VARNAME` and `export -nVARNAME` (combined form) blocked alongside `unset` and `env -u`. See `src/engine/hook.rs::detect_env_var_tampering` and `tests/hook_integration.rs` corpus entries `export-n` / `export-n-attached`. |
| `curl URL \| env bash` / `curl URL \| sudo bash` (+ wrapper variants) | v0.9.5 | Pipe-to-shell detection runs before transparent-wrapper unwrapping, covering 7 wrappers (`sudo`, `env`, `nice`, `timeout`, `nohup`, `exec`, `command`) with chained / absolute-path (`/usr/bin/env`, `/bin/sudo`) / stdin-flag (`-s`, `-`, `/dev/stdin`) / option-value (`-O optname`, `-o optname`, `--rcfile FILE`) / grouped-short (`-la argv0`, `-pv`) / `\|&` (stdout+stderr pipe) variants. Info-only flags (`--version`, `--help`, `--dump-strings`, `--dump-po-strings`, `--rpm-requires`, `-D`) and positional script paths remain Allow. See `src/unwrap.rs::tests` prefixed `curl_pipe_*` / `env_*` / `command_*` / `exec_*`. Refs [#170](https://github.com/yottayoshida/omamori/pull/170), #146 P1-1. |
| `curl URL \| env -S 'bash -e'` (split-string form) | v0.9.6 | Coarse-rule closure: any pipe-RHS invocation of `env -S` is blocked unconditionally regardless of STRING contents. Covers leading `KEY=VAL` assignments, leading env flags (`-i`/`-u`/`-C`), trailing argv, `--` terminator, nested `-S`, and the full GNU escape vocabulary (`\_`/`\n`/`\t`/`\v`/`\c`/`${VAR}`). False-positive bound: legitimate `env -S` use is concentrated in shebang lines (`#!/usr/bin/env -S prog args`), resolved by the kernel before an omamori hook sees the command. See `src/unwrap.rs` env-S handling and `tests/hook_integration.rs` corpus entry `pipe-wrapper-evasion-env-dash-s-block`. PR2 ([#184](https://github.com/yottayoshida/omamori/pull/184)) scope 5. |
| `curl URL \| bash -c 'source /dev/stdin'` (shell launcher reading piped payload) | v0.9.6 | Note: the v0.9.5 coarse rule already blocks any bare shell on a pipe RHS as pipe-to-shell (modulo info-only flags / positional script paths listed in the v0.9.5 row). The v0.9.6 scope 6 closure is the **launcher-internal detection** layered on top: an inner `source` or `.` (POSIX dot) builtin reading `/dev/stdin`, `/dev/fd/0`, or `/proc/self/fd/0` is recognised at the launcher boundary as a tested subset of the broader pipe-to-shell policy. The non-pipe common case `bash -c 'source /dev/stdin' < file` (explicit stdin redirect) remains Allow. `eval` / `exec` reading runtime stdin are **not yet** in the launcher-boundary closure — those remain in C below. See `tests/hook_integration.rs` corpus entry `pipe-launcher-source-stdin-block`. PR2 ([#184](https://github.com/yottayoshida/omamori/pull/184)) scope 6. |
| `curl URL \| doas bash` / `curl URL \| pkexec bash` (privilege-escalation wrappers) | v0.9.6 | OpenBSD `doas` and polkit `pkexec` are recognised as transparent elevation wrappers; pipe-RHS `doas bash` / `pkexec bash` block. Legitimate `doas -u user <non-shell-cmd>` remains Allow (FP-pinned). See `tests/hook_integration.rs` corpus entries `pipe-wrapper-evasion-doas-block` / `pipe-wrapper-evasion-pkexec-block`. PR2 ([#184](https://github.com/yottayoshida/omamori/pull/184)) scope 7. |
| Forward-compat fail-open on renamed tools | v0.9.6 | `HookInput::UnknownTool` no longer short-circuit-allows. `tool_input` shape (`command`/`cmd`/`file_path`/`path`/`url`) routes through the full pipeline regardless of `tool_name`; wrong-type fields (e.g. `command: 42`) fail closed. Unrecognised shapes still allow but emit `unknown_tool_fail_open` audit events and a one-line stderr hint per invocation. Refs [#182](https://github.com/yottayoshida/omamori/issues/182). |
| `PATH=/usr/bin:$PATH rm` / `env PATH=/usr/bin rm` (PATH override shim bypass) | v0.10.1 | Phase 1B `detect_path_shim_bypass()` detects inline `PATH=` assignment and `env` grammar variants (`env`, `env -i`, `env -u`, `env --`, `/usr/bin/env`) followed by a `SHIM_COMMANDS` member. Non-shimmed commands (`PATH=/x node script.js`) remain Allow. `export PATH=...` (shell config, no command) remains Allow. See `src/engine/hook.rs::detect_path_shim_bypass`, `tests/hook_integration.rs` corpus entries `path-override-*`. Refs [#227](https://github.com/yottayoshida/omamori/issues/227). |
| `curl URL \| env bash 2>&1` / `\| bash &>> log -s` (redirect-axis bypass on `pipe-to-shell + transparent-wrapper`) | v0.9.8 | The 2-boolean redirect classifier (`is_pure_redirect_op` / `is_concatenated_redirect`) carried in v0.9.5-v0.9.7 could not represent operand arity, so redirect operators with operand (e.g. `&>>` taking a file path) were misclassified as concatenated single-token redirects, letting downstream stdin-signal flags reach as if they were script paths. Replaced by `RedirectToken::{PureWithOperand, Concatenated, NotRedirect}` enum with explicit `token_span()` arity, used uniformly in `unwrap_transparent`, `strip_leading_noise`, and the new arity-aware skip in `classify_shell_args`. Single-digit fd prefixes (`0<`..`9>`, including `2<>file` etc.) handled via `strip_single_fd_digit` reclassification — automatically closes the `2<>` enumeration gap (V-028) surfaced during plan loop. V-027 (proc-sub + transparent wrapper) was already correct (proc-sub guard runs post-`unwrap_transparent`); v0.9.8 fills the test-gap with 9 wrappers × proc-sub regression cases. See `src/unwrap.rs::RedirectToken`, `tests/hook_integration.rs::HOOK_DECISION_CASES` (entries `redirect-axis-*-block` and `v027-proc-sub-*-block`), and `src/unwrap.rs::tests` FN-regression boundary suite. Refs [#212](https://github.com/yottayoshida/omamori/issues/212), #146 P1-1. v0.10.2 systematized the coverage with a 3D matrix (35 integration tests) spanning all 9 transparent wrappers × 5 redirect operators (`2>&1`, `>`, `>>`, `&>`, `<<<`) × compound-operator trailing (`; echo`, `&& echo`) and 8 FP pins for legitimate redirect usage (`git log > file`, `cargo build 2>&1 \| tee`, etc.). The `<<<` here-string operator correctly triggers the stdin-redirect exemption (Allow), confirming the v0.9.8 `segment_has_stdin_redirect` logic. See `tests/hook_integration.rs::HOOK_DECISION_CASES` entries prefixed `redirect-3d-*`. Refs [#219](https://github.com/yottayoshida/omamori/issues/219). |

#### B. Out of scope by design decision

| Attack vector | Decision | Rationale |
|---------------|----------|-----------|
| `python -c "shutil.rmtree(...)"` (interpreter family: `python -c` / `node -e` / `perl -e` / `ruby -e`) | [Decided out of scope per #74](https://github.com/yottayoshida/omamori/issues/74) | Zero real-world incidents in target tools (Claude Code, Cursor, Codex CLI); full-block approach disproportionate to the risk; protocol-level enforcement ([#14](https://github.com/yottayoshida/omamori/issues/14) MCP) is the right layer. |

#### C. Structural limits of static shell-word analysis

These are not closures pending future work — the current static-analysis pipeline cannot reach them without OS-level cooperation, runtime evaluation, or a product-level scope decision.

| Attack vector | Why undetectable |
|---------------|-----------------|
| `sudo rm -rf` (Layer 1 shim only — direct human execution outside AI hook input) | sudo changes PATH before the Layer 1 shim runs; shim is never invoked. AI hook input still reaches Layer 2, where `sudo` is unwrapped as a transparent wrapper — so AI-issued `sudo rm -rf` is detected there (see Hook Coverage). The residual is direct human execution outside hook coverage. (Note: `curl URL \| sudo bash` pipe-RHS is closed — see A above.) |
| `alias rm='/bin/rm'` | Alias/function overrides bypass string matching in hooks |
| `env -i rm -rf` (Layer 1 shim only — direct human execution outside AI hook input) | Clears all env vars including detectors before the Layer 1 shim runs. AI hook input still reaches Layer 2, where `env -i` is unwrapped as a transparent wrapper — so AI-issued `env -i rm -rf` is detected there. The residual is direct human execution outside hook coverage. |
| Obfuscated commands (base64, hex, variable expansion) | Static analysis cannot decode runtime-constructed commands |
| `bash -c "$VAR"` (VAR set earlier in the same shell) | Variable expansion requires runtime evaluation |
| `source /dev/fd/N N<&0` (standalone redirection-dup stdin alias) | Standalone: shell redirection creates a synthetic fd pointing at stdin, then `source /dev/fd/N` reads from it. Detection would require parsing `N<&0`-style redirections and tracking fd equivalence. Note: when used after a pipe (e.g. `curl … \| bash -c 'source /dev/fd/3' 3<&0`), pipe-to-shell detection catches the `bash` launcher on the pipe RHS — the residual is standalone invocations without a pipe context. (Direct `bash -c 'source /dev/stdin'` after a pipe is also closed — see A above.) |
| `curl URL \| source /dev/stdin` / `\| eval ...` (interpreters outside `SHELL_NAMES`, used directly on the pipe RHS) | Current `SHELL_NAMES = [bash, sh, zsh, dash, ksh]` does not include `source`, `eval`, or interpreter families (`python -c`, `perl -e`, `node -e`, `ruby -e`). Pipe-to-shell detection is bound to this list; expanding it has real false-positive risk (`cat data \| python -c 'parse'`) and requires product-level discussion. (Note: when `source` / `eval` are invoked *inside* a shell launcher like `bash -c 'source /dev/stdin'`, that case is closed — see A above.) |

## AI Config Bypass Guard (v0.3.2+)

Real-world testing ([#22](https://github.com/yottayoshida/omamori/issues/22)) showed that AI agents (Gemini CLI) can autonomously discover and use `omamori config disable` to remove protection rules before executing dangerous commands.

### Protection

- `config disable`, `config enable`, `config add`, `uninstall`, and `init --force` are blocked when AI detector env vars are present
- Uses the same detector logic as the PATH shim (`evaluate_detectors()`)
- Hooks also block these commands as string patterns (Claude Code + Cursor)
- Hooks block shell commands that modify `config.toml` (sed, echo, etc.)
- **Edit/Write file_path guard** (v0.8.0 #110): AI Edit/Write/MultiEdit operations on protected files (config, hooks, audit, settings.json) are blocked via `PROTECTED_FILE_PATTERNS` with path normalization and symlink resolution

### Known limitations

| Attack vector | Protected | Notes |
|--------------|-----------|-------|
| `omamori config disable` | Yes — env var guard | All tools with known env vars |
| `omamori uninstall` | Yes — env var guard | All tools with known env vars |
| Direct config.toml editing (Edit/Write) | **Yes** — file_path guard (v0.8.0) | Claude Code PreToolUse. Codex CLI: Bash only (structural limitation) |
| Direct config.toml editing (Bash: sed, echo >>) | Claude Code + Cursor | Hooks block Bash patterns containing config.toml |
| Direct config.toml editing (other tools) | **No** | Codex CLI, Gemini CLI cannot prevent file editing |
| env var unset → config disable | Partially | Hooks block env var unset. Without hooks, this attack succeeds |
| Unknown AI tool (no env var) | **No** | Guard depends on known env vars |

### Design philosophy

DCG (destructive_command_guard) explicitly states that adversarial AI bypass is out of scope. omamori chooses to address this attack surface, acknowledging that complete prevention is impossible in userspace but meaningful risk reduction is achievable through layered defense.

## Context-Aware Evaluation (v0.4.0+)

### Threat Model

Context-aware evaluation introduces dynamic action adjustment based on target paths and git status. This changes the attack surface from "static rules only" to "static rules + contextual overrides."

| Threat | DREAD | Mitigation |
|--------|-------|------------|
| **T2: Symlink downgrade** | 9.0 | `canonicalize()` resolves symlinks before matching. Failure → no downgrade (fail-close) |
| **T1: Path traversal** | 8.0 | Lexical normalization (`.`, `..`, `//`, trailing `/`) before matching. Raw path matching prohibited |
| **T10: TOCTOU** | 7.8 | Accepted residual risk. evaluate→execute window minimized. Cannot be eliminated in userspace |
| **T4: Git status spoofing** | 7.2 | `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR` removed from git subprocess |
| **T3: Config poisoning** | 7.0 | AI config bypass guard (v0.3.2) + NEVER_REGENERABLE hardcoded list |

### NEVER_REGENERABLE

The following paths cannot be classified as regenerable regardless of config: `src`, `lib`, `app`, `.git`, `.env`, `.ssh`. If a user adds these to `regenerable_paths`, the pattern is silently ignored and a config load warning is emitted.

### Unresolvable Working Directory (#460)

Relative target paths are resolved against the process's working directory before `protected_paths` is matched. When that directory cannot be resolved — it was deleted out from under the running command — there is no base to resolve against.

`protected_paths` matching walks a contiguous window of path components, so whether the missing base matters depends on the pattern. A single-component entry (`src/`, `.git/` — every entry in the default config) completes its window out of the target's own components and gives the same verdict either way. An entry of two or more components can need the leading part of that window to come from the base: with the real directory it matches, and against the synthetic `/` root that used to stand in for it, it silently does not — so Priority 1 escalation was skipped. That is a fail-*open* for that one rule, and it is the state #175 documented in `process_base_or_root`'s doc comment rather than closed.

Escalation now happens instead of a decision made without the information, and only where the gap exists: the config must carry a `protected_paths` entry whose window is wider than one component, and the target must be relative (an absolute target is never resolved against a base). **An absolute pattern is not exempt** — the dependency runs through the target's resolution rather than the pattern's shape, so `protected_paths = ["/tmp/proj/secret"]` with a real directory of `/tmp/proj` and a relative target `secret` matches, while against the synthetic root the target resolves to `/secret` and cannot contain that window. Two component shapes contribute nothing and are not counted: `.`, which normalization drops so it never appears in a resolved path (keeping `protected_paths = ["."]` at one component), and `..`, which normalization pops rather than emits, so a pattern carrying one matches nothing with or without a base.

Measured against a `2ceade2` build with an unlinked working directory: a `protected_paths = ["some/nested/dir"]` config left the rule's own action in place (no escalation) where this build blocks and names the reason; a single-component config produced byte-identical output on both. The reason string is the same on all three surfaces that print it — the shim's block message, `omamori explain`, and `omamori test` — and `explain` reports the base as unresolved rather than as `/` (its `--json` field is `null`, not `"/"`, so a consumer can tell "resolved to the root" from "there was no base").

This does not extend to `regenerable_paths`: a downgrade requires `canonicalize` to succeed, which a synthetic root generally will not, so an unresolvable directory can only ever suppress a downgrade — never cause one that should not happen.

### Context Message Accuracy (v0.4.1)

When context evaluation overrides a rule's action, the user-facing message is now generated by `ActionKind::context_message()`, which always matches the actual action. Previously, the original rule's `message` field was preserved, leading to misleading feedback (e.g. "moved to Trash" when the command was actually blocked due to a NEVER_REGENERABLE path).

**Breaking change**: Custom `message` fields on rules are overridden during context evaluation. Security accuracy is prioritized over custom text preservation.

### Residual Risks

| Risk | Reason for acceptance |
|------|----------------------|
| TOCTOU between evaluate and execute | Atomic path-check + delete is impossible in userspace |
| `trash` crate symlink behavior | Upstream dependency; monitor CHANGELOG |
| Unicode normalization differences | macOS HFS+/APFS normalizes to NFD; practical impact is limited |
| AI continuous path generation attempts | No rate limiting; mitigated by hooks |
| Git-aware disabled by default | Opt-in design; documented trade-off |

## Safe Defaults

- Missing config → fail-close using built-in default rules
- Broken config parse → fail-close using built-in default rules
- Trash failure → fail-close; omamori refuses to run the original `rm`
- `move-to` failure (any cause) → fail-close; omamori refuses to run the original command
- Blocked destination → rule disabled at config load time
- Sudo/elevated execution detected → block
- Binary crash remains a fail-open risk outside the process boundary

## Config Merge Model (v0.2+)

Built-in rules are always loaded first. User config rules are merged by `name`:
- Matching name → fields are overridden (partial overrides supported)
- New name → added as a new rule (requires `command` + `action`)
- Duplicate names in user config → warning, first occurrence wins

This means users cannot accidentally remove default protection by creating a config file. They can only override or disable specific rules intentionally.

## Internal Subprocess Isolation

The `stash-then-exec` action runs `git stash` as a subprocess. To prevent this internal call from triggering omamori's own protection (via PATH shim), the subprocess environment strips the default detector variables (`CLAUDECODE`, `AI_GUARD`).

## Audit Log (v0.7.0+)

Tamper-evident audit logging. Every command decision is recorded with HMAC integrity and hash-chain continuity.

### Schema

Each JSONL entry contains:

| Field | Description |
|-------|-------------|
| `chain_version` | Chain format version. Currently `2`; existing `1` entries remain valid and are never rewritten (see [Forward-Unknown Chain Versions](#forward-unknown-chain-versions-177) and ADR-0007) |
| `seq` | Monotonic sequence number. What keeps it monotonic is a refusal, not arithmetic: the tail's `seq` is read off disk and the append path never authenticates it, so the next number is derived with a checked increment and `append()` refuses to write when the tail leaves no successor — see [Sequence Numbers at the Representable Limit](#sequence-numbers-at-the-representable-limit-456) |
| `prev_hash` | HMAC of the previous entry (genesis for first entry) |
| `key_id` | Identifier of the HMAC key that produced this entry's `entry_hash`. `"default"` names the store's first key epoch; `"key-N"` names epoch N. Verification resolves the key through this field — see "Key rotation" below |
| `timestamp` | RFC 3339 UTC timestamp |
| `provider` | AI tool that triggered the command |
| `command` | Command name (e.g., `rm`, `git`) |
| `rule_id` | Matched rule name, if any |
| `action` | Rule action (trash, block, passthrough, etc.) |
| `result` | Execution result |
| `target_count` | Number of target arguments |
| `target_hash` | HMAC-SHA256 of target paths (privacy-preserving) |
| `entry_hash` | HMAC-SHA256 of a fixed-field-order canonical projection of the entry (chain integrity) — not the raw on-disk bytes; see [HMAC Integrity](#hmac-integrity) for the per-`chain_version` struct this is computed over |
| `pid` | Process ID of the omamori shim process that recorded this entry (short-lived — see [Process Provenance](#process-provenance-v0131-420) below) |
| `ppid` | Parent process ID at collection time — the process that launched the guarded command (the AI CLI or shell, not omamori itself) |
| `parent_process` | Resolved exec path of the parent process (`proc_pidpath`), plaintext, control characters stripped |
| `cwd_hash` | HMAC-SHA256 of the current working directory at collection time (privacy-preserving, same construction as `target_hash` but domain-separated) |

### Config mutation events (v0.13.x, #394)

`config disable`, `config enable`, and `config add` each append an audit event on success — `action` is `config-disable`/`config-enable`/`config-add`, `detection_layer` is `config-mutation`, `provider` is `cli` (these commands require passing `guard_ai_config_modification`'s runtime env-var check, but do not go through an interactive confirmation the way `break-glass` does, so they are not attributed `provider: "human"`). Only the rule name and command verb are recorded — never a rule's content (`--command`/`--match-any`/`--destination`/`--message` for `config add`), consistent with `target_hash` HMAC-hashing paths elsewhere rather than logging them in the clear. No-op invocations (e.g. disabling an already-disabled rule) do not append an event — only an actual on-disk mutation does. Appending is best-effort: the config write itself always takes priority, and a failure to append is a warning, never a reason to fail the command or roll back the write (state-first + audit-best-effort, mirroring `break-glass`'s pattern). These events reuse the existing `action`/`detection_layer` string fields — no schema change, no `chain_version` bump; `AuditEvent`'s `entry_hash` treats all field values as opaque data, so older and newer omamori versions can both parse and verify the same chain.

`override disable`/`override enable` (which mutate core-rule overrides, a more consequential class of change than a custom rule's toggle) are not yet covered by this audit trail — tracked as a follow-up.

### Key rotation events (#457)

`audit key rotate` appends one event on success — `action` is `audit-key-rotate`, `detection_layer` is `key-rotation`, `provider` is `cli`, and `result` names both epochs (`rotated default -> key-2`). It is written after the rename and signed with the new key, so it is the first entry of the new epoch. The retired key's *path* is not recorded, only the two epoch ids: the path is derivable from the id, and storing it would put the user's home directory in the log in the clear.

**`verify` does not special-case the event.** It is not a marker: nothing re-anchors at it, no epoch is inferred from it, and no key-resolution decision consults it. What it *is* is an ordinary chain entry — parsed, authenticated against the key its own `key_id` names, and counted in the `seq`/`prev_hash` continuity like every other line. Appending one to a chain that verifies leaves it verifying; the event carries no verification semantics beyond that of any other entry.

Appending is best-effort in the same sense as config mutation events: the rename has already happened and is never rolled back, so a failure to append is a warning and the command still exits 0. Reusing a non-zero exit would also make "the rotation failed" and "only the log line failed" indistinguishable to a caller — and a caller that retries would rotate a second time.

`[audit] strict = true` is **not** consulted here, nor for config mutations, nor for a break-glass *activation*. The rule is about ordering, not about the command: strict withholds an action whose audit entry would be written *before* it happens, and each of those three is already on disk by the time its record is attempted, so there is nothing left to withhold. A break-glass **bypass** is the opposite case — the guarded command has not run yet — and it does consult strict, blocking with exit 2 when its entry cannot be written.

The `result` text (`rotated default -> key-2`) is written for a human reading `omamori audit show`. It is **not a parse contract** — the epoch a given entry belongs to is `key_id`, which is a real field. Building a monitor on the shape of this sentence is building on something free to change; giving these events dedicated columns instead is tracked with the same follow-up as `unknown_tool_fail_open`'s borrowed `target_count`.

Two states produce a warning saying the rotation was **not recorded**, rather than an entry:

- auditing is disabled, so there is nowhere to write it
- the key store degraded between the rename and the record — the secret deleted, made unreadable, or replaced — so the entry could not be signed. An unsigned entry is unauthenticated and labelled `unresolved`; since `ADR-0007` forbids rewriting entries, that single line would leave the store reporting cannot-verify **permanently**, including after the condition is fixed. A lost record is recoverable, that is not

An unlistable key directory used to be the second of those. It no longer reaches the record at all — since #477 rotation refuses that state outright, before any key file is renamed or created, so there is no completed rotation left to describe.

**What this does not cover.** Only rotations performed through this command leave an event. Renaming the key files by hand reaches the same on-disk state with no record of it, and a crash between the rename and the append leaves the key rotated and unrecorded. The event is evidence that a rotation happened, never evidence that one did not.

**Two classes, one rule.** Operations that *change* the key store refuse when the epoch in play cannot be established — there is no safe guess, and a wrong one is unrecoverable. Ordinary appends do the opposite: they record without HMAC protection and let `verify` report cannot-verify, because for a shim decision or a Layer 2 deny the record is the only durable trace there is, and [absence of a row means the command was allowed](#forensic-semantics-v098). The dividing line is whether anything else on disk survives to say the event happened.

### Process Provenance (v0.13.1, #420)

Layer 1 (PATH shim) audit events carry a best-effort process snapshot — `pid`, `ppid`, `parent_process`, `cwd_hash` — so a future incident's actor can be correlated across entries from the audit log alone, without cross-referencing shell history, hook configuration, or process tables by hand. This was added after a real incident (2026-07-16) where a repeating destructive command pair had to be traced using only `target_hash`, with no way to tell whether the same launcher fired all 16 occurrences.

**Field definitions**:
- **`pid`** is the short-lived omamori shim process itself — it changes on every invocation and is not useful for correlation on its own.
- **`ppid`** is the process that launched the guarded command (the AI CLI, a shell, an editor's integrated terminal). This is the field that answers "did the same launcher fire this twice?" — group entries by `ppid` to find repeats.
- **`parent_process`** is `ppid`'s resolved exec path from `proc_pidpath` — the kernel's record, never `argv[0]` (which is fully attacker-controlled at exec time on Darwin). It answers "which installed application was that launcher?" (e.g. distinguishing a Homebrew `node` from an Electron app's bundled one).
- **`cwd_hash`** is an HMAC-SHA256 of the shim process's working directory at collection time, domain-separated from `target_hash` (see below). It answers "was this run from the directory I suspect?" — check with `omamori audit hash-cwd <path>` (below), never by eye.

**Not an authenticated identity.** All four fields are forensic best-effort hints, not proof. Collection happens in the same-user OS model this entire threat model operates under (see [Defense Boundary](#defense-boundary)): a shell hop (`sh -c ...`), deliberate orphaning, a double-fork, or a crafted binary name can each launder or defeat correlation. `None` in any field means collection failed or was skipped — it is never evidence of anything on its own, and should not be read as such during an investigation.

**Why `parent_process` is plaintext but `cwd_hash` is hashed**: this is a deliberate asymmetry, not an oversight. Identifying *which application* launched a command requires a human-readable path — hashing `parent_process` would make it useless for the investigation this feature exists to support. Confirming *whether a candidate directory matches* only requires equality testing, which a hash supports just as well as plaintext while limiting what a log reader (see [Audit Log Read Access](#audit-log-read-access-v097)) learns about directory layout. Both fields carry the same class of information a `pwd` or `ps` command would already reveal on the same machine to the same OS user — this does not cross the same-user threat boundary, it just makes what's already observable also *correlatable* from one file.

**`cwd_hash` domain separation**: computed as `HMAC-SHA256(secret, "omamori-cwd-v1\0" ++ cwd_bytes)` — a distinct domain tag and output prefix (`hmac-cwd:`, vs. `target_hash`'s `hmac-sha256:`) from `target_hash`'s construction. Without this, a log reader without the secret could use `cwd_hash == target_hash` as an equality oracle between the two columns whenever a command's target argument happened to equal its cwd.

**`omamori audit hash-cwd <path>` — matching a candidate directory against the log**: `cwd_hash` can't be checked against a suspected directory by eye. This command computes every hash a real log entry could plausibly carry for a given path and prints them for grepping. It spans two axes an investigator would otherwise have to reason about manually:
- **Key**: hashes are computed against every key in the keyring — the active key plus any retired ones kept from a prior `omamori audit key rotate` — since a rotation could have happened between when the suspect entry was written and when the investigation runs.
- **Path form**: `cwd_hash` is computed from `std::env::current_dir()`, which returns an already symlink-resolved path (e.g. macOS `/tmp` → `/private/tmp`). An investigator's hand-typed candidate is typically *not* resolved, so both the raw and canonicalized forms of the candidate are hashed — trying only one silently misses a real match.

**Folded into chain integrity on `chain_version: 2` entries, permanently absent on `chain_version: 1` entries (ADR-0006, updated by #177 B3)**: `pid`/`ppid`/`parent_process`/`cwd_hash` were originally deliberately excluded from `HashableEvent` (Design A) alongside `CHAIN_VERSION` staying at `1`. `CHAIN_VERSION` is now `2`, and `HashableEventV2` includes all four — a same-user attacker with direct write access to `audit.jsonl` but **without** the HMAC secret **can no longer** alter these fields on a v2 entry without `omamori audit verify` flagging it (`broken_at`). This is the same threat-model boundary as the rest of this document — an attacker who has also read the secret (`~/.local/share/omamori/audit-secret`, same OS user, chmod `0600`) can forge a self-consistent chain regardless of `chain_version`; the [Defense Boundary](#defense-boundary) table's "AI reads secret and forges valid chain" row already lists this as "Not protected" and this change does not alter it. This protection is *not* retroactive: existing `chain_version: 1` entries are never rewritten (ADR-0007), so their `pid`/`ppid`/`parent_process`/`cwd_hash` values remain exactly as unprotected as before — a same-user attacker can still alter them freely on any v1 entry. An investigation spanning the v1→v2 upgrade boundary must treat these fields as corroborating signal (cross-reference against shell history, hook configuration, process accounting) for v1 entries specifically, and as tamper-evident for v2 entries.

**Residual exposure via `--json`**: `parent_process` is sanitized once at collection time (control characters stripped — see below), which covers `omamori audit show --json` and any future display surface by construction. For a `chain_version: 1` entry, this does **not** cover a same-user attacker who writes a hand-crafted line directly to `audit.jsonl` bypassing omamori's own collection path entirely — that line's `parent_process` field is not chain-protected, so raw control bytes could be reintroduced there undetected. For a `chain_version: 2` entry, reintroducing control bytes changes the hashed field value and surfaces as `broken_at` on `omamori audit verify` — but an investigator who renders `--json` output *without* running `verify` first gets no such guarantee either way. An investigator piping `--json` output through `jq -r` or similar on a log of uncertain provenance should not assume every `parent_process` value is safe to render on a terminal without inspection, regardless of chain_version.

**Control character sanitization**: `parent_process` is stripped of ASCII/Unicode control characters (replaced with `U+FFFD`) and capped at 1024 characters once, at collection time — this covers every consumer (current and future) by construction rather than requiring each display site to sanitize separately. See the residual-exposure caveat immediately above for what this does and does not close.

**Incident investigation runbook**:
1. `omamori audit show --json | jq -r '.ppid' | sort | uniq -c | sort -rn` (add `--rule`/`--provider`/`--last N` to `show` first to narrow the entry set) to rank `ppid` values by how often they recur across suspicious entries — the same launcher firing more than once is the strongest correlation signal.
2. Cross-reference `parent_process` for those entries against installed application paths to identify which tool or shell was the actual launcher.
3. For directory correlation, run `omamori audit hash-cwd <suspected-path>` and grep the log for any of the printed candidate hashes.
4. Treat every finding from steps 1-3 as corroborating, not conclusive — cross-check against shell history, hook configuration, and process accounting before attributing an incident to a specific tool or process tree. See "Not an authenticated identity" above for why.

### HMAC Integrity

- **Per-install secret**: 32 bytes from `/dev/urandom`, stored at `~/.local/share/omamori/audit-secret` (chmod 0600)
- **target_hash**: `HMAC-SHA256(secret, targets)` — file paths are never stored in plaintext
- **entry_hash**: `HMAC-SHA256(secret, canonical_json(entry))` — computed over a fixed-field-order canonical struct, selected per-entry by its own declared `chain_version`: `HashableEvent` (15 fields) for `chain_version: 1`, `HashableEventV2` (20 fields — `HashableEvent`'s 15 plus `pid`/`ppid`/`parent_process`/`cwd_hash`/`wrapper_kind`) for `chain_version: 2` (#177 B3). Either way, the struct ensures deterministic hashing regardless of serde serialization options
- **Genesis**: First entry's `prev_hash` = `HMAC-SHA256(key, "omamori-genesis-v1")`, where *key* is
  the one named by that entry's `key_id` — **not** whichever key is active at verification time. A
  chain that began before a rotation is anchored to the retired key's genesis and stays anchored
  there; nothing on disk is rewritten when a rotation happens

### Hash Chain

Each entry's `prev_hash` contains the previous entry's `entry_hash`. This creates a tamper-evident chain: modifying or deleting any entry breaks the chain for all subsequent entries.

```
Entry 0: prev_hash = genesis_hash,  entry_hash = H0
Entry 1: prev_hash = H0,            entry_hash = H1
Entry 2: prev_hash = H1,            entry_hash = H2
         ↑ deleting Entry 1 breaks H2 verification
```

### Concurrent Safety

`append()` uses `flock(2)` (exclusive advisory lock) to prevent chain corruption when multiple omamori shim processes run simultaneously. The file is opened with `read+write+create` (not `O_APPEND`) to allow tail-reading for chain state under lock.

### Torn Line Recovery

If a previous write was interrupted (partial JSON line), `append()` detects the unterminated line and inserts a newline before writing the new entry. `read_last_valid_line()` scans backward, skipping invalid JSON fragments, to find the last intact chain entry.

### Defense Boundary

**What the audit log can and cannot protect against:**

| Attack | Defense | Effectiveness |
|--------|---------|---------------|
| AI modifies log via omamori hook layer | `PROTECTED_FILE_PATTERNS` + Phase 2 rules | Detected and blocked |
| AI modifies log entries (content change) | Hash chain (`entry_hash` mismatch) | Detected by `omamori audit verify` |
| AI deletes/reorders entries mid-chain | Hash chain (seq gap / `prev_hash` mismatch) | Detected by `omamori audit verify` — **unless** a `chain_version` entry this binary doesn't recognize is also planted ahead of the tamper (#177 B1): verification stops at that entry and reports exit 4 ("unrecognized chain_version", not tamper language) instead of exit 1. The tamper is not hidden — the high-water-mark is preserved untouched, `report`/`doctor` are non-quiet, and removing the planted entry restores full detection — but the *language* softens from "broken" to "unverifiable" while it's present. See [Forward-Unknown Chain Versions](#forward-unknown-chain-versions-177) |
| AI truncates log tail (removes last K entries) | Seq high-water-mark file (`<audit-log>.hwm`, e.g. `audit.jsonl.hwm`), symlink-safe atomic write/read | Detected by `omamori audit verify` (exit 3). Symlink swap and torn writes are rejected. A same-user attacker who directly overwrites the `.hwm` file's content (not via symlink) can still defeat detection — structural limitation, same as row below. The comparison **survives a verification halt** (#470): an entry whose `chain_version` or `key_id` this binary cannot resolve no longer suppresses it, so planting one ahead of the deletion does not buy silence and the verdict stays exit 3. What it compares against in that state is the end the surviving lines *state* rather than an authenticated one, so an attacker who also renumbers the tail can still hide the removal. See [Truncation Detection Across a Halt](#truncation-detection-across-a-halt-470) |
| AI accesses secret via omamori hook layer | `PROTECTED_FILE_PATTERNS` + Phase 2 rules | Detected and blocked |
| AI Edit/Write to protected files (config, audit, hooks, settings.json) | `is_protected_file_path` + `PROTECTED_FILE_PATTERNS` | **Blocked** (v0.8.0 #110) |
| AI directly operates on files via OS (bypassing hook layer) | None (same OS user) | **Not protected** (structural limitation) |
| AI reads secret and forges valid chain | None (same OS user) | **Not protected** (structural limitation) |

**Fundamental constraint**: AI agent and omamori run as the same OS user. Unix file permissions do not provide isolation. `PROTECTED_FILE_PATTERNS` and Phase 2 rules operate at the hook layer only (`check_command_for_hook()`). Complete filesystem isolation requires OS-level sandboxing — use your AI tool's sandbox (Codex CLI sandbox (on by default), Claude Code `/sandbox`, Cursor agent sandbox) or a dedicated tool like [nono](https://github.com/always-further/nono).

**`audit.path` and `HOME` are trust roots, not further validated** (#439): a relative or empty `audit.path` in config.toml is ignored (`AuditConfig::validate()` normalizes it away, closing the #210-class CWD-scatter hazard where the audit log and its HMAC secret land in the process's working directory). An *absolute* `audit.path`, and `HOME` itself, are trusted verbatim — a same-user attacker who can write config.toml or set `HOME` can still redirect where the log and secret are written (e.g. into their own writable directory to co-locate the secret). This is the same same-user structural limitation as the rest of this section, not a new gap.

### Audit Log Read Access (v0.9.7+)

`audit.jsonl` is user-readable by design. On a shared user account, anything that can read the home directory can also infer AI tool usage patterns — tool names, timestamps, command columns (and, for `unknown_tool_fail_open` events, top-level `tool_input` key counts) — from the audit log. Target paths are HMAC-hashed (`target_hash`), so concrete file paths are not disclosed, but the existence and shape of activity is.

**Process provenance fields (v0.13.1, #420)** add to this disclosure surface: `pid` and `ppid` are plaintext process IDs (low sensitivity — they are ephemeral and reused by the OS), but `parent_process` is a plaintext resolved exec path (e.g. `/Users/<name>/.nvm/versions/node/.../node` or `/Applications/Cursor.app/...`), which can reveal installed applications, username-bearing paths, or directory structure to anyone who can read the home directory. `cwd_hash` follows the same HMAC-hashing treatment as `target_hash` and does not add new plaintext disclosure. See [Process Provenance](#process-provenance-v0131-420) above for the full field-by-field rationale, including why `parent_process` is plaintext while `cwd_hash` is hashed.

This is consistent with the same-user OS threat model: HMAC integrity protects against forgery and tampering, not against read access. Encryption-at-rest is out of scope; the secret would live in the same home directory the attacker is already presumed able to read, which would not change the threat surface.

Operators who treat AI tool usage itself as confidential should run AI tools under a dedicated OS user, mount the audit directory on an encrypted volume keyed outside the home directory, or both.

### Report Read Access (v0.10.0+)

`omamori report` aggregates audit log data into summary statistics (block counts by layer/provider, unknown-tool fail-open counts, chain integrity status). This is the same data surface as `audit show` — read-only, no AI environment guard — consistent with the same-user OS threat model established above.

**Design boundaries**:
- Duration window is capped at 90 days (SEC-R4). Longer history is available via `audit show --all`.
- `--json` output is limited to 8 fields (SEC-R2): `period_days`, `actual_window_days`, `total_blocks`, `by_layer`, `by_provider`, `by_rule`, `chain_status`, `unknown_tool_fail_opens`. Per-rule counts are included because `audit show` already exposes the same data — the report adds convenience, not new information surface.
- Provider aggregation uses the `provider` field (e.g. `claude-code`, `codex-cli`), not internal wrapper names (channel separation maintained per v0.9.5 invariant).
- Unknown-tool shapes are reported as counts only; detailed tool names require `audit unknown` (SEC-R7).

**Accepted risk**: An AI agent polling `omamori report --json` on a schedule can observe activity patterns (block frequency, provider distribution). This is inherent to the same-user model — the agent can already read `audit.jsonl` directly. The report subcommand adds convenience, not new information surface.

### Secret Loss

If the secret file is deleted or unreadable:
- `load_or_create_secret()` attempts to generate a new secret
- If generation also fails, entries are written with `NO_HMAC_SECRET` marker
- `omamori audit verify` (v0.7.1) will flag these entries
- **Strict mode** (v0.7.3): When `audit.strict = true`, AI commands intercepted by the PATH shim are blocked if the secret is unavailable after re-creation attempt. Hook-only commands (not matching any shim rule) are not affected

### Key Rotation (v0.8.0+, semantics fixed in #457)

`omamori audit key rotate` renames the active secret to `audit-secret.{N}.retired` and generates a
new one. Entries written from that point carry `key_id: "key-{N+1}"`; entries written earlier keep
the id of the epoch that signed them (`"default"` for the store's first key).

**Retired key files must be kept.** They are not backups — they are the only way to verify entries
from their epoch, and deleting one is not recoverable.

What happens when one is missing depends on whether *any* retired key remains:

- **Some remain.** The entries signed by the deleted key report as **cannot verify** (exit 2),
  naming the key id that could not be resolved
- **None remain, and the store has an epoch record.** Same answer: **cannot verify** (exit 2). The
  record holds the active epoch where it is, so `"default"` is not aliased onto the active key
- **None remain, and the store has no epoch record.** The store is indistinguishable from one that
  never rotated. `"default"` resolves to the *active* key — an id that exists, holding the wrong
  bytes — so the affected entries report as **tampering** (exit 1)

The third case is what the second one used to be for every store. It was a known limitation, not a
judgement about the log, and PR-C1 closed it for any store that has rotated since — see the epoch
record below. ADR-0008's Update block records why the fix this paragraph originally proposed
("each key file records which epoch it belongs to") would not have worked: what has to be told
apart is a generation that is *gone*, and a file that is gone carries no tag.

#### The epoch record (PR-C1)

`audit-secret.epoch` holds one decimal integer — the highest epoch this store has ever handed out.
Rotation writes it between the rename and the new key's creation, durably, so a number is on disk
before any key can carry it. Epochs are then read as `max(recorded, max_retired + 1)`, which is
the previous derivation whenever the retired slots are intact and higher than it when they are
not.

- **A store with no record behaves exactly as it did before.** Only rotation writes one, so a
  store that has not rotated since upgrading never gains one, and a fresh install does not either.
- **The record is advisory, not enforced.** Removing it returns the store to deriving the epoch
  from the retired key files. `PROTECTED_FILE_PATTERNS` matches the `audit-secret` prefix, so an
  AI agent cannot write to it; an operator can.
- **A record that does not state an epoch fails closed**: `verify` exits 2 and `rotate` refuses,
  both naming the file and saying that removing it restores the derivation. This is stricter than
  the treatment of a corrupt `.retired` file, which is a non-fatal anomaly — the record decides
  which key epoch *every* entry is labelled with, so guessing past it is the thing being avoided.
- **A generation whose key is gone is not handed out again.** The store mints under the next
  number and records that. Entries under the lost epoch stay cannot-verify — their key really is
  gone — while entries written afterwards carry a label no earlier entry can hold.
- **Older binaries ignore the file.** It does not end in `.retired`, so no version of omamori
  counts it as a key. One state is conditional: a store that skipped an epoch is mislabelled by
  v0.16.0, and entries written there can read as cannot-verify after upgrading again.

#### How a rotation is ordered

1. Build the replacement key at `audit-secret.pending` (`O_EXCL`, `O_NOFOLLOW`, `fsync`).
2. Rename the active key into `audit-secret.{N}.retired`.
3. Record the new epoch (`fsync`).
4. Rename the replacement into `audit-secret`.
5. `fsync` the directory.

**Everything that can fail while producing a key fails at step 1**, where the store has not been
touched: no entropy source, no free descriptors, no room for the 64 bytes. Steps 2-4 are
directory-entry changes — a smaller surface, not an exempt one. `rename` can still return
`ENOSPC` when the target directory cannot be extended, and a failure in that window is reported
as an interrupted rotation, naming the file that moved.

A crash between steps 2 and 4 leaves the interrupted state described above, and the epoch record
is what makes the recovery skip that number instead of reusing it. A crash at step 1 leaves an
`audit-secret.pending` holding a key **nobody was given** — the readers never resolve that path,
so no entry can name it — and the next rotation removes it, saying so. Anything at that path that
is *not* a regular file is refused instead: a rotation will not delete a file omamori did not
write, and the refusal happens before the store changes, so it costs a rotation rather than a key.

#### What rotation guarantees

- Entries written before the rotation continue to verify, against the retired key, with no
  rewriting of anything on disk. The chain's genesis anchor and every prune point are recomputed
  with the key each one names, not with whichever key is currently active
- New entries are signed with the new key
- A key that cannot be found is reported as **cannot verify** (exit 2), distinctly from tampering
  (exit 1) and from an unrecognized `chain_version` (exit 4). "The key file is gone" and "the log
  was altered" are different situations with different remedies
- A rotation run through this command leaves a record of itself in the log — see
  [Key rotation events](#key-rotation-events-457). Before #457 a rotation was visible only because
  it broke the chain; fixing that removed the signal, and this replaces it with an explicit one

#### What rotation does *not* guarantee

**Rotating does not neutralize a leaked key.** `verify_chain` resolves each entry's key from the
`key_id` that entry declares, and performs no check that key epochs advance monotonically along
the chain. An attacker holding any past key — active or retired — can forge an entry that names
that key, and it will verify. Rotation limits which *future* entries a leaked key can produce; it
does not invalidate the leaked key for the purpose of forging entries labelled as belonging to its
own epoch.

Treat a leaked audit key as a permanent loss of tamper-evidence for the epochs it covers. Rotation
is hygiene against future exposure, not remediation of past exposure.

**The rotation record does not prove a rotation did not happen.** It is written only by
`omamori audit key rotate`; renaming the key files directly produces the same result silently, and
so does a crash between the rename and the append. An absent record is not evidence of an absent
rotation, and the record itself is an ordinary log entry — anyone who can write `audit.jsonl` can
remove it, exactly as they can any other.

#### Operational notes

- Files matching `audit-secret.*.retired` whose suffix is not a canonical decimal number (for
  example `audit-secret.bak.retired`) are ignored, not counted as rotations. Before #457 such a
  file shifted the `key_id` of every subsequent entry and could make an unrotated store report a
  broken chain
- The converse is **not** true, and it is the more dangerous case: a copy whose suffix *is* a
  canonical decimal is not ignored, it is registered as that epoch. Copying
  `audit-secret.1.retired` to `audit-secret.2.retired` gives `key-2` epoch 1's bytes while the
  active key moves to `key-3`, so entries already labelled `key-2` stop verifying — a permanent
  false tampering verdict, produced with no attacker. Keep spare copies **outside** the data
  directory
- The next retired slot is chosen from the highest index present, and rotation refuses to
  overwrite an existing retired key
- **Rotation requires a complete listing of the key directory, and refuses without one** (#477).
  Every other reader of that listing already failed closed; rotation is the only one that *changes*
  the store, and it was taking the highest index from a scan it never asked about. On a store whose
  low retired slots were tidied away, a failed scan reads as "never rotated", so the current key
  goes into `audit-secret.1.retired` and the new one is named after an epoch that already exists —
  and once the directory is readable again those entries resolve to the wrong bytes and report as
  tampering, permanently, with no attacker involved. The refusal renames and creates no key file
  and exits 1 — `audit-secret.lock` may already exist by then, which holds no key material and is
  recreated on demand; re-run once the directory can be listed. A listing that *stops partway* counts as no
  listing: an error mid-enumeration ends the iteration, so the unread remainder — which is where
  the highest epochs sort — would otherwise be silently absent from a result that looks complete
- The keyring loads at most 256 keys, keeping the highest indices. If more exist, `verify` reports
  the truncation rather than silently verifying against a partial set
- A rotation interrupted between the rename and the new key's creation leaves the retired key in
  place and the replacement uncreated. `audit key rotate` says so when the failure happens under
  it, naming the file the previous key was moved to, and stops there — it does not describe the
  store afterwards, because the failure can be `AlreadyExists`, which means some other writer has
  put a file at that path. Otherwise omamori reports the state the next time any command resolves a
  key, **after** attempting a replacement, and reports which of two things it then observed:
  - **An active key is present.** Entries from that point carry its label. On a store with an
    epoch record that label names a *new* generation: the interrupted rotation's number was
    recorded before its key existed, so it is not handed out a second time and no two secrets can
    share one `key_id`. Whatever that generation did sign, if anything, reports as cannot verify —
    its key is gone, which is the honest answer. On a store with no record the older behaviour
    stands: the replacement takes the very label the interrupted rotation was heading for, and if
    that rotation had already handed out a key under it, two secrets share one `key_id`, those
    entries are permanently unverifiable, and the verifier reports them as tampering rather than
    as cannot-verify, because the id resolves and only the bytes differ. Copying a retired file
    over the active key destroys it in either case.
  - **No active key could be created** — a directory that can be read and searched but not written
    denies it. Entries written while that lasts carry no HMAC at all and stay unverifiable;
    clearing the condition protects later ones, not those.

  **The warning is all that happens** in either case: omamori records nothing durable about the
  interruption and takes no repair action. The detection condition is "there is no `audit-secret`",
  not "the active key could not be read" — a directory that denies `open` while holding an intact
  key is a permissions fault, and treating it as an interrupted rotation used to print a recovery
  step that would have overwritten that key
- The data directory contains an `audit-secret.lock` file. It holds no data and is used only as an
  `flock` target, so that resolving the active key and rotating it cannot interleave. It is not a
  key and is never treated as one. It is recreated on demand, so losing it costs nothing beyond
  the serialization it provides — but note that `PROTECTED_FILE_PATTERNS` matches it (the rule is
  a `audit-secret` filename prefix), so an AI session cannot delete it through the shim or hook
  layers
- **No lock omamori takes is allowed to block indefinitely.** Acquisition uses `LOCK_NB` with a
  bounded retry budget (100 × 5 ms). What happens when that budget runs out differs by site, and
  only one of the three proceeds anyway: the key-store lock degrades to unlocked — rotation says
  so when it does — while `append` and `verify_chain` return the failure to their caller. This is
  not a performance choice. `flock` works on a read-only descriptor, so any local process able to open one of these
  files could otherwise hold a lock forever and stall every omamori surface — including
  `hook-check`, which would hang *before* printing its deny verdict and leave the outcome to the
  host's hook-timeout policy rather than to omamori. `PROTECTED_FILE_PATTERNS` does not help here:
  it governs AI-mediated file operations, not an interpreter calling `flock` directly. The lock
  file is created `0600`, like every other file omamori writes in this directory

### Strict Mode (v0.7.3+)

Opt-in fail-close mode. When enabled, AI commands intercepted by the PATH shim are blocked if the audit HMAC secret is unavailable, preventing unverifiable command execution. Commands that only pass through Layer 2 hooks (not matching any shim rule) are not affected — the secret-unavailable gate exists only on the shim path (`engine::shim`), which tests `secret_available()` before running the command. The hook path does build loggers, and consults `strict` too, but only in response to an append that actually failed.

**Configuration**:
```toml
[audit]
strict = true  # default: false
```

**Behavior**:

| Condition | strict=false (default) | strict=true |
|-----------|----------------------|-------------|
| Secret available | Normal operation | Normal operation |
| Secret unavailable + AI detected (shim path) | Log with `NO_HMAC_SECRET` | **Block command (exit 1)** |
| Secret unavailable + human terminal | Normal operation | Normal operation |
| Audit disabled (`enabled = false`) | — | strict ignored |

**Design decisions**:
- **Opt-in**: Default `false` preserves backward compatibility. Users explicitly opt in.
- **AI-only**: Only affects `detection.protected = true` paths. Human terminal use is never affected.
- **After re-creation attempt**: `AuditLogger::from_config()` calls `load_or_create_secret()` first. Strict only triggers when re-creation also fails.
- **Residual TOCTOU**: `secret_available()` check and subsequent `append()` are not atomic. An attacker deleting the secret between check and use could bypass strict mode. This is accepted because: (1) the attacker would need to delete the secret within the same process execution window, (2) `PROTECTED_FILE_PATTERNS` protects the secret file from AI-layer deletion.

### Symlink Protection (v0.7.3+)

Every file omamori reads is opened with `O_NOFOLLOW`, so a symlink is rejected by the kernel rather than followed to wherever it points. This prevents symlink attacks where an attacker replaces `audit.jsonl`, `audit-secret`, `config.toml` or a hook script with a link to `/dev/null` or a location they control.

The rule is enforced in **one place** — `atomic_file::open_read_regular` for reads, `atomic_file`'s `create_new`/rename helpers for writes — rather than restated per call site. That is a correction, not a style preference: the earlier per-caller form left three paths unprotected (`audit.jsonl.hwm`, `break-glass.json`, `config.toml`), two of which could hang `hook-check` before it printed its deny verdict. A check that lives on callers does not reach the next caller (#468).

The table below enumerates the **audit-file** operations specifically, because their individual failure modes differ. It is not the full set of protected reads; that set is "every read", by construction of the helper.

| Operation | File | Effect on symlink |
|-----------|------|-------------------|
| `append()` | audit.jsonl | `ELOOP` error, entry not written |
| `read_secret()` | audit-secret | Rejected before open, "possible attack" error, secret not loaded |
| `create_secret()` | audit-secret | `ELOOP` error, secret not created |
| `verify_chain()` | audit.jsonl | `ELOOP` error, verify fails |
| `show_entries()` | audit.jsonl | `ELOOP` error, show fails |
| `audit_summary()` | audit.jsonl | `ELOOP` error, count returns 0 |
| `with_key_store_lock()` | audit-secret.lock | `ELOOP` error, lock skipped; non-regular files rejected after open |
| `write_hwm()` | audit.jsonl.hwm | Refuses to write; final/temp symlink rejected before open |
| `read_hwm()` | audit.jsonl.hwm | `ELOOP` at the open, reported as tampered; a FIFO or directory there is refused the same way |

*Note: one of these does not rely on an `O_NOFOLLOW` open.*

- *`write_hwm()` publishes the final file via atomic `rename`, which cannot land on a symlink at the destination. `O_NOFOLLOW` is still used for the temp file during write.*
- *`read_secret()` gained an `lstat` pre-check in #457. It rejects a symlink **before** reaching its `O_NOFOLLOW` open, and its symlink branch deliberately keeps the same "possible attack" wording the `O_NOFOLLOW` path produced, since `verify_chain` distinguishes a symlinked secret from an ordinary missing one by that phrase.*

*A stat followed by an open is a TOCTOU window, so the pre-check is an early rejection with a precise message, **not** the enforcement. Both hazards are closed at the descriptor instead, by one shared helper (`atomic_file::open_read_regular`) that every read in omamori goes through: `O_NOFOLLOW | O_NONBLOCK` on the open (a FIFO cannot make `open()` wait for a writer), an `fstat` on the resulting descriptor that refuses anything which is not a regular file, and a `take()` bound applied there rather than to a prior `len()`. These paths are re-read on every command, so an attacker racing the window gets unlimited attempts; a check that only inspects the name is not a control.*

*The helper is shared rather than per-caller for a measured reason (#468). The first version of the check lived on `read_secret`, and the next caller added in the same change shipped without one. Three further paths — `audit.jsonl.hwm`, `break-glass.json` and `config.toml` — were still hanging afterwards, two of them hanging `hook-check` before it printed its deny verdict. A check that lives on callers does not reach the next caller.*

**Limitations**:

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| Parent directory symlinks not detected | `O_NOFOLLOW` only applies to the final path component | `create_dir_all` is called by omamori itself; `PROTECTED_FILE_PATTERNS` protects `.local/share/omamori` |
| Hardlink attacks not detected | `O_NOFOLLOW` does not affect hardlinks | Same-user structural limitation. Hardlinks require same-partition + same-user |
| Non-Unix platforms have no symlink protection | `O_NOFOLLOW` is Unix-specific (`#[cfg(unix)]`) | On non-Unix, audit operates without symlink protection. Document as known limitation |

### Audit Retention (v0.7.2+)

Optional automatic pruning of old audit entries. Preserves the tamper-evident property through a cryptographic prune_point.

**Configuration** (`~/.config/omamori/config.toml`):
```toml
[audit]
retention_days = 90  # 0 = unlimited (default)
```

**Security properties**:

| Property | Mechanism |
|----------|-----------|
| Prune_point authenticity | `entry_hash` = HMAC-SHA256 over all fields, computed with the key the prune point's `key_id` names (that key is required to forge it) |
| Prune_point anchoring | `prev_hash` = HMAC(key, "omamori-prune-v1") — distinct from chain genesis. *key* is again the one the prune point names, not whichever key is active at verification time; a prune that ran before a rotation stays anchored to the key it ran under |
| First-retained binding | `target_hash` = HMAC(key, "prune-bind:{count}:{first_retained_entry_hash}"), where *key* is the prune point's own — the same one its `key_id` names and its `entry_hash` authenticates under. Not the key of the first retained entry, which may belong to an earlier epoch |
| Minimum retention | 7 days enforced (values < 7 clamped with warning) |
| Minimum entry count | 1000 entries always retained regardless of age |
| Config protection | `omamori/config.toml` protected by `PROTECTED_FILE_PATTERNS` |
| Trigger frequency | Every 1000 appends (seq % 1000); zero overhead otherwise |

**Threat model**:

| Attack | Defense |
|--------|---------|
| Forge prune_point to hide evidence | entry_hash HMAC verification fails without secret |
| Delete entries after legitimate prune | target_hash binding mismatch detected by verify |
| Set retention_days=1 to fast-erase | Clamped to min 7; config.toml blocked from AI editing |
| Truncate file (remove prune_point + entries) | prev_hash ≠ genesis → chain broken |

**Verification**: `omamori audit verify` detects pruned chains and reports: `N entries verified, chain intact. (M entries pruned; prune_point anchored)`.

**Design decision**: In-place rewrite (not tmpfile→rename). Rationale: rename changes the inode, which breaks flock for any other process holding the old inode. Prune is best-effort under flock; crash during rewrite produces torn lines handled by existing recovery.

### Legacy Compatibility

Entries written before v0.7.0 lack chain fields. When `append()` encounters a legacy last entry (no `chain_version`), it starts a new chain from genesis (`seq=0`). `omamori audit verify` skips legacy entries with a warning. A log containing only legacy entries returns exit code 2 (no chain entries to verify). A legacy entry appearing *after* real chain entries have started (not at the head) fails closed as `broken_at` (#177): legacy entries never participate in `prev_hash`/`seq` continuity tracking, so an attacker could otherwise splice unaudited content into the middle of an otherwise-verified chain by making it look legacy. Note this fail-close is deliberately blind to *why* the entry looks legacy — a genuine downgrade (running an older omamori binary against a chain a newer one had already extended) produces the identical shape and is not distinguished from an attack; see Forward-Unknown Chain Versions below for the analogous, and equally undistinguishable, upgrade-direction case.

### Forward-Unknown Chain Versions (#177+)

An entry declaring a `chain_version` this binary doesn't recognize (a future format, or a downgrade after a newer entry was written) is *not* treated as tampering. `omamori audit verify` reports it distinctly and exits with code **4**, stopping verification at that entry — everything from it onward is counted but not trusted (the `prev_hash` chain running through an unauthenticated entry can't be relied on for anything after it either). `omamori report`/`doctor` surface this the same way, with wording that does not claim tampering. `append()` similarly refuses to write when the *last valid JSON line within the 64 KB tail window* (`read_last_valid_line`'s search range, not necessarily the file's literal last byte) has an unrecognized `chain_version`: it returns an error, so `[audit] strict = true` blocks the triggering command the same way it blocks on any other unrecordable event; in the default (non-strict) mode, every existing call site's own error handling turns this into a stderr warning only, never affecting the command's own block/allow decision (G-2, best-effort). **This warning is throttled on the Layer 1 (PATH shim) path** (`try_audit_append`, at most once per 5 minutes — pre-existing behavior shared by every append failure reason, not specific to this case), so a persistent unrecognized-`chain_version` tail (e.g. after a downgrade following a chain a newer omamori extended, or in an environment mixing binaries across the version boundary) surfaces one warning and then goes silent for up to 5 minutes at a time even though every intervening command's audit event is still silently dropped; the Layer 2 (hook) path (`warn_audit_append_error`, the break-glass site) is not throttled and warns on every failure. QA Phase 8 (#177 B3) confirmed this experimentally: a rapid sequence of Layer 1 commands against an unrecognized-version tail produced only the first warning, not one per command.

**Residual risk — exit 4 can be attacker-induced to soften real tampering.** Because a genuine future `chain_version` and a forged one are indistinguishable without a signature this binary can't verify, an attacker with `audit.jsonl` write access can plant one line ahead of an actual deletion/reorder — or, as of `chain_version` 2 (#177 B3), ahead of a `pid`/`ppid`/`parent_process`/`cwd_hash`/`wrapper_kind` value tampering on an otherwise-hashed v2 entry — to downgrade the report from exit 1 ("chain broken … may have been tampered with") to exit 4 ("unrecognized chain_version … not necessarily tampering"). This does **not** destroy evidence: the high-water-mark file is left untouched (not bootstrapped, not lowered) rather than silently advanced past the gap, `report`/`doctor` are non-quiet either way, and removing the planted line restores full detection of the underlying tamper. Tail truncation is deliberately left off that list: since #470 the mark is still **compared** in this state, so a removed tail behind the planted line is reported as truncation (exit 3) rather than downgraded — see [Truncation Detection Across a Halt](#truncation-detection-across-a-halt-470). The attacker also cannot mask anything that happened *before* the planted line — `broken_at` still wins if the real tamper is earlier in the file. This is the accepted cost of forward compatibility, not a defect to be patched away: refusing to verify past a version boundary the binary can't authenticate is the same design principle that makes the "unrecognized version" case safe in the first place. Operators: if `omamori audit verify` reports exit 4 and you are already running the latest omamori, treat it as possible tampering, not merely a version mismatch — the CLI reflects this same caution (`omamori audit verify --help` / the exit-4 message itself).

The tail-check's 64 KB window (shared with all `read_last_valid_line`/`read_chain_state` tail-reading) also means a sufficiently large amount of non-JSON content appended after a planted entry can push it out of the window `append()`'s refusal checks, letting appends resume — the refusal is a property of *the current tail*, not a permanent latch on the file. This mirrors `read_chain_state`'s pre-existing genesis-fallback behavior for any unparseable tail (not new in #177) and is **not** narrowed by #177 B3's `CHAIN_VERSION` 1→2 flip — the flip's scope is the version dispatch itself, not this orthogonal window-size hardening. Tracked in [#465](https://github.com/yottayoshida/omamori/issues/465) instead.

### Sequence Numbers at the Representable Limit (#456)

`append()` reads the tail entry's `seq` to number the entry it is about to write. That number is **not authenticated** at this point: the append path checks that `entry_hash` is a non-empty string and never recomputes it, so a single hand-written line can put any `u64` there — no HMAC key required. `u64::MAX` has no successor, so the increment is checked and a supported-version tail at the limit is refused rather than incremented.

Whether a successor exists is decided from `seq` alone, and **before** the check on `entry_hash`'s shape. That order is load-bearing: a malformed entry is answered by restarting the chain from genesis, which numbers the next entry `0` — so a line combining `seq: u64::MAX` with an empty `entry_hash` would otherwise take the restart path and reach the same `seq: 0` outcome the refusal exists to prevent, without ever passing through the increment.

The refusal takes the same shape as the unrecognized-`chain_version` refusal above: `append()` returns an error naming the number it observed, `[audit] strict = true` blocks the triggering command as it does for any other unrecordable event, and the default non-strict mode turns it into a stderr warning that does not change the command's own block/allow decision (G-2). The message does not call the line tampered — nothing in this path authenticated it. Nor does it say who wrote the line: omamori will itself write a `u64::MAX` entry when handed a tail numbered one below, so the number establishes only that counting did not produce the history leading to it.

**What the refusal prevents.** Without it, the next entry is numbered `0` — that was the shipped behaviour before `[profile.release]` set `overflow-checks = true`, and the flag alone would only have converted it into a panic, which is a different wrong answer for a store that is intact. A `seq` of `0` against a populated high-water-mark takes the truncation-detection path: `append()` warns that the tail *may have been truncated* when nothing was removed, and `omamori audit verify` compares the same way. In the narrower case where the `.hwm` sidecar is itself unreadable or symlinked (`HwmState::Tampered`), the wrapped value is written back as the new mark, lowering it to `0` and leaving later real truncation undetectable against it. Neither outcome requires the attacker to hold the HMAC key, which is what made this worth closing before 1.0 rather than documenting as residual.

**The other half of this root was closed separately.** The post-prune high-water-mark recomputation in `retention.rs` trusted on-disk `seq` values the same way — see [The Post-Prune High-Water-Mark](#the-post-prune-high-water-mark-461) below. What is still open under [#461](https://github.com/yottayoshida/omamori/issues/461) is a different concern in the same file: a prune that removes an unverifiable range leaves no trace of it.

### The Post-Prune High-Water-Mark (#461)

The high-water-mark records the highest `seq` written so far, and `omamori audit verify` compares the chain against it to detect a tail that has been removed. After a prune rewrites the log, the mark has to be recomputed from what remains.

That recomputation took the largest `seq` among the retained lines, read straight out of the JSON. Nothing checked whether the line it came from had been written by omamori — so one planted line with a high `seq` put the mark wherever its author chose. **No key is needed to write that line**: this recomputation was the only thing that read the field back.

What a raised mark produces is a false accusation, not concealment. `verify` reports a truncated tail when the mark sits above the chain, so the log is reported as cut when nothing was removed, and it stays reported that way — prune is the only thing that recomputes the mark, and it runs once per 1000 appends. Lowering the mark is what would hide a removal, and that is not reachable through this path, since the mark is a maximum. The defect is that tamper-evidence about the log was taken from the log without authenticating it, which is the root [#456](https://github.com/yottayoshida/omamori/issues/456) closed on the append side.

The mark now comes from an entry that authenticates against the key its own `key_id` names, resolved through the same keyring `verify` uses — so an entry signed with a *retired* key still counts, which an active-key-only check would have missed. Retained entries are tried in descending `seq` order and the first one that authenticates wins, so the ordinary case costs one HMAC rather than one per retained entry, and the answer is the same either way.

Two states leave the mark untouched rather than guessing at it. **No retained entry authenticates** — including the case where the keyring holds nothing usable, which arrives here identically because every lookup misses — leaves the previous mark in place and says which of the two it was, since one is a key-store fault an operator can fix and the other is a statement about the entries. And **with no secret at all the prune does not run**: `hmac_bytes` answers a `None` key with the fixed string `NO_HMAC_SECRET`, so the prune point standing where the removed entries used to be would carry a `target_hash` and an `entry_hash` any reader can reproduce — a prune-bind that binds nothing. Keeping the entries is the lesser loss, and the log says why it is growing.

Auto-prune is off by default (`retention_days = 0`), so none of this path runs in a default install.

**Still open in the same file.** A prune that removes a range containing unverifiable entries leaves no record that it did: `prune_point` carries an entry count and nothing about how many of those entries could not be verified, so a `verify` that reported exit 4 before the prune reports exit 0 after it. That is the remaining half of [#461](https://github.com/yottayoshida/omamori/issues/461); it needs a field the `AuditEvent` schema does not have today, which is a `chain_version` question rather than a change to this recomputation.

### Truncation Detection Across a Halt (#470)

`omamori audit verify` stops authenticating at an entry it cannot check — one declaring a `chain_version` this binary does not recognize (#177 B1), or naming a `key_id` the keyring does not hold (#457). From that point on the remaining lines are counted, not trusted, because the `prev_hash` chain runs through an entry whose authenticity is unknown.

That halt used to take the tail-truncation check down with it. It should not have: comparing the chain's end against the high-water-mark needs no key, and the halt says nothing about whether lines are missing. The gap was reachable in two steps, both of which an attacker with write access to `audit.jsonl` already has:

1. Rewrite one entry's `key_id` to an epoch this store has no file for. `key_id` is an ordinary field of the log — no HMAC key is needed, and every hash on the line stays byte-for-byte intact.
2. Delete as many trailing lines as wanted.

Measured on v0.16.0 before the fix: exit 2, "cannot verify from entry #1", and no mention of the removal. Deleting the same lines *without* step 1 reported exit 3 and named the truncation. One edited string bought silence — and #457 had made that string a far cheaper trigger than forging a `chain_version`, which was the only route the earlier analysis considered.

**What changed.** The comparison and the write are now gated separately, by what each can honestly use:

- The **comparison** runs whatever halted, against the last `seq` *stated* by a line at or after the halting line — that line included, and unverified by definition. Only a stated value counts: a line that omits `seq` is reported at the position it should have occupied, and that number is one past the last verified entry, so using it as an end would compare the mark against the halt point instead of the file. When nothing at or after the halt states a `seq` there is no end and the comparison is skipped, which is what a future format that renames the field would produce. When the comparison does fire, `tail_truncated` outranks the halt on all three surfaces that render a verdict: `audit verify` exits 3 rather than 2 or 4, `report --json` reports `truncated`, and `doctor` prints the truncated line. Substituting one verdict for another was the point of provoking the halt, so leaving any surface behind would have left the substitution working there.
- The **write** still comes from the last *authenticated* `seq`, and still only from a run that halted nowhere. This half of #177 B1's judgement is unchanged and load-bearing: the mark is what every later run compares against, so an unauthenticated end must never become one. A halted run may therefore report that the mark is missing or unreadable, and will not repair either.

**Residual risk — the compared end is not authenticated.** An attacker who deletes the tail *and* renumbers the line the file then ends on, so its `seq` still reaches the mark, hides the removal again. Taking the last stated `seq` rather than the largest is what keeps the cost there: against a maximum, one planted line anywhere in the remainder would have answered for the end. That is strictly narrower than the state this replaced, where changing a single character was enough, but it is not equivalent to authentication and is not claimed to be. The `.hwm` sidecar itself remains plaintext and directly overwritable by a same-user attacker — the structural limitation recorded in the Defense Boundary Matrix, unchanged here.

**Not addressed.** [#470](https://github.com/yottayoshida/omamori/issues/470) also proposes checking `seq` continuity and `prev_hash` linkage across the halted region. That is deliberately not done and the issue stays open for it: in a region the binary cannot authenticate, an attacker writes those fields too, so passing the check would assert nothing — and a future `chain_version` that changes what they mean would make it fail on genuine logs, which is the forward compatibility the halt exists to provide.

### Verify Information Disclosure Policy (v0.7.1+)

`omamori audit verify` is designed to be useful to the user while limiting information useful to an attacker:

| Information | Disclosed | Rationale |
|-------------|-----------|-----------|
| Entry count | Yes | Non-sensitive; needed for user to assess log completeness |
| Broken entry position (seq #) | Yes | Needed for investigation; without HMAC secret, position alone cannot repair chain |
| Expected hash value | **No** | Would allow targeted forgery if secret is also compromised |
| HMAC secret file path | **No** | Reduces attack surface; path is derivable from code but not explicitly provided |
| Chain structure (prev_hash linkage) | Via `--json` only | Machine consumers need full provenance for forensics/SIEM. HMAC protection means chain fields cannot be forged without secret |

**Recommendation**: Run `omamori audit verify` directly in a terminal, not through an AI agent. AI agents can read stdout and may misrepresent results to the user.

## Known Operational Caveats

### Layer 2 meta-pattern false-positives on developer workflows (v0.9.7–v0.10.3, resolved in v0.10.4)

**Resolved**: v0.10.4 removed the Phase 1A meta-pattern substring matching layer (25 entries: 18 path-based + 7 verb-based) that caused 5-12 false-positive blocks per day on legitimate developer workflows. The protection previously provided by meta-patterns is now covered by Phase 1B token-level detectors (env-var tampering, PATH override bypass), Phase 2 builtin rules (`omamori-*-block` for self-modification verbs), and `PROTECTED_FILE_PATTERNS` (Edit/Write tool gate). Commands like `git commit -m "fix config disable"`, `grep pattern ~/.claude/settings.json`, and `gh issue create --body "see audit.jsonl"` now pass through without false-positive blocks.

### Test-suite pollution of contributor `~/.claude/settings.json` (v0.9.7)

Running `cargo test` against omamori's own test suite on a machine that has Claude Code installed (i.e. a real `~/.claude/` directory exists) can leave dead entries in `~/.claude/settings.json` under `hooks.PreToolUse`. Affected entries point at temporary install paths under `$TMPDIR/omamori-install-*/hooks/claude-pretooluse.sh` that no longer exist after the test run cleans up. Bash tool invocations in Claude Code subsequently emit non-blocking errors per dead entry on every command. Filed as [#210](https://github.com/yottayoshida/omamori/issues/210) (closed not planned).

**Scope**: contributors only. Production install paths (`brew install omamori`, `cargo install omamori`, manual `omamori install --hooks`) all use the canonical `base_dir = ~/.omamori`, so registered command paths are permanent across runs and dedup works correctly. The accumulation is gated behind running `cargo test` on a machine with a real `~/.claude/` directory.

**Cause** (for contributors who want to understand the mechanism): seven test sites invoke `omamori install --hooks --base-dir /tmp/...` (six as a subprocess, one in-process) without overriding `HOME`. The child process's `merge_claude_settings` resolves `claude_home_dir()` from the developer's real `$HOME` and writes the test-only base_dir path into the developer's real `~/.claude/settings.json`. After test cleanup removes the base_dir, the entry's `command` path becomes a broken reference. Each test run adds another entry because the dedup logic in `is_omamori_owned_entry` keys on the current install_root and cannot recognize prior runs' base_dirs as owned.

**Manual cleanup** (sufficient for current contributor population — the maintainer):

```bash
cp ~/.claude/settings.json ~/.claude/settings.json.bak.$(date +%Y%m%d_%H%M%S)
jq '.hooks.PreToolUse |= map(select(.hooks[0].command | test("omamori-install-") | not))' \
  ~/.claude/settings.json > /tmp/settings.cleaned.json && \
  jq . /tmp/settings.cleaned.json > /dev/null && \
  mv /tmp/settings.cleaned.json ~/.claude/settings.json
```

This filter assumes the live entry's command path does not contain `omamori-install-` (i.e. is `~/.omamori/hooks/...` or similar canonical path).

**Why no automatic fix**: a full automated cleanup would require ~500 lines (test HOME isolation across 7 sites + dedup logic strengthening + warning UX + CI lint to prevent regression) for an issue with zero impact on production users and a one-line manual cleanup for contributors. The cost/value did not justify implementation in v0.9.7. If the contributor population grows or a related issue surfaces (e.g. [#206](https://github.com/yottayoshida/omamori/issues/206) OpenClaw hook coexistence touches the same identification logic), this can be reopened. See [#210 close comment](https://github.com/yottayoshida/omamori/issues/210#issuecomment-4350136214) for the full investigation log.

### Codex CLI sandbox constraints (v0.10.11+)

Codex CLI runs commands inside a [sandbox](https://developers.openai.com/codex/concepts/sandboxing) that restricts filesystem writes to the working directory and `/tmp` by default (`workspace-write` mode). This creates two structural limitations for omamori:

| Constraint | Root cause | Impact | Mitigation |
|------------|-----------|--------|------------|
| **Layer 1 PATH shim ineffective** | Codex spawns non-login shells — `~/.zshrc` is never sourced, so `~/.omamori/shim` is not in `$PATH` | Layer 1 interception does not fire. Commands like `rm -rf /` go directly to the system binary | Layer 2 hook (`hook-check --provider codex` via `~/.codex/hooks.json`) is unaffected and catches the same commands. Layer 1 is defense-in-depth; Layer 2 is the primary gate in Codex environments |
| **Audit log write fails (EPERM)** | `~/.local/share/omamori/audit.jsonl` is outside the sandbox's writable roots | `logger.append()` returns `PermissionDenied`. The audit chain has a gap for events that occur inside the sandbox | Block decisions are **not affected** — the hook returns "block" to the AI tool regardless of audit success (best-effort audit, SEC-7 invariant). omamori emits a stderr warning with sandbox-specific guidance when this occurs |

**Security impact**: None. Layer 2 hook protection is fully functional in Codex CLI. The PATH shim (Layer 1) is defense-in-depth that is already documented as bypassable via absolute paths (`/bin/rm`). Audit gaps mean `omamori audit show --action block` is incomplete for sandboxed sessions, but the block enforcement itself is intact.

**Workaround** (optional — enables audit recording inside sandbox): Add the omamori data directory to Codex's writable roots in `~/.codex/config.toml`:

```toml
[sandbox_workspace_write]
writable_roots = ["~/.local/share/omamori"]
```

See also: [ACCEPTANCE_TEST.md "Headless / Codex compatibility"](./ACCEPTANCE_TEST.md) for which acceptance test rows require non-sandboxed execution. Filed as [#271](https://github.com/yottayoshida/omamori/issues/271).

## AI-assisted Contribution Invariants (v0.9.3+)

omamori is developed with AI coding assistants (Claude Code / Codex). That
convenience creates an attack surface: an AI that subtly weakens supply-chain
defenses inside an otherwise innocent refactoring PR can bypass the product's
own philosophy.

These five invariants are **load-bearing**. A PR that removes or neutralizes
any of them SHOULD be rejected. If a future proposal argues for loosening one,
treat it as a security change (separate RFC, human review, not an AI-batched
cleanup).

**Enforcement state (v0.9.3 series)**: the invariants are introduced across
six PRs (PR1 policy -> PR6 release). Until the corresponding CI job listed
below is live, reviewers MUST enforce the rule manually. The `Intended CI
check` column describes the mechanism that becomes authoritative once v0.9.3
ships; before that, the column is a specification, not an existing guarantee.

| # | Invariant | Why it matters | Intended CI check (v0.9.3) |
|---|-----------|----------------|-----------------------------|
| 1 | `Cargo.lock` is tracked | `cargo install omamori --locked` must reproduce the exact dependency graph for consumers. An untracked lockfile makes release binaries non-reproducible and hides transitive-dep drift. | `invariants-check` job asserts `git ls-files Cargo.lock` is non-empty (added in PR2/PR3) |
| 2 | Every `uses:` in `.github/workflows/*.yml` is pinned to a 40-char SHA | Moving tags (`@v4`, `@main`) let a compromised action execute with our repo secrets (incl. `CARGO_REGISTRY_TOKEN`). SHA pinning shrinks this to SHA-1 collision difficulty. | `action-pin-check` regex match on `@[0-9a-f]{40}` (added in PR3) |
| 3 | `.gitignore` retains entries for `.claude/`, `investigation/`, `CLAUDE.local.md`, `target/`, `.env`, `.env.*` | These paths hold AI-agent context, private notes, and credentials. Removing an ignore rule risks accidental `git add` and subsequent crate/tarball inclusion. | `invariants-check` greps for required entries as fixed strings (added in PR3) |
| 4 | `Cargo.toml` has an `include = [...]` allowlist | Deny-by-default is the structural defense against "a stray tracked file leaks to crates.io". `exclude=` alone is reactive — it only blocks what you already thought of. | `invariants-check` parses `include=` array (added in PR3, populated in PR5) |
| 5 | CI jobs and release scripts always pass `--locked` to cargo | Without `--locked`, a fresh CI run can silently pick a newer transitive dep than the lockfile records, masking reproducibility bugs and dependency-confusion issues. | `pre-release-check.sh` runs `cargo ... --locked`; CI audit is manual review plus the `invariants-check` job (added in PR3) |

An AI-generated PR that proposes loosening any of these (e.g. "move
`Cargo.lock` to `.gitignore` for convenience", "pin at `@v4` instead of SHA",
"drop `--locked` to speed up CI") is a supply-chain regression, not a
quality-of-life change, and must be handled as such.

### Dependabot narrow configuration audit (v0.9.4+)

The `.github/dependabot.yml` `github-actions` ecosystem is narrowed to monthly patch-only updates (PR #160, v0.9.4). The narrowing relies on GitHub's documented guarantee that `ignore: version-update:*` does not suppress security updates — per [about-dependabot-security-updates](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates): *"There is no interaction between the settings specified in the `dependabot.yml` file and Dependabot security alerts."* That guarantee is external state whose observed behavior should be verified annually:

- Inspect the Dependabot alerts tab for the `github-actions` ecosystem over the last 12 months.
- Confirm that at least one Dependabot security PR arrived during the window for any pinned action that received an advisory. If zero security PRs arrived despite known advisories existing on pinned actions, the narrow config may have over-filtered — revert or relax.
- Re-read the GitHub docs page above to confirm the `ignore` / `update-types` semantics have not changed.

This audit is operational (not enforced in CI) and is scheduled annually from the v0.9.4 release date.
