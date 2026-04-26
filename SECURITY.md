# SECURITY

## How to read this document

This document covers omamori's security model, threat analysis, and known limitations. Different readers want different things:

| If you are... | Read in this order |
|---|---|
| **An operator** evaluating omamori for your team | [Security Model](#security-model) → [What It Protects](#what-it-protects-v090) → [Structural Limits](#structural-limits) → [Hook Coverage (Layer 2)](#hook-coverage-layer-2) → [Safe Defaults](#safe-defaults) |
| **A security researcher** auditing the design | [Design Invariants](#design-invariants-v090) → [Bypass Corpus Testing](#bypass-corpus-testing-v041) → [Audit Log](#audit-log-v070) → [Integrity Monitoring](#integrity-monitoring-v050) |
| **A contributor** preparing a PR | [AI-assisted Contribution Invariants](#ai-assisted-contribution-invariants-v093) |

For end-user installation and CLI usage, see [README.md](README.md). For known limitations classified by closure status — closed in v0.9.x / decided out of scope / structural — jump to [Bypass Corpus Testing → Known limitations (KNOWN_LIMIT)](#known-limitations-known_limit).

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

## Design Invariants (v0.9.0+)

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DI-7 | `doctor --fix` is blocked in AI environments | `guard_ai_config_modification("doctor --fix")` — prevents baseline normalization to hide tampering |
| DI-8 | `explain` is blocked in AI environments | `guard_ai_config_modification("explain")` — prevents oracle attacks (probing which commands are blocked) |
| DI-9 | `doctor --fix` and `explain` in `blocked_string_patterns` | Defense-in-depth: Layer 2 hooks also block these commands via string matching |
| DI-10 | `doctor --fix` repair order: install → hooks → chmod → baseline (last) | Baseline must reflect the post-repair state, not the pre-repair state |
| DI-11 | Command separators `\n`, `\r`, `&` are normalized before tokenization | `normalize_compound_operators` treats unquoted newlines as `;` and space-separates `&` (excluding `&>`, `>&`, `2>&1` redirects) |
| DI-12 | Env var tampering detection is token-level, not string-level | Phase 1B `detect_env_var_tampering` uses `shell_words::split` after normalization, with `is_command_position()` to prevent false positives on quoted strings and arguments |

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

### TOCTOU Risk (accepted)

Canary checks point-in-time state. Tampering between checks is not detected until the next shim invocation. This is a structural limitation of the no-daemon design. A filesystem watcher or daemon would eliminate this gap but contradicts omamori's zero-daemon philosophy.

### Self-Defense for Baseline

| Attack | Protection |
|--------|-----------|
| AI edits `.integrity.json` (Claude Code Edit/Write) | Hook block pattern: `".integrity.json"` |
| AI edits `.integrity.json` (Cursor Bash) | `blocked_command_patterns()` match |
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

1. **Phase 1 — Meta-patterns** (string-level): Catches tamper attempts (env var unset, config editing, `/bin/rm` direct paths, `.integrity.json` editing). These are intentionally broad — `unset CLAUDECODE` appearing anywhere in a command is blocked, including inside `echo`.

2. **Phase 2 — Unwrap Stack** (token-level): Tokenizes the command, strips shell wrappers, extracts inner commands from shell launchers, and evaluates each extracted command against the same rules as Layer 1.

**Broad match by design**: Meta-patterns use `command.contains(pattern)` substring matching. This means `ls ~/.local/share/omamori` is blocked alongside `rm -rf ~/.local/share/omamori`. Read-only commands on protected paths are intentionally blocked to prevent reconnaissance that could aid targeted attacks. Affected patterns include `audit.jsonl`, `audit-secret`, `.integrity.json`, `.local/share/omamori`, `omamori/config.toml`, and `.codex/hooks.json`.

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

### Supported Shell List

`bash`, `sh`, `zsh`, `dash`, `ksh`. Detected by basename (full paths recognized). `fish` and `nushell` are not currently supported — they may be added based on real-world bypass reports (corpus-driven).

### Claude Code Hooks

The generated PreToolUse hook script is a thin wrapper that delegates to `omamori hook-check`:

```sh
cat | omamori hook-check --provider claude-code
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

### Scope: unknown / new tools (v0.9.6+)

AI tool platforms ship new tools and rename existing ones on their own cadence; omamori is locally installed and updated on the user's cadence. A `tool_name` allowlist baked into the binary would always be slightly behind reality, so we route by **payload shape** instead of by name. See `README.md` → "How omamori handles new / renamed tools" for the full table.

The threat we care about: a provider-side rename of a write/exec tool silently bypasses Layer 2. Pre-v0.9.6, `HookInput::UnknownTool` short-circuited to allow regardless of the carried `tool_input`. Codex adversarial-review ② A-2 (2026-04-23, critical) flagged this as a forward-compat fail-open, and v0.9.6 closes it: a payload like `{"tool_name":"FuturePlanWriter","tool_input":{"command":"/bin/rm -rf /"}}` now reaches the full shell pipeline (meta-patterns, env-tampering, unwrap stack) on the strength of the `command` field alone. Wrong-type routing fields (`command: 42`) fail closed.

The residual risk is `tool_input` shapes we don't recognise at all (no `command`/`cmd`/`file_path`/`path`/`url`). That's still **Allow**, on purpose: starting to block unreviewed payload shapes would break user workflow on every legitimate AI tool update. But the silence is gone — the call is recorded as an `unknown_tool_fail_open` event in the audit chain, stderr carries a one-line hint, and `omamori doctor` surfaces a 30-day count. Users review the events with `omamori audit unknown`.

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
- **Redirection-dup stdin aliases** (`source /dev/fd/N N<&0`): shell redirection creates a synthetic file descriptor that points at stdin, then `source /dev/fd/N` reads from it. Detection would require parsing `N<&0`-style redirections and tracking fd equivalence to `/dev/stdin`. This is out of scope for v0.9.6 (Codex Phase 6-A Major #4); v0.9.7 will track a redirection-aware parser plan. Note that the common case `bash -c 'source /dev/stdin' < file` IS handled — an explicit stdin redirect exempts the segment from pipe-to-shell detection — but `N<&0` fd-dup patterns still slip through.
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
| P1 | `/bin/rm` + `/usr/bin/rm` path variants | `meta_patterns_cover_rm_path_boundaries` |
| P1 | All 6 detector env vars × 3 unset patterns | `meta_patterns_cover_all_detector_env_vars` |
| P2 | `config disable/enable`, `uninstall`, `init --force` | `meta_patterns_cover_config_modification` |
| P3 | `bash -c "rm -rf"`, `sudo env bash -c "rm -rf"` | `unwrap::tests::bash_c_*`, `unwrap::tests::chained_wrappers` |
| P3 | Pipe-to-shell (`curl \| bash`) | `unwrap::tests::curl_pipe_bash` |
| P3 | Dynamic generation (`bash -c "$(cmd)"`) | `unwrap::tests::dollar_paren_*` |
| P4 | False positive: `echo "rm -rf"`, `env NODE_ENV=production npm start` | `unwrap::tests::echo_with_dangerous_string`, `unwrap::tests::env_production_start` |
| P4 | `/bin/rmdir` false-positive regression | `meta_patterns_do_not_false_positive_on_rmdir` |

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
| `source /dev/fd/N N<&0` (redirection-dup stdin alias) | Shell redirection creates a synthetic file descriptor that points at stdin, then `source /dev/fd/N` reads from it. Detection would require parsing `N<&0`-style redirections and tracking fd equivalence to `/dev/stdin`. v0.9.7 will track a redirection-aware parser plan. (Note: the direct case `bash -c 'source /dev/stdin'` after a pipe is closed — see A above.) |
| `curl URL \| source /dev/stdin` / `\| eval ...` (interpreters outside `SHELL_NAMES`, used directly on the pipe RHS) | Current `SHELL_NAMES = [bash, sh, zsh, dash, ksh]` does not include `source`, `eval`, or interpreter families (`python -c`, `perl -e`, `node -e`, `ruby -e`). Pipe-to-shell detection is bound to this list; expanding it has real false-positive risk (`cat data \| python -c 'parse'`) and requires product-level discussion. (Note: when `source` / `eval` are invoked *inside* a shell launcher like `bash -c 'source /dev/stdin'`, that case is closed — see A above.) |

## AI Config Bypass Guard (v0.3.2+)

Real-world testing ([#22](https://github.com/yottayoshida/omamori/issues/22)) showed that AI agents (Gemini CLI) can autonomously discover and use `omamori config disable` to remove protection rules before executing dangerous commands.

### Protection

- `config disable`, `config enable`, `uninstall`, and `init --force` are blocked when AI detector env vars are present
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
| `chain_version` | Chain format version (currently `1`) |
| `seq` | Monotonic sequence number |
| `prev_hash` | HMAC of the previous entry (genesis for first entry) |
| `key_id` | HMAC key identifier (for future key rotation) |
| `timestamp` | RFC 3339 UTC timestamp |
| `provider` | AI tool that triggered the command |
| `command` | Command name (e.g., `rm`, `git`) |
| `rule_id` | Matched rule name, if any |
| `action` | Rule action (trash, block, passthrough, etc.) |
| `result` | Execution result |
| `target_count` | Number of target arguments |
| `target_hash` | HMAC-SHA256 of target paths (privacy-preserving) |
| `entry_hash` | HMAC-SHA256 of the entire entry (chain integrity) |

### HMAC Integrity

- **Per-install secret**: 32 bytes from `/dev/urandom`, stored at `~/.local/share/omamori/audit-secret` (chmod 0600)
- **target_hash**: `HMAC-SHA256(secret, targets)` — file paths are never stored in plaintext
- **entry_hash**: `HMAC-SHA256(secret, canonical_json(entry))` — computed over a fixed-field-order `HashableEvent` struct to ensure deterministic hashing regardless of serde serialization options
- **Genesis**: First entry's `prev_hash` = `HMAC-SHA256(secret, "omamori-genesis-v1")`

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
| AI modifies log via omamori hook layer | `blocked_command_patterns` | Detected and blocked |
| AI modifies log entries (content change) | Hash chain (`entry_hash` mismatch) | Detected by `omamori audit verify` |
| AI deletes/truncates log entries | Hash chain (seq gap / `prev_hash` mismatch) | Detected by `omamori audit verify` |
| AI accesses secret via omamori hook layer | `blocked_command_patterns` | Detected and blocked |
| AI Edit/Write to protected files (config, audit, hooks, settings.json) | `is_protected_file_path` + `PROTECTED_FILE_PATTERNS` | **Blocked** (v0.8.0 #110) |
| AI directly operates on files via OS (bypassing hook layer) | None (same OS user) | **Not protected** (structural limitation) |
| AI reads secret and forges valid chain | None (same OS user) | **Not protected** (structural limitation) |

**Fundamental constraint**: AI agent and omamori run as the same OS user. Unix file permissions do not provide isolation. `blocked_command_patterns` operates at the hook layer only (`check_command_for_hook()`). Complete filesystem isolation requires OS-level sandboxing — use your AI tool's sandbox (Codex CLI sandbox (on by default), Claude Code `/sandbox`, Cursor agent sandbox) or a dedicated tool like [nono](https://github.com/always-further/nono).

### Secret Loss

If the secret file is deleted or unreadable:
- `load_or_create_secret()` attempts to generate a new secret
- If generation also fails, entries are written with `NO_HMAC_SECRET` marker
- `omamori audit verify` (v0.7.1) will flag these entries
- **Strict mode** (v0.7.3): When `audit.strict = true`, AI commands intercepted by the PATH shim are blocked if the secret is unavailable after re-creation attempt. Hook-only commands (not matching any shim rule) are not affected

### Strict Mode (v0.7.3+)

Opt-in fail-close mode. When enabled, AI commands intercepted by the PATH shim are blocked if the audit HMAC secret is unavailable, preventing unverifiable command execution. Commands that only pass through Layer 2 hooks (not matching any shim rule) are not affected — the hook path does not hold an `AuditLogger` instance.

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
- **Residual TOCTOU**: `secret_available()` check and subsequent `append()` are not atomic. An attacker deleting the secret between check and use could bypass strict mode. This is accepted because: (1) the attacker would need to delete the secret within the same process execution window, (2) `blocked_command_patterns` protects the secret file from AI-layer deletion.

### Symlink Protection (v0.7.3+)

All audit file operations use `O_NOFOLLOW` to reject symlinks at the kernel level. This prevents symlink attacks where an attacker replaces `audit.jsonl` or `audit-secret` with a symlink to `/dev/null` or a controlled location.

**Protected operations** (6 total):

| Operation | File | Effect on symlink |
|-----------|------|-------------------|
| `append()` | audit.jsonl | `ELOOP` error, entry not written |
| `read_secret()` | audit-secret | `ELOOP` error, secret not loaded |
| `create_secret()` | audit-secret | `ELOOP` error, secret not created |
| `verify_chain()` | audit.jsonl | `ELOOP` error, verify fails |
| `show_entries()` | audit.jsonl | `ELOOP` error, show fails |
| `audit_summary()` | audit.jsonl | `ELOOP` error, count returns 0 |

**Limitations**:

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| Parent directory symlinks not detected | `O_NOFOLLOW` only applies to the final path component | `create_dir_all` is called by omamori itself; `blocked_command_patterns` protects `.local/share/omamori` |
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
| Prune_point authenticity | `entry_hash` = HMAC-SHA256 over all fields (secret required to forge) |
| Prune_point anchoring | `prev_hash` = HMAC(secret, "omamori-prune-v1") — distinct from chain genesis |
| First-retained binding | `target_hash` = HMAC(secret, "prune-bind:{count}:{first_retained_entry_hash}") |
| Minimum retention | 7 days enforced (values < 7 clamped with warning) |
| Minimum entry count | 1000 entries always retained regardless of age |
| Config protection | `omamori/config.toml` added to `blocked_command_patterns` |
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

Entries written before v0.7.0 lack chain fields. When `append()` encounters a legacy last entry (no `chain_version`), it starts a new chain from genesis (`seq=0`). `omamori audit verify` skips legacy entries with a warning. A log containing only legacy entries returns exit code 2 (no chain entries to verify).

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
