# SECURITY

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects (v0.7.0)

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
- Interpreter commands (`python -c "shutil.rmtree(...)"`) are not detected by the unwrap stack (which handles bash/sh/zsh/dash/ksh only). [Investigated and deferred](https://github.com/yottayoshida/omamori/issues/74): zero real-world incidents in target tools (Claude Code, Cursor, Codex CLI).
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

| Capability | Detection |
|-----------|-----------|
| Shell wrappers (`sudo`, `env`, `nohup`, `timeout`, `nice`, `exec`, `command`) | Stripped recursively to expose inner command |
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

### Hook Limitations

The unwrap stack is a static analyzer, not a shell interpreter. It cannot detect:
- Obfuscated commands (base64 encoding, hex encoding)
- Variable indirection (`CMD=rm; $CMD -rf /`)
- Commands constructed at runtime by interpreters (`python -c`, `node -e`)
- Heredoc content
- Encoded payloads decoded at execution time

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

These attack vectors **cannot** be detected by omamori's design. They are documented as comments in the test source and listed here for transparency:

| Attack vector | Why undetectable |
|---------------|-----------------|
| `sudo rm -rf` | sudo changes PATH before shim runs; shim is never invoked |
| `alias rm='/bin/rm'` | Alias/function overrides bypass string matching in hooks |
| `env -i rm -rf` | Clears all env vars including detectors; undetectable by hooks |
| Obfuscated commands (base64, hex, variable expansion) | Static analysis cannot decode runtime-constructed commands |
| `export -n CLAUDECODE` | Removes export attribute without unsetting; not caught by `unset` patterns |
| `python -c "shutil.rmtree(...)"` | Python/Node interpreters not in shell list; [investigated, zero incidents in target tools](https://github.com/yottayoshida/omamori/issues/74) |
| `bash -c "$VAR"` where VAR is set earlier | Variable expansion requires runtime evaluation |

## AI Config Bypass Guard (v0.3.2+)

Real-world testing ([#22](https://github.com/yottayoshida/omamori/issues/22)) showed that AI agents (Gemini CLI) can autonomously discover and use `omamori config disable` to remove protection rules before executing dangerous commands.

### Protection

- `config disable`, `config enable`, `uninstall`, and `init --force` are blocked when AI detector env vars are present
- Uses the same detector logic as the PATH shim (`evaluate_detectors()`)
- Hooks also block these commands as string patterns (Claude Code + Cursor)
- Hooks block shell commands that modify `config.toml` (sed, echo, etc.)
- **Not yet implemented**: file_path-aware blocking for Edit/Write tools (planned for v0.7+)

### Known limitations

| Attack vector | Protected | Notes |
|--------------|-----------|-------|
| `omamori config disable` | Yes — env var guard | All tools with known env vars |
| `omamori uninstall` | Yes — env var guard | All tools with known env vars |
| Direct config.toml editing (Edit/Write) | **No** | file_path-aware hook not yet implemented (v0.7+) |
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
| AI directly operates on files (bypassing omamori) | None (same OS user) | **Not protected** |
| AI reads secret and forges valid chain | None (same OS user) | **Not protected** |

**Fundamental constraint**: AI agent and omamori run as the same OS user. Unix file permissions do not provide isolation. `blocked_command_patterns` operates at the hook layer only (`check_command_for_hook()`). Complete filesystem isolation requires OS-level sandboxing ([#61](https://github.com/yottayoshida/omamori/issues/61)).

### Secret Loss

If the secret file is deleted or unreadable:
- `load_or_create_secret()` attempts to generate a new secret
- If generation also fails, entries are written with `NO_HMAC_SECRET` marker
- `omamori audit verify` (v0.7.1) will flag these entries
- A `strict` mode (v0.7.2) will allow users to block commands when the secret is unavailable

### Legacy Compatibility

Entries written before v0.7.0 lack chain fields. When `append()` encounters a legacy last entry (no `chain_version`), it starts a new chain from genesis (`seq=0`). `omamori audit verify` (v0.7.1) will skip legacy entries with a warning.
