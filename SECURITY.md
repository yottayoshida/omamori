# SECURITY

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects (v0.4.0)

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

## Structural Limits

- Full-path execution such as `/bin/rm` or `/usr/bin/git` can bypass the PATH shim. Mitigated by Layer 2 hooks (Claude Code + Cursor).
- `find -exec /bin/rm {} \;` bypasses both the find shim and the rm shim because rm is invoked via absolute path. Partially mitigated by Layer 2 hooks.
- `sudo` may change PATH before the shim runs.
- Interpreter commands (`python -c "shutil.rmtree(...)"`) are warned on by Layer 2 hooks for known destructive patterns, but **obfuscated code** (base64 encoding, heredoc, variable indirection, string concatenation) **cannot be detected**. This is a fundamental limitation of string-based pattern matching.
- Commands outside the curated default rules are not protected.
- Non-existent `destination` paths skip `canonicalize()` validation at config load time (caught at runtime via fail-close).
- macOS resolves `/etc` to `/private/etc` — the blocked prefix list includes `/private` to cover this.

## Environment Variable Detection

Detection uses **exact value matching**:
- `CLAUDECODE=1` is detected; `CLAUDECODE=true` or `CLAUDECODE=yes` is **not**
- `CLINE_ACTIVE=true` is detected; `CLINE_ACTIVE=1` is **not**

This is intentional: each detector's expected value is sourced from the actual tool implementation. If a tool changes its env var value in a future release, the detector must be updated.

## Hook Coverage (Layer 2)

### Claude Code Hooks

The generated PreToolUse hook script is a second defensive layer.

It catches:
- direct `/bin/rm` or `/usr/bin/rm` (with boundary matching to avoid `/bin/rmdir` false positives)
- attempts to unset detector env vars (`CLAUDECODE`, `CODEX_CI`, `CURSOR_AGENT`, `GEMINI_CLI`, `CLINE_ACTIVE`, `AI_GUARD`)
- **warns** on interpreter commands with known destructive patterns (`python -c "shutil.rmtree(...)"`, `node -e "rmSync(...)"`, `bash -c "rm -rf ..."`) — exit 0, not block

### Cursor Hooks

The `omamori cursor-hook` subcommand is a Rust-native `beforeShellExecution` handler for Cursor.

It provides the same protection as Claude Code hooks, using Cursor's JSON stdin/stdout protocol:
- Block (`permission: "deny"`): direct rm paths, env var unset attempts
- Warn (`permission: "ask"`): interpreter commands with destructive patterns

The Cursor hook uses `serde_json` for JSON generation to avoid Cursor's known malformed-JSON fail-open behavior.

### Hook Limitations

Hooks are **not a complete parser** and should be treated as partial coverage. Pattern matching is string-based and cannot detect:
- Obfuscated commands (base64 encoding, string concatenation)
- Indirect execution via variables or heredocs
- Commands constructed at runtime by the interpreter

## AI Config Bypass Guard (v0.3.2+)

Real-world testing ([#22](https://github.com/yottayoshida/omamori/issues/22)) showed that AI agents (Gemini CLI) can autonomously discover and use `omamori config disable` to remove protection rules before executing dangerous commands.

### Protection

- `config disable`, `config enable`, `uninstall`, and `init --force` are blocked when AI detector env vars are present
- Uses the same detector logic as the PATH shim (`evaluate_detectors()`)
- Hooks also block these commands as string patterns (Claude Code + Cursor)
- Claude Code PreToolUse hooks block direct `config.toml` file editing via Edit/Write tools

### Known limitations

| Attack vector | Protected | Notes |
|--------------|-----------|-------|
| `omamori config disable` | Yes — env var guard | All tools with known env vars |
| `omamori uninstall` | Yes — env var guard | All tools with known env vars |
| Direct config.toml editing (Edit/Write) | Claude Code only | PreToolUse hook blocks file_path match |
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

## Logging

Audit logs avoid storing raw file paths or argument values.

Current schema includes:
- `timestamp`
- `provider`
- `command`
- `rule_id`
- `action`
- `result`
- `target_count`
- `target_hash`

`target_hash` is derived from target paths using SHA-256 so operators can correlate repeated events without storing the original paths. The `destination` path for `move-to` actions is not recorded in audit logs; it can be derived from the `rule_id` via config lookup.
