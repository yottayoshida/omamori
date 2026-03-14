# SECURITY

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects In v0.2.0

- recursive `rm` variants matched by the default rules
- `git reset --hard`
- force pushes
- destructive `git clean`
- `chmod 777`
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

- Full-path execution such as `/bin/rm` or `/usr/bin/git` can bypass the PATH shim.
- `sudo` may change PATH before the shim runs.
- Other interpreters or subprocess launchers can bypass the rules entirely.
- Commands outside the curated default rules are not protected.
- Non-existent `destination` paths skip `canonicalize()` validation at config load time (caught at runtime via fail-close).
- macOS resolves `/etc` to `/private/etc` — the blocked prefix list includes `/private` to cover this.

## Claude Code Hook Coverage

The generated PreToolUse hook template is a second defensive layer for Claude Code only.

It is intended to catch:
- direct `/bin/rm` or `/usr/bin/rm` (with boundary matching to avoid `/bin/rmdir` false positives)
- attempts to unset `CLAUDECODE`

It is not a complete parser and should be treated as partial coverage, not full enforcement.

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
