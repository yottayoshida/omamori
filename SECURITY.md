# SECURITY

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects In v0.1.1

- recursive `rm` variants matched by the default rules
- `git reset --hard`
- force pushes
- destructive `git clean`
- `chmod 777`

### v0.1.1 Improvements

- **Flag normalization**: Combined short flags like `-rfv` are expanded to individual flags (`-r`, `-f`, `-v`) for matching. Expansion is restricted to ASCII alphabetic characters only. The original combined form is preserved for backward compatibility.
- **`--` separator**: The POSIX `--` end-of-options marker is now respected when extracting targets for the Trash action. Arguments after `--` are treated as targets regardless of leading `-`.
- **Hook pattern boundaries**: The Claude Code hook script now uses boundary-aware patterns to avoid matching `/bin/rmdir` when checking for `/bin/rm`.
- **Internal `git stash` isolation**: The `git stash` subprocess used by `stash-then-exec` now strips AI detector environment variables (`CLAUDECODE`, `AI_GUARD`) to prevent self-interference.
- **Signal exit codes**: Processes terminated by signals now return `128 + signal_number` per POSIX convention, instead of a generic exit code 1.

## Structural Limits

- Full-path execution such as `/bin/rm` or `/usr/bin/git` can bypass the PATH shim.
- `sudo` may change PATH before the shim runs.
- Other interpreters or subprocess launchers can bypass the rules entirely.
- `-R` as an alias for `-r` is not yet normalized (tracked for v0.2).
- Commands outside the curated default rules are not protected.

## Claude Code Hook Coverage

The generated PreToolUse hook template is a second defensive layer for Claude Code only.

It is intended to catch:
- direct `/bin/rm` or `/usr/bin/rm` (with boundary matching to avoid `/bin/rmdir` false positives)
- attempts to unset `CLAUDECODE`

It is not a complete parser and should be treated as partial coverage, not full enforcement.

## Safe Defaults

- Missing config -> fail-close using built-in default rules
- Broken config parse -> fail-close using built-in default rules
- Trash failure -> fail-close; omamori refuses to run the original `rm`
- Sudo/elevated execution detected -> block
- Binary crash remains a fail-open risk outside the process boundary

## Internal Subprocess Isolation

The `stash-then-exec` action runs `git stash` as a subprocess. To prevent this internal call from triggering omamori's own protection (via PATH shim), the subprocess environment strips the default detector variables (`CLAUDECODE`, `AI_GUARD`). Custom detector environment keys are not stripped in v0.1.1; this is tracked for v0.2 via an `OMAMORI_INTERNAL` flag.

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

`target_hash` is derived from target paths using SHA-256 so operators can correlate repeated events without storing the original paths.
