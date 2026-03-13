# SECURITY

## Security Model

`omamori` is a PATH-shim safeguard for AI-triggered shell commands. It reduces risk for a narrow set of destructive commands, but it is not a sandbox and it does not claim complete mediation.

## What It Protects In v0.1

- recursive `rm` variants matched by the default rules
- `git reset --hard`
- force pushes
- destructive `git clean`
- `chmod 777`

## Structural Limits

- Full-path execution such as `/bin/rm` or `/usr/bin/git` can bypass the PATH shim.
- `sudo` may change PATH before the shim runs.
- Other interpreters or subprocess launchers can bypass the rules entirely.
- Only exact-token matching is implemented in v0.1, so combined flags such as `-rfv` are not expanded.
- Commands outside the curated default rules are not protected.

## Claude Code Hook Coverage

The generated PreToolUse hook template is a second defensive layer for Claude Code only.

It is intended to catch:
- direct `/bin/rm` or `/usr/bin/rm`
- attempts to unset `CLAUDECODE`

It is not a complete parser and should be treated as partial coverage, not full enforcement.

## Safe Defaults

- Missing config -> fail-close using built-in default rules
- Broken config parse -> fail-close using built-in default rules
- Trash failure -> fail-close; omamori refuses to run the original `rm`
- Sudo/elevated execution detected -> block
- Binary crash remains a fail-open risk outside the process boundary

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
