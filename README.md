# omamori

> **Pre-1.0** — Breaking changes may occur between minor versions.

AI Agent's Omamori — protect your system from dangerous commands executed via AI CLI tools.

### Support Tiers

| Tier | Tools | What it means |
|------|-------|---------------|
| **Supported** | Claude Code, Codex CLI, Cursor | E2E tested every release. Issues investigated and fixed. |
| **Community** | Gemini CLI, Cline, others | Env var detection included but not tested. No guaranteed support. |
| **Fallback** | Any tool setting `AI_GUARD=1` | Generic detection. No tool-specific integration. |

### Detection Details

| Tool | Environment Variable | Value |
|------|---------------------|-------|
| Claude Code | `CLAUDECODE` | `1` |
| Codex CLI | `CODEX_CI` | `1` |
| Cursor | `CURSOR_AGENT` | `1` |
| Gemini CLI | `GEMINI_CLI` | `1` |
| Cline | `CLINE_ACTIVE` | `true` |
| Fallback | `AI_GUARD` | `1` |

Detection uses **exact value matching** (e.g. `CLAUDECODE=1` only, not `CLAUDECODE=true`).

### Protection Coverage (Supported Tools)

| Protection | Claude Code | Codex CLI | Cursor |
|-----------|------------|-----------|--------|
| Layer 1 — PATH shim (all rules) | ✅ | ✅ | ✅ |
| Layer 2 — Hooks (full-path bypass) | ✅ PreToolUse | ❌ | ✅ beforeShellExecution |
| Layer 2 — Hooks (interpreter warnings) | ✅ warn | ❌ | ✅ ask |
| Config guard (disable/uninstall blocked) | ✅ env var + hooks | ✅ env var | ✅ env var + hooks |
| config.toml direct edit guard | ✅ PreToolUse | ❌ | Bash only |

- **Layer 1 (PATH shim)**: Blocks dangerous commands when AI sets its env var. Bypassable via `/bin/rm` full-path execution.
- **Layer 2 (Hooks)**: Catches full-path bypass, env var unset, interpreter commands, and `config disable`/`uninstall`. Available for Claude Code and Cursor only.
- **Config guard** (v0.3.2+): `config disable`, `config enable`, `uninstall`, and `init --force` are blocked when AI detector env vars are present. Works for all detected tools.
- **config.toml edit guard**: PreToolUse hook blocks direct file editing (Claude Code only). Cursor blocks Bash-based edits.
- See [SECURITY.md](SECURITY.md) for full details and known limitations.

## What It Does

When an AI CLI tool (Claude Code, Codex, Cursor, etc.) runs a shell command, omamori intercepts dangerous operations and replaces them with safe alternatives. **Terminal direct execution is not affected.**

```
[AI CLI Tool] → CLAUDECODE=1 → rm -rf target/
                                  ↓
                            [omamori shim]
                                  ↓
                         moved to Trash instead
```

```
[Terminal]    →              → rm -rf target/
                                  ↓
                            [/usr/bin/rm]
                                  ↓
                            deleted normally
```

## Quick Start

### Install via Homebrew (macOS)

```bash
brew install yottayoshida/tap/omamori
```

### Or build from source

```bash
cargo install --path .
```

### Setup

```bash
# 1. Install shims + hooks + config (all in one command)
omamori install --hooks

# 2. Add shim directory to PATH (add to .zshrc / .bashrc)
export PATH="$HOME/.omamori/shim:$PATH"
```

That's it. `install --hooks` auto-generates `config.toml`, runs verification, and shows a checklist:

```
omamori setup complete:

Shims:
  [done] rm, git, chmod, find, rsync

Hooks:
  [done] Claude Code hook script
  [done] Cursor hook snippet

Config:
  [done] Created: ~/.config/omamori/config.toml
  [done] 7 rules verified, 12 detection tests passed

Next steps:
  [todo] Add to your shell profile:
    export PATH="$HOME/.omamori/shim:$PATH"
  [todo] Merge Cursor hook into .cursor/hooks.json
```

## How It Works

**Layer 1 — PATH shim**: Symlinks for `rm`, `git`, `chmod`, `find`, `rsync` point to the omamori binary. When invoked, omamori checks for AI tool environment variables (e.g. `CLAUDECODE=1`) and applies rules only if an AI tool is detected.

**Layer 2 — Hooks** (optional):
- **Claude Code**: A `PreToolUse` hook script catches bypass attempts like `/bin/rm` direct paths, `unset CLAUDECODE`, and warns on interpreter commands (`python -c "shutil.rmtree(...)"`).
- **Cursor**: A Rust-native `beforeShellExecution` handler (`omamori cursor-hook`) provides the same protection via Cursor's hook protocol.

## Default Rules

| Command | Pattern | Action |
|---------|---------|--------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | **trash** — move to macOS Trash |
| `git` | `reset --hard` | **stash-then-exec** — `git stash` first, then execute |
| `git` | `push --force`, `push -f` | **block** |
| `git` | `clean -fd`, `clean -fdx` | **block** |
| `chmod` | `777` | **block** |
| `find` | `-delete`, `--delete` | **block** |
| `rsync` | `--delete` and 7 variants | **block** |

Combined short flags are normalized: `rm -rfv` expands to match `-r` and `-rf` rules. The POSIX `--` separator is respected for target extraction.

rsync variants blocked: `--delete`, `--del`, `--delete-before`, `--delete-during`, `--delete-after`, `--delete-excluded`, `--delete-delay`, `--remove-source-files`.

## Configuration (v0.2+)

Built-in rules are always inherited. Config is auto-created by `install --hooks`. To regenerate manually:

```bash
omamori init              # Creates ~/.config/omamori/config.toml (chmod 600)
omamori init --force      # Overwrite existing config
omamori init --stdout     # Print template to stdout (backward compat)
```

**Disable a rule** via CLI (v0.3+):

```bash
omamori config disable git-push-force-block
omamori config enable git-push-force-block    # restore built-in default
omamori config list                           # show all rules with status
```

Or edit `config.toml` directly:

```toml
[[rules]]
name = "git-push-force-block"
enabled = false
```

**Move files to a custom directory** instead of Trash:

```toml
[[rules]]
name = "rm-to-backup"
command = "rm"
action = "move-to"
destination = "/tmp/omamori-quarantine/"
match_any = ["-r", "-rf", "-fr", "--recursive"]
message = "omamori moved targets to quarantine instead of deleting"
```

**Override an existing rule's action**:

```toml
[[rules]]
name = "rm-recursive-to-trash"
action = "move-to"
destination = "/tmp/omamori-quarantine/"
```

After editing, run `omamori test` to verify. Disabled rules show as `SKIP`:

```
Rules:
  PASS  rm-recursive-to-trash        rm -r|-rf|-fr|--recursive -> trash
  SKIP  git-push-force-block         (disabled by user config)
  ...
Summary: 7 rules (6 active, 1 disabled), 12 detection tests passed
```

### Configuration notes

- Config file requires `chmod 600` (permissions check enforced)
- Only write rules you want to change — everything else is inherited
- `destination` must be an absolute path on the same volume
- System directories (`/usr`, `/etc`, `/System`, `/Library`, `/bin`, `/sbin`, `/var`, `/private`) are blocked as destinations
- Symlinks are rejected as destinations
- `destination` directory must exist before use (omamori will not create it)

## Available Actions

| Action | Behavior |
|--------|----------|
| `trash` | Move targets to macOS Trash |
| `move-to` | Move targets to a user-specified directory (requires `destination`) |
| `stash-then-exec` | Run `git stash` first, then execute the original command |
| `block` | Refuse to execute |
| `log-only` | Log the event, then execute normally |

## Safe Defaults

| Scenario | Behavior |
|----------|----------|
| No AI env var detected | Pass through to real command (no interference) |
| Config file missing | Fail-close: built-in default rules apply |
| Config file broken | Fail-close: built-in default rules apply + warning |
| Trash / move-to fails | Fail-close: refuse to run the original command |
| `sudo` detected | Block the command |
| Blocked destination | Fail-close: rule is disabled at config load time |
| Shim binary crashes | Fail-open: real command runs |

## CLI

```
omamori test [--config PATH]                          # Verify policy rules
omamori exec [--config PATH] -- <command> [args...]   # Run through policy engine
omamori install [--base-dir PATH] [--hooks]           # Create shims + hooks + config
omamori uninstall [--base-dir PATH]                   # Remove shims + hook files
omamori init [--force] [--stdout]                     # Create/reset config file
omamori config list                                   # Show all rules with status
omamori config disable <rule>                         # Disable a rule (blocked by AI tools)
omamori config enable <rule>                          # Re-enable a rule (blocked by AI tools)
omamori cursor-hook                                   # Cursor beforeShellExecution handler
```

## Structural Limitations

These are inherent to the PATH shim approach and documented honestly:

- **Full-path execution** (`/bin/rm`, `/usr/bin/git`) bypasses the shim — mitigated by Layer 2 hooks (Claude Code + Cursor). Tools without hooks (Codex, Gemini) are vulnerable.
- **`sudo`** changes PATH before the shim runs — omamori blocks when it detects elevated execution in-process
- **Interpreter commands** (`python -c "shutil.rmtree(...)"`) — Layer 2 hooks **warn** on known destructive patterns, but obfuscated code (base64, heredoc, variable indirection) cannot be detected
- **`find -exec /bin/rm`** bypasses the find shim because rm is invoked via absolute path — partially mitigated by Layer 2 hooks
- **AI self-bypass**: `config disable`, `uninstall`, and `init --force` are blocked when AI env vars are detected (v0.3.2+). AI agents may still attempt direct `config.toml` file editing — blocked by PreToolUse hooks in Claude Code only. See [#22](https://github.com/yottayoshida/omamori/issues/22)
- **Cross-device moves** are not supported for `move-to` (use a destination on the same volume)

For the full security model, see [SECURITY.md](SECURITY.md).

## Related

- **[nanika](https://github.com/yottayoshida/nanika)** — explains what AI commands will do (detect + translate). Complementary to omamori (detect + replace).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
