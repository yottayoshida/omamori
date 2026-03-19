# omamori

[![CI](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml/badge.svg)](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/omamori.svg)](https://crates.io/crates/omamori)
[![homebrew](https://img.shields.io/badge/homebrew-tap-blue)](https://github.com/yottayoshida/homebrew-tap)
[![License](https://img.shields.io/crates/l/omamori)](LICENSE-MIT)

> Safety guard for AI CLI tools. Blocks dangerous commands — and resists being disabled.

When AI tools like Claude Code, Codex, or Cursor run shell commands, omamori intercepts destructive operations and replaces them with safe alternatives. It also defends itself against AI agents attempting to disable or bypass its protection.

**Terminal commands are never affected** — omamori only activates when it detects an AI tool's environment variable.

<!-- TODO: add demo GIF here -->

## Quick Start

```bash
# Install
brew install yottayoshida/tap/omamori

# Setup (shims + hooks + config — all in one)
omamori install --hooks

# Add to your shell profile (~/.zshrc or ~/.bashrc)
export PATH="$HOME/.omamori/shim:$PATH"
```

That's it. After `brew upgrade`, hooks are auto-updated on the next command.

## What It Blocks

| Command | Pattern | Action |
|---------|---------|--------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | **trash** — move to macOS Trash |
| `git` | `reset --hard` | **stash-then-exec** — `git stash` first |
| `git` | `push --force`, `push -f` | **block** |
| `git` | `clean -fd`, `clean -fdx` | **block** |
| `chmod` | `777` | **block** |
| `find` | `-delete`, `--delete` | **block** |
| `rsync` | `--delete` and 7 variants | **block** |

All rules are customizable via TOML config. See [Configuration](#configuration) below.

## How It Works

```
AI CLI tool → CLAUDECODE=1 → rm -rf src/
                                ↓
                          [omamori shim]
                                ↓
                        blocked (protected path)

Terminal → rm -rf src/
                ↓
          [/usr/bin/rm]
                ↓
          deleted normally
```

**Layer 1 — PATH shim**: Symlinks for `rm`, `git`, `chmod`, `find`, `rsync` point to omamori. Rules apply only when an AI environment variable is detected.

**Layer 2 — Hooks**: Catches bypass attempts (`/bin/rm` direct paths, `unset CLAUDECODE`, interpreter commands). Available for Claude Code and Cursor.

**Self-defense**: AI agents cannot `config disable`, `uninstall`, or edit `config.toml` while detected. See [SECURITY.md](SECURITY.md) for the full threat model.

## Supported Tools

| Tier | Tools | Coverage |
|------|-------|----------|
| **Supported** | Claude Code, Codex CLI, Cursor | E2E tested. Layer 1 + Layer 2 (where available). |
| **Community** | Gemini CLI, Cline, others | Layer 1 only. Not E2E tested. |
| **Fallback** | Any tool setting `AI_GUARD=1` | Layer 1 only. |

## Context-Aware Evaluation

omamori can adjust actions based on what the command targets:

| Command | Without context | With context |
|---------|----------------|-------------|
| `rm -rf target/` | trash | **log-only** (regenerable) |
| `rm -rf src/` | trash | **block** (protected) |
| `git reset --hard` (no changes) | stash-then-exec | **log-only** (git-aware) |

**Opt-in**: Add `[context]` to `~/.config/omamori/config.toml`. Built-in lists for regenerable (`target/`, `node_modules/`, etc.) and protected (`src/`, `.git/`, `.env`, etc.) paths activate automatically.

```toml
[context]
# Built-in defaults activate. Customize:
# regenerable_paths = ["my-cache/"]
# protected_paths = ["secrets/"]
```

Security features: symlink defense via `canonicalize()`, path traversal normalization, NEVER_REGENERABLE hardcoded list, fail-close on errors.

## Configuration

Built-in rules are always inherited. Only write the rules you want to change:

```bash
omamori config list                          # show all rules
omamori config disable git-push-force-block  # disable a rule
omamori config enable git-push-force-block   # restore default
omamori test                                 # verify policy
```

Or edit `~/.config/omamori/config.toml` directly. Config is auto-created by `install --hooks`. See `omamori init --stdout` for the full template.

<details>
<summary>Configuration examples</summary>

**Disable a rule**:
```toml
[[rules]]
name = "git-push-force-block"
enabled = false
```

**Move files to a custom directory**:
```toml
[[rules]]
name = "rm-to-backup"
command = "rm"
action = "move-to"
destination = "/tmp/omamori-quarantine/"
match_any = ["-r", "-rf", "-fr", "--recursive"]
```

**Override an existing rule**:
```toml
[[rules]]
name = "rm-recursive-to-trash"
action = "move-to"
destination = "/tmp/omamori-quarantine/"
```

**Notes**: Config requires `chmod 600`. Destinations must be absolute paths on the same volume. System directories and symlinks are rejected.

</details>

## CLI Reference

```
omamori install [--hooks]                # Setup shims + hooks + config
omamori test [--config PATH]             # Verify policy rules
omamori exec [--config PATH] -- CMD      # Run command through policy engine
omamori config list                      # Show rules with status
omamori config disable <rule>            # Disable a rule
omamori config enable <rule>             # Re-enable a rule
omamori init [--force] [--stdout]        # Create/reset config
omamori uninstall                        # Remove shims + hooks
omamori cursor-hook                      # Cursor hook handler
```

## Structural Limitations

These are inherent to the PATH shim approach and documented honestly:

- **Full-path execution** (`/bin/rm`) bypasses the shim — mitigated by Layer 2 hooks
- **`sudo`** changes PATH — omamori blocks when it detects elevated execution
- **Interpreter commands** (`python -c "shutil.rmtree(...)"`) — hooks warn on known patterns, but obfuscated code cannot be detected
- **AI self-bypass** — `config disable`/`uninstall` are blocked; direct file editing blocked by hooks (Claude Code only). See [#22](https://github.com/yottayoshida/omamori/issues/22)

For the full security model, bypass corpus, and known limitations, see [SECURITY.md](SECURITY.md).

## Related

- **[nanika](https://github.com/yottayoshida/nanika)** — explains what AI commands will do. Complementary to omamori.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
