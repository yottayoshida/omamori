# omamori

> **WIP — This project is under active development and not ready for general use.**
> Do not install in production environments. Breaking changes will occur without notice.

AI Agent's Omamori — protect your system from dangerous commands executed via AI CLI tools.

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

```bash
# 1. Build from source
cargo install --path .

# 2. Install shims + hook templates
omamori install --hooks

# 3. Add shim directory to PATH (add to .zshrc / .bashrc)
export PATH="$HOME/.omamori/shim:$PATH"

# 4. Verify
omamori test
```

After installation, `omamori test` shows which rules are active:

```
Rules:
  PASS  rm-recursive-to-trash        rm -r|-rf|-fr|--recursive -> trash
  PASS  git-reset-hard-stash         git reset --hard         -> stash-then-exec
  PASS  git-push-force-block         git push                 -> block
  PASS  git-clean-force-block        git clean                -> block
  PASS  chmod-777-block              chmod 777                -> block

Summary: 5 rules (5 active, 0 disabled), 4 detection tests passed
```

## How It Works

**Layer 1 — PATH shim**: Symlinks for `rm`, `git`, `chmod` point to the omamori binary. When invoked, omamori checks for AI tool environment variables (e.g. `CLAUDECODE=1`) and applies rules only if an AI tool is detected.

**Layer 2 — Claude Code Hooks** (optional): A `PreToolUse` hook script catches bypass attempts like `/bin/rm` direct paths or `unset CLAUDECODE`.

## Default Rules

| Command | Pattern | Action |
|---------|---------|--------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | **trash** — move to macOS Trash |
| `git` | `reset --hard` | **stash-then-exec** — `git stash` first, then execute |
| `git` | `push --force`, `push -f` | **block** |
| `git` | `clean -fd`, `clean -fdx` | **block** |
| `chmod` | `777` | **block** |

Combined short flags are normalized: `rm -rfv` expands to match `-r` and `-rf` rules. The POSIX `--` separator is respected for target extraction.

## Configuration (v0.2+)

Built-in rules are always inherited. Create a config file to customize:

```bash
# Generate a starter template
omamori init > ~/.config/omamori/config.toml
chmod 600 ~/.config/omamori/config.toml
```

**Disable a rule** (e.g. allow force push):

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
Summary: 5 rules (4 active, 1 disabled), 4 detection tests passed
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
omamori install [--base-dir PATH] [--hooks]           # Create shims + hook templates
omamori uninstall [--base-dir PATH]                   # Remove shims + hook files
omamori init                                          # Print config template to stdout
```

## Structural Limitations

These are inherent to the PATH shim approach and documented honestly:

- **Full-path execution** (`/bin/rm`, `/usr/bin/git`) bypasses the shim — partially mitigated by Layer 2 hooks
- **`sudo`** changes PATH before the shim runs — omamori blocks when it detects elevated execution in-process
- **Other interpreters** (`python -c "os.remove(...)"`, `perl -e`) are not intercepted
- **Non-rm destructive commands** (`find -delete`, `rsync --delete`) are not covered
- **Cross-device moves** are not supported for `move-to` (use a destination on the same volume)

For the full security model, see [SECURITY.md](SECURITY.md).

## Related

- **[nanika](https://github.com/yottayoshida/nanika)** — explains what AI commands will do (detect + translate). Complementary to omamori (detect + replace).

## License

MIT
