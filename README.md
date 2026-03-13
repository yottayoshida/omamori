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

Rules are configurable via TOML. See `config.default.toml` for the full schema.

## Safe Defaults

| Scenario | Behavior |
|----------|----------|
| No AI env var detected | Pass through to real command (no interference) |
| Config file missing | Fail-close: built-in default rules apply |
| Config file broken | Fail-close: built-in default rules apply + warning |
| Trash operation fails | Fail-close: refuse to run `rm` |
| `sudo` detected | Block the command |
| Shim binary crashes | Fail-open: real command runs |

## CLI

```
omamori test [--config PATH]                          # Verify policy rules
omamori exec [--config PATH] -- <command> [args...]   # Run through policy engine
omamori install [--base-dir PATH] [--hooks]           # Create shims + hook templates
omamori uninstall [--base-dir PATH]                   # Remove shims + hook files
```

## Structural Limitations

These are inherent to the PATH shim approach and documented honestly:

- **Full-path execution** (`/bin/rm`, `/usr/bin/git`) bypasses the shim — partially mitigated by Layer 2 hooks
- **`sudo`** changes PATH before the shim runs — omamori blocks when it detects elevated execution in-process
- **Other interpreters** (`python -c "os.remove(...)"`, `perl -e`) are not intercepted
- **Non-rm destructive commands** (`find -delete`, `rsync --delete`) are not covered in v0.1
- **Combined short flags** (`rm -rfv`) are not normalized — matching is exact-token based in v0.1

For the full security model, see [SECURITY.md](SECURITY.md).

## Related

- **[nanika](https://github.com/yottayoshida/nanika)** — explains what AI commands will do (detect + translate). Complementary to omamori (detect + replace).

## License

MIT
