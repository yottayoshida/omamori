# omamori

[![CI](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml/badge.svg)](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/omamori.svg)](https://crates.io/crates/omamori)
[![homebrew](https://img.shields.io/badge/homebrew-tap-blue)](https://github.com/yottayoshida/homebrew-tap)
[![License](https://img.shields.io/crates/l/omamori)](LICENSE-MIT)

> Safety guard for AI CLI tools. Blocks dangerous commands — and resists being disabled.
>
> Hook check completes in **<0.1ms** — no perceivable latency.

When AI tools like Claude Code, Codex, or Cursor run shell commands, omamori intercepts destructive operations and replaces them with safe alternatives.

Unlike other guards, omamori defends itself — AI agents cannot disable or bypass its protection ([#22](https://github.com/yottayoshida/omamori/issues/22)).

**macOS only** — Terminal commands are never affected; omamori only activates when it detects an AI tool's environment variable. See [Tool Compatibility](#tool-compatibility) for supported AI tools and CI coverage.

![omamori demo](demo.svg)

## Quick Start

```bash
# Install (macOS)
brew install yottayoshida/tap/omamori

# Setup (shims + hooks + config — all in one)
omamori install --hooks

# Add to your shell profile (~/.zshrc or ~/.bashrc)
export PATH="$HOME/.omamori/shim:$PATH"

# Verify everything is healthy
omamori doctor
```

That's it. Works with Claude Code Auto mode — no extra config needed.

> Requires omamori >= 0.9.0 for `doctor` and `explain` commands. For Cursor and Codex CLI, see [Tool Compatibility](#tool-compatibility).

## What It Blocks

| Command | Pattern | Action |
|---------|---------|--------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | **trash** — move to macOS Trash |
| `git` | `reset --hard` | **stash-then-exec** — `git stash` first |
| `git` | `push --force`, `push -f` | **block** |
| `git` | `clean -f`, `clean --force` | **block** |
| `chmod` | `777` | **block** |
| `find` | `-delete`, `--delete` | **block** |
| `rsync` | `--delete` + 7 variants | **block** |

<details>
<summary>rsync blocked variants</summary>

`--delete`, `--del`, `--delete-before`, `--delete-during`, `--delete-after`, `--delete-excluded`, `--delete-delay`, `--remove-source-files`

</details>

All rules are customizable via TOML config. See [Configuration](#configuration) below.

## Tool Compatibility

### Supported tiers

| Tier | Tools | Coverage |
|------|-------|----------|
| **Supported** | Claude Code, Codex CLI, Cursor | E2E tested. Layer 1 + Layer 2. Auto mode compatible. |
| **Community** | Gemini CLI, Cline, others | Layer 1 only. Not E2E tested. |
| **Fallback** | Any tool setting `AI_GUARD=1` | Layer 1 only. |

> The demo image above is a Claude Code capture; the same `block` / `log-only` / `trash` behaviour applies on Codex CLI and Cursor when their env vars are detected.

### Tool-specific notes

- **Claude Code**: hooks applied automatically. No action needed.
- **Codex CLI**: hooks and config auto-configured during install. Auto-sync regenerates wrappers on `brew upgrade`.
- **Cursor**: after `brew upgrade`, re-merge the hook snippet from `~/.omamori/hooks/cursor-hooks.snippet.json` into `.cursor/hooks.json`.

### Platforms

macOS only at runtime — shim paths and Trash integration are macOS-specific. CI verifies contributors' PRs on **macOS + Ubuntu** (`#[cfg(unix)]` regressions caught before merge). Windows is not supported.

### How omamori handles new / renamed tools

omamori routes by **payload shape** (`tool_input.command` / `cmd` / `file_path` / `path` / `url`), not by tool name. A renamed AI tool carrying a `command` field still reaches the full pipeline; unrecognised shapes still allow but emit `unknown_tool_fail_open` audit events. Review with `omamori audit unknown` or check `omamori doctor`'s 30-day count line.

For the full shape catalogue, scope, known operational noise (legitimate tools like `Glob` / `Task` landing in fail-open), and the strict-mode trade-off, see [SECURITY.md → Hook Coverage](SECURITY.md#hook-coverage-layer-2).

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

**Layer 1 — PATH shim**: symlinks for `rm`, `git`, `chmod`, `find`, `rsync` point to omamori. Rules apply only when an AI environment variable is detected.

**Layer 2 — Hooks**: evaluates commands against the same rules as Layer 1, with three additional capabilities:
- Recursively unwraps shell wrappers (`sudo env bash -c "..."` → extracts inner command).
- Blocks pipe-to-shell patterns (`curl URL | bash`, `curl URL | sudo bash`, and other transparent-wrapper variants — see [SECURITY.md](SECURITY.md)).
- Blocks dynamic command generation (`bash -c "$(cmd)"`).

Available for Claude Code, Cursor, and Codex CLI.

**Audit log**: records every command decision in a tamper-evident log — if an AI agent modifies any entry, the chain breaks and tampering is detected.
- Tamper-evident JSONL log at `~/.local/share/omamori/audit.jsonl`.
- HMAC-SHA256 signed and hash-chained — tampering breaks the chain and is detected.
- Per-install secret; file paths HMAC-hashed (never stored in plaintext).
- Set `retention_days` in config to automatically prune old entries — chain integrity is preserved across pruning.
- Logging enabled by default; retention is opt-in via config.

**Performance**: hook check completes in **well under 0.1ms** — typically ~1 µs to block, ~57 µs to allow. Subprocess startup by the AI tool itself dominates the cost, so omamori adds no perceivable latency. Measured locally with `cargo bench`; see [#124](https://github.com/yottayoshida/omamori/issues/124) for methodology and `benches/` for reproducible harnesses.

**Self-defense**: AI agents cannot `config disable`, `uninstall`, or edit `config.toml` while detected. Hooks block env var unsetting, config modification, and audit log/secret access via shell commands. This is a key differentiator from other CLI guards — omamori assumes adversarial AI behavior and defends against it.

**Auto mode compatible**: works seamlessly with Claude Code's [Auto mode](https://claude.com/blog/auto-mode) — safe commands proceed without prompts, dangerous commands are still hard-blocked.

**Auto-sync**: after `brew upgrade`, the shim detects version mismatch and auto-regenerates hook files on the next invocation.

**Core policy**: the 7 built-in rules cannot be disabled via `config.toml` — an AI agent setting `enabled = false` is silently ignored. For legitimate overrides, see `omamori override` in [CLI Reference](#cli-reference).

**Integrity monitoring** (`omamori status`): verifies all defense layers are intact — shims, hooks, config, core policy, PATH order. Detects tampering including subtle hook edits where the version comment is preserved but the body is rewritten.

**File protection**: AI Edit/Write operations on omamori's own files (config, hooks, audit log, integrity baseline, Claude Code settings.json) are blocked. See [SECURITY.md](SECURITY.md) for the full protected file list.

## Real-world Effect

omamori is dogfooded daily on the developer's own setup. Recent observed cases:

### 2026-04-23: Codex CLI tried to read `config.toml` during MCP re-auth

When Codex CLI ran `mcp login notion`, it first attempted `rg` / `sed` against `~/.codex/config.toml` to find the auth setting. omamori hooks blocked both reads ("blocked attempt to edit Codex config"). Codex then tried to use `omamori explain -- ...` as an oracle to probe protection — also blocked by oracle-attack prevention. Codex pivoted to `codex mcp --help` → `codex mcp login notion` and completed OAuth via the browser. No protection bypassed; user-side hint preserved for after-the-fact verification.

Full transcript: [`docs/dogfood/2026-04-23-codex-notion-mcp-reauth.md`](docs/dogfood/2026-04-23-codex-notion-mcp-reauth.md).

These are honest snapshots of a single developer's environment, not benchmark claims.

## Configuration

### Context-aware actions

omamori can adjust actions based on what the command targets:

| Command | Without context | With context |
|---------|----------------|-------------|
| `rm -rf target/` | trash | **log-only** (regenerable) |
| `rm -rf src/` | trash | **block** (protected) |
| `git reset --hard` (no changes) | stash-then-exec | **log-only** (git-aware) |

**Opt-in**: add `[context]` to `~/.config/omamori/config.toml`. Built-in lists for regenerable (`target/`, `node_modules/`, etc.) and protected (`src/`, `.git/`, `.env`, etc.) paths activate automatically.

```toml
[context]
# Built-in defaults activate with just [context].
# To customize, specify your own lists (replaces built-in defaults):
# regenerable_paths = ["target/", "node_modules/", "my-cache/"]
# protected_paths = ["src/", "lib/", ".git/", ".env", ".ssh/", "secrets/"]
```

> **Note**: specifying `regenerable_paths` or `protected_paths` **replaces** the built-in defaults (not appends). Include the built-in entries you want to keep.

Security features: symlink defense via `canonicalize()`, path traversal normalization, NEVER_REGENERABLE hardcoded list, fail-close on errors.

### Rule configuration

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

**Enable audit retention** (prunes entries older than N days):
```toml
[audit]
retention_days = 90  # 0 = keep all (default). Minimum 7 days.
```

**Enable strict mode** (block shim-intercepted commands when HMAC secret is unavailable):
```toml
[audit]
strict = true  # default: false. Hook-only commands (ls, cat, etc.) are not affected.
```

**Notes**: config requires `chmod 600`. Destinations must be absolute paths on the same volume. System directories and symlinks are rejected.

</details>

## CLI Reference

```
omamori install [--hooks]                # Setup shims + hooks + config (re-run after brew upgrade for Cursor)
omamori doctor [--fix] [--verbose] [--json]  # Diagnose and auto-repair installation
omamori explain [--json] -- <cmd...>     # Show what would happen to a command and why
omamori test [--config PATH]             # Verify policy rules
omamori status [--refresh]               # Health check all defense layers
omamori exec [--config PATH] -- CMD      # Run command through policy engine

omamori audit verify                     # Verify hash chain integrity (exit 0/1/2)
omamori audit show [--last N] [--json]   # View recent audit entries (default: last 20)
omamori audit show --all                 # View all entries
omamori audit show --rule <name>         # Filter by rule (substring match)
omamori audit show --provider <name>     # Filter by provider

omamori config list                      # Show rules with status
omamori config disable <rule>            # Disable a rule
omamori config enable <rule>             # Re-enable a rule
omamori override disable <rule>          # Override a core safety rule
omamori override enable <rule>           # Restore a core safety rule

omamori init [--force] [--stdout]        # Create/reset config
omamori uninstall                        # Remove shims + hooks
omamori hook-check [--provider NAME]     # Hook detection engine (used internally by hooks)
omamori cursor-hook                      # Cursor hook handler
omamori --version                        # Show version
```

## Scope and Limitations

### Sandbox complementarity

omamori operates at the **semantic layer** — it understands *what* a command does (Layer 1: shim, Layer 2: hooks). A filesystem sandbox operates at the **OS boundary** — it restricts *where* processes can read and write. These are complementary:

- omamori catches `rm -rf src/` before it runs (semantic: "dangerous command").
- A sandbox prevents damage if something slips through (boundary: "this process cannot write outside `/tmp`").

For defense in depth, combine omamori with your AI tool's sandbox (Codex CLI sandbox (default-on), Claude Code `/sandbox`, Cursor agent sandbox) or [nono](https://github.com/always-further/nono).

### Structural limitations

These are inherent to the PATH shim approach:

- **Full-path execution** (`/bin/rm`) bypasses the shim — mitigated by Layer 2 hooks.
- **`sudo`** changes PATH — omamori blocks when it detects elevated execution.
- **Interpreter commands** (`python -c "shutil.rmtree(...)"`) — not detected. [Decided out of scope per #74](https://github.com/yottayoshida/omamori/issues/74): zero real-world incidents in target tools.
- **Obfuscated commands** (base64, variable indirection) — cannot be detected by static analysis.
- **AI self-bypass** — `config disable` / `uninstall` are blocked; direct file editing blocked by hooks (Claude Code only).

For what omamori **does not** catch — by design or by structural limit — and for the full security model and bypass corpus, see [SECURITY.md](SECURITY.md).

## Contributing & License

Bug reports, security disclosures, and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, the SHA-pin policy, and the local pre-PR gate (`./scripts/pre-pr-check.sh`). Releases are reproducible: `Cargo.lock` is tracked, every CI `cargo` invocation runs with `--locked`, and every GitHub Action `uses:` ref is pinned to a 40-char SHA (Dependabot keeps them current). See [SECURITY.md](SECURITY.md#ai-assisted-contribution-invariants-v093) for the five invariants that govern AI-assisted contributions.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
