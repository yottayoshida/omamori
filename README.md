# omamori

[![CI](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml/badge.svg)](https://github.com/yottayoshida/omamori/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/omamori.svg)](https://crates.io/crates/omamori)
[![homebrew](https://img.shields.io/badge/homebrew-tap-blue)](https://github.com/yottayoshida/homebrew-tap)
[![License](https://img.shields.io/crates/l/omamori)](LICENSE-MIT)

> Deterministic semantic guard for AI CLI tools. Blocks covered destructive commands and self-disablement attempts, with tamper-evident audit trails.
>
> Fast local checks — no model calls, no daemon, no network dependency.

omamori is not a sandbox or a permission classifier. It is a local deterministic semantic guard for AI-triggered shell commands: it blocks covered destructive command classes before execution, blocks AI-driven self-disablement attempts, and runs alongside sandbox isolation and provider-level permission systems.

**macOS only** — terminal commands are passed through unless an AI tool environment is detected. See [Tool Compatibility](#tool-compatibility) for supported AI tools and coverage.

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

> `report` and the trust-dashboard `doctor` output require omamori >= 0.10.0.

## Verifiable Claims

What omamori claims, and how to verify each one:

| Claim | Verified by |
|-------|-------------|
| Covered destructive command classes are blocked or redirected | `omamori test`, CI |
| Supported hook deny events are written to a tamper-evident audit chain | `omamori audit verify` |
| Installed defense layers are present and intact | `omamori doctor`, `omamori status` |
| Hook checks are local and deterministic — no model calls, no network dependency | source, CI |
| AI-driven self-disablement attempts are blocked in supported tool paths | acceptance test suite |

Bypass classes outside this coverage scope remain possible — this is inherent to the PATH-shim and static-analysis approach. See [SECURITY.md](SECURITY.md) for the full bypass corpus and defense boundary.

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

Layer 2 hooks additionally block evasion patterns such as pipe-to-shell (`curl URL | bash`), dynamic command generation (`bash -c "$(cmd)"`), static shell expansion obfuscation (`$'rm'`, `{rm,-rf,/}`), environment-variable tampering, and PATH override attempts targeting shimmed commands. Since v0.10.3, trigger words inside data arguments (`git commit -m "..."`, `gh issue create --body "..."`) are recognized as non-command context and allowed through.

All rules are customizable via TOML config. See [Configuration](#configuration) below.

## Tool Compatibility

| Tool | Status | Coverage | Notes |
|------|--------|----------|-------|
| Claude Code | Supported | Layer 1 + Layer 2 | PreToolUse hook installed automatically. Auto Mode compatible. |
| Codex CLI | Supported | Layer 1 + Layer 2 | Hooks and config auto-configured during install. |
| Cursor | Supported | Layer 1 + Layer 2 | Re-merge generated hook snippet after upgrade. |
| Gemini CLI, Cline, others | Community | Layer 1 only | Not E2E tested. |
| Any tool setting `AI_GUARD=1` | Fallback | Layer 1 only | Generic opt-in detection. |

> The demo image above is a Claude Code capture; the same `block` / `log-only` / `trash` behavior applies on Codex CLI and Cursor when their env vars are detected.

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

### Defense layers

| Capability | What it does | Verified by |
|------------|--------------|-------------|
| **Layer 1 — PATH shim** | Intercepts destructive commands (`rm`, `git`, `chmod`, `find`, `rsync`) by name when an AI env var is detected | `omamori test`, CI |
| **Layer 2 — Hooks** | Catches evasion patterns: shell wrappers, pipe-to-shell, dynamic generation, PATH override bypass | Hook integration tests |
| **Self-defense** | Blocks self-modification commands (`config disable`, `uninstall`, etc.), hook/config editing, env-var unsetting while AI-detected | Acceptance test suite |
| **Audit chain** | HMAC-SHA256 signed, hash-chained tamper-evident JSONL log at `~/.local/share/omamori/audit.jsonl` | `omamori audit verify` |
| **Integrity monitoring** | Verifies shims, hooks, config, core policy, PATH order. Detects subtle hook body rewrites | `omamori doctor`, `omamori status` |
| **File protection** | Blocks AI Edit/Write on config, hooks, audit log, integrity baseline, Claude Code settings.json | Hook integration tests |
| **Auto-sync** | Detects version mismatch after `brew upgrade` and auto-regenerates hook files | Smoke test |

Core policy: built-in rules (13 as of v0.10.3, including self-protection rules) cannot be disabled via `config.toml` — an AI agent setting `enabled = false` is ignored. For legitimate overrides, see `omamori override` in [CLI Reference](#cli-reference).

**Performance**: hook check completes in well under 0.1ms in the benchmark harness — typically ~1 µs to block and ~57 µs to allow. Subprocess startup by the AI tool dominates total cost. See `benches/` and [#124](https://github.com/yottayoshida/omamori/issues/124) for methodology.

### Verifiability

`doctor` groups installation checks into Layer 1, Layer 2, and Integrity, then adds recent risk signals from the audit report.

<!-- update output samples when doctor/report format changes -->
```
$ omamori doctor
Protection status: OK

  [Layer 1] PATH shims 6/6
  [Layer 2] Hook defense 4/4
  [Integrity] Config & baseline 3/3
  [Risk signals] Last 30 days: quiet

  run `omamori doctor --verbose` for full details

$ omamori report --last 7d
omamori report — last 7 days

  Block events: 42
    by layer: layer2: 42
    by provider: claude-code: 38, codex: 4
  Audit log: intact
```

## Field Notes

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

omamori report [--last 7d] [--json] [--verbose]  # Aggregate audit summary (1d–90d)

omamori audit verify                     # Verify hash chain integrity (exit 0/1/2)
omamori audit show [--last N] [--json]   # View recent audit entries (default: last 20)
omamori audit show --all                 # View all entries
omamori audit show --rule <name>         # Filter by rule (substring match)
omamori audit show --provider <name>     # Filter by provider
omamori audit show --relaxed             # Filter to data-context relaxed allows

omamori config list                      # Show rules with status
omamori config disable <rule>            # Disable a rule
omamori config enable <rule>             # Re-enable a rule
omamori override disable <rule>          # Override a core safety rule
omamori override enable <rule>           # Restore a core safety rule

omamori init [--force] [--stdout]        # Create/reset config
omamori uninstall                        # Remove shims + hooks
omamori hook-check [--provider NAME] [--json-error]  # Hook detection engine (used internally by hooks)
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
- **Obfuscated commands** (base64, runtime variable indirection) — runtime-evaluated forms cannot be detected by static analysis. Static shell expansion at command verb position (`$'rm'`, `{rm,-rf,/}`) is caught since v0.10.2.
- **AI self-bypass** — `config disable` / `uninstall` are blocked; direct file editing blocked by hooks (Claude Code only).

For what omamori **does not** catch — by design or by structural limit — and for the full security model and bypass corpus, see [SECURITY.md](SECURITY.md).

## Contributing & License

Bug reports, security disclosures, and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, the SHA-pin policy, and the local pre-PR gate (`./scripts/pre-pr-check.sh`). Releases are reproducible: `Cargo.lock` is tracked, every CI `cargo` invocation runs with `--locked`, and every GitHub Action `uses:` ref is pinned to a 40-char SHA (Dependabot keeps them current). See [SECURITY.md](SECURITY.md#ai-assisted-contribution-invariants-v093) for the five invariants that govern AI-assisted contributions.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
