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

# One-command setup: shims + hooks + shell PATH + verify
omamori setup
```

That's it. `setup` installs shims and hooks, appends `$HOME/.omamori/shim` to your shell profile, and runs `omamori doctor` — all in one step. Works with Claude Code Auto mode, no extra config needed.

> **Already installed?** `omamori setup` is idempotent — safe to re-run after upgrades.
> For non-interactive environments (CI, scripts): `omamori setup --non-interactive`.
> Preview without changes: `omamori setup --dry-run`.

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

Layer 2 hooks defend against evasion patterns via builtin rules. Structural patterns are handled in two ways:

| Category | Examples | Default action |
|----------|----------|----------------|
| Extractable | pipe-to-shell (`curl … \| bash`), parse edge cases | **allow** with audit-logged staging file |
| Opaque | dynamic generation (`bash -c "$(cmd)"`), shell obfuscation (`$'rm'`, `{rm,-rf,/}`), oversized input | **block** |

Environment-variable tampering, PATH override attempts, and self-modification commands (`config disable`, `uninstall`, etc.) are always blocked. See [SECURITY.md](SECURITY.md) for the full structural pattern taxonomy.

> **v0.11.2+**: Extractable structural patterns are now allowed by default (with audit trail). To restore hard-block behavior for all structural patterns, set `[structural] action = "block"` in config.toml.

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

Core policy: built-in rules (14 as of v0.11.1, including self-protection rules) cannot be disabled via `config.toml` — an AI agent setting `enabled = false` is ignored. For legitimate overrides, see `omamori override` in [CLI Reference](#cli-reference).

**Performance**: hook check completes in well under 0.1ms in the benchmark harness — typically ~1 µs to block and ~57 µs to allow. Subprocess startup by the AI tool dominates total cost. See `benches/` and [#124](https://github.com/yottayoshida/omamori/issues/124) for methodology.

### Verifiability

`doctor` groups installation checks into Layer 1, Layer 2, and Integrity, then adds recent risk signals from the audit report.

<!-- update output samples when doctor/report format changes -->
```
$ omamori doctor
Protection status: OK

  [Layer 1] PATH shims 6/6
    last active: today
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

**Enabled by default** (v0.10.9+). Built-in lists for regenerable (`target/`, `node_modules/`, etc.) and protected (`src/`, `.git/`, `.env`, etc.) paths are active out of the box. To customize, add a `[context]` section to `~/.config/omamori/config.toml`:

```toml
[context]
# Specifying a list replaces the built-in defaults (not appends).
# regenerable_paths = ["target/", "node_modules/", "my-cache/"]
# protected_paths = ["src/", "lib/", ".git/", ".env", ".ssh/", "secrets/"]
```

> **Note**: specifying `regenerable_paths` or `protected_paths` **replaces** the built-in defaults (not appends). Include the built-in entries you want to keep.

Security features: symlink defense via `canonicalize()`, path traversal normalization, NEVER_REGENERABLE hardcoded list, fail-close on errors.

### Rule configuration

Built-in rules are always inherited. Only write the rules you want to change:

```bash
omamori config list                          # show all rules
omamori config add my-rule --command rm --action block --match-any -rf  # scaffold a custom rule
omamori config disable my-rule               # disable it
omamori config enable my-rule                # re-enable it
omamori override disable git-push-force-block  # disable a built-in (core rules use override, not config disable)
omamori test                                 # verify policy
```

Or edit `~/.config/omamori/config.toml` directly. Config is auto-created by `omamori setup` (or `install --hooks`). See `omamori init --stdout` for the full template.

<details>
<summary>Configuration examples</summary>

**Disable a custom rule** (built-ins ignore `enabled = false` here — see below):
```toml
[[rules]]
name = "my-rule"
enabled = false
```

**Disable a built-in rule** (core rules can only be disabled via `[overrides]`, equivalent to `omamori override disable <rule-name>`):
```toml
[overrides]
git-push-force-block = false
```

**Move files to a custom directory**:
```toml
[[rules]]
name = "rm-to-backup"
command = "rm"
action = "move-to"
destination = "/Users/you/.omamori-quarantine/"  # under your home directory, not /tmp
match_any = ["-r", "-rf", "-fr", "--recursive"]
```

**Override an existing rule**:
```toml
[[rules]]
name = "rm-recursive-to-trash"
action = "move-to"
destination = "/Users/you/.omamori-quarantine/"  # under your home directory, not /tmp
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

**Control structural block behavior** (materialize vs hard-block):
```toml
[structural]
action = "block"     # default: "materialize". Set to "block" to hard-block all structural patterns.
retention_days = 7   # auto-prune staging files older than N days. 0 = disabled.
max_files = 500      # cap on staging file count; oldest deleted first. 0 = disabled.
```

**Notes**: config requires `chmod 600`. Destinations must be absolute paths on the same volume. System directories and symlinks are rejected.

</details>

## CLI Reference

```
omamori setup [--dry-run] [--non-interactive] [--source PATH]  # One-command install + shell profile + verify
omamori install [--hooks] [--source PATH]  # Install shims + hooks (no shell profile)
omamori doctor [--fix] [--verbose] [--json]  # Diagnose and auto-repair installation
omamori explain [--json] -- <cmd...>     # Show what would happen to a command and why
omamori test [--config PATH]             # Verify policy rules
omamori status [--refresh]               # Health check all defense layers
omamori exec [--config PATH] -- CMD      # Run command through policy engine

omamori report [--last 7d] [--json] [--verbose]  # Aggregate audit summary (1d–90d)

omamori audit verify                     # Verify hash chain integrity (exit 0/1/2/3)
omamori audit show [--last N] [--json]   # View recent audit entries (default: last 20)
omamori audit show --all                 # View all entries
omamori audit show --rule <name>         # Filter by rule (substring match)
omamori audit show --provider <name>     # Filter by provider
omamori audit show --relaxed             # Filter to relaxed allows (legacy data-context flag; pre-v0.10.4 logs only)

omamori config list                      # Show rules with status
omamori config add <name> --command <cmd> --action <block|trash|stash|log-only|move-to> [--match-any <token>]... [--match-all <token>]... [--destination <abs-path>] [--message <text>]  # Scaffold a custom rule
omamori config disable <rule>            # Disable a rule
omamori config enable <rule>             # Re-enable a rule
omamori config validate [PATH]           # Validate config (exit 0/1/2)
omamori override disable <rule>          # Override a core safety rule
omamori override enable <rule>           # Restore a core safety rule

omamori break-glass --rule <id> [--duration <dur>]  # Time-limited bypass for false positives
omamori break-glass --status             # Show active bypasses
omamori break-glass --clear [--rule <id>]  # Revoke bypass(es)

omamori init [--force] [--stdout]        # Create/reset config
omamori uninstall                        # Remove shims + hooks
omamori hook-check [--provider NAME] [--json-error]  # Hook detection engine (used internally by hooks)
omamori cursor-hook                      # Cursor hook handler
omamori --version                        # Show version
```

## Troubleshooting

Stuck on something else — a false positive, a temporary bypass, "why was this blocked?", or a staging-file message? Start with the [FAQ](docs/FAQ.md). This section covers the hook-error class of problems specifically.

### Claude Code blocks every Bash command with a "hook error" / "No such file or directory"

This means the hook script registered in `~/.claude/settings.json` points at a path that no longer exists (e.g. a Homebrew Cellar path from a removed version, or a build directory that was cleaned up). omamori's hooks are fail-close by design, so a missing hook script blocks everything rather than silently allowing it.

**Fix**: in a plain terminal (not through an AI agent), run:

```bash
omamori install --hooks
```

This regenerates the hook script at the canonical path and re-merges the entry into `~/.claude/settings.json`. `omamori doctor --fix` diagnoses the same class of problem in more detail.

**Why a plain terminal, specifically**: the "hook error" you're seeing blocks *every* Bash command through Claude Code — including one where you ask the AI agent to run `omamori install --hooks` itself. That command would go through the exact same broken hook and fail the same way, so an AI agent cannot fix this from inside its own Bash tool no matter what it tries (verified in #355). The hook wrapper itself now prints this same guidance to stderr when it can't reach `hook-check` at all (a broken/missing exec path, not a policy decision) — if you see that message, it's confirming the same thing this section describes.

If the above doesn't fix it, check for a **project-level** `.claude/settings.json` (in the repository you're working in, not `~/.claude/settings.json`). A `PreToolUse` entry tagged `x-omamori-version` there can also point at a stale path — remove that entry manually, since `omamori install --hooks` only manages the user-level `~/.claude/settings.json`.

### Claude Code blocks every Bash command with a hook error that isn't "No such file or directory"

Unlike the missing-path case above, the hook's registered path can exist but still be the wrong binary — for example, if you're developing omamori itself and run `cargo build`/`cargo test` in the repo, the shim's background self-repair could (rarely) resolve its own executable to a stale build artifact and bake that path into the hook script (#349).

omamori verifies that a resolved path actually satisfies the hook's contract before writing it anywhere (#349), *and* refuses to persist a path that looks like a `cargo build`/`cargo test` artifact in the first place — `target/debug/...`, `target/release/...`, or the `cargo build --target <triple>` cross-compile layout — even when that binary would otherwise pass verification (#354). Both the background self-repair (triggered automatically on version/hash mismatch) and `omamori install --hooks`/`omamori setup` silently keep the existing hook / fail loudly (respectively) rather than pinning a path the next build can delete or replace out from under you. `omamori doctor` also detects a hook whose on-disk path no longer passes verification, even if the file's content otherwise looks up to date.

**Fix**: same as above — run `omamori install --hooks` in a plain terminal. If it fails, the error message names the broken path; make sure `omamori` on your `PATH` resolves to a stable install (Homebrew-linked or `~/.cargo/bin`), not a `target/debug`/`target/release` build directory, then retry. If you're intentionally developing omamori itself and want to pin a dev build anyway, pass `--source` explicitly: `omamori install --hooks --source <path>` or `omamori setup --source <path>` — this is the one case where you're making the provenance judgment the check otherwise makes automatically.

### Contributing to omamori: `cargo test` and your real `~/.claude` / `~/.codex`

omamori's test suite pins `HOME` to a throwaway directory for every subprocess/in-process test that touches settings merge (#210). If you add a new test that calls `install`/`uninstall` or spawns the `omamori` binary, inject an isolated `HOME` (see existing tests in `tests/integration.rs`) — otherwise the test can merge a dead hook path into your real `~/.claude/settings.json` or `~/.codex/hooks.json`.

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
- **AI self-bypass** — `config disable` / `uninstall` / `break-glass` are blocked; direct file editing blocked by hooks (Claude Code only). For human-initiated false positive recovery, use `omamori break-glass --rule <id>` (time-limited, audit-logged).

For what omamori **does not** catch — by design or by structural limit — and for the full security model and bypass corpus, see [SECURITY.md](SECURITY.md).

## Contributing & License

Bug reports and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, the SHA-pin policy, and the local pre-PR gate (`./scripts/pre-pr-check.sh`). For security vulnerabilities, see [SECURITY.md → Reporting a Vulnerability](SECURITY.md#reporting-a-vulnerability) instead of filing a public issue. Releases are reproducible: `Cargo.lock` is tracked, every CI `cargo` invocation runs with `--locked`, and every GitHub Action `uses:` ref is pinned to a 40-char SHA (Dependabot keeps them current). See [SECURITY.md](SECURITY.md#ai-assisted-contribution-invariants-v093) for the five invariants that govern AI-assisted contributions.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
