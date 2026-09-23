# How omamori works

What it blocks, which tools it covers, how the layers fit together, and what it does not catch.

## What It Blocks

| Command | Pattern | Action |
|---------|---------|--------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | **trash** — move to macOS Trash |
| `git` | `reset --hard` | **stash-then-exec** — `git stash` first, in the repository the reset acts on (`-C`, `--git-dir`, `--work-tree`, `GIT_DIR` included); **block** if another global option such as `-c` could move it |
| `git` | `push --force`, `push -f` | **block** |
| `git` | `clean -f`, `clean --force` | **block** |
| `chmod` | `777` | **block** |
| `find` | `-delete`, `--delete` | **block** |
| `rsync` | `--delete` + 7 variants | **block** |

**rsync blocked variants:**

`--delete`, `--del`, `--delete-before`, `--delete-during`, `--delete-after`, `--delete-excluded`, `--delete-delay`, `--remove-source-files`


Layer 2 hooks defend against evasion patterns via builtin rules. Structural patterns are handled in two ways:

| Category | Examples | Default action |
|----------|----------|----------------|
| Extractable | pipe-to-shell (`curl … \| bash`), parse edge cases | **allow** with audit-logged staging file |
| Opaque | dynamic generation (`bash -c "$(cmd)"`), shell obfuscation (`$'rm'`, `{rm,-rf,/}`), oversized input | **block** |

Environment-variable tampering, PATH override attempts, and self-modification commands (`config disable`, `uninstall`, etc.) are always blocked. See [SECURITY.md](../SECURITY.md) for the full structural pattern taxonomy.

> Extractable structural patterns are allowed by default, with an audit trail. To hard-block all structural patterns instead, set `[structural] action = "block"` in config.toml.

All rules are customizable via TOML config. See [Configuration](configuration.md).

## Tool Compatibility

| Tool | Status | Coverage | Notes |
|------|--------|----------|-------|
| Claude Code | Supported (Tier 1) | Layer 1 + Layer 2 | PreToolUse hook installed automatically. Auto Mode compatible. |
| Codex CLI | Supported (Tier 2) | Layer 1 + Layer 2 | Hooks and config auto-configured during install. |
| Cursor | Supported (Tier 2) | Layer 1 + Layer 2 | Re-merge generated hook snippet after upgrade. |
| Gemini CLI, Cline, others | Community | Layer 1 only | Not E2E tested. |
| Any tool setting `AI_GUARD=1` | Fallback | Layer 1 only | Generic opt-in detection. |

> The [README's demo image](../README.md#demo) is a Claude Code capture; the same `block` / `log-only` / `trash` behavior applies on Codex CLI and Cursor when their env vars are detected.

See [docs/CONTRACT.md → Supported tier](CONTRACT.md#supported-tier) for what Tier 1 (contractually guaranteed) versus Tier 2 (expected to work, no continuous verification) means.

### Platforms

macOS only at runtime — shim paths and Trash integration are macOS-specific. CI verifies contributors' PRs on **macOS + Ubuntu** (`#[cfg(unix)]` regressions caught before merge). Windows is not supported.

### How omamori handles new / renamed tools

omamori routes by **payload shape** (`tool_input.command` / `cmd` / `file_path` / `path` / `url`), not by tool name. A renamed AI tool carrying a `command` field still reaches the full pipeline; unrecognised shapes still allow but emit `unknown_tool_fail_open` audit events. Review with `omamori audit unknown` or check `omamori doctor`'s 30-day count line.

For the full shape catalogue, scope, known operational noise (legitimate tools like `Glob` / `Task` landing in fail-open), and the strict-mode trade-off, see [SECURITY.md → Hook Coverage](../SECURITY.md#hook-coverage-layer-2).

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
| **Audit chain** | HMAC-SHA256 signed, hash-chained tamper-evident JSONL log at `~/.local/share/omamori/audit.jsonl` — also records successful `config disable/enable/add` mutations, not just command decisions | `omamori audit verify` |
| **Integrity monitoring** | Verifies shims, hooks, config, core policy, PATH order. Detects subtle hook body rewrites | `omamori doctor`, `omamori status` |
| **File protection** | Blocks AI Edit/Write on config, hooks, audit log, integrity baseline, Claude Code settings.json | Hook integration tests |
| **Auto-sync** | Detects version mismatch after `brew upgrade` and auto-regenerates hook files | Smoke test |

Core policy: built-in rules (15 at 1.0, including self-protection rules) cannot be disabled via `config.toml` — an AI agent setting `enabled = false` is ignored. For legitimate overrides, see `omamori override` in [CLI Reference](cli.md).

**Performance**: hook check completes in well under 0.1ms in the benchmark harness — typically ~1 µs to block and ~57 µs to allow. Subprocess startup by the AI tool dominates total cost. See `benches/` and [#124](https://github.com/yottayoshida/omamori/issues/124) for methodology.

### Verifiability

`doctor` groups installation checks into Layer 1, Layer 2, and Integrity, then adds recent risk signals from the audit report.

<!-- update output samples when doctor/report format changes -->
```
$ omamori doctor
Protection status: OK

  [Layer 1] PATH shims 6/6
    last active: today
  [Layer 2] Hook defense 5/5
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

## Scope and Limitations

### Sandbox complementarity

omamori operates at the **semantic layer** — it understands *what* a command does (Layer 1: shim, Layer 2: hooks). A filesystem sandbox operates at the **OS boundary** — it restricts *where* processes can read and write. These are complementary:

- omamori catches `rm -rf src/` before it runs (semantic: "dangerous command").
- A sandbox prevents damage if something slips through (boundary: "this process cannot write outside `/tmp`").

For defense in depth, combine omamori with your AI tool's sandbox (Codex CLI sandbox (default-on), Claude Code `/sandbox`, Cursor agent sandbox) or [nono](https://github.com/always-further/nono). For the responsibility boundary between the two layers, concrete examples of what each catches, and recommended per-tool setup order, see [docs/reference-architecture.md](reference-architecture.md).

### Structural limitations

These are inherent to the PATH shim approach:

- **Full-path execution** (`/bin/rm`) bypasses the shim — mitigated by Layer 2 hooks.
- **`sudo`** changes PATH — omamori blocks when it detects elevated execution.
- **Interpreter commands** (`python -c "shutil.rmtree(...)"`) — not detected. [Decided out of scope per #74](https://github.com/yottayoshida/omamori/issues/74): zero real-world incidents in target tools.
- **Obfuscated commands** (base64, runtime variable indirection) — runtime-evaluated forms cannot be detected by static analysis. Static shell expansion at command verb position (`$'rm'`, `{rm,-rf,/}`) is caught.
- **AI self-bypass** — `config disable` / `uninstall` / `break-glass` are blocked; direct file editing blocked by hooks (Claude Code only). For human-initiated false positive recovery, use `omamori break-glass --rule <id>` (time-limited, audit-logged).

For what omamori **does not** catch — by design or by structural limit — and for the full security model and bypass corpus, see [SECURITY.md](../SECURITY.md).
