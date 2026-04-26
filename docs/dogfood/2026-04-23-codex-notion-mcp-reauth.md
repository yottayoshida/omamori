# 2026-04-23: omamori hook fired during Codex CLI Notion MCP re-authentication

## Summary

When Codex CLI ran `mcp login notion` (re-authentication for the Notion MCP server), Codex first attempted to read `~/.codex/config.toml` to locate the auth setting. omamori hooks blocked the reads in cascade. This is a real-world transcript validating that the v0.9.5 Codex config-protection layer and oracle-attack prevention work in production.

## Scenario

- User: yotta
- AI agent: Codex CLI
- Goal: OAuth re-authentication for Notion MCP
- Environment: omamori v0.9.5 (released 2026-04-20)

## Transcript excerpts

### 1. Codex's investigation intent

```
Confirm Notion MCP auth setup, then determine the re-auth command or config location.
First, read config.toml and any notion-related definitions.
```

### 2. omamori hook blocks direct config read

```
PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to edit Codex config
hint: run `omamori explain -- rg -n "notion|mcp" /Users/i.yoshida/.codex/config.toml .codex AGENTS.md` for details

PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to edit Codex config
hint: run `omamori explain -- sed -n '1,220p' /Users/i.yoshida/.codex/config.toml` for details
```

Both `rg` and `sed` reading the Codex `config.toml` were blocked.

### 3. Nested `omamori explain` bypass attempt also blocked

```
PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to run explain via AI (oracle attack prevention)
hint: run `omamori explain -- omamori explain -- sed -n '1,220p' /Users/i.yoshida/.codex/config.toml` for details
```

The hint omamori emitted included an `omamori explain -- ...` invocation. Codex tried to execute the hint as-is, but oracle-attack prevention rejected the nested form.

### 4. Codex pivots to a different path

```
Config reads are protected, so look up the Codex CLI re-auth flow.
Check Codex's help for the Notion / MCP auth subcommand.
```

Codex then ran `codex mcp --help` → `codex mcp list` → `codex mcp login notion` to start the OAuth flow, completing re-authentication via the browser.

## Observations

### Behaviours that worked as designed

| Behaviour | Outcome |
|---|---|
| `rg` reading `config.toml` | Blocked |
| `sed` reading `config.toml` | Blocked |
| `omamori explain -- omamori explain -- ...` nesting | Blocked (oracle-attack prevention) |
| Hint emitted so the user can verify after the fact | Preserved |

### Relation to v0.9.5 closures

This case validates the v0.9.5 hardening shipped in PR [#170](https://github.com/yottayoshida/omamori/pull/170):

- Pipe-to-shell with transparent wrappers is closed: `curl URL | env bash`, `curl URL | sudo bash`, and 7 wrapper variants (`sudo`, `env`, `nice`, `timeout`, `nohup`, `exec`, `command`) including chained, absolute-path, stdin-flag, and option-value forms.
- File-protection hooks block direct reads of `config.toml`, audit logs, hook scripts, and integrity baselines from AI-issued commands.
- Oracle-attack prevention blocks AI-issued `omamori explain` so the policy engine cannot be used as a probe.

The 2026-04-23 transcript captures *another* AI in real-world operation hitting the protection layer first (config read blocked, explain-as-oracle blocked) without finding any of the closed bypass paths.

### Design intent confirmed

- "AI cannot read Codex config" → **achieved**
- "Other AI cannot use omamori explain as an oracle" → **achieved**
- "User-side after-the-fact verification path is preserved (hint)" → **achieved**

## Note: peripheral noise not caused by omamori

The same transcript also contained these errors, which are not from omamori but from the Codex hook configuration:

```
UserPromptSubmit hook (failed) error: hook exited with code 127
PreToolUse hook (failed) error: PreToolUse hook returned unsupported permissionDecision:allow
```

- exit 127 = command not found (a different command referenced inside Codex's hook definitions failed PATH resolution).
- `permissionDecision:allow` = the Codex hook API does not accept this value (it is a Claude Code hook API value; the two have a spec-level difference).

## Citation use cases

This transcript can be cited in:

- The omamori README "Real-world Effect" section.
- v1.0 dogfooding evidence.
- A blog post such as "Preventing other AIs from peeking at your config".
- External review / audit evidence.

## Related

- v0.9.5 plan: Codex Phase 6-A logs under `investigation/`.
- `SECURITY.md`: wrapper-evasion section.
- `src/unwrap.rs`: bash-wrapper attack-surface coverage.
