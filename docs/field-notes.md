# Field notes

omamori is dogfooded daily on the developer's own setup. Recent observed cases:

## 2026-04-23: Codex CLI tried to read `config.toml` during MCP re-auth

When Codex CLI ran `mcp login notion`, it first attempted `rg` / `sed` against `~/.codex/config.toml` to find the auth setting. omamori hooks blocked both reads ("blocked attempt to edit Codex config"). Codex then tried to use `omamori explain -- ...` as an oracle to probe protection — also blocked by oracle-attack prevention. Codex pivoted to `codex mcp --help` → `codex mcp login notion` and completed OAuth via the browser. No protection bypassed; user-side hint preserved for after-the-fact verification.

Full transcript: [`dogfood/2026-04-23-codex-notion-mcp-reauth.md`](dogfood/2026-04-23-codex-notion-mcp-reauth.md).

These are honest snapshots of a single developer's environment, not benchmark claims.
