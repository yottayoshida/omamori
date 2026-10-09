# ADR-0018: Every Claude Code tool call reaches the hook, and only a shell command is ever approved by it

- **Status**: Accepted
- **Date**: 2026-10-09
- **Plan**: `.claude/plans/2026-10-09-omamori-509-520-521-576-editor-hook-and-audit-surfaces.md`
- **Issues**: [#576](https://github.com/yottayoshida/omamori/issues/576), [#520](https://github.com/yottayoshida/omamori/issues/520); the shell route stays with [#577](https://github.com/yottayoshida/omamori/issues/577)

## Context

`omamori install --hooks` has registered omamori's Claude Code `PreToolUse` entry with `"matcher": "Bash"` since v0.9.7 (#205), and migrated the earlier `"*"` to it as a legacy form. Claude Code therefore sent omamori shell commands and nothing else. Everything the hook decides about other tools was still implemented and tested — the tests call `hook-check` directly — but from v0.9.7 through 1.3.0 none of it ran in a Claude Code session:

- an AI agent's `Edit`/`Write` to `config.toml`, the audit log, the HMAC secret, the hook scripts or `~/.claude/settings.json` was not blocked (measured on 1.3.0: the file-protection guard blocks the call when given it; Claude Code's own `Write` created the same file in a live session);
- reading the HMAC secret through `Read` was not blocked;
- a renamed tool carrying `file_path`/`path`/`command` did not reach "the full pipeline regardless of `tool_name`".

SECURITY.md and G-5 state all three. v0.10.4 then removed the shell-side meta-patterns and handed their file protection to this same guard, so from v0.10.4 it was the only thing behind the promise.

Two properties of the hook made routing every tool unsafe as it stood:

1. On an allow, `hook-check` prints `permissionDecision: "allow"` (#62, so that Auto mode does not prompt for every shell command it already judged). Claude Code reads that as approval and skips its own permission prompt. Printed for every tool, it would approve every MCP call, every `WebFetch`, every edit.
2. An empty `tool_input`, or a routing field that is not a string, is refused with exit 2 regardless of the tool — correct for a shell command, wrong for the many tools that take no arguments.

## Decision

1. **The matcher is `"*"`.** Every tool call reaches the hook and is routed by the shape of its input, as SECURITY.md's "Scope: unknown / new tools" describes. The matcher lives in one constant read by the installer, `doctor` and the shim's settings sync; an entry still saying `"Bash"` is outdated and is rewritten.
2. **Only a shell command is ever approved by the hook.** For the `claude-code` provider, `permissionDecision: "allow"` is printed only when `tool_name` is `Bash`. Every other allowed call exits 0 with nothing on stdout, which Claude Code documents as "no decision": its normal permission flow applies. A tool carrying a `command` field (`Monitor`, some MCP tools) is still checked like a shell command, and still not approved by omamori.
3. **A missing or mistyped input is refused only for `Bash`.** For any other tool it is an unrecognised shape.
4. **Tool names relax, they never tighten.** After routing by shape, a file operation from a reading tool (`Read`, `Grep`, `NotebookRead`) is checked only for the audit secret — a file whose name starts with `audit-secret`, or a directory holding one; a listing tool (`Glob`, `LS`) is not checked; every other name, including an unknown one, gets the whole protected list. A renamed writing tool is therefore treated as a writer.
5. **A file-protection block is recorded** in the audit chain as `layer2:file-protection`, like every other Layer 2 deny, so that "no row means allow" stays true for the Claude Code path.
6. **An unrecognised shape is recorded once per tool name per day.** The record costs 35–41 ms (config, key store, locked append, two syncs) against 7–9 ms for the rest of the hook; with every tool routed it would run on every `AskUserQuestion`, `Agent` and MCP call. A sentinel under `~/.omamori` keyed by the tool name gates it; a new or renamed tool is still recorded the first time it is seen.
7. **`~/.omamori` is protected as a whole**, which covers the warning-throttle sentinels (#520) and the new unknown-tool sentinels, and `.claude/settings.local.json` is protected beside `settings.json`.

## Alternatives Considered

- **A name list (`Bash|Edit|Write|MultiEdit`, optionally `|Read|Grep`).** Rejected by the owner. It makes the editor tools work and leaves "a renamed tool still reaches the pipeline" false for Claude Code — the same silent loss as #576, waiting for the next rename.
- **A second settings entry for the editor tools.** Cleanup, duplicate detection and `doctor`'s check all assume one omamori entry.
- **Printing `"allow"` for every tool, as the `"*"` era did.** Approves every call the user's settings would have prompted for.
- **Recording every unrecognised shape** (the v0.9.6 design). 35–41 ms and an audit line on most tool calls, serialised on the log's lock.
- **Not recording unrecognised shapes at all.** Removes the only trace a renamed tool with an unknown field would leave.

## Consequences

- Claude Code sessions must be restarted to pick up the new matcher; the settings file is rewritten on the first guarded command after the upgrade.
- Files that match a protected pattern can no longer be edited by an AI agent in **any** project: `.claude/settings.json`, `.claude/settings.local.json`, `omamori/config.toml`, `audit.jsonl`, `.integrity.json`, the hook scripts, `audit-secret*`, `*.jsonl.hwm`, `*.prune-tmp`, `.codex/config.toml`, `.codex/hooks.json`, and anything under a `.omamori` directory. This is what the documents always said; it had not been enforced since v0.9.7.
- When omamori cannot answer — its binary missing, the hook script broken — the wrapper exits 2, and that now stops every tool call in Claude Code rather than only shell commands. This is G-6 (fail closed); a `!` command in Claude Code does not pass through the hook and can run `omamori install --hooks`.
- Not reached: a path carried in another field (`paths`, `file_paths`, `files`), `Grep` with no `path`, and every shell command (#577).
- Every tool call pays 7–9 ms; the first call of an unrecognised tool each day pays 35–41 ms.
