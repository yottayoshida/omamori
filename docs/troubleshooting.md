# Troubleshooting

Stuck on something else — a false positive, a temporary bypass, "why was this blocked?", or a staging-file message? Start with the [FAQ](FAQ.md). This section covers the hook-error class of problems specifically.

## Claude Code blocks every Bash command with a "hook error" / "No such file or directory"

This means the hook script registered in `~/.claude/settings.json` points at a path that no longer exists (e.g. a Homebrew Cellar path from a removed version, or a build directory that was cleaned up). omamori's hooks are fail-close by design, so a missing hook script blocks everything rather than silently allowing it.

**Fix**: in a plain terminal (not through an AI agent), run:

```bash
omamori install --hooks
```

This regenerates the hook script at the canonical path and re-merges the entry into `~/.claude/settings.json`. `omamori doctor --fix` diagnoses the same class of problem in more detail.

**Why a plain terminal, specifically**: the "hook error" you're seeing blocks *every* Bash command through Claude Code — including one where you ask the AI agent to run `omamori install --hooks` itself. That command would go through the exact same broken hook and fail the same way, so an AI agent cannot fix this from inside its own Bash tool no matter what it tries (verified in #355). The hook wrapper itself now prints this same guidance to stderr when it can't reach `hook-check` at all (a broken/missing exec path, not a policy decision) — if you see that message, it's confirming the same thing this section describes.

If the above doesn't fix it, check for a **project-level** `.claude/settings.json` (in the repository you're working in, not `~/.claude/settings.json`). A `PreToolUse` entry tagged `x-omamori-version` there can also point at a stale path — remove that entry manually, since `omamori install --hooks` only manages the user-level `~/.claude/settings.json`.

## Claude Code blocks every Bash command with a hook error that isn't "No such file or directory"

Unlike the missing-path case above, the hook's registered path can exist but still be the wrong binary — for example, if you're developing omamori itself and run `cargo build`/`cargo test` in the repo, the shim's background self-repair could (rarely) resolve its own executable to a stale build artifact and bake that path into the hook script (#349).

omamori verifies that a resolved path actually satisfies the hook's contract before writing it anywhere (#349), *and* refuses to persist a path that looks like a `cargo build`/`cargo test` artifact in the first place — `target/debug/...`, `target/release/...`, or the `cargo build --target <triple>` cross-compile layout — even when that binary would otherwise pass verification (#354). Both the background self-repair (triggered automatically on version/hash mismatch) and `omamori install --hooks`/`omamori setup` silently keep the existing hook / fail loudly (respectively) rather than pinning a path the next build can delete or replace out from under you. `omamori doctor` also detects a hook whose on-disk path no longer passes verification, even if the file's content otherwise looks up to date.

**Fix**: same as above — run `omamori install --hooks` in a plain terminal. If it fails, the error message names the broken path; make sure `omamori` on your `PATH` resolves to a stable install (Homebrew-linked or `~/.cargo/bin`), not a `target/debug`/`target/release` build directory, then retry. If you're intentionally developing omamori itself and want to pin a dev build anyway, pass `--source` explicitly: `omamori install --hooks --source <path>` or `omamori setup --source <path>` — this is the one case where you're making the provenance judgment the check otherwise makes automatically.

## Contributing to omamori: `cargo test` and your real `~/.claude` / `~/.codex`

omamori's test suite pins `HOME` to a throwaway directory for every subprocess/in-process test that touches settings merge (#210). If you add a new test that calls `install`/`uninstall` or spawns the `omamori` binary, inject an isolated `HOME` (see existing tests in `tests/integration.rs`) — otherwise the test can merge a dead hook path into your real `~/.claude/settings.json` or `~/.codex/hooks.json`.
