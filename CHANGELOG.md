# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [0.4.1] - 2026-03-19

### Fixed

- **Context override message accuracy** (#36): When context evaluation escalates an action (e.g. trash → block for `src/`), the user-facing message now reflects the actual action via `ActionKind::context_message()`. Previously, the original rule's message was preserved, leading to misleading feedback like "moved to Trash" when the command was actually blocked. This also fixes `message = None` rules silently losing context information.

### Added

- **Hook auto-sync after upgrade** (#26): The shim now detects hook version mismatch on startup and auto-regenerates hooks. After `brew upgrade omamori`, hooks are updated on the next shim invocation — no manual `install --hooks` needed. Uses a version comment (`# omamori hook v0.4.1`) embedded in the hook script.
- **Atomic file writes**: All hook file writes (install and regenerate) now use temp file + flush + rename to prevent partial writes from concurrent execution or crashes.
- **CI consistency checks**: Compile-time tests verify `config.default.toml` stays in sync with `default_rules()`, `default_detectors()`, and `NEVER_REGENERABLE ⊇ default_protected_paths()`.
- **Bypass corpus tests**: Systematic test coverage for known attack patterns (P1–P4) and documented KNOWN_LIMIT attack vectors that omamori cannot detect by design (sudo, alias, env -i, obfuscation, export -n).
- **`[context]` template** in `config.default.toml`: Commented-out section showing available context configuration options.

### Changed

- **Breaking**: Context override now always generates a new message matching the actual action. Custom `message` fields on rules are overridden during context evaluation. This prioritizes security accuracy over custom text preservation.

### Important

- **Existing users on v0.4.0**: Hook scripts will be auto-updated on next command. No action needed.

## [0.4.0] - 2026-03-18

### Added

- **Context-aware rule evaluation** (#13): omamori now evaluates command target paths and git status to dynamically adjust protection actions, reducing false positives while strengthening defense against truly dangerous operations.
  - **Tier 1 — Path-based risk scoring**: `regenerable_paths` (e.g., `target/`, `node_modules/`) downgrade to `log-only`; `protected_paths` (e.g., `src/`, `.git/`) escalate to `block`.
  - **Tier 2 — Git-aware evaluation** (opt-in): `git reset --hard` with no uncommitted changes → `log-only`; `git clean -fd` with no untracked files → `log-only`. Default off, enable via `[context.git] enabled = true`.
  - **NEVER_REGENERABLE safety list**: `src/`, `lib/`, `.git/`, `.env`, `.ssh/` etc. cannot be classified as regenerable even if misconfigured.
  - **Symlink attack defense** (T2, DREAD 9.0): `canonicalize()` resolves symlinks before pattern matching. Canonicalize failure → no downgrade (fail-close).
  - **Path traversal defense** (T1, DREAD 8.0): Lexical normalization before matching prevents `target/../src/` bypass.
  - **Git env var spoofing defense** (T4, DREAD 7.2): `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE` removed from git subprocess.
  - **Multi-target evaluation**: All targets are checked; the most severe action wins (`rm -rf target/ src/` → block, not log-only).
  - **`omamori test`** now shows a Context evaluation section when `[context]` is configured.
  - All context decisions are reported via stderr for transparency.
- **`--version` subcommand** (#31): `omamori --version`, `-V`, and `version` now display the current version.

### Fixed

- **config.default.toml sync** (#32): Updated to match `default_detectors()` and `default_rules()`. Fixed stale env vars (codex-cli: `AI_GUARD` → `CODEX_CI`, cursor: `AI_GUARD` → `CURSOR_AGENT`), added missing detectors (gemini-cli, cline, ai-guard-fallback) and rules (find-delete-block, rsync-delete-block).

### Important

- **Opt-in activation**: Context-aware evaluation is disabled by default. Add `[context]` to your `config.toml` to enable it. Without `[context]`, behavior is identical to v0.3.2.
- **Existing users**: Run `omamori install --hooks` to update hook scripts. (v0.4.1+ auto-updates hooks on next shim invocation.)

## [0.3.2] - 2026-03-17

### Security

- **AI config bypass guard** (#22): `config disable`, `config enable`, `uninstall`, and `init --force` are now blocked when AI detector environment variables are present (CLAUDECODE, CODEX_CI, CURSOR_AGENT, etc.). This prevents AI agents from disabling their own safety rules — a bypass observed in real-world testing with Gemini CLI.
- **Hooks protection expanded**: Claude Code and Cursor hooks now block `config disable/enable`, `uninstall`, `init --force`, and direct `config.toml` file editing attempts.
- **`default_detectors()` made public**: Guard logic reuses the same detector list as the PATH shim, ensuring consistency.

### Changed

- **Protection Coverage table** in README now shows per-tool breakdown including config guard and config.toml edit guard columns.
- **SECURITY.md** updated with AI Config Bypass Guard section, per-attack-vector protection matrix, and design philosophy statement.
- Existing tests updated with `clean_ai_env()` helper to prevent false failures in Claude Code sessions.

### Important

- **Existing users**: Run `omamori install --hooks` to update hook scripts with new protection patterns.
- **Human users are not affected**: Config changes work as before when run directly in the terminal (no AI env var present).

## [0.3.1] - 2026-03-17

### Added

- **Cursor hooks support**: New `omamori cursor-hook` Rust subcommand for Cursor's `beforeShellExecution` protocol. Uses `serde_json` for safe JSON generation (avoids Cursor's malformed JSON fail-open bug).
- **`install --hooks` generates Cursor snippet**: `.omamori/hooks/cursor-hooks.snippet.json` for manual merge into `.cursor/hooks.json`.
- **find/rsync shim protection**: `find -delete` and `rsync --delete` (8 variants including `--del`, `--delete-before/during/after`, `--delete-excluded`, `--delete-delay`, `--remove-source-files`) are now blocked.
- **Gemini CLI detector**: `GEMINI_CLI=1` (provisional, per agents.md #136).
- **Cline detector**: `CLINE_ACTIVE=true` (provisional, per agents.md #136).
- **Interpreter warnings** (Layer 2 hooks): `python -c "shutil.rmtree(...)"`, `node -e "rmSync(...)"`, `bash -c "rm -rf ..."` patterns are warned on (not blocked). Cursor hook uses `permission: "ask"` for user confirmation.
- **Shared block patterns**: `blocked_command_patterns()` function ensures Claude Code and Cursor hooks use identical block conditions.
- 9 new tests (total: 85). Covers cursor-hook JSON I/O, find/rsync rules, Gemini/Cline detectors, interpreter warnings.

### Changed

- **Install output**: Reorganized into categories (Shims / Hooks / Config / Next steps) for better readability.
- **SHIM_COMMANDS**: Expanded from `[rm, git, chmod]` to `[rm, git, chmod, find, rsync]`.
- **Detector count**: 4 → 6 (added gemini-cli, cline).
- **Policy tests**: 6 → 10 detection tests in `omamori test`.
- **rm path patterns**: Expanded to cover tab and single-quote token boundaries.

### Security

- **Cursor hook JSON safety**: Uses `serde_json` for all JSON generation. stdout is JSON only; logs go to stderr. Addresses Cursor's known malformed-JSON fail-open behavior.
- **Interpreter warning honesty**: Warnings are clearly `exit 0` (not block). SECURITY.md explicitly states that obfuscated interpreter commands cannot be detected.
- **find -exec /bin/rm**: Documented as a structural limitation in SECURITY.md.

### Important

- **Existing users**: Run `omamori install --hooks` to get new shims (find, rsync) and Cursor hook snippet.
- **Cursor users**: Merge `.omamori/hooks/cursor-hooks.snippet.json` into `.cursor/hooks.json` manually.

## [0.3.0] - 2026-03-16

### Added

- **`omamori init` file-write mode**: `init` now writes `config.toml` directly to `~/.config/omamori/` (or `$XDG_CONFIG_HOME/omamori/`) with chmod 600 applied automatically. No more `init > file && chmod 600` dance.
- **`omamori install --hooks` auto-config**: Install now auto-generates `config.toml` if missing, runs policy verification, and displays a `[done]/[todo]` checklist.
- **`omamori config list`**: New subcommand showing all rules with Name, Action, Status, and Source columns. Distinguishes `built-in`, `config (disabled)`, `config (modified)`, and `config` (custom rule).
- **`omamori config disable <rule>`**: Disable a built-in rule from the CLI (no TOML editing needed).
- **`omamori config enable <rule>`**: Re-enable a disabled rule (restores built-in default).
- **`XDG_CONFIG_HOME` support**: Config path respects `$XDG_CONFIG_HOME` with absolute path validation (XDG spec compliance).
- **`libc` dependency**: Added for `O_NOFOLLOW` flag in secure file creation.
- 21 new tests (total: 76). Covers init file-write, symlink rejection, install auto-config, config disable/enable, and warning message format.

### Changed

- **`omamori init` default behavior**: Now writes file directly instead of stdout. Use `--stdout` for the previous behavior. Use `--force` to overwrite existing config.
- **Warning messages**: Improved with 3-layer structure — what happened + current state + what to do (with copy-pasteable fix commands).
- **`install` output**: Changed from flat text to structured `[done]/[skip]/[todo]` checklist format.
- **Exit codes for `init`**: 0=success, 1=error, 2=file exists without `--force`.

### Security

- **Symlink hardening**: `init`, `install`, `config disable/enable` all reject symlinked config files, parent directories, and temp files. Uses `symlink_metadata()` + `O_NOFOLLOW` (double defense).
- **TOCTOU prevention**: New file creation uses `OpenOptions::create_new(true)` for atomic check+create.
- **Atomic writes**: `--force` mode uses temp file → `sync_all()` → rename for crash resilience.
- **Directory permissions**: Config directory created with chmod 700.
- **T4 safety**: `init` output is all-commented TOML — even `init --force` cannot neutralize built-in rules.

### Important

- **Breaking**: `omamori init` now writes a file instead of printing to stdout. Scripts using `omamori init > file` should switch to `omamori init` (direct) or `omamori init --stdout > file`.
- **Existing users**: Run `omamori init` to create `config.toml` if you haven't already. `install --hooks` will auto-create it on next run.

## [0.2.1] - 2026-03-15

### Fixed

- **Codex CLI detection**: Changed env var from `AI_GUARD` to `CODEX_CI` (confirmed via source code, `codex-rs/core/src/unified_exec/process_manager.rs`).
- **Cursor detection**: Changed env var from `AI_GUARD` to `CURSOR_AGENT` (provisional — based on Cursor Forum fix report, Aug 2025; verify with future Cursor releases).
- **Self-interference prevention**: `git_stash()` now derives env_remove list from the active detector config instead of a hardcoded list, preventing recursive shim calls when new detectors are added.
- **Hook script bypass protection**: Added `CODEX_CI`, `CURSOR_AGENT`, and `AI_GUARD` unset-block patterns to the Claude Code hook script.

### Added

- **`ai-guard-fallback` detector**: `AI_GUARD=1` retained as a low-trust fallback for unknown AI tools.
- 2 new policy detection tests (`codex-cli-is-protected`, `cursor-is-protected`) in `omamori test` output.
- 6 new unit tests for detector matching (positive + negative cases).

### Changed

- License changed from MIT to MIT OR Apache-2.0 (dual license, Rust crate convention).
- Detector count increased from 3 to 4 (added `ai-guard-fallback`).
- `SystemOps::new()` now accepts `detector_env_keys` parameter.

### Important

- **Existing users must re-run `omamori install --hooks`** to update the hook script with new bypass protection patterns.
- Detection uses exact `=1` value matching. `CODEX_CI=true` or `CURSOR_AGENT=yes` will not trigger protection.

## [0.2.0] - 2026-03-14

### Added

- **Config merge model**: Built-in default rules are always inherited. User config overrides by rule `name` — write only the rules you want to change.
- **`enabled` flag**: Disable individual rules with `enabled = false`. Defaults to `true` for backward compatibility (`#[serde(default = "default_true")]`).
- **`move-to` action**: Move files to a user-specified directory instead of macOS Trash. Requires `destination` field.
- **`omamori init` command**: Generates a commented TOML config template to stdout.
- **`omamori test` improvements**: Shows rule status table with SKIP for disabled rules, full `match_any` pattern display, and summary line.
- **Destination validation**: Absolute path required, blocked system prefix enforcement (`/usr`, `/etc`, `/System`, `/Library`, `/bin`, `/sbin`, `/var`, `/private`), symlink rejection at config load and runtime, cross-device move rejection.
- **Runtime blocked-prefix re-check**: `move_to_dir()` re-validates via `canonicalize()` to catch paths created after config load (TOCTOU mitigation).
- **Basename collision avoidance**: Dedup suffix (`_2`, `_3`, ...) prevents overwrite when multiple targets share the same filename.
- **MIT LICENSE file**.
- 16 new unit tests (total: 50).

### Changed

- Config file parsing now uses `UserConfig`/`UserRule` structs for partial overrides (all rule fields optional except `name`).
- `BLOCKED_DESTINATION_PREFIXES` is now a public constant shared between `config.rs` and `actions.rs`.
- `omamori test` output format changed from flat PASS/FAIL to structured Rules + Detection + Summary sections.
- `config.default.toml` updated with `enabled` and `move-to` examples.

### Fixed

- Blocked destination paths now **enforce** rule disabling (previously only warned).

## [0.1.1] - 2026-03-13

### Fixed

- **Trash target extraction**: Respect POSIX `--` separator when identifying rm targets. Arguments after `--` are now correctly treated as targets even if they start with `-`.
- **Flag normalization**: Combined short flags like `-rfv` are now expanded to individual flags for rule matching. Only ASCII alphabetic flags are expanded.
- **Hook pattern boundaries**: The Claude Code hook script now uses boundary-aware patterns, preventing false matches on commands like `/bin/rmdir`.
- **Internal git stash isolation**: The `git stash` subprocess strips AI detector env vars (`CLAUDECODE`, `AI_GUARD`) to prevent self-interference when omamori is in the PATH.
- **Signal exit codes**: Processes terminated by signals now return `128 + signal_number` per POSIX convention instead of generic exit code 1.

### Changed

- `RuleMatch` wrapper type removed; `match_rule()` now returns `Option<&RuleConfig>` directly (internal simplification, no API change).
- `ActionOutcome::message()` returns `&str` instead of `String` (internal optimization).
- `render_settings_snippet()` now properly escapes `"` and `\` in file paths for JSON output.

### Added

- `CommandInvocation::target_args()` method for POSIX-correct target extraction.
- `expand_short_flags()` for combined flag normalization.
- `exit_code_from_status()` helper using `ExitStatusExt::signal()` on Unix.
- Quick Start section in README.
- 14 new unit tests covering all v0.1.1 fixes.

## [Unreleased]

### Added

- Round 1 core policy engine for detector, rules, actions, audit, and CLI test flows.
- Round 2 installer and uninstall commands for shim generation.
- Claude Code hook template generation via `omamori install --hooks`.
- Expanded README and SECURITY documentation for protected and unprotected command coverage.

[0.4.1]: https://github.com/yottayoshida/omamori/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/yottayoshida/omamori/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/yottayoshida/omamori/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/yottayoshida/omamori/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/yottayoshida/omamori/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/yottayoshida/omamori/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yottayoshida/omamori/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/yottayoshida/omamori/compare/v0.1.0...v0.1.1
[Unreleased]: https://github.com/yottayoshida/omamori/commits/main
