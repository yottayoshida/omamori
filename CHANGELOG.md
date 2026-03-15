# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

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

[0.2.1]: https://github.com/yottayoshida/omamori/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yottayoshida/omamori/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/yottayoshida/omamori/compare/v0.1.0...v0.1.1
[Unreleased]: https://github.com/yottayoshida/omamori/commits/main
