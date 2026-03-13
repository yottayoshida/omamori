# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

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

[0.1.1]: https://github.com/yottayoshida/omamori/compare/v0.1.0...v0.1.1
[Unreleased]: https://github.com/yottayoshida/omamori/commits/main
