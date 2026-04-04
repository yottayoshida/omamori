# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [0.7.1] - 2026-04-05

### Added

- **`omamori audit verify`** (#29): Verify hash chain integrity of the audit log. Stream processing with `flock_shared` for concurrent safety. Exit codes: 0=intact, 1=broken, 2=error/missing. Legacy entries skipped with warning; legacy-only logs return exit 2 (no chain entries to verify). 3-line recovery guidance on chain break.
- **`omamori audit show`** (#29): View audit log entries with filters. Defaults to `--last 20` (matches `git log` convention). Supports `--all`, `--rule <name>`, `--provider <name>` (substring match), `--json` (full JSONL including chain fields for forensics). Human-readable table: 6 columns (no SEQ, no hashes).
- **`omamori status` Layer 3**: Detection section now shows audit status (entry count + verify prompt). Does not run full verification — avoids false "chain intact" on unverified data.
- **`omamori audit` help**: Running `omamori audit` with no subcommand shows audit-specific usage.

## [0.7.0] - 2026-04-04

### Added

- **Tamper-evident audit log** (#29): Every command decision is recorded in `~/.local/share/omamori/audit.jsonl` with HMAC-SHA256 integrity and hash-chain continuity. File paths are never stored in plaintext.
  - **HMAC-SHA256 target_hash**: Per-install secret (32 bytes, `/dev/urandom`) replaces plain SHA-256. Resists dictionary attacks on low-entropy paths.
  - **Hash chain**: Each entry includes `seq`, `prev_hash`, and `entry_hash`. Modifying or deleting any entry breaks the chain for all subsequent entries.
  - **Concurrent safety**: `flock(2)` advisory lock prevents chain corruption from parallel shim invocations.
  - **Torn line recovery**: Partial writes from crashes are detected and skipped; new entries always start on a clean line.
  - **Self-defense**: `audit.jsonl` and `audit-secret` paths added to `blocked_command_patterns`.

### Changed

- **Audit enabled by default**: `AuditConfig.enabled` now defaults to `true`. Existing users with no `[audit]` section in config.toml will see `audit.jsonl` created automatically. Set `enabled = false` to opt out.
- **`AuditEvent::from_outcome()` removed**: Replaced by `AuditLogger::create_event()`. HMAC secret is encapsulated inside the logger and never exposed via public API.

### Closed

- **#74 Interpreter detection**: NO-GO. [Investigated](https://github.com/yottayoshida/omamori/issues/74): zero real-world incidents in target tools. Full-block approach was disproportionate to the risk.

## [0.6.7] - 2026-04-01

### Changed

- **run_command() lazy init** (#80): Non-protected (non-AI) path now exits early with direct `Command::new()` passthrough. `match_rule`, context evaluation, and `ActionExecutor` are no longer constructed for human terminal commands. Source: Codex quality review S2-1.
- **Config mutation toml_edit** (#81): `config disable/enable` and `override disable/enable` rewritten from string surgery to `toml_edit::DocumentMut` structured editing. Common I/O pattern extracted into `mutate_config()` helper. Preserves comments and formatting. `toml::from_str` failsafe validation retained. Source: Codex quality review S2-2.
- **expand_short_flags O(n)** (#85): Duplicate check changed from `Vec::contains()` O(n²) to `[bool; 52]` lookup table for ASCII letters. Source: Codex quality review S3-1.

### Fixed

- **atomic_write uniqueness** (#82): Temp file names now include an `AtomicU64` sequence counter (`PID-seq` format). `create(true)+truncate(true)` replaced with `create_new(true)` (O_EXCL) for exclusive creation. `O_NOFOLLOW` maintained. Source: Codex quality review S2-3.
- **config.default.toml timeout_ms**: Corrected example value from `3000` to `100` to match code default (`default_timeout_ms()`). Introduced in v0.6.6.

## [0.6.6] - 2026-04-01

### Fixed

- **Cursor hook fail-close** (#75): Malformed JSON, missing/null `command` field now returns `deny` instead of `allow`. Closes a fail-open vulnerability (DREAD 8.6) where invalid input could bypass all protection.
- **Basename normalization** (#76): Commands with path traversal (`/bin/../bin/rm`, `./rm`) are now normalized via `basename()` before rule matching, preventing bypass of protection rules (DREAD 8.0).
- **git clean rule expansion** (#78): `match_any` changed from `["-fd", "-fdx"]` to `["-f", "--force"]`. Split flags (`git clean -f -d`) and long form (`git clean --force`) are now blocked. `context.rs` also uses `expand_short_flags` for consistent evaluation. **Breaking**: `git clean -f` (without `-d`) is now also blocked.
- **cursor_snippet_exe_path** (#59): Improved path extraction using `strip_suffix(" cursor-hook")` for robustness with space-containing paths.
- **regenerate_hooks else branch** (#60): Added warning log when `current_exe()` fails, making hook regeneration failures visible.

### Changed

- **stderr command logging removed** (#79): `cursor-hook` no longer logs the full command string to stderr, preventing potential secret leakage (DREAD 6.8).
- **print_cursor_response fallback** (#75): Serialization fallback JSON changed from `allow` to `deny` (fail-close).
- **expand_short_flags visibility** (#78): Changed from `fn` to `pub(crate) fn` for use in `context.rs`.
- **Test hermetic isolation** (#83): `auto_setup_codex` tests now use `#[serial]` with env var save/restore to prevent cross-test contamination.

### Docs

- **README.md** (#77): Corrected "direct config file editing" to "config modification via shell commands" — Edit/Write tool blocking is not yet implemented.
- **SECURITY.md** (#77): Corrected known limitations table — Edit/Write `file_path` blocking marked as "Not yet implemented (v0.7+)" instead of falsely claiming Claude Code coverage.
- **config.default.toml** (#77): `[context.git]` example updated from `uncommitted_escalation` to `enabled` + `timeout_ms` to match actual schema.

## [0.6.5] - 2026-03-31

### Added

- **20 new tests** (312 → 331): Complete coverage for all P0/P1 security-critical paths from issue #69.
  - `unwrap` fail-close limits (4): `TooManyTokens` (>1000) and `TooManySegments` (>20) boundary tests — previously 0 tests for these fail-close guards.
  - `IntegrityReport::exit_code` (4): direct tests for Fail=1, Warn=2, Ok=0, and Fail-takes-precedence-over-Warn.
  - `check_path_order` (4): all 4 branches — shim before/after /usr/bin, shim missing, /usr/bin missing.
  - `evaluate_git_context` git clean (2): `-fd`/`-fdx` untracked file detection (present → keep action, absent → LogOnly).
  - `evaluate_git_context` GIT_WORK_TREE spoofing (1): env var sanitization defense (complements existing GIT_DIR test).
  - `run_shim` integration smoke (1): end-to-end shim path via HOME-based DI + symlink invocation.
  - `AuditLogger` (3): `from_config` default path, `from_outcome` all-fields verification, JSONL special character integrity.

## [0.6.4] - 2026-03-31

### Fixed

- **`move_to_dir` canonicalize fail-close** (#69): Two-stage path resolution for blocked prefix check. Previously, `canonicalize()` failure silently skipped the check, allowing symlink-based bypass to system paths. Now uses dest-first canonicalize with parent fallback; any failure is rejected (fail-close).

### Changed

- **`ensure_hooks_current_at` testability**: Extracted `ensure_hooks_current_at(base_dir)` from `ensure_hooks_current()` for dependency injection in tests. No behavior change.
- README: Added sandbox complementarity section explaining omamori (semantic layer) vs. filesystem sandbox (OS boundary) and their defense-in-depth relationship.

### Added

- **39 new tests** (273 → 312): Comprehensive coverage for 8 previously untested gaps identified via QA Report-Only mapping, plus 1 adversarial scenario.
  - `evaluate_git_context` (7): real git repos, GIT_DIR spoof defense (T4), timeout fail-close.
  - `ensure_hooks_current_at` (5): version mismatch, T2 hash tampering, read-only dir failure.
  - `should_block_for_sudo` (1): non-root negative path.
  - `SystemOps::move_to_dir` (10+1 ignored): real FS operations — symlink rejection, blocked prefix, basename dedup, canonicalize fail-close, EXDEV.
  - `write_default_config` (4): permissions 600/700, symlink rejection, atomic write, no-force guard.
  - `load_config` (2): insecure/secure permission handling.
  - `AuditLogger` (4): from_config enable/disable, JSONL append integrity, I/O error path.
  - `write_baseline` (3): symlink rejection, atomic update, O_NOFOLLOW.
  - `auto_setup_codex_if_needed` (2): env-absent skip, wrapper-exists skip.
  - Adversarial: hooks symlink attack → hash mismatch detection and regeneration (ADV-01).
- `serial_test` v3 dev-dependency for CWD-sensitive git context tests.

## [0.6.3] - 2026-03-30

### Added

- **Codex CLI hook support** (#66): Full Tier 1 support for OpenAI Codex CLI (v0.117.0+) PreToolUse hooks.
  - **hooks.json auto-merge**: `omamori install --hooks` auto-detects `~/.codex/` and merges omamori's PreToolUse entry into `~/.codex/hooks.json`. Existing entries (UserPromptSubmit, etc.) are preserved.
  - **config.toml auto-write**: Sets `[features] codex_hooks = true` using `toml_edit` (preserves comments and formatting). Explicit `false` is respected (user intent).
  - **fail-close wrapper**: Codex CLI treats exit 1 as ALLOW (fail-open), unlike Claude Code which blocks on any non-zero exit. The wrapper script converts all non-zero exits to exit 2 for fail-close safety.
  - **shim auto-setup**: When `CODEX_CI` env is detected but the Codex wrapper doesn't exist, omamori auto-configures hooks on the first shim invocation. Users who install Codex after omamori get automatic protection.
  - **self-defense**: `blocked_command_patterns` now protects `.codex/hooks.json`, `.codex/config.toml`, `config.toml.bak`, and the `codex_hooks` feature flag from AI agent tampering.
  - **symlink checks**: Refuses to read/write hooks.json and config.toml if they are symlinks (consistent with existing O_NOFOLLOW pattern).
  - `omamori status` Layer 2 coverage now shows "Claude Code + Codex CLI + Cursor".
  - Codex wrapper included in integrity baseline.
  - `toml_edit` v0.22 dependency added.
  - 20 new tests (273 total).

## [0.6.2] - 2026-03-25

### Added

- **Claude Code Auto mode compatibility** (#62): `hook-check` now returns `hookSpecificOutput` JSON with `permissionDecision: "allow"` on stdout when a command is allowed. This follows the Claude Code hook protocol, ensuring omamori explicitly signals permission decisions rather than relying on implicit behavior (exit 0 + empty stdout).

### Unchanged

- **BLOCK path**: Exit code 2 + stderr message behavior is completely unchanged. `permissionDecision` JSON is only emitted on ALLOW — BLOCK uses exit code 2 which overrides all Claude Code permission rules.

## [0.6.1] - 2026-03-23

### Fixed

- **Cursor hook Cellar path resolution** (#56): `render_cursor_hooks_snippet()` and `regenerate_hooks()` now use `resolve_stable_exe_path()` to convert versioned Homebrew Cellar paths to stable symlink paths. Previously, `brew upgrade` + `brew cleanup` would silently break Cursor Layer 2 protection.
- **`omamori install` Cellar path**: `run_install_command()` now resolves the stable path before passing to `InstallOptions`.
- **`generate_baseline()` Cellar path**: Baseline `omamori_exe` field now records the stable path instead of the versioned Cellar path.

### Security

- **Cursor snippet integrity check** (T8): Upgraded from existence-only to SHA-256 hash comparison + dangling path detection. `omamori status` now reports FAIL on tampered snippets and WARN on dangling executable paths.
- **`atomic_write` O_NOFOLLOW** (T7): Temp file creation now uses `O_NOFOLLOW` to prevent symlink-following attacks on the predictable temp path, symmetric with `integrity.rs::write_new_file()`.

### Changed

- README: Clarified that Cursor hooks require manual re-merge after `brew upgrade`, unlike Claude Code hooks which auto-sync.

## [0.6.0] - 2026-03-22

### Added

- **Recursive Unwrap Stack** (#30): Token-aware command parser for Layer 2 hooks. Recursively strips shell wrappers (sudo, env, nohup, timeout, nice, exec, command) and extracts inner commands from shell launchers (bash/sh/zsh/dash/ksh -c) for rule matching.
  - **`omamori hook-check`**: New subcommand — unified hook detection engine. Reads stdin, runs 2-phase check (meta-patterns → unwrap stack → rule match), exits 0 (allow) or 2 (block).
  - **Compound command splitting**: `echo ok && rm -rf /` — each segment checked independently. Quote-aware pre-normalization handles `a&&b` (no spaces).
  - **Pipe-to-shell detection**: `curl url | bash` — unconditionally blocked.
  - **Process substitution**: `bash <(...)` — blocked.
  - **Dynamic generation**: `bash -c "$(cmd)"` — blocked (fail-close).
  - **Full-path shell recognition**: `/usr/local/bin/bash -c` detected via basename matching.
  - **Combined flag support**: `bash -lc` recognized as `-c` variant.
  - **env special handling**: `env NODE_ENV=production npm start` correctly parsed (KEY=VAL skipped).
  - **Fail-close limits**: depth > 5, tokens > 1000, segments > 20, input > 1MB, parse error — all BLOCK.
  - `shell-words` v1.1 dependency added (zero-dep, POSIX-compliant tokenizer).
  - 70 new unit tests for unwrap stack.
- **AuditEvent extension**: `detection_layer`, `unwrap_chain`, `raw_input_hash` fields added for #29 compatibility.

### Changed

- **Claude Code hook script**: Converted from 60-line shell `case` statement to 5-line thin wrapper delegating to `omamori hook-check`. All detection logic now in Rust.
- **Cursor hook**: Refactored to use shared `check_command_for_hook()` pipeline. Same detection for both providers.
- **`bash -c "rm -rf /"` is now BLOCKED** (was warn-only exit 0). The unwrap stack extracts `rm -rf /` and matches it against rules.
- **`sudo env bash -c "rm -rf /"` is now BLOCKED** (was pass-through). Wrappers are recursively stripped.

### Removed

- **Python/Node interpreter warn patterns**: `shutil.rmtree`, `rmSync`, etc. were previously warn-only (exit 0, "ask" permission) — effectively security theater since the command still executed. Removed in favor of future interpreter-aware unwrap.

### Security

- **Unified pipeline**: Claude Code and Cursor now share identical detection logic. No more dual-implementation sync risk.
- **Exit code contract**: 0 = allow, 2 = block, non-zero = fail-close.
- **T2 attack test updated**: Simulates replacing `omamori hook-check` with `true` in thin wrapper (previously simulated `exit 2` → `exit 0`).

## [0.5.0] - 2026-03-21

### Added

- **Integrity monitoring** (#28): Two-tier defense layer verification that detects tampering of omamori's own infrastructure.
  - **Canary check** (every shim invocation): `stat` + `readlink` (~0.05ms) verifies `.integrity.json` exists and shim symlink points to omamori binary.
  - **Full check** (`omamori status`): Verifies all shims, hook content hash, config permissions, core policy state, PATH order, and baseline integrity.
  - **`.integrity.json` baseline**: SHA-256 hashes of hooks and config, shim symlink targets, stored with chmod 600 + O_NOFOLLOW + atomic write.
  - **Auto-update**: Baseline refreshes after hook regen, config changes, install, and init. No false positives from legitimate operations.
  - **v0.4 migration**: First shim invocation auto-generates baseline with stderr info message.
- **`omamori status [--refresh]`**: Health check subcommand with grouped output (Shims / Hooks / Config / Core Policy / PATH / Baseline). Exit codes: 0=healthy, 1=FAIL, 2=WARN. `--refresh` regenerates baseline from current state.
- **Core policy immutability** (#48): 7 built-in safety rules cannot be disabled or weakened via `config.toml`. All fields except `message` are enforced. `config disable` on a core rule returns an error with guidance.
  - **`omamori override disable/enable <rule>`**: Explicit override mechanism for legitimate use cases (CI, solo dev). Blocked by AI guard + hooks.
  - **`[overrides]` section** in config.toml for persistent overrides.
  - **`config list`** now shows `core` vs `config` source and `(overridden)` status.
  - **`omamori test`** now includes Core Policy section.
- **Hook content hash verification** (#49, T2 fix, DREAD 9.0): `ensure_hooks_current()` now compares SHA-256 of `render_hook_script()` output against the actual file — detects AI attacks that keep the version comment but rewrite hook body (e.g. `exit 2` → `exit 0`).
- **Self-defense**: `.integrity.json` protected by hook block list (Claude Code + Cursor) and `blocked_command_patterns()`. `omamori override` blocked by hooks.
- 29 new tests (total: 160). Covers integrity canary, status output, baseline roundtrip, install baseline generation, hook block patterns, core policy immutability, override mechanism.

### Changed

- `SHIM_COMMANDS` visibility changed from `const` to `pub const` (needed by integrity module).
- `render_hook_script()`, `hook_content_hash()`, `parse_hook_version()` visibility changed from `pub(crate)` to `pub`.
- `ensure_hooks_current()` now returns `bool` indicating whether hooks were regenerated.
- `uninstall` now removes `.integrity.json`.

### Security

- **Implementation-derived hash**: Hook integrity uses `render_hook_script()` output as source of truth, not stored baseline. Eliminates baseline tampering as an attack vector for hook verification.
- **Trusted transitions only**: Baseline auto-updates restricted to omamori-initiated operations (install, hook regen, config CLI commands). External edits produce WARN, not auto-update.
- **TOCTOU**: Canary checks point-in-time state. Tampering between checks is not detected until the next invocation. Accepted structural limitation of no-daemon design.

### Important

- **Existing users**: Run `omamori install --hooks` to generate `.integrity.json` baseline and update hooks with new block patterns. Or simply use any shim command — baseline auto-generates on first invocation.
- **Core rules can no longer be disabled via config**: Use `omamori override disable <rule>` for legitimate overrides. AI agents cannot use this command.

## [0.4.2] - 2026-03-19

### Fixed

- **Shim symlinks survive `brew upgrade`** (#42): Shim symlinks now point to the stable Homebrew-linked path (e.g. `/opt/homebrew/bin/omamori`) instead of the versioned Cellar path. Previously, `brew upgrade` + `brew cleanup` caused dangling symlinks, silently disabling all protection until `install --hooks` was re-run.

### Changed

- **README redesigned**: Restructured for first-time visitors — tagline, Quick Start, and "What It Blocks" now appear before detailed configuration. Detection tables and version-specific notes moved to later sections.

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

[0.5.0]: https://github.com/yottayoshida/omamori/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/yottayoshida/omamori/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/yottayoshida/omamori/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/yottayoshida/omamori/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/yottayoshida/omamori/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/yottayoshida/omamori/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/yottayoshida/omamori/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/yottayoshida/omamori/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yottayoshida/omamori/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/yottayoshida/omamori/compare/v0.1.0...v0.1.1
[Unreleased]: https://github.com/yottayoshida/omamori/commits/main
