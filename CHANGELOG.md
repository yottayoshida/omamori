# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [0.9.7] - 2026-04-30

**Summary**: HMAC tamper-evident audit chain moat completion + `install --hooks` automation. Three structural closures tightened against silent gaps the v0.9.6 ship surfaced: (1) Layer 2 hook deny verdicts (`BlockMeta` / `BlockRule` / `BlockStructural`) now append to the HMAC audit chain — the marketed tamper-evident moat covered Layer 1 (PATH shim) end-to-end but had a structural gap at Layer 2 ([#181](https://github.com/yottayoshida/omamori/issues/181)); (2) `omamori install --hooks` automatically merges into `~/.claude/settings.json` instead of printing a `[todo]` snippet, with omamori-managed legacy-matcher entries auto-migrated and user-managed entries preserved verbatim ([#196](https://github.com/yottayoshida/omamori/issues/196)); (3) `omamori doctor` parses settings.json and verifies the omamori-managed entry's matcher syntax + script_path SHA-256, so doctor green now structurally implies Layer 2 active. Plus shim auto-sync extension (`ensure_settings_current()` parallels `ensure_hooks_current()`) so brew upgrade does not leave stale config behind, doc / test polish (#190, #194, #187), and a new SECURITY.md `## Known Operational Caveats` section documenting the meta-pattern false-positive surface that omamori's own development surfaces (commit messages, grep arguments, AI-review prompts that quote protected paths).

### Added

- **`omamori install --hooks` auto-merges `~/.claude/settings.json`** ([#196](https://github.com/yottayoshida/omamori/issues/196)). The previous `[todo]` snippet output asking the user to manually copy a JSON block is replaced by an in-place merge with `.bak` backup. New `merge_claude_settings()` mirrors the v0.9.5 `merge_codex_hooks` pattern but is a separate helper for Claude Code spec / atomic 0o600 write / 5-variant outcome enum (`Created` / `Merged` / `AlreadyPresent` / `MatcherMigrated` / `Skipped(reason)`).
- **Q2=c partial matcher migration**. omamori-managed Claude Code settings.json entries (identified by `command` field `~/.omamori/` prefix) carrying the legacy boolean matcher (`"tool == \"Bash\""`) are auto-migrated to the current spec simple string `"Bash"`. User-managed entries with legacy matchers receive a warning only — the principle "user config is not auto-edited" is preserved.
- **`ensure_settings_current()` shim auto-sync**. Mirrors `ensure_hooks_current()`: every shim invocation does a fast version check on `~/.claude/settings.json`, and if the omamori-managed entry's matcher / script_path drifted (e.g. after `brew upgrade`), the entry is auto-refreshed. Adds <0.1ms per invocation in the steady state.
- **`omamori doctor` settings.json verification**. New `check_claude_settings_integration` parses `~/.claude/settings.json`, locates the omamori-managed entry by command-path prefix, and verifies matcher syntax (current `"Bash"` form) plus `script_path` SHA-256 matches the installed hook script. Doctor green now structurally implies Layer 2 active.
- **DI-9 behavioral pins** ([#187](https://github.com/yottayoshida/omamori/issues/187) item 2). Two new entries in `tests/hook_integration.rs::HOOK_DECISION_CASES` covering `omamori doctor --fix` and `omamori explain` — the two `blocked_string_patterns()` entries that previously lacked behavioral coverage. PR4's "every blocked_string_patterns() entry should have at least one behavioral fixture" thesis applies universally.
- **Per-category floor map** ([#187](https://github.com/yottayoshida/omamori/issues/187) item 1). New `META_PATTERN_CATEGORY_FLOORS` const (12 prefixes / sum 23) catches category-selective drop that the global ≥18 floor misses. Defense-in-depth alongside the global floor; each prefix anchors with trailing `-` to prevent sub-prefix collision (`bin-rm-` vs `bin-rmdir-`).
- **Three new chain tamper class tests** ([#187](https://github.com/yottayoshida/omamori/issues/187) item 4). `chain_tamper_reorder_detected`, `chain_tamper_middle_deletion_detected`, `chain_tamper_genesis_rewrite_detected` — each pinning the raw on-disk signal (golden hash divergence) AND `verify::verify_chain` detector E2E (`broken_at.is_some()`) against `GOLDEN_ENTRY_HASHES` / `GOLDEN_GENESIS`. Lib tests 655 → 658.
- **`SECURITY.md ## Known Operational Caveats`** (new top-level section). Documents the Layer 2 meta-pattern substring-match false-positives that surface in developer workflows: commit messages, grep arguments, AI-review prompts that quote protected paths. Records four workarounds (`git commit -F`, contiguous-string splitting on the Bash command line, AI-tool file-edit interfaces, Codex MCP channel). Documented so operators reading omamori's own commit history understand that an occasional false-positive block during development is *evidence the layer is working*, not a regression.

### Changed

- **Layer 2 hook deny path appends to the HMAC audit chain** ([#181](https://github.com/yottayoshida/omamori/issues/181) B-1). Pre-v0.9.7, deny verdicts at `claude-pretooluse.sh` (`BlockMeta` / `BlockRule` / `BlockStructural`) wrote to stderr only and were absent from `audit.jsonl`. Every deny verdict now appends an audit event with `action = "block"`, `result = "block"`, before stderr emission. Best-effort with respect to the decision: an append failure surfaces a stderr warning but does not flip the block (fail-close on safety, fail-open on observability — mirrors the v0.9.6 PR6 `unknown_tool_fail_open` pattern).
- **`detection_layer` taxonomy extended for Layer 2** ([#181](https://github.com/yottayoshida/omamori/issues/181) C-1). Layer 2 deny events now carry one of: `"layer2:meta-pattern"` (string-level), `"layer2:rule"` (token-level rule match), `"layer2:pipe-to-shell:{wrapper}"` (transparent-wrapper pipe-to-shell, where `{wrapper}` is the basename from `unwrap::TRANSPARENT_WRAPPERS` — `env`, `sudo`, `timeout`, `nice`, `nohup`, `command`, `exec`, `doas`, `pkexec`), or `"layer2:structural"` (parse error / depth / dynamic generation / bare-shell pipe RHS). CHAIN_VERSION remains `1` — these are new string values for the existing field, following the v0.9.6 PR6 `"shape-routing"` precedent.
- **`audit show` table widened for PR6 / PR2 / PR3 event-class strings** ([#190](https://github.com/yottayoshida/omamori/issues/190) B-2). COMMAND column `{:<8}` → `{:<24}`, ACTION column `{:<15}` → `{:<24}`. PR6 reused these columns to carry tool_name (e.g. `FuturePlanWriter`) and `unknown_tool_fail_open` (22 chars) which overflowed the legacy widths; v0.9.7 deny-path additions similarly carry `block` plus `detection_layer` strings up to ~24 chars. No schema break, no field-semantics change. Regression test `show_pr6_unknown_tool_fail_open_keeps_columns_aligned` pins byte positions.

### Security

- **Block-reason stderr text invariant maintained**. Wrapper kind (in `detection_layer`) flows into the audit log only — stderr text stays the v0.9.5 fixed string (`"pipe to shell interpreter"` for all pipe-to-shell variants regardless of wrapper). The two channels are deliberately separated: an AI agent observing only stderr cannot iterate on wrapper variants while a forensic operator reading the audit log gets full attribution including the specific wrapper basename.
- **`PROTECTED_FILE_PATTERNS` covers `~/.claude/settings.json`** in 4 forms (absolute / `~` / `$HOME` / symlink) plus broken-parent canonicalize fallback. The `is_protected_file_path` guard now blocks AI Edit / Write / MultiEdit operations on the file in all canonical forms — the auto-merge install path writes settings.json via a separate non-AI-tool code path that does not cross `is_protected_file_path`.
- **`merge_claude_settings()` atomic write at explicit 0o600**. Settings.json is written via `tmpfile + rename` with explicit `0o600` mode independent of process umask, so a permissive umask cannot widen settings.json file permissions.
- **`merge_claude_settings()` parse-error fail-close**. If `~/.claude/settings.json` exists but does not parse as JSON (corrupted / partial / non-JSON content), the merge aborts with a clear error rather than overwriting — the user keeps their existing file unmodified.
- **`SECURITY.md ### Audit Log Read Access (v0.9.7+)`** ([#190](https://github.com/yottayoshida/omamori/issues/190) B-3). New subsection under Audit Log → Defense Boundary. `audit.jsonl` is `chmod 644` (user-readable) by design; HMAC integrity protects against forgery and tampering, not against read access. Operators who treat AI tool usage itself as confidential are pointed at dedicated OS users / encrypted volumes keyed outside the home directory.
- **SECURITY.md doctor 30-day clock-skew caveat** ([#190](https://github.com/yottayoshida/omamori/issues/190) B-4). New paragraph in "Scope: unknown / new tools" plus matching doc-comment on `src/cli/doctor.rs::print_unknown_tool_fail_open_summary`. Treat the count as a drift indicator, not a forensic counter — significant NTP rewinds skew the cutoff window.

### For users

- No installation change required. `omamori install --hooks` is now genuinely automatic for Claude Code settings.json — the `[todo]` line in the previous output is gone. `brew upgrade omamori` followed by any shim invocation auto-syncs both hooks and settings.json — no manual steps required.
- macOS-only. v0.9.7 introduces no platform expansion.
- Existing `audit.jsonl` continues to verify against the same hash chain; `CHAIN_VERSION` is unchanged. `omamori audit verify` should pass after upgrading. Layer 2 deny events from v0.9.7 onwards are interleaved with the existing Layer 1 events in the same chain.
- SIEM / downstream tooling: filter on `detection_layer` values starting with `"layer2:"` for full Layer 2 coverage. `detection_layer == "layer1"`-only filters silently exclude the new Layer 2 deny events.

### For contributors (CI)

- **Invariant #10** (`scripts/check-invariants.sh`, [#190](https://github.com/yottayoshida/omamori/issues/190) B-1). Pins existence of three v0.9.6 PR6 routing symbols in `src/engine/hook.rs`: `enum InputShape`, `fn classify_input_shape(`, `fn has_routing_field_with_wrong_type(`. Catches silent rename of the routing identity that would un-do v0.9.6's forward-compat fail-open closure.
- **Invariants #6f / #6g / #6h** ([#187](https://github.com/yottayoshida/omamori/issues/187) item 3 + Codex Round 1 P1). #6f pins `fn corpus_includes_meta_pattern_coverage` existence (the floor function itself is subject to silent drop). #6g pins `meta_pattern_count >= (18..23)` literal range. #6h pins `META_PATTERN_CATEGORY_FLOORS` const + iteration so the per-category guard cannot be silently removed leaving the global floor as the only protection.
- **Dependabot cargo ecosystem disabled** ([#202](https://github.com/yottayoshida/omamori/pull/202)). Cargo dependency updates are now manual via `cargo update`; the github-actions ecosystem (security-relevant) remains on monthly patch-only schedule per the v0.9.4 narrow config audit.

### Docs

- **ACCEPTANCE_TEST.md S-2 / S-6 §前提 / A-1 fixes** ([#194](https://github.com/yottayoshida/omamori/issues/194)). S-2 target changed from `/tmp/nonexistent` (trash-redirect on the `rm-recursive-to-trash` rule, exit 1) to `/etc/fstab` (system-owned, trash move EPERMs, fail-close → true deny). S-6 §前提 expanded with "Claude Code 安全層との precedence" warning + shim PATH-precedence verification (`which rm` should resolve to `~/.omamori/shim/rm`); the existing trailer "Layer 1 (S-*) は AI env 非依存" was corrected since shim's non-protected fast path passes through real `rm` (`src/engine/shim.rs:313`) — `CLAUDECODE=1` is required for every S-*/H-*/T-*/A-* row, not just Layer 2 / Tamper / Doctor / Audit. A-1 changed from `omamori audit` (help-only output) to `omamori audit show --rule rm-recursive-to-trash --last 5` with action-vs-result column semantics noted inline.
- **README**: no v0.9.7-specific narrative restructure (PR3 already updated the install --hooks line "applied automatically. No action needed." to be structurally true via the new merge logic).

### Migration notes

- `audit.jsonl` schema: `detection_layer` may now contain values starting with `"layer2:"` in addition to the existing `"layer1"` and `"shape-routing"`. SIEM pipelines that filter on `detection_layer == "layer1"` will silently exclude the new Layer 2 deny events; pipelines wanting full Layer 2 coverage should match values starting with `"layer2:"`.
- `~/.claude/settings.json`: v0.9.7's `omamori install --hooks` will auto-merge an omamori entry into the file (or refresh an existing legacy-matcher omamori entry). User-authored entries are preserved verbatim; the merge is content-additive only. A `.bak` is written before the merge.
- No config-file changes required. `omamori audit verify` continues to validate both pre-v0.9.7 and post-v0.9.7 entries against the same chain.

### Known limitations (carried into a future release)

- Unknown / forward-compat `tool_input` shape catalogue is intentionally narrow. Several known-good Claude Code tools (`NotebookEdit`, `Task`, `TodoWrite`, `WebSearch`) still land in the `unknown_tool_fail_open` branch. The 30-day count surfaced by `omamori doctor` is an upper bound on adversarial activity, not a lower bound — treat as a drift indicator. SECURITY.md "Scope: unknown / new tools" carries the full trade-off.
- Layer 2 meta-pattern false-positive on developer workflows (new in v0.9.7 SECURITY.md `## Known Operational Caveats`). Substring-match against the full Bash command string blocks legitimate workflows that *describe* protected configuration without modifying it (commit messages mentioning `audit.jsonl`, grep arguments containing `~/.claude/settings.json`, AI-review prompts that quote protected paths). Workarounds: `git commit -F`, contiguous-string splitting, AI-tool file-edit interfaces, Codex MCP. This is a known trade-off, not a bug.
- Static shell-word analysis cannot reach: obfuscated commands (base64, hex, variable expansion), runtime-constructed commands (`python -c`, `node -e`), heredoc content, alias / function overrides, redirection-dup stdin aliases (`source /dev/fd/N N<&0`). See SECURITY.md → Known Limitations section C.
- macOS-only. Linux / Windows are not supported in this release.

### PRs

- [#202](https://github.com/yottayoshida/omamori/pull/202) — `chore(deps): disable dependabot cargo ecosystem`. Cargo dependency updates are now manual; github-actions ecosystem narrow-config preserved per the v0.9.4 audit.
- [#204](https://github.com/yottayoshida/omamori/pull/204) — `feat(audit): Layer 2 hook deny audit append + wrapper-kind detection_layer`. Closes [#181](https://github.com/yottayoshida/omamori/issues/181) B-1 + C-1. Codex R1 → R5 all-legitimate Bug-fact (5 rounds, zero vacuous), exposed `feedback_phase2_shape_enumeration` discipline (root cause of the round inflation: failing to enumerate data shapes during Phase 2 detailed design).
- [#205](https://github.com/yottayoshida/omamori/pull/205) — `feat(install): auto-merge Claude Code settings.json + doctor verify + shim auto-sync`. Closes [#196](https://github.com/yottayoshida/omamori/issues/196). Codex R1 → R5 with subagent QA skip + 2 deferred items, merge GO confirmed by yotta. SECURITY.md `### Audit Log Read Access` placed under Defense Boundary (semantic precision over issue's suggested location).
- [#207](https://github.com/yottayoshida/omamori/pull/207) — `docs+ci: close #190 + #194 (doc cluster)`. Closes [#190](https://github.com/yottayoshida/omamori/issues/190) (4 P3 follow-ups) + [#194](https://github.com/yottayoshida/omamori/issues/194) (3 ACCEPTANCE_TEST.md doc fixes) + plan-driven SECURITY.md `## Known Operational Caveats` addition. Codex R1=Block (6 Bug-fact, including a P0 catching dangerous `unset CLAUDECODE` advice in §前提 that would have made S-1 / S-6 / T-1 actually delete `/`) → R2=Approve natural stop.
- [#208](https://github.com/yottayoshida/omamori/pull/208) — `test+ci: close #187 (test-strengthening cluster)`. Closes [#187](https://github.com/yottayoshida/omamori/issues/187) (4 P3 test-quality). Codex R1=Block (3 Bug-fact, including a P0 catching tamper tests' false confidence — they verified the raw signal but never invoked `verify_chain`, the actual detector) → R2=Approve natural stop. Lib tests 655 → 658 (+3 chain tamper class tests with `verify_chain` detector E2E pin).

## [0.9.6] - 2026-04-26

**Summary**: Shell-Layer Hardening Phase 2 ([#146](https://github.com/yottayoshida/omamori/issues/146) P2) + structure-based unknown-tool routing ([#182](https://github.com/yottayoshida/omamori/issues/182)) + observable fail-open with `audit unknown` / `doctor` 30-day line. Closes the v0.9.5-deferred `env -S 'bash -e'` / `bash -c 'source /dev/stdin'` pipe-RHS gaps, the net-new-in-v0.9.6 `doas` / `pkexec` privilege-escalation wrapper closure (PR2 scope 7), and the newly-identified `HookInput::UnknownTool` short-circuit-allow (Codex adversarial-review ② A-2, #182) that bypassed the full pipeline on any tool name omamori did not recognise. Cross-layer Layer 1 → Layer 2 implication pinned via 256-case `proptest` (#146 P1-4); the v0.9.5 Ubuntu CI quarantine ([#164](https://github.com/yottayoshida/omamori/issues/164)) is resolved structurally via [#183](https://github.com/yottayoshida/omamori/pull/183); README and SECURITY restructured for navigation. Runtime behavior is otherwise unchanged — omamori remains macOS-only.

### Added

- **`omamori audit unknown`** subcommand. Surfaces every `unknown_tool_fail_open` event in the audit log, paginated like `audit show` (`--last N`, `--json`); defaults to `--all` so review is complete by default. This is the user-facing review endpoint paired with the on-call stderr hint emitted at every unknown-shape invocation — an answer to "review what?".
- **`omamori audit show --action <name>`**. Generic exact-match filter on the `action` field; `audit unknown` is sugar over this.
- **`omamori doctor` "Last 30 days" line**. When the audit log carries any `unknown_tool_fail_open` events from the last 30 days, doctor surfaces the count and points at `omamori audit unknown`. Skipped when zero so doctor stays quiet on healthy installs.

### Changed

- **Unknown / forward-compat tools now route by `tool_input` shape, not `tool_name`** ([#182](https://github.com/yottayoshida/omamori/issues/182)). The previous `HookInput::UnknownTool` branch unconditionally allowed any tool whose name omamori did not recognise — meaning a provider-side rename (Claude Code → Cursor → Codex → next-week's CLI) of a write or exec tool would silently bypass Layer 2 protection. The hook now inspects `tool_input` field structure independently of the tool name: a `command`/`cmd` string routes through the full Bash pipeline; a `file_path`/`path` string routes through FileOp / protected-path checks; a `url` string is treated as read-only (allowed); anything else falls through to an *observable* fail-open. Wrong-type routing fields (e.g. `command: 42`) now fail closed rather than dropping into the unknown branch.
- **Observable fail-open for genuinely unknown shapes**. When a tool's `tool_input` matches none of the recognised shapes, omamori still allows the call (we keep user workflow alive rather than starting to block unreviewed tools retroactively), but the silence is gone: stderr now carries a one-line hint pointing at the new review surface, and an `unknown_tool_fail_open` event is appended to the audit chain. The `tool_input` payload structure (number of recognised top-level keys) is recorded so an analyst can see at a glance whether the tool sent zero fields, one field, or many. No `CHAIN_VERSION` bump — this introduces new values for the existing `action` field (`"unknown_tool_fail_open"`) and `detection_layer` field (`"shape-routing"`); parsers that don't recognise the values treat them as opaque.

### Security

- **Pipe-RHS bypass closures (Shell-Layer Hardening Phase 2)** ([#184](https://github.com/yottayoshida/omamori/pull/184), #146 P2). Three additional pipe-to-shell evasion surfaces blocked: `curl URL | env -S 'bash -e'` split-string form (PR2 scope 5, coarse-rule closure regardless of STRING contents), `curl URL | bash -c 'source /dev/stdin'` shell-launcher form with inner `source` / `.` (POSIX dot) builtin reading `/dev/stdin` / `/dev/fd/0` / `/proc/self/fd/0` (PR2 scope 6, layered on the v0.9.5 coarse pipe-RHS rule), and `curl URL | doas bash` / `curl URL | pkexec bash` privilege-escalation wrappers (PR2 scope 7). Legitimate use cases stay Allow (`env -S` shebang lines, `bash -c 'source /dev/stdin' < file` non-pipe redirect, `doas -u user <non-shell-cmd>` FP-pinned). See SECURITY.md → Known Limitations table A and `tests/hook_integration.rs` corpus entries `pipe-wrapper-evasion-env-dash-s-block` / `pipe-launcher-source-stdin-block` / `pipe-wrapper-evasion-doas-block` / `pipe-wrapper-evasion-pkexec-block`.
- **Forward-compat fail-open closed** ([#182](https://github.com/yottayoshida/omamori/issues/182), Codex adversarial-review ② A-2 critical). Before this change, a hostile or merely renamed tool could carry a payload like `{"tool_name":"FuturePlanWriter","tool_input":{"command":"/bin/rm -rf /"}}` and the entire shell pipeline (meta-pattern detection, env-tampering checks, unwrap stack) would never run because `HookInput::UnknownTool` short-circuited to allow. Equivalent payloads now Block at exit code 2.

### For users

- No config or installation change. macOS-only.
- **Protection guarantee is unchanged**: any payload carrying a recognised dangerous shape (`command`/`cmd`/`file_path`/`path`) still routes through the full pipeline regardless of `tool_name`. The new `unknown_tool_fail_open` events are observability noise on legitimate tools whose `tool_input` shape is not yet in the catalogue, not a regression in protection.
- Existing audit logs continue to verify against the same hash chain; `CHAIN_VERSION` is unchanged. `omamori audit verify` should pass after upgrading.
- If you have downstream tooling parsing audit JSON: **filter on `action == "unknown_tool_fail_open"` first** to isolate these events from your existing aggregations. Within those events, `result` is `"allow"`, `detection_layer` is `"shape-routing"`, and `command` / `target_count` are borrowed columns (carrying `tool_name` and `tool_input` top-level key count respectively); aggregations across action types over either column will be skewed. Dedicated columns are tracked for a future omamori release.

### For contributors (CI)

- **Ubuntu CI quarantine resolved structurally** ([#183](https://github.com/yottayoshida/omamori/pull/183), closes #164): The v0.9.5 `#[serial_test::serial]` quarantine on `context::tests::multi_target_*` is now resolved by threading an explicit base directory through `normalize_path` via new `pub(crate)` helpers (`normalize_path_with_base` / `resolve_path_with_base` / `evaluate_context_with_base`). Context tests no longer depend on process-wide CWD; Ubuntu `Test` CI no longer needs serial-test annotations on these paths.
- **Structural test quality migration** ([#186](https://github.com/yottayoshida/omamori/pull/186), refs #146 scope 4): 4 structural array-shape tests (`meta_patterns_cover_*`) migrated from internal-array assertions into the `tests/hook_integration.rs` E2E corpus where they pin observable Block / Allow behavior. Audit chain hash tests are now pinned against golden hex vectors instead of self-verifying helpers, eliminating the `(if helper passes) ⟹ (test passes)` tautology.

### Docs

- **README philosophy flip** ([#191](https://github.com/yottayoshida/omamori/pull/191)): the philosophy block is surfaced before Quick Start so first-time readers see the *why* before the *how*.
- **README H2 hierarchy compressed from 13 to 9** ([#192](https://github.com/yottayoshida/omamori/pull/192)): Quick Start purified, tool compatibility consolidated, a Real-world Effect section added, and Scope and Limitations merged. First-time-reader navigation cost is reduced without losing detail.
- **`SECURITY.md` "How to read this document" navigation table** ([#192](https://github.com/yottayoshida/omamori/pull/192)): a role-based reading-order table at the top of the file (operator / security researcher / contributor), deep-linking each role's recommended path through the principal sections (Security Model / Design Invariants / Bypass Corpus Testing / Audit Log / AI-assisted Contribution Invariants / etc.) so readers can jump to the path appropriate for their use case without scrolling.
- **`SECURITY.md` Known Limitations 3-way split** ([#191](https://github.com/yottayoshida/omamori/pull/191)): the previously-mixed table is now grouped into (A) closures landed in the v0.9.x series, (B) out-of-scope by design decision, and (C) structural limits of static shell-word analysis — so readers can distinguish a closure-pending row from a scope-by-design or static-analysis-bound row.
- **`docs/dogfood/2026-04-23-codex-notion-mcp-reauth.md` translated to English** ([#192](https://github.com/yottayoshida/omamori/pull/192)) per the repo's English-default documentation convention.

### Known limitations (carried into a future release)

The recognised shape catalogue (`command`/`cmd`/`file_path`/`path`/`url`) is intentionally narrow in this release. Several known-good Claude Code tools — `NotebookEdit` (`notebook_path`), `Task` (`subagent_type`/`prompt`), `TodoWrite` (`todos`), `WebSearch` (`query`), and similar — currently land in the unknown branch and emit a fail-open event on every invocation. Practical implications:

- `omamori audit unknown` and `omamori doctor`'s 30-day count are an **upper bound on adversarial activity, not a lower bound** — they include this routine legitimate-tool noise. Treat the count as a drift indicator: a sudden spike or an unfamiliar tool name is the actionable signal, not a steady non-zero baseline.
- The protection guarantee is **unchanged**: payloads carrying a recognised dangerous shape (`command`/`cmd`/`file_path`/`path`) reach the full pipeline regardless of `tool_name`. The noise is an observability artefact, not a hole in the routing.
- `target_count` and `command` borrow existing audit columns with adjusted semantics for `unknown_tool_fail_open` events specifically; downstream analytics that aggregate either column across action types will see skewed distributions. Filter by `action` first.

A future omamori release will widen the shape catalogue, add dedicated audit columns, ship opt-in `strict-mode` (fail-closed on unrecognised shapes), and add session-level stderr dedup. See `SECURITY.md` → "Scope: unknown / new tools" for the full trade-off.

### PRs

- [#183](https://github.com/yottayoshida/omamori/pull/183) — `refactor(context): thread explicit base through normalize_path stack`. Adds `normalize_path_with_base` / `resolve_path_with_base` / `evaluate_context_with_base` `pub(crate)` helpers so context tests no longer depend on process-wide CWD; releases the `multi_target_*` Ubuntu CI quarantine added in v0.9.5. Closes #164.
- [#184](https://github.com/yottayoshida/omamori/pull/184) — `feat(unwrap): Shell-Layer Hardening Phase 2 (scope 5+6+7)`. Closes pipe-RHS bypass surfaces across `env -S 'bash -e'` split-string form (scope 5), `bash -c 'source /dev/stdin'` shell-launcher form (scope 6, source/`.` builtin only — eval/exec carry to v0.9.7), and `doas` / `pkexec` privilege-escalation wrappers (scope 7). Subagent rounds 1 and 2 caught a raw-state gate-violation in the initial fix that reintroduced a different bypass via helper rename / caller mismatch — captured as the `feedback_fix_creates_new_bypass` discipline. Refs #146 P2.
- [#185](https://github.com/yottayoshida/omamori/pull/185) — `feat(tests): argument reordering corpus (scope 1 only)`. Adds the argument-reordering corpus for #146 P1-2. Scope 2 (`${IFS}` / ANSI-C `$'...'` / brace `{,}`) is **withdrawn** from v0.9.6: a narrow patch was rejected in favour of a structural `ObfuscatedExpansion` enum unification, promoted to #176 for v0.10.0. Refs #146 P1-2.
- [#186](https://github.com/yottayoshida/omamori/pull/186) — `test: structural test quality (#146 scope 4)`. Migrates 4 structural array-shape tests (`meta_patterns_cover_*`) into the `hook_integration.rs` E2E corpus, pins audit chain hash tests against golden hex vectors instead of self-verifying helpers, and documents the parse-result-layer rationale in-file for `unwrap` tests. 5 Codex rounds and a Claude proxy second pass; surfaced the `behavioral-pin-isolation` skill (1 fixture = 1 pattern isolate) and the `codex-proxy-review-operation` skill. Refs #146 scope 4.
- [#188](https://github.com/yottayoshida/omamori/pull/188) — `test(property): cross-layer Layer 1 → Layer 2 property test (#146 P1-4)`. Pins the one-way implication "Layer 1 destructive ⟹ Layer 2 Block" with a 256-case `proptest 1.11`, covering 6 destructive built-in rules × 14 wrapper variants. Trust boundary made structural via `#[cfg(test)]` gate on `check_command_for_hook_with_rules` — the hermetic helper does not exist in the released binary. Lib tests 595 → 600. Refs #146 P1-4 / #187 (deferred to v0.9.7).
- [#189](https://github.com/yottayoshida/omamori/pull/189) — `feat(hook): structure-based routing for unknown tools (#182)`. Replaces the old `HookInput::UnknownTool` short-circuit-allow with structure-based routing on `tool_input` shape (`command`/`cmd` → Bash pipeline, `file_path`/`path` → FileOp, `url` → read-only allow, otherwise observable fail-open). Adds `audit unknown` / `audit show --action` / `doctor` 30-day-line as the user-facing review surface. 6 rounds (Codex R1-R3 + Claude proxy R4-R6). Defers 4 P3 findings to #190. Closes #182.
- [#191](https://github.com/yottayoshida/omamori/pull/191) — `docs(release): philosophy flip + Known Limitations 3-way split`. README narrative restructure (philosophy block surfaced before Quick Start), `SECURITY.md` Known Limitations split into (A) closures landed in the v0.9.x series, (B) out-of-scope by design decision, and (C) structural limits of static shell-word analysis, and CHANGELOG `### Security` narrative balance fix (the prior PR6-bias under-represented PR2's pipe-RHS work). Codex R1-R3 + Claude proxy R4 (4 rounds total); proxy R4 surfaced the narrative-balance gap. Doc-only.
- [#192](https://github.com/yottayoshida/omamori/pull/192) — `docs: README 9-H2 restructure + SECURITY navigation + dogfood EN`. README compressed from 13 H2 to 9 H2 (Quick Start purification, Tool Compatibility consolidation, new Real-world Effect section, Scope and Limitations consolidation), `SECURITY.md` top-of-file navigation block, `docs/dogfood/2026-04-23-codex-notion-mcp-reauth.md` translated to English, and a narrative-gluing fix that resolved PR7 proxy R4 P3-1 and P3-2. Doc-only.

## [0.9.5] - 2026-04-20

**Summary**: Security patch ([#146](https://github.com/yottayoshida/omamori/issues/146) P1-1) + Ubuntu CI quarantine ([#164](https://github.com/yottayoshida/omamori/issues/164)) + docs refresh ([#167](https://github.com/yottayoshida/omamori/issues/167)). Closes the documented `curl URL | env bash` / `curl URL | sudo bash` wrapper-evasion gap. Runtime behavior is otherwise unchanged — omamori remains macOS-only.

### Security

- **Pipe-to-shell with transparent wrappers now blocked** ([#170](https://github.com/yottayoshida/omamori/pull/170), #146 P1-1): `curl URL | env bash`, `curl URL | sudo bash`, and equivalent patterns with `nice`, `timeout`, `nohup`, `exec`, `command` wrappers are blocked at Layer 2. Coverage includes chained wrappers (`sudo env bash`), absolute-path variants (`/usr/bin/env`, `/bin/sudo`), stdin-mode flags (`-s`, bare `-`, `/dev/stdin`), option-value pairs (`-O extglob`, `-o errexit`, `--rcfile /tmp/rc`), grouped short options (`-la argv0`, `-pv`), and bash's `|&` (stdout+stderr pipe). The gap was previously documented in v0.9.4 `SECURITY.md` and in `src/unwrap.rs::tests::{curl_pipe_env_bash_not_yet_blocked,echo_pipe_sudo_bash_not_yet_blocked}`; those tests are now flipped to assert `BlockReason::PipeToShell`. Implementation reorders pipe-to-shell classification to run before `unwrap_transparent`, with explicit wrapper list synced to the transparent-unwrap list (same 7 wrappers). Info-only flags (`--version`, `--help`, `--dump-strings`, `--dump-po-strings`, `--rpm-requires`, `-D`) and positional script paths (`bash script.sh`, `env VAR=1 bash script.sh`) remain Allow. Block reason text is unchanged (`pipe to shell interpreter`) so AI agents reading the error message cannot iterate to the next wrapper kind — wrapper-kind surfacing is tracked as a v0.9.6 audit-only logging addition.

### For users

- No config or installation change required. macOS-only. If you were relying on the v0.9.4 known-gap behavior, `curl URL | env bash` now fails closed at Layer 2.

### For contributors (CI)

- **Ubuntu CI leg quarantined** ([#168](https://github.com/yottayoshida/omamori/pull/168), #164): `context::tests::multi_target_all_regenerable_downgrades` and its neighbor `multi_target_protected_wins_over_regenerable` are now annotated `#[serial_test::serial]`. Root cause is a process-wide CWD dependency in `normalize_path()` shared with the `git_context_*` family that mutates CWD via `env::set_current_dir`. This patch is a targeted quarantine, not a structural fix — threading an explicit base dir through `normalize_path` is tracked as a v0.9.6 follow-up. Ubuntu `Test` flakes across v0.9.4 PRs #162 and #163 (the latter with zero Rust changes) were driven by this interaction; re-run loops on Ubuntu should now indicate real regressions.

### Docs

- **`ACCEPTANCE_TEST.md` errata fixed** ([#169](https://github.com/yottayoshida/omamori/pull/169), #167): Prerequisites now require `export CLAUDECODE=1` before Layer 2 / Tamper / Doctor / Audit items, with a leading Warning box explaining that shim only activates with an AI env var detected. Without this, plain-terminal runs silently destroy test files instead of being blocked. A-2 audit log path corrected from `~/.omamori/audit/` to the actual `~/.local/share/omamori/audit.jsonl` (XDG Base Directory). D-3 / D-4 document the intentional `omamori explain` self-defense block under Claude Code (DI-8) and provide a copy-paste `omamori hook-check --provider claude-code` dry-run as the equivalent verdict source. Layer 2 section now includes H-5 / H-6 manual checks for `curl | env bash` and `curl | sudo bash` matching the #146 P1-1 scope. AI-generated test count updated from `490件` to `544件` (post-v0.9.4).
- **`SECURITY.md` Known Limitations refreshed** ([#169](https://github.com/yottayoshida/omamori/pull/169)): `curl URL | env bash` / `sudo bash` rows updated to "Closed in v0.9.5" with explicit wrapper coverage list. `export -n CLAUDECODE` row corrected — it has been blocked since v0.9.2 Phase 1B token detection; the prior "undetectable" claim was stale. `env -S 'bash -e'` (split-string), `bash -c 'source /dev/stdin'` (stdin-consuming inner), and the `source`/`eval`/interpreter family are newly documented as pending for v0.9.6.

### Known limitations (carried into v0.9.6)

- **`normalize_path()` CWD dependency** (structural follow-up to #164): 14 other CWD-read tests in `context::tests` are not `#[serial_test::serial]`. If a future refactor introduces similar races, a structural fix threading an explicit base dir is required.
- **`env -S 'bash -e'` split-string form**: env parses its quoted argument as its own command line; `shell-words` at the outer level does not split the inner content. Tracked as v0.9.6 follow-up to #146.
- **`bash -c 'source /dev/stdin'` and `source`/`eval`/interpreter family**: these read command bodies from stdin at runtime and are outside `SHELL_NAMES`. Expanding the list has real false-positive risk (`cat data | python -c 'parse'`) and requires product-level discussion.

### PRs

- [#168](https://github.com/yottayoshida/omamori/pull/168) — `test(context): quarantine multi_target_* with #[serial_test::serial]`. Closes #164.
- [#169](https://github.com/yottayoshida/omamori/pull/169) — `docs(acceptance,security): refresh acceptance test prerequisites and Known Limitations`. Closes #167.
- [#170](https://github.com/yottayoshida/omamori/pull/170) — `fix(unwrap): detect pipe-to-shell through transparent wrappers`. 8 rounds of Codex Phase 6-A adversarial review + 1 round of 6-B test adversarial review shaped the final surface (16 distinct fixes recorded in commit history). Refs #146 (P1-1 only).
- [#173](https://github.com/yottayoshida/omamori/pull/173) — `docs(readme): clarify Layer 2 pipe-to-shell wrapper coverage`. README's "How It Works" → "Layer 2 — Hooks" bullet expanded to add `sudo bash` as a second example and link to `SECURITY.md` for the full wrapper list. UX-designer reviewed.

## [0.9.4] - 2026-04-19

**Summary**: CI coverage + dependabot noise reduction. Adds a Linux + macOS CI matrix and a hook integration test suite so that Layer 2 regressions surface before merge on both OSes; extends `scripts/check-invariants.sh` with structural invariants that fire before `cargo test`; narrows the `github-actions` Dependabot ecosystem to monthly patch-only updates (security updates are independent per GitHub docs). Runtime behavior is unchanged — omamori remains macOS-only.

### For users

- No runtime behavior change. omamori still operates on macOS only; shim paths and trash integration remain macOS-specific.
- `SECURITY.md` Known Limitations now documents the `curl URL | env bash` / `curl URL | sudo bash` pipe-wrapper gap as an implementation gap (not a design limit); runtime fix is tracked in [#146 P1-1](https://github.com/yottayoshida/omamori/issues/146) for v0.9.5+.
- `README.md` has a new **Supported Platforms** section distinguishing Runtime (macOS only) from CI matrix (macOS + Ubuntu), so contributors and installers see accurate information at the same point in the file.

### For contributors (CI)

- CI `test` and `clippy` now run on a `matrix: [macos-latest, ubuntu-latest]` (PR #162). `fail-fast: false` + `continue-on-error: false` — both OS legs must pass to merge. `fmt`, `publish-dry-run`, and `msrv` stay macOS-only to contain CI wall-clock time.
- New `tests/hook_integration.rs` (PR #162): table-driven 8-category corpus (allow baseline / direct-path bypass / `unset` / `env -u` / `export -n` / `VAR=` / compound separator / false-positive guard) plus dedicated tests for exit-code-2 pin, wrapper invariants (`set -eu` and `exit $?` must be present), and malformed/empty stdin fail-close. Spawns the installed hook script via `/bin/sh` with `PATH` injection so the full `installer → wrapper → hook-check` chain is exercised — the path contributor machines actually run.
- `scripts/check-invariants.sh` extended with structural invariants #6/#7/#8 (PR #163): hook integration shape (corpus must include both `Decision::Allow` and `Decision::Block`, zero `#[ignore]`, no `#[cfg(target_os)]`), `render_hook_script` contract (function body must retain `cat | omamori hook-check`, `set -eu`, `exit $?` — body-scoped to avoid false-pass against historical test fixtures elsewhere in `installer.rs`), and CODEOWNERS explicit-path validation (awk-based: non-comment line, path as first token, at least one `@owner` on the same line).
- `.github/CODEOWNERS` now lists `/tests/`, `/tests/hook_integration.rs`, `/fuzz/fuzz_targets/`, `/scripts/check-invariants.sh`, and `/src/unwrap.rs` as explicit security-critical paths (PR #163). The default `* @yottayoshida` line still covers them, but explicit entries survive future changes to the wildcard and surface the ownership intent to PR reviewers.

### Maintenance

- Dependabot `github-actions` ecosystem narrowed (PR #160): `schedule.interval` `weekly` → `monthly`, `open-pull-requests-limit` `5` → `2`, and `ignore: version-update:semver-major` + `semver-minor` on all deps. Cargo ecosystems (root + `/fuzz`) remain unchanged at weekly grouped minor + patch. Security updates are **unaffected** by the `ignore` rules per [GitHub docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates): *"There is no interaction between the settings specified in the `dependabot.yml` file and Dependabot security alerts."* `SECURITY.md` now includes an annual audit procedure for this narrow config.
- `SECURITY.md` AI-assisted Contribution Invariants section gains a new *Dependabot narrow configuration audit (v0.9.4+)* subsection documenting the annual verification procedure for the narrowed config's security-update reachability.

### Known flakes (carried into v0.9.5)

- `context::tests::multi_target_all_regenerable_downgrades` intermittently fails on the `Test (ubuntu-latest)` leg with the same signature (`left: None, right: Some(LogOnly)` at `src/context.rs:681`). Reproduced with zero Rust changes across PR #162 and PR #163 initial pushes — ordering-dependent between context tests. Re-run passes. Tracked as [#164](https://github.com/yottayoshida/omamori/issues/164) with `#[serial_test::serial]` as the low-effort fix candidate.

### PRs

- [#160](https://github.com/yottayoshida/omamori/pull/160) — dependabot narrow (`github-actions` monthly patch-only). Closes #159.
- [#162](https://github.com/yottayoshida/omamori/pull/162) — hook integration tests + Linux CI matrix.
- [#163](https://github.com/yottayoshida/omamori/pull/163) — structural invariants #6/#7/#8 + CODEOWNERS explicit paths.
- [#165](https://github.com/yottayoshida/omamori/pull/165) — document `curl | env bash` / `curl | sudo bash` implementation gap in SECURITY.md.

## [0.9.3] - 2026-04-17

**Summary**: Repository structure & SCM hygiene hardening (#147). A six-PR supply-chain series that makes `cargo install omamori --locked` reproducible, pins every CI action to a 40-char SHA, installs a deny-by-default allowlist for tarball contents, and flips the SECURITY.md *AI-assisted Contribution Invariants* from "intended" to mechanically enforced.

### Security (supply-chain)

- **Invariant #1: reproducible installs** — `Cargo.lock` is now tracked. All CI `cargo` invocations run with `--locked`. (PR #150)
- **Invariant #2: pinned actions** — every `uses:` in `.github/workflows/*` pinned to a 40-char SHA with a `# vX.Y.Z` comment. `action-pin-check` is a **CI gate**: all third-party-action jobs declare `needs: action-pin-check`, so no external action executes until pinning has been validated. (PR #151)
- **Invariant #3: enforced ignores** — `.gitignore` now audited via `git check-ignore` probes (not grep), so a `!pattern` negation cannot silently disable a required ignore rule. (PR #151)
- **Invariant #4: deny-by-default tarball** — `Cargo.toml include = [...]` allowlist drops the crates.io tarball from 58 files to 42, excluding `.github/*`, `scripts/*`, `rust-toolchain.toml`, `CONTRIBUTING.md`, `.editorconfig`, `.gitattributes`, `demo.svg`, `ACCEPTANCE_TEST.md`, `.gitignore`. `crate-contents-guard` enforces a **strict allowlist** (not denylist) at CI time; paths not on an explicit allow list fail the build. (PR #156)
- **Invariant #5: `--locked` everywhere** — enforced structurally via the invariants-check CI job. (PR #151)
- **Pinned cargo installs** — `cargo install cargo-tarpaulin` replaced by `taiki-e/install-action@v2.75.16` + `tool: cargo-tarpaulin@0.35.2` + `fallback: none`. `cargo-fuzz` pinned to `0.13.1` with `--locked`. (PR #155)
- **Fuzz artifact cap** — `retention-days: 7` on crash artifacts to avoid indefinitely advertising unpublished vulnerabilities (threat T9/M8). (PR #156)

### Added

- `.github/CODEOWNERS`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/dependabot.yml` (weekly grouped minor/patch for cargo + github-actions)
- `.editorconfig`, `.gitattributes`
- `CONTRIBUTING.md` — branch naming ladder, repository/automation map, SHA pin policy, `feat/*` migration schedule (legacy `feature/*` accepted until 2026-05-15)
- `SECURITY.md` — new *AI-assisted Contribution Invariants (v0.9.3+)* section. Five load-bearing invariants framed as mechanically-checked rules; rejecting any of them is treated as a security change, not a cleanup.
- `rust-toolchain.toml` — stable pin for dev + non-fuzz CI jobs. Fuzz (nightly) is intentionally not bound.
- `scripts/pre-pr-check.sh`, `scripts/pre-release-check.sh`
- `scripts/check-lockfile-regressions.sh` — detects direct-dep version downgrades via `cargo metadata --locked` + `git worktree` materialization of BASE (disambiguates same-named lockfile entries via package IDs).
- `scripts/check-action-pins.sh` — YAML-aware validator for SHA pinning. Covers step-level `jobs[].steps[].uses` and job-level reusable workflows; matches on parsed ref tokens so a comment like `@v4 # @<40hex>` cannot false-pass.
- `scripts/check-crate-contents.sh` — strict allowlist guard over `cargo package --list` output + binary-file MIME detection.
- `scripts/check-invariants.sh` — `python3 tomllib` structural check on `package.include`, plus `git check-ignore` probes.
- CI jobs: `action-pin-check` (gate), `invariants-check`, `crate-contents-guard`, `lockfile-sanity`.

### Changed

- MSRV unchanged at 1.92.
- Removed from crate tarball (16 files, all developer-only): `.github/*`, `scripts/*`, `rust-toolchain.toml`, `CONTRIBUTING.md`, `.editorconfig`, `.gitattributes`, `demo.svg`, `ACCEPTANCE_TEST.md`, `.gitignore`.

### Internal

- 6 PRs: #149 governance → #150 Cargo.lock → #151 SHA pin + gate → #155 cargo install pin → #156 artifact guard → this release.
- 14 Codex adversarial-review findings resolved across the series.
- New /develop process artifact: plan file `.claude/plans/2026-04-17-v093-repo-hygiene.md` (local, untracked).

### Found By

Codex (GPT-5.3) adversarial-review per PR + /plan Phase 3/5 Codex rounds. Plan authored by Claude (Opus 4.7) with two-round Codex adversarial-review before /develop.

## [0.9.2] - 2026-04-16

**Summary**: Security patch — fix three confirmed hook bypass vulnerabilities discovered by Codex adversarial test review. All bypasses are Layer 2 (hook) only; Layer 1 (PATH shim) was not affected.

### Security

- **DI-11: Command separator normalization** (#144): `normalize_compound_operators` now treats unquoted `\n`, `\r`, `\r\n` as command separators (equivalent to `;`), and space-separates single `&` (background operator) while preserving `&>`, `>&`, and `2>&1` redirects. `split_on_operators` now treats `&` as a segment boundary. Previously, `echo ok\nrm -rf /` and `echo x & rm -rf /` bypassed Layer 2 detection.

- **DI-12: Token-level env var tampering detection** (#145): Phase 1 meta-pattern check split into Phase 1A (string-level, path/config patterns) and Phase 1B (token-level, env var patterns). Phase 1B uses `shell_words::split` after `normalize_compound_operators` for whitespace normalization and quote awareness, with `is_command_position()` to prevent false positives on arguments and quoted strings. Detects `unset`, `env -u`, `export -n` (both separated and combined forms like `-uVAR`), and `VAR=` assignment. Previously, `unset  CLAUDECODE` (double space) and `unset\tCLAUDECODE` (tab) bypassed detection.

### Changed

- `blocked_command_patterns()` renamed to `blocked_string_patterns()` — env var patterns moved to token-level Phase 1B detection.
- `PROTECTED_ENV_VARS` constant added to `installer.rs` for centralized env var list.
- `is_env_assignment()` and `normalize_compound_operators()` promoted to `pub(crate)` for Phase 1B reuse.

### Internal

- Tests: 490 → 538 (+48 new tests for security fixes, adversarial coverage, and benign regression)
- Adversarial test review process established: Codex reviews Claude-written tests before merge (Phase 6-B in `/develop`)

### Found By

Codex (GPT-5.3) adversarial test review + Claude (Opus 4.6) CLI reproduction + 2-round Codex plan review.

## [0.9.1] - 2026-04-14

### Fixed

- Remove 3 stray files from crate package that were accidentally tracked in git: `.claude/plans/` (old plan), `PLAN.md`, `investigation/` (old PoC notes). No code changes.

## [0.9.0] - 2026-04-14

**Summary**: "UX Revolution" — two new commands (`doctor`, `explain`) that transform the user experience from "something broke" to "fix it" and from "why was I blocked?" to "here's why."

### Added

- **`omamori doctor`** (#117): Diagnose installation health. Shows only problems (or 3-line "all healthy" summary).
  - `--fix`: Auto-repair shims, hooks, config permissions, and baseline. Repair order: install → hooks → chmod → baseline (DI-10).
  - `--verbose`: Show all check items (works in both healthy and unhealthy states).
  - `--json`: Structured JSON output for automation.
  - AI guard (DI-7): `--fix` is blocked in AI environments to prevent baseline normalization attacks.

- **`omamori explain -- <command>`** (#118): Simulate command evaluation through both defense layers without executing.
  - Shows Layer 1 (PATH shim) rule match + context override and Layer 2 (hook) meta-pattern/unwrap evaluation.
  - `--json`: Structured JSON output. `--config PATH`: Custom config for testing.
  - AI guard (DI-8): Blocked in AI environments to prevent oracle attacks.
  - Exit code: 0 = would be allowed, 2 = would be blocked (consistent with `hook-check`).

- **Block message hint line**: All block messages (shim + hook) now include `hint: run \`omamori explain -- <cmd>\` for details`.

- **`Remediation` enum**: Each integrity check item carries a suggested fix action (`RunInstall`, `RegenerateHooks`, `RegenerateBaseline`, `ChmodConfig`, `ManualOnly`). Foundation for `doctor --fix`.

### Security

- **DI-7 through DI-10**: Four new design invariants for `doctor --fix` and `explain`. See SECURITY.md.
- **DI-9**: `blocked_command_patterns` updated with `omamori doctor --fix` and `omamori explain` (defense-in-depth via Layer 2 hooks).
- `guard_ai_config_modification` call sites: 7 → 9.

### Changed

- **README overhaul** (#120): Removed 5 version annotations. Added `doctor` to Quick Start. Added `doctor` and `explain` to CLI Reference. User-value ordering per UX rules.

### Internal

- Tests: 473 → 491 (+18 new tests for doctor and explain)

## [0.8.1] - 2026-04-12

**Summary**: Internal module split for maintainability. No behavior changes, no config changes. Existing installations work as-is.

### Changed

- **Module split** (#112): Monolithic `lib.rs` (2,893 lines) and `audit.rs` (2,765 lines) split into focused submodules (`src/audit/`, `src/engine/`, `src/cli/`, `src/util.rs`). `lib.rs` reduced to 103-line dispatcher.

### Internal

- 19 guardrail tests added before the split to lock security-critical invariants (#132)
- Tests: 453 → 473 (+20)

## [0.8.0] - 2026-04-11

**Summary**: Fail-close hook validation (**breaking** for non-standard integrations), Edit/Write file guard for protected files, audit key rotation, fuzz testing, MSRV 1.92.

### Breaking

- **Hook input validation is now strict** (#111): Malformed JSON input to hooks is blocked (exit 2) instead of falling back to string processing. If you see unexpected blocks after upgrading, verify your AI tool is sending valid hook input. Claude Code, Codex CLI, and Cursor are tested and unaffected.

### Security

- **Fail-close on malformed hook input** (#111): Hook layer now blocks (exit 2) when stdin is not valid JSON, missing required fields, or has wrong types. Previously fell back to raw string processing (fail-open). Typed `HookInput` enum replaces the old string-based extraction.

- **Edit/Write file_path guard** (#110): AI Edit/Write/MultiEdit operations targeting omamori's protected files are now blocked. 10 protected patterns: config.toml, .integrity.json, audit-secret, audit.jsonl, hook scripts, `.claude/settings.json`, `.codex/hooks.json`, `.codex/config.toml`. Path normalization includes `canonicalize()` + parent directory symlink resolution. 3-layer error messages (what/state/action) with `omamori config` CLI alternative.

- **New meta-patterns** (#110): `export -n` for 6 detector env vars (CLAUDECODE, CODEX_CI, CURSOR_AGENT, GEMINI_CLI, CLINE_ACTIVE, AI_GUARD). `.claude/settings.json` protection via both file_path guard and blocked_command_patterns.

- **Fuzz testing** (#113): 3 cargo-fuzz targets (fuzz_unwrap, fuzz_hook_input, fuzz_check_command) with CI integration (nightly schedule + PR). Found and fixed a panic in `unwrap_transparent()` on wrapper-only input (e.g., `sudo sudo sudo`).

### Fixed

- **Silent audit log failures** (#114): 3 instances of `let _ = logger.append(event)` replaced with `try_audit_append()`. Write failures now emit WARNING to stderr. In strict mode (`audit.strict = true`), write failure blocks the command (exit 1).

- **Parser panic on wrapper-only input** (#113): `unwrap_transparent()` panicked when input consisted entirely of wrappers with no actual command (e.g., `nice -n`, `sudo -u root`). Bounds check added.

### Added

- **Audit key rotation** (#116): `omamori audit key rotate` command. Renames active secret to `audit-secret.N.retired`, generates new secret. Multi-key verification in `verify_chain()` — old entries verify against retired key, new entries against active key. AI environment guard blocks rotation from AI context.

- **MSRV declaration** (#115): `rust-version = "1.92"` in Cargo.toml. CI MSRV check job added.

- **Coverage reporting** (#115): cargo-tarpaulin CI job with Codecov upload on main push.

### Changed

- Sandbox documentation updated: removed #61 references (NO-GO), updated to recommend platform-native sandboxes (Codex CLI, Claude Code `/sandbox`, Cursor) or [nono](https://github.com/always-further/nono).
- SECURITY.md updated: Edit/Write file operations on protected files now listed as "Blocked" instead of "Not protected".

### Stats

- Tests: 427 → 453 (+26)
- New CI jobs: MSRV check, Coverage, Fuzz (3 targets)

## [0.7.5] - 2026-04-07

### Fixed

- **Cursor/Codex hook shell-safe paths** (#104): `render_cursor_hooks_snippet` and `render_codex_pretooluse_script` now use `shell_words::quote` for executable path escaping, consistent with `codex_hooks_entry`. Also updated `cursor_snippet_exe_path` to use `shell_words::split` for robust path extraction.
- **Config destination symlink check was dead code** (#105): `validate_destination` checked for symlinks after `canonicalize()`, which resolves all symlinks — making the check always false. Moved the check before `canonicalize`. Runtime guard in `move_to_dir` is unchanged.
- **Config mutation not using hardened write** (#102): `mutate_config()` now uses atomic write (temp → fsync → rename) with `O_NOFOLLOW`, consistent with `write_baseline()` and `write_default_config()`.
- **Shim target not verified against baseline** (#101): `full_check()` now compares each shim's resolved symlink target against the baseline record using `canonicalize` on both sides (handles Homebrew Cellar ↔ stable paths). Mismatch reports `[WARN]` with repair guidance.
- **Config hash not compared to baseline** (#103): `full_check()` now compares the current config hash against the baseline. Detects out-of-band modification with `[WARN]`. Legitimate `omamori config` commands update the baseline automatically, avoiding false positives.

## [0.7.4] - 2026-04-06

### Fixed

- **`omamori status` false [ok] on symlink attack** (#98): `audit_summary()` now detects non-NotFound errors (ELOOP, permission denied) via `path_error` field instead of silently returning `entry_count = 0`. Status displays `[warn]` with the error message. Reordered status display to check `path_error` and `secret_available` before `entry_count == 0`.
- **`omamori audit verify` loses symlink cause on secret** (#99): `verify_chain()` now propagates symlink-specific error messages instead of mapping all `read_secret()` failures to generic "HMAC secret unavailable".
- **strict mode docs overstated scope** (#97): SECURITY.md and CHANGELOG clarified that strict mode only affects commands intercepted by the PATH shim, not hook-only commands.
- **`blocked_command_patterns` broad match undocumented** (#100): SECURITY.md now documents that meta-patterns use intentional substring matching, blocking read-only commands on protected paths to prevent reconnaissance.

## [0.7.3] - 2026-04-06

### Added

- **O_NOFOLLOW symlink defense** (#29): All 6 audit file operations (`append`, `read_secret`, `create_secret`, `verify_chain`, `show_entries`, `audit_summary`) now use `O_NOFOLLOW` to reject symlinks at the kernel level. Prevents symlink attacks where `audit.jsonl` or `audit-secret` is replaced with a symlink to `/dev/null` or attacker-controlled path. ELOOP errors are converted to user-friendly "symlink detected" messages. Unix-only (`#[cfg(unix)]`); non-Unix platforms operate without symlink protection.

- **Audit strict mode** (#29): Opt-in fail-close mode (`audit.strict = true`, default `false`). When enabled, AI commands intercepted by the PATH shim are blocked if the HMAC secret is unavailable after re-creation attempt. Human terminal use and hook-only commands are not affected.

- **Data directory protection** (#29): `.local/share/omamori` added to `blocked_command_patterns`. Prevents AI agents from deleting the entire data directory (which would simultaneously remove both `audit.jsonl` and `audit-secret`).

### Closed

- **#29**: Tamper-evident audit log — complete. All sub-features delivered across v0.7.0–v0.7.3: HMAC chain (v0.7.0), CLI verify/show/status (v0.7.1), retention/prune (v0.7.2), strict mode/O_NOFOLLOW hardening (v0.7.3).

## [0.7.2] - 2026-04-05

### Added

- **Audit retention + auto prune** (#29): Optional `retention_days` config prunes old audit entries while preserving tamper-evident chain integrity.
  - `retention_days` in `[audit]` section (default 0 = unlimited). Minimum 7 days enforced; values below are clamped with warning.
  - Auto-prune triggers every 1000 appends (`seq % 1000`) under flock. Zero overhead when not triggered.
  - **prune_point**: HMAC-protected chain entry inserted at the head of the pruned log. `prev_hash` = prune genesis (distinct from chain genesis), `target_hash` = HMAC binding to the first retained entry.
  - **verify_chain**: Recognizes prune_point, validates prune genesis anchor, verifies target_hash binding (detects post-prune deletion). Reports pruned count.
  - **show**: prune_point displayed as separator (`--- pruned N entries before YYYY-MM-DD ---`).
  - **status**: Shows retention info (`retention: Nd`) when configured.
  - Minimum retain 1000 entries regardless of age.
  - `omamori/config.toml` added to `blocked_command_patterns` to prevent AI agents from editing retention settings.

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
