#!/usr/bin/env bash
# check-invariants.sh
#
# Enforces SECURITY.md "AI-assisted Contribution Invariants (v0.9.3+)".
# Runs in the `invariants-check` CI job. Exits non-zero on any violation.
#
# Why a standalone script (not inline in ci.yml):
#   - Makes the check locally testable (same logic as CI).
#   - Avoids Python-heredoc indent fragility inside YAML `run: |` blocks.
#
# Requirements:
#   - Python 3.11+ (for `tomllib` in stdlib) — available on GitHub ubuntu-latest.
#   - `git`.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# ---------- Invariant #1: Cargo.lock is tracked ----------
if [ -z "$(git ls-files Cargo.lock)" ]; then
    echo "FAIL [invariant #1]: Cargo.lock is not tracked"
    fail=1
else
    echo "#1 OK: Cargo.lock is tracked"
fi

# ---------- Invariant #3: required paths are effectively ignored ----------
# `git check-ignore -q` respects the full .gitignore hierarchy *including*
# any `!pattern` negations, so a negation rule that silently disabled an
# ignore would be caught here.
probes=(
    ".claude/probe.md"
    "investigation/probe.md"
    "CLAUDE.local.md"
    "target/probe"
    ".env"
    ".env.local"
)
for probe in "${probes[@]}"; do
    if ! git check-ignore -q "$probe"; then
        echo "FAIL [invariant #3]: $probe is NOT effectively ignored"
        fail=1
    fi
done
echo "#3 OK: all required probes are effectively ignored"

# ---------- Invariant #4: package.include exists ----------
# TOML-aware check instead of grep: tolerates any formatting cargo accepts
# and cannot be fooled by an `include =` line outside the `[package]` table.
if ! python3 - <<'PYEOF'
import sys, tomllib
with open("Cargo.toml", "rb") as f:
    data = tomllib.load(f)
inc = data.get("package", {}).get("include")
if not isinstance(inc, list) or len(inc) == 0:
    print("FAIL [invariant #4]: package.include is missing or empty in Cargo.toml")
    sys.exit(1)
print(f"#4 OK: package.include has {len(inc)} entries")
PYEOF
then
    fail=1
fi

# ---------- Invariant #5: representative --locked usage ----------
if ! grep -q 'cargo test --locked' .github/workflows/ci.yml; then
    echo "FAIL [invariant #5]: cargo test must use --locked"
    fail=1
fi
if ! grep -q 'cargo publish --dry-run --locked' .github/workflows/ci.yml; then
    echo "FAIL [invariant #5]: cargo publish --dry-run must use --locked"
    fail=1
fi
echo "#5 OK: representative --locked invocations present"

# ---------- Invariant #6: hook integration test structural invariants (v0.9.4+, #121) ----------
# Structural (not name-based): the hook integration suite must (a) exist,
# (b) contain at least one test that spawns the hook script via /bin/sh,
# (c) include both Decision::Allow and Decision::Block in its corpus,
# (d) not use `#[ignore]`, (e) not gate on `#[cfg(target_os = ...)]`.
# These shape checks complement the runtime Rust invariant
# `corpus_includes_both_decisions` — if someone silently guts the corpus or
# disables a test with `#[ignore]`, the gate here fails before the Rust
# invariant even runs.
hi=tests/hook_integration.rs
hi_fail=0
if [ ! -f "$hi" ]; then
    echo "FAIL [invariant #6a]: $hi is missing"
    hi_fail=1
else
    if ! grep -qF 'Command::new("/bin/sh")' "$hi"; then
        echo "FAIL [invariant #6b]: $hi must spawn the hook script via /bin/sh"
        hi_fail=1
    fi
    if ! grep -qF 'Decision::Allow' "$hi"; then
        echo "FAIL [invariant #6c-allow]: $hi corpus must include Decision::Allow"
        hi_fail=1
    fi
    if ! grep -qF 'Decision::Block' "$hi"; then
        echo "FAIL [invariant #6c-block]: $hi corpus must include Decision::Block"
        hi_fail=1
    fi
    if grep -Eq '^[[:space:]]*#\[ignore\]' "$hi"; then
        echo "FAIL [invariant #6d]: $hi must have zero #[ignore] attributes"
        hi_fail=1
    fi
    # Strip single-line comments before matching so explanatory text like
    # "// never add #[cfg(target_os)] here" doesn't trip the check.
    if sed 's|//.*$||' "$hi" | grep -qF '#[cfg(target_os'; then
        echo "FAIL [invariant #6e]: $hi must not gate tests on target_os"
        hi_fail=1
    fi
fi
if [ "$hi_fail" -eq 0 ]; then
    echo "#6 OK: hook integration suite has required structure"
else
    fail=1
fi

# ---------- Invariant #7: render_hook_script delegation contract (v0.9.4+, #121) ----------
# The generated hook wrapper is the thin shell bridge between an AI tool and
# `omamori hook-check`. If this shape drifts (e.g. `set -eu` dropped,
# `cat | omamori hook-check` replaced, `exit $?` mutated), downstream tests
# and the hook integration suite may still pass while the wrapper silently
# stops enforcing policy. Pin the literal strings that make the contract.
ih=src/installer.rs
ih_fail=0
if [ ! -f "$ih" ]; then
    echo "FAIL [invariant #7a]: $ih is missing"
    ih_fail=1
else
    # Extract the body of `render_hook_script` so that matching fixture strings
    # elsewhere in the file (e.g. test fixtures with `set -eu`) cannot satisfy
    # the contract checks. The function spans from its `pub fn` line to the
    # next top-level closing `}` at column 1.
    fn_body=$(awk '
        /^pub fn render_hook_script/ { inside=1 }
        inside { print }
        inside && /^}/ { exit }
    ' "$ih")
    if [ -z "$fn_body" ]; then
        echo "FAIL [invariant #7b]: render_hook_script function must exist in $ih"
        ih_fail=1
    else
        if ! printf '%s\n' "$fn_body" | grep -qF 'hook-check --provider claude-code'; then
            echo "FAIL [invariant #7c]: render_hook_script must invoke hook-check --provider claude-code"
            ih_fail=1
        fi
        if printf '%s\n' "$fn_body" | grep -qF '| omamori hook-check'; then
            echo "FAIL [invariant #7f]: render_hook_script must NOT use bare omamori (PATH vulnerability)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'omamori_exe'; then
            echo "FAIL [invariant #7g]: render_hook_script must accept omamori_exe parameter"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'set -u'; then
            echo "FAIL [invariant #7d]: render_hook_script body must use set -u"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qE 'exit (0|2|\$\?)'; then
            echo "FAIL [invariant #7e]: render_hook_script body must propagate exit code"
            ih_fail=1
        fi
        # Codex① Round 1: a substring check on just "plain terminal" would
        # let a regression silently drop the agent-facing "do not retry"
        # line or the `omamori install --hooks` command while still passing.
        # Check all three fixed hint lines individually (kept in sync by
        # hand with src/installer.rs's RECOVERY_HINT_LINES test constant).
        if ! printf '%s\n' "$fn_body" | grep -qF 'this is not a decision about your command'; then
            echo "FAIL [invariant #7h]: render_hook_script must keep the recovery hint's first line (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'AI agent: do not retry this yourself'; then
            echo "FAIL [invariant #7p]: render_hook_script must keep the recovery hint's agent-facing line (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'plain terminal'; then
            echo "FAIL [invariant #7q]: render_hook_script must keep the recovery hint's plain-terminal instruction (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'omamori install --hooks'; then
            echo "FAIL [invariant #7r]: render_hook_script must keep the recovery hint's command (#353)"
            ih_fail=1
        fi
    fi

    # #356/#353: the Codex CLI wrapper is a twin of the Claude wrapper above
    # (same fail-close contract, different --provider). Codex has no
    # invariant coverage of its own until now — a change to one wrapper's
    # tail without the other would previously pass this gate silently.
    codex_fn_body=$(awk '
        /^pub fn render_codex_pretooluse_script/ { inside=1 }
        inside { print }
        inside && /^}/ { exit }
    ' "$ih")
    if [ -z "$codex_fn_body" ]; then
        echo "FAIL [invariant #7i]: render_codex_pretooluse_script function must exist in $ih"
        ih_fail=1
    else
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'hook-check --provider codex'; then
            echo "FAIL [invariant #7j]: render_codex_pretooluse_script must invoke hook-check --provider codex"
            ih_fail=1
        fi
        if printf '%s\n' "$codex_fn_body" | grep -qF '| omamori hook-check'; then
            echo "FAIL [invariant #7k]: render_codex_pretooluse_script must NOT use bare omamori (PATH vulnerability)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'omamori_exe'; then
            echo "FAIL [invariant #7l]: render_codex_pretooluse_script must accept omamori_exe parameter"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'set -u'; then
            echo "FAIL [invariant #7m]: render_codex_pretooluse_script body must use set -u"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qE 'exit (0|2|\$\?)'; then
            echo "FAIL [invariant #7n]: render_codex_pretooluse_script body must propagate exit code"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'this is not a decision about your command'; then
            echo "FAIL [invariant #7o]: render_codex_pretooluse_script must keep the recovery hint's first line (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'AI agent: do not retry this yourself'; then
            echo "FAIL [invariant #7s]: render_codex_pretooluse_script must keep the recovery hint's agent-facing line (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'plain terminal'; then
            echo "FAIL [invariant #7t]: render_codex_pretooluse_script must keep the recovery hint's plain-terminal instruction (#353)"
            ih_fail=1
        fi
        if ! printf '%s\n' "$codex_fn_body" | grep -qF 'omamori install --hooks'; then
            echo "FAIL [invariant #7u]: render_codex_pretooluse_script must keep the recovery hint's command (#353)"
            ih_fail=1
        fi
    fi
fi
if [ "$ih_fail" -eq 0 ]; then
    echo "#7 OK: render_hook_script contract intact"
else
    fail=1
fi

# ---------- Invariant #8: CODEOWNERS must explicitly list security-critical paths (v0.9.4+) ----------
# `* @owner` would implicitly cover everything, but explicit entries guarantee
# that future changes to the default line (e.g. adding a second owner or
# removing the wildcard) cannot silently drop ownership on these paths.
co=.github/CODEOWNERS
co_fail=0
if [ ! -f "$co" ]; then
    echo "FAIL [invariant #8a]: $co is missing"
    co_fail=1
else
    required_owners=(
        "/tests/"
        "/tests/hook_integration.rs"
        "/fuzz/fuzz_targets/"
        "/scripts/check-invariants.sh"
        "/src/unwrap.rs"
    )
    # Use awk to enforce: non-comment line, path is the first token, and at
    # least one @owner follows. A bare `grep -F "$path"` would let comments,
    # substring matches, or ownerless paths pass.
    for path in "${required_owners[@]}"; do
        if ! awk -v p="$path" '
            /^[[:space:]]*#/ { next }
            $1 == p {
                for (i = 2; i <= NF; i++) {
                    if ($i ~ /^@/) { ok=1; exit }
                }
            }
            END { exit !ok }
        ' "$co"; then
            echo "FAIL [invariant #8]: $co must include '$path' as a non-comment line with at least one @owner"
            co_fail=1
        fi
    done
fi
if [ "$co_fail" -eq 0 ]; then
    echo "#8 OK: CODEOWNERS includes required explicit paths"
else
    fail=1
fi

# ---------- Invariant #9: TRANSPARENT_WRAPPERS ↔ match-arm sync (v0.9.6, scope 7) ----------
# `const TRANSPARENT_WRAPPERS` in src/unwrap.rs is the single source of
# truth for basenames treated as transparent command wrappers. Every entry
# there MUST have a corresponding match arm in `unwrap_transparent`, where
# per-wrapper arg-consumption logic lives (sudo skips `-u/-g` values, env
# calls `skip_env_args`, etc.). Drift would silently reopen a pipe-to-shell
# bypass: `segment_executes_shell_via_wrappers` would still recognize the
# wrapper via the const, but `unwrap_transparent` would fail to strip its
# flags and leave the residual command in an inconsistent state that later
# logic could mis-classify as safe.
#
# `segment_executes_shell_via_wrappers` itself reads TRANSPARENT_WRAPPERS
# directly (Step A SoT refactor), so it is automatically in sync and needs
# no separate check here.
uw=src/unwrap.rs
uw_fail=0
if [ ! -f "$uw" ]; then
    echo "FAIL [invariant #9a]: $uw is missing"
    uw_fail=1
else
    # Extract quoted basenames from the TRANSPARENT_WRAPPERS const body.
    wrappers=$(awk '
        # Match visibility-prefixed const declarations:
        # `const TRANSPARENT_WRAPPERS`, `pub const ...`, `pub(crate) const ...` etc.
        # `pub(crate)` was added by v0.9.6 PR5 for the property test SoT check.
        /^(pub(\([a-z]+\))?[[:space:]]+)?const TRANSPARENT_WRAPPERS/ { inside=1; next }
        inside {
            if (/\];/) { exit }
            while (match($0, /"[a-zA-Z_][a-zA-Z0-9_-]*"/)) {
                print substr($0, RSTART+1, RLENGTH-2)
                $0 = substr($0, RSTART + RLENGTH)
            }
        }
    ' "$uw")
    if [ -z "$wrappers" ]; then
        echo "FAIL [invariant #9b]: TRANSPARENT_WRAPPERS is empty or unparseable in $uw"
        uw_fail=1
    fi
    # Extract the body of `unwrap_transparent` to scope match-arm checks
    # (avoids matching `"sudo" =>` that might appear in a comment or test
    # fixture elsewhere in the file).
    ut_body=$(awk '
        /^fn unwrap_transparent/ { inside=1 }
        inside { print }
        inside && /^}/ && !/^fn / { if (NR > 1) exit }
    ' "$uw")
    for w in $wrappers; do
        if ! printf '%s\n' "$ut_body" | grep -qF "\"$w\" =>"; then
            echo "FAIL [invariant #9c]: TRANSPARENT_WRAPPERS entry \"$w\" has no match arm in unwrap_transparent"
            uw_fail=1
        fi
    done
fi
if [ "$uw_fail" -eq 0 ]; then
    echo "#9 OK: TRANSPARENT_WRAPPERS ↔ unwrap_transparent match-arm sync intact"
else
    fail=1
fi

# ---------- Invariant #10: PR6 routing surface symbols (v0.9.6+, #190 B-1) ----------
# `enum InputShape` / `fn classify_input_shape` / `fn has_routing_field_with_wrong_type`
# in `src/engine/hook.rs` are the structural pins for v0.9.6's payload-shape
# routing of unknown tools (#182). Renaming or deleting any of them silently
# narrows the only contract that catches forward-compat fail-open: a payload
# carrying `command` / `cmd` / `file_path` / `path` must reach the full pipeline
# regardless of `tool_name`. Unit and integration tests would still pass on a
# rename if call sites moved together, but the routing identity would drift
# away from SECURITY.md's narrative. Pin the symbols here as a CI gate.
#
# Note on target file: issue #190 B-1 referenced `tests/hook_integration.rs`,
# but the three named symbols live in `src/engine/hook.rs` (production code,
# not test). The invariant pins the actual definition site. The trailing `\(`
# anchors `fn classify_input_shape` against the test helper
# `fn classify_input_shape_command_priority_over_url` (same prefix, no paren).
hk=src/engine/hook.rs
hk_fail=0
if [ ! -f "$hk" ]; then
    echo "FAIL [invariant #10a]: $hk is missing"
    hk_fail=1
else
    if ! grep -qE 'enum InputShape\b' "$hk"; then
        echo "FAIL [invariant #10b]: $hk must define 'enum InputShape'"
        hk_fail=1
    fi
    if ! grep -qE 'fn classify_input_shape\(' "$hk"; then
        echo "FAIL [invariant #10c]: $hk must define 'fn classify_input_shape('"
        hk_fail=1
    fi
    if ! grep -qE 'fn has_routing_field_with_wrong_type\(' "$hk"; then
        echo "FAIL [invariant #10d]: $hk must define 'fn has_routing_field_with_wrong_type('"
        hk_fail=1
    fi
fi
if [ "$hk_fail" -eq 0 ]; then
    echo "#10 OK: PR6 routing surface symbols intact"
else
    fail=1
fi

# ---------- Invariant: phase1a-relaxation-requires-phase2 (DI-13, v0.10.3+) ----------
# Phase 2 backstop for verb patterns that may be relaxed in Phase 1A by the
# data-flag allowlist (v0.10.3+, #240). These 7 builtin rules MUST exist in
# `default_rules()` so that a real self-modification invocation is caught
# even if Phase 1A is relaxed by the data-flag allowlist.
#
# Naming: identified by name rather than number so future re-orderings do
# not break SECURITY.md cross-references.
#
# The check narrows grep to the `default_rules()` body — Codex review (PR1a)
# noted the original wide-scope grep would pass even if a rule was deleted
# from default_rules() but kept in tests or core_rule_names() (false OK).
di13_fail=0
required_omamori_rules=(
    "omamori-config-modify-block"
    "omamori-uninstall-block"
    "omamori-init-force-block"
    "omamori-override-block"
    "omamori-doctor-fix-block"
    "omamori-explain-block"
    "omamori-break-glass-block"
    "omamori-audit-key-rotate-block"
)
cf=src/config.rs
default_rules_body=$(awk '
    /^pub fn default_rules\(\)/ { inside=1 }
    inside { print }
    inside && /^}/ { exit }
' "$cf")
for rule in "${required_omamori_rules[@]}"; do
    if ! printf '%s\n' "$default_rules_body" | grep -qF "\"$rule\""; then
        echo "FAIL [invariant phase1a-relaxation-requires-phase2/DI-13]: default_rules() must define \"$rule\""
        di13_fail=1
    fi
done
if [ "$di13_fail" -eq 0 ]; then
    echo "phase1a-relaxation-requires-phase2 OK: omamori-* builtin rules intact in default_rules() (DI-13)"
else
    fail=1
fi

# ---------- DI-14 RETIRED (v0.10.4) ----------
# strip_quoted_data removed: meta-pattern infrastructure deleted.
# FP relief achieved by removing 25 meta-patterns entirely.
echo "DI-14 RETIRED (v0.10.4): strip_quoted_data removed with meta-pattern infrastructure"

# ---------- DI-15 RETIRED (v0.10.4) ----------
# subst_depth tracking removed with strip_quoted_data.
echo "DI-15 RETIRED (v0.10.4): subst_depth removed with strip_quoted_data"

# ---------- DI-16 RETIRED (v0.10.4) ----------
# audit_log_hook_allow_relaxed and layer2:relaxed: removed with relaxed_by infrastructure.
echo "DI-16 RETIRED (v0.10.4): relaxed_by audit path removed with meta-pattern infrastructure"

# ---------- Invariant: faq-doc-sync (#328, PR-C3) ----------
# docs/FAQ.md must not rot against the code and SECURITY.md it points into:
#   (a) every `SECURITY.md#anchor` the FAQ references must resolve to a real
#       heading (regenerated here with GitHub's anchor rules: lowercase,
#       strip everything but [a-z0-9 _-], spaces -> hyphens);
#   (b) every `omamori <subcommand>` the FAQ shows the user -- in a fenced
#       ```bash example or backtick-quoted in prose -- must resolve to a real
#       dispatch arm. Checked at both words: the top-level verb against
#       src/lib.rs, and, for the commands that have their own sub-verbs
#       (config/override/audit), the second word against the file that
#       actually dispatches it -- a one-word check alone would pass
#       "omamori config bogus-verb" as long as "config" itself is real.
faq_fail=0
faq=docs/FAQ.md
if [ ! -f "$faq" ]; then
    echo "FAIL [invariant faq-doc-sync/#328]: $faq is missing"
    faq_fail=1
else
    # (a) SECURITY.md anchors, regenerated with GitHub's anchor rules:
    # lowercase, strip everything but [a-z0-9 _-], spaces -> hyphens.
    # LC_ALL=C forces byte-mode processing (a plain multi-byte tr/sed would
    # otherwise mangle the em dash differently); in byte mode, the em dash's
    # bytes are simply stripped by the character class, which matches
    # GitHub's own behavior for "Not caught — by design": the em dash
    # vanishes and its surrounding spaces each become a hyphen ("--").
    # Each extraction is wrapped in `(... || true)`: under this script's
    # global `set -euo pipefail`, a grep matching zero lines exits 1, which
    # would otherwise abort the whole invariants-check script right here
    # instead of reaching the FAIL diagnostics below.
    security_anchors=$( (grep -E '^#+ ' SECURITY.md || true) | sed -E 's/^#+ //' \
        | LC_ALL=C tr '[:upper:]' '[:lower:]' \
        | LC_ALL=C sed 's/[^a-z0-9 _-]//g; s/ /-/g')
    faq_anchors=$( (grep -oE 'SECURITY\.md#[a-z0-9_-]+' "$faq" || true) | sed 's/.*#//' | sort -u)
    for a in $faq_anchors; do
        if ! printf '%s\n' "$security_anchors" | grep -qxF "$a"; then
            echo "FAIL [invariant faq-doc-sync/#328]: FAQ references SECURITY.md#$a but no heading generates that anchor"
            faq_fail=1
        fi
    done

    # (b) omamori subcommand references. check_omamori_ref verifies `top` is
    # a real src/lib.rs dispatch arm and, if `sub` is non-empty, that `sub`
    # is a real dispatch arm in whichever file handles `top`'s own sub-verbs.
    # A top-level command with no entry in the case below fails loudly on a
    # two-word reference instead of silently passing -- that's a prompt to
    # extend the case statement, not a bug.
    check_omamori_ref() {
        top=$1
        sub=$2
        if ! grep -qF "Some(\"$top\")" src/lib.rs; then
            echo "FAIL [invariant faq-doc-sync/#328]: FAQ uses 'omamori $top' but src/lib.rs has no such subcommand"
            faq_fail=1
            return
        fi
        [ -z "$sub" ] && return
        case "$top" in
            config|override) subfile="src/cli/config_cmd.rs" ;;
            audit) subfile="src/cli/audit_cmd.rs" ;;
            *) subfile="" ;;
        esac
        if [ -z "$subfile" ]; then
            echo "FAIL [invariant faq-doc-sync/#328]: FAQ uses 'omamori $top $sub' but this invariant doesn't know which file dispatches '$top' sub-verbs -- add '$top' to the case statement in scripts/check-invariants.sh"
            faq_fail=1
        elif ! grep -qF "Some(\"$sub\")" "$subfile"; then
            echo "FAIL [invariant faq-doc-sync/#328]: FAQ uses 'omamori $top $sub' but $subfile has no '$sub' arm"
            faq_fail=1
        fi
    }
    # Extract "<top> [<sub>]" pairs from two places: fenced ```bash examples
    # (fence patterns allow leading whitespace -- blocks nested inside
    # Markdown list items are indented, and an anchored /^```bash/ silently
    # skips them, caught by mutation-testing this invariant) and
    # backtick-quoted mentions in running prose (e.g. "`omamori doctor`"), so
    # a reference isn't invisible to this check just because of where in the
    # doc it happens to be formatted. The second word only counts as a
    # sub-verb candidate if it starts with a letter (`[a-z][a-z-]*`) --
    # excludes flags (`--rule`) and placeholders (`<rule-name>`), which
    # would otherwise be misread as an unknown sub-verb.
    # Both greps are wrapped in `(... || true)` for the same reason as (a):
    # zero matches (e.g. a FAQ with no bash examples, or none in prose) would
    # otherwise make this whole assignment fail under pipefail and abort the
    # script via set -e before either scan's real findings get evaluated.
    faq_pairs=$( { \
        awk '/^[[:space:]]*```bash/{inblock=1; next} /^[[:space:]]*```/{inblock=0} inblock' "$faq" \
            | (grep -oE '(^|[ `(])omamori [a-z][a-z-]*( [a-z][a-z-]*)?' || true) | sed -E 's/.*omamori //'; \
        (grep -oE '`omamori [a-z][a-z-]*( [a-z][a-z-]*)?' "$faq" || true) | sed -E 's/`omamori //'; \
    } | sort -u)
    while IFS= read -r pair; do
        [ -z "$pair" ] && continue
        top=${pair%% *}
        if [ "$top" = "$pair" ]; then
            check_omamori_ref "$top" ""
        else
            check_omamori_ref "$top" "${pair#* }"
        fi
    done <<FAQ_PAIRS_EOF
$faq_pairs
FAQ_PAIRS_EOF
fi
if [ "$faq_fail" -eq 0 ]; then
    # Scope note: this only pins structural references (anchor targets exist,
    # subcommand/sub-verb names exist) -- it does NOT verify semantic claims
    # in the prose (durations, retention counts, "as of version X"). Those
    # still need a human to re-check on future FAQ or behavior changes.
    echo "faq-doc-sync OK: docs/FAQ.md SECURITY.md anchors and omamori subcommand references all resolve (#328)"
else
    fail=1
fi

# ---------- Invariant: contract-doc-sync (#401) ----------
# docs/CONTRACT.md must not rot against SECURITY.md, README.md, and the CLI
# it points into. Mirrors faq-doc-sync above (#328) but is NOT wired through
# check_omamori_ref() -- that function hardcodes `faq_fail=1` and FAQ-specific
# messages, so reusing it here would misattribute a CONTRACT.md failure to
# FAQ.md and silently leave contract_fail unset. check_omamori_ref_contract()
# below duplicates its ~10-line case statement rather than risk touching the
# already-shipped faq-doc-sync code path for the sake of DRY.
#
# Operations: (O1) omamori subcommand resolve, (O2) SECURITY.md anchor
# resolve, (O3) README->CONTRACT link exists, (O4) forbidden-word scan, (O5)
# G-ID uniqueness + sequence completeness, (O6) CONTRACT.md's own
# same-document anchor links resolve -- plus an N1 guard closing a gap the
# mirror source doesn't have to worry about: FAQ.md's non-```bash fences only
# ever hold sample OUTPUT (safe to skip), but CONTRACT.md's Verify blocks are
# commands -- a bare or wrongly-tagged fence would silently hide a real
# command from resolution, so any `omamori ...`-shaped line inside ANY fence
# must live inside a ```bash-tagged one specifically.
contract_fail=0
contract=docs/CONTRACT.md
if [ ! -f "$contract" ]; then
    echo "FAIL [invariant contract-doc-sync/#401]: $contract is missing"
    contract_fail=1
else
    # Shared anchor-generation algorithm for O2 and O6 below -- identical to
    # faq-doc-sync's (a) (GitHub's own rule: lowercase, strip to
    # [a-z0-9 _-], spaces to hyphens, LC_ALL=C byte-mode so em-dashes etc.
    # resolve the same way GitHub resolves them). Extracted into a function
    # here (unlike check_omamori_ref_contract below, which deliberately
    # duplicates rather than touches faq-doc-sync's existing
    # check_omamori_ref) because both call sites are new code introduced by
    # this PR -- there is no already-shipped behavior at risk from sharing it.
    contract_generate_anchors() {
        (grep -E '^#+ ' "$1" || true) | sed -E 's/^#+ //' \
            | LC_ALL=C tr '[:upper:]' '[:lower:]' \
            | LC_ALL=C sed 's/[^a-z0-9 _-]//g; s/ /-/g'
    }

    # (O2) SECURITY.md anchors -- safe to recompute independently since
    # CONTRACT.md is also in docs/ (same ../ depth).
    contract_security_anchors=$(contract_generate_anchors SECURITY.md)
    contract_sec_refs=$( (grep -oE 'SECURITY\.md#[a-z0-9_-]+' "$contract" || true) | sed 's/.*#//' | sort -u)
    for a in $contract_sec_refs; do
        if ! printf '%s\n' "$contract_security_anchors" | grep -qxF "$a"; then
            echo "FAIL [invariant contract-doc-sync/#401]: CONTRACT.md references SECURITY.md#$a but no heading generates that anchor"
            contract_fail=1
        fi
    done

    # (O6) CONTRACT.md's own same-document anchor links (At-a-glance -> G-N
    # headings, breaking-change-policy references, etc.) resolve to a real
    # heading in CONTRACT.md itself. This was flagged as an optional,
    # deferred operation during shape enumeration
    # (plans/vivid-petting-yeti-pr1-shapes.md, N5) and is added for real here
    # because a proxy adversarial test review pointed out the exact failure
    # mode it closes -- rewording a guarantee's heading (as this PR's own G-2
    # fix did, for an unrelated reason) silently breaks the At-a-glance link
    # pointing at its old anchor slug unless a human remembers to update it
    # by hand every time.
    contract_own_anchors=$(contract_generate_anchors "$contract")
    contract_own_refs=$( (grep -oE '\]\(#[a-z0-9_-]+\)' "$contract" || true) | sed -E 's/\]\(#//; s/\)//' | sort -u)
    for a in $contract_own_refs; do
        if ! printf '%s\n' "$contract_own_anchors" | grep -qxF "$a"; then
            echo "FAIL [invariant contract-doc-sync/#401]: CONTRACT.md links to its own #$a but no heading in CONTRACT.md generates that anchor"
            contract_fail=1
        fi
    done

    # (O1) omamori subcommand references, extracted from the same two sites
    # as faq-doc-sync: fenced ```bash blocks (indented fences included via
    # the `[[:space:]]*` prefix) and backtick-quoted prose.
    check_omamori_ref_contract() {
        top=$1
        sub=$2
        if ! grep -qF "Some(\"$top\")" src/lib.rs; then
            echo "FAIL [invariant contract-doc-sync/#401]: CONTRACT.md uses 'omamori $top' but src/lib.rs has no such subcommand"
            contract_fail=1
            return
        fi
        [ -z "$sub" ] && return
        case "$top" in
            config|override) subfile="src/cli/config_cmd.rs" ;;
            audit) subfile="src/cli/audit_cmd.rs" ;;
            *) subfile="" ;;
        esac
        if [ -z "$subfile" ]; then
            echo "FAIL [invariant contract-doc-sync/#401]: CONTRACT.md uses 'omamori $top $sub' but this invariant doesn't know which file dispatches '$top' sub-verbs -- add '$top' to the case statement in scripts/check-invariants.sh"
            contract_fail=1
        elif ! grep -qF "Some(\"$sub\")" "$subfile"; then
            echo "FAIL [invariant contract-doc-sync/#401]: CONTRACT.md uses 'omamori $top $sub' but $subfile has no '$sub' arm"
            contract_fail=1
        fi
    }
    contract_pairs=$( { \
        awk '/^[[:space:]]*```bash/{inblock=1; next} /^[[:space:]]*```/{inblock=0} inblock' "$contract" \
            | (grep -oE '(^|[ `(])omamori [a-z][a-z-]*( [a-z][a-z-]*)?' || true) | sed -E 's/.*omamori //'; \
        (grep -oE '`omamori [a-z][a-z-]*( [a-z][a-z-]*)?' "$contract" || true) | sed -E 's/`omamori //'; \
    } | sort -u)
    while IFS= read -r pair; do
        [ -z "$pair" ] && continue
        top=${pair%% *}
        if [ "$top" = "$pair" ]; then
            check_omamori_ref_contract "$top" ""
        else
            check_omamori_ref_contract "$top" "${pair#* }"
        fi
    done <<CONTRACT_PAIRS_EOF
$contract_pairs
CONTRACT_PAIRS_EOF

    # N1 guard: any fence (of ANY language tag, including bare) that contains
    # an `omamori <verb>`-shaped line must have opened with ```bash
    # specifically -- otherwise that command silently escapes the O1 scan
    # above (mutation-tested below with a deliberately bare-fenced Verify).
    contract_non_bash_fence_hits=$(awk '
        /^[[:space:]]*```/ {
            if (inblock) { inblock=0; next }
            else { inblock=1; lang=$0; sub(/^[[:space:]]*```/, "", lang); next }
        }
        inblock && /omamori [a-z]/ && lang != "bash" { print NR": "$0 }
    ' "$contract")
    if [ -n "$contract_non_bash_fence_hits" ]; then
        echo "FAIL [invariant contract-doc-sync/#401]: $contract has an 'omamori' command inside a fence that is not tagged \`\`\`bash -- Verify blocks must use \`\`\`bash so this invariant can resolve them:"
        echo "$contract_non_bash_fence_hits"
        contract_fail=1
    fi

    # (O3) README -> CONTRACT.md link exists. Reverse polarity from O1/O2
    # (0-match = FAIL here, not success), so this stays inside an `if` rather
    # than using the `(... || true)` idiom -- that idiom exists to stop a
    # 0-match from aborting the script under `set -e`, which `if grep -q`
    # already does safely on its own.
    if grep -qE '\]\(\.?/?docs/CONTRACT\.md([)#]| )' README.md; then
        : # OK: README links to CONTRACT.md
    else
        echo "FAIL [invariant contract-doc-sync/#401]: README.md has no link to docs/CONTRACT.md"
        contract_fail=1
    fi

    # (O4) Forbidden-word scan -- reverse polarity from O1/O2/O3: a MATCH is
    # the failure, so this is a forward `grep -q` with no `|| true` guard.
    # Copying that guard here would be a bug: a clean guarantee document
    # legitimately produces zero matches, and `|| true` exists to stop a
    # 0-match from aborting under pipefail -- there is nothing to protect
    # against in this direction. Newline-normalized first so a forbidden
    # phrase split across a line wrap in a future edit is not missed.
    contract_normalized=$(tr '\n' ' ' < "$contract")
    if printf '%s' "$contract_normalized" | grep -qiE 'complete protection|comprehensive|fully protects|prevents all|blocks all|guarantees safety|tamper-proof'; then
        echo "FAIL [invariant contract-doc-sync/#401]: $contract contains language that reads as an unbounded guarantee (e.g. 'complete protection', 'tamper-proof') -- see issue #401 acceptance criteria"
        contract_fail=1
    fi

    # (O5) G-ID uniqueness -- restricted to definition (heading) sites only.
    # At-a-glance / Authority Map cross-references to the same G-ID are not
    # duplicates; counting every occurrence would false-positive on them.
    contract_dup_ids=$(grep -oE '^#+ G-[0-9]+' "$contract" | sort | uniq -d)
    if [ -n "$contract_dup_ids" ]; then
        echo "FAIL [invariant contract-doc-sync/#401]: duplicate guarantee ID heading(s) in $contract:"
        echo "$contract_dup_ids"
        contract_fail=1
    fi

    # (O5b) G-ID sequence completeness -- catches accidental deletion of a
    # guarantee (e.g. G-4 silently dropped, leaving G-1,G-2,G-3,G-5,G-6) as a
    # gap in the sequence. Deliberately does NOT hardcode a fixed ceiling
    # (e.g. "must be exactly G-1..G-6 forever") -- the breaking-change policy
    # treats adding new coverage as non-breaking, so a legitimate future PR
    # adding G-7 must not need to touch this invariant. Numbers are
    # deduplicated before the contiguity walk so a duplicate already caught
    # above does not also register as a spurious gap.
    #
    # Contiguity alone has a blind spot a proxy adversarial review round
    # caught and this comment documents so it isn't reintroduced: deleting
    # the TRAILING (highest-numbered) guarantee leaves the remaining set
    # perfectly contiguous from 1 (deleting G-6 from G-1..G-6 leaves
    # G-1..G-5, which has no gap) -- contiguity checking cannot distinguish
    # "the list has always ended here" from "the last entry was silently
    # removed". CONTRACT_MIN_GUARANTEE_COUNT below closes that blind spot as
    # a floor, not a ceiling: exceeding it (future additions) never fails.
    # Only bump it when a guarantee is deliberately retired -- itself a
    # breaking change under this contract's own policy, so requiring a
    # conscious edit here at that time is correct, not a maintenance trap.
    contract_min_guarantee_count=6
    contract_g_numbers=$(grep -oE '^#+ G-[0-9]+' "$contract" | grep -oE '[0-9]+' | sort -n -u)
    if [ -z "$contract_g_numbers" ]; then
        echo "FAIL [invariant contract-doc-sync/#401]: $contract has no guarantee (G-N) headings at all"
        contract_fail=1
    else
        contract_expected=1
        contract_gap=""
        for n in $contract_g_numbers; do
            if [ "$n" -ne "$contract_expected" ]; then
                contract_gap="missing G-$contract_expected (next defined is G-$n)"
                break
            fi
            contract_expected=$((contract_expected + 1))
        done
        if [ -n "$contract_gap" ]; then
            echo "FAIL [invariant contract-doc-sync/#401]: guarantee ID sequence has a gap in $contract: $contract_gap"
            contract_fail=1
        fi
        contract_g_count=$(printf '%s\n' "$contract_g_numbers" | wc -l | tr -d ' ')
        if [ "$contract_g_count" -lt "$contract_min_guarantee_count" ]; then
            echo "FAIL [invariant contract-doc-sync/#401]: $contract has only $contract_g_count guarantee(s), expected at least $contract_min_guarantee_count -- a guarantee (possibly the trailing/highest-numbered one) may have been silently deleted. If one was deliberately retired, update contract_min_guarantee_count in this script."
            contract_fail=1
        fi
    fi
fi
if [ "$contract_fail" -eq 0 ]; then
    # Scope note (mirrors faq-doc-sync's 1c above): this only pins structural
    # references -- SECURITY.md anchor targets exist, CONTRACT.md's own
    # same-document anchor targets exist, subcommand/sub-verb names exist,
    # README links to CONTRACT.md, no forbidden phrase, G-IDs unique and
    # gap-free. It does NOT verify: prose semantics (effective date, version
    # ranges, revision-log accuracy, whether a guarantee's wording still
    # matches actual behavior), or that CONTRACT.md's own links INTO
    # README.md resolve to real README anchors (a deliberately accepted
    # scope limit -- extending anchor resolution to README.md as well as
    # SECURITY.md was considered and rejected during shape enumeration to
    # avoid growing this invariant's scope further). Those still need a
    # human to re-check on future CONTRACT.md changes.
    echo "contract-doc-sync OK: docs/CONTRACT.md SECURITY.md anchors, CONTRACT.md's own anchors, omamori subcommand references, README link, forbidden-word scan, and G-ID uniqueness/completeness all pass (#401)"
else
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "invariants-check: FAIL"
    exit 1
fi

echo
echo "invariants-check: OK"
