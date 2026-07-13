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

if [ "$fail" -ne 0 ]; then
    echo
    echo "invariants-check: FAIL"
    exit 1
fi

echo
echo "invariants-check: OK"
