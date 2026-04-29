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
    # #6f (PR #187 item 3): pin existence of the floor test itself. PR4 (#146
    # scope 4) introduced `corpus_includes_meta_pattern_coverage` to encode
    # the "silent pattern drop must fail the suite" guarantee, but the floor
    # function is itself subject to silent drop — a contributor who deletes
    # the function body passes CI quietly. Pin the function name here so
    # physical removal fails CI before reaching review.
    if ! grep -qF 'fn corpus_includes_meta_pattern_coverage' "$hi"; then
        echo "FAIL [invariant #6f]: PR #146 scope 4 floor test 'fn corpus_includes_meta_pattern_coverage' must be retained — it pins the silent-drop guarantee and is itself subject to silent drop"
        hi_fail=1
    fi
    # #6g (PR #187 item 3): pin the global meta-pattern floor at >= 18.
    # The exact range allows the head count to drift to 23 (PR #187 added
    # 2 DI-9 entries for total 23) without re-flagging this invariant on
    # every legitimate corpus growth. Floor below 18 means tactical drift
    # has eaten the safety margin and this should fail CI.
    if ! grep -qE 'meta_pattern_count >= *(18|19|20|21|22|23)' "$hi"; then
        echo "FAIL [invariant #6g]: meta-pattern global floor 'meta_pattern_count >= 18..23' must be present"
        hi_fail=1
    fi
    # #6h (PR #187 Codex R1 P1): pin the per-category floor map itself.
    # #6f and #6g pin only the global floor; without #6h, a future commit
    # could delete `META_PATTERN_CATEGORY_FLOORS` and its iteration, leaving
    # the global ≥18 floor as the only guard. That re-opens the
    # category-selective drop attack PR #187 item 1 was designed to close.
    # Pin both the const declaration and the iteration site so neither half
    # of the per-category guard can be silently removed.
    if ! grep -qF 'const META_PATTERN_CATEGORY_FLOORS' "$hi"; then
        echo "FAIL [invariant #6h]: PR #187 item 1 per-category floor map 'const META_PATTERN_CATEGORY_FLOORS' must be retained"
        hi_fail=1
    fi
    if ! grep -qF 'for (prefix, floor) in META_PATTERN_CATEGORY_FLOORS' "$hi"; then
        echo "FAIL [invariant #6h]: per-category floor iteration 'for (prefix, floor) in META_PATTERN_CATEGORY_FLOORS' must be retained"
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
        if ! printf '%s\n' "$fn_body" | grep -qF 'cat | omamori hook-check'; then
            echo "FAIL [invariant #7c]: render_hook_script must pipe stdin through omamori hook-check"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'set -eu'; then
            echo "FAIL [invariant #7d]: render_hook_script body must use set -eu"
            ih_fail=1
        fi
        if ! printf '%s\n' "$fn_body" | grep -qF 'exit $?'; then
            echo "FAIL [invariant #7e]: render_hook_script body must propagate exit code via exit \$?"
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

if [ "$fail" -ne 0 ]; then
    echo
    echo "invariants-check: FAIL"
    exit 1
fi

echo
echo "invariants-check: OK"
