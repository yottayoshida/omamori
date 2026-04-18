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
    if grep -qF '#[cfg(target_os' "$hi"; then
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
    if ! grep -qF 'pub fn render_hook_script' "$ih"; then
        echo "FAIL [invariant #7b]: render_hook_script function must exist in $ih"
        ih_fail=1
    fi
    if ! grep -qF 'cat | omamori hook-check' "$ih"; then
        echo "FAIL [invariant #7c]: render_hook_script must pipe stdin through omamori hook-check"
        ih_fail=1
    fi
    if ! grep -qF 'set -eu' "$ih"; then
        echo "FAIL [invariant #7d]: render_hook_script must use set -eu"
        ih_fail=1
    fi
    if ! grep -qF 'exit $?' "$ih"; then
        echo "FAIL [invariant #7e]: render_hook_script must propagate exit code via exit \$?"
        ih_fail=1
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
    for path in "${required_owners[@]}"; do
        if ! grep -qF "$path" "$co"; then
            echo "FAIL [invariant #8]: $co must include explicit owner for $path"
            co_fail=1
        fi
    done
fi
if [ "$co_fail" -eq 0 ]; then
    echo "#8 OK: CODEOWNERS includes required explicit paths"
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
