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

if [ "$fail" -ne 0 ]; then
    echo
    echo "invariants-check: FAIL"
    exit 1
fi

echo
echo "invariants-check: OK"
