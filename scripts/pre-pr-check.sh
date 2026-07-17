#!/usr/bin/env bash
# Local gate run before opening a PR.
# Mirrors the CI jobs most likely to catch a broken change quickly, with
# `--locked` on every cargo invocation so a stale Cargo.lock fails here
# instead of in CI. Not a full mirror of every CI job (proptest-deep,
# bench-compile, MSRV, coverage, publish-dry-run are CI-only) — this is the
# fast local pass, not a CI replacement.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "==> cargo clippy --all-targets --all-features --locked -- -D warnings"
cargo clippy --all-targets --all-features --locked -- -D warnings

echo "==> check-invariants.sh"
./scripts/check-invariants.sh

echo "==> verify-claims.sh"
./scripts/verify-claims.sh
./scripts/verify-claims.sh --self-test

echo "==> test-isolation-canary --self-test"
./scripts/test-isolation-canary.sh --self-test

echo "==> cargo test --all-features --locked (via test-isolation-canary)"
./scripts/test-isolation-canary.sh -- cargo test --all-features --locked

echo
echo "pre-pr-check: OK"
