#!/usr/bin/env bash
# Local gate run before opening a PR.
# Mirrors the CI jobs, with `--locked` on every cargo invocation so a stale
# Cargo.lock fails here instead of in CI.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "==> cargo clippy --all-targets --all-features --locked -- -D warnings"
cargo clippy --all-targets --all-features --locked -- -D warnings

echo "==> test-isolation-canary --self-test"
./scripts/test-isolation-canary.sh --self-test

echo "==> cargo test --all-features --locked (via test-isolation-canary)"
./scripts/test-isolation-canary.sh -- cargo test --all-features --locked

echo
echo "pre-pr-check: OK"
