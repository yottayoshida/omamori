#!/usr/bin/env bash
# check-lockfile-regressions.sh
#
# Detects direct-dependency version downgrades between a base ref and HEAD.
# Runs in the `lockfile-sanity` CI job and can be run locally before opening
# a PR that touches Cargo.lock.
#
# Rationale: an attacker or a reckless Dependabot rollback could silently
# downgrade a dependency with a known CVE. `--locked` alone will not catch
# this — it cheerfully honors the lockfile even if a direct dep was moved
# backwards. This script compares the resolved version of each direct
# dependency against BASE.
#
# Why cargo metadata (not awk over Cargo.toml/Cargo.lock):
#   - `[dependencies.name]` table-form syntax is correctly parsed.
#   - Same-named crates with different sources/versions in Cargo.lock are
#     disambiguated via the resolve graph (`.pkg` package IDs), not by
#     "first entry wins" grep.
#   - BASE is materialized through `git worktree add` so `cargo metadata`
#     has the full tree it expects (src/, manifests, …), not only Cargo.toml
#     + Cargo.lock.
#
# Bootstrap: if BASE does not yet have Cargo.lock (e.g. the PR that first
# tracks it), the script reports "skipping" and exits 0. Once Cargo.lock is
# in BASE, subsequent PRs are gated.
#
# Usage: check-lockfile-regressions.sh [base-ref]
#   base-ref defaults to origin/main.

set -euo pipefail

BASE="${1:-origin/main}"

cd "$(dirname "$0")/.."

if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
    echo "info: $BASE is not reachable — skipping regression check"
    exit 0
fi

if ! git show "$BASE:Cargo.lock" >/dev/null 2>&1; then
    echo "info: no Cargo.lock at $BASE (bootstrap case) — skipping regression check"
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (preinstalled on GitHub runners)"
    exit 2
fi

# ---------- extract direct-dep (name, version) pairs ----------
# `.resolve.root` is the root package id (single-package crate).
# `resolve.nodes[] | select(.id == $root) | .deps[]` walks the edges from root
# — these are exactly the direct dependencies as resolved by cargo. Each
# `.pkg` is a unique package id like "libc 0.2.183 (registry+...)", so
# duplicate names in the lockfile are not ambiguous here.
direct_deps() {
    # `.pkg` is a PURL-style package id, e.g.
    #   "registry+https://github.com/rust-lang/crates.io-index#hmac@0.12.1"
    # Splitting on "@" and taking the last element yields the version.
    # (Git / path dependencies also suffix "@X.Y.Z" when resolved, so this
    # holds across source types.)
    cargo metadata --locked --format-version 1 \
        | jq -r '
            .resolve.root as $root
            | .resolve.nodes[] | select(.id == $root) | .deps[]
            | "\(.name)\t\(.pkg | split("@") | last)"
        ' \
        | sort -u
}

HEAD_TSV="$(direct_deps)"

BASE_DIR="$(mktemp -d -t omamori-base-lockcheck-XXXXXX)"
cleanup() {
    git worktree remove --force "$BASE_DIR" >/dev/null 2>&1 || true
    rm -rf "$BASE_DIR"
}
trap cleanup EXIT

git worktree add --detach "$BASE_DIR" "$BASE" >/dev/null 2>&1

BASE_TSV="$(cd "$BASE_DIR" && direct_deps)"

# ---------- compare ----------
fail=0
while IFS=$'\t' read -r name head_v; do
    [ -z "$name" ] && continue
    base_v="$(echo "$BASE_TSV" | awk -F'\t' -v n="$name" '$1==n{print $2; exit}')"
    [ -z "$base_v" ] && continue          # new direct dep in HEAD
    [ "$base_v" = "$head_v" ] && continue # unchanged

    lowest="$(printf '%s\n%s\n' "$base_v" "$head_v" | sort -V | head -1)"
    if [ "$lowest" = "$head_v" ]; then
        echo "REGRESSION: $name  $base_v -> $head_v"
        fail=1
    fi
done <<<"$HEAD_TSV"

if [ "$fail" -ne 0 ]; then
    echo
    echo "lockfile-sanity: FAIL (direct-dep downgrade detected)"
    echo "If this was intentional (e.g. security-driven rollback), justify it in the PR description."
    exit 1
fi

echo "lockfile-sanity: OK"
