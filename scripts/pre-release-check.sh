#!/usr/bin/env bash
# Release gate. Run after bumping Cargo.toml + CHANGELOG.md and before
# `git tag` / `cargo publish`. Fails fast on anything that would poison a
# crates.io release.
set -euo pipefail

cd "$(dirname "$0")/.."

FAIL=0
warn()  { echo "WARN:  $*"; }
fail()  { echo "ERROR: $*"; FAIL=1; }

# 1. clean working tree
if [ -n "$(git status --porcelain)" ]; then
    fail "working tree is dirty (run 'git status'); refusing to release"
fi

# 2. Cargo.toml version vs. latest tag (if any)
VERSION="$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "(.*)"/\1/')"
if [ -z "$VERSION" ]; then
    fail "could not read version from Cargo.toml"
else
    echo "Cargo.toml version: $VERSION"
    LATEST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
    if [ -n "$LATEST_TAG" ] && [ "v$VERSION" != "$LATEST_TAG" ]; then
        warn "Cargo.toml is v$VERSION but latest tag is $LATEST_TAG — remember to tag v$VERSION before publishing"
    fi
fi

# 3. package listing: no forbidden files should ship to crates.io.
#
# NOTE (v0.9.3 transition): This is a denylist, which has structural false
# negatives — it only blocks what we thought of. PR5 replaces this with an
# allowlist strategy driven by `Cargo.toml` `include = [...]`, at which point
# this regex becomes a belt-and-suspenders layer over deny-by-default.
# Until then, this list expands to cover governance files that are currently
# tracked but do not belong in the crate tarball.
FORBIDDEN_REGEX='^(\.claude/|investigation/|\.github/|PLAN\.md$|ACCEPTANCE_TEST\.md$|demo\.svg$|CLAUDE\.local\.md$|omamori-test-sandbox/|fuzz/|\.editorconfig$|\.gitattributes$|CONTRIBUTING\.md$|scripts/)'
if ! PKG_LIST="$(cargo package --list --locked 2>&1)"; then
    fail "cargo package --list failed:"
    echo "$PKG_LIST"
else
    if LEAKED="$(echo "$PKG_LIST" | grep -E "$FORBIDDEN_REGEX" || true)"; [ -n "$LEAKED" ]; then
        fail "forbidden paths in package listing:"
        echo "$LEAKED"
    fi
fi

# 4. dry-run publish (uses the same --locked discipline)
echo "==> cargo publish --dry-run --locked"
if ! cargo publish --dry-run --locked; then
    fail "cargo publish --dry-run --locked failed"
fi

if [ "$FAIL" -ne 0 ]; then
    echo
    echo "pre-release-check: FAIL"
    exit 1
fi

echo
echo "pre-release-check: OK"
