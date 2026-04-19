#!/usr/bin/env bash
# check-crate-contents.sh
#
# Defense-in-depth layer over Cargo.toml `include = [...]` allowlist. Runs
# `cargo package --list --locked` and verifies the output is a subset of a
# known-good allowlist. Also rejects binary-looking files.
#
# Role: even with cargo's own `include =` as the primary structural
# defense, a future PR could widen the allowlist (e.g. `"**"`). This
# guard is the circuit breaker. It is intentionally strict — any path
# that is not *explicitly* expected fails the build, not just paths on
# the old denylist.
#
# The --allow-dirty is intentional when invoked from CI (the checkout
# tree is always clean) but kept so the script is runnable mid-edit
# locally.

set -euo pipefail
# pipefail is essential: a broken `cargo package --list` must not silently
# become an empty list that then "passes" a subset check.
set -o pipefail

cd "$(dirname "$0")/.."

# Exact filenames that are always OK to ship.
# Cargo.toml.orig and .cargo_vcs_info.json are cargo-generated.
ALLOWED_EXACT=(
    ".cargo_vcs_info.json"
    "Cargo.toml"
    "Cargo.toml.orig"
    "Cargo.lock"
    "README.md"
    "CHANGELOG.md"
    "SECURITY.md"
    "LICENSE-MIT"
    "LICENSE-APACHE"
    "config.default.toml"
)

# Path patterns (bash regex) for whole subtrees that are OK.
# Deliberately narrow — no `.*` at the root; every entry anchors a specific
# directory that belongs in a published crate.
ALLOWED_PATTERNS=(
    '^src/[A-Za-z0-9_/-]+\.rs$'
    '^tests/[A-Za-z0-9_/-]+\.rs$'
)

# Capture ONLY stdout — cargo writes progress (`Updating crates.io index`,
# `Compiling ...`) to stderr, and mixing it in makes those lines look like
# package paths to the allowlist check.
if ! list_out="$(cargo package --list --locked --allow-dirty)"; then
    echo "ERROR: cargo package --list failed"
    exit 1
fi

# Read package list into an array. Avoid `mapfile` / `readarray` because
# macOS ships bash 3.2 which lacks them; a plain while/read loop via
# process substitution is fail-closed for us (set -e is in effect).
pkg_files=()
while IFS= read -r line; do
    [ -z "$line" ] && continue
    pkg_files+=("$line")
done < <(printf '%s\n' "$list_out")

if [ "${#pkg_files[@]}" -eq 0 ]; then
    echo "ERROR: cargo package --list returned empty output — refusing to pass"
    exit 1
fi

fail=0

is_allowed() {
    local f="$1"
    for a in "${ALLOWED_EXACT[@]}"; do
        [ "$f" = "$a" ] && return 0
    done
    for p in "${ALLOWED_PATTERNS[@]}"; do
        if [[ "$f" =~ $p ]]; then
            return 0
        fi
    done
    return 1
}

unexpected=()
for f in "${pkg_files[@]}"; do
    [ -z "$f" ] && continue
    if ! is_allowed "$f"; then
        unexpected+=("$f")
        fail=1
    fi
done

if [ "${#unexpected[@]}" -gt 0 ]; then
    echo "FAIL: unexpected paths in crate tarball (not in allowlist):"
    for f in "${unexpected[@]}"; do
        echo "  $f"
    done
fi

# Binary-file detection. For each file in the package that is a regular
# file on disk, assert its MIME type is text/* (or cargo-generated json).
#
# Files with known-text extensions listed in the allowlist above are trusted
# without MIME re-check: `file --mime` heuristics are OS-specific and on some
# Linux distributions label markdown-heavy documents (heavy on URLs and code
# fences) as `application/javascript`. The structural defense (Cargo.toml
# `include=` allowlist + ALLOWED_EXACT / ALLOWED_PATTERNS above) already
# bounds what reaches this step; redundant MIME magic should not block a
# release over a downstream `file(1)` quirk.
for f in "${pkg_files[@]}"; do
    [ -z "$f" ] && continue
    case "$f" in
        Cargo.toml.orig|.cargo_vcs_info.json) continue ;;
        *.md|*.toml|*.lock|LICENSE-*|config.default.toml) continue ;;
    esac
    [ -f "$f" ] || continue
    mime="$(file --brief --mime "$f" 2>/dev/null || true)"
    if [ -z "$mime" ]; then
        echo "ERROR: could not determine MIME type for $f — refusing to pass"
        fail=1
        continue
    fi
    case "$mime" in
        text/*|inode/x-empty*|application/json*) : ;;
        *)
            echo "FAIL: binary-looking file in crate: $f ($mime)"
            fail=1
            ;;
    esac
done

if [ "$fail" -ne 0 ]; then
    echo
    echo "crate-contents-guard: FAIL"
    exit 1
fi

echo "crate-contents-guard: OK"
echo
echo "=== tarball contents (${#pkg_files[@]} files) ==="
printf '%s\n' "${pkg_files[@]}"
