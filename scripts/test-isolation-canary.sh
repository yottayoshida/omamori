#!/usr/bin/env bash
# test-isolation-canary.sh (#356)
#
# Detects test-suite writes that escape onto the developer's/CI runner's
# REAL ~/.claude, ~/.codex, or this repo's local ./.claude — the exact
# incident class from #210 (cargo test corrupted the maintainer's real
# ~/.claude/settings.json twice, 2026-07-04/05). Individual tests are
# already isolated via isolated_home() (tests/integration.rs) or
# with_test_home()/HomeGuard (src/installer.rs), but this canary is a
# suite-level backstop against a FUTURE test that forgets either pattern.
#
# Usage:
#   scripts/test-isolation-canary.sh -- <test command...>
#   scripts/test-isolation-canary.sh --self-test
#
# How the normal mode works:
#   1. Snapshot the REAL $HOME/.claude/settings.json, $HOME/.codex/hooks.json,
#      and this repo's local ./.claude/settings.json, if they exist. Never
#      created if absent (no-clobber) — only read.
#   2. Create a fresh throwaway HOME under $HOME (never system temp_dir() —
#      that path prefix is blocked by omamori's own hook; see CLAUDE.md),
#      seeded with sentinel .claude/settings.json and .codex/hooks.json.
#   3. Run the given test command with HOME/XDG_CONFIG_HOME/XDG_DATA_HOME/
#      XDG_CACHE_HOME all pointed at the throwaway dir. Any test that reads
#      the ambient HOME without its own per-test override lands here, not
#      on the real machine running this script.
#   4. Compare: (a) the throwaway sentinels must be byte-identical to their
#      pre-run seed — nothing wrote into them outside a per-test override;
#      (b) the real $HOME/.claude, $HOME/.codex, and ./.claude snapshots
#      from step 1 must also be unchanged (defense-in-depth: confirms
#      nothing leaked past the HOME override at all).
#
# A nonzero exit from the wrapped command does not short-circuit the
# comparison — a test that both fails AND corrupts real files must still
# have the corruption reported, not just look like an ordinary failure.
#
# --self-test proves the detection logic actually fires, rather than
# vacuously always passing — and that it fires for the RIGHT reason. It
# runs two independent passes, each corrupting exactly one throwaway
# sentinel (.claude, then .codex), and asserts that pass reports exactly
# that one violation and no others. Asserting "some check failed" alone
# would not catch e.g. an inverted comparison operator in check() — that
# mutation flips ALL untouched sentinels to "failed" while silently
# clearing the one that actually changed, and a bare fail-count check
# would still see a nonzero count and wrongly call it correct. This must
# run as a permanent CI step on every invocation — a one-off manual check
# would prove nothing once removed.
#
# Known limitations (documented in ADR-0002, not fixed here):
#   - Only catches writes that resolve through HOME/XDG_* env vars. A test
#     that hardcodes an absolute path outside these would not be caught.
#   - A test that deletes a sentinel and recreates byte-identical content
#     would not be caught (content is compared, not mtime).
#   - Only settings.json/hooks.json are sentineled — a test that creates a
#     new, different file under $HOME/.claude or $HOME/.codex without
#     touching the sentinel would not be caught. XDG_CONFIG_HOME/
#     XDG_DATA_HOME/XDG_CACHE_HOME are isolated to the throwaway dir (so a
#     leak there can't reach the real environment) but have no sentinel of
#     their own — this canary's detection scope is #210's exact incident
#     class (~/.claude, ~/.codex, repo ./.claude), not a general sandbox.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

MODE="run"
if [ "${1:-}" = "--self-test" ]; then
    MODE="self-test"
elif [ "${1:-}" = "--" ]; then
    shift
else
    echo "usage: $0 -- <test command...>" >&2
    echo "       $0 --self-test" >&2
    exit 2
fi

if [ "$MODE" = "run" ] && [ "$#" -eq 0 ]; then
    echo "usage: $0 -- <test command...>" >&2
    exit 2
fi

SENTINEL_CONTENT='{"__omamori_canary_sentinel__": true}'

real_claude_settings="$HOME/.claude/settings.json"
real_codex_hooks="$HOME/.codex/hooks.json"
repo_local_claude_settings="$REPO_ROOT/.claude/settings.json"

snapshot() {
    # Prints a checksum of the file's content, or the literal string
    # "__absent__" if the file does not exist — so "did not exist before"
    # vs "existed and changed" are both distinguishable in the comparison.
    if [ -f "$1" ]; then
        cksum <"$1"
    else
        echo "__absent__"
    fi
}

CURRENT_THROWAWAY=""
cleanup() {
    if [ -n "$CURRENT_THROWAWAY" ]; then
        rm -rf "$CURRENT_THROWAWAY"
    fi
}
trap cleanup EXIT

# one_pass <corrupt-target: none|claude|codex> [cmd...]
#
# Runs one full canary pass: snapshot the real no-clobber paths, create a
# fresh throwaway HOME with sentinels, either corrupt one sentinel directly
# (self-test) or run the given command under the throwaway HOME/XDG_* env
# (normal mode), then compare. Sets PASS_FAIL (0/1), PASS_CMD_STATUS (exit
# code of the wrapped command, 0 in self-test mode), and PASS_FAILED_LABELS
# (newline-joined list of check() labels that reported a change).
one_pass() {
    local corrupt_target="$1"
    shift || true

    local before_real_claude before_real_codex before_repo_claude
    before_real_claude="$(snapshot "$real_claude_settings")"
    before_real_codex="$(snapshot "$real_codex_hooks")"
    before_repo_claude="$(snapshot "$repo_local_claude_settings")"

    CURRENT_THROWAWAY="$(mktemp -d "$HOME/omamori-canary-XXXXXX")"
    local throwaway="$CURRENT_THROWAWAY"
    mkdir -p "$throwaway/.claude" "$throwaway/.codex"
    mkdir -p "$throwaway/.config" "$throwaway/.local/share" "$throwaway/.cache"
    printf '%s' "$SENTINEL_CONTENT" >"$throwaway/.claude/settings.json"
    printf '%s' "$SENTINEL_CONTENT" >"$throwaway/.codex/hooks.json"

    local before_tw_claude before_tw_codex
    before_tw_claude="$(snapshot "$throwaway/.claude/settings.json")"
    before_tw_codex="$(snapshot "$throwaway/.codex/hooks.json")"

    PASS_CMD_STATUS=0
    case "$corrupt_target" in
    claude)
        echo '{"corrupted": true}' >"$throwaway/.claude/settings.json"
        ;;
    codex)
        echo '{"corrupted": true}' >"$throwaway/.codex/hooks.json"
        ;;
    none)
        echo "==> Running: $* (HOME=$throwaway, isolation canary active)"
        # Pin CARGO_HOME/RUSTUP_HOME to their real, pre-swap locations
        # (defaulting to the ORIGINAL $HOME, captured before we overwrite
        # it below) before swapping HOME. rustup-managed cargo installs
        # (GitHub Actions runners) resolve the active toolchain and the
        # dependency/registry cache from these two vars, defaulting to
        # $HOME/.rustup and $HOME/.cargo when unset. Swapping HOME to an
        # empty throwaway dir without pinning them would make the wrapped
        # cargo invocation think no toolchain is installed at all —
        # forcing a cold reinstall (or a hard failure) and bypassing
        # setup-rust-toolchain's cache entirely. Homebrew-installed cargo
        # (a standalone binary, not a rustup proxy) is unaffected either
        # way, which is why this does not surface when testing locally.
        set +e
        CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
            RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
            HOME="$throwaway" \
            XDG_CONFIG_HOME="$throwaway/.config" \
            XDG_DATA_HOME="$throwaway/.local/share" \
            XDG_CACHE_HOME="$throwaway/.cache" \
            "$@"
        PASS_CMD_STATUS=$?
        set -e
        ;;
    esac

    PASS_FAIL=0
    PASS_FAILED_LABELS=""
    check() {
        local label="$1" before="$2" after="$3"
        if [ "$before" != "$after" ]; then
            echo "FAIL: $label changed"
            echo "  before: $before"
            echo "  after:  $after"
            PASS_FAIL=1
            PASS_FAILED_LABELS="${PASS_FAILED_LABELS}
${label}"
        fi
    }

    check "throwaway \$HOME/.claude/settings.json sentinel" \
        "$before_tw_claude" "$(snapshot "$throwaway/.claude/settings.json")"
    check "throwaway \$HOME/.codex/hooks.json sentinel" \
        "$before_tw_codex" "$(snapshot "$throwaway/.codex/hooks.json")"
    check "real \$HOME/.claude/settings.json (no-clobber)" \
        "$before_real_claude" "$(snapshot "$real_claude_settings")"
    check "real \$HOME/.codex/hooks.json (no-clobber)" \
        "$before_real_codex" "$(snapshot "$real_codex_hooks")"
    check "repo-local ./.claude/settings.json (no-clobber)" \
        "$before_repo_claude" "$(snapshot "$repo_local_claude_settings")"

    rm -rf "$throwaway"
    CURRENT_THROWAWAY=""
}

if [ "$MODE" = "self-test" ]; then
    self_test_fail=0

    echo "--- self-test pass 1/2: corrupt throwaway .claude sentinel only ---"
    one_pass claude
    expected="
throwaway \$HOME/.claude/settings.json sentinel"
    if [ "$PASS_FAILED_LABELS" != "$expected" ]; then
        echo "test-isolation-canary --self-test: FAIL — expected exactly one violation (.claude sentinel), got:${PASS_FAILED_LABELS:-\"(none)\"}"
        self_test_fail=1
    fi

    echo "--- self-test pass 2/2: corrupt throwaway .codex sentinel only ---"
    one_pass codex
    expected="
throwaway \$HOME/.codex/hooks.json sentinel"
    if [ "$PASS_FAILED_LABELS" != "$expected" ]; then
        echo "test-isolation-canary --self-test: FAIL — expected exactly one violation (.codex sentinel), got:${PASS_FAILED_LABELS:-\"(none)\"}"
        self_test_fail=1
    fi

    if [ "$self_test_fail" -ne 0 ]; then
        exit 1
    fi
    echo "test-isolation-canary --self-test: OK (each sentinel independently detected, no false positives)"
    exit 0
fi

one_pass none "$@"

if [ "$PASS_FAIL" -ne 0 ]; then
    echo
    echo "test-isolation-canary: FAIL — a test wrote outside its own isolated_home()/with_test_home() override."
    echo "See tests/integration.rs::isolated_home() / src/installer.rs::with_test_home() for the required pattern."
    exit 1
fi

if [ "$PASS_CMD_STATUS" -ne 0 ]; then
    echo
    echo "test-isolation-canary: isolation OK, but the wrapped command failed (exit $PASS_CMD_STATUS)."
    exit "$PASS_CMD_STATUS"
fi

echo "test-isolation-canary: OK"
