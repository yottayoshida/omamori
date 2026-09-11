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
#   Before any of that, omamori's own PATH shim directories are removed from
#   PATH for the whole run (#526) — see strip_omamori_shim_dirs below. On a
#   host with omamori installed, a test that spawns `git` through PATH
#   otherwise runs the *installed* omamori, and its shim self-heal writes the
#   throwaway sentinel: a red that is not about any test.
#
# A nonzero exit from the wrapped command does not short-circuit the
# comparison — a test that both fails AND corrupts real files must still
# have the corruption reported, not just look like an ordinary failure.
#
# --self-test proves the detection logic actually fires, rather than
# vacuously always passing — and that it fires for the RIGHT reason. Passes
# 1 and 2 each corrupt exactly one throwaway sentinel (.claude, then
# .codex), and assert that pass reports exactly that one violation and no
# others. Asserting "some check failed" alone
# would not catch e.g. an inverted comparison operator in check() — that
# mutation flips ALL untouched sentinels to "failed" while silently
# clearing the one that actually changed, and a bare fail-count check
# would still see a nonzero count and wrongly call it correct. This must
# run as a permanent CI step on every invocation — a one-off manual check
# would prove nothing once removed.
#
# Passes 3-5 (#526) cover the PATH step. Each re-runs this script in
# normal mode with a fake dir prepended to PATH, built by the same helper.
# Pass 3 (a dir named `shim` whose `git` links to `omamori`) must come back
# clean, with that dir named as removed. Pass 4 (`shim`, linking to
# `not-omamori`) and pass 5 (a dir named `bin`, linking to `omamori`) must
# each report exactly the .claude sentinel — the look-alikes stay on PATH.
# Passes 4 and 5 are what make pass 3 mean something: a fake that never
# wrote, or never reached PATH, would pass pass 3 just the same. They are
# judged on the FAIL labels, not the exit code — a wrapped command's own
# failure also exits 1 — and on the final line blaming a test. Pass 6 runs
# the child with HOME pointed at a fake "real" home and has the wrapped
# command write that home's settings.json by absolute path: only a real
# file changes, and the final line must say so rather than blame a test.
# Passes 4-6 are what pin failure_verdict at its call site, not just in
# isolation.
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
#   - PATH is cleaned of omamori's shim dirs only (#526). Any other tool on
#     the host's PATH that writes under $HOME is still the host's doing —
#     including omamori reached through a hand-made link in a directory not
#     named `shim` (e.g. `~/bin/git -> omamori`): it acts as a shim from
#     argv[0] alone. `omamori install`/`setup` never create that shape.
#   - A change to a *real* file cannot be attributed: a test that bypassed
#     HOME/XDG_* and another process on the host (an omamori shim run by
#     another session, say) look the same. The final line says so rather
#     than blaming a test — see failure_verdict.

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

# The command names `omamori install` links into its shim dir. Kept in sync
# with `SHIM_COMMANDS` in src/installer.rs — the self-test compares the two.
SHIMMED_COMMANDS="rm git chmod find rsync"

# A PATH entry is omamori's shim dir when it is an absolute path named
# `shim` (`omamori install` always uses `<base_dir>/shim`, `--base-dir`
# included) and one of those names in it is a symlink whose target's
# basename is `omamori`. The same test as `installer::shim_to_real_exe`,
# except that it follows one `readlink` hop — how `omamori install` creates
# them — rather than canonicalizing. The name condition keeps a directory
# like `~/bin`, which happens to hold one hand-made link to omamori, on PATH
# along with everything else in it.
is_omamori_shim_dir() {
    local dir="${1%/}" cmd target
    case "$dir" in
    /*/shim | /shim) ;;
    *) return 1 ;;
    esac
    for cmd in $SHIMMED_COMMANDS; do
        [ -L "$dir/$cmd" ] || continue
        target="$(readlink "$dir/$cmd")" || continue
        if [ "$(basename "$target")" = "omamori" ]; then
            return 0
        fi
    done
    return 1
}

# #526: remove every occurrence of an omamori shim dir from PATH, for this
# script and everything it runs. Tests that spawn `git` through PATH
# (src/context.rs's, and the production code they call) otherwise run the
# installed omamori, whose shim self-heal merges a hook entry into
# $HOME/.claude/settings.json — the throwaway's, under this script. A CI
# runner has no shim, so the red only ever appeared locally. This also sends
# this script's own `rm -rf` of the throwaway to the real `rm` rather than to
# the installed shim's trash action.
#
# Split by hand rather than with `IFS=: read -a`, which drops a trailing
# empty entry; empty and relative entries are kept exactly as they are
# (each kept entry is prefixed with one `:`, and the first is dropped).
REMOVED_SHIM_DIRS=""
strip_omamori_shim_dirs() {
    local rest="$PATH:" entry out=""
    while [ -n "$rest" ]; do
        entry="${rest%%:*}"
        rest="${rest#*:}"
        if is_omamori_shim_dir "$entry"; then
            REMOVED_SHIM_DIRS="${REMOVED_SHIM_DIRS:+$REMOVED_SHIM_DIRS }$entry"
            continue
        fi
        out="$out:$entry"
    done
    PATH="${out#:}"
}

strip_omamori_shim_dirs
echo "==> omamori shim dirs removed from PATH for this run: ${REMOVED_SHIM_DIRS:-(none)}"

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
CURRENT_FAKE=""
cleanup() {
    if [ -n "$CURRENT_THROWAWAY" ]; then
        rm -rf "$CURRENT_THROWAWAY"
    fi
    if [ -n "$CURRENT_FAKE" ]; then
        rm -rf "$CURRENT_FAKE"
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

# The line a failing run ends with. "A test wrote" is only claimed when a
# throwaway sentinel changed: nothing but this script's descendants has that
# HOME. When only a real file changed, the writer may be a test that
# bypassed HOME/XDG_* — or any other process on this host, such as an
# omamori shim run by another session re-merging settings.json after an
# upgrade, which removing shim dirs from *this* PATH cannot reach (#526).
failure_verdict() {
    case "$1" in
    *throwaway*)
        echo "test-isolation-canary: FAIL — a test wrote outside its own isolated_home()/with_test_home() override."
        echo "See tests/integration.rs::isolated_home() / src/installer.rs::with_test_home() for the required pattern."
        ;;
    *)
        echo "test-isolation-canary: FAIL — a real file changed during the run while every throwaway sentinel stayed intact."
        echo "Either a test bypassed HOME/XDG_* (e.g. a hardcoded absolute path) or another process on this host wrote it; rerun to tell them apart."
        ;;
    esac
}

if [ "$MODE" = "self-test" ]; then
    self_test_fail=0

    echo "--- self-test pass 1/6: corrupt throwaway .claude sentinel only ---"
    one_pass claude
    expected="
throwaway \$HOME/.claude/settings.json sentinel"
    if [ "$PASS_FAILED_LABELS" != "$expected" ]; then
        echo "test-isolation-canary --self-test: FAIL — expected exactly one violation (.claude sentinel), got:${PASS_FAILED_LABELS:-\"(none)\"}"
        self_test_fail=1
    fi

    echo "--- self-test pass 2/6: corrupt throwaway .codex sentinel only ---"
    one_pass codex
    expected="
throwaway \$HOME/.codex/hooks.json sentinel"
    if [ "$PASS_FAILED_LABELS" != "$expected" ]; then
        echo "test-isolation-canary --self-test: FAIL — expected exactly one violation (.codex sentinel), got:${PASS_FAILED_LABELS:-\"(none)\"}"
        self_test_fail=1
    fi

    # make_fake_shim_dir <target-name> [dir-name]: a dir named <dir-name>
    # (default `shim`; FAKE_SHIM) holding `git` as a symlink to a script
    # named <target-name>, which writes the .claude sentinel and exits 0.
    # It writes only when HOME is a canary throwaway, so a mutation that
    # stops this script from removing it cannot reach the real
    # $HOME/.claude/settings.json. `git`, not `rm`: this script never runs
    # `git`, but its cleanup runs `rm` under the real HOME.
    make_fake_shim_dir() {
        CURRENT_FAKE="$(mktemp -d "$HOME/omamori-canary-fake-XXXXXX")"
        FAKE_SHIM="$CURRENT_FAKE/${2:-shim}"
        mkdir "$CURRENT_FAKE/impl" "$FAKE_SHIM"
        cat >"$CURRENT_FAKE/impl/$1" <<'FAKE'
#!/bin/sh
case "$HOME" in
*/omamori-canary-*) printf '%s' '{"written_by_fake_shim": true}' >"$HOME/.claude/settings.json" ;;
esac
exit 0
FAKE
        chmod +x "$CURRENT_FAKE/impl/$1"
        ln -s "$CURRENT_FAKE/impl/$1" "$FAKE_SHIM/git"
    }

    # run_child_with_fake: re-run this script in normal mode, fake dir first
    # on PATH, wrapping `git --version`. Absolute path because `cd` above
    # makes a relative $0 unreachable.
    run_child_with_fake() {
        CHILD_STATUS=0
        CHILD_OUT="$(PATH="$FAKE_SHIM:$PATH" "$REPO_ROOT/scripts/test-isolation-canary.sh" -- git --version 2>&1)" || CHILD_STATUS=$?
    }

    drop_fake() {
        rm -rf "$CURRENT_FAKE"
        CURRENT_FAKE=""
    }

    # assert_child_blames_test <pass>: the child reported exactly the .claude
    # sentinel, and its final line (failure_verdict at its call site) blamed
    # a test.
    assert_child_blames_test() {
        local labels
        labels="$(sed -n 's/^FAIL: \(.*\) changed$/\1/p' <<<"$CHILD_OUT")"
        if [ "$labels" != "throwaway \$HOME/.claude/settings.json sentinel" ] || ! grep -q 'a test wrote outside' <<<"$CHILD_OUT"; then
            echo "test-isolation-canary --self-test: FAIL — pass $1 expected exactly one violation (.claude sentinel) blamed on a test, got exit $CHILD_STATUS:"
            printf '%s\n' "$CHILD_OUT"
            self_test_fail=1
        fi
    }

    echo "--- self-test pass 3/6: an omamori shim dir on PATH is removed before the wrapped command runs ---"
    make_fake_shim_dir omamori
    run_child_with_fake
    removed_line="$(sed -n 's/^==> omamori shim dirs removed from PATH for this run: //p' <<<"$CHILD_OUT")"
    case " $removed_line " in
    *" $FAKE_SHIM "*) removed_fake=1 ;;
    *) removed_fake=0 ;;
    esac
    if [ "$CHILD_STATUS" -ne 0 ] || grep -q '^FAIL: ' <<<"$CHILD_OUT" || [ "$removed_fake" -ne 1 ]; then
        echo "test-isolation-canary --self-test: FAIL — pass 3 expected exit 0, no violation, and $FAKE_SHIM named as removed; got exit $CHILD_STATUS:"
        printf '%s\n' "$CHILD_OUT"
        self_test_fail=1
    fi
    drop_fake

    echo "--- self-test pass 4/6: a look-alike dir whose symlink is not omamori stays on PATH ---"
    make_fake_shim_dir not-omamori
    run_child_with_fake
    assert_child_blames_test 4
    drop_fake

    echo "--- self-test pass 5/6: a dir not named shim stays on PATH even when its git links to omamori ---"
    make_fake_shim_dir omamori bin
    run_child_with_fake
    assert_child_blames_test 5
    drop_fake

    echo "--- self-test pass 6/6: a change to a real file alone is not blamed on a test ---"
    # The child's "real" home is a fake one inside CURRENT_FAKE, so the
    # real-file branch of the final line is reached without touching the
    # real $HOME. The wrapped command writes that home's settings.json by
    # absolute path — the one thing a HOME-isolated test cannot do by
    # accident and another process on the host can.
    CURRENT_FAKE="$(mktemp -d "$HOME/omamori-canary-fake-XXXXXX")"
    mkdir -p "$CURRENT_FAKE/home/.claude"
    printf '%s' '{}' >"$CURRENT_FAKE/home/.claude/settings.json"
    CHILD_STATUS=0
    # shellcheck disable=SC2016 # "$1" is the inner sh's argument, not ours
    CHILD_OUT="$(HOME="$CURRENT_FAKE/home" "$REPO_ROOT/scripts/test-isolation-canary.sh" -- \
        sh -c 'printf changed >"$1"' sh "$CURRENT_FAKE/home/.claude/settings.json" 2>&1)" || CHILD_STATUS=$?
    labels="$(sed -n 's/^FAIL: \(.*\) changed$/\1/p' <<<"$CHILD_OUT")"
    if [ "$labels" != "real \$HOME/.claude/settings.json (no-clobber)" ] \
        || ! grep -q 'a real file changed' <<<"$CHILD_OUT" \
        || grep -q 'a test wrote outside' <<<"$CHILD_OUT"; then
        echo "test-isolation-canary --self-test: FAIL — pass 6 expected only the real .claude file, reported as a real-file change, got exit $CHILD_STATUS:"
        printf '%s\n' "$CHILD_OUT"
        self_test_fail=1
    fi
    drop_fake

    # Passes 4-6 pin both branches of failure_verdict at its call site. The
    # one mix they do not reach — a throwaway sentinel and a real file both
    # changed — is still a test's doing, since only a descendant has the
    # throwaway HOME.
    echo "--- self-test: a throwaway and a real file both changing is blamed on a test ---"
    verdict_mixed="$(failure_verdict "
throwaway \$HOME/.claude/settings.json sentinel
real \$HOME/.claude/settings.json (no-clobber)")"
    case "$verdict_mixed" in
    *"a test wrote outside"*) ;;
    *)
        echo "test-isolation-canary --self-test: FAIL — a throwaway sentinel change must be attributed to a test even alongside a real one, got: $verdict_mixed"
        self_test_fail=1
        ;;
    esac

    echo "--- self-test: shimmed command list matches src/installer.rs ---"
    installer_list="$(sed -n 's/^pub const SHIM_COMMANDS: &\[&str\] = &\[\(.*\)\];$/\1/p' "$REPO_ROOT/src/installer.rs" | tr -d '" ')"
    script_list="$(printf '%s' "$SHIMMED_COMMANDS" | tr ' ' ',')"
    if [ "$installer_list" != "$script_list" ]; then
        echo "test-isolation-canary --self-test: FAIL — SHIMMED_COMMANDS ($script_list) differs from src/installer.rs SHIM_COMMANDS (${installer_list:-not found})"
        self_test_fail=1
    fi

    if [ "$self_test_fail" -ne 0 ]; then
        exit 1
    fi
    echo "test-isolation-canary --self-test: OK (each sentinel independently detected, no false positives; omamori shim dirs removed from PATH, look-alikes kept)"
    exit 0
fi

one_pass none "$@"

if [ "$PASS_FAIL" -ne 0 ]; then
    echo
    failure_verdict "$PASS_FAILED_LABELS"
    exit 1
fi

if [ "$PASS_CMD_STATUS" -ne 0 ]; then
    echo
    echo "test-isolation-canary: isolation OK, but the wrapped command failed (exit $PASS_CMD_STATUS)."
    exit "$PASS_CMD_STATUS"
fi

echo "test-isolation-canary: OK"
