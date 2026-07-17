#!/usr/bin/env bash
# verify-claims.sh (#403)
#
# README's "Verifiable Claims" table maps 5 rows (claim -> how to verify it)
# 1:1 to CONTRACT.md's G-1..G-5 (G-6 has no README row -- it is a structural
# property, not a push-button-verifiable one, and CONTRACT.md documents that
# directly). This script does NOT re-prove claims 1/2/3/5's behavior --
# regression-vector analysis (see the plan this PR implements) found their
# behavioral regressions are already caught by named cargo tests
# (policy_test.rs, property_tests.rs, config.rs, hook_integration.rs,
# check-invariants.sh's DI-13). Re-testing them here would be a vacuous
# second copy of the same assertion, not a new guarantee -- and if the
# underlying test is ever deleted, both copies vanish together, so the
# "double coverage" would be an illusion. This script's real job is narrower
# and does not overlap those tests:
#
#   M1: the README table's claim-to-verification mapping does not silently
#       rot (row count, CI job existence, G-ID existence, the "Verify
#       yourself" cell text, no `continue-on-error: true`).
#   M2/M3: claim 4 ("no model calls, no network dependency") is the ONE
#       claim with zero existing machine enforcement -- a dependency
#       allowlist tripwire (M2) and a hook-decision-path source-token
#       tripwire (M3) close that gap.
#   M4: the honest-limitation prose for claims 2/3/4 (documented in README's
#       "How these are checked" section) has not been silently deleted.
#   M5: the named cargo tests that "How these are checked" cites as backing
#       claims 1/2/3/5's behavioral regressions still exist and are not
#       `#[ignore]`d -- without this, that prose's claim would itself be
#       unverified.
#
# Modes:
#   scripts/verify-claims.sh              (default: read repo files in place)
#   scripts/verify-claims.sh --self-test   (inverted-control proof: injects
#                                            ONE violation per pass into a
#                                            temp copy and asserts the
#                                            resulting FAIL label is exactly
#                                            the expected one -- never the
#                                            product's own config.toml or
#                                            rules.rs; see the plan's
#                                            "config-immutability" section
#                                            for why that would test nothing)

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

readme=README.md
contract=docs/CONTRACT.md
ci_yml=.github/workflows/ci.yml
lockfile=Cargo.lock
approved_deps=scripts/approved-deps.txt

# M3 production hook-decision-path files (Phase 2 shape-enumeration
# "Additional check A" file set -- all currently 0-match on the token set
# below). Deliberately excludes test-only files; the `#[cfg(test)]`
# exclusion inside each file (extract_production_region below) is
# defense-in-depth for files that mix production code with an inline test
# module, not a substitute for this list.
m3_files="src/engine/hook.rs src/engine/shim.rs src/engine/exec.rs src/engine/guard.rs src/engine/mod.rs src/rules.rs src/unwrap.rs src/config.rs src/detector.rs src/context.rs src/actions.rs src/integrity.rs src/audit/chain.rs src/audit/mod.rs src/audit/provenance.rs src/audit/report.rs src/audit/retention.rs src/audit/secret.rs src/audit/verify.rs"

# extract_ci_job_ids <ci-yml-path>
#
# Block-scoped extraction of `jobs.<id>:` keys, reusing the same idiom as
# check-invariants.sh's function-body/CODEOWNERS-style block scanning
# (#7/#9/DI-13). A naive `grep -E '^  [a-z-]+:'` would also match
# `push:`/`pull_request:` (under `on:`) and `contents: read` (under
# `permissions:`), which sit at the identical 2-space indent as job ids --
# confirmed against the real file during shape enumeration.
extract_ci_job_ids() {
    awk '
        /^jobs:/ { injobs = 1; next }
        /^[^[:space:]#]/ { injobs = 0 }
        injobs && /^  [a-zA-Z][a-zA-Z0-9_-]*:[[:space:]]*$/ {
            line = $0
            gsub(/^  /, "", line)
            gsub(/:[[:space:]]*$/, "", line)
            print line
        }
    ' "$1"
}

# extract_production_region <rust-file>
#
# Truncates at the file's first top-level `#[cfg(test)]` or `mod tests`
# marker (Rust convention: test modules live at the file tail). Defense in
# depth for M3 -- none of today's m3_files trip the token scan even without
# this exclusion, but a future test that legitimately binds a local socket
# should not false-FAIL the tripwire.
extract_production_region() {
    awk '/^#\[cfg\(test\)\]/ { exit } /^mod tests/ { exit } { print }' "$1"
}

# assert_exact_count <actual> <expected> <tag> <context>
#
# Shared "did the loop/list actually process everything it should have"
# guard. M1 (row_num vs row_count), M3 (m3_files size), and M5 (named_tests
# size) each independently need this: without it, a read loop that silently
# iterated fewer times than its input has entries would report a vacuous
# OK/pass instead of catching the shrinkage.
assert_exact_count() {
    local actual="$1"
    local expected="$2"
    local tag="$3"
    local context="$4"
    if [ "$actual" -ne "$expected" ]; then
        echo "FAIL [$tag]: $context: got $actual, expected exactly $expected"
        return 1
    fi
    return 0
}

# ---------- M1: README claims table maps to CI/CONTRACT/src without rot ----------
#
# Table cells are markdown pipe-delimited; the region is bounded by
# `<!-- claims:start -->` / `<!-- claims:end -->` markers so this parser
# cannot confuse the Claims table with README's other pipe-table ("What It
# Blocks"). No existing doc-sync invariant parses a table cell-by-cell --
# this is genuinely new ground, confirmed during shape enumeration.
verify_claims_map() {
    local target_readme="$1"
    local target_ci="$2"
    local target_contract="$3"
    m1_fail=0

    if [ ! -f "$target_readme" ]; then
        echo "FAIL [claim map/#403]: $target_readme is missing"
        m1_fail=1
        return
    fi

    local job_ids
    job_ids="$(extract_ci_job_ids "$target_ci")"

    local contract_g_ids
    # Every stage after the first must also tolerate zero matches: under
    # `pipefail`, a mid-pipe grep exiting 1 (no match) makes the WHOLE
    # assignment fail even though the final `sort -u` exits 0, and since
    # this function is called as a bare top-level statement, `set -e` would
    # abort the entire script with no FAIL message printed (reproduced: a
    # CONTRACT.md with zero `G-N` headings crashes verify-claims.sh outright
    # instead of reporting the intended per-row FAIL -- Codex/code-review
    # finding).
    contract_g_ids="$( (grep -oE '^#+ G-[0-9]+' "$target_contract" || true) | grep -oE 'G-[0-9]+' | sort -u || true)"

    local table_region
    table_region="$(awk '/<!-- claims:start -->/{p=1; next} /<!-- claims:end -->/{p=0} p' "$target_readme")"

    if [ -z "$table_region" ]; then
        echo "FAIL [claim map/#403]: no <!-- claims:start --> / <!-- claims:end --> region found in $target_readme"
        m1_fail=1
        return
    fi

    # Data rows only: strip the header row and the `|---|` separator row.
    # `|| true` on the whole pipe (not just one stage) -- same reasoning as
    # contract_g_ids above: if the table region ever has zero `|`-prefixed
    # lines, an unguarded mid-pipe grep failure would abort the script
    # under set -e/pipefail before the row_count-ne-5 FAIL below ever runs
    # (reproduced).
    local data_rows
    data_rows="$(echo "$table_region" | grep '^|' | grep -v '^|---' | tail -n +2 || true)"

    local row_count
    row_count="$(echo "$data_rows" | grep -c '^|' || true)"

    if [ "$row_count" -ne 5 ]; then
        echo "FAIL [claim map/#403]: expected 5 claim rows in $target_readme, found $row_count (a claim row was added or removed without updating this script)"
        m1_fail=1
    fi

    local row_num=0
    while IFS= read -r row; do
        [ -z "$row" ] && continue
        row_num=$((row_num + 1))

        # Cell 2 = "Verify yourself" (the command a human runs). Checked
        # against a hardcoded expected-text map below, keyed by cell 4's
        # G-ID -- catching a claim's self-check command silently drifting
        # from what CONTRACT.md actually backs (Codex R1 P1 finding: this
        # cell previously went unchecked entirely).
        local verify_cell
        verify_cell="$(echo "$row" | awk -F'|' '{print $3}' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"

        # Cell 3 = CI job id (bare token, no pipes/spaces expected).
        local ci_cell
        ci_cell="$(echo "$row" | awk -F'|' '{print $4}' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"

        if [ -n "$ci_cell" ] && [ "$ci_cell" != "-" ]; then
            if ! printf '%s\n' "$job_ids" | grep -qxF "$ci_cell"; then
                echo "FAIL [claim map/#403]: row $row_num references CI job id '$ci_cell' but no such job exists in $target_ci"
                m1_fail=1
            else
                # continue-on-error: true on a mapped job silently defeats
                # the claim's enforcement without the job itself ever
                # showing red. Explicit-true only -- unset is GitHub
                # Actions' own default (false) and must not be flagged.
                if awk -v job="$ci_cell" '
                    $0 ~ "^  " job ":[[:space:]]*$" { injob = 1; next }
                    injob && /^  [a-zA-Z]/ { injob = 0 }
                    injob && /continue-on-error:[[:space:]]*true/ { found = 1 }
                    END { exit !found }
                ' "$target_ci"; then
                    echo "FAIL [claim map/#403]: row $row_num's CI job '$ci_cell' has continue-on-error: true -- a failing claim regression would not block merge"
                    m1_fail=1
                fi
            fi
        fi

        # Cell 4 = G-ID (e.g. "G-1").
        local g_cell
        g_cell="$(echo "$row" | awk -F'|' '{print $5}' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"

        if [ -n "$g_cell" ]; then
            if ! printf '%s\n' "$contract_g_ids" | grep -qxF "$g_cell"; then
                echo "FAIL [claim map/#403]: row $row_num references $g_cell but no such guarantee heading exists in $target_contract"
                m1_fail=1
            fi

            # Expected "Verify yourself" text per G-ID. G-4 is a negative
            # claim (no single command proves an absence -- see M2/M3
            # below), so its cell is prose, not a command.
            local expected_verify=""
            case "$g_cell" in
                G-1) expected_verify='`omamori test`' ;;
                G-2) expected_verify='`omamori audit verify`' ;;
                G-3) expected_verify='`omamori doctor`, `omamori status`' ;;
                G-4) expected_verify='source inspection' ;;
                G-5) expected_verify='`CLAUDECODE=1 omamori config disable rm-recursive-to-trash` (expect: blocked)' ;;
                # No fallthrough default: a row referencing a real-but-
                # unmapped G-ID (e.g. a future G-6 row) must not silently
                # skip this check -- that would reintroduce the exact rot
                # class this check exists to catch (Codex R2 finding).
                *)
                    echo "FAIL [claim map/#403]: row $row_num references $g_cell, which has no Verify-yourself mapping in this script (a claim row was added/repointed to a new G-ID without updating verify-claims.sh)"
                    m1_fail=1
                    ;;
            esac
            if [ -n "$expected_verify" ] && [ "$verify_cell" != "$expected_verify" ]; then
                echo "FAIL [claim map/#403]: row $row_num's Verify-yourself cell is '$verify_cell', expected '$expected_verify' for $g_cell"
                m1_fail=1
            fi
        fi
    done <<CLAIMS_ROWS_EOF
$data_rows
CLAIMS_ROWS_EOF

    # row_count above is computed independently of this loop (a plain
    # `grep -c`), so if the here-doc read loop ever silently iterated fewer
    # times than that (corrupted $data_rows, a shell quirk), m1_fail would
    # stay 0 and the OK message below would falsely claim all rows were
    # checked (Codex R3 issue proposal).
    if ! assert_exact_count "$row_num" "$row_count" "claim map/#403" "the row-check loop did not run against every row"; then
        m1_fail=1
    fi

    if [ "$m1_fail" -eq 0 ]; then
        echo "M1 OK: claims table maps to $row_count rows, all CI job ids and G-IDs resolve, no continue-on-error escape hatches"
    fi
}

# ---------- M2: claim 4 dependency tripwire (Cargo.lock name allowlist) ----------
#
# Deny-by-default: every `Cargo.lock` package name must be pre-approved.
# Name-only (not name+version+source). This tripwire's job is narrower: a
# *new* crate name entering the transitive closure, most critically one
# that adds a network client. Version drift on a direct dependency is a
# different, already-covered concern (lockfile-sanity diffs direct-dep
# downgrades against origin/main). Source drift on an already-approved
# name (swapping a crates.io dependency for a malicious git/path fork of
# the same name) is NOT covered by either check -- that class relies on
# human review of the tracked Cargo.lock diff, not a tripwire (security
# review finding).
verify_deps_allowlist() {
    local target_lock="$1"
    local target_allowlist="$2"
    m2_fail=0

    if [ ! -f "$target_lock" ]; then
        echo "FAIL [claim G-4/#403]: $target_lock is missing"
        m2_fail=1
        return
    fi
    if [ ! -f "$target_allowlist" ]; then
        echo "FAIL [claim G-4/#403]: $target_allowlist is missing"
        m2_fail=1
        return
    fi

    local lock_names allowed_names unknown stale
    lock_names="$( (grep '^name = ' "$target_lock" || true) | sed 's/^name = "//; s/"$//' | sort -u)"
    allowed_names="$(sort -u "$target_allowlist")"
    # `|| true` defensively, matching the guard discipline used throughout
    # this script: `comm` itself doesn't fail on an empty diff, but nothing
    # here should depend on that being true for every `comm` implementation.
    unknown="$(comm -23 <(printf '%s\n' "$lock_names") <(printf '%s\n' "$allowed_names") || true)"

    if [ -n "$unknown" ]; then
        echo "FAIL [claim G-4/#403]: $target_lock has dependencies not in $target_allowlist:"
        echo "$unknown"
        echo "  If this is a legitimate new dependency, add its name to $target_allowlist as a conscious edit."
        m2_fail=1
    else
        echo "M2 OK: all $(echo "$lock_names" | wc -l | tr -d ' ') Cargo.lock package names are pre-approved"
    fi

    # Informational only, does not fail the build: a name no longer present
    # in Cargo.lock but still in the allowlist cannot itself admit new code
    # (the tripwire above is deny-by-default on lock_names, not allow-by-
    # presence-in-allowlist) -- pruning it is routine maintenance, not a
    # security gap. Failing CI on this would tax every legitimate dependency
    # removal for no corresponding tripwire-strength gain.
    stale="$(comm -13 <(printf '%s\n' "$lock_names") <(printf '%s\n' "$allowed_names") || true)"
    if [ -n "$stale" ]; then
        echo "NOTE [claim G-4/#403]: $target_allowlist has $(echo "$stale" | grep -c '.' || true) name(s) no longer present in $target_lock (prune during routine maintenance if desired):"
        echo "$stale"
    fi
}

# ---------- M3: claim 4 source tripwire (hook-decision-path network APIs) ----------
#
# Word-boundary-anchored Rust network-API identifiers only. `curl`/`http`/
# `https://` are deliberately NOT tokens -- they appear legitimately in
# production code (an issue-report URL in a hint message, a config-template
# comment) and in rule-matching data for the commands omamori itself
# intercepts. `surf` (a real HTTP crate) is the sharpest trap: unanchored,
# it matches the English word "surface" -- confirmed 11 hits in production
# hook.rs during shape enumeration. `\b` word boundaries eliminate all of
# them while still catching `use surf;`.
# verify_source_tripwire [files-to-check]
#
# Defaults to the real hook-decision-path file set ($m3_files) when called
# with no argument; --self-test passes a temp-copy path instead so the
# self-test exercises this exact function (same token regex, same
# extract_production_region cfg(test) boundary) rather than a parallel
# standalone check that could silently drift from the real tripwire.
verify_source_tripwire() {
    local using_default_files=0
    [ $# -eq 0 ] && using_default_files=1
    local files_to_check="${1:-$m3_files}"
    m3_fail=0
    local tokens='\bstd::net\b|\bTcpStream\b|\bTcpListener\b|\bUdpSocket\b|\breqwest\b|\bhyper\b|\bureq\b|\bisahc\b|\bsurf\b|\bSocketAddr\b|\bto_socket_addrs\b'

    # Guarded only when scanning the real default set, not a self-test's
    # single-file override: --self-test's pass 3 calls this function
    # against one temp-copy path, which is not itself a test that $m3_files
    # (the production file list) still has its full membership. A future
    # edit that silently dropped a file (e.g. hook.rs) from $m3_files would
    # otherwise go unnoticed by both the self-test and this function
    # (Codex 6-B finding). Same expected-count pattern as M5's guard below.
    if [ "$using_default_files" -eq 1 ]; then
        local expected_m3_count=19
        local actual_m3_count
        actual_m3_count="$(echo "$files_to_check" | wc -w | tr -d ' ')"
        if ! assert_exact_count "$actual_m3_count" "$expected_m3_count" "claim G-4/#403" "m3_files entries (update expected_m3_count above if this file-set change was intentional)"; then
            m3_fail=1
        fi
    fi

    for f in $files_to_check; do
        if [ ! -f "$f" ]; then
            echo "FAIL [claim G-4/#403]: expected hook-decision-path file $f is missing"
            m3_fail=1
            continue
        fi
        local hits
        hits="$(extract_production_region "$f" | grep -nE "$tokens" || true)"
        if [ -n "$hits" ]; then
            echo "FAIL [claim G-4/#403]: $f contains a network-API identifier in its production region:"
            echo "$hits"
            m3_fail=1
        fi
    done

    if [ "$m3_fail" -eq 0 ]; then
        echo "M3 OK: no network-API identifiers in the hook-decision-path production region ($(echo "$files_to_check" | wc -w | tr -d ' ') files)"
    fi
}

# ---------- M4: honest-limitation prose has not been silently deleted ----------
#
# README's "How these are checked" section carries three limitation
# statements this script cannot itself verify by running code (claim 2's
# Cursor exclusion, claim 3's real-HOME-only exclusion, claim 4's
# negative-claim framing). If a future edit deletes one, the README would
# silently overclaim what is CI-enforced. Matched phrases are deliberately
# distinctive substrings of the actual limitation sentence, not a bare
# keyword like "Cursor" -- README mentions Cursor in several unrelated
# places (Tool Compatibility table, sandbox section), so a bare-keyword
# match would stay green even if the claim-2 limitation sentence itself
# were deleted (Codex R1 P1 finding).
verify_exclusion_prose() {
    local target_readme="$1"
    m4_fail=0

    if ! grep -qF "stderr-only and do not reach the audit chain" "$target_readme"; then
        echo "FAIL [claim G-2/#403]: $target_readme is missing the Cursor Layer-2-deny exclusion note"
        m4_fail=1
    fi
    if ! grep -qiF "real user's" "$target_readme"; then
        echo "FAIL [claim G-3/#403]: $target_readme is missing the real-user-HOME exclusion note"
        m4_fail=1
    fi
    if ! grep -qiF "no single push-button command that proves an absence" "$target_readme"; then
        echo "FAIL [claim G-4/#403]: $target_readme is missing the claim-4 negative-claim framing note"
        m4_fail=1
    fi

    if [ "$m4_fail" -eq 0 ]; then
        echo "M4 OK: honest-limitation prose for claims 2/3/4 present in $target_readme"
    fi
}

# ---------- M5: named-test rot guard (claims 1/2/3/5 lean on these by name) ----------
#
# "How these are checked" cites specific named cargo tests as the CI
# enforcement behind claims 1/2/3/5 (this script deliberately does not
# re-prove their behavior -- see the top-of-file comment). That citation is
# itself an unverified claim unless something pins the named tests still
# existing and still running. `G-ID|file|fn_name`, one per line -- plain
# text, not a bash associative array (bash 3.2 compatible; macOS ships 3.2
# by default and this script has no `#!/usr/bin/env bash` version floor).
named_tests="
G-1|src/cli/policy_test.rs|policy_tests_pass_with_default_config
G-1|src/property_tests.rs|coverage_matches_default_rules_destructive_set
G-2|tests/hook_integration.rs|hook_deny_blockmeta_creates_audit_entry
G-2|tests/hook_integration.rs|hook_deny_blockrule_creates_audit_entry
G-2|tests/hook_integration.rs|hook_materialize_pipe_to_shell_creates_audit_entry
G-2|tests/hook_integration.rs|hook_deny_blockstructural_creates_audit_entry
G-3|tests/cli.rs|status_command_outputs_health_check
G-3|tests/cli.rs|status_refresh_creates_baseline
G-3|tests/cli.rs|doctor_reports_hook_version_drift_in_human_and_json_output
G-5|tests/cli.rs|config_disable_rejects_all_core_rule_ids
G-5|tests/cli.rs|config_disable_blocked_in_ai_session
G-5|src/config.rs|merge_core_rule_ignores_disable_without_override
G-5|src/config.rs|core_rule_names_matches_default_rules_builtin_set
"

# check_named_test_pinned <file> <fn_name>
#
# Asserts `fn <fn_name>(` exists in <file> and is not `#[ignore]`d. The
# ignore-scan window is the 5 lines immediately above the `fn` line --
# enough to span `#[test]` plus a stacked attribute or two, without
# false-matching an unrelated `#[ignore]` elsewhere in the file.
check_named_test_pinned() {
    local file="$1"
    local fn_name="$2"

    if [ ! -f "$file" ]; then
        echo "FAIL [claim map/#403]: named-test file $file is missing (was it moved or renamed?)"
        return 1
    fi

    local fn_line
    fn_line="$(grep -nE "fn ${fn_name}\\(" "$file" | head -n1 | cut -d: -f1)"
    if [ -z "$fn_line" ]; then
        echo "FAIL [claim map/#403]: named test '$fn_name' not found in $file (deleted or renamed without updating this script)"
        return 1
    fi

    local start=$((fn_line - 5))
    [ "$start" -lt 1 ] && start=1
    if sed -n "${start},${fn_line}p" "$file" | grep -qE '#\[ignore'; then
        echo "FAIL [claim map/#403]: named test '$fn_name' in $file is #[ignore]d -- it no longer runs in CI"
        return 1
    fi

    return 0
}

verify_named_tests() {
    m5_fail=0
    local count=0
    # Hardcoded against $named_tests' own line count (not derived from it)
    # on purpose: if the here-doc read loop below ever iterates zero times
    # for any reason (an empty/corrupted $named_tests, a shell quirk in
    # some non-standard bash), `count` would silently stay 0 and this
    # function would report a vacuous "M5 OK: all 0 named tests..." pass --
    # exactly the kind of silent-drift this whole script exists to catch
    # (Codex R2 finding). expected_count is a manually-maintained constant;
    # update it if named_tests entries are added or removed.
    local expected_count=13

    while IFS='|' read -r g_id file fn_name; do
        [ -z "$g_id" ] && continue
        count=$((count + 1))
        if ! check_named_test_pinned "$file" "$fn_name"; then
            m5_fail=1
        fi
    done <<NAMED_TESTS_EOF
$named_tests
NAMED_TESTS_EOF

    if ! assert_exact_count "$count" "$expected_count" "claim map/#403" "verify_named_tests() named test count (update expected_count if named_tests entries were intentionally added/removed)"; then
        m5_fail=1
    fi

    if [ "$m5_fail" -eq 0 ]; then
        echo "M5 OK: all $count named tests backing claims 1/2/3/5 exist and are not #[ignore]d"
    fi
}

if [ "${1:-}" = "--self-test" ]; then
    self_test_fail=0
    tmpdir="$(mktemp -d "$HOME/omamori-verify-claims-selftest-XXXXXX")"
    cleanup() {
        # `trash` (macOS) if available, else plain rm -rf (CI runners have
        # no omamori installed, so rm -rf is unremarkable there).
        if command -v trash >/dev/null 2>&1; then
            trash "$tmpdir" 2>/dev/null || rm -rf "$tmpdir"
        else
            rm -rf "$tmpdir"
        fi
    }
    trap cleanup EXIT

    echo "--- self-test pass 1/7: inject a fake CI job id into the README claims table ---"
    cp "$readme" "$tmpdir/README.md"
    sed -i.bak 's/| `omamori test` | test | G-1 |/| `omamori test` | no-such-job | G-1 |/' "$tmpdir/README.md"
    rm -f "$tmpdir/README.md.bak"
    if out="$(verify_claims_map "$tmpdir/README.md" "$ci_yml" "$contract" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "FAIL [claim map/#403]: row 1 references CI job id 'no-such-job'"; then
        echo "verify-claims --self-test: FAIL — pass 1 (fake job id) did not produce the expected FAIL label. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 1/7: OK (fake job id correctly detected)"
    fi

    echo "--- self-test pass 2/7: inject a fake crate name into Cargo.lock ---"
    cp "$lockfile" "$tmpdir/Cargo.lock"
    printf '\n[[package]]\nname = "evilcrate"\nversion = "0.0.0"\n' >>"$tmpdir/Cargo.lock"
    if out="$(verify_deps_allowlist "$tmpdir/Cargo.lock" "$approved_deps" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "evilcrate"; then
        echo "verify-claims --self-test: FAIL — pass 2 (fake crate) did not produce the expected FAIL label. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 2/7: OK (fake crate name correctly detected)"
    fi

    echo "--- self-test pass 3/7: inject a network token into a hook-path source copy ---"
    mkdir -p "$tmpdir/src/engine"
    cp src/engine/hook.rs "$tmpdir/src/engine/hook.rs"
    # Insert at line 2 (top of file, well before the file's #[cfg(test)]
    # boundary) -- appending at EOF would land inside the excluded test
    # region and this pass would test nothing.
    sed -i.bak '2i\
use reqwest;
' "$tmpdir/src/engine/hook.rs"
    rm -f "$tmpdir/src/engine/hook.rs.bak"
    # Calls the real verify_source_tripwire() against the injected copy
    # (Codex R1 P1 finding: a standalone parallel grep here would not
    # notice if m3_files dropped hook.rs, or if the real token set stopped
    # containing "reqwest" -- only exercising the actual function does).
    if out="$(verify_source_tripwire "$tmpdir/src/engine/hook.rs" 2>&1)"; then
        :
    fi
    # Content-specific, not just the shared "FAIL [claim G-4/#403]" tag --
    # every FAIL branch in verify_source_tripwire (and the rest of this
    # script) shares that same tag, so matching only the tag would let this
    # pass report success for an unrelated failure reason (code-review
    # finding). Assert the actual injected token appears in the reported hit.
    if ! echo "$out" | grep -qF "FAIL [claim G-4/#403]" || ! echo "$out" | grep -qF "reqwest"; then
        echo "verify-claims --self-test: FAIL — pass 3 (injected reqwest) was not detected by the source tripwire scan. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 3/7: OK (injected network token correctly detected)"
    fi

    echo "--- self-test pass 4/7: delete the Cursor exclusion prose ---"
    cp "$readme" "$tmpdir/README-noexclusion.md"
    # Delete only the line carrying the distinctive claim-2 limitation
    # phrase, not every line containing "Cursor" -- README mentions Cursor
    # in several unrelated places (Tool Compatibility table, sandbox
    # section), and a self-test that scrubs all of them would not prove
    # M4 catches deletion of *this specific* limitation sentence.
    sed -i.bak '/stderr-only and do not reach the audit chain/d' "$tmpdir/README-noexclusion.md"
    rm -f "$tmpdir/README-noexclusion.md.bak"
    if out="$(verify_exclusion_prose "$tmpdir/README-noexclusion.md" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "FAIL [claim G-2/#403]"; then
        echo "verify-claims --self-test: FAIL — pass 4 (deleted Cursor prose) did not produce the expected FAIL label. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 4/7: OK (deleted exclusion prose correctly detected)"
    fi

    echo "--- self-test pass 5/7: swap the Verify-yourself cell for G-1 ---"
    cp "$readme" "$tmpdir/README-badverify.md"
    sed -i.bak 's/| `omamori test` | test | G-1 |/| `omamori explain` | test | G-1 |/' "$tmpdir/README-badverify.md"
    rm -f "$tmpdir/README-badverify.md.bak"
    if out="$(verify_claims_map "$tmpdir/README-badverify.md" "$ci_yml" "$contract" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "row 1's Verify-yourself cell is '\`omamori explain\`', expected '\`omamori test\`' for G-1"; then
        echo "verify-claims --self-test: FAIL — pass 5 (swapped Verify-yourself cell) did not produce the expected FAIL label. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 5/7: OK (mismatched Verify-yourself cell correctly detected)"
    fi

    echo "--- self-test pass 6/7: mark a named test #[ignore] in a temp copy ---"
    mkdir -p "$tmpdir/tests"
    # Insert #[ignore] immediately above a stable, well-known named test
    # (config_disable_rejects_all_core_rule_ids, G-5) rather than mutating
    # the real tests/cli.rs.
    awk '
        /^fn config_disable_rejects_all_core_rule_ids\(\)/ && !done {
            print "#[ignore]"
            done = 1
        }
        { print }
    ' tests/cli.rs >"$tmpdir/tests/cli.rs"
    if out="$(check_named_test_pinned "$tmpdir/tests/cli.rs" "config_disable_rejects_all_core_rule_ids" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "is #[ignore]d"; then
        echo "verify-claims --self-test: FAIL — pass 6 (injected #[ignore]) was not detected by the named-test-pin check. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 6/7: OK (#[ignore]d named test correctly detected)"
    fi

    echo "--- self-test pass 7/7: rename a named test out of existence in a temp copy ---"
    # check_named_test_pinned() has two distinct FAIL paths -- "#[ignore]d"
    # (pass 6) and "not found" (renamed/deleted). Only the first was
    # self-tested; a future edit that broke the not-found path specifically
    # would go unnoticed (Codex 6-B finding).
    sed 's/fn config_disable_rejects_all_core_rule_ids(/fn config_disable_rejects_all_core_rule_ids_RENAMED(/' \
        tests/cli.rs >"$tmpdir/tests/cli.rs"
    if out="$(check_named_test_pinned "$tmpdir/tests/cli.rs" "config_disable_rejects_all_core_rule_ids" 2>&1)"; then
        :
    fi
    if ! echo "$out" | grep -qF "not found in $tmpdir/tests/cli.rs"; then
        echo "verify-claims --self-test: FAIL — pass 7 (renamed-out-of-existence named test) was not detected by the named-test-pin check. Got:"
        echo "$out"
        self_test_fail=1
    else
        echo "pass 7/7: OK (renamed/deleted named test correctly detected)"
    fi

    if [ "$self_test_fail" -ne 0 ]; then
        echo "verify-claims --self-test: FAIL"
        exit 1
    fi
    echo "verify-claims --self-test: OK (all 7 tripwires independently fire on injected violations, no false positives)"
    exit 0
fi

verify_claims_map "$readme" "$ci_yml" "$contract"
[ "$m1_fail" -ne 0 ] && fail=1

verify_deps_allowlist "$lockfile" "$approved_deps"
[ "$m2_fail" -ne 0 ] && fail=1

verify_source_tripwire
[ "$m3_fail" -ne 0 ] && fail=1

verify_exclusion_prose "$readme"
[ "$m4_fail" -ne 0 ] && fail=1

verify_named_tests
[ "$m5_fail" -ne 0 ] && fail=1

if [ "$fail" -ne 0 ]; then
    echo
    echo "verify-claims: FAIL"
    exit 1
fi

echo
echo "verify-claims: OK"
