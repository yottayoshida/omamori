#!/usr/bin/env bash
# check-action-pins.sh
#
# Verify that every `uses:` reference in .github/workflows/*.yml is pinned
# to a 40-character commit SHA. Invoked by the `action-pin-check` job in
# ci.yml and the sentinel job in fuzz.yml.
#
# Why YAML-aware (not grep):
#   A grep over raw text cannot distinguish the SHA of an actual `uses:`
#   ref from a 40-hex substring inside a comment. `yq` extracts the
#   parsed `uses:` value itself, so `@v4 # @<40hex>` is correctly rejected.
#
# Covers:
#   - step-level: `.jobs[*].steps[*].uses`
#   - job-level (reusable workflow invocation): `.jobs[*].uses`
#
# Accepts:
#   - `owner/name@<40-hex>` (e.g. `actions/checkout@34e1...`)
#   - `owner/name/subpath@<40-hex>` (monorepo actions)
#   - local composite actions: `./path` or `../path`
#
# Preinstalled on GitHub-hosted runners. Locally: `brew install yq`.

set -euo pipefail

if ! command -v yq >/dev/null 2>&1; then
    echo "ERROR: yq is required (preinstalled on GitHub runners; 'brew install yq' locally)"
    exit 2
fi

SHA_RE='^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$'
LOCAL_RE='^\.\.?/'

fail=0

for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$wf" ] || continue

    # Collect step-level and job-level `uses:` values.
    refs="$(
        {
            yq eval '.jobs[].steps[]? | .uses // ""' "$wf" 2>/dev/null
            yq eval '.jobs[] | .uses // ""' "$wf" 2>/dev/null
        } | grep -v '^$' || true
    )"

    while IFS= read -r ref; do
        [ -z "$ref" ] && continue
        # Local composite actions are allowed (no remote ref).
        if [[ "$ref" =~ $LOCAL_RE ]]; then
            continue
        fi
        if ! [[ "$ref" =~ $SHA_RE ]]; then
            echo "FAIL: $wf: unpinned or malformed uses ref: $ref"
            fail=1
        fi
    done <<<"$refs"
done

if [ "$fail" -ne 0 ]; then
    echo
    echo "check-action-pins: FAIL — every uses: MUST be owner/name[/path]@<40-hex>"
    exit 1
fi

echo "check-action-pins: OK"
