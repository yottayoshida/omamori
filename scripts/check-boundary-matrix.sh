#!/usr/bin/env bash
# check-boundary-matrix.sh (#405)
#
# SECURITY.md's Defense Boundary Matrix (3 tables: Caught / Not caught -- by
# design / Not caught -- structural limit) is a human-readable audit
# document. docs/defense-boundary.json is a machine-readable strict
# projection of it, for external tooling/dashboards. This script enforces
# that the two cannot silently drift apart. It does NOT re-prove that the
# underlying coverage behaves correctly -- that is the job of the Rust test
# corpus each row's `verified_by` field points at (see docs/defense-
# boundary.json's own "disclaimer" field).
#
# What this script checks (B1-B7, plus B4b):
#   B1: docs/defense-boundary.json is valid JSON, docs/defense-boundary.
#       schema.json is ALSO valid JSON (its own syntax only -- entries[]
#       is never validated for conformance against the schema's per-
#       category `required`/`allOf` constraints, a known, documented gap),
#       all required top-level keys are present, entries[] is non-empty,
#       and every entries[].category is one of {caught, out_of_scope,
#       structural_limit} (an unrecognized category would otherwise drop
#       an entry out of every check below -- B3/B4/B5 all bucket by
#       category -- letting the JSON carry an arbitrary phantom claim
#       past every gate).
#   B2: every entries[].layer1/layer2 base token is a member of
#       status_vocabulary, AND status_vocabulary's key set matches
#       SECURITY.md's Defense Boundary Matrix legend bold-term set exactly
#       (SECURITY.md's legend is the single source of truth for the
#       vocabulary; this script never hardcodes it).
#   B3: each of the 3 tables' row count in SECURITY.md matches its
#       category's entry count in the JSON (derived from the md file each
#       run, never a hardcoded constant -- so a table growing/shrinking
#       cannot silently escape detection).
#   B4: each table's Surface-cell set (verbatim, markdown backticks kept,
#       `\|` unescaped to `|`) is exactly equal between SECURITY.md and the
#       JSON, in both directions. Prose columns (Reason/Why/Mitigation/
#       Reference/note) are NOT compared here -- semantic drift in prose is
#       a residual risk this script does not close (see the JSON's
#       disclaimer field). B4b: entries[].id is unique across the whole
#       file (surface-text uniqueness alone, checked by B4, would miss a
#       copy-pasted row that kept its source row's id).
#   B5: for the Caught table only, each row's Layer 1/Layer 2 STATUS BASE
#       TOKEN (the text before any " (note)" parenthetical) matches between
#       SECURITY.md and the JSON. This is what stops the JSON from claiming
#       broader coverage than the prose document -- B4's row-identity check
#       alone would not catch a status value silently drifting.
#   B6: the JSON's matrix_version matches the "(vX.Y.Z+)" version tag in
#       SECURITY.md's "### Defense Boundary Matrix" heading.
#   B7: SECURITY.md and README.md both reference docs/defense-boundary.json,
#       and this script's own CI job wiring (both the base check and
#       --self-test) exists in ci.yml with no continue-on-error: true. B7 is
#       grep-based against static, non-cell content (links, job names) and
#       is intentionally NOT exercised by --self-test below -- there is no
#       md-vs-JSON drift scenario for it to inject.
#
# Modes:
#   scripts/check-boundary-matrix.sh              (default: read repo files)
#   scripts/check-boundary-matrix.sh --self-test   (inverted-control proof:
#                                                    injects ONE violation
#                                                    per pass into temp
#                                                    copies and asserts the
#                                                    resulting FAIL label is
#                                                    exactly the expected
#                                                    one -- never the
#                                                    product's own
#                                                    SECURITY.md/JSON)

set -euo pipefail

cd "$(dirname "$0")/.."

security_md=SECURITY.md
json_file=docs/defense-boundary.json
schema_file=docs/defense-boundary.schema.json
readme=README.md
ci_yml=.github/workflows/ci.yml

fail=0

# run_check <security-md-path> <json-path>
#
# Single source of truth for B1-B6, called both by the real run (against
# the repo's own files) and by every --self-test pass (against a mutated
# temp copy) -- so self-test exercises the exact same parse/compare code,
# not a parallel check that could silently drift from it (same discipline
# as verify-claims.sh's verify_source_tripwire).
run_check() {
    local target_md="$1"
    local target_json="$2"
    local target_schema="$3"
    python3 - "$target_md" "$target_json" "$target_schema" <<'PYEOF'
import json, re, sys

md_path, json_path, schema_path = sys.argv[1], sys.argv[2], sys.argv[3]
fail = False


def fail_msg(tag, msg):
    global fail
    print(f"FAIL [{tag}]: {msg}")
    fail = True


# (heading, next_heading, category, ncols) per sub-table. Single source of
# truth: VALID_CATEGORIES below is derived from this, not independently
# hardcoded -- two lists of the same 3 category names is exactly the kind
# of drift this script exists to prevent (Codex proxy simplify finding).
TABLES = [
    ("#### Caught", "#### Not caught — by design", "caught", 4),
    ("#### Not caught — by design", "#### Not caught — structural limit", "out_of_scope", 3),
    ("#### Not caught — structural limit", None, "structural_limit", 3),
]


# ---------- B1: JSON syntax (data file + schema file) + required top-level keys ----------
try:
    with open(schema_path, encoding="utf-8") as f:
        json.loads(f.read())
except FileNotFoundError:
    fail_msg("boundary-matrix/#405 (B1)", f"{schema_path} is missing")
except json.JSONDecodeError as e:
    fail_msg("boundary-matrix/#405 (B1)", f"{schema_path} is not valid JSON: {e}")

try:
    with open(json_path, encoding="utf-8") as f:
        raw = f.read()
except FileNotFoundError:
    fail_msg("boundary-matrix/#405", f"{json_path} is missing")
    sys.exit(1)

try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    fail_msg("boundary-matrix/#405 (B1)", f"{json_path} is not valid JSON: {e}")
    sys.exit(1)

required_top = [
    "matrix_version",
    "generated_from",
    "canonical_source",
    "disclaimer",
    "status_vocabulary",
    "entries",
]
missing_top = [k for k in required_top if k not in data]
if missing_top:
    fail_msg("boundary-matrix/#405 (B1)", f"{json_path} is missing required key(s): {missing_top}")
    sys.exit(1)

entries = data["entries"]
if not isinstance(entries, list) or len(entries) == 0:
    # Vacuous-pass guard: an empty entries[] must be a hard failure, not a
    # trivially-satisfied "0 mismatches found" pass (verify-claims.sh M1
    # precedent -- see assert_exact_count's rationale).
    fail_msg("boundary-matrix/#405 (B1)", f"{json_path} entries[] is empty or not a list")
    sys.exit(1)

VALID_CATEGORIES = {category for _, _, category, _ in TABLES}
bad_category = [e.get("id", "?") for e in entries if e.get("category") not in VALID_CATEGORIES]
if bad_category:
    # An unrecognized category value silently drops an entry out of every
    # downstream check below (B3/B4/B5 all bucket by category) -- a typo'd
    # or fabricated category is otherwise invisible, letting the JSON carry
    # an arbitrary phantom claim past every gate (test-adversarial finding).
    fail_msg(
        "boundary-matrix/#405 (B1)",
        f"{json_path} has entrie(s) with an unrecognized category (must be one of {sorted(VALID_CATEGORIES)}): {bad_category}",
    )
    sys.exit(1)

print(f"B1 OK: {json_path} is valid JSON with all required top-level keys ({len(entries)} entries)")

# ---------- locate the matrix region + heading ----------
with open(md_path, encoding="utf-8") as f:
    lines = f.readlines()

heading_version = None
heading_re = re.compile(r"^### Defense Boundary Matrix \(([^)]+)\)")
for l in lines:
    m = heading_re.match(l)
    if m:
        heading_version = m.group(1)
        break

if heading_version is None:
    fail_msg("boundary-matrix/#405 (B6)", f"{md_path} is missing the '### Defense Boundary Matrix (vX.Y.Z+)' heading")

start = end = None
for i, l in enumerate(lines):
    if "<!-- boundary-matrix:start -->" in l:
        start = i
    if "<!-- boundary-matrix:end -->" in l:
        end = i
        break

if start is None or end is None:
    fail_msg(
        "boundary-matrix/#405",
        f"{md_path} is missing <!-- boundary-matrix:start --> / <!-- boundary-matrix:end --> markers",
    )
    sys.exit(1)

region = lines[start:end]

# ---------- B2a: legend bold terms == status_vocabulary keys ----------
legend_terms = set()
for l in region:
    legend_terms.update(re.findall(r"\*\*([^*]+)\*\*", l))

if not legend_terms:
    fail_msg("boundary-matrix/#405 (B2)", f"{md_path} boundary-matrix region has zero legend terms (vacuous)")

vocab_terms = set(data["status_vocabulary"].keys())
if legend_terms != vocab_terms:
    only_md = sorted(legend_terms - vocab_terms)
    only_json = sorted(vocab_terms - legend_terms)
    fail_msg(
        "boundary-matrix/#405 (B2)",
        f"legend vocabulary mismatch: only in {md_path}={only_md}, only in {json_path} status_vocabulary={only_json}",
    )
else:
    print(f"B2a OK: {len(vocab_terms)} legend terms match status_vocabulary exactly")

PLACEHOLDER = "\x00ESCPIPE\x00"


def split_row(row):
    # Whole-row placeholder-escape for `\|` BEFORE splitting on `|` -- two
    # confirmed occurrences in the matrix region (Caught-table Surface cell,
    # structural-limit Why cell), and a naive `split("|")` shifts every
    # column to its right (shape enumeration finding).
    escaped = row.rstrip("\n").replace("\\|", PLACEHOLDER)
    inner = escaped.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [c.replace(PLACEHOLDER, "|").strip() for c in inner.split("|")]


def base_and_note(cell):
    # Base token = trimmed text before the first " (" ; multi-word tokens
    # ("not covered", "not applicable") are real data (shape enumeration
    # A1), so this must NOT be a first-whitespace-word split. Note = text up
    # to the LAST ")" (A2 guard: tolerate an unlikely future nested paren
    # rather than truncating at the first one).
    idx = cell.find(" (")
    if idx == -1:
        return cell.strip(), None
    last_paren = cell.rfind(")")
    if last_paren == -1 or last_paren < idx:
        return cell.strip(), None
    return cell[:idx].strip(), cell[idx + 2 : last_paren]


def extract_table(region_lines, heading, next_heading):
    in_table = False
    pipe_lines = []
    for l in region_lines:
        if l.startswith(heading):
            in_table = True
            continue
        if next_heading and l.startswith(next_heading):
            break
        if in_table and l.startswith("|"):
            pipe_lines.append(l.rstrip("\n"))
    if len(pipe_lines) < 2:
        return []
    # Strip header row + `|---|` separator row; data rows only.
    return pipe_lines[2:]


md_by_category = {}
for heading, next_heading, category, ncols in TABLES:
    rows = extract_table(region, heading, next_heading)
    parsed = []
    for row in rows:
        cols = split_row(row)
        if len(cols) != ncols:
            fail_msg(
                "boundary-matrix/#405",
                f"a row in the '{category}' table has {len(cols)} column(s) after parsing, expected {ncols}: {row!r}",
            )
            continue
        parsed.append(cols)
    md_by_category[category] = parsed

json_by_category = {}
for e in entries:
    json_by_category.setdefault(e.get("category"), []).append(e)

# ---------- B2b: every JSON status value is in status_vocabulary ----------
for e in json_by_category.get("caught", []):
    for layer_key in ("layer1", "layer2"):
        val = e.get(layer_key)
        if val is not None and val not in vocab_terms:
            fail_msg(
                "boundary-matrix/#405 (B2)",
                f"'{e.get('surface')}': {json_path} {layer_key}={val!r} is not in status_vocabulary {sorted(vocab_terms)}",
            )

# ---------- B3: row-count parity (md-derived, never hardcoded) ----------
for _, _, category, _ in TABLES:
    md_count = len(md_by_category.get(category, []))
    json_count = len(json_by_category.get(category, []))
    if md_count == 0:
        fail_msg(
            "boundary-matrix/#405 (B3)",
            f"{md_path} '{category}' table has zero data rows (heading missing, or table emptied)",
        )
        continue
    if md_count != json_count:
        fail_msg(
            "boundary-matrix/#405 (B3)",
            f"'{category}': {md_path} has {md_count} row(s), {json_path} has {json_count} entrie(s)",
        )
    else:
        print(f"B3 OK: '{category}' row count matches ({md_count})")

# ---------- B4: surface set equality, per table, both directions ----------
for _, _, category, _ in TABLES:
    md_rows = md_by_category.get(category, [])
    json_entries = json_by_category.get(category, [])
    md_surfaces = [row[0] for row in md_rows]
    json_surfaces = [e["surface"] for e in json_entries]
    md_set = set(md_surfaces)
    json_set = set(json_surfaces)

    only_md = sorted(md_set - json_set)
    only_json = sorted(json_set - md_set)
    if only_md or only_json:
        fail_msg(
            "boundary-matrix/#405 (B4)",
            f"'{category}' surface set mismatch: only in {md_path}={only_md}, only in {json_path}={only_json}",
        )
    else:
        print(f"B4 OK: '{category}' surface sets match ({len(md_set)} entries)")

    if len(md_surfaces) != len(md_set):
        fail_msg("boundary-matrix/#405 (B4)", f"'{category}' has duplicate surface text within {md_path}")
    if len(json_surfaces) != len(json_set):
        fail_msg("boundary-matrix/#405 (B4)", f"'{category}' has duplicate surface text within {json_path}")

# ---------- B4b: entries[].id is unique across the whole file ----------
# The schema documents `id` as unique within entries[], but nothing above
# checks it (B4 only dedups on surface text) -- a copy-pasted row that kept
# its source row's id would otherwise pass silently.
all_ids = [e.get("id") for e in entries]
if len(all_ids) != len(set(all_ids)):
    dupes = sorted({i for i in all_ids if all_ids.count(i) > 1})
    fail_msg("boundary-matrix/#405 (B4b)", f"{json_path} has duplicate entries[].id value(s): {dupes}")
else:
    print(f"B4b OK: all {len(all_ids)} entries[].id values are unique")

# ---------- B5: Caught-table status base-token cross-check ----------
md_caught_by_surface = {row[0]: row for row in md_by_category.get("caught", [])}
b5_checked = 0
b5_had_mismatch = False
for e in json_by_category.get("caught", []):
    row = md_caught_by_surface.get(e["surface"])
    if row is None:
        continue  # already reported by B4; avoid a duplicate/misleading B5 message
    md_l1_base, _ = base_and_note(row[1])
    md_l2_base, _ = base_and_note(row[2])
    if e.get("layer1") != md_l1_base:
        fail_msg(
            "boundary-matrix/#405 (B5)",
            f"'{e['surface']}': layer1 status base token mismatch — {md_path}={md_l1_base!r}, {json_path}={e.get('layer1')!r}",
        )
        b5_had_mismatch = True
    if e.get("layer2") != md_l2_base:
        fail_msg(
            "boundary-matrix/#405 (B5)",
            f"'{e['surface']}': layer2 status base token mismatch — {md_path}={md_l2_base!r}, {json_path}={e.get('layer2')!r}",
        )
        b5_had_mismatch = True
    b5_checked += 1

if b5_checked > 0 and not b5_had_mismatch:
    print(f"B5 OK: {b5_checked} Caught-table status base token pair(s) checked, all matched")

# ---------- B6: matrix_version == SECURITY.md heading version tag ----------
if heading_version is not None:
    json_version = data.get("matrix_version")
    if json_version != heading_version:
        fail_msg(
            "boundary-matrix/#405 (B6)",
            f"matrix_version mismatch: {md_path} heading says {heading_version!r}, {json_path} says {json_version!r}",
        )
    else:
        print(f"B6 OK: matrix_version matches SECURITY.md heading ({heading_version!r})")

sys.exit(1 if fail else 0)
PYEOF
}

# ---------- B7: links + CI wiring (grep-based, not self-tested — see header) ----------
b7_check() {
    local b7_fail=0

    if [ ! -f "$json_file" ]; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $json_file is missing"
        b7_fail=1
    fi
    if [ ! -f "$schema_file" ]; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $schema_file is missing"
        b7_fail=1
    fi

    if ! grep -qF "defense-boundary.json" "$security_md"; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $security_md does not reference defense-boundary.json"
        b7_fail=1
    fi
    if ! grep -qF "defense-boundary.json" "$readme"; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $readme does not reference defense-boundary.json"
        b7_fail=1
    fi

    if ! grep -qF "check-boundary-matrix.sh" "$ci_yml"; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $ci_yml does not invoke check-boundary-matrix.sh"
        b7_fail=1
    fi
    if ! grep -qF "check-boundary-matrix.sh --self-test" "$ci_yml"; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $ci_yml does not invoke check-boundary-matrix.sh --self-test"
        b7_fail=1
    fi

    # continue-on-error: true, scoped to the invariants-check job only (a
    # different job legitimately using it must not false-trip this check --
    # Codex proxy R2 finding).
    if awk '
        /^  invariants-check:[[:space:]]*$/ { injob = 1; next }
        injob && /^  [a-zA-Z]/ { injob = 0 }
        injob && /continue-on-error:[[:space:]]*true/ { found = 1 }
        END { exit !found }
    ' "$ci_yml"; then
        echo "FAIL [boundary-matrix/#405 (B7)]: $ci_yml invariants-check job has continue-on-error: true"
        b7_fail=1
    fi

    if [ "$b7_fail" -eq 0 ]; then
        echo "B7 OK: links + CI wiring present, invariants-check has no continue-on-error: true"
    fi
    return "$b7_fail"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test_fail=0
    tmpdir="$(mktemp -d "$HOME/omamori-boundary-matrix-selftest-XXXXXX")"
    cleanup() {
        if command -v trash >/dev/null 2>&1; then
            trash "$tmpdir" 2>/dev/null || rm -rf "$tmpdir"
        else
            rm -rf "$tmpdir"
        fi
    }
    trap cleanup EXIT

    # fresh_copies: reset both temp files to the repo's real, unmutated
    # state before each pass, so passes cannot leak mutations into each
    # other.
    fresh_copies() {
        cp "$security_md" "$tmpdir/SECURITY.md"
        cp "$json_file" "$tmpdir/defense-boundary.json"
    }

    assert_fail_contains() {
        local pass_label="$1"
        local expected_substr="$2"
        local actual_output="$3"
        if ! printf '%s\n' "$actual_output" | grep -qF "$expected_substr"; then
            echo "check-boundary-matrix --self-test: FAIL — $pass_label did not produce the expected FAIL label. Got:"
            printf '%s\n' "$actual_output"
            self_test_fail=1
            return 1
        fi
        echo "$pass_label: OK"
        return 0
    }

    # sed_md: BSD/macOS-sed-compatible in-place edit of the tmpdir SECURITY.md
    # copy, with the .bak cleaned up immediately (never left for the EXIT
    # trap to clean up, matching every other mutation's tidiness).
    sed_md() {
        sed -i.bak "$1" "$tmpdir/SECURITY.md"
        rm -f "$tmpdir/SECURITY.md.bak"
    }

    # mutate_entry_field <entry-id> <field> <value>: set one field on one
    # entries[] object (matched by id) in the tmpdir defense-boundary.json
    # copy. Shared by the 3 self-test passes that each mutate exactly one
    # field of one entry.
    mutate_entry_field() {
        python3 - "$tmpdir/defense-boundary.json" "$1" "$2" "$3" <<'PYEOF'
import json, sys
p, entry_id, field, value = sys.argv[1:5]
data = json.load(open(p))
for e in data["entries"]:
    if e["id"] == entry_id:
        e[field] = value
        break
json.dump(data, open(p, "w"), indent=2)
PYEOF
    }

    echo "--- self-test pass 1/16: add a JSON entry with no matching md row ---"
    fresh_copies
    python3 - "$tmpdir/defense-boundary.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data["entries"].append({
    "id": "fake-injected-row",
    "category": "structural_limit",
    "surface": "This surface does not exist in SECURITY.md",
    "why": "injected by self-test",
    "mitigation": "injected by self-test",
})
json.dump(data, open(p, "w"), indent=2)
PYEOF
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 1/16 (JSON-side row with no md match)" "(B3)" "$out" || true
    assert_fail_contains "pass 1/16 (JSON-side row with no md match)" "(B4)" "$out" || true

    echo "--- self-test pass 2/16: add an md row with no matching JSON entry ---"
    fresh_copies
    # Insert a new structural-limit row right after the alias row (line
    # anchored on its exact known text) so the table's row count grows by
    # one without any corresponding JSON entry.
    python3 - "$tmpdir/SECURITY.md" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p, encoding="utf-8").readlines()
anchor = "| `alias rm='/bin/rm'` | Alias overrides bypass string matching | Layer 2 hooks cover AI tool paths |\n"
idx = lines.index(anchor)
lines.insert(idx + 1, "| Fake row with no JSON entry | injected by self-test | injected by self-test |\n")
open(p, "w", encoding="utf-8").writelines(lines)
PYEOF
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 2/16 (md-side row with no JSON match)" "(B3)" "$out" || true

    echo "--- self-test pass 3/16: typo a JSON status value out of the vocabulary ---"
    fresh_copies
    mutate_entry_field rm-rf layer1 supportd
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 3/16 (status typo out of vocabulary)" "(B2)" "$out" || true

    echo "--- self-test pass 4/16: break the JSON's syntax ---"
    fresh_copies
    printf '{not valid json' >"$tmpdir/defense-boundary.json"
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 4/16 (broken JSON syntax)" "(B1)" "$out" || true

    echo "--- self-test pass 5/16: empty the Caught table body ---"
    fresh_copies
    python3 - "$tmpdir/SECURITY.md" <<'PYEOF'
import re, sys
p = sys.argv[1]
lines = open(p, encoding="utf-8").readlines()
out = []
in_caught = False
skipped_header = 0
for l in lines:
    if l.startswith("#### Caught"):
        in_caught = True
        out.append(l)
        continue
    if l.startswith("#### Not caught — by design"):
        in_caught = False
        out.append(l)
        continue
    if in_caught and l.startswith("|"):
        # keep header + separator (first two "|" lines), drop all data rows
        if skipped_header < 2:
            out.append(l)
            skipped_header += 1
        continue
    out.append(l)
open(p, "w", encoding="utf-8").writelines(out)
PYEOF
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 5/16 (emptied Caught table, vacuous-pass guard)" "zero data rows" "$out" || true

    echo "--- self-test pass 6/16: delete the '#### Caught' heading itself ---"
    fresh_copies
    sed_md '/^#### Caught$/d'
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 6/16 (deleted Caught heading, 0-match not a silent crash)" "zero data rows" "$out" || true

    echo "--- self-test pass 7/16: change layer1 status base token for one Caught row (md-side) ---"
    fresh_copies
    sed_md 's/| `chmod 777` | supported | supported | `omamori test`, CI, hook integration |/| `chmod 777` | not covered | supported | `omamori test`, CI, hook integration |/'
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 7/16 (layer1 base token changed)" "(B5)" "$out" || true

    echo "--- self-test pass 8/16: alter one structural-limit surface cell (md-side) ---"
    fresh_copies
    sed_md "s/| \`alias rm='\/bin\/rm'\` |/| \`alias rm='\/bin\/rm-CHANGED'\` |/"
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 8/16 (structural-limit surface altered, only that table flags)" "'structural_limit' surface set mismatch" "$out" || true

    echo "--- self-test pass 9/16: delete 'not covered' from the legend ---"
    fresh_copies
    sed_md 's/· \*\*not covered\*\* (no protection at this layer, but another layer may cover it) //'
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 9/16 (legend term deleted)" "(B2)" "$out" || true

    echo "--- self-test pass 10/16: turn the escaped pipe into a literal pipe (md-side) ---"
    fresh_copies
    sed_md 's/curl URL \\| bash/curl URL | bash/'
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 10/16 (unescaped literal pipe shifts columns)" "column(s) after parsing" "$out" || true

    echo "--- self-test pass 11/16: change a status note only (must NOT fail) ---"
    fresh_copies
    sed_md 's/supported (v0.10.1)/supported (v0.11.0)/'
    mutate_entry_field path-override-bypass layer2_note v0.11.0
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "check-boundary-matrix --self-test: FAIL — pass 11/16 (note-only change) unexpectedly FAILed. Got:"
        printf '%s\n' "$out"
        self_test_fail=1
    else
        echo "pass 11/16 (note-only change does not trip base-token comparison): OK"
    fi

    echo "--- self-test pass 12/16: append text to a structural-limit surface cell (md-side) ---"
    fresh_copies
    sed_md "s/| \`alias rm='\/bin\/rm'\` |/| \`alias rm='\/bin\/rm'\` and shell functions |/"
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 12/16 (surface cell append-edit, set-equality catches it)" "'structural_limit' surface set mismatch" "$out" || true

    echo "--- self-test pass 13/16: break the schema file's own JSON syntax ---"
    fresh_copies
    cp "$schema_file" "$tmpdir/defense-boundary.schema.json"
    printf '{not valid json' >"$tmpdir/defense-boundary.schema.json"
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$tmpdir/defense-boundary.schema.json" 2>&1)"
    set -e
    assert_fail_contains "pass 13/16 (broken schema file syntax)" "(B1)" "$out" || true

    echo "--- self-test pass 14/16: duplicate an entries[].id across two rows ---"
    fresh_copies
    # chmod-777's id collides with the "rm -rf" row's id; surface text is
    # left untouched so B4 (surface set equality) does not also fire here.
    mutate_entry_field chmod-777 id rm-rf
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 14/16 (duplicate entries[].id)" "duplicate entries[].id" "$out" || true

    echo "--- self-test pass 15/16: change layer2 status base token for one Caught row (md-side, isolated from layer1) ---"
    fresh_copies
    sed_md 's/| Env-var tampering (`unset CLAUDECODE`, `export -n`) | not covered | supported | Hook integration env-tampering corpus |/| Env-var tampering (`unset CLAUDECODE`, `export -n`) | not covered | not applicable | Hook integration env-tampering corpus |/'
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 15/16 (layer2 base token changed, layer1 untouched)" "(B5)" "$out" || true

    echo "--- self-test pass 16/16: inject a JSON entry with an unrecognized category value ---"
    fresh_copies
    python3 - "$tmpdir/defense-boundary.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data["entries"].append({
    "id": "fake-typo-category",
    "category": "structual_limit",  # typo of "structural_limit"
    "surface": "Injected by self-test, phantom claim via category typo",
    "why": "injected by self-test",
    "mitigation": "injected by self-test",
})
json.dump(data, open(p, "w"), indent=2)
PYEOF
    set +e
    out="$(run_check "$tmpdir/SECURITY.md" "$tmpdir/defense-boundary.json" "$schema_file" 2>&1)"
    set -e
    assert_fail_contains "pass 16/16 (unrecognized category value)" "unrecognized category" "$out" || true

    if [ "$self_test_fail" -ne 0 ]; then
        echo "check-boundary-matrix --self-test: FAIL"
        exit 1
    fi
    echo "check-boundary-matrix --self-test: OK (all 16 passes behaved as expected, no false positives)"
    exit 0
fi

set +e
out="$(run_check "$security_md" "$json_file" "$schema_file" 2>&1)"
rc=$?
set -e
printf '%s\n' "$out"
[ "$rc" -ne 0 ] && fail=1

b7_check || fail=1

if [ "$fail" -ne 0 ]; then
    echo
    echo "check-boundary-matrix: FAIL"
    exit 1
fi

echo
echo "check-boundary-matrix: OK"
