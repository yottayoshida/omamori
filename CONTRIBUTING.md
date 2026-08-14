# Contributing to omamori

Thank you for considering a contribution. omamori is a security product for
AI-assisted development environments, so supply-chain integrity and small,
reviewable changes matter more than raw throughput.

---

## Branch naming

Use these prefixes. The PR template will remind you.

| Prefix       | Purpose                                                |
|--------------|--------------------------------------------------------|
| `feat/*`     | New feature or behavior change                         |
| `fix/*`      | Bug fix (no behavior change for correct inputs)        |
| `docs/*`     | Documentation only                                     |
| `refactor/*` | Internal refactor (no behavior change)                 |
| `ci/*`       | CI/CD or tooling changes                               |
| `security/*` | Security fix or hardening                              |

### `feature/*` → `feat/*` migration

`feature/*` was the historical prefix. Starting with v0.9.3, new branches MUST
use `feat/*`. Existing `feature/*` branches are accepted until **2026-05-15**
to let in-flight PRs land naturally. After that cutoff the maintainer may
prune or rename any remaining `feature/*` branches, and `feat/*` enforcement
may be promoted from PR-template checklist to a repository ruleset.

---

## Repository Layout & Automation

| Path / File                         | What it does                                                   |
|-------------------------------------|----------------------------------------------------------------|
| `Cargo.toml` `include=` / `exclude=` | Deny-by-default allowlist of files packaged to crates.io      |
| `Cargo.lock` (tracked, v0.9.3+)     | Reproducible builds for consumers of `cargo install --locked`  |
| `rust-toolchain.toml`               | Pins stable toolchain for dev + non-fuzz CI jobs               |
| `.github/workflows/ci.yml`          | Test, clippy, fmt, MSRV, coverage, guard jobs                  |
| `.github/workflows/fuzz.yml`        | Nightly fuzz (reproducibility NOT guaranteed — corpus is non-deterministic) |
| `.github/dependabot.yml`            | Weekly grouped bumps for cargo + github-actions                |
| `.github/CODEOWNERS`                | Ownership review hint for security-critical paths              |
| `.editorconfig` / `.gitattributes`  | Line-ending + whitespace normalization                         |
| `SECURITY.md`                       | Security model + AI-assisted contribution invariants           |
| `scripts/pre-pr-check.sh`           | Local gate (fmt / clippy / test, all `--locked`)               |
| `scripts/pre-release-check.sh`      | Release gate (clean tree / tag match / package listing / dry-run) |

---

## Process CWD discipline (#175)

`std::env::current_dir`/`std::env::set_current_dir` are banned crate-wide by
`clippy.toml`'s `disallowed-methods` (enforced via `[lints.clippy]` in
`Cargo.toml`, independent of CI's `-D warnings`). The one sanctioned read is
`context::process_base` — everywhere else that needs a base for relative-path
resolution should receive `base: &Path` explicitly (see
`context::normalize_path`/`resolve_path`/`evaluate_context` doc comments) or
call `context::process_base`/`process_base_or_root` itself.

If you hit this lint:

- **You're resolving a relative path (protection judgment, CLI inquiry
  command, etc.)** — thread `base: &Path` through instead, sourced from
  `context::process_base` at the entry point, not re-read deeper in the call
  stack.
- **You're writing a test that must observe the *real* process CWD** (e.g.
  asserting a code path did NOT pollute it — a #373-class regression
  witness) — this is a legitimate exception. Add
  `#[allow(clippy::disallowed_methods)]` with a `// reason:` comment
  immediately above the call explaining why the real CWD specifically (not
  an arbitrary absolute path) is needed. Grep `disallowed_methods` in this
  repo for existing examples before writing a new one — most cases are
  already covered by the same pattern.

---

## GitHub Actions SHA pinning

Every `uses:` in `.github/workflows/*.yml` MUST be pinned to a 40-character
commit SHA with a trailing `# vX.Y.Z` comment, e.g.

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

Dependabot updates both the SHA and the version comment automatically. Floating
tags (`@v4`, `@main`) are rejected by the `action-pin-check` CI job.

---

## Issue labels (#358)

Every open issue carries **exactly one priority label** (`tier-1` / `tier-2` /
`tier-3`) and **at least one type label**. This is an operating convention kept
by whoever triages, not something machinery enforces — the issue forms do not
auto-apply these labels, so a freshly filed issue may violate it until the next
triage pass.

Priority (`tier-N` — **not** the product-support "Tier 1 / Tier 2" defined in
[docs/CONTRACT.md](docs/CONTRACT.md); that tiering classifies *tool support
commitments*, this one ranks *issue urgency*, and the two share nothing but the
word):

| Label | Meaning |
|-------|---------|
| `tier-1` | High priority: verified defect or v1.0-contract critical |
| `tier-2` | Next phase: thesis-aligned hardening/UX |
| `tier-3` | Low-risk maintenance, documentation, and backlog hygiene |

Type (one or more of): `bug`, `security`, `enhancement`, `documentation`,
`maintenance`. The boundary that has needed spelling out: **`bug` means
something misbehaves today** — in the shipped product *or* in the repo's own
signal (a flaky test suite and a canary that false-fails are both `bug`);
**`maintenance` means nothing misbehaves but hygiene work is due** (a test that
proves less than it claims, a gitignored script, an opportunistic refactor).
`tier-3` + `maintenance` together mark low-risk backlog hygiene specifically.

Other labels (`epic`, `trust`, `false-positive`, `author-input-required`,
`dev:*`) are workflow or theme markers, orthogonal to the two axes above.

---

## Before opening a PR

Run the local gate once. It is a thin wrapper around the CI jobs, with
`--locked` on every `cargo` invocation so a stale `Cargo.lock` fails fast.

```bash
./scripts/pre-pr-check.sh
```

If `Cargo.lock` was updated during the run, commit it. Do not pass
`--allow-dirty` or `--no-verify` to `cargo` or `git`.

If your PR adds a Defense Boundary Matrix row or a `tests/hook_integration.rs`
corpus entry, keep the description and commit messages free of exploit
walkthroughs or step-by-step reproduction detail — see SECURITY.md's
[Corpus PR review criterion](SECURITY.md#corpus-pr-review-criterion).

---

## Releasing (maintainer only)

1. Bump `Cargo.toml` `version`.
2. Update `CHANGELOG.md`.
3. Run `./scripts/pre-release-check.sh` — this verifies a clean tree, the tag
   (once created) matches `Cargo.toml`, nothing forbidden appears in the
   package listing, and `cargo publish --dry-run --locked` passes.
4. `git tag vX.Y.Z && git push --tags`.
5. `cargo publish --locked` (never `--allow-dirty`).
6. Update the homebrew-tap formula.

See `.claude/plans/` for design notes on prior releases.
