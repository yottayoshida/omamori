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

## GitHub Actions SHA pinning

Every `uses:` in `.github/workflows/*.yml` MUST be pinned to a 40-character
commit SHA with a trailing `# vX.Y.Z` comment, e.g.

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

Dependabot updates both the SHA and the version comment automatically. Floating
tags (`@v4`, `@main`) are rejected by the `action-pin-check` CI job.

---

## Before opening a PR

Run the local gate once. It is a thin wrapper around the CI jobs, with
`--locked` on every `cargo` invocation so a stale `Cargo.lock` fails fast.

```bash
./scripts/pre-pr-check.sh
```

If `Cargo.lock` was updated during the run, commit it. Do not pass
`--allow-dirty` or `--no-verify` to `cargo` or `git`.

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
