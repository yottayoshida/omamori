<!-- Thank you for contributing to omamori.
     Keep PRs small (ideally < 100 lines of diff) and focused on a single change. -->

## Summary

<!-- 1-3 lines: what this PR changes and why. -->

## Change Type

- [ ] `feat/` — new feature or behavior change
- [ ] `fix/` — bug fix (no behavior change for correct inputs)
- [ ] `docs/` — documentation only
- [ ] `refactor/` — internal refactor (no behavior change)
- [ ] `ci/` — CI/CD or tooling changes
- [ ] `security/` — security fix or hardening

> **Branch prefix is MUST for new branches** (v0.9.3+): `feat/<slug>`, `fix/<slug>`, …
> Legacy `feature/*` branches are accepted **only until 2026-05-15** so in-flight
> PRs can land. After the cutoff, new `feature/*` branches may be rejected and
> remaining ones may be renamed or promoted to a GitHub ruleset. See
> `CONTRIBUTING.md` for the migration ladder.

## CI Checklist

- [ ] `./scripts/pre-pr-check.sh` passes locally (fmt + clippy + tests, all `--locked`)
- [ ] I did NOT run `cargo` commands with `--allow-dirty` or `--no-verify`
- [ ] If I bumped a dependency: `Cargo.lock` is updated and committed
- [ ] If I touched a workflow: every `uses:` is a 40-char SHA with a `# vX.Y.Z` comment
- [ ] If I touched `Cargo.toml`: `cargo publish --dry-run --locked` still succeeds

## Security Checklist

- [ ] No new `cargo install` without `--locked --version` (or `taiki-e/install-action` with `fallback: none`)
- [ ] No new files under `.claude/`, `investigation/`, or `CLAUDE.local.md` committed
- [ ] No secrets, tokens, or PII in diff / commit messages

## Context

<!-- Issue number, design doc, or prior PR. -->
