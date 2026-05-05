# Release Gates

This document codifies the implicit release gates that omamori has followed since v0.9.0. Every release must pass the applicable gate before `git tag` + `cargo publish` + `gh release create`.

## Patch release gate

All releases (including docs-only) must pass these:

- [ ] `cargo test --locked` pass (macOS + Ubuntu)
- [ ] `cargo clippy --locked -- -D warnings` pass
- [ ] `cargo fmt --check` pass
- [ ] `RUSTFLAGS="-D warnings" cargo test` pass
- [ ] Hook integration tests pass (`tests/hook_integration.rs`)
- [ ] Crate contents guard pass (`scripts/check-crate-contents.sh`)
- [ ] Publish dry-run pass (`cargo publish --dry-run --locked`)
- [ ] MSRV check pass
- [ ] Security audit pass (`cargo audit`)
- [ ] Lockfile sanity pass
- [ ] Action pin check pass
- [ ] CHANGELOG.md entry added
- [ ] Version bumped in `Cargo.toml`

## Security-affecting release gate (additive)

When the release closes a bypass or changes defense behavior, additionally:

- [ ] Bypass corpus updated (`tests/hook_integration.rs` new entries)
- [ ] SECURITY.md Known Limitations updated (section A closure row added)
- [ ] Defense Boundary Matrix row added or updated
- [ ] Live Claude Code path verified (acceptance test relevant rows)
- [ ] If Codex CLI / Cursor affected, target-specific acceptance test note added
- [ ] CHANGELOG includes threat-model impact description
- [ ] Known-bypass-becomes-row rule followed (matrix + corpus + Known Limitations)

## v1.0 release gate (additive)

v1.0 ships when:

- [ ] No open P0 / P1 known bypass in supported surfaces
- [ ] Live-path acceptance for Claude Code and Codex CLI (all acceptance test rows PASS)
- [ ] `omamori doctor` covers all supported install targets
- [ ] Defense Boundary Matrix published and live-verified for all supported cells
- [ ] Fallback / unsupported paths documented in SECURITY.md
- [ ] `omamori report` covers all supported providers
- [ ] README bounded claims match actual verified state

## Release ceremony

After all gates pass:

```bash
# 1. Version bump + CHANGELOG (single commit)
# 2. Tag
git tag vX.Y.Z

# 3. Push
git push && git push --tags

# 4. GitHub Release (title format: vX.Y.Z — <subtitle>)
gh release create vX.Y.Z --title "vX.Y.Z — <subtitle>" --notes-file <changelog-section>

# 5. Publish to crates.io
cargo publish --locked

# 6. Homebrew tap PR
# Update homebrew-tap formula, merge, verify `brew upgrade omamori`

# 7. Post-release verification
omamori --version  # confirms new version
omamori doctor     # confirms healthy install
```

Each step from tag onward is a separate checkpoint requiring explicit approval. See `rules/git.md` for the full protocol.
