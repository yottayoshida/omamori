# omamori

AI Agent dedicated command safeguard for dangerous shell operations.

- `omamori test` verifies the built-in policy set without touching the filesystem.
- `omamori exec -- <command>` exercises the policy engine before PATH shim installation.
- The current implementation covers Round 1 core policy logic from `PLAN.md`.
- Known v0.1 limitation: combined short flags such as `rm -rfv target` are not yet normalized,
  so matching is exact-token based.
