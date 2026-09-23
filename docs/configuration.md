# Configuration

How to change what omamori does. For the list of built-in rules, see [How omamori works](how-it-works.md#what-it-blocks).

## Context-aware actions

omamori can adjust actions based on what the command targets:

| Command | Without context | With context |
|---------|----------------|-------------|
| `rm -rf target/` | trash | **log-only** (regenerable) |
| `rm -rf src/` | trash | **block** (protected) |
| `git reset --hard` (no changes) | stash-then-exec | **log-only** (git-aware) |

**Enabled by default.** Built-in lists for regenerable (`target/`, `node_modules/`, etc.) and protected (`src/`, `.git/`, `.env`, etc.) paths are active out of the box. To customize, add a `[context]` section to `~/.config/omamori/config.toml`:

```toml
[context]
# Specifying a list replaces the built-in defaults (not appends).
# regenerable_paths = ["target/", "node_modules/", "my-cache/"]
# protected_paths = ["src/", "lib/", ".git/", ".env", ".ssh/", "secrets/"]
```

> **Note**: specifying `regenerable_paths` or `protected_paths` **replaces** the built-in defaults (not appends). Include the built-in entries you want to keep.

Security features: symlink defense via `canonicalize()`, path traversal normalization, NEVER_REGENERABLE hardcoded list, fail-close on errors.

## Rule configuration

Built-in rules are always inherited. Only write the rules you want to change:

```bash
omamori config list                          # show all rules
omamori config add my-rule --command rm --action block --match-any -rf  # scaffold a custom rule
omamori config disable my-rule               # disable it
omamori config enable my-rule                # re-enable it
omamori override disable git-push-force-block  # disable a built-in (core rules use override, not config disable)
omamori test                                 # verify policy
```

Or edit `~/.config/omamori/config.toml` directly. Config is auto-created by `omamori setup` (or `install --hooks`). See `omamori init --stdout` for the full template.

**Configuration examples:**

**Disable a custom rule** (built-ins ignore `enabled = false` here — see below):
```toml
[[rules]]
name = "my-rule"
enabled = false
```

**Disable a built-in rule** (core rules can only be disabled via `[overrides]`, equivalent to `omamori override disable <rule-name>`):
```toml
[overrides]
git-push-force-block = false
```

**Move files to a custom directory**:
```toml
[[rules]]
name = "rm-to-backup"
command = "rm"
action = "move-to"
destination = "/Users/you/.omamori-quarantine/"  # under your home directory, not /tmp
match_any = ["-r", "-rf", "-fr", "--recursive"]
```

**Override an existing rule**:
```toml
[[rules]]
name = "rm-recursive-to-trash"
action = "move-to"
destination = "/Users/you/.omamori-quarantine/"  # under your home directory, not /tmp
```

**Enable audit retention** (prunes entries older than N days):
```toml
[audit]
retention_days = 90  # 0 = keep all (default). Minimum 7 days.
```

**Enable strict mode** (block shim-intercepted commands when HMAC secret is unavailable):
```toml
[audit]
strict = true  # default: false. Hook-only commands (ls, cat, etc.) are not affected.
```

**Control structural block behavior** (materialize vs hard-block):
```toml
[structural]
action = "block"     # default: "materialize". Set to "block" to hard-block all structural patterns.
retention_days = 7   # auto-prune staging files older than N days. 0 = disabled.
max_files = 500      # cap on staging file count; oldest deleted first. 0 = disabled.
```

**Notes**: config requires `chmod 600`. Destinations must be absolute paths on the same volume. System directories and symlinks are rejected.
