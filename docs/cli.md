# CLI reference

Every `omamori` subcommand. Start with [Quick start](../README.md#quick-start) if you have not installed it yet.

```
omamori setup [--dry-run] [--non-interactive] [--source PATH]  # One-command install + shell profile + verify
omamori install [--hooks] [--source PATH]  # Install shims + hooks (no shell profile)
omamori doctor [--fix] [--verbose] [--json]  # Diagnose and auto-repair installation (exit 0/1/2)
                                         # A line under the headline points at the risk signals when they hold something to act on
omamori explain [--json] -- <cmd...>     # Show what would happen to a command and why
omamori test [--config PATH]             # Verify policy rules
omamori status [--refresh]               # Health check all defense layers (exit 0/1/2)
omamori exec [--config PATH] -- CMD      # Run command through policy engine

omamori report [--last 7d] [--json] [--verbose]  # Aggregate audit summary (1d–90d)

omamori audit verify                     # Verify hash chain integrity (exit 0/1/2/3/4)
omamori audit show [--last N] [--json]   # View recent audit entries (default: last 20)
omamori audit show --all                 # View all entries
omamori audit show --rule <name>         # Filter by rule (substring match)
omamori audit show --provider <name>     # Filter by provider
omamori audit show --relaxed             # Filter to relaxed allows (legacy data-context flag; pre-v0.10.4 logs only)

omamori config list                      # Show rules with status
omamori config add <name> --command <cmd> --action <block|trash|stash|log-only|move-to> [--match-any <token>]... [--match-all <token>]... [--destination <abs-path>] [--message <text>]  # Scaffold a custom rule
omamori config disable <rule>            # Disable a rule
omamori config enable <rule>             # Re-enable a rule
omamori config validate [PATH]           # Validate config (exit 0/1/2)
omamori override disable <rule>          # Override a core safety rule
omamori override enable <rule>           # Restore a core safety rule

omamori break-glass --rule <id> [--duration <dur>]  # Time-limited bypass for false positives
omamori break-glass --status             # Show active bypasses
omamori break-glass --clear [--rule <id>]  # Revoke bypass(es)

omamori init [--force] [--stdout]        # Create/reset config
omamori uninstall                        # Remove shims + hooks
omamori hook-check [--provider NAME] [--json-error]  # Hook detection engine (used internally by hooks)
omamori cursor-hook                      # Cursor hook handler
omamori --version                        # Show version
```
