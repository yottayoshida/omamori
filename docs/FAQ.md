# FAQ / Troubleshooting

Practical answers for the situations omamori users hit most often. Start here when you're stuck; each section links to the normative reference ([SECURITY.md](../SECURITY.md)) instead of restating it.

> Verified against omamori **v0.13.0**. If a command here disagrees with your installed version's `omamori --help`, trust `--help`.

| If this is you… | Go to |
|-----------------|-------|
| "omamori just blocked something I meant to do" | [omamori blocked something legitimate](#omamori-blocked-something-legitimate) |
| "I need to get past a block right now" | [I need to bypass temporarily](#i-need-to-bypass-temporarily) |
| "Why exactly was that command blocked?" | [Why was this command blocked?](#why-was-this-command-blocked) |
| "What is this staging file / 'materialized' message?" | [What is a staging file?](#what-is-a-staging-file--what-does-materialized-mean) |
| "`omamori audit verify` says the chain is broken" | [omamori audit verify says the chain is broken](#omamori-audit-verify-says-the-chain-is-broken) |
| "Would omamori catch X?" | [Does omamori protect against X?](#does-omamori-protect-against-x) |
| "Claude Code blocks *every* command with a hook error" | [README → Troubleshooting](../README.md#troubleshooting) (different problem class: a broken hook path, not a policy decision) |

---

## "omamori blocked something legitimate"

First decide: is this a **one-off** (you need this command to go through right now, once) or **recurring** (omamori keeps blocking a workflow you consider safe)?

### One-off → break-glass

Use a time-limited bypass for the specific rule that fired. See [I need to bypass temporarily](#i-need-to-bypass-temporarily) below.

### Recurring → adjust the ruleset

1. Find out which rule keeps firing. `omamori report` aggregates recent audit entries, including a per-rule breakdown:

   ```bash
   omamori report --last 7d
   ```

2. `omamori config list` shows every rule and its status — this is a read-only command and always allowed, including through an AI agent. To disable one, run `omamori override disable <rule-name>` **in a plain terminal** — that command mutates config and is blocked when run through an AI agent:

   ```bash
   omamori config list
   omamori override disable <rule-name>
   ```

   You'll also see `omamori config disable <rule-name>` — that's for non-core rules. Every built-in rule currently ships as core, so it rejects any built-in name ("is a core safety rule and cannot be disabled"); `override disable`, used above, is what actually works on a built-in today.

3. Or scope the behavior more precisely with a custom rule instead of disabling a built-in — again, **in a plain terminal**, since `config add` mutates config too and is blocked when run through an AI agent:

   ```bash
   omamori config add my-rule --command <cmd> --action <block|trash|stash|log-only|move-to> --match-any <token>
   ```

   (`--action move-to` additionally requires `--destination <abs-path>`; omitting it is a usage error, not a silently-ignored flag.)

   `config disable`/`config enable` accept custom rule names too (not just built-ins) — `omamori config disable my-rule` toggles the rule you just scaffolded. One honest caveat: this only works when the rule is written in `[[rules]]` array-of-tables form (which is what `config add` writes). A custom rule written by hand as an inline array (`rules = [{ name = "my-rule", ... }]`) still can't be toggled via `config disable`/`enable` — those commands will refuse rather than risk corrupting the file. To change or remove a rule in that form, edit `~/.config/omamori/config.toml` directly, then check it with `omamori config validate`.

   A successful `config disable`/`config enable`/`config add` is also recorded in the audit chain (`omamori audit show`) — these ruleset changes leave the same tamper-evident trail as command decisions do.

### Doctor says `awaiting first invocation` or `WARN last active`

These are health signals, not blocks:

- **`last active: awaiting first invocation`** — the PATH shims have never fired yet. Have your AI tool run a harmless guarded command (e.g. `git status`), then re-run `omamori doctor`; it should switch to `last active: today`. If it stays awaiting, the shims are probably not on `PATH` for your AI tool.
- **`WARN last active: N days ago`** — shims haven't fired in more than 3 days. Same likely cause: the shim directory dropped out of `PATH` (e.g. a shell profile change).
- **`WARN last active: future timestamp — clock skew detected`** — your system clock moved backwards; the heartbeat file is from the "future". Harmless once the clock is right.

`omamori doctor` prints a specific remediation hint next to each warning; `omamori doctor --fix` (plain terminal only) repairs the standard cases.

---

## "I need to bypass temporarily"

`break-glass` grants a time-limited, audit-logged bypass for one named rule:

```bash
omamori break-glass --rule <rule-id> --duration 30m --reason "restoring backup"
omamori break-glass --status
omamori break-glass --clear --rule <rule-id>
```

What to know before you reach for it:

- **Duration**: defaults to 1 hour; accepted range is 5 minutes to 24 hours. At most 3 bypasses can be active at once.
- **It requires a real interactive terminal.** The confirmation prompt cannot be answered from a pipe, a script, or an AI agent's shell — that is a deliberate safety gate, not a bug. Run it yourself, in your own terminal.
- **Recorded by default.** Activation, expiry, and every command that passes through an active bypass land in the audit log (`omamori audit show`) as long as audit logging is enabled — a bypass is visible, not silent.
- **Core self-protection rules can't be bypassed** (the `omamori-*-block` family). That's [DI-13](../SECURITY.md#design-invariants-v090), and it's what makes it safe to document this command openly: an AI agent cannot run it on your behalf.

If you find yourself breaking glass for the same rule repeatedly, that's the recurring case — adjust the ruleset instead ([previous section](#omamori-blocked-something-legitimate)).

---

## "Why was this command blocked?"

`omamori explain` simulates a command through both defense layers **without executing it** and reports what each layer would do and which rule matched:

```bash
omamori explain -- rm -rf /tmp/x
```

Abridged output:

```
Verdict: BLOCK
Layer 1 (PATH shim):  rule: rm-recursive-to-trash  action: trash
Layer 2 (hooks):      phase: rule: rm-recursive-to-trash
```

Read it as: which layer matched, which rule, and what action would apply (`trash` means the targets are moved to Trash instead of deleted; `block` refuses outright).

**Run it in your own terminal.** `explain` is itself blocked in AI-agent environments — if an AI could ask "would this be blocked?" before every attempt, it could probe the ruleset for gaps (oracle-attack prevention, by design). The `hint: run omamori explain …` line in a block message is addressed to *you*, the human, even when the AI is the one showing it to you.

`--json` gives the same verdict machine-readably; `--config PATH` simulates against an alternate config file.

---

## "What is a staging file?" / What does "materialized" mean?

Some command *shapes* — piping a download straight into a shell, unparseable input, extreme token counts — are structurally risky but very often legitimate. Hard-blocking all of them made omamori too noisy, so since v0.11.2 the default for these **structural patterns** is `materialize`:

- The command is **allowed to run**, and
- an exact copy of it is written to a **staging file** under `~/.local/share/omamori/staging/`, so you can review after the fact what actually went through. (If the staging write itself fails — disk full, permissions — that's logged as a warning and, by default, the command still runs with the receipt missing. If you've set `[audit] strict = true`, a failed staging write blocks the command instead — strict mode treats "no receipt" as a reason not to allow.)

So a `materialized — staging file: …` message means "this ran, and here's the receipt" — not "this was blocked". Staging files are pruned automatically (7-day retention, 500-file cap by default).

If you'd rather hard-block structural patterns than collect receipts:

```toml
# ~/.config/omamori/config.toml
[structural]
action = "block"     # default: "materialize"
```

Named-rule matches (`rm -rf` etc.) are unaffected by this setting — those always follow their rule's action. Details on the `[structural]` config section: [README.md → Rule configuration](../README.md#rule-configuration).

---

## "omamori audit verify says the chain is broken"

**Do not delete `audit.jsonl`.** Copy it aside first:

```bash
cp ~/.local/share/omamori/audit.jsonl ~/audit.jsonl.backup
```

Deleting the log is the one step here that cannot be undone, and most of the states that produce this message are recoverable without it.

Four different messages bring you here, and they mean different things:

| Message | Exit | What it means |
|---------|------|---------------|
| `chain broken at entry #N` / `The audit log may have been tampered with.` | 1 | An entry's hash does not match the key it names. Either the log was altered, **or** the key that entry was signed with is no longer the one its `key_id` resolves to |
| `cannot verify from entry #N — it names key "…", which is not in the keyring` | 2 | The key that entry names cannot be loaded. omamori is not accusing anything — it is saying it cannot check |
| `cannot verify — audit keyring: cannot list …` | 2 | The key directory itself could not be read. This is a permissions or storage problem, not a log problem: fix the directory and re-run |
| `cannot verify — <something about audit-secret>` | 2 | The active key file could not be read, and the message says why: it is a symlink, or not a regular file, or the wrong size, or not valid hex. The directory listed fine, so this is about that one file |
| `cannot verify — audit keyring: … audit-secret.epoch …` | 2 | The file recording which key epoch is current does not hold a number omamori wrote. Neither the log nor the keys are at fault — see "The epoch record was edited or corrupted" below |

### Work out which state you are in

1. **Which entry.** The message names it as `#N`. For a break near the head:

   ```bash
   omamori audit show --all --json | head -20
   ```

   For one further in, `omamori audit show --last 10 --json`. Use `--json`: it carries the `seq` field, and the plain table has no seq column.

2. **Which key that entry names.** Read `key_id` from that entry:

   - `"default"` — epoch 1, written before this store ever rotated
   - `"key-N"` — epoch N
   - `"unresolved"` — omamori wrote this entry while it could not determine which key epoch was active, so it carries no HMAC and never did. No key file is missing, and restoring one will not help

3. **Which key files exist.**

   ```bash
   ls -la ~/.local/share/omamori/
   ```

   An epoch's key sits in `audit-secret` while it is the current key, and moves to `audit-secret.{N}.retired` when the next rotation displaces it — **the number in the id and the number in the filename are the same one**:

   | `key_id` | Look in |
   |----------|---------|
   | `"default"` (epoch 1) | `audit-secret`, or `audit-secret.1.retired` if this store has rotated |
   | `"key-2"` | `audit-secret`, or `audit-secret.2.retired` |
   | `"key-N"` | `audit-secret`, or `audit-secret.N.retired` |

### Common causes

**A retired key file was deleted or renamed.** Tidying `~/.local/share/omamori/` is the usual way to get here. If you still have the file — in a backup, in Trash — put it back under its original name and re-run `omamori audit verify`. Nothing about the log itself changed; this is fully recoverable.

On a store that has rotated since omamori started recording key epochs, this reports as *cannot verify* (exit 2). On one that has not — no `audit-secret.epoch` file — deleting the **only** retired key still produces exit 1 and the tampering wording, because with nothing recorded and no `.retired` files left the store cannot tell itself apart from one that never rotated. The remedy is the same either way: put the file back.

**The epoch record was edited or corrupted.** `audit-secret.epoch` holds one decimal number, the highest key epoch this store has handed out, and omamori refuses to guess past a file that says anything else — that number decides which key every entry is checked against. Deleting it is safe, and is the documented way out:

```bash
rm ~/.local/share/omamori/audit-secret.epoch
```

The store then works the epoch out from the `.retired` files again, which is what it did before the record existed. You lose what the record buys — a deleted retired key goes back to reading as tampering rather than as cannot-verify — so if you have a backup of the file, prefer restoring it.

**A copy of a key was left in the directory.** A file named `audit-secret.<number>.retired` is read as that epoch's key, whatever it actually contains. Copying `.1.retired` to `.2.retired` gives epoch 2 the epoch-1 bytes, and every entry labelled `key-2` stops verifying. Keep spare copies **outside** this directory, or under a name that does not end in `.retired`.

**A rotation was interrupted.** If `.retired` files are present and `audit-secret` is missing, a rotation stopped between retiring the old key and creating its replacement. What to do depends on one thing:

- **Before any replacement exists** — `audit-secret` is still absent — *moving* (not copying) the highest-numbered `.retired` file back to `audit-secret` restores the state before the rotation. Use a form that refuses to overwrite, so a race or a misread does not cost you a key:

  ```bash
  cd ~/.local/share/omamori && mv -n audit-secret.2.retired audit-secret   # adjust the number
  ```

  If `audit-secret` still exists afterwards alongside the `.retired` file, `mv -n` declined and you are in the case below, not this one.
- **Once a replacement exists** — omamori tries to create one the next time any command needs a key, and prints a warning saying whether it managed to — moving a `.retired` file over it **destroys** the key that entries written since were signed with, and those entries then read as tampering permanently. Existing entries are never rewritten to repair this ([ADR-0007](adr/0007-no-in-place-rewrite-of-existing-audit-entries.md)).

  So check before you act, rather than assuming which side of that line you are on: `ls -l ~/.local/share/omamori/audit-secret`.

  If you are past that point, leave `audit-secret` alone. Entries from before the rotation still verify against their retired keys.

**A key could not be created while the store had none.** If omamori warned that `audit-secret` was absent *and* a replacement could not be created — a data directory that can be read and searched but not written does this — then everything written in that window carries no HMAC while still being labelled with the next epoch. Fixing the permissions creates a key under that same label, and those entries are then checked against it, fail, and are reported as tampering. They cannot be repaired ([ADR-0007](adr/0007-no-in-place-rewrite-of-existing-audit-entries.md)). The break is genuine in the sense that the hashes do not match; nothing was altered by anyone. Note the seq range from the warning's timestamp so you can tell those entries apart later.

One case is exempt, and the warning tells you which one you are in. If the same fault also stopped omamori from recording the new key epoch — the message names `audit-secret.epoch` and says it could not be advanced — then those entries are labelled `unresolved` rather than with an epoch, and no key can ever be created under that id. They stay cannot-verify. That reads worse and is better to have: nothing is accused of anything.

### If none of those apply

An entry whose hash does not match, with every key file present and untouched and no warning of the kind above in your logs, is what tampering looks like. Note that `key_id` is an ordinary field of `audit.jsonl` — anyone who can write the file can edit it — so an entry that moved from exit 1 to exit 2 is not itself reassuring. Treat both wordings as reportable when you did not touch the key directory yourself.

Entries before the break are still verified; the counts in the message say how many. Keep the copy you made at the top.

---

## "Does omamori protect against X?"

Plain-language answers for common cases. The [Defense Boundary Matrix](../SECURITY.md#defense-boundary-matrix-v0101) is the normative, test-backed version of this list — when in doubt, trust the matrix.

| Case | Protected? | How / why not |
|------|-----------|---------------|
| AI runs `rm -rf <dir>` | **Yes** | Layer 2 hooks — active in essentially every AI-agent session — deny the command outright. (If a command only reaches Layer 1, e.g. a plain terminal with no hook layer in front of it, the PATH shim converts it to a move-to-Trash instead of denying it.) |
| AI runs `/bin/rm -rf <dir>` (full path, dodging the PATH shim) | **Yes** | Layer 2 hooks catch it; the shim alone would not |
| AI wraps it: `sudo env bash -c "rm -rf …"` | **Yes** | Layer 2 unwraps wrapper chains before matching |
| AI pipes a download into a shell (`curl … \| bash`) | **Yes*** | *Materialized by default (allowed + staging receipt), or hard-blocked if you set `[structural] action = "block"` |
| AI tries to edit omamori's own config/hooks via Write/Edit tools | **Yes** | Protected-file gate blocks the file operation directly. (Trying the same thing as a *command* — `omamori config disable …` — is a separate mechanism, the [DI-13](../SECURITY.md#design-invariants-v090) self-modification rules.) |
| AI overwrites **your** source files via its native Write/Edit tools | **No — by design** | omamori guards Bash commands and its own files; your working tree's safety net is git hygiene (`git diff` before committing), not omamori |
| AI runs `python -c "shutil.rmtree(…)"` | **No — by design** | Interpreter internals are out of scope ([#74](https://github.com/yottayoshida/omamori/issues/74)) |
| Runtime-obfuscated commands (`X=rm; $X -rf …`) | **No — structural limit** | Static analysis can't evaluate runtime variables; sandbox isolation is the right tool there |

The last three rows are the honest part: omamori narrows the blast radius of known destructive patterns — it is not a sandbox. See [Not caught — by design](../SECURITY.md#not-caught--by-design) and [Not caught — structural limit](../SECURITY.md#not-caught--structural-limit) for the complete lists.

---

## A real-world example

[2026-04-23: Codex CLI, Notion MCP re-authentication](dogfood/2026-04-23-codex-notion-mcp-reauth.md) — a production transcript where Codex CLI tried to read `~/.codex/config.toml` during an OAuth re-auth, omamori's config-protection hooks blocked the reads in cascade, and the human completed the re-auth out-of-band. A compact illustration of the intended division of labor: the AI is walled off from omamori's own configuration, and the recovery path runs through the human's terminal.

---

*This page is a practical guide. For the security model, invariants, and verified boundaries, [SECURITY.md](../SECURITY.md) is normative.*
