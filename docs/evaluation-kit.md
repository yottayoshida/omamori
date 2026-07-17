# 30-day evaluation kit

> Verified against omamori **v0.13.1**. If a command here disagrees with your installed version's `omamori --help`, trust `--help`.

Thanks for evaluating omamori outside the author's own environment — every trust claim in [CONTRACT.md](CONTRACT.md) and [SECURITY.md](../SECURITY.md) is currently backed by single-author dogfood data, and an external run is the missing piece. This kit is self-contained: you should not need to ask the maintainer anything to complete it.

## Privacy, upfront

You report **aggregate numbers**, never raw command history. Everything you paste into the feedback form comes from two local, offline commands: `omamori report --last 30d` and `omamori doctor`. Neither ever prints the commands you actually ran — `report`'s output is counts (blocks by layer, by provider, by rule), not command text. Nothing is sent anywhere automatically; you paste output into a GitHub issue yourself, and only what you choose to paste.

Two caveats on what to paste:

- If you defined custom rules in `config.toml`, the rule names you chose appear in `report`'s "by rule" breakdown, and a rule name is a string you wrote — it can contain a project or client name. Skim that line before pasting; delete or generalize any name that identifies something you'd rather not share (see the feedback template below for exactly where this applies).
- Paste `doctor` output only from a healthy `Protection status: OK` run. On a `WARN`/`FAIL` run, `doctor` can print a config file path (which includes your OS username) or, if you have an active break-glass bypass, its rule name — paste those runs' output only after redacting the path/name, or skip the paste and just describe the state in words.

Do not attach `omamori audit show` output or the raw `audit.jsonl` file to any report — those do contain literal command text and file paths and are out of scope for this kit.

## The 30 days

**Day 1 — setup (about 10 minutes)**

1. Install and enable omamori per [README's Quick Start](../README.md#quick-start).
2. Run `omamori doctor`. Your single success signal is `Protection status: OK`. If it reports `FAIL`, follow the fix hints it prints (`omamori doctor --fix`, run directly in your terminal, not through an AI agent) before continuing.
3. Use your AI tool normally from here on. There is nothing else to actively do until something happens or Day 30 arrives.

**Days 2–29 — normal use**

Nothing to do by default. If omamori blocks a command you believe was a false positive, jot one line at the time (tool used, roughly what you were doing) — that context is easy to lose by Day 30 and is the most valuable thing in the final report. You do not need to file anything now.

**Day 30 — report (about 15 minutes)**

1. Run `omamori report --last 30d` and `omamori doctor`.
2. Open a new issue using the "Evaluation feedback" template and paste the two outputs where indicated.
3. Answer the questions in the template. None require anything beyond what you already have from step 1 and the notes you jotted along the way.

## If you stop early

Disabling or uninstalling omamori partway through is a valid, useful outcome — arguably the most useful one, since it is exactly the signal the evaluation exists to catch. Open the same "Evaluation feedback" issue template early; only the "did you disable/uninstall it, and why" question is required, everything else is optional. A two-question report at day 8 is a complete, valuable submission — please do not skip reporting because the 30 days didn't finish.

## Reporting a missed accident

If omamori failed to catch something it should have (a "miss"), do not describe or paste it into the public feedback template — even a general description of an unfixed gap can be enough to reconstruct it. The feedback template has no field for this; use [SECURITY.md's Reporting a Vulnerability](../SECURITY.md#reporting-a-vulnerability) instead. This keeps a not-yet-fixed gap from being disclosed in a public issue.

## Scope: what counts as a miss

A miss is scored against [SECURITY.md's Defense Boundary Matrix](../SECURITY.md#defense-boundary-matrix-v0101) — omamori guards a curated set of destructive command classes, not arbitrary commands. If in doubt whether something you hit is in scope, file the private report anyway; scoping it correctly is the maintainer's job, not yours.
