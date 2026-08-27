# ADR-0012: A departed reader does not change the verdict

- **Status**: Accepted
- **Date**: 2026-08-27
- **Plan**: `.claude/plans/2026-08-27-omamori-544-sigpipe.md`

## Context

Issue #544. `omamori doctor` and `omamori status` panic when their stdout is closed early, and
the panic replaces the exit code the command decided on. Measured on a healthy v1.0.5 install:
`omamori doctor` exits 0, `omamori doctor | head -3` exits 101. `doctor`'s exit code is a
three-value contract — 0 healthy, 1 fail, 2 warn-only, each pinned by its own test — and 101 is
none of them. Any early-closing reader triggers it: `| head`, `| grep -q`, `| less` where the
operator presses `q`, a script reading the first N lines.

Rust disables the default `SIGPIPE` disposition at startup, so a write to a closed pipe returns
`EPIPE` rather than terminating the process. `println!` panics on that error; a fallible writer
returns it.

**This codebase had already answered the question.** `audit show` handles the same condition
deliberately: `cli::audit_cmd` renders through a `&mut impl Write` and maps a `BrokenPipe` error to
`Ok(0)`, with a comment recording why — a reader taking the first few lines of a long log is a
normal, deliberate act, and reporting it as a failure is wrong. `tests/hook_integration.rs` pins
that with a process-level test that drops the read end before the child's first write and asserts
exit 0, under the name "a reader going away is not an error". That answer was reached in #457 and
had simply never been extended to the other two commands.

## Decision

`doctor` and `status` render through a sink (`cli::checks_display::Out`) that holds a
`&mut dyn Write` and **swallows write failures**, and both commands return the verdict they had
already computed.

Three properties are the decision:

**The verdict is independent of the output, not merely earlier than it.** `doctor`'s 0/1/2 comes
from the `CheckItem` list and `--fix`'s from what the repairs did; neither reads anything about
whether the text arrived. Ordering is not the property — `status` prints its banner *before* it
runs `full_check` — and relying on ordering would be wrong for exactly that case. What makes the
verdict safe is that a failed write neither aborts the flow nor feeds into the answer.

**Write failures are swallowed, never propagated.** No `?`, no `Result` added to any caller's
signature. Converting to `writeln!(out, …)?` would have been the obvious shape and is wrong here:
`run_fix` interleaves printing with repairs, so the first dead write would return early and
abandon the repair half-done — trading #544 for something worse. Dropping text and finishing the
work is the safe direction.

**The conversion is total, and that is checked statically.** All 102 stdout writes in the two
files went through the sink. A behavioural test only exercises the branches its fixture reaches,
so one `println!` left in a `--verbose` arm would keep panicking while every such test passed. A
unit test scans both files for bare `println!`/`print!` outside their test regions and requires
zero, and a second test proves that scanner finds a real call and is not fooled by `eprintln!`.

## Alternatives considered

**Restore the default `SIGPIPE` disposition in `main()`.** This was the plan of record until
review, and it is the shape most Unix CLIs use — one line, and every present and future
`println!` behaves conventionally. Rejected, for four independent reasons:

- It is the **opposite** of the answer `audit show` already gives. The process would die before
  `is_broken_pipe` could run, so `audit show | head` would stop exiting 0, and the test that pins
  that would fail. A codebase should not hold both answers.
- It does not restore the contract #544 is about. It replaces 101 with death by signal (141 as a
  caller sees it through `PIPESTATUS`), and 0/1/2 still never arrive.
- The disposition is inherited by the real commands the shim spawns, so it would change the exit
  status `git`/`rm`/`rsync` report through omamori — a separate, unmeasured behaviour that this
  issue explicitly did not scope.
- `setup`, `install`, `doctor --fix` and `status --refresh` interleave printing with mutation, so
  a closed reader could leave a partially applied install or an unrefreshed baseline, decided by
  scheduling.

**Convert only the two reported commands and leave the rest.** That is what this ADR does, but
the reasoning is worth recording: 10 other files still write to stdout with `println!`, across
147 call sites. `report` is the interesting one — it writes 7 lines with `println!` and does *not*
fail under `| head` (measured five times), because it computes for ~43 seconds and then emits
everything at once, so the whole
report reaches the pipe buffer before the reader can exit. It is not protected by design; it wins
a race. Migrating the remaining files belongs in its own change, not in a fix for a specific
exit-code contract.

**Add a third `Throttle::Never` — unrelated, noted to avoid confusion.** That idea belongs to
#494 and is recorded there.

## Consequences

`doctor` and `status` return the same exit code whether or not anyone is reading. A monitoring
script that pipes either command now sees 0, 1 or 2 where it saw 101.

**Output can be silently truncated.** When the reader leaves, the remaining lines are dropped and
nothing says so. That is the intended trade: the reader asked to stop reading. Nothing branches on
it in production — `Out::reader_left` exists for tests only — because the point of the type is
that the answer does not depend on it.

**A write failure that is not a broken pipe is also swallowed.** A full disk during `doctor` will
lose output rather than report it. This is accepted for the same reason: the verdict is still
correct, and the alternative reintroduces the abandoned-repair problem. The failure kind is
retained on the sink if a future change needs to surface it.

**The rest of the CLI still panics on a closed stdout.** `setup`, `install`, `explain`, `report`,
`config`, `policy_test`, `audit`'s non-`show` output and the two hook responses are unchanged.
The static check covers `doctor.rs` and `status.rs` only, so it will not notice a new `println!`
elsewhere.

**`shim`'s block path is unaffected and remains exposed on stderr.** It prints before it appends
to the audit chain (`engine::shim`), the reverse of the order `engine::hook` uses and documents,
so a closed *stderr* loses the audit row for a blocked command. That is true before and after this
change — nothing here touches stderr — and is worth its own issue.
