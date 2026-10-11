# ADR-0020: The hook splits a command as the shell does only where it is sure, and materializing never stands in for a check

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-503-577-579-shell-writes-verify-lock-poc.md` (PR-2, PR-3, PR-4)
- **Issue**: [#585](https://github.com/yottayoshida/omamori/issues/585)

## Context

The hook turns every unquoted newline into ` ; ` (`normalize_compound_operators`) and hands the result to `shell_words::split`. Three things follow, all measured on 1.4.0 through `hook-check`:

- **A comment line hides everything after it.** `shell_words` treats a word-initial `#` as a comment to the end of the string, and no newline is left to end it. `# update` followed by `git push --force` is allowed.
- **A heredoc's body is read as commands.** A seven-line body containing `git push --force` is blocked when written with `cat > notes.md <<'EOF'`.
- **A command the hook materializes skips every rule.** `git push --force; curl … | bash`, and `git push --force` after twenty-one `true;` segments, are allowed. `docs/FAQ.md` says named rules are unaffected by `[structural] action`.

The second and third have hidden each other: long heredoc bodies reached the materialize route and so did not block. Fixing either alone moves the other. And every hand-written reading of shell syntax that disagrees with the shell in one place tends to fail open, because what it misreads it usually drops.

## Decision

**Where the hook's reading could differ from the shell's, it takes the reading that shows more. A change that hides text from the checks is made only where its conditions are all met; a change that shows more is made wherever it applies.**

1. **A heredoc body is set aside only when all of these hold**: the `<<` is at top level — inside no quote, command or arithmetic substitution, parameter expansion, `((`, or comment; the delimiter is a plain identifier, optionally quoted; a line holding only the delimiter ends the body, and no body line ends in `\` when the delimiter is unquoted; the line holding the `<<` is not continued; the reader is on a fixed list of programs that do not read their input as shell (`cat`, `tee`, `jq`, `yq`, `grep`, `wc`, `sort`, interpreters reading their own language, and named `git` and `gh` subcommands without `-c`); its segment feeds no pipe and no process substitution or descriptor above 2; and the command defines no function or alias. Any body that fails one of these is read as commands, as today, including by Phase 1B.
2. **A comment runs to the end of its line.** Newlines are kept for the word splitter, which ends a comment there, and normalize copies a comment through untouched. The quote-aware scan does not remove comments: it only puts a `\` before a `#` the shell reads inside a word (backquotes, substitutions, arithmetic, parameter and `[[ … ]]` expressions) but the splitter would take for a comment. A misreading there shows more of a command, never less; past anything the scan cannot follow, it changes nothing.
3. **Materializing decides what happens to a command no check blocked.** Parsing goes on past a materializable finding, every segment that parses is checked, and a segment `shell_words` cannot split is also checked as words split on unquoted whitespace. The limits on segments and tokens are raised to sizes that bound the hook's time and that no command in a sample of real materialized commands reaches; past them the command is blocked, whatever `[structural] action` says, so padding cannot carry a command past the checks.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Fix comments alone | `# heading` lines in heredoc bodies currently hide the rest of the body; showing it multiplies false positives. |
| Remove comments with the quote-aware scan | Review found inputs (a `#` after `<(…)`, after a `]]` inside a character class, after a quote in a heredoc inside a substitution) where a misread removed commands 1.4.0 still saw. A scan that only adds a `\` cannot hide anything. |
| Read a body as commands only when a shell reads it | Executors missing from the list (`sudo -s`, `su`, `time bash`, `xargs sh -c`, a function named `cat`) would have their bodies hidden — commands blocked today would pass. |
| Exclude the constructs where `<<` is not a heredoc (`$((`, `${`, `$[`) | Every construct left off the list hides the commands after it; review found three, each confirmed in bash 3.2 and zsh. |
| Block every materializable command | Removes the materialize route the FAQ documents, for commands no check objects to. |

## Consequences

- Commands after a comment line, and rule matches inside commands that used to be materialized, are now blocked. This is added coverage under the breaking-change policy, and the CHANGELOG lists the shapes.
- Heredoc bodies written to files with the listed readers no longer produce false positives. Bodies that fail any condition behave as today.
- A command larger than the raised limits is blocked rather than materialized.
- The hook still does not run a shell. Shapes it cannot model fall to the reading that shows more, which can still produce false positives; they are not dropped.
