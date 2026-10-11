# ADR-0020: The hook splits a command as the shell does only where it is sure, and materializing never stands in for a check

- **Status**: Accepted
- **Date**: 2026-10-11
- **Plan**: `.claude/plans/2026-10-11-omamori-503-577-579-shell-writes-verify-lock-poc.md` (PR-2, PR-3, PR-4, PR-5)
- **Issues**: [#585](https://github.com/yottayoshida/omamori/issues/585), [#586](https://github.com/yottayoshida/omamori/issues/586)

## Context

The hook turns every unquoted newline into ` ; ` (`normalize_compound_operators`) and hands the result to `shell_words::split`. Three things follow, all measured on 1.4.0 through `hook-check`:

- **A comment line hides everything after it.** `shell_words` treats a word-initial `#` as a comment to the end of the string, and no newline is left to end it. `# update` followed by `git push --force` is allowed.
- **A heredoc's body is read as commands.** A seven-line body containing `git push --force` is blocked when written with `cat > notes.md <<'EOF'`.
- **A command the hook materializes skips every rule.** `git push --force; curl … | bash`, and `git push --force` after twenty-one `true;` segments, are allowed. `docs/FAQ.md` says named rules are unaffected by `[structural] action`.
- **A redirection moves the words a rule reads.** The shell applies a redirection the same wherever it is written in a simple command; `shell_words` leaves it among the words, and the parser skips it only before the program name. `omamori 2>/dev/null override disable …` is allowed, as are `omamori>/dev/null …`, `omamori <&- …`, `env 2>/dev/null -i omamori …` and `unset 2>/dev/null CLAUDECODE` ([#586](https://github.com/yottayoshida/omamori/issues/586)). Normalize also split `>|` into `>` and a pipe, and `<&` into `<` and a background `&`.

The second and third have hidden each other: long heredoc bodies reached the materialize route and so did not block. Fixing either alone moves the other. And every hand-written reading of shell syntax that disagrees with the shell in one place tends to fail open, because what it misreads it usually drops.

## Decision

**Where the hook's reading could differ from the shell's, it takes the reading that shows more. A change that hides text from the checks is made only where its conditions are all met; a change that shows more is made wherever it applies.**

1. **A heredoc body is set aside only when all of these hold**: the `<<` is at top level — inside no quote, command or arithmetic substitution, parameter expansion, `((`, or comment; the delimiter is a plain identifier, optionally quoted; a line holding only the delimiter ends the body, and no body line ends in `\` when the delimiter is unquoted; the line holding the `<<` is not continued; the reader is on a fixed list of programs that do not read their input as shell (`cat`, `tee`, `jq`, `yq`, `grep`, `wc`, `sort`, interpreters reading their own language, and named `git` and `gh` subcommands without `-c`); its segment feeds no pipe and no process substitution or descriptor above 2; and the command defines no function or alias. Any body that fails one of these is read as commands, as today, including by Phase 1B.
2. **A comment runs to the end of its line.** Newlines are kept for the word splitter, which ends a comment there, and normalize copies a comment through untouched. The quote-aware scan does not remove comments: it only puts a `\` before a `#` the shell reads inside a word (backquotes, substitutions, arithmetic, parameter and `[[ … ]]` expressions) but the splitter would take for a comment. A misreading there shows more of a command, never less; past anything the scan cannot follow, it changes nothing.
3. **Materializing decides what happens to a command no check blocked.** Parsing goes on past a materializable finding, every segment that parses is checked, and text `shell_words` cannot split is read by a scan that never fails — quotes, substitutions and groups nest as in the shell, operators outside quotes separate commands, and each line of a heredoc body outside a substitution is read on its own, so a quote in it cannot carry past the body's end. Phase 1B reads the same words. The limits on segments and tokens, counted over the whole command, are raised to sizes that bound the hook's time and that no command in a sample of real materialized commands reaches; past them the command is blocked, whatever `[structural] action` says, so padding cannot carry a command past the checks.

4. **A redirection does not move the words a rule reads.** Each command is also read with the redirections of every top-level simple command moved to its end, at every depth of `bash -c`, and checked as well — Phase 1B, the rules and the structural findings; the stricter verdict stands. The reading as written is unchanged but for normalize's reading of `>|` and `<&` (below), so a mistake in moving can add a block, never remove one. Only what the shell reads as a redirection moves: an operator outside quotes, substitutions, `[[ ]]` and parentheses, with its descriptor (`2>`, `10>`, `{fd}>`) and its word — a process substitution or a line continuation in that word included — and not `<(` or `>(`. A redirection ahead of the first word moves too: Phase 1B and the parser recognise only some of those. zsh's clobbering and both-stream operators (`>!`, `>>|`, `&>!`, `>&|` and their kin) are read as zsh reads them; where a `!` is in the command, a third reading takes the operators as bash does, where `>!` is `>` with the target `!`, so a word after it that is an argument in bash is read as one. Heredoc bodies and comments stay where they are. Normalize and the never-failing scan read an unescaped `>` followed by `|`, and `<` or `>` followed by `&`, as one redirection (`>|`, `<&`, `>&`; zsh's `>&|`). A heredoc body is not skipped where its end is not certain — an unquoted delimiter's line continued with `\`.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Fix comments alone | `# heading` lines in heredoc bodies currently hide the rest of the body; showing it multiplies false positives. |
| Remove comments with the quote-aware scan | Review found inputs (a `#` after `<(…)`, after a `]]` inside a character class, after a quote in a heredoc inside a substitution) where a misread removed commands 1.4.0 still saw. A scan that only adds a `\` cannot hide anything. |
| Read a body as commands only when a shell reads it | Executors missing from the list (`sudo -s`, `su`, `time bash`, `xargs sh -c`, a function named `cat`) would have their bodies hidden — commands blocked today would pass. |
| Exclude the constructs where `<<` is not a heredoc (`$((`, `${`, `$[`) | Every construct left off the list hides the commands after it; review found three, each confirmed in bash 3.2 and zsh. |
| Block every materializable command | Removes the materialize route the FAQ documents, for commands no check objects to. |
| Remove redirections instead of moving them | A stdin redirection on a shell after a pipe replaces the pipe's input; removed, `cat x \| bash < setup.sh` reads as a pipe into a shell. A heredoc operator removed leaves its body to be read as commands. |
| Read only the moved form | It is a model of the shell, and a model can be wrong; keeping the reading as written means a mistake can only add a block. |
| Move redirections inside `( … )` too | Splits `<(` from its `(` when a redirection comes before a process substitution, and gains nothing: the rules do not read commands inside parentheses today. |

## Consequences

- Commands after a comment line, and rule matches inside commands that used to be materialized, are now blocked. This is added coverage under the breaking-change policy, and the CHANGELOG lists the shapes.
- Heredoc bodies written to files with the listed readers no longer produce false positives. Bodies that fail any condition behave as today.
- A command larger than the raised limits is blocked rather than materialized.
- A command containing `<` or `>` is parsed twice.
- The hook still does not run a shell. Shapes it cannot model fall to the reading that shows more, which can still produce false positives; they are not dropped.
