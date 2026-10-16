# ADR-0021: A shell command is judged by where it writes, and by whether it names the audit secret

- **Status**: Accepted
- **Date**: 2026-10-11
- **Issue**: [#577](https://github.com/yottayoshida/omamori/issues/577)
- **Builds on**: [ADR-0018](0018-every-claude-code-tool-reaches-the-hook.md), whose protected list and secret check this applies to the shell route, and [ADR-0020](0020-the-hook-splits-a-command-as-the-shell-does-only-where-it-is-sure.md), which decides what text the checks see.

## Context

G-5 says hook and config file edits are blocked while an AI environment is detected, and SECURITY.md said the hooks block shell commands that modify `config.toml`. Since v0.10.4 removed the substring meta-patterns — for false positives on `grep` arguments, commit messages and prompts that merely mention a protected path (#240) — nothing has looked at a shell command's write targets. On 1.4.0, `echo x >> ~/.config/omamori/config.toml`, `sed -i` on it, `touch` under `~/.omamori`, and `cat` or `cp` of the audit secret are all allowed.

## Decision

**A shell command is blocked when it names one of omamori's own files, or a directory above one, in a position where the command writes; and when it names the audit secret, or the directory that holds it, anywhere, unless it only reads names.**

1. **Write positions are a fixed list**: redirection targets outside quotes (including fused, fd-prefixed, zsh `>!` and leading forms); the files of `tee`, `sponge`, and in-place `sed`, `perl` and `yq` (never their expressions); the destinations of `cp`, `install`, `rsync`, `ditto`; every operand of `mv`, the sources of a hard link (`ln` without `-s`, `cp -l`) and the link itself; `dd of=`; the output options of `curl` and `wget`; every operand of `touch`, `truncate`, `rm`, `unlink`, `rmdir`, `shred`, `mkdir`, `mkfifo`, `mknod`, `chmod`, `chown`, `chgrp`, `chflags`, `xattr`; the start points of a `find` that deletes or runs one of these; the literal operands of an `xargs` that runs one of these. Positions are counted after redirections are removed.
2. **Targets are judged by the editor tools' own function and list** (`is_protected_file_path`), with `~` expanded outside quotes and `$HOME` outside single quotes, as the shell does, and a relative path resolved against every candidate base: the process's directory, the hook input's `cwd` when absolute, and each literal `cd` earlier in the command. A name match against any base blocks. A directory above is judged where the command runs — the hook input's `cwd`, else the process's directory, moved by a `cd x &&` and widened by a `cd` that may fail — and blocks only when it holds under every place; a directory whose last components begin a protected name (`.claude`, `omamori` holding `config.toml`) counts wherever it lies. Globs are matched as patterns against the concrete protected paths; a glob only in its last component also has its directory read once, up to a fixed number of directories a command, to match protected names there. Substitutions, process substitutions and heredoc bodies that are not set aside are read as commands too.
3. **The secret is judged by name, not by reader.** Every word of a command is compared with the key path and its directory, computed once from the configuration; a file elsewhere whose name begins `audit-secret` counts when it exists. Commands that only read names (`ls`, `stat`, `test` and the like) are exempt only when their output feeds no pipe.
4. Blocks are recorded as editor-tool blocks are (`layer2:file-protection`), and cannot be bypassed by break-glass. A command a rule already blocks is reported by that rule, so its record and hint do not change.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Block any command that mentions a protected path, unless it is a known reader | Blocks `git add .claude/settings.json`, `python3 -m json.tool ~/.claude/settings.json` and paths in commit messages — the #240 class. |
| Restore substring matching | The same, and the reason v0.10.4 removed it. |
| Narrow G-5 and SECURITY.md to what is enforced today | Most of the measured writes have a recognisable form; the promise can be kept for them. |
| List the programs that read the secret | Readers are unbounded and a renamed one passes silently; naming the secret at all is rare, so the check is inverted. |
| Resolve relative paths against the hook input's `cwd` alone | `context.rs` forbids building the base from payload fields, and a failed or subshell `cd` would fall open. |

## Consequences

- The writes measured in #577 are blocked, on every provider whose shell commands reach the hook; the contract stays Claude Code.
- A file with a protected name is protected wherever it lies, as it is for the editor tools since ADR-0018 — including isolated test homes set up from a shell. The block message points to a script or a terminal.
- What is not reached is listed in SECURITY.md: programs and subcommands off the list, interpreters and scripts, `eval`, functions and aliases, paths built from variables other than `HOME`, targets read from standard input, links created earlier in the same command, and the directories above the secret's.
- Each write target is resolved once per base, through the editor tools' function. On a release build, 19,000 relative paths in one command are judged in under 2 seconds, well inside the hook's time limit, so no separate budget is set.
