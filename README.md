# omamori

AI Agent dedicated command safeguard for dangerous shell operations triggered via AI CLI tools.

## Commands

- `omamori test`
  - runs built-in policy checks without touching the filesystem
- `omamori exec -- <command>`
  - exercises the policy engine directly before PATH shim installation
- `omamori install [--base-dir PATH] [--source PATH] [--hooks]`
  - creates shims under `~/.omamori/shim/` by default
  - prints PATH guidance but does not edit shell rc files
  - with `--hooks`, generates Claude Code hook templates only
- `omamori uninstall [--base-dir PATH]`
  - removes generated shims and hook template files

## Protected Commands In v0.1

- `rm` with `-r`, `-rf`, `-fr`, `--recursive` -> `trash`
- `git reset --hard` -> `stash-then-exec`
- `git push --force` / `git push -f` -> `block`
- `git clean -fd` / `git clean -fdx` -> `block`
- `chmod 777` -> `block`

## Not Protected In v0.1

- direct full-path execution such as `/bin/rm`
  - mitigated partially through generated Claude Code hook templates
- `sudo` paths where the shell PATH changes before the shim can run
  - omamori blocks when it detects sudo/elevated execution in-process
- non-shell destructive behavior such as `python -c`, `perl -e`, or other interpreters
- commands outside the current rule set, such as `find -delete` or `rsync --delete`

## Known Limitations

- Combined short flags such as `rm -rfv target` are not normalized yet, so rule matching is exact-token based.
- PATH changes are never applied automatically.
- Claude settings are never edited automatically; hook integration is output as snippet/template files only.

## Round 2 Status

- Installer and uninstall flows generate shims under `~/.omamori/shim/`.
- Hook integration generates:
  - `~/.omamori/hooks/claude-pretooluse.sh`
  - `~/.omamori/hooks/claude-settings.snippet.json`
