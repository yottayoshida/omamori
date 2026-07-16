//! `omamori config`, `omamori override`, and `omamori init` subcommands.
//!
//! SECURITY (T6): `mutate_config` is a single atomic pipeline — DO NOT SPLIT.
//! SECURITY (T3): All config-mutating functions call `guard_ai_config_modification`.

use std::ffi::OsString;
use std::path::Path;

use crate::AppError;
use crate::config::{self, load_config};
use crate::engine::guard::guard_ai_config_modification;
use crate::engine::shim::{emit_config_warnings, update_baseline_silent};
use crate::installer::default_base_dir;
use crate::integrity;
use crate::rules;
use crate::util::USAGE_HINT;

// ---------------------------------------------------------------------------
// config subcommand
// ---------------------------------------------------------------------------

pub(crate) fn run_config_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("list") => run_config_list(),
        Some("validate") => run_config_validate(args.get(3).and_then(|item| item.to_str())),
        Some("add") => run_config_add(args),
        Some("disable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("config disable requires a rule name".to_string())
            })?;
            run_config_disable(rule_name)
        }
        Some("enable") => {
            let rule_name = args
                .get(3)
                .and_then(|item| item.to_str())
                .ok_or_else(|| AppError::Usage("config enable requires a rule name".to_string()))?;
            run_config_enable(rule_name)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown config subcommand: {other}\n\n{}",
            USAGE_HINT
        ))),
        None => Err(AppError::Usage(format!(
            "config requires a subcommand\n\n{}",
            USAGE_HINT
        ))),
    }
}

// ---------------------------------------------------------------------------
// override subcommand
// ---------------------------------------------------------------------------

pub(crate) fn run_override_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("disable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("override disable requires a rule name".to_string())
            })?;
            run_override_disable(rule_name)
        }
        Some("enable") => {
            let rule_name = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
                AppError::Usage("override enable requires a rule name".to_string())
            })?;
            run_override_enable(rule_name)
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown override subcommand: {other}\n\n{}",
            USAGE_HINT
        ))),
        None => Err(AppError::Usage(format!(
            "override requires a subcommand (disable|enable)\n\n{}",
            USAGE_HINT
        ))),
    }
}

// ---------------------------------------------------------------------------
// init subcommand
// ---------------------------------------------------------------------------

pub(crate) fn run_init_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut force = false;
    let mut stdout_mode = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--force" => {
                force = true;
                index += 1;
            }
            "--stdout" => {
                stdout_mode = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown init flag: {arg}\n\n{}",
                    USAGE_HINT
                )));
            }
        }
    }

    // Guard: init --force can overwrite existing config → block in AI sessions
    if force {
        guard_ai_config_modification("init --force")?;
    }

    // --stdout: backward-compatible stdout output
    if stdout_mode {
        print!("{}", config::config_template());
        return Ok(0);
    }

    // File write mode (default)
    let path = config::default_config_path().ok_or_else(|| {
        AppError::Config(
            "cannot determine config path: neither XDG_CONFIG_HOME nor HOME is set".to_string(),
        )
    })?;

    match config::write_default_config(&path, force) {
        Ok(result) => {
            eprintln!("Created {}", result.path.display());
            eprintln!("Run `omamori test` to verify your setup.");
            update_baseline_silent(&default_base_dir());
            Ok(0)
        }
        Err(AppError::Config(msg)) if msg.contains("already exists") => {
            eprintln!("omamori: {msg}");
            Ok(2)
        }
        Err(AppError::Config(msg)) if msg.contains("symlink") => {
            eprintln!("omamori: {msg}");
            Ok(1)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `known_names` is caller-supplied so the *scope* of what counts as "known"
/// can differ: `override disable/enable` pass core-only names (blast radius
/// unchanged — overrides only ever apply to built-ins); `config
/// disable/enable` (#388) pass core names **plus** the current config's
/// custom rule names, so a `config add`-created rule can be toggled too.
fn validate_rule_name(name: &str, known_names: &[String]) -> Result<(), AppError> {
    if !known_names.iter().any(|n| n == name) {
        return Err(AppError::Config(format!(
            "unknown rule `{name}`\n  Known rules: {}",
            known_names.join(", ")
        )));
    }
    Ok(())
}

fn core_rule_names_owned() -> Vec<String> {
    config::core_rule_names()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Core rule names plus every custom (non-builtin) rule name present in the
/// already-merged config — i.e. the set `config disable`/`enable` may
/// legally target (#388). Built from the *merged* rule set, not the raw
/// `[[rules]]` array, so a malformed custom entry that `merge_rules` skipped
/// (missing `command`/`action`) is correctly treated as not-yet-toggleable,
/// matching what `config list` would show.
fn known_rule_names(load_result: &config::ConfigLoadResult) -> Vec<String> {
    load_result
        .config
        .rules
        .iter()
        .map(|r| r.name.clone())
        .collect()
}

fn resolve_config_path_checked() -> Result<std::path::PathBuf, AppError> {
    let path = config::default_config_path().ok_or_else(|| {
        AppError::Config("cannot determine config path: HOME/XDG_CONFIG_HOME not set".to_string())
    })?;
    if path.exists() {
        config::reject_symlink_public(&path, "config path")?;
    }
    Ok(path)
}

fn is_core_rule(name: &str) -> bool {
    config::core_rule_names().contains(&name)
}

// ---------------------------------------------------------------------------
// Config mutation helper — shared read → parse → mutate → validate → write
// ---------------------------------------------------------------------------

/// SECURITY (T6): This is a single atomic pipeline — DO NOT SPLIT.
/// Read config.toml, parse as DocumentMut, apply mutation, validate, and write back.
/// The `toml::from_str` validation is an independent failsafe layer — do NOT remove.
pub(crate) fn mutate_config<F>(config_path: &Path, mutate: F) -> Result<(), AppError>
where
    F: FnOnce(&mut toml_edit::DocumentMut) -> Result<(), AppError>,
{
    let content = std::fs::read_to_string(config_path)?;
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| AppError::Config(format!("failed to parse config as TOML: {e}")))?;

    mutate(&mut doc)?;

    let new_content = doc.to_string();
    // Failsafe: validate with independent parser (toml_edit and toml are different impls).
    // DO NOT REMOVE — this catches toml_edit bugs that would corrupt config.toml.
    if toml::from_str::<toml::Value>(&new_content).is_err() {
        return Err(AppError::Config(
            "config mutation would create invalid TOML; aborting".to_string(),
        ));
    }
    // Hardened write: atomic (temp → fsync → rename) with O_NOFOLLOW (#102, #307).
    // `write_new_file` uses a CSPRNG-random temp name, so the old "reject if the
    // fixed temp path is a symlink" pre-check is moot — nothing predictable to
    // plant a symlink at.
    config::reject_symlink_public(config_path, "config path")?;
    integrity::write_new_file(config_path, &new_content)?;
    update_baseline_silent(&default_base_dir());
    Ok(())
}

// ---------------------------------------------------------------------------
// config disable / enable
// ---------------------------------------------------------------------------

/// Shared `[[rules]]` get-or-create (#389). `rules` absent -> create an empty
/// array-of-tables. `rules` present as `[[rules]]` -> return it (covers
/// normal entries, no-target-yet, and duplicate-name entries alike). Any
/// other shape (bare `[rules]` table, scalar, inline array, table-of-tables)
/// -> refuse rather than `disable`'s previous `doc.insert` (which silently
/// clobbered whatever was there). `caller` is embedded in the message.
///
/// This is the *sole* authoritative refuse point for the "valid TOML, but
/// not `[[rules]]` array form" shapes (an inline `rules = [{...}]` is a
/// genuinely working config — NOT malformed — so it will never be caught by
/// a `degraded` precheck; only this dispatch catches it). Callers should
/// still run a `degraded` precheck first for the truly-malformed shapes
/// (bare table, scalar, etc.) — it fires earlier with a better-targeted
/// "run `config validate`" message — but must not rely on it alone.
fn get_or_create_rules_array<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    caller: &str,
) -> Result<&'a mut toml_edit::ArrayOfTables, AppError> {
    if doc.get("rules").is_none() {
        doc.insert(
            "rules",
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
        );
    }
    doc.get_mut("rules")
        .and_then(|item| item.as_array_of_tables_mut())
        .ok_or_else(|| {
            AppError::Config(format!(
                "{caller}: existing `rules` in config.toml is not in `[[rules]]` array form; \
                 refusing to overwrite it.\n  Edit the config directly, or run `omamori init --force`."
            ))
        })
}

/// Shared malformed-config precondition (#389/#388): `disable`/`enable`
/// (like `add`'s existing O3) refuse to edit a `degraded` config rather than
/// building on the silent fallback-to-core-defaults state.
fn reject_if_degraded(
    caller: &str,
    load_result: &config::ConfigLoadResult,
) -> Result<(), AppError> {
    if load_result.degraded {
        return Err(AppError::Config(format!(
            "{caller}: config.toml is malformed and cannot be safely edited.\n  \
             Run `omamori config validate` to see the error,\n  \
             then fix it, or run `omamori init --force` to regenerate.\n  \
             ({caller} refuses to modify a degraded config to avoid data loss.)"
        )));
    }
    Ok(())
}

/// Shared raw-duplicate-name precondition (#389): an in-place `enabled`
/// rewrite only ever touches the *first* raw match by name — if the config
/// has more than one, `config disable`/`enable` must refuse rather than
/// silently rewrite one and leave the rest untouched while still reporting
/// success.
fn reject_if_duplicate_raw_entry(
    caller: &str,
    raw: &config::RawRuleArrayState,
    config_path: &Path,
    rule_name: &str,
) -> Result<(), AppError> {
    if raw.count > 1 {
        return Err(AppError::Config(format!(
            "{caller}: `{rule_name}` appears more than once in config.toml's `[[rules]]` \
             array; refusing to guess which entry to change.\n  \
             Edit {} directly to remove the duplicate, then retry.",
            config_path.display()
        )));
    }
    Ok(())
}

fn run_config_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config disable")?;

    let config_path = resolve_config_path_checked()?;
    // `load_config` handles a missing path internally (falls back to
    // `Config::default()`, i.e. core rules only) — so `known_rule_names`
    // is exactly the 15 core names when no config file exists yet. Every
    // one of those is then caught by the `is_core_rule` redirect below,
    // and any other name fails `validate_rule_name` as unknown. There is
    // therefore no reachable case where a config file needs to be created
    // here (unlike `config add`, which always creates something new): a
    // *custom* name can only validate successfully if it is already present
    // in an existing config.
    let precheck = load_config(Some(&config_path))?;
    reject_if_degraded("config disable", &precheck)?;

    validate_rule_name(rule_name, &known_rule_names(&precheck))?;

    if is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is a core safety rule and cannot be disabled.\n\n  \
             To override: omamori override disable {rule_name}\n  \
             To see core vs custom rules: omamori config list"
        )));
    }

    let raw = config::read_raw_rule_state(&config_path, rule_name)?;
    reject_if_duplicate_raw_entry("config disable", &raw, &config_path, rule_name)?;
    // Checked against the *raw* `enabled` value, not `precheck`'s
    // merged/validated state — a rule can be effectively disabled by
    // validation (e.g. a bad `move-to` destination) while its raw entry
    // has no explicit `enabled = false`. Reporting "already disabled" from
    // the merged state would skip the write here, and a later fix to the
    // validation issue would then silently reactivate the rule despite this
    // `disable` having reported success. Read generically (works for both
    // `[[rules]]` and inline-array form) — whether a subsequent write is
    // actually possible for this shape is `get_or_create_rules_array`'s
    // question alone, asked only if a write turns out to be needed (see
    // `RawRuleArrayState`'s doc comment).
    if !raw.enabled {
        eprintln!("Rule `{rule_name}` is already disabled.");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        let rules = get_or_create_rules_array(doc, "config disable")?;
        let entry = rules
            .iter_mut()
            .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name))
            .ok_or_else(|| {
                AppError::Config(format!(
                    "config disable: internal error — `{rule_name}` was found while loading \
                     config.toml but not while writing it; please report this as a bug."
                ))
            })?;
        entry["enabled"] = toml_edit::value(false);
        Ok(())
    })?;

    eprintln!("Disabled: {rule_name}");
    run_config_list()
}

fn run_config_enable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config enable")?;

    let config_path = resolve_config_path_checked()?;
    // `load_config` handles a missing path internally (falls back to
    // `Config::default()`, i.e. core rules only, `degraded = false`) — so
    // this naturally validates `rule_name` against "core names only" when
    // no config file exists yet, without a separate early return.
    let precheck = load_config(Some(&config_path))?;
    reject_if_degraded("config enable", &precheck)?;

    validate_rule_name(rule_name, &known_rule_names(&precheck))?;

    if !config_path.exists() {
        eprintln!("Rule `{rule_name}` is already enabled (built-in default).");
        return Ok(2);
    }

    let Some(existing) = precheck.config.rules.iter().find(|r| r.name == rule_name) else {
        return Err(AppError::Config(format!(
            "config enable: internal error — `{rule_name}` passed validation but is not in \
             the merged rule set; please report this as a bug."
        )));
    };
    let is_builtin = existing.is_builtin;

    // Core-rule disablement can happen two ways: a raw `rules` entry (which
    // core `enabled` immutability makes inert on its own — see
    // `raw_override_disables`'s doc comment) or `[overrides]` itself
    // (`omamori override disable`, the mechanism that's actually
    // effective). `config enable` only ever touches `rules`, so if
    // `[overrides]` is what's disabling this rule, redirect rather than
    // silently no-op-ing while claiming success.
    if is_builtin && config::raw_override_disables(&config_path, rule_name)? {
        return Err(AppError::Config(format!(
            "`{rule_name}` is disabled via `[overrides]`, not `config disable`.\n\n  \
             To restore it: omamori override enable {rule_name}\n  \
             To see core vs custom rules: omamori config list"
        )));
    }

    let raw = config::read_raw_rule_state(&config_path, rule_name)?;

    reject_if_duplicate_raw_entry("config enable", &raw, &config_path, rule_name)?;
    // Checked against the *raw* `enabled` value, not `existing.enabled`
    // (merged/validated) — see the matching note in `run_config_disable`.
    // A rule can be effectively disabled by validation alone (no explicit
    // raw `enabled = false`); reporting "already enabled" from the merged
    // state here is correct only when the raw toggle is the reason it's
    // off. If it's off for a raw reason, we still need to write (remove the
    // raw `enabled = false` / stub) even though the effective state may
    // remain disabled afterward due to the unrelated validation issue.
    if raw.enabled {
        eprintln!("Rule `{rule_name}` is already enabled.");
        // Angle-A follow-up finding: the raw toggle and the merged/
        // validated effective state can disagree (e.g. a `move-to` rule
        // with an invalid destination) — say so, rather than letting
        // "already enabled" read as "and therefore active", which
        // `omamori config list`'s warnings would immediately contradict.
        if !existing.enabled {
            eprintln!(
                "  Note: it is still shown as disabled in `omamori config list` — \
                 that's a separate validation issue (see the warning there), not \
                 the `enabled` toggle `config enable` controls."
            );
        }
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        let rules = get_or_create_rules_array(doc, "config enable")?;
        let idx = rules
            .iter()
            .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name))
            .ok_or_else(|| {
                AppError::Config(format!(
                    "config enable: internal error — `{rule_name}` was found while loading \
                     config.toml but not while writing it; please report this as a bug."
                ))
            })?;

        // A raw 2-key stub `{name, enabled=false}` — created by an earlier
        // `disable` on a *core* rule — can be deleted entirely once
        // re-enabled; that's exactly "restored to built-in default". A
        // custom rule's raw entry must NEVER be deleted by `enable`, no
        // matter its key count — deleting it would delete the rule itself
        // (this is the one thing that distinguishes the core and custom
        // paths here; #388 makes reaching this code with a custom name
        // possible for the first time).
        if is_builtin {
            let key_count = rules.iter().nth(idx).map_or(0, |t| t.iter().count());
            if key_count <= 2 {
                rules.remove(idx);
                return Ok(());
            }
        }
        if let Some(entry) = rules.iter_mut().nth(idx) {
            entry.remove("enabled");
        }
        Ok(())
    })?;

    if is_builtin {
        eprintln!("Enabled: {rule_name} (restored to built-in default)");
    } else {
        eprintln!("Enabled: {rule_name}");
    }
    run_config_list()
}

// ---------------------------------------------------------------------------
// config add
// ---------------------------------------------------------------------------

const CONFIG_ADD_USAGE: &str = "Usage: omamori config add <rule-name> --command <cmd> --action <block|trash|stash|log-only|move-to> [--match-any <token>]... [--match-all <token>]... [--destination <abs-path>] [--message <text>]";

struct ConfigAddArgs {
    rule_name: String,
    command: String,
    action: rules::ActionKind,
    match_any: Vec<String>,
    match_all: Vec<String>,
    destination: Option<String>,
    message: Option<String>,
}

fn parse_config_add_action(raw: &str) -> Result<rules::ActionKind, AppError> {
    rules::ActionKind::from_cli_str(raw).ok_or_else(|| {
        AppError::Usage(format!(
            "config add: unknown --action `{raw}`\n  Valid values: block, trash, stash, log-only, move-to\n\n{CONFIG_ADD_USAGE}"
        ))
    })
}

/// SECURITY (T2): every flag here is inserted into the TOML document via
/// `toml_edit`'s typed value API (see `run_config_add`'s `mutate_config` closure),
/// never via `format!`-based string concatenation. `toml_edit` escapes string
/// values, so metacharacters in `--rule-name`/`--match-any`/etc. cannot inject
/// a sibling TOML table (e.g. `[audit]`).
fn parse_config_add_args(args: &[OsString]) -> Result<ConfigAddArgs, AppError> {
    let rule_name = args
        .get(3)
        .and_then(|item| item.to_str())
        .ok_or_else(|| {
            AppError::Usage(format!(
                "config add requires a rule name\n\n{CONFIG_ADD_USAGE}"
            ))
        })?
        .to_string();

    if rule_name.starts_with('-') {
        return Err(AppError::Usage(format!(
            "config add requires a rule name as the first argument (got `{rule_name}`)\n\n{CONFIG_ADD_USAGE}"
        )));
    }

    let mut command: Option<String> = None;
    let mut action: Option<rules::ActionKind> = None;
    let mut match_any: Vec<String> = Vec::new();
    let mut match_all: Vec<String> = Vec::new();
    let mut destination: Option<String> = None;
    let mut message: Option<String> = None;

    let mut index = 4usize;
    while index < args.len() {
        let arg = args[index].to_str().unwrap_or("");
        let take_value = |flag: &str| -> Result<String, AppError> {
            let val = args
                .get(index + 1)
                .and_then(|v| v.to_str())
                .ok_or_else(|| {
                    AppError::Usage(format!(
                        "config add: {flag} requires a value\n\n{CONFIG_ADD_USAGE}"
                    ))
                })?;
            Ok(val.to_string())
        };
        match arg {
            "--command" => {
                command = Some(take_value("--command")?);
                index += 2;
            }
            "--action" => {
                let raw = take_value("--action")?;
                action = Some(parse_config_add_action(&raw)?);
                index += 2;
            }
            "--match-any" => {
                match_any.push(take_value("--match-any")?);
                index += 2;
            }
            "--match-all" => {
                match_all.push(take_value("--match-all")?);
                index += 2;
            }
            "--destination" => {
                destination = Some(take_value("--destination")?);
                index += 2;
            }
            "--message" => {
                message = Some(take_value("--message")?);
                index += 2;
            }
            other => {
                return Err(AppError::Usage(format!(
                    "config add: unknown flag `{other}`\n\n{CONFIG_ADD_USAGE}"
                )));
            }
        }
    }

    let command = command.ok_or_else(|| {
        AppError::Usage(format!(
            "config add: missing --command\n  Example: omamori config add {rule_name} --command rm --action block --match-any -rf\n\n{CONFIG_ADD_USAGE}"
        ))
    })?;
    // QA finding: an empty --command is accepted by the flag parser (it's a
    // present-but-blank value, not a missing flag) yet `rule.command != ""`
    // can never equal a real invocation's program name — same silent-break
    // class as an empty match token.
    if command.is_empty() {
        return Err(AppError::Usage(format!(
            "config add: --command must not be an empty string\n\n{CONFIG_ADD_USAGE}"
        )));
    }
    let action = action.ok_or_else(|| {
        AppError::Usage(format!(
            "config add: missing --action\n  Example: omamori config add {rule_name} --command {command} --action block --match-any -rf\n\n{CONFIG_ADD_USAGE}"
        ))
    })?;

    // Reject empty-string tokens first: `--match-any ""` (or a mix like
    // `--match-all "" --match-all -l`) is a de facto no-op that would slip
    // past an "is the Vec empty" check while still writing a token that can
    // never realistically match (rules.rs `rule_matches` requires exact
    // token equality, and no real invocation has a literal empty-string
    // arg — with match_all this makes the whole rule permanently
    // unmatchable, per Codex adversarial review). Checking this first means
    // the "at least one token" check below can just be a plain `is_empty()`.
    if match_any.iter().any(|t| t.is_empty()) || match_all.iter().any(|t| t.is_empty()) {
        return Err(AppError::Usage(format!(
            "config add: --match-any/--match-all tokens must not be empty strings\n\n{CONFIG_ADD_USAGE}"
        )));
    }
    // A rule with no match tokens matches every invocation of `command`
    // (rules.rs `rule_matches`: empty match_any/match_all is vacuously
    // true) — almost never what a guided `add` should scaffold.
    if match_any.is_empty() && match_all.is_empty() {
        return Err(AppError::Usage(format!(
            "config add: at least one --match-any or --match-all token is required\n  \
             A rule with no match tokens fires on every invocation of `{command}` — that's rarely intended.\n  \
             Example: omamori config add {rule_name} --command {command} --action {} --match-any -rf\n\n{CONFIG_ADD_USAGE}",
            action.as_str()
        )));
    }

    if destination.is_some() && action != rules::ActionKind::MoveTo {
        return Err(AppError::Usage(format!(
            "config add: --destination is only valid with --action move-to (got --action {})\n\n{CONFIG_ADD_USAGE}",
            action.as_str()
        )));
    }
    if destination.is_none() && action == rules::ActionKind::MoveTo {
        return Err(AppError::Usage(format!(
            "config add: --action move-to requires --destination <abs-path>\n\n{CONFIG_ADD_USAGE}"
        )));
    }

    Ok(ConfigAddArgs {
        rule_name,
        command,
        action,
        match_any,
        match_all,
        destination,
        message,
    })
}

fn run_config_add(args: &[OsString]) -> Result<i32, AppError> {
    // O1 (SECURITY T3/DI-13): guard first, before touching the filesystem or
    // even finishing arg parsing — mirrors disable/enable/override precedent.
    guard_ai_config_modification("config add")?;

    let parsed = parse_config_add_args(args)?;

    // O2 (DI-13): reject shadowing a core self-protection rule id up front.
    if is_core_rule(&parsed.rule_name) {
        return Err(AppError::Config(format!(
            "`{}` is a core safety rule id and cannot be shadowed.\n  \
             Core rule ids are non-overridable to prevent self-disablement (DI-13).\n  \
             To adjust a core rule: omamori override disable {}\n  \
             To see core vs custom rules: omamori config list",
            parsed.rule_name, parsed.rule_name
        )));
    }

    let config_path = resolve_config_path_checked()?;
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    // O3: precondition — refuse to edit a config that's already degraded (shape
    // (d)/(f)/(i) in the shape enumeration) rather than silently clobbering or
    // building on top of a fallback-to-core-defaults state (T3 silent fail).
    let precheck = load_config(Some(&config_path))?;
    reject_if_degraded("config add", &precheck)?;
    // Duplicate-name check against the RAW `[[rules]]` array, not the merged
    // `precheck.config.rules`. `merge_rules` records a name as "claimed" the
    // moment it's seen — even if that entry is malformed (missing command/
    // action) and gets skipped with just a warning (config.rs:311-348) — so a
    // pre-existing malformed entry sharing our new name would silently cause
    // *our* well-formed entry to be the one skipped on next load, while this
    // command still reports success (Codex R1 P0 finding).
    if config::raw_rule_names(&config_path)?.contains(&parsed.rule_name) {
        // NOTE (UX review): by this point `parsed.rule_name` is guaranteed to
        // NOT be a core rule id (the O2 shadow check above already rejected
        // that), so it can only be a pre-existing *custom* entry. Since #388,
        // `config disable <name>` accepts custom names too (previously it
        // only accepted built-ins, so this message used to avoid suggesting
        // it — Codex Round 1 removed-behavior audit finding: that reasoning
        // predates #388 and is now stale). Phrased as "if you want to
        // disable" rather than a flat imperative: it only actually succeeds
        // for `[[rules]]`-form entries, not a hand-written inline-array
        // duplicate (sweep-pass finding) — `config disable` will say so if
        // it doesn't apply here.
        return Err(AppError::Config(format!(
            "config add: a rule named `{}` already exists.\n  \
             If you want to disable it instead: omamori config disable {}\n  \
             To change it: edit {} directly, or remove the existing `[[rules]]` block first.",
            parsed.rule_name,
            parsed.rule_name,
            config_path.display()
        )));
    }

    // O4: destination policy (absolute, no symlink, not under a blocked system
    // prefix) — same policy `validate_rules` applies after load, enforced here
    // *before* writing so `add` never reports success for a rule that would be
    // silently disabled on next load.
    if let Some(dest) = &parsed.destination {
        let mut dest_warnings = Vec::new();
        if !config::validate_destination(dest, &parsed.rule_name, &mut dest_warnings) {
            // `validate_destination`'s messages are phrased for its other
            // caller (`validate_rules`, post-load: an existing rule gets
            // disabled) and end in "...; rule disabled" / "...; rule
            // disabled for security". Here nothing was ever created, so
            // "rule not created" is stated up front for correct context,
            // rather than trying to string-edit the reused message (an
            // earlier version of this fix truncated the real reason via
            // `.split("; rule disabled")`, which matches that substring
            // anywhere — including inside a maliciously/accidentally
            // crafted `--destination` value itself — silently dropping the
            // actual failure reason; /code-review R1 finding).
            return Err(AppError::Config(format!(
                "config add: invalid --destination, rule not created\n  {}",
                dest_warnings.join("\n  ")
            )));
        }
    }

    let mut new_table = toml_edit::Table::new();
    new_table["name"] = toml_edit::value(parsed.rule_name.as_str());
    new_table["command"] = toml_edit::value(parsed.command.as_str());
    new_table["action"] = toml_edit::value(parsed.action.as_str());
    if !parsed.match_any.is_empty() {
        let arr: toml_edit::Array = parsed.match_any.iter().map(|s| s.as_str()).collect();
        new_table["match_any"] = toml_edit::value(arr);
    }
    if !parsed.match_all.is_empty() {
        let arr: toml_edit::Array = parsed.match_all.iter().map(|s| s.as_str()).collect();
        new_table["match_all"] = toml_edit::value(arr);
    }
    if let Some(dest) = &parsed.destination {
        new_table["destination"] = toml_edit::value(dest.as_str());
    }
    if let Some(msg) = &parsed.message {
        new_table["message"] = toml_edit::value(msg.as_str());
    }
    // One clone for display (the closure below moves the original once,
    // rather than cloning it again in each of its two mutually-exclusive
    // branches — /code-review R1 simplification finding).
    let rendered_entry = new_table.clone();

    // O5: write via the shared atomic pipeline (SECURITY T6: DO NOT SPLIT).
    // Shared with disable/enable (#389) — an inline array `rules = [{...}]`
    // is valid, working TOML (NOT malformed), so the O3 `degraded` precheck
    // above does not catch it; `get_or_create_rules_array`'s own dispatch is
    // the actual (and only) guarantee against clobbering that shape.
    mutate_config(&config_path, |doc| {
        let array = get_or_create_rules_array(doc, "config add")?;
        array.push(new_table);
        Ok(())
    })?;

    // O6: post-write self-check — the rule we just wrote must load cleanly,
    // AND any pre-existing unrelated warning in the same file must still
    // surface, matching `disable`/`enable` (which both end by calling
    // `run_config_list()` -> `emit_config_warnings`). Checking only
    // `degraded` would silently swallow, say, another custom rule's
    // "missing command/action; skipped" warning on an otherwise-successful
    // `add` (/code-review R1 finding).
    let post = load_config(Some(&config_path))?;
    if post.degraded {
        return Err(AppError::Config(
            "config add: internal error — the config we just wrote failed to load cleanly. \
             This should not happen; please report this as a bug."
                .to_string(),
        ));
    }

    eprintln!(
        "Added rule `{}` to {}\n",
        parsed.rule_name,
        config_path.display()
    );
    eprintln!("[[rules]]\n{rendered_entry}");
    emit_config_warnings(&post);
    eprintln!("Next: run `omamori test` to verify the rule fires.");
    eprintln!("      run `omamori config list` to see it alongside built-ins.");

    Ok(0)
}

// ---------------------------------------------------------------------------
// override disable / enable
// ---------------------------------------------------------------------------

fn run_override_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("override disable")?;
    validate_rule_name(rule_name, &core_rule_names_owned())?;

    if !is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is not a core rule. Use `omamori config disable {rule_name}` instead."
        )));
    }

    let config_path = resolve_config_path_checked()?;
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    let content = std::fs::read_to_string(&config_path)?;
    if content
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| doc.get("overrides")?.get(rule_name)?.as_bool())
        == Some(false)
    {
        eprintln!("Rule `{rule_name}` is already overridden (disabled).");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        if !doc.contains_key("overrides") {
            doc["overrides"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        doc["overrides"][rule_name] = toml_edit::value(false);
        Ok(())
    })?;

    eprintln!("Override: disabled core rule `{rule_name}`");
    eprintln!("To restore: omamori override enable {rule_name}");
    run_config_list()
}

fn run_override_enable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("override enable")?;
    validate_rule_name(rule_name, &core_rule_names_owned())?;

    if !is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is not a core rule. Use `omamori config enable {rule_name}` instead."
        )));
    }

    let config_path = resolve_config_path_checked()?;

    if !config_path.exists() {
        eprintln!("Rule `{rule_name}` is already active (core default).");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        if let Some(overrides) = doc.get_mut("overrides").and_then(|t| t.as_table_mut()) {
            overrides.remove(rule_name);
            if overrides.is_empty() {
                doc.remove("overrides");
            }
        }
        Ok(())
    })?;

    eprintln!("Restored: core rule `{rule_name}` is active again.");
    run_config_list()
}

// ---------------------------------------------------------------------------
// config list
// ---------------------------------------------------------------------------

fn run_config_list() -> Result<i32, AppError> {
    let load_result = load_config(None)?;
    let config = &load_result.config;

    emit_config_warnings(&load_result);

    let defaults: std::collections::HashMap<String, _> = config::default_rules()
        .into_iter()
        .map(|r| (r.name.clone(), r))
        .collect();

    println!(
        "\n  {:<30} {:<40} {:<10} Source",
        "Rule", "Action", "Status"
    );
    println!("  {}", "-".repeat(100));

    for rule in &config.rules {
        let status = if rule.enabled { "active" } else { "disabled" };
        let source = if rule.is_builtin {
            if !rule.enabled {
                "core (overridden)"
            } else {
                "core"
            }
        } else if let Some(default) = defaults.get(&rule.name) {
            if !rule.enabled {
                "config (disabled)"
            } else if rule.action != default.action
                || rule.command != default.command
                || rule.match_all != default.match_all
                || rule.match_any != default.match_any
                || rule.destination != default.destination
            {
                "config (modified)"
            } else {
                "built-in"
            }
        } else {
            "config"
        };
        let action_str = match &rule.action {
            rules::ActionKind::MoveTo => {
                let dest = rule.destination.as_deref().unwrap_or("?");
                format!("move-to {dest}")
            }
            other => other.as_str().to_string(),
        };
        println!(
            "  {:<30} {:<40} {:<10} {}",
            rule.name, action_str, status, source
        );
    }

    if let Some(path) = config::default_config_path() {
        if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    println!(
                        "\n  Config: {} (permissions: {:o})",
                        path.display(),
                        meta.mode() & 0o777
                    );
                }
            }
            #[cfg(not(unix))]
            println!("\n  Config: {}", path.display());
        } else {
            println!("\n  Config: not found (run `omamori init` to create)");
        }
    }

    println!();
    Ok(0)
}

// ---------------------------------------------------------------------------
// config validate
// ---------------------------------------------------------------------------

fn run_config_validate(explicit_path: Option<&str>) -> Result<i32, AppError> {
    let path = match explicit_path {
        Some(p) => {
            let path = std::path::PathBuf::from(p);
            if !path.exists() {
                eprintln!("omamori config validate: not found: {}", path.display());
                return Ok(2);
            }
            config::reject_symlink_public(&path, "config path")?;
            Some(path)
        }
        None => {
            let default = config::default_config_path();
            if let Some(ref p) = default {
                if !p.exists() {
                    eprintln!("omamori config validate: not found: {}", p.display());
                    return Ok(2);
                }
            } else {
                eprintln!("omamori config validate: cannot determine config path");
                return Ok(2);
            }
            default
        }
    };

    let load_result = load_config(path.as_deref())?;

    if load_result.degraded {
        eprintln!("omamori config validate: invalid");
        for w in &load_result.warnings {
            eprintln!("  {w}");
        }
        return Ok(1);
    }

    if !load_result.warnings.is_empty() {
        eprintln!("omamori config validate: valid (with warnings)");
        for w in &load_result.warnings {
            eprintln!("  {w}");
        }
        return Ok(0);
    }

    let path_display = path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(default)".to_string());
    eprintln!("omamori config validate: valid — {path_display}");
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- GR-005: mutate_config pipeline (T6 guardrail) ---

    #[test]
    fn mutate_config_rejects_invalid_mutation() {
        let dir = std::env::temp_dir().join(format!("omamori-gr005-1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, "[rules]\n").unwrap();

        let original = std::fs::read_to_string(&config_path).unwrap();

        let result = mutate_config(&config_path, |doc| {
            doc.insert("__broken", toml_edit::Item::None);
            Ok(())
        });

        let after = std::fs::read_to_string(&config_path).unwrap_or_default();
        if result.is_err() {
            assert_eq!(
                after, original,
                "config must not be corrupted on mutation error"
            );
        } else {
            assert!(
                toml::from_str::<toml::Value>(&after).is_ok(),
                "mutate_config produced invalid TOML"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mutate_config_roundtrip_preserves_structure() {
        let dir = std::env::temp_dir().join(format!("omamori-gr005-2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");

        let initial = "[rules]\n[audit]\nenabled = true\n";
        std::fs::write(&config_path, initial).unwrap();

        let result = mutate_config(&config_path, |doc| {
            doc["audit"]["enabled"] = toml_edit::value(false);
            Ok(())
        });
        assert!(result.is_ok(), "valid mutation should succeed: {result:?}");

        let after = std::fs::read_to_string(&config_path).unwrap();
        let parsed: toml::Value = toml::from_str(&after).expect("output must be valid TOML");
        assert_eq!(
            parsed
                .get("audit")
                .and_then(|a| a.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(false),
            "mutation should have set audit.enabled = false"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn mutate_config_rejects_symlink_target() {
        let dir = std::env::temp_dir().join(format!("omamori-gr005-3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let real_file = dir.join("real.toml");
        std::fs::write(&real_file, "[rules]\n").unwrap();
        let config_path = dir.join("config.toml");
        std::os::unix::fs::symlink(&real_file, &config_path).unwrap();

        let result = mutate_config(&config_path, |doc| {
            doc["audit"]["enabled"] = toml_edit::value(false);
            Ok(())
        });

        assert!(
            result.is_err(),
            "mutate_config must refuse a symlinked config path"
        );
        assert!(
            config_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must still exist (not replaced by a regular file)"
        );
        assert_eq!(
            std::fs::read_to_string(&real_file).unwrap(),
            "[rules]\n",
            "symlink target must not be overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
