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
use crate::util::usage_text;

// ---------------------------------------------------------------------------
// config subcommand
// ---------------------------------------------------------------------------

pub(crate) fn run_config_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("list") => run_config_list(),
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
            usage_text()
        ))),
        None => Err(AppError::Usage(format!(
            "config requires a subcommand\n\n{}",
            usage_text()
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
            usage_text()
        ))),
        None => Err(AppError::Usage(format!(
            "override requires a subcommand (disable|enable)\n\n{}",
            usage_text()
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
                    usage_text()
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

fn validate_rule_name(name: &str) -> Result<(), AppError> {
    let known_names: Vec<String> = config::default_rules()
        .iter()
        .map(|r| r.name.clone())
        .collect();
    if !known_names.contains(&name.to_string()) {
        return Err(AppError::Config(format!(
            "unknown rule `{name}`\n  Known rules: {}",
            known_names.join(", ")
        )));
    }
    Ok(())
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
    // Hardened write: atomic (temp → fsync → rename) with O_NOFOLLOW (#102)
    config::reject_symlink_public(config_path, "config path")?;
    let temp_path = config_path.with_extension("toml.tmp");
    if temp_path.symlink_metadata().is_ok() {
        config::reject_symlink_public(&temp_path, "config temp")?;
        let _ = std::fs::remove_file(&temp_path);
    }
    integrity::write_new_file(&temp_path, &new_content)?;
    std::fs::File::open(&temp_path)?.sync_all()?;
    std::fs::rename(&temp_path, config_path)?;
    if let Some(dir) = config_path.parent()
        && let Ok(f) = std::fs::File::open(dir)
    {
        let _ = f.sync_all();
    }
    update_baseline_silent(&default_base_dir());
    Ok(())
}

// ---------------------------------------------------------------------------
// config disable / enable
// ---------------------------------------------------------------------------

fn run_config_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config disable")?;
    validate_rule_name(rule_name)?;

    if is_core_rule(rule_name) {
        return Err(AppError::Config(format!(
            "`{rule_name}` is a core safety rule and cannot be disabled.\n\n  \
             To override: omamori override disable {rule_name}\n  \
             To see core vs custom rules: omamori config list"
        )));
    }

    let config_path = resolve_config_path_checked()?;
    if !config_path.exists() {
        config::write_default_config(&config_path, false)?;
    }

    let load_result = load_config(None)?;
    if let Some(r) = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        && !r.enabled
    {
        eprintln!("Rule `{rule_name}` is already disabled.");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        let rules = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut());

        if let Some(entry) = rules.and_then(|tables| {
            tables
                .iter_mut()
                .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name))
        }) {
            entry["enabled"] = toml_edit::value(false);
            return Ok(());
        }

        let mut new_table = toml_edit::Table::new();
        new_table["name"] = toml_edit::value(rule_name);
        new_table["enabled"] = toml_edit::value(false);
        if let Some(array) = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut())
        {
            array.push(new_table);
        } else {
            let mut array = toml_edit::ArrayOfTables::new();
            array.push(new_table);
            doc.insert("rules", toml_edit::Item::ArrayOfTables(array));
        }
        Ok(())
    })?;

    eprintln!("Disabled: {rule_name}");
    run_config_list()
}

fn run_config_enable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("config enable")?;
    validate_rule_name(rule_name)?;

    let config_path = resolve_config_path_checked()?;

    if !config_path.exists() {
        eprintln!("Rule `{rule_name}` is already enabled (built-in default).");
        return Ok(2);
    }

    let load_result = load_config(None)?;
    if let Some(r) = load_result
        .config
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        && r.enabled
    {
        eprintln!("Rule `{rule_name}` is already enabled.");
        return Ok(2);
    }

    mutate_config(&config_path, |doc| {
        if let Some(tables) = doc
            .get_mut("rules")
            .and_then(|item| item.as_array_of_tables_mut())
        {
            let idx = tables
                .iter()
                .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(rule_name));

            if let Some(i) = idx {
                let key_count = tables.iter().nth(i).map_or(0, |t| t.iter().count());
                if key_count <= 2 {
                    tables.remove(i);
                } else {
                    if let Some(entry) = tables.iter_mut().nth(i) {
                        entry.remove("enabled");
                    }
                }
            }
        }
        Ok(())
    })?;

    eprintln!("Enabled: {rule_name} (restored to built-in default)");
    run_config_list()
}

// ---------------------------------------------------------------------------
// override disable / enable
// ---------------------------------------------------------------------------

fn run_override_disable(rule_name: &str) -> Result<i32, AppError> {
    guard_ai_config_modification("override disable")?;
    validate_rule_name(rule_name)?;

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
    validate_rule_name(rule_name)?;

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
        "\n  {:<30} {:<16} {:<10} Source",
        "Rule", "Action", "Status"
    );
    println!("  {}", "-".repeat(76));

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
            "  {:<30} {:<16} {:<10} {}",
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
}
