use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::AppError;
use crate::audit::AuditConfig;
use crate::detector::DetectorConfig;
use crate::rules::{ActionKind, RuleConfig};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_detectors")]
    pub detectors: Vec<DetectorConfig>,
    #[serde(default = "default_rules")]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub audit: AuditConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            detectors: default_detectors(),
            rules: default_rules(),
            audit: AuditConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigLoadResult {
    pub config: Config,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// User config (deserialized from TOML — all rule fields optional for merge)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct UserConfig {
    detectors: Option<Vec<DetectorConfig>>,
    #[serde(default)]
    rules: Vec<UserRule>,
    #[serde(default)]
    audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct UserRule {
    name: String,
    command: Option<String>,
    action: Option<ActionKind>,
    enabled: Option<bool>,
    destination: Option<String>,
    match_all: Option<Vec<String>>,
    match_any: Option<Vec<String>>,
    message: Option<String>,
}

// ---------------------------------------------------------------------------
// Blocked system directories for move-to destination
// ---------------------------------------------------------------------------

pub const BLOCKED_DESTINATION_PREFIXES: &[&str] = &[
    "/usr", "/etc", "/System", "/Library", "/bin", "/sbin", "/var", "/private",
];

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

pub fn load_config(path: Option<&Path>) -> Result<ConfigLoadResult, AppError> {
    let path = path.map(Path::to_path_buf).or_else(default_config_path);
    let mut warnings = Vec::new();

    let config = match path {
        Some(path) => {
            if !path.exists() {
                warnings.push(format!(
                    "config `{}` not found; using built-in default rules",
                    path.display()
                ));
                Config::default()
            } else if !permissions_are_safe(&path)? {
                warnings.push(format!(
                    "config `{}` permissions are not 600; using built-in default rules",
                    path.display()
                ));
                Config::default()
            } else {
                let content = fs::read_to_string(&path)?;
                match toml::from_str::<UserConfig>(&content) {
                    Ok(user_config) => build_merged_config(user_config, &mut warnings),
                    Err(error) => {
                        warnings.push(format!(
                            "failed to parse `{}` ({error}); using built-in default rules",
                            path.display()
                        ));
                        Config::default()
                    }
                }
            }
        }
        None => Config::default(),
    };

    Ok(ConfigLoadResult { config, warnings })
}

// ---------------------------------------------------------------------------
// Merge logic
// ---------------------------------------------------------------------------

fn build_merged_config(user: UserConfig, warnings: &mut Vec<String>) -> Config {
    let detectors = user.detectors.unwrap_or_else(default_detectors);
    let mut rules = merge_rules(default_rules(), &user.rules, warnings);
    validate_rules(&mut rules, warnings);
    Config {
        detectors,
        rules,
        audit: user.audit,
    }
}

fn merge_rules(
    defaults: Vec<RuleConfig>,
    user_rules: &[UserRule],
    warnings: &mut Vec<String>,
) -> Vec<RuleConfig> {
    // Check for duplicate names in user config
    let mut seen_names = HashSet::new();
    for ur in user_rules {
        if !seen_names.insert(&ur.name) {
            warnings.push(format!(
                "duplicate rule name `{}` in config; only the first occurrence is used",
                ur.name
            ));
        }
    }

    let mut merged = defaults;
    let mut applied_names = HashSet::new();

    for ur in user_rules {
        if applied_names.contains(&ur.name) {
            continue; // skip duplicates
        }
        applied_names.insert(ur.name.clone());

        if let Some(existing) = merged.iter_mut().find(|r| r.name == ur.name) {
            // Override existing rule fields
            apply_user_overrides(existing, ur);
        } else {
            // New rule — must have command + action
            match (&ur.command, &ur.action) {
                (Some(command), Some(action)) => {
                    let mut rule = RuleConfig::new(
                        &ur.name,
                        command,
                        action.clone(),
                        ur.match_all.clone().unwrap_or_default(),
                        ur.match_any.clone().unwrap_or_default(),
                        ur.message.clone(),
                    );
                    if let Some(enabled) = ur.enabled {
                        rule.enabled = enabled;
                    }
                    if let Some(dest) = &ur.destination {
                        rule.destination = Some(dest.clone());
                    }
                    merged.push(rule);
                }
                _ => {
                    warnings.push(format!(
                        "rule `{}` is not a built-in rule and is missing `command` or `action`; skipped",
                        ur.name
                    ));
                }
            }
        }
    }

    merged
}

fn apply_user_overrides(rule: &mut RuleConfig, ur: &UserRule) {
    if let Some(command) = &ur.command {
        rule.command = command.clone();
    }
    if let Some(action) = &ur.action {
        rule.action = action.clone();
    }
    if let Some(enabled) = ur.enabled {
        rule.enabled = enabled;
    }
    if let Some(dest) = &ur.destination {
        rule.destination = Some(dest.clone());
    }
    if let Some(match_all) = &ur.match_all {
        rule.match_all = match_all.clone();
    }
    if let Some(match_any) = &ur.match_any {
        rule.match_any = match_any.clone();
    }
    if let Some(message) = &ur.message {
        rule.message = Some(message.clone());
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_rules(rules: &mut [RuleConfig], warnings: &mut Vec<String>) {
    for rule in rules.iter_mut() {
        // MoveTo requires destination
        if rule.action == ActionKind::MoveTo && rule.destination.is_none() {
            warnings.push(format!(
                "rule `{}` uses action `move-to` but has no `destination`; rule disabled",
                rule.name
            ));
            rule.enabled = false;
        }

        // destination without MoveTo
        if rule.destination.is_some() && rule.action != ActionKind::MoveTo {
            warnings.push(format!(
                "rule `{}` has a `destination` but action is `{}`; destination is ignored",
                rule.name,
                rule.action.as_str()
            ));
        }

        // Validate destination path — violations disable the rule (enforcement)
        if let Some(dest) = &rule.destination.clone()
            && !validate_destination(dest, &rule.name, warnings)
        {
            rule.enabled = false;
        }
    }
}

/// Returns `true` if the destination is valid, `false` if it should be blocked.
fn validate_destination(dest: &str, rule_name: &str, warnings: &mut Vec<String>) -> bool {
    let path = Path::new(dest);

    // Must be absolute
    if !path.is_absolute() {
        warnings.push(format!(
            "rule `{rule_name}`: destination `{dest}` is not an absolute path; rule disabled"
        ));
        return false;
    }

    // Resolve canonical path (catches .. traversal)
    if let Ok(canonical) = path.canonicalize() {
        let canonical_str = canonical.to_string_lossy();
        for prefix in BLOCKED_DESTINATION_PREFIXES {
            if canonical_str.starts_with(prefix) {
                warnings.push(format!(
                    "rule `{rule_name}`: destination `{dest}` resolves to system directory \
                     `{canonical_str}`; rule disabled for security"
                ));
                return false;
            }
        }

        // Check symlink
        if let Ok(meta) = fs::symlink_metadata(&canonical)
            && meta.file_type().is_symlink()
        {
            warnings.push(format!(
                "rule `{rule_name}`: destination `{dest}` is a symlink; rule disabled for security"
            ));
            return false;
        }
    }
    // If canonicalize fails (path doesn't exist yet), we'll catch it at runtime
    true
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config").join("omamori").join("config.toml"))
}

fn default_detectors() -> Vec<DetectorConfig> {
    vec![
        DetectorConfig::env_var("claude-code", "CLAUDECODE", "1"),
        DetectorConfig::env_var("codex-cli", "AI_GUARD", "1"),
        DetectorConfig::env_var("cursor", "AI_GUARD", "1"),
    ]
}

pub fn default_rules() -> Vec<RuleConfig> {
    vec![
        RuleConfig::new(
            "rm-recursive-to-trash",
            "rm",
            ActionKind::Trash,
            Vec::new(),
            vec![
                "-r".to_string(),
                "-rf".to_string(),
                "-fr".to_string(),
                "--recursive".to_string(),
            ],
            Some(
                "omamori moved the recursive rm targets to Trash instead of deleting them"
                    .to_string(),
            ),
        ),
        RuleConfig::new(
            "git-reset-hard-stash",
            "git",
            ActionKind::StashThenExec,
            vec!["reset".to_string(), "--hard".to_string()],
            Vec::new(),
            Some("omamori stashed changes before running git reset --hard".to_string()),
        ),
        RuleConfig::new(
            "git-push-force-block",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["--force".to_string(), "-f".to_string()],
            Some("omamori blocked a force push".to_string()),
        ),
        RuleConfig::new(
            "git-clean-force-block",
            "git",
            ActionKind::Block,
            vec!["clean".to_string()],
            vec!["-fd".to_string(), "-fdx".to_string()],
            Some("omamori blocked git clean because it would remove untracked files".to_string()),
        ),
        RuleConfig::new(
            "chmod-777-block",
            "chmod",
            ActionKind::Block,
            Vec::new(),
            vec!["777".to_string()],
            Some("omamori blocked chmod 777".to_string()),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Permissions check
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn permissions_are_safe(path: &Path) -> Result<bool, AppError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok(metadata.mode() & 0o777 == 0o600)
}

#[cfg(not(unix))]
fn permissions_are_safe(_path: &Path) -> Result<bool, AppError> {
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_override_disables_rule() {
        let user_rules = vec![UserRule {
            name: "git-push-force-block".to_string(),
            command: None,
            action: None,
            enabled: Some(false),
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        assert!(!rule.enabled);
        assert_eq!(rule.action, ActionKind::Block); // action preserved
        assert!(warnings.is_empty());
    }

    #[test]
    fn merge_adds_new_rule() {
        let user_rules = vec![UserRule {
            name: "custom-rm".to_string(),
            command: Some("rm".to_string()),
            action: Some(ActionKind::MoveTo),
            enabled: None,
            destination: Some("/tmp/backup".to_string()),
            match_all: None,
            match_any: Some(vec!["-rf".to_string()]),
            message: Some("custom".to_string()),
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &mut warnings);

        let rule = merged.iter().find(|r| r.name == "custom-rm").unwrap();
        assert_eq!(rule.action, ActionKind::MoveTo);
        assert_eq!(rule.destination.as_deref(), Some("/tmp/backup"));
        assert!(rule.enabled);
    }

    #[test]
    fn merge_new_rule_without_command_warns() {
        let user_rules = vec![UserRule {
            name: "bad-rule".to_string(),
            command: None,
            action: None,
            enabled: Some(false),
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &mut warnings);

        assert!(merged.iter().all(|r| r.name != "bad-rule"));
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("missing `command` or `action`"))
        );
    }

    #[test]
    fn merge_duplicate_name_warns() {
        let user_rules = vec![
            UserRule {
                name: "git-push-force-block".to_string(),
                command: None,
                action: None,
                enabled: Some(false),
                destination: None,
                match_all: None,
                match_any: None,
                message: None,
            },
            UserRule {
                name: "git-push-force-block".to_string(),
                command: None,
                action: None,
                enabled: Some(true),
                destination: None,
                match_all: None,
                match_any: None,
                message: None,
            },
        ];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        assert!(!rule.enabled); // first occurrence wins
        assert!(warnings.iter().any(|w| w.contains("duplicate rule name")));
    }

    #[test]
    fn merge_preserves_all_defaults_when_no_user_rules() {
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &[], &mut warnings);
        assert_eq!(merged.len(), default_rules().len());
        assert!(warnings.is_empty());
    }

    #[test]
    fn merge_override_changes_action() {
        let user_rules = vec![UserRule {
            name: "rm-recursive-to-trash".to_string(),
            command: None,
            action: Some(ActionKind::MoveTo),
            enabled: None,
            destination: Some("/tmp/quarantine".to_string()),
            match_all: None,
            match_any: None,
            message: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "rm-recursive-to-trash")
            .unwrap();
        assert_eq!(rule.action, ActionKind::MoveTo);
        assert_eq!(rule.destination.as_deref(), Some("/tmp/quarantine"));
        // match_any is preserved from default
        assert!(!rule.match_any.is_empty());
    }

    #[test]
    fn validate_move_to_without_destination_disables_rule() {
        let mut rules = vec![RuleConfig::new(
            "bad",
            "rm",
            ActionKind::MoveTo,
            Vec::new(),
            Vec::new(),
            None,
        )];
        let mut warnings = Vec::new();
        validate_rules(&mut rules, &mut warnings);
        assert!(warnings.iter().any(|w| w.contains("no `destination`")));
        assert!(!rules[0].enabled); // rule gets disabled
    }

    #[test]
    fn validate_destination_on_non_move_to_warns() {
        let mut rules = vec![
            RuleConfig::new(
                "weird",
                "rm",
                ActionKind::Trash,
                Vec::new(),
                Vec::new(),
                None,
            )
            .with_destination("/tmp/x".to_string()),
        ];
        let mut warnings = Vec::new();
        validate_rules(&mut rules, &mut warnings);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("destination is ignored"))
        );
        assert!(rules[0].enabled); // rule stays enabled (just a warning)
    }

    #[test]
    fn validate_relative_destination_disables_rule() {
        let mut rules = vec![
            RuleConfig::new(
                "rel",
                "rm",
                ActionKind::MoveTo,
                Vec::new(),
                Vec::new(),
                None,
            )
            .with_destination("relative/path".to_string()),
        ];
        let mut warnings = Vec::new();
        validate_rules(&mut rules, &mut warnings);
        assert!(warnings.iter().any(|w| w.contains("not an absolute path")));
        assert!(!rules[0].enabled); // rule gets disabled
    }

    #[test]
    fn default_rules_all_enabled() {
        for rule in default_rules() {
            assert!(
                rule.enabled,
                "rule {} should be enabled by default",
                rule.name
            );
        }
    }

    #[test]
    fn user_config_without_detectors_uses_defaults() {
        let toml_str = r#"
[[rules]]
name = "git-push-force-block"
enabled = false
"#;
        let user: UserConfig = toml::from_str(toml_str).unwrap();
        assert!(user.detectors.is_none());
        let mut warnings = Vec::new();
        let config = build_merged_config(user, &mut warnings);
        assert_eq!(config.detectors.len(), 3); // defaults
    }

    #[test]
    fn user_config_with_custom_detectors_replaces() {
        let toml_str = r#"
[[detectors]]
name = "my-tool"
type = "env_var"
env_key = "MY_TOOL"
env_value = "1"
"#;
        let user: UserConfig = toml::from_str(toml_str).unwrap();
        assert!(user.detectors.is_some());
        let mut warnings = Vec::new();
        let config = build_merged_config(user, &mut warnings);
        assert_eq!(config.detectors.len(), 1);
        assert_eq!(config.detectors[0].name, "my-tool");
    }

    #[test]
    fn enabled_field_defaults_to_true_in_toml() {
        let toml_str = r#"
[[rules]]
name = "test-rule"
command = "rm"
action = "block"
"#;
        // Parse as full RuleConfig (simulating direct deserialization)
        #[derive(Deserialize)]
        struct Wrapper {
            rules: Vec<RuleConfig>,
        }
        let parsed: Wrapper = toml::from_str(toml_str).unwrap();
        assert!(parsed.rules[0].enabled);
    }
}
