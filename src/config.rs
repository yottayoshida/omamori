use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::AppError;
use crate::audit::AuditConfig;
use crate::context::ContextConfig;
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
    /// Context-aware evaluation config. Enabled by default (v0.10.9+).
    /// None disables context evaluation; Some(_) activates built-in defaults.
    #[serde(default)]
    pub context: Option<ContextConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            detectors: default_detectors(),
            rules: default_rules(),
            audit: AuditConfig::default(),
            context: Some(crate::context::ContextConfig::default()),
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
    #[serde(default)]
    context: Option<ContextConfig>,
    /// `[overrides]` section: `rule_name = false` allows disabling core rules.
    #[serde(default)]
    overrides: HashMap<String, bool>,
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
    /// Optional subcommand position constraint (DI-13, v0.10.3+).
    /// Only honored on user-defined rules (not on overrides of built-ins;
    /// changing built-in subcommand via override would weaken DI-13).
    #[serde(default)]
    subcommand: Option<String>,
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
                    "config not found at {}\n  \
                     Built-in default rules are active (safe to use as-is).\n  \
                     To create a config for customization, run: omamori init",
                    path.display()
                ));
                Config::default()
            } else if !permissions_are_safe(&path)? {
                warnings.push(format!(
                    "config permissions are too open at {}\n  \
                     Built-in default rules are active for security.\n  \
                     To fix, run: chmod 600 {}",
                    path.display(),
                    path.display()
                ));
                Config::default()
            } else {
                let content = fs::read_to_string(&path)?;
                match toml::from_str::<UserConfig>(&content) {
                    Ok(user_config) => build_merged_config(user_config, &mut warnings),
                    Err(error) => {
                        warnings.push(format!(
                            "failed to parse config at {} ({error})\n  \
                             Built-in default rules are active for safety.\n  \
                             Fix the syntax error or run: omamori init --force",
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
    let mut rules = merge_rules(default_rules(), &user.rules, &user.overrides, warnings);
    validate_rules(&mut rules, warnings);

    // Validate context config if present
    if let Some(ref ctx) = user.context {
        let ctx_warnings = crate::context::validate_regenerable_paths(&ctx.regenerable_paths);
        warnings.extend(ctx_warnings);
    }

    let (validated_audit, audit_warnings) = user.audit.validate();
    warnings.extend(audit_warnings);

    Config {
        detectors,
        rules,
        audit: validated_audit,
        context: user.context,
    }
}

fn merge_rules(
    defaults: Vec<RuleConfig>,
    user_rules: &[UserRule],
    overrides: &HashMap<String, bool>,
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
            apply_user_overrides(existing, ur, overrides, warnings);
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
                    if let Some(sub) = &ur.subcommand {
                        rule.subcommand = Some(sub.clone());
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

    // Apply [overrides] section: disable core rules that have explicit override
    for (rule_name, &enabled) in overrides {
        if !enabled
            && let Some(rule) = merged.iter_mut().find(|r| r.name == *rule_name)
            && rule.is_builtin
        {
            rule.enabled = false;
        }
    }

    merged
}

fn apply_user_overrides(
    rule: &mut RuleConfig,
    ur: &UserRule,
    overrides: &HashMap<String, bool>,
    warnings: &mut Vec<String>,
) {
    if rule.is_builtin {
        // Core rule immutability: only `message` can be customized.
        // `enabled` immutability can be bypassed via [overrides] section.
        let has_non_message = ur.command.is_some()
            || ur.action.is_some()
            || ur.match_all.is_some()
            || ur.match_any.is_some()
            || ur.destination.is_some();

        let has_enabled_override = ur.enabled.is_some();

        // Check if [overrides] section has an explicit entry for this rule
        let has_overrides_entry = overrides.contains_key(&rule.name);

        if has_non_message {
            // Check action specifically for upgrade vs downgrade
            if let Some(action) = &ur.action {
                if action.defense_level() < rule.action.defense_level() {
                    warnings.push(format!(
                        "rule `{}` is a core safety rule — action downgrade from `{}` to `{}` \
                         is not allowed. Override ignored.",
                        rule.name,
                        rule.action.as_str(),
                        action.as_str()
                    ));
                } else if action.defense_level() >= rule.action.defense_level()
                    && action != &rule.action
                {
                    // Same or higher defense level — allow action upgrade
                    rule.action = action.clone();
                }
                // Same action — no warning needed
            }

            // Warn about other non-message field overrides
            if ur.command.is_some()
                || ur.match_all.is_some()
                || ur.match_any.is_some()
                || ur.destination.is_some()
            {
                warnings.push(format!(
                    "rule `{}` is a core safety rule. Only `message` can be customized. \
                     Other overrides (`command`, `match_all`, `match_any`, `destination`) are ignored.",
                    rule.name
                ));
            }
        }

        if has_enabled_override && !has_overrides_entry && ur.enabled == Some(false) {
            warnings.push(format!(
                "rule `{}` is a core safety rule and cannot be disabled via config. \
                 Ignored. To override: omamori override disable {}",
                rule.name, rule.name
            ));
        }

        // Only apply message override
        if let Some(message) = &ur.message {
            rule.message = Some(message.clone());
        }

        return;
    }

    // Non-core rules: apply all overrides as before
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

    // Check symlink on original path before canonicalize resolves it (#105)
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        warnings.push(format!(
            "rule `{rule_name}`: destination `{dest}` is a symlink; rule disabled for security"
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
    }
    // If canonicalize fails (path doesn't exist yet), we'll catch it at runtime
    true
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Returns the default config file path, respecting `XDG_CONFIG_HOME`.
/// Priority: `$XDG_CONFIG_HOME/omamori/config.toml` → `$HOME/.config/omamori/config.toml`.
pub fn default_config_path() -> Option<PathBuf> {
    // XDG_CONFIG_HOME must be absolute if set
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let xdg_path = PathBuf::from(&xdg);
        if xdg_path.is_absolute() {
            return Some(xdg_path.join("omamori").join("config.toml"));
        }
        // Relative XDG_CONFIG_HOME is ignored (XDG spec requires absolute)
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config").join("omamori").join("config.toml"))
}

pub fn default_detectors() -> Vec<DetectorConfig> {
    vec![
        DetectorConfig::env_var("claude-code", "CLAUDECODE", "1"),
        DetectorConfig::env_var("codex-cli", "CODEX_CI", "1"),
        // Verified: Cursor sets CURSOR_AGENT=1. Confirmed via E2E testing (2026-03-17).
        DetectorConfig::env_var("cursor", "CURSOR_AGENT", "1"),
        // Provisional: based on agents.md #136 reports. Verify with actual tool releases.
        DetectorConfig::env_var("gemini-cli", "GEMINI_CLI", "1"),
        DetectorConfig::env_var("cline", "CLINE_ACTIVE", "true"),
        DetectorConfig::env_var("ai-guard-fallback", "AI_GUARD", "1"),
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
            Some("omamori intercepted recursive rm — targets not deleted".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "git-reset-hard-stash",
            "git",
            ActionKind::StashThenExec,
            vec!["reset".to_string(), "--hard".to_string()],
            Vec::new(),
            Some("omamori intercepted git reset --hard — changes preserved".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "git-push-force-block",
            "git",
            ActionKind::Block,
            vec!["push".to_string()],
            vec!["--force".to_string(), "-f".to_string()],
            Some("omamori blocked a force push".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "git-clean-force-block",
            "git",
            ActionKind::Block,
            vec!["clean".to_string()],
            vec!["-f".to_string(), "--force".to_string()],
            Some("omamori blocked git clean because it would remove untracked files".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "chmod-777-block",
            "chmod",
            ActionKind::Block,
            Vec::new(),
            vec!["777".to_string()],
            Some("omamori blocked chmod 777".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "find-delete-block",
            "find",
            ActionKind::Block,
            Vec::new(),
            vec!["-delete".to_string(), "--delete".to_string()],
            Some("omamori blocked find with -delete flag".to_string()),
        )
        .with_builtin(true),
        RuleConfig::new(
            "rsync-delete-block",
            "rsync",
            ActionKind::Block,
            Vec::new(),
            vec![
                "--delete".to_string(),
                "--del".to_string(),
                "--delete-before".to_string(),
                "--delete-during".to_string(),
                "--delete-after".to_string(),
                "--delete-excluded".to_string(),
                "--delete-delay".to_string(),
                "--remove-source-files".to_string(),
            ],
            Some("omamori blocked rsync with destructive flags".to_string()),
        )
        .with_builtin(true),
        // omamori self-modification protection (v0.10.3, DI-13).
        // Phase 2 backstop for verb patterns moved out of Phase 1A `command.contains`
        // by the data-flag allowlist. Without these, relaxing Phase 1A would let
        // raw `omamori config disable` / `omamori uninstall` etc. through.
        //
        // Each rule uses `with_subcommand(...)` so args[0] must match exactly,
        // preventing false positives like `omamori exec -- echo disable config`.
        RuleConfig::new(
            "omamori-config-modify-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            vec!["disable".to_string(), "enable".to_string()],
            Some("omamori blocked self-modification of rules".to_string()),
        )
        .with_subcommand("config")
        .with_builtin(true),
        RuleConfig::new(
            "omamori-uninstall-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            Vec::new(),
            Some("omamori blocked uninstall via AI".to_string()),
        )
        .with_subcommand("uninstall")
        .with_builtin(true),
        RuleConfig::new(
            "omamori-init-force-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            vec!["--force".to_string()],
            Some("omamori blocked init --force via AI".to_string()),
        )
        .with_subcommand("init")
        .with_builtin(true),
        RuleConfig::new(
            "omamori-override-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            Vec::new(),
            Some("omamori blocked override via AI".to_string()),
        )
        .with_subcommand("override")
        .with_builtin(true),
        RuleConfig::new(
            "omamori-doctor-fix-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            vec!["--fix".to_string()],
            Some("omamori blocked doctor --fix via AI".to_string()),
        )
        .with_subcommand("doctor")
        .with_builtin(true),
        RuleConfig::new(
            "omamori-explain-block",
            "omamori",
            ActionKind::Block,
            Vec::new(),
            Vec::new(),
            Some("omamori blocked explain via AI (oracle attack prevention)".to_string()),
        )
        .with_subcommand("explain")
        .with_builtin(true),
    ]
}

/// Names of the 13 core (built-in) safety rules: 7 generic + 6 omamori-* (DI-13).
pub fn core_rule_names() -> Vec<&'static str> {
    vec![
        "rm-recursive-to-trash",
        "git-reset-hard-stash",
        "git-push-force-block",
        "git-clean-force-block",
        "chmod-777-block",
        "find-delete-block",
        "rsync-delete-block",
        "omamori-config-modify-block",
        "omamori-uninstall-block",
        "omamori-init-force-block",
        "omamori-override-block",
        "omamori-doctor-fix-block",
        "omamori-explain-block",
    ]
}

// ---------------------------------------------------------------------------
// Config file writing
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct WriteConfigResult {
    pub path: PathBuf,
    pub created: bool,
}

/// Generate the default config template as a string (all rules commented out).
pub fn config_template() -> String {
    let defaults = default_rules();
    let mut out = String::new();
    out.push_str(
        "# omamori config — only write the rules you want to change.\n\
         # Built-in rules are inherited automatically.\n\
         # To disable a rule: set enabled = false\n\
         # To change an action: override the action field\n\
         #\n\
         # Docs: https://github.com/yottayoshida/omamori\n\
         #\n",
    );
    for rule in &defaults {
        out.push_str("\n# [[rules]]\n");
        out.push_str(&format!("# name = \"{}\"\n", rule.name));
        out.push_str(&format!("# command = \"{}\"\n", rule.command));
        out.push_str(&format!("# action = \"{}\"\n", rule.action.as_str()));
        if !rule.match_all.is_empty() {
            out.push_str(&format!("# match_all = {:?}\n", rule.match_all));
        }
        if !rule.match_any.is_empty() {
            out.push_str(&format!("# match_any = {:?}\n", rule.match_any));
        }
        out.push_str("# # enabled = false  # uncomment to disable this rule\n");
    }
    out.push_str(
        "\n# --- Custom rule example ---\n\
         # [[rules]]\n\
         # name = \"rm-to-backup\"\n\
         # command = \"rm\"\n\
         # action = \"move-to\"\n\
         # destination = \"/tmp/omamori-quarantine/\"\n\
         # match_any = [\"-r\", \"-rf\", \"-fr\", \"--recursive\"]\n\
         # message = \"omamori moved targets to backup instead of deleting\"\n",
    );
    out.push_str(
        "\n# --- Context-aware evaluation (enabled by default) ---\n\
         # Built-in defaults are active. Uncomment lines below to customize.\n\
         [context]\n\
         # regenerable_paths = [\"target/\", \"node_modules/\", \".next/\", \"dist/\", \
         \"build/\", \"__pycache__/\", \".cache/\"]\n\
         # protected_paths = [\"src/\", \"lib/\", \".git/\", \".env\", \".ssh/\"]\n\
         #\n\
         # [context.git]\n\
         # enabled = true\n\
         # timeout_ms = 100\n",
    );
    out
}

/// Write the default config template to the given path.
///
/// Safety features:
/// - Refuses to write to symlinks (`O_NOFOLLOW` + `symlink_metadata` check)
/// - `force=false`: uses `create_new(true)` to prevent TOCTOU races
/// - `force=true`: atomic write via temp file + rename + fsync
/// - Sets directory permissions to 700, file permissions to 600
pub fn write_default_config(path: &Path, force: bool) -> Result<WriteConfigResult, AppError> {
    let dir = path
        .parent()
        .ok_or_else(|| AppError::Config(format!("invalid config path: {}", path.display())))?;

    // Create directory with mode 700
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    } else {
        // P2 fix: reject symlinked parent directory
        reject_symlink(dir, "config directory")?;
    }

    // Check for symlink at target path
    if path.exists() || path.symlink_metadata().is_ok() {
        reject_symlink(path, "config path")?;

        if !force {
            return Err(AppError::Config(format!(
                "config already exists at {}\n  Use `omamori init --force` to overwrite.",
                path.display()
            )));
        }
    }

    let content = config_template();

    if force && path.exists() {
        // Atomic write: temp file → fsync → rename
        let temp_path = path.with_extension("toml.tmp");
        // P1 fix: reject symlink at temp path too
        if temp_path.symlink_metadata().is_ok() {
            reject_symlink(&temp_path, "temp config path")?;
            // Remove stale temp file (non-symlink) if it exists
            let _ = fs::remove_file(&temp_path);
        }
        write_new_config(&temp_path, &content)?;
        // fsync the file
        let file = fs::File::open(&temp_path)?;
        file.sync_all()?;
        drop(file);
        // Atomic rename
        fs::rename(&temp_path, path)?;
        // fsync the parent directory
        if let Ok(dir_file) = fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
    } else {
        // New file: use O_NOFOLLOW + create_new for TOCTOU safety
        write_new_config(path, &content)?;
    }

    Ok(WriteConfigResult {
        path: path.to_path_buf(),
        created: true,
    })
}

/// Public wrapper for symlink rejection (used by config enable/disable).
pub fn reject_symlink_public(path: &Path, label: &str) -> Result<(), AppError> {
    reject_symlink(path, label)
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), AppError> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(AppError::Config(format!(
            "{label} `{}` is a symlink; refusing to write for security",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn write_new_config(path: &Path, content: &str) -> Result<(), AppError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_new_config(path: &Path, content: &str) -> Result<(), AppError> {
    fs::write(path, content)?;
    Ok(())
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

    fn no_overrides() -> HashMap<String, bool> {
        HashMap::new()
    }

    #[test]
    fn merge_core_rule_ignores_disable_without_override() {
        // Core rule `enabled = false` in config is ignored (immutability)
        let user_rules = vec![UserRule {
            name: "git-push-force-block".to_string(),
            command: None,
            action: None,
            enabled: Some(false),
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        assert!(rule.enabled); // core rule stays enabled
        assert_eq!(rule.action, ActionKind::Block);
        assert!(
            warnings.iter().any(
                |w: &String| w.contains("core safety rule") && w.contains("cannot be disabled")
            ),
            "expected immutability warning, got: {warnings:?}"
        );
    }

    #[test]
    fn merge_core_rule_disabled_via_overrides_section() {
        // [overrides] section allows disabling core rules
        let user_rules = vec![UserRule {
            name: "git-push-force-block".to_string(),
            command: None,
            action: None,
            enabled: Some(false),
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
            subcommand: None,
        }];
        let mut overrides = HashMap::new();
        overrides.insert("git-push-force-block".to_string(), false);
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &overrides, &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        assert!(!rule.enabled); // overrides section allows disable
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
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

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
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        assert!(merged.iter().all(|r| r.name != "bad-rule"));
        assert!(
            warnings
                .iter()
                .any(|w: &String| w.contains("missing `command` or `action`"))
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
                subcommand: None,
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
                subcommand: None,
            },
        ];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        // Core rule: enabled = false is ignored, so it stays enabled
        assert!(rule.enabled);
        assert!(
            warnings
                .iter()
                .any(|w: &String| w.contains("duplicate rule name"))
        );
    }

    #[test]
    fn merge_preserves_all_defaults_when_no_user_rules() {
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &[], &no_overrides(), &mut warnings);
        assert_eq!(merged.len(), default_rules().len());
        assert!(warnings.is_empty());
    }

    #[test]
    fn merge_core_rule_action_downgrade_rejected() {
        // Trying to downgrade rm-recursive-to-trash from trash to log-only
        let user_rules = vec![UserRule {
            name: "rm-recursive-to-trash".to_string(),
            command: None,
            action: Some(ActionKind::LogOnly),
            enabled: None,
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "rm-recursive-to-trash")
            .unwrap();
        assert_eq!(rule.action, ActionKind::Trash); // stays at original
        assert!(
            warnings
                .iter()
                .any(|w: &String| w.contains("action downgrade")),
            "expected downgrade warning, got: {warnings:?}"
        );
    }

    #[test]
    fn merge_core_rule_action_upgrade_allowed() {
        // Upgrading rm-recursive-to-trash from trash to block is allowed
        let user_rules = vec![UserRule {
            name: "rm-recursive-to-trash".to_string(),
            command: None,
            action: Some(ActionKind::Block),
            enabled: None,
            destination: None,
            match_all: None,
            match_any: None,
            message: None,
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "rm-recursive-to-trash")
            .unwrap();
        assert_eq!(rule.action, ActionKind::Block); // upgraded
    }

    #[test]
    fn merge_core_rule_message_override_allowed() {
        let user_rules = vec![UserRule {
            name: "git-push-force-block".to_string(),
            command: None,
            action: None,
            enabled: None,
            destination: None,
            match_all: None,
            match_any: None,
            message: Some("my custom message".to_string()),
            subcommand: None,
        }];
        let mut warnings = Vec::new();
        let merged = merge_rules(default_rules(), &user_rules, &no_overrides(), &mut warnings);

        let rule = merged
            .iter()
            .find(|r| r.name == "git-push-force-block")
            .unwrap();
        assert_eq!(rule.message.as_deref(), Some("my custom message"));
        // No warnings for message-only override
        assert!(
            warnings.is_empty(),
            "no warnings for message override: {warnings:?}"
        );
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
    fn validate_symlink_destination_disables_rule() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("omamori-symdest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let link = dir.join("link");
        symlink(&real_dir, &link).unwrap();

        let mut rules = vec![
            RuleConfig::new(
                "sym",
                "rm",
                ActionKind::MoveTo,
                Vec::new(),
                Vec::new(),
                None,
            )
            .with_destination(link.display().to_string()),
        ];
        let mut warnings = Vec::new();
        validate_rules(&mut rules, &mut warnings);
        assert!(
            warnings.iter().any(|w| w.contains("is a symlink")),
            "expected symlink warning, got: {warnings:?}"
        );
        assert!(!rules[0].enabled);

        let _ = std::fs::remove_dir_all(dir);
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

    /// DI-13: omamori self-protect rules must exist in `default_rules()`.
    /// PR1c will relax Phase 1A verb-pattern substring match for `omamori`
    /// subcommands; without these Phase 2 builtin rules a real `omamori
    /// config disable` invocation would not be caught.
    #[test]
    fn default_rules_includes_omamori_self_protect_six_rules() {
        let rules = default_rules();
        let required: &[&str] = &[
            "omamori-config-modify-block",
            "omamori-uninstall-block",
            "omamori-init-force-block",
            "omamori-override-block",
            "omamori-doctor-fix-block",
            "omamori-explain-block",
        ];
        for name in required {
            let rule = rules
                .iter()
                .find(|r| r.name == *name)
                .unwrap_or_else(|| panic!("default_rules() must include {}", name));
            assert_eq!(
                rule.command, "omamori",
                "{} must target program 'omamori'",
                name
            );
            assert!(
                matches!(rule.action, ActionKind::Block),
                "{} must use Block action",
                name
            );
            assert!(rule.is_builtin, "{} must be marked as builtin", name);
            assert!(rule.enabled, "{} must be enabled by default", name);
        }
    }

    /// Verify each `omamori-*-block` rule actually matches its target invocation
    /// via `match_rule`, independently of Phase 1A `command.contains`.
    #[test]
    fn omamori_self_protect_rules_match_via_phase2() {
        use crate::rules::{CommandInvocation, match_rule};
        let rules = default_rules();
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "omamori",
                &["config", "disable", "rm-recursive-to-trash"],
                "omamori-config-modify-block",
            ),
            (
                "omamori",
                &["config", "enable", "git-reset-block"],
                "omamori-config-modify-block",
            ),
            ("omamori", &["uninstall"], "omamori-uninstall-block"),
            ("omamori", &["init", "--force"], "omamori-init-force-block"),
            ("omamori", &["override"], "omamori-override-block"),
            ("omamori", &["doctor", "--fix"], "omamori-doctor-fix-block"),
            (
                "omamori",
                &["explain", "rm", "-rf", "/"],
                "omamori-explain-block",
            ),
        ];
        for (program, args, expected) in cases {
            let inv = CommandInvocation::new(
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            );
            let matched = match_rule(&rules, &inv);
            assert!(
                matched.is_some(),
                "command `{} {:?}` should match a rule",
                program,
                args
            );
            assert_eq!(
                matched.unwrap().name,
                *expected,
                "command `{} {:?}` should match `{}`",
                program,
                args,
                expected
            );
        }
    }

    /// DI-13 false-positive regression guard. The `omamori-*-block` rules use
    /// `subcommand` constraint so that arguments at non-subcommand positions
    /// containing protected words do not trigger a false block. Without
    /// `subcommand`, `match_any` would match any argument anywhere.
    /// Codex review (PR1a R1) flagged this as a P2 regression risk.
    #[test]
    fn omamori_self_protect_rules_skip_false_positive_data_args() {
        use crate::rules::{CommandInvocation, match_rule};
        let rules = default_rules();
        // Each command has args[0] != target subcommand, but contains protected
        // words at non-subcommand positions. Should NOT match any omamori-* rule.
        let benign_cases: &[(&str, &[&str])] = &[
            ("omamori", &["exec", "--", "echo", "disable", "config"]),
            ("omamori", &["report", "--by_rule", "uninstall"]),
            ("omamori", &["audit", "show", "--filter", "override"]),
            ("omamori", &["status", "--note", "explain something"]),
            ("omamori", &["init"]), // no --force, must not match init-force-block
            ("omamori", &["doctor"]), // no --fix, must not match doctor-fix-block
        ];
        for (program, args) in benign_cases {
            let inv = CommandInvocation::new(
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            );
            let matched = match_rule(&rules, &inv);
            if let Some(m) = matched {
                assert!(
                    !m.name.starts_with("omamori-"),
                    "benign command `{} {:?}` must not match self-protect rule `{}`",
                    program,
                    args,
                    m.name
                );
            }
        }
    }

    /// Codex review (PR1a R2) [P2]: user-defined rules in TOML must honor the
    /// `subcommand` field. Earlier `UserRule` was missing this field, silently
    /// dropping it for custom rules. This test pins that user rules can declare
    /// `subcommand` and have it propagate into the resolved Config.
    #[test]
    fn user_rule_with_subcommand_field_is_honored() {
        let toml_str = r#"
[[rules]]
name = "my-custom-block"
command = "mytool"
action = "block"
subcommand = "danger"
match_any = ["--really"]
"#;
        let user: UserConfig = toml::from_str(toml_str).unwrap();
        let mut warnings = Vec::new();
        let config = build_merged_config(user, &mut warnings);
        let rule = config
            .rules
            .iter()
            .find(|r| r.name == "my-custom-block")
            .expect("user-defined rule should be merged");
        assert_eq!(
            rule.subcommand.as_deref(),
            Some("danger"),
            "subcommand field on user rule must be propagated"
        );
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
        assert_eq!(config.detectors.len(), 6); // defaults (claude-code, codex-cli, cursor, gemini-cli, cline, ai-guard-fallback)
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

    // --- CI consistency checks (PR 2: config.default.toml ↔ code sync) ---

    #[test]
    fn config_default_toml_rules_match_default_rules() {
        let toml_str = include_str!("../config.default.toml");
        let parsed: Config = toml::from_str(toml_str).unwrap();
        let toml_names: HashSet<&str> = parsed.rules.iter().map(|r| r.name.as_str()).collect();
        let code_rules = default_rules();
        let code_names: HashSet<&str> = code_rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            toml_names,
            code_names,
            "config.default.toml rules and default_rules() are out of sync.\n\
             In TOML only: {:?}\n\
             In code only: {:?}",
            toml_names.difference(&code_names).collect::<Vec<_>>(),
            code_names.difference(&toml_names).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn config_default_toml_detectors_match_default_detectors() {
        let toml_str = include_str!("../config.default.toml");
        let parsed: Config = toml::from_str(toml_str).unwrap();
        let toml_names: HashSet<&str> = parsed.detectors.iter().map(|d| d.name.as_str()).collect();
        let code_detectors = default_detectors();
        let code_names: HashSet<&str> = code_detectors.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            toml_names,
            code_names,
            "config.default.toml detectors and default_detectors() are out of sync.\n\
             In TOML only: {:?}\n\
             In code only: {:?}",
            toml_names.difference(&code_names).collect::<Vec<_>>(),
            code_names.difference(&toml_names).collect::<Vec<_>>(),
        );
    }

    // --- Context default-on (v0.10.9) ---

    #[test]
    fn default_config_has_context_enabled() {
        let config = Config::default();
        assert!(
            config.context.is_some(),
            "context should be enabled by default"
        );
        let ctx = config.context.unwrap();
        assert!(!ctx.regenerable_paths.is_empty());
        assert!(!ctx.protected_paths.is_empty());
        assert!(ctx.git.enabled, "git-aware should be enabled by default");
    }

    #[test]
    fn config_default_toml_context_matches_defaults() {
        let toml_str = include_str!("../config.default.toml");
        let parsed: Config = toml::from_str(toml_str).unwrap();
        let code_ctx = crate::context::ContextConfig::default();
        let toml_ctx = parsed
            .context
            .expect("config.default.toml must have [context]");
        assert_eq!(toml_ctx.regenerable_paths, code_ctx.regenerable_paths);
        assert_eq!(toml_ctx.protected_paths, code_ctx.protected_paths);
        assert_eq!(toml_ctx.git.enabled, code_ctx.git.enabled);
        assert_eq!(toml_ctx.git.timeout_ms, code_ctx.git.timeout_ms);
    }

    #[test]
    fn config_template_roundtrip_has_context() {
        let template = config_template();
        let parsed: Config = toml::from_str(&template).unwrap();
        assert!(
            parsed.context.is_some(),
            "config_template() must produce a TOML with [context] active"
        );
    }

    #[test]
    fn serde_empty_git_section_defaults_enabled_true() {
        let toml_str = "[context]\n[context.git]\n";
        let parsed: Config = toml::from_str(toml_str).unwrap();
        let ctx = parsed.context.expect("[context] should parse");
        assert!(
            ctx.git.enabled,
            "empty [context.git] should default to enabled=true"
        );
    }

    #[test]
    fn existing_config_without_context_stays_none() {
        let toml_str = r#"
[[detectors]]
name = "claude-code"
type = "env_var"
env_key = "CLAUDECODE"
env_value = "1"

[[rules]]
name = "rm-recursive-to-trash"
command = "rm"
action = "trash"
match_any = ["-r", "-rf"]
message = "moved to trash"
"#;
        let parsed: Config = toml::from_str(toml_str).unwrap();
        assert!(
            parsed.context.is_none(),
            "config without [context] section must parse to context: None"
        );
    }

    // --- G-05: write_default_config ---

    #[test]
    fn write_default_config_creates_with_correct_permissions() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g05-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = dir.join("config.toml");
        let result = write_default_config(&path, false);
        assert!(result.is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600, "file should be mode 600");
            let dir_meta = fs::metadata(&dir).unwrap();
            assert_eq!(dir_meta.mode() & 0o777, 0o700, "dir should be mode 700");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_default_config_rejects_symlink_target() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g05-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        #[cfg(unix)]
        {
            let real_file = dir.join("real.toml");
            fs::write(&real_file, "real").unwrap();
            let link_path = dir.join("config.toml");
            std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

            let result = write_default_config(&link_path, false);
            assert!(result.is_err());
            let err = format!("{}", result.unwrap_err());
            assert!(err.contains("symlink"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_default_config_force_atomic_write() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g05-3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = dir.join("config.toml");
        // First create
        write_default_config(&path, false).unwrap();
        let content1 = fs::read_to_string(&path).unwrap();

        // Force overwrite
        let result = write_default_config(&path, true);
        assert!(result.is_ok());
        let content2 = fs::read_to_string(&path).unwrap();
        assert_eq!(content1, content2, "content should be the same template");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_default_config_no_force_errors_on_existing() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g05-4-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = dir.join("config.toml");
        write_default_config(&path, false).unwrap();

        // Second create without force should fail
        let result = write_default_config(&path, false);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    // --- G-06: load_config permissions ---

    #[test]
    fn load_config_rejects_insecure_permissions() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g06-1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("config.toml");
        fs::write(&path, "# test config\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Set insecure permissions (world-readable)
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

            let result = load_config(Some(&path)).unwrap();
            // Should warn about permissions and use default config
            assert!(
                result.warnings.iter().any(|w| w.contains("permissions")),
                "should warn about insecure permissions"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_accepts_secure_permissions() {
        let dir = std::env::temp_dir().join(format!("omamori-cfg-g06-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("config.toml");
        // Write a minimal valid config
        fs::write(&path, "# valid config\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

            let result = load_config(Some(&path)).unwrap();
            // No permission warnings
            assert!(
                !result.warnings.iter().any(|w| w.contains("permissions")),
                "should not warn about secure permissions"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
