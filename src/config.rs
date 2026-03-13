use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::AppError;
use crate::audit::AuditConfig;
use crate::detector::DetectorConfig;
use crate::rules::{ActionKind, RuleConfig};

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
                match toml::from_str::<Config>(&content) {
                    Ok(config) => config,
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

fn default_rules() -> Vec<RuleConfig> {
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
