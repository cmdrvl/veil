#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::allowlist::DEFAULT_SAFE_PATTERNS;

const DEFAULT_AUTHORIZED_TOOLS: &[&str] = &[
    "shape",
    "rvl",
    "vacuum",
    "hash",
    "fingerprint",
    "profile",
    "canon",
    "lock",
    "pack",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub sensitivity: SensitivityConfig,
    pub allowlist: AllowlistConfig,
    pub spine: SpineConfig,
    pub policy: PolicyConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitivityConfig {
    pub protected: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistConfig {
    pub safe_patterns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpineConfig {
    pub authorized_tools: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub default: PolicyMode,
    pub audit_log: bool,
    pub audit_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Deny,
    Warn,
    Log,
}

pub fn load_config(repo_root: &Path) -> io::Result<Config> {
    let home = env::var_os("HOME").map(PathBuf::from);
    let xdg_config_home = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let xdg_state_home = env::var_os("XDG_STATE_HOME").map(PathBuf::from);
    let env_overrides = PartialConfig::from_env(home.as_deref(), xdg_state_home.as_deref())?;

    load_config_from_paths(
        repo_root,
        home.as_deref(),
        xdg_config_home.as_deref(),
        xdg_state_home.as_deref(),
        Path::new("/etc/veil/config.toml"),
        env_overrides,
    )
}

fn load_config_from_paths(
    repo_root: &Path,
    home: Option<&Path>,
    xdg_config_home: Option<&Path>,
    xdg_state_home: Option<&Path>,
    system_path: &Path,
    env_overrides: PartialConfig,
) -> io::Result<Config> {
    let mut config = Config::defaults(home, xdg_state_home)?;
    let user_path = user_config_path(home, xdg_config_home);
    let project_path = repo_root.join(".veil.toml");

    for (path, layer_name) in [
        (system_path, "system"),
        (user_path.as_path(), "user"),
        (project_path.as_path(), "project"),
    ] {
        if let Some(layer) = load_optional_config(path, layer_name, home)? {
            config.apply_partial(layer);
        }
    }

    config.apply_partial(env_overrides);
    Ok(config)
}

impl Config {
    fn defaults(home: Option<&Path>, xdg_state_home: Option<&Path>) -> io::Result<Self> {
        Ok(Self {
            sensitivity: SensitivityConfig {
                protected: Vec::new(),
            },
            allowlist: AllowlistConfig {
                safe_patterns: DEFAULT_SAFE_PATTERNS
                    .iter()
                    .map(|pattern| (*pattern).to_owned())
                    .collect(),
            },
            spine: SpineConfig {
                authorized_tools: DEFAULT_AUTHORIZED_TOOLS
                    .iter()
                    .map(|tool| (*tool).to_owned())
                    .collect(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: true,
                audit_path: default_audit_path(home, xdg_state_home)?,
            },
        })
    }

    fn apply_partial(&mut self, partial: PartialConfig) {
        if let Some(sensitivity) = partial.sensitivity
            && let Some(protected) = sensitivity.protected
        {
            self.sensitivity.protected = protected;
        }

        if let Some(allowlist) = partial.allowlist
            && let Some(safe_patterns) = allowlist.safe_patterns
        {
            self.allowlist.safe_patterns = safe_patterns;
        }

        if let Some(spine) = partial.spine
            && let Some(authorized_tools) = spine.authorized_tools
        {
            self.spine.authorized_tools = authorized_tools;
        }

        if let Some(policy) = partial.policy {
            if let Some(default_mode) = policy.default {
                self.policy.default = default_mode;
            }

            if let Some(audit_log) = policy.audit_log {
                self.policy.audit_log = audit_log;
            }

            if let Some(audit_path) = policy.audit_path {
                self.policy.audit_path = audit_path;
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PartialConfig {
    sensitivity: Option<PartialSensitivityConfig>,
    allowlist: Option<PartialAllowlistConfig>,
    spine: Option<PartialSpineConfig>,
    policy: Option<PartialPolicyConfig>,
}

impl PartialConfig {
    fn from_env(home: Option<&Path>, xdg_state_home: Option<&Path>) -> io::Result<Self> {
        let protected = split_csv_env("VEIL_PROTECTED");
        let safe_patterns = split_csv_env("VEIL_SAFE_PATTERNS");
        let authorized_tools = split_csv_env("VEIL_SPINE_TOOLS");
        let default_mode = parse_env_var("VEIL_POLICY", parse_policy_mode)?;
        let audit_log = parse_env_var("VEIL_AUDIT_LOG", parse_bool)?;
        let audit_path = parse_env_var("VEIL_AUDIT_PATH", |value| {
            Ok(expand_tilde(Path::new(value), home, xdg_state_home))
        })?;

        Ok(Self {
            sensitivity: protected.map(|items| PartialSensitivityConfig {
                protected: Some(items),
            }),
            allowlist: safe_patterns.map(|items| PartialAllowlistConfig {
                safe_patterns: Some(items),
            }),
            spine: authorized_tools.map(|items| PartialSpineConfig {
                authorized_tools: Some(items),
            }),
            policy: if default_mode.is_some() || audit_log.is_some() || audit_path.is_some() {
                Some(PartialPolicyConfig {
                    default: default_mode,
                    audit_log,
                    audit_path,
                })
            } else {
                None
            },
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PartialSensitivityConfig {
    protected: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PartialAllowlistConfig {
    safe_patterns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PartialSpineConfig {
    authorized_tools: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PartialPolicyConfig {
    #[serde(rename = "default")]
    default: Option<PolicyMode>,
    audit_log: Option<bool>,
    audit_path: Option<PathBuf>,
}

fn load_optional_config(
    path: &Path,
    layer_name: &str,
    home: Option<&Path>,
) -> io::Result<Option<PartialConfig>> {
    match fs::read_to_string(path) {
        Ok(contents) => toml::from_str::<PartialConfig>(&contents)
            .map(|config| Some(expand_partial_paths(config, home)))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid {layer_name} config at {}: {error}", path.display()),
                )
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn expand_partial_paths(mut config: PartialConfig, home: Option<&Path>) -> PartialConfig {
    if let Some(policy) = &mut config.policy
        && let Some(path) = &policy.audit_path
    {
        policy.audit_path = Some(expand_tilde(path, home, None));
    }

    config
}

fn user_config_path(home: Option<&Path>, xdg_config_home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(path) => path.join("veil/config.toml"),
        None => match home {
            Some(path) => path.join(".config/veil/config.toml"),
            None => PathBuf::from(".config/veil/config.toml"),
        },
    }
}

fn default_audit_path(home: Option<&Path>, xdg_state_home: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = xdg_state_home {
        return Ok(path.join("veil/audit.jsonl"));
    }

    if let Some(path) = home {
        return Ok(path.join(".local/state/veil/audit.jsonl"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "HOME or XDG_STATE_HOME must be set to resolve the default audit path",
    ))
}

fn split_csv_env(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn parse_env_var<T>(
    name: &str,
    parser: impl FnOnce(&str) -> io::Result<T>,
) -> io::Result<Option<T>> {
    match env::var(name) {
        Ok(value) => parser(&value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    }
}

fn parse_policy_mode(raw: &str) -> io::Result<PolicyMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "deny" => Ok(PolicyMode::Deny),
        "warn" => Ok(PolicyMode::Warn),
        "log" => Ok(PolicyMode::Log),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported VEIL_POLICY value `{raw}`"),
        )),
    }
}

fn parse_bool(raw: &str) -> io::Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported boolean value `{raw}`"),
        )),
    }
}

fn expand_tilde(path: &Path, home: Option<&Path>, xdg_state_home: Option<&Path>) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(stripped) = raw.strip_prefix("~/")
        && let Some(root) = home
    {
        return root.join(stripped);
    }

    if raw == "~"
        && let Some(root) = home
    {
        return root.to_path_buf();
    }

    if raw == "~/.local/state/veil/audit.jsonl"
        && let Some(root) = xdg_state_home
    {
        return root.join("veil/audit.jsonl");
    }

    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!("veil-{label}-{}-{nanos}", std::process::id()))
    }

    fn write_config(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("config directory should be creatable");
        }

        fs::write(path, contents).expect("config file should be writable");
    }

    fn load_for_test(
        repo_root: &Path,
        home: &Path,
        system_contents: Option<&str>,
        user_contents: Option<&str>,
        project_contents: Option<&str>,
        env_overrides: PartialConfig,
    ) -> io::Result<Config> {
        let system_path = repo_root.join("etc/veil/config.toml");
        let user_path = home.join(".config/veil/config.toml");
        let project_path = repo_root.join(".veil.toml");

        if let Some(contents) = system_contents {
            write_config(&system_path, contents);
        }

        if let Some(contents) = user_contents {
            write_config(&user_path, contents);
        }

        if let Some(contents) = project_contents {
            write_config(&project_path, contents);
        }

        load_config_from_paths(
            repo_root,
            Some(home),
            None,
            None,
            &system_path,
            env_overrides,
        )
    }

    #[test]
    fn missing_files_are_ignored_cleanly() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            None,
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(config.sensitivity.protected, Vec::<String>::new());
        assert_eq!(config.policy.default, PolicyMode::Deny);
        assert_eq!(
            config.policy.audit_path,
            home.join(".local/state/veil/audit.jsonl")
        );
    }

    #[test]
    fn system_layer_loads_when_present() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            Some(
                r#"
                [sensitivity]
                protected = ["system/**"]
                "#,
            ),
            None,
            None,
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(config.sensitivity.protected, vec!["system/**"]);
    }

    #[test]
    fn user_layer_overrides_system_layer() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            Some(
                r#"
                [policy]
                default = "log"
                "#,
            ),
            Some(
                r#"
                [policy]
                default = "warn"
                "#,
            ),
            None,
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(config.policy.default, PolicyMode::Warn);
    }

    #[test]
    fn project_layer_overrides_user_layer() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            None,
            Some(
                r#"
                [spine]
                authorized_tools = ["shape"]
                "#,
            ),
            Some(
                r#"
                [spine]
                authorized_tools = ["shape", "profile", "canon"]
                "#,
            ),
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(
            config.spine.authorized_tools,
            vec!["shape", "profile", "canon"]
        );
    }

    #[test]
    fn environment_overrides_project_for_protected_paths_and_policy() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let env_overrides = PartialConfig {
            sensitivity: Some(PartialSensitivityConfig {
                protected: Some(vec!["env/**".to_owned()]),
            }),
            allowlist: None,
            spine: None,
            policy: Some(PartialPolicyConfig {
                default: Some(PolicyMode::Warn),
                audit_log: Some(false),
                audit_path: None,
            }),
        };

        let config = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            Some(
                r#"
                [sensitivity]
                protected = ["project/**"]

                [policy]
                default = "deny"
                audit_log = true
                "#,
            ),
            env_overrides,
        )
        .unwrap();

        assert_eq!(config.sensitivity.protected, vec!["env/**"]);
        assert_eq!(config.policy.default, PolicyMode::Warn);
        assert!(!config.policy.audit_log);
    }

    #[test]
    fn full_precedence_order_uses_highest_available_layer() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let env_overrides = PartialConfig {
            sensitivity: Some(PartialSensitivityConfig {
                protected: Some(vec!["env/**".to_owned()]),
            }),
            allowlist: None,
            spine: Some(PartialSpineConfig {
                authorized_tools: Some(vec!["env-tool".to_owned()]),
            }),
            policy: Some(PartialPolicyConfig {
                default: Some(PolicyMode::Warn),
                audit_log: Some(false),
                audit_path: Some(home.join("custom/audit.jsonl")),
            }),
        };

        let config = load_for_test(
            &repo_root,
            &home,
            Some(
                r#"
                [sensitivity]
                protected = ["system/**"]

                [allowlist]
                safe_patterns = ["system.md"]

                [spine]
                authorized_tools = ["system-tool"]

                [policy]
                default = "log"
                audit_log = true
                "#,
            ),
            Some(
                r#"
                [allowlist]
                safe_patterns = ["user.md"]

                [spine]
                authorized_tools = ["user-tool"]
                "#,
            ),
            Some(
                r#"
                [allowlist]
                safe_patterns = ["project.md"]
                "#,
            ),
            env_overrides,
        )
        .unwrap();

        assert_eq!(config.sensitivity.protected, vec!["env/**"]);
        assert_eq!(config.allowlist.safe_patterns, vec!["project.md"]);
        assert_eq!(config.spine.authorized_tools, vec!["env-tool"]);
        assert_eq!(config.policy.default, PolicyMode::Warn);
        assert!(!config.policy.audit_log);
        assert_eq!(config.policy.audit_path, home.join("custom/audit.jsonl"));
    }

    #[test]
    fn invalid_toml_surfaces_a_clear_error() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let error = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            Some(
                r#"
                [policy
                default = "deny"
                "#,
            ),
            PartialConfig::default(),
        )
        .expect_err("invalid TOML should return an error");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("invalid project config"),
            "unexpected error message: {error}"
        );
    }
}
