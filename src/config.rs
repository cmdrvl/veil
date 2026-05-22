#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::allowlist::DEFAULT_SAFE_PATTERNS;

const DEFAULT_AUTHORIZED_TOOLS: &[&str] = &[
    "shape",
    "rvl",
    "vacuum",
    "hashbytes",
    "fingerprint",
    "profile",
    "canon",
    "lock",
    "pack",
];

const DEFAULT_CMDRVL_CONFIG_PROTECTION_SUBTREES: &[&str] = &[
    "config",
    "secrets",
    "state/cmdrvl-gtm/email-watch",
    "state/cmdrvl-cli/guard-receipts",
    "state/cmdrvl-holon/doctor-runs",
    "receipts",
    "migrations",
    "notices",
];

const CMDRVL_ROOT_DIR: &str = ".cmdrvl";
const VEIL_CONFIG_RELATIVE: &[&str] = &["config", "veil", "config.toml"];
const VEIL_AUDIT_RELATIVE: &[&str] = &["logs", "veil", "audit.jsonl"];
const MIGRATION_LOG_RELATIVE: &[&str] = &["migrations", "applied.jsonl"];
const DEPRECATED_NOTICE_RELATIVE: &[&str] = &["notices", "deprecated-paths.jsonl"];

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
    let user_path = user_config_path(home);
    let legacy_user_path = legacy_user_config_path(home, xdg_config_home);
    if legacy_user_path.exists() {
        migrate_legacy_file(
            home,
            &legacy_user_path,
            &user_path,
            "veil-user-config",
            "config",
        )?;
    } else {
        migrate_legacy_file(
            home,
            system_path,
            &user_path,
            "veil-system-config",
            "config",
        )?;
    }

    let audit_path = default_audit_path(home, xdg_state_home)?;
    if let Some(legacy_audit_path) = legacy_audit_path(home, xdg_state_home) {
        migrate_legacy_file(
            home,
            &legacy_audit_path,
            &audit_path,
            "veil-audit-log",
            "log",
        )?;
    }

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
                protected: default_cmdrvl_config_protection_patterns(home),
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
            self.sensitivity.protected =
                protected_with_cmdrvl_profile(&self.sensitivity.protected, protected);
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

fn default_cmdrvl_config_protection_patterns(home: Option<&Path>) -> Vec<String> {
    let root = cmdrvl_root(home);

    DEFAULT_CMDRVL_CONFIG_PROTECTION_SUBTREES
        .iter()
        .map(|subtree| protected_subtree_pattern(&root, subtree))
        .collect()
}

fn protected_subtree_pattern(root: &Path, subtree: &str) -> String {
    let path = root.join(subtree);
    format!("{}/**", path.to_string_lossy().replace('\\', "/"))
}

fn protected_with_cmdrvl_profile(existing: &[String], replacement: Vec<String>) -> Vec<String> {
    let mut protected = existing
        .iter()
        .filter(|pattern| is_cmdrvl_config_protection_pattern(pattern))
        .cloned()
        .collect::<Vec<_>>();

    append_unique(&mut protected, replacement);
    protected
}

fn is_cmdrvl_config_protection_pattern(pattern: &str) -> bool {
    pattern.starts_with(".cmdrvl/")
        || pattern.starts_with("~/.cmdrvl/")
        || pattern.contains("/.cmdrvl/")
}

fn append_unique(target: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !target.iter().any(|existing| existing == &item) {
            target.push(item);
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct PartialSensitivityConfig {
    protected: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialAllowlistConfig {
    safe_patterns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialSpineConfig {
    authorized_tools: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn user_config_path(home: Option<&Path>) -> PathBuf {
    join_relative(&cmdrvl_root(home), VEIL_CONFIG_RELATIVE)
}

fn legacy_user_config_path(home: Option<&Path>, xdg_config_home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(path) => path.join("veil/config.toml"),
        None => match home {
            Some(path) => path.join(".config/veil/config.toml"),
            None => PathBuf::from(".config/veil/config.toml"),
        },
    }
}

fn default_audit_path(home: Option<&Path>, _xdg_state_home: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = home {
        return Ok(join_relative(&cmdrvl_root(Some(path)), VEIL_AUDIT_RELATIVE));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "HOME must be set to resolve the default CMD+RVL audit path",
    ))
}

fn legacy_audit_path(home: Option<&Path>, xdg_state_home: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = xdg_state_home {
        return Some(path.join("veil/audit.jsonl"));
    }

    home.map(|path| path.join(".local/state/veil/audit.jsonl"))
}

fn cmdrvl_root(home: Option<&Path>) -> PathBuf {
    home.map(|path| path.join(CMDRVL_ROOT_DIR))
        .unwrap_or_else(|| PathBuf::from(CMDRVL_ROOT_DIR))
}

fn join_relative(root: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn migrate_legacy_file(
    home: Option<&Path>,
    legacy_path: &Path,
    canonical_path: &Path,
    path_class: &str,
    category: &str,
) -> io::Result<()> {
    if legacy_path == canonical_path || !legacy_path.exists() {
        return Ok(());
    }

    let root = cmdrvl_root(home);
    if canonical_path.exists() {
        append_migration_notice(
            &root,
            path_class,
            category,
            legacy_path,
            canonical_path,
            "canonical-preferred",
        )?;
        return Ok(());
    }

    if let Some(parent) = canonical_path.parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::copy(legacy_path, canonical_path) {
        Ok(_) => {
            preserve_permissions(legacy_path, canonical_path)?;
            append_migration_event(
                &root,
                path_class,
                category,
                legacy_path,
                canonical_path,
                "copied",
                "ok",
            )?;
            append_migration_notice(
                &root,
                path_class,
                category,
                legacy_path,
                canonical_path,
                "copied-to-canonical",
            )
        }
        Err(error) => {
            append_migration_event(
                &root,
                path_class,
                category,
                legacy_path,
                canonical_path,
                "copy",
                "error",
            )?;
            Err(error)
        }
    }
}

fn preserve_permissions(source: &Path, destination: &Path) -> io::Result<()> {
    let permissions = fs::metadata(source)?.permissions();
    fs::set_permissions(destination, permissions)
}

fn append_migration_event(
    root: &Path,
    path_class: &str,
    category: &str,
    source_path: &Path,
    destination_path: &Path,
    action: &str,
    outcome: &str,
) -> io::Result<()> {
    append_jsonl(
        &join_relative(root, MIGRATION_LOG_RELATIVE),
        json!({
            "ts": migration_timestamp(),
            "tool": "veil",
            "path_class": path_class,
            "category": category,
            "source_path": source_path.display().to_string(),
            "destination_path": destination_path.display().to_string(),
            "action": action,
            "outcome": outcome,
        }),
    )
}

fn append_migration_notice(
    root: &Path,
    path_class: &str,
    category: &str,
    source_path: &Path,
    destination_path: &Path,
    action: &str,
) -> io::Result<()> {
    append_jsonl(
        &join_relative(root, DEPRECATED_NOTICE_RELATIVE),
        json!({
            "ts": migration_timestamp(),
            "tool": "veil",
            "path_class": path_class,
            "category": category,
            "legacy_path": source_path.display().to_string(),
            "canonical_path": destination_path.display().to_string(),
            "action": action,
        }),
    )
}

fn append_jsonl(path: &Path, value: Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    file.write_all(b"\n")?;
    file.flush()
}

fn migration_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
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
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "veil-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }

    fn write_config(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("config directory should be creatable");
        }

        fs::write(path, contents).expect("config file should be writable");
    }

    fn read_jsonl(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("jsonl file should be readable")
            .lines()
            .map(|line| serde_json::from_str(line).expect("jsonl line should parse"))
            .collect()
    }

    fn canonical_user_config_path(home: &Path) -> PathBuf {
        user_config_path(Some(home))
    }

    fn migration_log_path(home: &Path) -> PathBuf {
        join_relative(&cmdrvl_root(Some(home)), MIGRATION_LOG_RELATIVE)
    }

    fn notice_log_path(home: &Path) -> PathBuf {
        join_relative(&cmdrvl_root(Some(home)), DEPRECATED_NOTICE_RELATIVE)
    }

    fn canonical_audit_path(home: &Path) -> PathBuf {
        default_audit_path(Some(home), None).expect("audit path should resolve")
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
        let user_path = legacy_user_config_path(Some(home), None);
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

    fn expected_cmdrvl_profile(home: &Path) -> Vec<String> {
        default_cmdrvl_config_protection_patterns(Some(home))
    }

    fn expected_with_cmdrvl_profile(home: &Path, extra: &[&str]) -> Vec<String> {
        let mut expected = expected_cmdrvl_profile(home);
        expected.extend(extra.iter().map(|pattern| (*pattern).to_owned()));
        expected
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

        assert_eq!(config.sensitivity.protected, expected_cmdrvl_profile(&home));
        assert_eq!(config.policy.default, PolicyMode::Deny);
        assert_eq!(
            config.policy.audit_path,
            home.join(".cmdrvl/logs/veil/audit.jsonl")
        );
        assert!(
            !canonical_user_config_path(&home).exists(),
            "missing legacy config should not create canonical config"
        );
    }

    #[test]
    fn default_cmdrvl_config_protection_profile_covers_canonical_subtrees() {
        let home = PathBuf::from("/tmp/home");
        let config = Config::defaults(Some(&home), None).unwrap();

        for pattern in [
            "/tmp/home/.cmdrvl/config/**",
            "/tmp/home/.cmdrvl/secrets/**",
            "/tmp/home/.cmdrvl/state/cmdrvl-gtm/email-watch/**",
            "/tmp/home/.cmdrvl/state/cmdrvl-cli/guard-receipts/**",
            "/tmp/home/.cmdrvl/state/cmdrvl-holon/doctor-runs/**",
            "/tmp/home/.cmdrvl/receipts/**",
            "/tmp/home/.cmdrvl/migrations/**",
            "/tmp/home/.cmdrvl/notices/**",
        ] {
            assert!(
                config
                    .sensitivity
                    .protected
                    .iter()
                    .any(|item| item == pattern),
                "missing protected pattern {pattern}"
            );
        }
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

        assert_eq!(
            config.sensitivity.protected,
            expected_with_cmdrvl_profile(&home, &["system/**"])
        );
        assert!(
            canonical_user_config_path(&home).exists(),
            "legacy system config should be copied into the canonical user config path"
        );
        let migration_events = read_jsonl(&migration_log_path(&home));
        assert!(migration_events.iter().any(|event| {
            event["path_class"] == "veil-system-config"
                && event["action"] == "copied"
                && event["outcome"] == "ok"
        }));
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
        assert!(
            canonical_user_config_path(&home).exists(),
            "legacy user config should be copied into the canonical root"
        );
    }

    #[test]
    fn legacy_user_config_is_copied_to_cmdrvl_root_on_first_run() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            None,
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

        let canonical_path = canonical_user_config_path(&home);
        assert_eq!(config.policy.default, PolicyMode::Warn);
        assert!(canonical_path.exists());

        let migration_events = read_jsonl(&migration_log_path(&home));
        assert!(migration_events.iter().any(|event| {
            event["path_class"] == "veil-user-config"
                && event["action"] == "copied"
                && event["outcome"] == "ok"
        }));

        let notices = read_jsonl(&notice_log_path(&home));
        assert!(notices.iter().any(|notice| {
            notice["path_class"] == "veil-user-config" && notice["action"] == "copied-to-canonical"
        }));
    }

    #[test]
    fn canonical_user_config_wins_when_legacy_also_exists() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");
        write_config(
            &canonical_user_config_path(&home),
            r#"
            [policy]
            default = "warn"
            "#,
        );
        write_config(
            &legacy_user_config_path(Some(&home), None),
            r#"
            [policy]
            default = "log"
            "#,
        );

        let config = load_config_from_paths(
            &repo_root,
            Some(&home),
            None,
            None,
            &repo_root.join("etc/veil/config.toml"),
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(config.policy.default, PolicyMode::Warn);
        let notices = read_jsonl(&notice_log_path(&home));
        assert!(notices.iter().any(|notice| {
            notice["path_class"] == "veil-user-config" && notice["action"] == "canonical-preferred"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_user_config_permissions_are_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");
        let legacy_path = legacy_user_config_path(Some(&home), None);
        write_config(
            &legacy_path,
            r#"
            [policy]
            default = "warn"
            "#,
        );
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600))
            .expect("legacy permissions should be writable");

        load_config_from_paths(
            &repo_root,
            Some(&home),
            None,
            None,
            &repo_root.join("etc/veil/config.toml"),
            PartialConfig::default(),
        )
        .unwrap();

        let mode = fs::metadata(canonical_user_config_path(&home))
            .expect("canonical config should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn invalid_legacy_user_config_reports_canonical_parse_failure() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");
        write_config(
            &legacy_user_config_path(Some(&home), None),
            r#"
            [policy
            default = "deny"
            "#,
        );

        let error = load_config_from_paths(
            &repo_root,
            Some(&home),
            None,
            None,
            &repo_root.join("etc/veil/config.toml"),
            PartialConfig::default(),
        )
        .expect_err("invalid migrated config should return an error");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains(&canonical_user_config_path(&home).display().to_string()),
            "error should identify the canonical config path: {error}"
        );
    }

    #[test]
    fn legacy_default_audit_log_is_copied_to_cmdrvl_logs() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");
        let legacy_path = home.join(".local/state/veil/audit.jsonl");
        write_config(
            &legacy_path,
            r#"{"tool":"Read","decision":"deny","path_class":"fixture"}"#,
        );

        let config = load_config_from_paths(
            &repo_root,
            Some(&home),
            None,
            None,
            &repo_root.join("etc/veil/config.toml"),
            PartialConfig::default(),
        )
        .unwrap();

        let canonical_path = canonical_audit_path(&home);
        assert_eq!(config.policy.audit_path, canonical_path);
        assert_eq!(
            fs::read_to_string(canonical_path).expect("canonical audit should be readable"),
            r#"{"tool":"Read","decision":"deny","path_class":"fixture"}"#
        );

        let migration_events = read_jsonl(&migration_log_path(&home));
        assert!(migration_events.iter().any(|event| {
            event["path_class"] == "veil-audit-log"
                && event["action"] == "copied"
                && event["outcome"] == "ok"
        }));
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

        assert_eq!(
            config.sensitivity.protected,
            expected_with_cmdrvl_profile(&home, &["env/**"])
        );
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

        assert_eq!(
            config.sensitivity.protected,
            expected_with_cmdrvl_profile(&home, &["env/**"])
        );
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

    #[test]
    fn secret_config_sections_are_rejected() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let error = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            Some(
                r#"
                [secrets]
                source = "aws-secrets-manager"
                "#,
            ),
            PartialConfig::default(),
        )
        .expect_err("veil config should not accept secret source sections");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("invalid project config"),
            "unexpected error message: {error}"
        );
        assert!(
            error.to_string().contains("unknown field `secrets`"),
            "secret config sections must not be silently ignored: {error}"
        );
    }

    #[test]
    fn cmdrvl_config_protection_profile_survives_all_overrides() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let env_overrides = PartialConfig {
            sensitivity: Some(PartialSensitivityConfig {
                protected: Some(vec!["env-only/**".to_owned()]),
            }),
            allowlist: None,
            spine: None,
            policy: None,
        };

        let config = load_for_test(
            &repo_root,
            &home,
            Some(
                r#"
                [sensitivity]
                protected = ["system-only/**"]
                "#,
            ),
            Some(
                r#"
                [sensitivity]
                protected = ["user-only/**"]
                "#,
            ),
            Some(
                r#"
                [sensitivity]
                protected = ["project-only/**"]
                "#,
            ),
            env_overrides,
        )
        .unwrap();

        assert_eq!(
            config.sensitivity.protected,
            expected_with_cmdrvl_profile(&home, &["env-only/**"])
        );
    }
}
