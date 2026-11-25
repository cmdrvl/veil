#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::allowlist::DEFAULT_SAFE_PATTERNS;
use crate::protected_corpus::CorpusLimits;
use crate::spine::DeniedFlags;

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
    "verify",
    "assess",
    "benchmark",
    "airlock",
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

/// Key in `[spine.denied_flags]` that sets the list applied to every tool.
const DENIED_FLAGS_DEFAULT_KEY: &str = "default";

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
    /// `[protected_corpus]`: how much a protected-corpus filter build may read.
    pub protected_corpus: CorpusLimits,
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
    pub denied_flags: DeniedFlags,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub default: PolicyMode,
    pub audit_log: bool,
    pub audit_path: PathBuf,
    /// Opt-in: operator preflight additionally requires a healthy dcg companion guard.
    pub require_dcg: bool,
    /// What veil does with a command whose arguments it cannot resolve to
    /// paths (bd-2mi). Denies by default: dynamic arguments are the canonical
    /// way around a path rule.
    pub dynamic_args: DynamicArgsMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Deny,
    Warn,
    Log,
}

/// `[policy] dynamic_args`: the stance on a reader, a bulk transfer, or any
/// command that runs where a protected path is in play, when one of its
/// arguments is a variable, substitution or placeholder veil cannot resolve.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DynamicArgsMode {
    /// Block it, as the global `[policy] default` says (`warn` and `log`
    /// still downgrade a block to a warning).
    #[default]
    Deny,
    /// Allow it and record it in the audit log, with the argument and the
    /// reason. The agent is not told: use it to measure what `deny` would
    /// block before turning it on.
    Warn,
    /// Do not judge unresolved arguments. Anything the path rules can read
    /// is still judged.
    Allow,
}

impl DynamicArgsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Allow => "allow",
        }
    }
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: true,
                audit_path: default_audit_path(home, xdg_state_home)?,
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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

        if let Some(spine) = partial.spine {
            if let Some(authorized_tools) = spine.authorized_tools {
                self.spine.authorized_tools = authorized_tools;
            }

            for (key, flags) in spine.denied_flags.unwrap_or_default() {
                if key == DENIED_FLAGS_DEFAULT_KEY {
                    self.spine.denied_flags.default = flags;
                } else {
                    self.spine.denied_flags.per_tool.insert(key, flags);
                }
            }
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

            if let Some(require_dcg) = policy.require_dcg {
                self.policy.require_dcg = require_dcg;
            }

            if let Some(dynamic_args) = policy.dynamic_args {
                self.policy.dynamic_args = dynamic_args;
            }
        }

        if let Some(corpus) = partial.protected_corpus {
            if let Some(max_files) = corpus.max_files {
                self.protected_corpus.max_files = max_files;
            }

            if let Some(max_bytes) = corpus.max_bytes {
                self.protected_corpus.max_bytes = max_bytes;
            }

            if let Some(max_file_bytes) = corpus.max_file_bytes {
                self.protected_corpus.max_file_bytes = max_file_bytes;
            }

            if let Some(max_walk_entries) = corpus.max_walk_entries {
                self.protected_corpus.max_walk_entries = max_walk_entries;
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
    protected_corpus: Option<PartialProtectedCorpusConfig>,
}

impl PartialConfig {
    fn from_env(home: Option<&Path>, xdg_state_home: Option<&Path>) -> io::Result<Self> {
        let protected = split_csv_env("VEIL_PROTECTED");
        let safe_patterns = split_csv_env("VEIL_SAFE_PATTERNS");
        let authorized_tools = split_csv_env("VEIL_SPINE_TOOLS");
        let default_mode = parse_env_var("VEIL_POLICY", parse_policy_mode)?;
        let audit_log = parse_env_var("VEIL_AUDIT_LOG", parse_bool)?;
        let dynamic_args = parse_env_var("VEIL_DYNAMIC_ARGS", parse_dynamic_args_mode)?;
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
                denied_flags: None,
            }),
            policy: if default_mode.is_some()
                || audit_log.is_some()
                || audit_path.is_some()
                || dynamic_args.is_some()
            {
                Some(PartialPolicyConfig {
                    default: default_mode,
                    audit_log,
                    audit_path,
                    require_dcg: None,
                    dynamic_args,
                })
            } else {
                None
            },
            protected_corpus: None,
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
    /// `[spine.denied_flags]`: the `default` key replaces the default deny list;
    /// every other key names a tool and adds flags denied for that tool only.
    denied_flags: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialPolicyConfig {
    #[serde(rename = "default")]
    default: Option<PolicyMode>,
    audit_log: Option<bool>,
    audit_path: Option<PathBuf>,
    require_dcg: Option<bool>,
    dynamic_args: Option<DynamicArgsMode>,
}

/// `[protected_corpus]`: limits for the one-way filter that `veil sandbox
/// --egress airlock` builds over `[sensitivity] protected` files.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialProtectedCorpusConfig {
    max_files: Option<usize>,
    max_bytes: Option<u64>,
    max_file_bytes: Option<u64>,
    max_walk_entries: Option<usize>,
}

fn load_optional_config(
    path: &Path,
    layer_name: &str,
    home: Option<&Path>,
) -> io::Result<Option<PartialConfig>> {
    match fs::read_to_string(path) {
        Ok(contents) => toml::from_str::<PartialConfig>(&contents)
            .map_err(|error| error.to_string())
            .and_then(|config| validate_partial(&config).map(|()| config))
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

/// Rejects `[spine.denied_flags]` entries that could never match an argument,
/// so a typo like `explicit` (missing dashes) fails loudly instead of leaving
/// the flag silently allowed. Also rejects a zero `[protected_corpus]` limit,
/// which would silently build no filter.
fn validate_partial(config: &PartialConfig) -> Result<(), String> {
    if let Some(corpus) = config.protected_corpus.as_ref() {
        for (name, value) in [
            ("max_files", corpus.max_files.map(|value| value as u64)),
            ("max_bytes", corpus.max_bytes),
            ("max_file_bytes", corpus.max_file_bytes),
            (
                "max_walk_entries",
                corpus.max_walk_entries.map(|value| value as u64),
            ),
        ] {
            if value == Some(0) {
                return Err(format!("protected_corpus.{name} must be greater than zero"));
            }
        }
    }

    let Some(denied_flags) = config
        .spine
        .as_ref()
        .and_then(|spine| spine.denied_flags.as_ref())
    else {
        return Ok(());
    };

    for (key, flags) in denied_flags {
        for flag in flags {
            let well_formed = flag.len() > 1
                && flag.starts_with('-')
                && !flag.contains('=')
                && !flag.chars().any(char::is_whitespace);
            if !well_formed {
                return Err(format!(
                    "spine.denied_flags.{key} entry `{flag}` must be a flag such as `--explicit` (leading dash, no `=` or whitespace)"
                ));
            }
        }
    }

    Ok(())
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

fn parse_dynamic_args_mode(raw: &str) -> io::Result<DynamicArgsMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "deny" => Ok(DynamicArgsMode::Deny),
        "warn" => Ok(DynamicArgsMode::Warn),
        "allow" => Ok(DynamicArgsMode::Allow),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported VEIL_DYNAMIC_ARGS value `{raw}` (use deny, warn or allow)"),
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
    fn protected_corpus_limits_default_and_layer_like_other_sections() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let defaults = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            None,
            PartialConfig::default(),
        )
        .unwrap();
        assert_eq!(defaults.protected_corpus, CorpusLimits::default());

        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");
        let layered = load_for_test(
            &repo_root,
            &home,
            Some(
                r#"
                [protected_corpus]
                max_files = 10
                max_bytes = 1000
                "#,
            ),
            Some(
                r#"
                [protected_corpus]
                max_files = 20
                "#,
            ),
            Some(
                r#"
                [protected_corpus]
                max_file_bytes = 500
                max_walk_entries = 99
                "#,
            ),
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(
            layered.protected_corpus,
            CorpusLimits {
                max_files: 20,
                max_bytes: 1000,
                max_file_bytes: 500,
                max_walk_entries: 99,
            },
            "user overrides system per key; project and system keys survive"
        );
    }

    #[test]
    fn protected_corpus_rejects_zero_limits_and_unknown_keys() {
        for (contents, needle) in [
            (
                "[protected_corpus]\nmax_files = 0\n",
                "protected_corpus.max_files must be greater than zero",
            ),
            (
                "[protected_corpus]\nmax_bytes = 0\n",
                "protected_corpus.max_bytes must be greater than zero",
            ),
            (
                "[protected_corpus]\nmax_file_bytes = 0\n",
                "protected_corpus.max_file_bytes must be greater than zero",
            ),
            (
                "[protected_corpus]\nmax_walk_entries = 0\n",
                "protected_corpus.max_walk_entries must be greater than zero",
            ),
            ("[protected_corpus]\nmax_filez = 5\n", "unknown field"),
        ] {
            let repo_root = unique_temp_root("repo");
            let home = unique_temp_root("home");

            let error = load_for_test(
                &repo_root,
                &home,
                None,
                None,
                Some(contents),
                PartialConfig::default(),
            )
            .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                error.to_string().contains(needle),
                "{contents:?} gave {error}"
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
    fn denied_flags_default_to_the_raw_value_flags() {
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

        assert_eq!(
            config.spine.denied_flags.default,
            vec!["--explicit", "--raw", "--dump", "--show-values"]
        );
        assert!(config.spine.denied_flags.per_tool.is_empty());
    }

    #[test]
    fn denied_flags_table_sets_default_and_per_tool_additions_with_layer_override() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let config = load_for_test(
            &repo_root,
            &home,
            None,
            Some(
                r#"
                [spine.denied_flags]
                default = ["--explicit"]
                shape = ["--columns"]
                profile = ["--values"]
                "#,
            ),
            Some(
                r#"
                [spine.denied_flags]
                shape = ["--head"]
                "#,
            ),
            PartialConfig::default(),
        )
        .unwrap();

        assert_eq!(config.spine.denied_flags.default, vec!["--explicit"]);
        assert_eq!(
            config.spine.denied_flags.per_tool.get("shape"),
            Some(&vec!["--head".to_owned()]),
            "project layer replaces the user layer's list for the same tool"
        );
        assert_eq!(
            config.spine.denied_flags.per_tool.get("profile"),
            Some(&vec!["--values".to_owned()]),
            "tools the project layer does not mention keep the user layer's list"
        );
    }

    #[test]
    fn denied_flags_entries_that_could_never_match_are_rejected_at_load() {
        for bad in ["explicit", "-", "--ex plicit", "--explicit=true", ""] {
            let repo_root = unique_temp_root("repo");
            let home = unique_temp_root("home");

            let error = load_for_test(
                &repo_root,
                &home,
                None,
                None,
                Some(&format!("[spine.denied_flags]\ndefault = [\"{bad}\"]\n")),
                PartialConfig::default(),
            )
            .expect_err("a flag entry that cannot match must fail loudly");

            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "entry `{bad}`");
            assert!(
                error.to_string().contains("spine.denied_flags.default"),
                "entry `{bad}`: {error}"
            );
        }
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
                require_dcg: None,
                dynamic_args: None,
            }),
            protected_corpus: None,
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
                denied_flags: None,
            }),
            policy: Some(PartialPolicyConfig {
                default: Some(PolicyMode::Warn),
                audit_log: Some(false),
                audit_path: Some(home.join("custom/audit.jsonl")),
                require_dcg: None,
                dynamic_args: None,
            }),
            protected_corpus: None,
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
            protected_corpus: None,
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

    #[test]
    fn require_dcg_defaults_off_and_can_be_enabled_in_config() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let defaults = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            None,
            PartialConfig::default(),
        )
        .unwrap();
        assert!(!defaults.policy.require_dcg);

        let strict = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            Some("[policy]\nrequire_dcg = true\n"),
            PartialConfig::default(),
        )
        .unwrap();
        assert!(strict.policy.require_dcg);
    }

    #[test]
    fn dynamic_args_denies_by_default_and_layers_system_user_project_env() {
        // Fresh directories for every load: a load with only a system file
        // migrates it into the user's config path, which a later load in the
        // same home would then prefer.
        let load = |system: Option<&str>,
                    user: Option<&str>,
                    project: Option<&str>,
                    env: PartialConfig| {
            let repo_root = unique_temp_root("repo");
            let home = unique_temp_root("home");
            load_for_test(&repo_root, &home, system, user, project, env).unwrap()
        };
        let toml = |mode: &str| format!("[policy]\ndynamic_args = \"{mode}\"\n");
        let from_env = |mode: DynamicArgsMode| PartialConfig {
            policy: Some(PartialPolicyConfig {
                dynamic_args: Some(mode),
                ..PartialPolicyConfig::default()
            }),
            ..PartialConfig::default()
        };

        let none = PartialConfig::default;
        assert_eq!(
            load(None, None, None, none()).policy.dynamic_args,
            DynamicArgsMode::Deny
        );
        assert_eq!(
            load(Some(&toml("warn")), None, None, none())
                .policy
                .dynamic_args,
            DynamicArgsMode::Warn
        );
        assert_eq!(
            load(Some(&toml("warn")), Some(&toml("allow")), None, none())
                .policy
                .dynamic_args,
            DynamicArgsMode::Allow
        );
        assert_eq!(
            load(
                Some(&toml("warn")),
                Some(&toml("allow")),
                Some(&toml("deny")),
                none()
            )
            .policy
            .dynamic_args,
            DynamicArgsMode::Deny
        );
        assert_eq!(
            load(
                None,
                None,
                Some(&toml("deny")),
                from_env(DynamicArgsMode::Warn)
            )
            .policy
            .dynamic_args,
            DynamicArgsMode::Warn
        );
        // a layer that sets another key leaves the mode alone
        assert_eq!(
            load(
                Some(&toml("allow")),
                None,
                Some("[policy]\nrequire_dcg = true\n"),
                none()
            )
            .policy
            .dynamic_args,
            DynamicArgsMode::Allow
        );
    }

    #[test]
    fn dynamic_args_rejects_values_it_does_not_know() {
        let repo_root = unique_temp_root("repo");
        let home = unique_temp_root("home");

        let error = load_for_test(
            &repo_root,
            &home,
            None,
            None,
            Some("[policy]\ndynamic_args = \"off\"\n"),
            PartialConfig::default(),
        )
        .expect_err("`off` is not a mode");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("dynamic_args"), "{error}");

        for (raw, expected) in [
            ("deny", DynamicArgsMode::Deny),
            (" WARN ", DynamicArgsMode::Warn),
            ("Allow", DynamicArgsMode::Allow),
        ] {
            assert_eq!(parse_dynamic_args_mode(raw).unwrap(), expected);
        }
        let error = parse_dynamic_args_mode("log").expect_err("`log` is a policy mode only");
        assert!(error.to_string().contains("VEIL_DYNAMIC_ARGS"), "{error}");
    }

    #[test]
    fn default_policy_authorizes_all_thirteen_spine_tools_and_still_blocks_raw_reads() {
        use crate::evaluator::{EvaluationInput, evaluate_access};
        use crate::extract::PathExposure;
        use crate::packs::PackRegistry;
        use crate::spine::detect_spine_invocation;
        use crate::types::{DecisionAction, ToolKind};

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
        let registry = PackRegistry::with_built_ins();
        let protected = home.join(".cmdrvl/secrets/holdings.csv");
        let protected_arg = protected.display().to_string();

        for tool in [
            "shape",
            "rvl",
            "vacuum",
            "hashbytes",
            "fingerprint",
            "profile",
            "canon",
            "lock",
            "pack",
            "verify",
            "assess",
            "benchmark",
            "airlock",
        ] {
            let command = format!("{tool} {protected_arg}");
            let detected = detect_spine_invocation(
                &command,
                &config.spine.authorized_tools,
                &config.spine.denied_flags,
                &repo_root,
            );
            assert!(
                detected.is_some(),
                "default config should authorize `{tool}`"
            );
            let invocation = detected.unwrap();
            let input = EvaluationInput::new(
                ToolKind::Bash,
                invocation.target_path.clone(),
                PathExposure::ReadsContents,
            )
            .with_spine_invocation(invocation);
            let decision = evaluate_access(&input, &config, &registry);
            assert_eq!(
                decision.action,
                DecisionAction::Allow,
                "`{tool}` must be allowed on a protected path: {:?}",
                decision.reason
            );
        }

        // Planted negatives: raw readers and unlisted tools are not authorized.
        for command in [
            format!("cat {protected_arg}"),
            format!("head {protected_arg}"),
            format!("not-a-spine-tool {protected_arg}"),
            format!("verifyx {protected_arg}"),
        ] {
            assert!(
                detect_spine_invocation(
                    &command,
                    &config.spine.authorized_tools,
                    &config.spine.denied_flags,
                    &repo_root
                )
                .is_none(),
                "`{command}` must not be treated as an authorized spine invocation"
            );
        }

        for tool in [ToolKind::Read, ToolKind::Grep, ToolKind::Bash] {
            let input = EvaluationInput::new(tool, protected.clone(), PathExposure::ReadsContents);
            let decision = evaluate_access(&input, &config, &registry);
            assert_eq!(
                decision.action,
                DecisionAction::Deny,
                "raw {tool:?} of a protected path must stay blocked"
            );
        }
    }
}
