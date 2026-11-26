//! Conservative Landlock filesystem ruleset compiler.
//!
//! Landlock only grants access beneath allowed hierarchies. It cannot allow a
//! broad parent and subtract one protected child, so this compiler omits an
//! entire top-level hierarchy whenever a configured protected pattern could
//! match anywhere beneath it. The result is safe but can make a normal
//! workspace unreadable. This module compiles rules. A Linux integration test
//! applies the compiled paths to a real kernel ruleset and verifies an allowed
//! and excluded read. Hook-time application remains launcher work.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::config::Config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadHierarchy {
    pub path: PathBuf,
    pub read_file: bool,
    pub read_dir: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRuleset {
    /// The top-level paths that receive read_file and read_dir rights.
    pub allowed: Vec<ReadHierarchy>,
    /// Top-level paths omitted because they contain or may contain a protected
    /// path. Excluding a parent also excludes its unprotected descendants.
    pub excluded: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

/// Compile a conservative read allowlist over the immediate children of
/// `filesystem_root`. `project_root` anchors relative config patterns.
pub fn compile(
    config: &Config,
    project_root: &Path,
    filesystem_root: &Path,
) -> io::Result<CompiledRuleset> {
    let project_root = normalize_absolute(project_root, Path::new("/"))?;
    let filesystem_root = normalize_absolute(filesystem_root, Path::new("/"))?;
    let mut protected_prefixes = Vec::with_capacity(config.sensitivity.protected.len());
    for pattern in &config.sensitivity.protected {
        let pattern = super::seatbelt::resolve_pattern(pattern, &project_root)?;
        protected_prefixes.push(static_prefix(&pattern));
    }

    let mut allowed = Vec::new();
    let mut excluded = BTreeSet::new();
    for entry in fs::read_dir(&filesystem_root)? {
        let entry = entry?;
        let path = normalize_absolute(&entry.path(), &filesystem_root)?;
        let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let denied = protected_prefixes.iter().any(|prefix| {
            path.starts_with(prefix)
                || prefix.starts_with(&path)
                || canonical.starts_with(prefix)
                || prefix.starts_with(&canonical)
        });

        if denied {
            excluded.insert(path);
            if canonical != entry.path() {
                excluded.insert(canonical);
            }
            continue;
        }

        let metadata = fs::metadata(&path)?;
        allowed.push(ReadHierarchy {
            path: canonical,
            read_file: true,
            read_dir: metadata.is_dir(),
        });
    }

    allowed.sort_by(|left, right| left.path.cmp(&right.path));
    let excluded: Vec<_> = excluded.into_iter().collect();
    let warnings = vec![
        "Landlock grants read access only beneath the listed top-level paths; any top-level path containing a protected pattern is excluded in full.".to_owned(),
        "This is a compiled ruleset plan only. Landlock application and kernel enforcement have not been verified on this host.".to_owned(),
    ];

    Ok(CompiledRuleset {
        allowed,
        excluded,
        warnings,
    })
}

fn static_prefix(pattern: &Path) -> PathBuf {
    let mut prefix = PathBuf::new();
    for component in pattern.components() {
        if component.as_os_str().to_string_lossy().contains('*') {
            break;
        }
        prefix.push(component.as_os_str());
    }
    prefix
}

fn normalize_absolute(path: &Path, base: &Path) -> io::Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Landlock hierarchy is not absolute: {}", path.display()),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AllowlistConfig, Config, DynamicArgsMode, McpConfig, PolicyConfig, PolicyMode,
        SensitivityConfig, SpineConfig,
    };
    use crate::protected_corpus::CorpusLimits;
    use crate::spine::DeniedFlags;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "veil-landlock-plan-{}-{time}-{count}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture root");
        path
    }

    fn config(protected: Vec<String>) -> Config {
        Config {
            sensitivity: SensitivityConfig { protected },
            allowlist: AllowlistConfig {
                safe_patterns: Vec::new(),
            },
            spine: SpineConfig {
                authorized_tools: Vec::new(),
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                egress: Some(PolicyMode::Warn),
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-landlock-test-audit.jsonl"),
                audit_inputs: false,
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
            mcp: McpConfig::default(),
        }
    }

    #[test]
    fn an_ancestor_hierarchy_is_excluded_instead_of_allowing_a_protected_child() {
        let fixture = temp_dir();
        let filesystem_root = fixture.join("filesystem");
        let workspace = filesystem_root.join("Users/agent/work");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(filesystem_root.join("bin")).expect("bin");

        let policy = config(vec![
            filesystem_root
                .join("Users/agent/work/data/**")
                .display()
                .to_string(),
        ]);
        let rules = compile(&policy, &workspace, &filesystem_root).expect("ruleset");

        assert_eq!(rules.allowed.len(), 1, "{rules:?}");
        assert_eq!(
            rules.allowed[0].path,
            fs::canonicalize(filesystem_root.join("bin")).expect("canonical bin")
        );
        assert!(rules.allowed[0].read_file && rules.allowed[0].read_dir);
        let users = filesystem_root.join("Users");
        let canonical_users = fs::canonicalize(&users).expect("canonical Users");
        let expected_excluded: Vec<_> = [users, canonical_users]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(rules.excluded, expected_excluded);
        assert!(
            rules
                .warnings
                .iter()
                .any(|warning| warning.contains("top-level"))
        );
    }
}
