//! macOS Seatbelt profile compiler.
//!
//! Seatbelt has path rules rather than a glob rule. Exact paths and whole
//! protected directory roots become literal/subpath denies. Other globs are
//! expanded against the filesystem at compile time under a fixed entry budget;
//! a new file matching one of those patterns needs the profile to be compiled
//! again. Symlink spellings and resolved targets are both denied.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::allowlist::SafePathMatcher;
use crate::config::Config;

/// Maximum number of filesystem entries examined while expanding one policy.
pub const MAX_GLOB_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledProfile {
    /// The profile text accepted by `/usr/bin/sandbox-exec`.
    pub profile: String,
    /// Limits callers should show before someone relies on the profile.
    pub warnings: Vec<String>,
    /// Number of distinct path-deny rules emitted (the `file-link` rule is not
    /// included).
    pub path_rules: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuleKind {
    Literal,
    Subpath,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DenyRule {
    path: PathBuf,
    kind: RuleKind,
}

/// Compile `[sensitivity].protected` from the already-merged configuration.
/// Relative patterns are resolved against `project_root`, matching the
/// workspace a sandbox invocation is about to launch. This deliberately
/// treats a relative pattern as workspace-scoped even though hook matching
/// also recognizes matching suffixes outside the workspace.
pub fn compile(config: &Config, project_root: &Path) -> io::Result<CompiledProfile> {
    compile_with_limit(config, project_root, MAX_GLOB_ENTRIES)
}

fn compile_with_limit(
    config: &Config,
    project_root: &Path,
    max_entries: usize,
) -> io::Result<CompiledProfile> {
    let project_root = absolute_path(project_root, Path::new("/"))?;
    let mut rules = BTreeSet::new();
    let mut warnings = vec![
        "(deny file-link) prevents the confined process from creating new hard links; it does not block reads through hard-link aliases created before confinement.".to_owned(),
        "This profile compiles configured [sensitivity].protected paths; hook-only built-in path classifiers are not expanded into Seatbelt rules.".to_owned(),
        "This compiler adds filesystem read denials only; it does not restrict network access or revoke read-capable file descriptors opened before confinement.".to_owned(),
        "sandbox-exec is deprecated; availability and profile behavior must be checked on each supported macOS release.".to_owned(),
        format!(
            "Relative [sensitivity].protected patterns are rooted at the sandbox project directory {}; matching suffixes outside that directory are not covered.",
            project_root.display()
        ),
    ];
    let mut entries = 0usize;

    for raw in &config.sensitivity.protected {
        let pattern = resolve_pattern(raw, &project_root)?;

        if let Some(root) = subpath_pattern_root(&pattern) {
            add_path(&root, true, &mut rules)?;
            continue;
        }

        if !pattern.to_string_lossy().contains('*') {
            add_path(&pattern, false, &mut rules)?;
            continue;
        }

        warnings.push(format!(
            "glob `{raw}` was expanded from its current filesystem matches; newly matching paths are not covered until this profile is recompiled."
        ));
        let matcher_pattern = pattern
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected glob is not valid UTF-8 and cannot be matched",
                )
            })?
            .trim_start_matches('/');
        let matcher = SafePathMatcher::from_patterns([matcher_pattern]);
        expand_glob(
            &matcher,
            &pattern,
            &project_root,
            max_entries,
            &mut entries,
            &mut rules,
        )?;
    }

    let path_rules = rules.len();
    let mut profile = String::from("(version 1)\n(allow default)\n(deny file-link)\n");
    for rule in rules {
        let path = seatbelt_string(&rule.path)?;
        match rule.kind {
            RuleKind::Literal => {
                profile.push_str(&format!("(deny file-read* (literal \"{path}\"))\n"))
            }
            RuleKind::Subpath => {
                profile.push_str(&format!("(deny file-read* (subpath \"{path}\"))\n"))
            }
        }
    }

    Ok(CompiledProfile {
        profile,
        warnings,
        path_rules,
    })
}

fn expand_glob(
    matcher: &SafePathMatcher,
    pattern: &Path,
    project_root: &Path,
    max_entries: usize,
    entries_seen: &mut usize,
    rules: &mut BTreeSet<DenyRule>,
) -> io::Result<()> {
    let anchor = glob_anchor(pattern, project_root);
    if !anchor.exists() {
        return Ok(());
    }

    let mut pending = VecDeque::from([anchor]);
    let mut visited = HashSet::new();
    while let Some(directory) = pending.pop_front() {
        let directory = absolute_path(&directory, project_root)?;
        let visit_key = fs::canonicalize(&directory).unwrap_or_else(|_| directory.clone());
        if !visited.insert(visit_key) {
            continue;
        }

        if matcher.covers_directory(&directory) {
            add_path(&directory, true, rules)?;
            continue;
        }

        let contents = fs::read_dir(&directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot expand protected glob beneath {}: {error}",
                    directory.display()
                ),
            )
        })?;

        for entry in contents {
            let entry = entry?;
            *entries_seen = entries_seen.saturating_add(1);
            if *entries_seen > max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "protected glob expansion exceeded the {max_entries}-entry limit; refusing an incomplete Seatbelt profile"
                    ),
                ));
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let target = fs::canonicalize(&path).ok();
            let target_metadata = target
                .as_deref()
                .and_then(|target| fs::metadata(target).ok());

            if matcher.is_safe(&path) {
                add_path(&path, metadata.is_dir(), rules)?;
            }
            if let (Some(target), Some(metadata)) = (target.as_deref(), target_metadata.as_ref())
                && (matcher.is_safe(target)
                    || (metadata.is_dir() && matcher.covers_directory(target)))
            {
                add_path(&path, metadata.is_dir(), rules)?;
                add_path(target, metadata.is_dir(), rules)?;
            }

            if metadata.is_dir() {
                pending.push_back(path);
            } else if metadata.file_type().is_symlink()
                && target_metadata
                    .as_ref()
                    .is_some_and(|target| target.is_dir())
                && let Some(target) = target
            {
                // Keep the alias path while walking so a glob rooted beneath
                // the alias matches its children. Canonical targets are used
                // for cycle detection and are added to the deny rules too.
                if matcher.is_safe(&path)
                    || matcher.covers_directory(&path)
                    || matcher.covers_directory(&target)
                {
                    add_path(&path, true, rules)?;
                    add_path(&target, true, rules)?;
                } else {
                    pending.push_back(path);
                }
            }
        }
    }

    Ok(())
}

fn glob_anchor(pattern: &Path, project_root: &Path) -> PathBuf {
    let mut prefix = PathBuf::new();
    for component in pattern.components() {
        if component.as_os_str().to_string_lossy().contains('*') {
            break;
        }
        prefix.push(component.as_os_str());
    }

    if prefix.as_os_str().is_empty() {
        return project_root.to_path_buf();
    }
    if prefix.is_dir() {
        prefix
    } else {
        prefix
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(project_root)
            .to_path_buf()
    }
}

fn subpath_pattern_root(pattern: &Path) -> Option<PathBuf> {
    let text = pattern.to_str()?;
    let root = text.strip_suffix("/**")?;
    if root.contains('*') {
        return None;
    }
    Some(PathBuf::from(root))
}

pub(super) fn resolve_pattern(pattern: &str, project_root: &Path) -> io::Result<PathBuf> {
    let home_suffix = pattern
        .strip_prefix('~')
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'));
    let expanded = if let Some(suffix) = home_suffix {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot resolve protected pattern `{pattern}` without HOME"),
            ));
        };
        home.join(suffix.strip_prefix('/').unwrap_or(suffix))
    } else {
        PathBuf::from(pattern)
    };
    absolute_path(&expanded, project_root)
}

fn absolute_path(path: &Path, base: &Path) -> io::Result<PathBuf> {
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
            format!("sandbox path is not absolute: {}", path.display()),
        ));
    }
    Ok(normalized)
}

fn add_path(path: &Path, directory_hint: bool, rules: &mut BTreeSet<DenyRule>) -> io::Result<()> {
    let path = absolute_path(path, Path::new("/"))?;
    let metadata = fs::metadata(&path).ok();
    let kind = if directory_hint || metadata.as_ref().is_some_and(fs::Metadata::is_dir) {
        RuleKind::Subpath
    } else {
        RuleKind::Literal
    };
    add_rule(path.clone(), kind, rules)?;

    if let Ok(target) = fs::canonicalize(&path)
        && target != path
    {
        let target_kind = if fs::metadata(&target).is_ok_and(|metadata| metadata.is_dir()) {
            RuleKind::Subpath
        } else {
            RuleKind::Literal
        };
        add_rule(target, target_kind, rules)?;
    }

    Ok(())
}

fn add_rule(path: PathBuf, kind: RuleKind, rules: &mut BTreeSet<DenyRule>) -> io::Result<()> {
    if path.to_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path is not valid UTF-8 and cannot be encoded in a Seatbelt profile",
        ));
    }
    rules.insert(DenyRule { path, kind });
    Ok(())
}

/// A profile under which a process can write no file. The broker runs each tool
/// under it, so no flag or subcommand of a tool (`--output`, a copy into an
/// evidence pack, a sliced CSV) can put unscanned bytes where the confined
/// client reads them.
pub const NO_FILE_WRITES_PROFILE: &str = "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (literal \"/dev/null\"))\n";

/// Rules, to append to a compiled profile, that keep the confined process from
/// changing `files` or anything under `subtrees`. No directory above one of
/// them may be renamed or removed, which would let another take its place.
/// Paths must be absolute with symlinked directories resolved, as Seatbelt
/// compares them.
pub fn write_denials(files: &[PathBuf], subtrees: &[PathBuf]) -> io::Result<String> {
    let mut rules = BTreeSet::new();
    let targets = files
        .iter()
        .map(|path| ("literal", path))
        .chain(subtrees.iter().map(|path| ("subpath", path)));

    for (kind, path) in targets {
        rules.insert(format!(
            "(deny file-write* ({kind} \"{}\"))\n",
            seatbelt_string(path)?
        ));
        for ancestor in path.ancestors().skip(1) {
            if ancestor.parent().is_some() {
                rules.insert(format!(
                    "(deny file-write-unlink (literal \"{}\"))\n",
                    seatbelt_string(ancestor)?
                ));
            }
        }
    }

    Ok(rules.into_iter().collect())
}

fn seatbelt_string(path: &Path) -> io::Result<String> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path is not valid UTF-8 and cannot be encoded in a Seatbelt profile",
        )
    })?;
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "protected path contains a control character: {}",
                path.display()
            ),
        ));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
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
            "veil-seatbelt-profile-{}-{time}-{count}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture root");
        path
    }

    fn config(protected: Vec<PathBuf>) -> Config {
        Config {
            sensitivity: SensitivityConfig {
                protected: protected
                    .into_iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
            },
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
                audit_path: PathBuf::from("/tmp/veil-seatbelt-test-audit.jsonl"),
                audit_inputs: false,
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
            mcp: McpConfig::default(),
        }
    }

    #[test]
    fn exact_files_and_directory_roots_become_different_deny_rules() {
        let root = temp_dir();
        let directory = root.join("data");
        fs::create_dir_all(&directory).expect("protected directory");
        let file = root.join("one.csv");
        fs::write(&file, "secret\n").expect("protected file");

        let profile =
            compile(&config(vec![directory.join("**"), file.clone()]), &root).expect("profile");

        assert!(profile.profile.contains(&format!(
            "(deny file-read* (subpath \"{}\"))",
            directory.display()
        )));
        assert!(profile.profile.contains(&format!(
            "(deny file-read* (literal \"{}\"))",
            file.display()
        )));
        assert!(profile.profile.contains("(deny file-link)"));
        assert!(profile.path_rules >= 2);
    }

    #[test]
    fn a_symlink_to_a_protected_file_and_its_target_are_both_denied() {
        let root = temp_dir();
        let protected = root.join("data/secret.csv");
        fs::create_dir_all(protected.parent().expect("parent")).expect("protected dir");
        fs::write(&protected, "sensitive\n").expect("protected file");
        let alias = root.join("outside-link.csv");
        std::os::unix::fs::symlink(&protected, &alias).expect("symlink alias");

        let profile = compile(&config(vec![alias.clone()]), &root).expect("profile");

        let resolved = fs::canonicalize(&protected).expect("resolved protected target");
        for path in [&resolved, &alias] {
            assert!(profile.profile.contains(&format!(
                "(deny file-read* (literal \"{}\"))",
                path.display()
            )));
        }
    }

    #[test]
    fn a_glob_is_expanded_and_warns_that_new_matches_need_recompilation() {
        let root = temp_dir();
        let directory = root.join("reports");
        fs::create_dir_all(&directory).expect("report directory");
        let protected = directory.join("secret.csv");
        fs::write(&protected, "sensitive\n").expect("protected file");
        let pattern = PathBuf::from("**/secret.csv");

        let profile = compile(&config(vec![pattern]), &root).expect("profile");

        assert!(profile.profile.contains(&format!(
            "(deny file-read* (literal \"{}\"))",
            protected.display()
        )));
        assert!(
            profile
                .warnings
                .iter()
                .any(|warning| warning.contains("newly matching paths"))
        );
    }

    #[test]
    fn an_incomplete_glob_expansion_fails_closed() {
        let root = temp_dir();
        fs::write(root.join("one.csv"), "sensitive\n").expect("protected file");

        let error = compile_with_limit(&config(vec![root.join("*.csv")]), &root, 0)
            .expect_err("a zero-entry budget cannot prove a complete profile");

        assert!(error.to_string().contains("refusing an incomplete"));
    }
}
