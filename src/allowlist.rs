#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A file name no real pattern is expected to name. Joined under a directory,
/// it asks whether the directory itself is covered by a `dir/**` pattern.
const DIRECTORY_PROBE: &str = ".veil-directory-probe";

pub const DEFAULT_SAFE_PATTERNS: &[&str] = &[
    "*.md",
    "*.toml",
    "*.lock",
    "docs/**",
    "tests/**",
    ".github/**",
    "*-report.json",
    "*-report.yaml",
    "package.json",
    "tsconfig.json",
    "Cargo.toml",
    "Cargo.lock",
];

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompiledPattern {
    ExactName(String),
    ExactPath(Vec<String>),
    Directory(Vec<String>),
    BasenameGlob(String),
    PathGlob(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafePathMatcher {
    patterns: Vec<CompiledPattern>,
}

impl Default for SafePathMatcher {
    fn default() -> Self {
        Self::from_patterns(DEFAULT_SAFE_PATTERNS.iter().copied())
    }
}

impl SafePathMatcher {
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = patterns
            .into_iter()
            .map(|pattern| CompiledPattern::compile(pattern.as_ref()))
            .collect();

        Self { patterns }
    }

    pub fn is_safe<P>(&self, path: P) -> bool
    where
        P: AsRef<Path>,
    {
        let normalized = NormalizedPath::from_path(path.as_ref());
        self.patterns
            .iter()
            .any(|pattern| pattern.matches(&normalized))
    }

    /// Looks for a path that these patterns cover at or beneath `directory`,
    /// the question a recursive content search has to answer before it runs.
    ///
    /// `dir/**` patterns match descendants only, so a directory is covered
    /// when a file placed directly in it would match; that is how the walk
    /// recognises a protected root, including `directory` itself. Entries are
    /// visited breadth first, so a protected root near the top is found before
    /// a deep tree spends the budget. Symlinks are not followed, as in
    /// `grep -r` and `rg`; a symlink counts as covered when its target is, so
    /// `grep -R` and `rg -L` are covered too. Directories that cannot be read
    /// are skipped: the search that follows could not read them either.
    ///
    /// `max_entries` bounds the work. When it is spent the answer is
    /// `Unverified`, never `Clear`: running out of budget is not evidence that
    /// nothing protected is there.
    pub fn scan_directory(&self, directory: &Path, max_entries: usize) -> DirectoryScan {
        if self.patterns.is_empty() {
            return DirectoryScan::Clear;
        }

        // A file under a `dir/**` root is found when its directory is probed,
        // which happens before its entries are read. Files therefore only
        // need the other pattern kinds, and most configs have none, which
        // keeps the walk to a directory read per directory.
        let file_patterns = self
            .patterns
            .iter()
            .any(|pattern| !matches!(pattern, CompiledPattern::Directory(_)));
        let mut pending = VecDeque::from([directory.to_path_buf()]);
        let mut inspected = 0usize;

        while let Some(current) = pending.pop_front() {
            if self.is_safe(current.join(DIRECTORY_PROBE)) {
                return DirectoryScan::Protected(current);
            }

            let Ok(entries) = fs::read_dir(&current) else {
                continue;
            };

            for entry in entries.flatten() {
                inspected += 1;
                if inspected > max_entries {
                    return DirectoryScan::Unverified { max_entries };
                }

                let Ok(kind) = entry.file_type() else {
                    continue;
                };

                if kind.is_dir() {
                    pending.push_back(entry.path());
                } else if file_patterns || kind.is_symlink() {
                    let path = entry.path();
                    if (file_patterns && self.matches_file_pattern(&path))
                        || (kind.is_symlink() && self.covers_target(&path))
                    {
                        return DirectoryScan::Protected(path);
                    }
                }
            }
        }

        DirectoryScan::Clear
    }

    /// Whether a pattern other than `dir/**` covers `path`.
    fn matches_file_pattern(&self, path: &Path) -> bool {
        let normalized = NormalizedPath::from_path(path);
        self.patterns.iter().any(|pattern| {
            !matches!(pattern, CompiledPattern::Directory(_)) && pattern.matches(&normalized)
        })
    }

    fn covers_target(&self, link: &Path) -> bool {
        let Ok(target) = fs::canonicalize(link) else {
            return false;
        };

        if target.is_dir() {
            self.is_safe(target.join(DIRECTORY_PROBE))
        } else {
            self.is_safe(&target)
        }
    }
}

/// What `SafePathMatcher::scan_directory` established about a directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryScan {
    /// This path, at or beneath the directory, is covered by a pattern.
    Protected(PathBuf),
    /// Every entry was inspected and none is covered.
    Clear,
    /// The directory holds more entries than the budget allows inspecting.
    Unverified { max_entries: usize },
}

impl CompiledPattern {
    fn compile(pattern: &str) -> Self {
        if let Some(directory) = pattern.strip_suffix("/**") {
            return Self::Directory(normalize_pattern_components(directory));
        }

        if pattern.contains('*') {
            if pattern.contains('/') {
                return Self::PathGlob(pattern.to_owned());
            }

            return Self::BasenameGlob(pattern.to_owned());
        }

        if pattern.contains('/') {
            return Self::ExactPath(normalize_pattern_components(pattern));
        }

        Self::ExactName(pattern.to_owned())
    }

    fn matches(&self, path: &NormalizedPath) -> bool {
        match self {
            Self::ExactName(name) => path.basename().is_some_and(|value| value == name),
            Self::ExactPath(components) => path.ends_with(components),
            Self::Directory(components) => path.contains_directory(components),
            Self::BasenameGlob(pattern) => path
                .basename()
                .is_some_and(|value| wildcard_matches(pattern, value)),
            Self::PathGlob(pattern) => wildcard_matches(pattern, &path.full_path),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedPath {
    components: Vec<String>,
    full_path: String,
}

impl NormalizedPath {
    fn from_path(path: &Path) -> Self {
        let components = path
            .components()
            .filter_map(|component| match component {
                Component::Prefix(prefix) => {
                    Some(prefix.as_os_str().to_string_lossy().into_owned())
                }
                Component::RootDir | Component::CurDir => None,
                Component::ParentDir => Some("..".to_owned()),
                Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            })
            .collect::<Vec<_>>();
        let full_path = components.join("/");

        Self {
            components,
            full_path,
        }
    }

    fn basename(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    fn ends_with(&self, suffix: &[String]) -> bool {
        self.components.ends_with(suffix)
    }

    fn contains_directory(&self, directory: &[String]) -> bool {
        if directory.is_empty() || self.components.len() <= directory.len() {
            return false;
        }

        self.components
            .windows(directory.len())
            .enumerate()
            .any(|(index, window)| {
                window == directory && index + directory.len() < self.components.len()
            })
    }
}

fn normalize_pattern_components(pattern: &str) -> Vec<String> {
    Path::new(pattern)
        .components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(prefix.as_os_str().to_string_lossy().into_owned()),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some("..".to_owned()),
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
        })
        .collect()
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    wildcard_matches_bytes(pattern.as_bytes(), candidate.as_bytes())
}

fn wildcard_matches_bytes(pattern: &[u8], candidate: &[u8]) -> bool {
    if pattern.is_empty() {
        return candidate.is_empty();
    }

    if pattern.starts_with(b"**") {
        let rest = &pattern[2..];

        if rest.is_empty() {
            return true;
        }

        return (0..=candidate.len())
            .any(|index| wildcard_matches_bytes(rest, &candidate[index..]));
    }

    if pattern[0] == b'*' {
        let rest = &pattern[1..];
        let max = candidate
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(candidate.len());

        return (0..=max).any(|index| wildcard_matches_bytes(rest, &candidate[index..]));
    }

    match candidate.split_first() {
        Some((first, tail)) if *first == pattern[0] => wildcard_matches_bytes(&pattern[1..], tail),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "veil-scan-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        fs::canonicalize(&dir).expect("temp dir should canonicalize")
    }

    fn put(root: &Path, relative: &str) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("file has a parent")).expect("parent dir");
        fs::write(&path, "row\n").expect("file should be written");
        path
    }

    fn matcher(patterns: &[&str]) -> SafePathMatcher {
        SafePathMatcher::from_patterns(patterns.iter())
    }

    #[test]
    fn finds_a_protected_directory_below_the_start() {
        let root = unique_dir("below");
        put(&root, "data/clients/holdings.csv");
        put(&root, "src/main.rs");

        let scan = matcher(&["data/**"]).scan_directory(&root, 1_000);

        assert_eq!(scan, DirectoryScan::Protected(root.join("data")));
    }

    #[test]
    fn the_start_directory_is_found_when_it_is_the_protected_root() {
        let root = unique_dir("self");
        put(&root, "data/a.csv");

        // `data/**` matches descendants of data, not data itself, so only the
        // probe recognises this directory as the protected root.
        assert!(!matcher(&["data/**"]).is_safe(root.join("data")));
        let scan = matcher(&["data/**"]).scan_directory(&root.join("data"), 1_000);

        assert_eq!(scan, DirectoryScan::Protected(root.join("data")));
    }

    #[test]
    fn a_directory_beneath_a_protected_root_is_found_at_the_start() {
        let root = unique_dir("inside");
        put(&root, "data/clients/2024/a.csv");

        let scan = matcher(&["data/**"]).scan_directory(&root.join("data/clients"), 1_000);

        assert_eq!(scan, DirectoryScan::Protected(root.join("data/clients")));
    }

    #[test]
    fn a_tree_with_nothing_protected_is_clear() {
        let root = unique_dir("clear");
        put(&root, "src/main.rs");
        put(&root, "docs/data.md");
        put(&root, "database/rows.sql");

        let scan = matcher(&["data/**", "secrets/**"]).scan_directory(&root, 1_000);

        assert_eq!(scan, DirectoryScan::Clear);
    }

    #[test]
    fn multi_component_roots_need_every_component() {
        let root = unique_dir("multi");
        put(&root, "clients/public/a.csv");
        let pattern = matcher(&["clients/private/**"]);

        assert_eq!(pattern.scan_directory(&root, 1_000), DirectoryScan::Clear);

        put(&root, "clients/private/b.csv");
        assert_eq!(
            pattern.scan_directory(&root, 1_000),
            DirectoryScan::Protected(root.join("clients/private"))
        );
    }

    #[test]
    fn file_patterns_are_found_deep_in_the_tree() {
        let root = unique_dir("files");
        put(&root, "a/b/c/notes.txt");
        let secret = put(&root, "a/b/c/holdings.secret");

        let scan = matcher(&["*.secret"]).scan_directory(&root, 1_000);

        assert_eq!(scan, DirectoryScan::Protected(secret));
    }

    #[test]
    fn root_and_file_patterns_together_each_find_their_own_kind() {
        let pattern = matcher(&["data/**", "*.secret"]);

        let only_root = unique_dir("mixed-root");
        put(&only_root, "data/plain.txt");
        put(&only_root, "src/main.rs");
        assert_eq!(
            pattern.scan_directory(&only_root, 1_000),
            DirectoryScan::Protected(only_root.join("data"))
        );

        let only_file = unique_dir("mixed-file");
        let secret = put(&only_file, "src/deep/holdings.secret");
        put(&only_file, "src/main.rs");
        assert_eq!(
            pattern.scan_directory(&only_file, 1_000),
            DirectoryScan::Protected(secret)
        );

        let neither = unique_dir("mixed-neither");
        put(&neither, "src/main.rs");
        assert_eq!(
            pattern.scan_directory(&neither, 1_000),
            DirectoryScan::Clear
        );
    }

    #[test]
    fn an_empty_pattern_list_never_touches_the_filesystem() {
        let missing = unique_dir("missing").join("nope");

        assert_eq!(
            matcher(&[]).scan_directory(&missing, 0),
            DirectoryScan::Clear
        );
    }

    #[test]
    fn a_missing_start_directory_is_clear_because_nothing_can_be_read_there() {
        let missing = unique_dir("gone").join("nope");

        assert_eq!(
            matcher(&["data/**"]).scan_directory(&missing, 1_000),
            DirectoryScan::Clear
        );
    }

    #[test]
    fn an_exhausted_budget_is_unverified_not_clear() {
        let root = unique_dir("budget");
        for index in 0..20 {
            put(&root, &format!("src/f{index}.rs"));
        }
        let pattern = matcher(&["data/**"]);

        // The tree holds 21 entries: the src directory and its 20 files.
        assert_eq!(
            pattern.scan_directory(&root, 5),
            DirectoryScan::Unverified { max_entries: 5 }
        );
        assert_eq!(
            pattern.scan_directory(&root, 20),
            DirectoryScan::Unverified { max_entries: 20 }
        );
        assert_eq!(pattern.scan_directory(&root, 21), DirectoryScan::Clear);
    }

    #[test]
    fn a_protected_root_near_the_top_is_found_before_a_deep_tree_spends_the_budget() {
        let root = unique_dir("breadth");
        put(&root, "data/a.csv");
        for index in 0..40 {
            put(&root, &format!("aaa/deep/f{index}.rs"));
        }

        let scan = matcher(&["data/**"]).scan_directory(&root, 10);

        assert_eq!(scan, DirectoryScan::Protected(root.join("data")));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_count_when_their_target_is_protected_but_are_not_followed() {
        use std::os::unix::fs::symlink;

        let root = unique_dir("links");
        let protected_file = put(&root, "data/a.csv");
        let protected_dir = root.join("data");
        let links = root.join("links");
        fs::create_dir_all(&links).expect("links dir");
        let pattern = matcher(&["data/**"]);

        let to_file = links.join("to-file");
        symlink(&protected_file, &to_file).expect("symlink to file");
        assert_eq!(
            pattern.scan_directory(&links, 1_000),
            DirectoryScan::Protected(to_file.clone())
        );
        fs::remove_file(&to_file).expect("remove own symlink");

        let to_dir = links.join("to-dir");
        symlink(&protected_dir, &to_dir).expect("symlink to dir");
        assert_eq!(
            pattern.scan_directory(&links, 1_000),
            DirectoryScan::Protected(to_dir.clone())
        );
        fs::remove_file(&to_dir).expect("remove own symlink");

        // A link to an unprotected tree is clear and is not descended into,
        // even though protected data sits below it, as with grep -r and rg.
        let outside = unique_dir("links-out");
        put(&outside, "inner/data/secret.csv");
        symlink(&outside, links.join("to-outside")).expect("symlink out");
        assert_eq!(pattern.scan_directory(&links, 1_000), DirectoryScan::Clear);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directories_are_skipped() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("unreadable");
        put(&root, "src/main.rs");
        let hidden = root.join("hidden");
        put(&root, "hidden/data/a.csv");
        fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).expect("chmod own dir");

        let readable_anyway = fs::read_dir(&hidden).is_ok();
        let scan = matcher(&["data/**"]).scan_directory(&root, 1_000);
        fs::set_permissions(&hidden, fs::Permissions::from_mode(0o755)).expect("restore own dir");

        if readable_anyway {
            // A user the mode does not bind (root) reads it, so nothing is skipped.
            assert_eq!(scan, DirectoryScan::Protected(root.join("hidden/data")));
        } else {
            assert_eq!(scan, DirectoryScan::Clear);
        }
    }
}
