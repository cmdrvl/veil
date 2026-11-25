#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A file name no real pattern is expected to name. Joined under a directory,
/// it asks whether the directory itself is covered by a `dir/**` pattern.
pub const DIRECTORY_PROBE: &str = ".veil-directory-probe";

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
    /// The patterns as written. They define what a match is; `index` answers
    /// the same question without trying each one.
    patterns: Vec<CompiledPattern>,
    index: PatternIndex,
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
        let patterns: Vec<CompiledPattern> = patterns
            .into_iter()
            .map(|pattern| CompiledPattern::compile(pattern.as_ref()))
            .collect();
        let index = PatternIndex::build(&patterns);

        Self { patterns, index }
    }

    pub fn is_safe<P>(&self, path: P) -> bool
    where
        P: AsRef<Path>,
    {
        let normalized = NormalizedPath::from_path(path.as_ref());
        self.index.matches(&normalized, true)
    }

    /// Whether `directory` is itself covered, so that anything created in it
    /// would be: the working directory is inside a `dir/**` root.
    pub fn covers_directory(&self, directory: &Path) -> bool {
        self.is_safe(directory.join(DIRECTORY_PROBE))
    }

    /// `is_safe` by trying every pattern in turn: the definition the index must
    /// agree with.
    #[cfg(test)]
    fn is_safe_linear(&self, path: &Path) -> bool {
        let normalized = NormalizedPath::from_path(path);
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

        self.scan_directory_with(directory, max_entries, |_| false)
    }

    /// Like [`Self::scan_directory`], also treating any path matched by
    /// `is_sensitive` as protected. This lets callers add their file-level
    /// sensitivity classifiers without changing the glob walk or its budget.
    /// It still walks when no configured patterns exist, since the additional
    /// classifier may recognize paths independently of those patterns.
    pub fn scan_directory_with<F>(
        &self,
        directory: &Path,
        max_entries: usize,
        mut is_sensitive: F,
    ) -> DirectoryScan
    where
        F: FnMut(&Path) -> bool,
    {
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
            if self.is_safe(current.join(DIRECTORY_PROBE)) || is_sensitive(&current) {
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
                } else {
                    let path = entry.path();
                    let classified = is_sensitive(&path)
                        || (kind.is_symlink()
                            && fs::canonicalize(&path).is_ok_and(|target| is_sensitive(&target)));
                    let matched_pattern = file_patterns && self.matches_file_pattern(&path);
                    if matched_pattern
                        || classified
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
        self.index.matches(&normalized, false)
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

/// What a directory scan established about configured patterns or an extra classifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryScan {
    /// This path, at or beneath the directory, is covered by a pattern or classifier.
    Protected(PathBuf),
    /// Every entry was inspected and none is covered by a pattern or classifier.
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

    /// What it means for this one pattern to cover `path`. The index answers
    /// the same question for all patterns at once; this is the reference the
    /// differential test checks it against.
    #[cfg(test)]
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

/// The patterns of one matcher, arranged so that a lookup touches only the
/// patterns that could match instead of every one (bd-29r). Building it is
/// linear in the number of patterns; a lookup is linear in the depth of the
/// path, plus the few patterns that share its file name ending or a directory
/// name with it. It answers exactly what trying each pattern in order does: the
/// differential test in this module holds it to that.
///
/// - `names`: a pattern that is one file name (`.env`).
/// - `segments`: a trie of path components for patterns that name components
///   (`data/clients/x.csv`, which must end the path, and `data/**`, which may
///   sit anywhere in it).
/// - `globs`: patterns with a `*`, reached through a component they must
///   contain, a literal ending, a literal start, or, failing those, scanned.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PatternIndex {
    names: HashSet<String>,
    segments: Trie,
    globs: GlobIndex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Trie {
    /// Node 0 is the root.
    nodes: Vec<TrieNode>,
    /// A pattern with no components (`/`) ends every path.
    ends_every_path: bool,
}

impl Default for Trie {
    fn default() -> Self {
        Self {
            nodes: vec![TrieNode::default()],
            ends_every_path: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TrieNode {
    children: HashMap<String, usize>,
    /// An exact-path pattern ends here: the path must end with these components.
    exact_path: bool,
    /// A `dir/**` pattern ends here: these components must be followed by at
    /// least one more.
    directory: bool,
}

impl Trie {
    fn insert(&mut self, components: &[String], directory: bool) {
        if components.is_empty() {
            self.ends_every_path |= !directory;
            return;
        }

        let mut node = 0;
        for component in components {
            node = match self.nodes[node].children.get(component) {
                Some(next) => *next,
                None => {
                    self.nodes.push(TrieNode::default());
                    let next = self.nodes.len() - 1;
                    self.nodes[node].children.insert(component.clone(), next);
                    next
                }
            };
        }

        if directory {
            self.nodes[node].directory = true;
        } else {
            self.nodes[node].exact_path = true;
        }
    }

    fn matches(&self, path: &[String], directories: bool) -> bool {
        if self.ends_every_path {
            return true;
        }

        for start in 0..path.len() {
            let mut node = 0;

            for (offset, component) in path[start..].iter().enumerate() {
                let Some(next) = self.nodes[node].children.get(component) else {
                    break;
                };
                node = *next;
                let ends_path = start + offset + 1 == path.len();

                if self.nodes[node].exact_path && ends_path {
                    return true;
                }
                if directories && self.nodes[node].directory && !ends_path {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GlobTarget {
    /// Matched against the file name (`*.csv`).
    Basename,
    /// Matched against the whole path (`data/*.csv`).
    FullPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Glob {
    pattern: String,
    target: GlobTarget,
}

impl Glob {
    fn matches(&self, path: &NormalizedPath) -> bool {
        match self.target {
            GlobTarget::Basename => path
                .basename()
                .is_some_and(|name| wildcard_matches(&self.pattern, name)),
            GlobTarget::FullPath => wildcard_matches(&self.pattern, &path.full_path),
        }
    }
}

/// Globs filed under a literal piece of text and the lengths of the pieces in
/// use, so a lookup tries one string per length instead of every glob.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TextBuckets {
    buckets: HashMap<String, Vec<Glob>>,
    lengths: Vec<usize>,
}

impl TextBuckets {
    fn insert(&mut self, text: &str, glob: Glob) {
        if !self.lengths.contains(&text.len()) {
            self.lengths.push(text.len());
        }
        self.buckets.entry(text.to_owned()).or_default().push(glob);
    }

    fn any_ending(&self, text: &str, path: &NormalizedPath) -> bool {
        self.lengths.iter().any(|length| {
            text.len() >= *length
                && text
                    .get(text.len() - length..)
                    .and_then(|tail| self.buckets.get(tail))
                    .is_some_and(|globs| globs.iter().any(|glob| glob.matches(path)))
        })
    }

    fn any_starting(&self, text: &str, path: &NormalizedPath) -> bool {
        self.lengths.iter().any(|length| {
            text.get(..*length)
                .and_then(|head| self.buckets.get(head))
                .is_some_and(|globs| globs.iter().any(|glob| glob.matches(path)))
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct GlobIndex {
    /// Globs with a literal path component of their own, such as `area7` in
    /// `**/area7/*.csv`: a path that lacks that component cannot match.
    by_component: HashMap<String, Vec<Glob>>,
    /// The rest, by the literal text after their last `*`...
    by_ending: TextBuckets,
    /// ...or, when they end in `*`, by the literal text before their first one
    /// (kept apart by what they match against, since the starts differ).
    by_basename_start: TextBuckets,
    by_path_start: TextBuckets,
    /// Globs that start and end with `*` (`**/*`, `*key*`): nothing to file them by.
    loose: Vec<Glob>,
}

impl GlobIndex {
    fn insert(&mut self, pattern: &str, target: GlobTarget) {
        let glob = Glob {
            pattern: pattern.to_owned(),
            target,
        };

        if target == GlobTarget::FullPath
            && let Some(component) = required_component(pattern)
        {
            self.by_component
                .entry(component.to_owned())
                .or_default()
                .push(glob);
        } else if let Some(ending) = pattern.rsplit('*').next().filter(|text| !text.is_empty()) {
            self.by_ending.insert(ending, glob);
        } else if let Some(start) = pattern.split('*').next().filter(|text| !text.is_empty()) {
            match target {
                GlobTarget::Basename => self.by_basename_start.insert(start, glob),
                GlobTarget::FullPath => self.by_path_start.insert(start, glob),
            }
        } else {
            self.loose.push(glob);
        }
    }

    fn matches(&self, path: &NormalizedPath) -> bool {
        path.components.iter().any(|component| {
            self.by_component
                .get(component)
                .is_some_and(|globs| globs.iter().any(|glob| glob.matches(path)))
        }) || self.by_ending.any_ending(&path.full_path, path)
            || path
                .basename()
                .is_some_and(|name| self.by_basename_start.any_starting(name, path))
            || self.by_path_start.any_starting(&path.full_path, path)
            || self.loose.iter().any(|glob| glob.matches(path))
    }
}

/// A component written in full, with a `/` after it, in a path glob: the text
/// `/area7/` (or a leading `area7/`) can only match a path that has a component
/// `area7`, since a `*` never turns part of a component into another.
fn required_component(pattern: &str) -> Option<&str> {
    let mut components = pattern.split('/').peekable();

    while let Some(component) = components.next() {
        if components.peek().is_some() && !component.is_empty() && !component.contains('*') {
            return Some(component);
        }
    }

    None
}

impl PatternIndex {
    fn build(patterns: &[CompiledPattern]) -> Self {
        let mut index = Self::default();

        for pattern in patterns {
            match pattern {
                CompiledPattern::ExactName(name) => {
                    index.names.insert(name.clone());
                }
                CompiledPattern::ExactPath(components) => {
                    index.segments.insert(components, false);
                }
                CompiledPattern::Directory(components) => {
                    index.segments.insert(components, true);
                }
                CompiledPattern::BasenameGlob(glob) => {
                    index.globs.insert(glob, GlobTarget::Basename);
                }
                CompiledPattern::PathGlob(glob) => {
                    index.globs.insert(glob, GlobTarget::FullPath);
                }
            }
        }

        index
    }

    /// Whether any pattern covers `path`. With `directories` false the
    /// `dir/**` patterns are left out: the question a directory walk asks of
    /// each file, since it already asked it of the directory.
    fn matches(&self, path: &NormalizedPath, directories: bool) -> bool {
        path.basename()
            .is_some_and(|name| self.names.contains(name))
            || self.segments.matches(&path.components, directories)
            || self.globs.matches(path)
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

    #[cfg(test)]
    fn ends_with(&self, suffix: &[String]) -> bool {
        self.components.ends_with(suffix)
    }

    #[cfg(test)]
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
    fn a_directory_is_covered_when_a_file_created_in_it_would_be() {
        let root = unique_dir("covers");
        put(&root, "data/clients/a.csv");
        put(&root, "src/main.rs");
        let matcher = matcher(&["data/**"]);

        // inside the protected root, at any depth, but not the root's parent
        assert!(matcher.covers_directory(&root.join("data")));
        assert!(matcher.covers_directory(&root.join("data/clients")));
        assert!(!matcher.covers_directory(&root));
        assert!(!matcher.covers_directory(&root.join("src")));
        // a name that only starts like the root is not the root
        assert!(!matcher.covers_directory(&root.join("database")));
        // nothing is covered by no patterns
        assert!(!self::matcher(&[]).covers_directory(&root.join("data")));
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
    fn extra_classifier_finds_sensitive_paths_without_globs() {
        let root = unique_dir("extra-classifier");
        let env_file = put(&root, ".env");
        put(&root, "src/main.rs");

        let scan = matcher(&[]).scan_directory_with(&root, 1_000, |path| {
            path.file_name().is_some_and(|name| name == ".env")
        });

        assert_eq!(scan, DirectoryScan::Protected(env_file));
    }

    #[test]
    fn extra_classifier_scans_still_stop_at_the_entry_budget() {
        let root = unique_dir("extra-budget");
        put(&root, "a.txt");
        put(&root, "b.txt");

        let scan = matcher(&[]).scan_directory_with(&root, 1, |_| false);

        assert_eq!(scan, DirectoryScan::Unverified { max_entries: 1 });
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

    // --- bd-29r: the pattern index answers what trying every pattern answers ---

    /// A small deterministic generator (xorshift64*), so a failure replays.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }

        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[self.below(items.len())]
        }
    }

    const LITERALS: &[&str] = &[
        "data", "clients", "x.csv", "y.csv", "d", "data2", ".env", "a", "b", "sub",
    ];
    const WILDCARDS: &[&str] = &["*", "**", "d*", "*.csv", "x*y", "*x*", "*data*", "*.env"];
    const ODD_PATTERNS: &[&str] = &[
        "/",
        "/**",
        "**",
        "*",
        "**/*",
        "./x",
        "a//b",
        "**/data/**",
        "*/*",
        "data*",
        "*.csv",
        "data/*",
        "**/clients/*.csv",
        "a/*/b",
        "x*y",
        "**/.env",
        "/data/x.csv",
        "",
    ];

    fn random_pattern(rng: &mut Rng) -> String {
        if rng.below(6) == 0 {
            return rng.pick(ODD_PATTERNS).to_owned();
        }

        let count = 1 + rng.below(4);
        let mut parts: Vec<&str> = (0..count)
            .map(|_| {
                if rng.below(10) < 6 {
                    rng.pick(LITERALS)
                } else {
                    rng.pick(WILDCARDS)
                }
            })
            .collect();
        match rng.below(6) {
            0 => parts.insert(0, "**"),
            1 => parts.insert(0, ""),
            2 => parts.insert(0, "."),
            _ => {}
        }

        let mut pattern = parts.join("/");
        if rng.below(3) == 0 {
            pattern.push_str("/**");
        }
        pattern
    }

    fn random_path(rng: &mut Rng) -> String {
        let count = rng.below(7);
        let parts: Vec<&str> = (0..count)
            .map(|_| match rng.below(14) {
                0 => "..",
                1 => ".",
                _ => rng.pick(LITERALS),
            })
            .collect();
        let joined = parts.join("/");

        if rng.below(2) == 0 {
            format!("/{joined}")
        } else {
            joined
        }
    }

    #[test]
    fn the_index_agrees_with_trying_every_pattern_on_random_patterns_and_paths() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut covered = 0usize;
        let mut total = 0usize;

        for _ in 0..4_000 {
            let patterns: Vec<String> = (0..1 + rng.below(10))
                .map(|_| random_pattern(&mut rng))
                .collect();
            let matcher = SafePathMatcher::from_patterns(patterns.iter());

            for _ in 0..30 {
                let path = random_path(&mut rng);
                let path = Path::new(&path);
                let expected = matcher.is_safe_linear(path);
                let normalized = NormalizedPath::from_path(path);
                let expected_files = matcher.patterns.iter().any(|pattern| {
                    !matches!(pattern, CompiledPattern::Directory(_))
                        && pattern.matches(&normalized)
                });

                assert_eq!(
                    matcher.is_safe(path),
                    expected,
                    "patterns {patterns:?}, path {path:?}"
                );
                assert_eq!(
                    matcher.matches_file_pattern(path),
                    expected_files,
                    "file patterns {patterns:?}, path {path:?}"
                );
                total += 1;
                covered += usize::from(expected);
            }
        }

        // The comparison is only worth something if both answers occur often.
        assert!(
            covered > total / 20 && covered < total - total / 20,
            "{covered} of {total} paths matched"
        );
    }

    #[test]
    fn the_index_keeps_the_quirks_of_the_patterns_as_written() {
        let path = |text: &str| Path::new(text).to_path_buf();

        // `/` is an exact path with no components, so it ends every path
        assert!(matcher(&["/"]).is_safe(path("anything/at/all")));
        // `dir/**` needs something below the directory, and may sit anywhere
        assert!(!matcher(&["data/**"]).is_safe(path("/repo/data")));
        assert!(matcher(&["data/**"]).is_safe(path("/repo/data/x")));
        assert!(matcher(&["data/**"]).is_safe(path("/repo/deep/data/x")));
        // a bare path pattern must end the path
        assert!(matcher(&["data/x.csv"]).is_safe(path("/repo/data/x.csv")));
        assert!(!matcher(&["data/x.csv"]).is_safe(path("/repo/data/x.csv/y")));
        // a glob with a slash is matched against the whole path, from its start
        assert!(matcher(&["data/*.csv"]).is_safe(path("data/x.csv")));
        assert!(!matcher(&["data/*.csv"]).is_safe(path("/repo/data/x.csv")));
        assert!(matcher(&["**/data/*.csv"]).is_safe(path("/repo/data/x.csv")));
        // a glob without one is matched against the file name
        assert!(matcher(&["*.csv"]).is_safe(path("/repo/data/x.csv")));
        assert!(!matcher(&["*.csv"]).is_safe(path("/repo/x.csv/y")));
        assert!(matcher(&[".env"]).is_safe(path("/repo/.env")));
    }

    #[test]
    fn ten_thousand_patterns_resolve_a_command_worth_of_paths_inside_a_millisecond() {
        let mut patterns: Vec<String> = Vec::new();
        for index in 0..2_000 {
            patterns.push(format!("zone{index}/**"));
            patterns.push(format!("vault{index}/file{index}.csv"));
            patterns.push(format!("secret{index}.txt"));
            patterns.push(format!("report{index}*.json"));
            patterns.push(format!("**/area{index}/*.parquet"));
        }
        assert_eq!(patterns.len(), 10_000);

        let build_start = std::time::Instant::now();
        let matcher = SafePathMatcher::from_patterns(patterns.iter());
        let build = build_start.elapsed();

        // Sixty-four paths, as many as one command's words get resolved: some
        // that a pattern covers, most that none does.
        let mut paths: Vec<PathBuf> = Vec::new();
        for index in 0..64usize {
            paths.push(match index % 8 {
                0 => PathBuf::from(format!("/repo/zone{}/deep/x.csv", index * 31)),
                1 => PathBuf::from(format!("/repo/vault{0}/file{0}.csv", index * 17)),
                2 => PathBuf::from(format!("/repo/notes/secret{}.txt", index * 7)),
                3 => PathBuf::from(format!("/repo/out/report{}-final.json", index * 11)),
                4 => PathBuf::from(format!("/repo/lake/area{}/part.parquet", index * 13)),
                5 => PathBuf::from(format!("/repo/src/module{index}/lib.rs")),
                6 => PathBuf::from(format!("/repo/docs/chapter{index}/README.md")),
                _ => PathBuf::from(format!("/repo/data/unrelated{index}.csv")),
            });
        }

        let mut best = std::time::Duration::MAX;
        let mut matched = 0usize;
        for _ in 0..50 {
            let start = std::time::Instant::now();
            matched = paths.iter().filter(|path| matcher.is_safe(path)).count();
            best = best.min(start.elapsed());
        }

        let linear_start = std::time::Instant::now();
        let linear_matched = paths
            .iter()
            .filter(|path| matcher.is_safe_linear(path))
            .count();
        let linear = linear_start.elapsed();

        eprintln!(
            "10k patterns: build {build:?}, 64 lookups {best:?} (trying every pattern: {linear:?}), {matched} matched"
        );
        assert_eq!(linear_matched, matched);
        assert_eq!(matched, 40);
        assert!(
            paths
                .iter()
                .all(|path| matcher.is_safe(path) == matcher.is_safe_linear(path)),
            "the index must agree with the linear matcher on these paths"
        );
        assert!(
            best < std::time::Duration::from_millis(1),
            "64 lookups took {best:?}"
        );
    }
}
