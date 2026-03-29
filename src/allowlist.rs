#![forbid(unsafe_code)]

use std::path::{Component, Path};

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
