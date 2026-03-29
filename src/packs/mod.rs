#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::path::Path;

use crate::types::{SensitivityResult, SensitivitySeverity};

pub const BUILTIN_PACK_NAMES: &[&str] = &[
    "core.filesystem",
    "core.credentials",
    "data.tabular",
    "data.xml",
    "data.database",
    "compliance.financial",
    "compliance.pii",
    "compliance.hipaa",
];

const FILESYSTEM_CONFIDENCE: f32 = 0.99;
const DATABASE_CONFIDENCE: f32 = 0.97;

#[derive(Clone, Copy, Debug)]
pub struct ClassificationRequest<'a> {
    pub path: &'a Path,
    pub directory_sensitive: bool,
}

impl<'a> ClassificationRequest<'a> {
    pub fn new(path: &'a Path, directory_sensitive: bool) -> Self {
        Self {
            path,
            directory_sensitive,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PackMatch {
    pub severity: SensitivitySeverity,
    pub confidence: f32,
    pub directory_sensitive: bool,
}

pub trait SensitivityPack: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch>;
}

#[derive(Debug, Default)]
pub struct PackRegistry {
    packs: Vec<Box<dyn SensitivityPack>>,
}

impl PackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_built_ins() -> Self {
        let mut registry = Self::new();
        registry.register_all(built_in_packs());
        registry
    }

    pub fn register(&mut self, pack: Box<dyn SensitivityPack>) -> &mut Self {
        let name = pack.name().to_owned();

        match self
            .packs
            .binary_search_by(|existing| existing.name().cmp(name.as_str()))
        {
            Ok(index) => self.packs[index] = pack,
            Err(index) => self.packs.insert(index, pack),
        }

        self
    }

    pub fn register_all<I>(&mut self, packs: I) -> &mut Self
    where
        I: IntoIterator<Item = Box<dyn SensitivityPack>>,
    {
        for pack in packs {
            self.register(pack);
        }

        self
    }

    pub fn classify<P>(&self, path: P, directory_sensitive: bool) -> Option<SensitivityResult>
    where
        P: AsRef<Path>,
    {
        let request = ClassificationRequest::new(path.as_ref(), directory_sensitive);
        self.classify_request(&request)
    }

    pub fn classify_request(
        &self,
        request: &ClassificationRequest<'_>,
    ) -> Option<SensitivityResult> {
        self.packs
            .iter()
            .filter_map(|pack| {
                pack.classify(request).map(|matched| SensitivityResult {
                    pack: pack.name().to_owned(),
                    severity: matched.severity,
                    confidence: matched.confidence,
                    directory_sensitive: matched.directory_sensitive,
                })
            })
            .fold(None, |best, candidate| match best {
                None => Some(candidate),
                Some(current) if compare_results(&candidate, &current) == Ordering::Greater => {
                    Some(candidate)
                }
                Some(current) => Some(current),
            })
    }

    pub fn pack_names(&self) -> Vec<&str> {
        self.packs.iter().map(|pack| pack.name()).collect()
    }
}

pub fn built_in_packs() -> Vec<Box<dyn SensitivityPack>> {
    BUILTIN_PACK_NAMES
        .iter()
        .copied()
        .map(|name| match name {
            "core.filesystem" => Box::new(FilesystemPack) as Box<dyn SensitivityPack>,
            "data.database" => Box::new(DatabasePack) as Box<dyn SensitivityPack>,
            _ => Box::new(NoopPack::new(name)) as Box<dyn SensitivityPack>,
        })
        .collect()
}

fn compare_results(left: &SensitivityResult, right: &SensitivityResult) -> Ordering {
    severity_rank(&left.severity)
        .cmp(&severity_rank(&right.severity))
        .then_with(|| left.confidence.total_cmp(&right.confidence))
        .then_with(|| left.directory_sensitive.cmp(&right.directory_sensitive))
        .then_with(|| right.pack.cmp(&left.pack))
}

fn severity_rank(severity: &SensitivitySeverity) -> u8 {
    match severity {
        SensitivitySeverity::Low => 0,
        SensitivitySeverity::Medium => 1,
        SensitivitySeverity::High => 2,
        SensitivitySeverity::Critical => 3,
    }
}

#[derive(Debug)]
struct NoopPack {
    name: &'static str,
}

impl NoopPack {
    const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl SensitivityPack for NoopPack {
    fn name(&self) -> &str {
        self.name
    }

    fn classify(&self, _request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        None
    }
}

#[derive(Debug)]
struct FilesystemPack;

impl SensitivityPack for FilesystemPack {
    fn name(&self) -> &str {
        "core.filesystem"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_sensitive_env_file(basename)
            || path.contains_component(".ssh")
            || basename.ends_with(".pem")
            || basename.ends_with(".key")
        {
            return Some(PackMatch {
                severity: SensitivitySeverity::Critical,
                confidence: FILESYSTEM_CONFIDENCE,
                directory_sensitive: false,
            });
        }

        None
    }
}

#[derive(Debug)]
struct DatabasePack;

impl SensitivityPack for DatabasePack {
    fn name(&self) -> &str {
        "data.database"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_database_file(basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::High,
                confidence: DATABASE_CONFIDENCE,
                directory_sensitive: false,
            });
        }

        None
    }
}

#[derive(Debug)]
struct PathView {
    components: Vec<String>,
}

impl PathView {
    fn new(path: &Path) -> Self {
        let components = path
            .to_string_lossy()
            .replace('\\', "/")
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(|component| component.to_ascii_lowercase())
            .collect();

        Self { components }
    }

    fn basename(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    fn contains_component(&self, needle: &str) -> bool {
        self.components.iter().any(|component| component == needle)
    }
}

fn is_sensitive_env_file(basename: &str) -> bool {
    if basename == ".env" {
        return true;
    }

    let Some(suffix) = basename.strip_prefix(".env.") else {
        return false;
    };

    !suffix.is_empty() && !matches!(suffix, "example" | "sample" | "template")
}

fn is_database_file(basename: &str) -> bool {
    matches!(
        file_extension(basename),
        Some("sqlite" | "sqlite3" | "db" | "db3" | "duckdb" | "dump")
    ) || matches_database_dump_suffix(basename)
}

fn file_extension(basename: &str) -> Option<&str> {
    basename.rsplit_once('.').map(|(_, extension)| extension)
}

fn matches_database_dump_suffix(basename: &str) -> bool {
    const DATABASE_DUMP_SUFFIXES: &[&str] = &[
        ".sql.gz",
        ".sql.bz2",
        ".sql.xz",
        ".sql.zst",
        ".sql.zip",
        ".sql.dump",
        ".dump.sql",
    ];

    DATABASE_DUMP_SUFFIXES
        .iter()
        .any(|suffix| basename.ends_with(suffix))
        || (basename.ends_with(".sql")
            && (basename.contains("dump")
                || basename.contains("backup")
                || basename.contains("snapshot")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[derive(Debug)]
    struct StaticPack {
        name: &'static str,
        result: Option<PackMatch>,
    }

    impl StaticPack {
        fn matching(
            name: &'static str,
            severity: SensitivitySeverity,
            confidence: f32,
            directory_sensitive: bool,
        ) -> Self {
            Self {
                name,
                result: Some(PackMatch {
                    severity,
                    confidence,
                    directory_sensitive,
                }),
            }
        }
    }

    impl SensitivityPack for StaticPack {
        fn name(&self) -> &str {
            self.name
        }

        fn classify(&self, _request: &ClassificationRequest<'_>) -> Option<PackMatch> {
            self.result.clone()
        }
    }

    #[derive(Debug)]
    struct RequestAwarePack;

    impl SensitivityPack for RequestAwarePack {
        fn name(&self) -> &str {
            "data.tabular"
        }

        fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
            if request.directory_sensitive && request.path == Path::new("protected/data.csv") {
                return Some(PackMatch {
                    severity: SensitivitySeverity::High,
                    confidence: 0.95,
                    directory_sensitive: true,
                });
            }

            None
        }
    }

    #[test]
    fn register_keeps_names_sorted_and_replaces_duplicates() {
        let mut registry = PackRegistry::new();
        registry.register(Box::new(StaticPack::matching(
            "zulu",
            SensitivitySeverity::Low,
            0.20,
            false,
        )));
        registry.register(Box::new(StaticPack::matching(
            "alpha",
            SensitivitySeverity::Medium,
            0.60,
            false,
        )));
        registry.register(Box::new(StaticPack::matching(
            "echo",
            SensitivitySeverity::High,
            0.70,
            false,
        )));
        registry.register(Box::new(StaticPack::matching(
            "echo",
            SensitivitySeverity::Critical,
            0.91,
            true,
        )));

        assert_eq!(registry.pack_names(), vec!["alpha", "echo", "zulu"]);

        let result = registry
            .classify("sample.txt", false)
            .expect("replacement pack should still dispatch");

        assert_eq!(result.pack, "echo");
        assert_eq!(result.severity, SensitivitySeverity::Critical);
        assert!((result.confidence - 0.91).abs() < f32::EPSILON);
        assert!(result.directory_sensitive);
    }

    #[test]
    fn classify_prefers_severity_confidence_and_directory_sensitivity() {
        let mut registry = PackRegistry::new();
        registry.register(Box::new(StaticPack::matching(
            "alpha",
            SensitivitySeverity::Critical,
            0.55,
            false,
        )));
        registry.register(Box::new(StaticPack::matching(
            "beta",
            SensitivitySeverity::Critical,
            0.91,
            false,
        )));
        registry.register(Box::new(StaticPack::matching(
            "gamma",
            SensitivitySeverity::Critical,
            0.91,
            true,
        )));
        registry.register(Box::new(StaticPack::matching(
            "zeta",
            SensitivitySeverity::High,
            1.00,
            true,
        )));

        let result = registry
            .classify("sample.txt", false)
            .expect("one of the fake packs should match");

        assert_eq!(result.pack, "gamma");
        assert_eq!(result.severity, SensitivitySeverity::Critical);
        assert!((result.confidence - 0.91).abs() < f32::EPSILON);
        assert!(result.directory_sensitive);
    }

    #[test]
    fn classify_uses_pack_name_as_stable_final_tiebreaker() {
        let mut registry = PackRegistry::new();
        registry.register(Box::new(StaticPack::matching(
            "zulu",
            SensitivitySeverity::High,
            0.75,
            true,
        )));
        registry.register(Box::new(StaticPack::matching(
            "alpha",
            SensitivitySeverity::High,
            0.75,
            true,
        )));

        let result = registry
            .classify("sample.txt", true)
            .expect("matching pack should be selected");

        assert_eq!(result.pack, "alpha");
    }

    #[test]
    fn classify_returns_result_with_pack_metadata_from_request() {
        let mut registry = PackRegistry::new();
        registry.register(Box::new(RequestAwarePack));

        let result = registry
            .classify("protected/data.csv", true)
            .expect("request-aware pack should match");

        assert_eq!(result.pack, "data.tabular");
        assert_eq!(result.severity, SensitivitySeverity::High);
        assert!((result.confidence - 0.95).abs() < f32::EPSILON);
        assert!(result.directory_sensitive);
    }

    #[test]
    fn built_in_registry_registers_named_pack_set_and_dispatches_cleanly() {
        let registry = PackRegistry::with_built_ins();
        let mut expected = BUILTIN_PACK_NAMES.to_vec();
        expected.sort_unstable();

        assert_eq!(registry.pack_names(), expected);
        assert_eq!(registry.classify("safe/report.json", false), None);
    }

    #[test]
    fn filesystem_pack_matches_common_sensitive_paths() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            ".env",
            ".env.production",
            ".ssh/id_rsa",
            "keys/service.pem",
            "keys/private.key",
        ] {
            let result = registry
                .classify(path, false)
                .expect("filesystem-sensitive path should match");

            assert_eq!(result.pack, "core.filesystem");
            assert_eq!(result.severity, SensitivitySeverity::Critical);
            assert!((result.confidence - FILESYSTEM_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn filesystem_pack_skips_safe_lookalikes() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            ".env.",
            ".env.example",
            ".env.sample",
            "docs/environment.md",
            "keys/private.key.pub",
            "ssh-notes/readme.txt",
        ] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("core.filesystem"),
            );
        }
    }

    #[test]
    fn database_pack_matches_global_database_artifacts() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "db/prod.sqlite",
            "warehouse/report.duckdb",
            "backups/customer.dump",
            "exports/prod.sql.gz",
            "exports/database_backup.sql",
            "exports/customer_snapshot.sql",
        ] {
            let result = registry
                .classify(path, false)
                .expect("database artifact should match");

            assert_eq!(result.pack, "data.database");
            assert_eq!(result.severity, SensitivitySeverity::High);
            assert!((result.confidence - DATABASE_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn database_pack_skips_non_database_paths() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "migrations/001_init.sql",
            "docs/duckdb.md",
            "reports/database.dbt",
            "exports/schema.sql.txt",
        ] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("data.database"),
            );
        }
    }

    #[test]
    fn database_pack_remains_global_when_directory_sensitive_input_is_true() {
        let registry = PackRegistry::with_built_ins();

        let direct_match = registry
            .classify("warehouse/report.duckdb", false)
            .expect("database artifact should match without directory sensitivity");
        let protected_match = registry
            .classify("warehouse/report.duckdb", true)
            .expect("database artifact should match with directory sensitivity");

        assert_eq!(direct_match, protected_match);
        assert_eq!(direct_match.pack, "data.database");
        assert!(!direct_match.directory_sensitive);
    }
}
