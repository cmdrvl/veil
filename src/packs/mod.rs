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
const CREDENTIALS_CONFIDENCE: f32 = 0.99;
const DATABASE_CONFIDENCE: f32 = 0.97;
const TABULAR_CONFIDENCE: f32 = 0.95;
const XML_CONFIDENCE: f32 = 0.94;
const FINANCIAL_CONFIDENCE: f32 = 0.96;
const PII_CONFIDENCE: f32 = 0.97;
const HIPAA_CONFIDENCE: f32 = 0.98;

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
            "core.credentials" => Box::new(CredentialsPack) as Box<dyn SensitivityPack>,
            "data.tabular" => Box::new(TabularPack) as Box<dyn SensitivityPack>,
            "data.xml" => Box::new(XmlPack) as Box<dyn SensitivityPack>,
            "data.database" => Box::new(DatabasePack) as Box<dyn SensitivityPack>,
            "compliance.financial" => Box::new(FinancialPack) as Box<dyn SensitivityPack>,
            "compliance.pii" => Box::new(PiiPack) as Box<dyn SensitivityPack>,
            "compliance.hipaa" => Box::new(HipaaPack) as Box<dyn SensitivityPack>,
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
struct CredentialsPack;

impl SensitivityPack for CredentialsPack {
    fn name(&self) -> &str {
        "core.credentials"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_credentials_file(&path, basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::Critical,
                confidence: CREDENTIALS_CONFIDENCE,
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
struct FinancialPack;

impl SensitivityPack for FinancialPack {
    fn name(&self) -> &str {
        "compliance.financial"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_financial_file(&path, basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::High,
                confidence: FINANCIAL_CONFIDENCE,
                directory_sensitive: false,
            });
        }

        None
    }
}

#[derive(Debug)]
struct PiiPack;

impl SensitivityPack for PiiPack {
    fn name(&self) -> &str {
        "compliance.pii"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_pii_file(&path, basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::High,
                confidence: PII_CONFIDENCE,
                directory_sensitive: false,
            });
        }

        None
    }
}

#[derive(Debug)]
struct HipaaPack;

impl SensitivityPack for HipaaPack {
    fn name(&self) -> &str {
        "compliance.hipaa"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_hipaa_file(&path, basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::Critical,
                confidence: HIPAA_CONFIDENCE,
                directory_sensitive: false,
            });
        }

        None
    }
}

#[derive(Debug)]
struct TabularPack;

impl SensitivityPack for TabularPack {
    fn name(&self) -> &str {
        "data.tabular"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        if !request.directory_sensitive {
            return None;
        }

        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_tabular_file(basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::High,
                confidence: TABULAR_CONFIDENCE,
                directory_sensitive: true,
            });
        }

        None
    }
}

#[derive(Debug)]
struct XmlPack;

impl SensitivityPack for XmlPack {
    fn name(&self) -> &str {
        "data.xml"
    }

    fn classify(&self, request: &ClassificationRequest<'_>) -> Option<PackMatch> {
        if !request.directory_sensitive {
            return None;
        }

        let path = PathView::new(request.path);
        let basename = path.basename()?;

        if is_xml_filing_file(basename) {
            return Some(PackMatch {
                severity: SensitivitySeverity::High,
                confidence: XML_CONFIDENCE,
                directory_sensitive: true,
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

    fn has_term(&self, needle: &str) -> bool {
        self.components
            .iter()
            .flat_map(|component| component_terms(component))
            .any(|term| term == needle)
    }

    fn has_any_term(&self, needles: &[&str]) -> bool {
        needles.iter().any(|needle| self.has_term(needle))
    }

    fn has_all_terms(&self, needles: &[&str]) -> bool {
        needles.iter().all(|needle| self.has_term(needle))
    }
}

fn component_terms(component: &str) -> impl Iterator<Item = &str> {
    component
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
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

fn is_credentials_file(path: &PathView, basename: &str) -> bool {
    const EXACT_CREDENTIAL_FILES: &[&str] = &[
        ".aws/credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "service-account.json",
        "service_account.json",
    ];

    if EXACT_CREDENTIAL_FILES
        .iter()
        .any(|candidate| basename == *candidate || path.components.join("/") == *candidate)
    {
        return true;
    }

    is_config_like_file(basename)
        && (path.has_any_term(&["credential", "credentials", "secret", "secrets"])
            || path.has_all_terms(&["access", "token"])
            || path.has_all_terms(&["refresh", "token"])
            || path.has_all_terms(&["oauth", "token"])
            || path.has_all_terms(&["api", "key"])
            || path.has_all_terms(&["service", "account"])
            || path.has_all_terms(&["database", "url"])
            || path.has_all_terms(&["db", "url"]))
}

fn is_tabular_file(basename: &str) -> bool {
    matches!(file_extension(basename), Some("csv" | "tsv" | "parquet"))
        || basename.ends_with(".csv.gz")
        || basename.ends_with(".tsv.gz")
}

fn is_financial_file(path: &PathView, basename: &str) -> bool {
    is_structured_data_file(basename)
        && (path.has_any_term(&["trade", "trades", "transaction", "transactions", "ledger"])
            || path.has_all_terms(&["fund", "holding"])
            || path.has_all_terms(&["fund", "holdings"])
            || path.has_all_terms(&["portfolio", "holding"])
            || path.has_all_terms(&["portfolio", "holdings"])
            || path.has_all_terms(&["fund", "nav"])
            || path.has_all_terms(&["portfolio", "nav"])
            || path.has_all_terms(&["portfolio", "position"])
            || path.has_all_terms(&["portfolio", "positions"]))
}

fn is_pii_file(path: &PathView, basename: &str) -> bool {
    is_structured_data_file(basename)
        && (path.has_any_term(&[
            "ssn",
            "passport",
            "pii",
            "dob",
            "birthdate",
            "taxpayer",
            "taxid",
        ]) || path.has_all_terms(&["driver", "license"]))
}

fn is_hipaa_file(path: &PathView, basename: &str) -> bool {
    is_structured_data_file(basename)
        && path.has_any_term(&[
            "hipaa",
            "phi",
            "patient",
            "patients",
            "medical",
            "clinical",
            "diagnosis",
            "diagnoses",
            "treatment",
            "treatments",
        ])
}

fn is_xml_filing_file(basename: &str) -> bool {
    matches!(file_extension(basename), Some("xml"))
        || basename.ends_with(".xml.gz")
        || basename.ends_with(".nport")
}

fn is_config_like_file(basename: &str) -> bool {
    matches!(
        file_extension(basename),
        Some("json" | "yaml" | "yml" | "toml" | "ini" | "conf" | "env")
    )
}

fn is_structured_data_file(basename: &str) -> bool {
    matches!(
        file_extension(basename),
        Some("csv" | "tsv" | "parquet" | "json" | "jsonl" | "xlsx" | "xls" | "xml")
    ) || basename.ends_with(".csv.gz")
        || basename.ends_with(".tsv.gz")
        || basename.ends_with(".xml.gz")
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
    fn credentials_pack_matches_secret_bearing_config_paths() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "config/credentials.json",
            "secrets/service-account.yaml",
            ".aws/credentials",
            "oauth/access_token.toml",
        ] {
            let result = registry
                .classify(path, false)
                .expect("credentials-bearing config path should match");

            assert_eq!(result.pack, "core.credentials");
            assert_eq!(result.severity, SensitivitySeverity::Critical);
            assert!((result.confidence - CREDENTIALS_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn credentials_pack_skips_docs_and_source_files() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "docs/credentials.md",
            "src/tokenizer.rs",
            "examples/service_account.rs",
            "docs/secrets.yaml.example",
        ] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("core.credentials"),
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

    #[test]
    fn financial_pack_matches_financial_data_artifacts() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "fund/holdings_2026.csv",
            "trades/daily_trades.parquet",
            "reports/nav_ledger.xlsx",
        ] {
            let result = registry
                .classify(path, false)
                .expect("financial data path should match");

            assert_eq!(result.pack, "compliance.financial");
            assert_eq!(result.severity, SensitivitySeverity::High);
            assert!((result.confidence - FINANCIAL_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn financial_pack_skips_safe_lookalikes() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "docs/financial-report.md",
            "src/trade.rs",
            "notes/portfolio.txt",
        ] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("compliance.financial"),
            );
        }
    }

    #[test]
    fn pii_pack_matches_personal_data_artifacts() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "exports/customer_ssn.csv",
            "records/passport_index.json",
            "hr/employee_dob.xlsx",
        ] {
            let result = registry
                .classify(path, false)
                .expect("PII-style path should match");

            assert_eq!(result.pack, "compliance.pii");
            assert_eq!(result.severity, SensitivitySeverity::High);
            assert!((result.confidence - PII_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn pii_pack_skips_safe_lookalikes() {
        let registry = PackRegistry::with_built_ins();

        for path in ["docs/passport.md", "src/pii.rs", "notes/taxpayer.txt"] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("compliance.pii"),
            );
        }
    }

    #[test]
    fn hipaa_pack_matches_health_record_artifacts() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "hipaa/patient_diagnosis.csv",
            "clinical/treatment_plan.json",
            "medical/patient_records.parquet",
        ] {
            let result = registry
                .classify(path, false)
                .expect("HIPAA-style path should match");

            assert_eq!(result.pack, "compliance.hipaa");
            assert_eq!(result.severity, SensitivitySeverity::Critical);
            assert!((result.confidence - HIPAA_CONFIDENCE).abs() < f32::EPSILON);
            assert!(!result.directory_sensitive);
        }
    }

    #[test]
    fn hipaa_pack_skips_safe_lookalikes() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "docs/hipaa.md",
            "src/patient.rs",
            "notes/medical-device.txt",
        ] {
            assert_ne!(
                registry
                    .classify(path, false)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("compliance.hipaa"),
            );
        }
    }

    #[test]
    fn tabular_pack_requires_directory_sensitive_input() {
        let registry = PackRegistry::with_built_ins();

        assert_eq!(registry.classify("protected/holdings.csv", false), None);

        let result = registry
            .classify("protected/holdings.csv", true)
            .expect("protected tabular file should match");

        assert_eq!(result.pack, "data.tabular");
        assert_eq!(result.severity, SensitivitySeverity::High);
        assert!((result.confidence - TABULAR_CONFIDENCE).abs() < f32::EPSILON);
        assert!(result.directory_sensitive);
    }

    #[test]
    fn tabular_pack_matches_protected_directory_data_files() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "protected/holdings.csv",
            "protected/nav.tsv",
            "protected/snapshots/report.parquet",
            "protected/exports/report.csv.gz",
        ] {
            let result = registry
                .classify(path, true)
                .expect("protected-directory tabular file should match");

            assert_eq!(result.pack, "data.tabular");
            assert!(result.directory_sensitive);
        }
    }

    #[test]
    fn tabular_pack_skips_non_tabular_paths_in_protected_directories() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "protected/readme.md",
            "protected/schema.sql",
            "protected/report.json",
        ] {
            assert_ne!(
                registry
                    .classify(path, true)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("data.tabular"),
            );
        }
    }

    #[test]
    fn xml_pack_requires_directory_sensitive_input() {
        let registry = PackRegistry::with_built_ins();

        assert_eq!(registry.classify("protected/nport/report.xml", false), None);

        let result = registry
            .classify("protected/nport/report.xml", true)
            .expect("protected XML filing should match");

        assert_eq!(result.pack, "data.xml");
        assert_eq!(result.severity, SensitivitySeverity::High);
        assert!((result.confidence - XML_CONFIDENCE).abs() < f32::EPSILON);
        assert!(result.directory_sensitive);
    }

    #[test]
    fn xml_pack_matches_protected_directory_filing_paths() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "protected/edgar/submission.xml",
            "protected/nport/filing.xml.gz",
            "protected/edgar/report.nport",
        ] {
            let result = registry
                .classify(path, true)
                .expect("protected XML-style filing should match");

            assert_eq!(result.pack, "data.xml");
            assert!(result.directory_sensitive);
        }
    }

    #[test]
    fn xml_pack_skips_non_xml_protected_directory_paths() {
        let registry = PackRegistry::with_built_ins();

        for path in [
            "protected/edgar/readme.md",
            "protected/edgar/report.csv",
            "protected/edgar/summary.json",
        ] {
            assert_ne!(
                registry
                    .classify(path, true)
                    .as_ref()
                    .map(|result| result.pack.as_str()),
                Some("data.xml"),
            );
        }
    }

    #[test]
    fn more_specific_heuristic_pack_beats_generic_tabular_match() {
        let registry = PackRegistry::with_built_ins();

        let result = registry
            .classify("protected/fund_holdings.csv", true)
            .expect("overlapping path should still classify deterministically");

        assert_eq!(result.pack, "compliance.financial");
        assert_eq!(result.severity, SensitivitySeverity::High);
        assert!((result.confidence - FINANCIAL_CONFIDENCE).abs() < f32::EPSILON);
    }
}
