#[path = "../src/allowlist.rs"]
mod allowlist;

use allowlist::SafePathMatcher;

#[test]
fn exact_patterns_match_file_names() {
    let matcher = SafePathMatcher::from_patterns(["Cargo.toml"]);

    assert!(matcher.is_safe("Cargo.toml"));
    assert!(matcher.is_safe("/tmp/veil/Cargo.toml"));
    assert!(!matcher.is_safe("/tmp/veil/Cargo.lock"));
}

#[test]
fn glob_patterns_match_safe_basenames() {
    let matcher = SafePathMatcher::from_patterns(["*.md", "*-report.json"]);

    assert!(matcher.is_safe("README.md"));
    assert!(matcher.is_safe("/tmp/veil/shape-report.json"));
    assert!(!matcher.is_safe("/tmp/veil/credentials.json"));
}

#[test]
fn directory_patterns_match_nested_safe_paths() {
    let matcher = SafePathMatcher::from_patterns(["docs/**", ".github/**"]);

    assert!(matcher.is_safe("docs/plan.md"));
    assert!(matcher.is_safe("/tmp/veil/.github/workflows/ci.yml"));
    assert!(!matcher.is_safe("/tmp/veil/src/docs.rs"));
}

#[test]
fn default_patterns_allow_known_safe_docs_and_configs() {
    let matcher = SafePathMatcher::default();

    assert!(matcher.is_safe("README.md"));
    assert!(matcher.is_safe("/tmp/veil/Cargo.toml"));
    assert!(matcher.is_safe("/tmp/veil/docs/plan.md"));
}

#[test]
fn default_patterns_do_not_allowlist_sensitive_looking_files() {
    let matcher = SafePathMatcher::default();

    assert!(!matcher.is_safe("credentials.json"));
    assert!(!matcher.is_safe("/tmp/veil/secrets.yaml"));
}

#[test]
fn matcher_can_be_reused_without_rebuilding_pattern_state() {
    let matcher = SafePathMatcher::default();

    for _ in 0..32 {
        assert!(matcher.is_safe("README.md"));
        assert!(matcher.is_safe("shape-report.yaml"));
        assert!(!matcher.is_safe("secrets.yaml"));
    }
}
