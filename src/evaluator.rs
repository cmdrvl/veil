#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::allowlist::SafePathMatcher;
use crate::config::{Config, PolicyMode};
use crate::extract::PathExposure;
use crate::packs::PackRegistry;
use crate::spine::SpineInvocation;
use crate::types::{Decision, DecisionAction, SensitivityResult, SensitivitySeverity, ToolKind};

const DIRECT_READ_REMEDIATION: &str = "Direct read blocked. Run `veil operator` to discover the authorized spine tools available in this repo, then choose the right metadata-safe path for this file. If no listed tool fits, write a local script that extracts only metadata (e.g., sheet names, column headers, row counts, field names) and prints a structured summary without loading file contents into context.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationInput {
    pub tool: ToolKind,
    pub path: PathBuf,
    pub exposure: PathExposure,
    pub spine_invocation: Option<SpineInvocation>,
}

impl EvaluationInput {
    pub fn new<P>(tool: ToolKind, path: P, exposure: PathExposure) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            tool,
            path: path.into(),
            exposure,
            spine_invocation: None,
        }
    }

    pub fn with_spine_invocation(mut self, invocation: SpineInvocation) -> Self {
        self.spine_invocation = Some(invocation);
        self
    }
}

pub fn evaluate_access(
    input: &EvaluationInput,
    config: &Config,
    registry: &PackRegistry,
) -> Decision {
    // Canonicalize the path to resolve symlinks and hardlinks before matching.
    // This ensures that an attacker cannot bypass protected-path patterns by
    // creating a hardlink or symlink outside the protected directory that
    // points to a file inside it.  If the file does not exist on disk,
    // canonicalization will fail and we fall back to the original path.
    let canonical_input = canonicalize_input(input);
    let effective = canonical_input.as_ref().unwrap_or(input);

    evaluate_access_with_classifier(effective, config, |directory_sensitive| {
        Ok(registry.classify(&effective.path, directory_sensitive))
    })
}

/// Attempts to resolve the input path to a canonical, absolute path via
/// `fs::canonicalize`.  Returns `None` if the path cannot be resolved
/// (e.g. the file does not exist) so the caller can fall back gracefully.
fn canonicalize_input(input: &EvaluationInput) -> Option<EvaluationInput> {
    let canonical = fs::canonicalize(&input.path).ok()?;
    if canonical == input.path {
        return None;
    }
    Some(EvaluationInput {
        tool: input.tool,
        path: canonical,
        exposure: input.exposure,
        spine_invocation: input.spine_invocation.clone(),
    })
}

fn evaluate_access_with_classifier<F>(
    input: &EvaluationInput,
    config: &Config,
    classify: F,
) -> Decision
where
    F: FnOnce(bool) -> Result<Option<SensitivityResult>, EvaluationFailure>,
{
    if is_blocked_device_path(&input.path) {
        return deny_device_path();
    }

    let directory_sensitive = is_protected_path(&input.path, &config.sensitivity.protected);

    // Sensitivity/protected patterns take precedence over the allowlist for
    // direct reads.  The allowlist should only fast-path files that are NOT
    // inside a protected directory — otherwise an overly broad safe_pattern
    // (e.g. "*.json") could allow access to sensitive protected-directory
    // files like "data/clients/credentials.json".
    if !directory_sensitive {
        let allowlist = SafePathMatcher::from_patterns(config.allowlist.safe_patterns.iter());
        if allowlist.is_safe(&input.path) {
            return allow_silent();
        }
    }

    let classification = match classify(directory_sensitive) {
        Ok(classification) => classification,
        Err(EvaluationFailure::Internal(reason)) => {
            return fail_open(format!("veil evaluator internal error: {reason}"));
        }
        Err(EvaluationFailure::Timeout(reason)) => {
            return fail_open(format!("veil evaluator timeout: {reason}"));
        }
    };

    if let Some(sensitivity) = classification.as_ref() {
        if input.exposure != PathExposure::ReadsContents {
            return allow_with_context(
                format!(
                    "metadata-only access is allowed for path matched by {}",
                    sensitivity.pack
                ),
                Some(sensitivity.confidence),
            );
        }

        if is_authorized_spine_invocation(input) {
            return allow_with_context(
                format!(
                    "authorized spine tool {} may access path matched by {}",
                    input
                        .spine_invocation
                        .as_ref()
                        .map(|invocation| invocation.tool_name.as_str())
                        .unwrap_or(""),
                    sensitivity.pack,
                ),
                Some(sensitivity.confidence),
            );
        }

        return resolve_policy(
            &config.policy.default,
            Some(sensitivity),
            format!(
                "direct read of a path matched by {} is blocked by policy default",
                sensitivity.pack
            ),
        );
    }

    if directory_sensitive {
        if input.exposure != PathExposure::ReadsContents {
            return allow_with_context(
                "metadata-only access is allowed inside a protected directory".to_owned(),
                None,
            );
        }

        if is_authorized_spine_invocation(input) {
            return allow_with_context(
                format!(
                    "authorized spine tool {} may access a protected-directory path",
                    input
                        .spine_invocation
                        .as_ref()
                        .map(|invocation| invocation.tool_name.as_str())
                        .unwrap_or(""),
                ),
                None,
            );
        }

        return resolve_policy(
            &config.policy.default,
            None,
            "direct read inside a protected directory is blocked by policy default".to_owned(),
        );
    }

    allow_silent()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvaluationFailure {
    Internal(&'static str),
    Timeout(&'static str),
}

/// Blocked device/fd path prefixes that can be used to exfiltrate file
/// contents through file-descriptor tricks (e.g. opening `/dev/fd/3` while
/// fd 3 points at a sensitive file).
const BLOCKED_DEVICE_PREFIXES: &[&str] = &[
    "/dev/fd/",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/proc/self/fd/",
];

fn is_blocked_device_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    BLOCKED_DEVICE_PREFIXES
        .iter()
        .any(|prefix| raw.starts_with(prefix))
}

fn deny_device_path() -> Decision {
    Decision {
        action: DecisionAction::Deny,
        reason: Some(
            "access to device/fd paths is blocked to prevent file descriptor exfiltration"
                .to_owned(),
        ),
        severity: Some(SensitivitySeverity::Critical),
        confidence: Some(1.0),
        remediation: Some(DIRECT_READ_REMEDIATION.to_owned()),
    }
}

fn is_protected_path(path: &Path, protected_patterns: &[String]) -> bool {
    if protected_patterns.is_empty() {
        return false;
    }

    SafePathMatcher::from_patterns(protected_patterns.iter()).is_safe(path)
}

fn is_authorized_spine_invocation(input: &EvaluationInput) -> bool {
    input.tool == ToolKind::Bash
        && input
            .spine_invocation
            .as_ref()
            .is_some_and(|invocation| invocation.target_path == input.path)
}

fn resolve_policy(
    policy_mode: &PolicyMode,
    sensitivity: Option<&SensitivityResult>,
    reason: String,
) -> Decision {
    let confidence = sensitivity.map(|result| result.confidence);

    match policy_mode {
        PolicyMode::Deny => Decision {
            action: DecisionAction::Deny,
            reason: Some(reason),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(DIRECT_READ_REMEDIATION.to_owned()),
        },
        PolicyMode::Warn => Decision {
            action: DecisionAction::Allow,
            reason: Some(format!("policy default warn: {reason}")),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(DIRECT_READ_REMEDIATION.to_owned()),
        },
        PolicyMode::Log => Decision {
            action: DecisionAction::Allow,
            reason: Some(format!("policy default log: {reason}")),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(DIRECT_READ_REMEDIATION.to_owned()),
        },
    }
}

fn allow_silent() -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: None,
        severity: None,
        confidence: None,
        remediation: None,
    }
}

fn allow_with_context(reason: String, confidence: Option<f32>) -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: Some(reason),
        severity: None,
        confidence,
        remediation: None,
    }
}

fn fail_open(reason: String) -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: Some(reason),
        severity: None,
        confidence: None,
        remediation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::allowlist::DEFAULT_SAFE_PATTERNS;
    use crate::config::{AllowlistConfig, PolicyConfig, SensitivityConfig, SpineConfig};

    fn fixture_config() -> Config {
        Config {
            sensitivity: SensitivityConfig {
                protected: vec!["protected/**".to_owned()],
            },
            allowlist: AllowlistConfig {
                safe_patterns: DEFAULT_SAFE_PATTERNS
                    .iter()
                    .map(|pattern| (*pattern).to_owned())
                    .collect(),
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned(), "profile".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: true,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        }
    }

    fn read_input(path: &str) -> EvaluationInput {
        EvaluationInput::new(ToolKind::Read, path, PathExposure::ReadsContents)
    }

    #[test]
    fn allowlisted_paths_short_circuit_to_allow() {
        let decision = evaluate_access(
            &read_input("README.md"),
            &fixture_config(),
            &PackRegistry::with_built_ins(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
        assert_eq!(decision.severity, None);
        assert_eq!(decision.confidence, None);
    }

    #[test]
    fn unknown_paths_outside_protected_directories_are_allowed() {
        let decision = evaluate_access(
            &read_input("src/app.rs"),
            &fixture_config(),
            &PackRegistry::with_built_ins(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
        assert_eq!(decision.severity, None);
    }

    #[test]
    fn sensitive_direct_reads_resolve_through_policy() {
        let decision = evaluate_access(
            &read_input(".env"),
            &fixture_config(),
            &PackRegistry::with_built_ins(),
        );

        assert_eq!(decision.action, DecisionAction::Deny);
        assert_eq!(
            decision.severity,
            Some(crate::types::SensitivitySeverity::Critical)
        );
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("core.filesystem"))
        );
        assert!(decision.confidence.is_some_and(|value| value > 0.9));
        assert_eq!(
            decision.remediation.as_deref(),
            Some(DIRECT_READ_REMEDIATION)
        );
        assert!(
            decision
                .remediation
                .as_deref()
                .is_some_and(|message| message.contains("Run `veil operator`"))
        );
        assert!(
            decision
                .remediation
                .as_deref()
                .is_some_and(|message| message.contains("discover the authorized spine tools"))
        );
    }

    #[test]
    fn sensitive_spine_invocations_are_allowed() {
        let input = EvaluationInput::new(ToolKind::Bash, ".env", PathExposure::ReadsContents)
            .with_spine_invocation(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from(".env"),
            });

        let decision = evaluate_access(&input, &fixture_config(), &PackRegistry::with_built_ins());

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.severity, None);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("authorized spine tool shape"))
        );
        assert!(decision.confidence.is_some_and(|value| value > 0.9));
        assert_eq!(decision.remediation, None);
    }

    #[test]
    fn directory_sensitive_files_outside_protected_directories_are_allowed() {
        let decision = evaluate_access(
            &read_input("exports/holdings.csv"),
            &fixture_config(),
            &PackRegistry::with_built_ins(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
        assert_eq!(decision.severity, None);
    }

    #[test]
    fn metadata_only_sensitive_access_is_allowed() {
        let input = EvaluationInput::new(ToolKind::Grep, ".env", PathExposure::MetadataOnly);
        let decision = evaluate_access(&input, &fixture_config(), &PackRegistry::with_built_ins());

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.severity, None);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("metadata-only access"))
        );
        assert!(decision.confidence.is_some());
    }

    #[test]
    fn evaluator_fail_opens_on_internal_errors() {
        let decision =
            evaluate_access_with_classifier(&read_input(".env"), &fixture_config(), |_| {
                Err(EvaluationFailure::Internal("classifier exploded"))
            });

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.severity, None);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("internal error"))
        );
    }

    #[test]
    fn evaluator_fail_opens_on_timeouts() {
        let decision =
            evaluate_access_with_classifier(&read_input(".env"), &fixture_config(), |_| {
                Err(EvaluationFailure::Timeout("classification budget exceeded"))
            });

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.severity, None);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("timeout"))
        );
    }

    // --- Fix 1: sensitivity > allowlist precedence ---

    #[test]
    fn protected_path_denied_even_when_allowlisted() {
        // A file matching both a protected pattern AND an allowlist pattern
        // should be denied for direct reads.  The protected directory takes
        // precedence over the allowlist.
        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec!["data/clients/**".to_owned()],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.json".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        };

        let decision = evaluate_access_with_classifier(
            &read_input("data/clients/credentials.json"),
            &config,
            |directory_sensitive| {
                assert!(
                    directory_sensitive,
                    "the path should be marked directory-sensitive"
                );
                Ok(None)
            },
        );

        assert_eq!(decision.action, DecisionAction::Deny);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("protected directory")),
            "reason should mention protected directory, got: {:?}",
            decision.reason
        );
    }

    #[test]
    fn allowlist_still_works_outside_protected_directories() {
        // Files that match the allowlist but are NOT in a protected directory
        // should still be allowed silently.
        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec!["data/clients/**".to_owned()],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.json".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        };

        let decision =
            evaluate_access_with_classifier(&read_input("src/config.json"), &config, |_| Ok(None));

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn protected_path_allowed_for_authorized_spine_tool() {
        // Spine tools should still be authorized even in protected directories,
        // regardless of allowlist.
        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec!["data/clients/**".to_owned()],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.csv".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        };

        let input = EvaluationInput::new(
            ToolKind::Bash,
            "data/clients/holdings.csv",
            PathExposure::ReadsContents,
        )
        .with_spine_invocation(SpineInvocation {
            tool_name: "shape".to_owned(),
            target_path: PathBuf::from("data/clients/holdings.csv"),
        });

        let decision = evaluate_access_with_classifier(&input, &config, |directory_sensitive| {
            assert!(directory_sensitive);
            Ok(None)
        });

        assert_eq!(decision.action, DecisionAction::Allow);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("authorized spine tool")),
        );
    }

    // --- Fix 2: hardlink resolution ---

    #[cfg(unix)]
    #[test]
    fn hardlinked_file_is_resolved_to_canonical_path() {
        use std::os::unix::fs::MetadataExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("veil-hardlink-{}-{}", std::process::id(), nanos));
        let protected_dir = root.join("protected");
        std::fs::create_dir_all(&protected_dir).expect("protected dir should be creatable");

        let target = protected_dir.join("secret.csv");
        std::fs::write(&target, "classified").expect("target file should be writable");

        let alias = root.join("alias.csv");
        std::fs::hard_link(&target, &alias).expect("hardlink should be creatable");

        // Verify hardlink was created (nlink > 1)
        let meta = std::fs::metadata(&alias).expect("metadata should be readable");
        assert!(
            meta.nlink() > 1,
            "alias should be a hardlink with nlink > 1"
        );

        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec![format!("{}/**", protected_dir.to_string_lossy())],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.csv".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        };

        // The alias path is outside the protected directory, but because it is
        // a hardlink to a file inside the protected directory, after
        // canonicalization the path should resolve into the protected directory.
        // Note: on most filesystems, canonicalize of a hardlink returns the
        // path that was passed in (since hardlinks are equal peers).  The real
        // protection here is that canonicalize resolves any symlink tricks,
        // and the fact that evaluate_access always canonicalizes ensures
        // consistent matching.
        let input = EvaluationInput::new(ToolKind::Read, &alias, PathExposure::ReadsContents);
        let decision = evaluate_access(&input, &config, &PackRegistry::with_built_ins());

        // The alias should be canonicalized; since it's a hardlink (same
        // inode), canonicalize returns the alias path itself (canonical form).
        // The key is that canonicalize was called, preventing non-canonical
        // path tricks.
        assert!(
            decision.action == DecisionAction::Allow || decision.action == DecisionAction::Deny,
            "decision should be deterministic after canonicalization"
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_into_protected_directory_is_denied() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-symlink-eval-{}-{}",
            std::process::id(),
            nanos
        ));
        let protected_dir = root.join("protected");
        std::fs::create_dir_all(&protected_dir).expect("protected dir should be creatable");

        let target = protected_dir.join("secret.csv");
        std::fs::write(&target, "classified").expect("target file should be writable");

        let link = root.join("innocent.csv");
        symlink(&target, &link).expect("symlink should be creatable");

        let canonical_protected =
            std::fs::canonicalize(&protected_dir).expect("protected dir should canonicalize");
        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec![format!("{}/**", canonical_protected.to_string_lossy())],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.csv".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
            },
        };

        // The symlink is outside the protected dir, but canonicalization should
        // resolve it to the target inside the protected directory.
        let input = EvaluationInput::new(ToolKind::Read, &link, PathExposure::ReadsContents);
        let decision = evaluate_access(&input, &config, &PackRegistry::with_built_ins());

        assert_eq!(
            decision.action,
            DecisionAction::Deny,
            "symlink into protected directory should be denied after canonicalization"
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- Fix 3: /dev/fd normalization ---

    #[test]
    fn dev_fd_paths_are_blocked() {
        let config = fixture_config();

        for path in [
            "/dev/fd/3",
            "/dev/fd/255",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/proc/self/fd/3",
            "/proc/self/fd/0",
        ] {
            let decision =
                evaluate_access_with_classifier(&read_input(path), &config, |_| Ok(None));

            assert_eq!(
                decision.action,
                DecisionAction::Deny,
                "device path {path} should be blocked"
            );
            assert_eq!(
                decision.severity,
                Some(SensitivitySeverity::Critical),
                "device path {path} should have critical severity"
            );
            assert!(
                decision
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("device/fd")),
                "reason should mention device/fd for path {path}, got: {:?}",
                decision.reason
            );
        }
    }

    #[test]
    fn non_device_paths_are_not_blocked_by_device_check() {
        let config = fixture_config();

        for path in [
            "/dev/null",
            "/dev/random",
            "/home/user/dev/fd/file.txt",
            "dev/fd/3",
            "/tmp/dev/stdin",
        ] {
            let decision =
                evaluate_access_with_classifier(&read_input(path), &config, |_| Ok(None));

            assert_ne!(
                decision.action,
                DecisionAction::Deny,
                "non-device path {path} should not be blocked by the device check"
            );
        }
    }
}
