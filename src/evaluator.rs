#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use crate::allowlist::SafePathMatcher;
use crate::config::{Config, PolicyMode};
use crate::extract::PathExposure;
use crate::packs::PackRegistry;
use crate::spine::SpineInvocation;
use crate::types::{Decision, DecisionAction, SensitivityResult, ToolKind};

const DIRECT_READ_REMEDIATION: &str = "Use an authorized spine tool instead of a direct read.";

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
    evaluate_access_with_classifier(input, config, |directory_sensitive| {
        Ok(registry.classify(&input.path, directory_sensitive))
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
    let allowlist = SafePathMatcher::from_patterns(config.allowlist.safe_patterns.iter());
    if allowlist.is_safe(&input.path) {
        return allow_silent();
    }

    let directory_sensitive = is_protected_path(&input.path, &config.sensitivity.protected);
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
}
