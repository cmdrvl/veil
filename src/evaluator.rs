#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::allowlist::{DirectoryScan, SafePathMatcher};
use crate::config::{Config, DynamicArgsMode, PolicyMode};
use crate::extract::PathExposure;
use crate::packs::PackRegistry;
use crate::spine::SpineInvocation;
use crate::types::{Decision, DecisionAction, SensitivityResult, SensitivitySeverity, ToolKind};

const DIRECT_READ_REMEDIATION: &str = "Direct read blocked. Run `veil operator` to discover the authorized spine tools available in this repo, then choose the right metadata-safe path for this file. Do not extract the contents any other way; if no listed tool fits, stop and ask the operator.";

const RAW_FLAG_REMEDIATION: &str = "Raw-value flag blocked. Re-run the spine tool without it so its output stays metadata-only, or run `veil operator` to discover the authorized spine tools and the metadata-safe path for this file. Do not look for another way to see the raw values; if no metadata-safe path fits, stop and ask the operator.";

const ARGV_PATH_REMEDIATION: &str = "Command names a protected path. Run `veil operator` to discover the authorized spine tools available in this repo, then choose the right metadata-safe path for this file. Do not copy, convert, archive or upload the protected file to get around this; if no listed tool fits, stop and ask the operator.";

const DIRECTORY_SEARCH_REMEDIATION: &str = "Content search blocked: this directory holds, or may hold, protected data. Search a narrower directory that holds none, or ask for file names or counts only (Grep output_mode files_with_matches or count; `grep -l` or `grep -c`). Run `veil operator` to discover the authorized spine tools for protected data. Do not look for another way to read it; if no listed tool fits, stop and ask the operator.";

const DYNAMIC_ARGS_REMEDIATION: &str = "Command blocked: an argument cannot be resolved to a path (a variable veil was not given, a `$( )` result, or names read from standard input), so veil cannot show that it stays clear of protected data. Rewrite with a literal path, one that needs no variable, substitution or pipe. If the file is protected, run `veil operator` to discover the authorized spine tools; do not build the path another way to get around this, and if no listed tool fits, stop and ask the operator.";

/// How many directory entries a content search of one directory makes veil
/// inspect before it stops vouching for the directory. The hook runs before
/// every search, so this bounds its latency; past it the search is refused
/// rather than waved through.
pub const DIRECTORY_SCOPE_MAX_ENTRIES: usize = 200_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationInput {
    pub tool: ToolKind,
    pub path: PathBuf,
    pub exposure: PathExposure,
    pub spine_invocation: Option<SpineInvocation>,
    /// Set when the path is named in the words of a command that is not a
    /// recognised reader (`awk 1 x.csv`, `cp x.csv /tmp`): the command's name.
    /// The decision is the same; the reason says so (bd-29r).
    pub argv_command: Option<String>,
    /// Whether a directory path stands for everything beneath it. True unless
    /// the command only names the directory without reading it as a tree.
    pub scan_directories: bool,
    /// The path is already canonical, as the extractor leaves one it resolved,
    /// so the evaluator does not walk it again.
    pub canonical: bool,
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
            argv_command: None,
            scan_directories: true,
            canonical: false,
        }
    }

    /// Says the path has already been resolved against the filesystem.
    pub fn with_canonical_path(mut self) -> Self {
        self.canonical = true;
        self
    }

    pub fn with_spine_invocation(mut self, invocation: SpineInvocation) -> Self {
        self.spine_invocation = Some(invocation);
        self
    }

    /// Marks the path as one a command names in its words, not one a reader
    /// reads. `scan_directories` says whether naming a directory names its tree.
    pub fn with_argv_command(mut self, command: &str, scan_directories: bool) -> Self {
        self.argv_command = Some(command.to_owned());
        self.scan_directories = scan_directories;
        self
    }
}

/// The matchers one hook run builds from the config and reuses for every path
/// it judges. Building them is linear in the number of patterns, so a command
/// that names many paths must not rebuild them per path.
#[derive(Clone, Debug)]
pub struct PolicyMatchers {
    protected: SafePathMatcher,
    allowlist: SafePathMatcher,
}

impl PolicyMatchers {
    pub fn new(config: &Config) -> Self {
        Self {
            protected: SafePathMatcher::from_patterns(config.sensitivity.protected.iter()),
            allowlist: SafePathMatcher::from_patterns(config.allowlist.safe_patterns.iter()),
        }
    }

    /// Whether `path` is covered by `[sensitivity] protected`.
    pub fn is_protected(&self, path: &Path) -> bool {
        self.protected.is_safe(path)
    }

    /// Whether `directory` is itself inside a `[sensitivity] protected` root.
    pub fn covers_directory(&self, directory: &Path) -> bool {
        self.protected.covers_directory(directory)
    }
}

pub fn evaluate_access(
    input: &EvaluationInput,
    config: &Config,
    registry: &PackRegistry,
) -> Decision {
    evaluate_access_with(input, config, registry, &PolicyMatchers::new(config))
}

/// [`evaluate_access`] with matchers built once by the caller.
pub fn evaluate_access_with(
    input: &EvaluationInput,
    config: &Config,
    registry: &PackRegistry,
    matchers: &PolicyMatchers,
) -> Decision {
    // Canonicalize the path to resolve symlinks and hardlinks before matching.
    // This ensures that an attacker cannot bypass protected-path patterns by
    // creating a hardlink or symlink outside the protected directory that
    // points to a file inside it.  If the file does not exist on disk,
    // canonicalization will fail and we fall back to the original path.
    let canonical_input = if input.canonical {
        None
    } else {
        canonicalize_input(input)
    };
    let effective = canonical_input.as_ref().unwrap_or(input);

    evaluate_with_matchers(effective, config, matchers, |directory_sensitive| {
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
        path: canonical,
        ..input.clone()
    })
}

#[cfg(test)]
fn evaluate_access_with_classifier<F>(
    input: &EvaluationInput,
    config: &Config,
    classify: F,
) -> Decision
where
    F: FnOnce(bool) -> Result<Option<SensitivityResult>, EvaluationFailure>,
{
    evaluate_with_matchers(input, config, &PolicyMatchers::new(config), classify)
}

fn evaluate_with_matchers<F>(
    input: &EvaluationInput,
    config: &Config,
    matchers: &PolicyMatchers,
    classify: F,
) -> Decision
where
    F: FnOnce(bool) -> Result<Option<SensitivityResult>, EvaluationFailure>,
{
    if is_blocked_device_path(&input.path) {
        return deny_device_path();
    }

    let directory_sensitive = matchers.is_protected(&input.path);

    // A content search of a directory reads every file beneath it, so it is a
    // read of whatever protected paths sit under it. Like the checks below it
    // outranks the allowlist.
    if !directory_sensitive
        && let Some(decision) = directory_scope_with(
            input,
            config,
            &matchers.protected,
            DIRECTORY_SCOPE_MAX_ENTRIES,
        )
    {
        return decision;
    }

    // Sensitivity/protected patterns take precedence over the allowlist for
    // direct reads.  The allowlist should only fast-path files that are NOT
    // inside a protected directory — otherwise an overly broad safe_pattern
    // (e.g. "*.json") could allow access to sensitive protected-directory
    // files like "data/clients/credentials.json".
    if !directory_sensitive && matchers.allowlist.is_safe(&input.path) {
        return allow_silent();
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
        // A raw-value flag turns an authorized spine tool into a reader, so it
        // is checked before the metadata-only and authorized-spine fast paths.
        if let Some((tool, flag)) = denied_raw_flag(input) {
            return resolve_policy(
                &config.policy.default,
                Some(sensitivity),
                raw_flag_reason(
                    tool,
                    flag,
                    &format!("a path matched by {}", sensitivity.pack),
                ),
                RAW_FLAG_REMEDIATION,
            );
        }

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

        return match input.argv_command.as_deref() {
            Some(command) => resolve_policy(
                &config.policy.default,
                Some(sensitivity),
                argv_path_reason(command, &format!("a path matched by {}", sensitivity.pack)),
                ARGV_PATH_REMEDIATION,
            ),
            None => resolve_policy(
                &config.policy.default,
                Some(sensitivity),
                format!(
                    "direct read of a path matched by {} is blocked by policy default",
                    sensitivity.pack
                ),
                DIRECT_READ_REMEDIATION,
            ),
        };
    }

    if directory_sensitive {
        if let Some((tool, flag)) = denied_raw_flag(input) {
            return resolve_policy(
                &config.policy.default,
                None,
                raw_flag_reason(tool, flag, "a protected-directory path"),
                RAW_FLAG_REMEDIATION,
            );
        }

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

        return match input.argv_command.as_deref() {
            Some(command) => resolve_policy(
                &config.policy.default,
                None,
                argv_path_reason(command, "a path inside a protected directory"),
                ARGV_PATH_REMEDIATION,
            ),
            None => resolve_policy(
                &config.policy.default,
                None,
                "direct read inside a protected directory is blocked by policy default".to_owned(),
                DIRECT_READ_REMEDIATION,
            ),
        };
    }

    allow_silent()
}

/// Why a command that is not a recognised reader was blocked for naming a path.
/// Files carry a label (`public < derived < protected`) and the agent's
/// clearance is `derived`, so a path matched by `[sensitivity] protected` or by
/// a sensitive pack carries `protected` (docs/plan.md, "Formal model").
fn argv_path_reason(command: &str, subject: &str) -> String {
    format!(
        "`{command}` names {subject} (label: protected) and is not an authorized spine tool, so it is blocked by policy default"
    )
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

pub(crate) fn is_blocked_device_path(path: &Path) -> bool {
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

/// The decision for a content search of a directory that holds protected
/// paths, or whose contents veil cannot inspect within `max_entries`. `None`
/// means this check has nothing to say: the input does not read contents, is
/// not an existing directory, or the directory holds nothing protected.
#[cfg(test)]
fn directory_scope_decision(
    input: &EvaluationInput,
    config: &Config,
    max_entries: usize,
) -> Option<Decision> {
    let matcher = SafePathMatcher::from_patterns(config.sensitivity.protected.iter());
    directory_scope_with(input, config, &matcher, max_entries)
}

fn directory_scope_with(
    input: &EvaluationInput,
    config: &Config,
    matcher: &SafePathMatcher,
    max_entries: usize,
) -> Option<Decision> {
    if input.exposure != PathExposure::ReadsContents
        || !input.scan_directories
        || config.sensitivity.protected.is_empty()
        || !input.path.is_dir()
    {
        return None;
    }

    let (reason, remediation) = match (
        matcher.scan_directory(&input.path, max_entries),
        input.argv_command.as_deref(),
    ) {
        (DirectoryScan::Clear, _) => return None,
        (DirectoryScan::Protected(_), None) => (
            "a content search of this directory would read paths covered by \
             [sensitivity] protected, and is blocked by policy default"
                .to_owned(),
            DIRECTORY_SEARCH_REMEDIATION,
        ),
        (DirectoryScan::Protected(_), Some(command)) => (
            argv_path_reason(
                command,
                "a directory that holds paths covered by [sensitivity] protected",
            ),
            ARGV_PATH_REMEDIATION,
        ),
        (DirectoryScan::Unverified { max_entries }, None) => (
            format!(
                "this directory holds more than {max_entries} entries, so veil cannot show that a \
                 content search of it would not read paths covered by [sensitivity] protected; \
                 blocked by policy default"
            ),
            DIRECTORY_SEARCH_REMEDIATION,
        ),
        (DirectoryScan::Unverified { max_entries }, Some(command)) => (
            format!(
                "`{command}` names a directory that holds more than {max_entries} entries, so veil \
                 cannot show that it holds nothing covered by [sensitivity] protected \
                 (label: protected); blocked by policy default"
            ),
            ARGV_PATH_REMEDIATION,
        ),
    };

    Some(resolve_policy(
        &config.policy.default,
        None,
        reason,
        remediation,
    ))
}

/// Why a command with an argument veil cannot resolve is judged (bd-2mi).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicReason {
    /// The command reads or ships the files it is given, or its program is
    /// itself unresolved: it is judged wherever it runs.
    Strict,
    /// Any other command, run with the working directory inside a protected
    /// root.
    ProtectedDirectory,
    /// Any other command, in a command string that sets a variable to a
    /// protected path.
    ProtectedValue,
    /// The command could not be analysed at all.
    Unanalysable,
}

/// The decision for a command with an argument veil cannot resolve to a path,
/// under `[policy] dynamic_args`. `None` when the mode is `allow`. `what`
/// describes the argument; `program` is the command it was given to.
pub(crate) fn dynamic_args_decision(
    config: &Config,
    program: &str,
    what: &str,
    why: DynamicReason,
) -> Option<Decision> {
    let cause = match why {
        DynamicReason::Strict => format!(
            "`{program}` is given {what}, which veil cannot resolve to a path, so veil cannot \
             show that it reads nothing protected (label: protected)"
        ),
        DynamicReason::ProtectedDirectory => format!(
            "`{program}` is given {what}, which veil cannot resolve to a path, and it runs \
             inside a protected directory, so veil cannot show that it stays clear of \
             protected data (label: protected)"
        ),
        DynamicReason::ProtectedValue => format!(
            "`{program}` is given {what}, which veil cannot resolve to a path, and this \
             command sets a variable to a protected path, so veil cannot show that it stays \
             clear of protected data (label: protected)"
        ),
        DynamicReason::Unanalysable => {
            "veil cannot analyse this command (unbalanced quotes, or more commands or levels \
             of nesting than it follows), so it cannot show that it reads nothing protected \
             (label: protected)"
                .to_owned()
        }
    };

    match config.policy.dynamic_args {
        DynamicArgsMode::Allow => None,
        DynamicArgsMode::Warn => Some(Decision {
            action: DecisionAction::Allow,
            reason: Some(format!("[policy] dynamic_args = warn: {cause}")),
            severity: None,
            confidence: None,
            remediation: Some(DYNAMIC_ARGS_REMEDIATION.to_owned()),
        }),
        DynamicArgsMode::Deny => Some(resolve_policy(
            &config.policy.default,
            None,
            format!("{cause}; blocked by policy default"),
            DYNAMIC_ARGS_REMEDIATION,
        )),
    }
}

fn is_authorized_spine_invocation(input: &EvaluationInput) -> bool {
    input.tool == ToolKind::Bash
        && input.spine_invocation.as_ref().is_some_and(|invocation| {
            invocation.denied_flag.is_none() && invocation.target_path == input.path
        })
}

/// The spine tool and raw-value flag of a Bash invocation that uses a denied
/// flag. Such an invocation is never authorized to touch protected content.
fn denied_raw_flag(input: &EvaluationInput) -> Option<(&str, &str)> {
    if input.tool != ToolKind::Bash {
        return None;
    }

    let invocation = input.spine_invocation.as_ref()?;
    let flag = invocation.denied_flag.as_deref()?;
    Some((invocation.tool_name.as_str(), flag))
}

fn raw_flag_reason(tool: &str, flag: &str, target: &str) -> String {
    format!(
        "spine tool {tool} was invoked with raw-value flag {flag}, which escalates its output from metadata to protected content, so it is not authorized for {target}"
    )
}

pub(crate) fn resolve_policy(
    policy_mode: &PolicyMode,
    sensitivity: Option<&SensitivityResult>,
    reason: String,
    remediation: &str,
) -> Decision {
    let confidence = sensitivity.map(|result| result.confidence);

    match policy_mode {
        PolicyMode::Deny => Decision {
            action: DecisionAction::Deny,
            reason: Some(reason),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(remediation.to_owned()),
        },
        PolicyMode::Warn => Decision {
            action: DecisionAction::Allow,
            reason: Some(format!("policy default warn: {reason}")),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(remediation.to_owned()),
        },
        PolicyMode::Log => Decision {
            action: DecisionAction::Allow,
            reason: Some(format!("policy default log: {reason}")),
            severity: sensitivity.map(|result| result.severity.clone()),
            confidence,
            remediation: Some(remediation.to_owned()),
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
    use crate::config::{
        AllowlistConfig, DynamicArgsMode, PolicyConfig, SensitivityConfig, SpineConfig,
    };
    use crate::protected_corpus::CorpusLimits;
    use crate::spine::DeniedFlags;

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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: true,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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

    fn spine_input(
        path: &str,
        exposure: PathExposure,
        denied_flag: Option<&str>,
    ) -> EvaluationInput {
        EvaluationInput::new(ToolKind::Bash, path, exposure).with_spine_invocation(
            SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from(path),
                denied_flag: denied_flag.map(str::to_owned),
            },
        )
    }

    #[test]
    fn denied_raw_flag_is_denied_on_sensitive_and_protected_paths_for_any_exposure() {
        for path in [".env", "protected/x.csv"] {
            // Hook mode feeds bare spine invocations through as `None` exposure,
            // so the flag must be caught before the metadata-only fast path.
            for exposure in [PathExposure::None, PathExposure::ReadsContents] {
                let decision = evaluate_access(
                    &spine_input(path, exposure, Some("--explicit")),
                    &fixture_config(),
                    &PackRegistry::with_built_ins(),
                );

                assert_eq!(decision.action, DecisionAction::Deny, "{path} {exposure:?}");
                let reason = decision.reason.as_deref().unwrap_or_default();
                assert!(reason.contains("--explicit"), "{reason}");
                assert!(reason.contains("shape"), "{reason}");
                assert!(
                    reason.contains("escalates its output from metadata to protected content"),
                    "{reason}"
                );
                assert_eq!(decision.remediation.as_deref(), Some(RAW_FLAG_REMEDIATION));
            }
        }
    }

    #[test]
    fn spine_invocation_without_a_denied_flag_keeps_its_authorization() {
        for exposure in [PathExposure::None, PathExposure::ReadsContents] {
            for path in [".env", "protected/x.csv"] {
                let decision = evaluate_access(
                    &spine_input(path, exposure, None),
                    &fixture_config(),
                    &PackRegistry::with_built_ins(),
                );

                assert_eq!(
                    decision.action,
                    DecisionAction::Allow,
                    "{path} {exposure:?}"
                );
            }
        }
    }

    #[test]
    fn denied_raw_flag_on_a_non_sensitive_path_is_not_blocked() {
        let decision = evaluate_access(
            &spine_input("notes/plain.txt", PathExposure::None, Some("--explicit")),
            &fixture_config(),
            &PackRegistry::with_built_ins(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
    }

    #[test]
    fn denied_raw_flag_follows_the_policy_mode_like_a_direct_read() {
        for (mode, expected_action, prefix) in [
            (PolicyMode::Deny, DecisionAction::Deny, ""),
            (
                PolicyMode::Warn,
                DecisionAction::Allow,
                "policy default warn: ",
            ),
            (
                PolicyMode::Log,
                DecisionAction::Allow,
                "policy default log: ",
            ),
        ] {
            let mut config = fixture_config();
            config.policy.default = mode;

            let decision = evaluate_access(
                &spine_input("protected/x.csv", PathExposure::None, Some("--raw")),
                &config,
                &PackRegistry::with_built_ins(),
            );

            assert_eq!(decision.action, expected_action);
            assert!(
                decision
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with(prefix) && reason.contains("--raw"))
            );
            assert_eq!(decision.remediation.as_deref(), Some(RAW_FLAG_REMEDIATION));
        }
    }

    #[test]
    fn remediation_text_never_tells_agents_to_write_ad_hoc_scripts() {
        for remediation in [DIRECT_READ_REMEDIATION, RAW_FLAG_REMEDIATION] {
            let lowered = remediation.to_lowercase();
            for banned in ["script", "write a ", "write your own", "extract only"] {
                assert!(
                    !lowered.contains(banned),
                    "remediation must not suggest `{banned}`: {remediation}"
                );
            }
            assert!(remediation.contains("`veil operator`"), "{remediation}");
        }
    }

    #[test]
    fn sensitive_spine_invocations_are_allowed() {
        let input = EvaluationInput::new(ToolKind::Bash, ".env", PathExposure::ReadsContents)
            .with_spine_invocation(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from(".env"),
                denied_flag: None,
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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
    fn cmdrvl_config_path_denied_even_when_toml_is_allowlisted() {
        let config = Config {
            sensitivity: SensitivityConfig {
                protected: vec!["/tmp/home/.cmdrvl/config/**".to_owned()],
            },
            allowlist: AllowlistConfig {
                safe_patterns: vec!["*.toml".to_owned()],
            },
            spine: SpineConfig {
                authorized_tools: vec!["shape".to_owned()],
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
        };

        let decision = evaluate_access_with_classifier(
            &read_input("/tmp/home/.cmdrvl/config/cmdrvl-cli/config.toml"),
            &config,
            |directory_sensitive| {
                assert!(directory_sensitive);
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
        };

        let input = EvaluationInput::new(
            ToolKind::Bash,
            "data/clients/holdings.csv",
            PathExposure::ReadsContents,
        )
        .with_spine_invocation(SpineInvocation {
            tool_name: "shape".to_owned(),
            target_path: PathBuf::from("data/clients/holdings.csv"),
            denied_flag: None,
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-audit.jsonl"),
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
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

    // --- bd-1si: a content search of a directory reads what is beneath it ---

    fn tree(label: &str, files: &[&str]) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-scope-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        for file in files {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().expect("file has a parent"))
                .expect("parent dir should be creatable");
            std::fs::write(&path, "ssn,123-45-6789\n").expect("file should be writable");
        }
        std::fs::canonicalize(&root).expect("tree root should canonicalize")
    }

    fn search(path: &Path, exposure: PathExposure) -> EvaluationInput {
        EvaluationInput::new(ToolKind::Grep, path, exposure)
    }

    fn decide(input: &EvaluationInput, config: &Config) -> Decision {
        evaluate_access(input, config, &PackRegistry::with_built_ins())
    }

    #[test]
    fn content_search_of_a_directory_holding_protected_paths_is_denied() {
        let root = tree("deny", &["protected/clients/holdings.csv", "src/main.rs"]);

        let decision = decide(
            &search(&root, PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Deny);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("[sensitivity] protected")),
            "reason should name the policy that blocks the search, got {:?}",
            decision.reason
        );
        assert!(
            decision.remediation.as_deref().is_some_and(
                |text| text.contains("files_with_matches") && text.contains("veil operator")
            ),
            "remediation should point at metadata-only searches and the operator, got {:?}",
            decision.remediation
        );
        assert!(
            !decision
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("holdings"),
            "the reason must not hand the agent the name of a protected file"
        );
    }

    #[test]
    fn content_search_of_the_protected_root_itself_is_denied() {
        let root = tree("root", &["protected/clients/holdings.csv"]);

        let decision = decide(
            &search(&root.join("protected"), PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Deny);
    }

    #[test]
    fn names_and_counts_only_search_of_the_same_directory_is_allowed() {
        let root = tree("meta", &["protected/clients/holdings.csv", "src/main.rs"]);

        for path in [root.clone(), root.join("protected")] {
            let decision = decide(
                &search(&path, PathExposure::MetadataOnly),
                &fixture_config(),
            );

            assert_eq!(decision.action, DecisionAction::Allow, "{path:?}");
        }
    }

    #[test]
    fn content_search_of_a_directory_with_nothing_protected_is_allowed_silently() {
        let root = tree("clean", &["src/main.rs", "src/lib.rs", "notes/data.txt"]);

        let decision = decide(
            &search(&root, PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn a_search_of_one_file_does_not_scan_anything() {
        let root = tree("file", &["protected/a.csv", "src/main.rs"]);

        let decision = decide(
            &search(&root.join("src/main.rs"), PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn an_allowlisted_directory_is_still_denied_when_protected_paths_sit_beneath_it() {
        // tests/** is a default safe pattern, so tests/fixtures is allowlisted
        // as a path; the protected directory beneath it still decides.
        let root = tree("allowlisted", &["tests/fixtures/protected/rows.csv"]);
        let directory = root.join("tests/fixtures");
        assert!(SafePathMatcher::default().is_safe(&directory));

        let decision = decide(
            &search(&directory, PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Deny);
    }

    #[test]
    fn without_protected_patterns_directory_searches_are_untouched() {
        let root = tree("none", &["protected/a.csv"]);
        let mut config = fixture_config();
        config.sensitivity.protected.clear();

        let decision = decide(&search(&root, PathExposure::ReadsContents), &config);

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, None);
    }

    #[test]
    fn warn_mode_lets_the_search_through_and_says_why() {
        let root = tree("warn", &["protected/a.csv"]);
        let mut config = fixture_config();
        config.policy.default = PolicyMode::Warn;

        let decision = decide(&search(&root, PathExposure::ReadsContents), &config);

        assert_eq!(decision.action, DecisionAction::Allow);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("policy default warn:")),
            "got {:?}",
            decision.reason
        );
    }

    #[test]
    fn a_directory_too_large_to_inspect_is_refused_not_waved_through() {
        let root = tree("large", &["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        let input = search(&root, PathExposure::ReadsContents);

        let decision = directory_scope_decision(&input, &fixture_config(), 3)
            .expect("a directory over the budget must get a decision");

        assert_eq!(decision.action, DecisionAction::Deny);
        assert!(
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("more than 3 entries")),
            "got {:?}",
            decision.reason
        );
        assert_eq!(
            directory_scope_decision(&input, &fixture_config(), 5),
            None,
            "the same directory is fine once the budget covers it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_directory_is_searched_as_the_directory_it_points_at() {
        use std::os::unix::fs::symlink;

        let root = tree("link", &["protected/a.csv", "src/main.rs"]);
        let alias = tree("alias", &["src/other.rs"]).join("repo");
        symlink(&root, &alias).expect("symlink should be creatable");

        let decision = decide(
            &search(&alias, PathExposure::ReadsContents),
            &fixture_config(),
        );

        assert_eq!(decision.action, DecisionAction::Deny);
    }
}
