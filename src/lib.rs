#![forbid(unsafe_code)]

pub mod allowlist;
pub mod audit;
pub mod config;
pub mod evaluator;
pub mod extract;
pub mod hook;
pub mod packs;
pub mod render;
pub mod spine;
pub mod types;

use std::error::Error;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use allowlist::SafePathMatcher;
use audit::{AuditRecord, append_audit_record};
use config::load_config;
use evaluator::{EvaluationInput, evaluate_access};
use extract::{PathExposure, extract_bash_read_paths, extract_read_or_grep_paths};
use hook::parse_hook_input;
use packs::PackRegistry;
use render::{RenderedDecision, render_decision};
use serde_json::Value;
use spine::detect_spine_invocation;
use types::{Decision, DecisionAction, HookInput, ToolKind};

#[derive(Clone, Debug)]
struct CandidateOutcome {
    path: PathBuf,
    decision: Decision,
    sensitivity: Option<String>,
}

pub fn run() -> Result<u8, Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_io(stdin.lock(), &mut stdout, &mut stderr)?;
    Ok(0)
}

fn run_with_io<R: Read, W: Write, E: Write>(
    mut reader: R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<()> {
    let mut input = String::new();
    reader.read_to_string(&mut input)?;
    let hook_input = parse_hook_input(&input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;

    let rendered = execute_hook_mode(&hook_input)?;
    stdout.write_all(rendered.stdout.as_bytes())?;
    stdout.write_all(b"\n")?;

    if let Some(message) = rendered.stderr.as_deref() {
        stderr.write_all(message.as_bytes())?;
        stderr.write_all(b"\n")?;
    }

    stdout.flush()?;
    stderr.flush()
}

fn execute_hook_mode(hook_input: &HookInput) -> io::Result<RenderedDecision> {
    let config = load_config(&hook_input.cwd)?;
    let registry = PackRegistry::with_built_ins();
    let extraction = extract_candidates(hook_input);
    let outcomes = evaluate_candidates(hook_input, &config, &registry, &extraction);
    let decision = select_decision(&outcomes);
    let mut rendered = render_decision(hook_input.protocol, &decision);

    if config.policy.audit_log
        && let Err(error) = append_audit_records(&config.policy.audit_path, hook_input, &outcomes)
    {
        append_stderr_line(&mut rendered, format!("Audit logging failed: {error}"));
    }

    Ok(rendered)
}

fn extract_candidates(hook_input: &HookInput) -> extract::PathExtraction {
    match hook_input.tool {
        ToolKind::Read | ToolKind::Grep => {
            extract_read_or_grep_paths(hook_input.tool, &hook_input.raw_args, &hook_input.cwd)
        }
        ToolKind::Bash => command_from_raw_args(&hook_input.raw_args)
            .map(|command| extract_bash_read_paths(&command, &hook_input.cwd))
            .unwrap_or_else(no_path_extraction),
        ToolKind::Unknown => no_path_extraction(),
    }
}

fn no_path_extraction() -> extract::PathExtraction {
    extract::PathExtraction {
        exposure: PathExposure::None,
        candidates: Vec::new(),
    }
}

fn command_from_raw_args(raw_args: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw_args)
        .ok()?
        .get("command")?
        .as_str()
        .map(str::to_owned)
}

fn evaluate_candidates(
    hook_input: &HookInput,
    config: &config::Config,
    registry: &PackRegistry,
    extraction: &extract::PathExtraction,
) -> Vec<CandidateOutcome> {
    let protected_matcher = SafePathMatcher::from_patterns(config.sensitivity.protected.iter());
    let spine_invocation = detect_spine(hook_input, config);
    let mut candidates = extraction.candidates.clone();

    if candidates.is_empty()
        && let Some(invocation) = spine_invocation.as_ref()
    {
        candidates.push(invocation.target_path.clone());
    }

    candidates
        .iter()
        .map(|path| {
            let directory_sensitive = protected_matcher.is_safe(path);
            let sensitivity = registry
                .classify(path, directory_sensitive)
                .map(|result| result.pack);
            let mut evaluation_input =
                EvaluationInput::new(hook_input.tool, path.clone(), extraction.exposure);

            if let Some(invocation) = spine_invocation.clone() {
                evaluation_input = evaluation_input.with_spine_invocation(invocation);
            }

            CandidateOutcome {
                path: path.clone(),
                decision: evaluate_access(&evaluation_input, config, registry),
                sensitivity,
            }
        })
        .collect()
}

fn detect_spine(hook_input: &HookInput, config: &config::Config) -> Option<spine::SpineInvocation> {
    if hook_input.tool != ToolKind::Bash {
        return None;
    }

    let command = command_from_raw_args(&hook_input.raw_args)?;
    detect_spine_invocation(&command, &config.spine.authorized_tools, &hook_input.cwd)
}

fn select_decision(outcomes: &[CandidateOutcome]) -> Decision {
    if let Some(outcome) = outcomes
        .iter()
        .find(|outcome| outcome.decision.action == DecisionAction::Deny)
    {
        return outcome.decision.clone();
    }

    outcomes
        .iter()
        .find(|outcome| outcome.decision.reason.is_some())
        .map(|outcome| outcome.decision.clone())
        .unwrap_or_else(allow_silent_decision)
}

fn allow_silent_decision() -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: None,
        severity: None,
        confidence: None,
        remediation: None,
    }
}

fn append_audit_records(
    audit_path: &Path,
    hook_input: &HookInput,
    outcomes: &[CandidateOutcome],
) -> io::Result<()> {
    if outcomes.is_empty() {
        return Ok(());
    }

    let timestamp = audit_timestamp();

    for outcome in outcomes {
        append_audit_record(
            audit_path,
            &AuditRecord {
                ts: timestamp.clone(),
                tool: audit_tool_name(hook_input.tool).to_owned(),
                path: outcome.path.to_string_lossy().into_owned(),
                decision: decision_name(&outcome.decision.action).to_owned(),
                reason: outcome.decision.reason.clone(),
                sensitivity: outcome.sensitivity.clone(),
                confidence: outcome.decision.confidence,
                session_id: hook_input.session_id.clone(),
            },
        )?;
    }

    Ok(())
}

fn audit_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "0".to_owned(),
    }
}

fn audit_tool_name(tool: ToolKind) -> &'static str {
    match tool {
        ToolKind::Read => "Read",
        ToolKind::Grep => "Grep",
        ToolKind::Bash => "Bash",
        ToolKind::Unknown => "Unknown",
    }
}

fn decision_name(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "allow",
        DecisionAction::Deny => "deny",
    }
}

fn append_stderr_line(rendered: &mut RenderedDecision, line: String) {
    match rendered.stderr.as_mut() {
        Some(stderr) if !stderr.is_empty() => {
            stderr.push('\n');
            stderr.push_str(&line);
        }
        Some(stderr) => stderr.push_str(&line),
        None => rendered.stderr = Some(line),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::BufRead;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("veil-{name}-{nanos}"))
    }

    fn configure_repo(repo_root: &Path, protected_patterns: &[&str]) -> PathBuf {
        fs::create_dir_all(repo_root).expect("repo root should be created");

        let audit_path = repo_root.join("state").join("audit.jsonl");
        let protected = protected_patterns
            .iter()
            .map(|pattern| format!("\"{pattern}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "[sensitivity]\nprotected = [{protected}]\n\n[policy]\ndefault = \"deny\"\naudit_log = true\naudit_path = \"{}\"\n",
            audit_path.to_string_lossy().replace('\\', "\\\\")
        );

        fs::write(repo_root.join(".veil.toml"), config).expect("config should be written");
        audit_path
    }

    fn read_audit_records(path: &Path) -> Vec<Value> {
        let file = fs::File::open(path).expect("audit file should exist");
        io::BufReader::new(file)
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(&line.expect("audit line should be readable"))
                    .expect("audit line should parse")
            })
            .collect()
    }

    #[test]
    fn run_with_io_allows_authorized_spine_command_and_audits_it() {
        let repo_root = unique_temp_dir("hook-allow");
        let audit_path = configure_repo(&repo_root, &["protected/**"]);
        fs::create_dir_all(repo_root.join("protected")).expect("protected dir should exist");
        fs::write(repo_root.join("protected").join("secret.bin"), "top secret")
            .expect("fixture file should be written");

        let input = format!(
            r#"{{
                "session_id":"gemini-session",
                "cwd":"{}",
                "hook_event_name":"BeforeTool",
                "tool_name":"run_shell_command",
                "tool_input":{{"command":"shape protected/secret.bin","description":"Summarize metadata only"}}
            }}"#,
            repo_root.display()
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_with_io(input.as_bytes(), &mut stdout, &mut stderr)
            .expect("hook pipeline should succeed");

        assert_eq!(
            String::from_utf8(stdout).expect("stdout should be UTF-8"),
            "{\"decision\":\"allow\"}\n"
        );
        assert!(stderr.is_empty());

        let records = read_audit_records(&audit_path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tool"], "Bash");
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["session_id"], "gemini-session");
        let recorded_path = Path::new(
            records[0]["path"]
                .as_str()
                .expect("audit path should be recorded as a string"),
        );
        assert!(recorded_path.ends_with(Path::new("protected").join("secret.bin")));
    }

    #[test]
    fn run_with_io_denies_direct_read_after_path_hardening_and_audits_it() {
        let repo_root = unique_temp_dir("hook-deny");
        let audit_path = configure_repo(&repo_root, &["protected/**"]);
        fs::create_dir_all(repo_root.join("protected").join("nested"))
            .expect("nested dir should exist");
        fs::write(repo_root.join("protected").join("secret.bin"), "classified")
            .expect("fixture file should be written");

        let input = format!(
            r#"{{
                "session_id":"claude-session",
                "cwd":"{}",
                "hook_event_name":"PreToolUse",
                "tool_name":"Read",
                "tool_input":{{"file_path":"protected/nested/../secret.bin"}}
            }}"#,
            repo_root.display()
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_with_io(input.as_bytes(), &mut stdout, &mut stderr)
            .expect("hook pipeline should succeed");

        assert_eq!(
            String::from_utf8(stdout).expect("stdout should be UTF-8"),
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"direct read inside a protected directory is blocked by policy default\"}}\n"
        );
        let stderr = String::from_utf8(stderr).expect("stderr should be UTF-8");
        assert!(stderr.contains("Sensitive file access blocked"));
        assert!(!stderr.contains("nested/.."));

        let records = read_audit_records(&audit_path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tool"], "Read");
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["session_id"], "claude-session");
        let recorded_path = Path::new(
            records[0]["path"]
                .as_str()
                .expect("audit path should be recorded as a string"),
        );
        assert!(recorded_path.ends_with(Path::new("protected").join("secret.bin")));
    }

    #[test]
    fn run_with_io_rejects_invalid_hook_payloads() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"unexpected":true}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("invalid hook payload should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_io_rejects_malformed_copilot_tool_args() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"cwd":"/tmp","toolName":"view","toolArgs":"not-json"}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("malformed Copilot toolArgs should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_io_rejects_malformed_snake_case_tool_input() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":"not-json"}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("malformed snake-case tool_input should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }
}
