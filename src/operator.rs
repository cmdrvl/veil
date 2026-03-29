#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use veil::allowlist::SafePathMatcher;
use veil::config::{self, Config, PolicyMode};
use veil::evaluator::{EvaluationInput, evaluate_access};
use veil::extract::{PathExposure, extract_read_or_grep_paths};
use veil::packs::PackRegistry;
use veil::types::{Decision, DecisionAction, SensitivityResult, ToolKind};

use crate::cli::{AuditArgs, ConfigArgs, DoctorArgs, PathCommandArgs};
use crate::hooks;

const RECENT_AUDIT_LIMIT: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
enum DoctorStatus {
    Ok,
    ActionNeeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DoctorCheck {
    name: &'static str,
    status: DoctorStatus,
    detail: String,
    remediation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DoctorReport {
    checks: Vec<DoctorCheck>,
}

#[derive(Clone, Debug, PartialEq)]
struct PathInspection {
    input_path: String,
    normalized_path: PathBuf,
    decision: Decision,
    allowlist_pattern: Option<String>,
    protected_pattern: Option<String>,
    sensitivity: Option<SensitivityResult>,
}

enum SettingsPathStatus {
    Resolved(PathBuf),
    Error(String),
}

pub fn run_config(args: &ConfigArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_config_for_repo(&repo_root, args.json)
}

pub fn run_audit(args: &AuditArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    let config = config::load_config(&repo_root)?;
    render_audit_for_path(&config.policy.audit_path, args.json, RECENT_AUDIT_LIMIT)
}

pub fn run_doctor(args: &DoctorArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_doctor_for_repo(&repo_root, args.json)
}

pub fn run_test(args: &PathCommandArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_test_for_repo(&repo_root, &args.path, args.json)
}

pub fn run_explain(args: &PathCommandArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_explain_for_repo(&repo_root, &args.path, args.json)
}

fn render_config_for_repo(
    repo_root: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let config = config::load_config(repo_root)?;

    if json_output {
        Ok(serde_json::to_string_pretty(&config_json(&config))?)
    } else {
        Ok(render_config_human(&config))
    }
}

fn render_audit_for_path(
    audit_path: &Path,
    json_output: bool,
    limit: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let entries = read_recent_audit_entries(audit_path, limit)?;

    if json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "path": audit_path.display().to_string(),
            "entries": entries,
        }))?)
    } else {
        Ok(render_audit_human(audit_path, &entries))
    }
}

fn render_doctor_for_repo(
    repo_root: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let report = build_doctor_report(
        repo_root,
        match hooks::default_settings_path() {
            Ok(path) => SettingsPathStatus::Resolved(path),
            Err(error) => SettingsPathStatus::Error(error.to_string()),
        },
    );

    if json_output {
        Ok(serde_json::to_string_pretty(&report.to_json_value())?)
    } else {
        Ok(render_doctor_human(&report))
    }
}

fn render_test_for_repo(
    repo_root: &Path,
    path: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let inspection = inspect_path(repo_root, path)?;

    if json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "input_path": inspection.input_path,
            "normalized_path": inspection.normalized_path.display().to_string(),
            "decision": decision_json(&inspection.decision),
        }))?)
    } else {
        Ok(render_test_human(&inspection))
    }
}

fn render_explain_for_repo(
    repo_root: &Path,
    path: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let inspection = inspect_path(repo_root, path)?;

    if json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "input_path": inspection.input_path,
            "normalized_path": inspection.normalized_path.display().to_string(),
            "match": {
                "kind": inspection.match_kind(),
                "allowlist_pattern": inspection.allowlist_pattern,
                "protected_pattern": inspection.protected_pattern,
                "pack": inspection.sensitivity.as_ref().map(|value| value.pack.clone()),
                "severity": inspection.sensitivity.as_ref().map(|value| severity_name(&value.severity)),
                "confidence": inspection.sensitivity.as_ref().map(|value| value.confidence),
                "directory_sensitive": inspection.sensitivity.as_ref().map(|value| value.directory_sensitive),
            },
            "decision": decision_json(&inspection.decision),
        }))?)
    } else {
        Ok(render_explain_human(&inspection))
    }
}

fn config_json(config: &Config) -> Value {
    json!({
        "sensitivity": {
            "protected": config.sensitivity.protected,
        },
        "allowlist": {
            "safe_patterns": config.allowlist.safe_patterns,
        },
        "spine": {
            "authorized_tools": config.spine.authorized_tools,
        },
        "policy": {
            "default": policy_mode_name(&config.policy.default),
            "audit_log": config.policy.audit_log,
            "audit_path": config.policy.audit_path.display().to_string(),
        },
    })
}

fn render_config_human(config: &Config) -> String {
    let mut output = String::new();
    output.push_str("Policy\n");
    let _ = writeln!(
        output,
        "  default: {}",
        policy_mode_name(&config.policy.default)
    );
    let _ = writeln!(output, "  audit_log: {}", config.policy.audit_log);
    let _ = writeln!(
        output,
        "  audit_path: {}",
        config.policy.audit_path.display()
    );

    render_string_list(
        &mut output,
        "Sensitivity",
        "protected",
        &config.sensitivity.protected,
    );
    render_string_list(
        &mut output,
        "Allowlist",
        "safe_patterns",
        &config.allowlist.safe_patterns,
    );
    render_string_list(
        &mut output,
        "Spine",
        "authorized_tools",
        &config.spine.authorized_tools,
    );

    output.trim_end().to_owned()
}

fn render_string_list(output: &mut String, heading: &str, label: &str, values: &[String]) {
    let _ = writeln!(output, "{heading}");
    let _ = writeln!(output, "  {label}:");
    if values.is_empty() {
        output.push_str("    - (none)\n");
        return;
    }

    for value in values {
        let _ = writeln!(output, "    - {value}");
    }
}

fn read_recent_audit_entries(path: &Path, limit: usize) -> io::Result<Vec<Value>> {
    if limit == 0 || !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(path)?;
    let mut recent = VecDeque::with_capacity(limit);

    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let value = serde_json::from_str::<Value>(&line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid audit JSONL at {} line {}: {error}",
                    path.display(),
                    line_number + 1
                ),
            )
        })?;

        if recent.len() == limit {
            recent.pop_front();
        }
        recent.push_back(value);
    }

    Ok(recent.into_iter().collect())
}

fn render_audit_human(path: &Path, entries: &[Value]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Audit");
    let _ = writeln!(output, "  path: {}", path.display());
    let _ = writeln!(output, "  entries: {}", entries.len());

    if entries.is_empty() {
        output.push_str("  recent:\n    - (none)\n");
        return output.trim_end().to_owned();
    }

    output.push_str("  recent:\n");
    for entry in entries {
        let _ = writeln!(output, "    - {}", audit_entry_summary(entry));
    }

    output.trim_end().to_owned()
}

fn audit_entry_summary(entry: &Value) -> String {
    let ts = string_field(entry, "ts").unwrap_or("<unknown-ts>");
    let tool = string_field(entry, "tool").unwrap_or("<unknown-tool>");
    let decision = string_field(entry, "decision").unwrap_or("<unknown-decision>");
    let path = string_field(entry, "path").unwrap_or("<unknown-path>");
    let mut summary = format!("{ts} {decision} {tool} {path}");

    let sensitivity = string_field(entry, "sensitivity");
    let confidence = entry.get("confidence").and_then(Value::as_f64);
    if sensitivity.is_some() || confidence.is_some() {
        summary.push_str(" [");
        if let Some(sensitivity) = sensitivity {
            summary.push_str(sensitivity);
        }
        if let Some(confidence) = confidence {
            if sensitivity.is_some() {
                summary.push_str(", ");
            }
            let _ = write!(summary, "{confidence:.2}");
        }
        summary.push(']');
    }

    if let Some(reason) = string_field(entry, "reason") {
        let _ = write!(summary, " — {reason}");
    }

    summary
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn build_doctor_report(repo_root: &Path, settings_status: SettingsPathStatus) -> DoctorReport {
    let mut checks = Vec::new();

    match config::load_config(repo_root) {
        Ok(config) => {
            checks.push(DoctorCheck {
                name: "config",
                status: DoctorStatus::Ok,
                detail: format!("loaded merged config for {}", repo_root.display()),
                remediation: None,
            });
            checks.push(DoctorCheck {
                name: "audit",
                status: DoctorStatus::Ok,
                detail: audit_check_detail(&config.policy.audit_path),
                remediation: None,
            });
        }
        Err(error) => checks.push(DoctorCheck {
            name: "config",
            status: DoctorStatus::ActionNeeded,
            detail: format!(
                "failed to load merged config for {}: {error}",
                repo_root.display()
            ),
            remediation: Some(
                "fix the invalid config file or environment overrides, then rerun `veil doctor`"
                    .to_owned(),
            ),
        }),
    }

    match settings_status {
        SettingsPathStatus::Resolved(path) => match hooks::has_managed_hooks(&path) {
            Ok(true) => checks.push(DoctorCheck {
                name: "hooks",
                status: DoctorStatus::Ok,
                detail: format!(
                    "managed Read/Grep/Bash hooks are installed in {}",
                    path.display()
                ),
                remediation: None,
            }),
            Ok(false) => checks.push(DoctorCheck {
                name: "hooks",
                status: DoctorStatus::ActionNeeded,
                detail: missing_hook_detail(&path),
                remediation: Some(
                    "run `veil install` to add the managed PreToolUse hook entries".to_owned(),
                ),
            }),
            Err(error) => checks.push(DoctorCheck {
                name: "hooks",
                status: DoctorStatus::ActionNeeded,
                detail: format!(
                    "failed to inspect Claude settings at {}: {error}",
                    path.display()
                ),
                remediation: Some("repair the settings file or rerun `veil install`".to_owned()),
            }),
        },
        SettingsPathStatus::Error(message) => checks.push(DoctorCheck {
            name: "hooks",
            status: DoctorStatus::ActionNeeded,
            detail: format!("could not resolve Claude settings path: {message}"),
            remediation: Some(
                "set `VEIL_CLAUDE_SETTINGS_PATH` or `HOME`, then rerun `veil doctor`".to_owned(),
            ),
        }),
    }

    DoctorReport { checks }
}

fn audit_check_detail(path: &Path) -> String {
    if path.exists() {
        format!("audit log exists at {}", path.display())
    } else {
        format!("audit log will be written to {}", path.display())
    }
}

fn missing_hook_detail(path: &Path) -> String {
    if path.exists() {
        format!("managed veil hooks are missing from {}", path.display())
    } else {
        format!("Claude settings file does not exist at {}", path.display())
    }
}

fn render_doctor_human(report: &DoctorReport) -> String {
    let mut output = String::new();
    let overall = if report.is_healthy() {
        "ok"
    } else {
        "action_needed"
    };
    let _ = writeln!(output, "Doctor");
    let _ = writeln!(output, "  overall: {overall}");

    for check in &report.checks {
        let status = match check.status {
            DoctorStatus::Ok => "ok",
            DoctorStatus::ActionNeeded => "action_needed",
        };
        let _ = writeln!(output, "  - {} [{}] {}", check.name, status, check.detail);
        if let Some(remediation) = &check.remediation {
            let _ = writeln!(output, "    fix: {remediation}");
        }
    }

    output.trim_end().to_owned()
}

fn render_test_human(inspection: &PathInspection) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Test");
    let _ = writeln!(output, "  input: {}", inspection.input_path);
    let _ = writeln!(
        output,
        "  normalized: {}",
        inspection.normalized_path.display()
    );
    let _ = writeln!(
        output,
        "  decision: {}",
        decision_action_name(&inspection.decision.action)
    );
    let _ = writeln!(
        output,
        "  reason: {}",
        inspection.decision.reason.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  confidence: {}",
        inspection
            .decision
            .confidence
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "(none)".to_owned())
    );
    let _ = writeln!(
        output,
        "  remediation: {}",
        inspection
            .decision
            .remediation
            .as_deref()
            .unwrap_or("(none)")
    );

    output.trim_end().to_owned()
}

fn render_explain_human(inspection: &PathInspection) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Explain");
    let _ = writeln!(output, "  input: {}", inspection.input_path);
    let _ = writeln!(
        output,
        "  normalized: {}",
        inspection.normalized_path.display()
    );
    let _ = writeln!(output, "  matched_by: {}", inspection.match_kind());
    let _ = writeln!(
        output,
        "  allowlist_pattern: {}",
        inspection.allowlist_pattern.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  protected_pattern: {}",
        inspection.protected_pattern.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  pack: {}",
        inspection
            .sensitivity
            .as_ref()
            .map(|value| value.pack.as_str())
            .unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  severity: {}",
        inspection
            .sensitivity
            .as_ref()
            .map(|value| severity_name(&value.severity))
            .unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  directory_sensitive: {}",
        inspection
            .sensitivity
            .as_ref()
            .is_some_and(|value| value.directory_sensitive)
    );
    let _ = writeln!(
        output,
        "  decision: {}",
        decision_action_name(&inspection.decision.action)
    );
    let _ = writeln!(
        output,
        "  reason: {}",
        inspection.decision.reason.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(
        output,
        "  remediation: {}",
        inspection
            .decision
            .remediation
            .as_deref()
            .unwrap_or("(none)")
    );

    output.trim_end().to_owned()
}

fn inspect_path(
    repo_root: &Path,
    raw_path: &Path,
) -> Result<PathInspection, Box<dyn std::error::Error>> {
    let config = config::load_config(repo_root)?;
    let normalized_path = normalize_cli_path(raw_path, repo_root).ok_or_else(|| {
        format!(
            "could not normalize `{}` with the hook-mode path hardening pipeline",
            raw_path.display()
        )
    })?;
    let allowlist_pattern =
        first_matching_pattern(&config.allowlist.safe_patterns, &normalized_path)
            .map(str::to_owned);
    let protected_pattern =
        first_matching_pattern(&config.sensitivity.protected, &normalized_path).map(str::to_owned);
    let directory_sensitive = protected_pattern.is_some();
    let registry = PackRegistry::with_built_ins();
    let sensitivity = registry.classify(&normalized_path, directory_sensitive);
    let decision = evaluate_access(
        &EvaluationInput::new(
            ToolKind::Read,
            normalized_path.clone(),
            PathExposure::ReadsContents,
        ),
        &config,
        &registry,
    );

    Ok(PathInspection {
        input_path: raw_path.to_string_lossy().into_owned(),
        normalized_path,
        decision,
        allowlist_pattern,
        protected_pattern,
        sensitivity,
    })
}

fn normalize_cli_path(raw_path: &Path, cwd: &Path) -> Option<PathBuf> {
    let extraction = extract_read_or_grep_paths(
        ToolKind::Read,
        &json!({ "file_path": raw_path.to_string_lossy() }).to_string(),
        cwd,
    );

    extraction.candidates.into_iter().next()
}

fn first_matching_pattern<'a>(patterns: &'a [String], path: &Path) -> Option<&'a str> {
    patterns.iter().find_map(|pattern| {
        SafePathMatcher::from_patterns([pattern.as_str()])
            .is_safe(path)
            .then_some(pattern.as_str())
    })
}

fn decision_json(decision: &Decision) -> Value {
    json!({
        "action": decision_action_name(&decision.action),
        "reason": decision.reason,
        "confidence": decision.confidence,
        "remediation": decision.remediation,
    })
}

fn decision_action_name(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "allow",
        DecisionAction::Deny => "deny",
    }
}

fn policy_mode_name(mode: &PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Deny => "deny",
        PolicyMode::Warn => "warn",
        PolicyMode::Log => "log",
    }
}

fn severity_name(severity: &veil::types::SensitivitySeverity) -> &'static str {
    match severity {
        veil::types::SensitivitySeverity::Low => "low",
        veil::types::SensitivitySeverity::Medium => "medium",
        veil::types::SensitivitySeverity::High => "high",
        veil::types::SensitivitySeverity::Critical => "critical",
    }
}

impl DoctorReport {
    fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == DoctorStatus::Ok)
    }

    fn to_json_value(&self) -> Value {
        json!({
            "ok": self.is_healthy(),
            "checks": self.checks.iter().map(|check| {
                json!({
                    "name": check.name,
                    "status": match check.status {
                        DoctorStatus::Ok => "ok",
                        DoctorStatus::ActionNeeded => "action_needed",
                    },
                    "detail": check.detail,
                    "remediation": check.remediation,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

impl PathInspection {
    fn match_kind(&self) -> &'static str {
        if self.allowlist_pattern.is_some() {
            "allowlist"
        } else if self.sensitivity.is_some() {
            "pack"
        } else if self.protected_pattern.is_some() {
            "protected_directory"
        } else {
            "none"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        env::temp_dir().join(format!("veil-operator-{label}-{nanos}"))
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory should be creatable");
        }

        fs::write(path, contents).expect("fixture file should be writable");
    }

    #[test]
    fn config_json_output_reflects_merged_config() {
        let repo_root = unique_temp_dir("config-json");
        write_file(
            &repo_root.join(".veil.toml"),
            r#"
            [sensitivity]
            protected = ["data/**"]

            [policy]
            default = "warn"
            audit_log = false
            audit_path = "/tmp/veil-audit.jsonl"
            "#,
        );

        let rendered =
            render_config_for_repo(&repo_root, true).expect("config rendering should succeed");
        let value: Value =
            serde_json::from_str(&rendered).expect("config JSON output should parse");

        assert_eq!(value["sensitivity"]["protected"], json!(["data/**"]));
        assert_eq!(value["policy"]["default"], "warn");
        assert_eq!(value["policy"]["audit_log"], false);
        assert_eq!(value["policy"]["audit_path"], "/tmp/veil-audit.jsonl");
    }

    #[test]
    fn audit_human_output_lists_recent_entries() {
        let audit_path = unique_temp_dir("audit-human").join("audit.jsonl");
        write_file(
            &audit_path,
            concat!(
                "{\"ts\":\"2026-03-01T16:00:00Z\",\"tool\":\"Read\",\"path\":\"data/a.csv\",\"decision\":\"deny\",\"reason\":\"blocked\",\"sensitivity\":\"data.tabular\",\"confidence\":0.95}\n",
                "{\"ts\":\"2026-03-01T16:05:00Z\",\"tool\":\"Bash\",\"path\":\"reports/out.json\",\"decision\":\"allow\"}\n"
            ),
        );

        let rendered =
            render_audit_for_path(&audit_path, false, 20).expect("audit rendering should succeed");

        assert!(rendered.contains("Audit"));
        assert!(rendered.contains("entries: 2"));
        assert!(rendered.contains("2026-03-01T16:00:00Z deny Read data/a.csv"));
        assert!(rendered.contains("blocked"));
    }

    #[test]
    fn audit_json_output_includes_recent_entries() {
        let audit_path = unique_temp_dir("audit-json").join("audit.jsonl");
        write_file(
            &audit_path,
            "{\"ts\":\"2026-03-01T16:00:00Z\",\"tool\":\"Read\",\"path\":\"data/a.csv\",\"decision\":\"deny\"}\n",
        );

        let rendered =
            render_audit_for_path(&audit_path, true, 20).expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&rendered).expect("audit JSON should parse");

        assert_eq!(value["path"], audit_path.display().to_string());
        assert_eq!(value["entries"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["entries"][0]["tool"], "Read");
    }

    #[test]
    fn doctor_human_output_reports_actionable_missing_hooks() {
        let repo_root = unique_temp_dir("doctor-missing-hooks");
        let settings_path = repo_root.join("claude/settings.json");

        let rendered = render_doctor_human(&build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
        ));

        assert!(rendered.contains("Doctor"));
        assert!(rendered.contains("config [ok]"));
        assert!(rendered.contains("hooks [action_needed]"));
        assert!(rendered.contains("run `veil install`"));
    }

    #[test]
    fn doctor_json_output_reports_healthy_when_hooks_are_installed() {
        let repo_root = unique_temp_dir("doctor-json");
        let settings_path = repo_root.join("claude/settings.json");
        write_file(
            &settings_path,
            r#"{
              "hooks": {
                "PreToolUse": [
                  { "matcher": "Read", "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }] },
                  { "matcher": "Grep", "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }] },
                  { "matcher": "Bash", "hooks": [{ "type": "command", "command": "$HOME/.local/bin/veil" }] }
                ]
              }
            }"#,
        );

        let value = build_doctor_report(&repo_root, SettingsPathStatus::Resolved(settings_path))
            .to_json_value();

        assert_eq!(value["ok"], true);
        assert_eq!(
            value["checks"]
                .as_array()
                .expect("checks should be an array")
                .iter()
                .filter(|check| check["status"] == "ok")
                .count(),
            3
        );
    }

    #[test]
    fn test_command_human_output_covers_allowlisted_paths() {
        let repo_root = unique_temp_dir("test-human");
        let rendered = render_test_for_repo(&repo_root, Path::new("README.md"), false)
            .expect("test rendering should succeed");

        assert!(rendered.contains("Test"));
        assert!(rendered.contains("decision: allow"));
        assert!(rendered.contains(&format!(
            "normalized: {}",
            repo_root.join("README.md").display()
        )));
    }

    #[test]
    fn test_command_json_output_covers_unsensitive_paths() {
        let repo_root = unique_temp_dir("test-json");
        let value: Value = serde_json::from_str(
            &render_test_for_repo(&repo_root, Path::new("src/app.rs"), true)
                .expect("test JSON rendering should succeed"),
        )
        .expect("test JSON should parse");

        assert_eq!(value["decision"]["action"], "allow");
        assert_eq!(value["decision"]["reason"], Value::Null);
        assert_eq!(
            value["normalized_path"],
            repo_root.join("src/app.rs").display().to_string()
        );
    }

    #[test]
    fn explain_command_human_output_covers_protected_sensitive_paths() {
        let repo_root = unique_temp_dir("explain-human");
        write_file(
            &repo_root.join(".veil.toml"),
            r#"
            [sensitivity]
            protected = ["protected/**"]
            "#,
        );

        let rendered =
            render_explain_for_repo(&repo_root, Path::new("protected/dataset.tsv"), false)
                .expect("explain rendering should succeed");

        assert!(rendered.contains("Explain"));
        assert!(rendered.contains("matched_by: pack"));
        assert!(rendered.contains("pack: data.tabular"));
        assert!(rendered.contains("protected_pattern: protected/**"));
        assert!(rendered.contains("decision: deny"));
    }

    #[test]
    fn explain_command_json_output_covers_allowlisted_paths() {
        let repo_root = unique_temp_dir("explain-json");
        let value: Value = serde_json::from_str(
            &render_explain_for_repo(&repo_root, Path::new("README.md"), true)
                .expect("explain JSON rendering should succeed"),
        )
        .expect("explain JSON should parse");

        assert_eq!(value["match"]["kind"], "allowlist");
        assert_eq!(value["match"]["allowlist_pattern"], "*.md");
        assert_eq!(value["decision"]["action"], "allow");
    }
}
