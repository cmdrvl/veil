#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use veil::allowlist::SafePathMatcher;
use veil::config::{self, Config, PolicyMode};
use veil::evaluator::{EvaluationInput, evaluate_access};
use veil::extract::{PathExposure, extract_read_or_grep_paths};
use veil::packs::{BUILTIN_PACK_NAMES, PackRegistry};
use veil::types::{Decision, DecisionAction, SensitivityResult, ToolKind};

use crate::cli::{
    AuditArgs, ConfigArgs, DirCommandArgs, DoctorArgs, JsonOutputArgs, PathCommandArgs,
};
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

#[derive(Clone, Debug, PartialEq)]
struct OperatorGuide {
    configured_authorized_tools: Vec<String>,
    tools: Vec<AuthorizedToolReference>,
}

#[derive(Clone, Debug, PartialEq)]
struct AuthorizedToolReference {
    configured_as: String,
    status: ToolReferenceStatus,
}

#[derive(Clone, Debug, PartialEq)]
enum ToolReferenceStatus {
    Available { manifest: Value },
    Missing { reason: String },
    Error { reason: String },
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

pub fn run_operator(args: &JsonOutputArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_operator_for_repo(&repo_root, args.json)
}

pub fn run_test(args: &PathCommandArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_test_for_repo(&repo_root, &args.path, args.json)
}

pub fn run_explain(args: &PathCommandArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_explain_for_repo(&repo_root, &args.path, args.json)
}

pub fn run_scan(args: &DirCommandArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    render_scan_for_repo(&repo_root, &args.dir, args.json)
}

pub fn run_packs(args: &JsonOutputArgs) -> Result<String, Box<dyn std::error::Error>> {
    render_packs(args.json)
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

fn render_operator_for_repo(
    repo_root: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let config = config::load_config(repo_root)?;
    let guide = build_operator_guide(&config);

    if json_output {
        Ok(serde_json::to_string_pretty(&guide.to_json_value())?)
    } else {
        Ok(render_operator_human(&guide))
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

fn render_scan_for_repo(
    repo_root: &Path,
    dir: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let scan_root = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        repo_root.join(dir)
    };
    let files = collect_scan_files(&scan_root)?;
    let inspections = files
        .into_iter()
        .map(|path| {
            let input_path = path
                .strip_prefix(repo_root)
                .map_or_else(|_| path.clone(), Path::to_path_buf);
            inspect_path(repo_root, &input_path)
        })
        .collect::<Result<Vec<_>, _>>()?;

    if json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "root": scan_root.display().to_string(),
            "files": inspections.iter().map(scan_entry_json).collect::<Vec<_>>(),
        }))?)
    } else {
        Ok(render_scan_human(&scan_root, &inspections))
    }
}

fn render_packs(json_output: bool) -> Result<String, Box<dyn std::error::Error>> {
    let inventory = built_in_pack_inventory();

    if json_output {
        Ok(serde_json::to_string_pretty(&json!({
            "packs": inventory.iter().map(|(name, description)| {
                json!({
                    "name": name,
                    "description": description,
                })
            }).collect::<Vec<_>>(),
        }))?)
    } else {
        Ok(render_packs_human(&inventory))
    }
}

fn build_operator_guide(config: &Config) -> OperatorGuide {
    OperatorGuide {
        configured_authorized_tools: config.spine.authorized_tools.clone(),
        tools: config
            .spine
            .authorized_tools
            .iter()
            .map(|configured_tool| describe_authorized_tool(configured_tool))
            .collect(),
    }
}

fn describe_authorized_tool(configured_tool: &str) -> AuthorizedToolReference {
    let describe_command = format!("{configured_tool} --describe");
    let (program, args) = match describe_command_parts(configured_tool) {
        Ok(parts) => parts,
        Err(reason) => {
            return AuthorizedToolReference {
                configured_as: configured_tool.to_owned(),
                status: ToolReferenceStatus::Error { reason },
            };
        }
    };

    let mut command = Command::new(&program);
    command.args(args).arg("--describe");

    let status = match command.output() {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<Value>(&output.stdout) {
                Ok(manifest) => ToolReferenceStatus::Available { manifest },
                Err(error) => ToolReferenceStatus::Error {
                    reason: format!("`{describe_command}` returned invalid JSON: {error}"),
                },
            }
        }
        Ok(output) => ToolReferenceStatus::Error {
            reason: format_describe_failure(&describe_command, &output.status, &output.stderr),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => ToolReferenceStatus::Missing {
            reason: format!("`{program}` was not found while running `{describe_command}`"),
        },
        Err(error) => ToolReferenceStatus::Error {
            reason: format!("failed to run `{describe_command}`: {error}"),
        },
    };

    AuthorizedToolReference {
        configured_as: configured_tool.to_owned(),
        status,
    }
}

fn describe_command_parts(configured_tool: &str) -> Result<(String, Vec<String>), String> {
    let parts = shlex::split(configured_tool)
        .ok_or_else(|| format!("could not parse configured tool command `{configured_tool}`"))?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| format!("configured tool command `{configured_tool}` is empty"))?;

    Ok((program.clone(), args.to_vec()))
}

fn format_describe_failure(
    command: &str,
    status: &std::process::ExitStatus,
    stderr: &[u8],
) -> String {
    let exit = status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| format!("exit {code}"),
    );
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();

    if stderr.is_empty() {
        format!("`{command}` failed with {exit}")
    } else {
        format!("`{command}` failed with {exit}: {stderr}")
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

fn render_operator_human(guide: &OperatorGuide) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Operator");
    let _ = writeln!(
        output,
        "  guidance: use these authorized spine tools instead of a direct read"
    );
    let _ = writeln!(output, "  rerun_with_json: veil operator --json");
    let _ = writeln!(output, "  configured: {}", guide.tools.len());
    let _ = writeln!(output, "  available: {}", guide.available_count());
    let _ = writeln!(output, "  unavailable: {}", guide.unavailable_count());

    if guide.tools.is_empty() {
        let _ = writeln!(output, "  tools: (none)");
        return output.trim_end().to_owned();
    }

    for tool in &guide.tools {
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "  - {} [{}]",
            tool.display_name(),
            tool.status.label()
        );
        let _ = writeln!(output, "    configured_as: {}", tool.configured_as);

        match &tool.status {
            ToolReferenceStatus::Available { manifest } => {
                if let Some(description) = manifest["description"].as_str() {
                    let _ = writeln!(output, "    description: {description}");
                }
                if let Some(binary) = manifest["invocation"]["binary"].as_str() {
                    let _ = writeln!(output, "    binary: {binary}");
                }
                let usages = manifest_usage_lines(manifest);
                if usages.is_empty() {
                    let _ = writeln!(output, "    usage: (not advertised)");
                } else {
                    let _ = writeln!(output, "    usage:");
                    for usage in usages {
                        let _ = writeln!(output, "      - {usage}");
                    }
                }
                let formats = manifest_string_array(manifest.pointer("/capabilities/formats"));
                if !formats.is_empty() {
                    let _ = writeln!(output, "    formats: {}", formats.join(", "));
                }
                let upstream = manifest_string_array(manifest.pointer("/pipeline/upstream"));
                let downstream = manifest_string_array(manifest.pointer("/pipeline/downstream"));
                let _ = writeln!(
                    output,
                    "    pipeline: upstream={} downstream={}",
                    join_or_none(&upstream),
                    join_or_none(&downstream)
                );
            }
            ToolReferenceStatus::Missing { reason } | ToolReferenceStatus::Error { reason } => {
                let _ = writeln!(output, "    reason: {reason}");
            }
        }
    }

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
        SettingsPathStatus::Resolved(path) => match hooks::inspect_managed_hooks(&path) {
            Ok(inspection) if inspection.is_healthy() => checks.push(DoctorCheck {
                name: "hooks",
                status: DoctorStatus::Ok,
                detail: healthy_hook_detail(&path, &inspection),
                remediation: None,
            }),
            Ok(inspection) => checks.push(DoctorCheck {
                name: "hooks",
                status: DoctorStatus::ActionNeeded,
                detail: actionable_hook_detail(&path, &inspection),
                remediation: Some(actionable_hook_remediation(&inspection)),
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

fn healthy_hook_detail(path: &Path, inspection: &hooks::ManagedHooksInspection) -> String {
    let mut executables = inspection
        .matchers
        .iter()
        .filter_map(|matcher| match &matcher.status {
            hooks::ManagedHookStatus::Installed { executable, .. } => {
                Some(executable.display().to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    executables.sort();
    executables.dedup();

    if executables.len() == 1 {
        format!(
            "managed Read/Grep/Bash hooks are installed in {} and resolve to {}",
            path.display(),
            executables[0]
        )
    } else {
        format!(
            "managed Read/Grep/Bash hooks are installed in {} and all configured commands resolve to executables",
            path.display()
        )
    }
}

fn actionable_hook_detail(path: &Path, inspection: &hooks::ManagedHooksInspection) -> String {
    let missing = inspection
        .matchers
        .iter()
        .filter_map(|matcher| {
            matches!(matcher.status, hooks::ManagedHookStatus::Missing).then_some(matcher.matcher)
        })
        .collect::<Vec<_>>();
    let invalid = inspection
        .matchers
        .iter()
        .filter_map(|matcher| match &matcher.status {
            hooks::ManagedHookStatus::Invalid { command, reason } => {
                Some(format!("{} => `{}` ({reason})", matcher.matcher, command))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut parts = Vec::new();
    if !missing.is_empty() {
        if path.exists() {
            parts.push(format!(
                "missing managed hooks for {} in {}",
                missing.join("/"),
                path.display()
            ));
        } else {
            parts.push(format!(
                "Claude settings file does not exist at {}",
                path.display()
            ));
        }
    }
    if !invalid.is_empty() {
        parts.push(format!(
            "managed hook commands do not resolve to executables: {}",
            invalid.join("; ")
        ));
    }

    parts.join(". ")
}

fn actionable_hook_remediation(inspection: &hooks::ManagedHooksInspection) -> String {
    let has_missing = inspection
        .matchers
        .iter()
        .any(|matcher| matches!(matcher.status, hooks::ManagedHookStatus::Missing));
    let has_invalid = inspection
        .matchers
        .iter()
        .any(|matcher| matches!(matcher.status, hooks::ManagedHookStatus::Invalid { .. }));

    match (has_missing, has_invalid) {
        (true, true) => {
            "run `veil install` to restore missing PreToolUse entries and rewrite the managed hook commands".to_owned()
        }
        (true, false) => {
            "run `veil install` to add the managed PreToolUse hook entries".to_owned()
        }
        (false, true) => {
            "run `veil install` to rewrite the managed hook commands to the current executable".to_owned()
        }
        (false, false) => "rerun `veil doctor` after reinstalling the hooks".to_owned(),
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

fn render_scan_human(scan_root: &Path, inspections: &[PathInspection]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Scan");
    let _ = writeln!(output, "  root: {}", scan_root.display());
    let _ = writeln!(output, "  files: {}", inspections.len());

    if inspections.is_empty() {
        output.push_str("  results:\n    - (none)\n");
        return output.trim_end().to_owned();
    }

    output.push_str("  results:\n");
    for inspection in inspections {
        let _ = writeln!(
            output,
            "    - {} {} [{}]",
            decision_action_name(&inspection.decision.action),
            inspection.input_path,
            inspection.match_kind()
        );
    }

    output.trim_end().to_owned()
}

fn render_packs_human(inventory: &[(&'static str, &'static str)]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Packs");
    for (name, description) in inventory {
        let _ = writeln!(output, "  - {name}: {description}");
    }

    output.trim_end().to_owned()
}

fn manifest_usage_lines(manifest: &Value) -> Vec<String> {
    manifest_string_array(manifest.pointer("/invocation/usage"))
}

fn manifest_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values.join(", ")
    }
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

fn collect_scan_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_scan_files_into(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_scan_files_into(root: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if root.is_file() {
        files.push(root.to_path_buf());
        return Ok(());
    }

    if !root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_scan_files_into(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
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
        "severity": decision.severity.as_ref().map(severity_name),
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

fn scan_entry_json(inspection: &PathInspection) -> Value {
    json!({
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
    })
}

fn built_in_pack_inventory() -> Vec<(&'static str, &'static str)> {
    BUILTIN_PACK_NAMES
        .iter()
        .copied()
        .map(|name| (name, pack_description(name)))
        .collect()
}

fn pack_description(name: &str) -> &'static str {
    match name {
        "core.filesystem" => "common secret-bearing filesystem paths",
        "core.credentials" => "credentials-bearing config and token targets",
        "data.tabular" => "protected-directory CSV, TSV, and parquet data",
        "data.xml" => "protected-directory XML filing artifacts",
        "data.database" => "database files and dump-style artifacts",
        "compliance.financial" => "financial records and holdings-style artifacts",
        "compliance.pii" => "personally identifying data artifacts",
        "compliance.hipaa" => "health-record artifacts",
        _ => "built-in sensitivity pack",
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

impl OperatorGuide {
    fn available_count(&self) -> usize {
        self.tools
            .iter()
            .filter(|tool| matches!(tool.status, ToolReferenceStatus::Available { .. }))
            .count()
    }

    fn unavailable_count(&self) -> usize {
        self.tools.len().saturating_sub(self.available_count())
    }

    fn to_json_value(&self) -> Value {
        json!({
            "schema_version": "veil.operator.v0",
            "guidance": "Use these authorized spine tools instead of a direct read.",
            "summary": {
                "configured": self.tools.len(),
                "available": self.available_count(),
                "unavailable": self.unavailable_count(),
            },
            "configured_authorized_tools": self.configured_authorized_tools,
            "tools": self.tools.iter().map(|tool| {
                match &tool.status {
                    ToolReferenceStatus::Available { manifest } => json!({
                        "configured_as": tool.configured_as,
                        "status": "available",
                        "reason": Value::Null,
                        "manifest": manifest,
                    }),
                    ToolReferenceStatus::Missing { reason } => json!({
                        "configured_as": tool.configured_as,
                        "status": "missing",
                        "reason": reason,
                        "manifest": Value::Null,
                    }),
                    ToolReferenceStatus::Error { reason } => json!({
                        "configured_as": tool.configured_as,
                        "status": "error",
                        "reason": reason,
                        "manifest": Value::Null,
                    }),
                }
            }).collect::<Vec<_>>(),
        })
    }
}

impl AuthorizedToolReference {
    fn display_name(&self) -> String {
        match &self.status {
            ToolReferenceStatus::Available { manifest } => manifest["name"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| configured_tool_display_name(&self.configured_as)),
            ToolReferenceStatus::Missing { .. } | ToolReferenceStatus::Error { .. } => {
                configured_tool_display_name(&self.configured_as)
            }
        }
    }
}

impl ToolReferenceStatus {
    fn label(&self) -> &'static str {
        match self {
            ToolReferenceStatus::Available { .. } => "available",
            ToolReferenceStatus::Missing { .. } => "missing",
            ToolReferenceStatus::Error { .. } => "error",
        }
    }
}

fn configured_tool_display_name(configured_tool: &str) -> String {
    shlex::split(configured_tool)
        .and_then(|parts| parts.into_iter().next())
        .and_then(|program| {
            Path::new(&program)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| configured_tool.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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

    fn create_executable(path: &Path) {
        write_file(path, "#!/bin/sh\nexit 0\n");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path)
                .expect("test executable should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)
                .expect("test executable permissions should be writable");
        }
    }

    fn create_describe_tool(path: &Path, stdout: &str, stderr: &str, exit_code: i32) {
        let script = format!(
            "#!/bin/sh\ncat <<'EOF'\n{stdout}\nEOF\ncat >&2 <<'EOF'\n{stderr}\nEOF\nexit {exit_code}\n"
        );
        write_file(path, &script);
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path)
                .expect("test executable should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)
                .expect("test executable permissions should be writable");
        }
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
    fn operator_command_json_output_combines_available_and_missing_tools() {
        let repo_root = unique_temp_dir("operator-json");
        let tool_path = repo_root.join("bin/shape");
        create_describe_tool(
            &tool_path,
            r#"{
              "schema_version": "operator.v0",
              "name": "shape",
              "description": "Schema profiler",
              "invocation": {
                "binary": "shape",
                "usage": ["shape sensitive.csv --json"]
              },
              "capabilities": {
                "formats": ["csv"]
              },
              "pipeline": {
                "upstream": [],
                "downstream": ["rvl"]
              }
            }"#,
            "",
            0,
        );
        write_file(
            &repo_root.join(".veil.toml"),
            &format!(
                "[spine]\nauthorized_tools = [\"{}\", \"/definitely/missing/rvl\"]\n",
                tool_path.display()
            ),
        );

        let rendered =
            render_operator_for_repo(&repo_root, true).expect("operator JSON should render");
        let value: Value = serde_json::from_str(&rendered).expect("operator JSON should parse");

        assert_eq!(value["schema_version"], "veil.operator.v0");
        assert_eq!(value["summary"]["configured"], 2);
        assert_eq!(value["summary"]["available"], 1);
        assert_eq!(value["summary"]["unavailable"], 1);
        assert!(
            value["tools"]
                .as_array()
                .expect("tools should be an array")
                .iter()
                .any(|tool| tool["status"] == "available" && tool["manifest"]["name"] == "shape")
        );
        assert!(
            value["tools"]
                .as_array()
                .expect("tools should be an array")
                .iter()
                .any(|tool| {
                    tool["status"] == "missing"
                        && tool["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("not found"))
                })
        );
    }

    #[test]
    fn operator_command_human_output_surfaces_usage_and_missing_tools() {
        let repo_root = unique_temp_dir("operator-human");
        let tool_path = repo_root.join("bin/shape");
        create_describe_tool(
            &tool_path,
            r#"{
              "schema_version": "operator.v0",
              "name": "shape",
              "description": "Schema profiler",
              "invocation": {
                "binary": "shape",
                "usage": ["shape sensitive.csv --json"]
              },
              "capabilities": {
                "formats": ["csv"]
              },
              "pipeline": {
                "upstream": [],
                "downstream": ["rvl"]
              }
            }"#,
            "",
            0,
        );
        write_file(
            &repo_root.join(".veil.toml"),
            &format!(
                "[spine]\nauthorized_tools = [\"{}\", \"/definitely/missing/rvl\"]\n",
                tool_path.display()
            ),
        );

        let rendered = render_operator_for_repo(&repo_root, false)
            .expect("operator human output should render");

        assert!(rendered.contains("Operator"));
        assert!(rendered.contains("shape [available]"));
        assert!(rendered.contains("shape sensitive.csv --json"));
        assert!(rendered.contains("rvl [missing]"));
    }

    #[test]
    fn operator_command_reports_invalid_describe_output() {
        let repo_root = unique_temp_dir("operator-invalid");
        let tool_path = repo_root.join("bin/broken");
        create_describe_tool(&tool_path, "not json", "", 0);
        write_file(
            &repo_root.join(".veil.toml"),
            &format!(
                "[spine]\nauthorized_tools = [\"{}\"]\n",
                tool_path.display()
            ),
        );

        let rendered =
            render_operator_for_repo(&repo_root, true).expect("operator JSON should render");
        let value: Value = serde_json::from_str(&rendered).expect("operator JSON should parse");

        assert_eq!(value["summary"]["available"], 0);
        assert_eq!(value["summary"]["unavailable"], 1);
        assert_eq!(value["tools"][0]["status"], "error");
        assert!(
            value["tools"][0]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("invalid JSON"))
        );
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
        let executable_path = repo_root.join("bin/veil");
        create_executable(&executable_path);
        write_file(
            &settings_path,
            &format!(
                r#"{{
              "hooks": {{
                "PreToolUse": [
                  {{ "matcher": "Read", "hooks": [{{ "type": "command", "command": "{}" }}] }},
                  {{ "matcher": "Grep", "hooks": [{{ "type": "command", "command": "{}" }}] }},
                  {{ "matcher": "Bash", "hooks": [{{ "type": "command", "command": "{}" }}] }}
                ]
              }}
            }}"#,
                executable_path.display(),
                executable_path.display(),
                executable_path.display()
            ),
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
    fn doctor_reports_invalid_hook_command_paths() {
        let repo_root = unique_temp_dir("doctor-invalid-hooks");
        let settings_path = repo_root.join("claude/settings.json");
        write_file(
            &settings_path,
            r#"{
              "hooks": {
                "PreToolUse": [
                  { "matcher": "Read", "hooks": [{ "type": "command", "command": "/definitely/missing/veil" }] },
                  { "matcher": "Grep", "hooks": [{ "type": "command", "command": "/definitely/missing/veil" }] },
                  { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/definitely/missing/veil" }] }
                ]
              }
            }"#,
        );

        let rendered = render_doctor_human(&build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
        ));

        assert!(rendered.contains("hooks [action_needed]"));
        assert!(rendered.contains("do not resolve to executables"));
        assert!(rendered.contains("run `veil install`"));
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

    #[test]
    fn scan_command_human_output_reports_sensitive_and_non_sensitive_examples() {
        let repo_root = unique_temp_dir("scan-human");
        write_file(
            &repo_root.join(".veil.toml"),
            r#"
            [sensitivity]
            protected = ["protected/**"]
            "#,
        );
        write_file(&repo_root.join("README.md"), "# docs");
        write_file(&repo_root.join("protected/holdings.csv"), "fund,value");

        let rendered =
            render_scan_for_repo(&repo_root, Path::new("."), false).expect("scan should render");

        assert!(rendered.contains("Scan"));
        assert!(rendered.contains("allow README.md [allowlist]"));
        assert!(rendered.contains("deny protected/holdings.csv [pack]"));
    }

    #[test]
    fn scan_command_json_output_lists_classified_files() {
        let repo_root = unique_temp_dir("scan-json");
        write_file(
            &repo_root.join(".veil.toml"),
            r#"
            [sensitivity]
            protected = ["protected/**"]
            "#,
        );
        write_file(&repo_root.join("README.md"), "# docs");
        write_file(&repo_root.join("protected/holdings.csv"), "fund,value");

        let value: Value = serde_json::from_str(
            &render_scan_for_repo(&repo_root, Path::new("."), true)
                .expect("scan JSON should render"),
        )
        .expect("scan JSON should parse");

        assert_eq!(value["files"].as_array().map(Vec::len), Some(3));
        assert!(
            value["files"]
                .as_array()
                .expect("files should be an array")
                .iter()
                .any(|entry| entry["match"]["pack"] == "data.tabular")
        );
        assert!(
            value["files"]
                .as_array()
                .expect("files should be an array")
                .iter()
                .any(|entry| entry["decision"]["action"] == "allow")
        );
    }

    #[test]
    fn packs_command_human_output_lists_builtin_packs() {
        let rendered = render_packs(false).expect("packs rendering should succeed");

        assert!(rendered.contains("Packs"));
        assert!(rendered.contains("core.filesystem"));
        assert!(rendered.contains("data.xml"));
    }

    #[test]
    fn packs_command_json_output_lists_builtin_inventory() {
        let value: Value =
            serde_json::from_str(&render_packs(true).expect("packs JSON should render"))
                .expect("packs JSON should parse");

        assert_eq!(
            value["packs"].as_array().map(Vec::len),
            Some(BUILTIN_PACK_NAMES.len())
        );
        assert!(
            value["packs"]
                .as_array()
                .expect("packs should be an array")
                .iter()
                .any(|entry| entry["name"] == "compliance.hipaa")
        );
    }
}
