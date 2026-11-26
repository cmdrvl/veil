#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use veil::allowlist::SafePathMatcher;
use veil::audit;
use veil::config::{self, Config, PolicyMode};
use veil::evaluator::{EvaluationInput, evaluate_access};
use veil::extract::{PathExposure, extract_read_or_grep_paths};
use veil::packs::{BUILTIN_PACK_NAMES, PackRegistry};
use veil::types::{Decision, DecisionAction, SensitivityResult, ToolKind};

use crate::cli::{
    AuditArgs, CapabilitiesArgs, ConfigArgs, DirCommandArgs, DoctorAction, DoctorArgs,
    DoctorCapabilitiesArgs, JsonOutputArgs, PathCommandArgs, ReplayArgs, RobotDocsArgs,
    SandboxArgs,
};
use crate::hooks;

const RECENT_AUDIT_LIMIT: usize = 20;
/// veil's own operator.v1 manifest. `--describe` and `capabilities --json`
/// both print exactly this document.
const OPERATOR_JSON: &str = include_str!("../operator.json");
const HOOK_DECISION_SCHEMA: &str = include_str!("../hook-decision.schema.json");
/// Family doctor report schema (`spine-rules` `cmdrvl.doctor.v1`) for every doctor mode.
const DOCTOR_SCHEMA_VERSION: &str = "cmdrvl.doctor.v1";
const DOCTOR_CAPABILITIES_SCHEMA_VERSION: &str = "veil.doctor.capabilities.v1";
const READ_ONLY_DOCTOR_CONTRACT: &str = "cmdrvl.read_only_doctor.v1";
/// What stands behind a veil decision, as `veil doctor` says it. veil is a hook
/// that reads the text of a tool call; nothing in it enforces an OS sandbox, so
/// every report says so and none says otherwise. The audit log's matching field
/// is `audit::ENFORCEMENT` (`hook`). Whatever makes this depend on whether a
/// sandbox is actually wrapping the agent (bd-apj) changes both together.
const ENFORCEMENT_MODE: &str = "hook-only";
const ENFORCEMENT_SUMMARY: &str = "advisory; parser-based";
/// Version tag on every `test`, `explain` and `scan` `--json` document,
/// including their error documents. These documents are decisions about
/// paths only: veil does not read file contents or message bodies to produce
/// them.
pub const PATH_DECISION_SCHEMA_VERSION: &str = "veil.path-decision.v1";

/// The path could not be normalized with the hook-mode path hardening
/// pipeline (empty, or holding control characters).
#[derive(Debug)]
pub struct PathUnnormalizable {
    path: String,
}

impl std::fmt::Display for PathUnnormalizable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not normalize `{}` with the hook-mode path hardening pipeline",
            self.path
        )
    }
}

impl std::error::Error for PathUnnormalizable {}

/// Why a `--json` path command failed, for the `error.code` field.
pub const PATH_ERROR_UNNORMALIZABLE: &str = "path_unnormalizable";
pub const PATH_ERROR_PREFLIGHT_REFUSED: &str = "guard_preflight_refused";
pub const PATH_ERROR_OTHER: &str = "error";

/// The `error.code` for a failure of `run_test`, `run_explain` or `run_scan`.
pub fn path_error_code(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if error.downcast_ref::<PathUnnormalizable>().is_some() {
        PATH_ERROR_UNNORMALIZABLE
    } else {
        PATH_ERROR_OTHER
    }
}

/// The document a `--json` path command prints on stdout when it fails, so a
/// wrapper never has to read stderr to learn why there is no decision.
pub fn path_error_json(code: &str, message: &str) -> String {
    json!({
        "schema_version": PATH_DECISION_SCHEMA_VERSION,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

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
    guard_posture: Value,
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
    if args.validate {
        return render_audit_validation(&config.policy.audit_path, args.json);
    }
    render_audit_for_path(
        &config.policy.audit_path,
        args.json,
        args.class.as_deref(),
        RECENT_AUDIT_LIMIT,
    )
}

pub fn run_replay(args: &ReplayArgs) -> Result<String, Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;
    let config = config::load_config(&repo_root)?;
    let audit_path = args
        .audit
        .as_deref()
        .unwrap_or(config.policy.audit_path.as_path());
    Ok(veil::replay::render_report(
        audit_path,
        &config,
        args.since.as_deref(),
    )?)
}

/// `veil --describe`: the operator manifest, byte-for-byte the repo's `operator.json`.
pub fn run_describe() -> String {
    OPERATOR_JSON.trim_end().to_owned()
}

/// `veil --schema`: JSON Schema for hook-mode stdout.
pub fn run_schema() -> String {
    HOOK_DECISION_SCHEMA.trim_end().to_owned()
}

pub fn run_capabilities(args: &CapabilitiesArgs) -> Result<String, Box<dyn std::error::Error>> {
    if args.json {
        Ok(run_describe())
    } else {
        let value: Value = serde_json::from_str(OPERATOR_JSON)?;
        Ok(render_capabilities_human(&value))
    }
}

pub fn run_robot_docs(_args: &RobotDocsArgs) -> Result<String, Box<dyn std::error::Error>> {
    Ok(render_robot_docs_guide())
}

/// Runs a doctor command and returns its output with the process exit code:
/// `0` healthy, `1` unhealthy (an `error` finding). Usage errors exit `2` in clap.
/// `doctor capabilities` and `doctor robot-docs` describe the tool; they do not
/// inspect health, so they always exit `0`.
pub fn run_doctor(args: &DoctorArgs) -> Result<(String, u8), Box<dyn std::error::Error>> {
    let repo_root = env::current_dir()?;

    // `--robot-triage` is the deprecated spelling of `doctor triage --json`.
    if args.robot_triage || matches!(&args.action, Some(DoctorAction::Triage(_))) {
        let report = current_doctor_report(&repo_root);
        let exit = report.exit_code();
        return Ok((
            serde_json::to_string_pretty(&report.to_triage_json_value())?,
            exit,
        ));
    }

    match &args.action {
        Some(DoctorAction::Capabilities(capabilities_args)) => {
            Ok((render_doctor_capabilities(capabilities_args)?, 0))
        }
        Some(DoctorAction::RobotDocs) => Ok((render_doctor_robot_docs(), 0)),
        Some(DoctorAction::Health(health_args)) => {
            render_doctor_health_for_repo(&repo_root, args.json || health_args.json)
        }
        // `Triage` already returned above; it shares the default arm only to keep the match exhaustive.
        Some(DoctorAction::Triage(_)) | None => {
            render_doctor_health_for_repo(&repo_root, args.json)
        }
    }
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

/// Compile the merged project policy into a reviewable macOS Seatbelt profile.
/// Printing modes are diagnostics only; `launch_sandbox` applies the compiled
/// profile to a child process and starts its broker outside confinement.
pub fn run_sandbox(args: &SandboxArgs) -> Result<String, Box<dyn std::error::Error>> {
    if !args.command.is_empty() {
        return Err("sandbox launch is handled by the launcher".into());
    }
    if args.print_profile == args.dry_run {
        return Err("choose exactly one of --print-profile or --dry-run".into());
    }

    let repo_root = env::current_dir()?;
    let config = config::load_config(&repo_root)?;
    let compiled = veil::sandbox::seatbelt::compile(&config, &repo_root)?;

    if args.print_profile {
        for warning in &compiled.warnings {
            eprintln!("warning: {warning}");
        }
        return Ok(compiled.profile);
    }

    let mut output = format!(
        "Seatbelt policy compiled for {}\nPath deny rules: {}\nProfile bytes: {}\nEnforcement applied: no (dry run only)\n",
        repo_root.display(),
        compiled.path_rules,
        compiled.profile.len()
    );
    for warning in compiled.warnings {
        writeln!(output, "Warning: {warning}")?;
    }
    Ok(output)
}

/// Start the broker outside Seatbelt and apply the compiled profile to the
/// requested client process. The broker is stopped and its socket removed when
/// the confined process exits.
pub fn launch_sandbox(command: &[OsString]) -> Result<u8, Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("veil sandbox requires a command after `--`".into());
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("the broker launcher currently requires macOS Seatbelt".into())
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;

        let project_root = env::current_dir()?;
        let config = config::load_config(&project_root)?;
        let compiled = veil::sandbox::seatbelt::compile(&config, &project_root)?;
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is required to launch the broker")?;
        let broker_dir = home.join(".cmdrvl/state/veil/broker");
        fs::create_dir_all(&broker_dir)?;
        let metadata = fs::symlink_metadata(&broker_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("broker state path must be a real directory".into());
        }
        fs::set_permissions(&broker_dir, fs::Permissions::from_mode(0o700))?;

        let session = broker_session_id();
        let socket = broker_dir.join(format!("{session}.sock"));
        let executable = env::current_exe()?;
        let mut profile = compiled.profile;
        profile.push_str(&veil::broker::sandbox_write_denials(
            &config,
            &env::var_os("PATH").unwrap_or_default(),
            &home.join(".cmdrvl/state/veil"),
        )?);
        let mut broker = Command::new(executable)
            .arg("--broker")
            .current_dir(&project_root)
            .env("VEIL_BROKER_SOCKET", &socket)
            .env("VEIL_BROKER_SESSION", &session)
            // The pipe stays open as long as this launcher lives; the broker
            // exits when it closes.
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            // Inherited so a startup or accept failure says why. Tool output
            // never reaches it: tool pipes are captured and scanned.
            .stderr(Stdio::inherit())
            .spawn()?;

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            if let Some(status) = broker.try_wait()? {
                return Err(format!("broker exited before opening its socket: {status}").into());
            }
            if Instant::now() >= ready_deadline {
                let _ = broker.kill();
                let _ = broker.wait();
                return Err("timed out waiting for the broker socket".into());
            }
            thread::sleep(Duration::from_millis(10));
        }

        let status = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(profile)
            .args(command)
            .env("VEIL_BROKER_SOCKET", &socket)
            .status();
        let _ = broker.kill();
        let stop_result = broker.wait().map(|_| ());
        let socket_result = fs::remove_file(&socket);
        let status = status?;
        stop_result?;
        socket_result?;
        Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1))
    }
}

#[cfg(target_os = "macos")]
fn broker_session_id() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or_default())
        .unwrap_or_default();
    format!(
        "{:08x}{:08x}",
        std::process::id(),
        u32::try_from(time).unwrap_or_default()
    )
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
    class: Option<&str>,
    limit: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let AuditWindow { entries, skipped } = read_recent_audit_entries(audit_path, class, limit)?;

    if json_output {
        let mut value = json!({
            "path": audit_path.display().to_string(),
            "entries": entries,
        });
        if let Some(object) = value.as_object_mut() {
            if let Some(class) = class {
                object.insert("class".to_owned(), json!(class));
            }
            // only when there are some, so a healthy log's document is unchanged
            if skipped > 0 {
                object.insert("skipped_lines".to_owned(), json!(skipped));
            }
        }
        Ok(serde_json::to_string_pretty(&value)?)
    } else {
        Ok(render_audit_human(audit_path, class, &entries, skipped))
    }
}

fn current_doctor_report(repo_root: &Path) -> DoctorReport {
    build_doctor_report(
        repo_root,
        match hooks::default_settings_path() {
            Ok(path) => SettingsPathStatus::Resolved(path),
            Err(error) => SettingsPathStatus::Error(error.to_string()),
        },
        hooks::detect_harness(|name| env::var(name).ok()),
        env::var_os("PATH").as_deref(),
    )
}

fn render_doctor_health_for_repo(
    repo_root: &Path,
    json_output: bool,
) -> Result<(String, u8), Box<dyn std::error::Error>> {
    let report = current_doctor_report(repo_root);
    let exit = report.exit_code();
    let config = config::load_config(repo_root)?;
    let rollout_warning = (config.policy.dynamic_args == config::DynamicArgsMode::Warn
        || config.policy.egress_mode() == &PolicyMode::Warn)
        .then(|| {
            "Track A rollout policy is in warn mode for dynamic arguments or egress; run `veil replay --since 30d` before switching to deny.".to_owned()
        });

    if json_output {
        let mut value = report.to_json_value();
        if let Some(warning) = rollout_warning {
            value["rollout_warnings"] = json!([warning]);
        }
        Ok((serde_json::to_string_pretty(&value)?, exit))
    } else {
        let mut rendered = render_doctor_human(&report);
        if let Some(warning) = rollout_warning {
            writeln!(rendered, "\nWarning: {warning}")?;
        }
        Ok((rendered, exit))
    }
}

/// `doctor capabilities`: a `cmdrvl.doctor.v1` report in `capabilities` mode whose
/// `contract` is the operator manifest, identical to `capabilities --json`.
/// It describes the tool and inspects nothing, so it carries no findings.
fn doctor_capabilities_report_value() -> Result<Value, serde_json::Error> {
    let mut value = json!({
        "schema_version": DOCTOR_SCHEMA_VERSION,
        "mode": "capabilities",
        "tool": "veil",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "healthy": true,
        "findings": [],
        "contract": serde_json::from_str::<Value>(OPERATOR_JSON)?,
    });
    value["doctor"] = doctor_capabilities_json_value();
    Ok(value)
}

fn render_doctor_capabilities(
    args: &DoctorCapabilitiesArgs,
) -> Result<String, Box<dyn std::error::Error>> {
    if args.json {
        Ok(serde_json::to_string_pretty(
            &doctor_capabilities_report_value()?,
        )?)
    } else {
        Ok(render_doctor_capabilities_human(
            &doctor_capabilities_json_value(),
        ))
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
            "schema_version": PATH_DECISION_SCHEMA_VERSION,
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
        let mut document = inspection_json(&inspection);
        document["schema_version"] = json!(PATH_DECISION_SCHEMA_VERSION);
        Ok(serde_json::to_string_pretty(&document)?)
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
            "schema_version": PATH_DECISION_SCHEMA_VERSION,
            // `components` drops a trailing `.`, so `scan .` reports the
            // directory itself, not `<dir>/.`.
            "root": scan_root.components().collect::<PathBuf>().display().to_string(),
            "files": inspections.iter().map(inspection_json).collect::<Vec<_>>(),
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

    let executable = match validate_describe_executable(&program) {
        Ok(executable) => executable,
        Err(reason) => {
            return AuthorizedToolReference {
                configured_as: configured_tool.to_owned(),
                status: ToolReferenceStatus::Error { reason },
            };
        }
    };

    let mut command = Command::new(executable);
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

fn validate_describe_executable(program: &str) -> Result<&str, String> {
    if program.trim().is_empty() {
        return Err("configured tool command has an empty executable".to_owned());
    }

    if program
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(format!(
            "configured tool executable `{program}` contains a control character"
        ));
    }

    Ok(program)
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
            "denied_flags": {
                "default": config.spine.denied_flags.default,
                "per_tool": config.spine.denied_flags.per_tool,
            },
        },
        "policy": {
            "default": policy_mode_name(&config.policy.default),
            "egress": policy_mode_name(config.policy.egress_mode()),
            "audit_log": config.policy.audit_log,
            "audit_path": config.policy.audit_path.display().to_string(),
            "audit_inputs": config.policy.audit_inputs,
            "dynamic_args": config.policy.dynamic_args.as_str(),
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
    let _ = writeln!(
        output,
        "  egress: {}",
        policy_mode_name(config.policy.egress_mode())
    );
    let _ = writeln!(
        output,
        "  dynamic_args: {}",
        config.policy.dynamic_args.as_str()
    );
    let _ = writeln!(output, "  audit_log: {}", config.policy.audit_log);
    let _ = writeln!(output, "  audit_inputs: {}", config.policy.audit_inputs);
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
    let _ = writeln!(output, "  denied_flags:");
    let denied_flags = &config.spine.denied_flags;
    let _ = writeln!(output, "    default: {}", denied_flags.default.join(" "));
    for (tool, flags) in &denied_flags.per_tool {
        let _ = writeln!(output, "    {tool}: {}", flags.join(" "));
    }

    output.trim_end().to_owned()
}

fn render_operator_human(guide: &OperatorGuide) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Operator");
    let _ = writeln!(
        output,
        "  guidance: start with `veil operator` when a sensitive-file read is blocked; choose an authorized spine tool instead of guessing a shell command"
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

/// Whether an audit entry is of `class`: its `class` (`egress`) or its
/// `reason_class` (`direct_read`, `argv_path`, `dynamic_path_unresolvable`,
/// `mcp_argument`).
fn entry_has_class(entry: &Value, class: &str) -> bool {
    string_field(entry, "class") == Some(class)
        || string_field(entry, "reason_class") == Some(class)
}

/// What `veil audit` read: the newest entries, and how many lines it could not
/// read and so left out.
struct AuditWindow {
    entries: Vec<Value>,
    skipped: usize,
}

/// The last `limit` entries of the audit log, or of its entries of `class`: the
/// filter comes first, so an old attempt is not pushed out of the window by
/// newer records of another class.
///
/// A line that is not an audit entry is counted and left out, not an error: one
/// damaged line used to make the whole log unreadable. `veil audit --validate`
/// says which lines they are.
fn read_recent_audit_entries(
    path: &Path,
    class: Option<&str>,
    limit: usize,
) -> io::Result<AuditWindow> {
    let mut window = AuditWindow {
        entries: Vec::new(),
        skipped: 0,
    };
    if limit == 0 || !path.exists() {
        return Ok(window);
    }

    let file = fs::File::open(path)?;
    let mut recent = VecDeque::with_capacity(limit);

    for line in BufReader::new(file).split(b'\n') {
        let fields = match audit::parse_line(&line?) {
            audit::Line::Blank => continue,
            audit::Line::Unparseable => {
                window.skipped += 1;
                continue;
            }
            audit::Line::Entry { fields, .. } => fields,
        };

        if class.is_some_and(|class| !entry_has_class(&fields, class)) {
            continue;
        }

        if recent.len() == limit {
            recent.pop_front();
        }
        recent.push_back(fields);
    }

    window.entries = recent.into_iter().collect();
    Ok(window)
}

/// `veil audit --validate`: every line of the log sorted into current, legacy
/// and unparseable.
fn render_audit_validation(
    audit_path: &Path,
    json_output: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let exists = audit_path.exists();
    let report = if exists {
        audit::validate(BufReader::new(fs::File::open(audit_path)?))?
    } else {
        audit::Validation::default()
    };

    if json_output {
        return Ok(serde_json::to_string_pretty(&json!({
            "path": audit_path.display().to_string(),
            "exists": exists,
            "schema_version": audit::SCHEMA_VERSION,
            "lines": report.lines,
            "blank": report.blank,
            "current": report.current,
            "legacy": report.legacy,
            "unparseable": report.unparseable,
            "unparseable_lines": report.unparseable_lines,
        }))?);
    }

    let mut output = String::new();
    let _ = writeln!(output, "Audit validation");
    let _ = writeln!(output, "  path: {}", audit_path.display());
    if !exists {
        output.push_str("  (no audit log at this path)\n");
        return Ok(output.trim_end().to_owned());
    }
    let _ = writeln!(output, "  lines: {} ({} blank)", report.lines, report.blank);
    let _ = writeln!(
        output,
        "  current ({}): {}",
        audit::SCHEMA_VERSION,
        report.current
    );
    let _ = writeln!(
        output,
        "  legacy (readable, no {}): {}",
        audit::SCHEMA_VERSION,
        report.legacy
    );
    let _ = writeln!(output, "  unparseable: {}", report.unparseable);
    if !report.unparseable_lines.is_empty() {
        let listed: Vec<String> = report
            .unparseable_lines
            .iter()
            .map(usize::to_string)
            .collect();
        let more = report.unparseable - report.unparseable_lines.len();
        let _ = write!(output, "  unparseable at line: {}", listed.join(", "));
        if more > 0 {
            let _ = write!(output, " (and {more} more)");
        }
        output.push('\n');
    }

    Ok(output.trim_end().to_owned())
}

fn render_audit_human(
    path: &Path,
    class: Option<&str>,
    entries: &[Value],
    skipped: usize,
) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Audit");
    let _ = writeln!(output, "  path: {}", path.display());
    if let Some(class) = class {
        let _ = writeln!(output, "  class: {class}");
    }
    let _ = writeln!(output, "  entries: {}", entries.len());
    if skipped > 0 {
        let _ = writeln!(
            output,
            "  skipped: {skipped} lines that are not audit entries (`veil audit --validate` lists them)"
        );
    }

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

fn build_doctor_report(
    repo_root: &Path,
    settings_status: SettingsPathStatus,
    harness: hooks::Harness,
    search_path: Option<&std::ffi::OsStr>,
) -> DoctorReport {
    let mut checks = Vec::new();
    let mut require_dcg = false;
    let mut mcp_screen = config::McpConfig::default().screen;

    match config::load_config(repo_root) {
        Ok(config) => {
            require_dcg = config.policy.require_dcg;
            mcp_screen = config.mcp.screen;
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

    let settings_path = match settings_status {
        SettingsPathStatus::Resolved(path) => Ok(path),
        SettingsPathStatus::Error(message) => Err(message),
    };
    let posture = hooks::inspect_guard_posture(harness, require_dcg, settings_path, search_path);
    checks.push(hooks_doctor_check(&posture));
    checks.extend(mcp_hook_doctor_check(&posture, mcp_screen));

    DoctorReport {
        checks,
        guard_posture: posture.to_json_value(),
    }
}

/// Whether the hook that sends MCP tool calls to veil is installed (bd-1wa).
/// Reported apart from `hooks`: operator commands do not refuse to run without
/// it, but an install without it does not screen MCP tool arguments. `None`
/// where veil cannot read the hook configuration: `hooks` says why.
fn mcp_hook_doctor_check(posture: &hooks::GuardPosture, screen: bool) -> Option<DoctorCheck> {
    let (Some(veil), Some(path)) = (&posture.veil, &posture.settings_path) else {
        return None;
    };
    let name = "mcp_hook";

    if !screen {
        return Some(DoctorCheck {
            name,
            status: DoctorStatus::Ok,
            detail: "MCP screening is off (`[mcp] screen = false`): MCP tool calls are not judged"
                .to_owned(),
            remediation: None,
        });
    }

    let status = veil.mcp().map(|matcher| &matcher.status);
    Some(match status {
        Some(hooks::ManagedHookStatus::Installed { executable, .. }) => DoctorCheck {
            name,
            status: DoctorStatus::Ok,
            detail: format!(
                "MCP tool calls are screened: the `{}` hook in {} resolves to {}",
                hooks::MCP_MATCHER,
                path.display(),
                executable.display()
            ),
            remediation: None,
        },
        Some(hooks::ManagedHookStatus::Invalid { command, reason }) => DoctorCheck {
            name,
            status: DoctorStatus::ActionNeeded,
            detail: format!(
                "the `{}` hook command `{command}` does not resolve to an executable ({reason}), so MCP tool arguments are not screened",
                hooks::MCP_MATCHER
            ),
            remediation: Some(
                "run `veil install` to rewrite the managed hook commands to the current executable"
                    .to_owned(),
            ),
        },
        Some(hooks::ManagedHookStatus::Missing) | None => DoctorCheck {
            name,
            status: DoctorStatus::ActionNeeded,
            detail: format!(
                "no PreToolUse hook for MCP tools (`{}`) in {}, so MCP tool arguments are not screened",
                hooks::MCP_MATCHER,
                path.display()
            ),
            remediation: Some(
                "run `veil install` to add the managed `mcp__.*` PreToolUse hook entry, or set `[mcp] screen = false` if MCP tools should not be screened"
                    .to_owned(),
            ),
        },
    })
}

fn hooks_doctor_check(posture: &hooks::GuardPosture) -> DoctorCheck {
    if posture.is_healthy() {
        let scope = match (&posture.veil, &posture.settings_path) {
            (Some(veil), Some(path)) => healthy_hook_detail(path, veil),
            _ => format!(
                "harness {}: veil hook configuration is not inspectable from here (unverified); no Claude hooks required",
                posture.harness.name()
            ),
        };
        let dcg = if posture.dcg.is_healthy() {
            dcg_hook_detail(&posture.dcg)
        } else {
            format!(
                "dcg not detected (optional; set `[policy] require_dcg = true` to require it): {}",
                dcg_hook_detail(&posture.dcg)
            )
        };
        return DoctorCheck {
            name: "hooks",
            status: DoctorStatus::Ok,
            detail: format!("{scope}; {dcg}"),
            remediation: None,
        };
    }

    let mut details = Vec::new();
    let mut remediations = Vec::new();
    if posture.harness == hooks::Harness::ClaudeCode {
        if let Some(error) = &posture.settings_error {
            details.push(error.clone());
            remediations.push(
                "set `VEIL_CLAUDE_SETTINGS_PATH` or `HOME`, repair the settings file, or rerun `veil install`"
                    .to_owned(),
            );
        } else if let (Some(veil), Some(path)) = (&posture.veil, &posture.settings_path)
            && !veil.is_healthy()
        {
            details.push(actionable_hook_detail(path, veil));
            remediations.push(actionable_hook_remediation(veil));
        }
    }
    if posture.require_dcg && !posture.dcg.is_healthy() {
        details.push(dcg_hook_detail(&posture.dcg));
        remediations.push(
            "install dcg, or set `[policy] require_dcg = false`, then rerun `veil doctor`"
                .to_owned(),
        );
    }

    DoctorCheck {
        name: "hooks",
        status: DoctorStatus::ActionNeeded,
        detail: details.join("; "),
        remediation: Some(remediations.join("; ")),
    }
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

fn dcg_hook_detail(inspection: &hooks::DcgHookInspection) -> String {
    match &inspection.status {
        hooks::ManagedHookStatus::Installed { executable, .. } => {
            format!("dcg Bash hook resolves to {}", executable.display())
        }
        hooks::ManagedHookStatus::Missing => "missing dcg Bash hook".to_owned(),
        hooks::ManagedHookStatus::Invalid { command, reason } => {
            format!("dcg Bash hook command `{command}` does not resolve: {reason}")
        }
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
        "healthy"
    } else {
        "attention_needed"
    };
    let _ = writeln!(
        output,
        "veil doctor {overall}: {} checks passed, {} findings",
        report.ok_count(),
        report.finding_count()
    );
    let _ = writeln!(output, "Doctor");
    let _ = writeln!(output, "  overall: {overall}");
    let _ = writeln!(
        output,
        "  enforcement: {ENFORCEMENT_MODE} ({ENFORCEMENT_SUMMARY})"
    );

    for check in &report.checks {
        let status = check.status.as_str();
        let _ = writeln!(output, "  - {} [{}] {}", check.name, status, check.detail);
        if let Some(remediation) = &check.remediation {
            let _ = writeln!(output, "    recommendation: {remediation}");
        }
    }

    output.trim_end().to_owned()
}

fn render_doctor_capabilities_human(value: &Value) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Doctor Capabilities");
    let _ = writeln!(
        output,
        "  schema_version: {}",
        value["schema_version"].as_str().unwrap_or("<unknown>")
    );
    let _ = writeln!(output, "  contract: {READ_ONLY_DOCTOR_CONTRACT}");
    let _ = writeln!(output, "  read_only: true");
    let _ = writeln!(output, "  fix_mode: not_available");
    let _ = writeln!(output, "  network: not_used");
    let _ = writeln!(output, "  commands:");
    for command in doctor_command_lines() {
        let _ = writeln!(output, "    - {command}");
    }
    output.push_str("  fixers: (none)\n");

    output.trim_end().to_owned()
}

fn render_capabilities_human(value: &Value) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Capabilities");
    let _ = writeln!(
        output,
        "  schema_version: {}",
        value["schema_version"].as_str().unwrap_or("<unknown>")
    );
    let _ = writeln!(output, "  tool: veil {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(output, "  hook_mode: veil < hook-payload.json");
    let _ = writeln!(output, "  discovery:");
    let _ = writeln!(output, "    - veil --describe");
    let _ = writeln!(output, "    - veil --robot-triage");
    let _ = writeln!(output, "    - veil capabilities --json");
    let _ = writeln!(output, "    - veil robot-docs guide");
    let _ = writeln!(output, "  commands:");
    for command in value["invocation"]["usage"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let _ = writeln!(output, "    - {command}");
    }

    output.trim_end().to_owned()
}

fn render_robot_docs_guide() -> String {
    [
        "veil robot-docs guide",
        "",
        "Quick start:",
        "- `veil doctor triage --json` returns one read-only cmdrvl.doctor.v1 report with next actions (exit 0 healthy, 1 unhealthy). `veil --robot-triage` is its deprecated alias.",
        "- `veil capabilities --json` (same document as `veil --describe`) returns the full machine-readable operator.v1 contract; `veil --schema` prints the JSON Schema for hook-mode stdout.",
        "- `veil operator --json` lists configured spine tools after guard hooks are healthy.",
        "- `veil test PATH --json` predicts the read decision for one path after guard hooks are healthy.",
        "- `veil explain PATH --json` shows allowlist/protected-pack matching after guard hooks are healthy.",
        "",
        "Hook mode:",
        "- Bare `veil` expects a Claude/Gemini/Copilot hook payload on stdin.",
        "- Do not run bare `veil` as a discovery command; use `veil --help` or the robot surfaces above.",
        "",
        "Guard preflight:",
        "- Under Claude Code, domain commands fail closed unless healthy veil Read/Grep/Bash hooks are installed. Other harnesses (Codex, Gemini CLI, Cursor, plain shell) do not need Claude hooks; their veil wiring is reported as unverified.",
        "- dcg is optional: set `[policy] require_dcg = true` to make a healthy dcg a hard requirement.",
        "- `veil doctor --json` and `veil doctor triage --json` report the detected harness and `guard_posture`; `veil doctor` and `veil doctor --json` also say `enforcement: hook-only (advisory; parser-based)`, because nothing in veil enforces an OS sandbox. Set `VEIL_HARNESS` (claude-code, codex, gemini-cli, cursor, plain) to override detection.",
        "- `veil doctor`, `veil capabilities --json`, `veil --describe`, `veil robot-docs guide`, `veil install`, and `veil uninstall` remain available for maintenance.",
        "",
        "Composition:",
        "- Use `dcg` to block destructive shell commands.",
        "- Use `veil` to block raw local sensitive reads.",
        "- Use authorized spine tools for metadata-safe local processing.",
        "- Use `airlock` to attest derived artifacts that later cross a model boundary.",
    ]
    .join("\n")
}

fn render_doctor_robot_docs() -> String {
    [
        "veil doctor robot-docs",
        "",
        "Read-only contract:",
        "- Runs local config, audit-path, and managed Claude hook detectors.",
        "- Does not install hooks, rewrite settings, write audit records, mutate config, or use network.",
        "- No fix mode is available in this release.",
        "",
        "Commands:",
        "- veil doctor",
        "- veil doctor --json",
        "- veil doctor capabilities --json",
        "- veil doctor triage --json",
        "- veil doctor robot-docs",
        "- Deprecated aliases (same documents): veil doctor health [--json], veil doctor --robot-triage, veil --robot-triage",
        "",
        "Exit codes: 0 healthy, 1 unhealthy (an error finding), 2 usage error. JSON is cmdrvl.doctor.v1.",
        "",
        "When `healthy` is false, follow `next_actions` (or `recommended_actions`) manually or run `veil install` only when the operator has chosen to repair hook settings.",
    ]
    .join("\n")
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
    let normalized_path =
        normalize_cli_path(raw_path, repo_root).ok_or_else(|| PathUnnormalizable {
            path: raw_path.display().to_string(),
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
        "confidence": confidence_json(decision.confidence),
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

/// One path's inspection: the `explain` document without its version tag and
/// each element of the `scan` `files` array.
fn inspection_json(inspection: &PathInspection) -> Value {
    json!({
        "input_path": inspection.input_path,
        "normalized_path": inspection.normalized_path.display().to_string(),
        "match": {
            "kind": inspection.match_kind(),
            "allowlist_pattern": inspection.allowlist_pattern,
            "protected_pattern": inspection.protected_pattern,
            "pack": inspection.sensitivity.as_ref().map(|value| value.pack.clone()),
            "severity": inspection.sensitivity.as_ref().map(|value| severity_name(&value.severity)),
            "confidence": confidence_json(inspection.sensitivity.as_ref().map(|value| value.confidence)),
            "directory_sensitive": inspection.sensitivity.as_ref().map(|value| value.directory_sensitive),
        },
        "decision": decision_json(&inspection.decision),
    })
}

/// Confidences are `f32`; widening one to `f64` prints 0.95 as
/// 0.949999988079071, which no wrapper test can compare against. Going through
/// the shortest decimal form keeps 0.95 as 0.95.
fn confidence_json(confidence: Option<f32>) -> Value {
    confidence
        .and_then(|value| value.to_string().parse::<f64>().ok())
        .map_or(Value::Null, Value::from)
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

    fn ok_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Ok)
            .count()
    }

    fn finding_count(&self) -> usize {
        self.checks.len().saturating_sub(self.ok_count())
    }

    fn status_name(&self) -> &'static str {
        if self.is_healthy() {
            "healthy"
        } else {
            "attention_needed"
        }
    }

    fn summary_json_value(&self) -> Value {
        json!({
            "status": self.status_name(),
            "checks": self.checks.len(),
            "passed": self.ok_count(),
            "findings": self.finding_count(),
            "read_only": true,
            "fixers": 0,
        })
    }

    fn checks_json_value(&self) -> Vec<Value> {
        self.checks
            .iter()
            .map(DoctorCheck::to_json_value)
            .collect::<Vec<_>>()
    }

    fn recommended_actions_json_value(&self) -> Vec<Value> {
        self.checks
            .iter()
            .filter_map(|check| {
                check.remediation.as_ref().map(|remediation| {
                    json!({
                        "check": check.name,
                        "action": remediation,
                    })
                })
            })
            .collect::<Vec<_>>()
    }

    /// Process exit code for this report: `0` healthy, `1` unhealthy.
    fn exit_code(&self) -> u8 {
        if self.is_healthy() { 0 } else { 1 }
    }

    /// `cmdrvl.doctor.v1` findings: one per check; a check needing action is an
    /// `error` finding, so `healthy` is exactly "no error finding".
    fn findings_json_value(&self) -> Vec<Value> {
        self.checks
            .iter()
            .map(|check| {
                let mut finding = json!({
                    "id": check.name,
                    "severity": match check.status {
                        DoctorStatus::Ok => "info",
                        DoctorStatus::ActionNeeded => "error",
                    },
                    "message": check.detail,
                });
                if let Some(fix) = &check.remediation {
                    finding["fix"] = json!(fix);
                }
                finding
            })
            .collect()
    }

    /// `cmdrvl.doctor.v1`, mode `health`. The pre-v1 detail fields (`checks`,
    /// `summary`, `recommended_actions`, `guard_posture`, `fixers`) remain as
    /// additive extras; `contract` is reserved for capabilities mode, so the old
    /// string of that name is now `read_only_contract`.
    fn to_json_value(&self) -> Value {
        json!({
            "schema_version": DOCTOR_SCHEMA_VERSION,
            "mode": "health",
            "tool": "veil",
            "tool_version": env!("CARGO_PKG_VERSION"),
            "healthy": self.is_healthy(),
            "findings": self.findings_json_value(),
            "version": env!("CARGO_PKG_VERSION"),
            "read_only_contract": READ_ONLY_DOCTOR_CONTRACT,
            "ok": self.is_healthy(),
            "summary": self.summary_json_value(),
            "checks": self.checks_json_value(),
            "recommended_actions": self.recommended_actions_json_value(),
            "guard_posture": self.guard_posture,
            "enforcement": {
                "mode": ENFORCEMENT_MODE,
                "summary": ENFORCEMENT_SUMMARY,
                "sandbox": false,
            },
            "fixers": [],
        })
    }

    /// `cmdrvl.doctor.v1`, mode `triage`. `next_actions` is never empty when unhealthy.
    fn to_triage_json_value(&self) -> Value {
        let mut next_actions: Vec<String> = self
            .checks
            .iter()
            .filter(|check| check.status == DoctorStatus::ActionNeeded)
            .filter_map(|check| check.remediation.clone())
            .collect();
        if !self.is_healthy() && next_actions.is_empty() {
            next_actions.push(
                "run `veil doctor` for details, then repair the reported findings".to_owned(),
            );
        }

        let mut value = self.to_json_value();
        value["mode"] = json!("triage");
        value["next_actions"] = json!(next_actions);
        value["doctor"] = doctor_capabilities_json_value();
        value
    }
}

impl DoctorStatus {
    fn as_str(&self) -> &'static str {
        match self {
            DoctorStatus::Ok => "ok",
            DoctorStatus::ActionNeeded => "action_needed",
        }
    }
}

impl DoctorCheck {
    fn to_json_value(&self) -> Value {
        json!({
            "name": self.name,
            "status": self.status.as_str(),
            "detail": self.detail,
            "remediation": self.remediation,
        })
    }
}

fn doctor_capabilities_json_value() -> Value {
    json!({
        "schema_version": DOCTOR_CAPABILITIES_SCHEMA_VERSION,
        "tool": "veil",
        "version": env!("CARGO_PKG_VERSION"),
        "contract": READ_ONLY_DOCTOR_CONTRACT,
        "read_only": true,
        "fix_mode": "not_available",
        "network": "not_used",
        "writes": {
            "config": false,
            "hooks": false,
            "audit_log": false,
            "doctor_artifacts": false,
            "network": false,
        },
        "commands": doctor_command_lines().iter().map(|command| {
            json!({
                "command": command,
                "read_only": true,
            })
        }).collect::<Vec<_>>(),
        "detectors": [
            {
                "name": "config",
                "description": "Loads the merged veil configuration from project, user, system, and environment layers.",
                "writes": false
            },
            {
                "name": "audit",
                "description": "Reports where audit records would be written without appending an audit record.",
                "writes": false
            },
            {
                "name": "hooks",
                "description": "Inspects managed Claude Read/Grep/Bash PreToolUse hook entries and executable resolution.",
                "writes": false
            },
            {
                "name": "mcp_hook",
                "description": "Inspects the managed Claude `mcp__.*` PreToolUse hook entry that sends MCP tool calls to veil, and its executable resolution. Not required by operator preflight; reported ok when `[mcp] screen = false`.",
                "writes": false
            }
        ],
        "fixers": [],
        "artifact_policy": {
            "doctor_dir": ".doctor/",
            "written_by_this_release": false,
            "gitignored": true
        }
    })
}

fn doctor_command_lines() -> Vec<&'static str> {
    vec![
        "veil doctor health",
        "veil doctor health --json",
        "veil doctor capabilities --json",
        "veil doctor robot-docs",
        "veil doctor --robot-triage",
    ]
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
            "guidance": "Start with veil operator when a sensitive-file read is blocked, then choose an authorized spine tool instead of guessing a shell command.",
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
            wait_until_executable(path);
        }
    }

    /// Returns once `path` can be executed.
    ///
    /// A script that was just written can fail to start with "Text file busy"
    /// (ETXTBSY) although the thread that wrote it has closed it: another test
    /// thread that forked while the file was open holds a copy of the write handle
    /// until its child execs. The operator reports a tool that does not start as
    /// an error, so a test of what the tool describes would then see no available
    /// tool. The kernel lets an exec through only when no process holds the file
    /// open for writing, so one exec that works shows the file is ready for every
    /// later one. Any other error, or a file still busy after ten seconds, fails
    /// here with the error itself.
    #[cfg(unix)]
    fn wait_until_executable(path: &Path) {
        let started = std::time::Instant::now();

        loop {
            match std::process::Command::new(path).arg("--describe").output() {
                Ok(_) => return,
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && started.elapsed() < std::time::Duration::from_secs(10) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!(
                    "test tool {} cannot be executed after {:?}: {error}",
                    path.display(),
                    started.elapsed()
                ),
            }
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
            dynamic_args = "warn"
            "#,
        );

        let human = render_config_for_repo(&repo_root, false)
            .expect("human config rendering should succeed");
        assert!(human.contains("  dynamic_args: warn\n"), "{human}");

        let rendered =
            render_config_for_repo(&repo_root, true).expect("config rendering should succeed");
        let value: Value =
            serde_json::from_str(&rendered).expect("config JSON output should parse");

        let protected = value["sensitivity"]["protected"]
            .as_array()
            .expect("protected patterns should be an array");
        let project_pattern = format!(
            "{}/data/**",
            fs::canonicalize(&repo_root)
                .expect("repo root should canonicalize")
                .display()
        );
        assert!(
            protected
                .iter()
                .any(|pattern| pattern.as_str() == Some(project_pattern.as_str())),
            "project protected pattern should be preserved"
        );
        for suffix in [
            "/.cmdrvl/config/**",
            "/.cmdrvl/secrets/**",
            "/.cmdrvl/state/cmdrvl-gtm/email-watch/**",
            "/.cmdrvl/state/cmdrvl-cli/guard-receipts/**",
            "/.cmdrvl/state/cmdrvl-holon/doctor-runs/**",
            "/.cmdrvl/receipts/**",
            "/.cmdrvl/migrations/**",
            "/.cmdrvl/notices/**",
        ] {
            assert!(
                protected
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|pattern| pattern.ends_with(suffix)),
                "missing CMD+RVL protected suffix {suffix}"
            );
        }
        assert_eq!(value["policy"]["default"], "warn");
        assert_eq!(value["policy"]["audit_log"], false);
        assert_eq!(value["policy"]["audit_path"], "/tmp/veil-audit.jsonl");
        assert_eq!(value["policy"]["dynamic_args"], "warn");
        assert_eq!(
            value["spine"]["denied_flags"]["default"],
            serde_json::json!(["--explicit", "--raw", "--dump", "--show-values"])
        );
        assert_eq!(
            value["spine"]["denied_flags"]["per_tool"],
            serde_json::json!({})
        );
    }

    #[test]
    fn config_output_shows_configured_denied_flags_in_json_and_human_forms() {
        let repo_root = unique_temp_dir("config-denied-flags");
        write_file(
            &repo_root.join(".veil.toml"),
            r#"
            [spine.denied_flags]
            default = ["--explicit"]
            shape = ["--columns"]
            "#,
        );

        let json = render_config_for_repo(&repo_root, true).expect("config JSON should render");
        let value: Value = serde_json::from_str(&json).expect("config JSON output should parse");
        assert_eq!(
            value["spine"]["denied_flags"],
            serde_json::json!({"default": ["--explicit"], "per_tool": {"shape": ["--columns"]}})
        );

        let human = render_config_for_repo(&repo_root, false).expect("config should render");
        assert!(human.contains("denied_flags:"), "{human}");
        assert!(human.contains("default: --explicit"), "{human}");
        assert!(human.contains("shape: --columns"), "{human}");
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
        assert_eq!(
            value["guidance"],
            "Start with veil operator when a sensitive-file read is blocked, then choose an authorized spine tool instead of guessing a shell command."
        );
        // the report is the message: a tool that did not start says why in it
        assert_eq!(value["summary"]["configured"], 2, "{rendered}");
        assert_eq!(value["summary"]["available"], 1, "{rendered}");
        assert_eq!(value["summary"]["unavailable"], 1, "{rendered}");
        assert!(
            value["tools"]
                .as_array()
                .expect("tools should be an array")
                .iter()
                .any(|tool| tool["status"] == "available" && tool["manifest"]["name"] == "shape"),
            "{rendered}"
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
                }),
            "{rendered}"
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

        assert!(rendered.contains("Operator"), "{rendered}");
        assert!(
            rendered.contains("start with `veil operator`"),
            "{rendered}"
        );
        assert!(
            rendered.contains("instead of guessing a shell command"),
            "{rendered}"
        );
        assert!(rendered.contains("shape [available]"), "{rendered}");
        assert!(
            rendered.contains("shape sensitive.csv --json"),
            "{rendered}"
        );
        assert!(rendered.contains("rvl [missing]"), "{rendered}");
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

        assert_eq!(value["summary"]["available"], 0, "{rendered}");
        assert_eq!(value["summary"]["unavailable"], 1, "{rendered}");
        assert_eq!(value["tools"][0]["status"], "error", "{rendered}");
        assert!(
            value["tools"][0]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("invalid JSON")),
            "{rendered}"
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

        let rendered = render_audit_for_path(&audit_path, false, None, 20)
            .expect("audit rendering should succeed");

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

        let rendered = render_audit_for_path(&audit_path, true, None, 20)
            .expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&rendered).expect("audit JSON should parse");

        assert_eq!(value["path"], audit_path.display().to_string());
        assert_eq!(value["entries"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["entries"][0]["tool"], "Read");
        // no filter, no `class` key; a healthy log skips nothing and says nothing
        assert!(value.get("class").is_none());
        assert!(value.get("skipped_lines").is_none());
    }

    /// A good entry, two halves of one record that two hooks wrote at once, and
    /// another good entry.
    fn damaged_audit_fixture(name: &str) -> PathBuf {
        let audit_path = unique_temp_dir(name).join("audit.jsonl");
        write_file(
            &audit_path,
            concat!(
                "{\"ts\":\"1\",\"tool\":\"Read\",\"path\":\"data/a.csv\",\"decision\":\"deny\"}\n",
                "{\"confidence\":null,\"decision\":\"allow{\"\"confid\n",
                ",\"ts\":\"1775603272\"}\n",
                "{\"ts\":\"2\",\"tool\":\"Bash\",\"path\":\"data/b.csv\",\"decision\":\"deny\"}\n",
            ),
        );
        audit_path
    }

    #[test]
    fn audit_lists_the_entries_it_can_read_and_counts_the_lines_it_cannot() {
        let audit_path = damaged_audit_fixture("audit-damaged");

        let human = render_audit_for_path(&audit_path, false, None, 20)
            .expect("a damaged line is not an error");
        assert!(human.contains("entries: 2"), "{human}");
        assert!(human.contains("skipped: 2 lines"), "{human}");
        assert!(human.contains("veil audit --validate"), "{human}");
        assert!(human.contains("data/a.csv"), "{human}");
        assert!(human.contains("data/b.csv"), "{human}");

        let json = render_audit_for_path(&audit_path, true, None, 20).expect("json");
        let value: Value = serde_json::from_str(&json).expect("audit JSON should parse");
        assert_eq!(value["entries"].as_array().map(Vec::len), Some(2));
        assert_eq!(value["skipped_lines"], 2);
    }

    #[test]
    fn audit_validate_counts_every_kind_of_line_in_json_and_text() {
        let audit_path = unique_temp_dir("audit-validate").join("audit.jsonl");
        write_file(
            &audit_path,
            concat!(
                "{\"schema_version\":\"veil.audit.v2\",\"ts\":\"1\",\"tool\":\"Read\",\"path\":\"a\",\"decision\":\"allow\"}\n",
                "{\"ts\":\"2\",\"tool\":\"Read\",\"path\":\"b\",\"decision\":\"allow\"}\n",
                "not json\n",
                "\n",
            ),
        );

        let json = render_audit_validation(&audit_path, true).expect("validation");
        let value: Value = serde_json::from_str(&json).expect("validation JSON should parse");
        assert_eq!(value["exists"], true);
        assert_eq!(value["schema_version"], "veil.audit.v2");
        assert_eq!(value["lines"], 4);
        assert_eq!(value["blank"], 1);
        assert_eq!(value["current"], 1);
        assert_eq!(value["legacy"], 1);
        assert_eq!(value["unparseable"], 1);
        assert_eq!(value["unparseable_lines"], json!([3]));

        let text = render_audit_validation(&audit_path, false).expect("validation");
        assert!(text.contains("lines: 4 (1 blank)"), "{text}");
        assert!(text.contains("current (veil.audit.v2): 1"), "{text}");
        assert!(
            text.contains("legacy (readable, no veil.audit.v2): 1"),
            "{text}"
        );
        assert!(text.contains("unparseable: 1"), "{text}");
        assert!(text.contains("unparseable at line: 3"), "{text}");
    }

    #[test]
    fn audit_validate_says_when_there_is_no_log_and_how_many_lines_it_leaves_unlisted() {
        let missing = unique_temp_dir("audit-validate-missing").join("audit.jsonl");
        let text = render_audit_validation(&missing, false).expect("validation");
        assert!(text.contains("no audit log at this path"), "{text}");
        let json = render_audit_validation(&missing, true).expect("validation");
        let value: Value = serde_json::from_str(&json).expect("validation JSON should parse");
        assert_eq!(value["exists"], false);
        assert_eq!(value["lines"], 0);

        let long = unique_temp_dir("audit-validate-long").join("audit.jsonl");
        write_file(&long, &"garbage\n".repeat(45));
        let text = render_audit_validation(&long, false).expect("validation");
        assert!(text.contains("unparseable: 45"), "{text}");
        assert!(text.contains("(and 25 more)"), "{text}");
    }

    /// Three egress denials, interleaved with other records, the newest of them
    /// followed by more records of other classes than the window holds.
    fn egress_audit_fixture(name: &str) -> PathBuf {
        let audit_path = unique_temp_dir(name).join("audit.jsonl");
        let line = |ts: u32, path: &str, reason_class: &str, class: &str| {
            format!(
                "{{\"ts\":\"2026-03-01T16:{ts:02}:00Z\",\"tool\":\"Bash\",\"path\":\"{path}\",\"decision\":\"deny\",\"reason_class\":\"{reason_class}\",\"class\":{class}}}\n"
            )
        };
        let mut text = String::new();
        text.push_str(&line(0, "first-egress", "argv_path", "\"egress\""));
        text.push_str(&line(1, "read-one", "direct_read", "null"));
        text.push_str(&line(2, "second-egress", "direct_read", "\"egress\""));
        text.push_str(&line(3, "read-two", "direct_read", "null"));
        text.push_str(&line(4, "third-egress", "argv_path", "\"egress\""));
        for minute in 5..12 {
            text.push_str(&line(minute, "later", "argv_path", "null"));
        }
        write_file(&audit_path, &text);
        audit_path
    }

    #[test]
    fn audit_class_egress_lists_only_egress_attempts() {
        let audit_path = egress_audit_fixture("audit-class-egress");

        let rendered = render_audit_for_path(&audit_path, true, Some("egress"), 20)
            .expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&rendered).expect("audit JSON should parse");

        let paths: Vec<&str> = value["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["path"].as_str().expect("path"))
            .collect();
        assert_eq!(paths, ["first-egress", "second-egress", "third-egress"]);
        assert_eq!(value["class"], "egress");

        let human = render_audit_for_path(&audit_path, false, Some("egress"), 20)
            .expect("audit rendering should succeed");
        assert!(human.contains("class: egress"), "{human}");
        assert!(human.contains("entries: 3"), "{human}");
        assert!(!human.contains("read-one"), "{human}");
    }

    #[test]
    fn the_class_filter_comes_before_the_window() {
        // seven newer records of another class must not push the attempts out
        let audit_path = egress_audit_fixture("audit-class-window");

        let rendered = render_audit_for_path(&audit_path, true, Some("egress"), 2)
            .expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&rendered).expect("audit JSON should parse");
        let paths: Vec<&str> = value["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["path"].as_str().expect("path"))
            .collect();
        assert_eq!(paths, ["second-egress", "third-egress"]);

        // the unfiltered window is the last two records of the log
        let unfiltered = render_audit_for_path(&audit_path, true, None, 2)
            .expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&unfiltered).expect("audit JSON should parse");
        assert_eq!(value["entries"][0]["path"], "later");
        assert_eq!(value["entries"][1]["path"], "later");
    }

    #[test]
    fn audit_class_also_matches_a_reason_class_and_may_match_nothing() {
        let audit_path = egress_audit_fixture("audit-class-reason");

        let rendered = render_audit_for_path(&audit_path, true, Some("direct_read"), 20)
            .expect("audit rendering should succeed");
        let value: Value = serde_json::from_str(&rendered).expect("audit JSON should parse");
        assert_eq!(value["entries"].as_array().map(Vec::len), Some(3));

        let none = render_audit_for_path(&audit_path, false, Some("dynamic_path_unresolvable"), 20)
            .expect("audit rendering should succeed");
        assert!(none.contains("entries: 0"), "{none}");
        assert!(none.contains("(none)"), "{none}");
    }

    #[test]
    fn doctor_human_output_reports_actionable_missing_hooks() {
        let repo_root = unique_temp_dir("doctor-missing-hooks");
        let settings_path = repo_root.join("claude/settings.json");

        let rendered = render_doctor_human(&build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
            hooks::Harness::ClaudeCode,
            None,
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
        let dcg_path = repo_root.join("bin/dcg");
        create_executable(&executable_path);
        create_executable(&dcg_path);
        write_file(
            &settings_path,
            &format!(
                r#"{{
              "hooks": {{
                "PreToolUse": [
                  {{ "matcher": "Read", "hooks": [{{ "type": "command", "command": "{}" }}] }},
                  {{ "matcher": "Grep", "hooks": [{{ "type": "command", "command": "{}" }}] }},
                  {{
                    "matcher": "Bash",
                    "hooks": [
                      {{ "type": "command", "command": "{}" }},
                      {{ "type": "command", "command": "{}" }}
                    ]
                  }},
                  {{ "matcher": "mcp__.*", "hooks": [{{ "type": "command", "command": "{}" }}] }}
                ]
              }}
            }}"#,
                executable_path.display(),
                executable_path.display(),
                executable_path.display(),
                dcg_path.display(),
                executable_path.display()
            ),
        );

        let value = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
            hooks::Harness::ClaudeCode,
            None,
        )
        .to_json_value();

        assert_eq!(value["schema_version"], "cmdrvl.doctor.v1");
        assert_eq!(value["mode"], "health");
        assert_eq!(value["healthy"], true);
        assert!(
            value["findings"]
                .as_array()
                .expect("findings should be an array")
                .iter()
                .all(|finding| finding["severity"] == "info"),
            "a healthy report has no error findings"
        );
        assert_eq!(value["read_only_contract"], READ_ONLY_DOCTOR_CONTRACT);
        assert!(
            value.get("contract").is_none(),
            "`contract` is reserved for capabilities mode"
        );
        assert_eq!(value["ok"], true);
        assert_eq!(
            value["checks"]
                .as_array()
                .expect("checks should be an array")
                .iter()
                .filter(|check| check["status"] == "ok")
                .count(),
            4,
            "config, audit, hooks and mcp_hook"
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
            hooks::Harness::ClaudeCode,
            None,
        ));

        assert!(rendered.contains("hooks [action_needed]"));
        assert!(rendered.contains("do not resolve to executables"));
        assert!(rendered.contains("run `veil install`"));
    }

    /// Claude settings with a hook for Read, Grep and Bash, and one for MCP
    /// tools when `mcp_command` says what it runs.
    fn settings_with_hooks(repo_root: &Path, command: &str, mcp_command: Option<&str>) -> PathBuf {
        let settings_path = repo_root.join("claude/settings.json");
        let hook = |matcher: &str, command: &str| {
            format!(
                r#"{{ "matcher": "{matcher}", "hooks": [{{ "type": "command", "command": "{command}" }}] }}"#
            )
        };
        let mut entries = vec![
            hook("Read", command),
            hook("Grep", command),
            hook("Bash", command),
        ];
        entries.extend(mcp_command.map(|mcp| hook("mcp__.*", mcp)));
        write_file(
            &settings_path,
            &format!(
                r#"{{ "hooks": {{ "PreToolUse": [{}] }} }}"#,
                entries.join(", ")
            ),
        );
        settings_path
    }

    fn mcp_hook_check(report: &DoctorReport) -> &DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.name == "mcp_hook")
            .expect("a Claude Code report has an mcp_hook check")
    }

    #[test]
    fn doctor_says_when_only_the_mcp_hook_is_missing_and_preflight_still_passes() {
        let repo_root = unique_temp_dir("doctor-no-mcp-hook");
        let executable_path = repo_root.join("bin/veil");
        create_executable(&executable_path);
        // an install made before MCP screening: Read, Grep and Bash only
        let settings_path =
            settings_with_hooks(&repo_root, &executable_path.display().to_string(), None);

        let report = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path.clone()),
            hooks::Harness::ClaudeCode,
            None,
        );

        let hooks_check = report.checks.iter().find(|check| check.name == "hooks");
        assert_eq!(
            hooks_check.map(|check| &check.status),
            Some(&DoctorStatus::Ok)
        );
        let mcp = mcp_hook_check(&report);
        assert_eq!(mcp.status, DoctorStatus::ActionNeeded);
        assert!(
            mcp.detail.contains("MCP tool arguments are not screened"),
            "{}",
            mcp.detail
        );
        assert!(
            mcp.remediation
                .as_deref()
                .is_some_and(|remediation| remediation.contains("veil install")),
            "{:?}",
            mcp.remediation
        );
        assert_eq!(report.exit_code(), 1);

        // operator commands are not refused for it: only the three required
        // hooks are a precondition
        let posture = hooks::inspect_guard_posture(
            hooks::Harness::ClaudeCode,
            false,
            Ok(settings_path),
            None,
        );
        assert!(posture.is_healthy(), "{:?}", posture.blockers());
    }

    #[test]
    fn doctor_mcp_check_passes_when_the_hook_is_installed_or_screening_is_off() {
        let repo_root = unique_temp_dir("doctor-mcp-hook-ok");
        let executable_path = repo_root.join("bin/veil");
        create_executable(&executable_path);
        let command = executable_path.display().to_string();
        let settings_path = settings_with_hooks(&repo_root, &command, Some(&command));

        let installed = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
            hooks::Harness::ClaudeCode,
            None,
        );
        assert_eq!(mcp_hook_check(&installed).status, DoctorStatus::Ok);
        assert!(
            mcp_hook_check(&installed).detail.contains("are screened"),
            "{}",
            mcp_hook_check(&installed).detail
        );

        // with `[mcp] screen = false` the hook is not wanted, so its absence is fine
        let off_root = unique_temp_dir("doctor-mcp-screen-off");
        write_file(&off_root.join(".veil.toml"), "[mcp]\nscreen = false\n");
        let off_settings = settings_with_hooks(&off_root, &command, None);
        let off = build_doctor_report(
            &off_root,
            SettingsPathStatus::Resolved(off_settings),
            hooks::Harness::ClaudeCode,
            None,
        );
        assert_eq!(mcp_hook_check(&off).status, DoctorStatus::Ok);
        assert!(
            mcp_hook_check(&off).detail.contains("screening is off"),
            "{}",
            mcp_hook_check(&off).detail
        );
    }

    #[test]
    fn doctor_mcp_check_reports_a_hook_command_that_does_not_resolve() {
        let repo_root = unique_temp_dir("doctor-mcp-hook-invalid");
        let executable_path = repo_root.join("bin/veil");
        create_executable(&executable_path);
        let settings_path = settings_with_hooks(
            &repo_root,
            &executable_path.display().to_string(),
            Some("/definitely/missing/veil"),
        );

        let report = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
            hooks::Harness::ClaudeCode,
            None,
        );

        let mcp = mcp_hook_check(&report);
        assert_eq!(mcp.status, DoctorStatus::ActionNeeded);
        assert!(mcp.detail.contains("does not resolve"), "{}", mcp.detail);
        assert!(
            mcp.detail.contains("/definitely/missing/veil"),
            "{}",
            mcp.detail
        );
    }

    #[test]
    fn a_harness_whose_hooks_veil_cannot_read_has_no_mcp_hook_check() {
        let repo_root = unique_temp_dir("doctor-mcp-codex");

        let report = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(repo_root.join("claude/settings.json")),
            hooks::Harness::Codex,
            None,
        );

        assert!(report.checks.iter().all(|check| check.name != "mcp_hook"));
    }

    #[test]
    fn doctor_capabilities_json_reports_read_only_no_fix_contract() {
        let rendered = render_doctor_capabilities(&DoctorCapabilitiesArgs { json: true })
            .expect("capabilities should render");
        let report: Value =
            serde_json::from_str(&rendered).expect("capabilities JSON should parse");
        assert_eq!(report["schema_version"], "cmdrvl.doctor.v1");
        assert_eq!(report["mode"], "capabilities");
        let value = &report["doctor"];

        assert_eq!(value["schema_version"], DOCTOR_CAPABILITIES_SCHEMA_VERSION);
        assert_eq!(value["contract"], READ_ONLY_DOCTOR_CONTRACT);
        assert_eq!(value["read_only"], true);
        assert_eq!(value["fix_mode"], "not_available");
        assert_eq!(value["network"], "not_used");
        assert_eq!(value["writes"]["hooks"], false);
        assert_eq!(
            value["fixers"].as_array().map(Vec::len),
            Some(0),
            "first doctor slice must not advertise fixers"
        );
    }

    #[test]
    fn doctor_robot_triage_json_includes_recommendations_for_missing_hooks() {
        let repo_root = unique_temp_dir("doctor-robot-triage");
        let settings_path = repo_root.join("claude/settings.json");
        let report = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(settings_path),
            hooks::Harness::ClaudeCode,
            None,
        );
        let value = report.to_triage_json_value();

        assert_eq!(value["schema_version"], "cmdrvl.doctor.v1");
        assert_eq!(value["mode"], "triage");
        assert_eq!(value["healthy"], false);
        assert_eq!(value["ok"], false);
        assert_eq!(value["summary"]["read_only"], true);
        assert!(
            value["recommended_actions"]
                .as_array()
                .is_some_and(|actions| !actions.is_empty())
        );
        assert!(
            value["next_actions"]
                .as_array()
                .is_some_and(|actions| !actions.is_empty()),
            "an unhealthy triage report must say what to do next"
        );
    }

    #[test]
    fn doctor_exit_code_is_one_exactly_when_an_error_finding_exists() {
        let repo_root = unique_temp_dir("doctor-exit-code");

        // Planted unhealthy: Claude Code with no hooks installed.
        let unhealthy = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(repo_root.join("claude/settings.json")),
            hooks::Harness::ClaudeCode,
            None,
        );
        assert_eq!(unhealthy.exit_code(), 1);
        assert!(!unhealthy.is_healthy());
        let findings = unhealthy.to_json_value()["findings"].clone();
        assert!(
            findings
                .as_array()
                .expect("findings array")
                .iter()
                .any(|finding| finding["id"] == "hooks" && finding["severity"] == "error"),
            "missing hooks must be an error finding"
        );
        assert_eq!(unhealthy.to_json_value()["healthy"], false);

        // Healthy: a non-Claude harness needs no Claude hooks.
        let healthy = build_doctor_report(
            &repo_root,
            SettingsPathStatus::Resolved(repo_root.join("claude/settings.json")),
            hooks::Harness::Codex,
            None,
        );
        assert_eq!(healthy.exit_code(), 0);
        assert_eq!(healthy.to_json_value()["healthy"], true);
    }

    #[test]
    fn doctor_capabilities_report_embeds_the_capabilities_document() {
        let value = doctor_capabilities_report_value().expect("report builds");
        assert_eq!(value["mode"], "capabilities");
        assert_eq!(value["healthy"], true);
        assert_eq!(
            value["contract"],
            serde_json::from_str::<Value>(OPERATOR_JSON).expect("manifest parses")
        );
    }

    #[test]
    fn doctor_robot_docs_names_no_fix_policy() {
        let rendered = render_doctor_robot_docs();

        assert!(rendered.contains("veil doctor health"));
        assert!(rendered.contains("veil doctor capabilities --json"));
        assert!(rendered.contains("No fix mode is available"));
    }

    #[test]
    fn top_level_capabilities_json_describes_standard_agent_surfaces() {
        let rendered = run_capabilities(&CapabilitiesArgs { json: true })
            .expect("top-level capabilities should render");
        let value: Value = serde_json::from_str(&rendered).expect("capabilities JSON should parse");

        assert_eq!(value["schema_version"], "operator.v1");
        assert_eq!(value["discovery"]["triage"], "veil doctor triage --json");
        assert_eq!(
            value["discovery"]["capabilities"],
            "veil capabilities --json"
        );
        assert_eq!(value["discovery"]["robot_docs"], "veil robot-docs guide");
        let commands = value["commands"]
            .as_array()
            .expect("commands should be an array");
        assert!(
            commands.iter().any(|command| command["name"] == "operator"
                && command["guard_preflight_required"] == true)
        );
        assert!(
            commands
                .iter()
                .any(|command| command["name"] == "install" && command["read_only"] == false)
        );
    }

    #[test]
    fn describe_and_capabilities_json_are_the_operator_json_file() {
        let file = include_str!("../operator.json").trim_end();
        assert_eq!(run_describe(), file);
        assert_eq!(
            run_capabilities(&CapabilitiesArgs { json: true }).expect("capabilities renders"),
            file
        );
    }

    #[test]
    fn manifest_guard_preflight_flags_match_main_preflight_list() {
        // main.rs decides which commands run the guard preflight; the manifest must agree.
        let manifest: Value = serde_json::from_str(OPERATOR_JSON).expect("manifest parses");
        for command in manifest["commands"].as_array().expect("commands array") {
            let name = command["name"].as_str().expect("command name");
            let declared = command["guard_preflight_required"] == true;
            // `sandbox` compiles a profile and runs nothing, so main.rs exempts it
            // (command_requires_guard_preflight) and the manifest says `false`.
            let exempt = matches!(
                name,
                "doctor"
                    | "capabilities"
                    | "robot-docs"
                    | "sandbox"
                    | "exec"
                    | "install"
                    | "uninstall"
            );
            assert_eq!(
                declared, !exempt,
                "manifest guard_preflight_required for `{name}` disagrees with main.rs preflight exemptions"
            );
        }
    }

    #[test]
    fn top_level_robot_docs_guide_explains_hook_mode_and_composition() {
        let rendered = run_robot_docs(&RobotDocsArgs { action: None })
            .expect("top-level robot docs should render");

        assert!(rendered.contains("veil --robot-triage"));
        assert!(rendered.contains("Bare `veil` expects"));
        assert!(rendered.contains("airlock"));
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
        write_file(&repo_root.join("protected/dataset.tsv"), "id,value\n1,2\n");

        let rendered =
            render_explain_for_repo(&repo_root, Path::new("protected/dataset.tsv"), false)
                .expect("explain rendering should succeed");
        let protected_pattern = format!(
            "{}/protected/**",
            fs::canonicalize(&repo_root)
                .expect("repo root should canonicalize")
                .display()
        );

        assert!(rendered.contains("Explain"));
        assert!(rendered.contains("matched_by: pack"));
        assert!(rendered.contains("pack: data.tabular"));
        assert!(rendered.contains(&format!("protected_pattern: {protected_pattern}")));
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
