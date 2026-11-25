use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn unique_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!("veil-doctor-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temporary HOME should be creatable");
    path
}

fn veil_command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command.env("HOME", home);
    command.env("XDG_STATE_HOME", home.join("state"));
    command.env("XDG_CONFIG_HOME", home.join("config"));
    command.env_remove("VEIL_PROTECTED");
    command.env_remove("VEIL_SAFE_PATTERNS");
    command.env_remove("VEIL_SPINE_TOOLS");
    command.env_remove("VEIL_POLICY");
    command.env_remove("VEIL_AUDIT_LOG");
    command.env_remove("VEIL_AUDIT_PATH");
    command.env_remove("VEIL_CLAUDE_SETTINGS_PATH");
    // Deterministic harness regardless of where the suite runs (agent, CI, shell).
    for marker in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_SANDBOX",
        "CODEX_THREAD_ID",
        "CODEX_CI",
        "GEMINI_CLI",
        "CURSOR_AGENT",
        "CURSOR_TRACE_ID",
    ] {
        command.env_remove(marker);
    }
    command.env("VEIL_HARNESS", "claude-code");
    command
}

/// A veil command under `harness` whose PATH contains only `path_dirs`, so
/// `dcg` is discoverable only when the test put it there.
fn veil_command_for(home: &Path, harness: &str, path_dirs: &[&Path]) -> Command {
    let mut command = veil_command(home);
    command.env("VEIL_HARNESS", harness);
    command.env(
        "PATH",
        env::join_paths(path_dirs).expect("test PATH should join"),
    );
    command
}

fn create_executable(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("executable parent should be creatable");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("test executable should be writable");
    file.write_all(b"#!/bin/sh\nexit 0\n")
        .expect("test executable should be writable");
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

fn install_healthy_guard_hooks(home: &Path) {
    let dcg_path = home.join("bin/dcg");
    create_executable(&dcg_path);
    let settings_path = home.join(".claude/settings.json");
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).expect("settings parent should be creatable");
    }
    fs::write(
        settings_path,
        format!(
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
                  }}
                ]
              }}
            }}"#,
            env!("CARGO_BIN_EXE_veil"),
            env!("CARGO_BIN_EXE_veil"),
            env!("CARGO_BIN_EXE_veil"),
            dcg_path.display()
        ),
    )
    .expect("settings should be writable");
}

fn doctor_json(home: &Path) -> (Option<i32>, Value) {
    let output = veil_command(home)
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");
    let value: Value = serde_json::from_slice(&output.stdout).expect("health JSON should parse");
    (output.status.code(), value)
}

fn check<'a>(report: &'a Value, name: &str) -> &'a Value {
    let found = report["checks"]
        .as_array()
        .expect("checks should be an array")
        .iter()
        .find(|check| check["name"] == name);
    assert!(found.is_some(), "no `{name}` check in {report}");
    found.expect("asserted just above")
}

#[test]
fn veil_install_adds_the_mcp_hook_and_doctor_then_passes() {
    let home = unique_home("install-mcp");
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");

    let install = veil_command_for(&home, "claude-code", &[&empty_bin])
        .arg("install")
        .output()
        .expect("install should run");
    assert!(install.status.success(), "{install:?}");

    let settings: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude/settings.json")).expect("settings should exist"),
    )
    .expect("settings should parse");
    let matchers: Vec<&str> = settings["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse should be an array")
        .iter()
        .map(|entry| entry["matcher"].as_str().expect("matcher"))
        .collect();
    assert_eq!(matchers, ["Read", "Grep", "Bash", "mcp__.*"]);

    let (code, report) = doctor_json(&home);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(check(&report, "mcp_hook")["status"], "ok", "{report}");

    // installing again changes nothing
    let again = veil_command_for(&home, "claude-code", &[&empty_bin])
        .arg("install")
        .output()
        .expect("install should run");
    assert!(again.status.success(), "{again:?}");
    let settings_again: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude/settings.json")).expect("settings should exist"),
    )
    .expect("settings should parse");
    assert_eq!(settings_again, settings);
}

#[test]
fn an_install_that_predates_mcp_screening_is_reported_but_still_runs_operator_commands() {
    let home = unique_home("old-install");
    install_healthy_guard_hooks(&home); // Read, Grep and Bash only

    // operator commands are not refused for the missing MCP hook
    let packs = veil_command(&home)
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");
    assert!(
        packs.status.success(),
        "{}",
        String::from_utf8_lossy(&packs.stderr)
    );

    // doctor says so, with the way to fix it, and exits 1
    let (code, report) = doctor_json(&home);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(check(&report, "hooks")["status"], "ok", "{report}");
    let mcp = check(&report, "mcp_hook");
    assert_eq!(mcp["status"], "action_needed", "{report}");
    assert!(
        mcp["remediation"]
            .as_str()
            .is_some_and(|remediation| remediation.contains("veil install")),
        "{mcp}"
    );
    assert!(
        report["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding["id"] == "mcp_hook" && finding["severity"] == "error")),
        "{report}"
    );

    // the guard posture is still healthy: only doctor reports the gap
    assert_eq!(report["guard_posture"]["preflight_ok"], true, "{report}");

    // after `veil install` the gap is closed
    let install = veil_command(&home)
        .arg("install")
        .output()
        .expect("install should run");
    assert!(install.status.success(), "{install:?}");
    let (code, report) = doctor_json(&home);
    assert_eq!(code, Some(0), "{report}");
}

#[test]
fn doctor_health_exits_one_when_claude_hooks_are_missing_and_writes_nothing() {
    // veil_command() pins the harness to claude-code and HOME is empty: unhealthy.
    let home = unique_home("health");
    let output = veil_command(&home)
        .args(["doctor", "health"])
        .output()
        .expect("doctor health should run");

    assert_eq!(output.status.code(), Some(1), "unhealthy doctor exits 1");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("veil doctor"));
    assert!(
        !home.join(".claude/settings.json").exists(),
        "read-only doctor must not create Claude settings"
    );
}

#[test]
fn doctor_says_veil_is_hook_only_whether_or_not_it_is_healthy() {
    // unhealthy: claude-code harness, no hooks installed
    let home = unique_home("enforcement-unhealthy");
    let output = veil_command(&home)
        .arg("doctor")
        .output()
        .expect("doctor should run");
    assert_eq!(output.status.code(), Some(1), "unhealthy doctor exits 1");
    let text = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(
        text.contains("enforcement: hook-only (advisory; parser-based)"),
        "{text}"
    );

    // healthy: a harness with nothing to verify
    let home = unique_home("enforcement-healthy");
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");
    let output = veil_command_for(&home, "codex", &[&empty_bin])
        .arg("doctor")
        .output()
        .expect("doctor should run");
    assert_eq!(output.status.code(), Some(0), "healthy doctor exits 0");
    let text = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(
        text.contains("enforcement: hook-only (advisory; parser-based)"),
        "{text}"
    );
    assert!(
        !text.contains("enforcement: sandbox"),
        "nothing in veil enforces a sandbox: {text}"
    );
}

#[test]
fn doctor_json_carries_the_enforcement_object() {
    let home = unique_home("enforcement-json");
    let (_, report) = doctor_json(&home);

    assert_eq!(report["enforcement"]["mode"], "hook-only", "{report}");
    assert_eq!(
        report["enforcement"]["summary"], "advisory; parser-based",
        "{report}"
    );
    assert_eq!(report["enforcement"]["sandbox"], false, "{report}");
}

#[test]
fn doctor_health_exits_zero_when_healthy() {
    let home = unique_home("health-ok");
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");

    let output = veil_command_for(&home, "codex", &[&empty_bin])
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");

    assert_eq!(output.status.code(), Some(0), "healthy doctor exits 0");
    let value: Value = serde_json::from_slice(&output.stdout).expect("health JSON should parse");
    assert_eq!(value["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(value["mode"], "health");
    assert_eq!(value["healthy"], true);
}

#[test]
fn doctor_json_exit_code_tracks_health_never_two() {
    let home = unique_home("health-json-unhealthy");
    let output = veil_command(&home)
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");

    // A parsed unhealthy report is exit 1, never the usage-error code 2.
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).expect("health JSON should parse");
    assert_eq!(value["healthy"], false);
    assert!(
        value["findings"].as_array().is_some_and(|findings| findings
            .iter()
            .any(|finding| finding["id"] == "hooks" && finding["severity"] == "error")),
        "the unhealthy report must name the failing check: {value}"
    );
}

#[test]
fn doctor_capabilities_json_embeds_the_operator_contract() {
    let home = unique_home("capabilities");
    let output = veil_command(&home)
        .args(["doctor", "capabilities", "--json"])
        .output()
        .expect("doctor capabilities should run");

    assert!(output.status.success());
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("capabilities JSON should parse");
    assert_eq!(value["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(value["mode"], "capabilities");
    assert_eq!(value["contract"]["schema_version"], "operator.v1");
    assert_eq!(value["doctor"]["read_only"], true);
    assert_eq!(value["doctor"]["fix_mode"], "not_available");
    assert_eq!(value["doctor"]["fixers"].as_array().map(Vec::len), Some(0));
}

#[test]
fn deprecated_robot_triage_spellings_emit_the_same_document_as_doctor_triage() {
    let home = unique_home("triage-aliases");
    let triage = |args: &[&str]| {
        let output = veil_command(&home)
            .args(args)
            .output()
            .expect("triage should run");
        // Unhealthy under claude-code with no hooks: every spelling exits 1.
        assert_eq!(output.status.code(), Some(1), "{args:?} exit code");
        serde_json::from_slice::<Value>(&output.stdout).expect("triage JSON should parse")
    };

    let canonical = triage(&["doctor", "triage", "--json"]);
    assert_eq!(canonical["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(canonical["mode"], "triage");
    assert!(
        canonical["next_actions"]
            .as_array()
            .is_some_and(|actions| !actions.is_empty()),
        "unhealthy triage must list next_actions"
    );
    assert_eq!(canonical["doctor"]["read_only"], true);

    assert_eq!(triage(&["doctor", "--robot-triage"]), canonical);
    assert_eq!(triage(&["--robot-triage"]), canonical);
}

#[test]
fn top_level_capabilities_json_is_available_without_guard_hooks() {
    let home = unique_home("top-level-capabilities");
    let output = veil_command(&home)
        .args(["capabilities", "--json"])
        .output()
        .expect("top-level capabilities should run");

    assert!(output.status.success());
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("capabilities JSON should parse");
    assert_eq!(value["schema_version"], "operator.v1");
    assert_eq!(
        value["discovery"]["capabilities"],
        "veil capabilities --json"
    );
    assert_eq!(value["composition"]["family"], "cmdrvl-boundary-guard");
    assert_eq!(
        value["composition"]["role"],
        "pre-tool guard that keeps raw sensitive files out of agent context"
    );
    assert!(
        value["composition"]["canonical_chain"][1]
            .as_str()
            .is_some_and(|step| step.contains("authorized spine subprocesses"))
    );
    assert!(
        value["composition"]["agent_rules"][2]
            .as_str()
            .is_some_and(|step| step.contains("airlock"))
    );
}

#[test]
fn top_level_robot_docs_guide_is_available_without_guard_hooks() {
    let home = unique_home("top-level-robot-docs");
    let output = veil_command(&home)
        .args(["robot-docs", "guide"])
        .output()
        .expect("top-level robot docs should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("veil robot-docs guide"));
    assert!(stdout.contains("Bare `veil` expects"));
    assert!(stdout.contains("Use `dcg` to block destructive shell commands."));
    assert!(stdout.contains("Use `airlock` to attest derived artifacts"));
}

#[test]
fn bare_empty_stdin_explains_hook_mode_and_discovery_commands() {
    let home = unique_home("empty-stdin");
    let output = veil_command(&home)
        .output()
        .expect("bare empty stdin should return a diagnostic");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("no hook payload received"));
    assert!(stderr.contains("veil --robot-triage"));
    assert!(stderr.contains("veil capabilities --json"));
}

#[test]
fn doctor_fix_is_not_available() {
    let home = unique_home("fix");
    let output = veil_command(&home)
        .args(["doctor", "--fix"])
        .output()
        .expect("doctor --fix should return a parser error");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("--fix"));
}

#[test]
fn domain_commands_fail_closed_without_guard_hooks() {
    let home = unique_home("preflight-missing");
    let output = veil_command(&home)
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(
        stderr.contains("guard preflight failed"),
        "stderr should report the failed guard preflight, got: {stderr}"
    );
    assert!(
        stderr.contains("veil Read/Grep/Bash hooks"),
        "stderr should name the missing veil hooks, got: {stderr}"
    );
    assert!(
        !stderr.contains("require_dcg` but"),
        "dcg must not be a blocker unless require_dcg is set, got: {stderr}"
    );
}

#[test]
fn claude_code_with_healthy_veil_hooks_does_not_need_dcg() {
    let home = unique_home("preflight-no-dcg");
    install_healthy_guard_hooks(&home);
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");
    // Rewrite settings so no dcg Bash hook exists at all.
    let veil = env!("CARGO_BIN_EXE_veil");
    fs::write(
        home.join(".claude/settings.json"),
        format!(
            r#"{{"hooks":{{"PreToolUse":[
              {{"matcher":"Read","hooks":[{{"type":"command","command":"{veil}"}}]}},
              {{"matcher":"Grep","hooks":[{{"type":"command","command":"{veil}"}}]}},
              {{"matcher":"Bash","hooks":[{{"type":"command","command":"{veil}"}}]}}
            ]}}}}"#
        ),
    )
    .expect("settings should be writable");

    let output = veil_command_for(&home, "claude-code", &[&empty_bin])
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");

    assert!(
        output.status.success(),
        "veil hooks alone must satisfy preflight; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn non_claude_harnesses_pass_preflight_without_claude_hooks_or_dcg() {
    for harness in ["codex", "gemini-cli", "cursor", "plain"] {
        let home = unique_home(&format!("preflight-{harness}"));
        let empty_bin = home.join("empty-bin");
        fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");

        let output = veil_command_for(&home, harness, &[&empty_bin])
            .args(["packs", "--json"])
            .output()
            .expect("domain command should run");

        assert!(
            output.status.success(),
            "{harness}: preflight must not require Claude hooks or dcg; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !home.join(".claude/settings.json").exists(),
            "{harness}: must not touch Claude settings"
        );
    }
}

#[test]
fn require_dcg_is_enforced_for_non_claude_harnesses_via_path() {
    let home = unique_home("preflight-require-dcg");
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");
    let config_dir = home.join(".cmdrvl/config/veil");
    fs::create_dir_all(&config_dir).expect("config dir should be creatable");
    fs::write(
        config_dir.join("config.toml"),
        "[policy]\nrequire_dcg = true\n",
    )
    .expect("config should be writable");

    let refused = veil_command_for(&home, "codex", &[&empty_bin])
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");
    assert!(
        !refused.status.success(),
        "require_dcg without dcg must refuse"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("dcg is required by `[policy] require_dcg` but is missing"),
        "stderr should explain the dcg requirement, got: {stderr}"
    );

    let dcg_bin = home.join("dcg-bin");
    create_executable(&dcg_bin.join("dcg"));
    let allowed = veil_command_for(&home, "codex", &[&dcg_bin])
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");
    assert!(
        allowed.status.success(),
        "require_dcg with dcg on PATH must pass; stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn doctor_json_reports_guard_posture_for_agents() {
    let home = unique_home("posture-json");
    let empty_bin = home.join("empty-bin");
    fs::create_dir_all(&empty_bin).expect("empty bin dir should be creatable");

    for (subcommand_args, label) in [
        (vec!["doctor", "health", "--json"], "doctor health"),
        (vec!["doctor", "--robot-triage"], "doctor --robot-triage"),
        (vec!["--robot-triage"], "--robot-triage"),
    ] {
        let output = veil_command_for(&home, "codex", &[&empty_bin])
            .args(&subcommand_args)
            .output()
            .expect("doctor should run");
        assert!(output.status.success(), "{label} should exit zero");
        let value: Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON should parse");
        let posture = &value["guard_posture"];
        assert_eq!(posture["harness"], "codex", "{label}");
        assert_eq!(posture["veil_hooks"]["status"], "unverified", "{label}");
        assert_eq!(posture["dcg"]["required"], false, "{label}");
        assert_eq!(posture["dcg"]["status"], "missing", "{label}");
        assert_eq!(posture["preflight_ok"], true, "{label}");
    }
}

#[test]
fn domain_commands_run_when_guard_hooks_are_healthy() {
    let home = unique_home("preflight-healthy");
    install_healthy_guard_hooks(&home);

    let output = veil_command(&home)
        .args(["packs", "--json"])
        .output()
        .expect("domain command should run");

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("packs JSON should parse");
    assert!(
        value["packs"]
            .as_array()
            .is_some_and(|packs| !packs.is_empty()),
        "packs JSON should include the built-in inventory"
    );
}
