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

#[test]
fn doctor_health_exits_zero_without_writing_hook_settings() {
    let home = unique_home("health");
    let output = veil_command(&home)
        .args(["doctor", "health"])
        .output()
        .expect("doctor health should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("veil doctor"));
    assert!(
        !home.join(".claude/settings.json").exists(),
        "read-only doctor must not create Claude settings"
    );
}

#[test]
fn doctor_capabilities_json_advertises_no_fixers() {
    let home = unique_home("capabilities");
    let output = veil_command(&home)
        .args(["doctor", "capabilities", "--json"])
        .output()
        .expect("doctor capabilities should run");

    assert!(output.status.success());
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("capabilities JSON should parse");
    assert_eq!(value["read_only"], true);
    assert_eq!(value["fix_mode"], "not_available");
    assert_eq!(value["fixers"].as_array().map(Vec::len), Some(0));
}

#[test]
fn doctor_robot_triage_json_is_machine_readable() {
    let home = unique_home("triage");
    let output = veil_command(&home)
        .args(["doctor", "--robot-triage"])
        .output()
        .expect("doctor robot triage should run");

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("triage JSON should parse");
    assert_eq!(value["schema_version"], "veil.doctor.triage.v1");
    assert_eq!(value["capabilities"]["read_only"], true);
    assert_eq!(
        value["capabilities"]["fixers"].as_array().map(Vec::len),
        Some(0)
    );
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
        stderr.contains("dcg") && stderr.contains("veil"),
        "stderr should name both required guards, got: {stderr}"
    );
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
