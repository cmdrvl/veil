use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn unique_home(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!("veil-doctor-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temporary HOME should be creatable");
    path
}

fn veil_command(home: &PathBuf) -> Command {
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
