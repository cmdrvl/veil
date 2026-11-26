//! `veil replay` re-evaluates stored tool inputs against a real project config.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

#[path = "common/user.rs"]
mod user;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn repo(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-replay-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::write(root.join("data/secret.csv"), "id,value\n1,x\n").expect("protected file");
    fs::write(root.join("notes.md"), "notes\n").expect("ordinary file");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"data/**\"]\n",
    )
    .expect("project config");
    user::write_config(&root, "[policy]\naudit_log = false\n");
    fs::canonicalize(root).expect("repo should canonicalize")
}

fn record(
    root: &Path,
    ts: u64,
    path: &str,
    decision: &str,
    command: Option<&str>,
    path_is_hash: bool,
) -> String {
    let tool_input = command.map(|command| {
        json!({
            "protocol": "claude_code",
            "tool_kind": "bash",
            "tool_name": "Bash",
            "cwd": root,
            "session_id": "replay-fixture",
            "raw_args": serde_json::to_string(&json!({"command": command})).expect("raw args JSON"),
        })
    });
    serde_json::to_string(&json!({
        "schema_version": "veil.audit.v2",
        "ts": ts.to_string(),
        "tool": "Bash",
        "path": path,
        "decision": decision,
        "reason": null,
        "reason_class": "direct_read",
        "class": null,
        "would_deny": decision == "deny",
        "path_is_hash": path_is_hash,
        "tool_input": tool_input,
    }))
    .expect("audit record JSON")
}

fn read_or_grep_record(
    root: &Path,
    ts: u64,
    path: &str,
    tool_name: &str,
    tool_kind: &str,
    raw_args: Value,
) -> String {
    serde_json::to_string(&json!({
        "schema_version": "veil.audit.v2",
        "ts": ts.to_string(),
        "tool": tool_name,
        "path": path,
        "decision": "allow",
        "reason": null,
        "reason_class": "direct_read",
        "class": null,
        "would_deny": false,
        "path_is_hash": false,
        "tool_input": {
            "protocol": "claude_code",
            "tool_kind": tool_kind,
            "tool_name": tool_name,
            "cwd": root,
            "session_id": "replay-fixture",
            "raw_args": serde_json::to_string(&raw_args).expect("raw args JSON"),
        },
    }))
    .expect("audit record JSON")
}

fn run_replay(root: &Path, audit: &Path, since: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .current_dir(root)
        .env("HOME", root)
        .env("VEIL_HARNESS", "plain")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_EGRESS_POLICY")
        .env_remove("VEIL_DYNAMIC_ARGS")
        .env_remove("VEIL_AUDIT_INPUTS")
        .env_remove("VEIL_AUDIT_LOG")
        .env_remove("VEIL_AUDIT_PATH")
        .arg("replay")
        .arg("--audit")
        .arg(audit)
        .arg("--since")
        .arg(since)
        .output()
        .expect("veil replay should start")
}

#[test]
fn replay_counts_known_flips_respects_since_and_skips_private_or_missing_inputs() {
    let root = repo("flips");
    let audit = root.join("audit.jsonl");
    let protected = root.join("data/secret.csv").to_string_lossy().into_owned();
    let ordinary = root.join("notes.md").to_string_lossy().into_owned();
    let rows = [
        // Excluded by --since.
        record(
            &root,
            99,
            &protected,
            "allow",
            Some("cat data/secret.csv"),
            false,
        ),
        record(
            &root,
            100,
            &protected,
            "allow",
            Some("cat data/secret.csv"),
            false,
        ),
        record(&root, 200, &ordinary, "deny", Some("cat notes.md"), false),
        record(
            &root,
            300,
            "blake3:0123456789abcdef",
            "allow",
            Some("cat data/secret.csv"),
            true,
        ),
        record(&root, 400, &protected, "allow", None, false),
    ];
    fs::write(&audit, format!("{}\n", rows.join("\n"))).expect("audit fixture");

    let output = run_replay(&root, &audit, "100");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("entries: 4"), "{report}");
    assert!(report.contains("replayed: 2"), "{report}");
    assert!(report.contains("skipped: 2"), "{report}");
    assert!(
        report.contains("direct_read: allow -> deny 1, deny -> allow 1"),
        "{report}"
    );
    assert!(report.contains("cat data/secret.csv"), "{report}");
}

#[test]
fn replay_caps_the_newly_denied_command_list_at_twenty() {
    let root = repo("top-twenty");
    let audit = root.join("audit.jsonl");
    let mut rows = Vec::new();
    for index in 0..21 {
        let name = format!("data/secret-{index:02}.csv");
        fs::write(root.join(&name), "private\n").expect("protected fixture");
        let path = root.join(&name).to_string_lossy().into_owned();
        rows.push(record(
            &root,
            100,
            &path,
            "allow",
            Some(&format!("cat {name}")),
            false,
        ));
    }
    fs::write(&audit, format!("{}\n", rows.join("\n"))).expect("audit fixture");

    let output = run_replay(&root, &audit, "0");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8_lossy(&output.stdout);
    let top = report
        .split("Top newly denied commands:\n")
        .nth(1)
        .expect("top commands section");
    let listed = top.lines().filter(|line| line.starts_with("  ")).count();
    assert_eq!(listed, 20, "{report}");
}

#[test]
fn replay_accepts_saved_read_and_grep_inputs() {
    let root = repo("read-grep");
    let audit = root.join("audit.jsonl");
    let protected = root.join("data/secret.csv").to_string_lossy().into_owned();
    let rows = [
        read_or_grep_record(
            &root,
            100,
            &protected,
            "Read",
            "read",
            json!({"file_path": "data/secret.csv"}),
        ),
        read_or_grep_record(
            &root,
            101,
            &protected,
            "Grep",
            "grep",
            json!({"path": "data/secret.csv", "pattern": "value"}),
        ),
    ];
    fs::write(&audit, format!("{}\n", rows.join("\n"))).expect("audit fixture");

    let output = run_replay(&root, &audit, "0");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("entries: 2"), "{report}");
    assert!(report.contains("replayed: 2"), "{report}");
    assert!(report.contains("allow -> deny 2"), "{report}");
}
