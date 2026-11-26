//! bd-tmn: a call veil has no reason to block gets no decision, so the
//! harness's own permission prompts still apply. The real binary, one payload
//! per harness protocol.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;

const CANARY: &str = "QUARTZ-NO-DECISION-CANARY";

fn fixture(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "veil-no-decision-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("protected")).expect("protected dir");
    fs::write(root.join("protected/secret.txt"), CANARY).expect("protected file");
    fs::write(root.join("notes.md"), "notes\n").expect("ordinary file");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected/**\"]\n",
    )
    .expect("config");
    fs::canonicalize(root).expect("canonical fixture root")
}

fn hook(root: &Path, payload: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .current_dir(root)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veil should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload should be written");
    child.wait_with_output().expect("veil should exit")
}

fn claude(root: &Path, tool: &str, input: Value) -> Value {
    json!({
        "session_id": "no-decision",
        "cwd": root,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
}

fn copilot(root: &Path, tool: &str, input: Value) -> Value {
    json!({ "cwd": root, "toolName": tool, "toolArgs": input.to_string() })
}

/// Exit 0 and not one byte on stdout, not even a newline.
#[track_caller]
fn assert_prints_nothing(output: &Output, what: &str) {
    assert_eq!(output.status.code(), Some(0), "{what}: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "", "{what}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "", "{what}");
}

#[test]
fn an_ordinary_claude_code_call_gets_no_output() {
    let root = fixture("claude");
    for (tool, input) in [
        ("Read", json!({ "file_path": "notes.md" })),
        ("Grep", json!({ "pattern": "x", "path": "notes.md" })),
        ("Bash", json!({ "command": "ls" })),
        ("Bash", json!({ "command": "git status" })),
        ("mcp__mail__send_email", json!({ "to": "a@example.com" })),
        ("Write", json!({ "file_path": "out.txt", "content": "x" })),
    ] {
        let output = hook(&root, &claude(&root, tool, input.clone()));
        assert_prints_nothing(&output, &format!("{tool} {input}"));
    }
}

#[test]
fn an_ordinary_copilot_call_gets_no_output() {
    let root = fixture("copilot");
    for (tool, input) in [
        ("view", json!({ "file_path": "notes.md" })),
        ("grep", json!({ "pattern": "x", "path": "notes.md" })),
        ("bash", json!({ "command": "ls" })),
    ] {
        let output = hook(&root, &copilot(&root, tool, input.clone()));
        assert_prints_nothing(&output, &format!("{tool} {input}"));
    }
}

#[test]
fn a_protected_read_is_still_denied_for_claude_code_and_copilot() {
    let root = fixture("deny");

    let output = hook(
        &root,
        &claude(
            &root,
            "Read",
            json!({ "file_path": "protected/secret.txt" }),
        ),
    );
    let reason = common::claude_denial(&output).expect("the protected read is denied");
    assert!(reason.contains("blocked by policy"), "{reason}");

    let output = hook(
        &root,
        &copilot(
            &root,
            "view",
            json!({ "file_path": "protected/secret.txt" }),
        ),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).expect("a deny is printed");
    assert_eq!(document["permissionDecision"], "deny", "{document}");
    assert!(
        document["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("blocked by policy")),
        "{document}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
}

/// Gemini CLI and Grok keep their reply: neither treats `allow` as approval.
#[test]
fn gemini_and_grok_still_get_their_allow_reply() {
    let root = fixture("gemini-grok");
    let gemini = json!({
        "session_id": "no-decision",
        "cwd": root,
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": { "command": "ls" },
    });
    let grok = json!({
        "sessionId": "no-decision",
        "cwd": root,
        "hookEventName": "pre_tool_use",
        "toolName": "run_terminal_command",
        "toolInput": { "command": "ls" },
    });

    for payload in [gemini, grok] {
        let output = hook(&root, &payload);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"decision\":\"allow\"}\n",
            "{payload}"
        );
    }
}

/// The reader every other test uses cannot count a failure as allowed.
#[cfg(unix)]
#[test]
fn the_shared_reader_takes_only_a_clean_silent_exit_as_allowed() {
    let run = |script: &str| {
        Command::new("/bin/sh")
            .args(["-c", script])
            .output()
            .expect("sh should run")
    };
    let accepts = |output: &Output| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            common::claude_denial(output)
        }))
    };

    assert_eq!(accepts(&run("exit 0")).ok(), Some(None));
    for script in [
        // silent, but not a clean exit
        "exit 1",
        "exit 2",
        "exit 101",
        "kill -KILL $$",
        // a clean exit that printed something other than one deny
        "echo",
        "echo panicked",
        r#"echo '{}'"#,
        r#"echo '{"decision":"allow"}'"#,
        r#"echo '{"permissionDecision":"deny","permissionDecisionReason":"x"}'"#,
        r#"echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'"#,
        r#"echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"x"}}'"#,
        r#"echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'"#,
        // a deny from a hook that then failed
        r#"echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}'; exit 1"#,
    ] {
        assert!(accepts(&run(script)).is_err(), "accepted `{script}`");
    }
    let deny = run(
        r#"echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}'"#,
    );
    assert_eq!(accepts(&deny).ok(), Some(Some("x".to_owned())));
}
