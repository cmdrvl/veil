//! bd-fxa: the hook judges `veil exec <authorized tool> ...` as it judges the
//! tool itself. Inside a sandbox it is the only way to run a spine tool on a
//! protected file, and the denial of a direct read tells the agent to run it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

static COUNTER: AtomicU64 = AtomicU64::new(0);

const VEIL: &str = env!("CARGO_BIN_EXE_veil");

struct Hook {
    decision: String,
    reason: String,
    stderr: String,
}

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "veil-exec-hook-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ))
}

/// A repo with `protected/**` protected, auditing off, an isolated HOME, and
/// the given extra config appended to `.veil.toml`.
fn repo(extra_config: &str) -> (PathBuf, PathBuf) {
    let repo_root = unique_dir("repo");
    let home = unique_dir("home");
    fs::create_dir_all(repo_root.join("protected")).expect("protected dir");
    fs::create_dir_all(&home).expect("home dir");
    for name in ["x.csv", "y.csv"] {
        fs::write(repo_root.join("protected").join(name), "secret,1\n").expect("fixture");
    }
    fs::write(
        repo_root.join(".veil.toml"),
        format!(
            "[sensitivity]\nprotected = [\"protected/**\"]\n\n[policy]\naudit_log = false\n\n{extra_config}"
        ),
    )
    .expect("config");
    (repo_root, home)
}

fn run_hook(repo_root: &Path, home: &Path, command: &str, broker: bool) -> Hook {
    let payload = serde_json::json!({
        "session_id": "veil-exec",
        "cwd": repo_root,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut veil = Command::new(VEIL);
    veil.current_dir(repo_root)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_DYNAMIC_ARGS")
        .env_remove("VEIL_BROKER_SOCKET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if broker {
        veil.env("VEIL_BROKER_SOCKET", "/nonexistent/broker.sock");
    }
    let mut child = veil.spawn().expect("veil should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload should be written");
    let output = child.wait_with_output().expect("veil should exit");
    let denial = common::claude_denial(&output);

    Hook {
        decision: if denial.is_some() { "deny" } else { "allow" }.to_owned(),
        reason: denial.unwrap_or_default(),
        stderr: String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
    }
}

#[test]
fn veil_exec_of_an_authorized_tool_is_judged_as_the_tool() {
    let (repo_root, home) = repo("[spine.denied_flags]\nprofile = [\"--values\"]\n");

    // each tail is run bare and through `veil exec`; the two must agree
    for (tail, expected) in [
        ("shape protected/x.csv", "allow"),
        ("shape protected/x.csv protected/y.csv --key id", "allow"),
        ("profile protected/x.csv --json", "allow"),
        ("rvl protected/x.csv protected/y.csv", "allow"),
        ("shape protected/x.csv | jq .", "allow"),
        ("shape protected/x.csv > shape-report.json", "allow"),
        ("shape --explicit protected/x.csv", "deny"),
        ("shape protected/x.csv --raw=all", "deny"),
        ("profile protected/x.csv --values", "deny"),
        ("shape protected/x.csv; cat protected/x.csv", "deny"),
        ("shape protected/x.csv && head -1 protected/y.csv", "deny"),
        ("shape protected/x.csv | grep -r secret protected", "deny"),
        ("shape $(cat protected/x.csv)", "deny"),
        ("shape protected/x.csv < protected/y.csv", "deny"),
    ] {
        let bare = run_hook(&repo_root, &home, tail, false);
        assert_eq!(bare.decision, expected, "`{tail}`: {}", bare.reason);
        // `--persist` is veil's own flag (bd-3qw): it changes nothing about the
        // tool that runs
        for exec in ["veil exec", "veil exec --persist"] {
            let through = run_hook(&repo_root, &home, &format!("{exec} {tail}"), false);
            assert_eq!(
                through.decision, expected,
                "`{exec} {tail}`: {}",
                through.reason
            );
        }
    }

    // wrappers in front, and veil spelled as the path of the running binary
    for command in [
        "env LANG=C veil exec shape protected/x.csv".to_owned(),
        "nohup veil exec shape protected/x.csv".to_owned(),
        "sh -c 'veil exec shape protected/x.csv'".to_owned(),
        format!("{VEIL} exec shape protected/x.csv"),
    ] {
        let hook = run_hook(&repo_root, &home, &command, false);
        assert_eq!(hook.decision, "allow", "`{command}`: {}", hook.reason);
    }
}

#[test]
fn veil_exec_authorizes_nothing_the_tool_alone_would_not() {
    let (repo_root, home) = repo("");
    fs::create_dir_all(repo_root.join("tools")).expect("tools dir");
    fs::write(repo_root.join("tools/veil"), "#!/bin/sh\ncat \"$3\"\n").expect("impostor");

    for command in [
        "veil exec cat protected/x.csv",
        "veil exec head -5 protected/x.csv",
        "veil exec notatool protected/x.csv",
        "veil exec env cat protected/x.csv",
        "veil exec -- cat protected/x.csv",
        "veil exec --persist cat protected/x.csv",
        // only veil's own flag, and only once, comes between `exec` and the tool
        "veil exec --persist --persist shape protected/x.csv",
        "veil exec --other shape protected/x.csv",
        "./tools/veil exec --persist shape protected/x.csv",
        // another program that happens to be called veil gets no authority
        "./tools/veil exec shape protected/x.csv",
        "tools/veil exec shape protected/x.csv",
        "/tmp/veil exec shape protected/x.csv",
        // other veil subcommands are judged as before
        "veil explain protected/x.csv",
        "veil test protected/x.csv --json",
        "veil shape protected/x.csv",
        "veil --describe exec shape protected/x.csv",
    ] {
        let hook = run_hook(&repo_root, &home, command, false);
        assert_eq!(hook.decision, "deny", "`{command}`: {}", hook.reason);
    }

    for command in ["veil doctor", "veil exec", "veil exec shape --help"] {
        let hook = run_hook(&repo_root, &home, command, false);
        assert_eq!(hook.decision, "allow", "`{command}`: {}", hook.reason);
    }

    // a tool the project does not authorize is not authorized through exec
    let (repo_root, home) = repo("[spine]\nauthorized_tools = [\"profile\"]\n");
    for (command, expected) in [
        ("veil exec shape protected/x.csv", "deny"),
        ("veil exec profile protected/x.csv", "allow"),
    ] {
        let hook = run_hook(&repo_root, &home, command, false);
        assert_eq!(hook.decision, expected, "`{command}`: {}", hook.reason);
    }
}

#[test]
fn the_command_the_sandbox_hint_names_is_allowed_by_the_hook() {
    let (repo_root, home) = repo("");

    let denial = run_hook(&repo_root, &home, "cat protected/x.csv", true);
    assert_eq!(denial.decision, "deny");
    let hint = denial
        .stderr
        .split_once("run: ")
        .and_then(|(_, rest)| rest.split_once(" (or another authorized spine tool)"))
        .map(|(command, _)| command.to_owned())
        .unwrap_or_default();
    assert!(
        hint.contains("<path>"),
        "no command in the hint: {}",
        denial.stderr
    );

    let command = hint.replace("<path>", "protected/x.csv");
    let hook = run_hook(&repo_root, &home, &command, true);
    assert_eq!(hook.decision, "allow", "`{command}`: {}", hook.reason);
}
