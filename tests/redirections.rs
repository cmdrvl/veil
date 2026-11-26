//! A redirection glued to the word before it (`cat .env>out.txt`) is the shell's
//! redirection, not part of the file's name. veil used to hand `.env>out.txt` on
//! as one word, which no protected pattern matches: with nothing configured
//! beyond the built-in packs, `cat .env>out.txt` copied a protected file to one
//! that was not, and `cat out.txt` read it from there. These tests drive the
//! real `veil` binary with Claude Code Bash payloads.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

mod common;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A repo with a protected `data/holdings.csv`, an ordinary `notes.md` and an
/// `.env`. `protected` is the `[sensitivity] protected` list, or `None` to leave
/// the project config with no sensitivity patterns at all (built-in packs only).
fn repo(label: &str, protected: Option<&str>) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-redirect-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::write(
        root.join("data/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("file");
    fs::write(root.join("notes.md"), "notes\n").expect("note");
    fs::write(root.join(".env"), "TOKEN=abc\n").expect("env file");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let sensitivity = protected
        .map(|list| format!("[sensitivity]\nprotected = {list}\n\n"))
        .unwrap_or_default();
    fs::write(
        root.join(".veil.toml"),
        format!("{sensitivity}[policy]\naudit_log = false\n"),
    )
    .expect("config should be written");

    root
}

/// Whether the hook denies a Bash command run from the repo root.
fn denied(root: &PathBuf, command: &str) -> bool {
    let payload = json!({
        "session_id": "redirections",
        "cwd": root,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .current_dir(root)
        .env("HOME", root)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_DYNAMIC_ARGS")
        .env_remove("VEIL_AUDIT_LOG")
        .env_remove("VEIL_AUDIT_PATH")
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
    let output = child.wait_with_output().expect("veil should exit");

    common::claude_denial(&output).is_some()
}

fn assert_all_denied(root: &PathBuf, commands: &[&str]) {
    for command in commands {
        assert!(denied(root, command), "should be denied: {command}");
    }
}

#[test]
fn a_redirect_glued_to_a_builtin_protected_file_does_not_hide_it() {
    // nothing configured: `.env` is protected by the built-in packs
    let root = repo("builtin", None);

    assert_all_denied(
        &root,
        &[
            "cat .env",
            "cat .env >out.txt",
            "cat .env>out.txt",
            "cat .env>>out.txt",
            "cat .env>&2",
            "cat .env>|out.txt",
            "cat .env&>/dev/null",
            "cat .env&>>out.txt",
            "cat .env>out.txt 2>&1",
            "cat .env<<<x",
            "cat<.env",
            "head -1 .env>out.txt",
            "tail .env>out.txt",
            "grep T .env>out.txt",
            "sort .env>out.txt",
            "awk 1 .env>out.txt",
            "sed p .env>out.txt",
            "cp .env>out.txt /tmp/x",
            "cat '.env'>out.txt",
            "cat \".env\">out.txt",
        ],
    );
}

#[test]
fn a_command_gets_the_same_decision_glued_to_its_redirect_as_spaced_from_it() {
    // Whatever veil decides about `cmd .env >out.txt`, it decides about
    // `cmd .env>out.txt`: the shell runs them the same way. (`wc -l .env` is let
    // through as a count, so both forms of it are.)
    for (label, protected, file) in [
        ("parity-builtin", None, ".env"),
        (
            "parity-named",
            Some(r#"["**/holdings.csv"]"#),
            "data/holdings.csv",
        ),
        ("parity-clean", Some(r#"["**/holdings.csv"]"#), "notes.md"),
    ] {
        let root = repo(label, protected);
        for program in [
            "cat",
            "head -3",
            "tail -n 2",
            "less",
            "grep a",
            "grep -c a",
            "grep -l a",
            "rg a",
            "awk 1",
            "sed p",
            "sort",
            "cut -f1",
            "wc -l",
            "jq .",
            "cp",
            "mv",
            "xxd",
            "base64",
            "python3 -c 'print(1)'",
            "env cat",
            "xargs cat",
        ] {
            for (spaced, glued) in [
                (
                    format!("{program} {file} >out.txt"),
                    format!("{program} {file}>out.txt"),
                ),
                (
                    format!("{program} {file} >>out.txt"),
                    format!("{program} {file}>>out.txt"),
                ),
                (
                    format!("{program} {file} >&2"),
                    format!("{program} {file}>&2"),
                ),
                (
                    format!("{program} {file} &>/dev/null"),
                    format!("{program} {file}&>/dev/null"),
                ),
                (
                    format!("{program} {file} <in.txt"),
                    format!("{program} {file}<in.txt"),
                ),
            ] {
                assert_eq!(
                    denied(&root, &glued),
                    denied(&root, &spaced),
                    "`{glued}` is decided differently from `{spaced}`"
                );
            }
        }
    }
}

#[test]
fn a_redirect_glued_to_a_file_named_in_the_project_config_does_not_hide_it() {
    // a pattern that names the file, so the directory the file is in tells veil nothing
    let root = repo("named", Some(r#"["**/holdings.csv"]"#));

    assert_all_denied(
        &root,
        &[
            "cat data/holdings.csv",
            "cat data/holdings.csv>out.txt",
            "cat data/holdings.csv>>out.txt",
            "cat data/holdings.csv>&2",
            "cat data/holdings.csv&>/dev/null",
            "head -3 data/holdings.csv>out.txt",
            "grep a data/holdings.csv>out.txt",
            "awk 1 data/holdings.csv>out.txt",
            "sort data/holdings.csv>out.txt",
            "cp data/holdings.csv>out.txt /tmp/x",
            "cat data/holdings.csv<<<x",
            "cat<data/holdings.csv",
            "cat <data/holdings.csv>out.txt",
            "echo go; cat data/holdings.csv>out.txt",
            "cat notes.md && cat data/holdings.csv>out.txt",
            "(cat data/holdings.csv>out.txt)",
            "sh -c 'cat data/holdings.csv>out.txt'",
            "cat data/holdings.csv>out.txt | wc -l",
        ],
    );
}

#[test]
fn a_redirect_is_still_no_reason_to_deny_what_names_nothing_protected() {
    let root = repo("allowed", Some(r#"["**/holdings.csv"]"#));

    for command in [
        "cat notes.md>out.txt",
        "cat notes.md >out.txt 2>&1",
        "cat notes.md 2>/dev/null",
        "echo hello>out.txt",
        "echo hello>>out.txt",
        "ls>listing.txt",
        "ls data 2>&1",
        "cat <notes.md",
        "cat<notes.md",
        // the `2` is part of the file name here, not a file descriptor: it is
        // `holdings.csv2`, which is not protected
        "cat data/holdings.csv2>/dev/null",
        // quoted, `>` is data
        "echo 'data/holdings.csv>x'",
        "grep -c 'a>b' notes.md",
        "awk '$1>2' notes.md",
        "cut -d'>' -f1 notes.md",
    ] {
        assert!(!denied(&root, command), "should be allowed: {command}");
    }
}
