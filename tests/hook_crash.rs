//! A hook that crashes must still block the call (bd-chg). A process that dies
//! on a signal, or exits with any status but 2, does not stop a tool call, so
//! `veil` judges the call in a second process and refuses when that one ends in
//! any other way than with an answer.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

mod common;

/// Makes the process that judges a call panic once it has started.
const FORCED_PANIC: &str = "VEIL_TEST_HOOK_PANIC";

/// More levels than the stack of either build holds.
const DEEP: usize = 200_000;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    project: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-crash-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let fixture = Self {
            project: root.join("project"),
            home: root.join("home"),
        };
        fs::create_dir_all(fixture.project.join("protected")).expect("protected");
        fs::create_dir_all(&fixture.home).expect("home");
        fs::write(fixture.project.join("protected/x.csv"), "a,b\n").expect("protected file");
        fs::write(
            fixture.project.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected/**\"]\n",
        )
        .expect("config");
        fixture
    }

    fn payload(&self, command: &str) -> String {
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.project,
        })
        .to_string()
    }

    fn hook(&self, input: &str, forced_panic: bool) -> Output {
        let mut veil = Command::new(env!("CARGO_BIN_EXE_veil"));
        veil.current_dir(&self.project)
            .env_clear()
            .env("HOME", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if forced_panic {
            veil.env(FORCED_PANIC, "1");
        }
        let mut child = veil.spawn().expect("veil should spawn");
        let mut pipe = child.stdin.take().expect("stdin should be piped");
        // a hook that dies early may close the pipe before it has read it all
        let _ = pipe.write_all(input.as_bytes());
        drop(pipe);
        child.wait_with_output().expect("veil should exit")
    }
}

/// Exit status 2 is what blocks the call. Nothing goes to stdout, where a part
/// of a reply could be read as one.
#[track_caller]
fn assert_blocked_by_the_crash(output: &Output, label: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{label}: {} {stderr}",
        output.status
    );
    assert!(
        output.stdout.is_empty(),
        "{label}: nothing on stdout, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("veil crashed while checking this call, so it is blocked"),
        "{label}: {stderr}"
    );
}

#[test]
fn a_panic_blocks_the_call() {
    let fixture = Fixture::new();
    let output = fixture.hook(&fixture.payload("echo MARKER-IN-THE-COMMAND"), true);
    assert_blocked_by_the_crash(&output, "forced panic");
    // what a panic says can quote what veil was reading
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("forced by"),
        "the panic's own words should not be passed on"
    );
}

/// Each of these ran veil out of stack, where it died on a signal. A shell runs
/// the first line before it reads the second, so the call has to be blocked
/// whatever the shell makes of the rest.
#[test]
fn running_out_of_stack_blocks_the_call() {
    let fixture = Fixture::new();
    let nested = |open: &str, core: &str, close: &str| {
        format!("{}{core}{}", open.repeat(DEEP), close.repeat(DEEP))
    };
    let second_lines = [
        format!("echo {}", nested("\"$(", "true", ")\"")),
        format!(
            "python3 -c 'import subprocess; subprocess.run({})'",
            nested("[", "", "]")
        ),
        format!(
            "python3 -c 'import os; os.system({})'",
            nested("(", "\"true\"", ")")
        ),
        format!("python3 -c 'open({})'", nested("Path(", "\"a\"", ")")),
    ];

    for second_line in second_lines {
        let label: String = second_line.chars().take(60).collect();
        let command = format!("cat protected/x.csv\n{second_line}");
        let output = fixture.hook(&fixture.payload(&command), false);
        assert_blocked_by_the_crash(&output, &label);
    }
}

#[test]
fn answers_and_errors_pass_through_unchanged() {
    let fixture = Fixture::new();

    let allowed = fixture.hook(&fixture.payload("echo hello"), false);
    assert_eq!(common::claude_denial(&allowed), None);
    assert!(allowed.stderr.is_empty(), "{:?}", allowed.stderr);

    let denied = fixture.hook(&fixture.payload("cat protected/x.csv"), false);
    assert!(common::claude_denial(&denied).is_some());
    assert!(
        !denied.stderr.is_empty(),
        "a denial also says why on stderr"
    );

    let error = fixture.hook("not a payload", false);
    assert_eq!(error.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&error.stderr);
    assert!(stderr.contains("invalid hook JSON"), "{stderr}");
    assert!(!stderr.contains("veil crashed"), "{stderr}");
}
