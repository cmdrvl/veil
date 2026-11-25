//! Bare `veil` is hook mode. Without a payload it must fail fast with discovery
//! guidance, never hang and never print an opaque parse error.
//!
//! Harness limit: the test harness has no pseudo-terminal, so a real TTY stdin
//! is covered only by the unit test of the terminal decision
//! (`lib::tests::terminal_stdin_is_rejected_...`) plus a manual pty run; here the
//! non-TTY cases (`/dev/null`, a closed pipe, whitespace, garbage) are exercised
//! against the real binary. An open pipe that never sends data is
//! indistinguishable from a hook harness that has not written yet, so it is
//! deliberately not rejected and not tested.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

fn run_with_stdin(stdin: Option<&[u8]>) -> (Output, Duration) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("NO_COLOR");
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let started = Instant::now();
    let mut child = command.spawn().expect("veil should spawn");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().expect("stdin should be piped");
        pipe.write_all(bytes).expect("stdin write should succeed");
        // Dropping the pipe closes it, so the child sees EOF.
    }
    let output = child.wait_with_output().expect("veil should exit");
    (output, started.elapsed())
}

fn assert_fast_guidance(output: &Output, elapsed: Duration, label: &str) {
    assert!(elapsed < TIMEOUT, "{label}: took {elapsed:?}");
    assert_eq!(output.status.code(), Some(2), "{label}: usage error exit");
    assert!(
        output.stdout.is_empty(),
        "{label}: nothing on stdout, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for hint in [
        "veil --robot-triage",
        "veil capabilities --json",
        "veil --help",
    ] {
        assert!(
            stderr.contains(hint),
            "{label}: stderr should point to `{hint}`, got: {stderr}"
        );
    }
}

#[test]
fn dev_null_stdin_exits_fast_with_guidance() {
    let (output, elapsed) = run_with_stdin(None);
    assert_fast_guidance(&output, elapsed, "/dev/null");
}

#[test]
fn closed_empty_pipe_exits_fast_with_guidance() {
    let (output, elapsed) = run_with_stdin(Some(b""));
    assert_fast_guidance(&output, elapsed, "empty pipe");
}

#[test]
fn whitespace_only_pipe_exits_fast_with_guidance() {
    let (output, elapsed) = run_with_stdin(Some(b" \n\t\n"));
    assert_fast_guidance(&output, elapsed, "whitespace pipe");
}

#[test]
fn garbage_payload_is_a_clear_error_not_a_hang_or_a_decision() {
    let (output, elapsed) = run_with_stdin(Some(b"definitely not a hook payload"));

    assert!(elapsed < TIMEOUT);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "an unparseable payload must not produce an allow/deny decision"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("veil:"),
        "stderr should carry a veil-prefixed error"
    );
}

#[test]
fn a_real_hook_payload_on_a_pipe_still_gets_a_decision() {
    let payload = br#"{"session_id":"s","cwd":"/tmp","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}"#;
    let (output, elapsed) = run_with_stdin(Some(payload));

    assert!(elapsed < TIMEOUT);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"decision":"allow"}"#
    );
}
