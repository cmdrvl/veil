//! Hook mode runs as two processes (bd-chg). A harness can let a tool call
//! through when its hook dies, so the process the harness starts does one thing:
//! it runs a second veil to judge the call, and blocks the call when that one
//! ends any way but with an answer. No handler inside the judging process could
//! do this for every crash: running out of stack aborts it without a panic.
//!
//! What this does not cover is the first process being killed, or taking longer
//! than the harness waits for a hook.

use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

use crate::cli;

/// The exit status that blocks a tool call. veil's own errors use it too.
const BLOCK: u8 = 2;

/// Judges the hook payload on standard input in a second veil, and passes on
/// what it answers.
pub fn run_hook() -> u8 {
    let judged = std::env::current_exe().and_then(|veil| {
        Command::new(veil)
            .arg(cli::HOOK_WORKER_FLAG)
            // the payload goes straight to it
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    });

    match judged {
        Ok(output) => pass_on(&output),
        Err(error) => block(&format!(
            "veil could not start its check, so this call is blocked ({error})."
        )),
    }
}

fn pass_on(output: &Output) -> u8 {
    let answered = match output.status.code() {
        Some(0) => 0,
        Some(2) => BLOCK,
        // What the dead process wrote is dropped: half a reply is no reply, and
        // what a panic says can quote what veil was reading.
        _ => {
            return block(&format!(
                "veil crashed while checking this call, so it is blocked ({}). Do not retry it in another form: stop and tell the operator.",
                output.status
            ));
        }
    };

    let mut stdout = io::stdout();
    let replied = stdout
        .write_all(&output.stdout)
        .and_then(|()| stdout.flush());
    // the diagnostics are not the reply, so losing them changes no decision
    let _ = io::stderr().write_all(&output.stderr);

    match replied {
        Ok(()) => answered,
        Err(error) => block(&format!(
            "veil could not send its reply, so this call is blocked ({error})."
        )),
    }
}

/// `eprintln!` panics when standard error is closed, and a panic here would let
/// the call through.
fn block(message: &str) -> u8 {
    let _ = writeln!(io::stderr(), "veil: {message}");
    BLOCK
}
