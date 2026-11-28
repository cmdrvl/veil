//! Hook mode runs as two processes (bd-chg, bd-8o6). A harness can let a tool
//! call through when its hook dies or takes too long, so the process the harness
//! starts does one thing: it runs a second veil to judge the call, and blocks the
//! call when that one ends any way but with an answer, or does not end by the
//! deadline. No handler inside the judging process could do this for every
//! crash: running out of stack aborts it without a panic.
//!
//! What this does not cover is the first process being killed, or a harness
//! that waits less than the deadline.

use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli;

/// The exit status that blocks a tool call. veil's own errors use it too.
const BLOCK: u8 = 2;

/// How long a check may take. It has to end before the harness stops waiting: by
/// default Copilot waits 30 seconds, Gemini CLI 60 and Claude Code 600. Grok
/// waits 5, which [`HARNESS_TIMEOUT_SECS`] raises where `veil install` wrote
/// the hook. The slowest ordinary check measured took under 2 seconds.
const DEADLINE: Duration = Duration::from_secs(20);

/// The least time `veil install` tells the harness to wait for the hook.
pub const HARNESS_TIMEOUT_SECS: u64 = 30;

/// A test shortens the deadline with this. It cannot lengthen it, so setting it
/// can only get calls blocked.
const SHORT_DEADLINE_ENV: &str = "VEIL_TEST_HOOK_DEADLINE_MS";

/// Judges the hook payload on standard input in a second veil, and passes on
/// what it answers.
pub fn run_hook() -> u8 {
    let deadline = std::env::var(SHORT_DEADLINE_ENV)
        .ok()
        .and_then(|text| text.parse().ok())
        .map_or(DEADLINE, |millis| {
            Duration::from_millis(millis).min(DEADLINE)
        });

    match judge(deadline) {
        Ok(Some(output)) => pass_on(&output),
        Ok(None) => block(
            "veil did not finish checking this call in time, so it is blocked. Make the command shorter or simpler, or search a smaller directory.",
        ),
        Err(error) => block(&format!(
            "veil could not run its check, so this call is blocked ({error})."
        )),
    }
}

/// What the judging process answered, or `None` when it had not by the
/// deadline.
fn judge(deadline: Duration) -> io::Result<Option<Output>> {
    let end = Instant::now() + deadline;
    let mut worker = Command::new(std::env::current_exe()?)
        .arg(cli::HOOK_WORKER_FLAG)
        // the payload goes straight to it
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let answer = collect(&mut worker, end);
    if !matches!(answer, Ok(Some(_))) {
        // not waited for: this process is about to end, and the wait for one
        // stuck in the kernel might not
        let _ = worker.kill();
    }
    answer
}

fn collect(worker: &mut Child, end: Instant) -> io::Result<Option<Output>> {
    // both are read at once, so that neither pipe fills and stops the worker
    let stdout = drain(worker.stdout.take())?;
    let stderr = drain(worker.stderr.take())?;

    let (Some(stdout), Some(stderr)) = (receive(&stdout, end)?, receive(&stderr, end)?) else {
        return Ok(None);
    };
    Ok(exit_status(worker, end)?.map(|status| Output {
        status,
        stdout,
        stderr,
    }))
}

/// Reads `pipe` to its end on a thread of its own.
fn drain(pipe: Option<impl Read + Send + 'static>) -> io::Result<Receiver<io::Result<Vec<u8>>>> {
    let mut pipe = pipe.ok_or_else(|| io::Error::other("a pipe to the check is missing"))?;
    let (sender, receiver) = mpsc::channel();
    // `thread::spawn` panics where this returns an error
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        let read = pipe.read_to_end(&mut bytes).map(|_| bytes);
        // nobody is listening once the deadline has passed
        let _ = sender.send(read);
    })?;
    Ok(receiver)
}

fn receive(pipe: &Receiver<io::Result<Vec<u8>>>, end: Instant) -> io::Result<Option<Vec<u8>>> {
    match pipe.recv_timeout(end.saturating_duration_since(Instant::now())) {
        Ok(read) => read.map(Some),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("reading from the check failed"))
        }
    }
}

/// The worker's pipes close as it ends, so this seldom waits.
fn exit_status(worker: &mut Child, end: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = worker.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= end {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(1));
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
