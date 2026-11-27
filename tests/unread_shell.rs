//! bd-ao5: shell text the hook allowed because it never read it. Each command
//! here is run in bash against a synthetic protected file where this machine can
//! run it, to show the read is real, and the hook must refuse it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod common;
#[path = "common/user.rs"]
mod user;

static COUNTER: AtomicU64 = AtomicU64::new(0);

const VEIL: &str = env!("CARGO_BIN_EXE_veil");
const CANARY: &str = "SYNTHETIC-PROTECTED-UNREAD-5043";
const SEARCH_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

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
            "veil-unread-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("root");
        let root = fs::canonicalize(root).expect("canonical root");
        let fixture = Self {
            project: root.join("project"),
            home: root.join("home"),
        };
        fs::create_dir_all(fixture.project.join("protected")).expect("protected");
        fs::create_dir_all(&fixture.home).expect("home");
        fs::write(
            fixture.project.join("protected/x.csv"),
            format!("{CANARY}\n"),
        )
        .expect("protected file");
        fs::write(fixture.project.join("notes.txt"), "notes\n").expect("note");
        fs::write(
            fixture.project.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected/**\"]\n",
        )
        .expect("config");
        user::write_config(&fixture.home, "[policy]\naudit_log = false\n");
        fixture
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.project)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", SEARCH_PATH);
        command
    }

    fn denies(&self, text: &str) -> bool {
        let payload = serde_json::json!({
            "session_id": "unread-shell",
            "cwd": self.project,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": text },
        });
        let mut child = self
            .command(VEIL)
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

    /// Whether running the command in bash shows the protected file, on either
    /// stream.
    fn shows(&self, text: &str) -> bool {
        let output = self
            .command("/bin/bash")
            .args(["--noprofile", "--norc", "-c", text])
            .stdin(Stdio::null())
            .output()
            .expect("bash should run");

        [output.stdout, output.stderr]
            .iter()
            .any(|stream| String::from_utf8_lossy(stream).contains(CANARY))
    }
}

fn installed(program: &str) -> bool {
    SEARCH_PATH
        .split(':')
        .any(|directory| Path::new(directory).join(program).exists())
}

/// Every command is denied. Those `runs` accepts are also run, and each of them
/// must show the file.
fn assert_refused(fixture: &Fixture, commands: &[&str], runs: impl Fn(&str) -> bool) {
    let mut allowed = Vec::new();
    for command in commands {
        if runs(command) {
            assert!(fixture.shows(command), "not a read here: `{command}`");
        }
        if !fixture.denies(command) {
            allowed.push(*command);
        }
    }
    assert!(allowed.is_empty(), "allowed:\n{}", allowed.join("\n"));
}

#[test]
fn the_shell_string_a_runner_is_handed_is_read() {
    let fixture = Fixture::new();

    // macOS forms: these three show the file there
    assert_refused(
        &fixture,
        &[
            "caffeinate bash -c 'cat protected/x.csv'",
            "caffeinate -i -t 5 bash -c 'cat protected/x.csv'",
            "script -q /dev/null bash -c 'cat protected/x.csv'",
            "sandbox-exec -p '(version 1)(allow default)' bash -c 'cat protected/x.csv'",
        ],
        |_| cfg!(target_os = "macos"),
    );
    // these run only where the runner takes this form
    assert_refused(
        &fixture,
        &["stdbuf -oL bash -c 'cat protected/x.csv'"],
        |_| installed("stdbuf"),
    );
    assert_refused(
        &fixture,
        &[
            "stdbuf -o L -e0 bash -c 'cat protected/x.csv'",
            "arch -arm64 bash -c 'cat protected/x.csv'",
            "arch -arch x86_64 -e A=1 bash -c 'cat protected/x.csv'",
            "script -q -c 'cat protected/x.csv' /dev/null",
            "script --command='cat protected/x.csv' /dev/null",
            "nohup caffeinate stdbuf -oL bash -c 'cat protected/x.csv'",
        ],
        |_| false,
    );
}

#[test]
fn a_redirection_written_before_a_command_does_not_hide_it() {
    let fixture = Fixture::new();

    assert_refused(
        &fixture,
        &[
            ">/dev/null bash -c 'cat protected/x.csv >&2'",
            "2>/dev/null bash -c 'cat protected/x.csv'",
            "< /dev/null bash -c 'cat protected/x.csv'",
            "> /dev/null bash -c 'cat protected/x.csv >&2'",
            "A=1 >/dev/null bash -c 'cat protected/x.csv >&2'",
            ">/dev/null A=1 bash -c 'cat protected/x.csv >&2'",
            "2>/dev/null </dev/null nohup bash -c 'cat protected/x.csv'",
        ],
        |_| true,
    );
}

#[test]
fn what_a_leading_redirection_reads_is_still_judged() {
    let fixture = Fixture::new();

    assert_refused(
        &fixture,
        &[
            "< protected/x.csv cat",
            "<protected/x.csv cat",
            "< protected/x.csv /bin/bash -c 'cat'",
            "2>/dev/null cat protected/x.csv",
        ],
        |_| true,
    );
}

#[test]
fn code_bash_runs_from_a_variable_is_read() {
    let fixture = Fixture::new();

    assert_refused(
        &fixture,
        &[
            "env 'BASH_FUNC_x%%=() { cat protected/x.csv; }' /bin/bash -c x",
            "PS4='$(cat protected/x.csv)' /bin/bash -xc true",
            "BASH_ENV='$(cat protected/x.csv >&2)' /bin/bash -c true",
            "export BASH_ENV='$(cat protected/x.csv >&2)'; /bin/bash -c true",
            "env PS4='+ $(cat protected/x.csv) ' /bin/bash -xc true",
            "BASH_ENV='$(cat protected/x.csv >&2)'; export BASH_ENV; /bin/bash -c true",
        ],
        |_| true,
    );
}

#[test]
fn a_trap_action_is_read_for_what_it_reads() {
    let fixture = Fixture::new();

    assert_refused(
        &fixture,
        &[
            "trap 'cat protected/x.csv' EXIT",
            "trap -- 'cat protected/x.csv' EXIT",
            "builtin trap 'cat protected/x.csv' EXIT",
            "trap 'sh -c \"cat protected/x.csv\"' EXIT",
            "trap 'true; cat protected/x.csv' DEBUG; true",
            "bash -c \"trap 'cat protected/x.csv' EXIT\"",
        ],
        |_| true,
    );
}

#[test]
fn ordinary_uses_of_the_same_forms_stay_allowed() {
    let fixture = Fixture::new();
    let mut denied = Vec::new();

    for command in [
        "trap 'rm -f \"$tmp\"' EXIT",
        "tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; cat notes.txt",
        "trap - EXIT",
        "trap '' INT TERM",
        "trap 'echo \"line $LINENO: $BASH_COMMAND\" >&2' ERR",
        "PS4='+ ${BASH_SOURCE}:${LINENO}: ' bash -x -c 'cat notes.txt'",
        "PS4='+ $(date +%s) ' bash -xc true",
        "BASH_ENV=notes.txt bash -c true",
        "2>/dev/null cat notes.txt",
        ">out.txt echo hello",
        "caffeinate -i cargo build",
        "stdbuf -oL tail -f notes.txt",
        "arch -arm64 brew list",
        "script -q /dev/null cargo test",
        "sandbox-exec -f profile.sb cat notes.txt",
    ] {
        if fixture.denies(command) {
            denied.push(command);
        }
    }
    assert!(denied.is_empty(), "denied:\n{}", denied.join("\n"));
}
