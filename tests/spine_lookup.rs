//! bd-jn6: spine-tool authority belongs to the program a tool's name finds. A
//! command that changes how names are found, or names another file, gets none.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const VEIL: &str = env!("CARGO_BIN_EXE_veil");

const CANARY: &str = "SYNTHETIC-PROTECTED-HOOK-7319";

struct Fixture {
    project: PathBuf,
    home: PathBuf,
    /// Where the installed tools are: the only directory on `PATH` that the
    /// fixture puts there.
    installed: PathBuf,
}

fn write_program(path: &Path, source: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("directory");
    fs::write(path, source).expect("program");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("permissions");
}

impl Fixture {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-spine-lookup-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("root");
        let root = fs::canonicalize(root).expect("canonical root");
        let fixture = Self {
            project: root.join("project"),
            home: root.join("home"),
            installed: root.join("installed"),
        };
        fs::create_dir_all(fixture.project.join("protected")).expect("protected");
        fs::create_dir_all(&fixture.home).expect("home");
        fs::write(
            fixture.project.join("protected/x.csv"),
            format!("{CANARY}\n"),
        )
        .expect("protected file");
        fs::write(
            fixture.project.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected/**\"]\n[policy]\naudit_log = false\n",
        )
        .expect("config");
        write_program(
            &fixture.installed.join("shape"),
            "#!/bin/sh\necho shape-report\n",
        );
        symlink(VEIL, fixture.installed.join("veil")).expect("installed veil");
        symlink(&fixture.installed, root.join("installed-link")).expect("linked directory");
        // impostors, where an agent can write: each prints the file it is given
        write_program(
            &fixture.project.join("tools/shape"),
            "#!/bin/sh\n/bin/cat \"$1\"\n",
        );
        write_program(
            &fixture.project.join("tools/veil"),
            "#!/bin/sh\n/bin/cat \"$3\"\n",
        );
        fs::write(fixture.project.join("env.sh"), "PATH=tools:$PATH\n").expect("env.sh");
        fs::write(fixture.project.join("report.sh"), "shape protected/x.csv\n").expect("report.sh");
        fixture
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.installed.display())
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.project)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", self.path());
        command
    }

    /// The hook's decision for a Bash call, and the reason and remediation text.
    fn hook(&self, text: &str) -> (String, String) {
        let payload = serde_json::json!({
            "session_id": "spine-lookup",
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
        assert_eq!(output.status.code(), Some(0), "`{text}`");
        let decision: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("a JSON decision");
        let decision = &decision["hookSpecificOutput"];
        (
            decision["permissionDecision"]
                .as_str()
                .expect("a decision")
                .to_owned(),
            format!(
                "{}\n{}",
                decision["permissionDecisionReason"]
                    .as_str()
                    .unwrap_or_default(),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    }

    /// Whether running the command in bash prints the protected file.
    fn leaks(&self, text: &str) -> bool {
        let output = self
            .command("/bin/bash")
            .args(["--noprofile", "--norc", "-c", text])
            .output()
            .expect("bash should run");
        String::from_utf8_lossy(&output.stdout).contains(CANARY)
    }
}

/// Each of these really does run something other than the installed tool: bash
/// prints the protected file. The hook must refuse them all.
#[test]
fn a_command_that_changes_how_a_tool_is_found_gets_no_authority() {
    let fixture = Fixture::new();
    let mut allowed = Vec::new();
    for command in [
        // set for one command
        "PATH=tools:/usr/bin:/bin shape protected/x.csv",
        "PATH=tools:/usr/bin:/bin veil exec shape protected/x.csv",
        "PATH=./tools:/usr/bin:/bin veil exec shape protected/x.csv",
        "PATH=tools:$PATH nohup shape protected/x.csv",
        "PATH+=:tools; PATH=tools:$PATH shape protected/x.csv",
        "env PATH=tools:/usr/bin:/bin veil exec shape protected/x.csv",
        "env -i PATH=tools shape protected/x.csv",
        "env -u HOME PATH=tools:/bin shape protected/x.csv",
        "env -S 'PATH=tools:/bin shape protected/x.csv'",
        "nohup env PATH=tools:/bin shape protected/x.csv",
        // set for the commands that follow
        "export PATH=tools:$PATH; shape protected/x.csv",
        "export PATH=\"tools:$PATH\" && veil exec shape protected/x.csv",
        "export PATH=tools:/usr/bin:/bin; shape protected/x.csv",
        "PATH=tools:$PATH; shape protected/x.csv",
        "declare -x PATH=tools:$PATH; shape protected/x.csv",
        "command export PATH=tools:/bin; shape protected/x.csv",
        "builtin export PATH=tools:/bin; shape protected/x.csv",
        "for PATH in tools; do shape protected/x.csv; done",
        "read PATH <<< tools; shape protected/x.csv",
        "printf -v PATH %s tools; shape protected/x.csv",
        "eval 'PATH=tools:$PATH'; shape protected/x.csv",
        "x=export; $x PATH=tools:/bin; shape protected/x.csv",
        // a loop reaches the tool again after the change
        "for i in 1 2; do shape protected/x.csv; PATH=tools:$PATH; done",
        // set by a trap before a later command
        "trap 'PATH=tools' DEBUG; shape protected/x.csv",
        "trap 'PATH=tools' ERR; false; shape protected/x.csv",
        "trap 'PATH=tools' USR1; kill -USR1 $$; shape protected/x.csv",
        "{ trap 'PATH=tools' DEBUG; }; shape protected/x.csv",
        "if true; then builtin trap -- 'PATH=tools' DEBUG; fi; shape protected/x.csv",
        "trap 'trap \"PATH=tools\" DEBUG' USR1; kill -USR1 $$; shape protected/x.csv",
        // an action or a script that only running the command shows
        "trap \"$(echo PATH=tools)\" DEBUG; shape protected/x.csv",
        "x=$(echo PATH=tools); trap \"$x\" DEBUG; shape protected/x.csv",
        "sh -c \"$(echo PATH=tools); shape protected/x.csv\"",
        "bash -c \"export $(echo PATH=tools); shape protected/x.csv\"",
        "bash <<EOF\n$(echo PATH=tools)\nshape protected/x.csv\nEOF",
        // computed text spliced into the middle of a script, or into what `env`
        // reads as its own
        "x=$(echo 'y;PATH=tools'); trap \"true $x\" DEBUG; shape protected/x.csv",
        "x=$(echo 'y;PATH=tools'); sh -c \"true $x; shape protected/x.csv\"",
        "x=$(echo PATH=tools:/bin); env $x shape protected/x.csv",
        "x=$(echo 'y PATH=tools:/bin'); env A=$x shape protected/x.csv",
        "x=$(echo 'y PATH=tools:/bin'); env -S \"A=$x shape protected/x.csv\"",
        "x=$(echo source); builtin \"$x\" env.sh; shape protected/x.csv",
        "x=$(echo source); command \"$x\" env.sh; shape protected/x.csv",
        "x=$(echo 'y;PATH=tools'); bash <<< \"true $x; shape protected/x.csv\"",
        "x=$(echo 'y;PATH=tools'); bash <<EOF\ntrue $x\nshape protected/x.csv\nEOF",
        // set by an expansion rather than an assignment
        ": ${BASH_ENV:=env.sh}; export BASH_ENV; bash -c 'shape protected/x.csv'",
        // under a name that only running the command shows
        "x=$(echo PATH); export $x=tools; shape protected/x.csv",
        "export \"$(echo PATH=tools)\"; shape protected/x.csv",
        "x=$(echo PATH); declare $x=tools; shape protected/x.csv",
        "x=$(echo PATH); printf -v $x %s tools; shape protected/x.csv",
        "x=$(echo PATH); read $x <<< tools; shape protected/x.csv",
        // a file veil does not read can set anything
        "source env.sh; shape protected/x.csv",
        ". ./env.sh && veil exec shape protected/x.csv",
        // handed to another shell
        "sh -c 'PATH=tools:$PATH shape protected/x.csv'",
        "PATH=tools:$PATH sh -c 'shape protected/x.csv'",
        "PATH=tools:$PATH bash report.sh",
        "BASH_ENV=env.sh bash -c 'shape protected/x.csv'",
        // a name given another meaning
        "function shape { /bin/cat protected/x.csv; }; shape protected/x.csv",
        "hash -p tools/shape shape; shape protected/x.csv",
        "shopt -s expand_aliases\nalias shape=/bin/cat\nshape protected/x.csv",
        // another file, named by its path
        "./tools/shape protected/x.csv",
        "tools/shape protected/x.csv",
        "cd tools && ./shape ../protected/x.csv",
    ] {
        assert!(fixture.leaks(command), "not an impostor: `{command}`");
        if fixture.hook(command).0 != "deny" {
            allowed.push(command);
        }
    }
    assert!(allowed.is_empty(), "allowed:\n{}", allowed.join("\n"));
}

/// These are refused too, and are not run here: they need another user, a
/// network or a program the test machine may lack, or fail when run.
#[test]
fn runners_with_their_own_lookup_get_no_authority() {
    let fixture = Fixture::new();
    let mut allowed = Vec::new();
    for command in [
        "sudo shape protected/x.csv",
        "doas shape protected/x.csv",
        "uv run shape protected/x.csv",
        "uvx shape protected/x.csv",
        "uv tool run shape protected/x.csv",
        "poetry run shape protected/x.csv",
        "pdm run shape protected/x.csv",
        "pipx run shape protected/x.csv",
        "npx shape protected/x.csv",
        "bunx shape protected/x.csv",
        "command -p shape protected/x.csv",
        "env -P tools shape protected/x.csv",
        "env -i shape protected/x.csv",
        "env - shape protected/x.csv",
        "env -u PATH shape protected/x.csv",
        "env --unset=PATH shape protected/x.csv",
        "LD_PRELOAD=./evil.so shape protected/x.csv",
        "DYLD_INSERT_LIBRARIES=./evil.dylib veil exec shape protected/x.csv",
        "ZDOTDIR=tools zsh -c 'shape protected/x.csv'",
        "HOME=tools bash -lc 'shape protected/x.csv'",
        "enable -f ./evil.so shape; shape protected/x.csv",
        "eval \"$SETUP\"; shape protected/x.csv",
        "unset PATH; shape protected/x.csv",
        "/tmp/shape protected/x.csv",
        "veil exec ./tools/shape protected/x.csv",
        // zsh, which an agent's shell may be
        "path=(tools $path); shape protected/x.csv",
        "path+=(tools); shape protected/x.csv",
        "path[1]=tools; shape protected/x.csv",
        "hash shape=tools/shape; shape protected/x.csv",
        "commands[shape]=tools/shape; shape protected/x.csv",
        "functions[shape]='/bin/cat $1'; shape protected/x.csv",
        "autoload -U shape; shape protected/x.csv",
    ] {
        if fixture.hook(command).0 != "deny" {
            allowed.push(command);
        }
    }
    assert!(allowed.is_empty(), "allowed:\n{}", allowed.join("\n"));
}

/// The control: what leaves lookup alone keeps its authority, including the
/// installed tool named by its path.
#[test]
fn a_command_that_leaves_lookup_alone_keeps_authority() {
    let fixture = Fixture::new();
    let installed = fixture.installed.display();
    let linked = fixture.installed.with_file_name("installed-link");
    let mut denied = Vec::new();
    for command in [
        "shape protected/x.csv".to_owned(),
        "veil exec shape protected/x.csv".to_owned(),
        "LC_ALL=C shape protected/x.csv".to_owned(),
        "env LANG=C veil exec shape protected/x.csv".to_owned(),
        "export LANG=C; shape protected/x.csv".to_owned(),
        "MY_PATH=tools shape protected/x.csv".to_owned(),
        "nohup shape protected/x.csv".to_owned(),
        "command shape protected/x.csv".to_owned(),
        "sh -c 'shape protected/x.csv'".to_owned(),
        "shape protected/x.csv --key PATH".to_owned(),
        "echo PATH is unchanged; shape protected/x.csv".to_owned(),
        "printf '%s\\n' PATH; shape protected/x.csv".to_owned(),
        "(cd protected && shape x.csv)".to_owned(),
        "hash -r; shape protected/x.csv".to_owned(),
        "trap 'echo done' EXIT INT; shape protected/x.csv".to_owned(),
        "trap '' INT; trap - INT; shape protected/x.csv".to_owned(),
        "export STAMP=\"$(date)\"; shape protected/x.csv".to_owned(),
        "read -r -p \"$HOSTNAME\" answer <<< y; shape protected/x.csv".to_owned(),
        "read -r line < \"$HOME/none\"; shape protected/x.csv".to_owned(),
        "files=(a b); shape protected/x.csv".to_owned(),
        "trap 'rm -f \"$scratch\"' EXIT; shape protected/x.csv".to_owned(),
        "LANG=\"$USER\" shape protected/x.csv".to_owned(),
        "env LANG=C shape protected/x.csv \"$USER\"".to_owned(),
        "sh -c 'shape protected/x.csv \"$0\"' \"$USER\"".to_owned(),
        "echo \"${USER:=nobody}\"; shape protected/x.csv".to_owned(),
        format!("{installed}/shape protected/x.csv"),
        format!("{}/shape protected/x.csv", linked.display()),
        format!("veil exec {installed}/shape protected/x.csv"),
    ] {
        assert!(!fixture.leaks(&command), "leaks: `{command}`");
        let (decision, why) = fixture.hook(&command);
        if decision != "allow" {
            denied.push(format!("{command}: {why}"));
        }
    }
    assert!(denied.is_empty(), "denied:\n{}", denied.join("\n"));
}

/// A `trap` action that expands to the whole command again. bash only stores
/// it; the hook, which reads actions, must not read it without end.
const TRAP_QUINE: &str = r#"e='='; q="'"; s='; trap "e$e$q$e$q; q$e\"$q\"; s$e$q$s$q$s" DEBUG'; trap "e$e$q$e$q; q$e\"$q\"; s$e$q$s$q$s" DEBUG"#;

/// The hook aborts if it runs out of stack, and a harness lets a command
/// through when its hook dies without a decision.
#[test]
fn a_trap_action_without_end_cannot_stop_the_hook_from_deciding() {
    let fixture = Fixture::new();
    for command in [
        format!("{TRAP_QUINE}; cat protected/x.csv"),
        format!("{TRAP_QUINE}; shape protected/x.csv"),
    ] {
        assert_eq!(fixture.hook(&command).0, "deny", "{command}");
    }
}

#[test]
fn env_split_strings_nested_without_end_cannot_stop_the_hook_from_deciding() {
    let fixture = Fixture::new();
    let nested = "-S".repeat(40_000);
    for command in [
        format!("env {nested} x; cat protected/x.csv"),
        format!("env {nested} x; shape protected/x.csv"),
    ] {
        assert_eq!(fixture.hook(&command).0, "deny", "{command:.60}");
    }
}

/// A refusal that would otherwise be puzzling says what withheld the authority.
#[test]
fn the_denial_says_why_the_tool_lost_its_authority() {
    let fixture = Fixture::new();
    let (decision, why) = fixture.hook("export PATH=tools:$PATH; shape protected/x.csv");
    assert_eq!(decision, "deny");
    assert!(
        why.contains("`shape` has no spine-tool authority here"),
        "{why}"
    );

    // a command that never had authority hears nothing about it
    let (decision, why) = fixture.hook("export PATH=tools:$PATH; cat protected/x.csv");
    assert_eq!(decision, "deny");
    assert!(!why.contains("spine-tool authority"), "{why}");
}
