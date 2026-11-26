//! A command string inside an interpreter's program (bd-5iy). `cat .env` typed
//! in the shell is a read veil judges; the same string in
//! `python3 -c "import os; os.system('cat .env')"` or `awk 'BEGIN{system("cat
//! .env")}'` is run by the interpreter, and a string with a space in it names no
//! path, so veil judged none of it. These tests drive the real `veil` binary with
//! Claude Code Bash payloads against a repo on disk, and read the audit record
//! for the file the denial names.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;
#[path = "common/user.rs"]
mod user;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Repo {
    root: PathBuf,
    audit: PathBuf,
}

/// A repo with `data/**` protected by its config, a credentials-pack `.env`, an
/// ordinary `notes.md` and an audit log. `dynamic_args` is the `[policy]
/// dynamic_args` value, or `None` for the default.
fn repo(label: &str, dynamic_args: Option<&str>) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-exec-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("scripts")).expect("scripts dir");
    fs::create_dir_all(root.join("state")).expect("state dir");
    fs::write(
        root.join("data/clients/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("protected file");
    fs::write(root.join(".env"), "TOKEN=abc\n").expect("env file");
    fs::write(root.join("notes.md"), "notes\n").expect("notes");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let audit = root.join("state/audit.jsonl");
    let dynamic = dynamic_args
        .map(|mode| format!("dynamic_args = \"{mode}\"\n"))
        .unwrap_or_default();
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"data/**\"]\n",
    )
    .expect("config should be written");
    user::write_config(
        &root,
        &format!(
            "[policy]\n{dynamic}audit_log = true\naudit_path = \"{}\"\n",
            audit.to_string_lossy().replace('\\', "\\\\")
        ),
    );

    Repo { root, audit }
}

/// A file of the repo: `name` is relative to its root.
fn write(repo: &Repo, name: &str, text: &str) {
    let path = repo.root.join(name);
    fs::create_dir_all(path.parent().expect("a file has a parent")).expect("parent dir");
    fs::write(path, text).expect("fixture file");
}

struct Verdict {
    denied: bool,
    /// What the hook told the agent.
    reason: String,
    /// The audit records this command wrote.
    records: Vec<Value>,
}

fn judge(repo: &Repo, command: &str) -> Verdict {
    let session = format!("exec-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
    let payload = json!({
        "session_id": session,
        "cwd": repo.root,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .current_dir(&repo.root)
        .env("HOME", &repo.root)
        .env("VEIL_HARNESS", "plain")
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

    let denial = common::claude_denial(&output);
    let records = fs::read_to_string(&repo.audit)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line should parse"))
        .filter(|record| record["session_id"] == session)
        .collect();

    Verdict {
        denied: denial.is_some(),
        reason: denial.unwrap_or_default(),
        records,
    }
}

/// The command is denied, and the audit log has a denial of `reason_class` whose
/// path is `path`: the file the command the program runs names.
fn assert_denied_for(repo: &Repo, command: &str, path: &str, reason_class: &str) {
    let verdict = judge(repo, command);
    assert!(
        verdict.denied,
        "should be denied: {command}\nrecords: {:?}",
        verdict.records
    );
    assert!(
        verdict.records.iter().any(|record| {
            record["decision"] == "deny"
                && record["reason_class"] == reason_class
                && record["path"] == repo.root.join(path).to_string_lossy().as_ref()
        }),
        "{command}: no {reason_class} denial of {path} in the audit log\nreason: {}\nrecords: {:?}",
        verdict.reason,
        verdict.records
    );
}

fn assert_allowed(repo: &Repo, commands: &[&str]) {
    for command in commands {
        let verdict = judge(repo, command);
        assert!(
            !verdict.denied,
            "should be allowed: {command}\nreason: {}\nrecords: {:?}",
            verdict.reason, verdict.records
        );
    }
}

#[test]
fn a_command_a_program_runs_is_judged_as_the_command_it_is() {
    let repo = repo("judged", None);

    for (command, path) in [
        // Python
        ("python3 -c \"import os; os.system('cat .env')\"", ".env"),
        (
            "python3 -c \"import os; print(os.popen('cat .env').read())\"",
            ".env",
        ),
        (
            "python3 -c \"import subprocess; subprocess.run('cat .env', shell=True)\"",
            ".env",
        ),
        (
            "python3 -c \"import subprocess; subprocess.check_output(['cat', '.env'])\"",
            ".env",
        ),
        (
            "python3 -c \"import subprocess; subprocess.run(['sh', '-c', 'cat .env'])\"",
            ".env",
        ),
        // the string is read whole, however it is put together
        (
            "python3 -c \"import os; os.system('cat ' + '.env')\"",
            ".env",
        ),
        ("python3 -c \"import os; os.system('cat ' '.env')\"", ".env"),
        (
            "python3 -c \"import os; os.system('cat \\x2eenv')\"",
            ".env",
        ),
        // the code is found wherever the option stands, and in a here-document
        ("python3 -Bc \"import os; os.system('cat .env')\"", ".env"),
        (
            "python3 - <<'EOF'\nimport os\nos.system('cat .env')\nEOF",
            ".env",
        ),
        (
            "python3 <<'EOF'\nimport subprocess\nsubprocess.run(['cat', '.env'])\nEOF",
            ".env",
        ),
        // Node
        (
            "node -e \"require('child_process').execSync('cat .env')\"",
            ".env",
        ),
        (
            "node -e \"require('child_process').spawnSync('cat', ['.env'])\"",
            ".env",
        ),
        // Perl
        ("perl -e 'system(\"cat .env\")'", ".env"),
        ("perl -e 'print `cat .env`'", ".env"),
        ("perl -e 'print qx(cat .env)'", ".env"),
        ("perl -e 'open(F, \"cat .env |\"); print <F>'", ".env"),
        ("perl -ne 'system(\"cat .env\")' notes.md", ".env"),
        // Ruby
        ("ruby -e 'system(\"cat .env\")'", ".env"),
        ("ruby -e 'puts `cat .env`'", ".env"),
        ("ruby -e 'puts IO.popen([\"cat\", \".env\"]).read'", ".env"),
        // R
        ("Rscript -e 'system(\"cat .env\")'", ".env"),
        ("Rscript -e 'system2(\"cat\", \".env\")'", ".env"),
        // awk
        ("awk 'BEGIN{system(\"cat .env\")}'", ".env"),
        ("gawk 'BEGIN{system(\"cat .env\")}'", ".env"),
        ("awk 'BEGIN{\"cat .env\" | getline x; print x}'", ".env"),
        ("awk 'BEGIN{print | \"cat .env\"}'", ".env"),
        ("awk 'BEGIN{\"cat .env\" |& getline x}'", ".env"),
        // a wrapper before the interpreter
        (
            "env python3 -c \"import os; os.system('cat .env')\"",
            ".env",
        ),
        ("timeout 5 perl -e 'system(\"cat .env\")'", ".env"),
        ("sh -c \"awk 'BEGIN{system(\\\"cat .env\\\")}'\"", ".env"),
    ] {
        assert_denied_for(&repo, command, path, "direct_read");
    }
}

#[test]
fn a_word_that_is_no_path_is_found_only_by_reading_the_string_as_a_command() {
    let repo = repo("bare", None);

    // `data` names no file by its shape: only the command `grep -r ssn data` does
    for command in [
        "python3 -c \"import os; os.system('grep -r ssn data')\"",
        "python3 -c \"import subprocess; subprocess.run(['grep', '-r', 'ssn', 'data'])\"",
        "python3 -c \"import os; os.execvp('grep', ['grep', '-r', 'ssn', 'data'])\"",
        "node -e \"require('child_process').spawnSync('grep', ['-r', 'ssn', 'data'])\"",
        "perl -e 'system(\"grep\", \"-r\", \"ssn\", \"data\")'",
        "ruby -e 'system(\"grep -r ssn data\")'",
        "awk 'BEGIN{system(\"grep -r \" \"ssn data\")}'",
        // the program is the here-string or the here-document the interpreter reads
        "python3 - <<< \"import os; os.system('grep -r ssn data')\"",
        "python3 - <<'EOF'\nimport os\nos.system('grep -r ssn data')\nEOF",
        "ruby - <<< \"system('grep -r ssn data')\"",
    ] {
        let verdict = judge(&repo, command);
        assert!(
            verdict.denied,
            "should be denied: {command}\nrecords: {:?}",
            verdict.records
        );
        assert!(
            verdict
                .records
                .iter()
                .any(|record| { record["decision"] == "deny" && record["origin"] == "wrapper" }),
            "{command}: the denial should be of a command the program ran\nrecords: {:?}",
            verdict.records
        );
    }
}

#[test]
fn the_commands_of_a_program_file_are_judged_and_the_file_is_named() {
    let repo = repo("files", None);
    write(
        &repo,
        "scripts/shell_out.py",
        "import os\nos.system(\"grep -r ssn data\")\n",
    );
    write(&repo, "scripts/sys.awk", "BEGIN { system(\"cat .env\") }\n");
    // names no path by its shape: only the command `grep -r ssn data` does
    write(
        &repo,
        "scripts/sys_data.awk",
        "BEGIN { system(\"grep -r ssn data\") }\n",
    );
    write(
        &repo,
        "scripts/read.awk",
        "BEGIN { while ((getline line < \".env\") > 0) print line }\n",
    );
    write(
        &repo,
        "scripts/shebang.awk",
        "#!/usr/bin/awk -f\nBEGIN { system(\"cat .env\") }\n",
    );
    write(
        &repo,
        "scripts/shell_out.rb",
        "system('grep', '-r', 'ssn', 'data')\n",
    );

    for command in [
        "python3 scripts/shell_out.py",
        "ruby scripts/shell_out.rb",
        "awk -f scripts/sys.awk notes.md",
        "awk -f scripts/sys_data.awk notes.md",
        "awk --file=scripts/sys.awk notes.md",
        "awk -fscripts/sys.awk notes.md",
        "awk -f scripts/read.awk notes.md",
        "./scripts/shebang.awk notes.md",
        "python3 -c 'print(1)' ; awk -f scripts/sys.awk notes.md",
    ] {
        let verdict = judge(&repo, command);
        assert!(
            verdict.denied,
            "should be denied: {command}\nrecords: {:?}",
            verdict.records
        );
        assert!(
            verdict.reason.contains("found in script"),
            "{command}: the denial should name the script\nreason: {}",
            verdict.reason
        );
        assert!(
            verdict
                .records
                .iter()
                .any(|record| { record["decision"] == "deny" && record["origin"] == "script" }),
            "{command}: the audit record should say it came from a script\nrecords: {:?}",
            verdict.records
        );
    }
}

#[test]
fn a_command_built_at_run_time_is_refused_like_a_word_veil_cannot_resolve() {
    let repo = repo("built", None);

    for (command, call) in [
        (
            "python3 -c \"import os, sys; os.system(sys.argv[1])\" 'cat .env'",
            "os.system(sys.argv[1])",
        ),
        (
            "python3 -c \"import os; c = 'ca' + 't .env'; os.system(c)\"",
            "os.system(c)",
        ),
        (
            "python3 -c \"import os; n = 'env'; os.system(f'cat .{n}')\"",
            "os.system(f'cat .{n}')",
        ),
        (
            // a list is read by no shell: the word it computes is one word of
            // `cat`, an unresolved argument, and the reason names it
            "python3 -c \"import subprocess, sys; subprocess.run(['cat', sys.argv[1]])\" notes.md",
            "`cat` is given `$value_the_program_computes`",
        ),
        (
            "python3 - 'cat .env' <<'EOF'\nimport os, sys\nos.system(sys.argv[1])\nEOF",
            "os.system(sys.argv[1])",
        ),
        (
            "node -e \"require('child_process').execSync(process.argv[1])\" 'cat .env'",
            "execSync(process.argv[1])",
        ),
        ("perl -e 'system($ARGV[0])' 'cat .env'", "system($ARGV[0])"),
        ("ruby -e 'system(ARGV[0])' 'cat .env'", "system(ARGV[0])"),
        (
            "Rscript -e 'system(commandArgs()[1])' 'cat .env'",
            "system(commandArgs()[1])",
        ),
        ("awk -v c='cat .env' 'BEGIN{system(c)}'", "system(c)"),
        ("awk -v c='cat .env' 'BEGIN{c | getline x}'", "c | getline"),
    ] {
        let verdict = judge(&repo, command);
        assert!(
            verdict.denied,
            "should be refused: {command}\nrecords: {:?}",
            verdict.records
        );
        assert!(
            verdict.records.iter().any(|record| {
                record["decision"] == "deny"
                    && record["reason_class"] == "dynamic_path_unresolvable"
            }),
            "{command}: no dynamic_path_unresolvable denial\nrecords: {:?}",
            verdict.records
        );
        assert!(
            verdict.reason.contains(call),
            "{command}: the reason should show the call `{call}`\nreason: {}",
            verdict.reason
        );
    }
}

#[test]
fn a_built_command_follows_the_dynamic_argument_stance() {
    let command = "python3 -c \"import os, sys; os.system(sys.argv[1])\" 'cat notes.md'";

    let deny = repo("stance-deny", None);
    assert!(judge(&deny, command).denied, "the default is deny");

    // `warn` allows and writes the finding to the audit log
    let warn = repo("stance-warn", Some("warn"));
    let verdict = judge(&warn, command);
    assert!(!verdict.denied, "warn allows: {}", verdict.reason);
    assert!(
        verdict.records.iter().any(|record| {
            record["reason_class"] == "dynamic_path_unresolvable"
                && record["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("dynamic_args = warn"))
        }),
        "warn should record the finding: {:?}",
        verdict.records
    );

    // `allow` does not judge unresolved arguments at all
    let allow = repo("stance-allow", Some("allow"));
    let verdict = judge(&allow, command);
    assert!(!verdict.denied, "allow allows: {}", verdict.reason);
    assert!(
        verdict
            .records
            .iter()
            .all(|record| record["reason_class"] != "dynamic_path_unresolvable"),
        "allow records nothing: {:?}",
        verdict.records
    );

    // a command the program spells out is a path named outright: judged
    // whichever value is set
    for mode in ["warn", "allow"] {
        let repo = repo(&format!("literal-{mode}"), Some(mode));
        assert_denied_for(
            &repo,
            "python3 -c \"import os; os.system('cat .env')\"",
            ".env",
            "direct_read",
        );
    }
}

#[test]
fn a_command_that_names_nothing_protected_is_allowed() {
    let repo = repo("controls", None);
    write(&repo, "scripts/plain.awk", "{ print $1 }\n");

    assert_allowed(
        &repo,
        &[
            // no command at all
            "python3 -c 'print(1)'",
            "node -e 'console.log(1)'",
            "ruby -e 'puts 1'",
            "perl -e 'print 1'",
            "Rscript -e 'print(1)'",
            "awk '{print $1}' notes.md",
            "awk '/a|b/ {print}' notes.md",
            "awk 'BEGIN { FS = \"|\" } { print $2 }' notes.md",
            "awk -f scripts/plain.awk notes.md",
            // a command that reads nothing protected is judged, and passes
            "python3 -c \"import os; os.system('ls notes.md')\"",
            "python3 -c \"import subprocess; subprocess.run(['git', 'status'])\"",
            "python3 -c \"import subprocess; print(subprocess.check_output(['date']))\"",
            "node -e \"require('child_process').execSync('echo hi')\"",
            "perl -e 'system(\"echo\", \"hi\")'",
            "ruby -e 'puts `date`'",
            "awk 'BEGIN{\"date\" | getline d; print d}'",
            "awk 'BEGIN{system(\"echo hi\")}'",
            // a call named in a string, a comment or a regular expression is no call
            "python3 -c \"print('os.system(cmd)')\"",
            "python3 -c \"# os.system(cmd)\nprint(1)\"",
            "node -e \"console.log(/a(b)/.exec('ab'))\"",
            "node -e \"const re = /x/; console.log(re.exec('x'))\"",
            "perl -e 'open(F, \"<\", \"notes.md\"); print <F>'",
            "perl -e 'print \"system(\\$x)\"'",
            "ruby -e 'puts File.read(\"notes.md\")'",
            "python3 -c \"import asyncio; asyncio.run(main)\"",
        ],
    );
}

#[test]
fn a_script_file_that_builds_a_command_is_not_refused_but_what_it_spells_out_is_judged() {
    let repo = repo("file-stance", None);
    write(
        &repo,
        "scripts/run_argument.py",
        "import os, sys\nos.system(sys.argv[1])\n",
    );
    write(
        &repo,
        "scripts/mixed.py",
        "import os, sys\nos.system(sys.argv[1])\nos.system('grep -r ssn data')\n",
    );
    write(&repo, "scripts/plain.awk", "{ print $1 }\n");

    // the stance holds what a person typed, not what a script does: scripts are
    // full of `subprocess.run(cmd)` (the README says so)
    assert_allowed(&repo, &["python3 scripts/run_argument.py 'cat notes.md'"]);

    // but the commands it does spell out are judged as typed
    let verdict = judge(&repo, "python3 scripts/mixed.py 'cat notes.md'");
    assert!(verdict.denied, "records: {:?}", verdict.records);
    assert!(
        verdict
            .reason
            .contains("found in script `scripts/mixed.py`"),
        "reason: {}",
        verdict.reason
    );
}

#[test]
fn a_program_that_hands_the_shell_many_commands_is_bounded() {
    let repo = repo("many", None);
    let calls = "os.system('echo hi'); ".repeat(400);
    let command = format!("python3 -c \"import os; {calls}\"");

    let verdict = judge(&repo, &command);
    assert!(verdict.denied, "past the cap the program is refused");
    assert!(
        verdict
            .records
            .iter()
            .any(|record| record["reason_class"] == "dynamic_path_unresolvable"),
        "records: {:?}",
        verdict.records
    );
}

#[test]
fn a_shell_the_program_starts_is_followed_like_one_typed() {
    let repo = repo("nested", None);
    write(
        &repo,
        "scripts/shell_out.py",
        "import os\nos.system(\"grep -r ssn data\")\n",
    );

    for command in [
        "python3 -c \"import os; os.system('sh -c \\\"cat .env\\\"')\"",
        "python3 -c \"import os; os.system('xargs cat <<< .env')\"",
        "python3 -c \"import os; os.system('cat $(echo .env)')\"",
        // text a shell cannot parse is unknown, not empty
        "python3 -c \"import os; os.system('echo \\\"unclosed')\"",
        // a script the program runs is read like one typed
        "python3 -c \"import os; os.system('python3 scripts/shell_out.py')\"",
        "node -e \"require('child_process').execSync('python3 scripts/shell_out.py')\"",
    ] {
        let verdict = judge(&repo, command);
        assert!(
            verdict.denied,
            "should be denied: {command}\nrecords: {:?}",
            verdict.records
        );
    }
}

/// `text` as one single-quoted shell word.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// `text` as a double-quoted Python string literal.
fn python_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `command` run through `levels` interpreters, each started by the one before:
/// `python3 -c 'import os; os.system("python3 -c ...")'`.
fn nested_in_programs(command: &str, levels: usize) -> String {
    let mut text = command.to_owned();

    for _ in 0..levels {
        text = format!(
            "python3 -c {}",
            shell_word(&format!("import os; os.system({})", python_string(&text)))
        );
    }
    text
}

#[test]
fn a_program_nested_past_the_levels_veil_follows_is_never_read_as_running_nothing() {
    let repo = repo("deep", None);

    // however deep `cat .env` is buried, it is judged or the command is refused:
    // the text past the depth veil follows is unknown, not empty
    for levels in 1..=7 {
        let command = nested_in_programs("cat .env", levels);
        let verdict = judge(&repo, &command);

        assert!(
            verdict.denied,
            "{levels} levels deep should be denied\nrecords: {:?}",
            verdict.records
        );
    }

    // the same nesting around a command that reads nothing protected still runs
    // while veil can follow it, and is refused only where it cannot
    assert_allowed(&repo, &[&nested_in_programs("echo hi", 1)]);
    assert_allowed(&repo, &[&nested_in_programs("echo hi", 2)]);
    let deep = judge(&repo, &nested_in_programs("echo hi", 7));
    assert!(deep.denied, "past the depth veil follows, nothing is shown");
}

#[test]
fn text_a_script_or_a_filter_reads_as_data_is_not_a_program() {
    let repo = repo("data", None);
    write(
        &repo,
        "scripts/plain.py",
        "import sys\nprint(sys.stdin.read())\n",
    );
    write(&repo, "scripts/plain.rb", "puts $stdin.read\n");

    assert_allowed(
        &repo,
        &[
            // the here-document is the input of a program that is a file
            "python3 scripts/plain.py <<'EOF'\nimport os\nos.system('cat .env')\nEOF",
            "ruby scripts/plain.rb <<< \"system('cat .env')\"",
            // and the input of an awk program that is its first operand
            "awk '{print}' <<'EOF'\nBEGIN { system(\"cat .env\") }\nEOF",
            "awk '{print $1}' <<< 'system(\"cat .env\")'",
            // a regular expression's `exec` is no process
            "node -e \"const re = /x/; console.log(re.exec(process.argv[1]))\" notes.md",
            // what follows `-m module` is the module's, not Python's code
            "python3 -m mytool -c \"import os; os.system('grep -r ssn data')\"",
            "python3 -mmytool -c \"import os; os.system('grep -r ssn data')\"",
            // a call that only shares a name with one that runs a command
            "python3 -c \"import asyncio; asyncio.run(main())\"",
            "ruby -e 'File.open(\"notes.md\") { |f| puts f.read }'",
        ],
    );
}
