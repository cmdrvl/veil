//! A script the same command string writes first, then runs. veil reads a script
//! file as it is on disk when the hook runs, and a file the string has not yet
//! written is not there: `printf 'r .env\n' > tmp.sed; sed -f tmp.sed notes.md`
//! was judged as running nothing, though `sed -f tmp.sed notes.md` alone is
//! denied once the file exists. These tests drive the real `veil` binary with
//! Claude Code Bash payloads against a repo on disk, and read the audit record
//! for the file the denial names.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

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
        "veil-written-{label}-{}-{nanos}-{counter}",
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
        format!(
            "[sensitivity]\nprotected = [\"data/**\"]\n\n[policy]\n{dynamic}audit_log = true\naudit_path = \"{}\"\n",
            audit.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .expect("config should be written");

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
    let session = format!("written-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "veil should exit 0 for {command}, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: Value =
        serde_json::from_slice(&output.stdout).expect("veil should print a JSON decision");
    let hook = &decision["hookSpecificOutput"];
    let records = fs::read_to_string(&repo.audit)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line should parse"))
        .filter(|record| record["session_id"] == session)
        .collect();

    Verdict {
        denied: hook["permissionDecision"] == "deny",
        reason: hook["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        records,
    }
}

/// The command is denied, and the audit log has a denial of `reason_class` whose
/// path is `path`: the file the script the string writes names.
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

/// The command is denied, and the audit log has a denial of `path`, the file the
/// script the string writes names, whichever way the script names it.
fn assert_names(repo: &Repo, command: &str, path: &str) {
    let verdict = judge(repo, command);
    assert!(
        verdict.denied,
        "should be denied: {command}\nrecords: {:?}",
        verdict.records
    );
    assert!(
        verdict.records.iter().any(|record| {
            record["decision"] == "deny"
                && record["reason_class"] != "dynamic_path_unresolvable"
                && record["path"] == repo.root.join(path).to_string_lossy().as_ref()
        }),
        "{command}: no denial of {path} in the audit log\nreason: {}\nrecords: {:?}",
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

/// Denied as the refusal of a script whose text veil cannot see.
fn assert_refused(repo: &Repo, command: &str) {
    let verdict = judge(repo, command);
    assert!(
        verdict.denied,
        "should be refused: {command}\nrecords: {:?}",
        verdict.records
    );
    assert!(
        verdict.records.iter().any(|record| {
            record["decision"] == "deny" && record["reason_class"] == "dynamic_path_unresolvable"
        }),
        "{command}: no dynamic_path_unresolvable denial\nreason: {}\nrecords: {:?}",
        verdict.reason,
        verdict.records
    );
}

#[test]
fn a_script_the_string_writes_is_judged_as_the_text_written() {
    let repo = repo("judged", None);

    // the two commands the bead measured as allowed, as they are denied once the
    // file exists: the `r` of a sed script is a direct read, and so is the open
    for command in [
        "printf 'r .env\\n' > tmp.sed; sed -f tmp.sed notes.md",
        "printf 'open(\".env\").read()\\n' > tmp.py && python3 tmp.py",
    ] {
        assert_denied_for(&repo, command, ".env", "direct_read");
    }

    for command in [
        // every interpreter veil reads
        "printf 'require(\"fs\").readFileSync(\".env\")\\n' > tmp.js; node tmp.js",
        "printf 'open(F, \".env\"); print <F>;\\n' > tmp.pl; perl tmp.pl",
        "printf 'puts File.read(\".env\")\\n' > tmp.rb; ruby tmp.rb",
        "printf 'cat .env\\n' > tmp.sh; sh tmp.sh",
        "printf 'cat .env\\n' > tmp.sh; bash tmp.sh",
        "printf 'cat .env\\n' > tmp.sh; source tmp.sh",
        "printf 'cat .env\\n' > tmp.sh; . ./tmp.sh",
        "printf 'BEGIN { system(\"cat .env\") }\\n' > tmp.awk; awk -f tmp.awk notes.md",
        // run by name, under the interpreter on its first line
        "printf '#!/bin/sh\\ncat .env\\n' > tmp.sh; chmod +x tmp.sh; ./tmp.sh",
        "printf '#!/usr/bin/env python3\\nprint(open(\".env\").read())\\n' > tmp.py; ./tmp.py",
        "printf '#!/usr/bin/sed -f\\nr .env\\n' > tmp.sed; ./tmp.sed notes.md",
    ] {
        assert_names(&repo, command, ".env");
    }
}

#[test]
fn every_way_of_writing_a_literal_body_is_followed() {
    let repo = repo("forms", None);

    for command in [
        // echo
        "echo 'r .env' > tmp.sed; sed -f tmp.sed notes.md",
        "echo 'r .env' >tmp.sed; sed -f tmp.sed notes.md",
        "echo r .env > tmp.sed; sed -f tmp.sed notes.md",
        "echo -n 'r .env' > tmp.sed; sed -f tmp.sed notes.md",
        "echo -e 'p\\nr .env' > tmp.sed; sed -f tmp.sed notes.md",
        "echo 'cat .env' > tmp.sh && sh tmp.sh",
        // the redirection first, and a variable the string sets
        ">tmp.sh echo 'cat .env'; sh tmp.sh",
        "BODY='r .env'; echo \"$BODY\" > tmp.sed; sed -f tmp.sed notes.md",
        // appended to a file the string has not written before
        "echo 'r .env' >> tmp.sed; sed -f tmp.sed notes.md",
        "echo 'p' > tmp.sed; echo 'r .env' >> tmp.sed; sed -f tmp.sed notes.md",
        // printf: the format and the arguments make the text
        "printf '%s\\n' 'r .env' > tmp.sed; sed -f tmp.sed notes.md",
        "printf 'r %s\\n' .env > tmp.sed; sed -f tmp.sed notes.md",
        "printf '%s\\n' p 'r .env' > tmp.sed; sed -f tmp.sed notes.md",
        "printf '%b' 'p\\nr .env\\n' > tmp.sed; sed -f tmp.sed notes.md",
        // here-documents and here-strings
        "cat > tmp.sh <<'EOF'\ncat .env\nEOF\nsh tmp.sh",
        "cat <<'EOF' > tmp.sh\ncat .env\nEOF\nsh tmp.sh",
        "cat >> tmp.sh <<'EOF'\ncat .env\nEOF\nsh tmp.sh",
        "cat > tmp.py <<'EOF'\nprint(open(\".env\").read())\nEOF\npython3 tmp.py",
        "cat > tmp.py <<EOF\nprint(open(\".env\").read())\nEOF\npython3 tmp.py",
        "cat > tmp.sed <<< 'r .env'; sed -f tmp.sed notes.md",
        "cat > tmp.sed <<<'r .env'; sed -f tmp.sed notes.md",
        "tee tmp.sh <<'EOF' > /dev/null\ncat .env\nEOF\nsh tmp.sh",
        "tee -a tmp.sh <<'EOF' >/dev/null\ncat .env\nEOF\nsh tmp.sh",
        "tee tmp.sed <<< 'r .env' > /dev/null; sed -f tmp.sed notes.md",
        // another directory, and a path spelled another way
        "mkdir -p tmp && printf 'cat .env\\n' > tmp/run.sh && sh tmp/run.sh",
        "cd scripts && printf 'cat ../.env\\n' > run.sh && sh run.sh",
        "printf 'cat .env\\n' > ./tmp.sh; sh tmp.sh",
        "printf 'cat .env\\n' > tmp.sh; sh ./scripts/../tmp.sh",
        // a wrapper, a subshell and a loop
        "sh -c \"printf 'cat .env\\\\n' > tmp.sh; sh tmp.sh\"",
        "(printf 'cat .env\\n' > tmp.sh); sh tmp.sh",
        "for i in 1 2; do sh tmp.sh; printf 'cat .env\\n' > tmp.sh; done",
        // a script that writes the next one
        "cat > first.sh <<'EOF'\nprintf 'r .env\\n' > second.sed\nsed -f second.sed notes.md\nEOF\nsh first.sh",
    ] {
        assert_names(&repo, command, ".env");
    }
}

#[test]
fn a_write_through_shell_grouping_or_a_redirected_run_is_not_a_way_around() {
    let repo = repo("grouped", None);

    let allowed: Vec<&str> = [
        "printf 'cat .env\\n' > t.sh; sh < t.sh",
        "printf 'cat .env\\n' > t.sh; bash -x t.sh",
        "printf 'cat .env\\n' > t.sh && env FOO=1 sh t.sh",
        "printf 'cat .env\\n' >t.sh;sh t.sh",
        "{ echo 'cat .env'; } > t.sh; sh t.sh",
        "(echo 'cat .env') > t.sh; sh t.sh",
        "exec > t.sh; echo 'cat .env'; sh t.sh",
        "echo 'cat .env' | tee t.sh >/dev/null; sh t.sh",
        "echo 'cat .env' 1>t.sh; timeout 5 bash ./t.sh",
        "printf 'cat .env\\n' > \"my t.sh\"; sh 'my t.sh'",
        "if true; then echo 'cat .env' > t.sh; fi; sh t.sh",
        "f=t.sh; echo 'cat .env' > $f; sh $f",
    ]
    .into_iter()
    .filter(|command| !judge(&repo, command).denied)
    .collect();

    assert!(allowed.is_empty(), "should be denied: {allowed:#?}");
}

#[test]
fn a_write_that_may_not_happen_does_not_hide_the_file_that_is_there() {
    let repo = repo("conditional", None);
    write(&repo, "tmp.py", "print(open('.env').read())\n");

    // the write may not run, and then the file on disk does
    for command in [
        "false && printf 'print(1)\\n' > tmp.py; python3 tmp.py",
        "printf 'print(1)\\n' > tmp.py || true; python3 tmp.py",
        "printf 'print(1)\\n' >> tmp.py; python3 tmp.py",
    ] {
        assert_names(&repo, command, ".env");
    }
}

#[test]
fn harmless_text_written_and_run_is_allowed() {
    let repo = repo("controls", None);
    write(&repo, "analyze.py", "print('analysis')\n");

    assert_allowed(
        &repo,
        &[
            "echo hi > x.sh; sh x.sh",
            "printf 's/a/b/\\n' > x.sed; sed -f x.sed notes.md",
            "printf 'print(1)\\n' > t.py; python3 t.py",
            "printf 'console.log(1)\\n' > t.js; node t.js",
            "printf 'echo done\\n' > t.sh && bash t.sh",
            "cat > t.sh <<'EOF'\necho done\nEOF\nsh t.sh",
            "cat > t.sed <<< 's/a/b/'; sed -f t.sed notes.md",
            "tee t.sh <<'EOF' > /dev/null\necho done\nEOF\nsh t.sh",
            "printf '%s\\n' 's/a/b/' 's/c/d/' > t.sed; sed -f t.sed notes.md",
            // text is written and not run: writing a name is not reading it
            "printf 'cat .env\\n' > t.sh; cat t.sh",
            "printf 'cat .env\\n' > t.sh; ls t.sh",
            // a program's output goes to a file, and the file is data
            "echo \"$HOME\" > out.txt; cat out.txt",
            "date > stamp.txt; python3 analyze.py",
            "python3 analyze.py > out.txt; cat out.txt",
        ],
    );
}

#[test]
fn a_body_built_at_run_time_is_refused_like_a_path_built_at_run_time() {
    let repo = repo("built", None);

    for command in [
        // a variable, a substitution, a pipe, a program's output
        "echo \"$BODY\" > t.py; python3 t.py",
        "printf '%s\\n' \"$BODY\" > t.py; python3 t.py",
        // `echo` without `-e` may or may not read a backslash as an escape: the
        // shell decides what the file holds
        "echo 'p\\nr .env' > t.sed; sed -f t.sed notes.md",
        "echo $(cat notes.md) > t.sh; sh t.sh",
        "cat notes.md | tee t.sh > /dev/null; sh t.sh",
        "date > t.sh; sh t.sh",
        "python3 -c 'print(1)' > t.py; python3 t.py",
        "echo hi | cat > t.sh; sh t.sh",
        "printf 'echo %s\\n' \"$(whoami)\" > t.sh; sh t.sh",
        // a here-document the shell expands
        "X=1; cat > t.sh <<EOF\necho $X\nEOF\nsh t.sh",
        "cat > t.sed <<< \"r $FILE\"; sed -f t.sed notes.md",
        // a printf this does not follow
        "printf '%q' 'r .env' > t.sed; sed -f t.sed notes.md",
        // every way an interpreter or a shell runs a file
        "echo $BODY > t.sed; sed -f t.sed notes.md",
        "echo $BODY > t.rb; ruby t.rb",
        "echo $BODY > t.sh; source t.sh",
        "echo $BODY > t.awk; awk -f t.awk notes.md",
    ] {
        assert_refused(&repo, command);
    }

    // where the body is not what the file is run for, nothing is refused
    assert_allowed(
        &repo,
        &[
            "echo \"$BODY\" > out.txt; cat out.txt",
            "date > stamp.txt; wc -l stamp.txt",
        ],
    );
}

#[test]
fn a_path_built_at_run_time_cannot_hide_a_script_that_is_not_there() {
    let repo = repo("target", None);
    write(&repo, "analyze.py", "print('analysis')\n");

    // the file written is any file, and the one run is not on disk: it may be it
    assert_refused(&repo, "echo 'print(1)' > \"$OUT\"; python3 gone.py");
    // the file run is there, and what the write replaces is a path built at run
    // time (README, Script Files)
    assert_allowed(&repo, &["echo 'print(1)' > \"$OUT\"; python3 analyze.py"]);
}

#[test]
fn a_body_built_at_run_time_follows_the_dynamic_argument_stance() {
    let command = "echo \"$BODY\" > t.py; python3 t.py";

    let deny = repo("stance-deny", None);
    assert_refused(&deny, command);

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

    // a body the string spells out is judged whichever value is set
    for mode in ["warn", "allow"] {
        let repo = repo(&format!("literal-{mode}"), Some(mode));
        assert_denied_for(
            &repo,
            "printf 'r .env\\n' > tmp.sed; sed -f tmp.sed notes.md",
            ".env",
            "direct_read",
        );
    }
}

#[test]
fn the_reason_names_the_script_the_string_writes() {
    let repo = repo("reason", None);

    let verdict = judge(
        &repo,
        "printf 'r .env\\n' > tmp.sed; sed -f tmp.sed notes.md",
    );
    assert!(verdict.denied, "{:?}", verdict.records);
    assert!(
        verdict.reason.contains("tmp.sed"),
        "the reason should name the script: {}",
        verdict.reason
    );

    let verdict = judge(&repo, "echo \"$BODY\" > t.sh; sh t.sh");
    assert!(verdict.denied, "{:?}", verdict.records);
    assert!(
        verdict.reason.contains("t.sh"),
        "the reason should name the script: {}",
        verdict.reason
    );
}

#[test]
fn a_script_too_large_to_read_is_judged_like_one_on_disk() {
    let repo = repo("large", None);
    // 300 KiB of text, written by a here-document: more than veil reads of any script
    let filler = "# padding\n".repeat(30_000);
    let command = format!("cat > t.sh <<'EOF'\n{filler}cat .env\nEOF\nsh t.sh");

    let verdict = judge(&repo, &command);
    assert!(
        verdict.denied,
        "an unread script in a directory with a protected path is denied: {:?}",
        verdict.records
    );
    assert!(
        verdict
            .records
            .iter()
            .any(|record| record["reason_class"] == "script_too_large_to_inspect"),
        "{:?}",
        verdict.records
    );
}
