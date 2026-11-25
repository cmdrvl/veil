//! `sed` commands inside a script name files (bd-pm8): `r` and `R` copy a file
//! into the output, `w` and `W` and the `w` flag of `s` write one. The name is
//! inside the script, which is one quoted word with a space in it, so no word
//! of the command is shaped like a path and veil used to judge none of them:
//! `sed 'r .env' notes.txt` printed a protected file. These tests drive the real
//! `veil` binary with Claude Code Bash payloads against a repo on disk, and read
//! the audit record for the file the denial names.

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

/// A repo with `data/**` protected by its config, `.env` protected by a built-in
/// pack, an ordinary `notes.txt`, and an audit log. `dynamic_args` is the
/// `[policy] dynamic_args` value, or `None` for the default.
fn repo(label: &str, dynamic_args: Option<&str>) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-sed-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::create_dir_all(root.join("state")).expect("state dir");
    fs::write(
        root.join("data/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("protected file");
    fs::write(root.join(".env"), "TOKEN=abc\n").expect("env file");
    fs::write(root.join("notes.txt"), "a line\nanother a line\n").expect("notes");

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

struct Verdict {
    denied: bool,
    /// What the hook told the agent.
    reason: String,
    /// The audit records this command wrote.
    records: Vec<Value>,
}

fn judge(repo: &Repo, command: &str) -> Verdict {
    let session = format!("sed-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
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
/// path is `path`: the file the script named.
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
fn r_and_big_r_read_a_protected_file_into_the_output() {
    let repo = repo("read", None);

    // the forms in the bead
    for command in [
        "sed 'r .env' notes.txt",
        "sed 'R .env' notes.txt",
        "sed -n '1r .env' notes.txt",
        // beside the script, other ways of giving it
        "sed -e p -e 'r .env' notes.txt",
        "sed --expression='r .env' notes.txt",
        "sed --expression 'r .env' notes.txt",
        "sed -ne 'r .env' notes.txt",
        "sed -n -e'r .env' notes.txt",
        "sed -s -n -- 'r .env' notes.txt",
        "sed -E 'r .env' notes.txt",
        "sed --posix 'r .env' notes.txt",
        "gsed 'r .env' notes.txt",
        "/usr/bin/sed 'r .env' notes.txt",
        // the in-place spellings of GNU and BSD
        "sed -i 'r .env' notes.txt",
        "sed -i.bak 'r .env' notes.txt",
        "sed -i '' 'r .env' notes.txt",
        "sed -i '' -e 'r .env' notes.txt",
        "sed -I '' 'r .env' notes.txt",
        "sed --in-place 'r .env' notes.txt",
        "sed --in-place=.bak 'r .env' notes.txt",
        // addresses
        "sed '$r .env' notes.txt",
        "sed '/a/r .env' notes.txt",
        "sed '/a/I,/b/!r .env' notes.txt",
        "sed '2,+1r .env' notes.txt",
        "sed '1~2r .env' notes.txt",
        "sed '\\%a%r .env' notes.txt",
        "sed '1 ! r .env' notes.txt",
        "sed 'r.env' notes.txt",
        // inside other commands
        "sed '/a/{\np\nr .env\n}' notes.txt",
        "sed 's/a/b/;r .env' notes.txt",
        "sed -n 'p;r .env' notes.txt",
        "sed ':a;N;$!ba;r .env' notes.txt",
        // other ways to name the same file
        "sed 'r ./.env' notes.txt",
        "sed 'r state/../.env' notes.txt",
        // wrapped, piped, nested
        "cat notes.txt | sed 'r .env'",
        "sed 'r .env' < notes.txt",
        "sed 'r .env' notes.txt | head -1",
        "cd . && sed 'r .env' notes.txt",
        "sh -c \"sed 'r .env' notes.txt\"",
        "env sed 'r .env' notes.txt",
        "(sed 'r .env' notes.txt)",
        "echo $(sed 'r .env' notes.txt)",
        "F=.env; sed \"r $F\" notes.txt",
    ] {
        assert_denied_for(&repo, command, ".env", "direct_read");
    }

    // a path the project's own config protects, not a pack's
    assert_denied_for(
        &repo,
        "sed 'r data/holdings.csv' notes.txt",
        "data/holdings.csv",
        "direct_read",
    );
}

#[test]
fn w_big_w_and_the_s_flag_write_a_protected_file() {
    let repo = repo("write", None);

    for command in [
        "sed -e 'w .env' notes.txt",
        "sed 'w .env' notes.txt",
        "sed -n 'w .env' notes.txt",
        "sed 'W .env' notes.txt",
        "sed '2w .env' notes.txt",
        "sed 's/a/b/w .env' notes.txt",
        "sed -n 's/a/b/gpw .env' notes.txt",
        "sed 's|a|b|w .env' notes.txt",
        "sed -i '' 's/a/b/w .env' notes.txt",
        "sed 's/[/]/x/w .env' notes.txt",
    ] {
        assert_denied_for(&repo, command, ".env", "argv_path");
    }

    assert_denied_for(
        &repo,
        "sed 'w data/holdings.csv' notes.txt",
        "data/holdings.csv",
        "argv_path",
    );
}

#[test]
fn the_script_file_and_the_input_file_are_still_judged_as_paths() {
    let repo = repo("paths", None);

    for command in [
        "sed -f .env notes.txt",
        "sed --file=.env notes.txt",
        "sed -n p .env",
        "sed -n p notes.txt .env",
    ] {
        assert_denied_for(&repo, command, ".env", "argv_path");
    }
}

#[test]
fn sed_scripts_that_name_no_protected_file_stay_allowed() {
    let repo = repo("allowed", None);

    assert_allowed(
        &repo,
        &[
            // the bead's controls
            "sed -n 5p notes.txt",
            "sed 's/a/b/' notes.txt",
            // text that is not a command
            "sed 's/r .env/x/' notes.txt",
            "sed 's/a/r .env/' notes.txt",
            "sed 'a r .env' notes.txt",
            "sed 'a\\r .env' notes.txt",
            "sed '1i\\\nr .env' notes.txt",
            "sed '# r .env' notes.txt",
            "sed 'y/r.env/x/' notes.txt",
            "sed '/r .env/d' notes.txt",
            "sed -n '/r .env/p' notes.txt",
            // files that are not protected
            "sed 'r notes.txt' notes.txt",
            "sed 's/a/b/w out.txt' notes.txt",
            "sed -n 's/a/b/w /dev/stdout' notes.txt",
            "sed 'w /dev/stderr' notes.txt",
            "sed 'r /dev/stdin' notes.txt",
            "sed 'r /dev/null' notes.txt",
            // what people write
            "sed -i 's/a/b/' notes.txt",
            "sed -i '' 's/a/b/' notes.txt",
            "sed -i.bak 's/a/b/' notes.txt",
            "sed -i '' -e 's/a/b/' notes.txt",
            "sed -n -e 1p -e 3p notes.txt",
            "sed -E 's/(a|b)+/X/g' notes.txt",
            "sed '/^$/d' notes.txt",
            "sed ':a;N;$!ba;s/\\n/ /g' notes.txt",
            "sed '$!N;s/\\n/ /' notes.txt",
            "sed 's/[/]/x/' notes.txt",
            "sed 's/[^]/]*//' notes.txt",
            "sed '1i\\header' notes.txt",
            "sed '$a footer' notes.txt",
            "sed '/a/{n;d}' notes.txt",
            "sed -n '$=' notes.txt",
            "sed '$a\\' notes.txt",
            "sed '2,$d' notes.txt",
            // found replaying real commands: a redirection is not the script, and
            // a file whose name begins with `e` is not GNU's `e` command
            "sed --version 2>&1 | head -1",
            "sed -n 5p notes.txt 2>&1",
            "sed 's/a/b/' notes.txt > out.txt",
            "sed 's/a/b/' notes.txt >> out.txt 2>/dev/null",
            "sed -i 's/a/b/' edgar.py",
            "sed -i '' 's/a/b/' error.log",
            "sed -i.bak -e 's/a/b/' edgar-transform/x.py && true",
            "sed 'y/abc/xyz/' notes.txt",
            "sed -e :a -e '$!N;s/\\n//;ta' notes.txt",
            "sed --version",
            "cat notes.txt | sed 's/a/b/'",
        ],
    );
}

#[test]
fn a_script_veil_cannot_parse_or_that_runs_a_command_is_refused_not_skipped() {
    let repo = repo("refused", None);

    // `sed` rejects most of these; `e` is the one sed runs. The repo root holds
    // nothing that makes it a protected directory, so this is the dynamic stance
    // for a filter, which applies anywhere.
    for command in [
        "sed 'k' notes.txt",
        "sed 'r' notes.txt",
        "sed 's/a/b' notes.txt",
        "sed '/a/{p' notes.txt",
        "sed 'e cat .env' notes.txt",
        "sed 's/a/b/e' notes.txt",
        "sed '1e echo hi' notes.txt",
        "sed -n '$!{e id}' notes.txt",
        "sed '/x/{p;r notes.txt}' notes.txt",
    ] {
        let verdict = judge(&repo, command);
        assert!(verdict.denied, "should be refused: {command}");
        assert!(
            verdict
                .records
                .iter()
                .any(|record| record["decision"] == "deny"
                    && record["reason_class"] == "dynamic_path_unresolvable"),
            "{command}: expected a dynamic_path_unresolvable denial: {:?}",
            verdict.records
        );
    }
}

#[test]
fn the_dynamic_args_setting_governs_a_refused_script_like_any_other_unresolved_word() {
    // `allow` does not judge words veil cannot resolve at all: a script it cannot
    // parse is one of them. A file the script names outright is still judged.
    let allow = repo("allow-mode", Some("allow"));

    assert_allowed(&allow, &["sed 'k' notes.txt", "sed 'e cat .env' notes.txt"]);
    assert_denied_for(&allow, "sed 'r .env' notes.txt", ".env", "direct_read");
    assert_denied_for(&allow, "sed 'w .env' notes.txt", ".env", "argv_path");

    // `warn` lets it through and leaves the finding in the audit log
    let warn = repo("warn-mode", Some("warn"));
    let verdict = judge(&warn, "sed 'k' notes.txt");
    assert!(!verdict.denied, "warn mode must not deny");
    assert!(
        verdict
            .records
            .iter()
            .any(|record| record["reason_class"] == "dynamic_path_unresolvable"),
        "warn mode records the finding: {:?}",
        verdict.records
    );
}
