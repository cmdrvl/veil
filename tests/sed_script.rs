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
    judge_in(repo, &repo.root, command)
}

/// A file of the repo: `name` is relative to its root.
fn write(repo: &Repo, name: &str, text: &str) {
    let path = repo.root.join(name);
    fs::create_dir_all(path.parent().expect("a file has a parent")).expect("parent dir");
    fs::write(path, text).expect("fixture file");
}

/// `command` run from `cwd`, a directory of the repo.
fn judge_in(repo: &Repo, cwd: &std::path::Path, command: &str) -> Verdict {
    let session = format!("sed-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
    let payload = json!({
        "session_id": session,
        "cwd": cwd,
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

// ---- a sed script FILE (bd-xu0): `sed -f read.sed` runs what is in the file,
// which the agent can write itself, so veil reads it like the script on the
// command line.

#[test]
fn a_script_file_that_reads_a_protected_file_is_denied() {
    let repo = repo("file-read", None);
    write(&repo, "read.sed", "r .env\n");
    write(&repo, "big.sed", "R .env\n");
    write(
        &repo,
        "addressed.sed",
        "# copy the secrets\n/a/{\n  p\n  r .env\n}\n",
    );
    write(&repo, "tools/read.sed", "1r .env\n");
    write(&repo, "crlf.sed", "r .env\r\n");
    write(&repo, "last-line.sed", "s/a/b/\n$r .env");
    write(&repo, "plain.sed", "s/a/b/\n");

    for command in [
        "sed -f read.sed notes.txt",
        "sed -f ./read.sed notes.txt",
        "sed -f tools/read.sed notes.txt",
        "sed -f big.sed notes.txt",
        "sed -f addressed.sed notes.txt",
        "sed -f crlf.sed notes.txt",
        "sed -f last-line.sed notes.txt",
        // the other ways of giving a script file
        "sed -nf read.sed notes.txt",
        "sed -n -f read.sed notes.txt",
        "sed -fread.sed notes.txt",
        "sed --file=read.sed notes.txt",
        "sed --file read.sed notes.txt",
        "sed --fi=read.sed notes.txt",
        // more than one script
        "sed -f plain.sed -f read.sed notes.txt",
        "sed -f read.sed -f plain.sed notes.txt",
        "sed -e p -f read.sed notes.txt",
        "sed -f read.sed -e p notes.txt",
        // options that come first: GNU runs the file, BSD takes `-f` as the suffix
        "sed -s -f read.sed notes.txt",
        "sed -E -f read.sed notes.txt",
        "sed -i -f read.sed notes.txt",
        "sed -i.bak -f read.sed notes.txt",
        "sed -i '' -f read.sed notes.txt",
        "sed --in-place -f read.sed notes.txt",
        "gsed -f read.sed notes.txt",
        "/usr/bin/sed -f read.sed notes.txt",
        // wrapped in the ways a command is
        "cat notes.txt | sed -f read.sed",
        "sed -f read.sed notes.txt | head",
        "sh -c 'sed -f read.sed notes.txt'",
        "env sed -f read.sed notes.txt",
        "(sed -f read.sed notes.txt)",
        "echo $(sed -f read.sed notes.txt)",
    ] {
        assert_denied_for(&repo, command, ".env", "direct_read");
    }

    let absolute = format!("sed -f {}/read.sed notes.txt", repo.root.display());
    assert_denied_for(&repo, &absolute, ".env", "direct_read");

    // the reason says which script it found the file in
    let verdict = judge(&repo, "sed -f read.sed notes.txt");
    assert!(
        verdict.reason.contains("found in script `read.sed`"),
        "{}",
        verdict.reason
    );
}

#[test]
fn a_script_file_that_writes_a_protected_file_is_denied() {
    let repo = repo("file-write", None);
    write(&repo, "write.sed", "w .env\n");
    write(&repo, "big-w.sed", "/a/W .env\n");
    write(&repo, "flag.sed", "s/a/b/w .env\n");
    write(&repo, "data.sed", "w data/holdings.csv\n");

    for command in [
        "sed -f write.sed notes.txt",
        "sed -n -f big-w.sed notes.txt",
        "sed -f flag.sed notes.txt",
        "sed -i -f write.sed notes.txt",
    ] {
        assert_denied_for(&repo, command, ".env", "argv_path");
    }
    assert_denied_for(
        &repo,
        "sed -f data.sed notes.txt",
        "data/holdings.csv",
        "argv_path",
    );
}

#[test]
fn a_script_file_veil_cannot_parse_or_that_runs_a_command_is_refused_not_skipped() {
    let repo = repo("file-refused", None);
    let broken = [
        ("exec.sed", "e id\n"),
        ("exec-flag.sed", "s/a/b/e\n"),
        ("exec-block.sed", "$!{\n  e cat .env\n}\n"),
        ("k.sed", "k\n"),
        ("no-name.sed", "r\n"),
        ("unterminated.sed", "s/a/b\n"),
        ("open-block.sed", "/x/{\np\n"),
    ];

    for (name, text) in broken {
        write(&repo, name, text);
        let command = format!("sed -f {name} notes.txt");
        let verdict = judge(&repo, &command);

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
        assert!(
            verdict
                .reason
                .contains(&format!("the sed script in {name}")),
            "{command}: the reason names the script file: {}",
            verdict.reason
        );
    }

    // `dynamic_args` governs it like a word veil cannot resolve; a file the
    // script names outright is judged in every mode
    let allow = repo_with_scripts("file-allow", "allow");
    assert_allowed(
        &allow,
        &["sed -f exec.sed notes.txt", "sed -f k.sed notes.txt"],
    );
    assert_denied_for(&allow, "sed -f read.sed notes.txt", ".env", "direct_read");
    assert_denied_for(&allow, "sed -f write.sed notes.txt", ".env", "argv_path");

    let warn = repo_with_scripts("file-warn", "warn");
    let verdict = judge(&warn, "sed -f exec.sed notes.txt");
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

fn repo_with_scripts(label: &str, dynamic_args: &str) -> Repo {
    let repo = repo(label, Some(dynamic_args));
    write(&repo, "exec.sed", "e id\n");
    write(&repo, "k.sed", "k\n");
    write(&repo, "read.sed", "r .env\n");
    write(&repo, "write.sed", "w .env\n");
    repo
}

#[test]
fn script_files_that_name_no_protected_file_stay_allowed() {
    let repo = repo("file-allowed", None);
    let scripts = [
        ("substitute.sed", "s/a/b/\n"),
        ("print.sed", "5p\n"),
        ("empty.sed", ""),
        ("comment.sed", "# only a comment\n"),
        ("shebang.sed", "#!/bin/sed -f\ns/a/b/\n"),
        ("quiet.sed", "#n\n1p\n"),
        ("insert.sed", "1i\\\nheader line\n"),
        ("append.sed", "/a/a\\\nfirst\\\nsecond\n"),
        ("transliterate.sed", "y/abc/xyz/\n"),
        ("join.sed", ":a;N;$!ba;s/\\n/ /g\n"),
        ("block.sed", "/x/{\np\nd\n}\n"),
        (
            "text-is-not-a-command.sed",
            "s/r .env/x/\na r .env\n# r .env\n",
        ),
        ("reads-notes.sed", "r notes.txt\n"),
        ("to-stdout.sed", "w /dev/stdout\n"),
        ("writes-state.sed", "s/a/b/w state/out.txt\n"),
    ];

    for (name, text) in scripts {
        write(&repo, name, text);
        assert_allowed(
            &repo,
            &[
                &format!("sed -f {name} notes.txt"),
                &format!("sed -nf {name} notes.txt"),
                // `-i -f script file` is an everyday GNU spelling: the BSD reading
                // takes `-f` as the suffix and must not refuse the command for it
                &format!("sed -i -f {name} notes.txt"),
                &format!("sed -i.bak --file={name} notes.txt"),
            ],
        );
    }
    assert_allowed(
        &repo,
        &[
            "sed -f substitute.sed -f print.sed notes.txt",
            "sed -e p -f substitute.sed notes.txt",
            "sed -f missing.sed notes.txt",
        ],
    );
}

#[test]
fn a_script_given_on_standard_input_is_read_where_veil_can_see_it() {
    let repo = repo("file-stdin", None);
    write(&repo, "read.sed", "r .env\n");
    write(&repo, "plain.sed", "s/a/b/\n");

    for command in [
        "sed -f - notes.txt <<'EOF'\nr .env\nEOF",
        "sed -f /dev/stdin notes.txt <<'EOF'\nr .env\nEOF",
        "sed -n -f - notes.txt <<EOF\n1r .env\nEOF",
        "sed -f - notes.txt <<< 'r .env'",
        "sed -f - notes.txt < read.sed",
        "sed -f /dev/stdin notes.txt < read.sed",
        "sed -e p -f - notes.txt <<'EOF'\nr .env\nEOF",
    ] {
        assert_denied_for(&repo, command, ".env", "direct_read");
    }
    assert_denied_for(
        &repo,
        "sed -f - notes.txt <<'EOF'\nw .env\nEOF",
        ".env",
        "argv_path",
    );

    // a script that comes down a pipe is not text veil has: refused, not skipped
    for command in [
        "cat read.sed | sed -f - notes.txt",
        "echo 'r .env' | sed -f - notes.txt",
    ] {
        let verdict = judge(&repo, command);
        assert!(verdict.denied, "should be refused: {command}");
        assert!(
            verdict
                .records
                .iter()
                .any(|record| record["decision"] == "deny"
                    && record["reason_class"] == "dynamic_path_unresolvable"),
            "{command}: {:?}",
            verdict.records
        );
    }

    // `/dev/stdin` is a device path, which the descriptor rule already refuses
    // on its own, whatever feeds it
    assert!(judge(&repo, "echo 'r .env' | sed -f /dev/stdin notes.txt").denied);

    assert_allowed(
        &repo,
        &[
            "sed -f - notes.txt <<'EOF'\ns/a/b/\nEOF",
            "sed -f - notes.txt <<< 's/a/b/'",
            "sed -f - notes.txt < plain.sed",
            "sed -n p notes.txt <<'EOF'\nr .env\nEOF",
        ],
    );
}

#[test]
fn a_file_run_by_name_whose_first_line_names_sed_is_a_sed_script() {
    let repo = repo("file-shebang", None);
    write(&repo, "read.sed", "#!/usr/bin/sed -f\nr .env\n");
    write(&repo, "env.sed", "#!/usr/bin/env -S sed -nf\n1r .env\n");
    write(&repo, "gnu.sed", "#!/usr/local/bin/gsed -f\nR .env\n");
    write(&repo, "write.sed", "#!/bin/sed -f\nw .env\n");
    write(&repo, "plain.sed", "#!/bin/sed -f\ns/a/b/\n");
    write(&repo, "exec.sed", "#!/bin/sed -f\ne id\n");

    for command in [
        "./read.sed notes.txt",
        "./env.sed notes.txt",
        "./gnu.sed notes.txt",
        "cat notes.txt | ./read.sed",
    ] {
        assert_denied_for(&repo, command, ".env", "direct_read");
    }
    assert_denied_for(&repo, "./write.sed notes.txt", ".env", "argv_path");

    let verdict = judge(&repo, "./exec.sed notes.txt");
    assert!(
        verdict.denied,
        "a shebang script that runs a command is refused"
    );
    assert_allowed(&repo, &["./plain.sed notes.txt"]);
}

#[test]
fn a_script_file_that_is_itself_protected_is_denied_and_never_quoted() {
    let repo = repo("file-protected", None);

    for (command, secret) in [
        ("sed -f .env notes.txt", "TOKEN"),
        ("sed -f data/holdings.csv notes.txt", "078-05-1120"),
        ("sed -nf data/holdings.csv notes.txt", "078-05-1120"),
        ("sed -f - notes.txt < data/holdings.csv", "078-05-1120"),
    ] {
        let verdict = judge(&repo, command);

        assert!(verdict.denied, "should be denied: {command}");
        assert!(
            !verdict.reason.contains(secret)
                && !serde_json::to_string(&verdict.records)
                    .expect("records serialize")
                    .contains(secret),
            "{command}: what is in a protected script must not reach a reason or the audit log: {}",
            verdict.reason
        );
    }

    // a link to a protected file is the protected file
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(repo.root.join(".env"), repo.root.join("linked.sed"))
            .expect("symlink");
        let verdict = judge(&repo, "sed -f linked.sed notes.txt");
        assert!(verdict.denied, "a link to .env: {}", verdict.reason);
        assert!(!verdict.reason.contains("TOKEN"), "{}", verdict.reason);
    }
}

#[test]
fn a_script_file_larger_than_the_limit_is_judged_like_other_unread_scripts() {
    let repo = repo("file-large", None);
    let line = "s/a/b/\n";
    let text = line.repeat(300_000 / line.len());
    write(&repo, "big.sed", &text);
    write(&repo, "clean/big.sed", &text);
    write(&repo, "clean/notes.txt", "a line\n");

    // where a protected path is within reach of the directory it runs in
    let verdict = judge(&repo, "sed -f big.sed notes.txt");
    assert!(verdict.denied, "unread and protected data in reach");
    assert!(
        verdict
            .records
            .iter()
            .any(|record| record["decision"] == "deny"
                && record["reason_class"] == "script_too_large_to_inspect"),
        "{:?}",
        verdict.records
    );

    // where none is, it is allowed
    let clean = repo.root.join("clean");
    let verdict = judge_in(&repo, &clean, "sed -f big.sed notes.txt");
    assert!(
        !verdict.denied,
        "nothing protected in reach: {}",
        verdict.reason
    );
}
