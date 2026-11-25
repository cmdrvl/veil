//! bd-5zy: the audit log. The real log of the machine this was written on had
//! `<cwd>/2>/dev/null` and `<cwd>/2>&1` as the `path` of thousands of entries,
//! no marker for which generation of the format an entry was, a hundred lines
//! that two hooks had written into each other, and a `veil audit` that gave up
//! at the first of them. These tests drive the real `veil` binary against a
//! real log on disk.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const HOLDINGS: &str = "data/clients/holdings.csv";

struct Repo {
    root: PathBuf,
    audit: PathBuf,
}

impl Repo {
    fn records(&self) -> Vec<Value> {
        fs::read_to_string(&self.audit)
            .map(|text| {
                text.lines()
                    .map(|line| serde_json::from_str(line).expect("audit line should parse"))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A repo whose `data/**` is protected and whose audit log is `state/audit.jsonl`.
fn repo(label: &str) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-audit-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("state")).expect("state dir");
    fs::write(root.join(HOLDINGS), "name,ssn\nada,078-05-1120\n").expect("protected file");
    fs::write(root.join("notes.md"), "notes\n").expect("note");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let audit = root.join("state/audit.jsonl");
    fs::write(
        root.join(".veil.toml"),
        format!(
            "[sensitivity]\nprotected = [\"data/**\"]\n\n[policy]\naudit_log = true\naudit_path = \"{}\"\n",
            audit.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .expect("config should be written");

    Repo { root, audit }
}

fn veil(repo: &Repo) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
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
        .env_remove("VEIL_AUDIT_PATH");
    command
}

fn payload(repo: &Repo, command: &str) -> String {
    json!({
        "session_id": "audit-log",
        "cwd": repo.root,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// Starts the hook for a Bash command and leaves it running.
fn spawn_hook(repo: &Repo, command: &str) -> std::process::Child {
    let mut child = veil(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veil should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(payload(repo, command).as_bytes())
        .expect("payload should be written");
    child
}

/// Runs the hook for a Bash command and returns whether it denied it.
fn hook(repo: &Repo, command: &str) -> bool {
    let output = spawn_hook(repo, command)
        .wait_with_output()
        .expect("veil should exit");
    assert_eq!(
        output.status.code(),
        Some(0),
        "veil should exit 0 for {command}, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: Value =
        serde_json::from_slice(&output.stdout).expect("veil should print a JSON decision");
    decision["hookSpecificOutput"]["permissionDecision"] == "deny"
}

fn audit(repo: &Repo, args: &[&str]) -> std::process::Output {
    veil(repo)
        .arg("audit")
        .args(args)
        .output()
        .expect("veil audit should run")
}

#[test]
fn redirections_are_never_the_path_of_an_audit_record() {
    let repo = repo("redirections");
    let commands = [
        "cat data/clients/holdings.csv 2>/dev/null",
        "cat data/clients/holdings.csv 2>&1",
        "cat data/clients/holdings.csv >out.txt 2>&1",
        "cat data/clients/holdings.csv >>out.log",
        "cat data/clients/holdings.csv>out.txt",
        "cat data/clients/holdings.csv&>/dev/null",
        "cat data/clients/holdings.csv &>/dev/null",
        "cat <data/clients/holdings.csv",
        "cat < data/clients/holdings.csv 2>/dev/null",
        "cat data/clients/holdings.csv | head -1 2>/dev/null",
        "cat 2>/dev/null data/clients/holdings.csv",
        "2>/dev/null cat data/clients/holdings.csv",
    ];

    for command in commands {
        assert!(hook(&repo, command), "should be denied: {command}");
    }

    let records = repo.records();
    assert_eq!(
        records.len(),
        commands.len(),
        "one record each: {records:?}"
    );
    for (record, command) in records.iter().zip(commands) {
        let path = record["path"].as_str().expect("path");
        assert!(
            path.ends_with(HOLDINGS),
            "the path is the file, not part of a redirection: {path} for {command}"
        );
        assert!(
            !path.contains(['<', '>', '&']),
            "no redirection in {path} for {command}"
        );
    }
}

#[test]
fn an_allowed_reader_records_the_file_it_read_and_never_its_redirections() {
    let repo = repo("quiet");

    // (command, how many records: a reader writes one for the file it reads,
    // a command that is not a reader writes none for a path that is not protected)
    let commands = [
        ("ls notes.md 2>/dev/null", 0),
        ("echo done 2>&1 >out.txt", 0),
        ("true 2>&1 | cat", 0),
        ("cat notes.md >out.txt 2>&1", 1),
        ("cat notes.md>out.txt", 1),
        ("grep -c x notes.md &>/dev/null", 1),
        ("cat <notes.md", 1),
        ("head -2 notes.md 2>/dev/null", 1),
    ];

    let mut expected = 0;
    for (command, records) in commands {
        assert!(!hook(&repo, command), "should be allowed: {command}");
        expected += records;
        assert_eq!(
            repo.records().len(),
            expected,
            "records after {command}: {:?}",
            repo.records()
        );
    }

    for record in repo.records() {
        let path = record["path"].as_str().expect("path");
        assert!(
            path.ends_with("/notes.md"),
            "the path is the file the command read: {path}"
        );
    }
}

#[test]
fn every_new_record_says_which_schema_it_is() {
    let repo = repo("schema");
    assert!(hook(&repo, "cat data/clients/holdings.csv"));
    assert!(hook(&repo, "cat data/clients/holdings.csv 2>/dev/null"));

    let records = repo.records();

    assert_eq!(records.len(), 2);
    for record in &records {
        assert_eq!(record["schema_version"], "veil.audit.v1", "{record}");
    }
}

/// The log of a machine that has run several versions of veil and two hooks at once.
fn mix_generations(repo: &Repo) {
    assert!(hook(repo, "cat data/clients/holdings.csv"));
    assert!(hook(repo, "cat data/clients/holdings.csv 2>/dev/null"));

    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&repo.audit)
        .expect("log should exist");
    log.write_all(
        concat!(
            // an 8-key record from before `origin`, `reason_class` and `class`
            "{\"confidence\":null,\"decision\":\"allow\",\"path\":\"/x/a.csv\",\"reason\":null,\"sensitivity\":null,\"session_id\":\"s\",\"tool\":\"Read\",\"ts\":\"1775187009\"}\n",
            // two records written into each other, then the tail of one
            "{\"confidence\":null,\"decision\":\"allow{\"\"confid\n",
            ",\"session_id\":\"faa60696\",\"tool\":\"Read\",\"ts\":\"1775187015\"}\n",
            "\n",
        )
        .as_bytes(),
    )
    .expect("legacy lines should be appended");
}

#[test]
fn audit_validate_counts_what_a_log_that_mixes_generations_holds() {
    let repo = repo("validate");
    mix_generations(&repo);

    let output = audit(&repo, &["--validate", "--json"]);

    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).expect("validation JSON");
    assert_eq!(value["schema_version"], "veil.audit.v1");
    assert_eq!(value["lines"], 6, "{value}");
    assert_eq!(value["current"], 2, "{value}");
    assert_eq!(value["legacy"], 1, "{value}");
    assert_eq!(value["unparseable"], 2, "{value}");
    assert_eq!(value["blank"], 1, "{value}");
    assert_eq!(value["unparseable_lines"], json!([4, 5]), "{value}");

    let human = audit(&repo, &["--validate"]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(human.status.success(), "{human:?}");
    assert!(text.contains("unparseable: 2"), "{text}");
    assert!(text.contains("unparseable at line: 4, 5"), "{text}");
}

#[test]
fn audit_validate_takes_no_class() {
    let repo = repo("validate-class");

    let output = audit(&repo, &["--validate", "--class", "egress"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn audit_reads_past_a_damaged_line_and_says_how_many_it_left_out() {
    let repo = repo("tolerant");
    mix_generations(&repo);

    let output = audit(&repo, &["--json"]);

    assert!(
        output.status.success(),
        "one damaged line no longer makes the log unreadable: {output:?}"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("audit JSON");
    assert_eq!(
        value["entries"].as_array().map(Vec::len),
        Some(3),
        "{value}"
    );
    assert_eq!(value["skipped_lines"], 2, "{value}");

    let human = audit(&repo, &[]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(human.status.success(), "{human:?}");
    assert!(text.contains("skipped: 2 lines"), "{text}");
}

#[test]
fn a_log_that_has_grown_to_the_limit_is_rotated_and_five_are_kept() {
    let repo = repo("rotate");
    let line = "{\"confidence\":null,\"decision\":\"allow\",\"path\":\"/x/a.csv\",\"reason\":null,\"sensitivity\":null,\"session_id\":\"s\",\"tool\":\"Read\",\"ts\":\"1775187009\"}\n";
    let full = line.repeat((10 * 1024 * 1024 / line.len()) + 1);
    fs::write(&repo.audit, &full).expect("a full log");
    // four rotated files already, and a fifth that is about to be dropped
    for index in 1..=5 {
        fs::write(
            repo.root.join(format!("state/audit.jsonl.{index}")),
            format!("marker-{index}\n"),
        )
        .expect("rotated file");
    }

    assert!(hook(&repo, "cat data/clients/holdings.csv"));

    let current = repo.records();
    assert_eq!(current.len(), 1, "the log starts again with this record");
    assert_eq!(current[0]["schema_version"], "veil.audit.v1");
    let rotated = |index: usize| {
        let file = repo.root.join(format!("state/audit.jsonl.{index}"));
        fs::read(&file).expect("every rotated file up to the fifth should exist")
    };
    assert_eq!(rotated(1), full.as_bytes(), "the full log is now .1");
    for index in 2..=5 {
        assert_eq!(
            String::from_utf8_lossy(&rotated(index)),
            format!("marker-{}\n", index - 1),
            "each rotated file moved up one place"
        );
    }
    assert!(
        !repo.root.join("state/audit.jsonl.6").exists(),
        "no more than five are kept"
    );
    let all: Vec<u8> = (1..=5).flat_map(rotated).collect();
    assert!(
        !String::from_utf8_lossy(&all).contains("marker-5"),
        "the oldest is the one that was dropped"
    );
}

#[test]
fn a_log_under_the_limit_is_not_rotated() {
    let repo = repo("no-rotate");
    assert!(hook(&repo, "cat data/clients/holdings.csv"));
    assert!(hook(&repo, "cat data/clients/holdings.csv"));

    assert_eq!(repo.records().len(), 2);
    assert!(!repo.root.join("state/audit.jsonl.1").exists());
}

#[test]
fn hooks_running_at_the_same_time_leave_a_log_that_reads_back() {
    // Each hook writes eight records. Written a token at a time, a dozen hooks
    // starting together wrote into each other (the damaged lines the real log
    // has); written as one line per record they cannot.
    let repo = repo("concurrent");
    // eight different protected files in one command: eight records per hook
    let files: Vec<String> = (0..8)
        .map(|index| {
            let name = format!("data/clients/h{index}.csv");
            fs::write(repo.root.join(&name), "x\n").expect("file");
            name
        })
        .collect();
    let command = format!("cat {}", files.join(" "));

    let hooks = 16;
    let children: Vec<_> = (0..hooks).map(|_| spawn_hook(&repo, &command)).collect();
    for child in children {
        let output = child.wait_with_output().expect("veil should exit");
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }

    let output = audit(&repo, &["--validate", "--json"]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("validation JSON");
    assert_eq!(value["unparseable"], 0, "no line is two records: {value}");
    assert_eq!(value["current"], value["lines"], "{value}");
    assert!(
        value["lines"].as_u64().is_some_and(|lines| lines >= hooks),
        "every hook wrote its records: {value}"
    );
}
