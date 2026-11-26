//! bd-1wa: MCP tool arguments. Claude Code fires `PreToolUse` for
//! `mcp__<server>__<tool>`, and a send-mail or upload tool takes the path of a
//! file as a string argument. veil judges every string in the arguments that
//! names a path, as it judges a word of a command, and records the denial under
//! the tool's own name with `reason_class: mcp_argument`. These tests drive the
//! real `veil` binary with Claude Code payloads against real files.
//!
//! What they do not cover, and the README says so: a directory argument that
//! merely holds a protected file (judged as a path, not scanned); a relative
//! name resolved by an MCP server whose working directory is not the agent's;
//! a path built inside a string (`"--file=x.csv"`, a comma-separated list);
//! object keys; percent-escapes in `file://` URLs; tools other than
//! `mcp__*` (`WebFetch`, `NotebookRead`).

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;

static COUNTER: AtomicU64 = AtomicU64::new(0);

const HOLDINGS: &str = "data/clients/holdings.csv";
const SPACED: &str = "data/q3 clients.csv";
const CLEAN: &str = "notes.md";

const MAIL: &str = "mcp__mail__send_email";
const UPLOAD: &str = "mcp__files__upload";

struct Repo {
    root: PathBuf,
    audit: PathBuf,
}

impl Repo {
    /// The absolute path of a file in the repo.
    fn at(&self, relative: &str) -> String {
        self.root.join(relative).display().to_string()
    }
}

struct Verdict {
    action: String,
    reason: Option<String>,
    stderr: String,
}

impl Verdict {
    fn denied(&self) -> bool {
        self.action == "deny"
    }
}

/// A repo whose `data/**` is protected, plus an ordinary note.
fn repo(label: &str) -> Repo {
    repo_with(label, "", "")
}

/// As [`repo`], with extra lines for `[policy]` and extra tables after it.
fn repo_with(label: &str, policy_lines: &str, tables: &str) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-mcp-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::write(root.join(HOLDINGS), "name,ssn\nada,078-05-1120\n").expect("protected file");
    fs::write(root.join(SPACED), "name,ssn\nada,078-05-1120\n").expect("spaced file");
    fs::write(root.join(CLEAN), "notes\n").expect("note");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let audit = root.join("state/audit.jsonl");
    fs::write(
        root.join(".veil.toml"),
        format!(
            "[sensitivity]\nprotected = [\"data/**\"]\n\n[policy]\naudit_log = true\naudit_path = \"{}\"\n{policy_lines}\n{tables}",
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

/// The hook's raw output for one tool call.
fn run(repo: &Repo, tool: &str, input: &Value) -> Output {
    let payload = json!({
        "session_id": "mcp",
        "cwd": repo.root,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    });

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
        .write_all(payload.to_string().as_bytes())
        .expect("payload should be written");
    child.wait_with_output().expect("veil should exit")
}

fn call(repo: &Repo, tool: &str, input: Value) -> Verdict {
    let output = run(repo, tool, &input);
    let denial = common::claude_denial(&output);

    Verdict {
        action: if denial.is_some() { "deny" } else { "allow" }.to_owned(),
        reason: denial,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn audit_records(repo: &Repo) -> Vec<Value> {
    fs::read_to_string(&repo.audit)
        .map(|text| {
            text.lines()
                .map(|line| serde_json::from_str(line).expect("audit line should parse"))
                .collect()
        })
        .unwrap_or_default()
}

fn assert_denied(repo: &Repo, tool: &str, input: Value) -> Verdict {
    let verdict = call(repo, tool, input.clone());
    assert!(
        verdict.denied(),
        "should be denied: {tool} {input} (got {})",
        verdict.action
    );
    verdict
}

fn assert_allowed(repo: &Repo, tool: &str, input: Value) {
    let verdict = call(repo, tool, input.clone());
    assert!(
        !verdict.denied(),
        "should be allowed: {tool} {input} (reason: {:?})",
        verdict.reason
    );
}

/// `{"a": [[... leaf ...]]}` with `depth` arrays around the leaf.
fn nested(depth: usize, leaf: Value) -> Value {
    let mut value = leaf;
    for _ in 0..depth {
        value = json!([value]);
    }
    json!({ "a": value })
}

#[test]
fn a_send_mail_tool_handed_a_protected_attachment_is_denied_and_names_the_field() {
    let repo = repo("attachments");

    let verdict = assert_denied(
        &repo,
        MAIL,
        json!({
            "to": "a@example.com",
            "subject": "q3",
            "attachments": [repo.at(CLEAN), repo.at(HOLDINGS)],
        }),
    );

    let reason = verdict.reason.expect("a denial carries its reason");
    assert!(reason.contains(MAIL), "{reason}");
    assert!(reason.contains("(argument `/attachments/1`)"), "{reason}");
    assert!(
        verdict.stderr.contains("MCP argument blocked"),
        "the agent is told what to do instead: {}",
        verdict.stderr
    );

    // the note is no record; the protected file is exactly one
    let records = audit_records(&repo);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["tool"], MAIL);
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reason_class"], "mcp_argument");
    assert_eq!(record["path"], repo.at(HOLDINGS));
    assert_eq!(record["origin"], "top");
    assert!(
        record["class"].is_null(),
        "an MCP tool is not labelled egress"
    );

    // clean attachments alone are allowed, and write nothing
    let clean = self::repo("attachments-clean");
    assert_allowed(
        &clean,
        MAIL,
        json!({ "to": "a@example.com", "attachments": [clean.at(CLEAN)] }),
    );
    assert!(audit_records(&clean).is_empty());
}

#[test]
fn a_single_path_is_judged_however_it_is_written() {
    let repo = repo("single");

    for value in [
        repo.at(HOLDINGS),
        HOLDINGS.to_owned(),
        format!("~/{HOLDINGS}"),
        format!("file://{}", repo.at(HOLDINGS)),
        format!("  {}\t", repo.at(HOLDINGS)),
        "data/clients/../clients/holdings.csv".to_owned(),
        // a rooted path is judged even when nothing is there
        repo.at("data/clients/not-yet-written.csv"),
    ] {
        let verdict = assert_denied(&repo, UPLOAD, json!({ "path": value }));
        assert!(
            verdict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("(argument `/path`)")),
            "{value}: {:?}",
            verdict.reason
        );
    }
}

#[test]
fn strings_that_are_not_paths_are_never_inspected() {
    let repo = repo("not-paths");

    for input in [
        // prose that mentions the file
        json!({ "body": "please see data/clients/holdings.csv for the numbers" }),
        json!({ "query": "SELECT * FROM 'data/clients/holdings.csv'" }),
        // a URL is not a path, whatever it ends in
        json!({ "url": "https://example.com/data/clients/holdings.csv" }),
        json!({ "url": "s3://bucket/data/clients/holdings.csv" }),
        // a file URL for another machine is not this machine's file
        json!({ "url": "file://other-host/data/clients/holdings.csv" }),
        // names that look like paths and are not there
        json!({ "repo": "owner/repo", "branch": "feature/x", "model": "vendor/model" }),
        // a relative name that no file answers to
        json!({ "path": "data/clients/missing.csv" }),
        json!({ "n": 7, "flag": true, "nothing": null, "ratio": 0.5 }),
        // a key is a name, not a value
        json!({ "data/clients/holdings.csv": "x" }),
        // a directory is judged as a path, not scanned for what it holds
        json!({ "cwd": repo.root.display().to_string() }),
    ] {
        assert_allowed(&repo, UPLOAD, input);
    }
    assert!(
        audit_records(&repo).is_empty(),
        "nothing protected was named: {:?}",
        audit_records(&repo)
    );
}

#[test]
fn nested_objects_and_arrays_are_walked_and_the_pointer_says_where() {
    let repo = repo("nested");

    let verdict = assert_denied(
        &repo,
        "mcp__crm__create_record",
        json!({
            "record": {
                "notes": ["fine", 3, null],
                "files": [
                    { "name": "a", "source": { "kind": "local", "path": repo.at(CLEAN) } },
                    { "name": "b", "source": { "kind": "local", "path": repo.at(HOLDINGS) } },
                ],
            },
        }),
    );

    assert!(
        verdict
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("(argument `/record/files/1/source/path`)")),
        "{:?}",
        verdict.reason
    );
}

#[test]
fn a_symlink_to_a_protected_file_is_followed() {
    let repo = repo("symlink");
    std::os::unix::fs::symlink(repo.root.join(HOLDINGS), repo.root.join("report.csv"))
        .expect("symlink");

    assert_denied(&repo, UPLOAD, json!({ "file": "report.csv" }));
    assert_denied(&repo, UPLOAD, json!({ "file": repo.at("report.csv") }));
}

#[test]
fn a_path_with_spaces_is_judged_when_a_file_of_that_name_is_there() {
    let repo = repo("spaces");

    assert_denied(&repo, UPLOAD, json!({ "file": SPACED }));
    assert_denied(&repo, UPLOAD, json!({ "file": repo.at(SPACED) }));

    // the same words with nothing there, or with more words around them
    assert_allowed(&repo, UPLOAD, json!({ "file": "data/q4 clients.csv" }));
    assert_allowed(
        &repo,
        UPLOAD,
        json!({ "file": repo.at("data/q4 clients.csv") }),
    );
    assert_allowed(
        &repo,
        UPLOAD,
        json!({ "note": format!("attach {SPACED} to the mail") }),
    );
}

#[test]
fn screening_can_be_turned_off_or_narrowed_to_the_tools_that_take_no_paths() {
    let protected = |repo: &Repo| json!({ "attachments": [repo.at(HOLDINGS)] });

    let off = repo_with("screen-off", "", "[mcp]\nscreen = false\n");
    assert_allowed(&off, MAIL, protected(&off));
    assert!(
        audit_records(&off).is_empty(),
        "nothing is judged, nothing is recorded"
    );

    let ignore = repo_with(
        "ignore",
        "",
        "[mcp]\nignore_tools = [\"mcp__mail__send_email\", \"mcp__crm__*\"]\n",
    );
    assert_allowed(&ignore, MAIL, protected(&ignore));
    assert_allowed(&ignore, "mcp__crm__anything", protected(&ignore));
    assert_denied(&ignore, "mcp__mail__send_draft", protected(&ignore));
    assert_denied(&ignore, UPLOAD, protected(&ignore));

    // on by default
    let default = repo("screen-default");
    assert_denied(&default, MAIL, protected(&default));
}

#[test]
fn an_ignore_entry_that_could_never_match_is_a_config_error() {
    // `send_email` is not `mcp__server__send_email`: left alone it would
    // silently screen the tool it was meant to exempt, or exempt nothing
    for entry in ["send_email", "mcp__a__*__b", "mcp__a b", ""] {
        let repo = repo_with(
            "bad-ignore",
            "",
            &format!("[mcp]\nignore_tools = [\"{entry}\"]\n"),
        );

        let output = run(&repo, MAIL, &json!({ "to": "a@example.com" }));

        assert!(!output.status.success(), "{entry:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("mcp.ignore_tools"), "{entry:?}: {stderr}");
    }
}

#[test]
fn a_warn_policy_lets_the_call_through_and_records_why() {
    let repo = repo_with("warn", "default = \"warn\"", "");

    assert_allowed(&repo, MAIL, json!({ "attachments": [repo.at(HOLDINGS)] }));

    let records = audit_records(&repo);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["reason_class"], "mcp_argument");
    let reason = records[0]["reason"]
        .as_str()
        .expect("a warning has a reason");
    assert!(reason.contains("policy default warn"), "{reason}");
    assert!(reason.contains("(argument `/attachments/0`)"), "{reason}");
}

#[test]
fn arguments_too_deep_to_read_are_denied_not_waved_through() {
    let repo = repo("deep");
    let leaf = || json!(repo.at(CLEAN));

    // 30 levels is read to the end
    assert_allowed(&repo, UPLOAD, nested(30, leaf()));

    // past the limit veil cannot show that nothing in it is protected, so it
    // does not say so: the protected path hides at the bottom
    let deep = nested(40, json!(repo.at(HOLDINGS)));
    let verdict = assert_denied(&repo, UPLOAD, deep.clone());
    let reason = verdict.reason.expect("a denial carries its reason");
    assert!(
        reason.contains("cannot show that none of them names a protected path"),
        "{reason}"
    );
    assert!(
        verdict.stderr.contains("too large to screen"),
        "{}",
        verdict.stderr
    );

    let records = audit_records(&repo);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["path"], "<arguments veil cannot screen>");
    assert_eq!(records[0]["reason_class"], "mcp_argument");

    // a tool the operator said takes no paths is not read at all
    let ignore = repo_with(
        "deep-ignore",
        "",
        "[mcp]\nignore_tools = [\"mcp__files__*\"]\n",
    );
    assert_allowed(&ignore, UPLOAD, deep);
}

#[test]
fn a_tool_with_more_strings_than_veil_reads_is_denied() {
    let repo = repo("many");
    let strings = |count: usize| json!({ "rows": vec![repo.at(CLEAN); count] });

    assert_allowed(&repo, UPLOAD, strings(10_000));
    assert_denied(&repo, UPLOAD, strings(10_001));
}

#[test]
fn veil_audit_class_mcp_argument_lists_what_was_handed_to_a_tool() {
    let repo = repo("audit-cli");

    assert_denied(&repo, MAIL, json!({ "attachments": [repo.at(HOLDINGS)] }));
    assert_denied(&repo, UPLOAD, json!({ "path": HOLDINGS }));
    assert_denied(
        &repo,
        "Bash",
        json!({ "command": format!("cat {HOLDINGS}") }),
    );

    let output = veil(&repo)
        .env("VEIL_HARNESS", "plain")
        .args(["audit", "--class", "mcp_argument", "--json"])
        .output()
        .expect("veil audit should run");
    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).expect("audit JSON should parse");
    assert_eq!(value["class"], "mcp_argument");
    let entries = value["entries"].as_array().expect("entries");
    let tools: Vec<&str> = entries
        .iter()
        .map(|entry| entry["tool"].as_str().expect("tool"))
        .collect();
    assert_eq!(
        tools,
        [MAIL, UPLOAD],
        "the Bash denial is not an MCP argument"
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry["reason_class"] == "mcp_argument")
    );

    // all three are there without the filter
    let output = veil(&repo)
        .env("VEIL_HARNESS", "plain")
        .args(["audit", "--json"])
        .output()
        .expect("veil audit should run");
    let value: Value = serde_json::from_slice(&output.stdout).expect("audit JSON should parse");
    assert_eq!(value["entries"].as_array().map(Vec::len), Some(3));
}

#[test]
fn a_tool_that_is_neither_built_in_nor_an_mcp_tool_is_still_refused() {
    let repo = repo("other-tool");

    let output = run(&repo, "WebFetch", &json!({ "url": "https://example.com" }));

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported Claude Code tool"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
