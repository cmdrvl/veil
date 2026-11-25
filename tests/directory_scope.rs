//! bd-1si: a content search of a directory reads every file beneath it, so the
//! hook must treat it as a read of whatever `[sensitivity] protected` covers
//! there. These tests drive the real `veil` binary with Claude Code
//! `PreToolUse` payloads against real directories on disk.
//!
//! What they do not cover: searches the extractor does not recognise as
//! searches (`git grep`), and built-in packs such as `.env` found beneath a
//! searched directory. Those are separate gaps, named in the bd-1si comment.
//! Searches after the first command of a line, inside `sh -c` and behind
//! `find -exec` are covered since bd-2kr; see `tests/shell_decomposition.rs`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Repo {
    root: PathBuf,
    audit: PathBuf,
}

struct Verdict {
    action: String,
    reason: Option<String>,
    /// What veil prints on stderr: the guidance the agent sees on a denial.
    stderr: String,
}

impl Verdict {
    fn denied(&self) -> bool {
        self.action == "deny"
    }
}

/// A repo whose `data/**` is protected, with one protected file and one
/// ordinary source file, both holding fake SSNs.
fn repo(label: &str) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-dirscope-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::write(
        root.join("data/clients/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("protected file");
    fs::write(
        root.join("src/main.rs"),
        "// ssn handling lives elsewhere\n",
    )
    .expect("source file");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let audit = root.join("state/audit.jsonl");
    fs::write(
        root.join(".veil.toml"),
        format!(
            "[sensitivity]\nprotected = [\"data/**\"]\n\n[policy]\ndefault = \"deny\"\naudit_log = true\naudit_path = \"{}\"\n",
            audit.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .expect("config should be written");

    Repo { root, audit }
}

fn run_hook(cwd: &Path, tool_name: &str, tool_input: Value) -> Verdict {
    let payload = json!({
        "session_id": "dirscope",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
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
        "veil should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: Value =
        serde_json::from_slice(&output.stdout).expect("veil should print a JSON decision");
    let specific = &decision["hookSpecificOutput"];

    Verdict {
        action: specific["permissionDecision"]
            .as_str()
            .expect("decision should carry permissionDecision")
            .to_owned(),
        reason: specific["permissionDecisionReason"]
            .as_str()
            .map(str::to_owned),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn grep(repo: &Repo, input: Value) -> Verdict {
    run_hook(&repo.root, "Grep", input)
}

fn bash(repo: &Repo, command: &str) -> Verdict {
    run_hook(&repo.root, "Bash", json!({ "command": command }))
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

#[test]
fn grep_content_search_of_a_directory_holding_protected_data_is_denied() {
    let repo = repo("grep-deny");
    let root = repo.root.to_string_lossy().into_owned();
    let data = repo.root.join("data").to_string_lossy().into_owned();
    let clients = repo
        .root
        .join("data/clients")
        .to_string_lossy()
        .into_owned();

    for (label, input) in [
        (
            "repo root, content",
            json!({ "pattern": "ssn", "path": root, "output_mode": "content" }),
        ),
        (
            "repo root, mode omitted",
            json!({ "pattern": "ssn", "path": root }),
        ),
        (
            "relative dot",
            json!({ "pattern": "ssn", "path": ".", "output_mode": "content" }),
        ),
        (
            "no path (searches the working directory)",
            json!({ "pattern": "ssn", "output_mode": "content" }),
        ),
        (
            "the protected root itself",
            json!({ "pattern": "ssn", "path": data, "output_mode": "content" }),
        ),
        (
            "a directory inside the protected root",
            json!({ "pattern": "ssn", "path": clients, "output_mode": "content" }),
        ),
        (
            "a file inside the protected root (already denied before bd-1si)",
            json!({ "pattern": "ssn", "path": format!("{data}/clients/holdings.csv"), "output_mode": "content" }),
        ),
    ] {
        let verdict = grep(&repo, input);

        assert!(
            verdict.denied(),
            "{label}: expected deny, got {}",
            verdict.action
        );
    }
}

#[test]
fn grep_denial_says_why_and_does_not_name_the_protected_file() {
    let repo = repo("grep-reason");

    let verdict = grep(
        &repo,
        json!({ "pattern": "ssn", "path": repo.root, "output_mode": "content" }),
    );

    let reason = verdict.reason.expect("a denial carries a reason");
    assert!(reason.contains("[sensitivity] protected"), "{reason}");
    assert!(
        verdict.stderr.contains("files_with_matches"),
        "the guidance should point at a metadata-only search: {}",
        verdict.stderr
    );
    for text in [reason.as_str(), verdict.stderr.as_str()] {
        assert!(
            !text.contains("holdings"),
            "the agent must not be handed the name of a protected file: {text}"
        );
    }
}

#[test]
fn grep_names_and_counts_of_a_protected_directory_are_allowed_and_audited() {
    let repo = repo("grep-meta");

    for mode in ["files_with_matches", "count"] {
        let verdict = grep(
            &repo,
            json!({ "pattern": "ssn", "path": repo.root, "output_mode": mode }),
        );

        assert!(
            !verdict.denied(),
            "{mode} on the repo root should be allowed"
        );
    }
    let verdict = grep(
        &repo,
        json!({ "pattern": "ssn", "path": repo.root.join("data"), "output_mode": "count" }),
    );
    assert!(
        !verdict.denied(),
        "count on the protected root is metadata only"
    );

    let records = audit_records(&repo);
    assert_eq!(records.len(), 3, "every search is audited: {records:?}");
    for record in &records {
        assert_eq!(record["tool"], "Grep");
        assert_eq!(record["decision"], "allow");
    }
    assert_eq!(
        records[2]["path"].as_str(),
        Some(repo.root.join("data").to_string_lossy().as_ref())
    );
}

#[test]
fn grep_content_search_of_a_directory_with_no_protected_data_is_allowed() {
    let repo = repo("grep-clean");

    let verdict = grep(
        &repo,
        json!({ "pattern": "ssn", "path": repo.root.join("src"), "output_mode": "content" }),
    );

    assert!(!verdict.denied());
    assert_eq!(verdict.reason, None);
}

#[test]
fn bash_content_searches_of_protected_data_are_denied() {
    let repo = repo("bash-deny");

    for command in [
        "grep ssn data/clients/holdings.csv",
        "grep -n ssn data/clients/holdings.csv",
        "grep -r ssn data",
        "grep -rn ssn data/",
        "grep -r ssn .",
        "grep -r ssn",
        "grep -R -i ssn data src",
        "egrep -r 'ssn|ein' data",
        "grep -e ssn -r data",
        "grep -A 2 -r ssn data",
        "grep -r ssn *",
        "grep -r ssn data/*.csv",
        "grep -f data/clients/holdings.csv src/main.rs",
        "grep -rl -f data/clients/holdings.csv src",
        "/usr/bin/grep -r ssn data",
        "env LC_ALL=C grep -r ssn data",
        "rg ssn data",
        "rg ssn",
        "rg -n -C 2 ssn data/",
        "rg -g '*.csv' ssn data",
        "rg ssn src/*.rs data",
        "ag ssn data",
        "ack ssn data",
        "ugrep -r ssn data",
    ] {
        let verdict = bash(&repo, command);

        assert!(
            verdict.denied(),
            "`{command}` reads protected content and must be denied"
        );
    }
}

#[test]
fn bash_names_and_counts_only_searches_are_allowed_and_audited() {
    let repo = repo("bash-meta");
    let commands = [
        "grep -l ssn data/clients/holdings.csv",
        "grep -rl ssn data",
        "grep -rl ssn",
        "grep -rL ssn data",
        "grep -c ssn data/clients/holdings.csv",
        "grep -rc ssn data",
        "grep -r --files-with-matches ssn data",
        "rg -l ssn data",
        "rg -c ssn data",
        "rg --files data",
        "rg --files",
        "ag -l ssn data",
        "ack -f data",
    ];

    for command in commands {
        let verdict = bash(&repo, command);

        assert!(
            !verdict.denied(),
            "`{command}` returns names or counts only and must be allowed, got {:?}",
            verdict.reason
        );
    }

    let records = audit_records(&repo);
    assert_eq!(
        records.len(),
        commands.len(),
        "every names-and-counts search is audited: {records:?}"
    );
    assert!(
        records
            .iter()
            .all(|record| record["tool"] == "Bash" && record["decision"] == "allow")
    );
}

#[test]
fn bash_searches_that_cannot_reach_protected_data_are_allowed() {
    let repo = repo("bash-clean");

    for command in [
        "grep ssn src/main.rs",
        "grep -r ssn src",
        "rg ssn src",
        "rg -n ssn src/main.rs",
        "ag ssn src",
        "grep ssn *.md",
        "grep ssn",
        "echo data",
    ] {
        let verdict = bash(&repo, command);

        assert!(
            !verdict.denied(),
            "`{command}` cannot reach protected data and must be allowed, got {:?}",
            verdict.reason
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_to_the_repo_is_searched_as_the_repo() {
    use std::os::unix::fs::symlink;

    let repo = repo("alias");
    let outside = repo.root.with_file_name(format!(
        "{}-alias",
        repo.root
            .file_name()
            .expect("repo root has a name")
            .to_string_lossy()
    ));
    symlink(&repo.root, &outside).expect("symlink should be creatable");

    let verdict = grep(
        &repo,
        json!({ "pattern": "ssn", "path": outside, "output_mode": "content" }),
    );

    assert!(
        verdict.denied(),
        "an alias must not hide the protected directory"
    );
}

/// A repo with a `.env` that only a built-in pack recognises, no `.veil.toml`,
/// and a scratch home so no user config or audit log is read or written.
fn pack_only_repo(label: &str) -> (PathBuf, PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "veil-packonly-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(base.join("repo/src")).expect("repo dir");
    fs::create_dir_all(base.join("home")).expect("home dir");
    fs::write(base.join("repo/.env"), "API_SECRET=hunter2\n").expect("pack-only file");
    fs::write(base.join("repo/src/main.rs"), "fn main() {}\n").expect("source file");

    let base = fs::canonicalize(&base).expect("base should canonicalize");
    (base.join("repo"), base)
}

fn bash_pack_only(command: &str) -> Verdict {
    let (repo, base) = pack_only_repo("search");
    let payload = json!({
        "session_id": "dirscope-pack-only",
        "cwd": repo,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .env("HOME", base.join("home"))
        .env("XDG_CONFIG_HOME", base.join("xdg-config"))
        .env("XDG_STATE_HOME", base.join("xdg-state"))
        .env("VEIL_AUDIT_PATH", base.join("audit.jsonl"))
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
    let decision: Value =
        serde_json::from_slice(&output.stdout).expect("veil should print a JSON decision");
    let specific = &decision["hookSpecificOutput"];

    Verdict {
        action: specific["permissionDecision"]
            .as_str()
            .expect("decision should carry permissionDecision")
            .to_owned(),
        reason: specific["permissionDecisionReason"]
            .as_str()
            .map(str::to_owned),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// bd-1si reopened: the directory walk only looks for paths covered by
/// `[sensitivity] protected`, so a file that a built-in pack alone recognises
/// is not found beneath a searched directory. Each of these commands reads
/// `.env` and is allowed today. Run with `cargo test --test directory_scope --
/// --ignored` to see the failure; remove the `ignore` when the walk consults
/// the packs.
#[test]
#[ignore = "bd-1si reopened: directory walk ignores built-in packs (.env found only by name)"]
fn a_recursive_search_finds_a_file_only_a_builtin_pack_protects() {
    let mut allowed = Vec::new();

    for command in [
        "grep -r SECRET .",
        "rg SECRET .",
        "rg SECRET",
        r"find . -exec cat {} \;",
    ] {
        let verdict = bash_pack_only(command);
        if !verdict.denied() {
            allowed.push(command);
        }
    }

    // Naming the file is denied today, which is what makes the gap a gap.
    assert!(
        bash_pack_only("cat .env").denied(),
        "naming `.env` is expected to be denied by the pack"
    );
    assert!(
        allowed.is_empty(),
        "these commands read `.env` and must be denied: {allowed:?}"
    );
}
