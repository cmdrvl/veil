//! bd-2kr: the hook judges each command a Bash tool call would run, not only
//! the first word of the string. These tests drive the real `veil` binary with
//! Claude Code `PreToolUse` payloads against real directories on disk.
//!
//! What they do not cover, and what is still allowed: a script fed to a shell
//! on stdin by a pipe (`echo '...' | sh`), `source`/`.`, `git grep`,
//! `docker exec`, `ssh host cmd` and the many other programs that run a
//! command and are not in the wrapper list. Variables and other expansions,
//! command text veil cannot parse and anything past the 64th segment are the
//! dynamic-argument stance's (bd-2mi); the last test here pins that they are
//! denied, and tests/dynamic_args.rs covers the stance itself.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Repo {
    root: PathBuf,
    audit: PathBuf,
}

struct Verdict {
    action: String,
    reason: Option<String>,
}

impl Verdict {
    fn denied(&self) -> bool {
        self.action == "deny"
    }
}

/// A repo whose `data/**` is protected, with one protected file, one ordinary
/// source file and one ordinary note.
fn repo(label: &str) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-shell-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::create_dir_all(root.join("outside")).expect("outside dir");
    fs::write(
        root.join("data/clients/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("protected file");
    fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("source file");
    fs::write(root.join("notes.md"), "notes\n").expect("note");

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

fn run_hook(repo: &Repo, tool_name: &str, tool_input: Value) -> Verdict {
    let payload = json!({
        "session_id": "shell-decomposition",
        "cwd": repo.root,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .env("HOME", &repo.root)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
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

    Verdict {
        action: if denial.is_some() { "deny" } else { "allow" }.to_owned(),
        reason: denial,
    }
}

fn bash(repo: &Repo, command: &str) -> Verdict {
    run_hook(repo, "Bash", json!({ "command": command }))
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

fn relative<'a>(repo: &Repo, record: &'a Value) -> &'a str {
    let path = record["path"].as_str().expect("audit path is a string");
    Path::new(path)
        .strip_prefix(&repo.root)
        .ok()
        .and_then(Path::to_str)
        .unwrap_or(path)
}

#[test]
fn every_bypass_the_bead_names_is_denied() {
    let repo = repo("bypass");
    let protected = "data/clients/holdings.csv";

    for command in [
        // the bead's own examples
        format!("sh -c \"cat {protected}\""),
        "find data -type f -exec cat {} \\;".to_owned(),
        "ls data | xargs -I{} cat data/{}".to_owned(),
        format!("echo $(cat {protected})"),
        format!("uv run python3 -c \"print(open('{protected}').read())\""),
        "sh -c \"find . -exec cat {} \\;\"".to_owned(),
        "cat da\"\"ta/clients/holdings.csv".to_owned(),
        // other separators and compound commands
        format!("true && cat {protected}"),
        format!("false || cat {protected}"),
        format!("echo hi; cat {protected}"),
        format!("echo hi | cat {protected}"),
        format!("echo hi\ncat {protected}"),
        format!("echo hi & cat {protected}"),
        format!("(cat {protected})"),
        format!("{{ cat {protected}; }}"),
        format!("if true; then cat {protected}; fi"),
        format!("for f in a; do cat {protected}; done"),
        format!("cat <<EOF\nhi\nEOF\ncat {protected}"),
        // other substitutions
        format!("echo `cat {protected}`"),
        format!("echo \"$(cat {protected})\""),
        format!("diff <(cat {protected}) notes.md"),
        format!("x=$(cat {protected})"),
        // other shells and ways to hand one a script
        format!("bash -c 'cat {protected}'"),
        format!("bash -lc 'cat {protected}'"),
        format!("zsh -c 'cat {protected}'"),
        format!("dash -c 'cat {protected}'"),
        format!("sh -c \"sh -c 'cat {protected}'\""),
        format!("eval \"cat {protected}\""),
        format!("bash <<< \"cat {protected}\""),
        format!("bash <<'EOF'\ncat {protected}\nEOF"),
        format!("bash < {protected}"),
        // wrappers
        format!("env A=1 nice -n 5 timeout 9 cat {protected}"),
        format!("env -u FOO cat {protected}"),
        format!("nohup cat {protected}"),
        format!("time cat {protected}"),
        format!("sudo -u root cat {protected}"),
        format!("sudo -s 'cat {protected}'"),
        format!("xargs -n1 cat {protected}"),
        format!("uv run --with pandas python3 -c \"open('{protected}')\""),
        format!("uvx --from x tool; uv run cat {protected}"),
        format!("pipx run --spec x cat {protected}"),
        format!("npx -y cat {protected}"),
        format!("npx -c 'cat {protected}'"),
        format!("poetry run cat {protected}"),
        // find
        "find . -name '*.csv' -exec cat {} +".to_owned(),
        "find data -execdir cat {} \\;".to_owned(),
        "find data -exec grep ssn {} +".to_owned(),
        format!("find data -exec sh -c 'cat {protected}' _ {{}} \\;"),
    ] {
        let verdict = bash(&repo, &command);

        assert!(
            verdict.denied(),
            "expected deny for `{command}`, got {} ({:?})",
            verdict.action,
            verdict.reason
        );
        // Denied by the evaluator's read policy (a protected path, a pack, or
        // a directory holding protected paths), not for some other reason.
        assert!(
            verdict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("is blocked by policy default")),
            "`{command}`: {:?}",
            verdict.reason
        );
    }
}

#[test]
fn bash_tracks_directory_changes_and_subshell_boundaries() {
    let repo = repo("cwd-tracking");

    for command in [
        "cd data && cat clients/holdings.csv",
        "pushd data; head -n 1 clients/holdings.csv",
        "env -C data cat clients/holdings.csv",
        "env --chdir=data cat clients/holdings.csv",
        "uv run --directory data cat clients/holdings.csv",
        "uv run -C data cat clients/holdings.csv",
        "git -C data show HEAD:clients/holdings.csv",
        "make -C data -f clients/holdings.csv",
        "make --directory=data --file=clients/holdings.csv",
        "echo $(cd data; cat clients/holdings.csv)",
        "cd $UNKNOWN; cat clients/holdings.csv",
    ] {
        let verdict = bash(&repo, command);
        assert!(
            verdict.denied(),
            "expected deny for `{command}`, got {} ({:?})",
            verdict.action,
            verdict.reason
        );
    }

    for command in [
        "cd outside && rg token",
        "pushd outside; rg token",
        "env -C outside rg token",
        "uv run --directory outside rg token",
        "(cd data); cat clients/holdings.csv",
        "cd data | cat clients/holdings.csv",
    ] {
        let verdict = bash(&repo, command);
        assert!(
            !verdict.denied(),
            "expected allow for `{command}`, got {:?}",
            verdict.reason
        );
    }
}

#[test]
fn clean_and_metadata_only_forms_stay_allowed() {
    let repo = repo("clean");

    for command in [
        "sh -c \"ls data\"",
        "sh -c 'echo hi'",
        "bash -lc 'cat src/main.rs'",
        "find src -type f -exec cat {} \\;",
        "find src -name '*.rs' -exec grep -n main {} +",
        "find data -type f -print",
        "find data -exec ls {} \\;",
        "find data -exec grep -l ssn {} +",
        "find data -exec grep -c ssn {} +",
        "echo $(date)",
        "echo `pwd`",
        "ls data | xargs echo",
        "git log | rg ssn",
        "git log --oneline | head -n 5",
        "echo hi; cat notes.md",
        "cat notes.md && cat src/main.rs",
        "uv run python3 -c \"print(1)\"",
        "timeout 5 ls data",
        "env A=1 ls",
        "xargs -n1 echo",
        "if true; then echo hi; fi",
        "for f in a b; do echo $f; done",
        "grep -rl ssn data",
        "cat <<'EOF'\ncat data/clients/holdings.csv\nEOF",
        "python3 <<'PY'\nprint('hi')\nPY",
    ] {
        let verdict = bash(&repo, command);

        assert!(
            !verdict.denied(),
            "expected allow for `{command}`, got {:?}",
            verdict.reason
        );
    }
}

#[test]
fn an_authorized_spine_tool_authorizes_only_its_own_command() {
    let repo = repo("spine");
    let protected = "data/clients/holdings.csv";

    for command in [
        format!("shape {protected}"),
        format!("shape {protected} | jq ."),
        format!("sh -c \"shape {protected}\""),
        format!("env LC_ALL=C timeout 9 shape {protected}"),
        "find data -exec shape {} \\;".to_owned(),
        format!("echo hi; shape {protected}"),
    ] {
        let verdict = bash(&repo, &command);
        assert!(
            !verdict.denied(),
            "spine tool should stay authorized for `{command}`: {:?}",
            verdict.reason
        );
    }

    for command in [
        format!("shape {protected}; cat {protected}"),
        format!("shape {protected} && cat {protected}"),
        format!("cat {protected}; shape {protected}"),
        format!("shape {protected} | cat {protected}"),
        format!("shape {protected}; sh -c 'cat {protected}'"),
        format!("shape {protected}; shape --explicit {protected}"),
        format!("shape {protected} $(cat {protected})"),
        // a variable that is not on the list takes the authority with it
        // (bd-szf)
        format!("env A=1 timeout 9 shape {protected}"),
        // in a uv project this runs `.venv/bin/shape`, which anything that can
        // write the project can put there (bd-jn6)
        format!("uv run shape {protected}"),
        format!("uv run shape --explicit {protected}"),
    ] {
        let verdict = bash(&repo, &command);
        assert!(
            verdict.denied(),
            "only the spine command is authorized, so `{command}` must be denied"
        );
    }
}

#[test]
fn the_audit_log_records_every_evaluated_command_with_how_it_was_reached() {
    let repo = repo("audit");

    let verdict = bash(
        &repo,
        "cat src/main.rs; echo $(cat notes.md) | wc -l; sh -c 'cat data/clients/holdings.csv'",
    );
    assert!(verdict.denied());

    let records = audit_records(&repo);
    let seen: Vec<(&str, &str, &str, &str)> = records
        .iter()
        .map(|record| {
            (
                relative(&repo, record),
                record["origin"].as_str().expect("origin is recorded"),
                record["decision"].as_str().expect("decision is recorded"),
                record["tool"].as_str().expect("tool is recorded"),
            )
        })
        .collect();

    assert_eq!(
        seen,
        [
            ("src/main.rs", "top", "allow", "Bash"),
            ("notes.md", "subshell", "allow", "Bash"),
            ("data/clients/holdings.csv", "wrapper", "deny", "Bash"),
        ]
    );
}

#[test]
fn a_read_call_is_audited_as_top() {
    let repo = repo("audit-read");
    let path = repo.root.join("data/clients/holdings.csv");

    let verdict = run_hook(&repo, "Read", json!({ "file_path": path }));
    assert!(verdict.denied());

    let records = audit_records(&repo);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["origin"], "top");
    assert_eq!(records[0]["tool"], "Read");
}

#[test]
fn the_first_deny_wins_but_every_command_is_still_evaluated_and_audited() {
    let repo = repo("first-deny");

    let verdict = bash(
        &repo,
        "cat data/clients/holdings.csv; cat src/main.rs; cat notes.md",
    );
    assert!(verdict.denied());

    let decisions: Vec<String> = audit_records(&repo)
        .iter()
        .map(|record| record["decision"].as_str().expect("decision").to_owned())
        .collect();
    assert_eq!(decisions, ["deny", "allow", "allow"]);
}

#[test]
fn unparseable_over_cap_and_variable_hidden_commands_are_denied_by_the_dynamic_stance() {
    let repo = repo("gaps");
    let protected = "data/clients/holdings.csv";

    // Unbalanced quote: veil cannot tell what runs (the shell runs the lines
    // before the quote), so it does not vouch for the command (bd-2mi).
    let unbalanced = bash(&repo, &format!("cat \"{protected}"));
    assert!(unbalanced.denied(), "an unbalanced quote is not analysed");

    // The first 64 segments are analysed; one past them is not, and a command
    // that cannot be seen to the end is not vouched for either.
    let padding = "echo x; ".repeat(64);
    let at_the_cap = bash(&repo, &format!("{padding}cat {protected}"));
    assert!(at_the_cap.denied(), "segment 65 is past the cap");
    let padding = "echo x; ".repeat(63);
    let within_the_cap = bash(&repo, &format!("{padding}cat {protected}"));
    assert!(
        within_the_cap.denied(),
        "segment 64 is within the cap and must be denied"
    );

    // A variable the string assigns is substituted before the path is judged.
    let variable = bash(&repo, &format!("f={protected}; cat $f"));
    assert!(variable.denied(), "the assigned path is judged");
}
