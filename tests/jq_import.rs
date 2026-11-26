//! `jq` names files in its module system (bd-3h5): `import "secret" as $d;`
//! opens `secret.json`, and `import "x" as m;` and `include "x";` open `x.jq`,
//! from the working directory, every `-L` directory and the import's own
//! `search`. The name is a string inside the program with no slash and no
//! extension, so no word of the command is shaped like a path and veil used to
//! judge none of them: `jq -n 'import "secret" as $d; $d'` printed a protected
//! file. These tests drive the real `veil` binary with Claude Code Bash payloads
//! against a repo on disk, and read the audit record for the file the denial names.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
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

/// A repo with `data/**` protected by its config, `secret.json` protected by the
/// credentials pack, an ordinary `notes.json` and `lib/plain.jq`, and an audit
/// log. `dynamic_args` is the `[policy] dynamic_args` value, or `None` for the
/// default.
fn repo(label: &str, dynamic_args: Option<&str>) -> Repo {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-jq-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("data/clients")).expect("data dir");
    fs::create_dir_all(root.join("lib")).expect("lib dir");
    fs::create_dir_all(root.join("state")).expect("state dir");
    fs::write(
        root.join("data/clients/holdings.json"),
        "{\"ssn\": \"078-05-1120\"}\n",
    )
    .expect("protected file");
    fs::write(root.join("secret.json"), "{\"token\": \"abc\"}\n").expect("secret file");
    fs::write(root.join("notes.json"), "[{\"a\": 1}, {\"a\": 2}]\n").expect("notes");
    fs::write(root.join("lib/plain.jq"), "def hello: \"hi\";\n").expect("plain module");

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
    let session = format!("jq-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
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
/// path is `path`: the file the program named.
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
fn an_import_reads_the_file_it_names_wherever_jq_looks() {
    let repo = repo("data", None);

    // the working directory, with and without `-L`
    for command in [
        "jq -n 'import \"secret\" as $d; $d'",
        "jq -L . -n 'import \"secret\" as $d; $d'",
        "jq -n -L . 'import \"secret\" as $d; $d'",
        "jq 'import \"secret\" as $d; $d' -n",
        "jq -n 'import \"secret\" as $d;\n$d'",
        "jq -n '# a comment\nimport \"secret\" as $d; $d'",
        "jq -n 'module {name: \"m\"}; import \"secret\" as $d; $d'",
        "jq -n 'import \"plain\" as p; import \"secret\" as $d; $d'",
        "jq -n 'import \"sec\\u0072et\" as $d; $d'",
        "jq -n 'import \"secret\" as $d::d; $d'",
        "jq -r -n 'import \"secret\" as $d; $d'",
        "jq --arg x 1 -n 'import \"secret\" as $d; $d'",
        "jq -n --args 'import \"secret\" as $d; $d' a b",
        "jq -n 'import \"secret\" as $d; $d' notes.json",
        "/usr/bin/jq -n 'import \"secret\" as $d; $d'",
        "jq -n 'import \"secret\" as $d {search: \"./\"}; $d'",
        "jq -n 'import \"secret\" as $d {search: [\"./nope\", \"./\"]}; $d'",
    ] {
        assert_denied_for(&repo, command, "secret.json", "argv_path");
    }

    // a protected directory given with each spelling of `-L`
    for command in [
        "jq -L data -n 'import \"clients/holdings\" as $d; $d'",
        "jq -Ldata -n 'import \"clients/holdings\" as $d; $d'",
        "jq -nL data 'import \"clients/holdings\" as $d; $d'",
        "jq -nLdata 'import \"clients/holdings\" as $d; $d'",
        "jq --library-path data -n 'import \"clients/holdings\" as $d; $d'",
        "jq -n 'import \"clients/holdings\" as $d; $d' -L data",
        "jq -L lib -L data -n 'import \"clients/holdings\" as $d; $d'",
        "jq -L data/clients -n 'import \"holdings\" as $d; $d'",
        "jq -n 'import \"data/clients/holdings\" as $d; $d'",
        "jq -n 'import \"holdings\" as $d {search: \"data/clients\"}; $d'",
        "jq -n 'import \"holdings\" as $d {search: [\"./data/clients\"]}; $d'",
        // a bare word is no path to judge: only the program says where jq looks
        "jq -n 'import \"clients/holdings\" as $d {search: \"data\"}; $d'",
        "jq -n 'import \"clients/holdings\" as $d {search: [\"nope\", \"data\"]}; $d'",
    ] {
        assert_denied_for(&repo, command, "data/clients/holdings.json", "argv_path");
    }
}

#[test]
fn include_and_a_module_import_read_a_jq_file_never_a_json_one() {
    let repo = repo("module", None);

    // `secret.json` is protected and `secret.jq` is not: jq says "module not
    // found" for these, so nothing protected is opened
    assert_allowed(
        &repo,
        &[
            "jq -n 'include \"secret\"; 1'",
            "jq -L . -n 'include \"secret\"; 1'",
            "jq -n 'import \"secret\" as s; 1'",
            "jq -L lib -n 'include \"plain\"; hello'",
            "jq -L lib -n 'import \"plain\" as p; p::hello'",
            // with a `search`, jq looks only there: not in `-L`, so the protected
            // data/clients/holdings.json is never opened
            "jq -L data -n 'import \"clients/holdings\" as $d {search: \"./lib\"}; $d'",
            "jq -L data -n 'import \"clients/holdings\" as $d {search: [\"./lib\", \"./nope\"]}; $d'",
        ],
    );

    // a protected module is named by the directory it is in
    write(
        &repo,
        "data/clients/holdings.jq",
        "# MARKER-4471\ndef x: 1;\n",
    );
    for command in [
        "jq -L data -n 'include \"clients/holdings\"; x'",
        "jq -L data -n 'import \"clients/holdings\" as h; 1'",
    ] {
        assert_denied_for(&repo, command, "data/clients/holdings.jq", "argv_path");
        let verdict = judge(&repo, command);
        assert!(
            !verdict.reason.contains("MARKER-4471"),
            "a protected module's text is never quoted: {}",
            verdict.reason
        );
    }

    // a link to the protected module is the protected module: denied, not quoted
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            repo.root.join("data/clients/holdings.jq"),
            repo.root.join("lib/linked.jq"),
        )
        .expect("symlink");
        let verdict = judge(&repo, "jq -L lib -n 'include \"linked\"; x'");
        assert!(verdict.denied, "records: {:?}", verdict.records);
        assert!(
            !verdict.reason.contains("MARKER-4471"),
            "a protected module's text is never quoted: {}",
            verdict.reason
        );
    }
}

#[test]
fn a_module_that_imports_a_file_is_read_for_what_it_imports() {
    let repo = repo("chain", None);

    write(
        &repo,
        "lib/evil.jq",
        "import \"secret\" as $d;\ndef leak: $d;\n",
    );
    write(&repo, "lib/outer.jq", "include \"evil\";\ndef go: leak;\n");
    write(
        &repo,
        "lib/search.jq",
        "import \"holdings\" as $h {search: \"../data/clients\"};\ndef leak: $h;\n",
    );
    write(
        &repo,
        "lib/fine.jq",
        "import \"plain\" as p;\ndef ok: p::hello;\n",
    );

    // one module deep, two deep, and a search relative to the module
    for (command, path) in [
        ("jq -L lib -n 'include \"evil\"; leak'", "secret.json"),
        ("jq -L lib -n 'include \"outer\"; go'", "secret.json"),
        (
            "jq -L lib -n 'include \"search\"; leak'",
            "data/clients/holdings.json",
        ),
    ] {
        assert_denied_for(&repo, command, path, "argv_path");
    }
    // the same module, found from the working directory instead of `-L`
    assert_denied_for(
        &repo,
        "jq -n 'include \"lib/evil\"; leak'",
        "secret.json",
        "argv_path",
    );

    // a module whose imports are ordinary names nothing protected
    assert_allowed(&repo, &["jq -L lib -n 'include \"fine\"; ok'"]);

    // a chain longer than veil follows is not guessed at: where protected data
    // is in reach it is denied, as a script too large to inspect is
    write(&repo, "lib/m1.jq", "include \"m2\";\n");
    write(&repo, "lib/m2.jq", "include \"m3\";\n");
    write(&repo, "lib/m3.jq", "include \"m4\";\n");
    write(&repo, "lib/m4.jq", "import \"secret\" as $d;\n");
    let verdict = judge(&repo, "jq -L lib -n 'include \"m1\"; 1'");
    assert!(verdict.denied, "records: {:?}", verdict.records);
    assert!(
        verdict
            .records
            .iter()
            .any(|record| record["reason_class"] == "script_too_large_to_inspect"),
        "records: {:?}",
        verdict.records
    );
}

#[test]
fn a_program_file_is_read_for_its_imports() {
    let repo = repo("program-file", None);

    write(&repo, "prog.jq", "import \"secret\" as $d; $d\n");
    write(
        &repo,
        "sub/prog.jq",
        "import \"secret\" as $d {search: \"..\"}; $d\n",
    );
    write(&repo, "plain.jq", "def f: 1; f\n");
    write(&repo, "uses-module.jq", "include \"evil\"; leak\n");
    write(
        &repo,
        "lib/evil.jq",
        "import \"secret\" as $d;\ndef leak: $d;\n",
    );

    for command in [
        "jq -n -f prog.jq",
        "jq -nf prog.jq",
        "jq -fn prog.jq",
        "jq --from-file prog.jq -n",
        "jq -f prog.jq notes.json",
        "jq -n -f sub/prog.jq",
        "jq -L lib -n -f uses-module.jq",
    ] {
        assert_denied_for(&repo, command, "secret.json", "argv_path");
    }

    assert_allowed(
        &repo,
        &[
            "jq -n -f plain.jq",
            "jq -f plain.jq notes.json",
            "jq --from-file plain.jq notes.json",
            // `-f` is a flag, and the first operand is the program file wherever
            // it stands (measured on jq 1.8.2: `jq in.json -f first.jq` runs
            // in.json as the program). Here notes.json is the program and
            // prog.jq an input file, which jq never runs.
            "jq notes.json -f prog.jq",
        ],
    );
}

#[test]
fn a_prelude_veil_cannot_read_is_refused_like_a_word_it_cannot_resolve() {
    let repo = repo("refused", None);

    for command in [
        // jq itself rejects both: "Import path must be constant" and a string that never ends
        "jq -n 'import \"sec\\(\"r\")et\" as $d; $d'",
        "jq -n 'import \"secret as $d; $d'",
        "jq -n 'import \"secret\" as; 1'",
        "jq -n 'include secret; 1'",
    ] {
        let verdict = judge(&repo, command);
        assert!(verdict.denied, "{command}\nrecords: {:?}", verdict.records);
        assert!(
            verdict
                .records
                .iter()
                .any(|record| record["reason_class"] == "dynamic_path_unresolvable"),
            "{command}\nrecords: {:?}",
            verdict.records
        );
    }

    // a program file that cannot be read is refused the same way, and the
    // reason names the file, not its text
    write(&repo, "broken.jq", "import \"MARKER-9902\n");
    let verdict = judge(&repo, "jq -n -f broken.jq");
    assert!(verdict.denied, "records: {:?}", verdict.records);
    assert!(verdict.reason.contains("broken.jq"), "{}", verdict.reason);
    assert!(
        !verdict.reason.contains("MARKER-9902"),
        "a refused file's text is not quoted: {}",
        verdict.reason
    );

    // under `warn` and `allow` the stance is the person's
    for mode in ["warn", "allow"] {
        let relaxed = self::repo(mode, Some(mode));
        let verdict = judge(&relaxed, "jq -n 'import \"sec\\(\"r\")et\" as $d; $d'");
        assert!(!verdict.denied, "{mode}: {}", verdict.reason);
    }
}

#[test]
fn ordinary_jq_commands_are_allowed() {
    let repo = repo("ordinary", None);

    write(&repo, "plain.jq", "def f: 1; f\n");
    write(&repo, "lib/also.jq", "def g: 2;\n");

    assert_allowed(
        &repo,
        &[
            "jq . notes.json",
            "jq -r '.[].a' notes.json",
            "jq -s 'map(.a) | add' notes.json",
            "jq '.[] | select(.a > 1)' notes.json",
            "jq -n 'def f: 1; f'",
            "jq -n '[1,2] | map(. * 2)'",
            "jq -n --arg import 1 '$import'",
            "jq -n --arg x import '$x'",
            "jq -n '\"import \\\"secret\\\" as $d;\"'",
            "jq -n '.import'",
            "jq -n '{important: 1}'",
            "jq -n 'def f: 1; include_me'",
            "jq -n 'import \"plain\" as p; 1'",
            "jq -n --indent 3 '.'",
            "jq -n --tab '.'",
            "jq -n -e 'true'",
            "jq -n --seq '1'",
            "jq -n --stream '1'",
            "jq --args -n '$ARGS' a b",
            "jq -n --jsonargs '$ARGS' 1 2",
            "cat notes.json | jq .",
            "jq . < notes.json",
            "jq -L lib -n 'include \"also\"; g'",
            "jq -n -f plain.jq",
        ],
    );
}
