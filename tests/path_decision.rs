//! The `veil.path-decision.v1` documents that `veil test`, `explain` and `scan`
//! print with `--json`: what a local wrapper (cmdrvl-cli) can parse instead of
//! reading human stderr. These tests run the real binary against real files and
//! pin the exact shape, so a field rename or a changed type fails here before a
//! wrapper finds out.
//!
//! The documents are decisions about PATHS. veil does not read file contents or
//! message bodies to produce them, and the manifest descriptions say so; the
//! last test ties that claim to `operator.json`.
//!
//! Not covered: a wrapper in another repo. No cmdrvl-cli code consumes these
//! documents yet, so "stable enough for wrapper integration tests" is shown only
//! by this repo's own pinning.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

const VERSION: &str = "veil.path-decision.v1";
const OPERATOR_JSON: &str = include_str!("../operator.json");

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Repo {
    root: PathBuf,
    home: PathBuf,
}

/// A repo with `data/**` protected, one allowlisted file, one ordinary source
/// file and one protected data file. Audit logging is off, so the tree holds
/// exactly the four files created here.
fn repo(label: &str) -> Repo {
    let base = env::temp_dir().join(format!(
        "veil-pathdecision-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let root = base.join("repo");
    let home = base.join("home");
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::create_dir_all(&home).expect("home dir");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"data/**\"]\n\n[policy]\ndefault = \"deny\"\naudit_log = false\n",
    )
    .expect("config");
    fs::write(root.join("notes.md"), "notes\n").expect("allowlisted file");
    fs::write(root.join("src/app.rs"), "fn main() {}\n").expect("source file");
    fs::write(
        root.join("data/holdings.csv"),
        "name,ssn\nada,078-05-1120\n",
    )
    .expect("protected file");

    Repo {
        root: fs::canonicalize(&root).expect("repo root should canonicalize"),
        home: fs::canonicalize(&home).expect("home should canonicalize"),
    }
}

fn veil(repo: &Repo, harness: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .args(args)
        .current_dir(&repo.root)
        .env("HOME", &repo.home)
        .env("XDG_STATE_HOME", repo.home.join("state"))
        .env("XDG_CONFIG_HOME", repo.home.join("config"))
        .env("VEIL_HARNESS", harness);
    for var in [
        "VEIL_PROTECTED",
        "VEIL_SAFE_PATTERNS",
        "VEIL_SPINE_TOOLS",
        "VEIL_POLICY",
        "VEIL_AUDIT_LOG",
        "VEIL_AUDIT_PATH",
    ] {
        command.env_remove(var);
    }
    command.output().expect("veil should run")
}

/// Runs `veil <args>` under a harness that needs no hook install, requires exit
/// 0 and returns the parsed stdout together with its raw text.
fn json_ok(repo: &Repo, args: &[&str]) -> (Value, String) {
    let output = veil(repo, "plain", args);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert_eq!(
        output.status.code(),
        Some(0),
        "veil {args:?}: stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "",
        "a decision leaves stderr empty"
    );
    (
        serde_json::from_str(&stdout).expect("stdout should be one JSON document"),
        stdout,
    )
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .expect("expected a JSON object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn set(names: &[&'static str]) -> BTreeSet<&'static str> {
    names.iter().copied().collect()
}

const DECISION_KEYS: &[&str] = &["action", "confidence", "reason", "remediation", "severity"];
const MATCH_KEYS: &[&str] = &[
    "allowlist_pattern",
    "confidence",
    "directory_sensitive",
    "kind",
    "pack",
    "protected_pattern",
    "severity",
];

#[test]
fn test_prints_the_exact_document_for_an_ordinary_file() {
    let repo = repo("test-allow");

    let (document, _) = json_ok(&repo, &["test", "src/app.rs", "--json"]);

    assert_eq!(
        document,
        json!({
            "schema_version": VERSION,
            "input_path": "src/app.rs",
            "normalized_path": repo.root.join("src/app.rs").display().to_string(),
            "decision": {
                "action": "allow",
                "reason": null,
                "severity": null,
                "confidence": null,
                "remediation": null,
            },
        })
    );
}

#[test]
fn test_denial_carries_every_field_a_wrapper_needs_for_a_receipt() {
    let repo = repo("test-deny");

    let (document, raw) = json_ok(&repo, &["test", "data/holdings.csv", "--json"]);

    assert_eq!(
        keys(&document),
        set(&[
            "decision",
            "input_path",
            "normalized_path",
            "schema_version"
        ])
    );
    assert_eq!(document["schema_version"], VERSION);
    assert_eq!(document["input_path"], "data/holdings.csv");
    assert_eq!(
        document["normalized_path"],
        repo.root.join("data/holdings.csv").display().to_string()
    );

    let decision = &document["decision"];
    assert_eq!(keys(decision), set(DECISION_KEYS));
    assert_eq!(decision["action"], "deny");
    assert_eq!(decision["severity"], "high");
    assert_eq!(
        decision["reason"],
        "direct read of a path matched by data.tabular is blocked by policy default"
    );
    assert!(
        decision["remediation"]
            .as_str()
            .is_some_and(|text| text.contains("veil operator")),
        "remediation should point at the operator: {decision}"
    );
    // The confidence is a decimal a wrapper can compare, not an f32 widened to
    // 0.949999988079071.
    assert_eq!(decision["confidence"].as_f64(), Some(0.95));
    assert!(
        raw.contains("\"confidence\": 0.95,") && !raw.contains("0.9499"),
        "confidence should print as 0.95: {raw}"
    );
}

#[test]
fn test_of_a_directory_holding_protected_paths_is_a_denial_with_a_reason() {
    let repo = repo("test-dir");

    let (document, _) = json_ok(&repo, &["test", "data", "--json"]);

    assert_eq!(document["decision"]["action"], "deny");
    assert!(
        document["decision"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("protected paths")),
        "{document}"
    );
}

#[test]
fn explain_adds_the_match_that_decided_it() {
    let repo = repo("explain");

    let (protected, _) = json_ok(&repo, &["explain", "data/holdings.csv", "--json"]);
    assert_eq!(
        keys(&protected),
        set(&[
            "decision",
            "input_path",
            "match",
            "normalized_path",
            "schema_version"
        ])
    );
    assert_eq!(protected["schema_version"], VERSION);
    assert_eq!(keys(&protected["match"]), set(MATCH_KEYS));
    assert_eq!(
        protected["match"],
        json!({
            "kind": "pack",
            "pack": "data.tabular",
            "protected_pattern": format!("{}/data/**", repo.root.display()),
            "allowlist_pattern": null,
            "severity": "high",
            "confidence": 0.95,
            "directory_sensitive": true,
        })
    );
    assert_eq!(protected["decision"]["action"], "deny");

    let (allowlisted, _) = json_ok(&repo, &["explain", "notes.md", "--json"]);
    assert_eq!(
        allowlisted["match"],
        json!({
            "kind": "allowlist",
            "pack": null,
            "protected_pattern": null,
            "allowlist_pattern": "*.md",
            "severity": null,
            "confidence": null,
            "directory_sensitive": null,
        })
    );
    assert_eq!(allowlisted["decision"]["action"], "allow");
}

#[test]
fn scan_lists_every_path_with_the_same_entry_shape() {
    let repo = repo("scan");

    let (document, _) = json_ok(&repo, &["scan", ".", "--json"]);

    assert_eq!(keys(&document), set(&["files", "root", "schema_version"]));
    assert_eq!(document["schema_version"], VERSION);
    assert_eq!(document["root"], repo.root.display().to_string());

    let files = document["files"].as_array().expect("files is an array");
    let names: BTreeSet<&str> = files
        .iter()
        .map(|entry| {
            entry["input_path"]
                .as_str()
                .expect("input_path is a string")
        })
        .collect();
    assert_eq!(
        names,
        set(&[".veil.toml", "data/holdings.csv", "notes.md", "src/app.rs"])
    );
    for entry in files {
        assert_eq!(
            keys(entry),
            set(&["decision", "input_path", "match", "normalized_path"]),
            "scan entries carry no schema_version of their own: {entry}"
        );
        assert_eq!(keys(&entry["decision"]), set(DECISION_KEYS));
        assert_eq!(keys(&entry["match"]), set(MATCH_KEYS));
    }
    let denied: Vec<&str> = files
        .iter()
        .filter(|entry| entry["decision"]["action"] == "deny")
        .map(|entry| entry["input_path"].as_str().expect("input_path"))
        .collect();
    assert_eq!(denied, ["data/holdings.csv"]);
}

#[test]
fn an_unnormalizable_path_is_a_json_error_on_stdout_with_exit_2() {
    let repo = repo("error-path");
    let bad = "a\tb";

    for command in ["test", "explain"] {
        let output = veil(&repo, "plain", &[command, bad, "--json"]);
        let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
        let message = "could not normalize `a\tb` with the hook-mode path hardening pipeline";

        assert_eq!(output.status.code(), Some(2), "{command}");
        assert_eq!(
            serde_json::from_str::<Value>(&stdout).expect("stdout should be JSON"),
            json!({
                "schema_version": VERSION,
                "error": { "code": "path_unnormalizable", "message": message },
            }),
            "{command}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "stderr keeps the message for humans: {command}"
        );
    }
}

#[test]
fn without_json_a_failure_is_still_only_on_stderr() {
    let repo = repo("error-human");

    let output = veil(&repo, "plain", &["test", "a\tb"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not normalize"));
}

#[test]
fn a_guard_preflight_refusal_is_a_json_error_with_its_own_code() {
    let repo = repo("preflight");

    for command in [["test", "notes.md"], ["explain", "notes.md"], ["scan", "."]] {
        let args = [command[0], command[1], "--json"];
        // Under Claude Code with no veil hooks installed in HOME, domain
        // commands refuse to run.
        let output = veil(&repo, "claude-code", &args);
        let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
        let document: Value = serde_json::from_str(&stdout).expect("stdout should be JSON");

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(
            keys(&document),
            set(&["error", "schema_version"]),
            "{args:?}"
        );
        assert_eq!(document["schema_version"], VERSION);
        assert_eq!(document["error"]["code"], "guard_preflight_refused");
        assert!(
            document["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("veil doctor")),
            "{document}"
        );
    }
}

#[test]
fn the_manifest_says_these_commands_decide_on_paths_only() {
    let manifest: Value = serde_json::from_str(OPERATOR_JSON).expect("operator.json should parse");
    let commands = manifest["commands"].as_array().expect("commands array");

    for name in ["test", "explain", "scan"] {
        let command = commands.iter().find(|command| command["name"] == name);
        assert!(command.is_some(), "operator.json should declare `{name}`");
        let description = command
            .and_then(|command| command["description"].as_str())
            .expect("description");

        assert!(
            description.contains("file contents and message bodies are not read"),
            "`{name}` must state that it does not read file contents or message bodies: {description}"
        );
    }
    assert!(
        manifest["exit_codes"]["2"]["meaning"]
            .as_str()
            .is_some_and(|meaning| meaning.contains("path command")),
        "exit 2 should cover a path command that produced no decision"
    );
}
