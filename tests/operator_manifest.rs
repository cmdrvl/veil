//! veil's own operator manifest: `operator.json`, `--describe`, `capabilities --json`, `--schema`.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use spine_rules::contract::{OperatorContract, assert_version_parity, cargo_package_version};

const OPERATOR_JSON: &str = include_str!("../operator.json");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!(
        "veil-manifest-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&dir).expect("scratch dir should be creatable");
    dir
}

fn veil(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command.current_dir(home);
    command.env("HOME", home);
    command.env("XDG_STATE_HOME", home.join("state"));
    command.env("XDG_CONFIG_HOME", home.join("config"));
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
    command
}

fn stdout_of(args: &[&str]) -> String {
    let home = scratch("introspect");
    let output = veil(&home).args(args).output().expect("veil should run");
    assert!(
        output.status.success(),
        "veil {args:?} should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout should be UTF-8")
}

#[test]
fn describe_is_byte_identical_to_operator_json() {
    assert_eq!(stdout_of(&["--describe"]), OPERATOR_JSON);
}

#[test]
fn capabilities_json_is_the_same_document_as_describe() {
    assert_eq!(stdout_of(&["capabilities", "--json"]), OPERATOR_JSON);
}

#[test]
fn operator_json_version_equals_cargo_package_version() {
    assert_eq!(
        cargo_package_version(CARGO_TOML).as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    let manifest: Value = serde_json::from_str(OPERATOR_JSON).expect("operator.json is JSON");
    assert_eq!(manifest["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_version_parity(OPERATOR_JSON, CARGO_TOML);
}

#[test]
fn operator_json_is_valid_operator_v1() {
    let contract = OperatorContract::parse(OPERATOR_JSON).expect("operator.json parses");
    assert_eq!(contract.validate(), Vec::<String>::new());
    assert_eq!(contract.name, "veil");
}

/// Public docs must not leak internal tracker ids such as `bd-37f`.
fn internal_bead_ids(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|word| {
            word.strip_prefix("bd-").is_some_and(|rest| {
                rest.len() >= 2 && rest.chars().all(|c| c.is_ascii_alphanumeric())
            })
        })
        .collect()
}

#[test]
fn readme_has_no_internal_bead_ids() {
    let leaks = internal_bead_ids(include_str!("../README.md"));
    assert!(
        leaks.is_empty(),
        "README leaks internal bead ids: {leaks:?}"
    );
}

#[test]
fn bead_id_scanner_catches_planted_leaks_and_ignores_prose() {
    assert_eq!(
        internal_bead_ids("tracked in bead `bd-37f`, also (bd-2ll)."),
        vec!["bd-37f", "bd-2ll"]
    );
    assert!(internal_bead_ids("a bd- prefix, abd-12 and bd-x? stay clean").is_empty());
}

#[test]
fn every_clap_subcommand_is_declared_in_the_manifest() {
    let manifest: Value = serde_json::from_str(OPERATOR_JSON).expect("operator.json is JSON");
    let declared: Vec<&str> = manifest["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .filter_map(|command| command["name"].as_str())
        .collect();

    let help = stdout_of(&["--help"]);
    let in_help: Vec<&str> = help
        .lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .collect();

    assert!(
        !in_help.is_empty(),
        "could not parse subcommands from --help:\n{help}"
    );
    for name in &in_help {
        assert!(
            declared.contains(name),
            "`veil {name}` exists in --help but is missing from operator.json"
        );
    }
    for name in &declared {
        assert!(
            in_help.contains(name),
            "operator.json declares `{name}` but `veil --help` does not list it"
        );
    }
}

/// Planted negatives: the validator the manifest is held to must reject drift.
#[test]
fn planted_bad_manifests_are_rejected() {
    let base: Value = serde_json::from_str(OPERATOR_JSON).expect("operator.json is JSON");
    let violations = |mutate: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        mutate(&mut doc);
        OperatorContract::parse(&doc.to_string())
            .expect("mutated manifest still parses")
            .validate()
    };

    assert!(
        violations(&|doc| {
            doc["commands"]
                .as_array_mut()
                .expect("commands")
                .retain(|command| command["name"] != "doctor");
        })
        .iter()
        .any(|violation| violation.contains("doctor")),
        "a manifest without `doctor` must be rejected"
    );
    assert!(
        !violations(&|doc| {
            doc["exit_codes"]["7"] = json!({"meaning": "bogus", "domain": "error"});
        })
        .is_empty(),
        "an undeclared exit code must be rejected"
    );
    assert!(
        !violations(&|doc| {
            doc["refusals"] = json!([{"code": "NOT_PREFIXED"}]);
        })
        .is_empty(),
        "a refusal code without the E_ prefix must be rejected"
    );
    assert!(
        !violations(&|doc| {
            doc["schema_version"] = json!("operator.v0");
        })
        .is_empty(),
        "a non-v1 schema_version must be rejected"
    );

    let result = std::panic::catch_unwind(|| {
        let stale = OPERATOR_JSON.replace(env!("CARGO_PKG_VERSION"), "0.0.1");
        assert_version_parity(&stale, CARGO_TOML);
    });
    assert!(
        result.is_err(),
        "a stale manifest version must fail the parity check"
    );
}

// ---- --schema -------------------------------------------------------------

fn run_hook(home: &Path, payload: &Value) -> Value {
    serde_json::from_slice(&hook_stdout(home, payload)).expect("hook stdout should be JSON")
}

fn hook_stdout(home: &Path, payload: &Value) -> Vec<u8> {
    let mut child = veil(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veil hook mode should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload should be written");
    let output = child.wait_with_output().expect("hook mode should finish");
    assert_eq!(output.status.code(), Some(0), "hook decisions exit 0");
    output.stdout
}

/// Does `value` satisfy the object shape (required keys present, only known keys) of `definition`?
fn matches_definition(value: &Value, definition: &Value) -> bool {
    let (Some(object), Some(properties)) =
        (value.as_object(), definition["properties"].as_object())
    else {
        return false;
    };
    let required = definition["required"]
        .as_array()
        .map(|keys| keys.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !required.iter().all(|key| object.contains_key(*key)) {
        return false;
    }
    object.iter().all(|(key, inner)| match properties.get(key) {
        None => false,
        Some(spec) if spec.get("properties").is_some() => matches_definition(inner, spec),
        Some(spec) => match (spec.get("enum"), spec.get("const")) {
            (Some(options), _) => options.as_array().is_some_and(|o| o.contains(inner)),
            (_, Some(constant)) => constant == inner,
            _ => true,
        },
    })
}

fn decision_matches_schema(decision: &Value, schema: &Value) -> bool {
    let defs = &schema["definitions"];
    schema["oneOf"]
        .as_array()
        .expect("schema oneOf")
        .iter()
        .filter_map(|entry| entry["$ref"].as_str())
        .filter_map(|reference| reference.strip_prefix("#/definitions/"))
        .any(|name| matches_definition(decision, &defs[name]))
}

#[test]
fn schema_is_the_checked_in_json_schema() {
    let schema: Value = serde_json::from_str(&stdout_of(&["--schema"])).expect("--schema is JSON");
    assert_eq!(
        schema,
        serde_json::from_str::<Value>(include_str!("../hook-decision.schema.json"))
            .expect("schema file is JSON")
    );
    assert!(schema.get("$schema").is_some());
    assert!(schema.get("definitions").is_some());
}

#[test]
fn real_hook_decisions_match_the_schema_and_a_bad_one_does_not() {
    let schema: Value = serde_json::from_str(&stdout_of(&["--schema"])).expect("--schema is JSON");
    let home = scratch("hook");
    fs::write(
        home.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected/**\"]\n[policy]\naudit_log = false\n",
    )
    .expect("config should be written");
    fs::create_dir_all(home.join("protected")).expect("protected dir");
    fs::write(home.join("protected/secret.txt"), "classified").expect("fixture");
    let cwd = home.display().to_string();

    let payloads = [
        // Gemini CLI allow / deny
        json!({"session_id":"s","cwd":cwd,"hook_event_name":"BeforeTool","tool_name":"run_shell_command",
               "tool_input":{"command":"ls"}}),
        json!({"session_id":"s","cwd":cwd,"hook_event_name":"BeforeTool","tool_name":"run_shell_command",
               "tool_input":{"command":"cat protected/secret.txt"}}),
        // Claude Code allow / deny
        json!({"session_id":"s","cwd":cwd,"hook_event_name":"PreToolUse","tool_name":"Read",
               "tool_input":{"file_path": format!("{cwd}/README.md")}}),
        json!({"session_id":"s","cwd":cwd,"hook_event_name":"PreToolUse","tool_name":"Read",
               "tool_input":{"file_path": format!("{cwd}/protected/secret.txt")}}),
    ];
    let mut saw_deny = 0;
    for payload in &payloads {
        let decision = run_hook(&home, payload);
        assert!(
            decision_matches_schema(&decision, &schema),
            "hook output {decision} does not match `veil --schema`"
        );
        if decision.to_string().contains("\"deny\"") {
            saw_deny += 1;
        }
    }
    assert_eq!(saw_deny, 2, "both protected-path payloads must be denied");

    // a write veil has no say about gets no output at all, which Claude Code
    // documents as no decision: its own permission rules apply
    let write = hook_stdout(
        &home,
        &json!({"session_id":"s","cwd":cwd,"hook_event_name":"PreToolUse","tool_name":"Write",
                "tool_input":{"file_path": format!("{cwd}/notes.txt"), "content": "x"}}),
    );
    assert_eq!(String::from_utf8_lossy(&write), "");

    // Planted negatives: shapes the schema must not accept.
    for bad in [
        json!({"decision": "maybe"}),
        json!({"decision": "allow", "extra": true}),
        json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        json!({}),
    ] {
        assert!(
            !decision_matches_schema(&bad, &schema),
            "schema checker wrongly accepted {bad}"
        );
    }
}
