//! Hook-mode enforcement of `[spine.denied_flags]` against the real binary:
//! an authorized spine tool run with a raw-value flag (`shape --explicit x.csv`)
//! is a reader, not a metadata producer, and must be denied on protected paths.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod common;
#[path = "common/user.rs"]
mod user;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Hook {
    denial: Option<String>,
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Hook {
    fn denied(&self) -> bool {
        self.denial.is_some()
    }

    fn allowed(&self) -> bool {
        self.denial.is_none()
    }
}

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "veil-spine-flags-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ))
}

/// A repo with `protected/**` protected, auditing off in an isolated HOME's
/// settings, and the given extra config appended to `.veil.toml`.
fn repo(extra_config: &str) -> (PathBuf, PathBuf) {
    let repo_root = unique_dir("repo");
    let home = unique_dir("home");
    fs::create_dir_all(repo_root.join("protected")).expect("protected dir");
    fs::create_dir_all(&home).expect("home dir");
    fs::write(repo_root.join("protected").join("x.csv"), "secret,1\n").expect("fixture");
    fs::write(
        repo_root.join(".veil.toml"),
        format!("[sensitivity]\nprotected = [\"protected/**\"]\n\n{extra_config}"),
    )
    .expect("config");
    user::write_config(&home, "[policy]\naudit_log = false\n");
    (repo_root, home)
}

fn run_hook(repo_root: &Path, home: &Path, command: &str) -> Hook {
    run_hook_on(repo_root, home, command, None)
}

/// [`run_hook`] with the `PATH` the hook looks tool names up on.
fn run_hook_on(repo_root: &Path, home: &Path, command: &str, search_path: Option<&Path>) -> Hook {
    let payload = serde_json::json!({
        "session_id": "spine-flags",
        "cwd": repo_root,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut veil = Command::new(env!("CARGO_BIN_EXE_veil"));
    if let Some(search_path) = search_path {
        veil.env("PATH", search_path);
    }
    let mut child = veil
        .env("HOME", home)
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

    Hook {
        // fails the test unless veil exited 0 and printed nothing or one deny
        denial: common::claude_denial(&output),
        stdout: String::from_utf8(output.stdout).expect("stdout should be UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr should be UTF-8"),
        code: output.status.code(),
    }
}

#[test]
fn spine_tools_on_protected_files_are_still_allowed_without_raw_flags() {
    let (repo_root, home) = repo("");
    let installed = home.join("bin");
    let shape = installed.join("shape");
    fs::create_dir_all(&installed).expect("tool directory");
    fs::write(&shape, "#!/bin/sh\n").expect("installed tool");
    fs::set_permissions(&shape, fs::Permissions::from_mode(0o755)).expect("mode");

    for command in [
        "shape protected/x.csv".to_owned(),
        "profile protected/x.csv --json".to_owned(),
        format!("{} protected/x.csv | jq .", shape.display()),
    ] {
        let hook = run_hook_on(&repo_root, &home, &command, Some(&installed));
        assert!(
            hook.allowed(),
            "`{command}` should be allowed: {}",
            hook.stdout
        );
        assert_eq!(hook.code, Some(0), "`{command}`");
    }
}

#[test]
fn default_raw_value_flags_are_denied_in_flag_and_flag_equals_forms() {
    let (repo_root, home) = repo("");

    for tool in ["shape", "profile", "rvl", "canon", "verify"] {
        for flag in ["--explicit", "--raw", "--dump", "--show-values"] {
            for command in [
                format!("{tool} {flag} protected/x.csv"),
                format!("{tool} {flag}=all protected/x.csv"),
                format!("{tool} protected/x.csv {flag}"),
            ] {
                let hook = run_hook(&repo_root, &home, &command);

                assert!(hook.denied(), "`{command}` must be denied: {}", hook.stdout);
                assert_eq!(hook.code, Some(0), "`{command}`");
                assert!(
                    hook.stdout.contains(flag),
                    "`{command}`: the denial reason must name {flag}: {}",
                    hook.stdout
                );
                assert!(
                    hook.stdout
                        .contains("escalates its output from metadata to protected content"),
                    "`{command}`: {}",
                    hook.stdout
                );
                assert!(
                    hook.stderr.contains("Raw-value flag blocked"),
                    "`{command}`: {}",
                    hook.stderr
                );
            }
        }
    }
}

#[test]
fn raw_value_flag_denial_follows_the_warn_policy_like_a_direct_read() {
    let (repo_root, home) = repo("");
    let audit_path = repo_root.join("audit.jsonl");
    user::write_config(
        &home,
        &format!(
            "[policy]\ndefault = \"warn\"\naudit_log = true\naudit_path = \"{}\"\n",
            audit_path.to_string_lossy().replace('\\', "\\\\")
        ),
    );

    let hook = run_hook(&repo_root, &home, "shape --explicit protected/x.csv");

    // Warn mode allows, exactly like a direct read in warn mode; veil's
    // renderer is silent on allow, so the warning lives in the audit record.
    assert!(hook.allowed(), "warn mode allows: {}", hook.stdout);
    let audit = fs::read_to_string(&audit_path).expect("warn mode must still audit the access");
    let record: serde_json::Value =
        serde_json::from_str(audit.lines().next().expect("one audit record"))
            .expect("audit record should parse");
    assert_eq!(record["decision"], "allow");
    let reason = record["reason"].as_str().unwrap_or_default();
    assert!(reason.starts_with("policy default warn: "), "{reason}");
    assert!(reason.contains("--explicit"), "{reason}");
}

#[test]
fn per_tool_denied_flags_extend_the_default_for_that_tool_only() {
    let (repo_root, home) = repo("[spine.denied_flags]\nshape = [\"--columns\"]\n");

    let denied = run_hook(&repo_root, &home, "shape --columns protected/x.csv");
    assert!(denied.denied(), "{}", denied.stdout);
    assert!(denied.stdout.contains("--columns"), "{}", denied.stdout);

    let other_tool = run_hook(&repo_root, &home, "profile --columns protected/x.csv");
    assert!(other_tool.allowed(), "{}", other_tool.stdout);

    let default_still_denied = run_hook(&repo_root, &home, "shape --explicit protected/x.csv");
    assert!(
        default_still_denied.denied(),
        "{}",
        default_still_denied.stdout
    );
}

#[test]
fn default_list_is_configurable() {
    let (repo_root, home) = repo("");
    user::write_config(
        &home,
        "[policy]\naudit_log = false\n[spine.denied_flags]\ndefault = [\"--only-this\"]\n",
    );

    let replaced = run_hook(&repo_root, &home, "shape --explicit protected/x.csv");
    assert!(
        replaced.allowed(),
        "the operator replaced the default list, so --explicit is no longer denied: {}",
        replaced.stdout
    );

    let configured = run_hook(&repo_root, &home, "shape --only-this=1 protected/x.csv");
    assert!(configured.denied(), "{}", configured.stdout);
}

#[test]
fn direct_read_denial_remediation_points_to_operator_and_never_to_ad_hoc_scripts() {
    let (repo_root, home) = repo("");

    let hook = run_hook(&repo_root, &home, "cat protected/x.csv");

    assert!(hook.denied(), "{}", hook.stdout);
    assert!(
        hook.stderr.contains("Run `veil operator`"),
        "{}",
        hook.stderr
    );
    assert!(
        hook.stderr.contains("discover the authorized spine tools"),
        "{}",
        hook.stderr
    );
    let lowered = hook.stderr.to_lowercase();
    for banned in ["script", "write a ", "extract only"] {
        assert!(
            !lowered.contains(banned),
            "remediation must not suggest `{banned}`: {}",
            hook.stderr
        );
    }
}
