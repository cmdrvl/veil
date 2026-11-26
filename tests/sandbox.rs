use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::process::Output;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture() -> PathBuf {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "veil-sandbox-cli-{}-{time}-{count}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("home")).expect("fixture home");
    fs::create_dir_all(root.join("config")).expect("fixture config");
    fs::create_dir_all(root.join("state")).expect("fixture state");
    fs::canonicalize(root).expect("canonical fixture root")
}

fn veil(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
    command
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("VEIL_PROTECTED", "protected-alias.txt")
        .env_remove("VEIL_SAFE_PATTERNS")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_AUDIT_LOG")
        .env_remove("VEIL_AUDIT_PATH")
        .env_remove("VEIL_DYNAMIC_ARGS");
    command
}

#[cfg(target_os = "macos")]
fn create_executable(path: &Path, source: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("executable directory");
    }
    fs::write(path, source).expect("executable should be written");
    let mut permissions = fs::metadata(path)
        .expect("executable should exist")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("executable permissions should be set");
}

#[cfg(target_os = "macos")]
fn sandbox_exec(profile: &str, root: &Path, program: &str, args: &[&str]) -> Output {
    Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .arg(program)
        .args(args)
        .current_dir(root)
        .output()
        .expect("sandbox-exec should launch the test command")
}

#[test]
fn dry_run_reports_compilation_without_claiming_enforcement() {
    let root = fixture();
    fs::write(root.join("protected-alias.txt"), "private\n").expect("protected file");

    let output = veil(&root)
        .arg("sandbox")
        .arg("--dry-run")
        .output()
        .expect("veil should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("dry-run output is UTF-8");
    assert!(stdout.contains("Seatbelt policy compiled"), "{stdout}");
    assert!(stdout.contains("Path deny rules:"), "{stdout}");
    assert!(
        stdout.contains("Enforcement applied: no (dry run only)"),
        "{stdout}"
    );
    assert!(stdout.contains("new hard links"), "{stdout}");
    assert!(
        stdout.contains("does not restrict network access"),
        "{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn generated_profile_denies_target_and_symlink_and_blocks_new_hardlinks() {
    use std::os::unix::fs::symlink;

    let root = fixture();
    let protected = root.join("protected.txt");
    let alias = root.join("protected-alias.txt");
    let unprotected = root.join("unprotected.txt");
    let existing_hardlink = root.join("preexisting-hardlink.txt");
    let new_hardlink = root.join("new-hardlink.txt");
    fs::write(&protected, "private payload\n").expect("protected file");
    fs::write(&unprotected, "public payload\n").expect("unprotected file");
    symlink(&protected, &alias).expect("symlink alias");
    fs::hard_link(&protected, &existing_hardlink).expect("pre-existing hardlink alias");

    let output = veil(&root)
        .arg("sandbox")
        .arg("--print-profile")
        .output()
        .expect("veil should compile the merged policy");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let profile = String::from_utf8(output.stdout).expect("Seatbelt profile is UTF-8");
    assert!(
        profile.starts_with("(version 1)\n(allow default)\n"),
        "{profile}"
    );
    assert!(profile.contains("(deny file-link)"), "{profile}");
    let resolved = fs::canonicalize(&protected).expect("resolved protected target");
    for path in [&alias, &resolved] {
        assert!(
            profile.contains(&format!("(literal \"{}\")", path.display())),
            "profile does not deny configured symlink and resolved target {}:\n{profile}",
            path.display()
        );
    }

    for path in [&protected, &alias] {
        let output = sandbox_exec(
            &profile,
            &root,
            "/bin/cat",
            &[path.to_str().expect("fixture path is UTF-8")],
        );
        assert!(
            !output.status.success(),
            "protected read unexpectedly succeeded"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
            "expected EPERM, got: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = sandbox_exec(
        &profile,
        &root,
        "/bin/cat",
        &[unprotected.to_str().expect("fixture path is UTF-8")],
    );
    assert!(
        output.status.success(),
        "unprotected read should remain available: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "public payload\n");

    let output = sandbox_exec(
        &profile,
        &root,
        "/bin/ln",
        &[
            protected.to_str().expect("fixture path is UTF-8"),
            new_hardlink.to_str().expect("fixture path is UTF-8"),
        ],
    );
    assert!(
        !output.status.success(),
        "new hardlink unexpectedly succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
        "expected file-link denial, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!new_hardlink.exists(), "denied hardlink was created");

    // ADR B-1 measured that a path-literal deny does not identify pre-existing
    // hardlink aliases. Keep that limit explicit in the executable test.
    let output = sandbox_exec(
        &profile,
        &root,
        "/bin/cat",
        &[existing_hardlink.to_str().expect("fixture path is UTF-8")],
    );
    assert!(
        output.status.success(),
        "pre-existing hardlink behavior changed; review the ADR and this limit assertion: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "private payload\n");
}

/// The text no confined process may print.
#[cfg(target_os = "macos")]
const MOVED_CANARY: &str = "MERIDIAN-VAULT-CONFIDENTIAL";

/// A project at `<fixture>/work/proj` and the profile veil compiles for
/// `protected`, which is TOML array contents.
#[cfg(target_os = "macos")]
fn compiled_project(protected: &str, files: &[(&str, &str)]) -> (PathBuf, String) {
    let root = fixture();
    let project = root.join("work/proj");
    fs::create_dir_all(&project).expect("project directory");
    for (path, text) in files {
        let path = project.join(path);
        fs::create_dir_all(path.parent().expect("a parent")).expect("fixture directory");
        fs::write(path, text).expect("fixture file");
    }
    fs::write(
        project.join(".veil.toml"),
        format!("[sensitivity]\nprotected = [{protected}]\n"),
    )
    .expect("project policy");
    let output = veil(&root)
        .current_dir(&project)
        .env_remove("VEIL_PROTECTED")
        .args(["sandbox", "--print-profile"])
        .output()
        .expect("veil should compile the profile");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        project,
        String::from_utf8(output.stdout).expect("profile is UTF-8"),
    )
}

/// A path-based read deny says nothing about a file once it has another name.
/// Renaming it, renaming a directory above it, swapping it with a public file,
/// and cloning a directory above it (macOS looks only at the top directory of a
/// clone) each printed a protected file before the profile refused them.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_process_cannot_give_protected_content_a_name_the_profile_allows() {
    const CLONE: &str = "/usr/bin/python3 -I -c 'import ctypes,sys; sys.exit(ctypes.CDLL(None).clonefile(sys.argv[1].encode(), sys.argv[2].encode(), 0) and 1)'";
    const SWAP: &str = "/usr/bin/python3 -I -c 'import ctypes,sys; sys.exit(ctypes.CDLL(None).renameatx_np(-2, sys.argv[1].encode(), -2, sys.argv[2].encode(), 2) and 1)'";

    let subtree = r#""data/**""#;
    let nested_file = r#""a/b/secret.txt""#;
    let glob = r#""reports/*.secret""#;
    let cases: Vec<(&str, &str, &str, String)> = vec![
        (
            "rename the file",
            subtree,
            "data/x.csv",
            "mv data/x.csv out; cat out".to_owned(),
        ),
        (
            "rename the protected directory",
            subtree,
            "data/x.csv",
            "mv data moved; cat moved/x.csv".to_owned(),
        ),
        (
            "rename the project",
            subtree,
            "data/x.csv",
            "cd .. && mv proj gone; cat gone/data/x.csv".to_owned(),
        ),
        (
            "rename the project's parent",
            subtree,
            "data/x.csv",
            "cd ../.. && mv work gone; cat gone/proj/data/x.csv".to_owned(),
        ),
        (
            "swap with a public file",
            subtree,
            "data/x.csv",
            format!("echo public > pub; {SWAP} data/x.csv pub; cat pub"),
        ),
        (
            "clone the project",
            subtree,
            "data/x.csv",
            format!("{CLONE} ../proj ../copy; cat ../copy/data/x.csv"),
        ),
        (
            "clone the project's parent",
            subtree,
            "data/x.csv",
            format!("{CLONE} ../../work ../../copy; cat ../../copy/proj/data/x.csv"),
        ),
        (
            "clone the project from an open descriptor",
            subtree,
            "data/x.csv",
            "/usr/bin/python3 -I -c 'import ctypes,os; ctypes.CDLL(None).fclonefileat(os.open(\".\", os.O_RDONLY), -2, b\"../copy\", 0)'; cat ../copy/data/x.csv".to_owned(),
        ),
        (
            "rename a directory above a protected file",
            nested_file,
            "a/b/secret.txt",
            "mv a z; cat z/b/secret.txt".to_owned(),
        ),
        (
            "clone a directory above a protected file",
            nested_file,
            "a/b/secret.txt",
            format!("{CLONE} a z; cat z/b/secret.txt"),
        ),
        (
            "rename the directory of a glob match",
            glob,
            "reports/q3.secret",
            "mv reports moved; cat moved/q3.secret".to_owned(),
        ),
    ];

    for (name, protected, file, command) in cases {
        let (project, profile) =
            compiled_project(protected, &[(file, &format!("{MOVED_CANARY}\n"))]);
        let output = sandbox_exec(&profile, &project, "/bin/sh", &["-c", &command]);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!shown.contains(MOVED_CANARY), "{name}: {shown}\n{profile}");
        assert_eq!(
            fs::read_to_string(project.join(file)).ok().as_deref(),
            Some(format!("{MOVED_CANARY}\n").as_str()),
            "{name}: the protected file should be where it was"
        );
    }

    // controls: the same operations on what is not protected still work
    let (project, profile) = compiled_project(
        subtree,
        &[("data/x.csv", "private\n"), ("src/lib.txt", "public\n")],
    );
    let command = format!(
        "set -e; mv src renamed; cat renamed/lib.txt; mkdir d; echo made > d/f; mv d e; cat e/f; \
         {CLONE} renamed cloned; cat cloned/lib.txt; /bin/cp -c e/f g; cat g; \
         echo one > p; echo two > q; {SWAP} p q; cat p; rm -r e; echo done"
    );
    let output = sandbox_exec(&profile, &project, "/bin/sh", &["-c", &command]);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "public\nmade\npublic\nmade\ntwo\ndone\n",
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Seatbelt compares resolved paths. A protected directory that does not exist
/// yet has none, so the part of it that does exist has to be resolved.
#[cfg(target_os = "macos")]
#[test]
fn a_protected_path_created_later_under_a_symlinked_directory_is_still_denied() {
    let root = fixture();
    let project = root.join("proj");
    fs::create_dir_all(project.join("real")).expect("real directory");
    std::os::unix::fs::symlink("real", project.join("linked")).expect("directory symlink");
    // and a link whose target does not exist yet
    std::os::unix::fs::symlink("real/absent", project.join("dangling")).expect("dangling link");
    fs::write(
        project.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"linked/later/**\", \"linked/one.key\", \"dangling/**\"]\n",
    )
    .expect("project policy");
    let output = veil(&root)
        .current_dir(&project)
        .env_remove("VEIL_PROTECTED")
        .args(["sandbox", "--print-profile"])
        .output()
        .expect("veil should compile the profile");
    assert!(output.status.success());
    let profile = String::from_utf8(output.stdout).expect("profile is UTF-8");

    // both appear after the profile was compiled
    fs::create_dir(project.join("real/later")).expect("later directory");
    fs::write(project.join("real/later/x.csv"), MOVED_CANARY).expect("later file");
    fs::write(project.join("real/one.key"), MOVED_CANARY).expect("later literal");
    fs::create_dir(project.join("real/absent")).expect("link target");
    fs::write(project.join("real/absent/y.csv"), MOVED_CANARY).expect("file behind the link");

    for path in [
        "linked/later/x.csv",
        "real/later/x.csv",
        "linked/one.key",
        "real/one.key",
        "dangling/y.csv",
        "real/absent/y.csv",
    ] {
        let output = sandbox_exec(&profile, &project, "/bin/cat", &[path]);
        assert!(!output.status.success(), "{path} was readable\n{profile}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(MOVED_CANARY),
            "{path}\n{profile}"
        );
    }
}

#[test]
fn a_denial_inside_a_sandbox_points_at_the_broker() {
    use std::io::Write as _;
    use std::process::Stdio;

    let root = fixture();
    let reason = |socket: Option<&str>| {
        let payload = serde_json::json!({
            "session_id": "broker-hint",
            "cwd": root,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "cat .env" },
        });
        let mut command = veil(&root);
        command
            .env("VEIL_HARNESS", "plain")
            .env_remove("VEIL_BROKER_SOCKET")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(socket) = socket {
            command.env("VEIL_BROKER_SOCKET", socket);
        }
        let mut child = command.spawn().expect("hook should start");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(payload.to_string().as_bytes())
            .expect("payload should be written");
        let output = child.wait_with_output().expect("hook should exit");
        let decision: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("a JSON decision");
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
        // remediation is what the hook says on standard error
        String::from_utf8(output.stderr).expect("stderr is UTF-8")
    };

    assert!(reason(Some("/tmp/broker.sock")).contains("run: veil exec shape <path>"));
    assert!(!reason(None).contains("veil exec"));
}

/// A `HOME` for a broker test. The session socket lives under it, and a macOS
/// Unix socket path must be under 104 bytes, which no directory under
/// `temp_dir()` leaves room for.
#[cfg(target_os = "macos")]
fn short_home() -> PathBuf {
    let home = PathBuf::from(format!(
        "/tmp/vb-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .subsec_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&home).expect("short fixture home");
    fs::canonicalize(home).expect("canonical fixture home")
}

/// The broker runs tools with the operator's own permissions, so nothing the
/// confined process does may change what the broker runs, or use a tool to put
/// protected bytes where the confined process can read them.
#[cfg(target_os = "macos")]
#[test]
fn sandboxed_client_cannot_turn_the_broker_into_cat() {
    let root = fixture();
    let home = short_home();
    let protected = root.join("protected.txt");
    fs::write(&protected, "MERIDIAN-VAULT-CONFIDENTIAL\nsecond row\n").expect("protected");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
    )
    .expect("project policy");
    fs::create_dir(root.join("sub")).expect("subdirectory");

    // The tool is reached through a symlink on PATH, as installed tools often are.
    let real_bin = root.join("real-bin");
    let real_shape = real_bin.join("shape-1.0");
    create_executable(
        &real_shape,
        "#!/bin/sh\nif [ \"$1\" = \"--copy\" ]; then /bin/cp \"$2\" \"$3\"; echo copied; exit 0; fi\nrows=$(/usr/bin/wc -l < \"$1\" | /usr/bin/tr -d ' ')\nprintf '{\"rows\":%s}\\n' \"$rows\"\n",
    );
    let bin = root.join("bin");
    fs::create_dir(&bin).expect("bin directory");
    std::os::unix::fs::symlink(&real_shape, bin.join("shape")).expect("tool symlink");
    let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("fixture PATH should be joinable");

    let script = r#"
veil=$1 root=$2 bin=$2/bin real=$2/real-bin
cd "$root/sub"
echo "SUBDIR=$("$veil" exec shape ../protected.txt)"
cd /usr
if "$veil" exec shape "$root/protected.txt" >/dev/null 2>&1; then echo OUTSIDE_CWD_ALLOWED; fi
cd "$root"
"$veil" exec shape --copy "$root/protected.txt" "$root/stolen.txt" >/dev/null 2>&1
if /bin/cat "$root/stolen.txt" 2>/dev/null; then echo COPY_ALLOWED; fi
evil='#!/bin/sh
/bin/cat "$1"'
(echo "$evil" > "$real/shape-1.0") 2>/dev/null && echo OVERWRITE_ALLOWED
/bin/rm -f "$bin/shape" 2>/dev/null && echo UNLINK_ALLOWED
/bin/mv "$real" "$root/moved-real" 2>/dev/null && echo RENAME_REAL_ALLOWED
/bin/mv "$bin" "$root/moved-bin" 2>/dev/null && echo RENAME_BIN_ALLOWED
(echo forged >> "$HOME/.cmdrvl/state/veil/derived.jsonl") 2>/dev/null && echo FORGE_ALLOWED
echo "AFTER=$("$veil" exec shape "$root/protected.txt")"
echo ordinary > "$root/ordinary-write.txt" && echo ORDINARY_WRITE_ALLOWED
"#;
    let output = veil(&root)
        .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
        .arg(env!("CARGO_BIN_EXE_veil"))
        .arg(&root)
        .env("HOME", &home)
        .env("PATH", path)
        .env("VEIL_PROTECTED", "protected.txt")
        .output()
        .expect("veil should launch the sandboxed client");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let context = format!(
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "{context}");
    // a relative path means what it means where the client stands
    assert!(stdout.contains("SUBDIR={\"rows\":2}"), "{context}");
    assert!(stdout.contains("AFTER={\"rows\":2}"), "{context}");
    // control: the confinement does not stop ordinary work in the project
    assert!(stdout.contains("ORDINARY_WRITE_ALLOWED"), "{context}");
    for escape in [
        "OUTSIDE_CWD_ALLOWED",
        "COPY_ALLOWED",
        "OVERWRITE_ALLOWED",
        "UNLINK_ALLOWED",
        "RENAME_REAL_ALLOWED",
        "RENAME_BIN_ALLOWED",
        "FORGE_ALLOWED",
        "MERIDIAN-VAULT-CONFIDENTIAL",
    ] {
        assert!(!stdout.contains(escape), "{escape}\n{context}");
    }
}

/// The broker must not outlive its launcher, even one that is killed outright
/// and so runs no cleanup.
#[cfg(target_os = "macos")]
#[test]
fn broker_exits_when_its_launcher_is_killed() {
    let root = fixture();
    let home = short_home();
    fs::write(root.join("protected.txt"), "private\n").expect("protected");

    let mut launcher = veil(&root)
        .args(["sandbox", "--", "/bin/sleep", "20"])
        .env("HOME", &home)
        .env("VEIL_PROTECTED", "protected.txt")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("veil should launch");
    let broker_dir = home.join(".cmdrvl/state/veil/broker");
    let sockets = || fs::read_dir(&broker_dir).map_or(0, |entries| entries.count());
    let wait_for = |wanted: usize| {
        (0..500).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            sockets() == wanted
        })
    };

    assert!(wait_for(1), "the session socket should appear");
    launcher.kill().expect("launcher should be killed");
    launcher.wait().expect("launcher should be reaped");
    assert!(wait_for(0), "the broker should remove its socket and exit");
}

#[cfg(target_os = "macos")]
#[test]
fn sandboxed_client_gets_only_scanned_derived_output_from_session_broker() {
    let root = fixture();
    let home = short_home();
    let protected = root.join("protected.txt");
    fs::write(
        &protected,
        "MERIDIAN-VAULT-CONFIDENTIAL\nsecond private row\n",
    )
    .expect("protected fixture");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
    )
    .expect("project policy");

    let fake_bin = root.join("bin");
    let shape = fake_bin.join("shape");
    create_executable(
        &shape,
        "#!/bin/sh\nif [ \"$1\" = \"--leak\" ]; then printf 'AKIAIOSFODNN7EXAMPLE\\n'; exit 0; fi\nif [ \"$1\" = \"--large\" ]; then /usr/bin/head -c 16777217 /dev/zero; exit 0; fi\nrows=$(/usr/bin/wc -l < \"$1\" | /usr/bin/tr -d ' ')\nprintf '{\"rows\":%s}\\n' \"$rows\"\n",
    );
    let path = std::env::join_paths(std::iter::once(fake_bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("fixture PATH should be joinable");

    let veil_binary = env!("CARGO_BIN_EXE_veil");
    let protected_arg = protected.to_str().expect("protected path is UTF-8");
    let script = format!(
        "mode=$(/usr/bin/stat -f '%Lp' \"$VEIL_BROKER_SOCKET\")\nif [ \"$mode\" = 600 ]; then echo SOCKET_0600; else exit 46; fi\nif /bin/cat '{protected_arg}' 2>/dev/null; then echo DIRECT_READ_ALLOWED; exit 41; else echo DIRECT_READ_DENIED; fi\n'{veil_binary}' exec shape '{protected_arg}'\nif '{veil_binary}' exec shape --leak '{protected_arg}' >/dev/null 2>&1; then echo SCANNER_ALLOWED; exit 42; else echo SCANNER_DENIED; fi\nif '{veil_binary}' exec shape --explicit '{protected_arg}' >/dev/null 2>&1; then echo FLAG_ALLOWED; exit 43; else echo FLAG_DENIED; fi\nif '{veil_binary}' exec cat '{protected_arg}' >/dev/null 2>&1; then echo TOOL_ALLOWED; exit 44; else echo TOOL_DENIED; fi\nif '{veil_binary}' exec shape --large '{protected_arg}' >/dev/null 2>&1; then echo OVERSIZE_ALLOWED; exit 45; else echo OUTPUT_CAP_ENFORCED; fi\ni=0\nwhile [ \"$i\" -lt 60 ]; do if '{veil_binary}' exec shape '{protected_arg}' >/dev/null 2>&1; then i=$((i + 1)); else echo CALL_CAP:$i; break; fi; done\n"
    );
    let output = veil(&root)
        .arg("sandbox")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .env("HOME", &home)
        .env("PATH", path)
        .env("VEIL_PROTECTED", "protected.txt")
        .output()
        .expect("veil should launch the sandboxed client");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("test output is UTF-8");
    assert!(stdout.contains("DIRECT_READ_DENIED"), "{stdout}");
    assert!(stdout.contains("SOCKET_0600"), "{stdout}");
    assert!(stdout.contains("{\"rows\":2}"), "{stdout}");
    assert!(stdout.contains("SCANNER_DENIED"), "{stdout}");
    assert!(stdout.contains("FLAG_DENIED"), "{stdout}");
    assert!(stdout.contains("TOOL_DENIED"), "{stdout}");
    assert!(stdout.contains("OUTPUT_CAP_ENFORCED"), "{stdout}");
    assert!(stdout.contains("CALL_CAP:59"), "{stdout}");
    assert!(!stdout.contains("MERIDIAN-VAULT-CONFIDENTIAL"), "{stdout}");
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"), "{stdout}");

    let audit_path = home.join(".cmdrvl/logs/veil/audit.jsonl");
    let audit = fs::read_to_string(audit_path).expect("broker calls should be audited");
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit JSON"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 65, "each broker call must have one record");
    assert!(records.iter().all(|record| {
        record["enforcement"] == "sandbox"
            && record["origin"] == "broker"
            && record["tool_input"]["input_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("blake3:"))
            && record["tool_input"]["output_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("blake3:"))
    }));
    assert!(records.iter().any(|record| {
        record["reason"].as_str().is_some_and(|reason| {
            reason.contains("SECRET_AWS_ACCESS_KEY") && reason.contains("blake3:")
        })
    }));
    let derived_path = home.join(".cmdrvl/state/veil/derived.jsonl");
    let derived = fs::read_to_string(derived_path).expect("derived outputs should be registered");
    assert!(derived.lines().count() >= 60, "{derived}");
    assert!(!derived.contains("MERIDIAN-VAULT-CONFIDENTIAL"));

    let socket_parent = home.join(".cmdrvl/state/veil/broker");
    assert!(
        socket_parent.exists(),
        "private broker state directory should remain"
    );
    assert_eq!(
        fs::metadata(&socket_parent)
            .expect("broker directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::read_dir(socket_parent)
            .expect("broker directory should be readable")
            .count(),
        0,
        "the session socket should be removed when its launcher exits"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_applies_compiled_read_rules() -> Result<(), Box<dyn std::error::Error>> {
    const CHILD_ROOT: &str = "VEIL_LANDLOCK_TEST_CHILD_ROOT";

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        landlock_child(&PathBuf::from(root))?;
        return Ok(());
    }

    let root = fixture();
    let project_root = root.join("workspace");
    let protected = project_root.join("protected");
    let allowed = root.join("allowed");
    fs::create_dir_all(&protected).expect("protected directory");
    fs::create_dir_all(&allowed).expect("allowed directory");
    fs::write(
        project_root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected/**\"]\n",
    )
    .expect("project policy");
    fs::write(allowed.join("public.txt"), "public payload\n").expect("allowed file");
    fs::write(protected.join("secret.txt"), "private payload\n").expect("protected file");

    let output = Command::new(std::env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "landlock_applies_compiled_read_rules",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ROOT, &root)
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env_remove("VEIL_PROTECTED")
        .env_remove("VEIL_SAFE_PATTERNS")
        .env_remove("VEIL_SPINE_TOOLS")
        .env_remove("VEIL_POLICY")
        .env_remove("VEIL_AUDIT_LOG")
        .env_remove("VEIL_AUDIT_PATH")
        .env_remove("VEIL_DYNAMIC_ARGS")
        .output()
        .expect("isolated Landlock test process should launch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "isolated Landlock process failed: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("LANDLOCK_ENFORCED") || stdout.contains("LANDLOCK_SKIP:"),
        "child reported neither enforcement nor a kernel capability skip: {stdout}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn landlock_child(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use landlock::{
        ABI, AccessFs, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };
    use std::error::Error;

    fn unsupported_by_kernel(error: &(dyn Error + 'static)) -> bool {
        let mut source = Some(error);
        while let Some(error) = source {
            if let Some(io_error) = error.downcast_ref::<std::io::Error>()
                && matches!(io_error.raw_os_error(), Some(38 | 95))
            {
                // ENOSYS or EOPNOTSUPP: the kernel does not provide Landlock.
                return true;
            }
            source = error.source();
        }
        false
    }

    fn apply_rules(root: &Path) -> Result<landlock::RestrictionStatus, Box<dyn Error>> {
        let project_root = root.join("workspace");
        let config = veil::config::load_config(&project_root).expect("load fixture config");
        let compiled = veil::sandbox::landlock::compile(&config, &project_root, root)
            .expect("compile Landlock read plan");
        let allowed_path = fs::canonicalize(root.join("allowed")).expect("canonical allowed path");
        let excluded_path = fs::canonicalize(&project_root).expect("canonical project path");
        assert!(
            compiled
                .allowed
                .iter()
                .any(|item| item.path == allowed_path),
            "compiled rules omit the public fixture: {compiled:?}"
        );
        assert!(
            compiled.excluded.iter().any(|path| path == &excluded_path),
            "compiled rules do not exclude the protected project: {compiled:?}"
        );

        let access_read = AccessFs::from_read(ABI::V1);
        let mut ruleset = Ruleset::default().handle_access(access_read)?.create()?;
        for hierarchy in compiled.allowed {
            assert!(
                hierarchy.read_file,
                "compiler omitted read_file: {hierarchy:?}"
            );
            assert!(
                hierarchy.read_dir,
                "compiler omitted read_dir: {hierarchy:?}"
            );
            let path = PathFd::new(&hierarchy.path)?;
            ruleset = ruleset.add_rule(PathBeneath::new(path, access_read))?;
        }
        Ok(ruleset.restrict_self()?)
    }

    let status = match apply_rules(root) {
        Ok(status) => status,
        Err(error) if unsupported_by_kernel(error.as_ref()) => {
            println!("LANDLOCK_SKIP: kernel reports Landlock unsupported: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    match status.landlock {
        LandlockStatus::NotEnabled => {
            println!("LANDLOCK_SKIP: kernel has Landlock support disabled");
        }
        LandlockStatus::NotImplemented => {
            println!("LANDLOCK_SKIP: kernel does not implement Landlock");
        }
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => {
            println!(
                "LANDLOCK_ENFORCED: effective_abi={effective_abi:?} kernel_abi={kernel_abi:?} no_new_privs={} ruleset={:?}",
                status.no_new_privs, status.ruleset
            );
            assert!(
                status.no_new_privs,
                "Landlock restriction did not set no_new_privs"
            );
            assert_eq!(status.ruleset, RulesetStatus::FullyEnforced);

            let root = fs::canonicalize(root).expect("canonical test root");
            let public = fs::read(root.join("allowed/public.txt")).expect("allowed file read");
            assert_eq!(public, b"public payload\n");
            let secret = fs::read(root.join("workspace/protected/secret.txt"));
            assert_eq!(
                secret
                    .expect_err("protected read unexpectedly succeeded")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }
    Ok(())
}
