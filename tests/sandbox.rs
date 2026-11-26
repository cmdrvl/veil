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

#[cfg(unix)]
fn create_executable(path: &Path, source: &str) {
    use std::os::unix::fs::PermissionsExt;

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

/// The client receives both of a tool's streams and can put them back
/// together, so splitting a value between them must not get it past the scanner
/// (bd-ds7). `veil exec` outside a sandbox runs the same check the broker does,
/// on every platform.
#[cfg(unix)]
#[test]
fn a_value_split_between_stdout_and_stderr_is_withheld() {
    // the two halves of a detector-positive example key, never whole in either
    const HEAD: &str = "AKIAIOSFODNN7EX";
    const TAIL: &str = "AMPLE";

    for (case, tool, withheld) in [
        (
            "stdout holds the head",
            format!("printf %s {HEAD}; printf %s {TAIL} >&2"),
            true,
        ),
        (
            "stderr holds the head",
            format!("printf %s {HEAD} >&2; printf %s {TAIL}"),
            true,
        ),
        (
            "each half is printed as a line",
            format!("echo {HEAD}; echo {TAIL} >&2"),
            true,
        ),
        (
            "control: ordinary output and a warning",
            "echo '{\"rows\":1}'; echo 'warning: one row skipped' >&2".to_owned(),
            false,
        ),
    ] {
        let root = fixture();
        fs::write(root.join("protected.txt"), "private\n").expect("protected");
        fs::write(
            root.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
        )
        .expect("project policy");
        create_executable(&root.join("bin/shape"), &format!("#!/bin/sh\n{tool}\n"));

        let output = veil(&root)
            .args(["exec", "shape", "protected.txt"])
            .env("PATH", root.join("bin"))
            .env("VEIL_PROTECTED", "protected.txt")
            .env_remove("VEIL_BROKER_SOCKET")
            .output()
            .expect("veil should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let context = format!("{case}\nstdout: {stdout}\nstderr: {stderr}");

        if withheld {
            assert_eq!(output.status.code(), Some(126), "{context}");
            assert!(stderr.contains("broker_output_denied"), "{context}");
            assert!(stdout.is_empty(), "{context}");
            assert!(
                !stderr.contains(HEAD) && !stderr.contains(TAIL),
                "{context}"
            );
        } else {
            assert_eq!(output.status.code(), Some(0), "{context}");
            assert_eq!(stdout, "{\"rows\":1}\n", "{context}");
            assert_eq!(stderr, "warning: one row skipped\n", "{context}");
        }
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

/// veil's settings sit under `~/.cmdrvl/config`, which is protected by default,
/// and the hook inside the sandbox must read them: failing to, it exits 2, and a
/// harness then blocks every tool call. Nothing else there becomes readable,
/// whatever the settings file has been made to point at.
#[cfg(target_os = "macos")]
#[test]
fn the_hook_inside_the_sandbox_reads_veils_own_settings_and_nothing_else() {
    use std::os::unix::fs::symlink;

    const SETTINGS: &str = "# VERMILION-SETTINGS-CANARY\n[policy]\naudit_log = false\n";
    const SECRET: &str = "OBSIDIAN-SETTINGS-CANARY";
    let script = r#"
veil=$1 payload=$2 other=$3
printf '%s' "$payload" | "$veil"
echo "HOOK_EXIT=$?"
/bin/cat "$other" protected.txt vault/config.toml 2>/dev/null
exit 0
"#;

    // `readable`: whether the hook gets its settings
    for (case, readable) in [
        ("a file", true),
        ("a link beside it", true),
        ("a link to a protected file", false),
        ("a directory that links to a protected one", false),
    ] {
        let root = fixture();
        let home = short_home();
        let settings_dir = home.join(".cmdrvl/config/veil");
        let other = home.join(".cmdrvl/config/other-tool/token.toml");
        fs::create_dir_all(other.parent().expect("parent")).expect("other tool directory");
        fs::write(&other, format!("# {SECRET}\n")).expect("another tool's config");
        // valid TOML, so that veil can load these when the settings lead to them
        fs::write(root.join("protected.txt"), format!("# {SECRET}\n")).expect("protected");
        fs::create_dir(root.join("vault")).expect("protected directory");
        fs::write(root.join("vault/config.toml"), format!("# {SECRET}\n")).expect("protected");
        fs::write(
            root.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected.txt\", \"vault/**\"]\n",
        )
        .expect("project policy");
        let settings = settings_dir.join("config.toml");
        if case.starts_with("a directory") {
            symlink(root.join("vault"), &settings_dir).expect("settings directory link");
        } else {
            fs::create_dir_all(&settings_dir).expect("settings directory");
            match case {
                "a file" => fs::write(&settings, SETTINGS).expect("settings"),
                "a link beside it" => {
                    fs::write(settings_dir.join("mine.toml"), SETTINGS).expect("settings");
                    symlink("mine.toml", &settings).expect("settings link");
                }
                _ => symlink(root.join("protected.txt"), &settings).expect("settings link"),
            }
        }
        let payload = serde_json::json!({
            "session_id": "settings",
            "cwd": root,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls" },
        })
        .to_string();

        let output = veil(&root)
            .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
            .args([env!("CARGO_BIN_EXE_veil"), &payload])
            .arg(&other)
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("VEIL_PROTECTED")
            .output()
            .expect("veil should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!(
            "{case}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(output.status.success(), "{context}");
        assert!(!stdout.contains(SECRET), "{context}");
        if readable {
            assert!(stdout.contains("HOOK_EXIT=0"), "{context}");
            assert!(
                stdout.contains("\"permissionDecision\":\"allow\""),
                "{context}"
            );
        } else {
            // the hook fails closed rather than the file becoming readable
            assert!(stdout.contains("HOOK_EXIT=2"), "{context}");
        }
    }
}

/// The broker appends to the audit log from outside the sandbox, and the
/// confined process can write where that log is. A link there must not turn the
/// broker's append into a write the command could not make itself.
#[cfg(target_os = "macos")]
#[test]
fn the_broker_does_not_write_through_a_linked_audit_log() {
    const ORIGINAL: &str = "#!/bin/sh\necho '{\"rows\":1}'\n";
    // point the log, or its rotation lock, at a tool; then have the broker write
    // a record that carries shell text; then run the tool
    let script = r#"
veil=$1 root=$2 planted=$3
log="$HOME/.cmdrvl/logs/veil/audit.jsonl"
/bin/mkdir -p "$HOME/.cmdrvl/logs/veil"
if [ "$planted" != before ]; then /bin/ln -sf "$root/bin/shape" "$log" && echo LINKED; fi
echo "FIRST: $("$veil" exec '$(/bin/cat protected.txt >&2)' 2>&1)"
echo "SECOND: $("$veil" exec shape protected.txt 2>&1)"
"#;

    for planted in ["during", "before"] {
        let root = fixture();
        let home = short_home();
        fs::write(root.join("protected.txt"), "MERIDIAN-VAULT-CONFIDENTIAL\n").expect("protected");
        fs::write(
            root.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
        )
        .expect("project policy");
        create_executable(&root.join("bin/shape"), ORIGINAL);
        if planted == "before" {
            // as an earlier session could have left it
            fs::create_dir_all(home.join(".cmdrvl/logs/veil")).expect("log directory");
            std::os::unix::fs::symlink(
                root.join("bin/shape"),
                home.join(".cmdrvl/logs/veil/audit.jsonl"),
            )
            .expect("planted link");
        }
        let path = std::env::join_paths([
            root.join("bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .expect("fixture PATH");

        let output = veil(&root)
            .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
            .arg(env!("CARGO_BIN_EXE_veil"))
            .arg(&root)
            .arg(planted)
            .env("HOME", &home)
            .env("PATH", path)
            .env("VEIL_PROTECTED", "protected.txt")
            .output()
            .expect("veil should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!(
            "planted {planted}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(output.status.success(), "{context}");
        assert!(!stdout.contains("MERIDIAN-VAULT-CONFIDENTIAL"), "{context}");
        assert_eq!(
            fs::read_to_string(root.join("bin/shape")).expect("tool"),
            ORIGINAL,
            "{context}"
        );
        // a call that cannot be recorded is refused
        for call in ["FIRST", "SECOND"] {
            assert!(
                stdout.contains(&format!("{call}: veil exec refused: broker_audit_failed")),
                "{context}"
            );
        }
    }
}

/// The veil that launched the session is the running broker, and it launches the
/// next session, so the confined process must not be able to change it.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_process_cannot_change_the_veil_that_launched_it() {
    let script = r#"
real=$1 link=$2
(printf x >> "$real") 2>/dev/null && echo APPENDED
(printf x >> "$link") 2>/dev/null && echo APPENDED_THROUGH_LINK
/bin/mv "$real" "$real.moved" 2>/dev/null && echo MOVED
/bin/rm -f "$link" 2>/dev/null && echo LINK_REMOVED
/bin/ln -sf /usr/bin/true "$link" 2>/dev/null && echo LINK_REPLACED
/bin/mv "$(/usr/bin/dirname "$real")" "$(/usr/bin/dirname "$real").moved" 2>/dev/null && echo DIRECTORY_MOVED
echo ordinary > ordinary.txt && echo ORDINARY_WRITE_ALLOWED
"#;

    for second_name in [false, true] {
        let root = fixture();
        let home = short_home();
        fs::write(root.join("protected.txt"), "private\n").expect("protected");
        // a copy, so that a failing run cannot damage the build under test,
        // started through a link as an installed veil often is
        let real = root.join("install/veil");
        let link = root.join("path/veil");
        fs::create_dir_all(real.parent().expect("parent")).expect("install directory");
        fs::create_dir_all(link.parent().expect("parent")).expect("link directory");
        fs::copy(env!("CARGO_BIN_EXE_veil"), &real).expect("copy of veil");
        std::os::unix::fs::symlink(&real, &link).expect("veil link");
        if second_name {
            fs::hard_link(&real, root.join("veil-second-name")).expect("second name");
        }
        let length = fs::metadata(&real).expect("veil").len();

        let output = Command::new(&link)
            .current_dir(&root)
            .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
            .arg(&real)
            .arg(&link)
            .env("HOME", &home)
            .env("VEIL_PROTECTED", "protected.txt")
            .env_remove("VEIL_BROKER_SOCKET")
            .output()
            .expect("veil should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let context = format!("second name: {second_name}\nstdout: {stdout}\nstderr: {stderr}");

        assert_eq!(
            fs::metadata(&real).ok().map(|veil| veil.len()),
            Some(length),
            "{context}"
        );
        assert_eq!(fs::read_link(&link).ok(), Some(real.clone()), "{context}");
        if second_name {
            assert!(!output.status.success(), "{context}");
            assert!(stdout.is_empty(), "{context}");
            assert!(stderr.contains("hard link"), "{context}");
        } else {
            assert!(output.status.success(), "{context}");
            assert_eq!(stdout, "ORDINARY_WRITE_ALLOWED\n", "{context}");
        }
    }
}

/// A confined command may not change what a later session takes its policy
/// from: it could drop a protection there and read the file next time.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_cannot_change_the_policy_a_later_session_loads() {
    use std::os::unix::fs::symlink;

    const STRICT: &str = "[sensitivity]\nprotected = [\"protected.txt\"]\n";
    const USER: &str = "[policy]\naudit_log = false\n";
    // each line prints its name when what it tries succeeds
    let script = r#"
project=$1 user=$2 legacy=$3 target=$4 legacy_parent=$5
weaken() { /bin/mkdir -p "$(/usr/bin/dirname "$1")"; printf '[sensitivity]\nprotected = []\n' > "$1"; }
(weaken "$project/sub/.veil.toml") 2>/dev/null && echo NESTED_CREATED
(weaken "$project/other/.VEIL.TOML") 2>/dev/null && echo OTHER_CASE_CREATED
/bin/mkdir -p "$project/linked" && /bin/ln -s /dev/null "$project/linked/.veil.toml" 2>/dev/null && echo NESTED_LINKED
printf 'x = 1\n' > "$project/draft" && /bin/mv "$project/draft" "$project/linked/.Veil.Toml" 2>/dev/null && echo RENAMED_INTO_PLACE
/bin/ln -s "$project/sub" "$legacy_parent" 2>/dev/null && echo LEGACY_PARENT_LINKED
(weaken "$legacy") 2>/dev/null && echo LEGACY_WRITTEN
(weaken "$HOME/.config/veil/config.toml") 2>/dev/null && echo HOME_LEGACY_WRITTEN
[ -e "$HOME/.cmdrvl/config" ] || { /bin/ln -s "$project/sub" "$HOME/.cmdrvl/config" 2>/dev/null && echo CONFIG_DIRECTORY_LINKED; }
(weaken "$user") 2>/dev/null && echo USER_WRITTEN
[ -n "$target" ] && (weaken "$target") 2>/dev/null && echo TARGET_WRITTEN
(weaken "$project/.veil.toml") 2>/dev/null && echo PROJECT_WRITTEN
/bin/mv "$project/.veil.toml" "$project/old.toml" 2>/dev/null && echo PROJECT_CONFIG_MOVED
/bin/rm "$project/.veil.toml" 2>/dev/null && echo PROJECT_CONFIG_REMOVED
/bin/mv "$project" "$project.moved" 2>/dev/null && echo PROJECT_MOVED
echo ordinary > ordinary.txt && echo ORDINARY_WRITE_ALLOWED
"#;

    let mut failures = Vec::new();
    for case in ["plain files", "linked files", "a second name"] {
        let root = fixture();
        let home = short_home();
        let project = root.join("project");
        fs::create_dir_all(&project).expect("project");
        fs::write(project.join("protected.txt"), format!("{MOVED_CANARY}\n")).expect("protected");
        let config = project.join(".veil.toml");
        let user = home.join(".cmdrvl/config/veil/config.toml");
        let legacy_parent = root.join("xdg");
        let legacy = legacy_parent.join("veil/config.toml");
        // the file a link leads to, which has another name altogether
        let mut target = PathBuf::new();
        match case {
            "plain files" => fs::write(&config, STRICT).expect("config"),
            "linked files" => {
                target = project.join("policy/strict.toml");
                fs::create_dir_all(target.parent().expect("parent")).expect("policy directory");
                fs::write(&target, STRICT).expect("config target");
                // where the volume ignores case, the link may spell its target
                // in another one than the names on disk
                let spelled = if root.join("PROJECT").is_dir() {
                    project.join("Policy/Strict.toml")
                } else {
                    target.clone()
                };
                symlink(&spelled, &config).expect("linked config");
                // the user's own settings, which already exist here
                fs::create_dir_all(user.parent().expect("parent")).expect("user directory");
                fs::write(&user, USER).expect("user config");
            }
            _ => {
                fs::write(&config, STRICT).expect("config");
                fs::hard_link(&config, root.join("second-name.toml")).expect("second name");
            }
        }
        let session = |program: &[&str]| {
            veil(&project)
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &legacy_parent)
                .env_remove("VEIL_PROTECTED")
                .args(["sandbox", "--"])
                .args(program)
                .output()
                .expect("veil should run")
        };

        let mut command = vec!["/bin/sh", "-c", script, "policy"];
        let words = [&project, &user, &legacy, &target, &legacy_parent]
            .map(|path| path.to_str().expect("UTF-8 path"));
        command.extend(words);
        let output = session(&command);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!(
            "{case}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if case == "a second name" {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() || !stderr.contains("hard link") {
                failures.push(context);
            }
            continue;
        }
        let user_kept =
            case != "linked files" || fs::read_to_string(&user).is_ok_and(|kept| kept == USER);
        if !output.status.success() || stdout != "ORDINARY_WRITE_ALLOWED\n" || !user_kept {
            failures.push(format!("{context}\nuser config kept: {user_kept}"));
        }

        let next = session(&["/bin/cat", "protected.txt"]);
        let printed = String::from_utf8_lossy(&next.stdout);
        if printed.contains(MOVED_CANARY) || next.status.success() {
            failures.push(format!(
                "{case}: the next session read the file: {printed}\n{}",
                String::from_utf8_lossy(&next.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// A later session follows links to find its policy, what to protect, its
/// state, the tools its broker runs and veil itself. A path may pass through
/// several links, and retargeting any one of them redirects the session.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_cannot_redirect_a_link_a_later_session_follows() {
    use std::os::unix::fs::symlink;

    // arguments: every link to attack, then `--`, then directories to move
    let script = r#"
while [ "$1" != -- ]; do
  /bin/ln -sfh /dev/null "$1" 2>/dev/null && echo "REPLACED $1"
  /bin/ln -sfh /dev/null next 2>/dev/null
  /bin/mv -fh next "$1" 2>/dev/null && echo "RENAMED_OVER $1"
  /bin/rm "$1" 2>/dev/null && echo "REMOVED $1"
  shift
done
shift
for directory in "$@"; do
  /bin/mv "$directory" "$directory.moved" 2>/dev/null && echo "MOVED $directory"
done
echo ordinary > ordinary.txt && echo ORDINARY_WRITE_ALLOWED
"#;

    let root = fixture();
    let home = short_home();
    let project = root.join("project");
    let write = |path: &Path, text: &str| {
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, text).expect("file");
    };
    let mut links = Vec::new();
    let mut link = |path: PathBuf, target: &str| {
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        symlink(target, &path).expect("link");
        links.push((path, PathBuf::from(target)));
    };

    // something to protect
    write(&project.join("store/x.csv"), &format!("{MOVED_CANARY}\n"));
    link(project.join("vault"), "links/vault-current");
    // written with `./`, as links often are
    link(project.join("links/vault-current"), "./../store");
    // the project's policy
    write(
        &project.join("config-store/strict.toml"),
        "[sensitivity]\nprotected = [\"vault/x.csv\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
    );
    link(project.join(".veil.toml"), "policy/current");
    link(project.join("policy/current"), "../via/strict.toml");
    link(project.join("via"), "config-store");
    // the user's settings
    write(
        &home.join("dotfiles/user.toml"),
        "[policy]\naudit_log = false\n",
    );
    link(
        home.join(".cmdrvl/config/veil/config.toml"),
        "../../../dotfiles/user-current",
    );
    link(home.join("dotfiles/user-current"), "user.toml");
    // veil's state, which holds what it has learned to protect
    fs::create_dir_all(home.join("dotfiles/state")).expect("state directory");
    link(home.join(".cmdrvl/state"), "../links/state-current");
    link(home.join("links/state-current"), "../dotfiles/state");
    // a tool the broker runs
    create_executable(&root.join("tools/shape-1"), "#!/bin/sh\necho SHAPE\n");
    link(root.join("bin/shape"), "current");
    link(root.join("bin/current"), "../tools/shape-1");
    // veil, copied so that a failing run cannot damage the build under test
    fs::create_dir_all(root.join("install")).expect("install directory");
    fs::copy(env!("CARGO_BIN_EXE_veil"), root.join("install/veil")).expect("copy of veil");
    link(root.join("path/veil"), "./current");
    link(root.join("path/current"), "../opt/current/veil");
    link(root.join("opt/current"), "../install");

    let directories = [
        project.join("links"),
        project.join("policy"),
        project.join("config-store"),
        home.join("dotfiles"),
        home.join("links"),
        root.join("tools"),
        root.join("opt"),
    ];
    // an earlier file of the tool's name that cannot be run is passed over
    write(&root.join("shadow/shape"), "not a program\n");
    let search = format!(
        "{}:{}:/usr/bin:/bin",
        root.join("shadow").display(),
        root.join("bin").display()
    );
    let output = Command::new(root.join("path/veil"))
        .current_dir(&project)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", search)
        .args(["sandbox", "--", "/bin/sh", "-c", script, "redirect"])
        .args(links.iter().map(|(path, _)| path))
        .arg("--")
        .args(&directories)
        .output()
        .expect("veil should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let context = format!(
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "{context}");
    assert_eq!(stdout, "ORDINARY_WRITE_ALLOWED\n", "{context}");
    for (path, target) in &links {
        assert_eq!(
            fs::read_link(path).ok().as_ref(),
            Some(target),
            "{}\n{context}",
            path.display()
        );
    }
}

/// The profile names a protected path as configured and as resolved. If a link
/// between the two could be retargeted, the next session would protect where it
/// led then, and the real file would be readable under its own name.
#[cfg(target_os = "macos")]
#[test]
fn a_protected_file_behind_two_links_stays_protected_in_the_next_session() {
    use std::os::unix::fs::symlink;

    let root = fixture();
    let home = short_home();
    for directory in ["store", "decoy", "links"] {
        fs::create_dir(root.join(directory)).expect("directory");
    }
    fs::write(root.join("store/x.csv"), format!("{MOVED_CANARY}\n")).expect("protected");
    fs::write(root.join("decoy/x.csv"), "decoy\n").expect("decoy");
    symlink("links/current", root.join("vault")).expect("first link");
    symlink("../store", root.join("links/current")).expect("second link");
    let session = |program: &[&str]| {
        veil(&root)
            .env("HOME", &home)
            .env("VEIL_PROTECTED", "vault/x.csv")
            .args(["sandbox", "--"])
            .args(program)
            .output()
            .expect("veil should run")
    };
    let read = ["/bin/cat", "store/x.csv"];

    let first = session(&read);
    assert!(!String::from_utf8_lossy(&first.stdout).contains(MOVED_CANARY));
    session(&["/bin/ln", "-sfh", "../decoy", "links/current"]);

    let next = session(&read);
    let printed = String::from_utf8_lossy(&next.stdout);
    assert!(!printed.contains(MOVED_CANARY), "{printed}");
    assert!(!next.status.success(), "{printed}");
}

/// A client that speaks the broker protocol itself, so that only reaching the
/// broker is in question. It tries one broker's socket under several names and
/// prints what each connection got back.
#[cfg(target_os = "macos")]
const BROKER_CLIENT: &str = r#"
import json, os, socket, sys
sock, project, work, dev, ino, mode = sys.argv[1:7]

def ask(label, path, cwd=None):
    if cwd:
        os.chdir(cwd)
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(10)
    try:
        client.connect(path)
        request = {"tool": "shape", "argv": ["secret.txt"], "cwd": project}
        client.sendall(json.dumps(request).encode() + b"\n")
        client.shutdown(socket.SHUT_WR)
        reply = b""
        while True:
            part = client.recv(65536)
            if not part:
                break
            reply += part
        frames = [json.loads(line) for line in reply.splitlines()]
        got = b"".join(bytes(f["chunk"]) for f in frames if "chunk" in f)
        print(label, "ANSWERED", got.decode().strip(), flush=True)
    except OSError as error:
        print(label, "UNREACHABLE", error.errno, flush=True)
    finally:
        client.close()

def symlinked():
    link = os.path.join(work, mode + ".sock")
    os.symlink(sock, link)
    return link

ask("direct", sock)
ask("symlink", symlinked())
ask("relative", os.path.basename(sock), os.path.dirname(sock))
ask("upper-case", os.path.join(os.path.dirname(sock), os.path.basename(sock).upper()))
ask("volfs", "/.vol/%s/%s" % (dev, ino))
if mode == "confined":
    # a new name for the socket, or for the directory it is in, that no rule
    # about the old one covers
    for label, source in [("renamed-socket", sock), ("renamed-directory", os.path.dirname(sock))]:
        moved = os.path.join(work, label)
        try:
            os.rename(source, moved)
        except OSError as error:
            print(label, "UNMOVED", error.errno, flush=True)
            continue
        ask(label, moved if source == sock else os.path.join(moved, os.path.basename(sock)))
        os.rename(moved, source)
"#;

/// A broker answers with its own session's project, policy and tools, and
/// another session may be denied exactly those files. A confined command must
/// reach no broker but its own (bd-xa6).
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_reaches_only_its_own_session_broker() {
    use std::os::unix::fs::MetadataExt;

    const SECRET: &str = "CROSS-SESSION-PRIVATE-8821";
    let session = |home: &Path, project: &Path, protected: &str, tool: &str| {
        fs::create_dir_all(project).expect("project");
        fs::write(
            project.join(".veil.toml"),
            format!("[sensitivity]\nprotected = [{protected}]\n[spine]\nauthorized_tools = [\"shape\"]\n"),
        )
        .expect("project policy");
        create_executable(&project.join("bin/shape"), tool);
        let path = std::env::join_paths([
            project.join("bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .expect("fixture PATH");
        let mut command = veil(project);
        command
            .env("HOME", home)
            .env("PATH", path)
            .env_remove("VEIL_PROTECTED");
        command
    };
    // Session A waits, with its broker listening, until the others are done.
    let waiting = r#"
printf '%s' "$VEIL_BROKER_SOCKET" > socket.tmp && /bin/mv socket.tmp socket.path
tries=0
while [ $tries -lt 1200 ] && [ ! -e go ]; do tries=$((tries + 1)); /bin/sleep 0.05; done
"#;

    // `shared_home`: whether both sessions are the same user home, as they are
    // unless one is pointed elsewhere
    for shared_home in [true, false] {
        let a = fixture().join("a");
        let a_home = short_home();
        fs::create_dir_all(&a).expect("project a");
        fs::write(a.join("secret.txt"), format!("{SECRET}\n")).expect("secret");
        let mut launcher = session(
            &a_home,
            &a,
            "\"secret.txt\"",
            "#!/bin/sh\n/bin/cat \"$1\"\n",
        )
        .args(["sandbox", "--", "/bin/sh", "-c", waiting])
        .spawn()
        .expect("session a should launch");
        assert!(
            (0..1000).any(|_| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                a.join("socket.path").exists()
            }),
            "session a should name its socket"
        );
        let socket = fs::read_to_string(a.join("socket.path")).expect("socket path");
        let metadata = fs::metadata(&socket).expect("socket a");
        let client = |command: &mut Command, work: &Path, mode: &str| {
            command
                .args([
                    &socket,
                    a.to_str().expect("utf-8"),
                    work.to_str().expect("utf-8"),
                ])
                .args([metadata.dev().to_string(), metadata.ino().to_string()])
                .arg(mode);
        };

        let b = fixture().join("b");
        let b_home = if shared_home {
            a_home.clone()
        } else {
            short_home()
        };
        fs::create_dir_all(&b).expect("project b");

        // control: outside a sandbox the same client is answered. Its links
        // go in a short directory, so that their paths fit a socket address.
        let links = short_home();
        let mut unconfined = Command::new("/usr/bin/python3");
        unconfined.args(["-I", "-c", BROKER_CLIENT]);
        client(&mut unconfined, &links, "control");
        let control = unconfined.output().expect("control client");
        let control = String::from_utf8_lossy(&control.stdout).into_owned();

        fs::write(b.join("own.txt"), "mine\n").expect("own file");
        let own_secret = a.join("secret.txt");
        let mut confined = session(
            &b_home,
            &b,
            &format!("\"own.txt\", \"{}\"", own_secret.display()),
            "#!/bin/sh\necho '{\"rows\":1}'\n",
        );
        let script = r#"
veil=$1 client=$2 a_secret=$3
shift 3
echo "OWN=$("$veil" exec shape own.txt)"
/bin/cat "$a_secret" 2>/dev/null || echo DIRECT_READ_REFUSED
/usr/bin/python3 -I -c "$client" "$@"
"#;
        confined
            .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
            .args([env!("CARGO_BIN_EXE_veil"), BROKER_CLIENT])
            .arg(&own_secret);
        client(&mut confined, &links, "confined");
        let output = confined.output().expect("session b should run");

        fs::write(a.join("go"), "").expect("release session a");
        assert!(launcher.wait().expect("session a should exit").success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let context = format!(
            "shared home: {shared_home}\ncontrol:\n{control}\nconfined:\n{stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for spelling in ["direct", "symlink", "relative"] {
            assert!(
                control.contains(&format!("{spelling} ANSWERED {SECRET}")),
                "{context}"
            );
        }
        assert!(output.status.success(), "{context}");
        // its own broker still answers it
        assert!(stdout.contains("OWN={\"rows\":1}"), "{context}");
        assert!(stdout.contains("DIRECT_READ_REFUSED"), "{context}");
        assert!(!stdout.contains(SECRET), "{context}");
        assert!(!stdout.contains("ANSWERED"), "{context}");
        for line in [
            "direct UNREACHABLE",
            "symlink UNREACHABLE",
            "relative UNREACHABLE",
            "upper-case UNREACHABLE",
            "volfs UNREACHABLE",
            "renamed-socket UNMOVED",
        ] {
            assert!(stdout.contains(line), "{line}\n{context}");
        }
    }
}

/// A path rule does not follow a file to its other names. A hard link made
/// before the session would let the confined process rewrite a tool the broker
/// runs, and the broker runs it outside the sandbox (bd-wwh).
#[cfg(target_os = "macos")]
#[test]
fn a_broker_tool_with_a_second_name_cannot_be_rewritten_by_the_confined_process() {
    const ORIGINAL: &str = "#!/bin/sh\necho '{\"rows\":1}'\n";
    // rewrite the tool through its other name, then ask the broker to run it
    let script = r#"
printf '#!/bin/sh\n/bin/cat "%s/protected.txt"\n' "$2" > "$2/second-name" && echo REWRITTEN
"$1" exec shape protected.txt
"#;

    // `aliased` names the file that gets the second name
    for (case, through_symlink, aliased) in [
        ("the PATH entry is the tool", false, "bin/shape"),
        (
            "the PATH entry links to the tool",
            true,
            "real-bin/shape-1.0",
        ),
        (
            "control: a tool the broker will not run",
            false,
            "later-bin/shape",
        ),
    ] {
        let root = fixture();
        let home = short_home();
        fs::write(root.join("protected.txt"), "MERIDIAN-VAULT-CONFIDENTIAL\n").expect("protected");
        fs::write(
            root.join(".veil.toml"),
            "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
        )
        .expect("project policy");
        create_executable(&root.join("later-bin/shape"), ORIGINAL);
        if through_symlink {
            create_executable(&root.join("real-bin/shape-1.0"), ORIGINAL);
            fs::create_dir(root.join("bin")).expect("bin directory");
            std::os::unix::fs::symlink(root.join("real-bin/shape-1.0"), root.join("bin/shape"))
                .expect("tool symlink");
        } else {
            create_executable(&root.join("bin/shape"), ORIGINAL);
        }
        let aliased = root.join(aliased);
        fs::hard_link(&aliased, root.join("second-name")).expect("second name");
        let path = std::env::join_paths(
            [root.join("bin"), root.join("later-bin")]
                .into_iter()
                .chain(std::env::split_paths(
                    &std::env::var_os("PATH").unwrap_or_default(),
                )),
        )
        .expect("fixture PATH should be joinable");

        let output = veil(&root)
            .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
            .arg(env!("CARGO_BIN_EXE_veil"))
            .arg(&root)
            .env("HOME", &home)
            .env("PATH", path)
            .env("VEIL_PROTECTED", "protected.txt")
            .output()
            .expect("veil should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let context = format!("{case}\nstdout: {stdout}\nstderr: {stderr}");

        assert!(!stdout.contains("MERIDIAN-VAULT-CONFIDENTIAL"), "{context}");
        if case.starts_with("control") {
            assert!(output.status.success(), "{context}");
            assert!(stdout.contains("{\"rows\":1}"), "{context}");
        } else {
            // refused before anything ran, naming the file and the reason
            assert!(!output.status.success(), "{context}");
            assert!(!stdout.contains("REWRITTEN"), "{context}");
            assert_eq!(
                fs::read_to_string(&aliased).expect("tool"),
                ORIGINAL,
                "{context}"
            );
            assert!(stderr.contains(&aliased.display().to_string()), "{context}");
            assert!(stderr.contains("hard link"), "{context}");
        }
    }
}

/// The broker and the launcher both remove the session socket, and the broker
/// can get there first (CI run 45750031750). A socket already gone is not a
/// failed session; one that cannot be removed is still an error.
#[cfg(target_os = "macos")]
#[test]
fn a_session_socket_that_is_already_gone_does_not_fail_the_launcher() {
    // The confined command names its socket, waits for the test to act on it
    // from outside the sandbox, and exits with a status of its own.
    let script = r#"
printf '%s' "$VEIL_BROKER_SOCKET" > socket.tmp && /bin/mv socket.tmp socket.path
tries=0
while [ $tries -lt 600 ]; do
  if [ -e go ]; then exit 7; fi
  tries=$((tries + 1))
  /bin/sleep 0.05
done
exit 1
"#;

    for unremovable in [false, true] {
        let root = fixture();
        let home = short_home();
        fs::write(root.join("protected.txt"), "private\n").expect("protected");
        let launcher = veil(&root)
            .args(["sandbox", "--", "/bin/sh", "-c", script])
            .env("HOME", &home)
            .env("VEIL_PROTECTED", "protected.txt")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("veil should launch");

        let announced = root.join("socket.path");
        assert!(
            (0..1000).any(|_| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                announced.exists()
            }),
            "the confined command should name its socket"
        );
        let socket = PathBuf::from(fs::read_to_string(&announced).expect("socket path"));
        fs::remove_file(&socket).expect("the socket is there to remove");
        if unremovable {
            // a directory cannot be removed the way a socket is
            fs::create_dir(&socket).expect("obstruction");
        }
        fs::write(root.join("go"), "").expect("release the confined command");

        let output = launcher.wait_with_output().expect("launcher should exit");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if unremovable {
            assert_ne!(output.status.code(), Some(7), "stderr: {stderr}");
            assert!(stderr.contains("veil: "), "stderr: {stderr}");
        } else {
            assert_eq!(output.status.code(), Some(7), "stderr: {stderr}");
            assert!(!stderr.contains("veil: "), "stderr: {stderr}");
        }
    }
}

/// A process this test started, outside any sandbox. It is killed and reaped
/// however the test ends.
#[cfg(target_os = "macos")]
struct Outsider(std::process::Child);

#[cfg(target_os = "macos")]
impl Drop for Outsider {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The broker, the launcher and everything else the user runs are outside the
/// sandbox, and the confined command must not be able to stop or kill them.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_signals_only_processes_in_its_own_sandbox() {
    use std::os::unix::process::CommandExt;

    let root = fixture();
    let home = short_home();
    fs::write(root.join("protected.txt"), "private\n").expect("protected");
    fs::write(
        root.join(".veil.toml"),
        "[sensitivity]\nprotected = [\"protected.txt\"]\n[spine]\nauthorized_tools = [\"shape\"]\n",
    )
    .expect("project policy");
    create_executable(&root.join("bin/shape"), "#!/bin/sh\necho '{\"rows\":1}'\n");
    let path = std::env::join_paths([
        root.join("bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .expect("fixture PATH");
    let mut outsider = Outsider(
        Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("outside process"),
    );

    // `kill 0` signals the whole process group, which holds the launcher and
    // the broker as well as this shell
    let script = r#"
veil=$1 outsider=$2
for signal in 0 STOP TERM KILL; do
  kill -$signal "$outsider" 2>/dev/null && echo "OUTSIDER_$signal"
done
kill -0 $$ && echo SELF
/bin/sleep 5 & child=$!
kill -TERM $child && echo CHILD
wait $child 2>/dev/null
/bin/sh -c '/bin/sleep 5 & echo $! > grandchild.pid; wait' &
for attempt in 1 2 3 4 5 6 7 8 9 10; do [ -s grandchild.pid ] && break; /bin/sleep 0.1; done
kill -TERM "$(/bin/cat grandchild.pid)" && echo GRANDCHILD
wait 2>/dev/null
trap '' TERM
kill -TERM 0
/bin/sleep 0.5
echo "BROKER: $("$veil" exec shape protected.txt 2>&1)"
"#;
    // its own group, so that `kill 0` can reach nothing this test did not start
    let output = veil(&root)
        .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
        .arg(env!("CARGO_BIN_EXE_veil"))
        .arg(outsider.0.id().to_string())
        .env("HOME", &home)
        .env("PATH", path)
        .env("VEIL_PROTECTED", "protected.txt")
        .process_group(0)
        .output()
        .expect("veil should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let context = format!(
        "status: {:?}\nstdout: {stdout}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        stdout, "SELF\nCHILD\nGRANDCHILD\nBROKER: {\"rows\":1}\n",
        "{context}"
    );
    assert!(output.status.success(), "{context}");
    assert_eq!(outsider.0.try_wait().expect("outsider status"), None);
    let state = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &outsider.0.id().to_string()])
        .output()
        .expect("ps should run");
    let state = String::from_utf8_lossy(&state.stdout);
    assert!(!state.trim().is_empty() && !state.contains('T'), "{state}");
}

/// An application that LaunchServices starts is not in the sandbox.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_cannot_start_an_application_outside_the_sandbox() {
    let root = fixture();
    fs::write(root.join("protected-alias.txt"), "private\n").expect("protected");
    let application = |name: &str| {
        let bundle = root.join(format!("{name}.app"));
        let marker = root.join(format!("{name}.started"));
        create_executable(
            &bundle.join("Contents/MacOS/probe"),
            &format!("#!/bin/sh\n/usr/bin/touch '{}'\n", marker.display()),
        );
        let identifier = format!(
            "com.cmdrvl.veil-test.{name}.{}.{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        // no window, no Dock icon
        fs::write(
            bundle.join("Contents/Info.plist"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n\
                 <key>CFBundleExecutable</key><string>probe</string>\n\
                 <key>CFBundleIdentifier</key><string>{identifier}</string>\n\
                 <key>CFBundlePackageType</key><string>APPL</string>\n\
                 <key>LSBackgroundOnly</key><true/>\n\
                 </dict></plist>\n"
            ),
        )
        .expect("Info.plist");
        (bundle, marker)
    };
    let appears = |marker: &Path, within: u64| {
        (0..within * 10).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            marker.exists()
        })
    };

    // the control: without the sandbox this really does start the application
    let (control, control_marker) = application("control");
    let started = std::time::Instant::now();
    let status = Command::new("/usr/bin/open")
        .args(["-g", "-n"])
        .arg(&control)
        .status()
        .expect("open should run");
    assert!(status.success(), "the control could not start: {status}");
    assert!(appears(&control_marker, 30), "the control never started");
    let needed = started.elapsed().as_secs();

    let (confined, confined_marker) = application("confined");
    let output = veil(&root)
        .args(["sandbox", "--", "/usr/bin/open", "-g", "-n"])
        .arg(&confined)
        .env("HOME", short_home())
        .output()
        .expect("veil should run");
    assert!(
        !appears(&confined_marker, (needed * 3).max(5)),
        "the application ran outside the sandbox"
    );
    assert!(!output.status.success(), "{output:?}");
}

/// A tmux server outside the sandbox runs whatever a client asks it to, and
/// agents are often started inside one, which names it in `$TMUX`. A listener
/// of this test's own stands in for the server, at each place tmux puts one.
#[cfg(target_os = "macos")]
#[test]
fn a_confined_command_cannot_reach_a_tmux_server() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    let root = fixture();
    let home = short_home();
    let named = short_home();
    let custom = short_home();
    fs::write(root.join("protected-alias.txt"), "private\n").expect("protected");
    let serve = |socket: &Path| {
        fs::create_dir_all(socket.parent().expect("parent")).expect("socket directory");
        let listener = UnixListener::bind(socket).expect("listener");
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.write_all(b"served\n");
            }
        });
        socket.to_path_buf()
    };

    // where tmux listens by default, under a user number nobody has
    let default_directory = PathBuf::from(format!(
        "/private/tmp/tmux-{}{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .subsec_nanos()
    ));
    let sockets = [
        serve(&default_directory.join("default")),
        // under $TMUX_TMPDIR
        serve(&named.join("tmux-501/other")),
        // wherever $TMUX says the server this session is in listens
        serve(&custom.join("run/server.sock")),
        // the control: another program's socket stays reachable
        serve(&home.join("unrelated.sock")),
    ];

    let script = r#"
ask() { answer=$(/usr/bin/nc -U "$1" </dev/null 2>/dev/null); echo "${answer:-refused}"; }
for socket in "$@"; do ask "$socket"; done
# a rule follows a name: neither a socket nor anything above it may be renamed
for original in "$1" "$2" "$3"; do
  directory=$(/usr/bin/dirname "$original")
  /bin/mv "$original" "$original.moved" 2>/dev/null && ask "$original.moved"
  /bin/mv "$directory" "$directory.moved" 2>/dev/null && ask "$directory.moved/$(/usr/bin/basename "$original")"
  above=$(/usr/bin/dirname "$directory")
  /bin/mv "$above" "$above.moved" 2>/dev/null && echo "MOVED $above"
done
"#;
    let output = veil(&root)
        .args(["sandbox", "--", "/bin/sh", "-c", script, "sh"])
        .args(&sockets)
        .env("HOME", &home)
        .env("TMUX_TMPDIR", &named)
        .env("TMUX", format!("{},4242,0", sockets[2].display()))
        .output()
        .expect("veil should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let context = format!(
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(stdout, "refused\nrefused\nrefused\nserved\n", "{context}");
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
