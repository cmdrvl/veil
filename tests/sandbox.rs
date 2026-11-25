use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
