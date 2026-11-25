use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
