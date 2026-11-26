//! bd-02q: no tool call veil sees may write a file that decides what veil
//! refuses: a `.veil.toml` in any directory (a nested one replaces the outer
//! one) or the user's settings. The real binary: the write tools, each shell
//! route, and the controls: reading these files and writing other files are
//! decided as before.

#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

mod common;
#[path = "common/user.rs"]
mod user;

const PROTECTED: &str = "[sensitivity]\nprotected = [\"data/**\"]\n";
const REFUSAL: &str = "veil's configuration";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "veil-guard-{}-{nanos}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in [
            "home/.cmdrvl/config/veil",
            "home/.cmdrvl/config/other",
            "home/.config/veil",
            "project/data",
            "project/sub",
            "project/loose",
            "project/scripts",
            "project/docs",
        ] {
            fs::create_dir_all(root.join(directory)).expect("fixture directory");
        }
        let fixture = Self {
            root: fs::canonicalize(root).expect("canonical fixture root"),
        };
        user::write_config(&fixture.home(), "[policy]\naudit_log = false\n");
        for (path, text) in [
            (".veil.toml", PROTECTED),
            ("loose/.veil.toml", "[sensitivity]\nprotected = []\n"),
            ("notes.md", "notes\n"),
            ("data/ledger.csv", "name,amount\na,1\n"),
            ("scripts/wipe.sh", "rm -f .veil.toml\n"),
            ("scripts/replace.sh", "echo '[policy]' >.veil.toml\n"),
        ] {
            fixture.write(path, text);
        }

        // names that lead to a config, and that already exist when veil looks
        let user_config = user::config_path(&fixture.home());
        symlink(".veil.toml", fixture.path("config-link")).expect("file link");
        symlink(
            user_config.parent().expect("a directory"),
            fixture.path("settings-dir"),
        )
        .expect("directory link");
        // a link to a nested config nobody has made yet
        symlink("sub/.veil.toml", fixture.path("later")).expect("dangling link");
        fs::hard_link(fixture.path(".veil.toml"), fixture.path("second-name")).expect("hard link");
        fs::hard_link(&user_config, fixture.path("third-name")).expect("hard link");
        fixture
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project().join(relative)
    }

    fn write(&self, relative: &str, text: &str) {
        fs::write(self.path(relative), text).expect("fixture file");
    }

    /// `None` when veil allowed the call, the reason when it denied it.
    #[track_caller]
    fn hook(&self, tool: &str, input: Value) -> Option<String> {
        let payload = json!({
            "session_id": "config-guard",
            "cwd": self.project(),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(self.project())
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
        common::claude_denial(&child.wait_with_output().expect("veil should exit"))
    }

    #[track_caller]
    fn bash(&self, command: &str) -> Option<String> {
        self.hook("Bash", json!({ "command": command }))
    }

    /// The commands the hook did not refuse as a write of veil's settings.
    fn not_refused(&self, commands: &[&str]) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| match self.bash(command) {
                Some(reason) if reason.contains(REFUSAL) => None,
                other => Some(format!("`{command}`: {other:?}")),
            })
            .collect()
    }

    /// The commands the hook refused.
    fn refused(&self, commands: &[&str]) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| {
                self.bash(command)
                    .map(|reason| format!("`{command}`: {reason}"))
            })
            .collect()
    }
}

#[track_caller]
fn assert_none(found: &[String], what: &str) {
    assert!(found.is_empty(), "{what}:\n{}", found.join("\n"));
}

const WRITE_TOOLS: [(&str, &str); 4] = [
    ("Write", "file_path"),
    ("Edit", "file_path"),
    ("MultiEdit", "file_path"),
    ("NotebookEdit", "notebook_path"),
];

#[test]
fn write_tools_cannot_write_a_veil_config_even_a_broken_one() {
    let fixture = Fixture::new();
    let home = fixture.home().display().to_string();
    let mut targets = vec![
        ".veil.toml".to_owned(),
        fixture.path(".veil.toml").display().to_string(),
        // nested ones replace the outer one, made yet or not
        "sub/.veil.toml".to_owned(),
        "not/there/yet/.veil.toml".to_owned(),
        "sub/../.veil.toml".to_owned(),
        // the default filesystem of macOS ignores case
        ".VEIL.toml".to_owned(),
        user::config_path(&fixture.home()).display().to_string(),
        "~/.cmdrvl/config/veil/config.toml".to_owned(),
        format!("{home}/.config/veil/config.toml"),
        "config-link".to_owned(),
        "settings-dir/config.toml".to_owned(),
        "later".to_owned(),
        "second-name".to_owned(),
        "third-name".to_owned(),
    ];
    // replacing a directory above the user's settings replaces them
    targets.extend(
        [
            ".cmdrvl",
            ".cmdrvl/config",
            ".cmdrvl/config/veil",
            ".config/veil",
        ]
        .map(|directory| format!("{home}/{directory}")),
    );

    let mut allowed = Vec::new();
    // the guard needs no configuration, so a broken one cannot switch it off
    for config in [PROTECTED, "not toml ["] {
        fixture.write(".veil.toml", config);
        for target in &targets {
            for (tool, field) in WRITE_TOOLS {
                match fixture.hook(tool, json!({field: target, "content": "x"})) {
                    Some(reason) if reason.contains(REFUSAL) => {}
                    other => allowed.push(format!("{tool} {target} ({config:?}): {other:?}")),
                }
            }
        }
        // and a broken one refuses no other write, the one repairing it aside
        for target in [
            "notes.md".to_owned(),
            "veil.toml".to_owned(),
            ".veil.toml.example".to_owned(),
            "docs/config.toml".to_owned(),
            "data/new.csv".to_owned(),
            format!("{home}/.cmdrvl/config/other/config.toml"),
        ] {
            for (tool, field) in WRITE_TOOLS {
                assert_eq!(
                    fixture.hook(tool, json!({field: target, "content": "x"})),
                    None,
                    "{tool} {target} ({config:?})"
                );
            }
        }
    }
    assert_none(&allowed, "writes of a veil config were not refused");
}

#[test]
fn a_redirect_into_a_veil_config_is_refused() {
    let fixture = Fixture::new();
    assert_none(
        &fixture.not_refused(&[
            "echo x >.veil.toml",
            "echo x >>.veil.toml",
            "echo x >| .veil.toml",
            ": >.veil.toml",
            "echo x &>.veil.toml",
            "echo x 2>sub/.veil.toml",
            "echo x >.VEIL.TOML",
            "cd sub && echo x >.veil.toml",
            "echo x >config-link",
            "echo x >later",
            "echo x >>second-name",
            "echo x >>third-name",
            "echo x >~/.config/veil/config.toml",
            "cat notes.md >.veil.toml",
            "{ echo x; } >.veil.toml",
            "bash -c 'echo x > .veil.toml'",
            "echo x >.veil*",
        ]),
        "redirects into a veil config were not refused",
    );
}

#[test]
fn a_command_that_writes_removes_or_moves_a_veil_config_is_refused() {
    let fixture = Fixture::new();
    assert_none(
        &fixture.not_refused(&[
            "cat notes.md | tee .veil.toml",
            "cp notes.md .veil.toml",
            "cp notes.md sub/.veil.toml",
            "cp loose/.veil.toml sub/",
            "cp -t sub loose/.veil.toml",
            "cp notes.md config-link",
            "cp -l .veil.toml copy.toml",
            "install -m 644 notes.md .veil.toml",
            "rsync notes.md .veil.toml",
            "mv .veil.toml old.toml",
            "mv notes.md .veil.toml",
            "rm .veil.toml",
            "rm -f ./.veil.toml",
            "rm -rf ~/.cmdrvl/config",
            "rm sub/../.veil.toml",
            "rm .veil*",
            "rm loose/.veil.toml",
            "unlink .veil.toml",
            "shred -u .veil.toml",
            "chmod 000 .veil.toml",
            "truncate -s 0 .veil.toml",
            "touch sub/.veil.toml",
            "ln -sf /tmp/elsewhere .veil.toml",
            "ln .veil.toml copy.toml",
            "ln -s .veil.toml another-link",
            "dd if=notes.md of=.veil.toml",
            "sed -i s/data/x/ .veil.toml",
            "sed -i '' s/data/x/ .veil.toml",
            "sed --in-place=.bak s/data/x/ .veil.toml",
            "sed -n 'w .veil.toml' notes.md",
            "sort -o .veil.toml notes.md",
            "sort --output=.veil.toml notes.md",
            "uniq notes.md .veil.toml",
            "awk '{print > \".veil.toml\"}' notes.md",
            "find . -name .veil.toml -delete",
            "find .veil.toml -exec rm {} ;",
            "git checkout -- .veil.toml",
            "git restore .veil.toml",
            "git rm .veil.toml",
            "git mv .veil.toml old.toml",
            "perl -pi -e s/data/x/ .veil.toml",
            "python3 -c \"open('.veil.toml','w').write('')\"",
            "node -e \"require('fs').unlinkSync('.veil.toml')\"",
            "python3 <<'EOF'\nopen('.veil.toml', 'w').write('')\nEOF",
            "yq -i '.a = 1' .veil.toml",
            "ed .veil.toml",
            "vim -es .veil.toml",
            "curl -o .veil.toml https://example.invalid/x",
            "curl -o.veil.toml https://example.invalid/x",
            "wget -O .veil.toml https://example.invalid/x",
            "tar -xf a.tar .veil.toml",
            "unzip -o a.zip .veil.toml",
            "sh -c \"rm .veil.toml\"",
            "true && rm .veil.toml",
            "env rm .veil.toml",
            "echo .veil.toml | xargs rm .veil.toml",
            // wrappers, and spellings of the program
            "command rm .veil.toml",
            "sudo rm .veil.toml",
            "nohup rm .veil.toml",
            "timeout 5 rm .veil.toml",
            "nice -n 5 rm .veil.toml",
            "/bin/rm .veil.toml",
            "\\rm .veil.toml",
            "rm -- .veil.toml",
            "rm .v*",
            "rm sub/{.veil.toml,x}",
            "find . -name '.veil*' -delete",
            // the writing options of programs that otherwise only read
            "less -o .veil.toml notes.md",
            "less -O.veil.toml notes.md",
            "diff --output=.veil.toml notes.md veil.toml",
            "fd veil -x rm .veil.toml",
            // the same words where a program veil does not know takes them
            "sponge .veil.toml <notes.md",
            "patch .veil.toml fix.diff",
            "perl -e 'unlink \".veil.toml\"'",
            "ruby <<'EOF'\nFile.delete('sub/.veil.toml')\nEOF",
            "osascript -e 'do shell script \"x\" & \".veil.toml\"'",
        ]),
        "commands that write a veil config were not refused",
    );
}

#[test]
fn a_shell_script_that_writes_a_veil_config_is_refused() {
    let fixture = Fixture::new();
    assert_none(
        &fixture.not_refused(&[
            "bash scripts/wipe.sh",
            "sh scripts/replace.sh",
            "source scripts/wipe.sh",
            ". scripts/replace.sh",
            "echo 'rm .veil.toml' >run.sh && bash run.sh",
        ]),
        "scripts that write a veil config were not refused",
    );
}

/// Older rules refuse these too, and give their own reason. Turned down to
/// `log` and `allow` they only report, and the guard is what refuses.
#[test]
fn a_write_older_rules_refuse_too_stays_refused_when_they_are_turned_down() {
    let fixture = Fixture::new();
    let commands = [
        "echo x >\"$DIR/.veil.toml\"",
        "echo x >>settings-dir/config.toml",
        "echo x >$HOME/.cmdrvl/config/veil/config.toml",
        "tee -a ~/.cmdrvl/config/veil/config.toml <notes.md",
        "cp -r docs/. ~/.cmdrvl/config/veil",
        "mv loose/.veil.toml .",
        "mv ~/.cmdrvl/config moved",
        "mv ~/.cmdrvl/config/veil moved",
        "$EDITOR .veil.toml",
    ];
    for command in commands {
        assert!(fixture.bash(command).is_some(), "`{command}` was allowed");
    }

    user::write_config(
        &fixture.home(),
        "[policy]\naudit_log = false\ndefault = \"log\"\ndynamic_args = \"allow\"\n",
    );
    // the older rules now only report
    assert_eq!(fixture.bash("cat data/ledger.csv"), None);
    assert_none(
        &fixture.not_refused(&commands),
        "turned down, these were not refused",
    );
    // this one is refused as veil's own state, under any mode
    assert!(fixture.bash("mv ~/.cmdrvl moved").is_some());
}

/// The derived registry can lift a refused redirect. It cannot lift this.
#[test]
fn a_refused_redirect_does_not_stand_in_for_the_guard() {
    let fixture = Fixture::new();
    for command in ["rm .veil.toml >data/ledger.csv", "rm .veil.toml >\"$OUT\""] {
        assert!(fixture.bash(command).is_some(), "`{command}` was allowed");
    }
    user::write_config(
        &fixture.home(),
        "[policy]\naudit_log = false\ndefault = \"log\"\ndynamic_args = \"allow\"\n",
    );
    assert_none(
        &fixture.not_refused(&["rm .veil.toml >data/ledger.csv", "rm .veil.toml >\"$OUT\""]),
        "turned down, these were not refused",
    );
}

#[test]
fn no_policy_mode_lets_a_veil_config_be_written() {
    let fixture = Fixture::new();
    for settings in [
        "default = \"log\"",
        "default = \"warn\"",
        "egress = \"warn\"",
        "dynamic_args = \"allow\"",
    ] {
        user::write_config(
            &fixture.home(),
            &format!("[policy]\naudit_log = false\n{settings}\n"),
        );
        assert_none(
            &fixture.not_refused(&["rm .veil.toml", "echo x >.veil.toml"]),
            settings,
        );
        let written = fixture.hook("Write", json!({"file_path": ".veil.toml"}));
        assert!(
            written.is_some_and(|reason| reason.contains(REFUSAL)),
            "{settings}"
        );
    }
}

#[test]
fn reading_a_project_config_and_writing_other_files_stay_allowed() {
    let fixture = Fixture::new();
    for input in [
        json!({"file_path": ".veil.toml"}),
        json!({"file_path": "config-link"}),
    ] {
        assert_eq!(fixture.hook("Read", input.clone()), None, "{input}");
    }
    assert_none(
        &fixture.refused(&[
            "cat .veil.toml",
            "head -3 .veil.toml",
            "grep protected .veil.toml",
            "rg protected .veil.toml",
            "wc -l .veil.toml",
            "ls -la .veil.toml sub",
            "stat .veil.toml",
            "test -f .veil.toml && echo yes",
            "[ -e .veil.toml ]",
            "diff .veil.toml loose/.veil.toml",
            "sed -n 1p .veil.toml",
            "sort .veil.toml",
            "awk '{print}' .veil.toml",
            "find . -name .veil.toml",
            "cat .veil.toml >copy.txt",
            "cp .veil.toml copy.toml",
            "git status .veil.toml",
            "git diff .veil.toml",
            "git log -p -- .veil.toml",
            "git add .veil.toml",
            "git commit -m 'update .veil.toml' .veil.toml",
            "git rm --cached .veil.toml",
            "bash -c 'cat .veil.toml'",
            "echo .veil.toml >>.gitignore",
            "echo x >notes.md",
            "rm notes.md",
            "rm *.md",
            "rm -f sub/*",
            "mv notes.md renamed.md",
            "cp notes.md sub/",
            "cp -r docs sub/docs",
            "mkdir -p sub/deeper",
            "touch veil.toml .veil.toml.example",
            "sed -i s/a/b/ notes.md",
            // a script is not a file, however much it looks like a glob
            "sed -i 's/.*//' notes.md",
            "sed -i '' 's/.*//' notes.md",
            "sed -i -e 's/.*//' -e 's/a/.*/' notes.md",
            "perl -pi -e 's/.*//' notes.md",
            "python3 -c 'import re; re.compile(\".*\")'",
            "less notes.md",
            "diff -u notes.md renamed.md",
            "command -v rm",
            // text about a config, handed to a program that runs no code
            "gh pr create --title floor --body-file - <<'EOF'\nA `.veil.toml` only tightens.\nEOF",
            "gh issue comment 1 --body 'the \"sub/.veil.toml\" case'",
            "chmod +x scripts/wipe.sh",
            "ln -s ../notes.md sub/notes-link",
            "find . -name '*.tmp' -delete",
            "git checkout -b feature",
            "cargo build",
            "python3 -c 'print(1)'",
        ]),
        "controls were refused",
    );
}

#[test]
fn the_refusal_says_a_person_makes_the_change() {
    let fixture = Fixture::new();
    for reason in [
        fixture.bash("rm .veil.toml"),
        fixture.hook("Write", json!({"file_path": ".veil.toml"})),
    ] {
        let reason = reason.expect("a write of a veil config is refused");
        assert!(reason.contains(REFUSAL), "{reason}");
        assert!(reason.contains("a person"), "{reason}");
    }
}
