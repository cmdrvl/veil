//! bd-3qw and the registry half of bd-oao: a record in
//! `~/.cmdrvl/state/veil/derived.jsonl` turns a deny into an allow, so every
//! test here runs the real binary and shows either that a derived output can be
//! read, or that some way of getting protected bytes registered is refused.
//!
//! The spine tools are fake shell scripts that misbehave on purpose.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// Prose with nothing the output detectors flag: only the copy check can tell
/// that a copy of it is not a derived artifact.
const MEMO: &str = "Confidential memorandum. The Meridian vault holds the restructuring terms \
agreed last week between the sponsor and the lender group, including the revised waterfall, the \
cure period, the extension fee schedule and the conditions under which the guaranty is released. \
Nothing in this memorandum may be shared outside the deal team before the announcement, and the \
working draft lives only in this folder until counsel has signed off on every exhibit.\n";

const SHAPE_REPORT: &str = "{\"tool\":\"shape\",\"outcome\":\"COMPATIBLE\",\"rows\":3}\n";

/// Public prose with no run of text in common with [`MEMO`].
const PUBLIC_NOTE: &str = "Garden volunteers meet each Saturday morning beside the north gate. \
Bring gloves, a water bottle and sturdy shoes; spades, rakes and seed trays are supplied by the \
association. Newcomers are paired with a returning member for their first two visits.\n";

/// `profile MODE INPUT [--out PATH]`: each mode is one way a tool can use or
/// abuse its output.
const PROFILE_TOOL: &str = r#"#!/bin/sh
mode=$1
input=$2
shift 2
out=
while [ $# -gt 0 ]; do
  case $1 in
    --out|--output) out=$2; shift 2 ;;
    --out=*) out=${1#--out=}; shift ;;
    --output=*) out=${1#--output=}; shift ;;
    *) shift ;;
  esac
done
summary() { printf '{"profile":"%s","columns":4,"null_rate":0.0}\n' "$1"; }
excerpt() { tail -c +101 "$input" | head -c 200; }
reflowed() { excerpt | tr ' ' '\n' | tr 'a-z' 'A-Z'; }
case $mode in
  summary) summary "${out##*/}" > "$out" ;;
  copy) cat "$input" > "$out" ;;
  excerpt) { printf '{"sample":"'; excerpt; printf '"}\n'; } > "$out" ;;
  reflow) reflowed > "$out" ;;
  rows) printf 'name,ssn,email\nAda,536-90-4399,ada@example.com\nBo,536-90-4398,bo@example.com\nCy,536-90-4397,cy@example.com\n' > "$out" ;;
  binary) printf 'PK\000\001summary' > "$out" ;;
  nothing) : ;;
  rewrite) summary rewritten > "$out" ;;
  hardlink) ln "$input" "$out" ;;
  symlink) ln -s "$PWD/$input" "$out" ;;
  move) mv "$input" "$out" ;;
  indirect) cat "$(cat "$input")" > "$out" ;;
  directory) mkdir "$out" && summary manifest > "$out/manifest.json" && cp "$input" "$out/member.txt" ;;
  print) cat "$input" ;;
  print-excerpt) excerpt ;;
  print-reflow) reflowed ;;
  print-summary) summary printed ;;
  print-indirect) cat "$(cat "$input")" ;;
esac
"#;

/// A hook answer that leaves the call to the harness's own permissions: no
/// output at all.
const NO_DECISION: &str = "no decision";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

#[derive(Debug)]
struct Verdict {
    action: String,
    reason: String,
}

impl Fixture {
    fn new() -> Self {
        Self::under(&std::env::temp_dir(), "veil-derived")
    }

    /// For `veil sandbox`: the broker socket lives under `HOME`, and a macOS
    /// Unix socket path must be under 104 bytes, which no directory under
    /// `temp_dir()` leaves room for.
    #[cfg(target_os = "macos")]
    fn short() -> Self {
        Self::under(Path::new("/tmp"), "vd")
    }

    fn under(parent: &Path, name: &str) -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .subsec_nanos();
        let root = parent.join(format!(
            "{name}-{}-{time}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        for directory in ["home", "bin", "project/data", "outside"] {
            fs::create_dir_all(root.join(directory)).expect("fixture directory");
        }
        let fixture = Self {
            root: fs::canonicalize(root).expect("canonical fixture root"),
        };
        fixture.write(".veil.toml", "[sensitivity]\nprotected = [\"data/**\"]\n");
        fixture.write("data/memo.txt", MEMO);
        fixture.write("data/ledger.csv", "loan_id,balance\n1,100\n2,200\n");
        fixture.tool(
            "shape",
            &format!("#!/bin/sh\nprintf '%s' '{SHAPE_REPORT}'\n"),
        );
        fixture.tool("profile", PROFILE_TOOL);
        fixture
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn state(&self) -> PathBuf {
        self.home().join(".cmdrvl/state/veil")
    }

    fn registry(&self) -> PathBuf {
        self.state().join("derived.jsonl")
    }

    fn key(&self) -> PathBuf {
        self.state().join("derived.key")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project().join(relative)
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, content).expect("fixture file");
    }

    fn tool(&self, name: &str, source: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, source).expect("fake tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable");
    }

    /// `veil` with nothing inherited: no harness session, no `VEIL_*`.
    fn veil(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_veil"));
        command
            .env_clear()
            .env("HOME", self.home())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .current_dir(self.project());
        command
    }

    fn exec_in(&self, session: Option<&str>, args: &[&str]) -> Output {
        let mut command = self.veil();
        if let Some(session) = session {
            command.env("CLAUDE_CODE_SESSION_ID", session);
        }
        command.arg("exec").args(args).output().expect("veil exec")
    }

    /// `veil exec` that must succeed, in the harness session `s1`.
    fn exec(&self, args: &[&str]) -> Output {
        let output = self.exec_in(Some("s1"), args);
        assert!(
            output.status.success(),
            "veil exec {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Runs a tool and saves what it printed, as `veil exec ... > to` would: a
    /// shell empties `to` before the tool starts.
    fn exec_to(&self, args: &[&str], to: &str) {
        self.write(to, "");
        let output = self.exec(args);
        fs::write(self.path(to), output.stdout).expect("redirected output");
    }

    fn hook(&self, session: &str, tool: &str, tool_input: Value) -> Verdict {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "session_id": session,
            "cwd": self.project(),
            "tool_name": tool,
            "tool_input": tool_input,
        });
        let mut child = self
            .veil()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("veil hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("payload");
        let output = child.wait_with_output().expect("hook exit");
        assert!(
            output.status.success(),
            "hook failed on {payload}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return Verdict {
                action: NO_DECISION.to_owned(),
                reason: String::new(),
            };
        }
        let document: Value = serde_json::from_slice(&output.stdout).expect("hook JSON");
        let nested = &document["hookSpecificOutput"];
        Verdict {
            action: nested["permissionDecision"]
                .as_str()
                .expect("an answer veil prints carries a decision")
                .to_owned(),
            reason: nested["permissionDecisionReason"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        }
    }

    fn read_in(&self, session: &str, path: impl AsRef<Path>) -> Verdict {
        self.hook(session, "Read", json!({"file_path": path.as_ref()}))
    }

    fn read(&self, relative: &str) -> Verdict {
        self.read_in("s1", self.path(relative))
    }

    fn bash(&self, command: &str) -> Verdict {
        self.hook("s1", "Bash", json!({"command": command}))
    }

    fn last_audit(&self) -> Value {
        let log = fs::read_to_string(self.home().join(".cmdrvl/logs/veil/audit.jsonl"))
            .expect("audit log");
        serde_json::from_str(log.lines().last().expect("a record")).expect("audit JSON")
    }

    fn assert_denied(&self, relative: &str, why: &str) -> Verdict {
        let verdict = self.read(relative);
        assert_eq!(verdict.action, "deny", "{why}: {relative}: {verdict:?}");
        verdict
    }

    /// Allowed *because* it is a registered derived output, as the audit log
    /// records it. An allow for any other reason would not count.
    fn assert_derived(&self, relative: &str, why: &str) {
        let verdict = self.read(relative);
        assert_eq!(verdict.action, "allow", "{why}: {relative}: {verdict:?}");
        let record = self.last_audit();
        assert_eq!(record["decision"], "allow", "{why}: {record}");
        assert!(
            record["reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("derived: ")),
            "{why}: {relative} was not allowed as derived: {record}"
        );
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_registered_output_is_readable_inside_a_protected_directory() {
    let fixture = Fixture::new();
    fixture.write("data/report.json", SHAPE_REPORT);
    fixture.assert_denied("data/report.json", "nothing is registered yet");

    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");

    fixture.assert_derived("data/report.json", "the broker returned these bytes");
    let grep = fixture.hook(
        "s1",
        "Grep",
        json!({"pattern": "rows", "path": fixture.path("data/report.json")}),
    );
    assert_eq!(grep.action, "allow", "a Grep of that one file: {grep:?}");
    fixture.assert_denied("data/ledger.csv", "the input stays protected");
    let search = fixture.hook(
        "s1",
        "Grep",
        json!({"pattern": "rows", "path": fixture.path("data")}),
    );
    assert_eq!(search.action, "deny", "a directory search: {search:?}");
    let cat = fixture.bash("cat data/report.json");
    assert_eq!(cat.action, "deny", "only Read and Grep use the registry");
}

#[test]
fn one_changed_byte_is_no_longer_derived() {
    let fixture = Fixture::new();
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");
    fixture.assert_derived("data/report.json", "as registered");

    let tampered = SHAPE_REPORT.replace("\"rows\":3", "\"rows\":4");
    fixture.write("data/report.json", &tampered);

    fixture.assert_denied("data/report.json", "one byte differs");
}

#[test]
fn a_report_name_unlocks_nothing() {
    let fixture = Fixture::new();
    // the registry exists and holds something else
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");

    fixture.write("data/memo-report.json", MEMO);
    fixture.assert_denied("data/memo-report.json", "a copy named like a report");

    // outside every protected directory, where a sensitivity pack flags the name
    fixture.write("exports/client-credentials-report.json", "{\"token\":1}\n");
    fixture.assert_denied(
        "exports/client-credentials-report.json",
        "a report name does not override a pack",
    );
}

#[test]
fn an_entry_ends_with_its_session_unless_persisted() {
    let fixture = Fixture::new();
    let report = fixture.path("data/report.json");
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");
    fixture.assert_derived("data/report.json", "the same session");

    let later = fixture.read_in("s2", &report);
    assert_eq!(later.action, "deny", "another session: {later:?}");
    assert!(later.reason.contains("another session"), "{}", later.reason);

    fixture.exec_to(
        &["--persist", "shape", "data/ledger.csv"],
        "data/report.json",
    );
    let kept = fixture.read_in("s2", &report);
    assert_eq!(kept.action, "allow", "--persist: {kept:?}");

    // a harness whose session veil cannot learn: only --persist lasts
    let fresh = Fixture::new();
    let output = fresh.exec_in(None, &["shape", "data/ledger.csv"]);
    fresh.write("data/report.json", &text(&output.stdout));
    fresh.assert_denied("data/report.json", "no session was recorded for the entry");
}

#[test]
fn a_forged_record_unlocks_nothing() {
    let fixture = Fixture::new();
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");
    // the hash an agent can learn from `hashbytes`
    let wanted = boundary_detectors::hash_match(MEMO.as_bytes());
    let real = fs::read_to_string(fixture.registry()).expect("registry");
    let real: Value = serde_json::from_str(real.lines().next().expect("record")).expect("JSON");

    let mut forged = Vec::new();
    // what a line written with the Write tool or a redirection can look like
    forged.push(json!({"hash": wanted, "files": [wanted], "tool": "shape",
        "argv_hash": wanted, "session": "s1", "persist": true, "ts": "1"}));
    let mut zero_mac = forged[0].clone();
    zero_mac["mac"] = json!("0".repeat(64));
    forged.push(zero_mac);
    // a real record, its MAC kept, pointed at the protected file
    let mut swapped = real.clone();
    swapped["files"] = json!([wanted]);
    forged.push(swapped);
    // the record format before bd-3qw
    forged.push(json!({"hash": wanted, "tool": "shape", "argv_hash": wanted,
        "session": "s1", "ts": "1"}));

    let mut registry = fs::OpenOptions::new()
        .append(true)
        .open(fixture.registry())
        .expect("registry");
    for line in &forged {
        writeln!(registry, "{line}").expect("forged line");
    }

    fixture.assert_denied("data/memo.txt", "no forged line carries a valid MAC");
    fixture.assert_derived("data/report.json", "the real record still counts");

    // a real record moved to another session, or made to persist
    for (field, value) in [("session", json!("s2")), ("persist", json!(true))] {
        let mut edited = real.clone();
        edited[field] = value;
        fs::write(fixture.registry(), format!("{edited}\n")).expect("edited registry");
        let verdict = fixture.read_in("s2", fixture.path("data/report.json"));
        assert_eq!(verdict.action, "deny", "edited `{field}`: {verdict:?}");
    }
}

#[test]
fn an_aliased_or_replaced_key_or_registry_unlocks_nothing() {
    let fixture = Fixture::new();
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");

    for (name, target) in [("registry", fixture.registry()), ("key", fixture.key())] {
        // bd-oao: a second name made before a sandbox was launched
        let alias = fixture.path(&format!("{name}-hardlink"));
        fs::hard_link(&target, &alias).expect("hard link");
        let verdict = fixture.assert_denied("data/report.json", "a file with two names");
        assert!(verdict.reason.contains("hard link"), "{}", verdict.reason);
        let refused = fixture.exec_in(Some("s1"), &["shape", "data/ledger.csv"]);
        assert!(!refused.status.success(), "{name}: exec wrote through it");
        assert!(refused.stdout.is_empty());
        fs::remove_file(&alias).expect("remove the alias");
        fixture.assert_derived("data/report.json", "one name again");

        // a symlink standing where the file was
        let moved = fixture.root.join("outside").join(name);
        fs::rename(&target, &moved).expect("move");
        symlink(&moved, &target).expect("symlink");
        fixture.assert_denied("data/report.json", "a symlinked file");
        fs::remove_file(&target).expect("remove the symlink");
        fs::rename(&moved, &target).expect("restore");
        fixture.assert_derived("data/report.json", "restored");
    }

    // another key: every record made under the old one is void
    fs::write(fixture.key(), [7u8; 32]).expect("replace the key");
    fixture.assert_denied("data/report.json", "a different key");

    // a key others on the machine could have read or written
    fs::set_permissions(fixture.key(), fs::Permissions::from_mode(0o644)).expect("mode");
    fixture.assert_denied("data/report.json", "a key with open permissions");
}

#[test]
fn exec_never_registers_a_raw_copy_of_a_protected_file() {
    let fixture = Fixture::new();
    for (mode, why) in [
        ("print", "the whole file"),
        ("print-excerpt", "200 bytes from the middle of it"),
        (
            "print-reflow",
            "those bytes, one word to a line, in capitals",
        ),
    ] {
        let output = fixture.exec(&["profile", mode, "data/memo.txt"]);
        let printed = text(&output.stdout);
        assert!(!printed.is_empty(), "{mode}: the tool printed nothing");
        assert!(
            text(&output.stderr).contains("not registered"),
            "{mode}: {}",
            text(&output.stderr)
        );
        fixture.write("data/copy.json", &printed);
        fixture.assert_denied("data/copy.json", why);
    }
    fixture.assert_denied("data/memo.txt", "the file itself");

    // too short to hold 24 bytes in a row, but the same bytes as a protected file
    fixture.write("data/pin.txt", "vault 4417\n");
    fixture.exec(&["profile", "print", "data/pin.txt"]);
    fixture.assert_denied("data/pin.txt", "identical to an input");

    // the control: output of the same tool that repeats nothing
    fixture.exec_to(
        &["profile", "print-summary", "data/memo.txt"],
        "data/ok.json",
    );
    fixture.assert_derived("data/ok.json", "a derived summary");
}

#[test]
fn a_file_written_under_out_is_checked_before_it_is_registered() {
    let fixture = Fixture::new();
    for (flag, name) in [("--out", "data/a.json"), ("--output", "data/b.json")] {
        fixture.exec(&["profile", "summary", "data/memo.txt", flag, name]);
        fixture.assert_derived(name, flag);
    }
    for (flag, name) in [("--out", "data/c.json"), ("--output", "data/d.json")] {
        let argument = format!("{flag}={name}");
        fixture.exec(&["profile", "summary", "data/memo.txt", &argument]);
        fixture.assert_derived(name, &argument);
    }
    // written outside the protected directory, then moved into it
    fixture.exec(&["profile", "summary", "data/memo.txt", "--out", "e.json"]);
    fs::rename(fixture.path("e.json"), fixture.path("data/e.json")).expect("move");
    fixture.assert_derived("data/e.json", "content, not name, carries the label");

    for (mode, why, refusal) in [
        ("copy", "a raw copy", "it copies or repeats text of"),
        (
            "excerpt",
            "an excerpt inside a report",
            "it copies or repeats text of",
        ),
        (
            "reflow",
            "a reflowed excerpt",
            "it copies or repeats text of",
        ),
        // the rows repeat no protected file, so only a detector can refuse them
        ("rows", "rows the detectors flag", "a detector flagged it"),
        ("binary", "binary output", "it is not text"),
        ("hardlink", "a second name of the input", "a hard link"),
        ("symlink", "a link to the input", "is a symlink"),
    ] {
        let target = format!("data/{mode}.json");
        let output = fixture.exec(&["profile", mode, "data/memo.txt", "--out", &target]);
        let said = text(&output.stderr);
        assert!(
            said.contains("not registered") && said.contains(refusal),
            "{mode}: expected `{refusal}`: {said}"
        );
        fixture.assert_denied(&target, why);
    }

    // the tool moves its protected input to the output path
    fixture.write("data/moving.txt", MEMO);
    fixture.exec(&[
        "profile",
        "move",
        "data/moving.txt",
        "--out",
        "data/moved.json",
    ]);
    fixture.assert_denied("data/moved.json", "the input, renamed");
}

#[test]
fn a_raw_copy_of_a_protected_file_not_named_on_the_command_line_is_not_registered() {
    let fixture = Fixture::new();
    // the tool is told only about a list; the list names the protected file
    fixture.write("list.txt", "data/memo.txt");

    fixture.exec(&["profile", "indirect", "list.txt", "--out", "data/via.json"]);

    fixture.assert_denied("data/via.json", "a protected file read through a manifest");

    // the control: the same indirection to a file that is not protected and
    // shares no text with one that is
    fixture.write("public.txt", PUBLIC_NOTE);
    fixture.write("public-list.txt", "public.txt");
    fixture.exec(&[
        "profile",
        "indirect",
        "public-list.txt",
        "--out",
        "data/pub.json",
    ]);
    fixture.assert_derived("data/pub.json", "nothing protected is repeated");

    // the same through standard output, saved as a redirect would
    fixture.exec_to(
        &["profile", "print-indirect", "list.txt"],
        "data/saved.json",
    );
    assert_eq!(
        fs::read_to_string(fixture.path("data/saved.json")).expect("saved"),
        MEMO,
        "the tool printed the protected file"
    );
    fixture.assert_denied("data/saved.json", "printed through a manifest");
    fixture.assert_denied("data/memo.txt", "the file the manifest names");
}

/// A bare name in `protected` covers the whole project, so the comparison does
/// too: running from a subdirectory does not hide a file from it.
#[test]
fn a_name_pattern_is_compared_across_the_project_not_only_under_the_call() {
    let fixture = Fixture::new();
    fixture.write(
        ".veil.toml",
        "[sensitivity]\nprotected = [\"data/**\", \"*.vault.txt\"]\n",
    );
    let vault = "The second tranche releases only after the escrow agent confirms receipt of \
every original deed, countersigned by both trustees, at the registry office on the quay.\n";
    fixture.write("terms.vault.txt", vault);
    fixture.write("work/list.txt", "../terms.vault.txt");
    let run_from_work = |args: &[&str]| {
        let output = fixture
            .veil()
            .current_dir(fixture.path("work"))
            .env("CLAUDE_CODE_SESSION_ID", "s1")
            .arg("exec")
            .args(args)
            .output()
            .expect("veil exec");
        assert!(output.status.success(), "{}", text(&output.stderr));
        output
    };

    let output = run_from_work(&["profile", "print-indirect", "list.txt"]);
    assert_eq!(text(&output.stdout), vault, "the tool printed the file");
    assert!(
        text(&output.stderr).contains("not registered"),
        "{}",
        text(&output.stderr)
    );
    fixture.write("data/saved.json", vault);
    fixture.assert_denied("data/saved.json", "a name-protected file above the call");

    // the control: from the same place, a file that is not protected
    fixture.write("work/public.txt", PUBLIC_NOTE);
    fixture.write("work/public-list.txt", "public.txt");
    let output = run_from_work(&["profile", "print-indirect", "public-list.txt"]);
    fixture.write("data/public-copy.json", &text(&output.stdout));
    fixture.assert_derived("data/public-copy.json", "it repeats nothing protected");
}

/// What veil registered is not what later outputs are compared with: two runs
/// of a tool share most of their text.
#[test]
fn an_earlier_registered_output_does_not_block_the_next_one() {
    let fixture = Fixture::new();
    for name in ["data/first.json", "data/second.json"] {
        fixture.exec(&["profile", "summary", "data/ledger.csv", "--out", name]);
        fixture.assert_derived(name, "the same shape as the one before it");
    }

    // the control: the same run beside such a file that veil did not register
    let fresh = Fixture::new();
    fresh.write(
        "data/first.json",
        "{\"profile\":\"first.json\",\"columns\":4,\"null_rate\":0.0}\n",
    );
    fresh.exec(&[
        "profile",
        "summary",
        "data/ledger.csv",
        "--out",
        "data/second.json",
    ]);
    fresh.assert_denied(
        "data/second.json",
        "it repeats text of an unregistered file",
    );
}

#[test]
fn a_file_that_existed_before_the_run_is_never_registered() {
    let fixture = Fixture::new();
    // the tool ignores --out, leaving the protected file that was already there
    fixture.exec(&[
        "profile",
        "nothing",
        "data/ledger.csv",
        "--output",
        "data/memo.txt",
    ]);
    fixture.assert_denied("data/memo.txt", "it existed before the run");

    // a link that existed before the run, pointing at the protected file
    symlink(
        fixture.path("data/memo.txt"),
        fixture.path("data/link.json"),
    )
    .expect("symlink");
    fixture.exec(&[
        "profile",
        "nothing",
        "data/ledger.csv",
        "--out",
        "data/link.json",
    ]);
    fixture.assert_denied("data/memo.txt", "named through a link");

    // even a clean overwrite is not taken: veil cannot tell it from no write
    fixture.write("data/old.json", "{}\n");
    fixture.exec(&[
        "profile",
        "rewrite",
        "data/ledger.csv",
        "--out",
        "data/old.json",
    ]);
    fixture.assert_denied("data/old.json", "overwrote an existing file");

    // a new path does not help while those bytes sit in a protected file that
    // veil has not registered
    fixture.exec(&[
        "profile",
        "rewrite",
        "data/ledger.csv",
        "--out",
        "data/twin.json",
    ]);
    fixture.assert_denied("data/twin.json", "the same bytes as data/old.json");

    // the control: the same write where no such file exists
    let fresh = Fixture::new();
    fresh.exec(&[
        "profile",
        "rewrite",
        "data/ledger.csv",
        "--out",
        "data/new.json",
    ]);
    fresh.assert_derived("data/new.json", "new in this run");
}

#[test]
fn a_directory_written_under_out_registers_only_what_passes() {
    let fixture = Fixture::new();

    fixture.exec(&[
        "profile",
        "directory",
        "data/memo.txt",
        "--out",
        "data/pack",
    ]);

    fixture.assert_derived("data/pack/manifest.json", "the manifest repeats nothing");
    fixture.assert_denied("data/pack/member.txt", "the member is the input");
}

#[test]
fn a_file_too_large_to_hash_is_refused_as_too_large_to_verify() {
    let fixture = Fixture::new();
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");
    let huge = fs::File::create(fixture.path("data/huge.json")).expect("huge file");
    huge.set_len(64 * 1024 * 1024 + 1).expect("sparse length");

    let verdict = fixture.assert_denied("data/huge.json", "over 64 MiB");

    assert!(
        verdict.reason.contains("too_large_to_verify"),
        "{}",
        verdict.reason
    );
}

#[test]
fn the_registry_rotates_and_an_entry_leaves_with_the_oldest_file() {
    let fixture = Fixture::new();
    let first = fixture.exec(&["--persist", "profile", "print-summary", "data/ledger.csv"]);
    fixture.write("data/first.json", &text(&first.stdout));
    fixture.assert_derived("data/first.json", "before any rotation");

    let junk = "{\"junk\":true}\n".repeat(800_000);
    assert!(junk.len() >= 10 * 1024 * 1024);
    let fill_and_register = |fixture: &Fixture| {
        fs::OpenOptions::new()
            .append(true)
            .open(fixture.registry())
            .and_then(|mut file| file.write_all(junk.as_bytes()))
            .expect("fill the registry");
        fixture.exec_to(
            &["--persist", "shape", "data/ledger.csv"],
            "data/latest.json",
        );
    };

    for rotation in 1..=5 {
        fill_and_register(&fixture);
        assert!(
            fixture
                .state()
                .join(format!("derived.jsonl.{rotation}"))
                .exists(),
            "rotation {rotation}"
        );
        assert!(
            fs::metadata(fixture.registry()).expect("registry").len() < 4096,
            "the current file starts again"
        );
        fixture.assert_derived("data/first.json", "still in a kept file");
        fixture.assert_derived("data/latest.json", "in the current file");
    }
    fill_and_register(&fixture);

    assert!(!fixture.state().join("derived.jsonl.6").exists());
    fixture.assert_denied("data/first.json", "its file was dropped");
}

#[test]
fn no_tool_call_reads_or_writes_the_key_or_registry() {
    let fixture = Fixture::new();
    fixture.exec(&["shape", "data/ledger.csv"]);
    let state = fixture.state().display().to_string();
    let home = fixture.home().display().to_string();
    // other names for the key that were made out of the hook's sight, and
    // directories that hold neither a protected path nor an obvious mention
    let outside = fixture.root.join("outside");
    let hard = outside.join("second-name");
    let soft = outside.join("pointer");
    fs::hard_link(fixture.key(), &hard).expect("hard link");
    symlink(fixture.key(), &soft).expect("symlink");
    let outside = outside.display().to_string();
    let commands = [
        format!("cat {outside}/second-name"),
        format!("cat {outside}/pointer"),
        format!("grep -r x {home}"),
        format!("rg x {home}/.cmdrvl"),
        format!("cp -r {home} {outside}/copy"),
        format!("tar cf {outside}/home.tar {home}/.cmdrvl/state"),
        format!("cat {state}/derived.key"),
        format!("head -c 32 {state}/derived.key"),
        format!("cp {state}/derived.key k"),
        format!("ln {state}/derived.jsonl ledger"),
        format!("ln -s {state}/derived.key k"),
        format!("hashbytes {state}/derived.key"),
        format!("profile print {state}/derived.key"),
        format!("pack seal {home}/.cmdrvl --output out"),
        format!("vacuum {home}"),
        format!("echo x > {state}/derived.key"),
        format!("echo x >{state}/derived.key"),
        format!("echo x>>{state}/derived.jsonl"),
        format!("echo x >| {state}/derived.key"),
        format!("echo x &>{state}/derived.key"),
        format!("echo x 2>>{state}/derived.jsonl"),
        format!("shape data/ledger.csv >>{state}/derived.jsonl"),
        format!("echo x >{state}/derived.jsonl.1"),
        "echo x >$HOME/.cmdrvl/state/veil/derived.key".to_owned(),
        "echo x >~/.cmdrvl/state/veil/derived.key".to_owned(),
        format!("cd {state} && echo x >derived.key"),
        format!("cd {state} && cp {home}/k derived.key"),
        format!("tee {state}/derived.key"),
        format!("dd if=/dev/zero of={state}/derived.key bs=32 count=1"),
        format!("truncate -s 32 {state}/derived.key"),
        format!("mv {state} {home}/old"),
        format!("mv {home}/prepared {state}"),
        format!("mv {home}/.cmdrvl {home}/old"),
        format!("python3 -c \"open('{state}/derived.key','w').write('x')\""),
        format!("sh -c 'echo x >{state}/derived.key'"),
        // a glob the shell expands to one of them
        format!("cat {state}/derived.k*"),
        format!("cat {state}/*"),
        format!("cat {home}/.cmdrvl/st*/veil/derived.k?y"),
        format!("head -c 32 {home}/.cmd*/state/veil/[d]erived.key"),
        format!("echo x > {state}/derived.k*"),
    ];

    for policy in ["deny", "log"] {
        // policy `log` waves protected reads through; it does not wave these
        fixture.write(
            ".veil.toml",
            &format!(
                "[sensitivity]\nprotected = [\"data/**\"]\n[policy]\ndefault = \"{policy}\"\n"
            ),
        );
        for command in &commands {
            let verdict = fixture.bash(command);
            assert_eq!(verdict.action, "deny", "{policy}: `{command}`: {verdict:?}");
        }
        for file in [
            fixture.key(),
            fixture.registry(),
            hard.clone(),
            soft.clone(),
        ] {
            let read = fixture.read_in("s1", &file);
            assert_eq!(read.action, "deny", "{policy}: Read {file:?}: {read:?}");
            let mcp = fixture.hook("s1", "mcp__files__read", json!({"path": file}));
            assert_eq!(mcp.action, "deny", "{policy}: MCP {file:?}: {mcp:?}");
        }
        for directory in [
            fixture.state(),
            fixture.home().join(".cmdrvl"),
            fixture.home(),
        ] {
            let search = fixture.hook(
                "s1",
                "Grep",
                json!({"pattern": "x", "path": directory, "output_mode": "content"}),
            );
            assert_eq!(
                search.action, "deny",
                "{policy}: Grep {directory:?}: {search:?}"
            );
        }
    }

    for command in [
        format!("ls -la {state}"),
        "veil derived list".to_owned(),
        "echo derived.key > notes.txt".to_owned(),
        "echo x > derived.key".to_owned(),
        format!("cd {home}/.cmdrvl && ls"),
        // globs that cannot expand to one of them (`*` skips hidden names)
        format!("cat {home}/*.txt"),
        format!("cat {home}/*/state/veil/derived.key"),
        "cat notes/derived.*".to_owned(),
    ] {
        let verdict = fixture.bash(&command);
        assert_eq!(verdict.action, "allow", "`{command}`: {verdict:?}");
    }
}

#[test]
fn write_tools_cannot_touch_the_key_or_registry() {
    let fixture = Fixture::new();
    fixture.exec(&["shape", "data/ledger.csv"]);
    let state = fixture.state();
    symlink(fixture.key(), fixture.path("key-link")).expect("symlink");
    symlink(&state, fixture.path("state-link")).expect("directory symlink");
    // a link to a file veil has not made yet
    symlink(state.join("derived.jsonl.1"), fixture.path("dangling")).expect("dangling");
    fs::hard_link(fixture.registry(), fixture.path("ledger-hardlink")).expect("hardlink");

    let mut targets = vec![
        fixture.key(),
        fixture.registry(),
        state.join("derived.jsonl.1"),
        state.join("derived.jsonl.5"),
        state.join("../veil/derived.key"),
        state.clone(),
        fixture.path("key-link"),
        fixture.path("state-link/derived.key"),
        fixture.path("dangling"),
        fixture.path("ledger-hardlink"),
        PathBuf::from("../home/.cmdrvl/state/veil/derived.key"),
        PathBuf::from("~/.cmdrvl/state/veil/derived.key"),
    ];
    if cfg!(target_os = "macos") {
        // the default filesystem there ignores case
        targets.push(fixture.home().join(".CMDRVL/State/Veil/DERIVED.KEY"));
    }

    // the guard needs no configuration, so a broken one cannot switch it off
    for config in ["[sensitivity]\nprotected = [\"data/**\"]\n", "not toml ["] {
        fixture.write(".veil.toml", config);
        for target in &targets {
            for (tool, field) in [
                ("Write", "file_path"),
                ("Edit", "file_path"),
                ("MultiEdit", "file_path"),
                ("NotebookEdit", "notebook_path"),
            ] {
                let verdict = fixture.hook("s1", tool, json!({field: target, "content": "x"}));
                assert_eq!(verdict.action, "deny", "{tool} {target:?}: {verdict:?}");
            }
        }
        // any other file is left to the harness: `allow` would skip its
        // permission prompt, so veil must not say it
        for target in [
            fixture.path("notes.md"),
            fixture.path("derived.key"),
            fixture.path("data/new.csv"),
            fixture.home().join(".cmdrvl/state/other/file"),
        ] {
            for tool in ["Write", "Edit", "MultiEdit"] {
                let verdict =
                    fixture.hook("s1", tool, json!({"file_path": target, "content": "x"}));
                assert_eq!(
                    verdict.action, NO_DECISION,
                    "{tool} {target:?}: {verdict:?}"
                );
            }
        }
    }
}

#[test]
fn exec_refuses_to_run_a_tool_against_veil_state() {
    let fixture = Fixture::new();
    fixture.exec(&["shape", "data/ledger.csv"]);
    let key_before = fs::read(fixture.key()).expect("key");
    // 32 chosen bytes, which a copying tool could put where the key is
    fixture.write("chosen.key", &"k".repeat(32));
    let key = fixture.key().display().to_string();
    let state = fixture.state().display().to_string();
    let home = fixture.home().display().to_string();
    let output_flag = format!("--output={key}");
    let cases: [&[&str]; 6] = [
        &["profile", "copy", "chosen.key", "--out", &key],
        &["profile", "copy", "chosen.key", &output_flag],
        &["profile", "copy", "chosen.key", "--out", &state],
        &["profile", "print", &key],
        &["profile", "directory", &state, "--out", "stolen"],
        &["profile", "print", &home],
    ];

    for arguments in cases {
        let output = fixture.exec_in(Some("s1"), arguments);
        assert!(!output.status.success(), "{arguments:?} ran");
        assert!(output.stdout.is_empty(), "{arguments:?} printed");
        assert!(
            text(&output.stderr).contains("broker_veil_state_forbidden"),
            "{arguments:?}: {}",
            text(&output.stderr)
        );
    }
    assert_eq!(fs::read(fixture.key()).expect("key"), key_before);
}

#[test]
fn derived_list_and_verify_report_the_registry() {
    let fixture = Fixture::new();
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");

    let list = fixture
        .veil()
        .args(["derived", "list", "--json"])
        .output()
        .expect("list");
    assert!(list.status.success(), "{}", text(&list.stderr));
    let document: Value = serde_json::from_slice(&list.stdout).expect("list JSON");
    let entries = document["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "{document}");
    assert_eq!(entries[0]["tool"], "shape");
    assert_eq!(entries[0]["session"], "s1");
    assert_eq!(entries[0]["valid"], true);

    let verify = |path: &str| {
        let output = fixture
            .veil()
            .args(["derived", "verify", path, "--json"])
            .output()
            .expect("verify");
        let document: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", text(&output.stderr)));
        (output.status.code(), document)
    };
    let (code, found) = verify("data/report.json");
    assert_eq!(
        (code, &found["status"]),
        (Some(0), &json!("registered")),
        "{found}"
    );
    assert_eq!(found["entries"][0]["session"], "s1");
    // an agent's own `veil derived verify` of a protected path is a command
    // that names it: only Read and Grep use the registry
    let asked = fixture.bash("veil derived verify data/report.json");
    assert_eq!(asked.action, "deny", "{asked:?}");
    let (code, missing) = verify("data/memo.txt");
    assert_eq!(
        (code, &missing["status"]),
        (Some(1), &json!("not_registered")),
        "{missing}"
    );

    fs::hard_link(fixture.registry(), fixture.path("alias")).expect("hardlink");
    let (code, refused) = verify("data/report.json");
    assert_eq!(
        (code, &refused["status"]),
        (Some(1), &json!("registry_refused")),
        "{refused}"
    );
}

#[test]
fn install_adds_the_write_guard() {
    let fixture = Fixture::new();

    let output = fixture.veil().arg("install").output().expect("install");

    assert!(output.status.success(), "{}", text(&output.stderr));
    let settings =
        fs::read_to_string(fixture.home().join(".claude/settings.json")).expect("settings");
    let settings: Value = serde_json::from_str(&settings).expect("settings JSON");
    let entries = settings["hooks"]["PreToolUse"].as_array().expect("entries");
    for tool in ["Write", "Edit", "MultiEdit", "NotebookEdit"] {
        let covered = entries.iter().any(|entry| {
            entry["matcher"]
                .as_str()
                .is_some_and(|matcher| matcher.split('|').any(|name| name == tool))
        });
        assert!(covered, "no veil hook for {tool}: {settings}");
    }
}

/// bd-oao, replayed: a second name for the registry or key, made before launch,
/// sits in a place the confined process may write or read.
#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_does_not_launch_over_an_aliased_registry_and_denies_the_key() {
    let fixture = Fixture::short();
    fixture.exec(&["shape", "data/ledger.csv"]);
    let sandbox = |script: &str| {
        fixture
            .veil()
            .args(["sandbox", "--", "/bin/sh", "-c", script])
            .output()
            .expect("veil sandbox")
    };

    for (name, target) in [("registry", fixture.registry()), ("key", fixture.key())] {
        let alias = fixture.path(&format!("{name}-hardlink"));
        fs::hard_link(&target, &alias).expect("hard link made before launch");
        let before = fs::read(&target).expect("contents");
        let output = sandbox("echo LAUNCHED; echo forged >> *-hardlink");
        assert!(!output.status.success(), "{name}: the sandbox launched");
        assert!(!text(&output.stdout).contains("LAUNCHED"), "{name}");
        assert!(
            text(&output.stderr).contains("hard link"),
            "{name}: {}",
            text(&output.stderr)
        );
        assert_eq!(fs::read(&target).expect("contents"), before, "{name}");
        fs::remove_file(&alias).expect("remove the alias");
    }

    // a registered output, and the hook's question about it
    fixture.exec_to(&["shape", "data/ledger.csv"], "data/report.json");
    fixture.assert_derived("data/report.json", "outside the sandbox");
    let question = json!({
        "session_id": "s1",
        "cwd": fixture.project(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": fixture.path("data/report.json")},
    });

    let output = sandbox(&format!(
        "echo LAUNCHED
         cat \"$HOME/.cmdrvl/state/veil/derived.key\" >/dev/null 2>&1 && echo KEY_READ
         cat \"$HOME/.cmdrvl/state/veil/derived.jsonl\" >/dev/null 2>&1 && echo REGISTRY_READ
         (echo x >> \"$HOME/.cmdrvl/state/veil/derived.key\") 2>/dev/null && echo KEY_WRITTEN
         printf '%s' '{question}' | '{veil}'
         echo \" HOOK_EXIT=$?\"
         '{veil}' exec shape data/ledger.csv",
        veil = env!("CARGO_BIN_EXE_veil")
    ));
    let stdout = text(&output.stdout);
    // the registry is out of the confined hook's reach, so it unlocks nothing
    // there, and the hook still answers
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "{stdout}: {}",
        text(&output.stderr)
    );
    assert!(stdout.contains("HOOK_EXIT=0"), "{stdout}");
    assert!(stdout.contains("LAUNCHED"), "{}", text(&output.stderr));
    for leak in ["KEY_READ", "REGISTRY_READ", "KEY_WRITTEN"] {
        assert!(!stdout.contains(leak), "{leak}: {stdout}");
    }
    // the broker, outside confinement, still reads the key and registers
    assert!(
        stdout.contains(SHAPE_REPORT.trim_end()),
        "{stdout}: {}",
        text(&output.stderr)
    );
}
