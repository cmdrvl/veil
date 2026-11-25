#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// Written on every record as `schema_version`. The records before it came in
/// generations with different keys and nothing to tell them apart; a reader
/// that meets any other value, or none, is looking at a legacy record.
pub const SCHEMA_VERSION: &str = "veil.audit.v1";

/// The audit log is rotated when it reaches this size...
pub const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// ...and this many rotated files are kept next to it (`audit.jsonl.1` is the
/// newest, `audit.jsonl.5` the oldest). The one after that is deleted: that is
/// how the log stays bounded.
pub const ROTATED_FILES: usize = 5;

/// The fields a line needs to be an audit entry at all, in any generation.
const REQUIRED_FIELDS: [&str; 4] = ["ts", "tool", "path", "decision"];

/// How many unparseable line numbers a validation report lists.
pub const LISTED_BAD_LINES: usize = 20;

#[derive(Clone, Debug, PartialEq)]
pub struct AuditRecord {
    pub ts: String,
    pub tool: String,
    pub path: String,
    pub decision: String,
    pub reason: Option<String>,
    pub sensitivity: Option<String>,
    pub confidence: Option<f32>,
    pub session_id: Option<String>,
    /// How the evaluated command was reached: `top`, `subshell` (inside `$( )`
    /// or backticks) or `wrapper` (`sh -c`, `xargs`, `find -exec`, `uv run`...).
    /// A Read or Grep call is `top`.
    pub origin: Option<String>,
    /// What kind of reference the path was: `direct_read` (a Read or Grep call,
    /// or a command veil recognises as a reader: `cat`, `grep`, a `<`
    /// redirect...) or `argv_path` (a path named in the words of any other
    /// command: `awk 1 x.csv`, `cp x.csv /tmp`, `curl -F f=@x.csv`). Lets an
    /// operator tell the readers veil knew about from the generic rule.
    pub reason_class: Option<String>,
    /// `egress` when the command sends what it is given somewhere else (`curl`,
    /// `scp`, `aws`, a mail client...) and the path it names is protected: the
    /// record `veil audit --class egress` answers "did anything try to leave"
    /// from. Null for every other record, whatever its `reason_class`.
    pub class: Option<String>,
}

impl AuditRecord {
    pub fn to_json_value(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "ts": self.ts,
            "tool": self.tool,
            "path": self.path,
            "decision": self.decision,
            "reason": self.reason,
            "sensitivity": self.sensitivity,
            "confidence": self.confidence,
            "session_id": self.session_id,
            "origin": self.origin,
            "reason_class": self.reason_class,
            "class": self.class,
        })
    }
}

pub fn default_audit_path() -> io::Result<PathBuf> {
    default_audit_path_from(env::var_os("HOME").map(PathBuf::from))
}

fn default_audit_path_from(home: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(home_dir) = home {
        return Ok(home_dir
            .join(".cmdrvl")
            .join("logs")
            .join("veil")
            .join("audit.jsonl"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "unable to resolve default CMD+RVL audit path from HOME",
    ))
}

pub fn append_default_audit_record(record: &AuditRecord) -> io::Result<PathBuf> {
    let path = default_audit_path()?;
    append_audit_record(&path, record)?;
    Ok(path)
}

pub fn append_audit_record(path: &Path, record: &AuditRecord) -> io::Result<()> {
    append_audit_record_rotating(path, record, ROTATE_BYTES, ROTATED_FILES)
}

/// Appends one record as one line, after rotating a log that has reached
/// `max_bytes` and keeping `keep` rotated files.
///
/// The line is built first and handed over in a single `write`. Written piece
/// by piece (which `serde_json::to_writer` does on an unbuffered file: a call
/// per token), two hooks running at once interleave their bytes and neither
/// record can be read back.
///
/// A rotation that failed does not stop the record being written; it is
/// reported once the record is safe.
pub fn append_audit_record_rotating(
    path: &Path,
    record: &AuditRecord,
    max_bytes: u64,
    keep: usize,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let rotation = rotate_if_full(path, max_bytes, keep);

    let mut line = serde_json::to_vec(&record.to_json_value())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    line.push(b'\n');

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&line)?;
    file.flush()?;

    rotation
}

/// The `index`th rotated file next to `path`: `audit.jsonl.1`, `audit.jsonl.2`...
pub fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// Moves a log that has reached `max_bytes` to `.1`, each rotated file up one
/// place, and drops what would be past `keep`.
///
/// Hooks run in parallel, so the move is made under an advisory lock on
/// `<log>.lock` and the size is looked at again once it is held: of the hooks
/// that find the log full, one rotates it and the rest find it small. Without
/// that, each of the rest would rotate the fresh, nearly empty log as well, and
/// every one of those pushes the oldest real file out of the `keep` kept.
fn rotate_if_full(path: &Path, max_bytes: u64, keep: usize) -> io::Result<()> {
    if !is_full(path, max_bytes)? {
        return Ok(());
    }

    let mut lock_name: OsString = path.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(PathBuf::from(lock_name))?;
    // released when `lock` is dropped, or if this process dies
    lock.lock()?;

    // another hook may have rotated while this one waited
    if !is_full(path, max_bytes)? {
        return Ok(());
    }

    let keep = keep.max(1);
    // each file moves over the one after it, so the oldest is replaced
    for index in (1..keep).rev() {
        match fs::rename(rotated_path(path, index), rotated_path(path, index + 1)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::rename(path, rotated_path(path, 1))
}

fn is_full(path: &Path, max_bytes: u64) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len() >= max_bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// One line of an audit log, read back.
#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    Blank,
    /// A JSON object with the fields every generation of the log has
    /// (`ts`, `tool`, `path`, `decision`). `current` is whether it carries this
    /// build's `schema_version`; a record without it is a legacy record, still
    /// readable.
    Entry {
        fields: Value,
        current: bool,
    },
    /// Not UTF-8, not JSON, not an object, or an object that cannot be an audit
    /// entry. Two hooks writing at once used to leave lines like this.
    Unparseable,
}

pub fn parse_line(bytes: &[u8]) -> Line {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Line::Unparseable;
    };
    if text.trim().is_empty() {
        return Line::Blank;
    }
    let Ok(fields @ Value::Object(_)) = serde_json::from_str::<Value>(text) else {
        return Line::Unparseable;
    };
    if !REQUIRED_FIELDS
        .iter()
        .all(|field| fields.get(*field).is_some_and(Value::is_string))
    {
        return Line::Unparseable;
    }

    let current = fields.get("schema_version").and_then(Value::as_str) == Some(SCHEMA_VERSION);
    Line::Entry { fields, current }
}

/// What reading a whole audit log came to.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validation {
    /// Every line, blank ones included.
    pub lines: usize,
    pub blank: usize,
    /// Carry this build's `schema_version`.
    pub current: usize,
    /// Readable, but from before `schema_version` (or from another version).
    pub legacy: usize,
    pub unparseable: usize,
    /// 1-based numbers of the first [`LISTED_BAD_LINES`] unparseable lines.
    pub unparseable_lines: Vec<usize>,
}

/// Reads every line of `reader` and sorts it. A line that cannot be read does not
/// stop the count: finding those is what this is for.
pub fn validate(reader: impl BufRead) -> io::Result<Validation> {
    let mut report = Validation::default();

    for (index, line) in reader.split(b'\n').enumerate() {
        report.lines += 1;
        match parse_line(&line?) {
            Line::Blank => report.blank += 1,
            Line::Entry { current: true, .. } => report.current += 1,
            Line::Entry { current: false, .. } => report.legacy += 1,
            Line::Unparseable => {
                report.unparseable += 1;
                if report.unparseable_lines.len() < LISTED_BAD_LINES {
                    report.unparseable_lines.push(index + 1);
                }
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_record() -> AuditRecord {
        AuditRecord {
            ts: "2026-03-01T16:00:00Z".to_owned(),
            tool: "Read".to_owned(),
            path: "data/clients/holdings.csv".to_owned(),
            decision: "deny".to_owned(),
            reason: Some("Protected by data.tabular".to_owned()),
            sensitivity: Some("data.tabular".to_owned()),
            confidence: Some(0.95),
            session_id: Some("session-123".to_owned()),
            origin: Some("top".to_owned()),
            reason_class: Some("direct_read".to_owned()),
            class: None,
        }
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after the Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!("veil-{name}-{nanos}"))
    }

    #[test]
    fn default_path_uses_cmdrvl_logs_root() {
        let path = default_audit_path_from(Some(PathBuf::from("/tmp/home")))
            .expect("home path should resolve");

        assert_eq!(
            path,
            PathBuf::from("/tmp/home/.cmdrvl/logs/veil/audit.jsonl")
        );
    }

    #[test]
    fn default_path_errors_without_any_base_directory() {
        let error = default_audit_path_from(None).expect_err("missing HOME should return an error");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn append_creates_parent_directories_and_writes_valid_jsonl() {
        let record = fixture_record();
        let path = unique_temp_dir("audit-write")
            .join("state")
            .join("audit.jsonl");

        append_audit_record(&path, &record).expect("append should succeed");

        let file = fs::File::open(&path).expect("audit file should exist");
        let mut lines = BufReader::new(file).lines();
        let value: Value = serde_json::from_str(
            &lines
                .next()
                .expect("one line should exist")
                .expect("line should be readable"),
        )
        .expect("line should be valid JSON");

        assert_eq!(value["tool"], "Read");
        assert_eq!(value["decision"], "deny");
        assert_eq!(value["session_id"], "session-123");
        assert_eq!(value["origin"], "top");
        assert_eq!(value["schema_version"], "veil.audit.v1");
    }

    fn numbered(number: usize, padding: usize) -> AuditRecord {
        AuditRecord {
            path: format!("p{number}"),
            reason: Some("x".repeat(padding)),
            ..fixture_record()
        }
    }

    fn lines_of(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn numbers_in(path: &Path) -> Vec<usize> {
        lines_of(path)
            .iter()
            .map(|line| {
                let value: Value = serde_json::from_str(line).expect("line should parse");
                value["path"].as_str().expect("path")[1..]
                    .parse()
                    .expect("a number")
            })
            .collect()
    }

    #[test]
    fn records_written_at_the_same_time_stay_whole_lines() {
        // Written token by token, 8 writers of kilobyte records interleave their
        // bytes (the real log has 100 such lines). Written as one `write`, every
        // line reads back.
        let path = unique_temp_dir("audit-concurrent").join("audit.jsonl");
        let writers = 8;
        let each = 150;

        std::thread::scope(|scope| {
            for writer in 0..writers {
                let path = &path;
                scope.spawn(move || {
                    for number in 0..each {
                        append_audit_record(path, &numbered(writer * 1000 + number, 1500))
                            .expect("append should succeed");
                    }
                });
            }
        });

        let report = validate(io::BufReader::new(fs::File::open(&path).expect("log")))
            .expect("log should be readable");
        assert_eq!(report.lines, writers * each);
        assert_eq!(report.current, writers * each, "{report:?}");
        assert_eq!(report.unparseable, 0, "{report:?}");
        let mut seen = numbers_in(&path);
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), writers * each, "no record lost or repeated");
    }

    #[test]
    fn a_full_log_rotates_and_only_the_newest_files_are_kept() {
        let path = unique_temp_dir("audit-rotate").join("audit.jsonl");
        let keep = 3;

        for number in 0..40 {
            append_audit_record_rotating(&path, &numbered(number, 300), 1500, keep)
                .expect("append should succeed");
        }

        for index in 1..=keep {
            assert!(
                rotated_path(&path, index).exists(),
                "audit.jsonl.{index} should exist"
            );
        }
        assert!(
            !rotated_path(&path, keep + 1).exists(),
            "a file past `keep` is not kept"
        );

        // newest in the log, then .1, .2, .3: each holds older records than the last
        let mut files = vec![numbers_in(&path)];
        files.extend((1..=keep).map(|index| numbers_in(&rotated_path(&path, index))));
        assert_eq!(
            files[0].last(),
            Some(&39),
            "the newest record is in the log"
        );
        for pair in files.windows(2) {
            let (newer, older) = (&pair[0], &pair[1]);
            assert!(!newer.is_empty() && !older.is_empty(), "{files:?}");
            assert!(
                older.iter().max() < newer.iter().min(),
                "older files hold older records: {files:?}"
            );
        }
        // what is kept is contiguous: rotation drops the oldest, never the middle
        let mut kept: Vec<usize> = files.concat();
        kept.sort_unstable();
        assert_eq!(kept.last(), Some(&39));
        assert!(
            kept.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "{kept:?}"
        );
        // and a log under the limit is not rotated
        let quiet = unique_temp_dir("audit-quiet").join("audit.jsonl");
        append_audit_record_rotating(&quiet, &numbered(1, 10), 1500, keep).expect("append");
        assert!(!rotated_path(&quiet, 1).exists());
    }

    #[test]
    fn a_hook_that_waited_for_the_lock_does_not_rotate_the_log_another_hook_just_rotated() {
        let dir = unique_temp_dir("audit-rotate-waits");
        let path = dir.join("audit.jsonl");
        fs::create_dir_all(&dir).expect("dir");
        fs::write(&path, "x".repeat(400)).expect("a full log");

        // This test plays the hook that holds the lock...
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("audit.jsonl.lock"))
            .expect("lock file");
        lock.lock().expect("lock");

        std::thread::scope(|scope| {
            // ...while this hook finds the log full and waits for it.
            let waiting = scope.spawn(|| {
                append_audit_record_rotating(&path, &numbered(2, 10), 400, 5).expect("append")
            });
            // A hook that has not reached its size check yet would see the
            // small log below and not wait at all, which passes whatever the
            // code does: the pause only makes the test as strict as it can be.
            std::thread::sleep(std::time::Duration::from_millis(300));

            // The lock holder rotates and starts a fresh log with a record.
            fs::rename(&path, rotated_path(&path, 1)).expect("rotate");
            let fresh = fixture_record().to_json_value().to_string();
            fs::write(&path, format!("{fresh}\n")).expect("fresh log");
            drop(lock);

            waiting.join().expect("the waiting hook finishes");
        });

        assert!(
            !rotated_path(&path, 2).exists(),
            "the fresh log is small: rotating it too would push a real file out of the five"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 1)).expect(".1"),
            "x".repeat(400),
            "the full log stays the first rotated file"
        );
        assert_eq!(
            lines_of(&path).len(),
            2,
            "the fresh record and the waiter's"
        );
    }

    #[test]
    fn hooks_that_find_the_log_full_together_rotate_it_once() {
        // `keep` is large so nothing is dropped: every record must be somewhere.
        // A log is only ever rotated when it is full, so no rotated file is
        // smaller than the limit; one that is was rotated twice.
        let path = unique_temp_dir("audit-rotate-race").join("audit.jsonl");
        let writers = 6;
        let each = 60;

        std::thread::scope(|scope| {
            for writer in 0..writers {
                let path = &path;
                scope.spawn(move || {
                    for number in 0..each {
                        append_audit_record_rotating(
                            path,
                            &numbered(writer * 1000 + number, 200),
                            2000,
                            500,
                        )
                        .expect("append should succeed");
                    }
                });
            }
        });

        let mut seen = numbers_in(&path);
        for index in 1..500 {
            let rotated = rotated_path(&path, index);
            if !rotated.exists() {
                break;
            }
            let size = fs::metadata(&rotated).expect("rotated file").len();
            assert!(size >= 2000, "{rotated:?} was rotated at {size} bytes");
            seen.extend(numbers_in(&rotated));
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), writers * each, "no record lost to a rotation");
    }

    #[test]
    fn a_rotation_that_fails_still_writes_the_record_and_says_so() {
        let dir = unique_temp_dir("audit-rotate-fails");
        let path = dir.join("audit.jsonl");
        fs::create_dir_all(&dir).expect("dir");
        fs::write(&path, "x".repeat(100)).expect("full log");
        // the lock file cannot be opened: it is a directory
        fs::create_dir_all(dir.join("audit.jsonl.lock")).expect("blocker");

        let outcome = append_audit_record_rotating(&path, &numbered(7, 10), 50, 3);

        assert!(outcome.is_err(), "the failed rotation is reported");
        let text = fs::read_to_string(&path).expect("log");
        assert!(
            text.contains("\"path\":\"p7\""),
            "the record is written anyway: {text}"
        );
    }

    #[test]
    fn validation_sorts_the_lines_of_a_log_that_mixes_generations() {
        let current = fixture_record().to_json_value().to_string();
        let eight_keys = r#"{"confidence":null,"decision":"allow","path":"a.csv","reason":null,"sensitivity":null,"session_id":"s","tool":"Read","ts":"1775187009"}"#;
        let interleaved = r#"{"confidence":null,"decision":"allow{""confid"#;
        let tail = r#","ts":"1775603272"}"#;
        let log = format!(
            "{current}\n{eight_keys}\n\n{interleaved}\n{tail}\n[1,2]\n{{\"ts\":\"1\"}}\n{current}\n"
        );

        let report = validate(log.as_bytes()).expect("a log should validate");

        assert_eq!(
            report,
            Validation {
                lines: 8,
                blank: 1,
                current: 2,
                legacy: 1,
                unparseable: 4,
                unparseable_lines: vec![4, 5, 6, 7],
            }
        );
    }

    #[test]
    fn validation_counts_a_line_that_is_not_utf8_and_lists_a_bounded_number() {
        let mut log = Vec::new();
        log.extend_from_slice(b"\xff\xfe not json\n");
        for _ in 0..50 {
            log.extend_from_slice(b"garbage\n");
        }

        let report = validate(log.as_slice()).expect("a log should validate");

        assert_eq!(report.unparseable, 51);
        assert_eq!(report.unparseable_lines.len(), LISTED_BAD_LINES);
        assert_eq!(report.unparseable_lines[0], 1);
    }

    #[test]
    fn a_record_that_is_not_an_object_with_the_core_fields_is_not_an_entry() {
        assert_eq!(parse_line(b""), Line::Blank);
        assert_eq!(parse_line(b"   "), Line::Blank);
        assert_eq!(parse_line(b"null"), Line::Unparseable);
        assert_eq!(
            parse_line(br#"{"ts":"1","tool":"Read","path":"a","decision":7}"#),
            Line::Unparseable
        );
        assert!(matches!(
            parse_line(br#"{"ts":"1","tool":"Read","path":"a","decision":"allow"}"#),
            Line::Entry { current: false, .. }
        ));
        assert!(matches!(
            parse_line(
                br#"{"schema_version":"veil.audit.v1","ts":"1","tool":"Read","path":"a","decision":"allow"}"#
            ),
            Line::Entry { current: true, .. }
        ));
        // another version is readable but not this one
        assert!(matches!(
            parse_line(
                br#"{"schema_version":"veil.audit.v2","ts":"1","tool":"Read","path":"a","decision":"allow"}"#
            ),
            Line::Entry { current: false, .. }
        ));
    }

    #[test]
    fn append_default_path_resolves_outside_the_repo_tree() {
        let temp_home = unique_temp_dir("audit-home");
        let path = default_audit_path_from(Some(temp_home.clone())).expect("path");

        assert!(path.starts_with(&temp_home));
        assert_eq!(
            path,
            temp_home
                .join(".cmdrvl")
                .join("logs")
                .join("veil")
                .join("audit.jsonl")
        );
    }

    #[test]
    fn multiple_writes_append_multiple_json_records() {
        let path = unique_temp_dir("audit-append").join("audit.jsonl");

        append_audit_record(&path, &fixture_record()).expect("first append should succeed");
        append_audit_record(
            &path,
            &AuditRecord {
                ts: "2026-03-01T16:05:00Z".to_owned(),
                tool: "Bash".to_owned(),
                path: "data/clients/report.csv".to_owned(),
                decision: "allow".to_owned(),
                reason: None,
                sensitivity: None,
                confidence: Some(0.42),
                session_id: Some("session-456".to_owned()),
                origin: Some("wrapper".to_owned()),
                reason_class: Some("argv_path".to_owned()),
                class: Some("egress".to_owned()),
            },
        )
        .expect("second append should succeed");

        let file = fs::File::open(&path).expect("audit file should exist");
        let lines = BufReader::new(file)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .expect("lines should be readable");

        assert_eq!(lines.len(), 2);

        let first: Value = serde_json::from_str(&lines[0]).expect("first line should parse");
        let second: Value = serde_json::from_str(&lines[1]).expect("second line should parse");

        assert_eq!(first["tool"], "Read");
        assert_eq!(second["tool"], "Bash");
        assert_eq!(second["decision"], "allow");
        assert_eq!(second["origin"], "wrapper");
        assert_eq!(first["reason_class"], "direct_read");
        assert_eq!(second["reason_class"], "argv_path");
        // `class` is its own field, null unless the record is an egress attempt
        assert!(first["class"].is_null());
        assert_eq!(second["class"], "egress");
    }
}
