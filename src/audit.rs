#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

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
}

impl AuditRecord {
    pub fn to_json_value(&self) -> Value {
        json!({
            "ts": self.ts,
            "tool": self.tool,
            "path": self.path,
            "decision": self.decision,
            "reason": self.reason,
            "sensitivity": self.sensitivity,
            "confidence": self.confidence,
            "session_id": self.session_id,
        })
    }
}

pub fn default_audit_path() -> io::Result<PathBuf> {
    default_audit_path_from(
        env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

fn default_audit_path_from(
    xdg_state_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> io::Result<PathBuf> {
    if let Some(state_home) = xdg_state_home {
        return Ok(state_home.join("veil").join("audit.jsonl"));
    }

    if let Some(home_dir) = home {
        return Ok(home_dir
            .join(".local")
            .join("state")
            .join("veil")
            .join("audit.jsonl"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "unable to resolve default audit path from XDG_STATE_HOME or HOME",
    ))
}

pub fn append_default_audit_record(record: &AuditRecord) -> io::Result<PathBuf> {
    let path = default_audit_path()?;
    append_audit_record(&path, record)?;
    Ok(path)
}

pub fn append_audit_record(path: &Path, record: &AuditRecord) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &record.to_json_value())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    file.write_all(b"\n")?;
    file.flush()
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
    fn default_path_prefers_xdg_state_home() {
        let path = default_audit_path_from(
            Some(PathBuf::from("/tmp/xdg-state")),
            Some(PathBuf::from("/tmp/home")),
        )
        .expect("xdg state path should resolve");

        assert_eq!(path, PathBuf::from("/tmp/xdg-state/veil/audit.jsonl"));
    }

    #[test]
    fn default_path_falls_back_to_home_local_state() {
        let path =
            default_audit_path_from(None, Some(PathBuf::from("/tmp/home"))).expect("home path");

        assert_eq!(
            path,
            PathBuf::from("/tmp/home/.local/state/veil/audit.jsonl")
        );
    }

    #[test]
    fn default_path_errors_without_any_base_directory() {
        let error =
            default_audit_path_from(None, None).expect_err("missing env should return an error");

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
    }

    #[test]
    fn append_default_path_resolves_outside_the_repo_tree() {
        let temp_home = unique_temp_dir("audit-home");
        let path = default_audit_path_from(None, Some(temp_home.clone())).expect("path");

        assert!(path.starts_with(&temp_home));
        assert_eq!(
            path,
            temp_home
                .join(".local")
                .join("state")
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
    }
}
