#![forbid(unsafe_code)]

//! The paths in the arguments of an MCP tool call (bd-1wa).
//!
//! Claude Code fires `PreToolUse` for `mcp__<server>__<tool>` as well, and an
//! MCP tool's arguments are JSON whose meaning veil does not know: an
//! `attachments` array of a send-mail tool, a `path` of an uploader. veil does
//! not guess which field is which. It reads every string value in the arguments
//! and judges the ones that name a path, and never looks inside a string for
//! content: it is a path guard, not a content scanner.
//!
//! A string names a path when
//!
//! - it is rooted (`/abs`, `~/x`, `file:///x`) and has no whitespace: it is
//!   judged whether or not the file exists, as a Bash word is; or
//! - it is anything else (a relative name, or any text with whitespace) and a
//!   file of that name exists: a note that happens to mention `data/x.csv` is
//!   prose, a file that is there is a file.
//!
//! A URL is not special-cased: `https://host/x` is a relative name that no
//! file answers to, so it is not judged. A `file://` URL is a path. Object
//! keys, numbers and booleans are never judged.
//!
//! Every string that is not rooted costs one `lstat`. They are not rationed:
//! a budget would let a call hide a file behind a screenful of other names.
//! The bound is [`MAX_STRINGS`], and arguments past it are refused.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

/// Arguments nested deeper than this are not read past.
pub(crate) const MAX_DEPTH: usize = 32;

/// Arguments holding more strings than this are not read past.
pub(crate) const MAX_STRINGS: usize = 10_000;

/// A string longer than this is text, not a path.
const MAX_PATH_BYTES: usize = 4096;

/// A path in the arguments of an MCP tool call and where it was.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArgumentPath {
    /// Absolute and normalised. Symlinks are not followed here: the evaluator
    /// follows them.
    pub path: PathBuf,
    /// The field it was found in, as a JSON pointer (RFC 6901): `/attachments/0`.
    pub pointer: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ArgumentScan {
    /// Each distinct path once, at the first field that held it, in the order
    /// of the document.
    pub paths: Vec<ArgumentPath>,
    /// The arguments are nested deeper, or hold more strings, than veil reads:
    /// some may not have been looked at.
    pub exceeded_limits: bool,
}

/// The paths among the string values of `raw_args` (a JSON object). Text that
/// is not JSON has none: the hook payload has been parsed already.
pub(crate) fn scan_arguments(raw_args: &str, cwd: &Path, home: Option<&Path>) -> ArgumentScan {
    let Ok(arguments) = serde_json::from_str::<Value>(raw_args) else {
        return ArgumentScan::default();
    };

    let mut walk = Walk {
        cwd,
        home,
        strings: 0,
        seen: HashSet::new(),
        scan: ArgumentScan::default(),
    };
    walk.visit(&arguments, &mut String::new(), 0);
    walk.scan
}

struct Walk<'a> {
    cwd: &'a Path,
    home: Option<&'a Path>,
    strings: usize,
    seen: HashSet<PathBuf>,
    scan: ArgumentScan,
}

impl Walk<'_> {
    fn visit(&mut self, value: &Value, pointer: &mut String, depth: usize) {
        match value {
            Value::String(text) => self.string(text, pointer),
            Value::Array(items) => {
                if !self.enter(depth) {
                    return;
                }
                for (index, item) in items.iter().enumerate() {
                    let length = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&index.to_string());
                    self.visit(item, pointer, depth + 1);
                    pointer.truncate(length);
                }
            }
            Value::Object(fields) => {
                if !self.enter(depth) {
                    return;
                }
                for (key, item) in fields {
                    let length = pointer.len();
                    pointer.push('/');
                    push_escaped(pointer, key);
                    self.visit(item, pointer, depth + 1);
                    pointer.truncate(length);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn enter(&mut self, depth: usize) -> bool {
        if depth >= MAX_DEPTH {
            self.scan.exceeded_limits = true;
            return false;
        }
        true
    }

    fn string(&mut self, text: &str, pointer: &str) {
        self.strings += 1;
        if self.strings > MAX_STRINGS {
            self.scan.exceeded_limits = true;
            return;
        }

        let Some(path) = self.locate(text) else {
            return;
        };
        if self.seen.insert(path.clone()) {
            self.scan.paths.push(ArgumentPath {
                path,
                pointer: pointer.to_owned(),
            });
        }
    }

    /// The absolute path `text` names, or `None` when it names none.
    fn locate(&self, text: &str) -> Option<PathBuf> {
        // A tool that trims its input would reach the file this names.
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_PATH_BYTES || text.chars().any(char::is_control) {
            return None;
        }

        let text = file_url_path(text).unwrap_or(text);
        let (path, rooted) = if text == "~" || text.starts_with("~/") {
            (
                self.home?
                    .join(text.trim_start_matches('~').trim_start_matches('/')),
                true,
            )
        } else if Path::new(text).is_absolute() {
            (PathBuf::from(text), true)
        } else {
            (self.cwd.join(text), false)
        };
        let path = lexical_normalize(&path);

        if rooted && !text.chars().any(char::is_whitespace) {
            return Some(path);
        }

        // Prose with a slash in it, or a bare word, is not a path unless a
        // file of that name is there. A symlink counts, dangling or not: the
        // evaluator follows it.
        fs::symlink_metadata(&path).ok().map(|_| path)
    }
}

/// The local path of a `file://` URL: `file:///x` and `file://localhost/x`.
/// A URL naming another host is not a local path. Percent-escapes are not
/// decoded.
fn file_url_path(text: &str) -> Option<&str> {
    if !text.get(..7)?.eq_ignore_ascii_case("file://") {
        return None;
    }
    let rest = &text[7..];

    if rest.starts_with('/') {
        return Some(rest);
    }
    if rest.get(..9)?.eq_ignore_ascii_case("localhost") && rest[9..].starts_with('/') {
        return Some(&rest[9..]);
    }
    None
}

/// `.` and `..` resolved without touching the filesystem. `..` at the root
/// stays at the root.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.parent().is_some() {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

/// RFC 6901: `~` is `~0` and `/` is `~1`.
fn push_escaped(pointer: &mut String, key: &str) {
    for ch in key.chars() {
        match ch {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            other => pointer.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn directory(label: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "veil-mcp-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("a test directory");
        dir
    }

    fn scan(arguments: &str, cwd: &Path) -> Vec<(String, String)> {
        scan_arguments(arguments, cwd, Some(Path::new("/home/me")))
            .paths
            .into_iter()
            .map(|found| (found.path.display().to_string(), found.pointer))
            .collect()
    }

    fn at(path: &str, pointer: &str) -> (String, String) {
        (path.to_owned(), pointer.to_owned())
    }

    #[test]
    fn an_array_of_attachments_names_each_path_by_its_pointer() {
        let found = scan(
            r#"{"to": "a@b.c", "attachments": ["/srv/a.csv", "/srv/data/b.csv"]}"#,
            Path::new("/repo"),
        );

        assert_eq!(
            found,
            [
                at("/srv/a.csv", "/attachments/0"),
                at("/srv/data/b.csv", "/attachments/1")
            ]
        );
    }

    #[test]
    fn nested_objects_and_arrays_are_walked() {
        let found = scan(
            r#"{"a": {"b": [{"file": "/x/y"}, 7, true, null, ["/x/z"]]}}"#,
            Path::new("/repo"),
        );

        assert_eq!(found, [at("/x/y", "/a/b/0/file"), at("/x/z", "/a/b/4/0")]);
    }

    #[test]
    fn a_pointer_escapes_slash_and_tilde_in_a_key() {
        let found = scan(r#"{"a/b": {"c~d": "/x/y"}}"#, Path::new("/repo"));

        assert_eq!(found, [at("/x/y", "/a~1b/c~0d")]);
    }

    #[test]
    fn a_rooted_path_is_judged_whether_or_not_it_exists() {
        let found = scan(
            r#"{"p": "/definitely/not/there/.env", "q": "~/.ssh/id_rsa", "r": "file:///x/.env", "s": "file://localhost/x/k.pem", "t": "FILE:///x/c.pem"}"#,
            Path::new("/repo"),
        );

        assert_eq!(
            found,
            [
                at("/definitely/not/there/.env", "/p"),
                at("/home/me/.ssh/id_rsa", "/q"),
                at("/x/.env", "/r"),
                at("/x/k.pem", "/s"),
                at("/x/c.pem", "/t"),
            ]
        );
    }

    #[test]
    fn a_relative_string_is_a_path_only_if_a_file_of_that_name_is_there() {
        let cwd = directory("relative");
        fs::create_dir_all(cwd.join("data")).unwrap();
        fs::write(cwd.join("data/clients.csv"), "x").unwrap();
        fs::write(cwd.join(".env"), "x").unwrap();

        let found = scan(
            r#"{"a": "data/clients.csv", "b": ".env", "c": "data/missing.csv", "d": "owner/repo", "e": "feature/x", "f": "hello"}"#,
            &cwd,
        );

        assert_eq!(
            found,
            [
                at(&cwd.join("data/clients.csv").display().to_string(), "/a"),
                at(&cwd.join(".env").display().to_string(), "/b"),
            ]
        );
    }

    #[test]
    fn a_dangling_symlink_is_there_for_the_evaluator_to_follow() {
        let cwd = directory("dangling");
        std::os::unix::fs::symlink("/nowhere/at/all", cwd.join("link")).unwrap();

        let found = scan(r#"{"a": "link"}"#, &cwd);

        assert_eq!(found, [at(&cwd.join("link").display().to_string(), "/a")]);
    }

    #[test]
    fn text_with_whitespace_is_a_path_only_if_a_file_of_that_name_is_there() {
        let cwd = directory("spaces");
        fs::create_dir_all(cwd.join("My Documents")).unwrap();
        fs::write(cwd.join("My Documents/q3 clients.csv"), "x").unwrap();
        let absolute = cwd.join("My Documents/q3 clients.csv");

        let found = scan(
            &serde_json::json!({
                "a": "My Documents/q3 clients.csv",
                "b": absolute.display().to_string(),
                "c": "/nowhere/My Documents/q3 clients.csv",
                "d": "please attach /srv/data/clients.csv to the mail",
            })
            .to_string(),
            &cwd,
        );

        assert_eq!(
            found,
            [at(&absolute.display().to_string(), "/a")],
            "the same file named twice is reported once"
        );
    }

    #[test]
    fn urls_are_not_paths_and_a_file_url_for_another_host_is_not_local() {
        let found = scan(
            r#"{"a": "https://example.com/x/.env", "b": "s3://bucket/key.csv", "c": "file://other-host/x/.env", "d": "gs://b/o", "e": "mailto:a@b.c"}"#,
            Path::new("/repo"),
        );

        assert_eq!(found, []);
    }

    #[test]
    fn dot_dot_cannot_climb_out_of_where_it_started_but_is_followed() {
        let found = scan(
            r#"{"a": "/repo/data/../.env", "b": "/../../etc/passwd", "c": "/repo/./x/../y"}"#,
            Path::new("/repo"),
        );

        assert_eq!(
            found,
            [
                at("/repo/.env", "/a"),
                at("/etc/passwd", "/b"),
                at("/repo/y", "/c"),
            ]
        );
    }

    #[test]
    fn a_string_is_trimmed_and_text_that_cannot_be_a_path_is_skipped() {
        let found = scan(
            &serde_json::json!({
                "a": "  /srv/x.csv\t",
                "b": "",
                "c": "   ",
                "d": "/srv/a\nb",
                "e": format!("/{}", "x".repeat(MAX_PATH_BYTES)),
            })
            .to_string(),
            Path::new("/repo"),
        );

        assert_eq!(found, [at("/srv/x.csv", "/a")]);
    }

    #[test]
    fn a_path_in_two_fields_is_reported_at_the_first() {
        let found = scan(r#"{"a": ["/srv/x"], "b": "/srv/x"}"#, Path::new("/repo"));

        assert_eq!(found, [at("/srv/x", "/a/0")]);
    }

    #[test]
    fn a_tilde_with_no_home_names_nothing() {
        let scan = scan_arguments(r#"{"a": "~/x", "b": "~"}"#, Path::new("/repo"), None);

        assert_eq!(scan, ArgumentScan::default());
    }

    #[test]
    fn a_bare_tilde_is_the_home_directory_and_another_users_is_not_expanded() {
        let found = scan(r#"{"a": "~", "b": "~root/x"}"#, Path::new("/repo"));

        // `~root/x` is a relative name; no such file is there.
        assert_eq!(found, [at("/home/me", "/a")]);
    }

    #[test]
    fn object_keys_numbers_and_booleans_are_not_judged() {
        let found = scan(
            r#"{"/srv/key": 1, "n": 12, "b": false, "z": null}"#,
            Path::new("/repo"),
        );

        assert_eq!(found, []);
    }

    #[test]
    fn arguments_nested_past_the_depth_limit_say_so() {
        let nested = |depth: usize| {
            let mut text = r#""/srv/x""#.to_owned();
            for _ in 0..depth {
                text = format!("[{text}]");
            }
            format!(r#"{{"a": {text}}}"#)
        };

        let shallow = scan_arguments(&nested(MAX_DEPTH - 2), Path::new("/repo"), None);
        assert!(!shallow.exceeded_limits);
        assert_eq!(shallow.paths.len(), 1);

        let deep = scan_arguments(&nested(MAX_DEPTH + 2), Path::new("/repo"), None);
        assert!(deep.exceeded_limits);
        assert!(deep.paths.is_empty(), "nothing is read past the limit");
    }

    #[test]
    fn arguments_with_more_strings_than_the_limit_say_so() {
        let strings = |count: usize| {
            let items = vec![r#""/srv/x""#; count].join(",");
            format!(r#"{{"a": [{items}]}}"#)
        };

        assert!(!scan_arguments(&strings(MAX_STRINGS), Path::new("/repo"), None).exceeded_limits);
        assert!(
            scan_arguments(&strings(MAX_STRINGS + 1), Path::new("/repo"), None).exceeded_limits
        );
    }

    #[test]
    fn other_names_in_front_of_a_file_do_not_hide_it_from_the_filesystem_check() {
        let cwd = directory("padding");
        fs::write(cwd.join("target.csv"), "x").unwrap();
        let mut names: Vec<String> = (0..1_000).map(|n| format!("missing-{n}.csv")).collect();
        names.push("target.csv".to_owned());
        names.push("target with spaces.csv".to_owned());
        fs::write(cwd.join("target with spaces.csv"), "x").unwrap();
        let arguments = serde_json::json!({ "files": names }).to_string();

        let scan = scan_arguments(&arguments, &cwd, None);

        let pointers: Vec<&str> = scan
            .paths
            .iter()
            .map(|found| found.pointer.as_str())
            .collect();
        assert_eq!(pointers, ["/files/1000", "/files/1001"]);
        assert!(!scan.exceeded_limits);
    }

    #[test]
    fn text_that_is_not_json_has_no_paths() {
        assert_eq!(
            scan_arguments("not json", Path::new("/repo"), None),
            ArgumentScan::default()
        );
    }
}
