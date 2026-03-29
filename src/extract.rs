#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::types::ToolKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathExposure {
    None,
    MetadataOnly,
    ReadsContents,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathExtraction {
    pub exposure: PathExposure,
    pub candidates: Vec<PathBuf>,
}

impl PathExtraction {
    fn none() -> Self {
        Self {
            exposure: PathExposure::None,
            candidates: Vec::new(),
        }
    }
}

pub fn extract_read_or_grep_paths(tool: ToolKind, raw_args: &str, cwd: &Path) -> PathExtraction {
    let Ok(raw_value) = serde_json::from_str::<Value>(raw_args) else {
        return PathExtraction::none();
    };

    match tool {
        ToolKind::Read => extract_read_path(&raw_value, cwd),
        ToolKind::Grep => extract_grep_path(&raw_value, cwd),
        _ => PathExtraction::none(),
    }
}

pub fn extract_bash_read_paths(command: &str, cwd: &Path) -> PathExtraction {
    let Some(tokens) = shlex::split(command) else {
        return PathExtraction::none();
    };

    let pipeline = left_pipeline(&tokens);
    let Some((program, args)) = pipeline.split_first() else {
        return PathExtraction::none();
    };

    let Some(paths) = command_paths(program, args) else {
        return PathExtraction::none();
    };

    let candidates = paths
        .into_iter()
        .filter_map(|path| normalize_path(&path, cwd))
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return PathExtraction::none();
    }

    PathExtraction {
        exposure: PathExposure::ReadsContents,
        candidates,
    }
}

fn extract_read_path(raw_value: &Value, cwd: &Path) -> PathExtraction {
    let Some(path) =
        string_field(raw_value, "file_path").and_then(|path| normalize_path(path, cwd))
    else {
        return PathExtraction::none();
    };

    PathExtraction {
        exposure: PathExposure::ReadsContents,
        candidates: vec![path],
    }
}

fn extract_grep_path(raw_value: &Value, cwd: &Path) -> PathExtraction {
    let Some(path) = string_field(raw_value, "path").and_then(|path| normalize_path(path, cwd))
    else {
        return PathExtraction::none();
    };

    PathExtraction {
        exposure: grep_exposure(raw_value),
        candidates: vec![path],
    }
}

fn string_field<'a>(raw_value: &'a Value, field: &str) -> Option<&'a str> {
    raw_value.get(field)?.as_str()
}

fn grep_exposure(raw_value: &Value) -> PathExposure {
    match string_field(raw_value, "output_mode") {
        Some("files_with_matches") => PathExposure::MetadataOnly,
        _ => PathExposure::ReadsContents,
    }
}

fn normalize_path(raw_path: &str, cwd: &Path) -> Option<PathBuf> {
    let candidate = Path::new(raw_path);
    if candidate.as_os_str().is_empty() {
        return None;
    }

    Some(if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    })
}

fn left_pipeline(tokens: &[String]) -> &[String] {
    match tokens.iter().position(|token| is_pipeline_separator(token)) {
        Some(index) => &tokens[..index],
        None => tokens,
    }
}

fn command_paths(program: &str, args: &[String]) -> Option<Vec<String>> {
    match command_name(program) {
        "cat" => Some(collect_simple_reader_paths(args)),
        "bat" | "less" | "more" => Some(collect_delimited_reader_paths(args)),
        "head" | "tail" => Some(collect_head_tail_paths(args)),
        _ => None,
    }
}

fn command_name(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

fn collect_simple_reader_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut parsing_options = true;

    for arg in args {
        if is_redirection(arg) {
            break;
        }

        if arg == "--" {
            parsing_options = false;
            continue;
        }

        if parsing_options && arg.starts_with('-') {
            continue;
        }

        parsing_options = false;
        if arg != "-" {
            paths.push(arg.clone());
        }
    }

    paths
}

fn collect_delimited_reader_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut parsing_options = true;

    for arg in args {
        if is_redirection(arg) {
            break;
        }

        if arg == "--" {
            parsing_options = false;
            continue;
        }

        if parsing_options && arg.starts_with('-') {
            continue;
        }

        parsing_options = false;
        if arg != "-" {
            paths.push(arg.clone());
        }
    }

    paths
}

fn collect_head_tail_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;
    let mut parsing_options = true;

    while index < args.len() {
        let arg = &args[index];
        if is_redirection(arg) {
            break;
        }

        if arg == "--" {
            parsing_options = false;
            index += 1;
            continue;
        }

        if parsing_options {
            if consumes_next_head_tail_arg(arg) {
                index += 2;
                continue;
            }

            if arg.starts_with('-') {
                index += 1;
                continue;
            }
        }

        parsing_options = false;
        if arg != "-" {
            paths.push(arg.clone());
        }
        index += 1;
    }

    paths
}

fn consumes_next_head_tail_arg(arg: &str) -> bool {
    matches!(arg, "-n" | "-c" | "--lines" | "--bytes")
}

fn is_redirection(arg: &str) -> bool {
    matches!(arg, "<" | ">" | ">>" | "1>" | "1>>" | "2>" | "2>>")
}

fn is_pipeline_separator(token: &str) -> bool {
    token.len() == 1 && token.as_bytes()[0] == b'|'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> &'static Path {
        Path::new("/workspace/veil")
    }

    #[test]
    fn read_keeps_absolute_paths() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            r#"{"file_path":"/tmp/secret.txt"}"#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/tmp/secret.txt")]
        );
    }

    #[test]
    fn read_normalizes_relative_paths_against_cwd() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            r#"{"file_path":"docs/plan.md"}"#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/docs/plan.md")]
        );
    }

    #[test]
    fn grep_content_mode_yields_a_candidate_path() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Grep,
            r#"{"path":"data/clients/holdings.csv","output_mode":"content"}"#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/data/clients/holdings.csv")]
        );
    }

    #[test]
    fn grep_files_with_matches_is_treated_as_metadata_only() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Grep,
            r#"{"path":"data/clients/holdings.csv","output_mode":"files_with_matches"}"#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::MetadataOnly);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/data/clients/holdings.csv")]
        );
    }

    #[test]
    fn missing_path_field_returns_no_candidates() {
        let extraction =
            extract_read_or_grep_paths(ToolKind::Read, r#"{"other":"value"}"#, workspace());

        assert_eq!(extraction, PathExtraction::none());
    }

    #[test]
    fn malformed_json_returns_no_candidates() {
        let extraction = extract_read_or_grep_paths(ToolKind::Grep, "{", workspace());

        assert_eq!(extraction, PathExtraction::none());
    }

    #[test]
    fn unsupported_tools_return_no_candidates() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Bash,
            r#"{"command":"cat secret.txt"}"#,
            workspace(),
        );

        assert_eq!(extraction, PathExtraction::none());
    }

    #[test]
    fn bash_cat_extracts_multiple_paths_and_quoted_arguments() {
        let extraction = extract_bash_read_paths(r#"cat "one file.txt" two.txt"#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![
                PathBuf::from("/workspace/veil/one file.txt"),
                PathBuf::from("/workspace/veil/two.txt"),
            ]
        );
    }

    #[test]
    fn bash_head_skips_count_arguments_before_the_file() {
        let extraction = extract_bash_read_paths(r#"head -n 20 logs/app.log"#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/logs/app.log")]
        );
    }

    #[test]
    fn bash_left_pipeline_reader_is_still_detected() {
        let extraction = extract_bash_read_paths(r#"cat data.csv | wc -l"#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/data.csv")]
        );
    }

    #[test]
    fn bash_non_reader_commands_return_no_candidates() {
        assert_eq!(
            extract_bash_read_paths(r#"ls data.csv"#, workspace()),
            PathExtraction::none()
        );
        assert_eq!(
            extract_bash_read_paths(r#"git diff README.md"#, workspace()),
            PathExtraction::none()
        );
        assert_eq!(
            extract_bash_read_paths(r#"cd docs"#, workspace()),
            PathExtraction::none()
        );
        assert_eq!(
            extract_bash_read_paths(r#"stat data.csv"#, workspace()),
            PathExtraction::none()
        );
    }
}
