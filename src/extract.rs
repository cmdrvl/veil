#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::types::ToolKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterpreterKind {
    Python,
    Node,
    Perl,
    Ruby,
    Shell,
}

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
    if parse_heredoc(command).is_some() {
        return extract_heredoc_bash_paths(command, cwd);
    }

    extract_tokenized_bash_paths(command, cwd)
}

fn extract_tokenized_bash_paths(command: &str, cwd: &Path) -> PathExtraction {
    let Some(tokens) = shlex::split(command) else {
        return PathExtraction::none();
    };

    let pipeline = left_pipeline(&tokens);
    let Some((program, args)) = pipeline.split_first() else {
        return PathExtraction::none();
    };

    let mut paths = command_paths(program, args).unwrap_or_default();
    paths.extend(collect_input_redirect_paths(args));
    paths.extend(collect_inline_interpreter_paths(program, args));

    let candidates = normalize_candidates(paths, cwd);

    if candidates.is_empty() {
        PathExtraction::none()
    } else {
        PathExtraction {
            exposure: PathExposure::ReadsContents,
            candidates,
        }
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

fn normalize_candidates(paths: Vec<String>, cwd: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for path in paths {
        let Some(candidate) = normalize_path(&path, cwd) else {
            continue;
        };

        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }

    candidates
}

fn left_pipeline(tokens: &[String]) -> &[String] {
    for (index, token) in tokens.iter().enumerate() {
        if is_pipeline_separator(token) {
            return &tokens[..index];
        }
    }

    tokens
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

fn collect_input_redirect_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];

        if arg.starts_with("<<") {
            index += 1;
            continue;
        }

        if arg == "<" || arg == "0<" {
            if let Some(path) = args.get(index + 1) {
                paths.push(path.clone());
            }
            index += 2;
            continue;
        }

        if let Some(path) = arg.strip_prefix('<')
            && !path.is_empty()
        {
            paths.push(path.to_owned());
        }

        index += 1;
    }

    paths
}

fn collect_inline_interpreter_paths(program: &str, args: &[String]) -> Vec<String> {
    let Some(kind) = interpreter_kind(command_name(program)) else {
        return Vec::new();
    };

    let script_flag = match kind {
        InterpreterKind::Python => "-c",
        InterpreterKind::Node | InterpreterKind::Perl | InterpreterKind::Ruby => "-e",
        InterpreterKind::Shell => return Vec::new(),
    };

    let mut index = 0;
    while index < args.len() {
        if args[index] == script_flag {
            if let Some(script) = args.get(index + 1) {
                return extract_interpreter_script_paths(kind, script);
            }

            break;
        }

        index += 1;
    }

    Vec::new()
}

fn extract_heredoc_bash_paths(command: &str, cwd: &Path) -> PathExtraction {
    let Some(heredoc) = parse_heredoc(command) else {
        return PathExtraction::none();
    };

    let pipeline = left_pipeline(&heredoc.header_tokens);
    let Some((program, args)) = pipeline.split_first() else {
        return PathExtraction::none();
    };

    let mut candidates = normalize_candidates(collect_input_redirect_paths(args), cwd);

    match interpreter_kind(command_name(program)) {
        Some(InterpreterKind::Python) => candidates.extend(normalize_candidates(
            extract_python_script_paths(heredoc.body),
            cwd,
        )),
        Some(InterpreterKind::Node) => candidates.extend(normalize_candidates(
            extract_node_script_paths(heredoc.body),
            cwd,
        )),
        Some(InterpreterKind::Perl) => candidates.extend(normalize_candidates(
            extract_perl_script_paths(heredoc.body),
            cwd,
        )),
        Some(InterpreterKind::Ruby) => candidates.extend(normalize_candidates(
            extract_ruby_script_paths(heredoc.body),
            cwd,
        )),
        Some(InterpreterKind::Shell) => {
            for line in heredoc.body.lines() {
                let extraction = extract_bash_read_paths(line, cwd);
                for candidate in extraction.candidates {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
        }
        None => {}
    }

    if candidates.is_empty() {
        PathExtraction::none()
    } else {
        PathExtraction {
            exposure: PathExposure::ReadsContents,
            candidates,
        }
    }
}

fn interpreter_kind(program: &str) -> Option<InterpreterKind> {
    match program {
        "python" | "python3" => Some(InterpreterKind::Python),
        "node" | "nodejs" => Some(InterpreterKind::Node),
        "perl" => Some(InterpreterKind::Perl),
        "ruby" => Some(InterpreterKind::Ruby),
        "bash" | "sh" | "zsh" => Some(InterpreterKind::Shell),
        _ => None,
    }
}

fn extract_interpreter_script_paths(kind: InterpreterKind, script: &str) -> Vec<String> {
    match kind {
        InterpreterKind::Python => extract_python_script_paths(script),
        InterpreterKind::Node => extract_node_script_paths(script),
        InterpreterKind::Perl => extract_perl_script_paths(script),
        InterpreterKind::Ruby => extract_ruby_script_paths(script),
        InterpreterKind::Shell => Vec::new(),
    }
}

fn extract_python_script_paths(script: &str) -> Vec<String> {
    let mut paths = quoted_literals_after_marker(script, "open(")
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();

    for (path, end) in quoted_literals_after_marker(script, "Path(") {
        if script[end..].trim_start().starts_with(").read") {
            paths.push(path);
        }
    }

    paths
}

fn extract_node_script_paths(script: &str) -> Vec<String> {
    quoted_literals_after_marker(script, "readFileSync(")
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn extract_perl_script_paths(script: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = script[offset..].find("open") {
        let start = offset + relative_start + "open".len();
        let Some((mode, mode_end)) = next_quoted_literal(script, start) else {
            break;
        };

        if mode == "<"
            && let Some((path, path_end)) = next_quoted_literal(script, mode_end)
        {
            paths.push(path);
            offset = path_end;
            continue;
        }

        offset = mode_end;
    }

    paths
}

fn extract_ruby_script_paths(script: &str) -> Vec<String> {
    let mut paths = quoted_literals_after_marker(script, "File.read(")
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    paths.extend(
        quoted_literals_after_marker(script, "IO.read(")
            .into_iter()
            .map(|(path, _)| path),
    );
    paths
}

fn quoted_literals_after_marker(script: &str, marker: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = script[offset..].find(marker) {
        let start = offset + relative_start + marker.len();
        let Some((path, end)) = parse_quoted_literal(script, start) else {
            offset = start;
            continue;
        };

        results.push((path, end));
        offset = end;
    }

    results
}

fn next_quoted_literal(script: &str, start: usize) -> Option<(String, usize)> {
    let bytes = script.as_bytes();
    let mut index = start;

    while index < bytes.len() {
        if bytes[index] == b'\'' || bytes[index] == b'"' {
            return parse_quoted_literal(script, index);
        }

        index += 1;
    }

    None
}

fn parse_quoted_literal(script: &str, start: usize) -> Option<(String, usize)> {
    let bytes = script.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'\'' && quote != b'"' {
        return next_quoted_literal(script, start);
    }

    let mut value = String::new();
    let mut index = start + 1;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            let escaped = *bytes.get(index + 1)?;
            value.push(char::from(escaped));
            index += 2;
            continue;
        }

        if byte == quote {
            return Some((value, index + 1));
        }

        value.push(char::from(byte));
        index += 1;
    }

    None
}

struct Heredoc<'a> {
    header_tokens: Vec<String>,
    body: &'a str,
}

fn parse_heredoc(command: &str) -> Option<Heredoc<'_>> {
    let header_end = command.find('\n')?;
    let header = &command[..header_end];
    let (delimiter, strip_tabs) = parse_heredoc_delimiter(header)?;
    let header_tokens = shlex::split(header)?;
    let body_start = header_end + 1;
    let mut body_end = None;

    for (offset, line) in command[body_start..].split_inclusive('\n').enumerate() {
        let absolute_start = body_start
            + command[body_start..]
                .split_inclusive('\n')
                .take(offset)
                .map(str::len)
                .sum::<usize>();
        let trimmed = line.strip_suffix('\n').unwrap_or(line);
        let candidate = if strip_tabs {
            trimmed.trim_start_matches('\t')
        } else {
            trimmed
        };

        if candidate == delimiter {
            body_end = Some(absolute_start);
            break;
        }
    }

    let body_end = body_end?;

    Some(Heredoc {
        header_tokens,
        body: &command[body_start..body_end],
    })
}

fn parse_heredoc_delimiter(header: &str) -> Option<(String, bool)> {
    let marker = header.find("<<")?;
    let bytes = header.as_bytes();
    let mut index = marker + 2;
    let mut strip_tabs = false;

    if bytes.get(index) == Some(&b'-') {
        strip_tabs = true;
        index += 1;
    }

    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }

    let quote = match bytes.get(index) {
        Some(b'\'') | Some(b'"') => {
            let quote = bytes[index];
            index += 1;
            Some(quote)
        }
        _ => None,
    };
    let start = index;

    while let Some(&byte) = bytes.get(index) {
        if Some(byte) == quote {
            return Some((header[start..index].to_owned(), strip_tabs));
        }

        if quote.is_none() && byte.is_ascii_whitespace() {
            break;
        }

        index += 1;
    }

    if quote.is_some() || index == start {
        return None;
    }

    Some((header[start..index].to_owned(), strip_tabs))
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

    #[test]
    fn bash_input_redirect_is_treated_as_a_file_read() {
        let extraction = extract_bash_read_paths(r#"cat < secret.txt"#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn python_inline_script_extracts_opened_file() {
        let extraction = extract_bash_read_paths(
            r#"python -c "from pathlib import Path; print(Path(\"secret.txt\").read_text())""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn node_inline_script_extracts_readfilesync_path() {
        let extraction = extract_bash_read_paths(
            r#"node -e "console.log(require('fs').readFileSync(\"secret.txt\", \"utf8\"))""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn perl_inline_script_extracts_open_path() {
        let extraction = extract_bash_read_paths(
            r#"perl -e "open my $fh, '<', 'secret.txt'; print <$fh>""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn ruby_inline_script_extracts_file_read_path() {
        let extraction =
            extract_bash_read_paths(r#"ruby -e "puts File.read(\"secret.txt\")""#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn shell_heredoc_body_reads_are_detected() {
        let extraction =
            extract_bash_read_paths("bash <<'EOF'\ncat < secret.txt\nEOF", workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.txt")]
        );
    }

    #[test]
    fn interpreter_heredoc_body_reads_are_detected() {
        let extraction = extract_bash_read_paths(
            "python <<'PY'\nfrom pathlib import Path\nprint(Path(\"two words.txt\").read_text())\nPY",
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/two words.txt")]
        );
    }

    #[test]
    fn nested_quoting_edge_cases_do_not_panic() {
        let extraction = extract_bash_read_paths(
            r#"python -c "print(open(\"two words.txt\").read())""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/two words.txt")]
        );
    }

    #[test]
    fn safe_commands_with_inline_strings_do_not_false_positive() {
        assert_eq!(
            extract_bash_read_paths(r#"echo "open('secret.txt')""#, workspace()),
            PathExtraction::none()
        );
        assert_eq!(
            extract_bash_read_paths(r#"mkdir -p "tmp/node -e""#, workspace()),
            PathExtraction::none()
        );
        assert_eq!(
            extract_bash_read_paths(r#"git status"#, workspace()),
            PathExtraction::none()
        );
    }
}
