#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::types::ToolKind;

const PYTHON_DIRECT_READ_CALLS: &[&str] = &[
    "open",
    "read_csv",
    "read_table",
    "read_fwf",
    "read_json",
    "read_excel",
    "read_parquet",
    "read_feather",
    "read_pickle",
    "read_orc",
    "read_sas",
    "read_spss",
    "read_stata",
    "read_xml",
    "read_ndjson",
    "scan_csv",
    "scan_parquet",
    "scan_ndjson",
    "loadtxt",
    "genfromtxt",
];
const PYTHON_PATH_READ_METHODS: &[&str] = &["read_text", "read_bytes", "open"];

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
    let Some((program, args)) = resolve_invocation(pipeline) else {
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
    let Some(path) = string_field(raw_value, "file_path")
        .or_else(|| string_field(raw_value, "path"))
        .and_then(|path| normalize_path(path, cwd))
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
    if raw_path.is_empty() || raw_path.chars().any(char::is_control) {
        return None;
    }

    let candidate = Path::new(raw_path);
    if candidate.as_os_str().is_empty() {
        return None;
    }

    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };
    let hardened = lexical_normalize(&absolute)?;

    if is_fd_indirection(&hardened) {
        return Some(resolve_indirection(&hardened).unwrap_or(hardened));
    }

    fs::canonicalize(&hardened).ok().or(Some(hardened))
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

fn resolve_invocation(tokens: &[String]) -> Option<(&str, &[String])> {
    let mut index = 0;

    while index < tokens.len() {
        let token = tokens[index].as_str();
        if is_env_assignment(token) {
            index += 1;
            continue;
        }

        match command_name(token) {
            "env" => {
                index += 1;
                while index < tokens.len() {
                    let token = tokens[index].as_str();
                    if token == "--" {
                        index += 1;
                        break;
                    }

                    if token.starts_with('-') || is_env_assignment(token) {
                        index += 1;
                        continue;
                    }

                    break;
                }
            }
            "command" | "builtin" | "nohup" => {
                index += 1;
                while index < tokens.len() {
                    let token = tokens[index].as_str();
                    if token == "--" {
                        index += 1;
                        break;
                    }

                    if token.starts_with('-') {
                        index += 1;
                        continue;
                    }

                    break;
                }
            }
            _ => return Some((token, &tokens[index + 1..])),
        }
    }

    None
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
    let mut paths = Vec::new();
    let bytes = script.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                index = skip_until_newline(bytes, index + 1);
            }
            b'\'' | b'"' => match skip_python_string(script, index) {
                Some(next) => index = next,
                None => break,
            },
            byte if is_identifier_start(byte) => {
                let start = index;
                let end = parse_identifier_chain(script, index);
                let name = &script[start..end];
                let after_name = skip_ascii_whitespace(script, end);

                if bytes.get(after_name) == Some(&b'(') {
                    let suffix = name.rsplit('.').next().unwrap_or(name);
                    if PYTHON_DIRECT_READ_CALLS.contains(&suffix)
                        && let Some((path, call_end)) =
                            parse_first_python_path_argument(script, after_name + 1)
                    {
                        paths.push(path);
                        index = call_end;
                        continue;
                    }

                    if suffix == "Path"
                        && let Some((path, path_end)) =
                            parse_first_python_path_argument(script, after_name + 1)
                    {
                        let after_path = skip_ascii_whitespace(script, path_end);
                        if bytes.get(after_path) == Some(&b')') {
                            let after_call = skip_ascii_whitespace(script, after_path + 1);
                            if bytes.get(after_call) == Some(&b'.') {
                                let method_start = after_call + 1;
                                if bytes
                                    .get(method_start)
                                    .is_some_and(|byte| is_identifier_start(*byte))
                                {
                                    let method_end = parse_identifier(script, method_start);
                                    let method = &script[method_start..method_end];
                                    let after_method = skip_ascii_whitespace(script, method_end);
                                    if bytes.get(after_method) == Some(&b'(')
                                        && PYTHON_PATH_READ_METHODS.contains(&method)
                                    {
                                        paths.push(path);
                                        index = after_method + 1;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }

                index = end;
            }
            _ => index += 1,
        }
    }

    paths
}

fn skip_until_newline(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            return index + 1;
        }
        index += 1;
    }

    bytes.len()
}

fn skip_python_string(script: &str, start: usize) -> Option<usize> {
    let bytes = script.as_bytes();
    let quote = *bytes.get(start)?;
    let triple_quoted =
        bytes.get(start + 1) == Some(&quote) && bytes.get(start + 2) == Some(&quote);
    let mut index = start + if triple_quoted { 3 } else { 1 };

    while index < bytes.len() {
        if !triple_quoted && bytes[index] == b'\\' {
            index += 2;
            continue;
        }

        if triple_quoted {
            if bytes.get(index) == Some(&quote)
                && bytes.get(index + 1) == Some(&quote)
                && bytes.get(index + 2) == Some(&quote)
            {
                return Some(index + 3);
            }
        } else if bytes[index] == quote {
            return Some(index + 1);
        }

        index += 1;
    }

    None
}

fn parse_first_python_path_argument(script: &str, start: usize) -> Option<(String, usize)> {
    let bytes = script.as_bytes();
    let index = skip_ascii_whitespace(script, start);
    let byte = *bytes.get(index)?;

    if byte == b'\'' || byte == b'"' {
        return parse_quoted_literal(script, index);
    }

    if !is_identifier_start(byte) {
        return None;
    }

    let name_end = parse_identifier_chain(script, index);
    let after_name = skip_ascii_whitespace(script, name_end);
    if bytes.get(after_name) == Some(&b'=') {
        return parse_first_python_path_argument(script, after_name + 1);
    }

    let name = &script[index..name_end];
    if name.rsplit('.').next().unwrap_or(name) != "Path" || bytes.get(after_name) != Some(&b'(') {
        return None;
    }

    let (path, path_end) = parse_first_python_path_argument(script, after_name + 1)?;
    let after_path = skip_ascii_whitespace(script, path_end);
    if bytes.get(after_path) == Some(&b')') {
        Some((path, after_path + 1))
    } else {
        None
    }
}

fn skip_ascii_whitespace(script: &str, mut index: usize) -> usize {
    let bytes = script.as_bytes();
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    index
}

fn parse_identifier_chain(script: &str, start: usize) -> usize {
    let bytes = script.as_bytes();
    let mut index = parse_identifier(script, start);

    while bytes.get(index) == Some(&b'.')
        && bytes
            .get(index + 1)
            .is_some_and(|byte| is_identifier_start(*byte))
    {
        index = parse_identifier(script, index + 1);
    }

    index
}

fn parse_identifier(script: &str, start: usize) -> usize {
    let bytes = script.as_bytes();
    let mut index = start;

    while bytes
        .get(index)
        .is_some_and(|byte| is_identifier_continue(*byte))
    {
        index += 1;
    }

    index
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
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

fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut prefix = None::<OsString>;
    let mut has_root = false;
    let mut parts = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() {
                    parts.pop();
                } else if !has_root {
                    return None;
                }
            }
            Component::Normal(value) => parts.push(value.to_os_string()),
        }
    }

    let mut normalized = PathBuf::new();
    if let Some(prefix) = prefix {
        normalized.push(prefix);
    }
    if has_root {
        normalized.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in parts {
        normalized.push(part);
    }

    if normalized.as_os_str().is_empty() {
        if has_root {
            normalized.push(std::path::MAIN_SEPARATOR_STR);
        } else {
            return None;
        }
    }

    Some(normalized)
}

fn resolve_indirection(path: &Path) -> Option<PathBuf> {
    let target = match fs::read_link(path) {
        Ok(target) => target,
        Err(_) => return Some(path.to_path_buf()),
    };
    let absolute = if target.is_absolute() {
        target
    } else if target.components().count() > 1 {
        path.parent()?.join(target)
    } else {
        return Some(path.to_path_buf());
    };
    let normalized = match lexical_normalize(&absolute) {
        Some(normalized) => normalized,
        None => return Some(path.to_path_buf()),
    };

    fs::canonicalize(&normalized)
        .ok()
        .or(Some(normalized))
        .or(Some(path.to_path_buf()))
}

fn is_fd_indirection(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    raw.starts_with("/dev/fd/") || raw.starts_with("/proc/self/fd/")
}

fn is_pipeline_separator(token: &str) -> bool {
    token.len() == 1 && token.as_bytes()[0] == b'|'
}

fn is_env_assignment(token: &str) -> bool {
    let Some((name, _value)) = token.split_once('=') else {
        return false;
    };

    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs::File;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn workspace() -> &'static Path {
        Path::new("/workspace/veil")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("veil-extract-{label}-{nanos}"))
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
    fn traversal_segments_are_collapsed_before_matching() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            r#"{"file_path":"../../secret.csv"}"#,
            Path::new("/workspace/veil/data/reports"),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.csv")]
        );
        assert!(
            extraction.candidates[0]
                .components()
                .all(|component| component != Component::ParentDir)
        );
    }

    #[test]
    fn null_byte_paths_are_rejected() {
        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            &json!({ "file_path": "secret\u{0}.csv" }).to_string(),
            workspace(),
        );

        assert_eq!(extraction, PathExtraction::none());
    }

    #[test]
    fn nonexistent_paths_with_spaces_and_unicode_are_hardened_without_panicking() {
        let cwd = Path::new("/workspace/veil/input dir");
        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            &json!({ "file_path": "./reports/../über summary.csv" }).to_string(),
            cwd,
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/input dir/über summary.csv")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_targets_are_resolved_when_the_target_exists() {
        let root = unique_temp_dir("symlink");
        let protected_dir = root.join("protected");
        fs::create_dir_all(&protected_dir).expect("protected directory should be creatable");
        let target = protected_dir.join("secret.csv");
        fs::write(&target, "classified").expect("target file should be writable");
        symlink(&target, root.join("alias.csv")).expect("symlink should be creatable");

        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            &json!({ "file_path": "alias.csv" }).to_string(),
            &root,
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![fs::canonicalize(&target).expect("target should canonicalize")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_descriptor_paths_are_resolved_when_supported_by_the_platform() {
        let root = unique_temp_dir("fd");
        fs::create_dir_all(&root).expect("temp directory should be creatable");
        let target = root.join("sensitive.csv");
        fs::write(&target, "classified").expect("target file should be writable");
        let file = File::open(&target).expect("target file should be openable");
        let fd_path = fd_proxy_path(&file).expect("platform should expose an fd path");

        let extraction = extract_read_or_grep_paths(
            ToolKind::Read,
            &json!({ "file_path": fd_path }).to_string(),
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(extraction.candidates.len(), 1);
        assert!(
            extraction.candidates[0]
                == fs::canonicalize(&target).expect("target should canonicalize")
                || extraction.candidates[0] == fd_path,
            "fd indirection should either resolve to the target or remain an unmangled fd path"
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
    fn python_inline_script_extracts_pandas_read_csv_path() {
        let extraction = extract_bash_read_paths(
            r#"python3 -c "import pandas as pd; df = pd.read_csv(\"secret.csv\")""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.csv")]
        );
    }

    #[test]
    fn python_inline_script_extracts_context_manager_open_with_whitespace() {
        let extraction = extract_bash_read_paths(
            r#"python3 -c "with open (\"two words.txt\", \"r\") as handle: print(handle.read())""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/two words.txt")]
        );
    }

    #[test]
    fn env_wrapped_python_inline_reads_are_detected() {
        let extraction = extract_bash_read_paths(
            r#"PYTHONWARNINGS=ignore python3 -c "import pandas as pd; pd.read_csv(\"secret.csv\")""#,
            workspace(),
        );

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/secret.csv")]
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
        assert_eq!(
            extract_bash_read_paths(
                r#"python3 -c "print(\"read_csv('secret.csv')\")""#,
                workspace(),
            ),
            PathExtraction::none()
        );
    }

    #[cfg(unix)]
    fn fd_proxy_path(file: &File) -> Option<PathBuf> {
        let fd = file.as_raw_fd();
        for base in [Path::new("/proc/self/fd"), Path::new("/dev/fd")] {
            if base.exists() {
                return Some(base.join(fd.to_string()));
            }
        }

        None
    }
}
