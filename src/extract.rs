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

    let (mut paths, exposure) = match search_command_paths(program, args) {
        Some(search) => (search.paths, search.exposure),
        None => (
            command_paths(program, args).unwrap_or_default(),
            PathExposure::ReadsContents,
        ),
    };
    paths.extend(collect_input_redirect_paths(args));
    paths.extend(collect_inline_interpreter_paths(program, args));

    let candidates = normalize_candidates(paths, cwd);

    if candidates.is_empty() {
        PathExtraction::none()
    } else {
        PathExtraction {
            exposure,
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
    // Grep searches the working directory when `path` is omitted, so an
    // omitted (or empty) path is a search of `cwd`, not a search of nothing.
    let raw_path = string_field(raw_value, "path")
        .filter(|path| !path.is_empty())
        .unwrap_or(".");
    let Some(path) = normalize_path(raw_path, cwd) else {
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

/// `files_with_matches` and `count` return file names and match counts, not
/// the matching text. Any other mode, and an omitted one, returns content.
fn grep_exposure(raw_value: &Value) -> PathExposure {
    match string_field(raw_value, "output_mode") {
        Some("files_with_matches" | "count") => PathExposure::MetadataOnly,
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

/// How one family of content-search commands spells its options. Each table
/// lists only options known to take a value: a value taken for an operand adds
/// a harmless extra path, while an operand taken for a value would hide a real
/// one, so an option missing here fails toward more paths, never fewer.
struct SearchSpec {
    short_with_value: &'static [char],
    long_with_value: &'static [&'static str],
    /// Searches directories recursively without being asked (rg, ag, ack).
    recursive_by_default: bool,
    recursive_short: &'static [char],
    recursive_long: &'static [&'static str],
    /// `-1`..`-9` mean a recursion depth rather than context lines (ugrep).
    digits_recurse: bool,
    /// Options that print names or counts instead of matching text.
    metadata_short: &'static [char],
    metadata_long: &'static [&'static str],
    /// Options that carry the pattern or replace it, so no operand is one.
    pattern_short: &'static [char],
    pattern_long: &'static [&'static str],
    /// Options whose value is a file the command reads for its patterns.
    pattern_file_short: &'static [char],
    pattern_file_long: &'static [&'static str],
}

/// `grep` may be GNU grep, BSD grep or, as on this machine, ugrep, so this
/// lists only the options that take a value in all three. `--context` is left
/// out because BSD grep's value is optional.
const GREP_SPEC: SearchSpec = SearchSpec {
    short_with_value: &['e', 'f', 'm', 'A', 'B', 'C', 'd', 'D'],
    long_with_value: &[
        "regexp",
        "file",
        "max-count",
        "after-context",
        "before-context",
        "directories",
        "devices",
        "include",
        "exclude",
        "exclude-from",
        "exclude-dir",
        "include-dir",
        "label",
        "binary-files",
    ],
    recursive_by_default: false,
    recursive_short: &['r', 'R'],
    recursive_long: &["recursive", "dereference-recursive"],
    digits_recurse: false,
    metadata_short: &['l', 'L', 'c', 'q'],
    metadata_long: &[
        "files-with-matches",
        "files-without-match",
        "count",
        "quiet",
        "silent",
    ],
    pattern_short: &['e', 'f'],
    pattern_long: &["regexp", "file"],
    pattern_file_short: &['f'],
    pattern_file_long: &["file"],
};

/// Value-taking options of ugrep 7.8, from its `--help`.
const UGREP_SPEC: SearchSpec = SearchSpec {
    short_with_value: &[
        'e', 'f', 'm', 'A', 'B', 'C', 'd', 'D', 'g', 'J', 'K', 'M', 'N', 'O', 't',
    ],
    long_with_value: &[
        "after-context",
        "before-context",
        "binary-files",
        "colors",
        "colours",
        "config",
        "context-separator",
        "context",
        "delay",
        "depth",
        "devices",
        "directories",
        "encoding",
        "exclude-dir",
        "exclude-from",
        "exclude-fs",
        "exclude",
        "file-extension",
        "file-magic",
        "file-type",
        "file",
        "filter",
        "format",
        "from",
        "glob",
        "iglob",
        "include-dir",
        "include-from",
        "include-fs",
        "include",
        "jobs",
        "label",
        "max-count",
        "max-files",
        "max-line",
        "max-size",
        "min-count",
        "min-line",
        "min-size",
        "neg-regexp",
        "range",
        "regexp",
        "replace",
        "zmax",
        "and",
        "andnot",
        "not",
    ],
    digits_recurse: true,
    pattern_short: &['e', 'f', 'N'],
    pattern_long: &["regexp", "file", "neg-regexp", "and", "andnot", "not"],
    ..GREP_SPEC
};

const RG_SPEC: SearchSpec = SearchSpec {
    short_with_value: &[
        'A', 'B', 'C', 'e', 'f', 'g', 't', 'T', 'm', 'M', 'j', 'd', 'E', 'r',
    ],
    long_with_value: &[
        "after-context",
        "before-context",
        "context",
        "regexp",
        "file",
        "glob",
        "iglob",
        "type",
        "type-not",
        "type-add",
        "type-clear",
        "max-count",
        "max-columns",
        "threads",
        "max-depth",
        "maxdepth",
        "max-filesize",
        "encoding",
        "engine",
        "replace",
        "sort",
        "sortr",
        "colors",
        "color",
        "context-separator",
        "field-context-separator",
        "field-match-separator",
        "path-separator",
        "pre",
        "pre-glob",
        "ignore-file",
        "hostname-bin",
        "dfa-size-limit",
        "regex-size-limit",
        "hyperlink-format",
        "generate",
    ],
    recursive_by_default: true,
    recursive_short: &[],
    recursive_long: &[],
    digits_recurse: false,
    metadata_short: &['l', 'c', 'q'],
    metadata_long: &[
        "files-with-matches",
        "files-without-match",
        "count",
        "count-matches",
        "quiet",
        "files",
        "type-list",
    ],
    pattern_short: &['e', 'f'],
    pattern_long: &["regexp", "file", "files", "type-list"],
    pattern_file_short: &['f'],
    pattern_file_long: &["file"],
};

const AG_SPEC: SearchSpec = SearchSpec {
    short_with_value: &['G', 'g', 'm', 'p'],
    long_with_value: &[
        "file-search-regex",
        "max-count",
        "ignore",
        "ignore-dir",
        "depth",
        "workers",
        "pager",
        "path-to-ignore",
        "width",
    ],
    recursive_by_default: true,
    recursive_short: &[],
    recursive_long: &[],
    digits_recurse: false,
    metadata_short: &['l', 'L', 'c', 'g'],
    metadata_long: &["files-with-matches", "files-without-matches", "count"],
    pattern_short: &['g'],
    pattern_long: &[],
    pattern_file_short: &[],
    pattern_file_long: &[],
};

const ACK_SPEC: SearchSpec = SearchSpec {
    short_with_value: &['A', 'B', 'C', 'm', 'g'],
    long_with_value: &[
        "after-context",
        "before-context",
        "context",
        "max-count",
        "type",
        "ignore-dir",
        "noignore-dir",
        "ignore-file",
        "pager",
        "color-filename",
        "color-match",
        "color-lineno",
        "output",
        "match",
    ],
    recursive_by_default: true,
    recursive_short: &[],
    recursive_long: &[],
    digits_recurse: false,
    metadata_short: &['l', 'L', 'c', 'f', 'g'],
    metadata_long: &["files-with-matches", "files-without-matches", "count"],
    pattern_short: &['f', 'g'],
    pattern_long: &["match"],
    pattern_file_short: &[],
    pattern_file_long: &[],
};

fn search_spec(program: &str) -> Option<&'static SearchSpec> {
    match program {
        "grep" | "egrep" | "fgrep" | "zgrep" | "zegrep" | "zfgrep" | "bzgrep" | "xzgrep" => {
            Some(&GREP_SPEC)
        }
        "ugrep" | "ug" => Some(&UGREP_SPEC),
        "rg" => Some(&RG_SPEC),
        "ag" => Some(&AG_SPEC),
        "ack" | "ack-grep" => Some(&ACK_SPEC),
        _ => None,
    }
}

struct SearchPaths {
    paths: Vec<String>,
    exposure: PathExposure,
}

/// The files and directories a grep-family command searches, and whether it
/// prints their content. Only the first simple command of a pipeline reaches
/// here, like the other readers.
///
/// A recursive search with no operand searches the working directory. An
/// operand with a shell wildcard is kept literally and, when the search
/// recurses, also as the directory before its first wildcard, since the shell
/// will expand it into names this function cannot see.
fn search_command_paths(program: &str, args: &[String]) -> Option<SearchPaths> {
    let spec = search_spec(command_name(program))?;

    let mut operands: Vec<&str> = Vec::new();
    let mut pattern_files: Vec<&str> = Vec::new();
    let mut recursive = spec.recursive_by_default;
    let mut metadata_only = false;
    let mut has_pattern_option = false;
    let mut options_ended = false;
    let mut index = 0;

    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;

        if options_ended || arg == "-" || !arg.starts_with('-') {
            operands.push(arg);
            continue;
        }

        if arg == "--" {
            options_ended = true;
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline_value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            metadata_only |= spec.metadata_long.contains(&name);
            // GNU-style parsers accept an unambiguous abbreviation of a long
            // option (`--recurs`). Missing one that recurses or carries the
            // pattern would hide a search or a path, so these two match by
            // prefix; the other tables match exactly because a miss there
            // only adds a path.
            recursive |= abbreviates_any(spec.recursive_long, name);
            has_pattern_option |= abbreviates_any(spec.pattern_long, name);

            let value = match inline_value {
                None if spec.long_with_value.contains(&name) => {
                    index += 1;
                    args.get(index - 1).map(String::as_str)
                }
                other => other,
            };
            recursive |= name == "directories" && value == Some("recurse");
            if spec.pattern_file_long.contains(&name)
                && let Some(file) = value
            {
                pattern_files.push(file);
            }
            continue;
        }

        let cluster = &arg[1..];
        if spec.digits_recurse && cluster.chars().all(|ch| ch.is_ascii_digit()) {
            recursive = true;
            continue;
        }

        for (offset, flag) in cluster.char_indices() {
            metadata_only |= spec.metadata_short.contains(&flag);
            recursive |= spec.recursive_short.contains(&flag);
            has_pattern_option |= spec.pattern_short.contains(&flag);

            if spec.short_with_value.contains(&flag) {
                let attached = &cluster[offset + flag.len_utf8()..];
                let value = if attached.is_empty() {
                    index += 1;
                    args.get(index - 1).map(String::as_str)
                } else {
                    Some(attached)
                };
                recursive |= flag == 'd' && value == Some("recurse");
                if spec.pattern_file_short.contains(&flag)
                    && let Some(file) = value
                {
                    pattern_files.push(file);
                }
                break;
            }
        }
    }

    // The first operand is the pattern unless an option already supplied one.
    if !has_pattern_option && !operands.is_empty() {
        operands.remove(0);
    }
    operands.retain(|operand| *operand != "-" && !looks_like_redirection(operand));

    if operands.is_empty() && recursive && collect_input_redirect_paths(args).is_empty() {
        operands.push(".");
    }

    let mut paths: Vec<String> = pattern_files
        .iter()
        .map(|file| (*file).to_owned())
        .collect();
    for operand in operands {
        paths.push(operand.to_owned());
        if recursive && let Some(directory) = directory_before_wildcard(operand) {
            paths.push(directory);
        }
    }

    // A pattern file is read as input and its content shapes the output, so a
    // names-and-counts flag does not make reading it metadata-only.
    let exposure = if metadata_only && pattern_files.is_empty() {
        PathExposure::MetadataOnly
    } else {
        PathExposure::ReadsContents
    };

    Some(SearchPaths { paths, exposure })
}

/// Whether `name` is one of `names` or an abbreviation of one (three or more
/// characters, as a parser would need to tell options apart).
fn abbreviates_any(names: &[&str], name: &str) -> bool {
    names
        .iter()
        .any(|candidate| *candidate == name || (name.len() >= 3 && candidate.starts_with(name)))
}

fn looks_like_redirection(operand: &str) -> bool {
    let rest = operand.trim_start_matches(|ch: char| ch.is_ascii_digit());
    rest.starts_with(['<', '>']) || rest.starts_with("&>")
}

fn has_shell_wildcard(operand: &str) -> bool {
    operand.contains(['*', '?', '[', '{'])
}

/// The longest leading run of path components with no wildcard (`.` when the
/// first component already has one), or `None` when there is no wildcard.
fn directory_before_wildcard(operand: &str) -> Option<String> {
    if !has_shell_wildcard(operand) {
        return None;
    }

    let mut prefix = PathBuf::new();
    for component in Path::new(operand).components() {
        if has_shell_wildcard(&component.as_os_str().to_string_lossy()) {
            break;
        }
        prefix.push(component);
    }

    if prefix.as_os_str().is_empty() {
        Some(".".to_owned())
    } else {
        Some(prefix.to_string_lossy().into_owned())
    }
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

    // --- bd-1si: directory-scope Grep and content search ---

    /// Exposure and candidates of a Bash command, with candidates shown
    /// relative to the workspace (`.` is the workspace itself).
    fn search(command: &str) -> (PathExposure, Vec<String>) {
        let extraction = extract_bash_read_paths(command, workspace());
        let candidates = extraction
            .candidates
            .iter()
            .map(|path| match path.strip_prefix(workspace()) {
                Ok(relative) if relative.as_os_str().is_empty() => ".".to_owned(),
                Ok(relative) => relative.to_string_lossy().into_owned(),
                Err(_) => path.to_string_lossy().into_owned(),
            })
            .collect();

        (extraction.exposure, candidates)
    }

    fn assert_search(command: &str, exposure: PathExposure, candidates: &[&str]) {
        assert_eq!(
            search(command),
            (
                exposure,
                candidates.iter().map(|path| (*path).to_owned()).collect()
            ),
            "command: {command}"
        );
    }

    #[test]
    fn grep_without_a_path_searches_the_working_directory() {
        for raw in [
            r#"{"pattern":"ssn","output_mode":"content"}"#,
            r#"{"pattern":"ssn","output_mode":"content","path":""}"#,
            r#"{"pattern":"ssn","output_mode":"content","path":null}"#,
        ] {
            let extraction = extract_read_or_grep_paths(ToolKind::Grep, raw, workspace());

            assert_eq!(extraction.exposure, PathExposure::ReadsContents, "{raw}");
            assert_eq!(
                extraction.candidates,
                vec![workspace().to_path_buf()],
                "{raw}"
            );
        }
    }

    #[test]
    fn grep_with_an_omitted_output_mode_reads_contents() {
        let extraction =
            extract_read_or_grep_paths(ToolKind::Grep, r#"{"path":"data"}"#, workspace());

        assert_eq!(extraction.exposure, PathExposure::ReadsContents);
        assert_eq!(
            extraction.candidates,
            vec![PathBuf::from("/workspace/veil/data")]
        );
    }

    #[test]
    fn grep_count_and_files_with_matches_are_metadata_only() {
        for mode in ["count", "files_with_matches"] {
            let extraction = extract_read_or_grep_paths(
                ToolKind::Grep,
                &json!({ "path": "data", "output_mode": mode }).to_string(),
                workspace(),
            );

            assert_eq!(extraction.exposure, PathExposure::MetadataOnly, "{mode}");
            assert_eq!(
                extraction.candidates,
                vec![PathBuf::from("/workspace/veil/data")],
                "{mode}"
            );
        }
    }

    #[test]
    fn a_read_without_a_path_still_has_no_candidates() {
        let extraction =
            extract_read_or_grep_paths(ToolKind::Read, r#"{"pattern":"x"}"#, workspace());

        assert_eq!(extraction, PathExtraction::none());
    }

    #[test]
    fn grep_family_content_searches_read_contents() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep ssn data/x.csv", Reads, &["data/x.csv"]);
        assert_search("grep -r ssn data", Reads, &["data"]);
        assert_search("grep -rn ssn data/", Reads, &["data"]);
        assert_search("grep -R -i ssn data other", Reads, &["data", "other"]);
        assert_search("egrep -r 'ssn|ein' data", Reads, &["data"]);
        assert_search("/usr/bin/grep -r ssn data", Reads, &["data"]);
        assert_search("env LC_ALL=C grep -r ssn data", Reads, &["data"]);
        assert_search("rg ssn data/", Reads, &["data"]);
        assert_search("rg -n -C 2 ssn data", Reads, &["data"]);
        assert_search("ag ssn data", Reads, &["data"]);
        assert_search("ack ssn data", Reads, &["data"]);
        assert_search("ugrep -r ssn data", Reads, &["data"]);
        assert_search("ug -rn ssn data", Reads, &["data"]);
    }

    #[test]
    fn names_and_counts_only_searches_are_metadata_only() {
        use PathExposure::MetadataOnly as Meta;

        assert_search("grep -l ssn data/x.csv", Meta, &["data/x.csv"]);
        assert_search("grep -rl ssn data", Meta, &["data"]);
        assert_search("grep -r --files-with-matches ssn data", Meta, &["data"]);
        assert_search("grep -rL ssn data", Meta, &["data"]);
        assert_search("grep -c ssn data/x.csv", Meta, &["data/x.csv"]);
        assert_search("grep -rc ssn data", Meta, &["data"]);
        assert_search("grep -r --count ssn data", Meta, &["data"]);
        assert_search("grep -rq ssn data", Meta, &["data"]);
        assert_search("rg -l ssn data", Meta, &["data"]);
        assert_search("rg -c ssn data", Meta, &["data"]);
        assert_search("rg --count-matches ssn data", Meta, &["data"]);
        assert_search("rg --files data", Meta, &["data"]);
        assert_search("rg --files", Meta, &["."]);
        assert_search("ag -l ssn data", Meta, &["data"]);
        assert_search("ag -c ssn data", Meta, &["data"]);
        assert_search("ag -g csv data", Meta, &["data"]);
        assert_search("ack -l ssn data", Meta, &["data"]);
        assert_search("ack -f data", Meta, &["data"]);
        assert_search("ugrep -rl ssn data", Meta, &["data"]);
    }

    #[test]
    fn a_recursive_search_with_no_operand_searches_the_working_directory() {
        use PathExposure::{MetadataOnly as Meta, ReadsContents as Reads};

        assert_search("grep -r ssn", Reads, &["."]);
        assert_search("grep -R ssn", Reads, &["."]);
        assert_search("grep --recursive ssn", Reads, &["."]);
        assert_search("grep -d recurse ssn", Reads, &["."]);
        assert_search("grep --directories=recurse ssn", Reads, &["."]);
        assert_search("grep -rl ssn", Meta, &["."]);
        assert_search("rg ssn", Reads, &["."]);
        assert_search("rg -l ssn", Meta, &["."]);
        assert_search("ag ssn", Reads, &["."]);
        assert_search("ack ssn", Reads, &["."]);
        assert_search("ug -2 ssn", Reads, &["."]);
    }

    #[test]
    fn a_search_that_reads_standard_input_has_no_path_to_check() {
        assert_eq!(search("grep ssn"), (PathExposure::None, vec![]));
        assert_eq!(search("grep -n ssn -"), (PathExposure::None, vec![]));
        assert_eq!(search("git grep ssn"), (PathExposure::None, vec![]));
        assert_search(
            "grep ssn < data/x.csv",
            PathExposure::ReadsContents,
            &["data/x.csv"],
        );
        assert_search(
            "rg ssn < data/x.csv",
            PathExposure::ReadsContents,
            &["data/x.csv"],
        );
    }

    #[test]
    fn option_values_are_not_mistaken_for_the_pattern_or_the_paths() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep -e ssn -r data", Reads, &["data"]);
        assert_search("grep -A 3 -r ssn data", Reads, &["data"]);
        assert_search("grep -nA3 ssn data/x", Reads, &["data/x"]);
        assert_search("grep -m 5 -r ssn data", Reads, &["data"]);
        assert_search("grep --include '*.csv' -r ssn data", Reads, &["data"]);
        assert_search("grep --include=*.csv -r ssn data", Reads, &["data"]);
        assert_search(
            "grep --exclude-dir node_modules -r ssn data",
            Reads,
            &["data"],
        );
        assert_search("grep -r -- -weird data", Reads, &["data"]);
        assert_search("grep -r ssn -- data", Reads, &["data"]);
        assert_search("rg -g '*.csv' ssn data", Reads, &["data"]);
        assert_search("rg -t csv -e ssn data other", Reads, &["data", "other"]);
        assert_search("rg --max-depth 2 --color never ssn data", Reads, &["data"]);
        assert_search("rg -r REDACTED ssn data", Reads, &["data"]);
        assert_search("ag -G '\\.csv$' ssn data", Reads, &["data"]);
        assert_search("ack -A 2 ssn data", Reads, &["data"]);
        assert_search("ug -g '*.csv' -r ssn data", Reads, &["data"]);
    }

    #[test]
    fn abbreviated_long_options_still_recurse_and_still_carry_the_pattern() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep --recurs ssn", Reads, &["."]);
        assert_search("grep --rec ssn", Reads, &["."]);
        assert_search("grep -r --reg=ssn data", Reads, &["data"]);
        assert_search("grep -r --regex ssn data", Reads, &["ssn", "data"]);
    }

    #[test]
    fn ugrep_value_options_are_not_mistaken_for_the_pattern_or_the_paths() {
        use PathExposure::ReadsContents as Reads;

        assert_search("ugrep -N skip -e ssn -r data", Reads, &["data"]);
        // `--and` may or may not replace the positional pattern, so `bar` is
        // kept as a harmless extra path rather than risk dropping a real one.
        assert_search("ug --and foo -r bar data", Reads, &["bar", "data"]);
        assert_search("ug -O rs,toml -r ssn data", Reads, &["data"]);
        assert_search("ug --file-type=rust -r ssn data", Reads, &["data"]);
        assert_search(
            "ug --max-files 3 --min-size 1k -r ssn data",
            Reads,
            &["data"],
        );
        // `grep` is ugrep on some machines, so ugrep-only options do not hide a path.
        assert_search("grep -N skip -e ssn -r data", Reads, &["skip", "data"]);
        // BSD grep's --context value is optional, so it never swallows an operand.
        assert_search("grep --context -r ssn data", Reads, &["data"]);
    }

    #[test]
    fn a_pattern_file_is_a_content_read_even_when_the_output_is_names_only() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep -f data/p.txt src", Reads, &["data/p.txt", "src"]);
        assert_search("grep -rl -f data/p.txt src", Reads, &["data/p.txt", "src"]);
        assert_search(
            "grep --file=data/p.txt -r src",
            Reads,
            &["data/p.txt", "src"],
        );
        assert_search("rg -f data/p.txt src", Reads, &["data/p.txt", "src"]);
    }

    #[test]
    fn shell_wildcards_also_name_the_directory_before_them_when_the_search_recurses() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep -r ssn data/*.csv", Reads, &["data/*.csv", "data"]);
        assert_search("grep -r ssn *", Reads, &["*", "."]);
        assert_search("grep -r ssn src/*/mod.rs", Reads, &["src/*/mod.rs", "src"]);
        assert_search("rg ssn src/*.rs", Reads, &["src/*.rs", "src"]);
        // Without -r grep never descends, so the wildcard is only the literal.
        assert_search("grep ssn *.csv", Reads, &["*.csv"]);
    }

    #[test]
    fn redirections_after_a_search_are_not_paths_and_a_redirect_like_pattern_is_not_one() {
        use PathExposure::ReadsContents as Reads;

        assert_search("grep -r ssn data 2>&1", Reads, &["data"]);
        assert_search("grep -r ssn data 2>/dev/null", Reads, &["data"]);
        // The pattern `1>2` is dropped as the pattern, so the path survives.
        assert_search("grep '1>2' data/x", Reads, &["data/x"]);
    }

    #[test]
    fn existing_readers_keep_their_exposure() {
        assert_search(
            "cat data/x.csv",
            PathExposure::ReadsContents,
            &["data/x.csv"],
        );
        assert_search(
            "head -n 5 data/x.csv",
            PathExposure::ReadsContents,
            &["data/x.csv"],
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
