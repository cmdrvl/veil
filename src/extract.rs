#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::types::ToolKind;

mod decompose;
mod egress;
mod exec;
mod expand;
mod jq;
mod lookup;
mod redirect;
mod script;
mod sed;
mod wrappers;
mod written;

pub use decompose::{
    MAX_DEPTH, MAX_SEGMENTS, Origin, STDIN_ARGUMENTS, SUBSTITUTION, ShellEnv, SimpleCommand,
    decompose, decompose_in,
};

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
    R,
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

/// What one simple command of a Bash tool command would read, and how it was
/// reached. Each one is evaluated on its own (bd-2kr).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandExtraction {
    pub origin: Origin,
    /// The command's words, for the checks that look at the command rather than
    /// at a path (an authorized spine tool). Empty for Read and Grep, and for
    /// text that could not be analysed.
    pub argv: Vec<String>,
    pub exposure: PathExposure,
    /// Paths a recognised reader (cat, grep, a redirect, an interpreter's
    /// accessor...) reads. These are direct reads.
    pub candidates: Vec<PathBuf>,
    /// Paths named in the command's words by any other command: `awk 1 x.csv`,
    /// `cp x.csv /tmp`, `curl -F f=@x.csv`. Never a path already in
    /// `candidates` (bd-29r).
    pub argv_paths: Vec<ArgvPath>,
    /// What the command does with `argv_paths`: it reads them, unless it is one
    /// of the commands that print only names, counts or sizes.
    pub argv_exposure: PathExposure,
    /// Whether a directory among `argv_paths` stands for everything beneath it.
    /// True for the commands that copy, archive or upload whole trees.
    pub argv_scans_directories: bool,
    /// Words that depend on something veil cannot resolve to a path: a
    /// variable it was not told the value of, a `$( )` result, or what `xargs`
    /// reads from standard input ([`STDIN_ARGUMENTS`]). As written (bd-2mi).
    pub unresolved: Vec<String>,
    /// The command's working directory depends on a path veil could not resolve.
    pub cwd_unresolved: bool,
    /// The command could not be analysed at all: unbalanced quotes, or more
    /// segments or nesting than veil follows (bd-2mi).
    pub opaque: bool,
    /// The command is one that reads or ships the files it is given, or its
    /// program is itself unresolved: an unresolved argument is blocked even
    /// when nothing protected is in play. Any other command is blocked only
    /// where a protected path is (bd-2mi).
    pub dynamic_strict: bool,
    /// What the command string assigns to variables (`d=data/clients`), as
    /// paths. A protected one puts every command of the string in a protected
    /// context (bd-2mi).
    pub assigned_paths: Vec<PathBuf>,
    /// The command sends what it is given somewhere else (`curl`, `scp`,
    /// `aws`, a mail client...). A protected path it names is an egress
    /// attempt, which the audit log records as such (bd-x8o).
    pub egress: bool,
    /// The script file this command came from, when it is not one the person
    /// typed: veil read a script an interpreter was asked to run and these are
    /// the paths in it (bd-1bk).
    pub script: Option<ScriptSource>,
    /// What the command's words say it writes: the targets of its output
    /// redirections and the values of words with `=` (`dd of=x`,
    /// `--output=x`). Only veil's own derived registry and key are checked
    /// against these (bd-3qw), so a word taken for a target by mistake costs
    /// nothing.
    pub write_targets: Vec<PathBuf>,
    /// The files the shell opens for writing on this command's line, told from
    /// quoted `>`s. One that a read would be refused is refused, whatever the
    /// command does with its words (bd-qe9).
    pub redirect_targets: Vec<PathBuf>,
    /// The command string changes which program a name runs, so a command in
    /// it gets no spine-tool authority (bd-jn6).
    pub lookup_changed: bool,
}

/// A script file an interpreter runs, read by veil as the text it is (bd-1bk).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptSource {
    /// As the command named it: `read.py`, `./tools/run.sh`.
    pub name: String,
    /// Where it is.
    pub path: PathBuf,
    /// The directory it runs in: where a relative path inside it resolves.
    pub run_in: PathBuf,
    /// Why veil did not read all of it, when it did not: it is larger than the
    /// limit, or the command runs more scripts than veil follows.
    pub unread: Option<String>,
}

/// A path a command names in its words. `resolved` says veil followed symlinks
/// and checked the filesystem; it is false for the words past
/// [`ARGV_FILESYSTEM_BUDGET`], which are only normalised as text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgvPath {
    pub path: PathBuf,
    pub resolved: bool,
}

/// How many words of one command veil resolves against the filesystem for the
/// path-anywhere-in-argv rule (bd-29r): the performance bound on the stat calls
/// one command can cost. Words past it are normalised as text, never statted.
pub const ARGV_FILESYSTEM_BUDGET: usize = 64;

impl CommandExtraction {
    /// A Read or Grep call: one path source with no command words.
    pub fn from_path_extraction(extraction: PathExtraction) -> Self {
        Self {
            origin: Origin::Top,
            argv: Vec::new(),
            exposure: extraction.exposure,
            candidates: extraction.candidates,
            argv_paths: Vec::new(),
            argv_exposure: PathExposure::None,
            argv_scans_directories: false,
            unresolved: Vec::new(),
            cwd_unresolved: false,
            opaque: false,
            dynamic_strict: false,
            assigned_paths: Vec::new(),
            egress: false,
            script: None,
            write_targets: Vec::new(),
            redirect_targets: Vec::new(),
            lookup_changed: false,
        }
    }

    /// Some argument depends on something veil could not resolve, or the whole
    /// command could not be analysed.
    pub fn has_dynamic_args(&self) -> bool {
        !self.unresolved.is_empty() || self.cwd_unresolved || self.opaque
    }
}

/// The simple commands of a Bash tool command, in the order they would run,
/// each with the paths it reads. A command that reads nothing is still listed:
/// its words may name an authorized spine tool.
pub fn extract_bash_commands(command: &str, cwd: &Path) -> Vec<CommandExtraction> {
    let env = ShellEnv {
        cwd: Some(cwd.to_path_buf()),
        home: home_directory(),
    };

    let mut commands = Vec::new();
    let mut scripts = script::Scripts::default();

    let simple_commands = decompose_in(command, &env);
    // A script the string writes is read as written, not as it is on disk now.
    scripts.collect_writes(&simple_commands, cwd);
    let lookup_changed = simple_commands.iter().any(|simple| simple.lookup_changed);

    for simple in simple_commands {
        let cwd = simple.cwd.as_deref().unwrap_or(cwd);

        commands.push(command_extraction(&simple, cwd));
        // An interpreter run on a script file: what is in the file is read too.
        script::inspect(&simple, cwd, &env, 0, &mut scripts, &mut commands);
    }

    // what the string changes, the scripts it runs inherit
    if lookup_changed {
        for found in &mut commands {
            found.lookup_changed = true;
        }
    }

    commands
}

fn home_directory() -> Option<String> {
    std::env::var("HOME").ok().filter(|home| !home.is_empty())
}

/// What standard input is for a command that reads its script from it
/// (`sed -f -`): the text of a here-document or here-string, a file redirected
/// in, or something veil cannot see, such as a pipe.
fn script_stdin<'a>(command: &'a SimpleCommand, args: &'a [String]) -> sed::Stdin<'a> {
    if let Some(body) = &command.heredoc_body {
        return sed::Stdin::Text(body);
    }

    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "<<<" {
            if let Some(text) = words.next() {
                return sed::Stdin::Text(text);
            }
        } else if let Some(text) = word.strip_prefix("<<<") {
            return sed::Stdin::Text(text);
        }
    }

    if command.redirects_in.is_empty() {
        sed::Stdin::Unknown
    } else {
        sed::Stdin::File
    }
}

fn command_extraction(command: &SimpleCommand, cwd: &Path) -> CommandExtraction {
    let assigned_paths = assigned_paths(&command.assigned, cwd);

    let Some((program, args)) = command.argv.split_first() else {
        // Text that could not be analysed: there is nothing to read paths
        // from, and the dynamic-argument stance decides what to do with it.
        return CommandExtraction {
            origin: command.origin,
            argv: Vec::new(),
            exposure: PathExposure::None,
            candidates: Vec::new(),
            argv_paths: Vec::new(),
            argv_exposure: PathExposure::None,
            argv_scans_directories: false,
            unresolved: Vec::new(),
            cwd_unresolved: command.cwd_unresolved,
            opaque: true,
            dynamic_strict: true,
            assigned_paths,
            egress: false,
            script: None,
            write_targets: Vec::new(),
            redirect_targets: redirect_targets(command, cwd),
            lookup_changed: command.lookup_changed,
        };
    };

    let (mut paths, exposure) = match search_command_paths(
        program,
        args,
        !command.redirects_in.is_empty(),
        command.stdin_piped,
    ) {
        Some(search) => (search.paths, search.exposure),
        None => (
            command_paths(program, args).unwrap_or_default(),
            PathExposure::ReadsContents,
        ),
    };
    paths.extend(command.redirects_in.iter().cloned());
    paths.extend(collect_inline_interpreter_paths(program, args));
    if let Some(body) = &command.heredoc_body {
        paths.extend(heredoc_script_paths(program, body));
        paths.extend(egress::script_paths(program, body));
    }
    paths.extend(egress::here_string_paths(program, args));
    paths.extend(egress::option_script_paths(program, args));

    // The files a sed script reads (`r`, `R`) are read like a `cat`'s; the ones
    // it writes (`w`, `W`, the `w` flag of `s`) are named paths, judged with the
    // other words of the command (bd-pm8). A script file (`-f read.sed`) is read
    // by `script.rs`; a `-f -` is read from here, where standard input is.
    let sed_script = sed::is_sed(command_name(program))
        .then(|| sed::script_files(args, script_stdin(command, args)));
    if let Some(script) = &sed_script {
        paths.extend(script.reads.iter().cloned());
    }
    let mut named: Vec<String> = sed_script
        .as_ref()
        .map_or_else(Vec::new, |script| script.writes.clone());

    // A jq program names the files it imports by a string with no slash and no
    // extension (`import "secret" as $d;` opens ./secret.json). The files it may
    // open are named paths, judged with the other words (bd-3h5). The program
    // file of `-f` and the modules an import loads are read by `script.rs`.
    let jq_program = jq::is_jq(command_name(program))
        .then(|| jq::inline_files(args, home_directory().as_deref()));
    if let Some(imports) = &jq_program {
        named.extend(imports.files.iter().cloned());
    }
    let script_writes: &[String] = &named;

    // A reader veil parses names its files exactly, so an unresolved word that
    // is a pattern or an option's value (`grep "$p" file`, `head -n $n file`)
    // is no file at all.
    let mut unresolved = if is_known_reader(program) {
        unresolved_files(&command.unresolved, &paths)
    } else {
        command.unresolved.clone()
    };
    // A jq program whose imports veil cannot read is as opaque as a word it
    // cannot resolve, and is refused the same way (bd-3h5).
    if let Some(text) = jq_program.and_then(|imports| imports.refused) {
        unresolved.push(text);
    }
    // A sed script veil cannot parse, or one that runs a command, is as opaque
    // as a word it cannot resolve: the dynamic-argument stance decides (bd-pm8).
    if let Some(script) = sed_script
        .as_ref()
        .and_then(|script| script.refused.clone())
    {
        unresolved.push(script);
    }
    // A program that hands the shell a command it builds at run time
    // (`os.system(cmd)`) is the same: the command it runs cannot be judged
    // (bd-5iy). The commands it spells out are judged by `script.rs`.
    let inline_refusal = script::inline_refusal(command);
    if let Some(call) = &inline_refusal {
        unresolved.push(call.clone());
    }

    let candidates = normalize_candidates(paths, cwd);
    let exposure = if candidates.is_empty() {
        PathExposure::None
    } else {
        exposure
    };

    // The readers above know which of their words are paths. Any other command
    // is judged by the path-shaped words it carries (bd-29r).
    let (argv_paths, argv_exposure, argv_scans_directories) = if is_known_reader(program) {
        (Vec::new(), PathExposure::None, false)
    } else {
        let exposure = argv_exposure(program, args);
        let scans_directories = BULK_TRANSFER_COMMANDS.contains(&command_name(program));
        let paths = argv_paths(
            program,
            args,
            script_writes,
            exposure == PathExposure::ReadsContents,
            &candidates,
            cwd,
        );
        (paths, exposure, scans_directories)
    };

    CommandExtraction {
        origin: command.origin,
        argv: command.argv.clone(),
        exposure,
        candidates,
        argv_paths,
        argv_exposure,
        argv_scans_directories,
        unresolved,
        cwd_unresolved: command.cwd_unresolved,
        opaque: false,
        dynamic_strict: is_dynamic_strict(program)
            || command.cwd_unresolved
            || inline_refusal.is_some(),
        assigned_paths,
        egress: egress::is_egress(program, args),
        script: None,
        write_targets: write_targets(&command.argv, cwd, home_directory().as_deref()),
        redirect_targets: redirect_targets(command, cwd),
        lookup_changed: command.lookup_changed,
    }
}

/// The paths a command's words say it writes.
fn write_targets(argv: &[String], cwd: &Path, home: Option<&str>) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut words = argv.iter().peekable();
    while let Some(word) = words.next() {
        let target = match output_redirection(word) {
            Some("") => words.peek().map(|next| next.as_str()),
            Some(attached) => Some(attached),
            None => word.split_once('=').map(|(_, value)| value),
        };
        let Some(target) = target.filter(|target| !target.is_empty()) else {
            continue;
        };
        // the shell expands `~` after an operator or an `=`, inside the word
        let expanded = match (target.strip_prefix('~'), home) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                format!("{home}{rest}")
            }
            _ => target.to_owned(),
        };
        // not normalised: `..` after a symlink goes where the symlink goes
        let path = cwd.join(expanded);
        if !targets.contains(&path) {
            targets.push(path);
        }
    }
    targets
}

/// What follows the operator of a word that redirects output (`>`, `>>`, `>|`,
/// `>&`, `&>`, `<>`, with or without a file descriptor): the target, or nothing
/// when the target is the next word.
fn output_redirection(word: &str) -> Option<&str> {
    redirect::after_operator(word).map(|rest| rest.trim_start_matches(['>', '|', '&']))
}

/// The files a command's line opens for writing, from the directory the command
/// runs in where the decomposer did not know it.
fn redirect_targets(command: &SimpleCommand, cwd: &Path) -> Vec<PathBuf> {
    // not normalised: `..` after a symlink goes where the symlink goes
    let from_cwd = |target: &String| cwd.join(target);
    command.redirects_out.iter().map(from_cwd).collect()
}

/// What is unresolved among the files a reader will open: the words `paths`
/// that still carry a variable, a `$( )` result or a brace list too long to
/// expand, and what `xargs` appends from standard input.
fn unresolved_files(unresolved: &[String], paths: &[String]) -> Vec<String> {
    let mut files: Vec<String> = unresolved
        .iter()
        .filter(|word| word.as_str() == STDIN_ARGUMENTS)
        .cloned()
        .collect();

    files.extend(
        paths
            .iter()
            .filter(|path| {
                path.contains(['$', SUBSTITUTION])
                    || (path.contains('{') && (path.contains(',') || path.contains("..")))
            })
            .cloned(),
    );
    files
}

/// Commands that print or ship the contents of the files they are given, besides
/// the readers and bulk transfers veil already knows. With an argument veil
/// cannot resolve, any of them may be reading a protected file.
const CONTENT_FILTER_COMMANDS: &[&str] = &[
    "awk",
    "gawk",
    "mawk",
    "sed",
    "gsed",
    "jq",
    "yq",
    "cut",
    "sort",
    "uniq",
    "tr",
    "paste",
    "join",
    "comm",
    "column",
    "nl",
    "fold",
    "fmt",
    "rev",
    "tac",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "base64",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    "diff",
    "cmp",
    "split",
    "iconv",
    "dd",
    "sqlite3",
    "duckdb",
    "zcat",
    "gzcat",
    "bzcat",
    "xzcat",
    "zgrep",
];

/// Whether an argument veil cannot resolve is blocked for this program even
/// where nothing protected is in play (bd-2mi): a reader, a filter or a bulk
/// transfer, or a program that is itself a variable or a `$( )` result.
fn is_dynamic_strict(program: &str) -> bool {
    let name = command_name(program);

    program.contains(['$', SUBSTITUTION])
        || is_known_reader(program)
        || CONTENT_FILTER_COMMANDS.contains(&name)
        || BULK_TRANSFER_COMMANDS.contains(&name)
}

/// The values a command string assigns to variables, as the paths they would
/// name from `cwd`. A value of several words stands for each of them.
fn assigned_paths(values: &[String], cwd: &Path) -> Vec<PathBuf> {
    normalize_candidates(
        values
            .iter()
            .flat_map(|value| value.split_whitespace())
            .map(str::to_owned)
            .collect(),
        cwd,
    )
}

/// Commands whose own parser tells veil exactly which words are paths, so the
/// generic rule would only add the pattern of a search or a number of lines.
fn is_known_reader(program: &str) -> bool {
    let name = command_name(program);
    search_spec(name).is_some() || matches!(name, "cat" | "bat" | "less" | "more" | "head" | "tail")
}

/// Commands that print names, counts, sizes or types, or that only create,
/// remove or re-permission what they name. Naming a protected path does not
/// put its content in the agent's context or copy it anywhere, so the rule
/// allows them and the audit log records the access. A short, closed list:
/// anything else that names a protected path is judged as a read.
const NAMES_AND_COUNTS_COMMANDS: &[&str] = &[
    "ls", "dir", "vdir", "wc", "stat", "du", "df", "tree", "file", "test", "[", "[[", "find",
    "realpath", "readlink", "basename", "dirname", "mkdir", "rmdir", "touch", "rm", "chmod",
    "chown", "chgrp", "cd", "pushd", "popd", "pwd", "echo", "printf", "true", "false", "which",
    "type", "mktemp",
];

/// `git` subcommands that stage, restore, list or commit paths without
/// printing what is in them. `diff`, `show`, `log -p`, `blame`, `cat-file`,
/// `archive` and the rest print or export content and stay reads.
const GIT_NAMES_ONLY_SUBCOMMANDS: &[&str] = &[
    "add",
    "rm",
    "mv",
    "restore",
    "reset",
    "checkout",
    "switch",
    "status",
    "ls-files",
    "ls-tree",
    "check-ignore",
    "commit",
    "rev-parse",
    "clean",
    "stash",
    "update-index",
];

/// Commands that carry a whole directory tree somewhere: copy, archive, sync or
/// upload. Naming a directory to one of them names everything beneath it.
const BULK_TRANSFER_COMMANDS: &[&str] = &[
    "cp", "mv", "tar", "zip", "unzip", "gzip", "bzip2", "xz", "7z", "7za", "rsync", "scp", "sftp",
    "rclone", "ditto", "pax", "cpio", "install", "curl", "wget", "aws", "gsutil", "az", "docker",
    "podman",
];

/// Extensions that mark a word as a file name even when nothing by that name
/// exists yet, or exists only after the shell expands a glob.
const FILE_EXTENSIONS: &[&str] = &[
    "csv", "tsv", "psv", "txt", "log", "json", "jsonl", "ndjson", "geojson", "xml", "xlsx", "xlsm",
    "xls", "ods", "parquet", "feather", "arrow", "orc", "avro", "sqlite", "sqlite3", "db",
    "duckdb", "mdb", "accdb", "sql", "dump", "bak", "pkl", "pickle", "npy", "npz", "h5", "hdf5",
    "sav", "dta", "sas7bdat", "pdf", "doc", "docx", "ppt", "pptx", "rtf", "zip", "gz", "tgz",
    "bz2", "xz", "zst", "tar", "7z", "yaml", "yml", "toml", "ini", "conf", "cfg", "env", "pem",
    "key", "crt", "cer", "p12", "pfx", "kdbx", "sh", "py", "rb", "pl", "js", "ts",
];

fn argv_exposure(program: &str, args: &[String]) -> PathExposure {
    let name = command_name(program);

    if NAMES_AND_COUNTS_COMMANDS.contains(&name) {
        return PathExposure::MetadataOnly;
    }

    if name == "git"
        && git_subcommand(args).is_some_and(|sub| GIT_NAMES_ONLY_SUBCOMMANDS.contains(&sub))
    {
        return PathExposure::MetadataOnly;
    }

    PathExposure::ReadsContents
}

/// The subcommand of a `git` command line, after the global options that take
/// a value (`-C dir`, `-c key=value`, `--git-dir=...`).
fn git_subcommand(args: &[String]) -> Option<&str> {
    const WITH_VALUE: &[&str] = &[
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--exec-path",
        "--config-env",
    ];
    let mut index = 0;

    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;

        if WITH_VALUE.contains(&arg) {
            index += 1;
        } else if !arg.starts_with('-') {
            return Some(arg);
        }
    }

    None
}

/// The path-shaped words of one command, resolved. Redirections are not
/// words: `2>/dev/null` and `> out.txt` are not paths the command reads, and
/// `< file` is already a read through `redirects_in`. `reads` says whether the
/// command reads what it names, in which case a glob also names the directory
/// it starts from. `named` are files the command's own script names outright,
/// which no word of it spells (a sed script's `w .env`): each is a path whether
/// or not it exists.
fn argv_paths(
    program: &str,
    args: &[String],
    named: &[String],
    reads: bool,
    already: &[PathBuf],
    cwd: &Path,
) -> Vec<ArgvPath> {
    let mut found: Vec<ArgvPath> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = already.iter().cloned().collect();
    let mut budget = ARGV_FILESYSTEM_BUDGET;
    let mut resolver = ArgvResolver::new(cwd);

    for word in argv_path_words(program, args, named) {
        let mut resolve = |raw: &str, found: &mut Vec<ArgvPath>| {
            let resolved = budget > 0;
            let path = if resolved {
                budget -= 1;
                resolver.resolve(raw, !word.certain)
            } else if word.certain {
                lexical_path(raw, cwd)
            } else {
                // Whether a bare word names anything takes a stat.
                None
            };
            let Some(path) = path else {
                return;
            };

            if ignorable_system_path(&path) || !seen.insert(path.clone()) {
                return;
            }
            found.push(ArgvPath { path, resolved });
        };

        resolve(&word.text, &mut found);
        if reads && let Some(directory) = directory_before_wildcard(&word.text) {
            resolve(&directory, &mut found);
        }
    }

    found
}

/// `/dev` and `/proc` hold devices and process state, not files an agent
/// could use to read protected data; the exception is the file-descriptor
/// paths the evaluator blocks outright.
fn ignorable_system_path(path: &Path) -> bool {
    (path.starts_with("/dev") || path.starts_with("/proc"))
        && !crate::evaluator::is_blocked_device_path(path)
}

struct PathWord {
    text: String,
    /// Shaped like a file name (a slash, or a known extension), so it names a
    /// path whether or not one exists. A bare word is only one if it exists.
    certain: bool,
}

/// The words of a command that may name a path, in order, without
/// duplicates. Besides whole words it takes the value of `--opt=value` and
/// `key=value` (curl's `file=@x.csv`), drops a leading `@` or `<`, and takes
/// each quoted literal inside a longer word (`select * from 'x.csv'`,
/// `open('x.csv')`). The script handed to a shell is skipped: the decomposer
/// runs it as commands of its own. `named` are added last, as certain paths.
fn argv_path_words(program: &str, args: &[String], named: &[String]) -> Vec<PathWord> {
    let mut words: Vec<PathWord> = Vec::new();
    let mut add = |text: &str| {
        let text = text.trim_start_matches(['@', '<']);
        let shaped = path_shaped(text);
        let plain = is_plain_name(text);

        if text.is_empty()
            || text == "-"
            || !(shaped || plain)
            || words.iter().any(|word| word.text == text)
        {
            return;
        }
        words.push(PathWord {
            text: text.to_owned(),
            certain: shaped,
        });
    };
    let shell = wrappers::SHELLS.contains(&command_name(program));
    let mut options_ended = false;

    if program.contains('/') {
        add(program);
    }

    for word in strip_redirection_words(args) {
        if word == "--" && !options_ended {
            options_ended = true;
            continue;
        }

        if shell && word.contains(char::is_whitespace) {
            continue;
        }

        let option = !options_ended && word.starts_with('-') && word.len() > 1;
        if !option {
            add(word);
        } else if !word.starts_with("--")
            && let Some(attached) = word.get(2..)
            && path_shaped(attached)
        {
            // `-fdata/x.csv`, `-C/srv/data`: a short option with its value attached.
            add(attached);
        }
        if let Some((_, value)) = word.split_once('=') {
            add(value);
        }
        // `git show HEAD:data/x.csv`, `scp data/x.csv host:/tmp`, `rsync host:x .`
        if let Some((_, tail)) = word.rsplit_once(':') {
            add(tail);
        }
        if word.contains(['\'', '"']) {
            for literal in quoted_literals(word) {
                add(literal);
            }
        }
    }

    // A file named inside a word taken whole: `-F f=@x.csv;type=text/csv`,
    // `--data-urlencode name@x.csv`, `x.csv#label` (bd-x8o).
    for file in egress::operand_paths(program, args) {
        add(&file);
    }

    // What the command's script names outright. `add` would drop a bare name
    // that is not shaped like a path (`.env`) unless it exists, but a script's
    // `w .env` names the file whether or not it is there yet.
    for file in named {
        if !file.is_empty() && !words.iter().any(|word| word.text == *file) {
            words.push(PathWord {
                text: file.clone(),
                certain: true,
            });
        }
    }

    words
}

/// The words of `args` that are not redirections. An attached redirection
/// (`2>/dev/null`, `>out`, `2>&1`) is dropped whole. A bare operator (`>`) is
/// dropped but the word after it is kept: `cut -d '>' -f1 x.csv` hands the
/// operator to the command as data once the quotes are gone, and the word
/// after it must not disappear with it. A redirect target in a protected
/// directory is therefore still named.
fn strip_redirection_words(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|word| !is_redirection_word(word))
        .collect()
}

/// `>`, `>>`, `2>`, `&>`, `<<<`, `>|`, `2>&1`, `2>/dev/null`, `>out`...: a word
/// that starts with an optional file descriptor and a redirection operator.
fn is_redirection_word(word: &str) -> bool {
    let operator = match word.strip_prefix('&') {
        Some(rest) => rest,
        None => word.trim_start_matches(|ch: char| ch.is_ascii_digit()),
    };

    operator.starts_with(['<', '>'])
}

/// Whether a word is shaped like a file name: it has a slash, or one of the
/// extensions in [`FILE_EXTENSIONS`].
fn path_shaped(text: &str) -> bool {
    text.contains('/')
        || Path::new(text)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                FILE_EXTENSIONS
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(extension))
            })
}

/// A bare word that could be a file or directory name: no spaces, quotes,
/// wildcards or shell syntax. Whether it is one depends on the filesystem.
fn is_plain_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && !text.chars().all(|ch| ch.is_ascii_digit())
        && !text.chars().any(|ch| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '\'' | '"'
                        | '$'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                        | ';'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '`'
                        | '\\'
                        | '='
                        | ','
                )
        })
}

/// The text between each pair of matching quotes in `word`, at most eight.
fn quoted_literals(word: &str) -> Vec<&str> {
    let mut literals = Vec::new();
    let mut rest = word;

    while literals.len() < 8
        && let Some(open) = rest.find(['\'', '"'])
    {
        let quote = rest.as_bytes()[open] as char;
        let after = &rest[open + 1..];
        let Some(close) = after.find(quote) else {
            break;
        };

        literals.push(&after[..close]);
        rest = &after[close + 1..];
    }

    literals
}

/// Resolves the words of one command to canonical paths. Words usually share a
/// directory (`src/a.rs src/b.rs ...`), so each directory is canonicalized once
/// and a word then costs one `lstat`, which also shows whether the word itself
/// is a symlink; only a symlink, which can point anywhere, is canonicalized in
/// full. A word that is not there is taken to be where its directory is.
struct ArgvResolver<'a> {
    cwd: &'a Path,
    parents: std::collections::HashMap<PathBuf, Option<PathBuf>>,
}

impl<'a> ArgvResolver<'a> {
    fn new(cwd: &'a Path) -> Self {
        Self {
            cwd,
            parents: std::collections::HashMap::new(),
        }
    }

    /// The canonical path `raw` names. With `must_exist` a word that names
    /// nothing is `None`, as for a bare word that may not be a path at all.
    fn resolve(&mut self, raw: &str, must_exist: bool) -> Option<PathBuf> {
        if raw.is_empty() || raw.chars().any(char::is_control) {
            return None;
        }

        let lexical = lexical_path(raw, self.cwd)?;
        if is_fd_indirection(&lexical) {
            return normalize_path(raw, self.cwd);
        }

        let (Some(parent), Some(name)) = (lexical.parent(), lexical.file_name()) else {
            // the root itself
            return fs::canonicalize(&lexical).ok().or(Some(lexical));
        };
        let canonical_parent = self
            .parents
            .entry(parent.to_path_buf())
            .or_insert_with(|| fs::canonicalize(parent).ok())
            .clone();
        let Some(canonical_parent) = canonical_parent else {
            // the directory is not there, so neither is the word
            return if must_exist { None } else { Some(lexical) };
        };

        let candidate = canonical_parent.join(name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                fs::canonicalize(&candidate).ok().or(Some(candidate))
            }
            Ok(_) => Some(candidate),
            Err(_) if must_exist => None,
            Err(_) => Some(candidate),
        }
    }
}

/// A word as a normalised absolute path, with no filesystem access.
fn lexical_path(raw: &str, cwd: &Path) -> Option<PathBuf> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }

    let candidate = Path::new(raw);
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };

    lexical_normalize(&absolute)
}

/// Paths an interpreter reads when its script arrives as a here-document.
/// Shells are handled by the decomposer, which runs the body as a script.
fn heredoc_script_paths(program: &str, body: &str) -> Vec<String> {
    match interpreter_kind(command_name(program)) {
        Some(InterpreterKind::Python) => extract_python_script_paths(body),
        Some(InterpreterKind::Node) => extract_node_script_paths(body),
        Some(InterpreterKind::Perl) => extract_perl_script_paths(body),
        Some(InterpreterKind::Ruby) => extract_ruby_script_paths(body),
        Some(InterpreterKind::R) => extract_r_script_paths(body),
        Some(InterpreterKind::Shell) | None => Vec::new(),
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
    /// These three also search standard input, not the working directory, when
    /// given no path and fed by a pipe; `grep -r` and `ugrep -r` search the
    /// working directory regardless.
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
/// prints their content. `has_input_redirect` is a `<` on the command and
/// `stdin_piped` is a pipe feeding it.
///
/// A recursive search with no operand searches the working directory, unless
/// it reads a redirect or, for the tools that do so, a pipe. An operand with a
/// shell wildcard is kept literally and, when the search recurses, also as the
/// directory before its first wildcard, since the shell will expand it into
/// names this function cannot see.
fn search_command_paths(
    program: &str,
    args: &[String],
    has_input_redirect: bool,
    stdin_piped: bool,
) -> Option<SearchPaths> {
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

    let reads_pipe = stdin_piped && spec.recursive_by_default;
    if operands.is_empty() && recursive && !has_input_redirect && !reads_pipe {
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

        // `2>/dev/null`, `>out.txt`, `<in.csv`: not a file the command was handed
        // (what `<` reads is collected with the input redirects)
        if is_redirection_word(arg) {
            continue;
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

        if is_redirection_word(arg) {
            continue;
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

        if is_redirection_word(arg) {
            index += 1;
            continue;
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

        // Every form below starts with `<` or is `0<`: most arguments are neither.
        if !matches!(arg.as_bytes().first(), Some(b'<' | b'0')) {
            index += 1;
            continue;
        }

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
        InterpreterKind::Node
        | InterpreterKind::Perl
        | InterpreterKind::Ruby
        | InterpreterKind::R => "-e",
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

fn interpreter_kind(program: &str) -> Option<InterpreterKind> {
    match versionless(program) {
        "python" | "python3" => Some(InterpreterKind::Python),
        "node" | "nodejs" | "bun" | "deno" => Some(InterpreterKind::Node),
        "perl" => Some(InterpreterKind::Perl),
        "ruby" => Some(InterpreterKind::Ruby),
        "Rscript" => Some(InterpreterKind::R),
        "bash" | "sh" | "zsh" => Some(InterpreterKind::Shell),
        _ => None,
    }
}

/// `python3.12` is `python3`, `ruby3.2` is `ruby`: the versioned names an
/// interpreter is installed under run the same scripts.
fn versionless(program: &str) -> &str {
    for family in ["python3", "python", "ruby", "perl"] {
        if let Some(version) = program.strip_prefix(family)
            && !version.is_empty()
            && version.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        {
            return family;
        }
    }

    program
}

fn extract_interpreter_script_paths(kind: InterpreterKind, script: &str) -> Vec<String> {
    match kind {
        InterpreterKind::Python => extract_python_script_paths(script),
        InterpreterKind::Node => extract_node_script_paths(script),
        InterpreterKind::Perl => extract_perl_script_paths(script),
        InterpreterKind::Ruby => extract_ruby_script_paths(script),
        InterpreterKind::R => extract_r_script_paths(script),
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

/// R's readers: base, readr, data.table, readxl and arrow.
const R_READ_CALLS: &[&str] = &[
    "read.csv(",
    "read.csv2(",
    "read.table(",
    "read.delim(",
    "read.delim2(",
    "readLines(",
    "readRDS(",
    "scan(",
    "fread(",
    "read_csv(",
    "read_tsv(",
    "read_delim(",
    "read_excel(",
    "read_parquet(",
    "read_feather(",
    "read_fwf(",
    "load(",
];

fn extract_r_script_paths(script: &str) -> Vec<String> {
    R_READ_CALLS
        .iter()
        .flat_map(|marker| quoted_literals_after_marker(script, marker))
        .map(|(path, _)| path)
        .collect()
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

    /// The paths of a Bash command as one flat extraction: the strongest
    /// exposure of any command that reads something, and every candidate in
    /// order. The single-command tests below read this; the hook itself
    /// evaluates `extract_bash_commands` one command at a time.
    fn extract_bash_read_paths(command: &str, cwd: &Path) -> PathExtraction {
        let mut flat = PathExtraction::none();
        for extracted in extract_bash_commands(command, cwd) {
            if extracted.candidates.is_empty() {
                continue;
            }
            flat.exposure = match (flat.exposure, extracted.exposure) {
                (PathExposure::ReadsContents, _) | (_, PathExposure::ReadsContents) => {
                    PathExposure::ReadsContents
                }
                (PathExposure::MetadataOnly, _) | (_, PathExposure::MetadataOnly) => {
                    PathExposure::MetadataOnly
                }
                _ => PathExposure::None,
            };
            for candidate in extracted.candidates {
                if !flat.candidates.contains(&candidate) {
                    flat.candidates.push(candidate);
                }
            }
        }
        flat
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

    // --- bd-2kr: shell decomposition and wrapper unwrapping ---

    /// Each command that reads something: how it was reached, its exposure and
    /// its candidates relative to the workspace.
    fn reads(command: &str) -> Vec<(&'static str, PathExposure, Vec<String>)> {
        extract_bash_commands(command, workspace())
            .into_iter()
            .filter(|extracted| !extracted.candidates.is_empty())
            .map(|extracted| {
                let candidates = extracted
                    .candidates
                    .iter()
                    .map(|path| match path.strip_prefix(workspace()) {
                        Ok(relative) if relative.as_os_str().is_empty() => ".".to_owned(),
                        Ok(relative) => relative.to_string_lossy().into_owned(),
                        Err(_) => path.to_string_lossy().into_owned(),
                    })
                    .collect();
                (extracted.origin.as_str(), extracted.exposure, candidates)
            })
            .collect()
    }

    fn assert_reads(command: &str, expected: &[(&str, PathExposure, &[&str])]) {
        let expected: Vec<(&str, PathExposure, Vec<String>)> = expected
            .iter()
            .map(|(origin, exposure, paths)| {
                (
                    *origin,
                    *exposure,
                    paths.iter().map(|path| (*path).to_owned()).collect(),
                )
            })
            .collect();
        assert_eq!(reads(command), expected, "command: {command}");
    }

    #[test]
    fn the_bypasses_the_bead_names_now_reach_the_reader() {
        use PathExposure::ReadsContents as Reads;

        assert_reads(
            r#"sh -c "cat data/x.csv""#,
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            r"find data -type f -exec cat {} \;",
            &[("wrapper", Reads, &["data"])],
        );
        assert_reads(
            "ls data | xargs -I{} cat data/{}",
            &[("wrapper", Reads, &["data/{}"])],
        );
        assert_reads(
            "echo $(cat data/x.csv)",
            &[("subshell", Reads, &["data/x.csv"])],
        );
        assert_reads(
            r#"uv run python3 -c "print(open('data/x.csv').read())""#,
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            r#"sh -c "find . -exec cat {} \;""#,
            &[("wrapper", Reads, &["."])],
        );
        // Quote splicing was already caught and stays caught.
        assert_reads(r#"cat da""ta/x.csv"#, &[("top", Reads, &["data/x.csv"])]);
    }

    #[test]
    fn a_reader_after_any_separator_is_found() {
        use PathExposure::ReadsContents as Reads;

        for command in [
            "echo hi; cat data/x.csv",
            "true && cat data/x.csv",
            "false || cat data/x.csv",
            "echo hi | cat data/x.csv",
            "echo hi\ncat data/x.csv",
            "echo hi & cat data/x.csv",
            "(cat data/x.csv)",
            "{ cat data/x.csv; }",
            "if true; then cat data/x.csv; fi",
            "for f in a; do cat data/x.csv; done",
            "echo hi # note\ncat data/x.csv",
            "cat <<EOF\nhi\nEOF\ncat data/x.csv",
        ] {
            assert_reads(command, &[("top", Reads, &["data/x.csv"])]);
        }
    }

    #[test]
    fn each_command_keeps_its_own_exposure_and_origin() {
        use PathExposure::{MetadataOnly as Meta, ReadsContents as Reads};

        assert_reads(
            "grep -rl ssn data; cat notes.md",
            &[("top", Meta, &["data"]), ("top", Reads, &["notes.md"])],
        );
        assert_reads(
            "cat a.txt; echo $(cat b.txt) | sh -c 'cat c.txt'",
            &[
                ("top", Reads, &["a.txt"]),
                ("subshell", Reads, &["b.txt"]),
                ("wrapper", Reads, &["c.txt"]),
            ],
        );
        assert_reads(
            "find data other -exec grep -l ssn {} +",
            &[("wrapper", Meta, &["data"]), ("wrapper", Meta, &["other"])],
        );
    }

    #[test]
    fn wrapper_chains_reach_the_reader_with_its_redirections() {
        use PathExposure::ReadsContents as Reads;

        assert_reads(
            "FOO=1 timeout 5 nice -n 3 sudo -u root env A=1 cat data/x.csv",
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            "sudo -u root cat < data/x.csv",
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            "eval \"cat data/x.csv\"",
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            "bash <<< \"cat data/x.csv\"",
            &[("wrapper", Reads, &["data/x.csv"])],
        );
        assert_reads(
            "bash < data/script.sh",
            &[("top", Reads, &["data/script.sh"])],
        );
        assert_reads(
            "xargs -n1 cat data/x.csv",
            &[("wrapper", Reads, &["data/x.csv"])],
        );
    }

    #[test]
    fn a_reader_fed_by_xargs_has_no_path_to_check_but_is_flagged_dynamic() {
        assert_eq!(reads("ls data | xargs cat"), vec![]);

        let decomposed = decompose("ls data | xargs cat");
        assert!(decomposed[1].has_dynamic_args());
        assert_eq!(decomposed[1].argv, vec!["cat".to_owned()]);
    }

    #[test]
    fn a_search_fed_by_a_pipe_reads_the_pipe_not_the_working_directory() {
        use PathExposure::ReadsContents as Reads;

        // rg, ag and ack search a pipe when given no path.
        assert_eq!(reads("git log | rg ssn"), vec![]);
        assert_eq!(reads("git log | ag ssn"), vec![]);
        assert_eq!(reads("git log | ack ssn"), vec![]);
        assert_eq!(reads("git ls-files | xargs rg ssn"), vec![]);
        // At the head of a pipeline they search the working directory.
        assert_reads("rg ssn | head", &[("top", Reads, &["."])]);
        // grep -r searches the working directory whatever feeds it.
        assert_reads("git log | grep -r ssn", &[("top", Reads, &["."])]);
        // A pipe does not stop an explicit path from being searched.
        assert_reads("git log | rg ssn data", &[("top", Reads, &["data"])]);
    }

    #[test]
    fn text_that_cannot_be_analysed_reads_nothing_and_is_marked_opaque() {
        let commands = extract_bash_commands("cat \"data/x.csv", workspace());

        assert_eq!(commands.len(), 1);
        assert!(commands[0].argv.is_empty());
        assert!(commands[0].candidates.is_empty());
        assert_eq!(commands[0].exposure, PathExposure::None);
    }

    #[test]
    fn a_heredoc_to_an_interpreter_is_data_for_that_interpreter_not_commands() {
        use PathExposure::ReadsContents as Reads;

        assert_reads(
            "python3 <<'PY'\nopen('data/x.csv').read()\nPY\ncat data/y.csv",
            &[
                ("top", Reads, &["data/x.csv"]),
                ("top", Reads, &["data/y.csv"]),
            ],
        );
        assert_eq!(reads("cat <<'EOF'\ncat data/x.csv\nEOF"), vec![]);
    }

    // --- bd-29r: the path-anywhere-in-argv rule ---

    /// The argv paths of the first command, relative to the workspace, each
    /// with whether veil resolved it against the filesystem.
    fn argv_refs(command: &str) -> Vec<(String, bool)> {
        let extracted = extract_bash_commands(command, workspace());
        extracted[0]
            .argv_paths
            .iter()
            .map(|argv| {
                let relative = match argv.path.strip_prefix(workspace()) {
                    Ok(path) if path.as_os_str().is_empty() => ".".to_owned(),
                    Ok(path) => path.to_string_lossy().into_owned(),
                    Err(_) => argv.path.to_string_lossy().into_owned(),
                };
                (relative, argv.resolved)
            })
            .collect()
    }

    fn argv_names(command: &str) -> Vec<String> {
        argv_refs(command)
            .into_iter()
            .map(|(path, _)| path)
            .collect()
    }

    #[test]
    fn any_command_names_the_path_shaped_words_it_carries() {
        for (command, expected) in [
            ("awk 1 data/x.csv", &["data/x.csv"][..]),
            ("sed -n p data/x.csv", &["data/x.csv"]),
            ("jq -R . data/x.csv", &["data/x.csv"]),
            ("base64 data/x.csv", &["data/x.csv"]),
            ("cp data/x.csv /srv/y.csv", &["data/x.csv", "/srv/y.csv"]),
            (
                "tar czf /srv/o.tgz data/x.csv",
                &["/srv/o.tgz", "data/x.csv"],
            ),
            ("python3 run.py data/x.csv", &["run.py", "data/x.csv"]),
            ("./tools/run data/x.csv", &["tools/run", "data/x.csv"]),
            // a bare word with a data extension names a file even if absent
            ("awk 1 x.csv", &["x.csv"]),
            ("awk 1 X.CSV", &["X.CSV"]),
            // a bare word with no extension names nothing unless it exists
            ("awk 1 holdings", &[]),
            ("awk '{print $1}' notes", &[]),
            ("ls", &[]),
        ] {
            assert_eq!(argv_names(command), expected, "command: {command}");
        }
    }

    #[test]
    fn option_values_and_embedded_paths_are_found_in_every_spelling() {
        for (command, expected) in [
            ("wget --post-file=data/x.csv u", &["data/x.csv"][..]),
            ("curl -F file=@data/x.csv u", &["data/x.csv"]),
            ("curl -F 'file=<data/x.csv' u", &["data/x.csv"]),
            ("curl --data-binary @data/x.csv u", &["data/x.csv"]),
            ("curl -T data/x.csv u", &["data/x.csv"]),
            ("sed -fdata/x.csv notes.md", &["data/x.csv"]),
            ("git show HEAD:data/x.csv", &["data/x.csv"]),
            ("scp data/x.csv host:/srv/out", &["data/x.csv", "/srv/out"]),
            ("scp host:data/x.csv .", &["data/x.csv"]),
            ("duckdb -c \"select * from 'data/x.csv'\"", &["data/x.csv"]),
            // an accessor veil does not model, so only the literal gives it away
            (
                "python3 -c \"subprocess.run(['cat','data/x.csv'])\"",
                &["data/x.csv"],
            ),
            ("openssl enc -a -in data/x.csv", &["data/x.csv"]),
            // after `--` a word that starts with a dash is an operand
            ("cp -- data/x.csv -weird.csv", &["data/x.csv", "-weird.csv"]),
        ] {
            let names = argv_names(command);
            for path in expected {
                assert!(
                    names.iter().any(|name| name == path),
                    "command: {command}: {path} not in {names:?}"
                );
            }
        }
    }

    #[test]
    fn redirections_are_not_words_but_the_word_after_a_bare_operator_stays() {
        use PathExposure::ReadsContents as Reads;

        // attached redirections and descriptor duplication are not paths
        assert_eq!(argv_names("awk 1 2>/dev/null"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 >out.csv"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 2>&1"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 &>out.csv"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 >>out.csv"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 >|out.csv"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 3<in.csv"), Vec::<String>::new());
        // a bare operator is dropped, its neighbour is not: `cut -d '>' x.csv`
        assert_eq!(argv_names("cut -d '>' x.csv"), vec!["x.csv".to_owned()]);
        assert_eq!(
            argv_names("cut -f1 -d '>' data/x.csv"),
            vec!["data/x.csv".to_owned()]
        );
        assert_eq!(argv_names("awk 1 > out.csv"), vec!["out.csv".to_owned()]);
        // an input redirect is still a direct read, found once
        assert_reads("awk 1 < data/x.csv", &[("top", Reads, &["data/x.csv"])]);
        assert_eq!(argv_names("awk 1 < data/x.csv"), Vec::<String>::new());
    }

    #[test]
    fn a_reader_is_not_handed_its_redirections_as_files_and_a_glued_one_hides_nothing() {
        use PathExposure::ReadsContents as Reads;

        // `cat x 2>/dev/null` reads `x`; `2>/dev/null` is where stderr goes. A
        // redirection once became a path (and an audit record) of its own, and
        // glued to the file (`x.csv>out`) it made the file's name another one.
        for command in [
            "cat data/x.csv 2>/dev/null",
            "cat data/x.csv 2>&1",
            "cat data/x.csv >out.txt",
            "cat data/x.csv >>log 2>&1",
            "cat data/x.csv>out.txt",
            "cat data/x.csv>&2",
            "cat data/x.csv&>/dev/null",
            "cat 2>/dev/null data/x.csv",
            "head -2 data/x.csv>out",
            "head -n 2 data/x.csv 2>/dev/null",
            "tail data/x.csv >out",
            "less data/x.csv 2>&1",
            "bat data/x.csv>out",
        ] {
            assert_reads(command, &[("top", Reads, &["data/x.csv"])]);
        }
        // an input redirect is a read of its target, once, glued or not
        assert_reads(
            "cat <data/x.csv 2>/dev/null",
            &[("top", Reads, &["data/x.csv"])],
        );
        assert_reads("cat<data/x.csv", &[("top", Reads, &["data/x.csv"])]);
        // and a word that only ends in a digit is not a descriptor
        assert_reads(
            "cat data/x.csv2>/dev/null",
            &[("top", Reads, &["data/x.csv2"])],
        );
    }

    #[test]
    fn a_path_a_reader_already_reads_is_not_named_twice() {
        use PathExposure::ReadsContents as Reads;

        // cat and the grep family know their own words, so the generic rule
        // does not look at them: a grep pattern with a slash is not a path.
        assert_reads("cat data/x.csv", &[("top", Reads, &["data/x.csv"])]);
        assert_eq!(argv_names("cat data/x.csv"), Vec::<String>::new());
        assert_eq!(
            argv_names("grep data/clients notes.md"),
            Vec::<String>::new()
        );
        assert_eq!(argv_names("rg -n 'a/b' src"), Vec::<String>::new());
        // a recognised redirect and the same path as a word are one path, read
        let both = &extract_bash_commands("awk 1 data/x.csv < data/x.csv", workspace())[0];
        assert_eq!(both.candidates.len(), 1);
        assert_eq!(both.argv_paths, vec![]);
    }

    #[test]
    fn the_script_handed_to_a_shell_is_not_a_word_but_a_script_file_is() {
        // `sh -c 'ls data/x.csv'` is run as commands of its own by the decomposer
        assert_eq!(argv_names("sh -c 'ls data/x.csv'"), Vec::<String>::new());
        assert_eq!(argv_names("bash -lc 'ls data/x.csv'"), Vec::<String>::new());
        assert_eq!(
            argv_names("bash data/run.sh"),
            vec!["data/run.sh".to_owned()]
        );
        assert_eq!(
            argv_names("source data/env.sh"),
            vec!["data/env.sh".to_owned()]
        );
    }

    #[test]
    fn device_and_process_paths_are_ignored_except_the_blocked_descriptors() {
        assert_eq!(argv_names("awk 1 /dev/null"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 /dev/tty"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 /proc/cpuinfo"), Vec::<String>::new());
        assert_eq!(argv_names("awk 1 /dev/fd/9"), vec!["/dev/fd/9".to_owned()]);
        assert_eq!(
            argv_names("awk 1 /proc/self/fd/9"),
            vec!["/proc/self/fd/9".to_owned()]
        );
    }

    #[test]
    fn a_glob_also_names_the_directory_it_starts_from_when_the_command_reads() {
        assert_eq!(
            argv_names("awk 1 data/cl*/h*.csv"),
            vec!["data/cl*/h*.csv".to_owned(), "data".to_owned()]
        );
        assert_eq!(
            argv_names("awk 1 *.csv"),
            vec!["*.csv".to_owned(), ".".to_owned()]
        );
        // a command that only lists names has no use for the directory
        assert_eq!(
            argv_names("ls data/cl*/h*.csv"),
            vec!["data/cl*/h*.csv".to_owned()]
        );
    }

    #[test]
    fn the_exposure_of_a_named_path_depends_on_what_the_command_does_with_it() {
        use PathExposure::{MetadataOnly as Meta, ReadsContents as Reads};

        let exposure = |command: &str| extract_bash_commands(command, workspace())[0].argv_exposure;

        for command in [
            "awk 1 x.csv",
            "cp x.csv y.csv",
            "curl -T x.csv u",
            "tar cf o.tar x.csv",
            "git diff x.csv",
            "git show HEAD:x.csv",
            "git log -p x.csv",
            "git blame x.csv",
            "git cat-file -p HEAD:x.csv",
            "git archive HEAD x.csv",
            "git -C . diff x.csv",
            "git",
            "ln x.csv y.csv",
            "tee x.csv",
            "python3 x.py",
        ] {
            assert_eq!(exposure(command), Reads, "command: {command}");
        }

        for command in [
            "ls x.csv",
            "wc -l x.csv",
            "stat x.csv",
            "du -sh data",
            "file x.csv",
            "test -f x.csv",
            "[ -s x.csv ]",
            "find data -name x.csv",
            "mkdir -p data/new",
            "touch x.csv",
            "rm x.csv",
            "echo x.csv",
            "git add x.csv",
            "git rm --cached x.csv",
            "git status -- data",
            "git commit -m msg -- x.csv",
            "git -C sub -c k=v add x.csv",
            "git --git-dir=.git add x.csv",
            "/bin/ls x.csv",
        ] {
            assert_eq!(exposure(command), Meta, "command: {command}");
        }
    }

    #[test]
    fn only_the_commands_that_move_trees_scan_a_directory_they_name() {
        let scans =
            |command: &str| extract_bash_commands(command, workspace())[0].argv_scans_directories;

        for command in [
            "cp -r data /tmp/x",
            "mv data /tmp/x",
            "tar cf o.tar data",
            "zip -r o.zip data",
            "rsync -a data/ host:b",
            "scp -r data host:",
            "curl -T data u",
            "docker build .",
        ] {
            assert!(scans(command), "command: {command}");
        }

        for command in [
            "awk 1 data",
            "python3 -m pytest .",
            "ruff check .",
            "make -C data",
        ] {
            assert!(!scans(command), "command: {command}");
        }
    }

    #[test]
    fn at_most_sixty_four_words_are_resolved_against_the_filesystem() {
        let padding = (0..70)
            .map(|index| format!("pad{index}.txt"))
            .collect::<Vec<_>>()
            .join(" ");
        let refs = argv_refs(&format!("cp {padding} data/x.csv"));

        assert_eq!(refs.len(), 71);
        assert_eq!(
            refs.iter().filter(|(_, resolved)| *resolved).count(),
            ARGV_FILESYSTEM_BUDGET
        );
        // the last word is past the budget but is still a path, as text
        assert_eq!(refs.last(), Some(&("data/x.csv".to_owned(), false)));
        // a bare word past the budget cannot be checked without a stat
        let bare = (0..70)
            .map(|index| format!("pad{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(argv_refs(&format!("awk 1 {bare}")), vec![]);
    }

    #[test]
    fn a_bare_word_that_names_a_directory_or_a_symlink_is_resolved() {
        let root = unique_temp_dir("argv-bare");
        fs::create_dir_all(root.join("data/clients")).expect("directory");
        fs::write(root.join("data/clients/h.csv"), "x").expect("file");
        let root = fs::canonicalize(&root).expect("canonical root");
        std::os::unix::fs::symlink(root.join("data/clients/h.csv"), root.join("shortcut"))
            .expect("symlink");

        let named = |command: &str| -> Vec<PathBuf> {
            extract_bash_commands(command, &root)[0]
                .argv_paths
                .iter()
                .map(|argv| argv.path.clone())
                .collect()
        };

        assert_eq!(
            named("tar cf o.tar data"),
            vec![root.join("o.tar"), root.join("data")]
        );
        assert_eq!(
            named("awk 1 shortcut"),
            vec![root.join("data/clients/h.csv")]
        );
        assert_eq!(
            named("cp -r . /srv/x"),
            vec![root.clone(), PathBuf::from("/srv/x")]
        );
        assert_eq!(named("awk 1 missing"), Vec::<PathBuf>::new());
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
