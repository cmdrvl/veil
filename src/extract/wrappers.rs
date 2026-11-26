//! bd-2kr: the programs that run another command, and the shells that run a
//! string. [`expand`] replaces `timeout 5 cat x` with `cat x`, runs `sh -c`
//! strings and `eval` back through the decomposer, and turns `find -exec` and
//! `xargs` into the command they run.
//!
//! The option tables below say which options of each wrapper take a value. A
//! value left out of a table is read as the command, which hides the real
//! command behind it: the opposite failure direction from the search tables in
//! `extract.rs`. Each table was checked against the installed tool where there
//! is one (`uv run --help`, `uvx --help`, `pipx run --help`, `npm exec`/`npx
//! --help`, `bunx --help`, GNU `timeout --help`, and the BSD `env`, `xargs`,
//! `nice` and `find` man pages on macOS). `sudo`, `doas`, `poetry`, `pdm` and
//! `deno` are not installed here or were not run, so those tables are from
//! their documentation and unchecked.

use std::fs;
use std::path::Path;

use super::decompose::{
    MAX_DEPTH, Origin, Run, STDIN_ARGUMENTS, SimpleCommand, action_changes_lookup, emit, script,
};
use super::{command_name, lookup};

/// Options a wrapper takes, and which of them carry a value.
struct Options {
    short_value: &'static [char],
    long_value: &'static [&'static str],
}

/// What [`skip_options`] found.
struct Skipped {
    /// Index of the first word that is not an option or an option's value.
    end: usize,
    /// Short option letters seen, anywhere in a cluster.
    short_flags: Vec<char>,
    /// `(name, value)` for each option that took a value.
    values: Vec<(String, String)>,
}

impl Skipped {
    fn value_of(&self, names: &[&str]) -> Option<&str> {
        self.values
            .iter()
            .find(|(name, _)| names.contains(&name.as_str()))
            .map(|(_, value)| value.as_str())
    }
}

/// Walks the leading options of `args`. `--` ends them; a lone `-` is a word.
fn skip_options(args: &[String], options: &Options) -> Skipped {
    let mut skipped = Skipped {
        end: 0,
        short_flags: Vec::new(),
        values: Vec::new(),
    };
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        i += 1;

        if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, value)) => skipped.values.push((format!("--{name}"), value.to_owned())),
                None if options.long_value.contains(&long) => {
                    if let Some(value) = args.get(i) {
                        skipped.values.push((arg.to_owned(), value.clone()));
                    }
                    i += 1;
                }
                None => {}
            }
            continue;
        }

        let cluster = &arg[1..];
        for (offset, flag) in cluster.char_indices() {
            skipped.short_flags.push(flag);
            if options.short_value.contains(&flag) {
                let attached = &cluster[offset + flag.len_utf8()..];
                let value = if attached.is_empty() {
                    i += 1;
                    args.get(i - 1).cloned()
                } else {
                    Some(attached.to_owned())
                };
                if let Some(value) = value {
                    skipped.values.push((format!("-{flag}"), value));
                }
                break;
            }
        }
    }

    skipped.end = i.min(args.len());
    skipped
}

const NO_OPTIONS: Options = Options {
    short_value: &[],
    long_value: &[],
};

/// `env`: GNU and BSD together (`-u`, `-C`, `-S`, BSD `-P`).
const ENV: Options = Options {
    short_value: &['u', 'C', 'S', 'P'],
    long_value: &["unset", "chdir", "split-string"],
};
/// `nice [-n N | --adjustment=N]`.
const NICE: Options = Options {
    short_value: &['n'],
    long_value: &["adjustment"],
};
/// `time` as a program (GNU `-f`, `-o`); the bash keyword takes only `-p`.
const TIME: Options = Options {
    short_value: &['f', 'o'],
    long_value: &["format", "output"],
};
/// GNU `timeout [-k DUR] [-s SIG] DURATION COMMAND`.
const TIMEOUT: Options = Options {
    short_value: &['k', 's'],
    long_value: &["kill-after", "signal"],
};
/// `sudo`; `-s` and `-i` start a shell and are handled apart from this table.
const SUDO: Options = Options {
    short_value: &['u', 'g', 'C', 'D', 'h', 'p', 'r', 't', 'U', 'T'],
    long_value: &[
        "user",
        "group",
        "close-from",
        "chdir",
        "host",
        "prompt",
        "role",
        "type",
        "other-user",
        "command-timeout",
    ],
};
const DOAS: Options = Options {
    short_value: &['u', 'C'],
    long_value: &[],
};
const EXEC: Options = Options {
    short_value: &['a'],
    long_value: &[],
};
/// BSD and GNU `xargs`. GNU's `-i`, `-l` and `-e` take only an attached value,
/// so they are flags here.
const XARGS: Options = Options {
    short_value: &['I', 'J', 'L', 'n', 'P', 'R', 'S', 's', 'E', 'd', 'a'],
    long_value: &[
        "arg-file",
        "delimiter",
        "max-args",
        "max-procs",
        "max-chars",
        "process-slot-var",
    ],
};
/// `uv run` and `uvx`/`uv tool run`: the union of the value-taking options in
/// both `--help` listings.
const UV: Options = Options {
    short_value: &['w', 'i', 'f', 'P', 'C', 'p', 'c', 'b'],
    long_value: &[
        "extra",
        "no-extra",
        "group",
        "no-group",
        "only-group",
        "no-editable-package",
        "env-file",
        "with",
        "with-editable",
        "with-requirements",
        "package",
        "from",
        "constraints",
        "build-constraints",
        "overrides",
        "python-platform",
        "torch-backend",
        "index",
        "default-index",
        "index-url",
        "extra-index-url",
        "find-links",
        "index-strategy",
        "keyring-provider",
        "upgrade-package",
        "upgrade-group",
        "resolution",
        "prerelease",
        "prerelease-package",
        "fork-strategy",
        "exclude-newer",
        "exclude-newer-package",
        "no-sources-package",
        "reinstall-package",
        "link-mode",
        "config-setting",
        "config-settings-package",
        "no-build-isolation-package",
        "no-build-package",
        "no-binary-package",
        "cache-dir",
        "refresh-package",
        "python",
        "color",
        "allow-insecure-host",
        "directory",
        "project",
        "config-file",
    ],
};
const PIPX: Options = Options {
    short_value: &['i'],
    long_value: &[
        "spec",
        "python",
        "pip-args",
        "python-args",
        "with",
        "index-url",
        "fetch-python",
        "backend",
        "cooldown",
    ],
};
const PDM: Options = Options {
    short_value: &['p'],
    long_value: &["project", "venv"],
};
/// `npx` / `npm exec`. `-c`/`--call` carries a shell string, read separately.
const NPX: Options = Options {
    short_value: &['p', 'w', 'c'],
    long_value: &[
        "package",
        "workspace",
        "call",
        "prefix",
        "cache",
        "registry",
        "userconfig",
        "loglevel",
    ],
};
const BUNX: Options = Options {
    short_value: &['p'],
    long_value: &["package"],
};
const DENO: Options = Options {
    short_value: &['c'],
    long_value: &[
        "config",
        "import-map",
        "lock",
        "cert",
        "location",
        "seed",
        "log-level",
    ],
};

pub(super) const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh",
];

/// What one step of unwrapping found.
enum Step {
    /// Not a wrapper: `words` is the command that runs.
    Done,
    /// Drop this many leading words; what is left is the command. `dynamic`
    /// when the wrapper adds arguments this module cannot see.
    Skip {
        count: usize,
        dynamic: bool,
        directory: Option<String>,
    },
    /// Replace the command with these words.
    Words(Vec<String>, Option<String>),
    /// The wrapper runs this string as a shell script.
    Script(String),
    /// `find` with `-exec`: the commands it runs, one per root and block.
    Exec(Vec<Vec<String>>),
}

/// Adds `command`, and whatever it runs, to `out`. A wrapper is replaced by
/// the command it runs. A shell is kept as well, since it can read through its
/// own redirections (`bash < data/x.sh`), and the script it runs follows it.
pub(super) fn expand(
    command: SimpleCommand,
    depth: usize,
    run: &mut Run,
    out: &mut Vec<SimpleCommand>,
) {
    let cwd = run.env.cwd.clone();
    let cwd_unresolved = run.cwd_unresolved;
    run.env.cwd = command.cwd.clone();
    run.cwd_unresolved = command.cwd_unresolved;
    expand_inner(command, depth, run, out);
    run.env.cwd = cwd;
    run.cwd_unresolved = cwd_unresolved;
}

fn expand_inner(command: SimpleCommand, depth: usize, run: &mut Run, out: &mut Vec<SimpleCommand>) {
    let mut command = command;
    let mut start = 0;
    let mut hops = 0;

    loop {
        let words = &command.argv[start..];
        let Some(program) = words.first().map(|word| command_name(word)) else {
            break;
        };

        // each wrapper, and what it turns out to run, on the way down
        let texts: Vec<&str> = words.iter().map(String::as_str).collect();
        let unnamed = command.computed.contains(&words[0]);
        run.lookup_changed |= lookup::changes_lookup(&texts, unnamed);

        // An action with something computed in it when it is set can be any
        // script; otherwise it is read.
        if program == "trap"
            && let Some(action) = lookup::trap_action(&words[1..])
        {
            run.lookup_changed |=
                command.computed.contains(action) || action_changes_lookup(action, depth, run);
        }

        if SHELLS.contains(&program) || program == "eval" {
            let is_eval = program == "eval";
            let scripts = shell_scripts(words, is_eval, &command);
            // likewise the text a shell or `eval` is handed to run
            run.lookup_changed |= if is_eval {
                !command.unresolved.is_empty()
            } else {
                command.heredoc_computed
                    || scripts.iter().any(|text| command.computed.contains(text))
            };
            command.argv.drain(..start);
            if !is_eval {
                emit(command, out);
            }
            for text in scripts {
                script(&text, Origin::Wrapper, depth + 1, run, out);
            }
            return;
        }

        let step = step(words);
        // Computed text among what `env` reads as its own can be an option or
        // an assignment, or, split at its spaces, several.
        if program == "env" {
            let own = match &step {
                Step::Skip { count, .. } => words.get(1..*count),
                _ => words.get(1..),
            };
            run.lookup_changed |= own
                .into_iter()
                .flatten()
                .any(|word| command.computed.contains(word));
        }

        match step {
            Step::Done => {
                let directories = native_directory_targets(words);
                for directory in directories {
                    set_directory(&mut command, &directory);
                }
                break;
            }
            Step::Skip {
                count,
                dynamic,
                directory,
            } => {
                start += count;
                command.origin = Origin::Wrapper;
                if dynamic {
                    command.unresolved.push(STDIN_ARGUMENTS.to_owned());
                }
                if let Some(directory) = directory {
                    set_directory(&mut command, &directory);
                    run.env.cwd = command.cwd.clone();
                    run.cwd_unresolved = command.cwd_unresolved;
                }
            }
            Step::Words(replacement, directory) => {
                command.argv = replacement;
                start = 0;
                command.origin = Origin::Wrapper;
                if let Some(directory) = directory {
                    set_directory(&mut command, &directory);
                    run.env.cwd = command.cwd.clone();
                    run.cwd_unresolved = command.cwd_unresolved;
                }
            }
            Step::Script(text) => {
                script(&text, Origin::Wrapper, depth + 1, run, out);
                return;
            }
            Step::Exec(commands) => {
                for argv in commands {
                    // `{}` became a root, which the directory scope judges; what
                    // the parent could not resolve (`find $d -exec ...`) stays
                    // unresolved for the command it runs.
                    let inner = SimpleCommand {
                        argv,
                        cwd: command.cwd.clone(),
                        cwd_unresolved: command.cwd_unresolved,
                        redirects_in: Vec::new(),
                        unresolved: command.unresolved.clone(),
                        computed: command.computed.clone(),
                        assigned: Vec::new(),
                        origin: Origin::Wrapper,
                        stdin_piped: command.stdin_piped,
                        heredoc_body: None,
                        heredoc_computed: false,
                        lookup_changed: false,
                    };
                    expand(inner, depth + 1, run, out);
                }
                return;
            }
        }

        hops += 1;
        if hops > MAX_DEPTH {
            // Too many wrappers to follow; what is left is not analysed.
            run.truncated = true;
            break;
        }
    }

    if start < command.argv.len() {
        command.argv.drain(..start);
        emit(command, out);
    }
}

/// The scripts a shell (or `eval`) runs: its `-c` string, else a here-string,
/// else a here-document, which the shell reads from standard input.
fn shell_scripts(words: &[String], eval: bool, command: &SimpleCommand) -> Vec<String> {
    let args = &words[1..];

    if eval {
        let joined = args.join(" ");
        return if joined.trim().is_empty() {
            Vec::new()
        } else {
            vec![joined]
        };
    }
    if let Some(text) = command_string(args) {
        return vec![text.to_owned()];
    }
    if let Some(position) = args.iter().position(|arg| arg == "<<<")
        && let Some(text) = args.get(position + 1)
    {
        return vec![text.clone()];
    }
    command.heredoc_body.iter().cloned().collect()
}

/// The `-c` string of a shell invocation: `-c`, or a cluster holding `c` such
/// as `-lc`, then the first word that is not an option.
fn command_string(args: &[String]) -> Option<&str> {
    let mut has_c = false;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--" => {
                i += 1;
                break;
            }
            "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file" => {
                i += 2;
                continue;
            }
            _ => {}
        }
        if arg.starts_with("--") || arg.starts_with('+') {
            i += 1;
        } else if let Some(cluster) = arg.strip_prefix('-')
            && !cluster.is_empty()
        {
            has_c |= cluster.contains('c');
            i += 1;
        } else {
            break;
        }
    }

    if has_c {
        args.get(i).map(String::as_str)
    } else {
        None
    }
}

fn step(words: &[String]) -> Step {
    let program = command_name(&words[0]);
    let args = &words[1..];

    match program {
        "env" => env_step(args),
        "nohup" | "builtin" => skip(1, &NO_OPTIONS, args, false),
        "command" => {
            // `command -v` and `-V` look a name up; they run nothing.
            let skipped = skip_options(args, &NO_OPTIONS);
            if skipped
                .short_flags
                .iter()
                .any(|flag| matches!(flag, 'v' | 'V'))
            {
                Step::Done
            } else {
                finish(1, skipped.end, args.len(), false)
            }
        }
        "exec" => skip(1, &EXEC, args, false),
        "nice" => skip(1, &NICE, args, false),
        "time" => skip(1, &TIME, args, false),
        "timeout" => {
            let skipped = skip_options(args, &TIMEOUT);
            // The duration is the first word after the options.
            finish(1, skipped.end + 1, args.len(), false)
        }
        "sudo" => {
            let skipped = skip_options(args, &SUDO);
            let shell = skipped
                .short_flags
                .iter()
                .any(|flag| matches!(flag, 's' | 'i'));
            let rest = &args[skipped.end.min(args.len())..];
            if shell && !rest.is_empty() {
                Step::Script(rest.join(" "))
            } else {
                finish(1, skipped.end, args.len(), false)
            }
        }
        "doas" => skip(1, &DOAS, args, false),
        "xargs" => {
            let skipped = skip_options(args, &XARGS);
            if skipped.end >= args.len() {
                // No utility: xargs runs `echo`.
                Step::Done
            } else {
                finish(1, skipped.end, args.len(), true)
            }
        }
        "find" => find_step(words),
        "uvx" => skip_with_directory(1, &UV, args, false, &["-C", "--directory"]),
        "uv" => match args.first().map(String::as_str) {
            Some("run") => skip_with_directory(2, &UV, &args[1..], false, &["-C", "--directory"]),
            Some("tool") if args.get(1).map(String::as_str) == Some("run") => {
                skip_with_directory(3, &UV, &args[2..], false, &["-C", "--directory"])
            }
            _ => Step::Done,
        },
        "pipx" => run_subcommand(args, &PIPX),
        "poetry" => run_subcommand(args, &NO_OPTIONS),
        "pdm" => run_subcommand(args, &PDM),
        "deno" => run_subcommand(args, &DENO),
        "bunx" => skip(1, &BUNX, args, false),
        "npx" => {
            let skipped = skip_options(args, &NPX);
            match skipped.value_of(&["-c", "--call"]) {
                Some(text) => Step::Script(text.to_owned()),
                None => finish(1, skipped.end, args.len(), false),
            }
        }
        _ => Step::Done,
    }
}

/// `wrapper <run> [options] command...` for the wrappers whose subcommand is `run`.
fn run_subcommand(args: &[String], options: &Options) -> Step {
    match args.first().map(String::as_str) {
        Some("run") => skip(2, options, &args[1..], false),
        _ => Step::Done,
    }
}

/// Skips `prefix` words (the wrapper and any subcommand) plus the options in `rest`.
fn skip(prefix: usize, options: &Options, rest: &[String], dynamic: bool) -> Step {
    let skipped = skip_options(rest, options);
    finish(prefix, skipped.end, rest.len(), dynamic)
}

fn skip_with_directory(
    prefix: usize,
    options: &Options,
    rest: &[String],
    dynamic: bool,
    directory_options: &[&str],
) -> Step {
    let skipped = skip_options(rest, options);
    let directory = skipped.value_of(directory_options).map(str::to_owned);
    finish_with_directory(prefix, skipped.end, rest.len(), dynamic, directory)
}

/// `Skip` over `prefix + options` words, or `Done` when nothing would be left
/// to run.
fn finish(prefix: usize, options_end: usize, available: usize, dynamic: bool) -> Step {
    finish_with_directory(prefix, options_end, available, dynamic, None)
}

fn finish_with_directory(
    prefix: usize,
    options_end: usize,
    available: usize,
    dynamic: bool,
    directory: Option<String>,
) -> Step {
    if options_end >= available {
        return Step::Done;
    }
    Step::Skip {
        count: prefix + options_end,
        dynamic,
        directory,
    }
}

/// `env [options] [NAME=value]... command`. `-S` carries words to run.
fn env_step(args: &[String]) -> Step {
    let mut i = 0;
    let mut directory = None;

    loop {
        let skipped = skip_options(&args[i..], &ENV);
        if let Some(value) = skipped.value_of(&["-C", "--chdir"]) {
            directory = Some(value.to_owned());
        }
        if let Some(text) = skipped.value_of(&["-S", "--split-string"])
            && let Some(mut words) = shlex::split(text)
        {
            words.extend(args[i + skipped.end..].iter().cloned());
            return if words.is_empty() {
                Step::Done
            } else {
                Step::Words(words, directory)
            };
        }
        i += skipped.end;

        let before = i;
        while args
            .get(i)
            .is_some_and(|word| super::is_env_assignment(word))
        {
            i += 1;
        }
        if i == before {
            break;
        }
    }

    finish_with_directory(1, i, args.len(), false, directory)
}

fn set_directory(command: &mut SimpleCommand, target: &str) {
    let dynamic = command
        .unresolved
        .iter()
        .any(|unresolved| unresolved == target)
        || target.contains(['*', '?', '[', '\u{1}']);
    if dynamic {
        command.cwd_unresolved = true;
        return;
    }

    let target = Path::new(target);
    let candidate = if target.is_absolute() {
        target.to_path_buf()
    } else if command.cwd_unresolved {
        return;
    } else if let Some(cwd) = &command.cwd {
        cwd.join(target)
    } else {
        command.cwd_unresolved = true;
        return;
    };

    match fs::canonicalize(&candidate) {
        Ok(path) if path.is_dir() => {
            command.cwd = Some(path);
            command.cwd_unresolved = false;
        }
        _ => command.cwd_unresolved = true,
    }
}

/// `git -C` and `make -C` change the directory used by their own file paths.
/// They stay as commands; only the base for resolving those paths changes.
fn native_directory_targets(words: &[String]) -> Vec<String> {
    let Some(program) = words.first().map(|word| command_name(word)) else {
        return Vec::new();
    };
    let args = &words[1..];
    let mut targets = Vec::new();

    match program {
        "git" => {
            let mut i = 0;
            while i < args.len() {
                let arg = args[i].as_str();
                if arg == "-C" {
                    if let Some(target) = args.get(i + 1) {
                        targets.push(target.clone());
                    }
                    i += 2;
                } else if let Some(target) = arg.strip_prefix("-C")
                    && !target.is_empty()
                {
                    targets.push(target.to_owned());
                    i += 1;
                } else if matches!(
                    arg,
                    "-c" | "--git-dir"
                        | "--work-tree"
                        | "--namespace"
                        | "--super-prefix"
                        | "--exec-path"
                        | "--config-env"
                ) {
                    i += 2;
                } else if !arg.starts_with('-') {
                    break;
                } else {
                    i += 1;
                }
            }
        }
        "make" => {
            let mut i = 0;
            while i < args.len() {
                let arg = args[i].as_str();
                if arg == "-C" || arg == "--directory" {
                    if let Some(target) = args.get(i + 1) {
                        targets.push(target.clone());
                    }
                    i += 2;
                } else if let Some(target) = arg.strip_prefix("--directory=") {
                    targets.push(target.to_owned());
                    i += 1;
                } else if let Some(target) = arg.strip_prefix("-C")
                    && !target.is_empty()
                {
                    targets.push(target.to_owned());
                    i += 1;
                } else if !arg.starts_with('-') {
                    break;
                } else {
                    i += 1;
                }
            }
        }
        _ => return Vec::new(),
    }

    targets
}

/// `find [options] roots... [expression]` with `-exec`, `-execdir`, `-ok` or
/// `-okdir`: each such block, once per root, with `{}` replaced by the root.
/// The commands run on files under the roots, so a reader of `{}` reads the
/// roots as directories, which the directory-scope check understands.
fn find_step(words: &[String]) -> Step {
    let args = &words[1..];
    let mut roots: Vec<&str> = Vec::new();
    let mut i = 0;

    // Leading options: -H -L -P -E -X -d -s -x, -f PATH (BSD), -D OPTS, -O<n>.
    while i < args.len() {
        match args[i].as_str() {
            "-H" | "-L" | "-P" | "-E" | "-X" | "-d" | "-s" | "-x" => i += 1,
            "-f" => {
                if let Some(root) = args.get(i + 1) {
                    roots.push(root);
                }
                i += 2;
            }
            "-D" => i += 2,
            option
                if option.starts_with("-O") && option[2..].bytes().all(|b| b.is_ascii_digit()) =>
            {
                i += 1;
            }
            _ => break,
        }
    }
    while i < args.len() && !is_expression_start(&args[i]) {
        roots.push(&args[i]);
        i += 1;
    }
    if roots.is_empty() {
        roots.push(".");
    }

    let mut blocks: Vec<&[String]> = Vec::new();
    while i < args.len() {
        if matches!(args[i].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            let begin = i + 1;
            let length = args[begin..]
                .iter()
                .position(|word| word == ";" || word == "+")
                .unwrap_or(args.len() - begin);
            blocks.push(&args[begin..begin + length]);
            i = begin + length;
        }
        i += 1;
    }
    if blocks.is_empty() {
        return Step::Done;
    }

    let mut commands = Vec::new();
    for block in blocks.into_iter().filter(|block| !block.is_empty()) {
        if block.iter().any(|word| word.contains("{}")) {
            for root in &roots {
                commands.push(block.iter().map(|word| word.replace("{}", root)).collect());
            }
        } else {
            commands.push(block.to_vec());
        }
    }
    Step::Exec(commands)
}

fn is_expression_start(word: &str) -> bool {
    word.starts_with('-') || matches!(word, "(" | ")" | "!" | ",")
}

#[cfg(test)]
mod tests {
    use super::super::decompose::{Origin, ShellEnv, decompose, decompose_in};
    use super::*;

    /// The argv of every command `command` would run.
    fn run(command: &str) -> Vec<Vec<String>> {
        decompose(command).into_iter().map(|c| c.argv).collect()
    }

    fn argv(text: &str) -> Vec<String> {
        shlex::split(text).expect("test argv should split")
    }

    fn assert_runs(command: &str, expected: &[&str]) {
        let expected: Vec<Vec<String>> = expected.iter().map(|text| argv(text)).collect();
        assert_eq!(run(command), expected, "command: {command}");
    }

    #[test]
    fn env_is_replaced_by_the_command_it_runs() {
        assert_runs("env cat x", &["cat x"]);
        assert_runs("env A=1 B=2 cat x", &["cat x"]);
        assert_runs("env -i A=1 cat x", &["cat x"]);
        assert_runs("env -u FOO cat x", &["cat x"]);
        assert_runs("env -C /tmp -u FOO A=1 cat x", &["cat x"]);
        assert_runs("env -- cat x", &["cat x"]);
        assert_runs("env -S 'cat x'", &["cat x"]);
        assert_runs("env -S 'cat' y", &["cat y"]);
        assert_runs("/usr/bin/env cat x", &["cat x"]);
        assert_runs("env", &["env"]);
        assert_runs("env A=1", &["env A=1"]);
    }

    #[test]
    fn directory_flags_set_the_working_directory_for_commands() {
        let cwd = std::env::current_dir().expect("working directory");
        let env = ShellEnv {
            cwd: Some(cwd.clone()),
            home: None,
        };
        let source = std::fs::canonicalize(cwd.join("src")).expect("src directory");

        for command in [
            "env -C src cat main.rs",
            "env --chdir=src cat main.rs",
            "uv run --directory src cat main.rs",
            "uv run -C src cat main.rs",
            "uvx -C src cat main.rs",
            "git -C src show HEAD:main.rs",
            "make -C src -f Makefile",
            "make --directory=src --file=Makefile",
        ] {
            let commands = decompose_in(command, &env);
            assert_eq!(
                commands.last().expect("wrapped command").cwd.as_deref(),
                Some(source.as_path()),
                "{command}: {commands:?}"
            );
        }
    }

    #[test]
    fn nice_nohup_time_and_exec_are_transparent() {
        assert_runs("nice cat x", &["cat x"]);
        assert_runs("nice -n 5 cat x", &["cat x"]);
        assert_runs("nice -n5 cat x", &["cat x"]);
        assert_runs("nice -10 cat x", &["cat x"]);
        assert_runs("nice --adjustment=5 cat x", &["cat x"]);
        assert_runs("nohup cat x", &["cat x"]);
        assert_runs("time cat x", &["cat x"]);
        assert_runs("time -p cat x", &["cat x"]);
        assert_runs("/usr/bin/time -o out.txt cat x", &["cat x"]);
        assert_runs("exec cat x", &["cat x"]);
        assert_runs("exec -a name cat x", &["cat x"]);
        assert_runs("command cat x", &["cat x"]);
        assert_runs("builtin cat x", &["cat x"]);
    }

    #[test]
    fn command_v_looks_a_name_up_and_runs_nothing() {
        assert_runs("command -v cat", &["command -v cat"]);
        assert_runs("command -V cat", &["command -V cat"]);
    }

    #[test]
    fn timeout_skips_its_options_and_the_duration() {
        assert_runs("timeout 5 cat x", &["cat x"]);
        assert_runs("timeout -s KILL 5 cat x", &["cat x"]);
        assert_runs("timeout -k 1 -s TERM 5s cat x", &["cat x"]);
        assert_runs("timeout --signal=KILL --kill-after 1 5 cat x", &["cat x"]);
        assert_runs("timeout --foreground -v 5 cat x", &["cat x"]);
        assert_runs("timeout 5", &["timeout 5"]);
    }

    #[test]
    fn sudo_and_doas_skip_their_options_and_run_shell_strings() {
        assert_runs("sudo cat x", &["cat x"]);
        assert_runs("sudo -n -E cat x", &["cat x"]);
        assert_runs("sudo -u root -g wheel cat x", &["cat x"]);
        assert_runs("sudo --user=root cat x", &["cat x"]);
        assert_runs("sudo -- cat x", &["cat x"]);
        assert_runs("doas cat x", &["cat x"]);
        assert_runs("doas -u root cat x", &["cat x"]);
        // `-s` and `-i` hand the rest to a shell as one command line.
        assert_runs("sudo -s 'cat x; cat y'", &["cat x", "cat y"]);
        assert_runs("sudo -i cat x", &["cat x"]);
        assert_runs("sudo -v", &["sudo -v"]);
    }

    #[test]
    fn xargs_runs_its_utility_with_arguments_it_reads_from_standard_input() {
        let commands = decompose("ls data | xargs cat");

        assert_eq!(commands[1].argv, argv("cat"));
        assert_eq!(commands[1].unresolved, vec![STDIN_ARGUMENTS.to_owned()]);
        assert!(commands[1].has_dynamic_args());
        assert_eq!(commands[1].origin, Origin::Wrapper);
        assert!(!commands[0].has_dynamic_args());

        assert_runs("xargs -n 1 cat", &["cat"]);
        assert_runs("xargs -0 -P 4 -n1 cat x", &["cat x"]);
        assert_runs("xargs -I{} cat data/{}", &["cat data/{}"]);
        assert_runs("xargs -I {} cat data/{}", &["cat data/{}"]);
        assert_runs("xargs -J % cp % dest", &["cp % dest"]);
        assert_runs("xargs --max-args=2 --null cat", &["cat"]);
        assert_runs("xargs -a list.txt cat", &["cat"]);
        assert_runs("xargs -d '\\n' cat", &["cat"]);
        assert_runs("xargs -r -t cat", &["cat"]);
        // With no utility xargs runs echo.
        assert_runs("xargs", &["xargs"]);
        assert_runs("xargs -n 1", &["xargs -n 1"]);
    }

    #[test]
    fn find_exec_runs_the_command_once_per_root_with_the_root_in_place_of_braces() {
        assert_runs("find data -type f -exec cat {} \\;", &["cat data"]);
        assert_runs("find data -type f -exec cat {} +", &["cat data"]);
        assert_runs("find data -execdir cat {} \\;", &["cat data"]);
        assert_runs("find data -ok cat {} \\;", &["cat data"]);
        assert_runs(
            "find data other -exec cat {} \\;",
            &["cat data", "cat other"],
        );
        assert_runs("find -exec cat {} \\;", &["cat ."]);
        assert_runs(
            "find . -name '*.csv' -exec grep -l ssn {} +",
            &["grep -l ssn ."],
        );
        assert_runs("find -L data -exec cat {} \\;", &["cat data"]);
        assert_runs("find -f data -exec cat {} \\;", &["cat data"]);
        assert_runs("find data -exec cat prefix/{} \\;", &["cat prefix/data"]);
        assert_runs("find data -exec echo done \\;", &["echo done"]);
        assert_runs(
            "find data -exec head -n1 {} \\; -exec wc -l {} \\;",
            &["head -n1 data", "wc -l data"],
        );
        assert_runs("find data -type f -name x", &["find data -type f -name x"]);
        assert_runs(
            "find data \\( -name a -o -name b \\) -exec cat {} \\;",
            &["cat data"],
        );
    }

    #[test]
    fn find_exec_commands_are_wrapper_origin_and_their_braces_are_the_literal_root() {
        let commands = decompose("find data -exec cat {} \\;");

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].argv, argv("cat data"));
        assert_eq!(commands[0].origin, Origin::Wrapper);
        // `{}` became the root, which the directory scope judges
        assert!(!commands[0].has_dynamic_args());

        // a root that is itself unresolved leaves the command unresolved
        let commands = decompose("find $d -exec cat {} \\;");
        assert_eq!(commands[0].unresolved, vec!["$d".to_owned()]);
    }

    #[test]
    fn package_runners_are_replaced_by_the_command_they_run() {
        assert_runs("uv run cat x", &["cat x"]);
        assert_runs("uv run python -c 'print(1)'", &["python -c print(1)"]);
        assert_runs("uv run --with pandas python x.py", &["python x.py"]);
        assert_runs(
            "uv run -w pandas -p 3.12 --env-file e python x.py",
            &["python x.py"],
        );
        assert_runs(
            "uv run --directory sub --project p python x.py",
            &["python x.py"],
        );
        assert_runs("uv run -- cat x", &["cat x"]);
        assert_runs("uv run", &["uv run"]);
        assert_runs("uv sync", &["uv sync"]);
        assert_runs("uvx ruff check", &["ruff check"]);
        assert_runs("uvx --from ruff ruff check", &["ruff check"]);
        assert_runs("uvx --with a --python 3.12 tool arg", &["tool arg"]);
        assert_runs("uv tool run --from x tool arg", &["tool arg"]);
        assert_runs("pipx run cowsay hi", &["cowsay hi"]);
        assert_runs("pipx run --spec pkg --python 3.12 tool arg", &["tool arg"]);
        assert_runs("pipx install x", &["pipx install x"]);
        assert_runs("poetry run python x.py", &["python x.py"]);
        assert_runs("pdm run -p proj python x.py", &["python x.py"]);
        assert_runs("npx prettier x", &["prettier x"]);
        assert_runs("npx -y prettier x", &["prettier x"]);
        assert_runs("npx -p pkg --yes prettier x", &["prettier x"]);
        assert_runs("npx --package=pkg prettier x", &["prettier x"]);
        assert_runs("bunx prettier x", &["prettier x"]);
        assert_runs("bunx --bun -p pkg tool arg", &["tool arg"]);
        assert_runs("deno run -A --config c.json script.ts", &["script.ts"]);
    }

    #[test]
    fn npx_c_and_shell_c_run_a_string() {
        assert_runs("npx -c 'cat x'", &["cat x"]);
        assert_runs("npx --call 'cat x; cat y'", &["cat x", "cat y"]);
        assert_runs("npx -p pkg -c 'cat x'", &["cat x"]);
    }

    #[test]
    fn shells_keep_their_own_command_and_run_the_c_string() {
        let commands = decompose("sh -c \"cat data/x.csv\"");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].argv, argv("sh -c 'cat data/x.csv'"));
        assert_eq!(commands[0].origin, Origin::Top);
        assert_eq!(commands[1].argv, argv("cat data/x.csv"));
        assert_eq!(commands[1].origin, Origin::Wrapper);

        for shell in ["sh", "bash", "zsh", "dash", "ksh", "/bin/bash", "fish"] {
            let commands = decompose(&format!("{shell} -c 'cat a; cat b'"));
            let inner: Vec<_> = commands.iter().skip(1).map(|c| c.argv.clone()).collect();
            assert_eq!(inner, vec![argv("cat a"), argv("cat b")], "{shell}");
        }
    }

    #[test]
    fn shell_option_clusters_and_values_do_not_hide_the_script() {
        for command in [
            "bash -lc 'cat x'",
            "bash -ec 'cat x'",
            "bash -c -- 'cat x'",
            "bash --norc -c 'cat x'",
            "bash -o pipefail -c 'cat x'",
            "bash -O extglob -c 'cat x'",
            "bash --rcfile r -c 'cat x'",
            "sh -c 'cat x' arg0 arg1",
        ] {
            assert!(
                run(command).contains(&argv("cat x")),
                "{command}: {:?}",
                run(command)
            );
        }
        // Without -c the first word is a script file, not a command line.
        assert!(!run("bash script.sh").contains(&argv("script.sh")));
        assert_eq!(run("bash script.sh"), vec![argv("bash script.sh")]);
    }

    #[test]
    fn here_strings_and_heredocs_fed_to_a_shell_are_scripts() {
        assert!(run("bash <<< 'cat data/x.csv'").contains(&argv("cat data/x.csv")));
        assert!(run("sh <<EOF\ncat data/x.csv\nEOF").contains(&argv("cat data/x.csv")));
        assert!(run("bash <<'EOF'\ncat a\ncat b\nEOF").contains(&argv("cat b")));
        // A here-document fed to a program that is not a shell is data.
        assert!(!run("cat <<'EOF'\ncat data/x.csv\nEOF").contains(&argv("cat data/x.csv")));
    }

    #[test]
    fn eval_runs_its_arguments_as_a_script() {
        assert_runs("eval 'cat x'", &["cat x"]);
        assert_runs("eval cat x", &["cat x"]);
        assert_runs("eval \"cat x; cat y\"", &["cat x", "cat y"]);
    }

    #[test]
    fn wrappers_chain_and_nest() {
        assert_runs("sudo env A=1 nice -n 5 timeout 9 cat x", &["cat x"]);
        assert_runs(
            "timeout 5 bash -c 'find . -exec cat {} \\;'",
            &["bash -c 'find . -exec cat {} \\;'", "cat ."],
        );
        assert_runs(
            "sh -c \"find . -exec cat {} \\;\"",
            &["sh -c 'find . -exec cat {} \\;'", "cat ."],
        );
        assert!(run("sh -c \"sh -c 'cat x'\"").contains(&argv("cat x")));
        assert!(run("bash -c 'echo $(cat x)'").contains(&argv("cat x")));
        assert!(
            run("env sh -c 'uv run python -c \"print(1)\"'")
                .contains(&argv("python -c 'print(1)'"))
        );
        assert_runs("find data -exec sudo cat {} \\;", &["cat data"]);
        assert!(run("find data -exec sh -c 'cat \"$1\"' _ {} \\;").contains(&argv("cat \"$1\"")));
    }

    #[test]
    fn a_wrapper_chain_is_bounded() {
        let chain = format!("{} cat x", "env ".repeat(40));
        let commands = decompose(&chain);

        // Too deep to follow: the rest is flagged rather than looped on.
        assert!(
            commands.iter().any(SimpleCommand::is_opaque),
            "{commands:?}"
        );
    }

    #[test]
    fn a_redirection_on_a_wrapper_belongs_to_the_command_it_runs() {
        let commands = decompose("sudo -u root cat < data/x.csv");

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].redirects_in, vec!["data/x.csv".to_owned()]);
    }
}
