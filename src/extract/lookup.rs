//! Whether a command changes which program a name runs (bd-jn6, bd-szf).
//!
//! An authorized spine tool is allowed to read protected files because it is
//! that tool. A command can put another program in its place: through the
//! environment it hands a program, by giving the name another meaning, by
//! running text veil does not read in the same shell, or through a runner that
//! looks names up its own way. veil does not work out which later words such a
//! change reaches (a loop runs an earlier line again), so one anywhere in a
//! command string withholds spine authority from all of it.
//!
//! For the environment the rule is a list of what may be carried, since too
//! many variables can carry code to name them: bash alone takes a function from
//! any `BASH_FUNC_name%%`. The other ways are a list of the ones known.

use super::decompose::{MAX_DEPTH, PROCESS_SUBSTITUTION, SUBSTITUTION};
use super::{command_name, is_shell_assignment};

/// The variables a command may put into a program's environment and keep spine
/// authority: locale, time zone and terminal settings.
const MAY_BE_CARRIED: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "TZ",
    "TERM",
    "COLUMNS",
    "LINES",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
];

fn may_be_carried(name: &str) -> bool {
    // a word as written may still have the quote it starts with
    MAY_BE_CARRIED.contains(&name.trim_start_matches(['"', '\'']))
}

/// Variables that decide which file a name runs, what is loaded into it, or
/// what a shell reads before it starts. bash's own variables are among them:
/// `BASH_ENV`, and its tables `BASH_CMDS` and `BASH_ALIASES`.
fn is_lookup_variable(name: &str) -> bool {
    matches!(name, "PATH" | "HOME" | "ZDOTDIR" | "ENV")
        || name.starts_with("BASH")
        || name.starts_with("LD_")
        || name.starts_with("DYLD_")
}

/// Whether setting `name` in the shell itself can reach what runs later. A
/// variable already in the environment hands its new value on. veil sees the
/// hook's environment, which stands in for the shell's. The shell sets `_`
/// itself, so setting it there changes nothing.
fn changes_what_follows(name: &str) -> bool {
    is_lookup_variable(name)
        || (name != "_" && !may_be_carried(name) && std::env::var_os(name).is_some())
}

/// What zsh finds names through: the array form of `PATH`, the paths it loads
/// functions and modules from, and its tables of commands, functions and
/// aliases. They are matched where they are subscripted or given an array,
/// since a plain `path=` is an ordinary variable elsewhere.
const ZSH_TABLES: &[&str] = &[
    "path",
    "fpath",
    "module_path",
    "commands",
    "functions",
    "aliases",
    "galiases",
];

/// A name only running the command would show: `$x`, or what a substitution
/// prints.
fn is_computed(name: &str) -> bool {
    name.contains(['$', SUBSTITUTION, PROCESS_SUBSTITUTION])
}

/// The name an assignment word sets, and whether it sets one element:
/// `NAME=x`, `NAME+=x` or `NAME[i]=x`.
fn assigned_name(word: &str) -> Option<(&str, bool)> {
    let (name, _) = word.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    Some(match name.split_once('[') {
        Some((name, _)) => (name, true),
        None => (name, false),
    })
}

/// Whether an assignment the shell makes for itself can reach what runs later.
fn assignment_changes_what_follows(word: &str) -> bool {
    assigned_name(word).is_some_and(|(name, element)| {
        changes_what_follows(name) || (element && ZSH_TABLES.contains(&name))
    })
}

/// `${PATH:=x}` and `${PATH=x}` assign while they expand, and `${!name:=x}`
/// assigns whatever `name` names.
fn expands_into_a_lookup_variable(word: &str) -> bool {
    word.split("${").skip(1).any(|expansion| {
        let (indirect, expansion) = match expansion.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, expansion),
        };
        let end = expansion
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(expansion.len());
        let (name, operator) = expansion.split_at(end);
        (operator.starts_with('=') || operator.starts_with(":="))
            && (indirect || is_lookup_variable(name))
    })
}

/// The words of `args` that are not redirections or what they name.
fn without_redirections<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut words = Vec::with_capacity(args.len());
    let mut args = args.iter().copied();
    while let Some(arg) = args.next() {
        let operator = arg.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
        if !operator.starts_with(['<', '>']) {
            words.push(arg);
        } else if operator.trim_start_matches(['<', '>', '|']).is_empty() {
            // the file is the next word
            args.next();
        }
    }
    words
}

/// `-p`, or a cluster such as `-rp`, among the options before the first operand.
fn has_short_option(args: &[&str], option: char) -> bool {
    args.iter()
        .take_while(|arg| arg.starts_with('-') && arg.len() > 1)
        .any(|arg| !arg.starts_with("--") && arg.contains(option))
}

/// Whether these words, a command with whatever assignments lead it, change
/// lookup for themselves or for what runs after them. `unresolved_program` says
/// the program is a word veil could not resolve.
pub(super) fn changes_lookup(words: &[&str], unresolved_program: bool) -> bool {
    if words
        .iter()
        .any(|word| expands_into_a_lookup_variable(word))
    {
        return true;
    }
    let leading = words
        .iter()
        .take_while(|word| is_shell_assignment(word))
        .count();
    let Some((program, args)) = words[leading..].split_first() else {
        // no command: the shell keeps these for itself
        return words
            .iter()
            .any(|word| assignment_changes_what_follows(word));
    };
    // what leads a command is put into its environment
    if words[..leading].iter().any(|word| {
        assigned_name(word).is_none_or(|(name, _)| {
            // `IFS= read -r line` sets it for the builtin alone
            !(may_be_carried(name) || (name == "IFS" && *program == "read"))
        })
    }) {
        return true;
    }
    // A command veil cannot name may be a builtin such as `source`. A builtin
    // has no slash in it.
    if unresolved_program && !program.contains('/') {
        return true;
    }

    match *program {
        // text veil does not read, run in this shell
        "source" | "." => true,
        // another meaning for a name; `autoload` is zsh's way to define one
        // from a file, and `zmodload` loads code
        "function" | "enable" | "autoload" | "zmodload" => true,
        "alias" => args.iter().any(|arg| arg.contains('=')),
        // `-p` in bash, `name=file` in zsh
        "hash" => has_short_option(args, 'p') || args.iter().any(|arg| arg.contains('=')),
        "export" => export_changes_lookup(args),
        // `-x` exports; `-n` makes one variable a name for another. zsh's
        // `integer` and `float` declare too.
        "declare" | "typeset" | "local" | "readonly" | "integer" | "float" => {
            declare_changes_lookup(args)
        }
        // every later assignment exported, or later words made assignments
        "set" => turns_on_exporting(args.iter().copied()),
        "shopt" | "setopt" => args.iter().any(|arg| is_exporting_option(arg)),
        // `-c` starts the program with no environment, so no `PATH`
        "exec" => has_short_option(args, 'c'),
        "unset" => sets_a_variable(args, &[], is_lookup_variable),
        "read" => sets_a_variable(
            args,
            &['d', 'i', 'n', 'N', 'p', 't', 'u'],
            changes_what_follows,
        ),
        "mapfile" | "readarray" => sets_a_variable(
            args,
            &['c', 'C', 'd', 'n', 'O', 's', 'u'],
            changes_what_follows,
        ),
        // the word after the option string
        "getopts" => args
            .get(1)
            .is_some_and(|name| changes_what_follows(name) || is_computed(name)),
        // the loop variable; the words after `in` are only its values
        "for" | "select" => args.first().is_some_and(|name| changes_what_follows(name)),
        "let" => args.iter().any(|arg| assignment_changes_what_follows(arg)),
        "printf" => args
            .windows(2)
            .any(|pair| pair[0] == "-v" && (changes_what_follows(pair[1]) || is_computed(pair[1]))),
        _ => runner_changes_lookup(command_name(program), args),
    }
}

/// Everything `export` names goes to every program that runs after it.
fn export_changes_lookup(args: &[&str]) -> bool {
    let args = without_redirections(args);
    let operands = args.iter().filter(|arg| !arg.starts_with('-'));
    if has_short_option(&args, 'n') {
        // taken out of the environment
        return operands.into_iter().any(|arg| {
            let name = assigned_name(arg).map_or(*arg, |(name, _)| name);
            is_computed(name) || is_lookup_variable(name)
        });
    }
    operands.into_iter().any(|arg| {
        let name = assigned_name(arg).map_or(*arg, |(name, _)| name);
        !may_be_carried(name)
    })
}

fn declare_changes_lookup(args: &[&str]) -> bool {
    let args = without_redirections(args);
    if has_short_option(&args, 'n') {
        return true;
    }
    let exported = has_short_option(&args, 'x');
    args.iter()
        .filter(|arg| !arg.starts_with(['-', '+']))
        .any(|arg| {
            let name = assigned_name(arg).map_or(*arg, |(name, _)| name);
            if exported {
                !may_be_carried(name)
            } else {
                is_computed(name) || assignment_changes_what_follows(arg)
            }
        })
}

/// `allexport` and `keyword`, however a shell lets them be spelled.
fn is_exporting_option(name: &str) -> bool {
    let name = name
        .chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(name.as_str(), "allexport" | "keyword")
}

/// Whether the options leading `args`, for `set` or a shell, turn on `-a`
/// (export what is assigned) or `-k` (assignments anywhere among a command's
/// words go into its environment).
fn turns_on_exporting<'a>(mut args: impl Iterator<Item = &'a str>) -> bool {
    while let Some(arg) = args.next() {
        if matches!(arg, "--" | "-") {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            if is_exporting_option(long) {
                return true;
            }
        } else if let Some(cluster) = arg.strip_prefix(['-', '+']) {
            let on = arg.starts_with('-');
            if on && cluster.contains(['a', 'k']) {
                return true;
            }
            if cluster.ends_with(['o', 'O']) && args.next().is_some_and(is_exporting_option) && on {
                return true;
            }
        } else {
            break;
        }
    }
    false
}

/// A shell started in a way that changes what names mean inside it.
pub(super) fn shell_changes_lookup(shell: &str, args: &[String]) -> bool {
    // veil reads scripts as POSIX shell text, which these do not speak
    if matches!(shell, "fish" | "csh" | "tcsh") {
        return true;
    }
    // a startup file the command names can define anything
    names_a_startup_file(args) || turns_on_exporting(args.iter().map(String::as_str))
}

/// `--rcfile file` or `--init-file file` anywhere among the shell's own
/// options, which end at its script.
fn names_a_startup_file(args: &[String]) -> bool {
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        if arg.starts_with("--rcfile") || arg.starts_with("--init-file") {
            return true;
        }
        if arg == "--" {
            break;
        }
        if let Some(cluster) = arg.strip_prefix(['-', '+']) {
            // a long option, which starts with the second `-`, takes no value here
            if !cluster.starts_with('-') && cluster.ends_with(['o', 'O']) {
                args.next();
            }
        } else {
            break;
        }
    }
    false
}

/// Whether `read` and its kin may set a variable `matters` picks out: an
/// operand before any redirection, skipping the values of the options that
/// take one.
fn sets_a_variable(args: &[&str], value_options: &[char], matters: fn(&str) -> bool) -> bool {
    let mut args = args.iter().take_while(|arg| !arg.starts_with(['<', '>']));
    while let Some(arg) = args.next() {
        if arg.len() > 1 && arg.starts_with('-') {
            if arg.ends_with(value_options) {
                args.next();
            }
        } else if matters(arg) || is_computed(arg) {
            return true;
        }
    }
    false
}

/// The action in `trap ACTION SIGNAL...`: a script the shell stores and may
/// run before the commands that follow. `-`, `-l` and `-p` name none.
pub(super) fn trap_action(args: &[String]) -> Option<&String> {
    args.iter()
        .find(|arg| *arg != "--")
        .filter(|action| !action.starts_with('-'))
}

/// A program that runs another one and finds it its own way.
fn runner_changes_lookup(program: &str, args: &[&str]) -> bool {
    let subcommand = args.first().copied();
    match program {
        // another user, with that user's search path
        "sudo" | "doas" => true,
        // an environment or a downloaded package comes first
        "uvx" | "npx" | "bunx" => true,
        "uv" => subcommand == Some("run") || args.starts_with(&["tool", "run"]),
        "poetry" | "pdm" | "pipx" | "deno" => subcommand == Some("run"),
        // `command -p` searches the system's default path
        "command" => has_short_option(args, 'p'),
        // GNU: puts a variable of the command's choosing into each program's
        // environment
        "xargs" => args.iter().any(|arg| arg.starts_with("--process-slot-var")),
        "env" => env_changes_lookup(args, 0),
        _ => false,
    }
}

/// `env` given anything but options known to leave lookup alone and
/// assignments of variables that may be carried. `-i` and `-` drop `PATH`, BSD
/// `-P` replaces the search path, and an option veil does not know could do
/// either. `splits` counts the `-S` strings these words came out of.
fn env_changes_lookup(args: &[&str], splits: usize) -> bool {
    let mut args = without_redirections(args).into_iter();
    let mut options_ended = false;
    while let Some(arg) = args.next() {
        if arg == "-" {
            return true;
        }
        if arg == "--" && !options_ended {
            options_ended = true;
        } else if let Some(long) = arg.strip_prefix("--").filter(|_| !options_ended) {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "unset" => {
                    if value
                        .or_else(|| args.next())
                        .is_some_and(is_lookup_variable)
                    {
                        return true;
                    }
                }
                "chdir" => {
                    if value.is_none() {
                        args.next();
                    }
                }
                "split-string" => {
                    if value
                        .or_else(|| args.next())
                        .is_some_and(|text| split_string_changes_lookup(text, splits))
                    {
                        return true;
                    }
                }
                "null"
                | "debug"
                | "block-signal"
                | "default-signal"
                | "ignore-signal"
                | "list-signal-handling"
                | "help"
                | "version" => {}
                _ => return true,
            }
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|_| !options_ended) {
            for (offset, flag) in cluster.char_indices() {
                match flag {
                    'v' | '0' => {}
                    'u' | 'C' | 'S' => {
                        let attached = &cluster[offset + 1..];
                        let value = if attached.is_empty() {
                            args.next()
                        } else {
                            Some(attached)
                        };
                        let changes = match flag {
                            'u' => value.is_some_and(is_lookup_variable),
                            'S' => {
                                value.is_some_and(|text| split_string_changes_lookup(text, splits))
                            }
                            _ => false,
                        };
                        if changes {
                            return true;
                        }
                        break;
                    }
                    _ => return true,
                }
            }
        } else if let Some((name, _)) = arg.split_once('=') {
            // `env` takes any name, whatever is in it
            if !may_be_carried(name) {
                return true;
            }
        } else {
            // the command: what follows is its own
            break;
        }
    }
    false
}

/// The words `env -S` splits its string into are options and assignments too,
/// and may hold another `-S`. Past [`MAX_DEPTH`] of them the answer is yes: an
/// unbounded descent could end the hook before it decides.
fn split_string_changes_lookup(text: &str, splits: usize) -> bool {
    if splits >= MAX_DEPTH {
        return true;
    }
    shlex::split(text).is_none_or(|words| {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        env_changes_lookup(&words, splits + 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn changes(command: &str) -> bool {
        changes_lookup(&command.split(' ').collect::<Vec<_>>(), false)
    }

    #[test]
    fn only_the_command_and_what_leads_it_are_read() {
        for command in [
            "PATH=x shape a",
            "LANG=C PATH+=x shape a",
            "PATH[0]=x",
            "export LANG=C PATH=x",
            "declare -n alias_of_path=PATH",
            "env --split-string=PATH=x shape",
            "env -iv shape",
            "env -v -u LD_LIBRARY_PATH shape",
            "for PATH in a b",
            "read -r PATH",
            "export $x=y",
            "hash tool=/tmp/tool",
            "commands[shape]=x",
            ": ${BASH_ENV:=env.sh}",
            "echo ${!name=tools}",
            // only what is listed may be carried
            "MY_SETTING=x shape a",
            "LANG=C MY_SETTING=x shape a",
            "env MY_SETTING=x shape",
            "env BASH_FUNC_shape%%=x bash",
            "env -- BASH_FUNC_shape%%=x bash",
            "env --new-option shape",
            "env -x shape",
            "export STAMP=$now",
            "export -f shape",
            "declare -gx MY_SETTING=x",
            "BASH_CMDS[shape]=x",
            "BASH_ALIASES[shape]=x",
            "set -k",
            "set -ea",
            "set -o allexport",
            "set -euo keyword",
            "setopt ALL_EXPORT",
            "shopt -so allexport",
            "exec -c bash",
            "xargs --process-slot-var=SLOT shape",
            "zmodload zsh/system",
            "module_path=x module",
        ] {
            assert!(changes(command), "{command}");
        }
        for command in [
            "shape PATH=x",
            "shape --key PATH",
            "grep PATH=x notes.txt",
            "export -n LANG",
            "unset LANG",
            "printf %s PATH",
            "env -u LANG shape",
            "env LANG=C grep -i PATH",
            "env -C dir shape -i",
            "alias",
            "hash -r",
            "command -v shape",
            "uv sync",
            "for name in PATH HOME",
            "read -r -p $prompt answer",
            "read -r line < $file",
            "mapfile -t -n $count rows",
            "path=data/clients",
            "totals[1]=2",
            "echo ${USER:=nobody} ${PATH:-none} ${HOME}",
            "LANG=C LC_ALL=C TZ=UTC NO_COLOR=1 shape a",
            "env LC_ALL=C TERM=dumb shape",
            "env 'LC_ALL=C' shape",
            "env -v -- LANG=C shape",
            "export LANG=C LC_ALL=C 2>/dev/null",
            "export -p > exports.txt",
            "IFS= read -r veil_row",
            "set -euo pipefail",
            "set -- -a -k",
            "shopt -s nullglob",
            "declare -i veil_total=1",
            "exec shape a",
        ] {
            assert!(!changes(command), "{command}");
        }
    }

    #[test]
    fn a_shell_is_read_by_its_options_up_to_its_script() {
        let changes = |shell: &str, args: &str| {
            let args = args.split(' ').map(str::to_owned).collect::<Vec<_>>();
            shell_changes_lookup(shell, &args)
        };
        for (shell, args) in [
            ("bash", "--rcfile f -ic x"),
            ("bash", "-i --init-file f -c x"),
            ("bash", "-o errexit --rcfile f -c x"),
            ("bash", "-kc x"),
            ("sh", "-a -c x"),
            ("bash", "-o allexport -c x"),
            ("zsh", "--all-export -c x"),
            ("tcsh", "-f -c x"),
            ("csh", "script"),
            ("fish", "-c x"),
        ] {
            assert!(changes(shell, args), "{shell} {args}");
        }
        for (shell, args) in [
            ("bash", "-euo pipefail -c x"),
            ("bash", "--noprofile --norc -c x"),
            ("bash", "-lc x"),
            ("sh", "script -a --rcfile"),
            ("zsh", "-c x"),
        ] {
            assert!(!changes(shell, args), "{shell} {args}");
        }
    }

    #[test]
    fn an_unnamed_program_counts_only_when_it_could_be_a_builtin() {
        assert!(changes_lookup(&["$x", "env.sh"], true));
        assert!(!changes_lookup(&["$VENV/bin/python", "run.py"], true));
        assert!(changes_lookup(&["LANG=C", "$x"], true));
    }
}
