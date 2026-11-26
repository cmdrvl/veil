//! Whether a command changes which program a name runs (bd-jn6).
//!
//! An authorized spine tool is allowed to read protected files because it is
//! that tool. A command can put another program in its place: by setting
//! `PATH` or a variable that loads code, by giving the name another meaning,
//! by running text veil does not read in the same shell, or through a runner
//! that looks names up its own way. veil does not work out which later words
//! such a change reaches (a loop runs an earlier line again), so one anywhere
//! in a command string withholds spine authority from all of it.

use super::decompose::{MAX_DEPTH, PROCESS_SUBSTITUTION, SUBSTITUTION};
use super::{command_name, is_env_assignment};

/// Variables that decide which file a name runs, what is loaded into it, or
/// what a shell reads before it starts.
fn is_lookup_variable(name: &str) -> bool {
    matches!(name, "PATH" | "HOME" | "ZDOTDIR" | "BASH_ENV" | "ENV")
        || name.starts_with("LD_")
        || name.starts_with("DYLD_")
}

/// What zsh finds names through: the array form of `PATH`, the path it loads
/// functions from, and its tables of commands, functions and aliases. They are
/// matched where they are subscripted or given an array, since a plain `path=`
/// is an ordinary variable elsewhere.
const ZSH_TABLES: &[&str] = &[
    "path",
    "fpath",
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

/// `PATH=x`, `PATH+=x`, `PATH[0]=x`, or one of zsh's `path[1]=x`.
fn assigns_lookup_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        let name = name.strip_suffix('+').unwrap_or(name);
        match name.split_once('[') {
            Some((name, _)) => is_lookup_variable(name) || ZSH_TABLES.contains(&name),
            None => is_lookup_variable(name),
        }
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
        .take_while(|word| {
            is_env_assignment(word) || word.contains("+=") || assigns_lookup_variable(word)
        })
        .count();
    if words[..leading]
        .iter()
        .any(|word| assigns_lookup_variable(word))
    {
        return true;
    }
    let Some((program, args)) = words[leading..].split_first() else {
        return false;
    };
    // A command veil cannot name may be a builtin such as `source`. A builtin
    // has no slash in it.
    if unresolved_program && !program.contains('/') {
        return true;
    }

    match *program {
        // text veil does not read, run in this shell
        "source" | "." => true,
        // another meaning for a name
        // `autoload` is zsh's way to define one from a file
        "function" | "enable" | "autoload" => true,
        "alias" => args.iter().any(|arg| arg.contains('=')),
        // `-p` in bash, `name=file` in zsh
        "hash" => has_short_option(args, 'p') || args.iter().any(|arg| arg.contains('=')),
        // setting a variable; `-n` makes one a name for another
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            args.iter().any(|arg| {
                let name = arg.split_once('=').map_or(*arg, |(name, _)| name);
                assigns_lookup_variable(arg) || is_computed(name)
            }) || (*program != "export" && has_short_option(args, 'n'))
        }
        "unset" => sets_a_lookup_variable(args, &[]),
        "read" => sets_a_lookup_variable(args, &['d', 'i', 'n', 'N', 'p', 't', 'u']),
        "mapfile" | "readarray" => {
            sets_a_lookup_variable(args, &['c', 'C', 'd', 'n', 'O', 's', 'u'])
        }
        // the word after the option string
        "getopts" => args
            .get(1)
            .is_some_and(|name| is_lookup_variable(name) || is_computed(name)),
        // the loop variable; the words after `in` are only its values
        "for" | "select" => args.first().is_some_and(|name| is_lookup_variable(name)),
        "let" => args.iter().any(|arg| assigns_lookup_variable(arg)),
        "printf" => args
            .windows(2)
            .any(|pair| pair[0] == "-v" && (is_lookup_variable(pair[1]) || is_computed(pair[1]))),
        _ => runner_changes_lookup(command_name(program), args),
    }
}

/// Whether `read` and its kin may set a lookup variable: an operand before any
/// redirection, skipping the values of the options that take one.
fn sets_a_lookup_variable(args: &[&str], value_options: &[char]) -> bool {
    let mut args = args.iter().take_while(|arg| !arg.starts_with(['<', '>']));
    while let Some(arg) = args.next() {
        if arg.len() > 1 && arg.starts_with('-') {
            if arg.ends_with(value_options) {
                args.next();
            }
        } else if is_lookup_variable(arg) || is_computed(arg) {
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
        "env" => env_changes_lookup(args, 0),
        _ => false,
    }
}

/// `env` with an option or an assignment that changes lookup: `-i` and `-` drop
/// `PATH`, BSD `-P` replaces the search path. `splits` counts the `-S` strings
/// these words came out of.
fn env_changes_lookup(args: &[&str], splits: usize) -> bool {
    let mut args = args.iter().copied();
    while let Some(arg) = args.next() {
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "ignore-environment" => return true,
                "unset"
                    if value
                        .or_else(|| args.next())
                        .is_some_and(is_lookup_variable) =>
                {
                    return true;
                }
                "chdir" if value.is_none() => {
                    args.next();
                }
                "split-string"
                    if value
                        .or_else(|| args.next())
                        .is_some_and(|text| split_string_changes_lookup(text, splits)) =>
                {
                    return true;
                }
                _ => {}
            }
        } else if let Some(cluster) = arg.strip_prefix('-') {
            if cluster.is_empty() {
                return true;
            }
            for (offset, flag) in cluster.char_indices() {
                if matches!(flag, 'i' | 'P') {
                    return true;
                }
                if matches!(flag, 'u' | 'C' | 'S') {
                    let attached = &cluster[offset + 1..];
                    let value = if attached.is_empty() {
                        args.next()
                    } else {
                        Some(attached)
                    };
                    let changes = match flag {
                        'u' => value.is_some_and(is_lookup_variable),
                        'S' => value.is_some_and(|text| split_string_changes_lookup(text, splits)),
                        _ => false,
                    };
                    if changes {
                        return true;
                    }
                    break;
                }
            }
        } else if assigns_lookup_variable(arg) {
            return true;
        } else if !arg.contains('=') {
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
            "export STAMP=$now",
            "path=data/clients",
            "totals[1]=2",
            "echo ${USER:=nobody} ${PATH:-none} ${HOME}",
        ] {
            assert!(!changes(command), "{command}");
        }
    }

    #[test]
    fn an_unnamed_program_counts_only_when_it_could_be_a_builtin() {
        assert!(changes_lookup(&["$x", "env.sh"], true));
        assert!(!changes_lookup(&["$VENV/bin/python", "run.py"], true));
        assert!(changes_lookup(&["LANG=C", "$x"], true));
    }
}
