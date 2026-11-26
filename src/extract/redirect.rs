//! bd-qe9: the files a command line's output redirections write.
//!
//! The words are read as written, quotes and all, because only there can an
//! operator be told from a `'>'` handed to a command as data. The scanner puts
//! a blank before an unquoted `<` or `>` glued to a word, so every operator
//! begins a word.

use std::path::{Path, PathBuf};
use std::slice;

use super::decompose::PROCESS_SUBSTITUTION;
use super::expand::{ShellEnv, Vars};

/// What one output redirection writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedirectTarget {
    /// A file, by the path the shell will open.
    File(PathBuf),
    /// A target veil cannot resolve to a file, as it was written. The shell
    /// may open any file at all (bd-bow).
    Unresolved(String),
}

/// What follows the `>` or `<>` (which opens for reading and writing) of a word
/// that begins with an output redirection, with or without a descriptor or the
/// `&` of `&>`.
pub(super) fn after_operator(word: &str) -> Option<&str> {
    let operator = match word.strip_prefix('&') {
        Some(rest) => rest,
        None => word.trim_start_matches(|ch: char| ch.is_ascii_digit()),
    };
    operator
        .strip_prefix("<>")
        .or_else(|| operator.strip_prefix('>'))
}

/// The target of each output redirection among `words`, as written.
fn written_targets<'a>(words: &[&'a str]) -> Vec<&'a str> {
    let mut targets = Vec::new();
    let mut words = words.iter().copied();

    while let Some(word) = words.next() {
        let Some(after) = after_operator(word) else {
            continue;
        };

        // `>>` and `>|`; after `&` the target may be a descriptor to copy
        let after = after.trim_start_matches(['>', '|']);
        let (after, copies) = match after.strip_prefix('&') {
            Some(rest) => (rest.trim_start_matches('|'), true),
            None => (after, false),
        };

        // zsh writes `>!` and `>>!`; to bash the `!` begins the file's name
        let (target, without_bang) = match after {
            "" | "!" => (words.next(), None),
            _ => (Some(after), after.strip_prefix('!')),
        };
        for target in target.into_iter().chain(without_bang) {
            if !(copies && is_descriptor(target)) {
                targets.push(target);
            }
        }
    }

    targets
}

/// What `>&` copies or closes: `2`, `-`, or `1-` which moves one.
fn is_descriptor(target: &str) -> bool {
    let digits = target.strip_suffix('-').unwrap_or(target);
    digits.chars().all(|ch| ch.is_ascii_digit())
}

/// Where the words of a line are run from, and how far veil can trust what it
/// knows there.
pub(super) struct Place<'a> {
    pub cwd: Option<&'a Path>,
    /// veil cannot be sure the shell is in `cwd`.
    pub cwd_unresolved: bool,
    /// The script the line is in was written with a value the shell may not
    /// hold ([`Vars::may_be_inherited`]).
    pub doubted: bool,
}

/// What the shell opens for writing when it runs the words `raw` at `place`. A
/// target veil cannot be sure of is listed as unresolved, and so is the file
/// veil would take it for, if any, which is judged too.
pub(super) fn writes(
    raw: &[&str],
    vars: &Vars,
    env: &ShellEnv,
    place: &Place<'_>,
) -> Vec<RedirectTarget> {
    let mut writes = Vec::new();

    for written in written_targets(raw) {
        // a quote veil cannot read fails the whole command where its words are
        // expanded, so there is nothing to add to that here
        let Some(words) = vars.words(&[written], env) else {
            continue;
        };
        // whatever veil makes of such a target, the shell may make another
        // thing of it, an empty value and so no word at all included
        let doubted = place.doubted || vars.may_be_inherited(written);
        if doubted {
            writes.push(RedirectTarget::Unresolved(written.to_owned()));
        }
        for word in words {
            let text = word.text;
            // `> >(cmd)` is a pipe to a command, which is judged as one
            if text.chars().eq([PROCESS_SUBSTITUTION]) {
                continue;
            }
            // text that still looks unexpanded counts as it does in a reader's
            // file: zsh expands `$=name` and `$~name`, which veil leaves as is
            if word.unresolved.is_some()
                || !super::unresolved_files(&[], slice::from_ref(&text)).is_empty()
            {
                writes.push(RedirectTarget::Unresolved(written.to_owned()));
                continue;
            }
            if text.is_empty() {
                continue;
            }
            // a relative name in a directory veil cannot follow may be any file
            if place.cwd_unresolved && !doubted && !Path::new(&text).is_absolute() {
                writes.push(RedirectTarget::Unresolved(written.to_owned()));
            }
            // and the file it names in veil's best guess at one is judged too
            writes.push(RedirectTarget::File(match place.cwd {
                Some(cwd) => cwd.join(&text),
                None => PathBuf::from(text),
            }));
        }
    }

    writes
}

#[cfg(test)]
mod tests {
    use super::written_targets;

    #[test]
    fn every_operator_names_its_target() {
        for (words, expected) in [
            (&[">", "a"][..], &["a"][..]),
            (&[">a"], &["a"]),
            (&[">>a"], &["a"]),
            (&["2>>", "a"], &["a"]),
            (&["10>a"], &["a"]),
            (&["&>a"], &["a"]),
            (&["&>>", "a"], &["a"]),
            (&[">|a"], &["a"]),
            (&[">&a"], &["a"]),
            (&[">&", "a"], &["a"]),
            (&["<>a"], &["a"]),
            (&[">!", "a"], &["a"]),
            (&[">>!a"], &["!a", "a"]),
            (&["x", ">a", "y", ">b"], &["a", "b"]),
        ] {
            assert_eq!(written_targets(words), expected, "{words:?}");
        }
    }

    #[test]
    fn descriptors_inputs_and_quoted_operators_write_no_file() {
        for words in [
            &["2>&1"][..],
            &[">&2"],
            &[">&", "2"],
            &["2>&-"],
            &["1>&2-"],
            &["<a"],
            &["<<<a"],
            &["'>'", "a"],
            &["\">>a\""],
            &["\\>a"],
            &["a>b"],
            &["->a"],
            &[">"],
        ] {
            assert!(written_targets(words).is_empty(), "{words:?}");
        }
    }
}
