//! bd-qe9: the files a command line's output redirections write.
//!
//! The words are read as written, quotes and all, because only there can an
//! operator be told from a `'>'` handed to a command as data. The scanner puts
//! a blank before an unquoted `<` or `>` glued to a word, so every operator
//! begins a word.

use std::path::Path;

use super::decompose::{PROCESS_SUBSTITUTION, SUBSTITUTION};
use super::expand::{ShellEnv, Vars};

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

/// The files the shell opens for writing when it runs the words `raw`, from the
/// directory `cwd`. A target veil cannot resolve is left out: it is one of the
/// command's unresolved words, which the dynamic-argument stance judges.
pub(super) fn writes(raw: &[&str], vars: &Vars, env: &ShellEnv, cwd: Option<&Path>) -> Vec<String> {
    let mut writes = Vec::new();

    for target in written_targets(raw) {
        // a quote veil cannot read fails the whole command where its words are
        // expanded, so there is nothing to add to that here
        let Some(words) = vars.words(&[target], env) else {
            continue;
        };
        for word in words {
            let text = word.text;
            if word.unresolved.is_some()
                || text.is_empty()
                || text.contains([SUBSTITUTION, PROCESS_SUBSTITUTION])
            {
                continue;
            }
            writes.push(match cwd {
                Some(cwd) => cwd.join(&text).to_string_lossy().into_owned(),
                None => text,
            });
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
