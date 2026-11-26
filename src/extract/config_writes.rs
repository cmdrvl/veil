//! bd-02q: what a command could write, remove, move or re-permission, for the
//! guard on veil's configuration. Whether a path is one of those files is
//! decided where it is judged (`policy_guard`); nothing here looks at policy.
//!
//! A program known to write nothing is skipped, a program that writes is read
//! for the words it writes, and for any other program every word that could
//! name a file counts: naming a config to a program veil does not know is
//! enough.

use std::fs;
use std::path::{Path, PathBuf};

/// How far a path a command may write has to be followed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteReach {
    /// The command writes this file.
    File,
    /// The command removes, moves, replaces or re-permissions what is here, so
    /// a directory that holds the user's settings counts too.
    Tree,
    /// A program veil does not know names this. A glob counts only when it
    /// spells out part of a config's name.
    Mention,
}

/// A path a command may write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigWrite {
    /// Not normalised: `..` after a symlink goes where the symlink goes.
    pub path: PathBuf,
    pub reach: WriteReach,
}

/// Programs that write none of the files they name. A shell is one: the
/// commands it is handed are judged on their own.
const WRITES_NOTHING: &[&str] = &[
    "cat",
    "bat",
    "head",
    "tail",
    "more",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "wc",
    "ls",
    "dir",
    "vdir",
    "stat",
    "du",
    "df",
    "file",
    "test",
    "[",
    "[[",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "echo",
    "printf",
    "true",
    "false",
    "cd",
    "pushd",
    "popd",
    "pwd",
    "which",
    "type",
    "command",
    "cmp",
    "comm",
    "md5",
    "md5sum",
    "shasum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "cksum",
    "od",
    "hexdump",
    "strings",
    "cut",
    "tr",
    "column",
    "nl",
    "fold",
    "paste",
    "join",
    "rev",
    "tac",
    "jq",
    "source",
    ".",
    "export",
    "local",
    "declare",
    "readonly",
    "eza",
    "exa",
    "delta",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
];

/// Programs that remove or re-permission each file they are given.
const REMOVES: &[&str] = &["rm", "unlink", "rmdir", "shred", "chmod", "chown", "chgrp"];

/// Programs that empty, add to or create each file they are given.
const WRITES_OPERANDS: &[&str] = &["tee", "touch", "truncate", "mkdir"];

/// `git` subcommands that leave the files they name as they are.
const GIT_LEAVES_FILES: &[&str] = &[
    "status",
    "log",
    "show",
    "diff",
    "blame",
    "cat-file",
    "ls-files",
    "grep",
    "add",
    "commit",
    "rev-parse",
    "check-ignore",
    "ls-tree",
    "annotate",
    "shortlog",
    "describe",
];

/// What the command `name args` may write, from `cwd`. `heredoc` is the text on
/// its standard input when the command string carries it, and `script_writes`
/// the files a script veil parsed says it writes (`sed 'w out'`).
pub(super) fn config_writes(
    name: &str,
    args: &[String],
    heredoc: Option<&str>,
    script_writes: &[String],
    cwd: &Path,
    home: Option<&str>,
) -> Vec<ConfigWrite> {
    let mut found = Found {
        writes: Vec::new(),
        cwd,
        home,
        runs_code: runs_code(name),
    };
    found.add_all(script_writes.iter().map(String::as_str), WriteReach::File);

    let words = without_redirections(args);
    if WRITES_NOTHING.contains(&name) {
        return found.writes;
    }
    if REMOVES.contains(&name) {
        found.add_all(operands(&words, &[]), WriteReach::Tree);
        return found.writes;
    }
    if WRITES_OPERANDS.contains(&name) {
        found.add_all(operands(&words, &[]), WriteReach::File);
        return found.writes;
    }

    match name {
        "cp" | "install" | "rsync" | "ditto" | "scp" => found.copy(name, &words),
        "mv" | "ln" => found.move_or_link(&words),
        "dd" => found.add_all(
            words.iter().filter_map(|word| word.strip_prefix("of=")),
            WriteReach::File,
        ),
        "sed" | "gsed" => {
            if words.iter().any(|word| edits_in_place(word)) {
                found.add_all(sed_files(&words), WriteReach::File);
            }
        }
        // these only read, but for the file they are told to log or print into
        "less" => {
            for (short, long) in [('o', "--log-file"), ('O', "--LOG-FILE")] {
                found.add_all(option_values(&words, short, long), WriteReach::File);
            }
        }
        "diff" => found.add_all(
            words
                .iter()
                .filter_map(|word| word.strip_prefix("--output=")),
            WriteReach::File,
        ),
        "sort" => found.add_all(option_values(&words, 'o', "--output"), WriteReach::File),
        "tree" => found.add_all(option_values(&words, 'o', "--output"), WriteReach::File),
        // `uniq in out`, `xxd in out`
        "uniq" | "xxd" => found.add_all(
            operands(&words, &["-f", "-s", "-w", "-c", "-g", "-l"])
                .into_iter()
                .skip(1),
            WriteReach::File,
        ),
        "yq" if words
            .iter()
            .any(|word| edits_in_place(word) || *word == "--inplace") =>
        {
            found.add_all(operands(&words, &[]), WriteReach::File);
        }
        "yq" => {}
        "awk" | "gawk" | "mawk" | "nawk" => {
            if words.iter().any(|word| word.contains('>')) || words.contains(&"inplace") {
                found.mentions(&words, heredoc);
            }
        }
        "find" => {
            if find_changes_files(&words) {
                found.mentions(&words, heredoc);
            }
        }
        "fd" | "fdfind" => {
            if words
                .iter()
                .any(|word| matches!(*word, "-x" | "-X" | "--exec" | "--exec-batch"))
            {
                found.mentions(&words, heredoc);
            }
        }
        "git" => found.git(&words, heredoc),
        "tar" | "gtar" | "bsdtar" => {
            if tar_extracts(&words) {
                found.mentions(&words, heredoc);
            } else {
                found.add_all(option_values(&words, 'f', "--file"), WriteReach::File);
            }
        }
        _ => found.mentions(&words, heredoc),
    }
    found.writes
}

/// What a sed script file says it writes.
pub(super) fn script_file_writes(
    names: &[String],
    cwd: &Path,
    home: Option<&str>,
) -> Vec<ConfigWrite> {
    let mut found = Found {
        writes: Vec::new(),
        cwd,
        home,
        runs_code: false,
    };
    found.add_all(names.iter().map(String::as_str), WriteReach::File);
    found.writes
}

/// A program that runs the code it is handed, so a file it opens may be named
/// by a quoted string inside a word or in its standard input. To any other
/// program such text is only text, as in the body of a pull request.
fn runs_code(name: &str) -> bool {
    name.starts_with("python")
        || matches!(
            name,
            "node"
                | "nodejs"
                | "deno"
                | "bun"
                | "perl"
                | "ruby"
                | "php"
                | "lua"
                | "R"
                | "Rscript"
                | "osascript"
                | "tclsh"
                | "pwsh"
                | "awk"
                | "gawk"
                | "mawk"
                | "nawk"
        )
}

struct Found<'a> {
    writes: Vec<ConfigWrite>,
    cwd: &'a Path,
    home: Option<&'a str>,
    runs_code: bool,
}

impl Found<'_> {
    fn locate(&self, word: &str) -> PathBuf {
        // the shell expands `~` at the start of a word or after an `=`
        let expanded = match (word.strip_prefix('~'), self.home) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                format!("{home}{rest}")
            }
            _ => word.to_owned(),
        };
        self.cwd.join(expanded)
    }

    fn add(&mut self, word: &str, reach: WriteReach) {
        if word.is_empty() || word == "-" {
            return;
        }
        let write = ConfigWrite {
            path: self.locate(word),
            reach,
        };
        self.writes.push(write);
    }

    fn add_all<'w>(&mut self, words: impl IntoIterator<Item = &'w str>, reach: WriteReach) {
        for word in words {
            self.add(word, reach);
        }
    }

    /// Where `source` lands in the directory `destination`.
    fn add_inside(&mut self, destination: &str, source: &str, reach: WriteReach) {
        // contents copied into the directory itself
        if source == "." || source.ends_with('/') || source.ends_with("/.") {
            self.add(destination, WriteReach::Tree);
        } else if let Some(name) = Path::new(source).file_name() {
            let path = self.locate(destination).join(name);
            self.writes.push(ConfigWrite { path, reach });
        }
    }

    fn is_directory(&self, word: &str) -> bool {
        word.ends_with('/') || fs::metadata(self.locate(word)).is_ok_and(|found| found.is_dir())
    }

    /// The sources and the destination of a copy, move or link.
    fn sources_and_destination<'w>(
        name: &str,
        words: &[&'w str],
    ) -> (Vec<&'w str>, Option<&'w str>, bool) {
        // `-t` names the directory for these; to `rsync` it keeps times
        let takes_target = matches!(name, "cp" | "install" | "mv" | "ln");
        let target = takes_target
            .then(|| option_values(words, 't', "--target-directory").pop())
            .flatten();
        let valued: &[&str] = match name {
            "install" => &["-m", "-o", "-g", "-t"],
            "rsync" => &["-e", "-f", "-B", "-T"],
            "scp" => &["-i", "-P", "-o", "-c", "-F", "-J", "-l", "-S"],
            "cp" | "mv" | "ln" => &["-t", "-S"],
            _ => &[],
        };
        let mut sources = operands(words, valued);
        match target {
            Some(directory) => (sources, Some(directory), true),
            None => {
                let destination = if sources.len() > 1 {
                    sources.pop()
                } else {
                    None
                };
                let many = sources.len() > 1;
                (sources, destination, many)
            }
        }
    }

    /// A copy writes its destination; what it reads it leaves as it was.
    fn copy(&mut self, name: &str, words: &[&str]) {
        let (sources, destination, mut into) = Self::sources_and_destination(name, words);
        // a link is another name for the source, which a later write goes through
        let links = name == "cp"
            && words.iter().any(|word| {
                *word == "--link" || *word == "--symbolic-link" || short_has(word, &['l', 's'])
            });
        if links {
            self.add_all(sources.iter().copied(), WriteReach::File);
        }
        if words.contains(&"--remove-source-files") {
            self.add_all(sources.iter().copied(), WriteReach::Tree);
        }
        let Some(destination) = destination else {
            return;
        };
        into = into || self.is_directory(destination);
        if into {
            for source in sources {
                self.add_inside(destination, source, WriteReach::Tree);
            }
        } else {
            self.add(destination, WriteReach::Tree);
        }
    }

    /// A move or a link changes what every name it is given leads to.
    fn move_or_link(&mut self, words: &[&str]) {
        let (sources, destination, into) = Self::sources_and_destination("mv", words);
        self.add_all(sources.iter().copied(), WriteReach::Tree);
        let Some(destination) = destination else {
            return;
        };
        self.add(destination, WriteReach::Tree);
        if into || self.is_directory(destination) {
            for source in sources {
                self.add_inside(destination, source, WriteReach::Tree);
            }
        }
    }

    fn git(&mut self, words: &[&str], heredoc: Option<&str>) {
        let mut rest = words.iter();
        let subcommand = loop {
            match rest.next() {
                // global options whose value is the next word
                Some(&("-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace")) => {
                    rest.next();
                }
                Some(word) if word.starts_with('-') => {}
                found => break found.copied(),
            }
        };
        let leaves = subcommand.is_some_and(|name| {
            GIT_LEAVES_FILES.contains(&name) || (name == "rm" && words.contains(&"--cached"))
        });
        if leaves {
            self.add_all(
                words
                    .iter()
                    .filter_map(|word| word.strip_prefix("--output=")),
                WriteReach::File,
            );
        } else {
            self.mentions(words, heredoc);
        }
    }

    /// Everything in the words of a program veil does not know that could name
    /// a file: a word, what follows its `=` or a short option, and, for a
    /// program that runs code, what it quotes.
    fn mentions(&mut self, words: &[&str], heredoc: Option<&str>) {
        for word in words {
            self.add(word, WriteReach::Mention);
            if let Some((_, value)) = word.split_once('=') {
                self.add(value, WriteReach::Mention);
            }
            if word.starts_with('-')
                && !word.starts_with("--")
                && let Some(value) = word.get(2..)
            {
                self.add(value, WriteReach::Mention);
            }
            self.quoted(word);
        }
        if let Some(text) = heredoc {
            self.quoted(text);
        }
    }

    fn quoted(&mut self, text: &str) {
        const QUOTES: [char; 3] = ['\'', '"', '`'];
        if self.runs_code && text.contains(QUOTES) {
            for piece in text.split(QUOTES) {
                self.add(piece, WriteReach::Mention);
            }
        }
    }
}

/// `args` without the redirections, which are judged as the shell opens them.
fn without_redirections(args: &[String]) -> Vec<&str> {
    let mut kept = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        let operator = word
            .strip_prefix('&')
            .unwrap_or_else(|| word.trim_start_matches(|ch: char| ch.is_ascii_digit()));
        if operator.starts_with(['<', '>']) {
            // an operator with nothing attached takes the next word
            if operator
                .trim_start_matches(['<', '>', '|', '&', '!', '-'])
                .is_empty()
            {
                words.next();
            }
            continue;
        }
        kept.push(word.as_str());
    }
    kept
}

/// The words that are not options. `valued` are options whose value is the
/// next word.
fn operands<'w>(words: &[&'w str], valued: &[&str]) -> Vec<&'w str> {
    let mut found = Vec::new();
    let mut words = words.iter();
    let mut options = true;
    while let Some(&word) = words.next() {
        if options && word == "--" {
            options = false;
        } else if options && word.len() > 1 && word.starts_with('-') {
            if valued.contains(&word) {
                words.next();
            }
        } else {
            found.push(word);
        }
    }
    found
}

/// The values of the option `-x` (alone, ending a group, or with the value
/// attached) and `--long`.
fn option_values<'w>(words: &[&'w str], short: char, long: &str) -> Vec<&'w str> {
    let mut values = Vec::new();
    let mut words = words.iter();
    while let Some(&word) = words.next() {
        if word == long {
            values.extend(words.next().copied());
        } else if let Some(rest) = word.strip_prefix(long) {
            values.extend(rest.strip_prefix('='));
        } else if let Some(group) = word.strip_prefix('-').filter(|rest| !rest.starts_with('-'))
            && let Some(at) = group.find(short)
        {
            match &group[at + short.len_utf8()..] {
                "" => values.extend(words.next().copied()),
                attached => values.push(attached),
            }
        }
    }
    values
}

/// A group of short options that has one of `letters`.
fn short_has(word: &str, letters: &[char]) -> bool {
    word.strip_prefix('-')
        .is_some_and(|group| !group.starts_with('-') && group.contains(letters))
}

/// The files a `sed` is given: its operands, but for the script, which is the
/// first of them where no `-e` or `-f` gives it.
fn sed_files<'w>(words: &[&'w str]) -> Vec<&'w str> {
    let given = words.iter().any(|word| {
        word.starts_with("--expression")
            || word.starts_with("--file")
            || short_has(word, &['e', 'f'])
    });
    operands(words, &["-e", "-f"])
        .into_iter()
        // the empty suffix of `-i ''` is neither
        .filter(|word| !word.is_empty())
        .skip(usize::from(!given))
        .collect()
}

fn edits_in_place(word: &str) -> bool {
    word.starts_with("--in-place") || short_has(word, &['i'])
}

/// `find` that deletes, prints into a file, or runs a program that may write.
fn find_changes_files(words: &[&str]) -> bool {
    let runs_a_writer = words.windows(2).any(|pair| {
        matches!(pair[0], "-exec" | "-execdir" | "-ok" | "-okdir")
            && !Path::new(pair[1])
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    WRITES_NOTHING.contains(&name) && !matches!(name, "sh" | "bash" | "zsh")
                })
    });
    runs_a_writer
        || words
            .iter()
            .any(|word| *word == "-delete" || word.starts_with("-fprint") || *word == "-fls")
}

/// Whether `tar` is asked to write the files an archive holds.
fn tar_extracts(words: &[&str]) -> bool {
    words.iter().enumerate().any(|(index, word)| {
        *word == "--extract"
            || *word == "--get"
            || short_has(word, &['x'])
            // `tar xf a.tar`: the first word may be the options with no dash
            || (index == 0 && !word.starts_with('-') && word.contains('x'))
    })
}
