//! What one command string writes to files before it runs them.
//!
//! veil reads a script file as it is on disk when the hook runs. A script the
//! same string writes first is not there yet: `printf 'r .env\n' > tmp.sed; sed
//! -f tmp.sed notes.md` ran a file veil never saw, though the second half alone
//! is denied once the file exists. [`Written`] keeps what the string writes to a
//! file, so the reader of a script judges the text that will be there.
//!
//! The text is known when the string spells it out: `echo` and `printf`
//! arguments, a here-document or a here-string, sent to a file by `>`, `>>` or
//! `tee`. A file written with text veil cannot see (a variable, a substitution,
//! a pipe, a program's output) is [`Writes::Computed`]: run as a script, it is as
//! unresolved as a word veil cannot resolve, and the dynamic-argument stance
//! decides. Text built at run time that no literal shows (`printf "$X"`,
//! `base64 -d`) is the same limit as a path built at run time.
//!
//! The record is the writes of the whole string, in no order. A loop runs a
//! script an earlier iteration wrote, and a write after `&&` or `||` may not
//! happen, so what is on disk is still judged beside what is written. Reading too
//! much is only over-blocking; reading too little hides a script.

use std::collections::HashMap;
use std::path::Path;

use super::script::{locate, usable};
use super::{SimpleCommand, command_name, lexical_path};

/// The most files one string is followed writing. Past it every script is as
/// unknown as one written with text veil cannot see.
const MAX_FILES: usize = 256;

/// What a command string writes, by file.
#[derive(Default)]
pub(super) struct Written {
    files: HashMap<String, Vec<Body>>,
    /// A command wrote to a path veil cannot resolve (`> "$OUT"`): any file is
    /// one it may have written.
    computed_target: bool,
    /// More files than [`MAX_FILES`].
    overflow: bool,
}

enum Body {
    Text(String),
    Unknown,
}

/// What the string writes to one file.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Writes {
    /// Nothing the string writes is the file: it is read as it is on disk.
    Untouched,
    /// The text written, one write after another.
    Text(String),
    /// Something is written that veil cannot see.
    Computed,
}

impl Written {
    /// Adds the writes of `commands`, run in `cwd` unless they say otherwise.
    pub(super) fn collect(&mut self, commands: &[SimpleCommand], cwd: &Path) {
        for command in commands {
            // a redirection may come first: `>x.sh printf 'cat .env'`
            let line = split(&command.argv);
            let cwd = command.cwd.as_deref().unwrap_or(cwd);
            let Some((program, args)) = line.words.split_first() else {
                // a redirection with no command: the end of a `{ }` or `( )`
                // group, or `exec > file`. What reaches the file is written
                // elsewhere in the string.
                for output in &line.outputs {
                    self.record(output.target, cwd, command, None);
                }
                continue;
            };
            if line.outputs.is_empty() && !is_tee(program) {
                continue;
            }

            let text = stdout_text(program, args, command, &line);

            for output in &line.outputs {
                let body = if output.stdout { text.clone() } else { None };
                self.record(output.target, cwd, command, body);
            }
            if is_tee(program) {
                let from_stdin = stdin_text(command, &line);
                for target in args.iter().filter(|word| !is_option(word)) {
                    self.record(target, cwd, command, from_stdin.clone());
                }
            }
        }
    }

    fn record(&mut self, target: &str, cwd: &Path, command: &SimpleCommand, text: Option<String>) {
        // a terminal, a descriptor and the bit bucket are not a file to run
        if target.starts_with("/dev/") {
            return;
        }
        if !usable(target) || command.cwd_unresolved {
            self.computed_target = true;
            return;
        }

        let key = key(&locate(target, cwd));
        if !self.files.contains_key(&key) && self.files.len() >= MAX_FILES {
            self.overflow = true;
            return;
        }
        self.files
            .entry(key)
            .or_default()
            .push(text.map_or(Body::Unknown, Body::Text));
    }

    /// What the string writes to `path`. `on_disk` is whether a file is there
    /// now: a file veil sees is not one a path built at run time may be writing.
    pub(super) fn find(&self, path: &Path, on_disk: bool) -> Writes {
        if self.overflow {
            return Writes::Computed;
        }

        match self.files.get(&key(path)) {
            Some(bodies) => {
                let mut text = String::new();
                for body in bodies {
                    match body {
                        Body::Text(piece) => {
                            text.push_str(piece);
                            if !piece.ends_with('\n') {
                                text.push('\n');
                            }
                        }
                        Body::Unknown => return Writes::Computed,
                    }
                }
                Writes::Text(text)
            }
            None if self.computed_target && !on_disk => Writes::Computed,
            None => Writes::Untouched,
        }
    }

    /// The first line of the first text written to `path`: a file run by name is
    /// run under the interpreter that line names.
    pub(super) fn first_line(&self, path: &Path) -> Option<String> {
        match self.files.get(&key(path))?.first()? {
            Body::Text(text) => text.lines().next().map(str::to_owned),
            Body::Unknown => None,
        }
    }
}

/// How a path is compared with the paths written: spelled out, its directory
/// followed when it is there, and not by case, since a volume may not tell
/// `Run.sh` from `run.sh`.
fn key(path: &Path) -> String {
    let text = path.to_string_lossy();
    let normal = lexical_path(&text, Path::new("/")).unwrap_or_else(|| path.to_path_buf());
    let resolved = match (normal.parent(), normal.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|parent| parent.join(name))
            .unwrap_or_else(|_| normal.clone()),
        _ => normal,
    };

    resolved.to_string_lossy().to_lowercase()
}

fn is_tee(program: &str) -> bool {
    command_name(program) == "tee"
}

fn is_option(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-')
}

// ---- the words of a command ---------------------------------------------------

/// A command's words, its program the first, with its redirections taken out.
struct Line<'a> {
    words: Vec<&'a str>,
    outputs: Vec<Output<'a>>,
    /// The text after `<<<`.
    here_string: Option<&'a str>,
    /// Standard input is a file.
    reads_file: bool,
}

struct Output<'a> {
    target: &'a str,
    /// What the command writes to standard output, not to another descriptor.
    stdout: bool,
}

fn split(argv: &[String]) -> Line<'_> {
    let mut line = Line {
        words: Vec::new(),
        outputs: Vec::new(),
        here_string: None,
        reads_file: false,
    };
    let mut words = argv.iter().map(String::as_str);

    while let Some(word) = words.next() {
        if let Some(text) = word.strip_prefix("<<<") {
            line.here_string = Some(if text.is_empty() {
                words.next().unwrap_or_default()
            } else {
                text
            });
            continue;
        }
        if word.starts_with("<<") {
            continue;
        }

        let digits = word.trim_start_matches(|ch: char| ch.is_ascii_digit());
        if let Some(rest) = digits.strip_prefix('<') {
            // `<file`, `0< file`, `<&3`, `<>file`: not a here-document, not a script
            if rest.is_empty() {
                words.next();
            }
            if !rest.starts_with('&') {
                line.reads_file = true;
            }
            continue;
        }

        let (descriptor, operator) = match word.strip_prefix('&') {
            Some(rest) => ("&", rest),
            None => word.split_at(word.len() - digits.len()),
        };
        let Some(after) = operator.strip_prefix('>') else {
            line.words.push(word);
            continue;
        };
        let stdout = matches!(descriptor, "" | "1" | "&");

        // `>>`, `>|` and `&>>`; `>&` copies a descriptor unless a file follows
        let (after, copies) = match after.strip_prefix('&') {
            Some(rest) => (rest, true),
            None => (after.strip_prefix(['>', '|']).unwrap_or(after), false),
        };
        let target = if after.is_empty() {
            words.next().unwrap_or_default()
        } else {
            after
        };
        let descriptor_copy = target == "-" || target.chars().all(|ch| ch.is_ascii_digit());
        if target.is_empty() || (copies && descriptor_copy) {
            continue;
        }

        line.outputs.push(Output {
            target,
            // `>&file` sends both streams to the file
            stdout: stdout || copies,
        });
    }
    line
}

// ---- the text a command writes ------------------------------------------------

/// What a command writes to standard output, when its text is all there in the
/// words: `echo`, `printf`, and `cat` or `tee` of a here-document.
fn stdout_text(
    program: &str,
    args: &[&str],
    command: &SimpleCommand,
    line: &Line<'_>,
) -> Option<String> {
    if !command.unresolved.is_empty() {
        return None;
    }

    match command_name(program) {
        "echo" => Some(echo_text(args)),
        "printf" => printf_text(args),
        "tee" => stdin_text(command, line),
        "cat" if args.iter().all(|word| *word == "-") => stdin_text(command, line),
        _ => None,
    }
}

/// What a command reads from standard input, when it is a here-document or a
/// here-string with nothing in it the shell computes.
fn stdin_text(command: &SimpleCommand, line: &Line<'_>) -> Option<String> {
    if command.stdin_piped
        || line.reads_file
        || command.heredoc_computed
        || !command.unresolved.is_empty()
    {
        return None;
    }

    let mut text = command.heredoc_body.clone();
    if let Some(string) = line.here_string {
        let text = text.get_or_insert_with(String::new);
        text.push_str(string);
        text.push('\n');
    }
    text
}

/// `echo`'s text. `-e` and `-E` say whether a backslash is an escape. Without
/// either it depends on the shell, so a text with a backslash is given both ways.
fn echo_text(words: &[&str]) -> String {
    let mut newline = true;
    let mut escapes: Option<bool> = None;
    let mut index = 0;
    while let Some(flags) = words.get(index).and_then(|word| word.strip_prefix('-')) {
        if flags.is_empty() || !flags.chars().all(|ch| matches!(ch, 'n' | 'e' | 'E')) {
            break;
        }
        for flag in flags.chars() {
            match flag {
                'n' => newline = false,
                'e' => escapes = Some(true),
                _ => escapes = Some(false),
            }
        }
        index += 1;
    }

    let raw = words[index..].join(" ");
    let text = match escapes {
        Some(true) => escaped(&raw, true).0,
        Some(false) => raw,
        None if raw.contains('\\') => format!("{raw}\n{}", escaped(&raw, true).0),
        None => raw,
    };
    let mut text = text;
    if newline {
        text.push('\n');
    }
    text
}

/// `printf`'s text: the format, reused until the arguments are used up. `None`
/// for a conversion this does not follow.
fn printf_text(words: &[&str]) -> Option<String> {
    let words = match words.first() {
        Some(&"--") => &words[1..],
        _ => words,
    };
    let (format, arguments) = words.split_first()?;
    if format.starts_with('-') && *format != "-" {
        return None;
    }

    let format: Vec<char> = format.chars().collect();
    let mut out = String::new();
    let mut next = 0;

    loop {
        let started = next;
        let mut index = 0;

        while index < format.len() {
            match format[index] {
                '\\' => {
                    let (text, used, stop) = escape(&format, index, false);
                    out.push_str(&text);
                    index += used;
                    if stop {
                        return Some(out);
                    }
                }
                '%' => {
                    let (text, used) = conversion(&format[index..], arguments, &mut next)?;
                    out.push_str(&text);
                    index += used;
                }
                other => {
                    out.push(other);
                    index += 1;
                }
            }
        }
        if next == started || next >= arguments.len() {
            return Some(out);
        }
    }
}

/// One `%` conversion at the start of `spec`, and how many characters it is.
fn conversion(spec: &[char], arguments: &[&str], next: &mut usize) -> Option<(String, usize)> {
    let mut index = 1;
    if spec.get(index) == Some(&'%') {
        return Some(("%".to_owned(), 2));
    }

    while matches!(spec.get(index), Some('-' | '+' | ' ' | '#' | '0' | '\'')) {
        index += 1;
    }
    while spec.get(index).is_some_and(char::is_ascii_digit) {
        index += 1;
    }
    if spec.get(index) == Some(&'.') {
        index += 1;
        while spec.get(index).is_some_and(char::is_ascii_digit) {
            index += 1;
        }
    }
    while matches!(
        spec.get(index),
        Some('h' | 'l' | 'L' | 'q' | 'j' | 'z' | 't')
    ) {
        index += 1;
    }

    let conversion = *spec.get(index)?;
    let argument = arguments.get(*next).copied();
    *next += 1;
    let argument = argument.unwrap_or_default();

    let text = match conversion {
        's' => argument.to_owned(),
        'b' => escaped(argument, true).0,
        'c' => argument
            .chars()
            .next()
            .map(String::from)
            .unwrap_or_default(),
        'd' | 'i' | 'u' => number(argument)?.to_string(),
        'x' => format!("{:x}", number(argument)?),
        'X' => format!("{:X}", number(argument)?),
        'o' => format!("{:o}", number(argument)?),
        // `%q` quotes, a width of `*` reads an argument, a float or a date format:
        // text veil does not work out
        _ => return None,
    };
    Some((text, index + 1))
}

fn number(argument: &str) -> Option<i64> {
    if argument.is_empty() {
        return Some(0);
    }
    argument.parse().ok()
}

/// `text` with its backslash escapes taken as `printf` takes them, and whether
/// `\c` ended it.
fn escaped(text: &str, in_argument: bool) -> (String, bool) {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] == '\\' {
            let (piece, used, stop) = escape(&chars, index, in_argument);
            out.push_str(&piece);
            index += used;
            if stop {
                return (out, true);
            }
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    (out, false)
}

/// The backslash escape at `chars[at]`: the text it stands for, how many
/// characters it is, and whether it ends the output (`\c`). A character it does
/// not know stays as written. `\0NNN` is octal in an argument of `%b`, `\NNN` in
/// a format.
fn escape(chars: &[char], at: usize, in_argument: bool) -> (String, usize, bool) {
    let Some(&letter) = chars.get(at + 1) else {
        return ("\\".to_owned(), 1, false);
    };
    let simple = |text: &str| (text.to_owned(), 2, false);

    match letter {
        '\\' => simple("\\"),
        'a' => simple("\u{7}"),
        'b' => simple("\u{8}"),
        'e' | 'E' => simple("\u{1b}"),
        'f' => simple("\u{c}"),
        'n' => simple("\n"),
        'r' => simple("\r"),
        't' => simple("\t"),
        'v' => simple("\u{b}"),
        '\'' => simple("'"),
        '"' => simple("\""),
        '?' => simple("?"),
        'c' => (String::new(), 2, true),
        'x' => numeric(chars, at + 2, 16, 2, 2),
        'u' => numeric(chars, at + 2, 16, 4, 2),
        'U' => numeric(chars, at + 2, 16, 8, 2),
        '0'..='7' => {
            // `%b` takes `\0NNN` and `\NNN`; a format takes `\NNN`
            let (from, digits) = if letter == '0' && in_argument {
                (at + 2, 3)
            } else {
                (at + 1, 3)
            };
            numeric(chars, from, 8, digits, from - at)
        }
        _ => ("\\".to_owned(), 1, false),
    }
}

/// Up to `digits` digits of `radix` from `chars[from]`, as the character they
/// name; `prefix` characters of the escape come before them.
fn numeric(
    chars: &[char],
    from: usize,
    radix: u32,
    digits: usize,
    prefix: usize,
) -> (String, usize, bool) {
    let mut value: u32 = 0;
    let mut count = 0;

    while count < digits {
        let Some(digit) = chars.get(from + count).and_then(|ch| ch.to_digit(radix)) else {
            break;
        };
        value = value.saturating_mul(radix).saturating_add(digit);
        count += 1;
    }
    if count == 0 {
        return ("\\".to_owned(), 1, false);
    }

    let character = char::from_u32(value).unwrap_or('\u{fffd}');
    (character.to_string(), prefix + count, false)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::extract::{ShellEnv, decompose_in};

    fn written(command: &str) -> Written {
        let env = ShellEnv {
            cwd: Some(PathBuf::from("/work")),
            home: None,
        };
        let mut written = Written::default();
        written.collect(&decompose_in(command, &env), Path::new("/work"));
        written
    }

    fn text(command: &str, file: &str) -> Writes {
        written(command).find(&Path::new("/work").join(file), false)
    }

    fn lines(command: &str, file: &str) -> Vec<String> {
        match text(command, file) {
            Writes::Text(text) => text.lines().map(str::to_owned).collect(),
            other => panic!("{command}: {other:?}"),
        }
    }

    #[test]
    fn echo_text_is_the_words_and_a_newline() {
        assert_eq!(lines("echo r .env > x", "x"), ["r .env"]);
        assert_eq!(lines("echo 'r .env' > x", "x"), ["r .env"]);
        assert_eq!(lines("echo -n 'r .env' > x", "x"), ["r .env"]);
        assert_eq!(lines("echo -ne 'r .env' > x", "x"), ["r .env"]);
        // a flag that is not one is text
        assert_eq!(lines("echo -x hi > x", "x"), ["-x hi"]);
    }

    #[test]
    fn a_backslash_in_echo_text_is_read_both_ways() {
        let text = lines("echo 'p\\nr .env' > x", "x");

        assert!(text.contains(&"r .env".to_owned()), "{text:?}");
        assert!(text.contains(&"p\\nr .env".to_owned()), "{text:?}");
    }

    #[test]
    fn printf_text_is_the_format_filled_in_and_reused() {
        assert_eq!(lines("printf 'r .env\\n' > x", "x"), ["r .env"]);
        assert_eq!(lines("printf 'r %s\\n' .env > x", "x"), ["r .env"]);
        assert_eq!(lines("printf '%s\\n' p 'r .env' > x", "x"), ["p", "r .env"]);
        assert_eq!(
            lines("printf '%b' 'p\\nr .env\\n' > x", "x"),
            ["p", "r .env"]
        );
        assert_eq!(lines("printf '%5s|%-3s|\\n' a b > x", "x"), ["a|b|"]);
        assert_eq!(lines("printf '100%%\\n' > x", "x"), ["100%"]);
        assert_eq!(lines("printf '%d-%x\\n' 12 255 > x", "x"), ["12-ff"]);
        assert_eq!(lines("printf 'a\\tb\\x41\\101\\n' > x", "x"), ["a\tbAA"]);
        // no argument for a conversion is empty text
        assert_eq!(lines("printf 'a%sb\\n' > x", "x"), ["ab"]);
        // arguments with nothing to fill are not printed
        assert_eq!(lines("printf 'hi\\n' extra > x", "x"), ["hi"]);
    }

    #[test]
    fn printf_stops_at_backslash_c() {
        assert_eq!(
            text("printf 'a\\cb' > x", "x"),
            Writes::Text("a\n".to_owned())
        );
    }

    #[test]
    fn a_printf_this_does_not_follow_is_computed() {
        assert_eq!(text("printf '%q' 'r .env' > x", "x"), Writes::Computed);
        assert_eq!(text("printf '%*d' 3 4 > x", "x"), Writes::Computed);
        assert_eq!(text("printf '%f' 1 > x", "x"), Writes::Computed);
        assert_eq!(text("printf -v var x > x", "x"), Writes::Computed);
    }

    #[test]
    fn here_documents_and_here_strings_are_the_text() {
        assert_eq!(lines("cat > x <<'EOF'\nr .env\nEOF", "x"), ["r .env"]);
        assert_eq!(lines("cat <<'EOF' > x\nr .env\nEOF", "x"), ["r .env"]);
        assert_eq!(lines("cat > x <<< 'r .env'", "x"), ["r .env"]);
        assert_eq!(lines("cat > x <<<'r .env'", "x"), ["r .env"]);
        assert_eq!(
            lines("tee x <<'EOF' >/dev/null\nr .env\nEOF", "x"),
            ["r .env"]
        );
        assert_eq!(lines("tee -a x <<< 'r .env' > /dev/null", "x"), ["r .env"]);
        assert_eq!(lines("cat - > x <<< 'r .env'", "x"), ["r .env"]);
    }

    #[test]
    fn a_here_document_the_shell_expands_is_computed() {
        assert_eq!(
            text("cat > x <<EOF\necho $HOME\nEOF", "x"),
            Writes::Computed
        );
        assert_eq!(
            text("cat > x <<EOF\necho `date`\nEOF", "x"),
            Writes::Computed
        );
        assert_eq!(
            text("cat > x <<EOF\necho \\$HOME\nEOF", "x"),
            Writes::Computed
        );
        // one with nothing to expand is the text; so is a quoted one with a `$`
        assert_eq!(lines("cat > x <<EOF\necho hi\nEOF", "x"), ["echo hi"]);
        assert_eq!(
            lines("cat > x <<'EOF'\necho $HOME\nEOF", "x"),
            ["echo $HOME"]
        );
    }

    #[test]
    fn text_the_string_does_not_spell_out_is_computed() {
        for command in [
            "echo \"$BODY\" > x",
            "echo $(date) > x",
            "printf '%s' \"$BODY\" > x",
            "date > x",
            "cat notes.md > x",
            "cat notes.md | tee x",
            "echo hi | tee x",
            "cat x2 > x",
            "cat < notes.md > x",
            "cat > x <<< \"$BODY\"",
            "python3 gen.py > x",
        ] {
            assert_eq!(text(command, "x"), Writes::Computed, "{command}");
        }
    }

    #[test]
    fn redirections_that_write_no_file_are_not_writes() {
        for command in [
            "echo hi",
            "echo hi > /dev/null",
            "echo hi 2>&1",
            "echo hi >&2",
            "echo hi 1>&2",
            "cat x 2>/dev/null",
            "cat < x",
            "sort <in >/dev/stdout",
        ] {
            assert_eq!(text(command, "x"), Writes::Untouched, "{command}");
        }
    }

    #[test]
    fn a_stream_that_is_not_standard_output_carries_no_text() {
        // standard error is empty, and the file is made
        assert_eq!(text("echo hi 2> x", "x"), Writes::Computed);
        assert_eq!(text("echo hi 2>x", "x"), Writes::Computed);
        // both streams
        assert_eq!(lines("echo hi &> x", "x"), ["hi"]);
        assert_eq!(lines("echo hi >& x", "x"), ["hi"]);
        assert_eq!(lines("echo hi 1> x", "x"), ["hi"]);
        assert_eq!(lines("echo hi >| x", "x"), ["hi"]);
        assert_eq!(lines("echo hi >> x", "x"), ["hi"]);
    }

    #[test]
    fn every_write_to_a_file_is_kept() {
        assert_eq!(
            lines("echo a > x; echo b >> x; echo c > x", "x"),
            ["a", "b", "c"]
        );
        assert_eq!(text("echo a > x; date >> x", "x"), Writes::Computed);
    }

    #[test]
    fn a_path_is_the_same_path_however_it_is_spelled() {
        let written = written("echo hi > ./sub/../x; echo there > /work/Y");

        for name in ["x", "./x", "sub/../x", "/work/x", "X"] {
            assert_eq!(
                written.find(&Path::new("/work").join(name), false),
                Writes::Text("hi\n".to_owned()),
                "{name}"
            );
        }
        assert_eq!(
            written.find(Path::new("/work/y"), false),
            Writes::Text("there\n".to_owned())
        );
        assert_eq!(written.find(Path::new("/work/z"), false), Writes::Untouched);
        assert_eq!(
            written.find(Path::new("/other/x"), false),
            Writes::Untouched
        );
    }

    #[test]
    fn a_working_directory_the_string_changes_is_followed() {
        let work = std::env::temp_dir().join(format!("veil-written-cwd-{}", std::process::id()));
        std::fs::create_dir_all(work.join("sub")).expect("directory");
        let work = std::fs::canonicalize(&work).expect("canonical directory");
        let env = ShellEnv {
            cwd: Some(work.clone()),
            home: None,
        };
        let mut written = Written::default();
        written.collect(&decompose_in("cd sub && echo hi > x", &env), &work);

        assert_eq!(
            written.find(&work.join("sub/x"), false),
            Writes::Text("hi\n".to_owned())
        );
        assert_eq!(written.find(&work.join("x"), false), Writes::Untouched);
    }

    #[test]
    fn a_path_built_at_run_time_may_be_any_file_that_is_not_there() {
        let written = written("echo hi > \"$OUT\"");

        assert_eq!(
            written.find(Path::new("/work/gone.py"), false),
            Writes::Computed
        );
        assert_eq!(
            written.find(Path::new("/work/here.py"), true),
            Writes::Untouched
        );
    }

    #[test]
    fn past_the_files_followed_every_script_is_unknown() {
        let command = SimpleCommand::opaque();
        let mut written = Written::default();

        for index in 0..MAX_FILES {
            written.record(
                &format!("f{index}"),
                Path::new("/work"),
                &command,
                Some("hi".to_owned()),
            );
        }
        assert_eq!(
            written.find(Path::new("/work/f0"), true),
            Writes::Text("hi\n".to_owned())
        );
        assert_eq!(
            written.find(Path::new("/work/other"), true),
            Writes::Untouched
        );

        // one file more than are followed
        written.record(
            "one-more",
            Path::new("/work"),
            &command,
            Some("hi".to_owned()),
        );
        assert_eq!(written.find(Path::new("/work/f0"), true), Writes::Computed);
        assert_eq!(
            written.find(Path::new("/work/other"), true),
            Writes::Computed
        );
    }

    #[test]
    fn the_first_line_is_the_first_write() {
        let written = written("printf '#!/bin/sh\\necho hi\\n' > x; echo more >> x");

        assert_eq!(
            written.first_line(Path::new("/work/x")).as_deref(),
            Some("#!/bin/sh")
        );
        assert_eq!(written.first_line(Path::new("/work/y")), None);
    }
}
