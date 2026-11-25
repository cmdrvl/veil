//! bd-2kr: turn a Bash tool command string into the simple commands that would
//! actually run, so each one can be checked on its own.
//!
//! `sh -c "cat data/x.csv"`, `find data -exec cat {} \;`, `echo $(cat data/x.csv)`
//! and `ls data | xargs -I{} cat data/{}` all hide a reader behind something the
//! extractor used to treat as the whole command. This module splits on `;`, `&`,
//! `&&`, `||`, `|` and newlines, descends into `$( )`, backticks and `<( )`,
//! unwraps `sh -c` and the wrapper programs in [`super::wrappers`], and hands
//! back one [`SimpleCommand`] per command that would run.
//!
//! It reads the text only. It follows the variables the command string sets
//! itself, `$HOME`, `$PWD`, `~` and brace lists (see [`super::expand`]), and
//! nothing else: not globs (a glob is judged by the directory it starts in),
//! aliases or functions. A word that still depends on something it could not
//! resolve is listed in [`SimpleCommand::unresolved`] as it was written, and
//! what to do about that is the dynamic-argument stance (bd-2mi, in `lib.rs`).
//!
//! Text it cannot analyse (unbalanced quotes, more than [`MAX_DEPTH`] levels of
//! nesting, more than [`MAX_SEGMENTS`] segments) comes back as an *opaque*
//! command: empty `argv`. The caps mean padding a command with 64 `true;`
//! cannot hide a reader after them from the first 64 segments, but it does hide
//! one past them, which is why the stance treats an opaque command as unknown.

use super::expand::{self, Vars, Word};
use super::wrappers;
use super::{collect_input_redirect_paths, is_env_assignment};

pub use super::expand::ShellEnv;

/// Levels of nesting (substitutions, `-c` strings, wrappers) followed before the
/// rest is reported as opaque.
pub const MAX_DEPTH: usize = 8;
/// Segments analysed in one command string, counted across every level.
pub const MAX_SEGMENTS: usize = 64;

/// What an `xargs` command has in [`SimpleCommand::unresolved`]: the arguments
/// it reads from standard input, which no text shows.
pub const STDIN_ARGUMENTS: &str = "<arguments read from standard input>";

/// Stands in for a `$( )`, backtick or `<( )` body in a segment's text, so the
/// words around it split as the shell would split them. It is a control
/// character, which path normalization already discards.
pub const SUBSTITUTION: char = '\u{1}';

/// Stands in for a `<( )` or `>( )` body. Unlike [`SUBSTITUTION`] it is not
/// listed in [`SimpleCommand::unresolved`]: the word is a pipe, not a path.
pub(super) const PROCESS_SUBSTITUTION: char = '\u{2}';

/// Words that start a compound-command line but are not the command. A
/// `matches!` rather than a slice: it is asked of the first word of every command.
fn is_leading_keyword(word: &str) -> bool {
    matches!(
        word,
        "!" | "{"
            | "}"
            | "if"
            | "then"
            | "elif"
            | "else"
            | "fi"
            | "while"
            | "until"
            | "do"
            | "done"
            | "coproc"
    )
}

/// Words that make the whole segment a loop or case header, with no command.
fn is_header_keyword(word: &str) -> bool {
    matches!(word, "for" | "select" | "case" | "esac" | "in" | "function")
}

/// How a simple command was reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Written directly in the command string.
    Top,
    /// Inside `$( )`, backticks or `<( )`.
    Subshell,
    /// Run by something else: `sh -c`, `eval`, `env`, `xargs`, `find -exec`, `uv run`...
    Wrapper,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Top => "top",
            Self::Subshell => "subshell",
            Self::Wrapper => "wrapper",
        }
    }
}

/// One command that would run: its words, with leading assignments, keywords
/// and wrapper programs already removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleCommand {
    /// The program and its arguments. Redirections stay in it, as written.
    pub argv: Vec<String>,
    /// Files this command reads through `<`.
    pub redirects_in: Vec<String>,
    /// Words that depend on something this module could not resolve: a variable
    /// it was not told the value of, a substitution, a brace list too long to
    /// expand, or ([`STDIN_ARGUMENTS`]) what `xargs` reads from standard input.
    /// Each is as it was written. Globs are not listed: a glob can only match
    /// beneath the directory it starts in, which the path rules already judge.
    /// The consumer is the dynamic-argument stance (bd-2mi).
    pub unresolved: Vec<String>,
    /// Every value the command string assigns to a variable (`d=data/clients`),
    /// wherever in the string it is assigned. A protected directory named there
    /// puts the whole string in a protected context.
    pub assigned: Vec<String>,
    pub origin: Origin,
    /// Standard input comes from an earlier command in a pipeline.
    pub stdin_piped: bool,
    /// The here-document attached to this command, when it has one.
    pub heredoc_body: Option<String>,
}

impl SimpleCommand {
    /// Text that could not be analysed, or part of it past a cap.
    pub fn opaque() -> Self {
        Self {
            argv: Vec::new(),
            redirects_in: Vec::new(),
            unresolved: Vec::new(),
            assigned: Vec::new(),
            origin: Origin::Top,
            stdin_piped: false,
            heredoc_body: None,
        }
    }

    pub fn is_opaque(&self) -> bool {
        self.argv.is_empty()
    }

    /// Some word depends on something this module could not resolve, or the
    /// whole command could not be analysed.
    pub fn has_dynamic_args(&self) -> bool {
        !self.unresolved.is_empty() || self.is_opaque()
    }
}

/// Shared across one `decompose` call: the segment budget, why it stopped, and
/// what the command string has assigned so far.
#[derive(Default)]
pub(super) struct Run {
    segments: usize,
    pub(super) truncated: bool,
    pub(super) failed: bool,
    env: ShellEnv,
    vars: Vars,
    assigned: Vec<String>,
}

impl Run {
    fn take_segment(&mut self) -> bool {
        if self.segments >= MAX_SEGMENTS {
            self.truncated = true;
            return false;
        }
        self.segments += 1;
        true
    }
}

/// The simple commands in `command`, in the order they would run: a
/// substitution before the command that holds it, a wrapper's inner command in
/// place of the wrapper. Variables are followed from the text alone; see
/// [`decompose_in`] to resolve `$HOME` and `$PWD` too.
pub fn decompose(command: &str) -> Vec<SimpleCommand> {
    decompose_in(command, &ShellEnv::default())
}

/// [`decompose`] for a command that runs where `env` says: `$PWD` is its
/// working directory, `$HOME` and `~` its home.
pub fn decompose_in(command: &str, env: &ShellEnv) -> Vec<SimpleCommand> {
    let mut run = Run {
        env: env.clone(),
        vars: Vars::for_command(command),
        ..Run::default()
    };
    let mut commands = Vec::new();

    script(command, Origin::Top, 0, &mut run, &mut commands);

    if run.failed {
        return vec![SimpleCommand::opaque()];
    }
    if run.truncated {
        commands.push(SimpleCommand::opaque());
    }
    for simple in &mut commands {
        simple.assigned = run.assigned.clone();
    }
    commands
}

/// Decomposes one script (the whole command, a substitution body, a `-c`
/// string) into `out`. `origin` is how the script was reached.
pub(super) fn script(
    text: &str,
    origin: Origin,
    depth: usize,
    run: &mut Run,
    out: &mut Vec<SimpleCommand>,
) {
    if depth > MAX_DEPTH {
        run.truncated = true;
        return;
    }
    let Some(segments) = scan(text) else {
        run.failed = true;
        return;
    };

    for segment in segments {
        if !run.take_segment() {
            return;
        }
        for body in &segment.substitutions {
            script(body, Origin::Subshell, depth + 1, run, out);
        }
        let words = match expand::plain_words(&segment.text) {
            Some(words) => words,
            None => {
                let Some(raw) = expand::raw_words(&segment.text) else {
                    run.failed = true;
                    return;
                };

                // `f=data/x.csv` runs nothing; it tells the words that follow
                // what `$f` is. `export f=data/x.csv` also hands it to every
                // program after it, which veil does not read, so the statement
                // goes on to be judged as a command naming that path.
                if let Some(pairs) = expand::assignment_words(&raw) {
                    for (name, written) in pairs {
                        let value = run.vars.value(&written, &run.env);
                        if let Some(value) = &value {
                            run.assigned.push(value.clone());
                        }
                        run.vars.assign(&name, value);
                    }
                    if !expand::exports_to_environment(&raw) {
                        continue;
                    }
                }

                let Some(words) = run.vars.words(&raw, &run.env) else {
                    run.failed = true;
                    return;
                };
                words
            }
        };

        // `for f in a b c; do cat $f; done`: until `done`, `$f` is each of the
        // words in turn, and every one of them is judged.
        if let Some((name, values)) = for_header(&words) {
            run.vars.assign_loop(name, values);
            continue;
        }

        // `f=data/x.csv sh -c 'cat $f'`: the assignment is the environment of
        // what runs, so the script it runs sees it; the words of the command
        // itself were expanded without it.
        let prefix = prefix_assignments(&words);
        let Some(command) = simple_command(words, &segment, origin) else {
            continue;
        };
        run.assigned
            .extend(prefix.iter().map(|(_, value)| value.clone()));
        let saved = run.vars.scoped(&prefix);
        wrappers::expand(command, depth, run, out);
        run.vars.restore(saved);
    }
}

/// The loop variable and words of a `for name in words` header, the words as
/// `None` when any of them could not be resolved. `None` for any other command.
fn for_header(words: &[Word]) -> Option<(&str, Option<Vec<String>>)> {
    let start = words
        .iter()
        .position(|word| !is_leading_keyword(&word.text))?;
    let header = &words[start..];

    if header.first()?.text != "for" || header.get(2)?.text != "in" {
        return None;
    }
    let name = header[1].text.as_str();
    if !expand::is_name(name) {
        return None;
    }

    let list = &header[3..];
    let values = list
        .iter()
        .all(|word| word.unresolved.is_none())
        .then(|| list.iter().map(|word| word.text.clone()).collect());
    Some((name, values))
}

fn prefix_assignments(words: &[Word]) -> Vec<(String, String)> {
    words
        .iter()
        .take_while(|word| is_env_assignment(&word.text))
        .filter_map(|word| word.text.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn simple_command(
    mut words: Vec<Word>,
    segment: &Segment,
    origin: Origin,
) -> Option<SimpleCommand> {
    let start = words
        .iter()
        .position(|word| !(is_env_assignment(&word.text) || is_leading_keyword(&word.text)))?;
    if is_header_keyword(&words[start].text) {
        return None;
    }

    // the words move, text to argv and unresolved text to its own list: nothing
    // is copied, and a command with no leading assignment keeps its Vec
    let words = if start == 0 {
        words
    } else {
        words.split_off(start)
    };
    let mut argv = Vec::with_capacity(words.len());
    let mut unresolved = Vec::new();
    for word in words {
        argv.push(word.text);
        unresolved.extend(word.unresolved);
    }

    Some(SimpleCommand {
        unresolved,
        argv,
        redirects_in: Vec::new(),
        assigned: Vec::new(),
        origin,
        stdin_piped: segment.stdin_piped,
        heredoc_body: segment.heredoc.clone(),
    })
}

/// Fills in what depends on the final argv, then adds the command to `out`.
pub(super) fn emit(mut command: SimpleCommand, out: &mut Vec<SimpleCommand>) {
    command.redirects_in = command
        .argv
        .get(1..)
        .map(collect_input_redirect_paths)
        .unwrap_or_default();
    out.push(command);
}

/// The text between two separators, with what the scanner learned about it.
#[derive(Default)]
struct Segment {
    /// Shell text for the word splitter: quotes kept, substitutions replaced by
    /// [`SUBSTITUTION`], here-document operators removed.
    text: String,
    stdin_piped: bool,
    heredoc: Option<String>,
    /// Bodies of `$( )`, backticks and `<( )` found in `text`, and in an
    /// expanding here-document body.
    substitutions: Vec<String>,
}

impl Segment {
    fn is_blank(&self) -> bool {
        // Nearly every segment starts with a visible ASCII byte: say so before
        // asking `trim` about Unicode white space.
        let starts_visible = self
            .text
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_graphic());

        !starts_visible
            && self.text.trim().is_empty()
            && self.substitutions.is_empty()
            && self.heredoc.is_none()
    }
}

struct PendingHeredoc {
    delimiter: String,
    strip_tabs: bool,
    /// An unquoted delimiter makes the body expand `$( )` and backticks.
    expands: bool,
    /// Index in `segments` of the command the here-document belongs to.
    segment: usize,
}

/// Splits `text` at unquoted separators. `None` for text `shlex` would also
/// reject: an unterminated quote, substitution or backtick, or a trailing
/// backslash.
fn scan(text: &str) -> Option<Vec<Segment>> {
    let bytes = text.as_bytes();

    // Text with nothing the scanner acts on (`echo c`, `cat data/x.csv`) is one
    // segment, unchanged: the state machine below would copy it byte for byte.
    if !bytes.iter().any(|&byte| SCAN_SPECIAL[byte as usize]) {
        let segment = Segment {
            text: text.to_owned(),
            ..Segment::default()
        };
        return Some(if segment.is_blank() {
            Vec::new()
        } else {
            vec![segment]
        });
    }

    let mut segments: Vec<Segment> = Vec::new();
    let mut current = Segment::default();
    let mut pending: Vec<PendingHeredoc> = Vec::new();
    let mut piped = false;
    let mut word_start = true;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let next = text[i + 1..].chars().next()?;
                if next == '\n' {
                    // A line continuation joins the lines and vanishes.
                    i += 2;
                    continue;
                }
                current.text.push('\\');
                current.text.push(next);
                i += 1 + next.len_utf8();
                word_start = false;
            }
            b'\'' => {
                let end = i + 1 + text[i + 1..].find('\'')?;
                current.text.push_str(&text[i..=end]);
                i = end + 1;
                word_start = false;
            }
            b'"' => {
                i = scan_double_quoted(text, i, &mut current)?;
                word_start = false;
            }
            b'`' => {
                let (body, end) = backtick_body(text, i)?;
                substitute(&mut current, body);
                i = end + 1;
                word_start = false;
            }
            b'$' if bytes.get(i + 1) == Some(&b'\'') => {
                // `$'...'` ends at the first quote a backslash does not escape.
                let end = expand::ansi_c_end(text, i + 1)?;
                current.text.push_str(&text[i..=end]);
                i = end + 1;
                word_start = false;
            }
            b'$' => {
                if bytes.get(i + 1) == Some(&b'(') {
                    let end = matching_paren(text, i + 2)?;
                    substitute(&mut current, text[i + 2..end].to_owned());
                    i = end + 1;
                } else {
                    // `$name` is expanded later, with the variables known by then.
                    current.text.push('$');
                    i += 1;
                }
                word_start = false;
            }
            b'<' | b'>' if bytes.get(i + 1) == Some(&b'(') => {
                // The command is judged like any other; what the word stands
                // for is a pipe, never a file whose name could be protected.
                let end = matching_paren(text, i + 2)?;
                current.substitutions.push(text[i + 2..end].to_owned());
                current.text.push(PROCESS_SUBSTITUTION);
                i = end + 1;
                word_start = false;
            }
            b'<' if bytes[i..].starts_with(b"<<<") => {
                current.text.push_str("<<<");
                i += 3;
                word_start = true;
            }
            b'<' if bytes.get(i + 1) == Some(&b'<') => match heredoc_operator(text, i) {
                Some((heredoc, end)) => {
                    pending.push(PendingHeredoc {
                        segment: segments.len(),
                        ..heredoc
                    });
                    i = end;
                    word_start = true;
                }
                None => {
                    current.text.push_str("<<");
                    i += 2;
                    word_start = false;
                }
            },
            b'#' if word_start => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b';' | b'(' | b')' => {
                end_segment(&mut segments, &mut current, &mut piped, false);
                i += 1;
                word_start = true;
            }
            b'\n' => {
                end_segment(&mut segments, &mut current, &mut piped, false);
                i = read_heredoc_bodies(text, i + 1, &mut pending, &mut segments);
                word_start = true;
            }
            b'&' => {
                let after_redirect = i > 0 && matches!(bytes[i - 1], b'<' | b'>');
                let next = bytes.get(i + 1).copied();
                if after_redirect || next == Some(b'>') {
                    // `2>&1`, `<&3`, `&>file`: part of a redirection.
                    current.text.push('&');
                    i += 1;
                    word_start = false;
                } else {
                    end_segment(&mut segments, &mut current, &mut piped, false);
                    i += if next == Some(b'&') { 2 } else { 1 };
                    word_start = true;
                }
            }
            b'|' => {
                let after_redirect = i > 0 && bytes[i - 1] == b'>';
                let next = bytes.get(i + 1).copied();
                if after_redirect {
                    // `>|` forces an overwrite; it is not a pipe.
                    current.text.push('|');
                    i += 1;
                    word_start = false;
                } else if next == Some(b'|') {
                    end_segment(&mut segments, &mut current, &mut piped, false);
                    i += 2;
                    word_start = true;
                } else {
                    end_segment(&mut segments, &mut current, &mut piped, true);
                    i += if next == Some(b'&') { 2 } else { 1 };
                    word_start = true;
                }
            }
            b' ' | b'\t' => {
                current.text.push(bytes[i] as char);
                i += 1;
                word_start = true;
            }
            _ => {
                let ch = text[i..].chars().next()?;
                current.text.push(ch);
                i += ch.len_utf8();
                i += copy_plain_run(text, i, &mut current.text);
                word_start = false;
            }
        }
    }

    end_segment(&mut segments, &mut current, &mut piped, false);
    segments.retain(|segment| !segment.is_blank());
    Some(segments)
}

/// Copies the bytes from `from` up to the next byte the scanner treats
/// specially, and returns how many it copied. Non-ASCII bytes are never
/// special, so the copy always ends on a character boundary.
fn copy_plain_run(text: &str, from: usize, into: &mut String) -> usize {
    // a table and a plain loop: this runs for every run of every command
    let bytes = text.as_bytes();
    let mut end = from;
    while end < bytes.len() && !SCAN_STOPS[bytes[end] as usize] {
        end += 1;
    }
    into.push_str(&text[from..end]);
    end - from
}

/// Bytes that end a plain run in [`scan`]: each has an arm of its own, or (a
/// blank) is told apart because it starts a word.
static SCAN_STOPS: [bool; 256] = expand::byte_table(b"\\'\"`$<>;()&|\n \t#");

/// Bytes that make [`scan`] do more than copy: [`SCAN_STOPS`] without the blanks,
/// which it copies too.
static SCAN_SPECIAL: [bool; 256] = expand::byte_table(b"\\'\"`$<>;()&|\n#");

fn end_segment(
    segments: &mut Vec<Segment>,
    current: &mut Segment,
    piped: &mut bool,
    next_piped: bool,
) {
    let mut finished = std::mem::take(current);
    finished.stdin_piped = *piped;
    segments.push(finished);
    *piped = next_piped;
}

fn substitute(current: &mut Segment, body: String) {
    current.substitutions.push(body);
    current.text.push(SUBSTITUTION);
}

/// Scans a double-quoted string starting at the opening quote, copying it to
/// `current` with each substitution replaced. Returns the index after the
/// closing quote.
fn scan_double_quoted(text: &str, start: usize, current: &mut Segment) -> Option<usize> {
    let bytes = text.as_bytes();
    current.text.push('"');
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                current.text.push('"');
                return Some(i + 1);
            }
            b'\\' => {
                let next = text[i + 1..].chars().next()?;
                current.text.push('\\');
                current.text.push(next);
                i += 1 + next.len_utf8();
            }
            b'`' => {
                let (body, end) = backtick_body(text, i)?;
                substitute(current, body);
                i = end + 1;
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                let end = matching_paren(text, i + 2)?;
                substitute(current, text[i + 2..end].to_owned());
                i = end + 1;
            }
            b'$' => {
                current.text.push('$');
                i += 1;
            }
            _ => {
                // Everything else is literal until the next special byte.
                let mut end = i + 1;
                while end < bytes.len() && !DOUBLE_QUOTE_STOPS[bytes[end] as usize] {
                    end += 1;
                }
                current.text.push_str(&text[i..end]);
                i = end;
            }
        }
    }

    None
}

/// The body of the backtick pair opening at `start` and the index of the
/// closing backtick. Inside backticks `\\`, `` \` `` and `\$` lose their backslash.
fn backtick_body(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut body = String::new();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'`' => return Some((body, i)),
            b'\\' => {
                let next = text[i + 1..].chars().next()?;
                if !matches!(next, '`' | '\\' | '$') {
                    body.push('\\');
                }
                body.push(next);
                i += 1 + next.len_utf8();
            }
            _ => {
                // up to the next byte that ends the body or escapes; a byte of a
                // multi-byte character is neither, so the run ends on a boundary
                let mut end = i + 1;
                while end < bytes.len() && !BACKTICK_STOPS[bytes[end] as usize] {
                    end += 1;
                }
                body.push_str(&text[i..end]);
                i = end;
            }
        }
    }

    None
}

/// Bytes with an arm of their own inside a double-quoted string.
static DOUBLE_QUOTE_STOPS: [bool; 256] = expand::byte_table(b"\"\\`$");

/// Bytes with an arm of their own inside a backtick body.
static BACKTICK_STOPS: [bool; 256] = expand::byte_table(b"`\\");

/// The index of the `)` closing a substitution whose body starts at `from`.
/// Parentheses inside quotes, escapes and nested backticks do not count.
fn matching_paren(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 1usize;
    let mut i = from;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1 + text[i + 1..].chars().next()?.len_utf8();
                continue;
            }
            b'\'' => {
                i += 2 + text[i + 1..].find('\'')?;
                continue;
            }
            b'"' => {
                i = skip_double_quoted(text, i)?;
                continue;
            }
            b'`' => {
                i = backtick_body(text, i)?.1 + 1;
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }

    None
}

/// The index after the double-quoted string opening at `start`.
fn skip_double_quoted(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some(i + 1),
            b'\\' => i += 1 + text[i + 1..].chars().next()?.len_utf8(),
            b'`' => i = backtick_body(text, i)?.1 + 1,
            b'$' if bytes.get(i + 1) == Some(&b'(') => i = matching_paren(text, i + 2)? + 1,
            _ => i += 1,
        }
    }

    None
}

/// Parses `<<DELIM`, `<<-DELIM`, `<<'DELIM'`, `<<"DELIM"` or `<<\DELIM` at
/// `start`. `None` when no delimiter follows (`1<<2` in arithmetic).
fn heredoc_operator(text: &str, start: usize) -> Option<(PendingHeredoc, usize)> {
    let bytes = text.as_bytes();
    let mut i = start + 2;
    let strip_tabs = bytes.get(i) == Some(&b'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }

    let mut delimiter = String::new();
    let mut quoted = false;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'\'' | b'"') => {
                let end = i + 1 + text[i + 1..].find(quote as char)?;
                delimiter.push_str(&text[i + 1..end]);
                quoted = true;
                i = end + 1;
            }
            b'\\' => {
                let next = text[i + 1..].chars().next()?;
                delimiter.push(next);
                quoted = true;
                i += 1 + next.len_utf8();
            }
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => break,
            _ => {
                let ch = text[i..].chars().next()?;
                delimiter.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    if delimiter.is_empty() {
        return None;
    }
    Some((
        PendingHeredoc {
            delimiter,
            strip_tabs,
            expands: !quoted,
            segment: 0,
        },
        i,
    ))
}

/// Reads the body of each pending here-document, starting at `from` (the line
/// after the one holding the operators), and attaches it to its command.
/// Returns where scanning resumes.
///
/// A body with no terminator line is attached but not consumed: the rest of the
/// text is also scanned as commands. Bash would treat it as input to the
/// command, but `((x<<2))` is not a here-document, and hiding every later line
/// behind a false one would be worse than checking a few input lines as commands.
fn read_heredoc_bodies(
    text: &str,
    from: usize,
    pending: &mut Vec<PendingHeredoc>,
    segments: &mut [Segment],
) -> usize {
    let mut position = from;

    for heredoc in std::mem::take(pending) {
        let Some(segment) = segments.get_mut(heredoc.segment) else {
            continue;
        };
        let (body, next) = match heredoc_body(text, position, &heredoc) {
            Some((body, next)) => (body, Some(next)),
            None => (text[position..].to_owned(), None),
        };

        if heredoc.expands {
            segment.substitutions.extend(expansions(&body));
        }
        match &mut segment.heredoc {
            Some(existing) => existing.push_str(&body),
            None => segment.heredoc = Some(body),
        }
        match next {
            Some(next) => position = next,
            None => break,
        }
    }

    position
}

/// The lines from `from` up to the terminator line, and the index after that line.
fn heredoc_body(text: &str, from: usize, heredoc: &PendingHeredoc) -> Option<(String, usize)> {
    let mut offset = from;

    for line in text[from..].split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let content = if heredoc.strip_tabs {
            content.trim_start_matches('\t')
        } else {
            content
        };
        if content == heredoc.delimiter {
            return Some((text[from..offset].to_owned(), offset + line.len()));
        }
        offset += line.len();
    }

    None
}

/// Substitution bodies in text that a shell expands like a here-document body:
/// `$( )` and backticks, with `\$` and `` \` `` escaping them.
fn expansions(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1 + body[i + 1..].chars().next().map_or(0, char::len_utf8);
            }
            b'`' => match backtick_body(body, i) {
                Some((inner, end)) => {
                    found.push(inner);
                    i = end + 1;
                }
                None => i += 1,
            },
            b'$' if bytes.get(i + 1) == Some(&b'(') => match matching_paren(body, i + 2) {
                Some(end) => {
                    found.push(body[i + 2..end].to_owned());
                    i = end + 1;
                }
                None => i += 1,
            },
            _ => i += 1,
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argvs(command: &str) -> Vec<Vec<String>> {
        decompose(command)
            .into_iter()
            .map(|simple| simple.argv)
            .collect()
    }

    fn words(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    fn assert_commands(command: &str, expected: &[&str]) {
        let expected: Vec<Vec<String>> = expected.iter().map(|text| words(text)).collect();
        assert_eq!(argvs(command), expected, "command: {command}");
    }

    #[test]
    fn splits_on_every_unquoted_separator() {
        assert_commands("a x; b y", &["a x", "b y"]);
        assert_commands("a x && b y || c z", &["a x", "b y", "c z"]);
        assert_commands("a x | b y |& c z", &["a x", "b y", "c z"]);
        assert_commands("a x\nb y\n\nc z", &["a x", "b y", "c z"]);
        assert_commands("a x & b y", &["a x", "b y"]);
        assert_commands("a x;b y&&c z", &["a x", "b y", "c z"]);
        assert_commands("(a x; b y)", &["a x", "b y"]);
    }

    #[test]
    fn quoted_and_escaped_separators_do_not_split() {
        assert_eq!(argvs(r#"echo "a;b" 'c|d' e\;f"#).len(), 1);
        assert_eq!(
            argvs(r#"echo "a;b" 'c|d' e\;f"#),
            vec![vec![
                "echo".to_owned(),
                "a;b".to_owned(),
                "c|d".to_owned(),
                "e;f".to_owned()
            ]]
        );
        assert_eq!(argvs("echo a\\\nb").len(), 1);
    }

    #[test]
    fn redirection_ampersands_and_clobber_pipes_do_not_split() {
        assert_eq!(argvs("cmd 2>&1").len(), 1);
        assert_eq!(argvs("cmd >&2").len(), 1);
        assert_eq!(argvs("cmd &>out.txt").len(), 1);
        assert_eq!(argvs("cmd >| out.txt").len(), 1);
        assert_eq!(argvs("cmd <&3").len(), 1);
    }

    #[test]
    fn marks_the_commands_that_read_a_pipe() {
        let commands = decompose("a | b && c | d; e");
        let piped: Vec<(&str, bool)> = commands
            .iter()
            .map(|command| (command.argv[0].as_str(), command.stdin_piped))
            .collect();

        assert_eq!(
            piped,
            [
                ("a", false),
                ("b", true),
                ("c", false),
                ("d", true),
                ("e", false)
            ]
        );
    }

    #[test]
    fn comments_end_at_the_newline_but_only_at_the_start_of_a_word() {
        assert_commands("a x # b y; c z\nd w", &["a x", "d w"]);
        assert_eq!(
            argvs("echo a#b"),
            vec![vec!["echo".to_owned(), "a#b".to_owned()]]
        );
    }

    #[test]
    fn leading_assignments_and_keywords_are_not_the_command() {
        assert_commands("FOO=1 BAR=2 cat x", &["cat x"]);
        assert_commands(
            "if test -f x; then cat y; else cat z; fi",
            &["test -f x", "cat y", "cat z"],
        );
        assert_commands("while read l; do cat $l; done", &["read l", "cat $l"]);
        assert_commands("{ cat x; }", &["cat x"]);
        assert_commands("! cat x", &["cat x"]);
        // the keywords are not commands; the loop variable is each word in turn
        assert_commands("for f in a b; do cat $f; done", &["cat a b"]);
        assert_commands("for f; do cat $f; done", &["cat $f"]);
        assert_commands("case $x in a) cat y;; esac", &["cat y"]);
        assert_commands("FOO=1", &[]);
    }

    #[test]
    fn substitutions_are_commands_of_their_own_and_run_first() {
        let commands = decompose("echo $(cat data/x.csv)");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].argv, words("cat data/x.csv"));
        assert_eq!(commands[0].origin, Origin::Subshell);
        assert_eq!(commands[1].argv[0], "echo");
        assert_eq!(commands[1].origin, Origin::Top);
        assert_eq!(commands[1].unresolved, vec![SUBSTITUTION.to_string()]);
        assert!(commands[1].has_dynamic_args());
        assert!(!commands[0].has_dynamic_args());
    }

    fn commands_named(command: &str, program: &str) -> Vec<SimpleCommand> {
        decompose(command)
            .into_iter()
            .filter(|simple| simple.argv.first().is_some_and(|word| word == program))
            .collect()
    }

    #[test]
    fn a_loop_over_known_words_judges_every_word() {
        // `cat $f` over two words reads both: the command carries both paths.
        for command in [
            "for f in a.csv b.csv; do cat $f; done",
            "for f in a.csv b.csv\ndo\n  cat \"$f\"\ndone",
            "for f in a.csv b.csv; do cat ${f}; done",
            "for f in a.csv b.csv; do (cat $f); done",
            "for f in {a,b}.csv; do cat $f; done",
        ] {
            let cats = commands_named(command, "cat");
            assert_eq!(cats.len(), 1, "{command}");
            assert_eq!(cats[0].argv, words("cat a.csv b.csv"), "{command}");
            assert!(cats[0].unresolved.is_empty(), "{command}");
        }

        let copies = commands_named("for f in a b; do cp $f $f.bak; done", "cp");
        assert_eq!(copies[0].argv, words("cp a b a.bak b.bak"));

        // two loops multiply: every pair is reached
        let cats = commands_named(
            "for a in x y; do for b in 1 2; do cat $a$b; done; done",
            "cat",
        );
        assert_eq!(cats[0].argv, words("cat x1 x2 y1 y2"));
        assert!(cats[0].unresolved.is_empty());

        // a glob in the list is left for the path rules, as it is everywhere
        let cats = commands_named("for f in data/*.csv; do cat $f; done", "cat");
        assert_eq!(cats[0].argv, words("cat data/*.csv"));
        assert!(cats[0].unresolved.is_empty());

        // an empty list runs nothing: the word is gone
        let cats = commands_named("for f in; do cat $f; done", "cat");
        assert_eq!(cats[0].argv, words("cat"));
    }

    #[test]
    fn a_loop_variable_veil_cannot_pin_down_stays_unresolved() {
        for command in [
            // the list is a command's output, or has an unset variable
            "for f in $(ls); do cat $f; done",
            "for f in `ls`; do cat $f; done",
            "for f in $LIST; do cat $f; done",
            "for f in a $LIST; do cat $f; done",
            // no list: the positional parameters
            "for f; do cat $f; done",
            // assigned elsewhere too
            "for f in a b; do f=c; cat $f; done",
            "f=x; for f in a b; do cat $f; done",
            "for f in a b; do for f in c d; do cat $f; done; done",
            // changed by something that reads it
            "for f in a b; do read f; cat $f; done",
            // more values than veil follows
            "for a in {1..10}; do for b in {1..10}; do cat $a$b; done; done",
            // an unquoted value with a blank is several words
            "for f in 'a b'; do cat $f; done",
            // not a plain name
            "for f.x in a b; do cat $f.x; done",
        ] {
            let cats = commands_named(command, "cat");
            assert!(!cats.is_empty(), "{command}");
            assert!(
                cats.iter().all(|cat| !cat.unresolved.is_empty()),
                "{command}: {cats:?}"
            );
        }

        // quoted, the value with a blank is one word and is known
        let cats = commands_named("for f in 'a b'; do cat \"$f\"; done", "cat");
        assert_eq!(cats[0].argv, vec!["cat".to_owned(), "a b".to_owned()]);
        assert!(cats[0].unresolved.is_empty());

        // a name assigned from a loop variable is not guessed at
        let cats = commands_named("for f in a b; do g=$f; cat $g; done", "cat");
        assert!(!cats[0].unresolved.is_empty(), "{cats:?}");
    }

    #[test]
    fn an_ansi_c_string_ends_at_the_quote_a_backslash_does_not_escape() {
        // The quote after the backslash is part of the string, so the `;`
        // after it separates two commands and the second one runs.
        assert_commands(
            "echo $'\\''; cat data/clients/x.csv; echo $'x'",
            &["echo '", "cat data/clients/x.csv", "echo x"],
        );
        // and a separator inside the string separates nothing
        assert_eq!(argvs("echo $'a;b|c' d").len(), 1);
        assert_eq!(
            argvs("echo $'a;b|c' d")[0],
            vec!["echo".to_owned(), "a;b|c".to_owned(), "d".to_owned()]
        );
        // unterminated: nothing can be said about the text
        assert_eq!(decompose("echo $'oops"), vec![SimpleCommand::opaque()]);
        assert_eq!(decompose("echo $'oops\\'"), vec![SimpleCommand::opaque()]);
    }

    #[test]
    fn a_process_substitution_word_is_a_pipe_and_not_an_unresolved_path() {
        for command in [
            "diff <(sort data/a.csv) <(sort data/b.csv)",
            "tee >(cat data/x.csv) > /dev/null",
        ] {
            let commands = decompose(command);
            assert!(
                commands.iter().any(|simple| simple
                    .argv
                    .first()
                    .is_some_and(|word| word == "sort" || word == "cat")),
                "the commands inside are still found: {command}"
            );
            assert!(
                commands.iter().all(|simple| simple.unresolved.is_empty()),
                "{command}: {commands:?}"
            );
        }

        // a command substitution beside one is still unresolved
        let commands = decompose("diff <(sort a) $(ls)");
        let diff = commands
            .iter()
            .find(|simple| simple.argv.first().is_some_and(|word| word == "diff"))
            .expect("diff is found");
        assert_eq!(diff.unresolved, vec![SUBSTITUTION.to_string()]);
    }

    #[test]
    fn every_substitution_form_is_found() {
        for command in [
            "echo $(cat data/x.csv)",
            "echo `cat data/x.csv`",
            "echo \"$(cat data/x.csv)\"",
            "echo \"a `cat data/x.csv` b\"",
            "echo $(echo $(cat data/x.csv))",
            "echo $(echo `cat data/x.csv`)",
            "diff <(cat data/x.csv) other",
            "tee >(cat data/x.csv)",
            "echo $(echo ')'; cat data/x.csv)",
            "echo $(echo \")\"; cat data/x.csv)",
            "x=$(cat data/x.csv)",
            "cat <<EOF\n$(cat data/x.csv)\nEOF",
            "cat <<EOF\n`cat data/x.csv`\nEOF",
        ] {
            assert!(
                argvs(command).contains(&words("cat data/x.csv")),
                "`cat data/x.csv` not found in {command}: {:?}",
                argvs(command)
            );
        }
    }

    #[test]
    fn single_quotes_and_escapes_keep_a_substitution_from_running() {
        for command in [
            "echo '$(cat data/x.csv)'",
            r"echo \$\(cat data/x.csv\)",
            r#"echo "\$(cat data/x.csv)""#,
            "echo '`cat data/x.csv`'",
            "cat <<'EOF'\n$(cat data/x.csv)\nEOF",
            "cat <<EOF\n\\$(cat data/x.csv)\nEOF",
        ] {
            assert!(
                !argvs(command).contains(&words("cat data/x.csv")),
                "{command} runs nothing: {:?}",
                argvs(command)
            );
        }
    }

    /// The unresolved words of the last command `command` runs.
    fn unresolved(command: &str) -> Vec<String> {
        decompose(command)
            .pop()
            .map(|c| c.unresolved)
            .unwrap_or_default()
    }

    #[test]
    fn words_veil_cannot_resolve_are_listed_as_written() {
        let marker = SUBSTITUTION.to_string();

        for (command, expected) in [
            ("cat $f", vec!["$f"]),
            ("cat ${f}", vec!["${f}"]),
            ("cat \"$f\"", vec!["\"$f\""]),
            ("cat data/$d/x.csv", vec!["data/$d/x.csv"]),
            ("cat $(echo x)", vec![marker.as_str()]),
            ("cat `echo x`", vec![marker.as_str()]),
            ("cat \"$(echo x)/y\"", vec!["\"\u{1}/y\""]),
            ("cat $1", vec!["$1"]),
            ("cat $@", vec!["$@"]),
            ("cat ${f:-x}", vec!["${f:-x}"]),
            // no home directory is known here
            ("cat ~/x", vec!["~/x"]),
            ("cat ~other/x", vec!["~other/x"]),
            ("cat $a $b ok", vec!["$a", "$b"]),
            ("$CMD data/x.csv", vec!["$CMD"]),
            ("cat {1..65}", vec!["{1..65}"]),
        ] {
            assert_eq!(unresolved(command), expected, "{command}");
        }
    }

    #[test]
    fn globs_braces_quoted_text_and_known_words_are_not_unresolved() {
        for command in [
            "cat data/x.csv",
            "cat data/*.csv",
            "cat data/?.csv",
            "cat data/[ab].csv",
            "cat 'data/*.csv'",
            "cat \"data/*.csv\"",
            "cat '$f'",
            "cat \"\\$f\"",
            "cat a~b",
            "cat 100$",
            "echo $ x",
            "cat /tmp/out.$$",
            "cat data/{a,b}.csv",
            "cat {data,docs}/x.csv",
            "cat {}",
        ] {
            assert_eq!(unresolved(command), Vec::<String>::new(), "{command}");
        }

        assert_eq!(
            decompose("cat data/{a,b}.csv")[0].argv,
            words("cat data/a.csv data/b.csv")
        );
        assert_eq!(
            decompose("cat {data,docs}/x.csv")[0].argv,
            words("cat data/x.csv docs/x.csv")
        );
        // `{}` is not a list, and a glob stays a glob for the directory rules
        assert_eq!(
            decompose("cat {} data/*.csv")[0].argv,
            words("cat {} data/*.csv")
        );
    }

    #[test]
    fn home_and_pwd_come_from_the_environment_the_command_runs_in() {
        let env = ShellEnv {
            cwd: Some("/work/repo".into()),
            home: Some("/home/me".to_owned()),
        };

        let commands = decompose_in("cat ~/a $HOME/b ${PWD}/c ~", &env);
        assert_eq!(
            commands[0].argv,
            words("cat /home/me/a /home/me/b /work/repo/c /home/me")
        );
        assert!(commands[0].unresolved.is_empty());

        // without an environment the same words are unresolved
        assert_eq!(
            unresolved("cat ~/a $HOME/b"),
            vec!["~/a".to_owned(), "$HOME/b".to_owned()]
        );
    }

    #[test]
    fn an_assigned_variable_is_substituted_in_the_words_that_follow() {
        for command in [
            "f=data/x.csv; cat $f",
            "f=data/x.csv\ncat $f",
            "f=data/x.csv && cat $f",
            "export f=data/x.csv; cat \"$f\"",
            "export f=data/x.csv; cat ${f}",
            "declare -x f=data/x.csv; cat $f",
            "local f=data/x.csv; cat $f",
            "readonly f=data/x.csv; cat $f",
            "f='data/x.csv'; cat $f",
            "f=\"data/x.csv\"; cat $f",
            "(f=data/x.csv; cat $f)",
            "echo hi; f=data/x.csv; echo hi; cat $f",
        ] {
            let commands = decompose(command);
            let cat = commands
                .iter()
                .find(|c| c.argv[0] == "cat")
                .unwrap_or_else(|| panic!("{command}: no cat in {commands:?}"));

            assert_eq!(cat.argv, words("cat data/x.csv"), "{command}");
            assert!(cat.unresolved.is_empty(), "{command}");
        }
    }

    #[test]
    fn several_assignments_chain_and_each_value_is_recorded() {
        let commands = decompose("d=data; c=$d/clients; f=$c/holdings.csv; cat $f $c/x $d");

        assert_eq!(
            commands[0].argv,
            words("cat data/clients/holdings.csv data/clients/x data")
        );
        assert!(commands[0].unresolved.is_empty());
        assert_eq!(
            commands[0].assigned,
            words("data data/clients data/clients/holdings.csv")
        );

        // two on one line
        let commands = decompose("a=data b=x.csv; cat $a/$b");
        assert_eq!(commands[0].argv, words("cat data/x.csv"));
    }

    #[test]
    fn a_prefix_assignment_is_the_environment_of_a_script_it_runs_and_nothing_else() {
        // the script sees it
        let commands = decompose("f=data/x.csv sh -c 'cat $f'");
        let cat = commands
            .iter()
            .find(|c| c.argv[0] == "cat")
            .expect("the script's cat");
        assert_eq!(cat.argv, words("cat data/x.csv"));
        assert!(cat.assigned.contains(&"data/x.csv".to_owned()));

        // the command's own words are expanded without it, as a shell does
        assert_eq!(unresolved("f=data/x.csv cat $f"), vec!["$f".to_owned()]);
        // and a later command does not see it
        assert_eq!(
            unresolved("f=data/x.csv true; cat $f"),
            vec!["$f".to_owned()]
        );
    }

    #[test]
    fn an_assignment_from_the_environment_of_a_nested_script_reaches_it() {
        let cat = decompose("export f=data/x.csv; bash -c 'cat $f'")
            .into_iter()
            .find(|c| c.argv[0] == "cat")
            .expect("the script's cat");
        assert_eq!(cat.argv, words("cat data/x.csv"));

        let cat = decompose("f=data/x.csv; echo $(cat $f)")
            .into_iter()
            .find(|c| c.argv[0] == "cat")
            .expect("the substitution's cat");
        assert_eq!(cat.argv, words("cat data/x.csv"));
    }

    #[test]
    fn a_variable_that_could_hold_another_value_is_never_substituted() {
        for command in [
            // reassigned: the branch or the loop decides
            "f=safe.txt; f=data/x.csv; cat $f",
            "f=safe.txt; if true; then f=data/x.csv; fi; cat $f",
            "f=safe.txt; while true; do cat $f; f=data/x.csv; done",
            "f=safe.txt; f+=x; cat $f",
            // set by a builtin
            "f=safe.txt; for f in data/x.csv; do cat $f; done",
            "f=safe.txt; read f < data/x.csv; cat $f",
            // never set, set later, or set to something unresolved
            "cat $f",
            "cat $f; f=safe.txt",
            "f=$(echo safe.txt); cat $f",
            "f=$other; cat $f",
        ] {
            let commands = decompose(command);
            let cat = commands
                .iter()
                .rev()
                .find(|c| c.argv[0] == "cat")
                .unwrap_or_else(|| panic!("{command}: no cat in {commands:?}"));

            assert_eq!(cat.unresolved, vec!["$f".to_owned()], "{command}");
        }
    }

    #[test]
    fn pwd_is_not_trusted_after_a_cd() {
        let env = ShellEnv {
            cwd: Some("/work/repo".into()),
            home: None,
        };

        assert_eq!(
            decompose_in("cat $PWD/x", &env)[0].argv,
            words("cat /work/repo/x")
        );
        assert_eq!(
            decompose_in("cd data; cat $PWD/x", &env)[1].unresolved,
            vec!["$PWD/x".to_owned()]
        );
    }

    #[test]
    fn find_exec_inherits_what_its_roots_leave_unresolved() {
        let inner = decompose("find $d -exec cat {} \\;");
        assert_eq!(inner.last().expect("cat").unresolved, vec!["$d".to_owned()]);

        let known = decompose("d=data; find $d -exec cat {} \\;");
        assert_eq!(known.last().expect("cat").argv, words("cat data"));
        assert!(known.last().expect("cat").unresolved.is_empty());
    }

    #[test]
    fn heredoc_bodies_are_attached_and_the_commands_after_them_still_run() {
        let commands = decompose("python3 <<'PY'\nopen('data/x.csv')\nPY\ncat data/y.csv");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].argv, words("python3"));
        assert_eq!(
            commands[0].heredoc_body.as_deref(),
            Some("open('data/x.csv')\n")
        );
        assert_eq!(commands[1].argv, words("cat data/y.csv"));
        assert_eq!(commands[1].heredoc_body, None);
    }

    #[test]
    fn heredoc_forms() {
        let body = |command: &str| decompose(command)[0].heredoc_body.clone();

        assert_eq!(body("cat <<EOF\na\nEOF").as_deref(), Some("a\n"));
        assert_eq!(body("cat <<-EOF\n\ta\n\tEOF").as_deref(), Some("\ta\n"));
        assert_eq!(body("cat <<\"EOF\"\na\nEOF").as_deref(), Some("a\n"));
        assert_eq!(body("cat <<\\EOF\na\nEOF").as_deref(), Some("a\n"));
        assert_eq!(body("cat <<EOF | wc -l\na\nEOF").as_deref(), Some("a\n"));
        // The operator and its delimiter are not arguments.
        assert_eq!(argvs("cat <<EOF\na\nEOF"), vec![words("cat")]);
        // `<<<` is a here-string, not a here-document.
        assert_eq!(body("cat <<< hello"), None);
    }

    #[test]
    fn a_heredoc_with_no_terminator_does_not_hide_the_lines_after_it() {
        let commands = decompose("cat <<EOF\ncat data/x.csv\n");

        assert!(
            commands.iter().any(|c| c.argv == words("cat data/x.csv")),
            "{commands:?}"
        );
        assert_eq!(
            commands[0].heredoc_body.as_deref(),
            Some("cat data/x.csv\n")
        );
        // Arithmetic `<<` is not a heredoc either.
        assert!(
            argvs("((x<<2))\ncat data/x.csv").contains(&words("cat data/x.csv")),
            "{:?}",
            argvs("((x<<2))\ncat data/x.csv")
        );
    }

    #[test]
    fn unbalanced_text_is_one_opaque_command() {
        for command in [
            "cat \"data/x.csv",
            "cat 'data/x.csv",
            "cat data/x.csv\\",
            "echo $(cat data/x.csv",
            "echo `cat data/x.csv",
            "echo \"$(cat data/x.csv\"",
        ] {
            let commands = decompose(command);
            assert_eq!(commands, vec![SimpleCommand::opaque()], "{command}");
            assert!(commands[0].is_opaque() && commands[0].has_dynamic_args());
        }
    }

    #[test]
    fn segment_cap_keeps_the_first_64_and_flags_the_rest() {
        let command = (0..70)
            .map(|n| format!("echo {n}"))
            .collect::<Vec<_>>()
            .join("; ");
        let commands = decompose(&command);

        assert_eq!(commands.len(), MAX_SEGMENTS + 1);
        assert_eq!(commands[0].argv, words("echo 0"));
        assert_eq!(commands[MAX_SEGMENTS - 1].argv, words("echo 63"));
        assert!(commands[MAX_SEGMENTS].is_opaque());

        let at_the_cap = (0..MAX_SEGMENTS)
            .map(|n| format!("echo {n}"))
            .collect::<Vec<_>>()
            .join("; ");
        assert!(decompose(&at_the_cap).iter().all(|c| !c.is_opaque()));
    }

    #[test]
    fn depth_cap_flags_what_is_nested_too_deeply() {
        let nest = |levels: usize| {
            let mut command = "cat data/x.csv".to_owned();
            for _ in 0..levels {
                command = format!("echo $({command})");
            }
            command
        };

        let reachable = decompose(&nest(MAX_DEPTH));
        assert!(reachable.iter().any(|c| c.argv == words("cat data/x.csv")));
        assert!(reachable.iter().all(|c| !c.is_opaque()));

        let too_deep = decompose(&nest(MAX_DEPTH + 1));
        assert!(too_deep.iter().any(SimpleCommand::is_opaque));
    }

    #[test]
    fn plain_words_split_exactly_as_shlex_splits_them() {
        for command in [
            "cat da\"\"ta/x.csv",
            r#"cat "one file.txt" two.txt"#,
            r#"python -c "print(open(\"two words.txt\").read())""#,
            "grep 'a b' \"c d\" e\\ f",
            "echo héllo 'wörld' \"ü\"",
            "cat 'it'\\''s'",
            "head -n 20 logs/app.log",
        ] {
            let commands = decompose(command);
            assert_eq!(commands.len(), 1, "{command}");
            assert_eq!(
                Some(commands[0].argv.clone()),
                shlex::split(command),
                "{command}"
            );
        }
    }

    #[test]
    fn scan_of_plain_text_is_what_the_state_machine_makes_of_it() {
        // Text with nothing special takes a shortcut. A trailing newline sends
        // the same text through the full scanner without changing its segments
        // (the empty one after the newline is dropped), so they must agree.
        for text in [
            "",
            " ",
            "\t \t",
            "\r",
            "\u{a0}",
            " \u{2003} ",
            "echo",
            "echo c",
            "  echo   c  ",
            "cat data/clients/holdings.csv",
            "cat café/naïve.csv 日本語",
            "a\rb",
            "k=v cmd --flag=x -n 3 @host:path 50% ~/x",
        ] {
            let quick = scan(text).expect("plain text scans");
            let full = scan(&format!("{text}\n")).expect("plain text with a newline scans");

            let shape = |segments: &[Segment]| {
                segments
                    .iter()
                    .map(|segment| {
                        (
                            segment.text.clone(),
                            segment.stdin_piped,
                            segment.heredoc.clone(),
                            segment.substitutions.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(shape(&quick), shape(&full), "{text:?}");
        }

        // and what is special still goes through the scanner
        assert_eq!(scan("echo a; echo b").expect("scans").len(), 2);
        assert_eq!(scan("echo $(x)").expect("scans")[0].substitutions, ["x"]);
        assert_eq!(scan("# a comment").expect("scans").len(), 0);
    }

    #[test]
    fn four_kib_of_command_decomposes_in_under_a_millisecond() {
        // Worst cases at about 4 KiB that the segment cap allows: one long
        // segment full of quotes and substitutions, and 30 segments that each
        // carry a nested one (30 x 2 = 60 of the 64 segments).
        let long_segment = format!("echo {}", "\"a b $(echo c) 'd'\" `e` $f ".repeat(4096 / 27));
        let padding = "p".repeat(90);
        let many_segments = (0..30)
            .map(|n| format!("cat \"data/{n:03}/{padding}.csv\" $(echo {n}) 'x'"))
            .collect::<Vec<_>>()
            .join("; ");
        for command in [&long_segment, &many_segments] {
            assert!(command.len() >= 3500, "{} bytes", command.len());
        }
        assert!(decompose(&many_segments).iter().all(|c| !c.is_opaque()));

        // Timing is the minimum over many runs, the usual way to keep a
        // scheduler hiccup from failing a microbenchmark.
        for command in [&long_segment, &many_segments] {
            let best = (0..50)
                .map(|_| {
                    let started = std::time::Instant::now();
                    std::hint::black_box(decompose(std::hint::black_box(command)));
                    started.elapsed()
                })
                .min()
                .expect("at least one run");

            // Visible with `cargo test -- --nocapture`.
            eprintln!(
                "decompose of {} bytes: best of 50 runs = {best:?}",
                command.len()
            );
            assert!(
                best < std::time::Duration::from_millis(1),
                "{} bytes took {best:?}",
                command.len()
            );
        }
    }
}
