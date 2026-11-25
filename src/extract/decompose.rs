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
//! It reads the text only. It does not expand variables, globs, aliases or
//! functions: a word that depends on one is flagged in
//! [`SimpleCommand::has_dynamic_args`] and left as written, and what to do about
//! that is the dynamic-argument stance (bd-2mi), not decided here.
//!
//! Text it cannot analyse (unbalanced quotes, more than [`MAX_DEPTH`] levels of
//! nesting, more than [`MAX_SEGMENTS`] segments) comes back as an *opaque*
//! command: empty `argv`, `has_dynamic_args` true. Nothing downstream denies an
//! opaque command yet, so today that fails open, as an unparseable command
//! always has. The caps mean padding a command with 64 `true;` cannot hide a
//! reader after them from the first 64 segments, but it does hide one past them.

use super::wrappers;
use super::{collect_input_redirect_paths, is_env_assignment};

/// Levels of nesting (substitutions, `-c` strings, wrappers) followed before the
/// rest is reported as opaque.
pub const MAX_DEPTH: usize = 8;
/// Segments analysed in one command string, counted across every level.
pub const MAX_SEGMENTS: usize = 64;

/// Stands in for a `$( )`, backtick or `<( )` body in a segment's text, so the
/// words around it split as the shell would split them. It is a control
/// character, which path normalization already discards.
const SUBSTITUTION: char = '\u{1}';

/// Words that start a compound-command line but are not the command.
const LEADING_KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "elif", "else", "fi", "while", "until", "do", "done", "coproc",
];
/// Words that make the whole segment a loop or case header, with no command.
const HEADER_KEYWORDS: &[&str] = &["for", "select", "case", "esac", "in", "function"];

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
    /// Some word depends on something this module does not expand (a variable,
    /// a substitution, a glob, `{}` from `find -exec`, or arguments `xargs`
    /// reads from standard input). The consumer is the dynamic-argument stance
    /// (bd-2mi); nothing in veil branches on it yet.
    pub has_dynamic_args: bool,
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
            has_dynamic_args: true,
            origin: Origin::Top,
            stdin_piped: false,
            heredoc_body: None,
        }
    }

    pub fn is_opaque(&self) -> bool {
        self.argv.is_empty()
    }
}

/// Shared across one `decompose` call: the segment budget and why it stopped.
#[derive(Default)]
pub(super) struct Run {
    segments: usize,
    pub(super) truncated: bool,
    pub(super) failed: bool,
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
/// place of the wrapper.
pub fn decompose(command: &str) -> Vec<SimpleCommand> {
    let mut run = Run::default();
    let mut commands = Vec::new();

    script(command, Origin::Top, 0, &mut run, &mut commands);

    if run.failed {
        return vec![SimpleCommand::opaque()];
    }
    if run.truncated {
        commands.push(SimpleCommand::opaque());
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
        let Some(words) = shlex::split(&segment.text) else {
            run.failed = true;
            return;
        };
        if let Some(command) = simple_command(words, &segment, origin) {
            wrappers::expand(command, depth, run, out);
        }
    }
}

fn simple_command(
    mut words: Vec<String>,
    segment: &Segment,
    origin: Origin,
) -> Option<SimpleCommand> {
    let start = words
        .iter()
        .position(|word| !(is_env_assignment(word) || LEADING_KEYWORDS.contains(&word.as_str())))?;
    if HEADER_KEYWORDS.contains(&words[start].as_str()) {
        return None;
    }

    Some(SimpleCommand {
        argv: words.split_off(start),
        redirects_in: Vec::new(),
        has_dynamic_args: segment.dynamic,
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
    /// Shell text for `shlex`: quotes kept, substitutions replaced by
    /// [`SUBSTITUTION`], here-document operators removed.
    text: String,
    dynamic: bool,
    stdin_piped: bool,
    heredoc: Option<String>,
    /// Bodies of `$( )`, backticks and `<( )` found in `text`, and in an
    /// expanding here-document body.
    substitutions: Vec<String>,
}

impl Segment {
    fn is_blank(&self) -> bool {
        self.text.trim().is_empty() && self.substitutions.is_empty() && self.heredoc.is_none()
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
            b'$' => {
                match bytes.get(i + 1) {
                    Some(b'(') => {
                        let end = matching_paren(text, i + 2)?;
                        substitute(&mut current, text[i + 2..end].to_owned());
                        i = end + 1;
                    }
                    Some(&next) if starts_expansion(next) => {
                        current.dynamic = true;
                        current.text.push('$');
                        i += 1;
                    }
                    _ => {
                        current.text.push('$');
                        i += 1;
                    }
                }
                word_start = false;
            }
            b'<' | b'>' if bytes.get(i + 1) == Some(&b'(') => {
                let end = matching_paren(text, i + 2)?;
                substitute(&mut current, text[i + 2..end].to_owned());
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
            b'*' | b'?' | b'[' | b'{' => {
                current.dynamic = true;
                current.text.push(bytes[i] as char);
                i += 1;
                word_start = false;
            }
            b'~' if word_start => {
                current.dynamic = true;
                current.text.push('~');
                i += 1;
                word_start = false;
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
    let run = text.as_bytes()[from..]
        .iter()
        .take_while(|byte| {
            !matches!(
                byte,
                b'\\'
                    | b'\''
                    | b'"'
                    | b'`'
                    | b'$'
                    | b'<'
                    | b'>'
                    | b';'
                    | b'('
                    | b')'
                    | b'&'
                    | b'|'
                    | b'\n'
                    | b' '
                    | b'\t'
                    | b'*'
                    | b'?'
                    | b'['
                    | b'{'
                    | b'~'
                    | b'#'
            )
        })
        .count();
    into.push_str(&text[from..from + run]);
    run
}

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
    current.dynamic = true;
}

/// The byte after `$` that makes it an expansion: `$name`, `${...}`, `$1`,
/// `$@`, `$?` and the like.
fn starts_expansion(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'{' | b'@' | b'*' | b'#' | b'?' | b'$' | b'!' | b'-'
        )
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
                if bytes.get(i + 1).is_some_and(|&next| starts_expansion(next)) {
                    current.dynamic = true;
                }
                current.text.push('$');
                i += 1;
            }
            _ => {
                // Everything else is literal until the next special byte.
                let run = bytes[i..]
                    .iter()
                    .take_while(|byte| !matches!(byte, b'"' | b'\\' | b'`' | b'$'))
                    .count();
                current.text.push_str(&text[i..i + run]);
                i += run;
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
                let ch = text[i..].chars().next()?;
                body.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    None
}

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
        assert_commands("for f in a b; do cat $f; done", &["cat $f"]);
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
        assert!(commands[1].has_dynamic_args);
        assert!(!commands[0].has_dynamic_args);
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

    #[test]
    fn dynamic_words_are_flagged() {
        for command in [
            "cat $f",
            "cat ${f}",
            "cat \"$f\"",
            "cat data/*.csv",
            "cat data/?.csv",
            "cat data/[ab].csv",
            "cat data/{a,b}.csv",
            "cat ~/x",
            "cat $(echo x)",
            "cat `echo x`",
            "cat $1",
            "cat $@",
        ] {
            assert!(
                decompose(command).iter().any(|c| c.has_dynamic_args),
                "{command} should be dynamic"
            );
        }
        for command in [
            "cat data/x.csv",
            "cat 'data/*.csv'",
            "cat \"data/*.csv\"",
            "cat '$f'",
            "cat a~b",
            "cat 100$",
            "echo $ x",
        ] {
            assert!(
                decompose(command).iter().all(|c| !c.has_dynamic_args),
                "{command} should not be dynamic"
            );
        }
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
            assert!(commands[0].is_opaque() && commands[0].has_dynamic_args);
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
