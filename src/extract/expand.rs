//! bd-2mi: what a shell expands in a command's words before it runs them, as
//! far as veil can follow it from the text alone.
//!
//! `f=data/clients.csv; cat $f` reads a protected file through a word the
//! decomposer used to leave as `$f`. This module keeps the assignments of one
//! command string, substitutes `$name` and `${name}` from them, resolves `$HOME`,
//! `$PWD` and a leading `~` from the hook's own environment, and expands brace
//! lists (`data/{a,b}.csv`, `{1..3}`). A word that still depends on something
//! veil cannot know (a variable it was never told, `$(...)`, a list that would
//! expand to more than [`MAX_BRACE_WORDS`] words) comes back with the text it was
//! written as, in [`Word::unresolved`]. The dynamic-argument stance reads that.
//!
//! A variable is only trusted when its value is certain. A name that is assigned
//! more than once anywhere in the command string, appended to, or set by `read`,
//! `for`, `mapfile` and the like could hold a different value when a loop or a
//! branch runs, so every reference to it is unresolved. Assignments are tracked
//! in text order with no scoping: `(f=x); cat $f` sees `f=x` although a shell
//! would not. That errs toward judging more, not less.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::decompose::SUBSTITUTION;
use super::is_env_assignment;

/// Brace expansion yields at most this many words from one word. A list that
/// would yield more is left as written and reported as unresolved.
pub(super) const MAX_BRACE_WORDS: usize = 64;

/// What the caller knows about the shell a command runs in.
#[derive(Clone, Debug, Default)]
pub struct ShellEnv {
    /// The working directory, for `$PWD`.
    pub cwd: Option<PathBuf>,
    /// The home directory, for `$HOME` and a leading `~`.
    pub home: Option<String>,
}

/// One word after expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Word {
    pub text: String,
    /// The word as it was written, when something in it could not be resolved.
    pub unresolved: Option<String>,
}

/// The variables of one command string whose values veil is sure of.
#[derive(Default)]
pub(super) struct Vars {
    values: BTreeMap<String, String>,
    /// The loop variables of `for name in words; do ...; done` whose words are
    /// all known: a word that uses one stands for each value in turn.
    loops: BTreeMap<String, Vec<String>>,
    /// Names whose value cannot be known from the text.
    unknown: BTreeSet<String>,
}

/// What `$name` is looked up in while one word is read: the caller's shell,
/// and the loop variables bound to one value each.
#[derive(Clone, Copy)]
struct Scope<'a> {
    env: &'a ShellEnv,
    binding: &'a [(&'a str, &'a str)],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

impl Vars {
    /// The variables of `command`, with every name that cannot be trusted
    /// already marked.
    pub(super) fn for_command(command: &str) -> Self {
        Self {
            values: BTreeMap::new(),
            loops: BTreeMap::new(),
            unknown: unknowable_names(command),
        }
    }

    /// Records `name=value` for the words that follow. `None` means the value
    /// could not be resolved, so the name is forgotten rather than guessed.
    pub(super) fn assign(&mut self, name: &str, value: Option<String>) {
        self.loops.remove(name);
        match value {
            Some(value) if !self.unknown.contains(name) => {
                self.values.insert(name.to_owned(), value);
            }
            _ => {
                self.values.remove(name);
            }
        }
    }

    /// Records `for name in values`: until the loop ends the name stands for
    /// each of `values`. `None` (a list veil cannot resolve) or too many values
    /// forgets the name.
    pub(super) fn assign_loop(&mut self, name: &str, values: Option<Vec<String>>) {
        self.values.remove(name);
        match values {
            Some(values) if !self.unknown.contains(name) && values.len() <= MAX_BRACE_WORDS => {
                self.loops.insert(name.to_owned(), values);
            }
            _ => {
                self.loops.remove(name);
            }
        }
    }

    /// Sets `pairs` for one command only (`f=x sh -c 'cat $f'`), and returns what
    /// [`Vars::restore`] needs to put things back.
    pub(super) fn scoped(&mut self, pairs: &[(String, String)]) -> Vec<(String, Option<String>)> {
        pairs
            .iter()
            .filter(|(name, _)| !self.unknown.contains(name))
            .map(|(name, value)| {
                (
                    name.clone(),
                    self.values.insert(name.clone(), value.clone()),
                )
            })
            .collect()
    }

    pub(super) fn restore(&mut self, saved: Vec<(String, Option<String>)>) {
        for (name, old) in saved.into_iter().rev() {
            match old {
                Some(value) => {
                    self.values.insert(name, value);
                }
                None => {
                    self.values.remove(&name);
                }
            }
        }
    }

    fn lookup(&self, name: &str, env: &ShellEnv, binding: &[(&str, &str)]) -> Option<String> {
        if self.unknown.contains(name) {
            return None;
        }
        if let Some((_, value)) = binding.iter().find(|(bound, _)| *bound == name) {
            return Some((*value).to_owned());
        }
        if let Some(value) = self.values.get(name) {
            return Some(value.clone());
        }

        match name {
            "HOME" => env.home.clone(),
            "PWD" => env
                .cwd
                .as_ref()
                .map(|cwd| cwd.to_string_lossy().into_owned()),
            _ => None,
        }
    }

    /// The words `raw` (as [`raw_words`] split them) become: braces expanded,
    /// variables and `~` substituted, quotes removed.
    pub(super) fn words(&self, raw: &[&str], env: &ShellEnv) -> Option<Vec<Word>> {
        let mut words = Vec::with_capacity(raw.len());

        for &written in raw {
            if !needs_expansion(written) {
                // Most words are plain text: nothing to expand or to unquote.
                words.push(Word {
                    text: written.to_owned(),
                    unresolved: None,
                });
            } else if !written.contains('{') {
                self.push_alternative(written, written, env, &mut words)?;
            } else {
                match brace_expand(written) {
                    Some(alternatives) => {
                        for alternative in &alternatives {
                            self.push_alternative(written, alternative, env, &mut words)?;
                        }
                    }
                    None => self.push_word(written, written, true, &[], env, &mut words)?,
                }
            }
        }

        Some(words)
    }

    /// Adds the words one alternative of `written` becomes: one for each value
    /// of the loop variables it uses, and one when it uses none. A loop that
    /// would make more than [`MAX_BRACE_WORDS`] words is left unresolved.
    fn push_alternative(
        &self,
        written: &str,
        alternative: &str,
        env: &ShellEnv,
        words: &mut Vec<Word>,
    ) -> Option<()> {
        let names = if self.loops.is_empty() {
            Vec::new()
        } else {
            self.loops_used_by(alternative)
        };
        if names.is_empty() {
            return self.push_word(written, alternative, false, &[], env, words);
        }

        // Every combination of values, so that each path a loop would reach is
        // judged: `cat $f` over `a b` is `cat a b`.
        let mut bindings: Vec<Vec<(&str, &str)>> = vec![Vec::new()];
        for name in names {
            let values = &self.loops[name];
            if bindings.len().saturating_mul(values.len()) > MAX_BRACE_WORDS {
                return self.push_word(written, alternative, true, &[], env, words);
            }
            bindings = bindings
                .iter()
                .flat_map(|so_far| {
                    values.iter().map(move |value| {
                        let mut next = so_far.clone();
                        next.push((name, value.as_str()));
                        next
                    })
                })
                .collect();
        }

        for binding in &bindings {
            self.push_word(written, alternative, false, binding, env, words)?;
        }
        Some(())
    }

    /// The loop variables `text` refers to as `$name` or `${name}`. A reference
    /// inside single quotes counts too: that only adds alternatives.
    fn loops_used_by(&self, text: &str) -> Vec<&str> {
        let mut used: Vec<&str> = Vec::new();

        for (position, _) in text.match_indices('$') {
            let rest = &text[position + 1..];
            let (rest, braced) = match rest.strip_prefix('{') {
                Some(inside) => (inside, true),
                None => (rest, false),
            };
            let length = rest
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            let name = &rest[..length];
            if braced && !rest[length..].starts_with('}') {
                continue;
            }
            if let Some((known, _)) = self.loops.get_key_value(name)
                && !self.unknown.contains(name)
                && !used.contains(&known.as_str())
            {
                used.push(known.as_str());
            }
        }

        used
    }

    /// Substitutes and unquotes one alternative of `written`, and adds the word
    /// it becomes (none, for an unquoted expansion of nothing).
    fn push_word(
        &self,
        written: &str,
        alternative: &str,
        too_many: bool,
        binding: &[(&str, &str)],
        env: &ShellEnv,
        words: &mut Vec<Word>,
    ) -> Option<()> {
        let processed = self.process(alternative, env, binding);
        if processed.text.is_empty() && !processed.quoted {
            // an unquoted expansion of nothing leaves no word
            return Some(());
        }

        words.push(Word {
            text: processed.text,
            unresolved: (processed.unresolved || too_many).then(|| written.to_owned()),
        });
        Some(())
    }

    /// The value written on the right of `name=`, or `None` when it depends on
    /// something unresolved (a loop variable included: it has several values).
    pub(super) fn value(&self, raw: &str, env: &ShellEnv) -> Option<String> {
        let processed = self.process(raw, env, &[]);
        (!processed.unresolved).then_some(processed.text)
    }

    /// Reads one written word the way a shell does: removes quotes and
    /// backslashes and inserts the value of each `$name` it knows, literally. A
    /// value is never read again for quotes, `$` or blanks. `binding` gives the
    /// loop variables one value each.
    fn process(&self, raw: &str, env: &ShellEnv, binding: &[(&str, &str)]) -> Processed {
        let bytes = raw.as_bytes();
        let mut out = String::with_capacity(raw.len());
        let mut unresolved = false;
        let mut quoted = false;
        let mut quote = Quote::None;
        let mut i = 0;

        if bytes.first() == Some(&b'~') {
            match bytes.get(1) {
                None | Some(b'/') => match env.home.as_deref() {
                    Some(home) => {
                        out.push_str(home);
                        i = 1;
                    }
                    None => unresolved = true,
                },
                // `~user`, `~+`, `~-`: someone else's directory, or the last one.
                Some(_) => unresolved = true,
            }
        }

        while i < bytes.len() {
            match (quote, bytes[i]) {
                (Quote::Single, b'\'') => {
                    quote = Quote::None;
                    i += 1;
                }
                (Quote::Single, _) => {
                    let mut end = i;
                    while end < bytes.len() && bytes[end] != b'\'' {
                        end += 1;
                    }
                    out.push_str(&raw[i..end]);
                    i = end;
                }
                (Quote::None, b'\'') => {
                    quote = Quote::Single;
                    quoted = true;
                    i += 1;
                }
                (Quote::Double, b'\'') => {
                    out.push('\'');
                    i += 1;
                }
                (Quote::None, b'$') if bytes.get(i + 1) == Some(&b'\'') => {
                    // `$'...'`: the escapes of the C language are decoded
                    quoted = true;
                    let Some(end) = ansi_c_end(raw, i + 1) else {
                        unresolved = true;
                        out.push_str(&raw[i..]);
                        break;
                    };
                    match decode_ansi_c(&raw[i + 2..end]) {
                        Some(text) => out.push_str(&text),
                        None => {
                            unresolved = true;
                            out.push_str(&raw[i..=end]);
                        }
                    }
                    i = end + 1;
                }
                (Quote::None, b'$') if bytes.get(i + 1) == Some(&b'"') => {
                    // `$"..."` is a double-quoted string, translated if the
                    // shell has a translation: the `$` goes
                    i += 1;
                }
                (_, b'"') => {
                    quote = if quote == Quote::Double {
                        Quote::None
                    } else {
                        Quote::Double
                    };
                    quoted = true;
                    i += 1;
                }
                (_, b'\\') => {
                    quoted = true;
                    let next = raw[i + 1..].chars().next();
                    match next {
                        // a line continuation vanishes
                        Some('\n') => {}
                        Some(next) if quote == Quote::None || "$\"\\`".contains(next) => {
                            out.push(next);
                        }
                        // in double quotes any other backslash stays
                        Some(next) => {
                            out.push('\\');
                            out.push(next);
                        }
                        None => out.push('\\'),
                    }
                    i += 1 + next.map_or(0, char::len_utf8);
                }
                (_, SUBSTITUTION_BYTE) => {
                    unresolved = true;
                    out.push(SUBSTITUTION);
                    i += 1;
                }
                (_, b'$') => {
                    let scope = Scope { env, binding };
                    i = self.dollar(raw, i, quote, scope, &mut out, &mut unresolved);
                }
                _ => {
                    let mut end = i;
                    while end < bytes.len() && !STOPS[bytes[end] as usize] {
                        end += 1;
                    }
                    out.push_str(&raw[i..end]);
                    i = end;
                }
            }
        }

        Processed {
            text: out,
            unresolved,
            quoted,
        }
    }

    /// Handles the `$` at `at`; returns the index after what it consumed.
    fn dollar(
        &self,
        raw: &str,
        at: usize,
        quote: Quote,
        scope: Scope<'_>,
        out: &mut String,
        unresolved: &mut bool,
    ) -> usize {
        let rest = &raw[at + 1..];

        let (name, end) = match rest.as_bytes().first() {
            Some(b'{') => {
                let Some(close) = rest.find('}') else {
                    out.push('$');
                    *unresolved = true;
                    return at + 1;
                };
                let end = at + 1 + close + 1;
                let body = &rest[1..close];
                if !is_name(body) {
                    // `${f:-x}`, `${#f}`, `${f%.csv}`, `${10}`
                    out.push_str(&raw[at..end]);
                    *unresolved = true;
                    return end;
                }
                (body, end)
            }
            Some(first) if first.is_ascii_alphabetic() || *first == b'_' => {
                let length = rest
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    .count();
                (&rest[..length], at + 1 + length)
            }
            // `$$`, `$?`, `$!`, `$#`, `$-` are numbers or flags, never a path.
            Some(b'$' | b'?' | b'!' | b'#' | b'-') => {
                out.push('0');
                return at + 2;
            }
            // `$1`, `$@`, `$*`: arguments veil is not told.
            Some(next) if next.is_ascii_digit() || matches!(next, b'@' | b'*') => {
                out.push_str(&raw[at..at + 2]);
                *unresolved = true;
                return at + 2;
            }
            _ => {
                out.push('$');
                return at + 1;
            }
        };

        match self.lookup(name, scope.env, scope.binding) {
            // An unquoted value with blanks would split into several words.
            Some(value) if quote == Quote::None && value.contains(char::is_whitespace) => {
                out.push_str(&raw[at..end]);
                *unresolved = true;
            }
            Some(value) => out.push_str(&value),
            None => {
                out.push_str(&raw[at..end]);
                *unresolved = true;
            }
        }

        end
    }
}

struct Processed {
    text: String,
    unresolved: bool,
    /// The word had a quote or a backslash, so an empty result is still a word.
    quoted: bool,
}

/// Whether a written word has anything the expansion or the unquoting would
/// change: braces, `$`, a leading `~`, a substitution marker, a quote or a
/// backslash.
fn needs_expansion(word: &str) -> bool {
    let bytes = word.as_bytes();
    if bytes.first() == Some(&b'~') {
        return true;
    }

    // A table and a plain loop: this runs for every word of every command.
    let mut i = 0;
    while i < bytes.len() {
        if EXPANDS[bytes[i] as usize] {
            return true;
        }
        i += 1;
    }
    false
}

/// Bytes that make a word need expansion or unquoting.
static EXPANDS: [bool; 256] = byte_table(b"{$'\"\\\x01");
/// Bytes that end a run of ordinary text while a word is read: quotes, a
/// backslash, `$` and the substitution marker.
static STOPS: [bool; 256] = byte_table(b"$'\"\\\x01");

const fn byte_table(bytes: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0;
    while i < bytes.len() {
        table[bytes[i] as usize] = true;
        i += 1;
    }
    table
}

/// The index of the quote that closes the `$'...'` string whose opening quote
/// is at `open`. A backslash escapes the next character, so `\'` does not close
/// it, which is the difference from a plain single-quoted string.
pub(super) fn ansi_c_end(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = open + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' => return Some(i),
            b'\\' => i += 1 + text[i + 1..].chars().next()?.len_utf8(),
            _ => i += 1,
        }
    }

    None
}

/// What the body of a `$'...'` string expands to, the way bash reads it:
/// `\n`, `\t`, `\xHH`, octal `\NNN`, `\uHHHH` and the rest. `None` when the
/// result is not text (a byte that is not UTF-8, a code point that does not
/// exist). A NUL ends the string, as it does in the shell.
fn decode_ansi_c(body: &str) -> Option<String> {
    fn digits(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        radix: u32,
        most: usize,
    ) -> Option<u32> {
        let mut value = None;
        for _ in 0..most {
            let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(radix)) else {
                break;
            };
            chars.next();
            value = Some(value.unwrap_or(0) * radix + digit);
        }
        value
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(body.len());
    let mut chars = body.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut encoded = [0; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            continue;
        }

        let Some(escape) = chars.next() else {
            bytes.push(b'\\');
            break;
        };
        let byte = match escape {
            'a' => 0x07,
            'b' => 0x08,
            'e' | 'E' => 0x1b,
            'f' => 0x0c,
            'n' => b'\n',
            'r' => b'\r',
            't' => b'\t',
            'v' => 0x0b,
            '\\' | '\'' | '"' | '?' => escape as u8,
            'x' => match digits(&mut chars, 16, 2) {
                Some(value) => value as u8,
                None => {
                    bytes.extend_from_slice(b"\\x");
                    continue;
                }
            },
            '0'..='7' => {
                let mut value = escape.to_digit(8)?;
                for _ in 0..2 {
                    let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(8)) else {
                        break;
                    };
                    chars.next();
                    value = value * 8 + digit;
                }
                value as u8
            }
            'u' | 'U' => {
                let most = if escape == 'u' { 4 } else { 8 };
                let Some(value) = digits(&mut chars, 16, most) else {
                    bytes.extend_from_slice(if escape == 'u' { b"\\u" } else { b"\\U" });
                    continue;
                };
                let mut encoded = [0; 4];
                let text = char::from_u32(value)?.encode_utf8(&mut encoded);
                if value == 0 {
                    break;
                }
                bytes.extend_from_slice(text.as_bytes());
                continue;
            }
            'c' => match chars.next() {
                Some(next) if next.is_ascii() => (next as u8) & 0x1f,
                _ => return None,
            },
            other => {
                let mut encoded = [0; 4];
                bytes.push(b'\\');
                bytes.extend_from_slice(other.encode_utf8(&mut encoded).as_bytes());
                continue;
            }
        };

        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }

    String::from_utf8(bytes).ok()
}

pub(super) fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// The words of a segment whose text has nothing to expand or unquote (no
/// quote, backslash, `$`, brace, `~` or substitution marker) and does not begin
/// with an assignment. Most commands are like that. `None` for any other text,
/// which takes the general path.
pub(super) fn plain_words(text: &str) -> Option<Vec<Word>> {
    let bytes = text.as_bytes();
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];
        if NOT_PLAIN[byte as usize] {
            return None;
        }

        let blank = matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
        match (blank, start) {
            (true, Some(begin)) => {
                words.push(Word {
                    text: text[begin..i].to_owned(),
                    unresolved: None,
                });
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
        i += 1;
    }
    if let Some(begin) = start {
        words.push(Word {
            text: text[begin..].to_owned(),
            unresolved: None,
        });
    }

    Some(words)
}

/// Bytes that take a segment off the plain path: everything in [`EXPANDS`], a
/// `~` anywhere, and `=` (it may be an assignment).
static NOT_PLAIN: [bool; 256] = byte_table(b"{$~'\"\\=\x01");

const SUBSTITUTION_BYTE: u8 = SUBSTITUTION as u8;

/// Splits one segment's text into words at unquoted blanks, keeping each word
/// as written (quotes and backslashes included). `None` for an unterminated
/// quote or a trailing backslash, which the shell would reject too.
pub(super) fn raw_words(text: &str) -> Option<Vec<&str>> {
    let mut words = Vec::new();
    let mut start = None;
    let mut quote = Quote::None;
    let mut chars = text.char_indices().peekable();

    while let Some((at, ch)) = chars.next() {
        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match ch {
                '"' => quote = Quote::None,
                '\\' => {
                    chars.next()?;
                }
                _ => {}
            },
            Quote::None => match ch {
                ' ' | '\t' | '\n' | '\r' => {
                    if let Some(begin) = start.take() {
                        words.push(&text[begin..at]);
                    }
                }
                _ => {
                    start.get_or_insert(at);
                    match ch {
                        '\'' => quote = Quote::Single,
                        '"' => quote = Quote::Double,
                        '\\' => {
                            chars.next()?;
                        }
                        // `$'...'`: a backslash escapes a quote inside it
                        '$' if text[at + 1..].starts_with('\'') => {
                            let end = ansi_c_end(text, at + 1)?;
                            while chars.next_if(|&(index, _)| index <= end).is_some() {}
                        }
                        _ => {}
                    }
                }
            },
        }
    }

    if quote != Quote::None {
        return None;
    }
    if let Some(begin) = start {
        words.push(&text[begin..]);
    }
    Some(words)
}

/// `name=value` pairs when the words only set variables: `a=1 b=2`, or
/// `export a=1 b`, `declare -x a=1`, `local`, `readonly`, `typeset`. `value` is
/// as written. `None` when the words run a command, or set nothing.
pub(super) fn assignment_words(raw: &[&str]) -> Option<Vec<(String, String)>> {
    let declaring = matches!(
        raw.first().copied(),
        Some("export" | "declare" | "typeset" | "local" | "readonly")
    );
    let mut rest = if declaring { &raw[1..] } else { raw };
    if declaring {
        let options = rest.iter().take_while(|word| word.starts_with('-')).count();
        rest = &rest[options..];
    }

    let mut pairs = Vec::new();
    for word in rest {
        if is_env_assignment(word)
            && let Some((name, value)) = word.split_once('=')
        {
            pairs.push((name.to_owned(), value.to_owned()));
        } else if !declaring {
            return None;
        }
    }

    (!pairs.is_empty()).then_some(pairs)
}

/// Whether the words put what they set into the environment of every program
/// that runs after them: `export`, or `declare`/`typeset` with `-x`. veil does
/// not read what those programs do with it, so a protected path exported this
/// way is judged as named, which is what it did before assignments were tracked.
pub(super) fn exports_to_environment(raw: &[&str]) -> bool {
    match raw.first().copied() {
        Some("export") => true,
        Some("declare" | "typeset") => raw[1..]
            .iter()
            .take_while(|word| word.starts_with('-'))
            .any(|option| option.contains('x')),
        _ => false,
    }
}

/// Names whose value veil cannot know from reading the command once: assigned
/// more than once (a branch or a loop may have run either; a `for name in` is
/// one assignment), appended to with `+=`, set by `read`, `select`, `mapfile`,
/// `readarray`, `getopts`, `printf -v` or a `for` with no list, or `PWD` and
/// `OLDPWD` once the command changes directory.
fn unknowable_names(command: &str) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    let bytes = command.as_bytes();

    for (position, _) in command.match_indices('=') {
        let append = position > 0 && bytes[position - 1] == b'+';
        let end = position - usize::from(append);
        let start = bytes[..end]
            .iter()
            .rposition(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
            .map_or(0, |index| index + 1);
        let name = &command[start..end];
        if !is_name(name) {
            continue;
        }

        if append {
            unknown.insert(name.to_owned());
        } else {
            *counts.entry(name.to_owned()).or_default() += 1;
        }
    }
    // Within one command (up to the next separator), the words after these
    // builtins may be names they set. Most commands name none of them.
    const BUILTINS: &[&str] = &[
        "for", "select", "read", "mapfile", "getopts", "printf", "cd", "pushd", "popd",
    ];
    if BUILTINS.iter().any(|builtin| command.contains(builtin)) {
        builtins_set_names(command, &mut counts, &mut unknown);
    }

    unknown.extend(
        counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(name, _)| name),
    );
    unknown
}

/// Marks the names the builtins in `command` set. `for name in` counts as one
/// assignment of `name`: its words are known when the loop is read, so the name
/// is trusted unless it is assigned anywhere else too.
fn builtins_set_names(
    command: &str,
    counts: &mut BTreeMap<String, usize>,
    unknown: &mut BTreeSet<String>,
) {
    for chunk in command.split([';', '&', '|', '(', ')', '\n']) {
        let tokens: Vec<&str> = chunk.split_whitespace().collect();

        for (index, token) in tokens.iter().enumerate() {
            let named = match *token {
                "for" => {
                    if let Some(name) = tokens.get(index + 1)
                        && tokens.get(index + 2) == Some(&"in")
                        && is_name(name)
                    {
                        *counts.entry((*name).to_owned()).or_default() += 1;
                        continue;
                    }
                    // `for name;` loops over the arguments veil is not told
                    1
                }
                "select" => 1,
                "read" | "mapfile" | "readarray" | "getopts" => usize::MAX,
                "cd" | "pushd" | "popd" => {
                    unknown.insert("PWD".to_owned());
                    unknown.insert("OLDPWD".to_owned());
                    0
                }
                "printf" if tokens.get(index + 1) == Some(&"-v") => {
                    // `printf -v name format ...` sets `name`
                    if let Some(name) = tokens.get(index + 2) {
                        unknown.insert((*name).to_owned());
                    }
                    0
                }
                _ => 0,
            };

            for name in tokens.iter().skip(index + 1).take(named) {
                let name = name.trim_matches(['"', '\'']);
                if is_name(name) {
                    unknown.insert(name.to_owned());
                }
            }
        }
    }
}

/// The words `word` expands to under brace expansion: `data/{a,b}.csv` is
/// `data/a.csv` and `data/b.csv`, `{1..3}` is `1 2 3`. Braces in quotes, `${...}`
/// and groups that are not lists (`{}`, `{a}`) stay as they are. `None` when
/// more than [`MAX_BRACE_WORDS`] words would result.
fn brace_expand(word: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    expand_braces(word, &mut out)?;
    Some(out)
}

fn expand_braces(word: &str, out: &mut Vec<String>) -> Option<()> {
    let Some(group) = find_group(word)? else {
        if out.len() >= MAX_BRACE_WORDS {
            return None;
        }
        out.push(word.to_owned());
        return Some(());
    };

    for item in &group.items {
        let next = format!("{}{item}{}", &word[..group.open], &word[group.close + 1..]);
        expand_braces(&next, out)?;
    }
    Some(())
}

struct Group {
    open: usize,
    close: usize,
    items: Vec<String>,
}

/// The first brace list in `word`: `Some(Some(group))`, or `Some(None)` when
/// there is none. `None` means the list would be longer than
/// [`MAX_BRACE_WORDS`].
fn find_group(word: &str) -> Option<Option<Group>> {
    let marks = brace_marks(word);

    for (index, &(open, mark)) in marks.iter().enumerate() {
        if mark != b'{' {
            continue;
        }

        let mut depth = 0usize;
        let mut commas = Vec::new();
        let mut close = None;
        for &(position, mark) in &marks[index..] {
            match mark {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(position);
                        break;
                    }
                }
                _ => {
                    if depth == 1 {
                        commas.push(position);
                    }
                }
            }
        }
        let Some(close) = close else {
            continue;
        };

        let items = if commas.is_empty() {
            match sequence(&word[open + 1..close])? {
                Some(items) => items,
                None => continue,
            }
        } else {
            let mut items = Vec::with_capacity(commas.len() + 1);
            let mut from = open + 1;
            for comma in commas {
                items.push(word[from..comma].to_owned());
                from = comma + 1;
            }
            items.push(word[from..close].to_owned());
            items
        };

        return Some(Some(Group { open, close, items }));
    }

    Some(None)
}

/// Byte positions of the braces and commas outside quotes, escapes and `${...}`.
fn brace_marks(word: &str) -> Vec<(usize, u8)> {
    let bytes = word.as_bytes();
    let mut marks = Vec::new();
    let mut quote = Quote::None;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];
        match quote {
            Quote::Single => {
                if byte == b'\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match byte {
                b'"' => quote = Quote::None,
                b'\\' => i += 1,
                _ => {}
            },
            Quote::None => match byte {
                b'\'' => quote = Quote::Single,
                b'"' => quote = Quote::Double,
                b'\\' => i += 1,
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    i = bytes[i..]
                        .iter()
                        .position(|&b| b == b'}')
                        .map_or(bytes.len(), |length| i + length);
                }
                b'{' | b'}' | b',' => marks.push((i, byte)),
                _ => {}
            },
        }
        i += 1;
    }

    marks
}

/// `1..5`, `5..1`, `01..10`, `1..10..3`, `a..e`: `Some(None)` when `body` is
/// not a sequence, `None` when it is one with too many items.
fn sequence(body: &str) -> Option<Option<Vec<String>>> {
    let parts: Vec<&str> = body.split("..").collect();
    if !(2..=3).contains(&parts.len()) {
        return Some(None);
    }
    let step = match parts.get(2) {
        Some(text) => match text.parse::<i64>() {
            Ok(step) => step.unsigned_abs().max(1) as i64,
            Err(_) => return Some(None),
        },
        None => 1,
    };

    if let (Ok(from), Ok(to)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        let padded = [parts[0], parts[1]].iter().any(|text| {
            let digits = text.trim_start_matches('-');
            digits.len() > 1 && digits.starts_with('0')
        });
        let width = if padded {
            parts[0].len().max(parts[1].len())
        } else {
            0
        };
        let count = (from - to).unsigned_abs() / step as u64 + 1;
        if count > MAX_BRACE_WORDS as u64 {
            return None;
        }

        let direction = if from <= to { step } else { -step };
        let mut items = Vec::new();
        let mut value = from;
        loop {
            items.push(format!("{value:0width$}"));
            value += direction;
            if (direction > 0 && value > to) || (direction < 0 && value < to) {
                break;
            }
        }
        return Some(Some(items));
    }

    let letter = |text: &str| match text.as_bytes() {
        [byte] if byte.is_ascii_alphabetic() => Some(*byte),
        _ => None,
    };
    if let (Some(from), Some(to)) = (letter(parts[0]), letter(parts[1])) {
        let direction = if from <= to { step } else { -step };
        let mut items = Vec::new();
        let mut value = i64::from(from);
        loop {
            items.push(char::from(value as u8).to_string());
            value += direction;
            if (direction > 0 && value > i64::from(to)) || (direction < 0 && value < i64::from(to))
            {
                break;
            }
        }
        return Some(Some(items));
    }

    Some(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> ShellEnv {
        ShellEnv {
            cwd: Some(PathBuf::from("/work/repo")),
            home: Some("/home/me".to_owned()),
        }
    }

    fn raw(text: &str) -> Vec<&str> {
        raw_words(text).expect("text should split")
    }

    fn expand(vars: &Vars, text: &str) -> Vec<(String, bool)> {
        vars.words(&raw(text), &env())
            .expect("words should expand")
            .into_iter()
            .map(|word| (word.text, word.unresolved.is_some()))
            .collect()
    }

    fn texts(vars: &Vars, text: &str) -> Vec<String> {
        expand(vars, text)
            .into_iter()
            .map(|(text, _)| text)
            .collect()
    }

    fn with(command: &str, assignments: &[(&str, &str)]) -> Vars {
        let mut vars = Vars::for_command(command);
        for (name, value) in assignments {
            vars.assign(name, Some((*value).to_owned()));
        }
        vars
    }

    #[test]
    fn ansi_c_quoting_expands_to_the_text_the_shell_would_pass() {
        let vars = with("f=x", &[("f", "x")]);

        // The same file name written four ways a person can hide it.
        for written in [
            "cat $'.env'",
            "cat $'.e\\x6ev'",
            "cat $'\\056env'",
            "cat $'\\u002eenv'",
            "cat $'.e'nv",
            "cat .$'env'",
        ] {
            assert_eq!(texts(&vars, written), vec!["cat", ".env"], "{written}");
        }

        for (written, expected) in [
            ("echo $'a b'", "a b"),
            ("echo $'it\\'s'", "it's"),
            ("echo $'tab\\there'", "tab\there"),
            ("echo $'\\x41\\101\\u00e9'", "AAé"),
            ("echo $'back\\\\slash'", "back\\slash"),
            ("echo $'\\cA'", "\u{1}"),
            // not an escape bash knows: the backslash stays
            ("echo $'\\q'", "\\q"),
            ("echo $'\\x'", "\\x"),
            // a NUL ends the string
            ("echo $'ab\\x00cd'", "ab"),
            // nothing is substituted inside it
            ("echo $'$f'", "$f"),
        ] {
            assert_eq!(texts(&vars, written), vec!["echo", expected], "{written}");
        }

        // inside double quotes `$'` is just a dollar and a quote
        assert_eq!(texts(&vars, "echo \"$'x'\""), vec!["echo", "$'x'"]);
        // the translation form is the plain double-quoted string
        assert_eq!(texts(&vars, "echo $\"x y\" $f"), vec!["echo", "x y", "x"]);
        // an empty one is still an argument
        assert_eq!(texts(&vars, "echo $'' x"), vec!["echo", "", "x"]);
    }

    #[test]
    fn ansi_c_text_that_is_not_text_is_unresolved_not_guessed() {
        let vars = with("f=x", &[("f", "x")]);

        // 0xff is not UTF-8, and U+D800 is not a character
        for written in ["cat $'\\xff'", "cat $'\\ud800'"] {
            assert_eq!(
                expand(&vars, written),
                vec![("cat".to_owned(), false), (written[4..].to_owned(), true)],
                "{written}"
            );
        }
    }

    #[test]
    fn a_backslash_quote_does_not_end_an_ansi_c_string_when_words_are_split() {
        assert_eq!(raw("echo $'it\\'s' x"), vec!["echo", "$'it\\'s'", "x"]);
        assert_eq!(raw("echo $'a b' c"), vec!["echo", "$'a b'", "c"]);
        assert_eq!(raw("echo $'\\\\' x"), vec!["echo", "$'\\\\'", "x"]);
        assert_eq!(raw_words("echo $'unterminated"), None);
        assert_eq!(raw_words("echo $'ends with a backslash\\'"), None);

        assert_eq!(ansi_c_end("$'ab'", 1), Some(4));
        assert_eq!(ansi_c_end("$'a\\'b' x", 1), Some(6));
        assert_eq!(ansi_c_end("$'é\\é'", 1), Some(7));
        assert_eq!(ansi_c_end("$'open", 1), None);
    }

    #[test]
    fn quotes_of_the_other_kind_and_backslashes_inside_quotes_are_text() {
        let vars = with("f=x", &[("f", "x")]);

        assert_eq!(texts(&vars, "echo \"it's\""), vec!["echo", "it's"]);
        assert_eq!(
            texts(&vars, "echo 'say \"hi\"'"),
            vec!["echo", "say \"hi\""]
        );
        assert_eq!(
            texts(&vars, "echo \"a\\\"b\" \"c\\d\" \"\\$f\""),
            vec!["echo", "a\"b", "c\\d", "$f"]
        );
        assert_eq!(
            texts(&vars, "echo a\\ b \\$f \\\\"),
            vec!["echo", "a b", "$f", "\\"]
        );
        assert_eq!(texts(&vars, "echo ''\"\"x"), vec!["echo", "x"]);
        assert_eq!(texts(&vars, "echo é\"é\"$f"), vec!["echo", "ééx"]);
    }

    #[test]
    fn any_short_run_of_special_characters_is_handled_without_hanging_or_panicking() {
        let alphabet = [
            '\'',
            '"',
            '\\',
            '$',
            '{',
            '}',
            ',',
            '~',
            'a',
            '1',
            SUBSTITUTION,
            'é',
            '/',
            '=',
        ];
        let vars = with("a=data", &[("a", "data")]);
        let mut words = vec![String::new()];
        let mut checked = 0;

        for _ in 0..4 {
            let mut next = Vec::new();
            for word in &words {
                for ch in alphabet {
                    let mut longer = word.clone();
                    longer.push(ch);
                    next.push(longer);
                }
            }
            for word in &next {
                // an unterminated quote is rejected by the splitter, not here
                let _ = vars.words(&[word.as_str()], &env());
                let _ = vars.value(word, &env());
                let _ = raw_words(word);
                let _ = brace_expand(word);
                checked += 1;
            }
            words = next;
        }

        assert!(checked > 40_000, "{checked}");
    }

    #[test]
    fn raw_words_keep_quotes_and_split_only_at_unquoted_blanks() {
        assert_eq!(
            raw(r#"cat "a b" 'c d' e\ f g"#),
            vec!["cat", r#""a b""#, "'c d'", r"e\ f", "g"]
        );
        assert_eq!(raw(r#"echo """#), vec!["echo", r#""""#]);
        assert!(raw_words("echo 'open").is_none());
        assert!(raw_words(r#"echo "open"#).is_none());
        assert!(raw_words("echo trailing\\").is_none());
    }

    #[test]
    fn an_assigned_variable_is_substituted_in_every_spelling() {
        let vars = with("f=data/x.csv cat $f", &[("f", "data/x.csv")]);

        for text in ["cat $f", "cat ${f}", "cat \"$f\"", "cat \"${f}\""] {
            assert_eq!(
                expand(&vars, text),
                vec![("cat".to_owned(), false), ("data/x.csv".to_owned(), false)],
                "{text}"
            );
        }
        assert_eq!(
            texts(&vars, "cat $f/../y.csv ${f}.bak"),
            vec!["cat", "data/x.csv/../y.csv", "data/x.csv.bak"]
        );
    }

    #[test]
    fn single_quotes_and_escaped_dollars_are_not_expanded() {
        let vars = with("f=data/x.csv", &[("f", "data/x.csv")]);

        assert_eq!(texts(&vars, "echo '$f' \\$f"), vec!["echo", "$f", "$f"]);
        assert!(
            expand(&vars, "echo '$f' \\$f")
                .iter()
                .all(|(_, flagged)| !flagged)
        );
    }

    #[test]
    fn a_variable_veil_was_not_told_is_unresolved_and_kept_as_written() {
        let vars = Vars::default();

        for (text, written) in [
            ("cat $f", "$f"),
            ("cat ${f}", "${f}"),
            ("cat \"$f\"", "\"$f\""),
            ("cat data/${dir}/x", "data/${dir}/x"),
            ("cat ${f:-x}", "${f:-x}"),
            ("cat ${#f}", "${#f}"),
            ("cat $1", "$1"),
            ("cat $@", "$@"),
            ("cat ~other/x", "~other/x"),
        ] {
            let words = vars.words(&raw(text), &env()).expect("expands");
            assert_eq!(
                words[1].unresolved.as_deref(),
                Some(written),
                "{text}: {words:?}"
            );
        }
    }

    #[test]
    fn home_pwd_and_a_leading_tilde_come_from_the_hook_environment() {
        let vars = Vars::for_command("cat ~/x $HOME/y ${PWD}/z");

        assert_eq!(
            expand(&vars, "cat ~/x $HOME/y ${PWD}/z ~"),
            vec![
                ("cat".to_owned(), false),
                ("/home/me/x".to_owned(), false),
                ("/home/me/y".to_owned(), false),
                ("/work/repo/z".to_owned(), false),
                ("/home/me".to_owned(), false),
            ]
        );

        let without_home = vars
            .words(&raw("cat ~/x $HOME"), &ShellEnv::default())
            .expect("expands");
        assert!(
            without_home[1..]
                .iter()
                .all(|word| word.unresolved.is_some())
        );
    }

    #[test]
    fn pwd_is_not_trusted_once_the_command_changes_directory() {
        for command in [
            "cd data && cat $PWD/x",
            "pushd data; cat $PWD/x",
            "cd -; cat $OLDPWD/x",
        ] {
            let vars = Vars::for_command(command);
            let words = vars
                .words(&raw("cat $PWD/x $OLDPWD/x"), &env())
                .expect("expands");

            assert!(
                words[1..].iter().all(|word| word.unresolved.is_some()),
                "{command}: {words:?}"
            );
        }
    }

    #[test]
    fn numeric_specials_stand_in_as_a_number() {
        let vars = Vars::default();

        assert_eq!(
            expand(&vars, "cat /tmp/out.$$ /tmp/s.$? /tmp/n.$#"),
            vec![
                ("cat".to_owned(), false),
                ("/tmp/out.0".to_owned(), false),
                ("/tmp/s.0".to_owned(), false),
                ("/tmp/n.0".to_owned(), false),
            ]
        );
    }

    #[test]
    fn a_dollar_that_starts_no_expansion_is_text() {
        let vars = Vars::default();

        assert_eq!(
            texts(&vars, "echo $ x 100$ a$"),
            vec!["echo", "$", "x", "100$", "a$"]
        );
        assert!(
            expand(&vars, "echo $ x 100$ a$")
                .iter()
                .all(|(_, flagged)| !flagged)
        );
    }

    #[test]
    fn an_unquoted_value_with_blanks_would_split_so_it_is_unresolved_but_a_quoted_one_is_not() {
        let vars = with("f='a b'", &[("f", "a b")]);

        let unquoted = vars.words(&raw("cat $f"), &env()).expect("expands");
        assert!(unquoted[1].unresolved.is_some());

        let quoted = vars.words(&raw("cat \"$f\""), &env()).expect("expands");
        assert_eq!(quoted[1].text, "a b");
        assert!(quoted[1].unresolved.is_none());
    }

    #[test]
    fn a_value_with_quotes_or_dollars_is_read_back_literally() {
        let vars = with("f=x", &[("f", "it's $HOME \"q\" `x`")]);

        assert_eq!(
            texts(&vars, "echo \"$f\""),
            vec!["echo", "it's $HOME \"q\" `x`"]
        );
    }

    #[test]
    fn an_empty_unquoted_expansion_leaves_no_word_but_a_quoted_one_leaves_an_empty_word() {
        let vars = with("e=", &[("e", "")]);

        assert_eq!(texts(&vars, "cat $e data/x.csv"), vec!["cat", "data/x.csv"]);
        assert_eq!(
            texts(&vars, "cat \"$e\" data/x.csv"),
            vec!["cat", "", "data/x.csv"]
        );
    }

    #[test]
    fn a_command_substitution_marker_is_unresolved() {
        let vars = Vars::default();
        let words = vars
            .words(&raw(&format!("cat {SUBSTITUTION}/x")), &env())
            .expect("expands");

        assert!(words[1].unresolved.is_some());
    }

    #[test]
    fn a_name_assigned_twice_or_by_a_builtin_is_never_trusted() {
        for command in [
            "f=a; f=b; cat $f",
            "if x; then f=a; else f=b; fi; cat $f",
            "f=a; f+=b; cat $f",
            "f=a; while read f; do cat $f; done",
            "f=a; for f in x y; do cat $f; done",
            "f=a; printf -v f %s x; cat $f",
            "f=a; mapfile f < x; cat $f",
            "f=a; read -r f; cat $f",
            "f=a; getopts ab f; cat $f",
        ] {
            let mut vars = Vars::for_command(command);
            vars.assign("f", Some("a".to_owned()));

            let words = vars.words(&raw("cat $f"), &env()).expect("expands");
            assert!(words[1].unresolved.is_some(), "{command}: {words:?}");
        }
    }

    #[test]
    fn a_name_assigned_once_is_trusted_and_other_names_do_not_disturb_it() {
        let command = "f=data/x.csv; g=other; cat $f";
        let mut vars = Vars::for_command(command);
        vars.assign("f", Some("data/x.csv".to_owned()));

        assert_eq!(texts(&vars, "cat $f"), vec!["cat", "data/x.csv"]);
    }

    #[test]
    fn a_value_that_could_not_be_resolved_makes_the_name_unresolved() {
        let mut vars = Vars::for_command("f=$(date); cat $f");
        vars.assign("f", None);

        let words = vars.words(&raw("cat $f"), &env()).expect("expands");
        assert!(words[1].unresolved.is_some());
    }

    #[test]
    fn a_value_is_expanded_from_the_names_before_it() {
        let mut vars = Vars::for_command("a=data; b=$a/clients; cat $b");
        vars.assign("a", Some("data".to_owned()));
        let b = vars.value("$a/clients", &env());
        assert_eq!(b.as_deref(), Some("data/clients"));
        vars.assign("b", b);

        assert_eq!(
            texts(&vars, "cat $b/x.csv"),
            vec!["cat", "data/clients/x.csv"]
        );
        assert_eq!(vars.value("$nothing/x", &env()), None);
        assert_eq!(
            vars.value("\"quoted value\"", &env()).as_deref(),
            Some("quoted value")
        );
        assert_eq!(vars.value("~/x", &env()).as_deref(), Some("/home/me/x"));
    }

    #[test]
    fn scoped_values_apply_to_one_command_and_are_restored() {
        let mut vars = with("f=old g=x", &[("f", "old")]);

        let saved = vars.scoped(&[
            ("f".to_owned(), "new".to_owned()),
            ("g".to_owned(), "gv".to_owned()),
        ]);
        assert_eq!(texts(&vars, "echo $f $g"), vec!["echo", "new", "gv"]);

        vars.restore(saved);
        assert_eq!(texts(&vars, "echo $f"), vec!["echo", "old"]);
        assert!(expand(&vars, "echo $g")[1].1);
    }

    fn pairs(words: &[&str]) -> Option<Vec<(String, String)>> {
        assignment_words(words)
    }

    #[test]
    fn assignment_words_are_recognised_with_and_without_a_declaring_builtin() {
        let expected = |name: &str, value: &str| (name.to_owned(), value.to_owned());

        assert_eq!(
            pairs(&["f=data/x.csv"]),
            Some(vec![expected("f", "data/x.csv")])
        );
        assert_eq!(
            pairs(&["a=1", "b=\"two words\""]),
            Some(vec![expected("a", "1"), expected("b", "\"two words\"")])
        );
        assert_eq!(
            pairs(&["export", "f=x", "g"]),
            Some(vec![expected("f", "x")])
        );
        assert_eq!(
            pairs(&["declare", "-x", "-r", "f=x"]),
            Some(vec![expected("f", "x")])
        );
        assert_eq!(pairs(&["local", "f="]), Some(vec![expected("f", "")]));

        // a command with a prefix assignment, a command, nothing set
        assert_eq!(pairs(&["f=x", "cat", "y"]), None);
        assert_eq!(pairs(&["cat", "f=x"]), None);
        assert_eq!(pairs(&["export"]), None);
        assert_eq!(pairs(&["export", "f"]), None);
        assert_eq!(pairs(&["f+=x"]), None);
    }

    #[test]
    fn only_a_declaration_that_exports_reaches_the_programs_after_it() {
        for words in [
            &["export", "f=x"][..],
            &["export", "-n", "f=x"],
            &["declare", "-x", "f=x"],
            &["declare", "-rx", "f=x"],
            &["typeset", "-x", "f=x"],
        ] {
            assert!(exports_to_environment(words), "{words:?}");
        }

        for words in [
            &["f=x"][..],
            &["declare", "f=x"],
            &["declare", "-r", "f=x"],
            &["local", "f=x"],
            &["readonly", "f=x"],
            // the option after the first word that is not one is the value's
            &["declare", "f=x", "-x"],
            &["cat", "export"],
            &[],
        ] {
            assert!(!exports_to_environment(words), "{words:?}");
        }
    }

    fn braces(word: &str) -> Vec<String> {
        brace_expand(word).expect("should expand")
    }

    #[test]
    fn brace_lists_expand_with_their_preamble_and_postscript() {
        assert_eq!(braces("data/{a,b}.csv"), vec!["data/a.csv", "data/b.csv"]);
        assert_eq!(
            braces("{data,docs}/x.csv"),
            vec!["data/x.csv", "docs/x.csv"]
        );
        assert_eq!(braces("x{a,}y"), vec!["xay", "xy"]);
        assert_eq!(braces("{a,b}{1,2}"), vec!["a1", "a2", "b1", "b2"]);
        assert_eq!(braces("{a,{b,c}}"), vec!["a", "b", "c"]);
        assert_eq!(braces("da{ta,}/x"), vec!["data/x", "da/x"]);
    }

    #[test]
    fn brace_sequences_count_pad_and_step() {
        assert_eq!(braces("f{1..3}"), vec!["f1", "f2", "f3"]);
        assert_eq!(braces("{3..1}"), vec!["3", "2", "1"]);
        assert_eq!(braces("{08..11}"), vec!["08", "09", "10", "11"]);
        assert_eq!(braces("{1..10..4}"), vec!["1", "5", "9"]);
        assert_eq!(braces("{a..d}"), vec!["a", "b", "c", "d"]);
        assert_eq!(braces("{e..c}"), vec!["e", "d", "c"]);
        assert_eq!(braces("{-1..1}"), vec!["-1", "0", "1"]);
    }

    #[test]
    fn braces_that_are_not_lists_stay_as_written() {
        for word in [
            "{}",
            "{a}",
            "a{b",
            "a}b",
            "'{a,b}'",
            "\"{a,b}\"",
            "\\{a,b\\}",
            "${f}",
            "${f:-a,b}",
            "{1..x}",
            "{a..bb}",
            "{1..}",
        ] {
            assert_eq!(braces(word), vec![word.to_owned()], "{word}");
        }
        // the inner list of `{a{b,c}}` is a list, the outer is not
        assert_eq!(braces("{a{b,c}}"), vec!["{ab}", "{ac}"]);
    }

    #[test]
    fn a_list_that_would_expand_too_far_is_left_unresolved() {
        assert!(brace_expand("{1..64}").is_some());
        assert!(brace_expand("{1..65}").is_none());
        assert!(brace_expand("{a,b,c,d,e,f,g,h}{a,b,c,d,e,f,g,h}{a,b}").is_none());

        let vars = Vars::default();
        let words = vars.words(&raw("cat {1..65}"), &env()).expect("expands");
        assert_eq!(words.len(), 2);
        assert_eq!(words[1].unresolved.as_deref(), Some("{1..65}"));
    }

    #[test]
    fn expanded_alternatives_are_separate_words_and_see_variables() {
        let vars = with("d=data", &[("d", "data")]);

        assert_eq!(
            texts(&vars, "cat $d/{a,b}.csv"),
            vec!["cat", "data/a.csv", "data/b.csv"]
        );
        assert_eq!(texts(&vars, "echo {1..3}"), vec!["echo", "1", "2", "3"]);
    }
}
