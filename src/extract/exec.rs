//! bd-5iy: the commands an interpreter's program runs.
//!
//! `cat .env` typed in the shell is a read veil judges. The same string inside a
//! program an interpreter runs (`python3 -c "import os; os.system('cat .env')"`,
//! `awk 'BEGIN{system("cat .env")}'`) is run by the interpreter, and a word that
//! is not a path (`cat .env` is one string with a space in it) was never judged.
//!
//! This module finds the calls that hand a string to the shell or to exec and
//! reads their arguments as literals:
//!
//! - Python: `os.system`, `os.popen`, `subprocess.*`, `os.exec*`, `os.spawn*`,
//!   `commands.getoutput`, `pty.spawn`
//! - Node (and bun, deno): `child_process.exec`, `execSync`, `spawn`, `execFile`,
//!   `Bun.spawn`, `` Bun.$`...` ``, `Deno.Command`
//! - Perl: `system`, `exec`, backticks, `qx`, `readpipe`, a pipe `open`, `open2`
//!   and `open3`
//! - Ruby: `system`, `exec`, `spawn`, backticks, `%x`, `IO.popen`, `Open3.*`,
//!   `Process.spawn`, a pipe `open`
//! - R: `system`, `system2`, `shell`, `pipe`
//! - awk: `system()`, `"cmd" | getline`, `print | "cmd"`
//!
//! A string made of literals (concatenated, or adjacent, or an argument list of
//! them) is a command line, handed back as shell text for the same decomposition
//! a typed command gets. What is built at run time is judged as far as it can be:
//!
//! - an argument list (`["git", "show", rev]`) is read by no shell, so a word it
//!   computes is one unresolved word of the command, judged as `git show $rev`
//!   typed is: a reader or filter given one is denied, other programs only where
//!   a protected path is in play;
//! - a shell string with a part it computes (`"cat " + name`, `f"cat {name}"`, a
//!   variable) is read by a shell, which can turn the part into anything,
//!   `; cat .env` included; and a list whose program is computed runs a program
//!   veil does not know. These calls are `refused`, and the caller treats them
//!   like a word veil cannot resolve.
//!
//! This is best effort, like the rest of veil's reading of programs. A program
//! that reaches exec by another road (`getattr(os, "system")`, an alias of the
//! function, `eval`, a command read from a file) is not seen; only an OS sandbox
//! is airtight.

/// The language of a program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Language {
    Python,
    Node,
    Perl,
    Ruby,
    R,
    Awk,
}

/// What a program runs.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Found {
    /// Every command line a call hands to the shell or to exec, as shell text.
    pub commands: Vec<String>,
    /// The first call whose command is not a literal, as the program wrote it.
    pub refused: Option<String>,
}

/// The most command lines taken from one program. A program with more is
/// refused, so that a file of `system("...")` cannot make judging it slow.
const MAX_COMMANDS: usize = 128;

/// The most tokens looked at to find the end of an argument or a call. An
/// argument longer than this is not one veil follows to its end.
const MAX_SPAN: usize = 512;

/// The most items taken from one list.
const MAX_ITEMS: usize = 256;

/// What stands in a command line for a word the program computes: a variable
/// nothing assigns, which the decomposer turns into an unresolved word. It is
/// the word the reason shows.
const COMPUTED: &str = "$value_the_program_computes";

/// The commands `text`, a program in `language`, runs.
pub(super) fn find(language: Language, text: &str) -> Found {
    let tokens = lex(language, text);
    let parser = Parser {
        language,
        text,
        tokens: &tokens,
        child_process: mentions(text, &["child_process", "Bun", "Deno"]),
        subprocess: mentions(text, &["subprocess"]),
    };
    let mut found = Found::default();

    parser.calls(&mut found);
    if found.commands.len() > MAX_COMMANDS {
        found.commands.truncate(MAX_COMMANDS);
        found
            .refused
            .get_or_insert_with(|| format!("more than {MAX_COMMANDS} commands in one program"));
    }
    found
}

fn mentions(text: &str, names: &[&str]) -> bool {
    names.iter().any(|name| text.contains(name))
}

// ---- the programs a command line holds ---------------------------------------

/// The programs on an interpreter's command line, and the awk program files.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Programs {
    pub language: Option<Language>,
    /// The code given in the command (`-c`, `-e`, awk's program word).
    pub inline: Vec<String>,
    /// Awk program files (`-f`), which the caller reads.
    pub files: Vec<String>,
}

/// The code in the command `name args`: nothing for a program that is no
/// interpreter or runs a file.
pub(super) fn programs(name: &str, args: &[String]) -> Programs {
    let mut found = Programs::default();

    if is_awk(name) {
        found.language = Some(Language::Awk);
        awk_programs(args, &mut found);
        return found;
    }

    let (language, base) = match super::interpreter_kind(name) {
        Some(super::InterpreterKind::Python) => (Language::Python, Style::Python),
        Some(super::InterpreterKind::Node) => (Language::Node, Style::Node),
        Some(super::InterpreterKind::Perl) => (Language::Perl, Style::Perl),
        Some(super::InterpreterKind::Ruby) => (Language::Ruby, Style::Ruby),
        Some(super::InterpreterKind::R) => (Language::R, Style::R),
        // a shell runs its `-c` string through the wrappers, not through here
        Some(super::InterpreterKind::Shell) => return found,
        None if name == "R" => (Language::R, Style::R),
        None => return found,
    };
    found.language = Some(language);

    let rest = if name == "deno" {
        // `deno eval CODE`
        match args.iter().position(|word| !word.starts_with('-')) {
            Some(index) if args[index] == "eval" => &args[index + 1..],
            _ => return found,
        }
    } else {
        args
    };
    style_programs(base, rest, name == "deno", &mut found.inline);
    found
}

pub(super) fn is_awk(name: &str) -> bool {
    matches!(name, "awk" | "gawk" | "mawk" | "nawk")
}

/// How an interpreter spells its command-line options.
#[derive(Clone, Copy)]
enum Style {
    Python,
    Node,
    Perl,
    Ruby,
    R,
}

impl Style {
    /// The short options whose value is the code.
    fn code(self) -> &'static [char] {
        match self {
            Self::Python => &['c'],
            Self::Node => &['e', 'p'],
            Self::Perl => &['e', 'E'],
            Self::Ruby | Self::R => &['e'],
        }
    }

    /// The short options that take a value that is not code: the rest of the
    /// word, or the next word.
    fn value(self) -> &'static [char] {
        match self {
            Self::Python => &['W', 'X', 'Q'],
            Self::Node => &['r', 'C'],
            Self::Perl => &['I'],
            Self::Ruby => &['r', 'I', 'C', 'E'],
            Self::R => &[],
        }
    }

    /// The short options whose value, if any, is the rest of the same word: what
    /// follows them is not a cluster of options.
    fn attached(self) -> &'static [char] {
        match self {
            Self::Perl => &['M', 'm', 'i', 'F', 'x', 'C', 'd', 'D', '0'],
            Self::Ruby => &['K', 'x', 'F', 'i', '0'],
            Self::Python | Self::Node | Self::R => &[],
        }
    }

    /// Long options that take the next word, and the long options that are code.
    fn long_with_value(self) -> &'static [&'static str] {
        match self {
            Self::Node => &[
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--conditions",
                "--input-type",
                "--env-file",
                "--title",
            ],
            Self::Python => &["--check-hash-based-pycs"],
            Self::Perl | Self::Ruby | Self::R => &[],
        }
    }

    fn long_code(self) -> &'static [&'static str] {
        match self {
            Self::Node => &["--eval", "--print"],
            _ => &[],
        }
    }
}

/// The code among `args`, up to the first word that is a script file or `--`.
fn style_programs(style: Style, args: &[String], deno_eval: bool, out: &mut Vec<String>) {
    let mut index = 0;

    while index < args.len() {
        let word = args[index].as_str();
        index += 1;

        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (format!("--{name}"), Some(value)),
                None => (word.to_owned(), None),
            };

            if style.long_code().contains(&name.as_str()) {
                match attached {
                    Some(value) => out.push(value.to_owned()),
                    None => {
                        if let Some(code) = args.get(index) {
                            out.push(code.clone());
                            index += 1;
                        }
                    }
                }
            } else if attached.is_none() && style.long_with_value().contains(&name.as_str()) {
                index += 1;
            }
            continue;
        }
        if word.len() > 1 && word.starts_with('-') {
            for (position, option) in word.char_indices().skip(1) {
                let rest = &word[position + option.len_utf8()..];

                if style.code().contains(&option) {
                    // `-pe CODE`: `p` prints, `e` takes the code
                    if matches!(style, Style::Node) && option == 'p' && !rest.is_empty() {
                        continue;
                    }
                    if !rest.is_empty() {
                        out.push(rest.to_owned());
                    } else if let Some(code) = args.get(index) {
                        out.push(code.clone());
                        index += 1;
                    }
                    break;
                }
                // `-m module`: what follows is the module's
                if matches!(style, Style::Python) && option == 'm' {
                    return;
                }
                if style.value().contains(&option) {
                    if rest.is_empty() {
                        index += 1;
                    }
                    break;
                }
                if style.attached().contains(&option) {
                    break;
                }
            }
            continue;
        }
        if deno_eval {
            // `deno eval CODE`: the first word that is not an option
            out.push(word.to_owned());
            break;
        }
        // a script file: the rest is its arguments
        break;
    }
}

/// An awk command line: the program is the first word that is not an option,
/// unless `-f` names the program files (or `-e` gives the source, in gawk).
fn awk_programs(args: &[String], found: &mut Programs) {
    const WITH_VALUE: &[&str] = &[
        "-v",
        "-F",
        "-i",
        "-l",
        "-W",
        "-E",
        "--assign",
        "--field-separator",
        "--include",
        "--load",
        "--exec",
    ];
    let mut index = 0;
    let mut explicit = false;

    while index < args.len() {
        let word = args[index].as_str();
        index += 1;

        if word == "--" {
            // options end; the program is the next word
            if !explicit && let Some(program) = args.get(index) {
                found.inline.push(program.clone());
            }
            break;
        }
        if let Some(name) = word.strip_prefix("--file=") {
            found.files.push(name.to_owned());
            explicit = true;
        } else if let Some(source) = word.strip_prefix("--source=") {
            found.inline.push(source.to_owned());
            explicit = true;
        } else if word == "--file" || word == "-f" {
            if let Some(name) = args.get(index) {
                found.files.push(name.clone());
                index += 1;
            }
            explicit = true;
        } else if word == "--source" || word == "-e" {
            if let Some(source) = args.get(index) {
                found.inline.push(source.clone());
                index += 1;
            }
            explicit = true;
        } else if let Some(name) = word.strip_prefix("-f").filter(|name| !name.is_empty()) {
            found.files.push(name.to_owned());
            explicit = true;
        } else if WITH_VALUE.contains(&word) {
            index += 1;
        } else if word.starts_with('-') && word.len() > 1 {
            // `-F,`, `-vx=1`, `--posix`: nothing more to take
        } else {
            if !explicit {
                found.inline.push(word.to_owned());
            }
            break;
        }
    }
}

// ---- the tokens of a program --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// A name, a number, a `$name` or `@name`.
    Word,
    Str,
    /// A backtick or `qx` string in a language that runs it.
    Command,
    Punct,
    Newline,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    /// The name, the content of a string, or the punctuation.
    text: String,
    /// A string with something put into it at run time: `f"{x}"`, `"$x"`,
    /// `"#{x}"`, `` `${x}` ``.
    dynamic: bool,
    /// A string quoted with backticks.
    backtick: bool,
    start: usize,
    end: usize,
}

impl Token {
    fn is(&self, kind: Kind, text: &str) -> bool {
        self.kind == kind && self.text == text
    }

    fn punct(&self, text: &str) -> bool {
        self.is(Kind::Punct, text)
    }

    fn word(&self, text: &str) -> bool {
        self.is(Kind::Word, text)
    }
}

struct Lexer<'a> {
    language: Language,
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
    tokens: Vec<Token>,
}

fn lex(language: Language, text: &str) -> Vec<Token> {
    let mut lexer = Lexer {
        language,
        text,
        bytes: text.as_bytes(),
        index: 0,
        tokens: Vec::new(),
    };

    lexer.run();
    lexer.tokens
}

impl Lexer<'_> {
    fn push(&mut self, kind: Kind, text: String, start: usize) {
        self.tokens.push(Token {
            kind,
            text,
            dynamic: false,
            backtick: false,
            start,
            end: self.index,
        });
    }

    fn peek(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.index + offset).copied()
    }

    fn newlines_matter(&self) -> bool {
        matches!(self.language, Language::Ruby | Language::Awk)
    }

    fn run(&mut self) {
        while self.index < self.bytes.len() {
            let byte = self.bytes[self.index];
            let start = self.index;

            if byte == b'\n' {
                self.index += 1;
                if self.newlines_matter() {
                    self.push(Kind::Newline, String::new(), start);
                }
            } else if byte.is_ascii_whitespace() {
                self.index += 1;
            } else if self.language == Language::Awk && byte == b'\\' && self.peek(1) == Some(b'\n')
            {
                // a line continued
                self.index += 2;
            } else if self.comment(byte) {
                // skipped
            } else if matches!(byte, b'\'' | b'"' | b'`') {
                self.quoted(byte, start, "");
            } else if self.language == Language::Awk && byte == b'/' && self.regex_allowed() {
                self.skip_regex();
            } else if self.language == Language::Python
                && byte == b'\\'
                && self.peek(1) == Some(b'\n')
            {
                // a line continued
                self.index += 2;
            } else if byte.is_ascii_alphanumeric()
                || byte == b'_'
                || (matches!(byte, b'$' | b'@')
                    && matches!(self.language, Language::Perl | Language::Ruby)
                    && self
                        .peek(1)
                        .is_some_and(|next| next.is_ascii_alphanumeric() || next == b'_'))
                || byte >= 0x80
            {
                self.word(start);
            } else if self.language == Language::Ruby && byte == b'%' && self.percent_literal(start)
            {
                // `%w(a b)`, `%x(cmd)`: pushed
            } else {
                self.operator(start);
            }
        }
    }

    /// Skips a comment that starts at the current byte.
    fn comment(&mut self, byte: u8) -> bool {
        let line_comment = match self.language {
            Language::Node => byte == b'/' && self.peek(1) == Some(b'/'),
            Language::Perl => {
                byte == b'#'
                    && self
                        .index
                        .checked_sub(1)
                        .is_none_or(|before| self.bytes[before] != b'$')
            }
            _ => byte == b'#',
        };
        if line_comment {
            while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                self.index += 1;
            }
            return true;
        }
        if self.language == Language::Node && byte == b'/' && self.peek(1) == Some(b'*') {
            self.index += 2;
            while self.index < self.bytes.len()
                && !(self.bytes[self.index] == b'*' && self.peek(1) == Some(b'/'))
            {
                self.index += 1;
            }
            self.index = (self.index + 2).min(self.bytes.len());
            return true;
        }
        false
    }

    /// Whether a `/` here starts an awk regular expression: it does where an
    /// operand is expected.
    fn regex_allowed(&self) -> bool {
        match self.tokens.last() {
            None => true,
            Some(token) => match token.kind {
                Kind::Word => matches!(token.text.as_str(), "print" | "printf" | "return" | "in"),
                Kind::Str | Kind::Command => false,
                Kind::Newline => true,
                Kind::Punct => !matches!(token.text.as_str(), ")" | "]"),
            },
        }
    }

    fn skip_regex(&mut self) {
        self.index += 1;
        while self.index < self.bytes.len() {
            match self.bytes[self.index] {
                b'\\' => self.index += 2,
                b'/' => {
                    self.index += 1;
                    return;
                }
                b'\n' => return,
                _ => self.index += 1,
            }
        }
        self.index = self.index.min(self.bytes.len());
    }

    fn word(&mut self, start: usize) {
        if matches!(self.bytes[self.index], b'$' | b'@') {
            self.index += 1;
        }
        while self.index < self.bytes.len()
            && (self.bytes[self.index].is_ascii_alphanumeric()
                || self.bytes[self.index] == b'_'
                || self.bytes[self.index] >= 0x80)
        {
            self.index += 1;
        }
        let name = self.text[start..self.index].to_owned();

        // a string prefix: `r"..."`, `f'...'`, `rb"..."`
        if self.language == Language::Python
            && name.len() <= 2
            && name
                .bytes()
                .all(|byte| matches!(byte.to_ascii_lowercase(), b'r' | b'b' | b'u' | b'f'))
            && matches!(self.peek(0), Some(b'\'' | b'"'))
        {
            let quote = self.bytes[self.index];
            self.quoted(quote, start, &name.to_ascii_lowercase());
            return;
        }
        // Perl's quote-like operators: `q(..)`, `qq{..}`, `qw/../`, `qx'..'`
        if self.language == Language::Perl
            && matches!(name.as_str(), "q" | "qq" | "qw" | "qx")
            && self.quote_like_follows()
        {
            self.quote_like(&name, start);
            return;
        }

        self.push(Kind::Word, name, start);
    }

    fn quote_like_follows(&self) -> bool {
        !self.tokens.last().is_some_and(|token| token.punct("->"))
            && matches!(
                self.peek(0),
                Some(b'(' | b'[' | b'{' | b'<' | b'|' | b'!' | b'/' | b'\'' | b'"')
            )
    }

    /// `q(..)`, `qq(..)`, `qw(..)`, `qx(..)` and the Ruby `%`-literals: the body
    /// between the delimiters, which nest when they are brackets.
    fn delimited(&mut self) -> Option<String> {
        let open = self.bytes[self.index];
        let close = match open {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            other => other,
        };
        let mut depth = 0usize;
        let mut index = self.index + 1;
        let mut body = Vec::new();

        while index < self.bytes.len() {
            let byte = self.bytes[index];
            if byte == b'\\' && index + 1 < self.bytes.len() {
                body.push(byte);
                body.push(self.bytes[index + 1]);
                index += 2;
                continue;
            }
            if byte == close && depth == 0 {
                self.index = index + 1;
                return Some(String::from_utf8_lossy(&body).into_owned());
            }
            if open != close && byte == open {
                depth += 1;
            } else if open != close && byte == close {
                depth -= 1;
            }
            body.push(byte);
            index += 1;
        }
        None
    }

    fn quote_like(&mut self, name: &str, start: usize) {
        let Some(body) = self.delimited() else {
            self.push(Kind::Word, name.to_owned(), start);
            return;
        };

        match name {
            "qw" => {
                self.push(Kind::Punct, "[".to_owned(), start);
                for (position, word) in body.split_whitespace().enumerate() {
                    if position > 0 {
                        self.push(Kind::Punct, ",".to_owned(), start);
                    }
                    self.push(Kind::Str, word.to_owned(), start);
                }
                self.push(Kind::Punct, "]".to_owned(), start);
            }
            "q" => self.push(Kind::Str, unescape(&body, Escapes::Single, true), start),
            "qq" => {
                let dynamic = interpolates(self.language, &body);
                self.push(Kind::Str, unescape(&body, Escapes::Double, true), start);
                self.mark_last(dynamic, false);
            }
            _ => {
                let dynamic = interpolates(self.language, &body);
                self.push(Kind::Command, unescape(&body, Escapes::Double, true), start);
                self.mark_last(dynamic, false);
            }
        }
    }

    fn mark_last(&mut self, dynamic: bool, backtick: bool) {
        if let Some(token) = self.tokens.last_mut() {
            token.dynamic = dynamic;
            token.backtick = backtick;
        }
    }

    /// `%w(a b)`, `%i(a b)`, `%q(..)`, `%Q(..)`, `%x(..)` in Ruby.
    fn percent_literal(&mut self, start: usize) -> bool {
        let operand_expected = match self.tokens.last() {
            None => true,
            Some(token) => match token.kind {
                Kind::Word => matches!(
                    token.text.as_str(),
                    "system" | "exec" | "spawn" | "puts" | "return" | "popen" | "open" | "print"
                ),
                Kind::Str | Kind::Command => false,
                Kind::Newline => true,
                Kind::Punct => !matches!(token.text.as_str(), ")" | "]" | "}"),
            },
        };
        if !operand_expected {
            return false;
        }

        let saved = self.index;
        self.index += 1;
        let letter = match self.peek(0) {
            Some(byte @ (b'w' | b'W' | b'i' | b'I' | b'q' | b'Q' | b'x')) => {
                self.index += 1;
                byte
            }
            Some(b'(' | b'[' | b'{' | b'<' | b'|' | b'!') => b'Q',
            _ => {
                self.index = saved;
                return false;
            }
        };
        if !matches!(
            self.peek(0),
            Some(b'(' | b'[' | b'{' | b'<' | b'|' | b'!' | b'/')
        ) {
            self.index = saved;
            return false;
        }
        let Some(body) = self.delimited() else {
            self.index = saved;
            return false;
        };

        match letter {
            b'w' | b'W' | b'i' | b'I' => {
                self.push(Kind::Punct, "[".to_owned(), start);
                for (position, word) in body.split_whitespace().enumerate() {
                    if position > 0 {
                        self.push(Kind::Punct, ",".to_owned(), start);
                    }
                    self.push(Kind::Str, word.to_owned(), start);
                }
                self.push(Kind::Punct, "]".to_owned(), start);
            }
            b'q' => self.push(Kind::Str, unescape(&body, Escapes::Single, true), start),
            b'Q' => {
                let dynamic = interpolates(self.language, &body);
                self.push(Kind::Str, unescape(&body, Escapes::Double, true), start);
                self.mark_last(dynamic, false);
            }
            _ => {
                let dynamic = interpolates(self.language, &body);
                self.push(Kind::Command, unescape(&body, Escapes::Double, true), start);
                self.mark_last(dynamic, false);
            }
        }
        true
    }

    fn operator(&mut self, start: usize) {
        const TWO: &[&str] = &[
            "||", "|&", "&&", "=>", "->", "::", "==", "!=", "<=", ">=", "=~",
        ];
        let two = self.text.get(self.index..self.index + 2);

        if let Some(two) = two.filter(|two| TWO.contains(two)) {
            self.index += 2;
            self.push(Kind::Punct, two.to_owned(), start);
            return;
        }
        let character = self.text[self.index..]
            .chars()
            .next()
            .map_or(String::new(), String::from);
        self.index += character.len().max(1);
        self.push(Kind::Punct, character, start);
    }

    /// A string that starts at the current quote. A string with no end on its
    /// line is no string (a backtick string, and a Python triple-quoted one, may
    /// run on): its quote is punctuation, so that a stray one cannot swallow the
    /// rest of the program.
    fn quoted(&mut self, quote: u8, start: usize, prefix: &str) {
        let triple = self.language == Language::Python
            && quote != b'`'
            && self.peek(1) == Some(quote)
            && self.peek(2) == Some(quote);
        let begin = self.index + if triple { 3 } else { 1 };
        let mut index = begin;
        let mut end = None;

        while index < self.bytes.len() {
            let byte = self.bytes[index];

            if byte == b'\\' && !(self.language == Language::Awk && index + 1 >= self.bytes.len()) {
                index += 2;
                continue;
            }
            if triple {
                if byte == quote
                    && self.bytes.get(index + 1) == Some(&quote)
                    && self.bytes.get(index + 2) == Some(&quote)
                {
                    end = Some(index);
                    break;
                }
            } else if byte == quote {
                end = Some(index);
                break;
            } else if byte == b'\n' && quote != b'`' {
                break;
            }
            index += 1;
        }

        let Some(end) = end else {
            self.index += 1;
            self.push(Kind::Punct, (quote as char).to_string(), start);
            return;
        };

        let body = &self.text[begin..end.min(self.bytes.len())];
        self.index = end + if triple { 3 } else { 1 };

        let raw = prefix.contains('r');
        let escapes = match (self.language, quote) {
            (Language::Perl | Language::Ruby, b'\'') => Escapes::Single,
            _ => Escapes::Double,
        };
        let (kind, backtick) = match (self.language, quote) {
            (Language::Perl | Language::Ruby, b'`') => (Kind::Command, true),
            (_, b'`') => (Kind::Str, true),
            _ => (Kind::Str, false),
        };
        let dynamic = match (self.language, quote) {
            (Language::Python, _) => prefix.contains('f') && python_interpolates(body),
            (Language::Node, b'`') => body.contains("${"),
            (Language::Perl | Language::Ruby, b'\'') => false,
            (Language::Perl | Language::Ruby, _) => interpolates(self.language, body),
            _ => false,
        };
        let text = if raw {
            body.to_owned()
        } else {
            unescape(body, escapes, self.language != Language::Python)
        };

        self.push(kind, text, start);
        self.mark_last(dynamic, backtick);
    }
}

/// Whether a Python f-string body puts anything in at run time (`{x}`; `{{` is a
/// brace).
fn python_interpolates(body: &str) -> bool {
    let mut chars = body.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
            }
            '{' => return true,
            _ => {}
        }
    }
    false
}

/// Whether a double-quoted Perl or Ruby string body puts anything in at run
/// time: `$x`, `@x`, `${x}` in Perl, `#{x}`, `#$x`, `#@x` in Ruby.
fn interpolates(language: Language, body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();

        if byte == b'\\' {
            index += 2;
            continue;
        }
        let hit = match language {
            Language::Perl => match byte {
                b'$' => next.is_some_and(|next| {
                    next.is_ascii_alphanumeric() || matches!(next, b'_' | b'{' | b'$' | b'&' | b'!')
                }),
                b'@' => next.is_some_and(|next| {
                    next.is_ascii_alphabetic() || matches!(next, b'_' | b'{' | b'$')
                }),
                _ => false,
            },
            Language::Ruby => byte == b'#' && matches!(next, Some(b'{' | b'$' | b'@')),
            _ => false,
        };
        if hit {
            return true;
        }
        index += 1;
    }
    false
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Escapes {
    /// Perl and Ruby single quotes: only `\\` and `\'` are escapes.
    Single,
    Double,
}

/// The text a string body stands for. `drop_unknown`: a backslash before a
/// character that is no escape is dropped (Python keeps it).
fn unescape(body: &str, escapes: Escapes, drop_unknown: bool) -> String {
    if !body.contains('\\') {
        return body.to_owned();
    }
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();

    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        let Some(next) = chars.next() else {
            out.push('\\');
            break;
        };

        if escapes == Escapes::Single {
            if matches!(next, '\\' | '\'') {
                out.push(next);
            } else {
                out.push('\\');
                out.push(next);
            }
            continue;
        }

        match next {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            'e' => out.push('\u{1b}'),
            '\n' => {}
            'x' => hex(&mut chars, 2, &mut out, drop_unknown),
            'u' if chars.peek() == Some(&'{') => {
                chars.next();
                let digits: String = chars.by_ref().take_while(|digit| *digit != '}').collect();
                if let Some(decoded) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(decoded);
                }
            }
            'u' => hex(&mut chars, 4, &mut out, drop_unknown),
            '0'..='7' => {
                let mut value = next.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.peek().and_then(|digit| digit.to_digit(8)) {
                        Some(digit) => {
                            value = value * 8 + digit;
                            chars.next();
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
            }
            '\\' | '\'' | '"' | '`' | '$' | '@' | '#' | '/' | ' ' => out.push(next),
            other => {
                if !drop_unknown {
                    out.push('\\');
                }
                out.push(other);
            }
        }
    }
    out
}

/// `\xNN` and `\uNNNN`: the character, when `count` hex digits follow.
fn hex(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    count: usize,
    out: &mut String,
    drop_unknown: bool,
) {
    let mut digits = String::new();

    while digits.len() < count {
        match chars.peek() {
            Some(digit) if digit.is_ascii_hexdigit() => {
                digits.push(*digit);
                chars.next();
            }
            _ => break,
        }
    }
    match u32::from_str_radix(&digits, 16)
        .ok()
        .filter(|_| digits.len() == count)
        .and_then(char::from_u32)
    {
        Some(decoded) => out.push(decoded),
        None => {
            if !drop_unknown {
                out.push('\\');
            }
            out.push('x');
            out.push_str(&digits);
        }
    }
}

// ---- the calls ---------------------------------------------------------------

/// What an argument is.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Str(String),
    List(Vec<Value>),
    /// `{ ... }`: options, or an environment; neither is a command.
    Object,
    /// Not a literal.
    Dynamic,
}

#[derive(Clone, Debug)]
struct Item {
    /// `shell=True`, `args=...`: the name of a keyword argument.
    keyword: Option<String>,
    value: Value,
    /// The first word of the argument, as written (`True` in `shell=True`).
    first: Option<String>,
    /// The tokens of the argument: from, to (not included).
    span: (usize, usize),
}

/// The arguments of a call, and the token after them.
struct Arguments {
    items: Vec<Item>,
    next: usize,
    /// Every argument was followed to its end.
    complete: bool,
}

/// How a call turns its arguments into commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
    /// The first argument is shell text (`os.system`, `exec`, `system()`).
    Shell,
    /// `subprocess.run`: shell text, or an argument list.
    Subprocess,
    /// `spawn`, `execFile`: the program, then a list of its arguments.
    Argv,
    /// `os.execvp`, `os.spawnlp`: a list, or the words after `skip` arguments.
    Exec(usize),
    /// Every literal string among the arguments is a word of one command.
    Words,
    /// `system` in Perl and Ruby: one argument is shell text, several are a
    /// command and its arguments; `skip` handles come first.
    Auto(usize),
    /// `open` with a pipe in the file name.
    Pipe,
}

struct Parser<'a> {
    language: Language,
    text: &'a str,
    tokens: &'a [Token],
    child_process: bool,
    subprocess: bool,
}

/// What ends the arguments of a call written without parentheses.
const STATEMENT_ENDS: &[&str] = &[
    "if", "unless", "or", "and", "do", "then", "rescue", "end", "while", "until", "foreach", "for",
];

impl Parser<'_> {
    fn token(&self, index: usize) -> Option<&Token> {
        self.tokens.get(index)
    }

    fn calls(&self, found: &mut Found) {
        if self.language == Language::Awk {
            self.awk_calls(found);
        }

        for index in 0..self.tokens.len() {
            let token = &self.tokens[index];

            match token.kind {
                // a backtick string run as a command (Perl, Ruby, `qx`)
                Kind::Command => self.record(&self.string_call(index, index), found),
                Kind::Word => {
                    if let Some(site) = self.site(index) {
                        self.record(&site, found);
                    }
                }
                // Bun's shell: $`cat .env`
                Kind::Punct
                    if self.language == Language::Node
                        && token.text == "$"
                        && self.token(index + 1).is_some_and(|next| next.backtick) =>
                {
                    self.record(&self.string_call(index, index + 1), found);
                }
                _ => {}
            }
        }
    }

    /// The command a string token is, as a call: a backtick string, `qx`.
    fn string_call(&self, label: usize, string: usize) -> CallSite {
        let token = &self.tokens[string];

        CallSite {
            start: label,
            label,
            args: Arguments {
                items: vec![Item {
                    keyword: None,
                    value: if token.dynamic {
                        Value::Dynamic
                    } else {
                        Value::Str(token.text.clone())
                    },
                    first: None,
                    span: (string, string + 1),
                }],
                next: string + 1,
                complete: true,
            },
            call: Call::Shell,
        }
    }

    /// The call at `index`, when the word there is one that runs a command.
    fn site(&self, index: usize) -> Option<CallSite> {
        let name = self.tokens[index].text.as_str();
        let before = index.checked_sub(1).and_then(|before| self.token(before));

        if before.is_some_and(|token| {
            (token.kind == Kind::Word
                && matches!(token.text.as_str(), "def" | "function" | "sub" | "class" | "fn"))
                // `$object->system(1)` is a method of an object
                || (self.language == Language::Perl && token.punct("->"))
        }) {
            return None;
        }
        let qualifier = self.qualifier(index);
        let call = self.classify(name, &qualifier)?;

        let open = self.token(index + 1);
        let (arguments, label) = if open.is_some_and(|token| token.punct("(")) {
            (self.arguments(index + 2, true), index)
        } else if matches!(self.language, Language::Perl | Language::Ruby) {
            let next = open?;
            let starts_arguments = match next.kind {
                Kind::Str | Kind::Command => true,
                Kind::Word => !STATEMENT_ENDS.contains(&next.text.as_str()),
                Kind::Punct => matches!(next.text.as_str(), "[" | "{" | "\\"),
                Kind::Newline => false,
            };
            if !starts_arguments {
                return None;
            }
            (self.arguments(index + 1, false), index)
        } else {
            return None;
        };

        Some(CallSite {
            start: index,
            label,
            args: arguments,
            call,
        })
    }

    /// The names before a call: `os` and `subprocess` in `os.system(..)`.
    fn qualifier(&self, index: usize) -> Vec<&str> {
        let mut names = Vec::new();
        let mut position = index;

        while position >= 2
            && matches!(self.tokens[position - 1].text.as_str(), "." | "::" | "->")
            && self.tokens[position - 1].kind == Kind::Punct
            && self.tokens[position - 2].kind == Kind::Word
            && names.len() < 4
        {
            names.push(self.tokens[position - 2].text.as_str());
            position -= 2;
        }
        names.reverse();
        names
    }

    fn classify(&self, name: &str, qualifier: &[&str]) -> Option<Call> {
        let owner = qualifier.last().copied();

        match self.language {
            Language::Python => match name {
                "system" | "popen" | "popen2" | "popen3" | "popen4" | "getoutput"
                | "getstatusoutput" => Some(Call::Shell),
                "check_output" | "check_call" | "Popen" => Some(Call::Subprocess),
                "run" | "call" if self.subprocess => Some(Call::Subprocess),
                "execl" | "execle" | "execlp" | "execlpe" | "execv" | "execve" | "execvp"
                | "execvpe" => Some(Call::Exec(1)),
                "spawnl" | "spawnle" | "spawnlp" | "spawnlpe" | "spawnv" | "spawnve"
                | "spawnvp" | "spawnvpe" => Some(Call::Exec(2)),
                "posix_spawn" | "posix_spawnp" => Some(Call::Exec(1)),
                "spawn" if owner == Some("pty") => Some(Call::Subprocess),
                _ => None,
            },
            Language::Node => match name {
                "execSync" => Some(Call::Shell),
                "execFileSync" | "spawnSync" | "execFile" => Some(Call::Argv),
                "exec" if self.child_process && owner != Some("RegExp") => Some(Call::Shell),
                "spawn" if self.child_process && owner == Some("Bun") => Some(Call::Words),
                "spawn" if self.child_process => Some(Call::Argv),
                "run" | "Command" if owner == Some("Deno") => Some(Call::Words),
                _ => None,
            },
            Language::Perl => match name {
                "system" | "exec" => Some(Call::Auto(0)),
                "readpipe" => Some(Call::Shell),
                "open2" => Some(Call::Auto(2)),
                "open3" => Some(Call::Auto(3)),
                "open" => Some(Call::Pipe),
                _ => None,
            },
            Language::Ruby => match name {
                "system" | "exec" | "spawn" => Some(Call::Auto(0)),
                "popen" => Some(Call::Auto(0)),
                "capture2" | "capture2e" | "capture3" | "popen2" | "popen2e" | "popen3"
                    if owner == Some("Open3") =>
                {
                    Some(Call::Auto(0))
                }
                "pipeline" | "pipeline_r" | "pipeline_w" | "pipeline_rw" | "pipeline_start"
                    if owner == Some("Open3") =>
                {
                    Some(Call::Auto(0))
                }
                // `open("| cmd")` runs a command; `File.open` does not
                "open" if matches!(owner, None | Some("Kernel" | "IO")) => Some(Call::Pipe),
                "read" | "readlines" | "foreach" if owner == Some("IO") => Some(Call::Pipe),
                _ => None,
            },
            Language::R => match name {
                "system" | "shell" | "pipe" | "shell.exec" => Some(Call::Shell),
                "system2" => Some(Call::Argv),
                _ => None,
            },
            Language::Awk => (name == "system").then_some(Call::Shell),
        }
    }

    // ---- arguments ----

    /// The arguments that start at token `start`: to the `)` that closes the call
    /// when `paren`, else to the end of the statement.
    fn arguments(&self, start: usize, paren: bool) -> Arguments {
        let mut items = Vec::new();
        let mut index = start;
        let mut complete = true;

        loop {
            index = self.skip_newlines(index, paren);
            let Some(token) = self.token(index) else {
                // a call that is never closed is not followed to its end
                complete = !paren;
                break;
            };
            if paren && token.punct(")") {
                index += 1;
                break;
            }
            if !paren && self.statement_ends(token) {
                break;
            }
            if items.len() >= MAX_ITEMS {
                complete = false;
                break;
            }

            let keyword = self.keyword(index);
            if keyword.is_some() {
                index += 2;
            }
            let from = index;
            let first = self.token(index).map(|token| token.text.clone());
            let (value, next) = self.value(index, paren);
            index = self.skip_newlines(next, paren);
            items.push(Item {
                keyword,
                value,
                first,
                span: (from, next),
            });

            match self.token(index) {
                Some(token) if token.punct(",") => index += 1,
                Some(token) if token.punct("=>") => index += 1,
                Some(token) if paren && token.punct(")") => {
                    index += 1;
                    break;
                }
                Some(token) if !paren && self.statement_ends(token) => break,
                Some(_) => {
                    // something follows the argument that veil did not expect
                    complete = false;
                    index = self.skip_to_close(index, paren);
                    if self.token(index).is_some_and(|token| token.punct(")")) && paren {
                        index += 1;
                    }
                    break;
                }
                None => {
                    complete = !paren;
                    break;
                }
            }
        }

        Arguments {
            items,
            next: index,
            complete,
        }
    }

    fn skip_newlines(&self, mut index: usize, inside_parentheses: bool) -> usize {
        while inside_parentheses
            && self
                .token(index)
                .is_some_and(|token| token.kind == Kind::Newline)
        {
            index += 1;
        }
        index
    }

    fn statement_ends(&self, token: &Token) -> bool {
        match token.kind {
            Kind::Newline => true,
            Kind::Punct => matches!(token.text.as_str(), ";" | "}" | ")" | "||" | "&&"),
            Kind::Word => STATEMENT_ENDS.contains(&token.text.as_str()),
            _ => false,
        }
    }

    /// `name=` (Python and R), `name:` (Ruby, JavaScript): a keyword argument.
    fn keyword(&self, index: usize) -> Option<String> {
        let name = self.token(index)?;
        let mark = self.token(index + 1)?;

        if name.kind != Kind::Word || mark.kind != Kind::Punct {
            return None;
        }
        let keyword = matches!(
            (self.language, mark.text.as_str()),
            (Language::Python | Language::R, "=") | (Language::Ruby | Language::Node, ":")
        );
        keyword.then(|| name.text.clone())
    }

    /// One argument that starts at `index`, and the token after it.
    fn value(&self, index: usize, paren: bool) -> (Value, usize) {
        let Some(token) = self.token(index) else {
            return (Value::Dynamic, index);
        };

        if token.punct("[") {
            return self.list(index + 1, "]");
        }
        // `system(*%w(cat .env))`: the list is the arguments
        if token.punct("*") && matches!(self.language, Language::Ruby | Language::Python) {
            return match self.value(index + 1, paren) {
                (list @ Value::List(_), next) => (list, next),
                (_, next) => (Value::Dynamic, next),
            };
        }
        if token.punct("{") {
            return (Value::Object, self.skip_to_close(index, paren));
        }
        if self.language == Language::R
            && token.kind == Kind::Word
            && matches!(token.text.as_str(), "c" | "list")
            && self.token(index + 1).is_some_and(|open| open.punct("("))
        {
            return self.list(index + 2, ")");
        }
        if self.language == Language::R
            && token.kind == Kind::Word
            && matches!(token.text.as_str(), "paste" | "paste0")
            && self.token(index + 1).is_some_and(|open| open.punct("("))
        {
            let separator = if token.text == "paste" { " " } else { "" };
            let (parts, next) = self.list(index + 2, ")");

            if let Value::List(parts) = parts {
                let mut pieces = Vec::new();
                for part in parts {
                    match part {
                        Value::Str(text) => pieces.push(text),
                        _ => return (Value::Dynamic, next),
                    }
                }
                return (Value::Str(pieces.join(separator)), next);
            }
            return (Value::Dynamic, next);
        }

        if let Some((text, next)) = self.literal(index)
            && self.ends_argument(next, paren)
        {
            return (Value::Str(text), next);
        }

        let end = self.skip_to_close(index, paren);
        (Value::Dynamic, end)
    }

    /// A list that starts after its opening bracket, up to `close`.
    fn list(&self, start: usize, close: &str) -> (Value, usize) {
        let mut items = Vec::new();
        let mut index = start;

        loop {
            index = self.skip_newlines(index, true);
            let Some(token) = self.token(index) else {
                return (Value::Dynamic, index);
            };
            if token.punct(close) {
                return (Value::List(items), index + 1);
            }
            if items.len() >= MAX_ITEMS {
                return (Value::Dynamic, index);
            }

            let (value, next) = self.value(index, true);
            index = self.skip_newlines(next, true);
            items.push(value);

            match self.token(index) {
                Some(token) if token.punct(",") => index += 1,
                Some(token) if token.punct(close) => {}
                _ => {
                    let end = self.skip_to_close(index, true);
                    return (Value::Dynamic, end + 1);
                }
            }
        }
    }

    /// Whether the argument that ended at `index` really ends there: the next
    /// token closes or separates it.
    fn ends_argument(&self, index: usize, paren: bool) -> bool {
        match self.token(index) {
            None => true,
            Some(token) => match token.kind {
                Kind::Newline => true,
                Kind::Punct => {
                    matches!(token.text.as_str(), "," | ")" | "]" | "}" | ";" | "=>")
                        || (!paren && matches!(token.text.as_str(), "||" | "&&"))
                }
                Kind::Word => !paren && STATEMENT_ENDS.contains(&token.text.as_str()),
                _ => false,
            },
        }
    }

    /// A string made of literals: pieces joined by the language's concatenation
    /// or set side by side, and the token after it.
    fn literal(&self, start: usize) -> Option<(String, usize)> {
        let mut index = start;
        let mut text = String::new();
        let mut pieces = 0;

        loop {
            let token = self.token(index)?;

            if token.kind == Kind::Str && !token.dynamic {
                text.push_str(&token.text);
                index += 1;
            } else if token.punct("(") && pieces == 0 {
                let (inner, next) = self.literal(index + 1)?;
                if !self.token(next)?.punct(")") {
                    return None;
                }
                text = inner;
                index = next + 1;
            } else {
                return None;
            }
            pieces += 1;

            match self.token(index) {
                Some(operator)
                    if operator.kind == Kind::Punct && self.concatenates(&operator.text) =>
                {
                    index += 1;
                }
                Some(next) if next.kind == Kind::Str => {}
                _ => return Some((text, index)),
            }
            if pieces >= MAX_ITEMS {
                return None;
            }
        }
    }

    fn concatenates(&self, operator: &str) -> bool {
        match self.language {
            Language::Python | Language::Node | Language::Ruby => operator == "+",
            Language::Perl => operator == ".",
            Language::R | Language::Awk => false,
        }
    }

    /// The token where the argument that starts at `index` ends: the next `,` or
    /// closing bracket outside brackets of its own. An argument longer than
    /// [`MAX_SPAN`] tokens ends where veil stops looking.
    fn skip_to_close(&self, start: usize, paren: bool) -> usize {
        let mut depth = 0usize;
        let mut index = start;

        while let Some(token) = self.token(index) {
            if index - start >= MAX_SPAN {
                return index;
            }
            match token.kind {
                Kind::Punct => match token.text.as_str() {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => {
                        if depth == 0 {
                            return index;
                        }
                        depth -= 1;
                    }
                    "," | "=>" if depth == 0 => return index,
                    ";" if depth == 0 && !paren => return index,
                    _ => {}
                },
                Kind::Newline if depth == 0 && !paren => return index,
                _ => {}
            }
            index += 1;
        }
        index
    }

    // ---- turning a call into command lines ----

    fn record(&self, site: &CallSite, found: &mut Found) {
        let mut lines = Vec::new();
        let mut dynamic = !site.args.complete;

        self.commands_of(site, &mut lines, &mut dynamic);
        found.commands.extend(lines);

        if dynamic && found.refused.is_none() {
            found.refused = Some(self.label(site));
        }
    }

    /// The call as the program wrote it, from its name to the end of its
    /// arguments.
    fn label(&self, site: &CallSite) -> String {
        let mut first = site.label;
        while first >= 2
            && self.tokens[first - 1].kind == Kind::Punct
            && matches!(self.tokens[first - 1].text.as_str(), "." | "::" | "->")
            && self.tokens[first - 2].kind == Kind::Word
        {
            first -= 2;
        }
        let start = self.tokens[first].start;
        let last = site.args.next.saturating_sub(1).max(site.start);
        let end = self
            .tokens
            .get(last)
            .map_or(self.text.len(), |token| token.end)
            .max(start);

        self.text[start..end.min(self.text.len())].trim().to_owned()
    }

    fn commands_of(&self, site: &CallSite, lines: &mut Vec<String>, dynamic: &mut bool) {
        let items = &site.args.items;
        let positional: Vec<&Item> = items.iter().filter(|item| item.keyword.is_none()).collect();
        let named = |name: &str| {
            items
                .iter()
                .find(|item| item.keyword.as_deref() == Some(name))
        };

        match site.call {
            Call::Shell => {
                let item = positional
                    .first()
                    .copied()
                    .or_else(|| named("command"))
                    .or_else(|| named("cmd"));
                match item {
                    Some(item) => self.shell_text(&item.value, lines, dynamic),
                    None => *dynamic = true,
                }
            }
            Call::Subprocess => {
                let Some(item) = positional.first().copied().or_else(|| named("args")) else {
                    *dynamic = true;
                    return;
                };
                let shell = named("shell").is_some_and(|item| {
                    !matches!(item.first.as_deref(), Some("False" | "false" | "0"))
                });

                match &item.value {
                    Value::List(list) => {
                        if shell && let Some(Value::Str(first)) = list.first() {
                            lines.push(first.clone());
                        }
                        self.argv(list, lines, dynamic);
                    }
                    other => self.shell_text(other, lines, dynamic),
                }
            }
            Call::Argv => {
                let Some(program) = positional.first().copied().or_else(|| named("command")) else {
                    *dynamic = true;
                    return;
                };
                let mut words = vec![program.value.clone()];

                match positional.get(1).map(|item| &item.value) {
                    Some(Value::List(list)) => words.extend(list.iter().cloned()),
                    Some(Value::Object) | None => {}
                    Some(other @ Value::Str(_)) if self.language == Language::R => {
                        words.push(other.clone());
                    }
                    // `spawn("cat", args)`: an argument list the program holds
                    // in a variable is a word it computes
                    Some(_) => words.push(Value::Dynamic),
                }
                if self.language == Language::R
                    && let Some(item) = named("args")
                {
                    match &item.value {
                        Value::List(list) => words.extend(list.iter().cloned()),
                        other => words.push(other.clone()),
                    }
                }
                self.argv(&words, lines, dynamic);
            }
            Call::Exec(skip) => {
                let list = positional.iter().find_map(|item| match &item.value {
                    Value::List(list) => Some(list.clone()),
                    _ => None,
                });
                let words: Vec<Value> = match list {
                    Some(list) => list,
                    None => positional
                        .iter()
                        .skip(skip)
                        .map(|item| item.value.clone())
                        .collect(),
                };
                self.argv(&words, lines, dynamic);
            }
            Call::Words => {
                let mut words = Vec::new();
                for item in items {
                    match &item.value {
                        // `Deno.Command("cat", {args: [".env"]})`, `Bun.spawn({cmd: [...]})`
                        Value::Object => {
                            let (from, to) = item.span;
                            for token in &self.tokens[from.min(to)..to.min(self.tokens.len())] {
                                if token.kind == Kind::Str && !token.dynamic {
                                    words.push(Value::Str(token.text.clone()));
                                }
                            }
                        }
                        other => flatten(other, &mut words),
                    }
                }
                self.argv(&words, lines, dynamic);
            }
            Call::Auto(skip) => {
                let mut rest: Vec<&Item> = positional;
                // a leading environment hash (`system({"A" => "b"}, "cmd")`)
                while rest.first().is_some_and(|item| item.value == Value::Object) {
                    rest.remove(0);
                }
                let rest: Vec<&Item> = rest.into_iter().skip(skip).collect();

                match rest.as_slice() {
                    [] => *dynamic = true,
                    [one] => match &one.value {
                        Value::List(list) => self.argv(list, lines, dynamic),
                        other => self.shell_text(other, lines, dynamic),
                    },
                    many => {
                        let words: Vec<Value> =
                            many.iter().map(|item| item.value.clone()).collect();
                        self.argv(&words, lines, dynamic);
                    }
                }
            }
            Call::Pipe => self.pipe_open(&positional, lines, dynamic),
        }
    }

    /// An argument that is shell text.
    fn shell_text(&self, value: &Value, lines: &mut Vec<String>, dynamic: &mut bool) {
        match value {
            Value::Str(text) => lines.push(text.clone()),
            Value::List(list) => self.argv(list, lines, dynamic),
            Value::Object => {}
            Value::Dynamic => *dynamic = true,
        }
    }

    /// A command and its arguments, each a word. No shell reads them, so a word
    /// the program computes is one word and nothing more: it is left as an
    /// unresolved word of the command, which is judged as one typed would be
    /// (`git show $rev` runs, `cat $f` does not). What is not known is the
    /// program itself, and then the call is refused.
    fn argv(&self, words: &[Value], lines: &mut Vec<String>, dynamic: &mut bool) {
        let mut line: Vec<String> = Vec::new();
        let mut flat: Vec<&Value> = Vec::new();

        for word in words {
            match word {
                Value::List(list) => flat.extend(list),
                other => flat.push(other),
            }
        }
        for word in flat {
            match word {
                Value::Str(text) => line.push(shell_quote(text)),
                Value::Dynamic | Value::List(_) => {
                    if line.is_empty() {
                        *dynamic = true;
                        return;
                    }
                    line.push(COMPUTED.to_owned());
                }
                Value::Object => {}
            }
        }
        if !line.is_empty() {
            lines.push(line.join(" "));
        }
    }

    /// `open(F, "cat .env |")`, `open(F, "| cmd")`, `open(F, "-|", "cmd", ...)`,
    /// Ruby's `open("| cmd")`: a file name that is a command.
    fn pipe_open(&self, positional: &[&Item], lines: &mut Vec<String>, dynamic: &mut bool) {
        let (name, rest) = match self.language {
            Language::Perl => match positional.get(1) {
                Some(item) => (&item.value, positional.get(2..).unwrap_or(&[])),
                None => return,
            },
            _ => match positional.first() {
                Some(item) => (&item.value, positional.get(1..).unwrap_or(&[])),
                None => return,
            },
        };
        let Value::Str(name) = name else {
            // an ordinary file name veil cannot see: a read of a path, not a command
            return;
        };
        let trimmed = name.trim();

        if matches!(trimmed, "-|" | "|-") && self.language == Language::Perl {
            let words: Vec<Value> = rest.iter().map(|item| item.value.clone()).collect();
            match words.as_slice() {
                [] => {}
                [one] => self.shell_text(one, lines, dynamic),
                many => self.argv(many, lines, dynamic),
            }
        } else if let Some(command) = trimmed.strip_prefix('|') {
            lines.push(command.trim().to_owned());
        } else if let Some(command) = trimmed.strip_suffix('|')
            && self.language == Language::Perl
        {
            lines.push(command.trim().to_owned());
        }
    }

    // ---- awk ----

    /// `"cmd" | getline`, `print | "cmd"`.
    fn awk_calls(&self, found: &mut Found) {
        for index in 0..self.tokens.len() {
            let token = &self.tokens[index];
            if !(token.punct("|") || token.punct("|&")) {
                continue;
            }

            let (value, label) = if self
                .token(index + 1)
                .is_some_and(|next| next.word("getline"))
            {
                self.awk_left(index)
            } else if self.awk_prints_before(index) {
                self.awk_right(index)
            } else {
                continue;
            };

            match value {
                Value::Str(text) => found.commands.push(text),
                _ => {
                    found.refused.get_or_insert_with(|| {
                        self.text[label.0.min(self.text.len())..label.1.min(self.text.len())]
                            .trim()
                            .to_owned()
                    });
                }
            }
        }
    }

    /// The command that stands before `| getline`, and where it is written.
    fn awk_left(&self, pipe: usize) -> (Value, (usize, usize)) {
        let mut start = pipe;
        let mut depth = 0usize;

        while start > 0 {
            let token = &self.tokens[start - 1];
            let stops = match token.kind {
                Kind::Newline => true,
                Kind::Punct => match token.text.as_str() {
                    ")" => {
                        depth += 1;
                        false
                    }
                    "(" => {
                        if depth == 0 {
                            true
                        } else {
                            depth -= 1;
                            false
                        }
                    }
                    ";" | "{" | "}" | "," | "=" | "&&" | "||" | "!" | "?" | ":" => depth == 0,
                    _ => false,
                },
                Kind::Word => {
                    depth == 0
                        && matches!(
                            token.text.as_str(),
                            "print" | "printf" | "while" | "if" | "return" | "else"
                        )
                }
                _ => false,
            };
            if stops || pipe - start >= MAX_SPAN {
                break;
            }
            start -= 1;
        }

        let begin = self.tokens.get(start).map_or(0, |token| token.start);
        let end = self.tokens[pipe].start;
        let region = &self.tokens[start..pipe];

        if let Some((text, next)) = self.awk_literal(region)
            && next == region.len()
        {
            return (Value::Str(text), (begin, end));
        }
        (Value::Dynamic, (begin, self.tokens[pipe + 1].end))
    }

    /// The command that stands after `print ... |`.
    fn awk_right(&self, pipe: usize) -> (Value, (usize, usize)) {
        let mut end = pipe + 1;

        while let Some(token) = self.token(end) {
            let stops = match token.kind {
                Kind::Newline => true,
                Kind::Punct => matches!(token.text.as_str(), ";" | "}"),
                _ => false,
            };
            if stops || end - pipe >= MAX_SPAN {
                break;
            }
            end += 1;
        }

        let begin = self.tokens[pipe].start;
        let finish = self
            .tokens
            .get(end.saturating_sub(1))
            .map_or(self.text.len(), |token| token.end);
        let region = &self.tokens[pipe + 1..end];

        if let Some((text, next)) = self.awk_literal(region)
            && next == region.len()
        {
            return (Value::Str(text), (begin, finish));
        }
        (Value::Dynamic, (begin, finish))
    }

    /// A run of string literals, which awk concatenates.
    fn awk_literal(&self, region: &[Token]) -> Option<(String, usize)> {
        let mut text = String::new();
        let mut index = 0;

        while let Some(token) = region.get(index) {
            let literal = token.kind == Kind::Str && !token.dynamic;
            if token.punct("(") || token.punct(")") {
                index += 1;
                continue;
            }
            if !literal {
                return None;
            }
            text.push_str(&token.text);
            index += 1;
        }
        (!region.is_empty()).then_some((text, index))
    }

    /// Whether a `print` or `printf` starts the statement the pipe at `pipe` ends.
    fn awk_prints_before(&self, pipe: usize) -> bool {
        let mut index = pipe;
        let mut depth = 0usize;

        while index > 0 {
            let token = &self.tokens[index - 1];
            match token.kind {
                Kind::Newline => return false,
                Kind::Punct => match token.text.as_str() {
                    ")" => depth += 1,
                    "(" => depth = depth.saturating_sub(1),
                    ";" | "{" | "}" if depth == 0 => return false,
                    _ => {}
                },
                Kind::Word if matches!(token.text.as_str(), "print" | "printf") && depth == 0 => {
                    return true;
                }
                _ => {}
            }
            if pipe - index >= MAX_SPAN {
                return false;
            }
            index -= 1;
        }
        false
    }
}

struct CallSite {
    /// The token of the name the call is made by.
    start: usize,
    /// Where the label of a refusal starts.
    label: usize,
    args: Arguments,
    call: Call,
}

fn flatten(value: &Value, words: &mut Vec<Value>) {
    match value {
        Value::List(list) => {
            for inner in list {
                flatten(inner, words);
            }
        }
        Value::Object => {}
        other => words.push(other.clone()),
    }
}

/// `word` as one shell word, whatever it holds.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(language: Language, text: &str) -> Vec<String> {
        find(language, text).commands
    }

    fn refused(language: Language, text: &str) -> bool {
        find(language, text).refused.is_some()
    }

    #[test]
    fn python_hands_a_string_to_the_shell() {
        for text in [
            "import os; os.system('cat .env')",
            "import os\nos.system(\"cat .env\")",
            "import os; os.popen('cat .env').read()",
            "import subprocess; subprocess.run('cat .env', shell=True)",
            "import subprocess; subprocess.check_output('cat .env', shell=True)",
            "import subprocess; subprocess.Popen(\"cat .env\", shell=True)",
            "import commands; commands.getoutput('cat .env')",
            "import os; os.system('cat ' + '.env')",
            "import os; os.system('cat ' '.env')",
            "import os; os.system(('cat .env'))",
            "import os; os.system(r'cat .env')",
            "import os; os.system('cat \\x2eenv')",
            "import os; os.system(f'cat .env')",
        ] {
            assert_eq!(commands(Language::Python, text), ["cat .env"], "{text}");
            assert!(!refused(Language::Python, text), "{text}");
        }
    }

    #[test]
    fn python_runs_an_argument_list() {
        let text = "import subprocess; subprocess.run(['cat', '.env'])";
        assert_eq!(commands(Language::Python, text), ["'cat' '.env'"]);

        let text = "import subprocess; subprocess.run(['sh', '-c', 'cat .env'])";
        assert_eq!(commands(Language::Python, text), ["'sh' '-c' 'cat .env'"]);

        let text = "import os; os.execvp('cat', ['cat', '.env'])";
        assert_eq!(commands(Language::Python, text), ["'cat' '.env'"]);

        let text = "import os; os.execl('/bin/cat', 'cat', '.env')";
        assert_eq!(commands(Language::Python, text), ["'cat' '.env'"]);

        let text = "import os; os.spawnlp(os.P_WAIT, 'cat', 'cat', '.env')";
        assert_eq!(commands(Language::Python, text), ["'cat' '.env'"]);

        let text = "import subprocess; subprocess.run(args=['cat', '.env'])";
        assert_eq!(commands(Language::Python, text), ["'cat' '.env'"]);

        // with shell=True a one-element list is shell text
        let text = "import subprocess; subprocess.run(['cat .env'], shell=True)";
        assert!(commands(Language::Python, text).contains(&"cat .env".to_owned()));
    }

    #[test]
    fn python_commands_built_at_run_time_are_refused() {
        for text in [
            "import os; os.system(cmd)",
            "import os; os.system('cat ' + name)",
            "import os; os.system(f'cat {name}')",
            "import os; os.system('cat %s' % name)",
            "import os; os.system('cat {}'.format(name))",
            "import os; os.system(' '.join(parts))",
            "import subprocess; subprocess.run(cmd, shell=True)",
            "import subprocess; subprocess.run([prog, 'x'])",
            "import os; os.system(input())",
        ] {
            assert!(refused(Language::Python, text), "{text}");
        }

        let found = find(Language::Python, "import os; os.system('cat ' + name)");
        assert_eq!(found.refused.as_deref(), Some("os.system('cat ' + name)"));
    }

    #[test]
    fn a_word_an_argument_list_computes_is_an_unresolved_word_not_a_refusal() {
        let computed = "'cat' $value_the_program_computes";

        for (language, text) in [
            (
                Language::Python,
                "import subprocess; subprocess.run(['cat', name])",
            ),
            (
                Language::Python,
                "import subprocess; subprocess.run(['cat', f'{d}/x'])",
            ),
            (
                Language::Python,
                "import subprocess; subprocess.check_output(['cat', sys.argv[1]])",
            ),
            (
                Language::Python,
                "import os; os.execvp('cat', ['cat', name])",
            ),
            (
                Language::Node,
                "require('child_process').spawn('cat', args)",
            ),
            (
                Language::Node,
                "require('child_process').spawnSync('cat', [name])",
            ),
            (Language::Perl, "system('cat', $file)"),
            (Language::Ruby, "system('cat', file)"),
            (Language::R, "system2('cat', args = name)"),
        ] {
            let found = find(language, text);
            assert_eq!(found.commands, [computed], "{text}");
            assert_eq!(found.refused, None, "{text}");
        }

        // the words around it are still judged
        let found = find(
            Language::Python,
            "import subprocess; subprocess.run(['git', 'show', f'{rev}:.beads/issues.jsonl'])",
        );
        assert_eq!(found.commands, ["'git' 'show' $value_the_program_computes"]);
        assert_eq!(found.refused, None);

        // but the program is not known, and a shell string can become anything
        for (language, text) in [
            (
                Language::Python,
                "import subprocess; subprocess.run([prog, 'x'])",
            ),
            (Language::Python, "import subprocess; subprocess.run(cmd)"),
            (Language::Python, "import os; os.system('git show ' + rev)"),
            (Language::Perl, "system($prog, 'x')"),
        ] {
            assert!(refused(language, text), "{text}");
        }
    }

    #[test]
    fn python_with_no_command_runs_nothing() {
        for text in [
            "print(1)",
            "import os; print(os.getcwd())",
            "import sys; sys.exit(0)",
            "print('os.system(cmd)')",
            "# os.system(cmd)\nprint(1)",
            "import json; json.dumps({'a': 1})",
            "app.run(host='0.0.0.0')",
            "import asyncio; asyncio.run(main())",
            "d = {'system': 1}",
            "def system(x): return x",
            "x = '''\nos.system(cmd)\n'''",
        ] {
            let found = find(Language::Python, text);
            assert_eq!(found, Found::default(), "{text}");
        }
    }

    #[test]
    fn python_run_is_a_command_only_where_subprocess_is_used() {
        assert!(!refused(Language::Python, "app.run(config)"));
        assert!(refused(
            Language::Python,
            "import subprocess; runner.run(config)"
        ));
    }

    #[test]
    fn node_runs_a_command() {
        for text in [
            "require('child_process').execSync('cat .env')",
            "const {exec} = require('child_process'); exec(\"cat .env\", cb)",
            "require('child_process').execSync(`cat .env`)",
            "require('child_process').execSync('cat ' + '.env')",
            "cp.execSync('cat .env', {encoding: 'utf8'})",
        ] {
            assert_eq!(commands(Language::Node, text), ["cat .env"], "{text}");
        }

        let text = "require('child_process').spawn('cat', ['.env'])";
        assert_eq!(commands(Language::Node, text), ["'cat' '.env'"]);
        let text = "require('child_process').execFileSync('cat', ['.env'])";
        assert_eq!(commands(Language::Node, text), ["'cat' '.env'"]);
        let text = "require('child_process').spawnSync('sh', ['-c', 'cat .env'])";
        assert_eq!(commands(Language::Node, text), ["'sh' '-c' 'cat .env'"]);
        let text = "require('child_process').spawn('cat', ['.env'], {stdio: 'inherit'})";
        assert_eq!(commands(Language::Node, text), ["'cat' '.env'"]);
        assert!(!refused(Language::Node, text));
    }

    #[test]
    fn node_regex_exec_is_no_command() {
        for text in [
            "const m = /a(b)/.exec(line); console.log(m)",
            "re.exec(line)",
            "console.log(1)",
            "const x = {exec: 1}",
        ] {
            assert_eq!(find(Language::Node, text), Found::default(), "{text}");
        }
    }

    #[test]
    fn node_commands_built_at_run_time_are_refused() {
        for text in [
            "require('child_process').execSync(cmd)",
            "require('child_process').execSync(`cat ${name}`)",
            "require('child_process').execSync('cat ' + name)",
            "require('child_process').spawn(prog, args)",
            "require('child_process').exec(process.argv[2])",
        ] {
            assert!(refused(Language::Node, text), "{text}");
        }
    }

    #[test]
    fn bun_and_deno_run_commands() {
        let text = "Bun.spawn(['cat', '.env'])";
        assert_eq!(commands(Language::Node, text), ["'cat' '.env'"]);
        let text = "new Deno.Command('cat', {args: ['.env']})";
        let found = commands(Language::Node, text);
        assert!(
            found.iter().any(|line| line.contains("'.env'")),
            "{found:?}"
        );
    }

    #[test]
    fn perl_and_ruby_run_a_command() {
        for text in [
            "system(\"cat .env\")",
            "system 'cat .env';",
            "system(\"cat\", \".env\")",
            "exec('cat .env')",
            "my $x = `cat .env`;",
            "my $x = qx(cat .env);",
            "my $x = qx{cat .env};",
            "my $x = readpipe('cat .env');",
            "open(F, \"cat .env |\");",
            "open(F, \"| cat .env\");",
            "open(F, \"-|\", \"cat .env\");",
            "open(F, '-|', 'cat', '.env');",
            "system(q(cat .env))",
            "system('cat ' . '.env')",
            "system(qw(cat .env))",
        ] {
            let found = commands(Language::Perl, text);
            assert!(
                found
                    .iter()
                    .any(|line| line == "cat .env" || line == "'cat' '.env'"),
                "{text}: {found:?}"
            );
            assert!(!refused(Language::Perl, text), "{text}");
        }
    }

    #[test]
    fn perl_commands_built_at_run_time_are_refused() {
        for text in [
            "system($cmd)",
            "system(\"cat $file\")",
            "system \"cat $file\";",
            "my $x = `cat $file`;",
            "system($prog, 'x')",
            "system(\"cat @files\")",
        ] {
            assert!(refused(Language::Perl, text), "{text}");
        }
        // an email address and a lone dollar are not interpolations
        assert!(!refused(Language::Perl, "system(\"echo a\\@b.com \\$5\")"));
    }

    #[test]
    fn perl_without_a_command_runs_nothing() {
        for text in [
            "print \"hello\\n\";",
            "open(F, '<', $path);",
            "open(my $fh, '<', 'x.txt') or die;",
            "print 'system(\"x\")';",
            "# system($x)\nprint 1;",
            "my %h = (system => 1);",
            "$obj->system(1)",
        ] {
            assert_eq!(
                find(Language::Perl, text).commands,
                Vec::<String>::new(),
                "{text}"
            );
        }
        assert!(!refused(Language::Perl, "open(F, '<', $path);"));
    }

    #[test]
    fn ruby_runs_a_command() {
        for text in [
            "system('cat .env')",
            "system \"cat .env\"",
            "system 'cat', '.env'",
            "x = `cat .env`",
            "x = %x(cat .env)",
            "x = %x{cat .env}",
            "exec('cat .env')",
            "spawn('cat .env')",
            "IO.popen('cat .env').read",
            "IO.popen(['cat', '.env']).read",
            "Open3.capture2('cat .env')",
            "Open3.capture3('cat', '.env')",
            "Process.spawn('cat .env')",
            "Kernel.system('cat .env')",
            "open('| cat .env')",
            "system({'A' => 'b'}, 'cat .env')",
            "system(*%w(cat .env))",
        ] {
            let found = commands(Language::Ruby, text);
            assert!(
                found
                    .iter()
                    .any(|line| line == "cat .env" || line == "'cat' '.env'"),
                "{text}: {found:?}"
            );
        }
    }

    #[test]
    fn ruby_commands_built_at_run_time_are_refused() {
        for text in [
            "system(cmd)",
            "system \"cat #{file}\"",
            "x = `cat #{file}`",
            "IO.popen(cmd)",
            "system(prog, 'x')",
        ] {
            assert!(refused(Language::Ruby, text), "{text}");
        }
        assert!(!refused(Language::Ruby, "puts 'hello'"));
        assert!(!refused(Language::Ruby, "File.read('x.txt')"));
        assert!(!refused(Language::Ruby, "open('x.txt')"));
    }

    #[test]
    fn r_runs_a_command() {
        for text in [
            "system('cat .env')",
            "system(\"cat .env\", intern = TRUE)",
            "system(command = 'cat .env')",
            "shell('cat .env')",
            "readLines(pipe('cat .env'))",
            "system(paste0('cat ', '.env'))",
            "system(paste('cat', '.env'))",
        ] {
            assert_eq!(commands(Language::R, text), ["cat .env"], "{text}");
        }
        let text = "system2('cat', args = c('.env'))";
        assert_eq!(commands(Language::R, text), ["'cat' '.env'"]);
        assert!(refused(Language::R, "system(cmd)"));
        assert!(refused(Language::R, "system(paste('cat', f))"));
        assert!(!refused(Language::R, "print(1)"));
    }

    #[test]
    fn awk_runs_a_command() {
        for text in [
            "BEGIN{system(\"cat .env\")}",
            "BEGIN { system(\"cat \" \".env\") }",
            "BEGIN{\"cat .env\" | getline x; print x}",
            "BEGIN{while((\"cat .env\" | getline l) > 0) print l}",
            "BEGIN{print | \"cat .env\"}",
            "{print $1 | \"cat .env\"}",
            "BEGIN{printf \"x\" | \"cat .env\"}",
            "BEGIN{\"cat .env\" |& getline x}",
            "BEGIN {\n  cmd = 1\n  \"cat .env\" | getline x\n}",
        ] {
            assert_eq!(commands(Language::Awk, text), ["cat .env"], "{text}");
            assert!(!refused(Language::Awk, text), "{text}");
        }
    }

    #[test]
    fn awk_commands_built_at_run_time_are_refused() {
        for text in [
            "BEGIN{system(cmd)}",
            "BEGIN{system(\"cat \" f)}",
            "BEGIN{cmd | getline x}",
            "BEGIN{(\"cat \" f) | getline x}",
            "{print | cmd}",
            "{print $1 | \"sort \" opt}",
        ] {
            assert!(refused(Language::Awk, text), "{text}");
        }
    }

    #[test]
    fn awk_with_no_command_runs_nothing() {
        for text in [
            "{print $1}",
            "/a|b/ {print}",
            "BEGIN{print \"a | b\"}",
            "{ n += $1 } END { print n }",
            "BEGIN { FS = \"|\" } { print $2 }",
            "# system(cmd)\n{print}",
            "$1 ~ /x|y/ || $2 > 3 {print}",
            "BEGIN{getline l < \"x.txt\"; print l}",
        ] {
            assert_eq!(find(Language::Awk, text), Found::default(), "{text}");
        }
    }

    fn inline(name: &str, args: &[&str]) -> Vec<String> {
        let args: Vec<String> = args.iter().map(|word| (*word).to_owned()).collect();
        programs(name, &args).inline
    }

    #[test]
    fn the_code_of_an_interpreter_is_found_wherever_the_option_stands() {
        assert_eq!(inline("python3", &["-c", "x"]), ["x"]);
        assert_eq!(inline("python3", &["-Bc", "x"]), ["x"]);
        assert_eq!(inline("python3", &["-uc", "x"]), ["x"]);
        assert_eq!(inline("python3", &["-cx"]), ["x"]);
        assert_eq!(inline("python3", &["-W", "ignore", "-c", "x"]), ["x"]);
        assert_eq!(inline("python3.12", &["-c", "x"]), ["x"]);
        assert!(inline("python3", &["x.py", "-c", "y"]).is_empty());
        assert!(inline("python3", &["-m", "http.server"]).is_empty());
        assert_eq!(inline("node", &["-e", "x"]), ["x"]);
        assert_eq!(inline("node", &["-pe", "x"]), ["x"]);
        assert_eq!(inline("node", &["--eval", "x"]), ["x"]);
        assert_eq!(inline("node", &["--eval=x"]), ["x"]);
        assert_eq!(inline("node", &["-r", "m", "-e", "x"]), ["x"]);
        assert_eq!(inline("bun", &["-e", "x"]), ["x"]);
        assert_eq!(inline("deno", &["eval", "x"]), ["x"]);
        assert!(inline("deno", &["run", "x.ts"]).is_empty());
        assert_eq!(inline("perl", &["-e", "x"]), ["x"]);
        assert_eq!(inline("perl", &["-ne", "x"]), ["x"]);
        assert_eq!(inline("perl", &["-lane", "x"]), ["x"]);
        assert_eq!(inline("perl", &["-pi", "-e", "x"]), ["x"]);
        assert_eq!(inline("perl", &["-Mstrict", "-e", "x"]), ["x"]);
        assert_eq!(inline("perl", &["-E", "x"]), ["x"]);
        assert_eq!(inline("ruby", &["-e", "x", "-e", "y"]), ["x", "y"]);
        assert_eq!(inline("ruby", &["-ne", "x"]), ["x"]);
        assert_eq!(inline("Rscript", &["-e", "x"]), ["x"]);
        assert_eq!(inline("R", &["--vanilla", "-e", "x"]), ["x"]);
        assert!(inline("cat", &["-e", "x"]).is_empty());
    }

    #[test]
    fn the_program_of_awk_is_the_first_word_that_is_not_an_option() {
        assert_eq!(inline("awk", &["{print}", "f.txt"]), ["{print}"]);
        assert_eq!(
            inline("awk", &["-F,", "{print $1}", "f.txt"]),
            ["{print $1}"]
        );
        assert_eq!(inline("awk", &["-F", ",", "{print $1}"]), ["{print $1}"]);
        assert_eq!(inline("awk", &["-v", "x=1", "{print x}"]), ["{print x}"]);
        assert_eq!(inline("gawk", &["--", "{print}"]), ["{print}"]);
        assert_eq!(inline("gawk", &["-e", "BEGIN{x}"]), ["BEGIN{x}"]);

        let args: Vec<String> = ["-f", "a.awk", "-f", "b.awk", "data.txt"]
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
        let found = programs("awk", &args);
        assert_eq!(found.files, ["a.awk", "b.awk"]);
        assert!(found.inline.is_empty());

        let args = vec!["--file=a.awk".to_owned(), "x.txt".to_owned()];
        assert_eq!(programs("awk", &args).files, ["a.awk"]);
        let args = vec!["-fa.awk".to_owned(), "x.txt".to_owned()];
        assert_eq!(programs("awk", &args).files, ["a.awk"]);
    }

    #[test]
    fn a_program_of_many_calls_is_cut_off_and_refused() {
        let text = "system('ls');".repeat(MAX_COMMANDS + 10);
        let found = find(Language::Perl, &text);

        assert_eq!(found.commands.len(), MAX_COMMANDS);
        assert!(found.refused.is_some());
    }

    #[test]
    fn a_program_made_to_be_slow_is_read_in_linear_time() {
        let started = std::time::Instant::now();

        for text in [
            "os.system(".repeat(20_000),
            "[".repeat(40_000),
            "system(".repeat(20_000),
            "'".repeat(40_000),
            format!("os.system({})", "f(".repeat(20_000)),
            format!("os.system({})", "a, ".repeat(20_000)),
        ] {
            for language in [
                Language::Python,
                Language::Node,
                Language::Perl,
                Language::Ruby,
                Language::R,
                Language::Awk,
            ] {
                let _ = find(language, &text);
            }
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_stray_quote_does_not_swallow_the_rest_of_the_program() {
        assert_eq!(
            commands(
                Language::Python,
                "x = \"it's\nimport os; os.system('cat .env')"
            ),
            ["cat .env"]
        );
        assert_eq!(
            commands(Language::Python, "x = 'a\nos.system('cat .env')\n"),
            ["cat .env"]
        );
    }

    #[test]
    fn shell_quoting_keeps_a_word_whole() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}
