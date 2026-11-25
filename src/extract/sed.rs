//! The files a `sed` script names (bd-pm8).
//!
//! `sed 'r .env' notes.txt` copies `.env` after every line of `notes.txt`; `R`
//! copies it a line at a time; `w`, `W` and the `w` flag of `s` write a file.
//! The file name is inside the script, which is one quoted word with a space in
//! it, so no word of the command is shaped like a path and the argv rule never
//! sees it. This module reads the script the way sed does and returns the names.
//!
//! It is a parser, not a search for `r ` in the text: `s/r .env/x/` replaces
//! text, `a\ r .env` appends text, `# r .env` is a comment, and none of them
//! names a file. A script it cannot parse is refused (the caller turns that into
//! the dynamic-argument stance), never skipped: sed itself rejects what this
//! rejects, so a script that does not parse costs nothing that worked.
//!
//! GNU sed, BSD sed (macOS) and busybox differ in places that matter to where a
//! command ends: BSD skips a `[...]` bracket when it looks for the closing
//! delimiter and GNU does not, GNU ends a label at `;` and BSD at the end of the
//! line, and `-i` takes the next word as a suffix on BSD only. veil does not know
//! which sed runs, so each script is read under every combination and the files
//! are the union: a name any reading finds is judged. The script is refused only
//! when no reading parses it.

/// Programs that are sed.
pub(super) fn is_sed(name: &str) -> bool {
    matches!(name, "sed" | "gsed")
}

/// What the scripts of one `sed` command line do to files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ScriptFiles {
    /// `r` and `R`: files the script copies into the output.
    pub reads: Vec<String>,
    /// `w`, `W` and the `w` flag of `s`: files the script writes.
    pub writes: Vec<String>,
    /// The script, as written, when veil cannot judge what it does: no reading
    /// parses it, or it runs a command (`e`, or the `e` flag of `s`).
    pub refused: Option<String>,
}

/// The files named by the script(s) in `args`, the words after `sed`.
pub(super) fn script_files(args: &[String]) -> ScriptFiles {
    // `sed --version 2>&1`, `sed p notes.txt > out`: a redirection is the
    // shell's, not an operand, and must not be taken for the script.
    let args: Vec<String> = super::strip_redirection_words(args)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut files = ScriptFiles::default();
    // Each way of reading the command line: whether it is GNU's, and its scripts.
    let mut readings: Vec<(bool, Vec<String>)> = Vec::new();

    // Which word is the script depends on whether `-i` takes the next word as
    // its suffix (BSD) or only an attached one (GNU).
    for gnu in [true, false] {
        let scripts = scripts_in(&args, !gnu);
        if !scripts.is_empty() && !readings.iter().any(|(_, known)| *known == scripts) {
            readings.push((gnu, scripts));
        }
    }

    let Some((_, first)) = readings.first() else {
        return files;
    };
    let shown = first.join(" ; ");
    let mut parsed = false;
    let mut runs = false;

    for (gnu, scripts) in &readings {
        // sed joins the pieces with newlines, so `-e 'a\' -e text` is one command.
        let text = scripts.join("\n");

        for dialect in DIALECTS {
            if let Some(found) = parse(&text, dialect, *gnu) {
                parsed = true;
                runs |= found.runs;
                merge(&mut files.reads, found.reads);
                merge(&mut files.writes, found.writes);
            }
        }
    }

    if !parsed || runs {
        files.refused = Some(shown);
    }
    files
}

fn merge(into: &mut Vec<String>, names: Vec<String>) {
    for name in names {
        if !into.contains(&name) {
            into.push(name);
        }
    }
}

// ------------------------------------------------------------ the options

/// How a long option takes its value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Long {
    Flag,
    /// A script: `--expression=S` or `--expression S`.
    Expression,
    /// A script file: `--file=F` or `--file F`.
    File,
    /// A number: `--line-length=N` or `--line-length N`.
    Number,
}

const LONG_OPTIONS: &[(&str, Long)] = &[
    ("binary", Long::Flag),
    ("debug", Long::Flag),
    ("expression", Long::Expression),
    ("file", Long::File),
    ("follow-symlinks", Long::Flag),
    ("help", Long::Flag),
    ("in-place", Long::Flag),
    ("line-length", Long::Number),
    ("null-data", Long::Flag),
    ("posix", Long::Flag),
    ("quiet", Long::Flag),
    ("regexp-extended", Long::Flag),
    ("sandbox", Long::Flag),
    ("separate", Long::Flag),
    ("silent", Long::Flag),
    ("unbuffered", Long::Flag),
    ("version", Long::Flag),
    ("zero-terminated", Long::Flag),
];

/// A long option by its name or by any prefix that names only one, as GNU
/// getopt takes it (`--expr=`, `--e=`). An ambiguous or unknown name is a flag.
fn long_option(name: &str) -> Long {
    if let Some((_, kind)) = LONG_OPTIONS.iter().find(|(full, _)| *full == name) {
        return *kind;
    }

    let mut matches = LONG_OPTIONS
        .iter()
        .filter(|(full, _)| !name.is_empty() && full.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some((_, kind)), None) => *kind,
        _ => Long::Flag,
    }
}

/// The script text on the command line: every `-e` and `--expression` value, or,
/// with neither `-e` nor `-f`, the first operand. `-f` makes the script a file
/// whose name the argv rule already judges and whose contents are not read here.
fn scripts_in(args: &[String], suffix_takes_word: bool) -> Vec<String> {
    let mut scripts: Vec<String> = Vec::new();
    let mut script_file = false;
    let mut first_operand: Option<&str> = None;
    let mut options_ended = false;
    let mut index = 0;

    while index < args.len() {
        let word = args[index].as_str();
        index += 1;

        if options_ended || word == "-" || !word.starts_with('-') {
            first_operand.get_or_insert(word);
            continue;
        }
        if word == "--" {
            options_ended = true;
            continue;
        }

        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match (long_option(name), value) {
                (Long::Expression, Some(value)) => scripts.push(value.to_owned()),
                (Long::Expression, None) => {
                    if let Some(next) = args.get(index) {
                        scripts.push(next.clone());
                    }
                    index += 1;
                }
                (Long::File, value) => {
                    script_file = true;
                    index += usize::from(value.is_none());
                }
                (Long::Number, None) => index += 1,
                _ => {}
            }
            continue;
        }

        // A cluster of short options: `-n`, `-ne`, `-i.bak`, `-nf`.
        for (offset, option) in word.char_indices().skip(1) {
            let rest = &word[offset + option.len_utf8()..];

            match option {
                'e' => {
                    if !rest.is_empty() {
                        scripts.push(rest.to_owned());
                    } else {
                        if let Some(next) = args.get(index) {
                            scripts.push(next.clone());
                        }
                        index += 1;
                    }
                    break;
                }
                'f' => {
                    script_file = true;
                    index += usize::from(rest.is_empty());
                    break;
                }
                'l' => {
                    index += usize::from(rest.is_empty());
                    break;
                }
                // GNU: the rest of the word is the backup suffix. BSD: the next
                // word is, even when it is empty.
                'i' | 'I' => {
                    index += usize::from(suffix_takes_word && rest.is_empty());
                    break;
                }
                _ => {}
            }
        }
    }

    if scripts.is_empty()
        && !script_file
        && let Some(operand) = first_operand
    {
        scripts.push(operand.to_owned());
    }
    scripts
}

// ------------------------------------------------------------- the parser

/// One reading of where commands end. Every combination is tried.
#[derive(Clone, Copy)]
struct Dialect {
    /// `s/[/]/x/`: a delimiter inside `[...]` does not end the pattern (BSD).
    brackets: bool,
    /// A label runs to the end of the line (BSD); otherwise it ends at a space,
    /// `;` or `}` (GNU).
    label_to_newline: bool,
}

const DIALECTS: [Dialect; 4] = [
    Dialect {
        brackets: false,
        label_to_newline: false,
    },
    Dialect {
        brackets: true,
        label_to_newline: true,
    },
    Dialect {
        brackets: false,
        label_to_newline: true,
    },
    Dialect {
        brackets: true,
        label_to_newline: false,
    },
];

/// File names sed itself treats as its standard streams (GNU documents them for
/// `r` and `w`; BSD opens them as the descriptors they are). veil leaves them
/// out: what `r /dev/stdin` copies is what the pipeline already gave sed, and
/// what `w /dev/stdout` writes is sed's own output.
const SED_STREAMS: &[&str] = &["/dev/stdin", "/dev/stdout", "/dev/stderr"];

#[derive(Default)]
struct Found {
    reads: Vec<String>,
    writes: Vec<String>,
    runs: bool,
}

struct Parser {
    text: Vec<char>,
    at: usize,
    dialect: Dialect,
    /// The reading is GNU sed's. Only GNU has the `e` command and the `e` flag;
    /// BSD sed rejects them, so in a BSD reading they do not parse. That matters
    /// when `-i` hands the next word to the BSD reading as a script: a file
    /// called `edgar.py` must not parse as `e dgar.py`.
    gnu: bool,
    found: Found,
}

/// What the script names, or `None` if this reading cannot parse it.
fn parse(script: &str, dialect: Dialect, gnu: bool) -> Option<Found> {
    let mut parser = Parser {
        text: script.chars().collect(),
        at: 0,
        dialect,
        gnu,
        found: Found::default(),
    };
    parser.script()?;
    Some(parser.found)
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.text.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let next = self.peek()?;
        self.at += 1;
        Some(next)
    }

    fn eat(&mut self, expected: char) -> bool {
        let found = self.peek() == Some(expected);
        self.at += usize::from(found);
        found
    }

    /// Spaces and tabs, not newlines.
    fn blanks(&mut self) {
        while self
            .peek()
            .is_some_and(|next| next != '\n' && next.is_whitespace())
        {
            self.at += 1;
        }
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|next| next.is_ascii_digit()) {
            self.at += 1;
        }
    }

    /// Up to and through the end of the line.
    fn line(&mut self) {
        while let Some(next) = self.bump() {
            if next == '\n' {
                break;
            }
        }
    }

    fn script(&mut self) -> Option<()> {
        let mut open = 0usize;

        loop {
            while self
                .peek()
                .is_some_and(|next| next.is_whitespace() || next == ';')
            {
                self.at += 1;
            }
            let Some(first) = self.peek() else {
                return (open == 0).then_some(());
            };
            if first == '#' {
                self.line();
                continue;
            }

            self.address()?;
            self.blanks();
            while self.eat('!') {
                self.blanks();
            }

            match self.bump()? {
                '{' => open += 1,
                '}' => {
                    open = open.checked_sub(1)?;
                    self.end()?;
                }
                '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P' | 'x' | 'z'
                | 'F' => self.end()?,
                // An optional line length or exit code.
                'l' | 'L' | 'q' | 'Q' => {
                    self.blanks();
                    self.digits();
                    self.end()?;
                }
                'a' | 'i' | 'c' => self.text()?,
                ':' | 'b' | 't' | 'T' | 'v' => self.label()?,
                'r' | 'R' => {
                    let names = self.file()?;
                    self.found.reads.extend(names);
                }
                'w' | 'W' => {
                    let names = self.file()?;
                    self.found.writes.extend(names);
                }
                's' => self.substitute()?,
                'y' => self.transliterate()?,
                // GNU `e [command]`: runs a command, to the end of the line.
                'e' if self.gnu => {
                    self.found.runs = true;
                    self.line();
                }
                _ => return None,
            }
        }
    }

    /// An optional address or `addr,addr` range in front of a command.
    fn address(&mut self) -> Option<()> {
        if !self.one_address(false)? {
            return Some(());
        }
        self.blanks();
        if self.eat(',') {
            self.blanks();
            if !self.one_address(true)? {
                return None;
            }
        }
        Some(())
    }

    /// `Some(true)` if one was read, `Some(false)` if none starts here, `None`
    /// if one starts here and is malformed. `second` allows `+N` and `~N`.
    fn one_address(&mut self, second: bool) -> Option<bool> {
        let brackets = self.dialect.brackets;

        match self.peek() {
            Some(next) if next.is_ascii_digit() => {
                self.digits();
                // `first~step`
                if self.eat('~') {
                    self.digits();
                }
            }
            Some('$') => self.at += 1,
            Some('+' | '~') if second => {
                self.at += 1;
                self.digits();
            }
            Some('/') => {
                self.at += 1;
                self.delimited('/', brackets)?;
                self.regex_flags();
            }
            // `\%regex%`
            Some('\\') => {
                self.at += 1;
                let delimiter = self.bump()?;
                if delimiter == '\n' || delimiter == '\\' {
                    return None;
                }
                self.delimited(delimiter, brackets)?;
                self.regex_flags();
            }
            _ => return Some(false),
        }
        Some(true)
    }

    fn regex_flags(&mut self) {
        while matches!(self.peek(), Some('I' | 'M')) {
            self.at += 1;
        }
    }

    /// Text up to the next unescaped `delimiter`, which is consumed. A backslash
    /// escapes the next character, a newline included; an unescaped newline ends
    /// the line, which sed reports as an unterminated command.
    fn delimited(&mut self, delimiter: char, brackets: bool) -> Option<()> {
        loop {
            match self.bump()? {
                next if next == delimiter => return Some(()),
                '\n' => return None,
                '\\' => {
                    self.bump()?;
                }
                '[' if brackets => self.bracket()?,
                _ => {}
            }
        }
    }

    /// A bracket expression, after its `[`: `[^]a]`, `[[:space:]]`.
    fn bracket(&mut self) -> Option<()> {
        self.eat('^');
        self.eat(']');

        loop {
            match self.bump()? {
                ']' => return Some(()),
                '\n' => return None,
                '[' if matches!(self.peek(), Some(':' | '.' | '=')) => {
                    let kind = self.bump()?;
                    loop {
                        let next = self.bump()?;
                        if next == '\n' {
                            return None;
                        }
                        if next == kind && self.eat(']') {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// What ends a command: the end of the script, `;`, a newline, or a `}` or
    /// `#` that the next step reads.
    fn end(&mut self) -> Option<()> {
        self.blanks();
        match self.peek() {
            None => Some(()),
            Some(';' | '\n') => {
                self.at += 1;
                Some(())
            }
            Some('}' | '#') => Some(()),
            Some(_) => None,
        }
    }

    /// The text of `a`, `i` and `c`, after the command: `a text`, `a\text`, or
    /// `a\` and the text on the following lines, each but the last ending in a
    /// backslash. The rest of the line is text, so a `;` or `}` in it ends nothing.
    fn text(&mut self) -> Option<()> {
        self.blanks();

        if self.eat('\\') {
            let mark = self.at;
            self.blanks();
            // `$a\` and nothing after it is valid in GNU sed, and an idiom: it
            // appends nothing, which adds the final newline a file lacks.
            if self.peek() == Some('\n') {
                // `a\` and spaces and a newline: GNU and BSD disagree on whether
                // the spaces are the text, so what follows could be a command.
                if self.at != mark {
                    return None;
                }
                self.at += 1;
            } else {
                self.at = mark;
            }
        } else if matches!(self.peek(), None | Some('\n')) {
            // `a` with nothing after it: sed reports a missing text.
            return None;
        }

        loop {
            match self.bump() {
                None | Some('\n') => return Some(()),
                Some('\\') => {
                    self.bump();
                }
                Some(_) => {}
            }
        }
    }

    /// A label, after `:`, `b`, `t`, `T` or `v`.
    fn label(&mut self) -> Option<()> {
        self.blanks();

        while let Some(next) = self.peek() {
            let ends = next == '\n'
                || (!self.dialect.label_to_newline
                    && (next.is_whitespace() || matches!(next, ';' | '}')));
            if ends {
                break;
            }
            self.at += 1;
        }
        self.end()
    }

    /// The file name of `r`, `R`, `w`, `W` and the `w` flag: everything to the end
    /// of the line, `;` and `}` included. A name with trailing spaces is the name
    /// with them in sed; both spellings are returned.
    fn file(&mut self) -> Option<Vec<String>> {
        self.blanks();
        let start = self.at;
        while !matches!(self.peek(), None | Some('\n')) {
            self.at += 1;
        }
        let raw: String = self.text[start..self.at].iter().collect();
        self.eat('\n');

        // sed reports a missing file name.
        if raw.is_empty() {
            return None;
        }
        // sed's own names for its standard streams are not files it opens
        // (`w /dev/stdout` is how a script prints the lines it matched).
        if SED_STREAMS.contains(&raw.as_str()) {
            return Some(Vec::new());
        }
        let trimmed = raw.trim_end().to_owned();
        let mut names = vec![raw];
        if !trimmed.is_empty() && trimmed != names[0] {
            names.push(trimmed);
        }
        Some(names)
    }

    /// `s/pattern/replacement/flags`, after the `s`.
    fn substitute(&mut self) -> Option<()> {
        let delimiter = self.bump()?;
        if delimiter == '\n' || delimiter == '\\' {
            return None;
        }
        self.delimited(delimiter, self.dialect.brackets)?;
        self.delimited(delimiter, false)?;

        loop {
            match self.peek() {
                Some('g' | 'p' | 'i' | 'I' | 'm' | 'M') => self.at += 1,
                Some(next) if next.is_ascii_digit() => self.at += 1,
                Some('e') if self.gnu => {
                    self.at += 1;
                    self.found.runs = true;
                }
                Some('w') => {
                    self.at += 1;
                    let names = self.file()?;
                    self.found.writes.extend(names);
                    return Some(());
                }
                _ => break,
            }
        }
        self.end()
    }

    /// `y/source/destination/`, after the `y`.
    fn transliterate(&mut self) -> Option<()> {
        let delimiter = self.bump()?;
        if delimiter == '\n' || delimiter == '\\' {
            return None;
        }
        self.delimited(delimiter, false)?;
        self.delimited(delimiter, false)?;
        self.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn files(args: &[&str]) -> ScriptFiles {
        script_files(
            &args
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    fn reads(args: &[&str]) -> Vec<String> {
        files(args).reads
    }

    fn writes(args: &[&str]) -> Vec<String> {
        files(args).writes
    }

    #[test]
    fn r_and_big_r_read_the_file_the_rest_of_the_line_names() {
        assert_eq!(reads(&["r .env", "notes.txt"]), words(".env"));
        assert_eq!(reads(&["R .env", "notes.txt"]), words(".env"));
        assert_eq!(reads(&["-n", "1r .env", "notes.txt"]), words(".env"));
        assert_eq!(reads(&["$r .env", "notes.txt"]), words(".env"));
        assert_eq!(reads(&["1,3r .env"]), words(".env"));
        assert_eq!(reads(&["/a/r .env"]), words(".env"));
        assert_eq!(reads(&["/a/I,/b/!r .env"]), words(".env"));
        assert_eq!(reads(&["\\%a%r .env"]), words(".env"));
        assert_eq!(reads(&["1~2r .env"]), words(".env"));
        assert_eq!(reads(&["2,+3r .env"]), words(".env"));
        assert_eq!(reads(&["1 ! r .env"]), words(".env"));
        assert_eq!(reads(&["r.env"]), words(".env"));
        assert_eq!(reads(&["/x/{p;r .env"]), Vec::<String>::new());
        assert_eq!(reads(&["/x/{p;r .env\n}"]), words(".env"));
        // `}` on the same line is part of the name in sed, which then reports an
        // unmatched `{`: the script is refused
        assert!(files(&["/x/{p;r .env}"]).refused.is_some());
        assert_eq!(
            reads(&["r data/clients/x.csv"]),
            words("data/clients/x.csv")
        );
    }

    #[test]
    fn the_name_is_the_rest_of_the_line_as_in_sed() {
        // `; p` is part of the name in sed, so the script reads a file called
        // `.env; p`. veil judges that name, and the one without trailing spaces.
        assert_eq!(reads(&["r .env; p"]), vec![".env; p".to_owned()]);
        assert_eq!(
            reads(&["r .env "]),
            vec![".env ".to_owned(), ".env".to_owned()]
        );
        // a newline ends it, so the next line is a command again
        assert_eq!(reads(&["r .env\np"]), words(".env"));
        assert_eq!(files(&["r .env\np"]).refused, None);
    }

    #[test]
    fn w_big_w_and_the_s_flag_write_files() {
        assert_eq!(writes(&["-e", "w .env", "notes.txt"]), words(".env"));
        assert_eq!(writes(&["W .env"]), words(".env"));
        assert_eq!(writes(&["s/a/b/w .env", "notes.txt"]), words(".env"));
        assert_eq!(writes(&["s/a/b/gw .env"]), words(".env"));
        assert_eq!(writes(&["s/a/b/2pw .env"]), words(".env"));
        assert_eq!(writes(&["s|a|b|w out.txt"]), words("out.txt"));
        assert_eq!(reads(&["s/a/b/w .env"]), Vec::<String>::new());
    }

    #[test]
    fn text_is_not_a_command() {
        for script in [
            "s/r .env/x/",
            "s/a/r .env/",
            "s/a/b/;s/r .env/x/",
            "# r .env",
            "a r .env",
            "a\\r .env",
            "i\\\nr .env",
            "c\\\nfirst\\\nr .env",
            "y/r.env/x/",
            "/r .env/d",
            "/x/s/r .env/y/",
            ":r .env",
            "b r",
        ] {
            let found = files(&[script, "notes.txt"]);
            assert_eq!(
                (found.reads, found.writes, found.refused),
                (Vec::new(), Vec::new(), None),
                "{script}"
            );
        }
    }

    #[test]
    fn a_command_after_text_or_a_comment_is_still_a_command() {
        assert_eq!(reads(&["a x\nr .env"]), words(".env"));
        assert_eq!(reads(&["# note\nr .env"]), words(".env"));
        assert_eq!(reads(&["s/a/b/\nr .env"]), words(".env"));
        assert_eq!(reads(&["a\\\ntext\nr .env"]), words(".env"));
        assert_eq!(reads(&["a\\\ntext\\\nmore\nr .env"]), words(".env"));
        assert_eq!(reads(&["p;r .env"]), words(".env"));
        assert_eq!(reads(&["$!N;r .env"]), words(".env"));
        assert_eq!(reads(&[":a;N;$!ba;r .env"]), words(".env"));
    }

    #[test]
    fn every_way_of_giving_the_script_is_read() {
        let env = words(".env");
        assert_eq!(reads(&["-e", "p", "-e", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-er .env", "notes.txt"]), env);
        assert_eq!(reads(&["-ne", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-ner .env", "notes.txt"]), env);
        assert_eq!(reads(&["--expression=r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--expression", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--expr=r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--e=r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-s", "-n", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-E", "-n", "--", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--posix", "r .env"]), env);
        assert_eq!(reads(&["-l", "5", "r .env"]), env);
        assert_eq!(reads(&["--line-length=5", "r .env"]), env);
        // GNU: the suffix is attached, the script is the first operand.
        assert_eq!(reads(&["-i.bak", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-i", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--in-place=.bak", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["--in-place", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-ni", "r .env", "notes.txt"]), env);
        // BSD: the next word is the suffix, even an empty one.
        assert_eq!(reads(&["-i", "", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-i", ".bak", "-e", "r .env", "notes.txt"]), env);
        assert_eq!(reads(&["-I", "", "r .env", "notes.txt"]), env);
        // the a\ text continues into the next -e, as in sed
        assert_eq!(reads(&["-e", "a\\", "-e", "r .env"]), Vec::<String>::new());
        assert_eq!(reads(&["-e", "a\\", "-e", "text", "-e", "r .env"]), env);
    }

    #[test]
    fn sed_own_standard_stream_names_are_not_files() {
        assert_eq!(files(&["w /dev/stdout"]), ScriptFiles::default());
        assert_eq!(files(&["s/a/b/w /dev/stderr"]), ScriptFiles::default());
        assert_eq!(files(&["r /dev/stdin"]), ScriptFiles::default());
        // any other device path is still a name for the evaluator to judge
        assert_eq!(writes(&["w /dev/fd/1"]), words("/dev/fd/1"));
        assert_eq!(reads(&["r /dev/fd/3"]), words("/dev/fd/3"));
    }

    #[test]
    fn a_script_file_is_not_read_here() {
        // the name `-f` is given is a path the argv rule judges; the first operand
        // is then an input file, not a script
        for args in [
            vec!["-f", "script.sed", "r .env"],
            vec!["--file=script.sed", "r .env"],
            vec!["--file", "script.sed", "r .env"],
            vec!["-nf", "script.sed", "r .env"],
            vec!["-fscript.sed", "r .env"],
        ] {
            assert_eq!(files(&args), ScriptFiles::default(), "{args:?}");
        }
        // but an -e beside it is still a script
        assert_eq!(reads(&["-f", "script.sed", "-e", "r .env"]), words(".env"));
    }

    #[test]
    fn nothing_to_parse_is_not_a_refusal() {
        for args in [
            vec![],
            vec!["--version"],
            vec!["--help"],
            vec!["-n"],
            vec!["-i"],
            vec!["-e"],
        ] {
            assert_eq!(files(&args), ScriptFiles::default(), "{args:?}");
        }
    }

    #[test]
    fn a_script_that_runs_a_command_is_refused() {
        for script in [
            "e cat .env",
            "e",
            "1e echo hi",
            "s/a/b/e",
            "s/a/b/ge",
            "$!{e id}",
        ] {
            let found = files(&[script, "notes.txt"]);
            assert!(found.refused.is_some(), "{script}");
        }
        assert_eq!(
            files(&["e cat .env", "notes.txt"]).refused.as_deref(),
            Some("e cat .env")
        );
    }

    #[test]
    fn a_script_no_reading_parses_is_refused() {
        for script in [
            "k",
            "r",
            "w",
            "s/a/b",
            "s/a",
            "s",
            "y/abc/xyz",
            "/a",
            "/a/",
            "1,",
            "{p",
            "p}",
            "pp",
            "a",
            "a\\  \ntext",
            "s/a/b/z",
            "1,3",
            "s/a\nb/c/",
            "!!",
            "\\",
        ] {
            let found = files(&[script, "notes.txt"]);
            assert_eq!(found.refused.as_deref(), Some(script), "{script:?}");
        }
    }

    #[test]
    fn the_readings_of_a_bracket_and_a_label_are_a_union() {
        // BSD skips the bracket, GNU does not: one reading parses each.
        assert_eq!(files(&["s/[/]/x/"]).refused, None);
        assert_eq!(files(&["s/[/]/x/w .env"]).writes, words(".env"));
        assert_eq!(files(&["/[/]/d"]).refused, None);
        assert_eq!(files(&["s/[[:space:]/]*//"]).refused, None);
        assert_eq!(files(&["s/[^]/]*//"]).refused, None);
        // a label that runs to the newline (BSD) swallows `;r .env`, a label that
        // ends at `;` (GNU) does not: the file is found
        assert_eq!(reads(&["b end;r .env\n:end"]), words(".env"));
        assert_eq!(reads(&[":a;r .env"]), words(".env"));
    }

    #[test]
    fn a_suffix_taken_for_the_script_does_not_refuse_a_good_script() {
        // BSD reading: the suffix is `s/a/b/` and the script is `notes.txt`,
        // which is not a script. The GNU reading parses, so nothing is refused.
        assert_eq!(
            files(&["-i", "s/a/b/", "notes.txt"]),
            ScriptFiles::default()
        );
        assert_eq!(files(&["-i", "5d", "notes.txt"]), ScriptFiles::default());
    }

    #[test]
    fn a_file_name_is_not_parsed_as_the_gnu_exec_command() {
        // Found replaying real commands: with `-i` the BSD reading takes the next
        // word as the script, and `edgar-transform/x.py` begins with `e`. BSD has
        // no `e`, so that reading does not parse and the command is not refused.
        for file in [
            "edgar.py",
            "edgar-transform/x.py",
            "error.log",
            "e",
            "ex.txt",
        ] {
            assert_eq!(
                files(&["-i", "s/a/b/", file]),
                ScriptFiles::default(),
                "{file}"
            );
            assert_eq!(
                files(&["-i", "", "s/a/b/", file]),
                ScriptFiles::default(),
                "{file}"
            );
            assert_eq!(
                files(&["-i.bak", "s/a/b/", file]),
                ScriptFiles::default(),
                "{file}"
            );
        }
        // GNU runs the command when the script is the one `-i` leaves alone
        assert!(files(&["-i", "e id", "f"]).refused.is_some());
        assert!(files(&["-i.bak", "e id", "f"]).refused.is_some());
        // and with `-i ''` GNU reads `e id` as an input file, BSD rejects it
        assert_eq!(files(&["-i", "", "e id", "f"]), ScriptFiles::default());
    }

    #[test]
    fn a_redirection_is_not_the_script() {
        // Found replaying real commands: `sed --version 2>&1` was refused because
        // `2>&1` was taken for the script.
        for args in [
            vec!["--version", "2>&1"],
            vec!["-n", "2>&1"],
            vec!["s/a/b/", "notes.txt", "2>/dev/null"],
            vec!["s/a/b/", "notes.txt", ">", "out.txt"],
            vec!["s/a/b/", "notes.txt", ">>out.txt"],
            vec!["s/a/b/", "notes.txt", "2>&1"],
        ] {
            assert_eq!(files(&args), ScriptFiles::default(), "{args:?}");
        }
        assert_eq!(reads(&["2>&1", "r .env"]), words(".env"));
        assert_eq!(reads(&[">out", "r .env", "notes.txt"]), words(".env"));
        assert_eq!(reads(&["r .env", "notes.txt", "2>&1"]), words(".env"));
    }

    #[test]
    fn scripts_people_write_all_parse() {
        for script in [
            "5p",
            "s/a/b/",
            "s/a/b/g",
            "s|a|b|",
            "s#a#b#g",
            "s,a,b,",
            "s a b ",
            "/^$/d",
            "/^#/d",
            "$d",
            "1d",
            "1,3d",
            "2,$d",
            "1!G;h;$!d",
            "$!N;s/\\n/ /",
            ":a;N;$!ba;s/\\n/ /g",
            ":a\nN\n$!ba\ns/\\n/ /g",
            "s/[[:space:]]*$//",
            "s/^[ \\t]*//;s/[ \\t]*$//",
            "/foo/,/bar/d",
            "/foo/{p;q}",
            "/foo/{\np\nq\n}",
            "/foo/!d",
            "s/\\(a\\)\\(b\\)/\\2\\1/",
            "s/a\\/b/c/",
            "s/\\//_/g",
            "y/abc/xyz/",
            "1i\\header",
            "1i\\\nheader",
            "$a\\footer",
            "$a footer",
            // appends nothing, which adds the final newline a file lacks
            "$a\\",
            "/x/c\\replaced",
            "1~2d",
            "0~3p",
            "2,+3d",
            "/a/,+2p",
            "2q",
            "q5",
            "p;p",
            "/start/,/end/p",
            "s/.*/\"&\"/",
            "s/a/b/Ig",
            "s/a/b/w /dev/stdout",
            "w /dev/stderr",
            "n;d",
            "=",
            "l",
            "l 20",
            "{p}",
            "{p;p}",
            "/a/{n;d}",
            "/a/{s//b/;}",
            "#n\np",
            "/x/ s/a/b/",
            "1 d",
            "$ p",
            "s/a/b/ ; s/c/d/",
            "$!{h;d};x;G",
            "/^\\s*$/d",
            "s/[^,]*,//2",
            "s/'/\"/g",
            "s/a/\\\nb/",
            "/x/I p",
            "s/a/b/;T;d",
            "",
            "  ",
            ";;p;;",
            "\n",
        ] {
            let found = files(&[script, "notes.txt"]);
            assert_eq!(
                (found.reads, found.writes, found.refused),
                (Vec::new(), Vec::new(), None),
                "{script:?}"
            );
        }
    }

    #[test]
    fn a_huge_script_does_not_overflow_the_stack() {
        let script = "{".repeat(100_000);
        assert!(files(&[script.as_str()]).refused.is_some());
        let script = format!("{}p{}", "{".repeat(100_000), "}".repeat(100_000));
        assert_eq!(files(&[script.as_str()]).refused, None);
    }
}
