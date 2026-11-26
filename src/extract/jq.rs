//! The files a `jq` program names through its module system (bd-3h5).
//!
//! `jq -n 'import "secret" as $d; $d'` prints `./secret.json`. The file name is a
//! string inside the program, with no slash or extension, so no word of the
//! command is shaped like a path and the argv rule never sees it. jq has no other
//! way to open a file from inside a program: `input` reads the files on the
//! command line, which are words, and `--rawfile` and `--slurpfile` name theirs
//! on the command line too. The module system is the whole gap.
//!
//! What jq does, measured on jq 1.8.2:
//!
//! - `import "x" as $d;` opens `x.json`, or `x/x.json` (the data, as an array);
//!   `import "x" as m;` and `include "x";` open `x.jq`, or `x/x.jq`. A name with
//!   directories (`clients/holdings`) opens `clients/holdings.json` and
//!   `clients/holdings/holdings.json`;
//! - they are looked for in the working directory and in every `-L` directory
//!   (so `-L` adds to the working directory and does not replace it), or in
//!   `~/.jq` when there is no `-L`. An import with `{search: "dir"}` metadata is
//!   looked for only in the directories it names, relative to the file the
//!   import is in, and neither the working directory nor `-L` is searched;
//! - imports come first: after the optional `module {...};` line and before any
//!   definition. jq rejects an `import` anywhere else;
//! - a `.jq` module that does not parse is reported with its own source line,
//!   so naming a protected file as a module leaks a line of it, as `.json` does
//!   in full;
//! - `-f` is a flag: the first operand is then the program file, and its imports
//!   are searched from the working directory, not from the file's own directory.
//!
//! This module reads the program the way jq does and returns the files an import
//! may open. It reads the prelude only: the rest of a jq program opens no file.
//! A prelude it cannot read (a name built with `\( )`, which jq itself rejects,
//! an unterminated string) is refused, never skipped, like a sed script.

use std::collections::HashSet;

/// Programs that are jq.
pub(super) fn is_jq(name: &str) -> bool {
    name == "jq"
}

/// How a jq command line gives its program.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct CommandLine {
    /// The program text, when it is on the command line.
    pub program: Option<String>,
    /// The program file: with `-f` or `--from-file`, the first operand.
    pub program_file: Option<String>,
    /// The `-L` and `--library-path` directories, in order.
    pub libraries: Vec<String>,
}

/// The program and library directories of the words after `jq`.
pub(super) fn command_line(args: &[String]) -> CommandLine {
    let args: Vec<&str> = super::strip_redirection_words(args);
    let mut libraries: Vec<String> = Vec::new();
    let mut from_file = false;
    let mut first: Option<String> = None;
    let mut options_ended = false;
    let mut index = 0;

    while index < args.len() {
        let word = args[index];
        index += 1;

        if options_ended || word == "-" || !word.starts_with('-') {
            first.get_or_insert_with(|| word.to_owned());
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
            match (name, value) {
                // jq 1.8.2 takes `--library-path dir` only; `=` is accepted here
                // too, since a spelling jq rejects costs nothing to read.
                ("library-path", Some(dir)) => libraries.push(dir.to_owned()),
                ("library-path", None) => {
                    if let Some(next) = args.get(index) {
                        libraries.push((*next).to_owned());
                    }
                    index += 1;
                }
                ("from-file", _) => from_file = true,
                // two words: a name and a value or a file
                ("arg" | "argjson" | "slurpfile" | "rawfile", None) => index += 2,
                ("indent", None) => index += 1,
                _ => {}
            }
            continue;
        }

        // A cluster of short options: `-n`, `-rn`, `-nf`, `-nL lib`, `-Llib`.
        for (offset, option) in word.char_indices().skip(1) {
            match option {
                'f' => from_file = true,
                'L' => {
                    let rest = &word[offset + option.len_utf8()..];
                    if rest.is_empty() {
                        if let Some(next) = args.get(index) {
                            libraries.push((*next).to_owned());
                        }
                        index += 1;
                    } else {
                        libraries.push(rest.to_owned());
                    }
                    break;
                }
                _ => {}
            }
        }
    }

    let mut line = CommandLine {
        libraries,
        ..CommandLine::default()
    };
    if from_file {
        line.program_file = first;
    } else {
        line.program = first;
    }
    line
}

/// One `import` or `include` directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Import {
    /// The module name, as the string says it.
    pub name: String,
    /// `import "x" as $d;`: the data in `x.json`. Otherwise a module, `x.jq`.
    pub data: bool,
    /// The directories of the import's `{search: ...}` metadata, as written.
    pub search: Vec<String>,
}

/// What the imports at the start of a program are.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Prelude {
    pub imports: Vec<Import>,
    /// The prelude could not be read in full, or has more imports than veil
    /// follows: what it opens is not known.
    pub refused: bool,
}

/// More directives than any real program has. A prelude past it is refused.
const MAX_IMPORTS: usize = 64;

/// How deep the metadata of an import may nest arrays and objects. Real
/// metadata is one level, `{search: ["a", "b"]}`; past this it is refused.
const MAX_NESTING: usize = 32;

/// The imports at the start of the jq program `text`: the optional `module`
/// line, then every `import` and `include` before the first thing that is
/// neither. Whatever follows opens no file, and is not read.
pub(super) fn prelude(text: &str) -> Prelude {
    let mut parser = Parser {
        text: text.chars().collect(),
        at: 0,
        nesting: 0,
    };
    let mut found = Prelude::default();

    parser.skip();
    if parser.keyword("module") && parser.module_line().is_none() {
        found.refused = true;
        return found;
    }

    loop {
        parser.skip();
        let data_or_module = if parser.keyword("import") {
            true
        } else if parser.keyword("include") {
            false
        } else {
            return found;
        };

        let Some(import) = parser.directive(data_or_module) else {
            found.refused = true;
            return found;
        };
        found.imports.push(import);
        if found.imports.len() > MAX_IMPORTS {
            found.refused = true;
            return found;
        }
    }
}

struct Parser {
    text: Vec<char>,
    at: usize,
    /// Arrays and objects open at `at`.
    nesting: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.text.get(self.at).copied()
    }

    /// Whitespace, and `#` comments to the end of the line. A comment ends at
    /// the newline in every jq; newer ones also continue it after a backslash,
    /// and reading the next line as code only finds more, never fewer.
    fn skip(&mut self) {
        while let Some(next) = self.peek() {
            if next.is_whitespace() {
                self.at += 1;
            } else if next == '#' {
                while self.peek().is_some_and(|ch| ch != '\n') {
                    self.at += 1;
                }
            } else {
                break;
            }
        }
    }

    /// The next word, without consuming it: an identifier, with `::` segments.
    fn word(&self) -> String {
        let mut end = self.at;
        while let Some(ch) = self.text.get(end) {
            let colon = *ch == ':'
                && self.text.get(end + 1) == Some(&':')
                && self
                    .text
                    .get(end + 2)
                    .is_some_and(|next| next.is_alphabetic() || *next == '_');
            if ch.is_alphanumeric() || *ch == '_' {
                end += 1;
            } else if colon {
                end += 2;
            } else {
                break;
            }
        }
        self.text[self.at..end].iter().collect()
    }

    /// Consumes `word` when it is the next whole word.
    fn keyword(&mut self, word: &str) -> bool {
        if self.word() == word {
            self.at += word.chars().count();
            true
        } else {
            false
        }
    }

    fn eat(&mut self, expected: char) -> bool {
        self.skip();
        let found = self.peek() == Some(expected);
        self.at += usize::from(found);
        found
    }

    /// `module {...};`
    fn module_line(&mut self) -> Option<()> {
        self.skip();
        self.object(&mut Vec::new())?;
        self.eat(';').then_some(())
    }

    /// What follows `import` or `include`: the name, for an import `as` and the
    /// binding, the optional metadata object, and `;`.
    fn directive(&mut self, import: bool) -> Option<Import> {
        self.skip();
        let name = self.string()?;
        let mut data = false;

        if import {
            self.skip();
            if !self.keyword("as") {
                return None;
            }
            self.skip();
            data = self.eat('$');
            self.skip();
            let binding = self.word();
            if binding.is_empty() {
                return None;
            }
            self.at += binding.chars().count();
        }

        let mut search = Vec::new();
        self.skip();
        if self.peek() == Some('{') {
            self.object(&mut search)?;
        }
        self.eat(';').then_some(Import { name, data, search })
    }

    /// A string literal, escapes decoded. One with an interpolation (`\( )`) is
    /// no constant, and jq rejects it as a module name.
    fn string(&mut self) -> Option<String> {
        if self.peek() != Some('"') {
            return None;
        }
        self.at += 1;
        let mut out = String::new();

        loop {
            let ch = self.peek()?;
            self.at += 1;
            match ch {
                '"' => return Some(out),
                '\\' => {
                    let escape = self.peek()?;
                    self.at += 1;
                    match escape {
                        '"' | '\\' | '/' => out.push(escape),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.unicode()?),
                        _ => return None,
                    }
                }
                _ => out.push(ch),
            }
        }
    }

    /// The four hex digits after `\u`, joined with a following `\uXXXX` when
    /// the first is half of a surrogate pair.
    fn unicode(&mut self) -> Option<char> {
        let first = self.hex4()?;

        if (0xD800..0xDC00).contains(&first) {
            if self.peek() != Some('\\') || self.text.get(self.at + 1) != Some(&'u') {
                return None;
            }
            self.at += 2;
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return None;
            }
            return char::from_u32(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00));
        }
        char::from_u32(first)
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits: String = self.text.get(self.at..self.at + 4)?.iter().collect();
        self.at += 4;
        u32::from_str_radix(&digits, 16).ok()
    }

    /// A constant object. The strings of its `search` key (one string, or an
    /// array of them) are added to `search`.
    fn object(&mut self, search: &mut Vec<String>) -> Option<()> {
        self.skip();
        if !self.eat('{') {
            return None;
        }
        self.skip();
        if self.eat('}') {
            return Some(());
        }

        loop {
            self.skip();
            let key = if self.peek() == Some('"') {
                self.string()?
            } else {
                let word = self.word();
                if word.is_empty() {
                    return None;
                }
                self.at += word.chars().count();
                word
            };
            if !self.eat(':') {
                return None;
            }
            self.value(key == "search", search)?;
            self.skip();
            if self.eat('}') {
                return Some(());
            }
            if !self.eat(',') {
                return None;
            }
        }
    }

    /// Runs `inner` one level deeper. A value nested past [`MAX_NESTING`] is
    /// refused, so a command of ten thousand `[` cannot overflow the stack of
    /// the hook, which would be no decision at all.
    fn nested(&mut self, inner: impl FnOnce(&mut Self) -> Option<()>) -> Option<()> {
        if self.nesting >= MAX_NESTING {
            return None;
        }
        self.nesting += 1;
        let parsed = inner(self);
        self.nesting -= 1;
        parsed
    }

    /// A constant value. Strings are collected when `collect` is set.
    fn value(&mut self, collect: bool, search: &mut Vec<String>) -> Option<()> {
        self.skip();
        match self.peek()? {
            '"' => {
                let text = self.string()?;
                if collect {
                    search.push(text);
                }
                Some(())
            }
            '[' => self.nested(|parser| {
                parser.at += 1;
                parser.skip();
                if parser.eat(']') {
                    return Some(());
                }
                loop {
                    parser.value(collect, search)?;
                    parser.skip();
                    if parser.eat(']') {
                        return Some(());
                    }
                    if !parser.eat(',') {
                        return None;
                    }
                }
            }),
            '{' => self.nested(|parser| parser.object(&mut Vec::new())),
            _ => {
                // a number, `true`, `false` or `null`
                let start = self.at;
                while self
                    .peek()
                    .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-' | '+'))
                {
                    self.at += 1;
                }
                (self.at > start).then_some(())
            }
        }
    }
}

/// The files `import` may open, in the order jq looks. `module_dir` is the
/// directory of the file the import is in (`.` for a program on the command
/// line); `home` is the home directory, for the default search `~/.jq`.
///
/// Without a `search` in its metadata an import is looked for in the working
/// directory and in every `-L` directory, or in `~/.jq` when there is no `-L`.
/// With one, jq looks only in the directories it names: neither the working
/// directory nor `-L` is searched (measured on jq 1.8.2). A `search` that names
/// no directory (`[]`) is read as none, so as the default search, which names
/// more than jq opens, never fewer.
pub(super) fn candidates(
    import: &Import,
    libraries: &[String],
    module_dir: &str,
    home: Option<&str>,
) -> Vec<String> {
    let mut directories: Vec<String> = Vec::new();

    if import.search.is_empty() {
        directories.push(".".to_owned());
        if libraries.is_empty() {
            if let Some(home) = home {
                directories.push(format!("{home}/.jq"));
            }
        } else {
            directories.extend(libraries.iter().cloned());
        }
    }
    for dir in &import.search {
        if dir.starts_with('/') {
            directories.push(dir.clone());
        } else if let (Some(rest), Some(home)) = (dir.strip_prefix("~/"), home) {
            directories.push(format!("{home}/{rest}"));
        } else {
            // jq resolves the main program's from the working directory, and a
            // module's from the module: either is read, since which one a
            // program file's own `search` is relative to is not settled.
            if module_dir == "." {
                directories.push(dir.clone());
            } else {
                directories.push(format!("{module_dir}/{dir}"));
                directories.push(format!("./{dir}"));
            }
        }
    }

    let extension = if import.data { "json" } else { "jq" };
    let last = import.name.rsplit('/').next().unwrap_or(&import.name);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();

    for dir in directories {
        for file in [
            format!("{dir}/{}.{extension}", import.name),
            format!("{dir}/{}/{last}.{extension}", import.name),
        ] {
            if seen.insert(file.clone()) {
                out.push(file);
            }
        }
    }
    out
}

/// The module files (`.jq`) among the candidates of `imports`: those that a
/// reader of the program must open to see what they import in turn.
pub(super) fn module_candidates(
    imports: &[Import],
    libraries: &[String],
    module_dir: &str,
    home: Option<&str>,
) -> Vec<String> {
    imports
        .iter()
        .filter(|import| !import.data)
        .flat_map(|import| candidates(import, libraries, module_dir, home))
        .collect()
}

/// What an inline program (not a program file) names: every file its imports
/// may open, to be judged as named paths, and whether the prelude is refused.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Named {
    pub files: Vec<String>,
    pub refused: Option<String>,
}

/// The files the program on the command line `args` names. A program file
/// (`-f`) is read by the caller, which has the file.
pub(super) fn inline_files(args: &[String], home: Option<&str>) -> Named {
    let line = command_line(args);
    let Some(program) = &line.program else {
        return Named::default();
    };
    let found = prelude(program);
    let mut named = Named::default();

    for import in &found.imports {
        named
            .files
            .extend(candidates(import, &line.libraries, ".", home));
    }
    if found.refused {
        named.refused = Some(program.clone());
    }
    named
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(args: &[&str]) -> Vec<String> {
        args.iter().map(|word| (*word).to_owned()).collect()
    }

    fn names(program: &str) -> Vec<(String, bool)> {
        prelude(program)
            .imports
            .into_iter()
            .map(|import| (import.name, import.data))
            .collect()
    }

    fn pair(name: &str, data: bool) -> (String, bool) {
        (name.to_owned(), data)
    }

    #[test]
    fn the_program_and_the_library_directories_are_found_however_they_are_given() {
        let line = |args: &[&str]| command_line(&owned(args));

        assert_eq!(line(&["-n", "1"]).program.as_deref(), Some("1"));
        assert_eq!(line(&["-n", "1"]).libraries, Vec::<String>::new());
        for args in [
            &["-L", "lib", "-n", "1"][..],
            &["-Llib", "-n", "1"],
            &["-nL", "lib", "1"],
            &["-rnL", "lib", "1"],
            &["--library-path", "lib", "-n", "1"],
            &["-n", "1", "-L", "lib"],
        ] {
            let found = line(args);
            assert_eq!(found.libraries, owned(&["lib"]), "{args:?}");
            assert_eq!(found.program.as_deref(), Some("1"), "{args:?}");
        }
        assert_eq!(
            line(&["-L", "a", "-L", "b", "1"]).libraries,
            owned(&["a", "b"])
        );

        // options with values do not hide the program
        for args in [
            &["--arg", "x", "import", "1"][..],
            &["--argjson", "x", "1", "1"],
            &["--rawfile", "x", "f", "1"],
            &["--slurpfile", "x", "f", "1"],
            &["--indent", "3", "1"],
            &["-n", "--args", "1", "a", "b"],
            &["-r", "--", "1"],
        ] {
            assert_eq!(line(args).program.as_deref(), Some("1"), "{args:?}");
        }
    }

    #[test]
    fn with_dash_f_the_first_operand_is_the_program_file() {
        for args in [
            &["-f", "prog.jq"][..],
            &["-nf", "prog.jq"],
            &["-fn", "prog.jq"],
            &["--from-file", "prog.jq"],
            &["prog.jq", "-f"],
            &["-n", "-f", "prog.jq", "input.json"],
        ] {
            let found = command_line(&owned(args));
            assert_eq!(found.program_file.as_deref(), Some("prog.jq"), "{args:?}");
            assert_eq!(found.program, None, "{args:?}");
        }
    }

    #[test]
    fn a_prelude_is_the_module_line_and_the_imports_before_the_first_definition() {
        assert_eq!(
            names("import \"secret\" as $d; $d"),
            vec![pair("secret", true)]
        );
        assert_eq!(names("include \"mod\"; 1"), vec![pair("mod", false)]);
        assert_eq!(names("import \"mod\" as m; m::f"), vec![pair("mod", false)]);
        assert_eq!(
            names("module {name: \"x\"}; import \"a\" as $a; include \"b\"; import \"c\" as c; 1"),
            vec![pair("a", true), pair("b", false), pair("c", false)]
        );
        assert_eq!(
            names("# a comment\nimport \"a\" as $a; # another\n\nimport \"b\" as $b;\n$a"),
            vec![pair("a", true), pair("b", true)]
        );
        assert_eq!(
            names("import \"clients/holdings\" as $d; $d"),
            vec![pair("clients/holdings", true)]
        );
        // `$d::d`, and a binding with a module prefix
        assert_eq!(names("import \"a\" as $d::d; 1"), vec![pair("a", true)]);

        // a name written with escapes is the name it spells
        assert_eq!(names("import \"sec\\u0072et\" as $d; 1")[0].0, "secret");
        assert_eq!(names("import \"a\\/b\" as $d; 1")[0].0, "a/b");
        assert_eq!(
            names("import \"\\ud83d\\ude00\" as $d; 1")[0].0,
            "\u{1f600}"
        );

        // no import, or nothing at the start: nothing to follow, nothing refused
        for program in [
            "",
            ".",
            ".a[]",
            "def f: 1; f",
            "import_data",
            ".import",
            "important",
            "$import",
            "def f: 1; import \"x\" as $d; 1",
            "\"import \\\"secret\\\" as $d;\"",
        ] {
            assert_eq!(prelude(program), Prelude::default(), "{program:?}");
        }
    }

    #[test]
    fn the_search_metadata_is_read() {
        let found = prelude("import \"a\" as $d {search: \"./sub\"}; 1");
        assert_eq!(found.imports[0].search, owned(&["./sub"]));

        let found = prelude("import \"a\" as $d {search: [\"./x\", \"../y\"], optional: true}; 1");
        assert_eq!(found.imports[0].search, owned(&["./x", "../y"]));

        let found = prelude("include \"a\" {\"search\": \"/abs\", n: [1, {k: \"v\"}]}; 1");
        assert_eq!(found.imports[0].search, owned(&["/abs"]));
        assert!(!found.refused);

        // another key's strings are not directories
        let found = prelude("import \"a\" as $d {other: \"./sub\"}; 1");
        assert!(found.imports[0].search.is_empty());
    }

    #[test]
    fn a_prelude_veil_cannot_read_is_refused() {
        for program in [
            "import \"sec\\(\"r\")et\" as $d; $d",
            "import \"secret",
            "import \"secret\" as; 1",
            "import \"secret\" $d; 1",
            "import \"secret\" as $d",
            "import secret as $d; 1",
            "include \"a\" {search: }; 1",
            "include \"a\" {search: \"x\"; 1",
            "import \"a\\q\" as $d; 1",
            "import \"\\ud83d\" as $d; 1",
            "module 1; import \"a\" as $d; 1",
            "include",
        ] {
            assert!(prelude(program).refused, "{program:?}");
        }

        let many = "import \"a\" as $a;".repeat(MAX_IMPORTS + 1);
        assert!(prelude(&many).refused);
        let few = "import \"a\" as $a;".repeat(MAX_IMPORTS);
        assert!(!prelude(&few).refused);
    }

    #[test]
    fn metadata_nested_without_end_is_refused_and_cannot_overflow_the_stack() {
        // ten thousand and a million levels: recursion this deep would overflow
        // the stack of the hook, which is no decision at all
        for depth in [MAX_NESTING + 1, 10_000, 1_000_000] {
            for (open, close) in [("[", "]"), ("{a:", "}")] {
                let program = format!(
                    "import \"a\" as $d {{search: {}\"x\"{}}}; 1",
                    open.repeat(depth),
                    close.repeat(depth)
                );
                assert!(prelude(&program).refused, "depth {depth} {open}");
            }
        }
        // and a thousand unclosed ones
        let program = format!("import \"a\" as $d {{search: {}", "[".repeat(1000));
        assert!(prelude(&program).refused);

        // real metadata is one or two levels deep
        let found = prelude("import \"a\" as $d {search: [[\"x\"]], extra: {k: [1, 2]}}; 1");
        assert!(!found.refused);
        assert_eq!(found.imports[0].search, owned(&["x"]));
        let found = prelude(&format!(
            "import \"a\" as $d {{search: {}\"x\"{}}}; 1",
            "[".repeat(MAX_NESTING),
            "]".repeat(MAX_NESTING)
        ));
        assert!(!found.refused);
    }

    #[test]
    fn candidates_follow_the_search_jq_makes() {
        let import = |name: &str, data: bool| Import {
            name: name.to_owned(),
            data,
            search: Vec::new(),
        };

        // the working directory is searched with no `-L`, and `~/.jq`
        assert_eq!(
            candidates(&import("secret", true), &[], ".", Some("/home/me")),
            owned(&[
                "./secret.json",
                "./secret/secret.json",
                "/home/me/.jq/secret.json",
                "/home/me/.jq/secret/secret.json",
            ])
        );
        // `-L` adds directories and takes the default away; the working directory stays
        assert_eq!(
            candidates(
                &import("mod", false),
                &owned(&["lib"]),
                ".",
                Some("/home/me")
            ),
            owned(&["./mod.jq", "./mod/mod.jq", "lib/mod.jq", "lib/mod/mod.jq"])
        );
        // a name with directories: the last component names the file inside it
        assert_eq!(
            candidates(
                &import("clients/holdings", true),
                &owned(&["data"]),
                ".",
                None
            ),
            owned(&[
                "./clients/holdings.json",
                "./clients/holdings/holdings.json",
                "data/clients/holdings.json",
                "data/clients/holdings/holdings.json",
            ])
        );
        // the data form opens `.json` and the module form `.jq`, never the other
        let data = candidates(&import("x", true), &[], ".", None);
        assert!(data.iter().all(|file| file.ends_with(".json")));
        let module = candidates(&import("x", false), &[], ".", None);
        assert!(module.iter().all(|file| file.ends_with(".jq")));
    }

    #[test]
    fn search_metadata_replaces_the_default_directories_and_is_relative_to_the_file_the_import_is_in()
     {
        let with_search = |dirs: &[&str]| Import {
            name: "x".to_owned(),
            data: true,
            search: owned(dirs),
        };

        let found = candidates(
            &with_search(&["./sub", "/abs", "~/mine"]),
            &owned(&["lib"]),
            ".",
            Some("/h"),
        );
        assert!(found.contains(&"./sub/x.json".to_owned()));
        assert!(found.contains(&"/abs/x.json".to_owned()));
        assert!(found.contains(&"/h/mine/x.json".to_owned()));
        // jq searches only these: not the working directory, `-L` or `~/.jq`
        assert_eq!(found.len(), 6, "{found:?}");
        for default in ["./x.json", "lib/x.json", "/h/.jq/x.json"] {
            assert!(!found.contains(&default.to_owned()), "{default}: {found:?}");
        }

        // in a module in `lib`, a relative directory is read from the module and from here
        let found = candidates(&with_search(&["../sub"]), &[], "lib", None);
        assert!(found.contains(&"lib/../sub/x.json".to_owned()));
        assert!(found.contains(&"./../sub/x.json".to_owned()));
    }

    #[test]
    fn the_modules_among_the_candidates_are_the_jq_files_of_the_non_data_imports() {
        let found = prelude("import \"d\" as $d; include \"m\"; import \"n\" as n; 1");
        let modules = module_candidates(&found.imports, &[], ".", None);

        assert_eq!(
            modules,
            owned(&["./m.jq", "./m/m.jq", "./n.jq", "./n/n.jq"])
        );
    }

    #[test]
    fn an_inline_program_names_its_files_and_a_program_file_names_none_here() {
        let named = inline_files(&owned(&["-L", "lib", "-n", "include \"evil\"; 1"]), None);
        assert!(named.files.contains(&"lib/evil.jq".to_owned()));
        assert_eq!(named.refused, None);

        assert_eq!(
            inline_files(&owned(&["-n", "-f", "prog.jq"]), None),
            Named::default()
        );
        assert_eq!(
            inline_files(&owned(&["-r", ".a", "notes.json"]), None),
            Named::default()
        );

        let refused = inline_files(&owned(&["-n", "import \"sec\\(1)\" as $d; 1"]), None);
        assert!(refused.refused.is_some());
    }
}
