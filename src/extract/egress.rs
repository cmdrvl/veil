//! Egress commands (bd-x8o): commands that send what they are given somewhere
//! else, and the files they name inside a word veil would otherwise take whole.
//!
//! veil judges every word of a command as a path, which already catches
//! `curl -T .env host` and `scp .env host:`. What that does not see is a file
//! named inside a word: curl's `-F f=@x.csv;type=text/plain`,
//! `--data-urlencode name@x.csv`, `gh release upload v1 x.csv#label`, or the
//! `put x.csv` of a script fed to `sftp` on standard input. This module names
//! those files. Each is only a candidate: it is denied when it is protected,
//! like any other word.

use std::net::Ipv6Addr;

use super::command_name;
use super::decompose::{PROCESS_SUBSTITUTION, SUBSTITUTION};

/// Programs whose purpose is to send. Any protected path one of them is given
/// is on its way off the machine, whatever the option that carries it.
const SENDERS: &[&str] = &[
    "curl", "wget", "scp", "rsync", "sftp", "ftp", "lftp", "rclone", "aws", "gsutil", "az", "gh",
    "nc", "ncat", "netcat", "socat", "mail", "mailx", "mutt", "sendmail", "msmtp", "swaks",
];

/// Programs that read a script of commands from standard input or a here-string
/// and send what its `put` lines name.
const SCRIPTED_TRANSFER: &[&str] = &["ftp", "sftp", "lftp", "tnftp", "pftp"];

/// Whether `program` sends what it is given: a sender above, `osascript`
/// driving Mail, or `open -a Mail`.
pub(super) fn is_egress(program: &str, args: &[String]) -> bool {
    let name = command_name(program);

    SENDERS.contains(&name)
        || (name == "osascript" && args.iter().any(|arg| names_mail(arg)))
        || (name == "open" && opens_mail(args))
}

fn names_mail(script: &str) -> bool {
    let script = script.to_ascii_lowercase();
    script.contains("\"mail\"") || script.contains("'mail'")
}

fn opens_mail(args: &[String]) -> bool {
    args.windows(2).any(|pair| {
        pair[0] == "-a"
            && matches!(
                pair[1].to_ascii_lowercase().trim_end_matches(".app"),
                "mail" | "messages"
            )
    })
}

/// Files `program` names inside a word that veil takes whole.
pub(super) fn operand_paths(program: &str, args: &[String]) -> Vec<String> {
    match command_name(program) {
        "curl" => curl_operands(args),
        "gh" => gh_operands(args),
        _ => Vec::new(),
    }
}

/// The short and long options of a web client that take no value, so the word
/// after one is not its value. An option missing here fails toward judging that
/// word as a path.
struct ValuelessOptions {
    short: &'static str,
    long: &'static [&'static str],
}

const CURL: ValuelessOptions = ValuelessOptions {
    short: "sSLfiIkvOgNJRG46#",
    long: &[
        "--",
        // takes a value, and it is an address
        "--url",
        "--silent",
        "--show-error",
        "--location",
        "--fail",
        "--fail-with-body",
        "--compressed",
        "--include",
        "--head",
        "--insecure",
        "--verbose",
        "--globoff",
        "--get",
        "--remote-name",
        "--remote-header-name",
        "--no-progress-meter",
        "--progress-bar",
        "--no-buffer",
        "--path-as-is",
        "--http1.1",
        "--http2",
        "--ipv4",
        "--ipv6",
    ],
};

const WGET: ValuelessOptions = ValuelessOptions {
    short: "qvcNSr",
    long: &[
        "--",
        "-nv",
        "-nc",
        "-nd",
        "-nH",
        "-np",
        "--quiet",
        "--verbose",
        "--no-verbose",
        "--spider",
        "--server-response",
        "--continue",
        "--no-clobber",
        "--content-disposition",
        "--no-check-certificate",
        "--recursive",
        "--no-parent",
    ],
};

const GH_API: ValuelessOptions = ValuelessOptions {
    short: "i",
    long: &[
        "--",
        "--include",
        "--paginate",
        "--silent",
        "--slurp",
        "--verbose",
    ],
};

/// What may make the shell turn one written word into others: a glob, a brace
/// list or something it computes.
const MAY_BE_REWRITTEN: &[char] = &[
    '*',
    '?',
    '[',
    '{',
    '}',
    '(',
    '`',
    '$',
    SUBSTITUTION,
    PROCESS_SUBSTITUTION,
];

/// Whether `word`, which follows `before` among the arguments of `program`, is a
/// web address that `curl`, `wget` or `gh api` takes to fetch, and so is not
/// judged as the name of a local file (bd-a5g, bd-ov7).
///
/// `program` is the word as written: `./curl` and `/tmp/curl` may be any
/// program. `before` is every argument ahead of `word`, redirections included.
/// The caller must also know that nothing in the command changes what the bare
/// name runs; veil cannot see what was changed before the command. The word
/// must be a whole address (or curl's `--url=` one), must not follow an option
/// that may take it as a value, such as a file to upload, and must not follow a
/// word the shell may rewrite. This says nothing about what a client writes.
pub(super) fn is_fetched_address(program: &str, before: &[&str], word: &str) -> bool {
    let options = match program {
        "curl" => &CURL,
        "wget" => &WGET,
        "gh" if before.first() == Some(&"api") => &GH_API,
        _ => return false,
    };

    // The shell takes redirections and what they name out of the arguments, so
    // the word written before another may not be the one the client gets before
    // it. Each form has a `<` or a `>`: with one anywhere ahead, veil does not
    // work out which word that is.
    if before.iter().any(|earlier| earlier.contains(['<', '>'])) {
        return false;
    }
    let address = match word.strip_prefix("--url=") {
        // after `--` it is not an option
        Some(value) if program == "curl" && !before.contains(&"--") => value,
        _ => word,
    };
    if !is_whole_web_address(address) {
        return false;
    }

    before.last().is_none_or(|&previous| {
        if let Some(letters) = previous.strip_prefix('-') {
            // `-sSL`; wget's `-qO-` writes to standard output
            let letters = match program {
                "wget" => letters.strip_suffix("O-").unwrap_or(letters),
                _ => letters,
            };
            options.long.contains(&previous)
                || (!letters.is_empty()
                    && letters.chars().all(|letter| options.short.contains(letter)))
        } else {
            // what the shell rewrites may come out as any option
            !previous.contains(MAY_BE_REWRITTEN)
        }
    })
}

/// Whether the whole of `word` is one plain `http` or `https` address that names
/// a host as the web does (a dotted name, `localhost` or an IPv6 address in
/// brackets) and has no `..` segment. A space, a quote, `*`, a bracket that is
/// not around that host, or what could be shell syntax, and it is not.
fn is_whole_web_address(word: &str) -> bool {
    let Some((scheme, rest)) = word.split_once("://") else {
        return false;
    };
    let plain = |byte: u8| byte.is_ascii_graphic() && !b"$`'\"()<>|;\\{}*".contains(&byte);
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || !rest.bytes().all(plain)
        || rest
            .split(['/', '?', '#', '&', '='])
            .any(|part| part == "..")
    {
        return false;
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let brackets = rest.matches(['[', ']']).count();

    if let Some(bracketed) = host.strip_prefix('[') {
        return brackets == 2
            && bracketed.split_once(']').is_some_and(|(number, port)| {
                number.parse::<Ipv6Addr>().is_ok()
                    && (port.is_empty() || port.strip_prefix(':').is_some_and(is_port))
            });
    }
    let name = host.split(':').next().unwrap_or_default();

    brackets == 0
        && name.starts_with(|first: char| first.is_ascii_alphanumeric())
        && (name.trim_end_matches('.').contains('.') || name.eq_ignore_ascii_case("localhost"))
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Files an `ftp`, `sftp` or `lftp` script sends: the `put` lines of a
/// here-document body or a here-string.
pub(super) fn script_paths(program: &str, script: &str) -> Vec<String> {
    if !SCRIPTED_TRANSFER.contains(&command_name(program)) {
        return Vec::new();
    }

    let mut paths = Vec::new();
    let mut directory: Option<String> = None;

    for line in script.lines().flat_map(|line| line.split(';')) {
        let words = script_words(line);
        let Some((command, operands)) = words.split_first() else {
            continue;
        };

        // sftp batch files let a command start with `-` to ignore its failure
        match command
            .trim_start_matches('-')
            .to_ascii_lowercase()
            .as_str()
        {
            "lcd" => directory = operands.first().cloned(),
            "put" | "reput" | "send" | "append" => {
                if let Some(file) = local_operands(operands).first() {
                    paths.push(joined(directory.as_deref(), file));
                }
            }
            "mput" => {
                for file in local_operands(operands) {
                    paths.push(joined(directory.as_deref(), &file));
                }
            }
            _ => {}
        }
    }

    paths
}

/// Files a here-string (`<<< "put x.csv"`) hands to a scripted transfer.
pub(super) fn here_string_paths(program: &str, args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;

        if arg == "<<<" {
            if let Some(script) = args.get(index) {
                paths.extend(script_paths(program, script));
            }
            index += 1;
        } else if let Some(script) = arg.strip_prefix("<<<") {
            paths.extend(script_paths(program, script));
        }
    }

    paths
}

/// Files an `lftp -c 'put x'` or `lftp -e 'put x; bye'` script argument sends.
pub(super) fn option_script_paths(program: &str, args: &[String]) -> Vec<String> {
    if command_name(program) != "lftp" {
        return Vec::new();
    }

    (0..args.len())
        .filter_map(|index| option_value(args, index, &["-c", "-e"], &[]))
        .flat_map(|(script, _)| script_paths(program, script))
        .collect()
}

fn joined(directory: Option<&str>, file: &str) -> String {
    match directory {
        Some(directory) if !file.starts_with(['/', '~']) => format!("{directory}/{file}"),
        _ => file.to_owned(),
    }
}

/// The local files of a `put` or `mput` line: its words that are not options
/// (`-O dir` and `-o name` carry a value of their own).
fn local_operands(operands: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut skip = false;

    for word in operands {
        if skip {
            skip = false;
        } else if matches!(word.as_str(), "-O" | "-o") {
            skip = true;
        } else if !word.starts_with('-') {
            files.push(word.clone());
        }
    }

    files
}

/// The words of one script line, quotes removed (`put "a b.csv"`).
fn script_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;

    for ch in line.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => current.push(ch),
        }
    }
    if started || !current.is_empty() {
        words.push(current);
    }

    words
}

/// The value of the option at `args[index]` when it is one of `short` or
/// `long`, and how many words it took: `-F v`, `-Fv`, `--form v`, `--form=v`.
fn option_value<'a>(
    args: &'a [String],
    index: usize,
    short: &[&str],
    long: &[&str],
) -> Option<(&'a str, usize)> {
    let arg = args[index].as_str();

    if short.iter().chain(long).any(|name| arg == *name) {
        return args.get(index + 1).map(|value| (value.as_str(), 2));
    }
    for name in long {
        if let Some(value) = arg
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some((value, 1));
        }
    }
    if !arg.starts_with("--") {
        for name in short {
            if let Some(value) = arg.strip_prefix(name).filter(|value| !value.is_empty()) {
                return Some((value, 1));
            }
        }
    }

    None
}

fn curl_operands(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;

    while index < args.len() {
        if let Some((value, taken)) = option_value(args, index, &["-F"], &["--form"]) {
            paths.extend(form_files(value));
            index += taken;
        } else if let Some((value, taken)) = option_value(args, index, &[], &["--data-urlencode"]) {
            paths.extend(urlencoded_file(value));
            index += taken;
        } else if let Some((value, taken)) =
            option_value(args, index, &["-E"], &["--cert", "--proxy-cert"])
        {
            paths.extend(certificate_file(value));
            index += taken;
        } else {
            index += 1;
        }
    }

    paths
}

/// The file of `-F name=@file;type=text/plain`, `name=<file` or
/// `name=@"a;b.csv"`; `name=@a,b` sends two. Anything after the file is
/// curl's own option (`;type=`, `;filename=`).
fn form_files(value: &str) -> Vec<String> {
    let Some((_, content)) = value.split_once('=') else {
        return Vec::new();
    };
    let (several, rest) = if let Some(rest) = content.strip_prefix('@') {
        (true, rest)
    } else if let Some(rest) = content.strip_prefix('<') {
        (false, rest)
    } else {
        return Vec::new();
    };

    let file = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or(""),
        None => rest.split(';').next().unwrap_or(""),
    };

    if several {
        file.split(',')
            .filter(|file| !file.is_empty())
            .map(str::to_owned)
            .collect()
    } else if file.is_empty() {
        Vec::new()
    } else {
        vec![file.to_owned()]
    }
}

/// The file of `--data-urlencode @file` or `name@file`. `name=content` and
/// `=content` carry text, and an `@` after the `=` belongs to that text.
fn urlencoded_file(value: &str) -> Option<String> {
    if let Some(file) = value.strip_prefix('@') {
        return Some(file.to_owned());
    }

    let at = value.find('@')?;
    if value.find('=').is_some_and(|equals| equals < at) {
        return None;
    }

    Some(value[at + 1..].to_owned())
}

/// The file of `--cert file[:password]`.
fn certificate_file(value: &str) -> Option<String> {
    if value.starts_with("pkcs11:") {
        return None;
    }

    value
        .split(':')
        .next()
        .filter(|file| !file.is_empty())
        .map(str::to_owned)
}

/// The file of a `gh release upload tag file#label` (or `release create`)
/// asset: the label follows a `#`. Other `gh` words carry a `#` as text
/// (`--title "Fix #12"`).
fn gh_operands(args: &[String]) -> Vec<String> {
    if args.first().map(String::as_str) != Some("release") {
        return Vec::new();
    }

    args.iter()
        .filter(|arg| !arg.starts_with('-'))
        .filter_map(|arg| arg.split_once('#'))
        .map(|(file, _)| file)
        .filter(|file| !file.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn operands(program: &str, line: &str) -> Vec<String> {
        operand_paths(program, &words(line))
    }

    #[test]
    fn the_senders_and_only_the_senders_are_egress() {
        for program in [
            "curl",
            "wget",
            "scp",
            "rsync",
            "sftp",
            "ftp",
            "rclone",
            "aws",
            "gsutil",
            "az",
            "gh",
            "nc",
            "socat",
            "mail",
            "mutt",
            "sendmail",
            "swaks",
            "/usr/bin/curl",
        ] {
            assert!(is_egress(program, &[]), "{program}");
        }
        for program in ["cat", "cp", "tar", "git", "ssh", "python3", "sed", "ls"] {
            assert!(!is_egress(program, &[]), "{program}");
        }
    }

    #[test]
    fn osascript_and_open_are_egress_only_when_they_drive_mail() {
        let mail = words("-e 'tell application \"Mail\" to activate'");
        assert!(is_egress("osascript", &mail));
        assert!(!is_egress("osascript", &words("-e 'beep'")));
        assert!(!is_egress(
            "osascript",
            &words("-e 'tell application \"Finder\" to activate'")
        ));

        assert!(is_egress("open", &words("-a Mail x.csv")));
        assert!(is_egress("open", &words("-a mail.app x.csv")));
        assert!(is_egress("open", &words("-a Messages x.csv")));
        assert!(!is_egress("open", &words("-a Preview x.csv")));
        assert!(!is_egress("open", &words("x.csv")));
    }

    #[test]
    fn a_form_field_names_its_file_before_curls_own_options() {
        assert_eq!(
            operands("curl", "-F f=@.env;type=text/plain https://h"),
            [".env"]
        );
        assert_eq!(
            operands("curl", "-F f=@.env;filename=x https://h"),
            [".env"]
        );
        assert_eq!(
            operands("curl", "--form f=@.env;type=a/b https://h"),
            [".env"]
        );
        assert_eq!(
            operands("curl", "--form=f=@.env;type=a/b https://h"),
            [".env"]
        );
        assert_eq!(operands("curl", "-Ff=@.env;type=a/b https://h"), [".env"]);
        assert_eq!(operands("curl", "-F f=<.env https://h"), [".env"]);
        assert_eq!(
            operands("curl", "-F f=@a.csv,b.csv https://h"),
            ["a.csv", "b.csv"]
        );

        // quotes keep a `;` in the name
        assert_eq!(
            operand_paths(
                "curl",
                &["-F".to_owned(), "f=@\"a;b.csv\";type=x".to_owned()]
            ),
            ["a;b.csv"]
        );

        // text and an empty file name are not files
        assert!(operands("curl", "-F name=value https://h").is_empty());
        assert!(operands("curl", "-F f=@ https://h").is_empty());
        assert!(operands("curl", "-F nothing https://h").is_empty());
    }

    #[test]
    fn urlencode_reads_a_file_after_an_at_that_comes_before_any_equals() {
        assert_eq!(
            operands("curl", "--data-urlencode name@.env https://h"),
            [".env"]
        );
        assert_eq!(
            operands("curl", "--data-urlencode @.env https://h"),
            [".env"]
        );
        assert_eq!(
            operands("curl", "--data-urlencode=name@.env https://h"),
            [".env"]
        );

        // an `@` after the `=` is part of the text
        assert!(operands("curl", "--data-urlencode mail=a@b.c https://h").is_empty());
        assert!(operands("curl", "--data-urlencode =a@b.c https://h").is_empty());
        assert!(operands("curl", "--data-urlencode plain https://h").is_empty());
    }

    #[test]
    fn a_certificate_option_names_a_file_before_its_password() {
        assert_eq!(operands("curl", "--cert .env:secret https://h"), [".env"]);
        assert_eq!(operands("curl", "-E .env:secret https://h"), [".env"]);
        assert_eq!(operands("curl", "--cert .env https://h"), [".env"]);
        assert!(operands("curl", "--cert pkcs11:token=x https://h").is_empty());
    }

    #[test]
    fn a_release_asset_names_its_file_before_the_label() {
        assert_eq!(operands("gh", "release upload v1 .env#label"), [".env"]);
        assert_eq!(
            operands("gh", "release upload v1 ./a.csv#a_label b.csv"),
            ["./a.csv"]
        );
        assert_eq!(operands("gh", "release create v1 .env#label"), [".env"]);
        assert!(operands("gh", "release upload v1 a.csv").is_empty());
        // a `#` in another subcommand's words is text
        assert!(operands("gh", "issue create --title x#y").is_empty());
        assert!(operands("gh", "pr comment 3 --body a.csv#b").is_empty());
    }

    #[test]
    fn other_programs_have_no_hidden_operands() {
        assert!(operands("scp", "-F f=@.env x host:").is_empty());
        assert!(operands("cat", ".env#label").is_empty());
    }

    #[test]
    fn a_transfer_script_names_the_files_it_sends() {
        let script = "cd /remote\nput .env\nmput a.csv \"b c.csv\"\nget down.csv\nbye\n";
        assert_eq!(script_paths("sftp", script), [".env", "a.csv", "b c.csv"]);
        assert_eq!(script_paths("ftp", "PUT .env"), [".env"]);
        assert_eq!(script_paths("sftp", "-put .env"), [".env"]);
        assert_eq!(script_paths("ftp", "put .env remote.name"), [".env"]);
        assert_eq!(script_paths("ftp", "send .env"), [".env"]);
        assert_eq!(script_paths("ftp", "append .env"), [".env"]);
        assert_eq!(script_paths("lftp", "put -O /r .env; bye"), [".env"]);
        assert_eq!(script_paths("sftp", "put -r data"), ["data"]);

        // downloads and navigation send nothing
        assert!(script_paths("sftp", "get .env\nls\ncd x\nlcd y").is_empty());
        // another program's lines are not a transfer script
        assert!(script_paths("cat", "put .env").is_empty());
    }

    #[test]
    fn a_local_directory_change_applies_to_the_files_that_follow() {
        assert_eq!(
            script_paths("sftp", "lcd data\nput .env\nput /abs/x.csv"),
            ["data/.env", "/abs/x.csv"]
        );
    }

    #[test]
    fn an_lftp_script_argument_is_a_transfer_script() {
        let lftp = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            option_script_paths("lftp", &args)
        };

        assert_eq!(lftp(&["-c", "put .env"]), [".env"]);
        assert_eq!(lftp(&["-c", "open host; put -O /r .env"]), [".env"]);
        assert_eq!(lftp(&["host", "-e", "put .env; bye"]), [".env"]);
        assert_eq!(lftp(&["-cput .env"]), [".env"]);
        assert_eq!(lftp(&["-e", "mput a.csv b.csv"]), ["a.csv", "b.csv"]);

        // downloads send nothing, and another option's value is not a script
        assert!(lftp(&["-c", "get .env"]).is_empty());
        assert!(lftp(&["-u", "put .env", "host"]).is_empty());
        assert!(lftp(&["host"]).is_empty());
        // only lftp takes its script this way
        assert!(option_script_paths("sftp", &["-c".to_owned(), "put .env".to_owned()]).is_empty());
    }

    const ADDRESS: &str = "https://a.example/data/x";

    fn fetched(program: &str, before: &[&str], word: &str) -> bool {
        is_fetched_address(program, before, word)
    }

    #[test]
    fn only_the_bare_web_clients_fetch_an_address() {
        assert!(fetched("curl", &[], ADDRESS));
        assert!(fetched("wget", &[], ADDRESS));
        assert!(fetched("gh", &["api"], ADDRESS));

        for program in ["./curl", "/usr/bin/curl", "CURL", "base64", "http"] {
            assert!(!fetched(program, &[], ADDRESS), "{program}");
        }
        assert!(!fetched("gh", &[], ADDRESS));
        assert!(!fetched("gh", &["repo", "view"], ADDRESS));
        assert!(!fetched("gh", &["-R", "o/r", "api"], ADDRESS));
    }

    #[test]
    fn the_word_before_an_address_must_not_take_it_as_a_value() {
        for previous in ["-s", "-sSL", "--silent", "--url", "page.htm", "--"] {
            assert!(fetched("curl", &[previous], ADDRESS), "{previous}");
        }
        assert!(fetched("wget", &["-qO-"], ADDRESS));

        for previous in ["-T", "-sST", "-d", "--upload-file", "-K", "-", "-qO-"] {
            assert!(!fetched("curl", &[previous], ADDRESS), "{previous}");
        }
        for previous in ["-i", "-O", "--post-file", "--url", "-"] {
            assert!(!fetched("wget", &[previous], ADDRESS), "{previous}");
        }
    }

    #[test]
    fn a_word_the_shell_may_rewrite_must_not_come_before_an_address() {
        let substitution = format!("a{SUBSTITUTION}");
        let process = format!("a{PROCESS_SUBSTITUTION}");

        for previous in [
            "x*",
            "x?",
            "x[ab]",
            "{-s,-T}",
            "x}",
            "x(y)",
            "`x`",
            "$x",
            "x$y",
            &substitution,
            &process,
        ] {
            assert!(!fetched("curl", &[previous], ADDRESS), "{previous:?}");
        }
    }

    #[test]
    fn a_redirection_anywhere_ahead_stops_the_exception() {
        for before in [
            &["-T", ">", "out"][..],
            &["-T", ">&", "out"],
            &["-T", "{fd}>", "out"],
            &["-T", "<", "in"],
            &["2>/dev/null"],
            &[">", "-T"],
            &["2>&1", "-s"],
        ] {
            assert!(!fetched("curl", before, ADDRESS), "{before:?}");
        }
    }

    #[test]
    fn curls_url_option_is_checked_like_a_bare_address() {
        let option = format!("--url={ADDRESS}");

        assert!(fetched("curl", &[], &option));
        assert!(fetched("curl", &["-s"], &option));
        for before in [
            &["-T"][..],
            &["--upload-file"],
            &["--"],
            &["--", "x"],
            &["$x"],
            &["-T", ">", "out"],
        ] {
            assert!(!fetched("curl", before, &option), "{before:?}");
        }
        assert!(!fetched("wget", &[], &option));
        assert!(!fetched("curl", &[], "--url=file:///data/x"));
        assert!(!fetched("curl", &[], "--upload-file=https://a.example/x"));
    }

    #[test]
    fn a_whole_web_address_names_a_web_host_and_holds_no_pattern() {
        for address in [
            ADDRESS,
            "HTTP://A.EXAMPLE/x",
            "http://localhost:8080/x",
            "https://user@www.example.com:443/x?a=1&b=2#part",
            "http://[::1]/x",
            "http://[2001:db8::1]:8080/x",
            "http://user@[::1]",
        ] {
            assert!(is_whole_web_address(address), "{address}");
        }
        for address in [
            "data/x",
            "file:///data/x",
            "ftp://a.example/x",
            "https://data/x",
            "https://../x",
            "https://a.example/../x",
            "https://a.example/?f=..",
            "https://a.example/a b",
            "https://a.example/a;b",
            "https://a.example/$x",
            "https://a.example/{a,b}",
            "https://a.example/data/*",
            "https://*.example/x",
            "https://a.example/[ab]",
            "https://a.example/x]",
            "https://x[::1]/y",
            "https://[data]/x",
            "https://[::1/x",
            "https://[::1]x/y",
            "https://[::1]:/y",
            "https://[::1]:8o/y",
            "https://[::1]/[y]",
            "https://[]/y",
        ] {
            assert!(!is_whole_web_address(address), "{address}");
        }
    }

    #[test]
    fn a_here_string_is_a_transfer_script() {
        assert_eq!(
            here_string_paths("sftp", &words("host <<< put")[..]).len(),
            0,
            "the script is the next word"
        );
        assert_eq!(
            here_string_paths(
                "sftp",
                &["host".to_owned(), "<<<".to_owned(), "put .env".to_owned()]
            ),
            [".env"]
        );
        assert_eq!(
            here_string_paths("sftp", &["host".to_owned(), "<<<put .env".to_owned()]),
            [".env"]
        );
        assert!(here_string_paths("sftp", &["host".to_owned(), "<<<".to_owned()]).is_empty());
        assert!(here_string_paths("cat", &["<<<".to_owned(), "put .env".to_owned()]).is_empty());
    }
}
