//! bd-1bk: a script file an interpreter is asked to run, read as the text it is.
//!
//! `python3 -c "open('data/x.csv')"` names its file inside the code and veil
//! reads that code. `python3 read.py` hides the same code in a file, which an
//! agent can write in three lines and run. When a command runs a script, veil
//! reads the file (the script is not protected data: the agent wrote it or could
//! have) and judges what is in it:
//!
//! - for Python, Node (also bun and deno), Ruby, Perl and R: the reads veil
//!   already finds in a `-c` string (`open(...)`, `read_csv(...)`,
//!   `readFileSync(...)`...) are direct reads, and every string or word in the
//!   file that is shaped like a path is named like a word of a command, which the
//!   path rule judges. A path built from literals (`os.path.join("data",
//!   "clients", "a.csv")`, `Path(BASE) / "a.csv"`, `f"{BASE}/a.csv"`,
//!   `BASE + "/a.csv"`, where `BASE` is assigned a literal) is worked out and
//!   named too;
//! - for `bash`, `sh`, `zsh` and `source`: the file is split into the commands it
//!   would run, each judged as if it had been typed, and those that run another
//!   script are followed.
//!
//! A file run by name (`./x.py`) is read when its first line names an
//! interpreter. A Python directory runs its `__main__.py`.
//!
//! An `http` or `https` address is not read as a path, here or in a typed
//! command (bd-a5g, bd-ov7).
//!
//! This is best effort, and the remediation says so. A script that builds a path
//! at run time, takes it from the environment or a file, or imports a module
//! that does, is not seen; only an OS sandbox is airtight. A script larger than
//! [`SCRIPT_LIMIT`], or the 17th script of one command, is not read: it is denied
//! where a protected path is in reach, and allowed with a record where none is.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{
    ArgvPath, ArgvResolver, CommandExtraction, InterpreterKind, Origin, PathExposure,
    RedirectTarget, SUBSTITUTION, ScriptSource, ShellEnv, SimpleCommand, command_extraction,
    command_name, decompose_in, exec, extract_interpreter_script_paths, home_directory,
    ignorable_system_path, interpreter_kind, is_plain_name, jq, lexical_path, normalize_candidates,
    path_shaped, sed, strip_redirection_words,
    written::{Writes, Written},
};

/// The largest script veil reads, in bytes.
pub(super) const SCRIPT_LIMIT: u64 = 256 * 1024;

/// Scripts read for one Bash call, and the bytes of them. A script that runs a
/// script that runs a script is followed [`MAX_DEPTH`] deep.
const MAX_SCRIPTS: usize = 16;
const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 3;

/// How many of a script's words are checked against the filesystem. Past it a
/// word is compared with the protected patterns as text, which costs no stat
/// and cannot be crowded out by padding.
const FILESYSTEM_BUDGET: usize = 512;

/// The longest string or word veil treats as a path.
const MAX_TOKEN: usize = 4096;

/// What veil has read of the scripts one Bash call runs, and what the call
/// writes to files before it runs them (bd-4uy).
#[derive(Default)]
pub(super) struct Scripts {
    read: usize,
    bytes: u64,
    written: Written,
}

impl Scripts {
    /// The writes of `commands`, which the scripts they run are read against.
    pub(super) fn collect_writes(&mut self, commands: &[SimpleCommand], cwd: &Path) {
        self.written.collect(commands, cwd);
    }
}

/// The script a simple command runs, when it runs one.
struct Run {
    kind: InterpreterKind,
    /// The program as typed.
    program: String,
    /// The script as typed.
    name: String,
    path: PathBuf,
}

/// Adds to `out` what the script `command` runs says it reads: nothing when the
/// command runs no script.
pub(super) fn inspect(
    command: &SimpleCommand,
    cwd: &Path,
    env: &ShellEnv,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    for run in sed_scripts(command, cwd, scripts) {
        inspect_sed(&run, cwd, depth, scripts, out);
    }
    inspect_jq(command, cwd, depth, scripts, out);
    inspect_inline(command, cwd, env, depth, scripts, out);
    inspect_awk(command, cwd, env, depth, scripts, out);

    let Some(run) = find_script(command, cwd, scripts) else {
        return;
    };
    let (path, contents) = read_script(&run.path, run.kind, depth, scripts);
    let source = |unread: Option<String>| ScriptSource {
        name: run.name.clone(),
        path: fs::canonicalize(&path).unwrap_or_else(|_| path.clone()),
        run_in: cwd.to_path_buf(),
        unread,
    };

    match contents {
        Contents::Nothing => {}
        Contents::Unread(why) => out.push(extraction(&run.program, &run.name, source(Some(why)))),
        Contents::Computed => out.push(computed(&run.program, &run.name, source(None))),
        Contents::Text(text) if run.kind == InterpreterKind::Shell => {
            shell_commands(&text, &source(None), cwd, env, depth, scripts, out);
        }
        Contents::Text(text) => {
            let source = source(None);
            let candidates =
                normalize_candidates(extract_interpreter_script_paths(run.kind, &text), cwd);
            let argv_paths = path_words(run.kind, &text, &candidates, cwd);
            let mut found = extraction(&run.program, &run.name, source.clone());

            if !candidates.is_empty() {
                found.exposure = PathExposure::ReadsContents;
            }
            found.candidates = candidates;
            found.argv_paths = argv_paths;
            found.argv_exposure = PathExposure::ReadsContents;
            out.push(found);

            // the commands the file hands to the shell, as if they were typed (bd-5iy)
            if let Some(language) = language_of(run.kind) {
                for line in exec::find(language, &text).commands {
                    shell_commands(&line, &source, cwd, env, depth, scripts, out);
                }
            }
        }
    }
}

fn language_of(kind: InterpreterKind) -> Option<exec::Language> {
    match kind {
        InterpreterKind::Python => Some(exec::Language::Python),
        InterpreterKind::Node => Some(exec::Language::Node),
        InterpreterKind::Perl => Some(exec::Language::Perl),
        InterpreterKind::Ruby => Some(exec::Language::Ruby),
        InterpreterKind::R => Some(exec::Language::R),
        InterpreterKind::Shell => None,
    }
}

// ---- command strings inside a program (bd-5iy) ------------------------------------

/// The programs `command` hands an interpreter in its own text: the code of `-c`
/// and `-e`, an awk program, or the here-document or here-string the interpreter
/// reads as its program.
fn inline_programs(command: &SimpleCommand) -> (Option<exec::Language>, Vec<String>) {
    let Some((program, args)) = command.argv.split_first() else {
        return (None, Vec::new());
    };
    let name = command_name(program);
    let found = exec::programs(name, args);
    let Some(language) = found.language else {
        return (None, Vec::new());
    };
    let mut texts = found.inline;

    if texts.is_empty()
        && let Some(kind) = interpreter_kind(name)
        && script_operand(kind, name, args) == Operand::Stdin
    {
        if let Some(body) = &command.heredoc_body {
            texts.push(body.clone());
        } else if let Some(position) = args.iter().position(|arg| arg == "<<<")
            && let Some(text) = args.get(position + 1)
        {
            texts.push(text.clone());
        }
    }
    (Some(language), texts)
}

/// The first call in the program a command runs that hands the shell a command
/// built at run time, as the program wrote it.
pub(super) fn inline_refusal(command: &SimpleCommand) -> Option<String> {
    let (language, texts) = inline_programs(command);
    let language = language?;

    texts
        .iter()
        .find_map(|text| exec::find(language, text).refused)
}

/// The commands the program in a command's own text runs, each judged as if it
/// had been typed, and the scripts those run. What a program builds at run time
/// is refused by [`inline_refusal`], not here.
fn inspect_inline(
    command: &SimpleCommand,
    cwd: &Path,
    env: &ShellEnv,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    let (language, texts) = inline_programs(command);
    let Some(language) = language else {
        return;
    };
    if depth >= MAX_DEPTH {
        // A program nested past the levels veil follows is as unknown as text it
        // cannot parse: it is reported opaque, as the decomposer reports a shell
        // string nested too deep, never read as running nothing.
        if texts
            .iter()
            .any(|text| !exec::find(language, text).commands.is_empty())
        {
            let mut found = command_extraction(command, cwd);

            found.origin = Origin::Wrapper;
            found.opaque = true;
            out.push(found);
        }
        return;
    }

    for text in texts {
        for line in exec::find(language, &text).commands {
            typed_commands(&line, cwd, env, depth, scripts, out);
        }
    }
}

/// A command line a program hands the shell, as `extract_bash_commands` would
/// extract it. It is part of what was typed, so a word veil cannot resolve in it
/// is judged as it would be there.
fn typed_commands(
    line: &str,
    cwd: &Path,
    env: &ShellEnv,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    let inner_env = ShellEnv {
        cwd: Some(cwd.to_path_buf()),
        home: env.home.clone(),
    };

    let commands = decompose_in(line, &inner_env);
    scripts.collect_writes(&commands, cwd);

    for inner in commands {
        let inner_cwd = inner.cwd.as_deref().unwrap_or(cwd);
        let mut found = command_extraction(&inner, inner_cwd);

        // run by the interpreter, as `sh -c` runs its string. Text veil cannot
        // analyse comes back opaque from `command_extraction`.
        found.origin = Origin::Wrapper;
        out.push(found);

        if !inner.is_opaque() {
            inspect(&inner, inner_cwd, env, depth + 1, scripts, out);
        }
    }
}

/// The program files of an awk command: `awk -f read.awk`, or `./read.awk` with
/// `#!/usr/bin/awk -f` on its first line. What is in them is read as the text of
/// a script, for the paths it names and the commands it runs.
fn inspect_awk(
    command: &SimpleCommand,
    cwd: &Path,
    env: &ShellEnv,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    let Some((program, args)) = command.argv.split_first() else {
        return;
    };
    let mut names = if exec::is_awk(command_name(program)) {
        exec::programs(command_name(program), args).files
    } else {
        Vec::new()
    };

    if names.is_empty()
        && program.contains('/')
        && usable(program)
        && shebang_program_in(&locate(program, cwd), &scripts.written)
            .is_some_and(|name| exec::is_awk(&name))
    {
        names.push(program.clone());
    }

    for name in names.into_iter().filter(|name| usable(name)) {
        let (path, contents) =
            read_script(&locate(&name, cwd), InterpreterKind::Shell, depth, scripts);
        let source = |unread: Option<String>| ScriptSource {
            name: name.clone(),
            path: fs::canonicalize(&path).unwrap_or_else(|_| path.clone()),
            run_in: cwd.to_path_buf(),
            unread,
        };

        match contents {
            Contents::Nothing => {}
            Contents::Unread(why) => out.push(extraction(program, &name, source(Some(why)))),
            Contents::Computed => out.push(computed(program, &name, source(None))),
            Contents::Text(text) => {
                let source = source(None);
                let mut found = extraction(program, &name, source.clone());

                // awk's strings are the double-quoted kind, and `#` starts a comment
                found.argv_paths = path_words(InterpreterKind::Perl, &text, &[], cwd);
                found.argv_exposure = PathExposure::ReadsContents;
                out.push(found);

                for line in exec::find(exec::Language::Awk, &text).commands {
                    shell_commands(&line, &source, cwd, env, depth, scripts, out);
                }
            }
        }
    }
}

/// The commands a shell script runs, each as `extract_bash_commands` would
/// extract it, then the scripts those run. A word veil cannot resolve is not an
/// argument to judge here: scripts are full of `$1` and `"$f"`, and the
/// dynamic-argument stance is for what the person typed.
fn shell_commands(
    text: &str,
    source: &ScriptSource,
    cwd: &Path,
    env: &ShellEnv,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    let inner_env = ShellEnv {
        cwd: Some(cwd.to_path_buf()),
        home: env.home.clone(),
    };

    let commands = decompose_in(text, &inner_env);
    scripts.collect_writes(&commands, cwd);

    for inner in commands {
        if inner.argv.is_empty() && !inner.is_opaque() {
            continue;
        }
        let inner_cwd = inner.cwd.as_deref().unwrap_or(cwd);
        let mut found = command_extraction(&inner, inner_cwd);

        found.origin = Origin::Script;
        found.script = Some(ScriptSource {
            run_in: inner_cwd.to_path_buf(),
            ..source.clone()
        });
        found.unresolved.clear();
        found.cwd_unresolved = false;
        // nor is a target veil cannot resolve, which is one of those words
        found
            .redirect_targets
            .retain(|target| matches!(target, RedirectTarget::File(_)));
        // Keep the decomposer's opaque tail. Dropping it would let a protected
        // read after an unbalanced construct or the segment cap disappear.
        found.opaque = inner.is_opaque();
        found.dynamic_strict = false;
        out.push(found);

        if !inner.is_opaque() {
            inspect(&inner, inner_cwd, env, depth + 1, scripts, out);
        }
    }
}

/// A sed script file a command runs: `sed -f read.sed`, or `./read.sed` with
/// `#!/usr/bin/sed -f` on its first line (bd-xu0).
struct SedRun {
    /// The program as typed.
    program: String,
    /// The script file as typed.
    name: String,
    path: PathBuf,
}

/// The sed script files `command` runs: every `-f` and `--file` of a `sed`, the
/// file `-f -` has redirected in, or a file run by name whose first line names
/// sed. Empty for any other command.
fn sed_scripts(command: &SimpleCommand, cwd: &Path, scripts: &Scripts) -> Vec<SedRun> {
    let Some((program, args)) = command.argv.split_first() else {
        return Vec::new();
    };

    if sed::is_sed(command_name(program)) {
        let operands = sed::script_file_operands(args);
        let mut names = operands.named;
        if operands.stdin {
            names.extend(command.redirects_in.iter().cloned());
        }

        return names
            .into_iter()
            .filter(|name| usable(name))
            .map(|name| SedRun {
                program: program.clone(),
                path: locate(&name, cwd),
                name,
            })
            .collect();
    }

    if program.contains('/') && usable(program) {
        let path = locate(program, cwd);

        if shebang_program_in(&path, &scripts.written).is_some_and(|name| sed::is_sed(&name)) {
            return vec![SedRun {
                program: program.clone(),
                name: program.clone(),
                path,
            }];
        }
    }
    Vec::new()
}

/// What a sed script file names, as the commands a script on the command line
/// would be judged: `r` and `R` are direct reads, `w`, `W` and the `w` flag are
/// named paths. A file veil cannot parse, or one that runs a command (`e`), is as
/// opaque as a word it cannot resolve, and the dynamic-argument stance decides.
fn inspect_sed(
    run: &SedRun,
    cwd: &Path,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    // a sed script is a plain file: only Python runs a directory
    let (path, contents) = read_script(&run.path, InterpreterKind::Shell, depth, scripts);
    let source = |unread: Option<String>| ScriptSource {
        name: run.name.clone(),
        path: fs::canonicalize(&path).unwrap_or_else(|_| path.clone()),
        run_in: cwd.to_path_buf(),
        unread,
    };

    match contents {
        Contents::Nothing => {}
        Contents::Unread(why) => out.push(extraction(&run.program, &run.name, source(Some(why)))),
        Contents::Computed => out.push(computed(&run.program, &run.name, source(None))),
        Contents::Text(text) => {
            let named = sed::file_script_files(&text);
            let mut found = extraction(&run.program, &run.name, source(None));

            found.candidates = normalize_candidates(named.reads, cwd);
            if !found.candidates.is_empty() {
                found.exposure = PathExposure::ReadsContents;
            }
            found.config_writes = super::config_writes::script_file_writes(
                &named.writes,
                cwd,
                super::home_directory().as_deref(),
            );
            found.argv_paths = named_paths(&named.writes, cwd);
            found.argv_exposure = PathExposure::ReadsContents;
            if named.refused.is_some() {
                // Said in the reason as the script file: its text is not shown.
                found
                    .unresolved
                    .push(format!("the sed script in {}", run.name));
                found.dynamic_strict = true;
            }
            out.push(found);
        }
    }
}

/// A jq file whose imports are read: the program file of `-f`, or a module an
/// import may load.
#[derive(Clone)]
struct JqFile {
    /// As typed, or as the module search spells it.
    name: String,
    /// How many files that import files lead to this one.
    level: usize,
}

/// The most candidate module files one jq command queues. Each import of each
/// file names a handful, and a file that exists adds its own.
const MAX_JQ_QUEUE: usize = 2048;

/// The files a jq program file, and the jq modules an import loads, name in turn
/// (bd-3h5). What an inline program names is added by `command_extraction`; the
/// modules it includes are read here, since a module can import a data file as
/// well (`include "evil"` where evil.jq says `import "secret" as $d;`).
///
/// jq looks for a module in several places and stops at the first, but veil reads
/// every candidate that exists: a file jq would not have loaded can only add
/// names to judge, never hide one. A file veil cannot read in full, or whose
/// prelude it cannot parse, is as opaque as an unresolved word.
fn inspect_jq(
    command: &SimpleCommand,
    cwd: &Path,
    depth: usize,
    scripts: &mut Scripts,
    out: &mut Vec<CommandExtraction>,
) {
    let Some((program, args)) = command.argv.split_first() else {
        return;
    };
    if !jq::is_jq(command_name(program)) {
        return;
    }

    let line = jq::command_line(args);
    let home = home_directory();
    let mut queue: Vec<JqFile> = Vec::new();

    match (&line.program_file, &line.program) {
        (Some(file), _) if usable(file) => queue.push(JqFile {
            name: file.clone(),
            level: 0,
        }),
        (None, Some(text)) => {
            let found = jq::prelude(text);
            let modules =
                jq::module_candidates(&found.imports, &line.libraries, ".", home.as_deref());
            queue.extend(modules.into_iter().map(|name| JqFile { name, level: 1 }));
        }
        _ => {}
    }

    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut next = 0;

    while let Some(file) = queue.get(next).cloned() {
        next += 1;

        let located = locate(&file.name, cwd);
        let key = fs::canonicalize(&located).unwrap_or_else(|_| located.clone());
        if !seen.insert(key) {
            continue;
        }

        let (path, contents) = read_script(
            &located,
            InterpreterKind::Shell,
            depth + file.level,
            scripts,
        );
        let source = |unread: Option<String>| ScriptSource {
            name: file.name.clone(),
            path: fs::canonicalize(&path).unwrap_or_else(|_| path.clone()),
            run_in: cwd.to_path_buf(),
            unread,
        };

        match contents {
            Contents::Nothing => {}
            Contents::Unread(why) => out.push(extraction(program, &file.name, source(Some(why)))),
            Contents::Computed => out.push(computed(program, &file.name, source(None))),
            Contents::Text(text) => {
                let found = jq::prelude(&text);
                // The imports of a file are searched from the working directory
                // and the `-L` directories; its own directory is the base of a
                // relative `search`.
                let directory = match file.name.rsplit_once('/') {
                    Some(("", _)) => "/",
                    Some((directory, _)) => directory,
                    None => ".",
                };
                let mut named: Vec<String> = Vec::new();
                for import in &found.imports {
                    named.extend(jq::candidates(
                        import,
                        &line.libraries,
                        directory,
                        home.as_deref(),
                    ));
                }

                let mut extracted = extraction(program, &file.name, source(None));
                extracted.argv_paths = named_paths(&named, cwd);
                extracted.argv_exposure = PathExposure::ReadsContents;
                if found.refused {
                    // Said in the reason as the file: its text is not shown.
                    extracted
                        .unresolved
                        .push(format!("the jq program in {}", file.name));
                    extracted.dynamic_strict = true;
                }
                out.push(extracted);

                if queue.len() < MAX_JQ_QUEUE {
                    let modules = jq::module_candidates(
                        &found.imports,
                        &line.libraries,
                        directory,
                        home.as_deref(),
                    );
                    queue.extend(modules.into_iter().map(|name| JqFile {
                        name,
                        level: file.level + 1,
                    }));
                }
            }
        }
    }
}

/// Paths a script names that are paths whether or not a file is there, resolved
/// like the words of a command: the first [`FILESYSTEM_BUDGET`] against the
/// filesystem, the rest as text.
fn named_paths(names: &[String], cwd: &Path) -> Vec<ArgvPath> {
    let mut found: Vec<ArgvPath> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut resolver = ArgvResolver::new(cwd);

    for (index, name) in names.iter().enumerate() {
        let resolved = index < FILESYSTEM_BUDGET;
        let path = if resolved {
            resolver.resolve(name, false)
        } else {
            lexical_path(name, cwd)
        };
        let Some(path) = path else {
            continue;
        };

        if !ignorable_system_path(&path) && seen.insert(path.clone()) {
            found.push(ArgvPath { path, resolved });
        }
    }
    found
}

/// An extraction that names the script and nothing else; the caller fills in
/// what was found in it.
fn extraction(program: &str, name: &str, source: ScriptSource) -> CommandExtraction {
    CommandExtraction {
        origin: Origin::Script,
        argv: vec![program.to_owned(), name.to_owned()],
        exposure: PathExposure::None,
        candidates: Vec::new(),
        argv_paths: Vec::new(),
        argv_exposure: PathExposure::None,
        argv_scans_directories: false,
        unresolved: Vec::new(),
        cwd_unresolved: false,
        opaque: false,
        dynamic_strict: false,
        assigned_paths: Vec::new(),
        egress: false,
        script: Some(source),
        write_targets: Vec::new(),
        redirect_targets: Vec::new(),
        config_writes: Vec::new(),
        lookup_changed: false,
    }
}

/// An extraction for a script the command string writes with text veil cannot
/// see (bd-4uy): it is run, and what it reads is not known, as for a word veil
/// cannot resolve. The dynamic-argument stance decides.
fn computed(program: &str, name: &str, source: ScriptSource) -> CommandExtraction {
    let mut found = extraction(program, name, source);

    found.unresolved.push(format!(
        "{name}, a script this command string writes with text veil cannot see"
    ));
    found.dynamic_strict = true;
    found
}

// ---- which script a command runs --------------------------------------------

fn find_script(command: &SimpleCommand, cwd: &Path, scripts: &Scripts) -> Option<Run> {
    let (program, args) = command.argv.split_first()?;
    let base = command_name(program);

    if let Some(kind) = interpreter_kind(base) {
        let name = match script_operand(kind, base, args) {
            Operand::File(name) => name.to_owned(),
            // `python3 < read.py`: the file on standard input is the script
            Operand::Stdin => command
                .redirects_in
                .iter()
                .find(|word| usable(word))?
                .clone(),
            Operand::Inline => return None,
        };
        return Some(Run {
            kind,
            program: program.clone(),
            path: locate(&name, cwd),
            name,
        });
    }

    if matches!(base, "source" | ".") {
        let name = strip_redirection_words(args)
            .into_iter()
            .find(|word| usable(word))?;
        return Some(Run {
            kind: InterpreterKind::Shell,
            program: program.clone(),
            path: locate(name, cwd),
            name: name.to_owned(),
        });
    }

    if !usable(program) {
        return None;
    }
    let path = locate(program, cwd);

    // `./x.py`: a file run by name runs under the interpreter on its first line.
    let by_first_line = if program.contains('/') {
        shebang_kind_in(&path, &scripts.written).or_else(|| {
            // text veil cannot see has no first line to read: run by name, it is
            // a script whose text is unknown
            (scripts.written.find(&path, path.exists()) == Writes::Computed)
                .then_some(InterpreterKind::Shell)
        })
    } else {
        None
    };
    // `uv run read.py`, `deno run read.ts`: veil sees through the wrapper to the
    // file it runs, which the wrapper hands to the interpreter its extension names.
    let by_extension = if command.origin == Origin::Wrapper {
        extension_kind(&path)
    } else {
        None
    };
    let kind = by_first_line.or(by_extension)?;

    Some(Run {
        kind,
        program: program.clone(),
        name: program.clone(),
        path,
    })
}

/// The interpreter that runs a file with this extension.
fn extension_kind(path: &Path) -> Option<InterpreterKind> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();

    match extension.as_str() {
        "py" => Some(InterpreterKind::Python),
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" => Some(InterpreterKind::Node),
        "rb" => Some(InterpreterKind::Ruby),
        "pl" => Some(InterpreterKind::Perl),
        "r" => Some(InterpreterKind::R),
        _ => None,
    }
}

pub(super) fn locate(name: &str, cwd: &Path) -> PathBuf {
    let path = Path::new(name);

    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// A word that names one file: not a variable, a substitution or a glob.
pub(super) fn usable(word: &str) -> bool {
    !word.is_empty() && !word.contains(['$', SUBSTITUTION, '*', '?', '[', '`'])
}

/// How an interpreter's command line is read: the options that take the next
/// word as their value, those after which no script file follows (the code is
/// in the command, or comes from a module or standard input), and whether the
/// script comes after a subcommand.
struct Options {
    with_value: &'static [&'static str],
    inline: &'static [&'static str],
    subcommand: Subcommand,
}

enum Subcommand {
    None,
    /// `bun run x.ts`, or `bun x.ts`.
    Optional(&'static str),
    /// `deno run x.ts`; any other subcommand runs no script file.
    Required(&'static str),
}

fn options(kind: InterpreterKind, name: &str) -> Options {
    match (kind, name) {
        (InterpreterKind::Python, _) => Options {
            with_value: &["-W", "-X", "-Q", "--check-hash-based-pycs"],
            inline: &["-c", "-m"],
            subcommand: Subcommand::None,
        },
        (InterpreterKind::Node, "bun") => Options {
            with_value: &[
                "--cwd",
                "--config",
                "--preload",
                "-r",
                "--env-file",
                "--port",
            ],
            inline: &["-e", "--eval", "-p", "--print"],
            subcommand: Subcommand::Optional("run"),
        },
        (InterpreterKind::Node, "deno") => Options {
            with_value: &[
                "-c",
                "--config",
                "--import-map",
                "--lock",
                "--cert",
                "--location",
                "--seed",
                "--v8-flags",
            ],
            inline: &[],
            subcommand: Subcommand::Required("run"),
        },
        (InterpreterKind::Node, _) => Options {
            with_value: &[
                "-r",
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--conditions",
                "-C",
                "--input-type",
                "--env-file",
                "--title",
            ],
            inline: &["-e", "--eval", "-p", "--print"],
            subcommand: Subcommand::None,
        },
        (InterpreterKind::Ruby, _) => Options {
            with_value: &["-r", "-I", "-C", "-E"],
            inline: &["-e"],
            subcommand: Subcommand::None,
        },
        (InterpreterKind::Perl, _) => Options {
            with_value: &["-I", "-M", "-m"],
            inline: &["-e", "-E"],
            subcommand: Subcommand::None,
        },
        (InterpreterKind::R, _) => Options {
            with_value: &[],
            inline: &["-e"],
            subcommand: Subcommand::None,
        },
        (InterpreterKind::Shell, _) => Options {
            with_value: &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"],
            inline: &["-c"],
            subcommand: Subcommand::None,
        },
    }
}

/// Where an interpreter's code is.
#[derive(Debug, Eq, PartialEq)]
enum Operand<'a> {
    /// In a file the command names.
    File(&'a str),
    /// In the command itself (`-c`, `-e`), or in a module or a file veil cannot
    /// name: there is no script file to read.
    Inline,
    /// On standard input, which `python3 < read.py` fills from a file.
    Stdin,
}

/// The script file among an interpreter's arguments: the first word that is not
/// an option or an option's value.
fn script_operand<'a>(kind: InterpreterKind, name: &str, args: &'a [String]) -> Operand<'a> {
    let options = options(kind, name);
    let words = strip_redirection_words(args);
    let mut index = 0;
    let mut options_ended = false;
    let mut subcommand_seen = false;

    while index < words.len() {
        let word = words[index];
        index += 1;

        if !options_ended && word == "--" {
            options_ended = true;
            continue;
        }

        if !options_ended && word.starts_with('-') && word.len() > 1 {
            // `-cCODE`, `-mmodule`: the value attached to a short option.
            let attached =
                |flag: &&str| flag.len() == 2 && !flag.starts_with("--") && word.starts_with(*flag);
            if options.inline.contains(&word) || options.inline.iter().any(attached) {
                return Operand::Inline;
            }
            if options.with_value.contains(&word) {
                index += 1;
            }
            continue;
        }

        if word == "-" {
            return Operand::Stdin;
        }

        match options.subcommand {
            Subcommand::Required(subcommand) if !subcommand_seen => {
                if word != subcommand {
                    return Operand::Inline;
                }
                subcommand_seen = true;
                continue;
            }
            Subcommand::Optional(subcommand) if !subcommand_seen => {
                subcommand_seen = true;
                if word == subcommand {
                    continue;
                }
            }
            _ => {}
        }

        return if usable(word) {
            Operand::File(word)
        } else {
            Operand::Inline
        };
    }

    Operand::Stdin
}

/// The interpreter named on the first line of a file run by name, when it is one
/// veil reads: `#!/usr/bin/env python3`, `#!/bin/bash`.
/// A file the command string writes is read as written (bd-4uy).
fn shebang_kind_in(path: &Path, written: &Written) -> Option<InterpreterKind> {
    interpreter_kind(&shebang_program_in(path, written)?)
}

/// [`shebang_program`] of a file the command string writes first, as written.
fn shebang_program_in(path: &Path, written: &Written) -> Option<String> {
    match written.first_line(path) {
        Some(line) if line.starts_with("#!") => program_of_line(&line[2..]),
        _ => shebang_program(path),
    }
}

/// The program named on the first line of a file run by name, `env` looked
/// through: `python3` for `#!/usr/bin/env -S python3 -u`, `sed` for
/// `#!/usr/bin/sed -f`.
fn shebang_program(path: &Path) -> Option<String> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut head = [0u8; 256];
    let length = File::open(path).ok()?.read(&mut head).ok()?;
    let first_line = head[..length]
        .strip_prefix(b"#!")?
        .split(|byte| *byte == b'\n')
        .next()?;
    program_of_line(&String::from_utf8_lossy(first_line))
}

/// The program a first line names, after its `#!`.
fn program_of_line(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let mut program = command_name(words.next()?);

    if program == "env" {
        // `#!/usr/bin/env -S python3 -u`, `#!/usr/bin/env FOO=1 python3`
        let named = words.find(|word| !word.starts_with('-') && !word.contains('='))?;
        program = command_name(named);
    }

    Some(program.to_owned())
}

// ---- reading it -------------------------------------------------------------

enum Contents {
    Text(String),
    /// A script that is there and that veil did not read; why.
    Unread(String),
    /// The command string writes the file with text veil cannot see (bd-4uy).
    Computed,
    /// Not a file veil reads: nothing by that name, a pipe, a directory.
    Nothing,
}

/// A script as it will be when the command runs it: the text on disk, and the text
/// the command string writes to the file before it runs it. Both are read, since
/// the write may not happen (`false && printf ... > x`), or may come after a run
/// in a loop. A file the string writes with text veil cannot see is
/// [`Contents::Computed`].
fn read_script(
    path: &Path,
    kind: InterpreterKind,
    depth: usize,
    scripts: &mut Scripts,
) -> (PathBuf, Contents) {
    let (path, contents) = read_file(path, kind, depth, scripts);
    let on_disk = !matches!(contents, Contents::Nothing);

    match scripts.written.find(&path, on_disk) {
        Writes::Untouched => (path, contents),
        Writes::Computed => (path, Contents::Computed),
        Writes::Text(written) => {
            let (mut text, counted) = match contents {
                Contents::Text(text) => (text, true),
                Contents::Nothing => (String::new(), false),
                other => return (path, other),
            };
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            let before = text.len() as u64;
            text.push_str(&written);

            let size = text.len() as u64;
            if size > SCRIPT_LIMIT {
                return (path, Contents::Unread(too_large(size)));
            }
            // the disk text was counted when it was read
            let added = size - before;
            if !counted {
                if depth >= MAX_DEPTH
                    || scripts.read >= MAX_SCRIPTS
                    || scripts.bytes + size > MAX_SCRIPT_BYTES
                {
                    return (path, Contents::Unread(beyond_followed()));
                }
                scripts.read += 1;
            }
            scripts.bytes += added;
            (path, Contents::Text(text))
        }
    }
}

fn beyond_followed() -> String {
    format!(
        "is more script than veil follows for one command ({MAX_DEPTH} levels, \
         {MAX_SCRIPTS} scripts, {MAX_SCRIPT_BYTES} bytes)"
    )
}

/// The file as it is on disk.
fn read_file(
    path: &Path,
    kind: InterpreterKind,
    depth: usize,
    scripts: &mut Scripts,
) -> (PathBuf, Contents) {
    let mut path = path.to_path_buf();
    let Ok(mut metadata) = fs::metadata(&path) else {
        return (path, Contents::Nothing);
    };

    if metadata.is_dir() && kind == InterpreterKind::Python {
        // `python3 pkg/` runs `pkg/__main__.py`
        path.push("__main__.py");
        match fs::metadata(&path) {
            Ok(inner) => metadata = inner,
            Err(_) => return (path, Contents::Nothing),
        }
    }
    if !metadata.is_file() {
        return (path, Contents::Nothing);
    }

    let size = metadata.len();
    if size > SCRIPT_LIMIT {
        return (path, Contents::Unread(too_large(size)));
    }
    if depth >= MAX_DEPTH || scripts.read >= MAX_SCRIPTS || scripts.bytes + size > MAX_SCRIPT_BYTES
    {
        return (path, Contents::Unread(beyond_followed()));
    }

    let Ok(file) = File::open(&path) else {
        return (path, Contents::Nothing);
    };
    let mut buffer = Vec::new();
    // one byte more than the limit shows a file that grew since it was measured
    if file
        .take(SCRIPT_LIMIT + 1)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return (path, Contents::Nothing);
    }
    if buffer.len() as u64 > SCRIPT_LIMIT {
        return (path, Contents::Unread(too_large(buffer.len() as u64)));
    }

    scripts.read += 1;
    scripts.bytes += buffer.len() as u64;
    let text = String::from_utf8_lossy(&buffer).into_owned();
    (path, Contents::Text(text))
}

fn too_large(size: u64) -> String {
    format!("is {size} bytes, more than the {SCRIPT_LIMIT} bytes veil reads")
}

// ---- the paths in a script --------------------------------------------------

/// A word of a script that may name a path. `certain` words have a slash: they
/// name a path whether or not one exists. The rest name one only if it exists.
struct Word {
    text: String,
    certain: bool,
}

/// The paths a script names, resolved, with the most telling first: what the
/// script builds from literals, then the strings and words with a slash, then
/// the bare file names. The first [`FILESYSTEM_BUDGET`] are checked against the
/// filesystem; the rest are compared with the protected patterns as text.
fn path_words(kind: InterpreterKind, text: &str, already: &[PathBuf], cwd: &Path) -> Vec<ArgvPath> {
    let mut found = Vec::new();
    let mut seen: HashSet<PathBuf> = already.iter().cloned().collect();
    let mut resolver = ArgvResolver::new(cwd);
    let mut budget = FILESYSTEM_BUDGET;

    for word in words(kind, text, cwd) {
        let resolved = budget > 0;
        let path = if resolved {
            budget -= 1;
            resolver.resolve(&word.text, !word.certain)
        } else {
            lexical_path(&word.text, cwd)
        };
        let Some(path) = path else {
            continue;
        };

        if ignorable_system_path(&path) || !seen.insert(path.clone()) {
            continue;
        }
        found.push(ArgvPath { path, resolved });
    }

    found
}

fn words(kind: InterpreterKind, text: &str, cwd: &Path) -> Vec<Word> {
    let tokens = lex(kind, text);
    let folder = Folder::new(&tokens);
    let mut words: Vec<Word> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |word: &str, certain: bool| {
        let word = word.trim_end_matches('.');

        if word.is_empty()
            || word.len() > MAX_TOKEN
            || word.contains('$')
            || !word.bytes().any(|byte| byte.is_ascii_alphanumeric())
            || !seen.insert(word.to_owned())
        {
            return;
        }
        words.push(Word {
            text: word.to_owned(),
            certain,
        });
    };

    // a word holding a web address is not a path (bd-a5g); what else its text
    // holds is still found word by word below
    let mut add = |word: &str, certain: bool| {
        if matches!(without_web_addresses(word, cwd), Cow::Borrowed(_)) {
            add(word, certain);
        }
    };

    // what the script builds out of literals
    for built in folder.built() {
        add(&built, built.contains('/'));
    }

    // a string that is shaped like a path, whole: it may hold spaces
    for token in &tokens {
        if let Tok::Str(content) = token
            && path_shaped(content)
        {
            add(content, content.contains('/'));
        }
    }

    // any word of the text, comments and all: no reading of the syntax is
    // needed to see `data/clients/a.csv`, and none can be led astray
    let text = without_web_addresses(text, cwd);
    let mut bare: Vec<&str> = Vec::new();
    for word in text.split(is_separator) {
        if word.contains('/') {
            add(word, true);
        } else if path_shaped(word) || is_dotfile(word) {
            bare.push(word);
        }
    }
    for word in bare {
        add(word, false);
    }

    // a quoted name with no slash or extension: `"credentials"`, `"id_rsa"`
    for token in &tokens {
        if let Tok::Str(content) = token
            && content.len() <= 255
            && is_plain_name(content)
        {
            add(content, false);
        }
    }

    words
}

/// bd-a5g: `text` with its `http://` and `https://` addresses blanked out.
/// Split into words, `https://host/data/x` leaves `//host/data/x`, which reads
/// as an absolute path under `data/`.
///
/// An address is blanked only when it is unlikely to be a local path too: it
/// starts a word, names a web host, climbs with no `..`, and no entry named
/// `https:` (or `http:`) is in `cwd`. What it holds in braces is code and is kept. Borrowed
/// means there was nothing to blank.
pub(super) fn without_web_addresses<'a>(text: &'a str, cwd: &Path) -> Cow<'a, str> {
    let bytes = text.as_bytes();
    let mut kept = String::new();
    let mut copied = 0;

    for (separator, _) in text.match_indices("://") {
        let Some(start) = web_scheme_start(bytes, separator) else {
            continue;
        };
        let host = separator + 3;
        if start < copied
            || !bytes
                .get(host)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'[')
            || fs::symlink_metadata(cwd.join(&text[start..=separator])).is_ok()
        {
            continue;
        }

        let (end, literal, code) = web_address(text, host);
        if !names_a_web_host(&literal)
            || literal
                .split(['/', '?', '#', '&', '='])
                .any(|segment| segment == "..")
        {
            continue;
        }

        kept.push_str(&text[copied..start]);
        kept.push(' ');
        kept.push_str(&code);
        copied = end;
    }

    if copied == 0 {
        return Cow::Borrowed(text);
    }
    kept.push_str(&text[copied..]);
    Cow::Owned(kept)
}

/// Whether the address whose own characters are `address` names a host as the
/// web does: a dotted name, `localhost` or a bracketed number. `https://data/x`
/// may be the local `data/x`, seen through a link named `https:`.
fn names_a_web_host(address: &str) -> bool {
    let authority = address.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.starts_with('[') {
        return true;
    }
    let name = host.split(':').next().unwrap_or_default();
    name.trim_end_matches('.').contains('.') || name.eq_ignore_ascii_case("localhost")
}

/// Where the scheme before the `://` at `separator` starts, when it is `http` or
/// `https` and begins a word.
fn web_scheme_start(bytes: &[u8], separator: usize) -> Option<usize> {
    ["https", "http"].iter().find_map(|scheme| {
        let start = separator.checked_sub(scheme.len())?;
        let begins_word = start == 0 || {
            let before = bytes[start - 1];
            !before.is_ascii_alphanumeric() && !b"+-._/".contains(&before)
        };
        (begins_word && bytes[start..separator].eq_ignore_ascii_case(scheme.as_bytes()))
            .then_some(start)
    })
}

/// The address whose host starts at `from`: where it ends, its own characters,
/// and the code between its braces.
fn web_address(text: &str, from: usize) -> (usize, String, String) {
    let mut literal = String::new();
    let mut code = String::new();
    let mut depth = 0_usize;

    for (offset, character) in text[from..].char_indices() {
        let index = from + offset;
        match character {
            '\n' => return (index, literal, code),
            '{' => {
                depth += 1;
                code.push(' ');
            }
            '}' if depth > 0 => {
                depth -= 1;
                code.push(' ');
            }
            _ if depth > 0 => code.push(character),
            '\'' | '"' | '`' | '(' | ')' | '<' | '>' | ';' | '|' | '\\' | ',' | '}' => {
                return (index, literal, code);
            }
            // `&` joins the parts of a query; `&&` and `& ` end a command
            '&' if text[index + 1..]
                .chars()
                .next()
                .is_none_or(|next| next == '&' || next.is_whitespace()) =>
            {
                return (index, literal, code);
            }
            _ if character.is_whitespace() => return (index, literal, code),
            _ => literal.push(character),
        }
    }

    (text.len(), literal, code)
}

fn is_separator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '\'' | '"'
                | '`'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | ','
                | ';'
                | '='
                | '|'
                | '&'
                | '!'
                | '*'
                | '?'
                | '#'
                | ':'
                | '\\'
                | '+'
                | '@'
                | '^'
        )
}

/// `.env`, `.netrc`: a name that starts with a dot and is more than dots.
fn is_dotfile(word: &str) -> bool {
    word.len() > 1
        && word.starts_with('.')
        && word.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && is_plain_name(word)
}

// ---- reading the syntax just far enough to build paths ------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum Tok {
    Str(String),
    Ident(String),
    Punct(u8),
}

/// The strings, names and punctuation of a script, without comments. It knows
/// enough of each language to find where a string ends (a string stops at the
/// end of its line, so a stray quote cannot swallow the file) and nothing more.
fn lex(kind: InterpreterKind, text: &str) -> Vec<Tok> {
    let bytes = text.as_bytes();
    let slash_comments = kind == InterpreterKind::Node;
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];

        if byte.is_ascii_whitespace() {
            index += 1;
        } else if (byte == b'#' && !slash_comments)
            || (slash_comments && byte == b'/' && bytes.get(index + 1) == Some(&b'/'))
        {
            index = line_end(bytes, index);
        } else if slash_comments && byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = block_comment_end(bytes, index + 2);
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            match string_at(bytes, index, kind == InterpreterKind::Python) {
                Some((content, next)) => {
                    tokens.push(Tok::Str(content));
                    index = next;
                }
                None => {
                    tokens.push(Tok::Punct(byte));
                    index += 1;
                }
            }
        } else if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
            {
                index += 1;
            }
            tokens.push(Tok::Ident(
                String::from_utf8_lossy(&bytes[start..index]).into_owned(),
            ));
        } else {
            tokens.push(Tok::Punct(byte));
            index += 1;
        }
    }

    tokens
}

fn line_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn block_comment_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            return index + 2;
        }
        index += 1;
    }
    bytes.len()
}

/// The string that starts at `start`, and where it ends. A string with no end
/// on its line is no string (a backtick string may run on, as may a Python
/// triple-quoted one).
fn string_at(bytes: &[u8], start: usize, triple_quotes: bool) -> Option<(String, usize)> {
    let quote = bytes[start];
    let triple = triple_quotes
        && quote != b'`'
        && bytes.get(start + 1) == Some(&quote)
        && bytes.get(start + 2) == Some(&quote);
    let mut index = start + if triple { 3 } else { 1 };
    let mut content = Vec::new();
    let mut overflow = false;
    let mut push = |byte: u8, content: &mut Vec<u8>| {
        if content.len() < MAX_TOKEN {
            content.push(byte);
        } else {
            overflow = true;
        }
    };

    while index < bytes.len() {
        let byte = bytes[index];

        if triple {
            if byte == quote
                && bytes.get(index + 1) == Some(&quote)
                && bytes.get(index + 2) == Some(&quote)
            {
                index += 3;
                return Some((finish(content, overflow), index));
            }
            push(byte, &mut content);
            index += 1;
            continue;
        }

        if byte == b'\\' {
            match bytes.get(index + 1) {
                Some(&next) if next == quote || next == b'\\' => push(next, &mut content),
                Some(&next) => {
                    push(b'\\', &mut content);
                    push(next, &mut content);
                }
                None => {}
            }
            index += 2;
            continue;
        }
        if byte == quote {
            return Some((finish(content, overflow), index + 1));
        }
        if byte == b'\n' && quote != b'`' {
            return None;
        }
        push(byte, &mut content);
        index += 1;
    }

    None
}

fn finish(content: Vec<u8>, overflow: bool) -> String {
    if overflow {
        String::new()
    } else {
        String::from_utf8_lossy(&content).into_owned()
    }
}

/// The deepest call inside a call that is followed, the most arguments of one
/// call, the most terms of one expression and the most tokens skipped over in
/// an argument veil cannot work out: bounds on the work done at each token, so
/// that a file of `join(` repeated cannot make reading it take quadratic time.
const MAX_NESTING: usize = 8;
const MAX_ARGUMENTS: usize = 64;
const MAX_TERMS: usize = 64;
const MAX_SKIP: usize = 64;

/// What an expression comes to, and where it ends.
struct Folded {
    value: String,
    next: usize,
    /// Put together from more than one piece: a join, a concatenation.
    composite: bool,
    /// Every piece was worked out. A call with a variable among its arguments
    /// gives the pieces that were (its value is still worth naming) but is not
    /// what a name assigned from it stands for.
    complete: bool,
}

/// Works out the paths a script builds from literals and from names it assigns
/// a literal (or something built from literals) once.
struct Folder<'a> {
    tokens: &'a [Tok],
    constants: HashMap<String, String>,
}

impl<'a> Folder<'a> {
    fn new(tokens: &'a [Tok]) -> Self {
        let mut folder = Self {
            tokens,
            constants: HashMap::new(),
        };

        // A name can be assigned something built from a name assigned before
        // it, so look three times.
        for _ in 0..3 {
            let mut assigned: Vec<(String, String)> = Vec::new();

            for index in 0..tokens.len() {
                if let Some((name, value_start)) = folder.assignment(index)
                    && let Some(folded) = folder.expr(value_start, 0)
                    && folded.complete
                    && !folder.constants.contains_key(name)
                {
                    assigned.push((name.to_owned(), folded.value));
                }
            }
            if assigned.is_empty() {
                break;
            }
            folder.constants.extend(assigned);
        }

        folder
    }

    /// `NAME = value`, `NAME: type = value`, `NAME <- value`: the name and
    /// where the value starts.
    fn assignment(&self, index: usize) -> Option<(&str, usize)> {
        let Tok::Ident(name) = self.tokens.get(index)? else {
            return None;
        };
        if let Some(Tok::Punct(
            b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^'
            | b':',
        )) = index
            .checked_sub(1)
            .and_then(|before| self.tokens.get(before))
        {
            return None;
        }

        let punct = |offset: usize| match self.tokens.get(index + offset) {
            Some(Tok::Punct(byte)) => Some(*byte),
            _ => None,
        };
        let start = match (punct(1), punct(2)) {
            // `==` compares
            (Some(b'='), Some(b'=')) => return None,
            (Some(b'='), _) => index + 2,
            // `<-`
            (Some(b'<'), Some(b'-')) => index + 3,
            // `NAME: type = value`
            (Some(b':'), _)
                if matches!(self.tokens.get(index + 2), Some(Tok::Ident(_)))
                    && punct(3) == Some(b'=')
                    && punct(4) != Some(b'=') =>
            {
                index + 4
            }
            _ => return None,
        };

        Some((key(name), start))
    }

    /// Every path the script builds out of more than one piece, and every string
    /// with a name of the script's inside it.
    fn built(&self) -> Vec<String> {
        let mut built: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for index in 0..self.tokens.len() {
            match &self.tokens[index] {
                Tok::Str(content) => {
                    if let Some(substituted) = self.substituted(content)
                        && seen.insert(substituted.clone())
                    {
                        built.push(substituted);
                    }
                    self.built_at(index, &mut built, &mut seen);
                }
                Tok::Ident(_) => self.built_at(index, &mut built, &mut seen),
                Tok::Punct(_) => {}
            }
        }

        built
    }

    fn built_at(&self, index: usize, built: &mut Vec<String>, seen: &mut HashSet<String>) {
        if let Some(folded) = self.expr(index, 0)
            && folded.composite
            && !folded.value.is_empty()
            && seen.insert(folded.value.clone())
        {
            built.push(folded.value);
        }
    }

    /// `a + b`, `a / b`, or a term.
    fn expr(&self, start: usize, nesting: usize) -> Option<Folded> {
        let mut folded = self.term(start, nesting)?;

        for _ in 0..MAX_TERMS {
            let slash = match self.tokens.get(folded.next) {
                Some(Tok::Punct(b'+')) => false,
                Some(Tok::Punct(b'/')) => true,
                _ => break,
            };
            let Some(right) = self.term(folded.next + 1, nesting) else {
                // `base + name`: what comes after the operator is not known
                folded.complete = false;
                break;
            };

            folded.value = if slash {
                join_two(&folded.value, &right.value)
            } else {
                folded.value + &right.value
            };
            folded.next = right.next;
            folded.composite = true;
            folded.complete &= right.complete;
        }

        Some(folded)
    }

    fn term(&self, index: usize, nesting: usize) -> Option<Folded> {
        match self.tokens.get(index)? {
            Tok::Str(content) => Some(Folded {
                value: self.substituted(content).unwrap_or_else(|| content.clone()),
                next: index + 1,
                composite: false,
                complete: true,
            }),
            Tok::Ident(name) => {
                if nesting < MAX_NESTING
                    && let Some(call) = self.call(index, nesting + 1)
                {
                    return Some(call);
                }
                self.constants.get(key(name)).map(|value| Folded {
                    value: value.clone(),
                    next: index + 1,
                    composite: false,
                    complete: true,
                })
            }
            Tok::Punct(_) => None,
        }
    }

    /// `os.path.join("a", b)`, `Path("a", "b") / "c"`, `File.join(...)`,
    /// `file.path(...)`: the pieces of the call that veil can work out, joined.
    /// A piece it cannot work out (a variable that is not a literal, the
    /// directory of the script) is left out.
    fn call(&self, start: usize, nesting: usize) -> Option<Folded> {
        let mut names: Vec<&str> = Vec::new();
        let mut last = start;

        loop {
            let Tok::Ident(name) = self.tokens.get(last)? else {
                return None;
            };
            names.push(name);
            if self.tokens.get(last + 1) == Some(&Tok::Punct(b'.'))
                && matches!(self.tokens.get(last + 2), Some(Tok::Ident(_)))
            {
                last += 2;
            } else {
                break;
            }
        }
        if self.tokens.get(last + 1) != Some(&Tok::Punct(b'(')) || !builds_paths(&names) {
            return None;
        }

        let mut pieces: Vec<String> = Vec::new();
        let mut complete = true;
        let mut index = last + 2;

        for _ in 0..MAX_ARGUMENTS {
            match self.expr(index, nesting) {
                Some(folded) => {
                    complete &= folded.complete;
                    pieces.push(folded.value);
                    index = folded.next;
                }
                None => {
                    complete = false;
                    index = self.skip_argument(index);
                }
            }
            match self.tokens.get(index) {
                Some(Tok::Punct(b',')) => index += 1,
                Some(Tok::Punct(b')')) => {
                    index += 1;
                    break;
                }
                // not a call veil follows to its end
                _ => {
                    complete = false;
                    break;
                }
            }
        }
        if pieces.is_empty() {
            return None;
        }

        let mut value = pieces
            .iter()
            .fold(String::new(), |joined, piece| join_two(&joined, piece));

        // `Path("data") / "clients" / "a.csv"`
        for _ in 0..MAX_TERMS {
            if self.tokens.get(index) != Some(&Tok::Punct(b'/')) {
                break;
            }
            let Some(right) = self.term(index + 1, nesting) else {
                complete = false;
                break;
            };
            value = join_two(&value, &right.value);
            index = right.next;
            complete &= right.complete;
        }

        Some(Folded {
            value,
            next: index,
            composite: true,
            complete,
        })
    }

    /// The end of an argument veil cannot work out: the next `,` or `)` that is
    /// not inside brackets of its own. An argument longer than [`MAX_SKIP`]
    /// tokens ends where veil stops looking, which is neither of those: the call
    /// is then not one veil follows to its end.
    fn skip_argument(&self, start: usize) -> usize {
        let mut depth = 0usize;
        let mut index = start;

        while let Some(token) = self.tokens.get(index) {
            if index - start >= MAX_SKIP {
                return index;
            }
            match token {
                Tok::Punct(b'(' | b'[' | b'{') => depth += 1,
                Tok::Punct(b')' | b']' | b'}') => {
                    if depth == 0 {
                        return index;
                    }
                    depth -= 1;
                }
                Tok::Punct(b',') if depth == 0 => return index,
                _ => {}
            }
            index += 1;
        }

        index
    }

    /// A string with a name of the script's inside it (`f"{BASE}/a.csv"`,
    /// `` `${BASE}/a.csv` ``, `"#{BASE}/a.csv"`), with the value put in.
    fn substituted(&self, text: &str) -> Option<String> {
        if !text.contains('{') {
            return None;
        }

        let mut result = String::new();
        let mut rest = text;
        let mut changed = false;

        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                break;
            };
            let name = &after[..close];
            let value = if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                None
            } else {
                self.constants.get(key(name))
            };

            match value {
                Some(value) => {
                    let head = &rest[..open];
                    result.push_str(head.strip_suffix(['$', '#']).unwrap_or(head));
                    result.push_str(value);
                    changed = true;
                }
                None => result.push_str(&rest[..open + close + 2]),
            }
            rest = &after[close + 1..];
        }
        result.push_str(rest);

        changed.then_some(result)
    }
}

/// A name without the sigil a language puts in front of it.
fn key(name: &str) -> &str {
    name.trim_start_matches('$')
}

/// The calls that join path pieces: Python's `os.path.join`, `Path(...)` and
/// `.joinpath`, Node's `path.join` and `path.resolve`, Ruby's `File.join`, R's
/// `file.path`, Java's `Paths.get`.
fn builds_paths(names: &[&str]) -> bool {
    let Some((last, before)) = names.split_last() else {
        return false;
    };

    match *last {
        "join" | "joinpath" | "Path" | "PurePath" | "PurePosixPath" | "resolve" => true,
        "get" => before.last() == Some(&"Paths"),
        "path" => before.last() == Some(&"file"),
        _ => false,
    }
}

/// `join("a/", "b")` and `join("a", "b")` are `a/b`; an absolute piece starts
/// again, as it does in `os.path.join`.
fn join_two(left: &str, right: &str) -> String {
    if left.is_empty() || right.starts_with('/') {
        right.to_owned()
    } else if right.is_empty() {
        left.to_owned()
    } else if left.ends_with('/') {
        format!("{left}{right}")
    } else {
        format!("{left}/{right}")
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn argv(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    /// The interpreter a file on disk names on its first line.
    fn shebang_kind(path: &Path) -> Option<InterpreterKind> {
        shebang_kind_in(path, &Written::default())
    }

    /// The script file named, or `None` when the code is not in a named file.
    fn operand(kind: InterpreterKind, name: &str, command: &str) -> Option<String> {
        match script_operand(kind, name, &argv(command)) {
            Operand::File(file) => Some(file.to_owned()),
            Operand::Inline | Operand::Stdin => None,
        }
    }

    fn texts(kind: InterpreterKind, script: &str) -> Vec<String> {
        words(kind, script, Path::new("."))
            .into_iter()
            .map(|word| word.text)
            .collect()
    }

    fn built(script: &str) -> Vec<String> {
        let tokens = lex(InterpreterKind::Python, script);
        Folder::new(&tokens).built()
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "veil-script-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        fs::canonicalize(&dir).expect("temp dir should canonicalize")
    }

    #[test]
    fn the_script_is_the_first_word_that_is_not_an_option_or_its_value() {
        use InterpreterKind::*;

        assert_eq!(
            operand(Python, "python3", "read.py"),
            Some("read.py".into())
        );
        assert_eq!(
            operand(Python, "python3", "-W ignore -u read.py data.csv"),
            Some("read.py".into())
        );
        assert_eq!(
            operand(Python, "python3", "-Wignore -B read.py"),
            Some("read.py".into())
        );
        assert_eq!(
            operand(Python, "python3", "-- read.py"),
            Some("read.py".into())
        );
        assert_eq!(
            operand(Node, "node", "--require ./hook.js --no-warnings run.js"),
            Some("run.js".into())
        );
        assert_eq!(
            operand(Ruby, "ruby", "-I lib -w run.rb"),
            Some("run.rb".into())
        );
        assert_eq!(
            operand(Perl, "perl", "-I lib -w run.pl"),
            Some("run.pl".into())
        );
        assert_eq!(
            operand(R, "Rscript", "--vanilla run.R"),
            Some("run.R".into())
        );
        assert_eq!(
            operand(Shell, "bash", "-e -o pipefail run.sh x"),
            Some("run.sh".into())
        );
    }

    #[test]
    fn code_that_is_not_in_a_file_names_no_script() {
        use InterpreterKind::*;

        assert_eq!(operand(Python, "python3", "-c print(1) read.py"), None);
        assert_eq!(operand(Python, "python3", "-cprint(1)"), None);
        assert_eq!(operand(Python, "python3", "-m http.server"), None);
        assert_eq!(operand(Python, "python3", "-"), None);
        assert_eq!(operand(Node, "node", "-e code run.js"), None);
        assert_eq!(operand(Node, "node", "--eval code"), None);
        assert_eq!(operand(Ruby, "ruby", "-e code"), None);
        assert_eq!(operand(Perl, "perl", "-e code"), None);
        assert_eq!(operand(R, "Rscript", "-e code"), None);
        assert_eq!(operand(Shell, "bash", "-c code run.sh"), None);
        assert_eq!(operand(Shell, "bash", "-s"), None);
    }

    #[test]
    fn code_on_standard_input_is_told_apart_from_code_in_the_command() {
        let kind =
            |kind, name: &str, command: &str| match script_operand(kind, name, &argv(command)) {
                Operand::File(file) => format!("file {file}"),
                Operand::Inline => "inline".to_owned(),
                Operand::Stdin => "stdin".to_owned(),
            };

        assert_eq!(kind(InterpreterKind::Python, "python3", ""), "stdin");
        assert_eq!(kind(InterpreterKind::Python, "python3", "-u"), "stdin");
        assert_eq!(kind(InterpreterKind::Python, "python3", "-"), "stdin");
        assert_eq!(kind(InterpreterKind::Shell, "bash", "-s"), "stdin");
        assert_eq!(kind(InterpreterKind::Shell, "bash", "-e"), "stdin");
        assert_eq!(kind(InterpreterKind::Python, "python3", "-c x"), "inline");
        assert_eq!(
            kind(InterpreterKind::Python, "python3", "read.py"),
            "file read.py"
        );
    }

    #[test]
    fn a_script_that_cannot_be_named_is_not_read() {
        use InterpreterKind::*;

        assert_eq!(operand(Python, "python3", "$script"), None);
        assert_eq!(operand(Python, "python3", "scripts/*.py"), None);
        assert_eq!(operand(Python, "python3", "-W"), None);
    }

    #[test]
    fn bun_and_deno_run_their_script_after_a_subcommand() {
        use InterpreterKind::*;

        assert_eq!(operand(Node, "bun", "run x.ts"), Some("x.ts".into()));
        assert_eq!(operand(Node, "bun", "x.ts"), Some("x.ts".into()));
        assert_eq!(operand(Node, "bun", "-e code"), None);
        assert_eq!(
            operand(Node, "deno", "run --allow-read --config c.json x.ts"),
            Some("x.ts".into())
        );
        assert_eq!(operand(Node, "deno", "eval code"), None);
        assert_eq!(operand(Node, "deno", "task start"), None);
    }

    #[test]
    fn versioned_interpreters_are_the_interpreter() {
        assert_eq!(
            interpreter_kind("python3.12"),
            Some(InterpreterKind::Python)
        );
        assert_eq!(interpreter_kind("python3"), Some(InterpreterKind::Python));
        assert_eq!(interpreter_kind("ruby3.2"), Some(InterpreterKind::Ruby));
        assert_eq!(interpreter_kind("perl5.38.0"), Some(InterpreterKind::Perl));
        assert_eq!(interpreter_kind("Rscript"), Some(InterpreterKind::R));
        assert_eq!(interpreter_kind("bun"), Some(InterpreterKind::Node));
        assert_eq!(interpreter_kind("pythonista"), None);
        assert_eq!(interpreter_kind("perlbrew"), None);
        assert_eq!(interpreter_kind("python3-config"), None);
    }

    #[test]
    fn a_first_line_names_the_interpreter_of_a_file_run_by_name() {
        let dir = temp_dir("shebang");
        let write = |name: &str, text: &str| {
            let path = dir.join(name);
            fs::write(&path, text).expect("script should be written");
            path
        };

        assert_eq!(
            shebang_kind(&write("a", "#!/usr/bin/env python3\nprint(1)\n")),
            Some(InterpreterKind::Python)
        );
        assert_eq!(
            shebang_kind(&write("b", "#!/usr/bin/env -S node --no-warnings\n")),
            Some(InterpreterKind::Node)
        );
        assert_eq!(
            shebang_kind(&write("c", "#!/usr/bin/env FOO=1 ruby\n")),
            Some(InterpreterKind::Ruby)
        );
        assert_eq!(
            shebang_kind(&write("d", "#!/bin/bash -e\necho hi\n")),
            Some(InterpreterKind::Shell)
        );
        assert_eq!(shebang_kind(&write("e", "#!/usr/bin/awk -f\n")), None);
        assert_eq!(shebang_kind(&write("f", "print(1)\n")), None);
        assert_eq!(shebang_kind(&dir), None);
        assert_eq!(shebang_kind(&dir.join("missing")), None);

        // sed is no interpreter veil reads as code, but a sed script file is
        // read as sed (bd-xu0), so the program the line names is what is asked
        assert_eq!(
            shebang_program(&write("g", "#!/usr/bin/sed -f\nr .env\n")).as_deref(),
            Some("sed")
        );
        assert_eq!(
            shebang_program(&write("h", "#!/usr/bin/env -S sed -nf\n")).as_deref(),
            Some("sed")
        );
        assert_eq!(shebang_kind(&write("i", "#!/usr/bin/sed -f\n")), None);
        assert_eq!(shebang_program(&write("j", "r .env\n")), None);
    }

    #[test]
    fn paths_built_from_literals_are_worked_out() {
        let python = |script: &str| built(script);

        assert!(
            python(r#"p = os.path.join("data", "clients", "a.csv")"#)
                .contains(&"data/clients/a.csv".to_owned())
        );
        assert!(
            python(
                r#"BASE = "data/clients"
f = os.path.join(BASE, "a.csv")"#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
        assert!(
            python(r#"p = Path("data") / "clients" / "a.csv""#)
                .contains(&"data/clients/a.csv".to_owned())
        );
        assert!(
            python(r#"p = Path("data", "clients", "a.csv")"#)
                .contains(&"data/clients/a.csv".to_owned())
        );
        assert!(
            python(
                r#"BASE = "data/clients/"
p = BASE + "a.csv""#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
        assert!(
            python(
                r#"BASE = "data/clients"
p = f"{BASE}/a.csv""#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
        // a name built from a name that was built
        assert!(
            python(
                r#"A = "data"
B = os.path.join(A, "clients")
p = os.path.join(B, "a.csv")"#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
        // an annotated assignment
        assert!(
            python(
                r#"BASE: str = "data/clients"
p = os.path.join(BASE, "a.csv")"#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
    }

    #[test]
    fn what_cannot_be_worked_out_is_left_out_not_guessed() {
        // the script's own directory is unknown: the pieces after it are kept
        let node = lex(
            InterpreterKind::Node,
            r#"path.join(__dirname, "data", "clients", "a.csv")"#,
        );
        assert!(
            Folder::new(&node)
                .built()
                .contains(&"data/clients/a.csv".to_owned())
        );

        let python = |script: &str| built(script);
        assert!(
            python(r#"p = os.path.join(base_dir, "data", user_id)"#).contains(&"data".to_owned())
                || python(r#"p = os.path.join(base_dir, "data", user_id)"#).is_empty()
        );
        // `==` compares; it does not assign
        assert!(
            !python(
                r#"if mode == "data/clients":
    p = os.path.join(mode, "a.csv")"#
            )
            .contains(&"data/clients/a.csv".to_owned())
        );
        // an absolute piece starts again
        assert!(
            python(r#"p = os.path.join("tmp", "/data/clients", "a.csv")"#)
                .contains(&"/data/clients/a.csv".to_owned())
        );
        // a call that is not a path join builds nothing
        assert!(python(r#"p = str("data", "clients")"#).is_empty());
    }

    #[test]
    fn the_other_languages_build_paths_their_own_way() {
        let node = lex(
            InterpreterKind::Node,
            "const b = 'data';\nconst p = path.join(b, 'clients', 'a.csv');\nconst t = `${b}/clients/a.csv`;",
        );
        let built = Folder::new(&node).built();
        assert!(
            built.contains(&"data/clients/a.csv".to_owned()),
            "{built:?}"
        );

        let ruby = lex(
            InterpreterKind::Ruby,
            "base = 'data'\np = File.join(base, 'clients', 'a.csv')\nq = \"#{base}/clients/a.csv\"",
        );
        let built = Folder::new(&ruby).built();
        assert!(
            built.contains(&"data/clients/a.csv".to_owned()),
            "{built:?}"
        );

        let r = lex(
            InterpreterKind::R,
            "base <- 'data'\np <- file.path(base, 'clients', 'a.csv')",
        );
        let built = Folder::new(&r).built();
        assert!(
            built.contains(&"data/clients/a.csv".to_owned()),
            "{built:?}"
        );
    }

    #[test]
    fn a_file_built_to_make_the_builder_slow_is_still_read_in_linear_time() {
        // Without a bound on the work at each token, `join(` repeated makes
        // every token scan the rest of the file.
        let nested = "os.path.join(".repeat(20_000);
        let unclosed = format!("{nested}\nx = open('data/clients/a.csv')\n");
        let commas = format!("os.path.join({})\n", "a, ".repeat(40_000));
        let brackets = format!("p = join({}", "[".repeat(40_000));

        let started = std::time::Instant::now();
        for script in [&unclosed, &commas, &brackets] {
            let words = texts(InterpreterKind::Python, script);
            let tokens = lex(InterpreterKind::Python, script);
            let built = Folder::new(&tokens).built();
            assert!(built.len() < 1000, "{}", built.len());
            // the literal after all that is still a word
            if script == &unclosed {
                assert!(words.contains(&"data/clients/a.csv".to_owned()));
            }
        }
        assert!(
            started.elapsed().as_secs() < 20,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_comment_is_not_code_for_the_builder_but_its_paths_are_still_words() {
        let tokens = lex(
            InterpreterKind::Python,
            "# p = os.path.join('data', 'clients', 'a.csv')\nx = 1\n",
        );
        assert!(Folder::new(&tokens).built().is_empty());

        // the plain text of a comment is judged like any other word
        let words = texts(
            InterpreterKind::Python,
            "# reads data/clients/a.csv\nx = 1\n",
        );
        assert!(
            words.contains(&"data/clients/a.csv".to_owned()),
            "{words:?}"
        );

        let node = lex(
            InterpreterKind::Node,
            "// p = path.join('data', 'clients')\n/* path.join('a', 'b') */\n",
        );
        assert!(Folder::new(&node).built().is_empty());
    }

    #[test]
    fn words_that_could_name_a_path_are_found_wherever_they_are() {
        let words = texts(
            InterpreterKind::Python,
            "import os\nx = open('data/clients/a.csv')\ny = ['data/b.csv', \"c.json\"]\nprint(f'{x}')\n",
        );

        assert!(
            words.contains(&"data/clients/a.csv".to_owned()),
            "{words:?}"
        );
        assert!(words.contains(&"data/b.csv".to_owned()), "{words:?}");
        assert!(words.contains(&"c.json".to_owned()), "{words:?}");
        // no slash and no extension: not a path word unless it is a quoted name
        assert!(!words.contains(&"import".to_owned()), "{words:?}");
        assert!(!words.contains(&"print".to_owned()), "{words:?}");
    }

    #[test]
    fn a_quoted_name_and_a_dotfile_are_path_words_but_a_number_or_a_sentence_is_not() {
        let words = texts(
            InterpreterKind::Python,
            "a = open('credentials')\nb = '.env'\nc = 'hello world'\nd = '42'\ne = 'utf-8'\n",
        );

        assert!(words.contains(&"credentials".to_owned()), "{words:?}");
        assert!(words.contains(&".env".to_owned()), "{words:?}");
        assert!(!words.contains(&"hello world".to_owned()), "{words:?}");
        assert!(!words.contains(&"42".to_owned()), "{words:?}");
    }

    #[test]
    fn a_quoted_path_with_spaces_is_one_word() {
        let words = texts(InterpreterKind::Python, "x = open('data/q3 clients.csv')\n");

        assert!(
            words.contains(&"data/q3 clients.csv".to_owned()),
            "{words:?}"
        );
    }

    #[test]
    fn a_word_with_a_variable_in_it_is_not_a_path() {
        let words = texts(InterpreterKind::Python, "x = '$HOME/data/a.csv'\n");

        assert!(words.is_empty(), "{words:?}");
    }

    #[test]
    fn a_stray_quote_does_not_swallow_the_rest_of_the_file() {
        // the apostrophe in the comment opens a string that never ends on its line
        let words = texts(
            InterpreterKind::Python,
            "# it's here\nx = open('data/clients/a.csv')\n",
        );

        assert!(
            words.contains(&"data/clients/a.csv".to_owned()),
            "{words:?}"
        );
    }

    #[test]
    fn padding_does_not_push_a_word_past_the_budget() {
        let dir = temp_dir("padding");
        let mut script = String::new();
        for index in 0..2000 {
            script.push_str(&format!("x{index} = 'decoy/{index}.txt'\n"));
        }
        script.push_str("y = open('data/clients/a.csv')\n");

        let paths = path_words(InterpreterKind::Python, &script, &[], &dir);
        let wanted = dir.join("data/clients/a.csv");

        assert!(
            paths.iter().any(|found| found.path == wanted),
            "the last word is still named"
        );
        assert!(
            paths.iter().filter(|found| found.resolved).count() <= FILESYSTEM_BUDGET,
            "only the budget is checked against the filesystem"
        );
    }

    #[test]
    fn a_script_larger_than_the_limit_is_not_read_and_says_why() {
        let dir = temp_dir("large");
        let big = dir.join("big.py");
        fs::write(&big, "x = 1\n".repeat((SCRIPT_LIMIT as usize / 6) + 10)).expect("big script");
        let small = dir.join("small.py");
        fs::write(&small, "x = 1\n").expect("small script");

        let mut scripts = Scripts::default();
        let unread = match read_script(&big, InterpreterKind::Python, 0, &mut scripts).1 {
            Contents::Unread(why) => Some(why),
            Contents::Text(_) | Contents::Computed | Contents::Nothing => None,
        };
        assert!(
            unread.as_deref().is_some_and(|why| why.contains("bytes")),
            "a script over the limit is not read, and says why: {unread:?}"
        );
        assert!(matches!(
            read_script(&small, InterpreterKind::Python, 0, &mut scripts).1,
            Contents::Text(_)
        ));
        assert!(matches!(
            read_script(
                &dir.join("missing.py"),
                InterpreterKind::Python,
                0,
                &mut scripts
            )
            .1,
            Contents::Nothing
        ));
        assert!(matches!(
            read_script(&dir, InterpreterKind::Ruby, 0, &mut scripts).1,
            Contents::Nothing
        ));
    }

    #[test]
    fn a_python_directory_runs_its_main_module() {
        let dir = temp_dir("pkg");
        fs::create_dir_all(dir.join("pkg")).expect("package dir");
        fs::write(dir.join("pkg/__main__.py"), "x = open('a.csv')\n").expect("main module");

        let mut scripts = Scripts::default();
        let (path, contents) =
            read_script(&dir.join("pkg"), InterpreterKind::Python, 0, &mut scripts);

        assert_eq!(path, dir.join("pkg/__main__.py"));
        assert!(matches!(contents, Contents::Text(_)));
    }

    #[test]
    fn scripts_that_run_scripts_are_followed_only_so_deep_and_so_many() {
        let dir = temp_dir("budget");
        let file = dir.join("s.py");
        fs::write(&file, "x = 1\n").expect("script");

        let mut scripts = Scripts::default();
        assert!(matches!(
            read_script(&file, InterpreterKind::Python, MAX_DEPTH, &mut scripts).1,
            Contents::Unread(_)
        ));

        let mut scripts = Scripts::default();
        for _ in 0..MAX_SCRIPTS {
            assert!(matches!(
                read_script(&file, InterpreterKind::Python, 0, &mut scripts).1,
                Contents::Text(_)
            ));
        }
        assert!(matches!(
            read_script(&file, InterpreterKind::Python, 0, &mut scripts).1,
            Contents::Unread(_)
        ));
    }

    #[test]
    fn a_shell_script_is_run_as_the_commands_it_holds_and_the_scripts_they_run() {
        let dir = temp_dir("shell");
        fs::write(dir.join("inner.py"), "x = open('data/clients/a.csv')\n").expect("inner");
        fs::write(
            dir.join("outer.sh"),
            "#!/bin/sh\nset -e\ncat data/b.csv\npython3 inner.py \"$1\"\n",
        )
        .expect("outer");

        let env = ShellEnv {
            cwd: Some(dir.clone()),
            home: None,
        };
        let simple = decompose_in("bash outer.sh x", &env);
        let mut out = Vec::new();
        let mut scripts = Scripts::default();
        for command in &simple {
            inspect(command, &dir, &env, 0, &mut scripts, &mut out);
        }

        let names: Vec<_> = out
            .iter()
            .map(|command| {
                (
                    command.argv.first().cloned().unwrap_or_default(),
                    command.script.as_ref().map(|source| source.name.clone()),
                )
            })
            .collect();
        assert!(out.iter().all(|command| command.origin == Origin::Script));
        assert!(
            names.contains(&("cat".to_owned(), Some("outer.sh".to_owned()))),
            "{names:?}"
        );
        assert!(
            names.contains(&("python3".to_owned(), Some("outer.sh".to_owned()))),
            "{names:?}"
        );
        // the script `outer.sh` runs is read too, and named as the script it is
        assert!(
            names.contains(&("python3".to_owned(), Some("inner.py".to_owned()))),
            "{names:?}"
        );
        let inner = out
            .iter()
            .find(|command| {
                command
                    .script
                    .as_ref()
                    .is_some_and(|source| source.name == "inner.py")
            })
            .expect("inner.py is read");
        // `open(...)` is a read veil recognises, so the file is a direct read and
        // not repeated among the words
        assert!(inner.candidates.contains(&dir.join("data/clients/a.csv")));
        assert!(
            !inner
                .argv_paths
                .iter()
                .any(|found| found.path == dir.join("data/clients/a.csv"))
        );
        // `$1` is a word veil cannot resolve; it is not an argument to judge
        assert!(out.iter().all(|command| command.unresolved.is_empty()));
    }

    #[test]
    fn an_unanalysable_shell_script_stays_opaque() {
        let dir = temp_dir("opaque");
        fs::write(
            dir.join("broken.sh"),
            "echo 'unterminated\ncat data/a.csv\n",
        )
        .expect("broken");

        let env = ShellEnv {
            cwd: Some(dir.clone()),
            home: None,
        };
        let simple = decompose_in("bash broken.sh", &env);
        let mut out = Vec::new();
        let mut scripts = Scripts::default();
        for command in &simple {
            inspect(command, &dir, &env, 0, &mut scripts, &mut out);
        }

        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].opaque, "{out:?}");
        assert_eq!(out[0].origin, Origin::Script);
        assert_eq!(
            out[0].script.as_ref().map(|source| source.name.as_str()),
            Some("broken.sh")
        );
    }

    #[test]
    fn a_wrapper_hands_the_file_it_runs_to_the_interpreter_its_extension_names() {
        let dir = temp_dir("wrapper");
        fs::write(dir.join("read.py"), "x = open('data/clients/a.csv')\n").expect("script");
        fs::write(dir.join("read.ts"), "const t = 'data/clients/a.csv';\n").expect("script");
        fs::write(dir.join("notes.txt"), "data/clients/a.csv\n").expect("text");

        let env = ShellEnv {
            cwd: Some(dir.clone()),
            home: None,
        };
        let read = |command: &str| {
            let mut out = Vec::new();
            let mut scripts = Scripts::default();
            for found in &decompose_in(command, &env) {
                inspect(found, &dir, &env, 0, &mut scripts, &mut out);
            }
            out.iter()
                .filter_map(|command| command.script.as_ref().map(|source| source.name.clone()))
                .collect::<Vec<_>>()
        };

        assert_eq!(read("uv run read.py"), ["read.py"]);
        assert_eq!(read("deno run --allow-read read.ts"), ["read.ts"]);
        assert_eq!(read("env FOO=1 read.py"), ["read.py"]);
        // a file typed as the command, with no wrapper, is not run by an interpreter
        assert!(read("read.py").is_empty());
        // an extension that no interpreter claims
        assert!(read("uv run notes.txt").is_empty());
    }

    #[test]
    fn a_command_that_runs_no_script_adds_nothing() {
        let dir = temp_dir("none");
        let env = ShellEnv {
            cwd: Some(dir.clone()),
            home: None,
        };

        for command in [
            "ls -l",
            "cat x.csv",
            "python3 -c 'print(1)'",
            "python3 missing.py",
            "git status",
        ] {
            let simple = decompose_in(command, &env);
            let mut out = Vec::new();
            let mut scripts = Scripts::default();
            for found in &simple {
                inspect(found, &dir, &env, 0, &mut scripts, &mut out);
            }
            assert!(out.is_empty(), "{command}");
        }
    }
}
