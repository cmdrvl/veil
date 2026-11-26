#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Flags that escalate an authorized spine tool from metadata-safe output to raw
/// protected values. `shape --explicit x.csv` is an authorized tool producing
/// raw content, so these are denied unless an operator reconfigures them.
pub const DEFAULT_DENIED_FLAGS: &[&str] = &["--explicit", "--raw", "--dump", "--show-values"];

/// Flag policy table for authorized spine tools: a default deny list plus
/// per-tool additions. A per-tool list extends the default for that tool; it
/// never replaces it, so a tool entry cannot silently weaken the baseline.
/// Hook mode enforces it today; the Track B broker reuses it unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeniedFlags {
    pub default: Vec<String>,
    pub per_tool: BTreeMap<String, Vec<String>>,
}

impl Default for DeniedFlags {
    fn default() -> Self {
        Self {
            default: DEFAULT_DENIED_FLAGS
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            per_tool: BTreeMap::new(),
        }
    }
}

impl DeniedFlags {
    /// Returns the first configured flag that `args` uses for `tool`, matching
    /// both `--flag` and `--flag=value`. Every argument is scanned, including
    /// ones after `--` or a redirection, so position cannot hide a flag.
    pub fn find<'a>(&'a self, tool: &str, args: &[String]) -> Option<&'a str> {
        let tool_flags = self.per_tool.get(tool).map(Vec::as_slice).unwrap_or(&[]);

        self.default
            .iter()
            .chain(tool_flags)
            .map(String::as_str)
            .find(|flag| args.iter().any(|arg| arg_uses_flag(arg, flag)))
    }
}

fn arg_uses_flag(arg: &str, flag: &str) -> bool {
    arg == flag
        || arg
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpineInvocation {
    pub tool_name: String,
    pub target_path: PathBuf,
    /// The denied raw-value flag this invocation uses, if any. An invocation
    /// with a denied flag is never authorized to read protected content.
    pub denied_flag: Option<String>,
}

impl SpineInvocation {
    /// The same invocation, judged for another path its command names. An
    /// authorized spine tool is authorized for everything its words name, not
    /// only the first path (bd-29r); a denied flag still applies to all of it.
    pub fn for_path(&self, path: PathBuf) -> Self {
        Self {
            target_path: path,
            ..self.clone()
        }
    }
}

pub fn detect_spine_invocation(
    command: &str,
    authorized_tools: &[String],
    denied_flags: &DeniedFlags,
    cwd: &Path,
) -> Option<SpineInvocation> {
    let tokens = shlex::split(command)?;
    detect_spine_argv(left_pipeline(&tokens), authorized_tools, denied_flags, cwd)
}

/// Like [`detect_spine_invocation`] for one simple command whose words are
/// already split, such as each command of a decomposed Bash command (bd-2kr).
/// The words are the command's own, so nothing here looks for a pipeline.
pub fn detect_spine_argv(
    argv: &[String],
    authorized_tools: &[String],
    denied_flags: &DeniedFlags,
    cwd: &Path,
) -> Option<SpineInvocation> {
    let (program, args) = through_veil_exec(argv, authorized_tools, cwd).split_first()?;

    let tool_name = authorized_tool_name(program, authorized_tools)?;
    let target_path = extract_target_path(args, cwd)?;
    let denied_flag = denied_flags.find(&tool_name, args).map(str::to_owned);

    Some(SpineInvocation {
        tool_name,
        target_path,
        denied_flag,
    })
}

/// `veil exec [--persist] TOOL ARGS...` runs TOOL through the broker, so when
/// TOOL is an authorized spine tool the command is judged as `TOOL ARGS...`
/// (bd-fxa). `--persist` is veil's own flag (bd-3qw). Anything else is still
/// judged as a command named `veil`.
fn through_veil_exec<'a>(
    argv: &'a [String],
    authorized_tools: &[String],
    cwd: &Path,
) -> &'a [String] {
    let [program, subcommand, rest @ ..] = argv else {
        return argv;
    };
    let from_tool = match rest {
        [flag, after @ ..] if flag == "--persist" => after,
        _ => rest,
    };
    match from_tool {
        [tool, ..]
            if subcommand == "exec"
                && authorized_tool_name(tool, authorized_tools).is_some()
                && names_this_veil(program, cwd) =>
        {
            from_tool
        }
        _ => argv,
    }
}

/// The word `veil`, found on `PATH` as a bare spine tool name is, or a path to
/// the program that is running. A spine tool is recognised by its file name,
/// but this must not be: any other script called `veil` would get its place.
fn names_this_veil(program: &str, cwd: &Path) -> bool {
    if program == "veil" {
        return true;
    }
    program.contains('/')
        && std::env::current_exe()
            .and_then(fs::canonicalize)
            .is_ok_and(|running| {
                fs::canonicalize(cwd.join(program)).is_ok_and(|named| named == running)
            })
}

fn left_pipeline(tokens: &[String]) -> &[String] {
    for (index, token) in tokens.iter().enumerate() {
        if is_pipeline_separator(token) {
            return &tokens[..index];
        }
    }

    tokens
}

fn authorized_tool_name(program: &str, authorized_tools: &[String]) -> Option<String> {
    let program_basename = command_name(program);

    authorized_tools.iter().find_map(|configured_tool| {
        let configured_basename = command_name(configured_tool);
        if configured_tool == program || configured_basename == program_basename {
            Some(configured_basename.to_owned())
        } else {
            None
        }
    })
}

fn extract_target_path(args: &[String], cwd: &Path) -> Option<PathBuf> {
    let mut parsing_options = true;

    for arg in args {
        if is_redirection(arg) {
            break;
        }

        if arg == "--" {
            parsing_options = false;
            continue;
        }

        if parsing_options && arg.starts_with('-') {
            continue;
        }

        if arg == "-" {
            continue;
        }

        return normalize_path(arg, cwd);
    }

    None
}

fn command_name(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

fn normalize_path(raw_path: &str, cwd: &Path) -> Option<PathBuf> {
    let candidate = Path::new(raw_path);
    if candidate.as_os_str().is_empty() {
        return None;
    }

    Some(if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    })
}

fn is_redirection(arg: &str) -> bool {
    matches!(arg, "<" | ">" | ">>" | "1>" | "1>>" | "2>" | "2>>")
}

fn is_pipeline_separator(token: &str) -> bool {
    token.len() == 1 && token.as_bytes()[0] == b'|'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> &'static Path {
        Path::new("/workspace/veil")
    }

    fn authorized_tools() -> Vec<String> {
        vec!["shape".to_owned(), "profile".to_owned()]
    }

    fn detect(command: &str) -> Option<SpineInvocation> {
        detect_spine_invocation(
            command,
            &authorized_tools(),
            &DeniedFlags::default(),
            workspace(),
        )
    }

    fn denied_flag(command: &str) -> Option<String> {
        detect(command)
            .expect("command should be detected as a spine invocation")
            .denied_flag
    }

    #[test]
    fn matches_a_basic_spine_invocation() {
        assert_eq!(
            detect("shape sensitive.csv"),
            Some(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from("/workspace/veil/sensitive.csv"),
                denied_flag: None,
            })
        );
    }

    #[test]
    fn matches_a_full_path_spine_invocation() {
        assert_eq!(
            detect("/usr/local/bin/shape sensitive.csv"),
            Some(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from("/workspace/veil/sensitive.csv"),
                denied_flag: None,
            })
        );
    }

    #[test]
    fn matches_a_piped_spine_invocation() {
        assert_eq!(
            detect("profile filings/report.xml | jq .summary"),
            Some(SpineInvocation {
                tool_name: "profile".to_owned(),
                target_path: PathBuf::from("/workspace/veil/filings/report.xml"),
                denied_flag: None,
            })
        );
    }

    #[test]
    fn rejects_non_spine_commands() {
        assert_eq!(detect("cat sensitive.csv"), None);
    }

    #[test]
    fn default_denied_flags_are_reported_in_flag_and_flag_equals_forms() {
        for flag in ["--explicit", "--raw", "--dump", "--show-values"] {
            assert_eq!(
                denied_flag(&format!("shape {flag} sensitive.csv")).as_deref(),
                Some(flag),
                "`shape {flag} <path>`"
            );
            assert_eq!(
                denied_flag(&format!("profile {flag}=true sensitive.csv")).as_deref(),
                Some(flag),
                "`profile {flag}=true <path>`"
            );
        }
    }

    #[test]
    fn denied_flags_are_found_anywhere_in_the_invocation() {
        for command in [
            "shape sensitive.csv --explicit",
            "shape sensitive.csv --json --explicit=1",
            "shape -- sensitive.csv --explicit",
            "shape sensitive.csv > out.txt --explicit",
            "shape '--explicit' sensitive.csv",
            "shape --expl\"\"icit sensitive.csv",
            "/usr/local/bin/shape --explicit sensitive.csv | jq .",
        ] {
            assert_eq!(
                denied_flag(command).as_deref(),
                Some("--explicit"),
                "`{command}`"
            );
        }
    }

    #[test]
    fn similar_looking_arguments_are_not_denied_flags() {
        for command in [
            "shape sensitive.csv --json",
            "shape sensitive.csv --explicitly",
            "shape sensitive.csv --no-explicit",
            "shape explicit.csv",
            "shape sensitive.csv | jq --raw-output .rows",
            "shape sensitive.csv | grep --explicit",
        ] {
            assert_eq!(denied_flag(command), None, "`{command}`");
        }
    }

    #[test]
    fn per_tool_flags_extend_the_default_for_that_tool_only() {
        let mut denied = DeniedFlags::default();
        denied
            .per_tool
            .insert("profile".to_owned(), vec!["--values".to_owned()]);
        let detect_with = |command: &str| {
            detect_spine_invocation(command, &authorized_tools(), &denied, workspace())
                .unwrap()
                .denied_flag
        };

        assert_eq!(
            detect_with("profile --values sensitive.csv").as_deref(),
            Some("--values")
        );
        assert_eq!(detect_with("shape --values sensitive.csv"), None);
        assert_eq!(
            detect_with("profile --explicit sensitive.csv").as_deref(),
            Some("--explicit"),
            "a per-tool entry must not drop the default deny list"
        );
    }

    #[test]
    fn replacing_the_default_list_changes_what_is_denied() {
        let denied = DeniedFlags {
            default: vec!["--only-this".to_owned()],
            per_tool: BTreeMap::new(),
        };
        let invocation = detect_spine_invocation(
            "shape --explicit sensitive.csv",
            &authorized_tools(),
            &denied,
            workspace(),
        )
        .unwrap();

        assert_eq!(invocation.denied_flag, None);
    }
}
