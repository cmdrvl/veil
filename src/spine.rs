#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpineInvocation {
    pub tool_name: String,
    pub target_path: PathBuf,
}

pub fn detect_spine_invocation(
    command: &str,
    authorized_tools: &[String],
    cwd: &Path,
) -> Option<SpineInvocation> {
    let tokens = shlex::split(command)?;
    let pipeline = left_pipeline(&tokens);
    let (program, args) = pipeline.split_first()?;

    let tool_name = authorized_tool_name(program, authorized_tools)?;
    let target_path = extract_target_path(args, cwd)?;

    Some(SpineInvocation {
        tool_name,
        target_path,
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

    #[test]
    fn matches_a_basic_spine_invocation() {
        let invocation =
            detect_spine_invocation("shape sensitive.csv", &authorized_tools(), workspace());

        assert_eq!(
            invocation,
            Some(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from("/workspace/veil/sensitive.csv"),
            })
        );
    }

    #[test]
    fn matches_a_full_path_spine_invocation() {
        let invocation = detect_spine_invocation(
            "/usr/local/bin/shape sensitive.csv",
            &authorized_tools(),
            workspace(),
        );

        assert_eq!(
            invocation,
            Some(SpineInvocation {
                tool_name: "shape".to_owned(),
                target_path: PathBuf::from("/workspace/veil/sensitive.csv"),
            })
        );
    }

    #[test]
    fn matches_a_piped_spine_invocation() {
        let invocation = detect_spine_invocation(
            "profile filings/report.xml | jq .summary",
            &authorized_tools(),
            workspace(),
        );

        assert_eq!(
            invocation,
            Some(SpineInvocation {
                tool_name: "profile".to_owned(),
                target_path: PathBuf::from("/workspace/veil/filings/report.xml"),
            })
        );
    }

    #[test]
    fn rejects_non_spine_commands() {
        let invocation =
            detect_spine_invocation("cat sensitive.csv", &authorized_tools(), workspace());

        assert_eq!(invocation, None);
    }
}
