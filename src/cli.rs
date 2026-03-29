#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "veil",
    version,
    about = "Data exfiltration guard for AI coding agents"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<OperatorCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum OperatorCommand {
    Test { path: PathBuf },
    Explain { path: PathBuf },
    Scan { dir: PathBuf },
    Packs,
    Config,
    Audit,
    Doctor,
    Install,
    Uninstall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dispatch {
    HookMode,
    Operator(OperatorCommand),
}

impl Cli {
    pub fn dispatch(self) -> Dispatch {
        match self.command {
            Some(command) => Dispatch::Operator(command),
            None => Dispatch::HookMode,
        }
    }
}

pub fn parse_env() -> Result<Dispatch, clap::Error> {
    parse_from(std::env::args_os())
}

pub fn parse_from<I, T>(args: I) -> Result<Dispatch, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(args).map(Cli::dispatch)
}

impl OperatorCommand {
    pub fn as_name(&self) -> &'static str {
        match self {
            Self::Test { .. } => "test",
            Self::Explain { .. } => "explain",
            Self::Scan { .. } => "scan",
            Self::Packs => "packs",
            Self::Config => "config",
            Self::Audit => "audit",
            Self::Doctor => "doctor",
            Self::Install => "install",
            Self::Uninstall => "uninstall",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Dispatch {
        parse_from(args.iter().copied()).expect("CLI parse should succeed")
    }

    #[test]
    fn no_subcommand_selects_hook_mode() {
        assert_eq!(parse(&["veil"]), Dispatch::HookMode);
    }

    #[test]
    fn test_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "test", "fixtures/sample.txt"]),
            Dispatch::Operator(OperatorCommand::Test {
                path: PathBuf::from("fixtures/sample.txt"),
            })
        );
    }

    #[test]
    fn explain_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "explain", "fixtures/sample.txt"]),
            Dispatch::Operator(OperatorCommand::Explain {
                path: PathBuf::from("fixtures/sample.txt"),
            })
        );
    }

    #[test]
    fn scan_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "scan", "fixtures"]),
            Dispatch::Operator(OperatorCommand::Scan {
                dir: PathBuf::from("fixtures"),
            })
        );
    }

    #[test]
    fn flag_only_subcommands_select_expected_variants() {
        for (name, command) in [
            ("packs", OperatorCommand::Packs),
            ("config", OperatorCommand::Config),
            ("audit", OperatorCommand::Audit),
            ("doctor", OperatorCommand::Doctor),
            ("install", OperatorCommand::Install),
            ("uninstall", OperatorCommand::Uninstall),
        ] {
            assert_eq!(
                parse(&["veil", name]),
                Dispatch::Operator(command),
                "expected `{name}` to map to the correct operator command"
            );
        }
    }

    #[test]
    fn help_lists_supported_subcommands() {
        let mut help = Vec::new();
        Cli::command()
            .write_long_help(&mut help)
            .expect("help rendering should succeed");
        let help = String::from_utf8(help).expect("help should be valid UTF-8");

        for name in [
            "test",
            "explain",
            "scan",
            "packs",
            "config",
            "audit",
            "doctor",
            "install",
            "uninstall",
        ] {
            assert!(
                help.contains(name),
                "expected help output to mention `{name}`"
            );
        }
    }
}
