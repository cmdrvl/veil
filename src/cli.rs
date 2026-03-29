#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConfigArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct AuditArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct PathCommandArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum OperatorCommand {
    Test(PathCommandArgs),
    Explain(PathCommandArgs),
    Scan { dir: PathBuf },
    Packs,
    Config(ConfigArgs),
    Audit(AuditArgs),
    Doctor(DoctorArgs),
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
            Self::Config(_) => "config",
            Self::Audit(_) => "audit",
            Self::Doctor(_) => "doctor",
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
            Dispatch::Operator(OperatorCommand::Test(PathCommandArgs {
                path: PathBuf::from("fixtures/sample.txt"),
                json: false,
            }))
        );
    }

    #[test]
    fn explain_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "explain", "fixtures/sample.txt"]),
            Dispatch::Operator(OperatorCommand::Explain(PathCommandArgs {
                path: PathBuf::from("fixtures/sample.txt"),
                json: false,
            }))
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
            (
                "config",
                OperatorCommand::Config(ConfigArgs { json: false }),
            ),
            ("audit", OperatorCommand::Audit(AuditArgs { json: false })),
            (
                "doctor",
                OperatorCommand::Doctor(DoctorArgs { json: false }),
            ),
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

    #[test]
    fn config_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "config", "--json"]),
            Dispatch::Operator(OperatorCommand::Config(ConfigArgs { json: true }))
        );
    }

    #[test]
    fn audit_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "audit", "--json"]),
            Dispatch::Operator(OperatorCommand::Audit(AuditArgs { json: true }))
        );
    }

    #[test]
    fn doctor_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "doctor", "--json"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs { json: true }))
        );
    }

    #[test]
    fn test_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "test", "fixtures/sample.txt", "--json"]),
            Dispatch::Operator(OperatorCommand::Test(PathCommandArgs {
                path: PathBuf::from("fixtures/sample.txt"),
                json: true,
            }))
        );
    }

    #[test]
    fn explain_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "explain", "fixtures/sample.txt", "--json"]),
            Dispatch::Operator(OperatorCommand::Explain(PathCommandArgs {
                path: PathBuf::from("fixtures/sample.txt"),
                json: true,
            }))
        );
    }
}
