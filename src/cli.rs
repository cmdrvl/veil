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
    #[arg(long = "robot-triage", help = "Emit read-only JSON triage for agents")]
    robot_triage: bool,
    #[command(subcommand)]
    command: Option<OperatorCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct CapabilitiesArgs {
    #[arg(long, help = "Emit the capabilities contract as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct RobotDocsArgs {
    #[command(subcommand)]
    pub action: Option<RobotDocsAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum RobotDocsAction {
    #[command(about = "Print the agent quick-start guide")]
    Guide,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConfigArgs {
    #[arg(long, help = "Emit merged config as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct AuditArgs {
    #[arg(long, help = "Emit recent audit entries as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorArgs {
    #[arg(long = "robot-triage", help = "Emit read-only doctor triage JSON")]
    pub robot_triage: bool,
    #[arg(long, help = "Emit doctor health as JSON")]
    pub json: bool,
    #[command(subcommand)]
    pub action: Option<DoctorAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum DoctorAction {
    #[command(about = "Inspect config, audit path, and hook health")]
    Health(DoctorHealthArgs),
    #[command(about = "Describe read-only doctor commands and contract")]
    Capabilities(DoctorCapabilitiesArgs),
    #[command(about = "Print doctor-specific robot guidance")]
    RobotDocs,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorHealthArgs {
    #[arg(long, help = "Emit doctor health as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorCapabilitiesArgs {
    #[arg(long, help = "Emit doctor capabilities as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct PathCommandArgs {
    #[arg(help = "Path to inspect with veil's read-decision pipeline")]
    pub path: PathBuf,
    #[arg(long, help = "Emit the path inspection as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DirCommandArgs {
    #[arg(help = "Directory tree to scan with veil's read-decision pipeline")]
    pub dir: PathBuf,
    #[arg(long, help = "Emit scan results as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct JsonOutputArgs {
    #[arg(long, help = "Emit machine-readable JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum OperatorCommand {
    #[command(about = "Emit the machine-readable CLI capabilities contract")]
    Capabilities(CapabilitiesArgs),
    #[command(about = "Print agent-facing operational guidance")]
    RobotDocs(RobotDocsArgs),
    #[command(about = "Discover authorized spine tools for sensitive-file work")]
    Operator(JsonOutputArgs),
    #[command(about = "Predict whether one path would be allowed or denied")]
    Test(PathCommandArgs),
    #[command(about = "Explain allowlist, protected-pattern, and pack matches for one path")]
    Explain(PathCommandArgs),
    #[command(about = "Scan a directory tree and classify each file path")]
    Scan(DirCommandArgs),
    #[command(about = "List built-in sensitivity packs")]
    Packs(JsonOutputArgs),
    #[command(about = "Show the merged active configuration")]
    Config(ConfigArgs),
    #[command(about = "Show recent audit log entries")]
    Audit(AuditArgs),
    #[command(about = "Inspect local config, audit, and hook health without writing")]
    Doctor(DoctorArgs),
    #[command(about = "Install managed veil Claude PreToolUse hooks")]
    Install,
    #[command(about = "Remove managed veil Claude PreToolUse hooks")]
    Uninstall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dispatch {
    HookMode,
    Operator(OperatorCommand),
}

impl Cli {
    pub fn dispatch(self) -> Dispatch {
        if self.robot_triage {
            return Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: true,
                json: false,
                action: None,
            }));
        }

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
            Dispatch::Operator(OperatorCommand::Scan(DirCommandArgs {
                dir: PathBuf::from("fixtures"),
                json: false,
            }))
        );
    }

    #[test]
    fn flag_only_subcommands_select_expected_variants() {
        for (name, command) in [
            (
                "capabilities",
                OperatorCommand::Capabilities(CapabilitiesArgs { json: false }),
            ),
            (
                "robot-docs",
                OperatorCommand::RobotDocs(RobotDocsArgs { action: None }),
            ),
            (
                "operator",
                OperatorCommand::Operator(JsonOutputArgs { json: false }),
            ),
            (
                "packs",
                OperatorCommand::Packs(JsonOutputArgs { json: false }),
            ),
            (
                "config",
                OperatorCommand::Config(ConfigArgs { json: false }),
            ),
            ("audit", OperatorCommand::Audit(AuditArgs { json: false })),
            (
                "doctor",
                OperatorCommand::Doctor(DoctorArgs {
                    robot_triage: false,
                    json: false,
                    action: None,
                }),
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
            "capabilities",
            "robot-docs",
            "operator",
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

        assert!(help.contains("Emit the machine-readable CLI capabilities contract"));
        assert!(help.contains("Discover authorized spine tools"));
        assert!(help.contains("Inspect local config, audit, and hook health"));
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
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: false,
                json: true,
                action: None,
            }))
        );
    }

    #[test]
    fn doctor_health_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "doctor", "health", "--json"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: false,
                json: false,
                action: Some(DoctorAction::Health(DoctorHealthArgs { json: true })),
            }))
        );
    }

    #[test]
    fn doctor_capabilities_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "doctor", "capabilities", "--json"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: false,
                json: false,
                action: Some(DoctorAction::Capabilities(DoctorCapabilitiesArgs {
                    json: true,
                })),
            }))
        );
    }

    #[test]
    fn doctor_robot_docs_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "doctor", "robot-docs"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: false,
                json: false,
                action: Some(DoctorAction::RobotDocs),
            }))
        );
    }

    #[test]
    fn doctor_robot_triage_flag_selects_expected_mode() {
        assert_eq!(
            parse(&["veil", "doctor", "--robot-triage"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: true,
                json: false,
                action: None,
            }))
        );
    }

    #[test]
    fn top_level_robot_triage_flag_selects_doctor_triage() {
        assert_eq!(
            parse(&["veil", "--robot-triage"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: true,
                json: false,
                action: None,
            }))
        );
    }

    #[test]
    fn capabilities_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "capabilities", "--json"]),
            Dispatch::Operator(OperatorCommand::Capabilities(CapabilitiesArgs {
                json: true,
            }))
        );
    }

    #[test]
    fn robot_docs_guide_subcommand_selects_expected_variant() {
        assert_eq!(
            parse(&["veil", "robot-docs", "guide"]),
            Dispatch::Operator(OperatorCommand::RobotDocs(RobotDocsArgs {
                action: Some(RobotDocsAction::Guide),
            }))
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

    #[test]
    fn scan_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "scan", "fixtures", "--json"]),
            Dispatch::Operator(OperatorCommand::Scan(DirCommandArgs {
                dir: PathBuf::from("fixtures"),
                json: true,
            }))
        );
    }

    #[test]
    fn packs_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "packs", "--json"]),
            Dispatch::Operator(OperatorCommand::Packs(JsonOutputArgs { json: true }))
        );
    }

    #[test]
    fn operator_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "operator", "--json"]),
            Dispatch::Operator(OperatorCommand::Operator(JsonOutputArgs { json: true }))
        );
    }
}
