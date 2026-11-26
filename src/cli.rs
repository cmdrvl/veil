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
    #[arg(long = "broker", hide = true)]
    broker_mode: bool,
    #[arg(long = "robot-triage", help = "Emit read-only JSON triage for agents")]
    robot_triage: bool,
    #[arg(
        long,
        help = "Print the operator manifest (same document as `capabilities --json`) and exit"
    )]
    describe: bool,
    #[arg(
        long,
        help = "Print the JSON Schema for hook-mode stdout (the permission decision) and exit"
    )]
    schema: bool,
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
    #[arg(
        long,
        value_name = "CLASS",
        value_parser = ["egress", "direct_read", "argv_path", "dynamic_path_unresolvable", "mcp_argument", "script_too_large_to_inspect", "redirect_write"],
        help = "Only entries of one class: `egress` (a command that sends a protected path), or a reason_class"
    )]
    pub class: Option<String>,
    #[arg(
        long,
        conflicts_with = "class",
        help = "Count the audit log's lines by kind (current, legacy, unparseable) and list the unparseable ones"
    )]
    pub validate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ReplayArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Audit JSONL file; defaults to the configured audit path"
    )]
    pub audit: Option<PathBuf>,
    #[arg(
        long,
        value_name = "TIME",
        help = "Replay entries since Unix seconds or a duration such as 30d"
    )]
    pub since: Option<String>,
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
    #[command(about = "Emit doctor triage JSON with next actions (always JSON)")]
    Triage(DoctorTriageArgs),
    #[command(about = "Print doctor-specific robot guidance")]
    RobotDocs,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorHealthArgs {
    #[arg(long, help = "Emit doctor health as JSON")]
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DoctorTriageArgs {
    #[arg(long, help = "Accepted for symmetry; triage is always JSON")]
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
pub struct SandboxArgs {
    #[arg(long, conflicts_with = "dry_run")]
    pub print_profile: bool,
    #[arg(long, conflicts_with = "print_profile")]
    pub dry_run: bool,
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["print_profile", "dry_run"],
        help = "Write the profile applied to this launch to a new file"
    )]
    pub profile_out: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with_all = ["print_profile", "dry_run", "command"],
        help = "Open a confined shell: $SHELL, or /bin/sh"
    )]
    pub shell: bool,
    #[arg(last = true, value_name = "COMMAND", num_args = 1..)]
    pub command: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
#[command(override_usage = "veil exec [--persist] <TOOL> [ARGS]...")]
pub struct ExecArgs {
    #[arg(
        long,
        help = "Let the output stay readable as derived after this session ends"
    )]
    pub persist: bool,
    /// The tool and its arguments. One positional, so that every word from the
    /// tool's name on is the tool's, one spelled like veil's flag included.
    #[arg(
        value_name = "TOOL",
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DerivedArgs {
    #[command(subcommand)]
    pub action: DerivedAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum DerivedAction {
    #[command(about = "List the derived registry's records")]
    List(JsonOutputArgs),
    #[command(about = "Say whether a file's bytes are registered; exit 0 only if they are")]
    Verify(DerivedVerifyArgs),
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct DerivedVerifyArgs {
    #[arg(help = "File to hash and look up")]
    pub path: PathBuf,
    #[arg(long, help = "Emit machine-readable JSON")]
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
    #[command(about = "Compile an opt-in macOS Seatbelt policy")]
    Sandbox(SandboxArgs),
    #[command(about = "Run an authorized metadata tool through the broker")]
    Exec(ExecArgs),
    #[command(about = "Inspect the registry of derived outputs")]
    Derived(DerivedArgs),
    #[command(about = "List built-in sensitivity packs")]
    Packs(JsonOutputArgs),
    #[command(about = "Show the merged active configuration")]
    Config(ConfigArgs),
    #[command(about = "Show recent audit log entries")]
    Audit(AuditArgs),
    #[command(about = "Replay saved tool inputs against the current policy")]
    Replay(ReplayArgs),
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
    BrokerMode,
    Describe,
    Schema,
    Operator(OperatorCommand),
}

impl Cli {
    pub fn dispatch(self) -> Dispatch {
        if self.broker_mode {
            return Dispatch::BrokerMode;
        }

        if self.describe {
            return Dispatch::Describe;
        }

        if self.schema {
            return Dispatch::Schema;
        }

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
    fn describe_and_schema_flags_select_introspection() {
        assert_eq!(parse(&["veil", "--describe"]), Dispatch::Describe);
        assert_eq!(parse(&["veil", "--schema"]), Dispatch::Schema);
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
    fn sandbox_compiler_modes_select_expected_variant() {
        assert_eq!(
            parse(&["veil", "sandbox", "--print-profile"]),
            Dispatch::Operator(OperatorCommand::Sandbox(SandboxArgs {
                print_profile: true,
                dry_run: false,
                profile_out: None,
                shell: false,
                command: Vec::new(),
            }))
        );
        assert_eq!(
            parse(&["veil", "sandbox", "--", "/bin/echo", "hello"]),
            Dispatch::Operator(OperatorCommand::Sandbox(SandboxArgs {
                print_profile: false,
                dry_run: false,
                profile_out: None,
                shell: false,
                command: vec!["/bin/echo".into(), "hello".into()],
            }))
        );
        assert_eq!(
            parse(&["veil", "sandbox", "--dry-run"]),
            Dispatch::Operator(OperatorCommand::Sandbox(SandboxArgs {
                print_profile: false,
                dry_run: true,
                profile_out: None,
                shell: false,
                command: Vec::new(),
            }))
        );
        assert_eq!(
            parse(&["veil", "sandbox", "--profile-out", "a.sb", "--shell"]),
            Dispatch::Operator(OperatorCommand::Sandbox(SandboxArgs {
                print_profile: false,
                dry_run: false,
                profile_out: Some("a.sb".into()),
                shell: true,
                command: Vec::new(),
            }))
        );
    }

    #[test]
    fn exec_forwards_tool_arguments_in_typed_positions() {
        assert_eq!(
            parse(&["veil", "exec", "shape", "--explicit", "private.csv"]),
            exec(false, &["shape", "--explicit", "private.csv"])
        );
    }

    fn exec(persist: bool, command: &[&str]) -> Dispatch {
        Dispatch::Operator(OperatorCommand::Exec(ExecArgs {
            persist,
            command: command.iter().map(|word| (*word).to_owned()).collect(),
        }))
    }

    #[test]
    fn exec_takes_persist_only_before_the_tool() {
        assert_eq!(
            parse(&["veil", "exec", "--persist", "shape", "private.csv"]),
            exec(true, &["shape", "private.csv"])
        );
        // after the tool name every word is the tool's, this one included
        for words in [
            ["shape", "--persist", "private.csv"],
            ["shape", "private.csv", "--persist"],
            ["shape", "--help", "--version"],
            ["shape", "--", "-x"],
        ] {
            assert_eq!(
                parse(&["veil", "exec", words[0], words[1], words[2]]),
                exec(false, &words)
            );
        }
        assert!(Cli::try_parse_from(["veil", "exec"]).is_err());
        assert!(Cli::try_parse_from(["veil", "exec", "--persist"]).is_err());
    }

    #[test]
    fn derived_subcommands_list_and_verify() {
        assert_eq!(
            parse(&["veil", "derived", "list", "--json"]),
            Dispatch::Operator(OperatorCommand::Derived(DerivedArgs {
                action: DerivedAction::List(JsonOutputArgs { json: true }),
            }))
        );
        assert_eq!(
            parse(&["veil", "derived", "verify", "report.json"]),
            Dispatch::Operator(OperatorCommand::Derived(DerivedArgs {
                action: DerivedAction::Verify(DerivedVerifyArgs {
                    path: PathBuf::from("report.json"),
                    json: false,
                }),
            }))
        );
        assert!(Cli::try_parse_from(["veil", "derived"]).is_err());
    }

    #[test]
    fn hidden_broker_flag_selects_internal_mode() {
        assert_eq!(parse(&["veil", "--broker"]), Dispatch::BrokerMode);
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
            (
                "audit",
                OperatorCommand::Audit(AuditArgs {
                    json: false,
                    class: None,
                    validate: false,
                }),
            ),
            (
                "replay",
                OperatorCommand::Replay(ReplayArgs {
                    audit: None,
                    since: None,
                }),
            ),
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
            "sandbox",
            "exec",
            "derived",
            "packs",
            "config",
            "audit",
            "replay",
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
            Dispatch::Operator(OperatorCommand::Audit(AuditArgs {
                json: true,
                class: None,
                validate: false,
            }))
        );
    }

    #[test]
    fn replay_subcommand_accepts_audit_path_and_since_window() {
        assert_eq!(
            parse(&[
                "veil",
                "replay",
                "--audit",
                "state/audit.jsonl",
                "--since",
                "30d"
            ]),
            Dispatch::Operator(OperatorCommand::Replay(ReplayArgs {
                audit: Some(PathBuf::from("state/audit.jsonl")),
                since: Some("30d".to_owned()),
            }))
        );
    }

    #[test]
    fn audit_validate_is_a_report_of_its_own_and_takes_no_class() {
        assert_eq!(
            parse(&["veil", "audit", "--validate", "--json"]),
            Dispatch::Operator(OperatorCommand::Audit(AuditArgs {
                json: true,
                class: None,
                validate: true,
            }))
        );
        assert!(
            Cli::try_parse_from(["veil", "audit", "--validate", "--class", "egress"]).is_err(),
            "validation counts the whole log; a class filter has nothing to select"
        );
    }

    #[test]
    fn audit_subcommand_accepts_a_class_and_nothing_else() {
        assert_eq!(
            parse(&["veil", "audit", "--class", "egress", "--json"]),
            Dispatch::Operator(OperatorCommand::Audit(AuditArgs {
                json: true,
                class: Some("egress".to_owned()),
                validate: false,
            }))
        );
        for class in [
            "direct_read",
            "argv_path",
            "dynamic_path_unresolvable",
            "mcp_argument",
            "script_too_large_to_inspect",
            "redirect_write",
        ] {
            assert_eq!(
                parse(&["veil", "audit", "--class", class]),
                Dispatch::Operator(OperatorCommand::Audit(AuditArgs {
                    json: false,
                    class: Some(class.to_owned()),
                    validate: false,
                }))
            );
        }

        // a typo is an error, not an empty result that reads as "nothing left"
        assert!(
            Cli::try_parse_from(["veil", "audit", "--class", "egres"]).is_err(),
            "an unknown class must be refused"
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
    fn doctor_triage_subcommand_accepts_json_flag() {
        assert_eq!(
            parse(&["veil", "doctor", "triage", "--json"]),
            Dispatch::Operator(OperatorCommand::Doctor(DoctorArgs {
                robot_triage: false,
                json: false,
                action: Some(DoctorAction::Triage(DoctorTriageArgs { json: true })),
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
