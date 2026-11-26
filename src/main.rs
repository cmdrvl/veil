#![forbid(unsafe_code)]

use std::process::ExitCode;

mod cli;
mod hooks;
mod operator;

fn main() -> ExitCode {
    match dispatch() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("veil: {err}");
            ExitCode::from(2)
        }
    }
}

fn dispatch() -> Result<u8, Box<dyn std::error::Error>> {
    match cli::parse_env() {
        Ok(cli::Dispatch::BrokerMode) => {
            veil::broker::run_broker_from_env()?;
            Ok(0)
        }
        Ok(cli::Dispatch::HookMode) => veil::run(),
        Ok(cli::Dispatch::Describe) => {
            println!("{}", operator::run_describe());
            Ok(0)
        }
        Ok(cli::Dispatch::Schema) => {
            println!("{}", operator::run_schema());
            Ok(0)
        }
        Ok(cli::Dispatch::Operator(command)) => dispatch_operator(command),
        Err(err) => err.exit(),
    }
}

fn dispatch_operator(command: cli::OperatorCommand) -> Result<u8, Box<dyn std::error::Error>> {
    if command_requires_guard_preflight(&command) && !runs_its_own_guard_preflight(&command) {
        enforce_guard_preflight()?;
    }

    match command {
        cli::OperatorCommand::Capabilities(args) => {
            println!("{}", operator::run_capabilities(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::RobotDocs(args) => {
            println!("{}", operator::run_robot_docs(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Operator(args) => {
            println!("{}", operator::run_operator(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Test(args) => {
            path_decision_command(args.json, || operator::run_test(&args))
        }
        cli::OperatorCommand::Explain(args) => {
            path_decision_command(args.json, || operator::run_explain(&args))
        }
        cli::OperatorCommand::Scan(args) => {
            path_decision_command(args.json, || operator::run_scan(&args))
        }
        cli::OperatorCommand::Sandbox(args) => {
            if args.command.is_empty() {
                println!("{}", operator::run_sandbox(&args)?);
                Ok(0)
            } else {
                operator::launch_sandbox(&args.command)
            }
        }
        cli::OperatorCommand::Exec(args) => {
            let mut command = args.command.into_iter();
            let tool = command.next().ok_or("veil exec needs a tool")?;
            let exit_code = veil::broker::run_exec(tool, command.collect(), args.persist)?;
            Ok(u8::try_from(exit_code).unwrap_or(1))
        }
        cli::OperatorCommand::Derived(args) => derived_command(&args),
        cli::OperatorCommand::Packs(args) => {
            println!("{}", operator::run_packs(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Config(args) => {
            println!("{}", operator::run_config(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Audit(args) => {
            println!("{}", operator::run_audit(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Replay(args) => {
            println!("{}", operator::run_replay(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Doctor(args) => {
            let (rendered, exit_code) = operator::run_doctor(&args)?;
            println!("{rendered}");
            Ok(exit_code)
        }
        cli::OperatorCommand::Install => {
            let path = hooks::install_default()?;
            println!("Installed veil hooks in {}", path.display());
            Ok(0)
        }
        cli::OperatorCommand::Uninstall => {
            let path = hooks::uninstall_default()?;
            println!("Removed veil hooks from {}", path.display());
            Ok(0)
        }
    }
}

/// `veil derived`: read-only reports on the derived registry. `verify` exits 1
/// for a file that is not registered.
fn derived_command(args: &cli::DerivedArgs) -> Result<u8, Box<dyn std::error::Error>> {
    let registry = veil::derived::Registry::from_env()
        .ok_or("HOME is not set, so there is no derived registry")?;
    match &args.action {
        cli::DerivedAction::List(list) => {
            println!("{}", veil::derived::render_list(&registry, list.json)?);
            Ok(0)
        }
        cli::DerivedAction::Verify(verify) => {
            let (rendered, registered) =
                veil::derived::render_verify(&registry, &verify.path, verify.json)?;
            println!("{rendered}");
            Ok(u8::from(!registered))
        }
    }
}

/// `test`, `explain` and `scan` are what a wrapper calls to get a decision
/// about a path. They run the guard preflight themselves so that, under
/// `--json`, a refusal is a JSON document on stdout like every other failure.
fn runs_its_own_guard_preflight(command: &cli::OperatorCommand) -> bool {
    matches!(
        command,
        cli::OperatorCommand::Test(_)
            | cli::OperatorCommand::Explain(_)
            | cli::OperatorCommand::Scan(_)
    )
}

/// Runs the guard preflight and then `run`, printing its output. Under
/// `--json` any failure is printed as a `veil.path-decision.v1` error document
/// on stdout (the message also goes to stderr, for humans) and exits 2;
/// without `--json` it is returned and reported on stderr as before.
fn path_decision_command(
    json: bool,
    run: impl FnOnce() -> Result<String, Box<dyn std::error::Error>>,
) -> Result<u8, Box<dyn std::error::Error>> {
    let outcome = match enforce_guard_preflight() {
        Ok(()) => run().map_err(|error| (operator::path_error_code(error.as_ref()), error)),
        Err(error) => Err((operator::PATH_ERROR_PREFLIGHT_REFUSED, error)),
    };

    match outcome {
        Ok(rendered) => {
            println!("{rendered}");
            Ok(0)
        }
        Err((code, error)) if json => {
            let message = error.to_string();
            println!("{}", operator::path_error_json(code, &message));
            eprintln!("veil: {message}");
            Ok(2)
        }
        Err((_, error)) => Err(error),
    }
}

fn command_requires_guard_preflight(command: &cli::OperatorCommand) -> bool {
    !matches!(
        command,
        cli::OperatorCommand::Doctor(_)
            | cli::OperatorCommand::Capabilities(_)
            | cli::OperatorCommand::RobotDocs(_)
            | cli::OperatorCommand::Sandbox(_)
            | cli::OperatorCommand::Exec(_)
            | cli::OperatorCommand::Install
            | cli::OperatorCommand::Uninstall
    )
}

fn enforce_guard_preflight() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = std::env::current_dir()?;
    let config = veil::config::load_config(&repo_root)
        .map_err(|error| format!("guard preflight failed: could not load config: {error}"))?;
    let posture = hooks::inspect_guard_posture(
        hooks::detect_harness(|name| std::env::var(name).ok()),
        config.policy.require_dcg,
        hooks::default_settings_path().map_err(|error| error.to_string()),
        std::env::var_os("PATH").as_deref(),
    );

    if posture.is_healthy() {
        Ok(())
    } else {
        Err(posture.refusal().into())
    }
}
