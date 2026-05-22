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
        Ok(cli::Dispatch::HookMode) => veil::run(),
        Ok(cli::Dispatch::Operator(command)) => dispatch_operator(command),
        Err(err) => err.exit(),
    }
}

fn dispatch_operator(command: cli::OperatorCommand) -> Result<u8, Box<dyn std::error::Error>> {
    if command_requires_guard_preflight(&command) {
        enforce_guard_preflight()?;
    }

    match command {
        cli::OperatorCommand::Operator(args) => {
            println!("{}", operator::run_operator(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Test(args) => {
            println!("{}", operator::run_test(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Explain(args) => {
            println!("{}", operator::run_explain(&args)?);
            Ok(0)
        }
        cli::OperatorCommand::Scan(args) => {
            println!("{}", operator::run_scan(&args)?);
            Ok(0)
        }
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
        cli::OperatorCommand::Doctor(args) => {
            println!("{}", operator::run_doctor(&args)?);
            Ok(0)
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

fn command_requires_guard_preflight(command: &cli::OperatorCommand) -> bool {
    !matches!(
        command,
        cli::OperatorCommand::Doctor(_)
            | cli::OperatorCommand::Install
            | cli::OperatorCommand::Uninstall
    )
}

fn enforce_guard_preflight() -> Result<(), Box<dyn std::error::Error>> {
    let settings_path = hooks::default_settings_path().map_err(|error| {
        format!("guard preflight failed: could not resolve active hook settings path: {error}")
    })?;
    let inspection = hooks::inspect_guard_preflight(&settings_path).map_err(|error| {
        format!(
            "guard preflight failed: could not inspect hook settings at {}: {error}",
            settings_path.display()
        )
    })?;

    if inspection.is_healthy() {
        Ok(())
    } else {
        Err(hooks::guard_preflight_refusal(&settings_path, &inspection).into())
    }
}
