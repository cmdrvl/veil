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
    match command {
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
        command => Err(format!("`veil {}` is not implemented yet", command.as_name()).into()),
    }
}
