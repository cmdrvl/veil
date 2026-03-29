#![forbid(unsafe_code)]

use std::process::ExitCode;

mod cli;

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
        Ok(cli::Dispatch::Operator(command)) => {
            Err(format!("`veil {}` is not implemented yet", command.as_name()).into())
        }
        Err(err) => err.exit(),
    }
}
