#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match veil::run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("veil: {err}");
            ExitCode::from(2)
        }
    }
}
