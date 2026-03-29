#![forbid(unsafe_code)]

pub mod allowlist;
pub mod extract;
pub mod spine;
pub mod types;

use std::error::Error;
use std::io::{self, Read, Write};

use types::{Decision, DecisionAction};

pub fn run() -> Result<u8, Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    run_with_io(stdin.lock(), &mut stdout)?;
    Ok(0)
}

fn run_with_io<R: Read, W: Write>(mut reader: R, writer: &mut W) -> io::Result<()> {
    let mut input = String::new();
    reader.read_to_string(&mut input)?;
    drop(input);

    let response = render_stub_response(&stub_decision());
    writer.write_all(response.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn stub_decision() -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: Some("veil scaffold stub allows all requests".to_owned()),
        confidence: Some(1.0),
        remediation: None,
    }
}

fn render_stub_response(decision: &Decision) -> String {
    let permission_decision = match decision.action {
        DecisionAction::Allow => "allow",
        DecisionAction::Deny => "deny",
    };

    // The scaffold stays protocol-agnostic for now and emits the smallest
    // hook-shaped response needed to unblock downstream implementation.
    format!(r#"{{"permissionDecision":"{permission_decision}"}}"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_io_emits_allow_response() {
        let input = br#"{"tool":"Read","tool_input":{"file_path":"secret.txt"}}"#;
        let mut output = Vec::new();

        run_with_io(&input[..], &mut output).expect("stub runner should succeed");

        assert_eq!(
            String::from_utf8(output).expect("output should be UTF-8"),
            "{\"permissionDecision\":\"allow\"}\n"
        );
    }

    #[test]
    fn stub_decision_populates_shared_fields() {
        let decision = stub_decision();

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(
            decision.reason.as_deref(),
            Some("veil scaffold stub allows all requests")
        );
        assert!(
            decision
                .confidence
                .is_some_and(|value| (value - 1.0).abs() < f32::EPSILON)
        );
        assert_eq!(decision.remediation, None);
    }
}
