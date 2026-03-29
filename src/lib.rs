#![forbid(unsafe_code)]

pub mod allowlist;
pub mod audit;
pub mod config;
pub mod evaluator;
pub mod extract;
pub mod hook;
pub mod packs;
pub mod render;
pub mod spine;
pub mod types;

use std::error::Error;
use std::io::{self, Read, Write};

use hook::parse_hook_input;
use render::render_decision;
use types::{Decision, DecisionAction, HookProtocol};

pub fn run() -> Result<u8, Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    run_with_io(stdin.lock(), &mut stdout)?;
    Ok(0)
}

fn run_with_io<R: Read, W: Write>(mut reader: R, writer: &mut W) -> io::Result<()> {
    let mut input = String::new();
    reader.read_to_string(&mut input)?;
    let hook_input = parse_hook_input(&input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;

    let response = render_stub_response(hook_input.protocol, &stub_decision());
    writer.write_all(response.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn stub_decision() -> Decision {
    Decision {
        action: DecisionAction::Allow,
        reason: Some("veil scaffold stub allows all requests".to_owned()),
        severity: None,
        confidence: Some(1.0),
        remediation: None,
    }
}

fn render_stub_response(protocol: HookProtocol, decision: &Decision) -> String {
    render_decision(protocol, decision).stdout
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_io_emits_allow_response() {
        let input = br#"{
            "session_id":"abc123",
            "cwd":"/repo",
            "hook_event_name":"PreToolUse",
            "tool_name":"Read",
            "tool_input":{"file_path":"secret.txt"}
        }"#;
        let mut output = Vec::new();

        run_with_io(&input[..], &mut output).expect("stub runner should succeed");

        assert_eq!(
            String::from_utf8(output).expect("output should be UTF-8"),
            "{\"permissionDecision\":\"allow\"}\n"
        );
    }

    #[test]
    fn run_with_io_uses_detected_protocol_for_stub_output() {
        let input = br#"{
            "session_id":"gemini-1",
            "cwd":"/repo",
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"pwd"}
        }"#;
        let mut output = Vec::new();

        run_with_io(&input[..], &mut output).expect("stub runner should succeed");

        assert_eq!(
            String::from_utf8(output).expect("output should be UTF-8"),
            "{\"decision\":\"allow\"}\n"
        );
    }

    #[test]
    fn run_with_io_rejects_invalid_hook_payloads() {
        let mut output = Vec::new();

        let error = run_with_io(br#"{"unexpected":true}"#.as_slice(), &mut output)
            .expect_err("invalid hook payload should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(output.is_empty());
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
        assert_eq!(decision.severity, None);
        assert_eq!(decision.remediation, None);
    }
}
