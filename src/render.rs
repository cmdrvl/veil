#![forbid(unsafe_code)]

use serde_json::json;

use crate::types::{Decision, DecisionAction, HookProtocol, SensitivitySeverity};

const CLAUDE_PRE_TOOL_EVENT: &str = "PreToolUse";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedDecision {
    pub stdout: String,
    pub stderr: Option<String>,
}

pub fn render_decision(protocol: HookProtocol, decision: &Decision) -> RenderedDecision {
    let stdout = match protocol {
        HookProtocol::ClaudeCode => render_claude_stdout(decision),
        HookProtocol::GitHubCopilot | HookProtocol::Unknown => render_permission_stdout(decision),
        HookProtocol::GeminiCli => render_gemini_stdout(decision),
    };

    let stderr = match decision.action {
        DecisionAction::Allow => None,
        DecisionAction::Deny => Some(render_deny_stderr(decision)),
    };

    RenderedDecision { stdout, stderr }
}

fn render_claude_stdout(decision: &Decision) -> String {
    let mut payload = json!({
        "hookSpecificOutput": {
            "hookEventName": CLAUDE_PRE_TOOL_EVENT,
            "permissionDecision": permission_decision(decision),
        }
    });

    if decision.action == DecisionAction::Deny
        && let Some(reason) = &decision.reason
    {
        payload["hookSpecificOutput"]["permissionDecisionReason"] = json!(reason);
    }

    payload.to_string()
}

fn render_permission_stdout(decision: &Decision) -> String {
    let mut payload = json!({
        "permissionDecision": permission_decision(decision),
    });

    if decision.action == DecisionAction::Deny
        && let Some(reason) = &decision.reason
    {
        payload["permissionDecisionReason"] = json!(reason);
    }

    payload.to_string()
}

fn render_gemini_stdout(decision: &Decision) -> String {
    let mut payload = json!({
        "decision": permission_decision(decision),
    });

    if decision.action == DecisionAction::Deny
        && let Some(reason) = &decision.reason
    {
        payload["reason"] = json!(reason);
    }

    payload.to_string()
}

fn permission_decision(decision: &Decision) -> &'static str {
    match decision.action {
        DecisionAction::Allow => "allow",
        DecisionAction::Deny => "deny",
    }
}

fn render_deny_stderr(decision: &Decision) -> String {
    let mut lines = vec![
        "Sensitive file access blocked".to_owned(),
        format!(
            "Reason: {}",
            decision.reason.as_deref().unwrap_or("no reason provided")
        ),
        format!(
            "Severity: {}",
            decision
                .severity
                .as_ref()
                .map(severity_label)
                .unwrap_or("unknown")
        ),
    ];

    if let Some(confidence) = decision.confidence {
        lines.push(format!("Confidence: {confidence:.2}"));
    }

    if let Some(remediation) = &decision.remediation {
        lines.push(format!("Remediation: {remediation}"));
    }

    lines.join("\n")
}

fn severity_label(severity: &SensitivitySeverity) -> &'static str {
    match severity {
        SensitivitySeverity::Low => "low",
        SensitivitySeverity::Medium => "medium",
        SensitivitySeverity::High => "high",
        SensitivitySeverity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_decision() -> Decision {
        Decision {
            action: DecisionAction::Allow,
            reason: None,
            severity: None,
            confidence: None,
            remediation: None,
        }
    }

    fn deny_decision() -> Decision {
        Decision {
            action: DecisionAction::Deny,
            reason: Some("matched by core.filesystem".to_owned()),
            severity: Some(SensitivitySeverity::Critical),
            confidence: Some(0.99),
            remediation: Some("Use `shape` instead of reading raw contents.".to_owned()),
        }
    }

    #[test]
    fn claude_allow_output_is_silent_on_stderr() {
        let rendered = render_decision(HookProtocol::ClaudeCode, &allow_decision());

        assert_eq!(
            rendered.stdout,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#
        );
        assert_eq!(rendered.stderr, None);
    }

    #[test]
    fn claude_deny_output_includes_reason_and_guidance() {
        let rendered = render_decision(HookProtocol::ClaudeCode, &deny_decision());

        assert_eq!(
            rendered.stdout,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"matched by core.filesystem"}}"#
        );
        assert!(
            rendered
                .stderr
                .as_deref()
                .is_some_and(|stderr| stderr.contains("Severity: critical"))
        );
        assert!(
            rendered
                .stderr
                .as_deref()
                .is_some_and(|stderr| stderr.contains("Confidence: 0.99"))
        );
        assert!(
            rendered
                .stderr
                .as_deref()
                .is_some_and(|stderr| stderr.contains("Remediation: Use `shape`"))
        );
    }

    #[test]
    fn gemini_allow_output_is_silent_on_stderr() {
        let rendered = render_decision(HookProtocol::GeminiCli, &allow_decision());

        assert_eq!(rendered.stdout, r#"{"decision":"allow"}"#);
        assert_eq!(rendered.stderr, None);
    }

    #[test]
    fn gemini_deny_output_includes_reason_and_guidance() {
        let rendered = render_decision(HookProtocol::GeminiCli, &deny_decision());

        assert_eq!(
            rendered.stdout,
            r#"{"decision":"deny","reason":"matched by core.filesystem"}"#
        );
        assert!(
            rendered
                .stderr
                .as_deref()
                .is_some_and(|stderr| stderr.contains("Reason: matched by core.filesystem"))
        );
    }

    #[test]
    fn copilot_allow_output_is_silent_on_stderr() {
        let rendered = render_decision(HookProtocol::GitHubCopilot, &allow_decision());

        assert_eq!(rendered.stdout, r#"{"permissionDecision":"allow"}"#);
        assert_eq!(rendered.stderr, None);
    }

    #[test]
    fn copilot_deny_output_includes_reason_and_guidance() {
        let rendered = render_decision(HookProtocol::GitHubCopilot, &deny_decision());

        assert_eq!(
            rendered.stdout,
            r#"{"permissionDecision":"deny","permissionDecisionReason":"matched by core.filesystem"}"#
        );
        assert!(
            rendered
                .stderr
                .as_deref()
                .is_some_and(|stderr| stderr.contains("Sensitive file access blocked"))
        );
    }
}
