#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

use serde_json::Value;

use crate::types::{HookInput, HookProtocol, ToolKind};

#[derive(Debug)]
pub struct HookParseError {
    message: String,
}

impl HookParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for HookParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for HookParseError {}

pub fn parse_hook_input(input: &str) -> Result<HookInput, HookParseError> {
    let payload: Value = serde_json::from_str(input)
        .map_err(|error| HookParseError::new(format!("invalid hook JSON: {error}")))?;

    if is_claude_payload(&payload) {
        return parse_snake_case_payload(&payload, HookProtocol::ClaudeCode);
    }

    if is_copilot_payload(&payload) {
        return parse_camel_case_payload(&payload, HookProtocol::GitHubCopilot);
    }

    if is_gemini_payload(&payload) {
        return parse_gemini_payload(&payload);
    }

    Err(HookParseError::new(
        "unsupported hook payload: could not detect Claude Code, Gemini CLI, or GitHub Copilot",
    ))
}

fn is_claude_payload(payload: &Value) -> bool {
    string_field(payload, "hook_event_name").is_some_and(|value| value == "PreToolUse")
        && payload.get("tool_name").is_some()
        && payload.get("tool_input").is_some()
}

fn is_copilot_payload(payload: &Value) -> bool {
    payload.get("toolName").is_some() && payload.get("toolArgs").is_some()
}

fn is_gemini_payload(payload: &Value) -> bool {
    ["protocol", "client", "source"].iter().any(|field| {
        string_field(payload, field)
            .is_some_and(|value| value.to_ascii_lowercase().contains("gemini"))
    })
}

fn parse_gemini_payload(payload: &Value) -> Result<HookInput, HookParseError> {
    if payload.get("tool_name").is_some() && payload.get("tool_input").is_some() {
        parse_snake_case_payload(payload, HookProtocol::GeminiCli)
    } else if payload.get("toolName").is_some() && payload.get("toolArgs").is_some() {
        parse_camel_case_payload(payload, HookProtocol::GeminiCli)
    } else {
        Err(HookParseError::new(
            "Gemini CLI payload is missing tool_name/tool_input or toolName/toolArgs",
        ))
    }
}

fn parse_snake_case_payload(
    payload: &Value,
    protocol: HookProtocol,
) -> Result<HookInput, HookParseError> {
    let tool_name = required_string(payload, "tool_name")?;
    let raw_args = required_json(payload, "tool_input")?;

    Ok(HookInput {
        protocol,
        tool: normalize_tool_kind(tool_name)?,
        raw_args,
    })
}

fn parse_camel_case_payload(
    payload: &Value,
    protocol: HookProtocol,
) -> Result<HookInput, HookParseError> {
    let tool_name = required_string(payload, "toolName")?;
    let raw_args = required_raw_args(payload, "toolArgs")?;

    Ok(HookInput {
        protocol,
        tool: normalize_tool_kind(tool_name)?,
        raw_args,
    })
}

fn required_string<'a>(payload: &'a Value, field: &str) -> Result<&'a str, HookParseError> {
    string_field(payload, field)
        .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))
}

fn required_json(payload: &Value, field: &str) -> Result<String, HookParseError> {
    serde_json::to_string(
        payload
            .get(field)
            .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))?,
    )
    .map_err(|error| HookParseError::new(format!("could not serialize `{field}`: {error}")))
}

fn required_raw_args(payload: &Value, field: &str) -> Result<String, HookParseError> {
    let value = payload
        .get(field)
        .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))?;

    match value {
        Value::String(raw) => Ok(raw.clone()),
        _ => serde_json::to_string(value).map_err(|error| {
            HookParseError::new(format!("could not serialize `{field}`: {error}"))
        }),
    }
}

fn string_field<'a>(payload: &'a Value, field: &str) -> Option<&'a str> {
    payload.get(field)?.as_str()
}

fn normalize_tool_kind(name: &str) -> Result<ToolKind, HookParseError> {
    match name.to_ascii_lowercase().as_str() {
        "read" => Ok(ToolKind::Read),
        "grep" => Ok(ToolKind::Grep),
        "bash" => Ok(ToolKind::Bash),
        other => Err(HookParseError::new(format!(
            "unsupported tool `{other}` in hook payload"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_claude_code_pre_tool_payload() {
        let parsed = parse_hook_input(
            r#"{
              "session_id": "abc123",
              "cwd": "/repo",
              "hook_event_name": "PreToolUse",
              "tool_name": "Read",
              "tool_input": { "file_path": "secret.txt" }
            }"#,
        )
        .expect("Claude hook payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::ClaudeCode);
        assert_eq!(parsed.tool, ToolKind::Read);
        assert_eq!(parsed.raw_args, r#"{"file_path":"secret.txt"}"#);
    }

    #[test]
    fn parses_gemini_cli_payload_with_explicit_protocol_marker() {
        let parsed = parse_hook_input(
            r#"{
              "protocol": "gemini-cli",
              "cwd": "/repo",
              "tool_name": "Grep",
              "tool_input": { "path": "data/report.csv", "output_mode": "content" }
            }"#,
        )
        .expect("Gemini CLI payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::GeminiCli);
        assert_eq!(parsed.tool, ToolKind::Grep);
        assert_eq!(
            serde_json::from_str::<Value>(&parsed.raw_args).expect("raw args should stay JSON"),
            serde_json::json!({
                "path": "data/report.csv",
                "output_mode": "content",
            })
        );
    }

    #[test]
    fn parses_github_copilot_payload_with_tool_args_string() {
        let parsed = parse_hook_input(
            r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "bash",
              "toolArgs": "{\"command\":\"ls\"}"
            }"#,
        )
        .expect("Copilot payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::GitHubCopilot);
        assert_eq!(parsed.tool, ToolKind::Bash);
        assert_eq!(parsed.raw_args, r#"{"command":"ls"}"#);
    }

    #[test]
    fn malformed_or_unsupported_payloads_fail_gracefully() {
        assert!(parse_hook_input(r#"{"unexpected":true}"#).is_err());
        assert!(parse_hook_input("not json").is_err());
    }
}
