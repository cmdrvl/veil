#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use serde_json::Value;

use crate::types::{HookInput, HookProtocol, ToolKind};

const CLAUDE_PRE_TOOL_EVENT: &str = "PreToolUse";
const GEMINI_BEFORE_TOOL_EVENT: &str = "BeforeTool";

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

    if is_gemini_payload(&payload) {
        return parse_snake_case_payload(&payload, HookProtocol::GeminiCli);
    }

    if is_copilot_payload(&payload) {
        return parse_camel_case_payload(&payload, HookProtocol::GitHubCopilot);
    }

    Err(HookParseError::new(
        "unsupported hook payload: could not detect Claude Code, Gemini CLI, or GitHub Copilot",
    ))
}

fn is_claude_payload(payload: &Value) -> bool {
    string_field(payload, "hook_event_name").is_some_and(|value| value == CLAUDE_PRE_TOOL_EVENT)
        && payload.get("tool_name").is_some()
        && payload.get("tool_input").is_some()
}

fn is_copilot_payload(payload: &Value) -> bool {
    payload.get("toolName").is_some() && payload.get("toolArgs").is_some()
}

fn is_gemini_payload(payload: &Value) -> bool {
    let hook_event_matches = string_field(payload, "hook_event_name")
        .is_some_and(|value| value == GEMINI_BEFORE_TOOL_EVENT);
    let snake_case_tool_fields =
        payload.get("tool_name").is_some() && payload.get("tool_input").is_some();
    let explicit_marker = ["protocol", "client", "source"].iter().any(|field| {
        string_field(payload, field)
            .is_some_and(|value| value.to_ascii_lowercase().contains("gemini"))
    });

    snake_case_tool_fields && (hook_event_matches || explicit_marker)
}

fn parse_snake_case_payload(
    payload: &Value,
    protocol: HookProtocol,
) -> Result<HookInput, HookParseError> {
    let tool_name = required_string(payload, "tool_name")?;
    let cwd = required_path(payload, "cwd")?;
    let raw_args = required_json(payload, "tool_input")?;

    Ok(HookInput {
        protocol,
        tool: normalize_tool_kind(protocol, tool_name)?,
        cwd,
        raw_args,
    })
}

fn parse_camel_case_payload(
    payload: &Value,
    protocol: HookProtocol,
) -> Result<HookInput, HookParseError> {
    let tool_name = required_string(payload, "toolName")?;
    let cwd = required_path(payload, "cwd")?;
    let raw_args = required_raw_args(payload, "toolArgs")?;

    Ok(HookInput {
        protocol,
        tool: normalize_tool_kind(protocol, tool_name)?,
        cwd,
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

fn required_path(payload: &Value, field: &str) -> Result<PathBuf, HookParseError> {
    Ok(PathBuf::from(required_string(payload, field)?))
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

fn normalize_tool_kind(protocol: HookProtocol, name: &str) -> Result<ToolKind, HookParseError> {
    let lower = name.to_ascii_lowercase();

    let tool = match protocol {
        HookProtocol::ClaudeCode => match lower.as_str() {
            "read" => ToolKind::Read,
            "grep" => ToolKind::Grep,
            "bash" => ToolKind::Bash,
            _ => {
                return Err(HookParseError::new(format!(
                    "unsupported Claude Code tool `{name}` in hook payload"
                )));
            }
        },
        HookProtocol::GeminiCli => match lower.as_str() {
            "read_file" | "read_many_files" => ToolKind::Read,
            "grep_search" | "search_file_content" => ToolKind::Grep,
            "run_shell_command" => ToolKind::Bash,
            _ => {
                return Err(HookParseError::new(format!(
                    "unsupported Gemini CLI tool `{name}` in hook payload"
                )));
            }
        },
        HookProtocol::GitHubCopilot => match lower.as_str() {
            "view" | "read" => ToolKind::Read,
            "search" | "grep" => ToolKind::Grep,
            "bash" => ToolKind::Bash,
            _ => {
                return Err(HookParseError::new(format!(
                    "unsupported GitHub Copilot tool `{name}` in hook payload"
                )));
            }
        },
        HookProtocol::Unknown => {
            return Err(HookParseError::new(format!(
                "unsupported tool `{name}` in hook payload"
            )));
        }
    };

    Ok(tool)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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
        assert_eq!(parsed.cwd, Path::new("/repo"));
        assert_eq!(parsed.raw_args, r#"{"file_path":"secret.txt"}"#);
    }

    #[test]
    fn parses_gemini_before_tool_payload() {
        let parsed = parse_hook_input(
            r#"{
              "session_id": "gemini-session",
              "cwd": "/repo",
              "hook_event_name": "BeforeTool",
              "tool_name": "read_file",
              "tool_input": { "file_path": "data/report.csv", "offset": 0, "limit": 20 }
            }"#,
        )
        .expect("Gemini CLI payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::GeminiCli);
        assert_eq!(parsed.tool, ToolKind::Read);
        assert_eq!(parsed.cwd, Path::new("/repo"));
        assert_eq!(
            serde_json::from_str::<Value>(&parsed.raw_args).expect("raw args should stay JSON"),
            serde_json::json!({
                "file_path": "data/report.csv",
                "offset": 0,
                "limit": 20,
            })
        );
    }

    #[test]
    fn parses_github_copilot_payload_with_view_tool() {
        let parsed = parse_hook_input(
            r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "view",
              "toolArgs": "{\"path\":\"docs/plan.md\"}"
            }"#,
        )
        .expect("Copilot payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::GitHubCopilot);
        assert_eq!(parsed.tool, ToolKind::Read);
        assert_eq!(parsed.cwd, Path::new("/tmp"));
        assert_eq!(parsed.raw_args, r#"{"path":"docs/plan.md"}"#);
    }

    #[test]
    fn normalizes_protocol_specific_search_and_shell_tools() {
        let gemini = parse_hook_input(
            r#"{
              "session_id": "gemini-session",
              "cwd": "/repo",
              "hook_event_name": "BeforeTool",
              "tool_name": "grep_search",
              "tool_input": { "pattern": "TODO", "path": "." }
            }"#,
        )
        .expect("Gemini grep_search payload should parse");
        let copilot = parse_hook_input(
            r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "bash",
              "toolArgs": "{\"command\":\"ls\"}"
            }"#,
        )
        .expect("Copilot bash payload should parse");

        assert_eq!(gemini.tool, ToolKind::Grep);
        assert_eq!(copilot.tool, ToolKind::Bash);
    }

    #[test]
    fn malformed_or_unsupported_payloads_fail_gracefully() {
        assert!(parse_hook_input(r#"{"unexpected":true}"#).is_err());
        assert!(parse_hook_input("not json").is_err());
        assert!(
            parse_hook_input(
                r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "edit",
              "toolArgs": "{\"path\":\"src/main.rs\"}"
            }"#
            )
            .is_err()
        );
    }
}
