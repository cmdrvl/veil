#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use serde_json::Value;

use crate::types::{HookInput, HookProtocol, ToolKind};

const CLAUDE_PRE_TOOL_EVENT: &str = "PreToolUse";
const GEMINI_BEFORE_TOOL_EVENT: &str = "BeforeTool";
const GROK_PRE_TOOL_EVENT: &str = "pre_tool_use";
const GROK_BASH_TOOL_NAMES: &[&str] = &["run_terminal_command", "run_terminal_cmd"];

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

    if is_grok_payload(&payload) {
        return parse_grok_payload(&payload);
    }

    if is_copilot_payload(&payload) {
        return parse_camel_case_payload(&payload, HookProtocol::GitHubCopilot);
    }

    Err(HookParseError::new(
        "unsupported hook payload: could not detect Claude Code, Gemini CLI, Grok, or GitHub Copilot",
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

/// xAI Grok CLI / Grok Build TUI `PreToolUse` payload. Wire shape: camelCase
/// `hookEventName: "pre_tool_use"`, `toolName`, `toolInput` (a JSON object,
/// not a string like GitHub Copilot's `toolArgs`), `cwd`, `sessionId`. Grok
/// also reads `~/.claude/settings.json` directly for hook compatibility, so
/// a payload reaching this binary via that route is genuinely Grok's own
/// wire format, not a translated Claude Code payload. See
/// `~/.grok/docs/user-guide/10-hooks.md`.
fn is_grok_payload(payload: &Value) -> bool {
    let event_matches =
        string_field(payload, "hookEventName").is_some_and(|value| value == GROK_PRE_TOOL_EVENT);
    let bash_tool_matches = string_field(payload, "toolName")
        .is_some_and(|value| GROK_BASH_TOOL_NAMES.contains(&value));
    let camel_case_tool_fields =
        payload.get("toolName").is_some() && payload.get("toolInput").is_some();

    camel_case_tool_fields && (event_matches || bash_tool_matches)
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
        session_id: string_field(payload, "session_id").map(str::to_owned),
        raw_args,
    })
}

fn parse_grok_payload(payload: &Value) -> Result<HookInput, HookParseError> {
    let tool_name = required_string(payload, "toolName")?;
    let cwd = required_path(payload, "cwd")?;
    let raw_args = required_json(payload, "toolInput")?;

    Ok(HookInput {
        protocol: HookProtocol::Grok,
        tool: normalize_tool_kind(HookProtocol::Grok, tool_name)?,
        cwd,
        session_id: string_field(payload, "sessionId").map(str::to_owned),
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
        session_id: None,
        raw_args,
    })
}

fn required_string<'a>(payload: &'a Value, field: &str) -> Result<&'a str, HookParseError> {
    string_field(payload, field)
        .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))
}

fn required_json(payload: &Value, field: &str) -> Result<String, HookParseError> {
    serialize_object(
        payload
            .get(field)
            .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))?,
        field,
    )
}

fn required_path(payload: &Value, field: &str) -> Result<PathBuf, HookParseError> {
    Ok(PathBuf::from(required_string(payload, field)?))
}

fn required_raw_args(payload: &Value, field: &str) -> Result<String, HookParseError> {
    let value = payload
        .get(field)
        .ok_or_else(|| HookParseError::new(format!("hook payload is missing `{field}`")))?;

    match value {
        Value::String(raw) => {
            let parsed: Value = serde_json::from_str(raw).map_err(|error| {
                HookParseError::new(format!(
                    "hook payload `{field}` must be valid JSON object text: {error}"
                ))
            })?;

            ensure_object(&parsed, field, "must decode to a JSON object")?;

            Ok(raw.clone())
        }
        Value::Object(_) => serialize_object(value, field),
        _ => Err(HookParseError::new(format!(
            "hook payload `{field}` must be a JSON object or object-encoded string"
        ))),
    }
}

fn serialize_object(value: &Value, field: &str) -> Result<String, HookParseError> {
    ensure_object(value, field, "must be a JSON object")?;
    serde_json::to_string(value)
        .map_err(|error| HookParseError::new(format!("could not serialize `{field}`: {error}")))
}

fn ensure_object(value: &Value, field: &str, requirement: &str) -> Result<(), HookParseError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(HookParseError::new(format!(
            "hook payload `{field}` {requirement}"
        )))
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
        HookProtocol::Grok => match lower.as_str() {
            "read_file" => ToolKind::Read,
            "grep" => ToolKind::Grep,
            "run_terminal_command" | "run_terminal_cmd" => ToolKind::Bash,
            _ => {
                return Err(HookParseError::new(format!(
                    "unsupported Grok tool `{name}` in hook payload"
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
        assert_eq!(parsed.session_id.as_deref(), Some("abc123"));
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
        assert_eq!(parsed.session_id.as_deref(), Some("gemini-session"));
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
        assert_eq!(parsed.session_id, None);
        assert_eq!(parsed.raw_args, r#"{"path":"docs/plan.md"}"#);
    }

    #[test]
    fn parses_grok_pre_tool_use_read_payload() {
        let parsed = parse_hook_input(
            r#"{
              "hookEventName": "pre_tool_use",
              "sessionId": "abc-123",
              "cwd": "/repo",
              "workspaceRoot": "/repo",
              "permissionMode": "default",
              "toolName": "read_file",
              "toolInput": { "path": "secret.txt" },
              "timestamp": "2026-04-14T12:00:00Z"
            }"#,
        )
        .expect("Grok read_file payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::Grok);
        assert_eq!(parsed.tool, ToolKind::Read);
        assert_eq!(parsed.cwd, Path::new("/repo"));
        assert_eq!(parsed.session_id.as_deref(), Some("abc-123"));
        assert_eq!(parsed.raw_args, r#"{"path":"secret.txt"}"#);
    }

    #[test]
    fn parses_grok_pre_tool_use_grep_payload() {
        let parsed = parse_hook_input(
            r#"{
              "hookEventName": "pre_tool_use",
              "sessionId": "abc-123",
              "cwd": "/repo",
              "toolName": "grep",
              "toolInput": { "pattern": "TODO", "path": "." }
            }"#,
        )
        .expect("Grok grep payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::Grok);
        assert_eq!(parsed.tool, ToolKind::Grep);
    }

    #[test]
    fn parses_grok_pre_tool_use_bash_payload_via_tool_name_alias() {
        // dcg's own Grok integration documents both the abbreviated and full
        // spellings of Grok's shell tool name (issue #319 history); veil
        // must recognize both.
        for tool_name in ["run_terminal_command", "run_terminal_cmd"] {
            let payload = format!(
                r#"{{
                  "hookEventName": "pre_tool_use",
                  "sessionId": "abc-123",
                  "cwd": "/repo",
                  "toolName": "{tool_name}",
                  "toolInput": {{ "command": "npm test" }}
                }}"#
            );
            let parsed =
                parse_hook_input(&payload).expect("Grok terminal-command payload should parse");

            assert_eq!(parsed.protocol, HookProtocol::Grok);
            assert_eq!(parsed.tool, ToolKind::Bash);
        }
    }

    #[test]
    fn grok_payload_is_not_misclassified_as_copilot_or_claude() {
        // Grok's camelCase toolName + object-valued toolInput must not be
        // swallowed by Copilot's toolName+toolArgs check, and its camelCase
        // field names must not accidentally satisfy Claude's snake_case
        // hook_event_name/tool_name/tool_input check.
        let parsed = parse_hook_input(
            r#"{
              "hookEventName": "pre_tool_use",
              "sessionId": "abc-123",
              "cwd": "/repo",
              "toolName": "read_file",
              "toolInput": { "path": "secret.txt" }
            }"#,
        )
        .expect("Grok payload should parse");

        assert_eq!(parsed.protocol, HookProtocol::Grok);
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
              "cwd": "/tmp",
              "hook_event_name": "PreToolUse",
              "tool_name": "Read",
              "tool_input": "not-json"
            }"#
            )
            .is_err()
        );
        assert!(
            parse_hook_input(
                r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "view",
              "toolArgs": "not-json"
            }"#
            )
            .is_err()
        );
        assert!(
            parse_hook_input(
                r#"{
              "timestamp": 1704614400000,
              "cwd": "/tmp",
              "toolName": "view",
              "toolArgs": "\"docs/plan.md\""
            }"#
            )
            .is_err()
        );
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
