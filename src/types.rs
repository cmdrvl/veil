#![forbid(unsafe_code)]

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub action: DecisionAction,
    pub reason: Option<String>,
    pub severity: Option<SensitivitySeverity>,
    pub confidence: Option<f32>,
    pub remediation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookProtocol {
    ClaudeCode,
    GeminiCli,
    GitHubCopilot,
    Grok,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolKind {
    Read,
    Grep,
    Bash,
    /// A tool an MCP server provides (`mcp__server__tool`). Its arguments are
    /// JSON veil does not know the meaning of, so every string in them that
    /// names a path is judged (bd-1wa).
    Mcp,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookInput {
    pub protocol: HookProtocol,
    pub tool: ToolKind,
    /// The tool's name as the harness sent it. The audit record and the reason
    /// of an MCP decision carry it, because `ToolKind::Mcp` is every server's
    /// every tool.
    pub tool_name: String,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
    pub raw_args: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensitivitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SensitivityResult {
    pub pack: String,
    pub severity: SensitivitySeverity,
    pub confidence: f32,
    pub directory_sensitive: bool,
}
