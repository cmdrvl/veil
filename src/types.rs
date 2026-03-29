#![forbid(unsafe_code)]

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub action: DecisionAction,
    pub reason: Option<String>,
    pub confidence: Option<f32>,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookProtocol {
    ClaudeCode,
    GeminiCli,
    GitHubCopilot,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolKind {
    Read,
    Grep,
    Bash,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookInput {
    pub protocol: HookProtocol,
    pub tool: ToolKind,
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
