#![forbid(unsafe_code)]

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionAction {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InformationLabel {
    Public,
    Derived,
    Protected,
}

impl InformationLabel {
    /// Join labels when an output is derived from more than one input.
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Protected, _) | (_, Self::Protected) => Self::Protected,
            (Self::Derived, _) | (_, Self::Derived) => Self::Derived,
            (Self::Public, Self::Public) => Self::Public,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Derived => "derived",
            Self::Protected => "protected",
        }
    }

    pub fn annotation(self) -> String {
        format!("(label: {})", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Clearance {
    Public,
    Derived,
    Protected,
}

impl Clearance {
    pub const fn admits(self, label: InformationLabel) -> bool {
        matches!(
            (self, label),
            (Self::Protected, _)
                | (
                    Self::Derived,
                    InformationLabel::Public | InformationLabel::Derived
                )
                | (Self::Public, InformationLabel::Public)
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Derived => "derived",
            Self::Protected => "protected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessAssessment {
    pub label: InformationLabel,
    pub clearance: Clearance,
    pub verdict: DecisionAction,
}

impl AccessAssessment {
    pub const fn from_clearance(label: InformationLabel, clearance: Clearance) -> Self {
        let verdict = if clearance.admits(label) {
            DecisionAction::Allow
        } else {
            DecisionAction::Deny
        };
        Self {
            label,
            clearance,
            verdict,
        }
    }

    pub const fn new(
        label: InformationLabel,
        clearance: Clearance,
        verdict: DecisionAction,
    ) -> Self {
        Self {
            label,
            clearance,
            verdict,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub action: DecisionAction,
    pub label: InformationLabel,
    pub clearance: Clearance,
    pub reason: Option<String>,
    pub severity: Option<SensitivitySeverity>,
    pub confidence: Option<f32>,
    pub remediation: Option<String>,
}

impl Decision {
    pub const fn assessment(&self) -> AccessAssessment {
        AccessAssessment::new(self.label, self.clearance, self.action)
    }
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
    /// A tool that writes a file (Write, Edit, MultiEdit, NotebookEdit). veil
    /// screens it for one thing: whether the file is its own derived registry
    /// or key (bd-3qw).
    Write,
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
