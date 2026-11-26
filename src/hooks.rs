#![forbid(unsafe_code)]
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

/// The `PreToolUse` matcher for the tools an MCP server provides (bd-1wa). It
/// is a regular expression, not a tool name: Claude Code matches it against
/// `mcp__<server>__<tool>`.
pub(crate) const MCP_MATCHER: &str = "mcp__.*";

/// The tools veil has always judged. An install without a hook for each is not
/// guarded, and operator commands refuse to run in one.
const REQUIRED_MATCHERS: &[&str] = &["Read", "Grep", "Bash"];

/// The tools that write files. Their hook keeps them from veil's derived
/// registry and its key (bd-3qw); veil judges nothing else about them.
pub(crate) const WRITE_MATCHERS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

/// Every matcher `veil install` writes. Only [`REQUIRED_MATCHERS`] are required:
/// an install made before bd-1wa or bd-3qw is guarded as it always was, and
/// `veil doctor` says what is not screened until `veil install` is run again.
const MANAGED_MATCHERS: &[&str] = &[
    "Read",
    "Grep",
    "Bash",
    MCP_MATCHER,
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
];
const LEGACY_VEIL_COMMAND: &str = "$HOME/.local/bin/veil";
const SETTINGS_OVERRIDE_ENV: &str = "VEIL_CLAUDE_SETTINGS_PATH";
const HARNESS_OVERRIDE_ENV: &str = "VEIL_HARNESS";
const DCG_COMMAND_STEMS: &[&str] = &[
    "dcg",
    "destructive_command_guard",
    "destructive-command-guard",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedHooksInspection {
    pub matchers: Vec<ManagedMatcherInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardPreflightInspection {
    pub veil: ManagedHooksInspection,
    pub dcg: DcgHookInspection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedMatcherInspection {
    pub matcher: &'static str,
    pub status: ManagedHookStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DcgHookInspection {
    pub status: ManagedHookStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedHookStatus {
    Installed {
        command: String,
        executable: PathBuf,
    },
    Missing,
    Invalid {
        command: String,
        reason: String,
    },
}

pub fn install_default() -> io::Result<PathBuf> {
    let settings_path = default_settings_path()?;
    install_into_path(&settings_path)?;
    Ok(settings_path)
}

pub fn uninstall_default() -> io::Result<PathBuf> {
    let settings_path = default_settings_path()?;
    uninstall_from_path(&settings_path)?;
    Ok(settings_path)
}

pub(crate) fn default_settings_path() -> io::Result<PathBuf> {
    default_settings_path_from(
        std::env::var_os(SETTINGS_OVERRIDE_ENV),
        std::env::var_os("HOME"),
    )
}

#[cfg(test)]
pub(crate) fn inspect_managed_hooks(path: &Path) -> io::Result<ManagedHooksInspection> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);
    Ok(inspect_veil_entries(entries))
}

pub(crate) fn inspect_guard_preflight(path: &Path) -> io::Result<GuardPreflightInspection> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);

    Ok(GuardPreflightInspection {
        veil: inspect_veil_entries(entries),
        dcg: inspect_dcg_entries(entries),
    })
}

/// The agent harness veil is running under. Only `ClaudeCode` has hook
/// configuration veil can inspect (`~/.claude/settings.json`); for the others
/// veil reports the guard posture as unverified rather than failing closed on
/// a file format that harness does not use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Harness {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    Plain,
}

impl Harness {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::Codex => "codex",
            Harness::GeminiCli => "gemini-cli",
            Harness::Cursor => "cursor",
            Harness::Plain => "plain",
        }
    }

    fn from_override(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Harness::ClaudeCode),
            "codex" => Some(Harness::Codex),
            "gemini" | "gemini-cli" => Some(Harness::GeminiCli),
            "cursor" => Some(Harness::Cursor),
            "plain" | "none" | "shell" | "ci" => Some(Harness::Plain),
            _ => None,
        }
    }
}

/// Detects the active harness. `VEIL_HARNESS` is authoritative; otherwise the
/// harness's own environment markers are used, falling back to `Plain`.
pub(crate) fn detect_harness(var: impl Fn(&str) -> Option<String>) -> Harness {
    if let Some(harness) =
        var(HARNESS_OVERRIDE_ENV).and_then(|value| Harness::from_override(&value))
    {
        return harness;
    }

    let set = |name: &str| var(name).is_some_and(|value| !value.is_empty());
    if set("CLAUDECODE") || set("CLAUDE_CODE_ENTRYPOINT") {
        Harness::ClaudeCode
    } else if set("CODEX_SANDBOX") || set("CODEX_THREAD_ID") || set("CODEX_CI") {
        Harness::Codex
    } else if set("GEMINI_CLI") {
        Harness::GeminiCli
    } else if set("CURSOR_AGENT") || set("CURSOR_TRACE_ID") {
        Harness::Cursor
    } else {
        Harness::Plain
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardPosture {
    pub harness: Harness,
    pub require_dcg: bool,
    /// `Some` only when the harness is Claude Code and its settings were readable.
    pub veil: Option<ManagedHooksInspection>,
    pub dcg: DcgHookInspection,
    pub settings_path: Option<PathBuf>,
    pub settings_error: Option<String>,
}

/// Inspects what guard enforcement is genuinely active for `harness`.
///
/// * Claude Code: veil Read/Grep/Bash hooks in Claude settings are required.
/// * Other harnesses / plain shell: Claude settings are not consulted.
/// * dcg is required only when `require_dcg` is set. Under Claude Code it is
///   looked up as a Bash PreToolUse hook; elsewhere as an executable on PATH.
pub(crate) fn inspect_guard_posture(
    harness: Harness,
    require_dcg: bool,
    settings_path: Result<PathBuf, String>,
    search_path: Option<&std::ffi::OsStr>,
) -> GuardPosture {
    if harness != Harness::ClaudeCode {
        return GuardPosture {
            harness,
            require_dcg,
            veil: None,
            dcg: DcgHookInspection {
                status: dcg_status_from_path(search_path),
            },
            settings_path: None,
            settings_error: None,
        };
    }

    let missing_dcg = DcgHookInspection {
        status: ManagedHookStatus::Missing,
    };
    match settings_path {
        Err(error) => GuardPosture {
            harness,
            require_dcg,
            veil: None,
            dcg: missing_dcg,
            settings_path: None,
            settings_error: Some(format!(
                "could not resolve active hook settings path: {error}"
            )),
        },
        Ok(path) => match inspect_guard_preflight(&path) {
            Ok(inspection) => GuardPosture {
                harness,
                require_dcg,
                veil: Some(inspection.veil),
                dcg: inspection.dcg,
                settings_path: Some(path),
                settings_error: None,
            },
            Err(error) => GuardPosture {
                harness,
                require_dcg,
                veil: None,
                dcg: missing_dcg,
                settings_error: Some(format!(
                    "could not inspect hook settings at {}: {error}",
                    path.display()
                )),
                settings_path: Some(path),
            },
        },
    }
}

fn dcg_status_from_path(search_path: Option<&std::ffi::OsStr>) -> ManagedHookStatus {
    for stem in DCG_COMMAND_STEMS {
        if let Some(candidate) = find_in_search_path(stem, search_path)
            && let Ok(metadata) = fs::metadata(&candidate)
            && metadata.is_file()
            && is_executable(&metadata)
        {
            return ManagedHookStatus::Installed {
                command: (*stem).to_owned(),
                executable: fs::canonicalize(&candidate).unwrap_or(candidate),
            };
        }
    }
    ManagedHookStatus::Missing
}

impl GuardPosture {
    /// Reasons operator commands must refuse. Empty means preflight passes.
    pub(crate) fn blockers(&self) -> Vec<String> {
        let mut blockers = Vec::new();

        if self.harness == Harness::ClaudeCode {
            match (&self.settings_error, &self.veil) {
                (Some(error), _) => blockers.push(error.clone()),
                (None, Some(veil)) if !veil.is_healthy() => {
                    blockers.push("veil Read/Grep/Bash hooks are missing or invalid".to_owned());
                }
                _ => {}
            }
        }

        if self.require_dcg {
            match &self.dcg.status {
                ManagedHookStatus::Installed { .. } => {}
                ManagedHookStatus::Missing => blockers
                    .push("dcg is required by `[policy] require_dcg` but is missing".to_owned()),
                ManagedHookStatus::Invalid { command, reason } => blockers.push(format!(
                    "dcg is required by `[policy] require_dcg` but `{command}` is invalid: {reason}"
                )),
            }
        }

        blockers
    }

    pub(crate) fn is_healthy(&self) -> bool {
        self.blockers().is_empty()
    }

    pub(crate) fn refusal(&self) -> String {
        let settings = self
            .settings_path
            .as_ref()
            .map(|path| format!(" Settings: {}", path.display()))
            .unwrap_or_default();
        format!(
            "guard preflight failed ({}): {}. Refusing to run domain work. Run `veil doctor` for details; run `veil install` to repair veil hooks, or set `[policy] require_dcg = false` if dcg is not wanted.{settings}",
            self.harness.name(),
            self.blockers().join("; ")
        )
    }

    pub(crate) fn to_json_value(&self) -> Value {
        let (veil_status, veil_detail) = match (self.harness, &self.veil, &self.settings_error) {
            (Harness::ClaudeCode, _, Some(error)) => ("unverified", error.clone()),
            (Harness::ClaudeCode, Some(veil), None) if veil.is_healthy() => (
                "healthy",
                "veil Read/Grep/Bash PreToolUse hooks are installed in Claude settings".to_owned(),
            ),
            (Harness::ClaudeCode, _, None) => (
                "unhealthy",
                "veil Read/Grep/Bash PreToolUse hooks are missing or invalid in Claude settings"
                    .to_owned(),
            ),
            (harness, _, _) => (
                "unverified",
                format!(
                    "veil cannot inspect {} hook configuration; wire `veil` as that harness's pre-tool hook",
                    harness.name()
                ),
            ),
        };
        let (dcg_status, dcg_detail) = match &self.dcg.status {
            ManagedHookStatus::Installed { executable, .. } => (
                "installed",
                format!("dcg resolves to {}", executable.display()),
            ),
            ManagedHookStatus::Missing => ("missing", "dcg not found".to_owned()),
            ManagedHookStatus::Invalid { command, reason } => (
                "invalid",
                format!("dcg `{command}` does not resolve: {reason}"),
            ),
        };

        json!({
            "harness": self.harness.name(),
            "veil_hooks": { "status": veil_status, "detail": veil_detail },
            "dcg": {
                "required": self.require_dcg,
                "status": dcg_status,
                "detail": dcg_detail,
            },
            "preflight_ok": self.is_healthy(),
            "blockers": self.blockers(),
        })
    }
}

fn inspect_veil_entries(entries: &[Value]) -> ManagedHooksInspection {
    let matchers = MANAGED_MATCHERS
        .iter()
        .map(|matcher| ManagedMatcherInspection {
            matcher,
            status: entries
                .iter()
                .filter(|entry| matcher_matches(entry, matcher))
                .find_map(managed_hook_command)
                .map_or(
                    ManagedHookStatus::Missing,
                    |command| match resolve_hook_command_executable(&command) {
                        Ok(executable) => ManagedHookStatus::Installed {
                            command,
                            executable,
                        },
                        Err(reason) => ManagedHookStatus::Invalid { command, reason },
                    },
                ),
        })
        .collect();

    ManagedHooksInspection { matchers }
}

fn inspect_dcg_entries(entries: &[Value]) -> DcgHookInspection {
    let status = entries
        .iter()
        .filter(|entry| matcher_matches(entry, "Bash"))
        .find_map(dcg_hook_command)
        .map_or(
            ManagedHookStatus::Missing,
            |command| match resolve_hook_command_executable(&command) {
                Ok(executable) => ManagedHookStatus::Installed {
                    command,
                    executable,
                },
                Err(reason) => ManagedHookStatus::Invalid { command, reason },
            },
        );

    DcgHookInspection { status }
}

impl ManagedHooksInspection {
    /// Every hook veil requires is installed and resolves. The MCP hook is not
    /// required (see [`MANAGED_MATCHERS`]): it has its own check.
    pub(crate) fn is_healthy(&self) -> bool {
        self.matchers
            .iter()
            .filter(|matcher| REQUIRED_MATCHERS.contains(&matcher.matcher))
            .all(|matcher| matches!(matcher.status, ManagedHookStatus::Installed { .. }))
    }

    /// The hook for MCP tool calls.
    pub(crate) fn mcp(&self) -> Option<&ManagedMatcherInspection> {
        self.matchers
            .iter()
            .find(|matcher| matcher.matcher == MCP_MATCHER)
    }

    /// The tools that write files and have no hook that resolves to a program.
    pub(crate) fn unguarded_write_tools(&self) -> Vec<&'static str> {
        WRITE_MATCHERS
            .iter()
            .copied()
            .filter(|tool| {
                !self.matchers.iter().any(|matcher| {
                    matcher.matcher == *tool
                        && matches!(matcher.status, ManagedHookStatus::Installed { .. })
                })
            })
            .collect()
    }
}

impl DcgHookInspection {
    pub(crate) fn is_healthy(&self) -> bool {
        matches!(self.status, ManagedHookStatus::Installed { .. })
    }
}

#[cfg(test)]
impl GuardPreflightInspection {
    pub(crate) fn is_healthy(&self) -> bool {
        self.veil.is_healthy() && self.dcg.is_healthy()
    }
}

fn default_settings_path_from(
    override_path: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> io::Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(PathBuf::from(path));
    }

    let home = home.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "could not resolve Claude settings path: `{SETTINGS_OVERRIDE_ENV}` and `HOME` are unset"
            ),
        )
    })?;

    Ok(PathBuf::from(home).join(".claude/settings.json"))
}

fn install_into_path(path: &Path) -> io::Result<()> {
    let command = resolved_veil_command()?;
    install_into_path_with_command(path, &command)
}

fn install_into_path_with_command(path: &Path, command: &str) -> io::Result<()> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);

    for matcher in MANAGED_MATCHERS {
        install_matcher_hook(entries, matcher, command);
    }

    write_settings(path, &settings)
}

fn uninstall_from_path(path: &Path) -> io::Result<()> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);

    entries.retain_mut(|entry| {
        let Some(entry_object) = entry.as_object_mut() else {
            return true;
        };
        let Some(hooks) = entry_object.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };

        hooks.retain(|hook| !is_managed_veil_hook(hook));
        !hooks.is_empty()
    });

    write_settings(path, &settings)
}

fn install_matcher_hook(entries: &mut Vec<Value>, matcher: &str, command: &str) {
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| matcher_matches(entry, matcher))
    {
        let hooks = entry_hooks(entry);
        let mut updated_managed_hook = false;
        hooks.retain_mut(|hook| {
            if !is_managed_veil_hook(hook) {
                return true;
            }

            if updated_managed_hook {
                return false;
            }

            set_hook_command(hook, command);
            updated_managed_hook = true;
            true
        });
        if !updated_managed_hook {
            hooks.push(veil_hook(command));
        }
        return;
    }

    entries.push(json!({
        "matcher": matcher,
        "hooks": [veil_hook(command)],
    }));
}

fn matcher_matches(entry: &Value, matcher: &str) -> bool {
    entry
        .get("matcher")
        .and_then(Value::as_str)
        .is_some_and(|value| matcher_covers_tool(value, matcher))
}

/// Claude Code (and compatible agents) parse a `PreToolUse` matcher as a
/// `|`-delimited alternation of tool names, not a literal string -- a hook
/// registered under `"Bash|PowerShell"` covers both `Bash` and `PowerShell`
/// calls. Managed-hook detection must match that semantics, or a
/// well-behaved combined-matcher hook (e.g. dcg's `Bash|PowerShell` entry)
/// is invisible to exact-equality checks even though it is fully installed
/// and working.
fn matcher_covers_tool(entry_matcher: &str, tool: &str) -> bool {
    entry_matcher
        .split('|')
        .any(|alternative| alternative.trim() == tool)
}

fn entry_hooks(entry: &mut Value) -> &mut Vec<Value> {
    let object = ensure_object(entry);
    let hooks = object
        .entry("hooks".to_owned())
        .or_insert_with(|| json!([]));
    if !hooks.is_array() {
        *hooks = json!([]);
    }

    hooks
        .as_array_mut()
        .expect("hooks entry should always be an array after normalization")
}

fn pre_tool_use_entries(settings: &mut Value) -> &mut Vec<Value> {
    let root = ensure_object(settings);
    let hooks = root.entry("hooks".to_owned()).or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }

    let hooks_object = hooks
        .as_object_mut()
        .expect("hooks object should always be normalized to a map");
    let pre_tool_use = hooks_object
        .entry("PreToolUse".to_owned())
        .or_insert_with(|| json!([]));
    if !pre_tool_use.is_array() {
        *pre_tool_use = json!([]);
    }

    pre_tool_use
        .as_array_mut()
        .expect("PreToolUse should always be an array after normalization")
}

fn ensure_object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = json!({});
    }

    value
        .as_object_mut()
        .expect("value should always be an object after normalization")
}

fn veil_hook(command: &str) -> Value {
    json!({
        "type": "command",
        "command": command,
    })
}

fn managed_hook_command(entry: &Value) -> Option<String> {
    entry
        .get("hooks")
        .and_then(Value::as_array)?
        .iter()
        .find_map(managed_hook_command_from_hook)
}

fn dcg_hook_command(entry: &Value) -> Option<String> {
    entry
        .get("hooks")
        .and_then(Value::as_array)?
        .iter()
        .find_map(dcg_hook_command_from_hook)
}

fn managed_hook_command_from_hook(hook: &Value) -> Option<String> {
    let command = command_hook_command(hook)?;
    is_managed_veil_command(&command).then_some(command)
}

fn dcg_hook_command_from_hook(hook: &Value) -> Option<String> {
    let command = command_hook_command(hook)?;
    is_dcg_command(&command).then_some(command)
}

fn command_hook_command(hook: &Value) -> Option<String> {
    let object = hook.as_object()?;

    let is_command_hook = object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "command");
    if !is_command_hook {
        return None;
    }

    object
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn is_managed_veil_hook(hook: &Value) -> bool {
    managed_hook_command_from_hook(hook).is_some()
}

fn is_managed_veil_command(command: &str) -> bool {
    if command == LEGACY_VEIL_COMMAND {
        return true;
    }

    command_program(command)
        .and_then(|program| {
            Path::new(&program)
                .file_stem()
                .and_then(OsStr::to_str)
                .map(str::to_owned)
        })
        .is_some_and(|stem| stem == "veil")
}

fn is_dcg_command(command: &str) -> bool {
    command_program(command)
        .and_then(|program| {
            Path::new(&program)
                .file_stem()
                .and_then(OsStr::to_str)
                .map(str::to_owned)
        })
        .map(|stem| stem.to_ascii_lowercase())
        .is_some_and(|stem| DCG_COMMAND_STEMS.iter().any(|candidate| candidate == &stem))
}

fn set_hook_command(hook: &mut Value, command: &str) {
    let object = ensure_object(hook);
    object.insert("type".to_owned(), Value::String("command".to_owned()));
    object.insert("command".to_owned(), Value::String(command.to_owned()));
}

fn resolved_veil_command() -> io::Result<String> {
    let executable = std::env::current_exe()?;
    let executable = executable.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "current executable path contains non-UTF-8 data: {}",
                executable.display()
            ),
        )
    })?;

    shlex::try_quote(executable)
        .map(|quoted| quoted.into_owned())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn resolve_hook_command_executable(command: &str) -> Result<PathBuf, String> {
    let program = command_program(command)
        .ok_or_else(|| format!("could not parse managed hook command `{command}`"))?;
    let program = expand_program_path(&program)?;
    let executable = if references_path(&program) {
        PathBuf::from(&program)
    } else {
        find_in_path(&program).ok_or_else(|| format!("`{program}` was not found in PATH"))?
    };
    let metadata =
        fs::metadata(&executable).map_err(|error| format!("{}: {error}", executable.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a file", executable.display()));
    }
    if !is_executable(&metadata) {
        return Err(format!("{} is not executable", executable.display()));
    }

    fs::canonicalize(&executable).or(Ok(executable))
}

fn command_program(command: &str) -> Option<String> {
    shlex::split(command).and_then(|parts| parts.into_iter().next())
}

fn expand_program_path(program: &str) -> Result<String, String> {
    if let Some(suffix) = program.strip_prefix("$HOME/") {
        let home = std::env::var("HOME")
            .map_err(|_| format!("`HOME` is unset, so `{program}` cannot be resolved"))?;
        return Ok(PathBuf::from(home).join(suffix).display().to_string());
    }

    if let Some(suffix) = program.strip_prefix("${HOME}/") {
        let home = std::env::var("HOME")
            .map_err(|_| format!("`HOME` is unset, so `{program}` cannot be resolved"))?;
        return Ok(PathBuf::from(home).join(suffix).display().to_string());
    }

    if let Some(suffix) = program.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .map_err(|_| format!("`HOME` is unset, so `{program}` cannot be resolved"))?;
        return Ok(PathBuf::from(home).join(suffix).display().to_string());
    }

    Ok(program.to_owned())
}

fn references_path(program: &str) -> bool {
    let path = Path::new(program);
    path.is_absolute() || path.components().count() > 1
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    find_in_search_path(program, std::env::var_os("PATH").as_deref())
}

fn find_in_search_path(program: &str, search_path: Option<&OsStr>) -> Option<PathBuf> {
    search_path.and_then(|path| {
        std::env::split_paths(path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.exists())
    })
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

fn load_settings(path: &Path) -> io::Result<Value> {
    if !path.exists() {
        return Ok(json!({}));
    }

    let contents = fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Ok(json!({}));
    }

    serde_json::from_str(&contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid Claude settings JSON at {}: {error}",
                path.display()
            ),
        )
    })
}

fn write_settings(path: &Path, settings: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let serialized = serde_json::to_string_pretty(settings).map_err(io::Error::other)?;
    fs::write(path, format!("{serialized}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_VEIL_COMMAND: &str = "/opt/homebrew/bin/veil";

    fn temp_settings_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after the unix epoch")
            .as_nanos();

        std::env::temp_dir()
            .join(format!("veil-hooks-{name}-{unique}-{}", std::process::id()))
            .join("settings.json")
    }

    fn read_settings(path: &Path) -> Value {
        serde_json::from_str(
            &fs::read_to_string(path).expect("settings file should be readable after mutation"),
        )
        .expect("settings file should be valid JSON")
    }

    fn temp_executable_path(name: &str) -> PathBuf {
        temp_settings_path(name)
            .parent()
            .expect("settings path should always have a parent directory")
            .join("veil")
    }

    fn create_executable(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory should be creatable");
        }
        fs::write(path, "#!/bin/sh\nexit 0\n").expect("test executable should be writable");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path)
                .expect("test executable should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)
                .expect("test executable permissions should be writable");
        }
    }

    fn quote_test_command(path: &Path) -> String {
        shlex::try_quote(
            path.to_str()
                .expect("test executable path should be valid UTF-8"),
        )
        .expect("test executable path should be shell-quotable")
        .into_owned()
    }

    #[test]
    fn install_adds_expected_pretooluse_entries() {
        let path = temp_settings_path("install");

        install_into_path_with_command(&path, TEST_VEIL_COMMAND)
            .expect("install should create a settings file");
        let settings = read_settings(&path);

        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should be an array");
        assert_eq!(
            entries.len(),
            8,
            "Read, Grep, Bash, the MCP tools and the four tools that write files"
        );
        for tool in WRITE_MATCHERS {
            assert!(MANAGED_MATCHERS.contains(tool), "{tool}");
            assert!(
                !REQUIRED_MATCHERS.contains(tool),
                "{tool} must stay optional"
            );
        }

        for matcher in MANAGED_MATCHERS {
            let entry = entries
                .iter()
                .find(|entry| matcher_matches(entry, matcher))
                .expect("expected a managed matcher entry");
            let hooks = entry["hooks"].as_array().expect("hooks should be an array");
            assert_eq!(hooks, &[veil_hook(TEST_VEIL_COMMAND)]);
        }
        assert!(
            entries.iter().any(|entry| entry["matcher"] == "mcp__.*"),
            "the MCP matcher is the regular expression `mcp__.*`"
        );
    }

    #[test]
    fn install_adds_the_mcp_hook_to_an_install_that_predates_it() {
        let path = temp_settings_path("install-adds-mcp");
        let executable_path = temp_executable_path("install-adds-mcp");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] },
                        {
                            "matcher": "Custom",
                            "hooks": [{ "type": "command", "command": "/usr/local/bin/custom" }]
                        }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        // before: guarded as it always was, and the MCP hook is reported missing
        let before = inspect_managed_hooks(&path).expect("managed hook probe should succeed");
        assert!(before.is_healthy(), "the three required hooks are enough");
        assert_eq!(
            before.mcp().map(|matcher| &matcher.status),
            Some(&ManagedHookStatus::Missing)
        );
        assert!(
            inspect_guard_preflight(&path)
                .expect("preflight probe should succeed")
                .veil
                .is_healthy(),
            "operator commands must not start refusing for the missing MCP hook"
        );

        install_into_path_with_command(&path, &command).expect("install should succeed");

        let after = inspect_managed_hooks(&path).expect("managed hook probe should succeed");
        assert!(matches!(
            after.mcp().map(|matcher| &matcher.status),
            Some(ManagedHookStatus::Installed { .. })
        ));
        let settings = read_settings(&path);
        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should remain an array");
        assert_eq!(entries.len(), 9, "the unrelated Custom entry is kept");
        assert!(entries.iter().any(|entry| matcher_matches(entry, "Custom")));
    }

    #[test]
    fn an_mcp_hook_inside_a_combined_matcher_counts_as_installed() {
        let path = temp_settings_path("mcp-combined");
        let executable_path = temp_executable_path("mcp-combined");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] },
                        { "matcher": "WebFetch|mcp__.*", "hooks": [veil_hook(&command)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let inspection = inspect_managed_hooks(&path).expect("managed hook probe should succeed");
        assert!(matches!(
            inspection.mcp().map(|matcher| &matcher.status),
            Some(ManagedHookStatus::Installed { .. })
        ));

        install_into_path_with_command(&path, &command).expect("install should succeed");
        let settings = read_settings(&path);
        assert_eq!(
            settings["hooks"]["PreToolUse"].as_array().map(Vec::len),
            Some(8),
            "install reuses the combined entry instead of adding a second"
        );
    }

    #[test]
    fn uninstall_removes_the_mcp_hook_too() {
        let path = temp_settings_path("uninstall-mcp");
        install_into_path_with_command(&path, TEST_VEIL_COMMAND).expect("install should succeed");

        uninstall_from_path(&path).expect("uninstall should succeed");

        let settings = read_settings(&path);
        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should remain an array");
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn install_is_idempotent_on_second_run() {
        let path = temp_settings_path("idempotent");

        install_into_path_with_command(&path, TEST_VEIL_COMMAND)
            .expect("first install should succeed");
        install_into_path_with_command(&path, TEST_VEIL_COMMAND)
            .expect("second install should also succeed");

        let settings = read_settings(&path);
        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should remain an array");

        assert_eq!(entries.len(), 8);
        for matcher in MANAGED_MATCHERS {
            let entry = entries
                .iter()
                .find(|entry| matcher_matches(entry, matcher))
                .expect("expected a managed matcher entry");
            assert_eq!(
                entry["hooks"].as_array().expect("hooks should be an array"),
                &[veil_hook(TEST_VEIL_COMMAND)]
            );
        }
    }

    #[test]
    fn install_rewrites_legacy_managed_hook_commands() {
        let path = temp_settings_path("rewrite-legacy");
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(LEGACY_VEIL_COMMAND)] },
                        { "matcher": "Grep", "hooks": [veil_hook(LEGACY_VEIL_COMMAND)] },
                        { "matcher": "Bash", "hooks": [veil_hook(LEGACY_VEIL_COMMAND)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        install_into_path_with_command(&path, TEST_VEIL_COMMAND)
            .expect("install should rewrite legacy commands");
        let settings = read_settings(&path);
        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should remain an array");

        for matcher in MANAGED_MATCHERS {
            let entry = entries
                .iter()
                .find(|entry| matcher_matches(entry, matcher))
                .expect("expected a managed matcher entry");
            assert_eq!(
                entry["hooks"].as_array().expect("hooks should be an array"),
                &[veil_hook(TEST_VEIL_COMMAND)]
            );
        }
    }

    #[test]
    fn uninstall_removes_only_veil_owned_entries() {
        let path = temp_settings_path("uninstall");
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read",
                        "hooks": [
                            veil_hook(TEST_VEIL_COMMAND),
                            { "type": "command", "command": "$HOME/.local/bin/dcg" }
                        ]
                    },
                    {
                        "matcher": "Custom",
                        "hooks": [
                            { "type": "command", "command": "/usr/local/bin/custom" }
                        ]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [veil_hook(TEST_VEIL_COMMAND)]
                    }
                ]
            }
        });
        write_settings(&path, &settings).expect("fixture settings should be writable");

        uninstall_from_path(&path).expect("uninstall should succeed");
        let settings = read_settings(&path);
        let entries = settings["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse should remain an array");

        let read_entry = entries
            .iter()
            .find(|entry| matcher_matches(entry, "Read"))
            .expect("non-veil hooks should preserve the matcher entry");
        assert_eq!(
            read_entry["hooks"]
                .as_array()
                .expect("hooks should be an array"),
            &[json!({ "type": "command", "command": "$HOME/.local/bin/dcg" })]
        );

        assert!(
            entries.iter().all(|entry| !matcher_matches(entry, "Bash")),
            "empty matcher entries should be removed once veil owns the only hook"
        );
        assert!(
            entries.iter().any(|entry| matcher_matches(entry, "Custom")),
            "unrelated hook entries should be preserved"
        );
    }

    #[test]
    fn default_settings_path_honors_override_env() {
        let override_path = PathBuf::from("/tmp/custom-settings.json");

        assert_eq!(
            default_settings_path_from(Some(override_path.clone().into_os_string()), None)
                .expect("override env should be honored"),
            override_path
        );
    }

    #[test]
    fn managed_hook_probe_requires_all_matchers() {
        let path = temp_settings_path("managed-hooks-missing");
        let executable_path = temp_executable_path("managed-hooks-missing");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let inspection = inspect_managed_hooks(&path).expect("managed hook probe should succeed");
        assert!(
            !inspection.is_healthy(),
            "all managed matchers must be present"
        );
        assert!(inspection.matchers.iter().any(|matcher| {
            matcher.matcher == "Grep" && matches!(matcher.status, ManagedHookStatus::Missing)
        }));
    }

    #[test]
    fn managed_hook_probe_accepts_fully_installed_settings() {
        let path = temp_settings_path("managed-hooks-present");
        let executable_path = temp_executable_path("managed-hooks-present");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        assert!(
            inspect_managed_hooks(&path)
                .expect("managed hook probe should succeed")
                .is_healthy(),
            "all managed matchers are installed"
        );
    }

    #[test]
    fn managed_hook_probe_reports_invalid_command_paths() {
        let path = temp_settings_path("managed-hooks-invalid");
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook("/definitely/missing/veil")] },
                        { "matcher": "Grep", "hooks": [veil_hook("/definitely/missing/veil")] },
                        { "matcher": "Bash", "hooks": [veil_hook("/definitely/missing/veil")] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let inspection = inspect_managed_hooks(&path).expect("managed hook probe should succeed");
        assert!(
            !inspection.is_healthy(),
            "missing executables should fail the probe"
        );
        for matcher in inspection
            .matchers
            .iter()
            .filter(|matcher| REQUIRED_MATCHERS.contains(&matcher.matcher))
        {
            assert!(
                matches!(matcher.status, ManagedHookStatus::Invalid { .. }),
                "{}: {:?}",
                matcher.matcher,
                matcher.status
            );
        }
        assert_eq!(
            inspection.mcp().map(|matcher| &matcher.status),
            Some(&ManagedHookStatus::Missing),
            "the fixture has no MCP entry"
        );
    }

    #[test]
    fn guard_preflight_requires_dcg_bash_hook() {
        let path = temp_settings_path("guard-preflight-missing-dcg");
        let executable_path = temp_executable_path("guard-preflight-missing-dcg");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let inspection =
            inspect_guard_preflight(&path).expect("guard preflight probe should succeed");

        assert!(inspection.veil.is_healthy());
        assert!(!inspection.is_healthy());
        assert!(matches!(inspection.dcg.status, ManagedHookStatus::Missing));
        let posture = inspect_guard_posture(Harness::ClaudeCode, true, Ok(path.clone()), None);
        assert!(
            posture
                .refusal()
                .contains("dcg is required by `[policy] require_dcg` but is missing")
        );
    }

    #[test]
    fn guard_preflight_finds_dcg_in_later_bash_entry() {
        let path = temp_settings_path("guard-preflight-split-bash");
        let veil_path = temp_executable_path("guard-preflight-split-bash");
        let dcg_path = veil_path
            .parent()
            .expect("test executable should have a parent")
            .join("dcg");
        create_executable(&veil_path);
        create_executable(&dcg_path);
        let veil_command = quote_test_command(&veil_path);
        let dcg_command = quote_test_command(&dcg_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&veil_command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&veil_command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&veil_command)] },
                        {
                            "matcher": "Bash",
                            "hooks": [
                                { "type": "command", "command": dcg_command }
                            ]
                        }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        assert!(
            inspect_guard_preflight(&path)
                .expect("guard preflight probe should succeed")
                .is_healthy(),
            "preflight should scan all active Bash entries"
        );
    }

    #[test]
    fn guard_preflight_accepts_healthy_veil_and_dcg_hooks() {
        let path = temp_settings_path("guard-preflight-ok");
        let veil_path = temp_executable_path("guard-preflight-ok");
        let dcg_path = veil_path
            .parent()
            .expect("test executable should have a parent")
            .join("dcg");
        create_executable(&veil_path);
        create_executable(&dcg_path);
        let veil_command = quote_test_command(&veil_path);
        let dcg_command = quote_test_command(&dcg_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&veil_command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&veil_command)] },
                        {
                            "matcher": "Bash",
                            "hooks": [
                                veil_hook(&veil_command),
                                { "type": "command", "command": dcg_command }
                            ]
                        }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        assert!(
            inspect_guard_preflight(&path)
                .expect("guard preflight probe should succeed")
                .is_healthy(),
            "veil and dcg hooks should both be healthy"
        );
    }

    #[test]
    fn guard_preflight_finds_dcg_under_combined_bash_powershell_matcher() {
        // dcg's real installer registers a single PreToolUse entry with
        // matcher "Bash|PowerShell" rather than a bare "Bash" entry. That
        // combined matcher must still satisfy the dcg Bash-hook check
        // (bd-nff): Claude Code treats `|` as an alternation, and a
        // literal-equality check on "Bash" alone produced a permanent false
        // "missing dcg Bash hook" even when dcg was fully installed.
        let path = temp_settings_path("guard-preflight-combined-matcher");
        let veil_path = temp_executable_path("guard-preflight-combined-matcher");
        let dcg_path = veil_path
            .parent()
            .expect("test executable should have a parent")
            .join("dcg");
        create_executable(&veil_path);
        create_executable(&dcg_path);
        let veil_command = quote_test_command(&veil_path);
        let dcg_command = quote_test_command(&dcg_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&veil_command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&veil_command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&veil_command)] },
                        {
                            "matcher": "Bash|PowerShell",
                            "hooks": [
                                { "type": "command", "command": dcg_command }
                            ]
                        }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let inspection =
            inspect_guard_preflight(&path).expect("guard preflight probe should succeed");

        assert!(
            matches!(inspection.dcg.status, ManagedHookStatus::Installed { .. }),
            "dcg hook under a combined Bash|PowerShell matcher should be recognized as installed"
        );
        assert!(inspection.is_healthy());
    }

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn detects_each_harness_from_its_environment_markers() {
        assert_eq!(detect_harness(env_of(&[])), Harness::Plain);
        assert_eq!(
            detect_harness(env_of(&[("CLAUDECODE", "1")])),
            Harness::ClaudeCode
        );
        assert_eq!(
            detect_harness(env_of(&[("CODEX_SANDBOX", "seatbelt")])),
            Harness::Codex
        );
        assert_eq!(
            detect_harness(env_of(&[("GEMINI_CLI", "1")])),
            Harness::GeminiCli
        );
        assert_eq!(
            detect_harness(env_of(&[("CURSOR_AGENT", "1")])),
            Harness::Cursor
        );
        // Empty markers do not count, and VEIL_HARNESS wins over markers.
        assert_eq!(
            detect_harness(env_of(&[("CLAUDECODE", "")])),
            Harness::Plain
        );
        assert_eq!(
            detect_harness(env_of(&[("CLAUDECODE", "1"), ("VEIL_HARNESS", "plain")])),
            Harness::Plain
        );
        // An unrecognized override falls back to marker detection.
        assert_eq!(
            detect_harness(env_of(&[("GEMINI_CLI", "1"), ("VEIL_HARNESS", "bogus")])),
            Harness::GeminiCli
        );
    }

    #[test]
    fn non_claude_posture_ignores_claude_settings_and_missing_dcg() {
        // Settings path is deliberately unresolvable: it must not matter.
        let posture = inspect_guard_posture(
            Harness::Codex,
            false,
            Err("HOME unset".to_owned()),
            Some(OsStr::new("")),
        );

        assert!(posture.is_healthy());
        assert!(posture.blockers().is_empty());
        assert_eq!(
            posture.to_json_value()["veil_hooks"]["status"],
            "unverified"
        );
    }

    #[test]
    fn require_dcg_blocks_non_claude_harness_until_dcg_is_on_path() {
        let dir = temp_executable_path("posture-require-dcg")
            .parent()
            .expect("temp dir has a parent")
            .to_path_buf();
        fs::create_dir_all(&dir).expect("temp dir should be creatable");

        let missing = inspect_guard_posture(
            Harness::Cursor,
            true,
            Err(String::new()),
            Some(dir.as_os_str()),
        );
        assert!(!missing.is_healthy());
        assert!(missing.refusal().contains("require_dcg"));

        create_executable(&dir.join("dcg"));
        let present = inspect_guard_posture(
            Harness::Cursor,
            true,
            Err(String::new()),
            Some(dir.as_os_str()),
        );
        assert!(present.is_healthy());
        assert_eq!(present.to_json_value()["dcg"]["status"], "installed");
    }

    #[test]
    fn non_executable_dcg_on_path_does_not_satisfy_require_dcg() {
        let dir = temp_executable_path("posture-dcg-not-executable")
            .parent()
            .expect("temp dir has a parent")
            .to_path_buf();
        fs::create_dir_all(&dir).expect("temp dir should be creatable");
        fs::write(dir.join("dcg"), "not executable").expect("fixture should be writable");

        let posture = inspect_guard_posture(
            Harness::Plain,
            true,
            Err(String::new()),
            Some(dir.as_os_str()),
        );

        #[cfg(unix)]
        assert!(!posture.is_healthy());
        #[cfg(not(unix))]
        let _ = posture;
    }

    #[test]
    fn claude_code_still_requires_healthy_veil_hooks_without_require_dcg() {
        let path = temp_settings_path("posture-claude-no-hooks");
        write_settings(&path, &json!({})).expect("fixture settings should be writable");

        let posture = inspect_guard_posture(Harness::ClaudeCode, false, Ok(path), None);

        assert!(!posture.is_healthy());
        assert_eq!(
            posture.blockers(),
            vec!["veil Read/Grep/Bash hooks are missing or invalid".to_owned()]
        );

        let unresolvable = inspect_guard_posture(
            Harness::ClaudeCode,
            false,
            Err("HOME unset".to_owned()),
            None,
        );
        assert!(!unresolvable.is_healthy());
    }

    #[test]
    fn claude_code_with_healthy_veil_hooks_passes_without_dcg_unless_required() {
        let path = temp_settings_path("posture-claude-veil-only");
        let executable_path = temp_executable_path("posture-claude-veil-only");
        create_executable(&executable_path);
        let command = quote_test_command(&executable_path);
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook(&command)] },
                        { "matcher": "Grep", "hooks": [veil_hook(&command)] },
                        { "matcher": "Bash", "hooks": [veil_hook(&command)] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        let optional = inspect_guard_posture(Harness::ClaudeCode, false, Ok(path.clone()), None);
        assert!(optional.is_healthy());

        let required = inspect_guard_posture(Harness::ClaudeCode, true, Ok(path), None);
        assert!(!required.is_healthy());
        assert_eq!(required.blockers().len(), 1);
    }
}
