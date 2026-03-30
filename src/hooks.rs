#![forbid(unsafe_code)]
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

const MANAGED_MATCHERS: &[&str] = &["Read", "Grep", "Bash"];
const LEGACY_VEIL_COMMAND: &str = "$HOME/.local/bin/veil";
const SETTINGS_OVERRIDE_ENV: &str = "VEIL_CLAUDE_SETTINGS_PATH";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedHooksInspection {
    pub matchers: Vec<ManagedMatcherInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedMatcherInspection {
    pub matcher: &'static str,
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

pub(crate) fn inspect_managed_hooks(path: &Path) -> io::Result<ManagedHooksInspection> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);
    let matchers = MANAGED_MATCHERS
        .iter()
        .map(|matcher| ManagedMatcherInspection {
            matcher,
            status: entries
                .iter()
                .find(|entry| matcher_matches(entry, matcher))
                .and_then(managed_hook_command)
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

    Ok(ManagedHooksInspection { matchers })
}

impl ManagedHooksInspection {
    pub(crate) fn is_healthy(&self) -> bool {
        self.matchers
            .iter()
            .all(|matcher| matches!(matcher.status, ManagedHookStatus::Installed { .. }))
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
        .is_some_and(|value| value == matcher)
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

fn managed_hook_command_from_hook(hook: &Value) -> Option<String> {
    let object = hook.as_object()?;

    let is_command_hook = object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "command");
    if !is_command_hook {
        return None;
    }

    let command = object.get("command").and_then(Value::as_str)?;
    is_managed_veil_command(command).then(|| command.to_owned())
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
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
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
        assert_eq!(entries.len(), 3);

        for matcher in MANAGED_MATCHERS {
            let entry = entries
                .iter()
                .find(|entry| matcher_matches(entry, matcher))
                .expect("expected a managed matcher entry");
            let hooks = entry["hooks"].as_array().expect("hooks should be an array");
            assert_eq!(hooks, &[veil_hook(TEST_VEIL_COMMAND)]);
        }
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

        assert_eq!(entries.len(), 3);
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
        assert!(
            inspection
                .matchers
                .iter()
                .all(|matcher| { matches!(matcher.status, ManagedHookStatus::Invalid { .. }) })
        );
    }
}
