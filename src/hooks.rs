#![forbid(unsafe_code)]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

const MANAGED_MATCHERS: &[&str] = &["Read", "Grep", "Bash"];
const VEIL_COMMAND: &str = "$HOME/.local/bin/veil";
const SETTINGS_OVERRIDE_ENV: &str = "VEIL_CLAUDE_SETTINGS_PATH";

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

pub(crate) fn has_managed_hooks(path: &Path) -> io::Result<bool> {
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);

    Ok(MANAGED_MATCHERS.iter().all(|matcher| {
        entries
            .iter()
            .find(|entry| matcher_matches(entry, matcher))
            .and_then(|entry| entry.get("hooks").and_then(Value::as_array))
            .is_some_and(|hooks| hooks.iter().any(is_veil_hook))
    }))
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
    let mut settings = load_settings(path)?;
    let entries = pre_tool_use_entries(&mut settings);

    for matcher in MANAGED_MATCHERS {
        install_matcher_hook(entries, matcher);
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

        hooks.retain(|hook| !is_veil_hook(hook));
        !hooks.is_empty()
    });

    write_settings(path, &settings)
}

fn install_matcher_hook(entries: &mut Vec<Value>, matcher: &str) {
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| matcher_matches(entry, matcher))
    {
        let hooks = entry_hooks(entry);
        if !hooks.iter().any(is_veil_hook) {
            hooks.push(veil_hook());
        }
        return;
    }

    entries.push(json!({
        "matcher": matcher,
        "hooks": [veil_hook()],
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

fn veil_hook() -> Value {
    json!({
        "type": "command",
        "command": VEIL_COMMAND,
    })
}

fn is_veil_hook(hook: &Value) -> bool {
    let Some(object) = hook.as_object() else {
        return false;
    };

    object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "command")
        && object
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|value| value == VEIL_COMMAND)
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn install_adds_expected_pretooluse_entries() {
        let path = temp_settings_path("install");

        install_into_path(&path).expect("install should create a settings file");
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
            assert_eq!(hooks, &[veil_hook()]);
        }
    }

    #[test]
    fn install_is_idempotent_on_second_run() {
        let path = temp_settings_path("idempotent");

        install_into_path(&path).expect("first install should succeed");
        install_into_path(&path).expect("second install should also succeed");

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
                &[veil_hook()]
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
                            veil_hook(),
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
                        "hooks": [veil_hook()]
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
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook()] },
                        { "matcher": "Bash", "hooks": [veil_hook()] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        assert!(
            !has_managed_hooks(&path).expect("managed hook probe should succeed"),
            "all managed matchers must be present"
        );
    }

    #[test]
    fn managed_hook_probe_accepts_fully_installed_settings() {
        let path = temp_settings_path("managed-hooks-present");
        write_settings(
            &path,
            &json!({
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Read", "hooks": [veil_hook()] },
                        { "matcher": "Grep", "hooks": [veil_hook()] },
                        { "matcher": "Bash", "hooks": [veil_hook()] }
                    ]
                }
            }),
        )
        .expect("fixture settings should be writable");

        assert!(
            has_managed_hooks(&path).expect("managed hook probe should succeed"),
            "all managed matchers are installed"
        );
    }
}
