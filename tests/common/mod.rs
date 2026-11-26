//! How the tests read what the hook answered to a Claude Code payload (bd-tmn).
//!
//! A call is allowed only when veil exited 0 and printed nothing at all, which
//! is no decision. Anything it prints has to be exactly one deny. A crash,
//! another exit status or any other output fails the test, so none of them can
//! be counted as allowed.

use std::process::Output;

use serde_json::{Value, json};

/// `None` when veil allowed the call, `Some(reason)` when it denied it.
#[track_caller]
pub fn claude_denial(output: &Output) -> Option<String> {
    assert_eq!(
        output.status.code(),
        Some(0),
        "veil should exit 0 ({}), stdout: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        return None;
    }

    let text = std::str::from_utf8(&output.stdout).expect("hook stdout should be UTF-8");
    let line = text
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("a hook reply should end with a newline: {text:?}"));
    let document: Value = serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("a hook reply should be one JSON object ({error}): {text}"));
    let reason = document["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| panic!("what veil prints should be a deny with a reason: {text}"))
        .to_owned();
    assert_eq!(
        document,
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }),
        "what veil prints should be exactly one deny"
    );

    Some(reason)
}
