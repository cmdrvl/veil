#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::audit::{self, Line};
use crate::config::Config;
use crate::packs::PackRegistry;
use crate::types::{HookInput, HookProtocol, ToolKind};

const MAX_REPLAY_INPUT_BYTES: usize = 1024 * 1024;
// Audit JSON escapes the raw JSON tool input and then escapes it once more as
// a JSON string. Keep a finite ceiling while allowing worst-case valid input.
const MAX_REPLAY_RECORD_BYTES: usize = 16 * 1024 * 1024;
const COMMAND_LABEL_BYTES: usize = 240;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RuleCounts {
    allow_to_deny: usize,
    deny_to_allow: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReplayCounts {
    total_entries: usize,
    replayed: usize,
    skipped: usize,
    flips: BTreeMap<String, RuleCounts>,
    newly_denied: BTreeMap<String, usize>,
}

/// Re-evaluates replayable Bash, Read, and Grep audit records with the current
/// merged policy. Rotated audit files are included so a 30-day report can span
/// normal size-based rotation.
pub fn render_report(
    audit_path: &Path,
    config: &Config,
    since: Option<&str>,
) -> io::Result<String> {
    let cutoff = since.map(parse_since).transpose()?;
    let mut counts = ReplayCounts::default();
    let registry = PackRegistry::with_built_ins();

    for path in std::iter::once(audit_path.to_path_buf())
        .chain((1..=audit::ROTATED_FILES).map(|index| audit::rotated_path(audit_path, index)))
    {
        if !path.exists() {
            continue;
        }
        replay_file(&path, config, &registry, cutoff, &mut counts)?;
    }

    Ok(render_counts(&counts, since))
}

fn replay_file(
    path: &Path,
    config: &Config,
    registry: &PackRegistry,
    cutoff: Option<u64>,
    counts: &mut ReplayCounts,
) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(path)?);
    while let Some((line, oversized)) = next_record(&mut reader)? {
        if oversized {
            counts.total_entries += 1;
            counts.skipped += 1;
            continue;
        }

        let Line::Entry { fields, .. } = audit::parse_line(&line) else {
            continue;
        };
        if cutoff.is_some_and(|cutoff| timestamp(&fields).is_none_or(|ts| ts < cutoff)) {
            continue;
        }

        counts.total_entries += 1;
        let Some(input) = parse_tool_input(&fields) else {
            counts.skipped += 1;
            continue;
        };

        if compare_entry(&fields, &input, config, registry, counts) {
            counts.replayed += 1;
        } else {
            counts.skipped += 1;
        }
    }
    Ok(())
}

/// Reads one newline-delimited record without allocating beyond the replay
/// bound, even if the audit file contains a malformed multi-gigabyte line.
fn next_record(reader: &mut impl BufRead) -> io::Result<Option<(Vec<u8>, bool)>> {
    let mut record = Vec::new();
    let mut oversized = false;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if record.is_empty() && !oversized {
                Ok(None)
            } else {
                Ok(Some((record, oversized)))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content_len = newline.unwrap_or(available.len());
        if !oversized {
            if record.len().saturating_add(content_len) > MAX_REPLAY_RECORD_BYTES {
                record.clear();
                oversized = true;
            } else {
                let Some(content) = available.get(..content_len) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "buffer returned an invalid replay record boundary",
                    ));
                };
                record.extend_from_slice(content);
            }
        }
        reader.consume(consumed);

        if newline.is_some() {
            return Ok(Some((record, oversized)));
        }
    }
}

fn parse_tool_input(fields: &Value) -> Option<HookInput> {
    if fields.get("path_is_hash").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let input = fields.get("tool_input")?.as_object()?;
    let protocol = match input.get("protocol")?.as_str()? {
        "claude_code" => HookProtocol::ClaudeCode,
        "gemini_cli" => HookProtocol::GeminiCli,
        "github_copilot" => HookProtocol::GitHubCopilot,
        "grok" => HookProtocol::Grok,
        "unknown" => return None,
        _ => return None,
    };
    let tool = match input.get("tool_kind")?.as_str()? {
        "read" => ToolKind::Read,
        "grep" => ToolKind::Grep,
        "bash" => ToolKind::Bash,
        "mcp" | "unknown" => return None,
        _ => return None,
    };
    let raw_args = input.get("raw_args")?.as_str()?;
    if raw_args.len() > MAX_REPLAY_INPUT_BYTES {
        return None;
    }

    Some(HookInput {
        protocol,
        tool,
        tool_name: input.get("tool_name")?.as_str()?.to_owned(),
        cwd: PathBuf::from(input.get("cwd")?.as_str()?),
        session_id: input
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        raw_args: raw_args.to_owned(),
    })
}

fn compare_entry(
    fields: &Value,
    input: &HookInput,
    config: &Config,
    registry: &PackRegistry,
    counts: &mut ReplayCounts,
) -> bool {
    let Some(path) = fields.get("path").and_then(Value::as_str) else {
        return false;
    };
    let Some(old_denied) = fields
        .get("decision")
        .and_then(Value::as_str)
        .and_then(|decision| match decision {
            "allow" => Some(false),
            "deny" => Some(true),
            _ => None,
        })
    else {
        return false;
    };
    let decisions = crate::evaluate_for_replay(input, config, registry);
    let current = decisions
        .iter()
        .find(|decision| decision.path.to_string_lossy() == path);
    // If current evaluation found another candidate but not this historical
    // path, the record cannot be compared reliably (for example, the checkout
    // moved or the parser's path spelling changed).
    if current.is_none() && !decisions.is_empty() {
        return false;
    }
    let current_denied = current.as_ref().is_some_and(|decision| decision.would_deny);

    if old_denied == current_denied {
        return true;
    }

    let rule = current
        .as_ref()
        .map(|decision| decision.rule)
        .or_else(|| fields.get("reason_class").and_then(Value::as_str))
        .unwrap_or("unknown")
        .to_owned();
    let rule_counts = counts.flips.entry(rule).or_default();
    if old_denied {
        rule_counts.deny_to_allow += 1;
    } else {
        rule_counts.allow_to_deny += 1;
        let label = command_label(input);
        *counts.newly_denied.entry(label).or_default() += 1;
    }
    true
}

fn command_label(input: &HookInput) -> String {
    let args: Value = serde_json::from_str(&input.raw_args).unwrap_or(Value::Null);
    let command = if input.tool == ToolKind::Bash {
        args.get("command").and_then(Value::as_str).unwrap_or("")
    } else {
        input.tool_name.as_str()
    };
    let escaped = command.replace('\n', "\\n").replace('\r', "\\r");
    let mut end = escaped.len().min(COMMAND_LABEL_BYTES);
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    let mut label = String::new();
    if let Some(prefix) = escaped.get(..end) {
        label.push_str(prefix);
    }
    if end < escaped.len() {
        label.push('…');
    }
    if label.is_empty() {
        format!("{} <arguments unavailable>", input.tool_name)
    } else {
        label
    }
}

fn timestamp(fields: &Value) -> Option<u64> {
    fields.get("ts")?.as_str()?.parse().ok()
}

fn parse_since(value: &str) -> io::Result<u64> {
    if let Some(days) = value.strip_suffix('d') {
        let days = days.parse::<u64>().map_err(invalid_since)?;
        let seconds = days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| invalid_since(value))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_since(value))?
            .as_secs();
        return Ok(now.saturating_sub(seconds));
    }
    value.parse().map_err(invalid_since)
}
fn invalid_since(value: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid --since value {value}; use Unix seconds or a duration such as 30d"),
    )
}

fn render_counts(counts: &ReplayCounts, since: Option<&str>) -> String {
    let mut output = String::from("veil replay\n");
    if let Some(since) = since {
        output.push_str(&format!("  since: {since}\n"));
    }
    output.push_str(&format!(
        "  entries: {}\n  replayed: {}\n  skipped: {}\n",
        counts.total_entries, counts.replayed, counts.skipped
    ));

    output.push_str("\nPolicy flips by rule:\n");
    if counts.flips.is_empty() {
        output.push_str("  none\n");
    } else {
        for (rule, values) in &counts.flips {
            output.push_str(&format!(
                "  {rule}: allow -> deny {}, deny -> allow {}\n",
                values.allow_to_deny, values.deny_to_allow
            ));
        }
    }

    output.push_str("\nTop newly denied commands:\n");
    let mut newly_denied: Vec<_> = counts.newly_denied.iter().collect();
    newly_denied.sort_by(|(left_command, left_count), (right_command, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_command.cmp(right_command))
    });
    if newly_denied.is_empty() {
        output.push_str("  none\n");
    } else {
        for (index, (command, count)) in newly_denied.into_iter().take(20).enumerate() {
            output.push_str(&format!("  {}. ({count}) {command}\n", index + 1));
        }
    }
    output.trim_end().to_owned()
}
