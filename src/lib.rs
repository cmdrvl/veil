#![forbid(unsafe_code)]

pub mod allowlist;
pub mod audit;
pub mod config;
pub mod evaluator;
pub mod extract;
pub mod hook;
mod mcp;
pub mod packs;
pub mod protected_corpus;
pub mod render;
pub mod replay;
pub mod sandbox;
pub mod spine;
pub mod types;

use std::cell::OnceCell;
use std::error::Error;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use allowlist::DIRECTORY_PROBE;
use audit::{AuditRecord, append_audit_record};
use config::load_config;
use evaluator::{
    DynamicReason, EvaluationInput, PolicyMatchers, dynamic_args_decision, evaluate_access_with,
};
use extract::{
    CommandExtraction, Origin, PathExposure, STDIN_ARGUMENTS, SUBSTITUTION, ScriptSource,
    extract_bash_commands, extract_read_or_grep_paths,
};
use hook::parse_hook_input;
use packs::PackRegistry;
use render::{RenderedDecision, render_decision};
use serde_json::{Value, json};
use spine::detect_spine_argv;
use types::{Decision, DecisionAction, HookInput, HookProtocol, InformationLabel, ToolKind};

#[derive(Clone, Debug)]
struct CandidateOutcome {
    path: PathBuf,
    decision: Decision,
    sensitivity: Option<String>,
    /// How the command that reached this path was reached (bd-2kr).
    origin: Origin,
    reason_class: ReasonClass,
    /// A command that sends what it is given somewhere else was denied for
    /// naming this path (bd-x8o). The audit log's `class`.
    egress: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayDecision {
    pub path: PathBuf,
    pub rule: &'static str,
    pub would_deny: bool,
}

/// What an egress denial tells the agent besides the reason: the path is on its
/// way off the machine, so a copy or an encoding of it is no way around the rule,
/// and there are two ways to get the information somewhere: a derived artifact
/// attested by `airlock`, or a send that goes out under the send-path policy
/// (the calling wrapper or the send-policy / disclosure service the README
/// names under "Boundary With Outbound Screening").
const EGRESS_REMEDIATION: &str = "Egress blocked: this command would send a protected path off this machine. Do not send the protected file itself, or a copy, archive or encoding of it. For information that will cross a model boundary: run `veil operator` to discover the authorized spine tools, derive a metadata-safe artifact, and have `airlock` attest it. For anything sent to a person or a service: it goes out under the send-path policy (the calling wrapper, or the send-policy / disclosure service, that checks the recipient, authorization and approval), not from this session; stop and ask the operator to do the transfer under that policy.";

/// Marks the denial of a command that sends what it is given (`curl`, `scp`,
/// `aws`, a mail client...) as an egress attempt: its remediation says so and
/// the audit record carries `class: egress`. Any other decision is unchanged.
fn classify_egress(command: &CommandExtraction, mut decision: Decision) -> (Decision, bool) {
    let egress = command.egress && would_deny(&decision);
    if egress {
        decision.remediation = Some(EGRESS_REMEDIATION.to_owned());
    }
    (decision, egress)
}

fn would_deny(decision: &Decision) -> bool {
    decision.action == DecisionAction::Deny
        || decision.reason.as_deref().is_some_and(|reason| {
            reason.starts_with("policy default warn:")
                || reason.starts_with("policy default log:")
                || reason.starts_with("[policy] dynamic_args = warn:")
        })
}

fn warn_mode_would_deny(decision: &Decision) -> bool {
    decision.action == DecisionAction::Allow
        && decision.reason.as_deref().is_some_and(|reason| {
            reason.starts_with("policy default warn:")
                || reason.starts_with("[policy] dynamic_args = warn:")
        })
}

/// How a path came to be judged (bd-29r, bd-2mi, bd-1wa, bd-1bk): read by
/// something veil recognises as a reader, named in the words of some other
/// command, not a path veil could work out at all, handed to an MCP tool in its
/// arguments, or a script veil was asked to run and could not read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReasonClass {
    DirectRead,
    ArgvPath,
    DynamicPath,
    McpArgument,
    ScriptTooLarge,
}

impl ReasonClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::DirectRead => "direct_read",
            Self::ArgvPath => "argv_path",
            Self::DynamicPath => "dynamic_path_unresolvable",
            Self::McpArgument => "mcp_argument",
            Self::ScriptTooLarge => "script_too_large_to_inspect",
        }
    }
}

/// What a denial that comes from the inside of a script adds to its remediation:
/// reading a script is a best effort, and the denial is not the only way a
/// script could have reached a path.
const SCRIPT_REMEDIATION: &str = " veil read this script as text and that is best effort: a script can build a path veil cannot see, and only an OS sandbox is airtight.";

/// What the denial of a script veil could not read tells the agent.
const SCRIPT_UNREAD_REMEDIATION: &str = "Script not inspected: veil reads scripts as text, up to a limit, to show that they name no protected path, and could not read this one. Split it into smaller scripts, or run the work through an authorized spine tool (`veil operator` lists them). veil reading scripts is a best effort; only an OS sandbox is airtight. If the script genuinely must run as it is, stop and ask the operator.";

/// What a denial of an MCP argument tells the agent: the tool may read the
/// path or send it on, and a copy of it is the same file to the tool.
const MCP_REMEDIATION: &str = "MCP argument blocked: this tool call hands a protected path to an MCP tool, which may read it or send it off this machine. Do not pass the protected file, or a copy, archive or encoding of it. Run `veil operator` to discover the authorized spine tools and derive a metadata-safe artifact instead; `airlock` attests which derived artifacts later cross the model boundary. If the data really must go through this tool, stop and ask the operator.";

/// What a denial of arguments veil did not read to the end tells the agent.
const MCP_OVERSIZE_REMEDIATION: &str = "MCP arguments too large to screen: call the tool with fewer strings and less nesting, so that veil can show that none of them names a protected path. If the tool genuinely needs arguments this large, stop and ask the operator.";

/// Audit replay inputs are bounded independently of the hook input parser.
const MAX_AUDIT_TOOL_INPUT_BYTES: usize = 1024 * 1024;

const BARE_INVOCATION_GUIDANCE: &str = "no hook payload received on stdin; bare `veil` is hook mode. Pipe a Claude/Gemini/Copilot hook payload into stdin, or run `veil --robot-triage`, `veil capabilities --json`, or `veil robot-docs guide` for operator discovery. For help with veil, run `veil --help`.";

/// Hook mode reads stdin to EOF. A terminal never reaches EOF, so refuse it
/// with discovery guidance instead of waiting for a human to press Ctrl-D.
fn reject_terminal_stdin(stdin_is_terminal: bool) -> io::Result<()> {
    if stdin_is_terminal {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            BARE_INVOCATION_GUIDANCE,
        ))
    } else {
        Ok(())
    }
}

pub fn run() -> Result<u8, Box<dyn Error>> {
    let stdin = io::stdin();
    reject_terminal_stdin(stdin.is_terminal())?;
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_io(stdin.lock(), &mut stdout, &mut stderr)?;
    Ok(0)
}

fn run_with_io<R: Read, W: Write, E: Write>(
    mut reader: R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<()> {
    let mut input = String::new();
    reader.read_to_string(&mut input)?;

    if input.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            BARE_INVOCATION_GUIDANCE,
        ));
    }

    let hook_input = parse_hook_input(&input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;

    let rendered = execute_hook_mode(&hook_input)?;
    stdout.write_all(rendered.stdout.as_bytes())?;
    stdout.write_all(b"\n")?;

    if let Some(message) = rendered.stderr.as_deref() {
        stderr.write_all(message.as_bytes())?;
        stderr.write_all(b"\n")?;
    }

    stdout.flush()?;
    stderr.flush()
}

fn execute_hook_mode(hook_input: &HookInput) -> io::Result<RenderedDecision> {
    let config = load_config(&hook_input.cwd)?;
    let registry = PackRegistry::with_built_ins();
    let outcomes = if hook_input.tool == ToolKind::Mcp {
        if config.mcp.screens(&hook_input.tool_name) {
            evaluate_mcp(hook_input, &config, &registry)
        } else {
            Vec::new()
        }
    } else {
        let commands = extract_commands(hook_input);
        evaluate_commands(hook_input, &config, &registry, &commands)
    };
    let decision = select_decision(&outcomes);
    let mut rendered = render_decision(hook_input.protocol, &decision);

    let warned = outcomes
        .iter()
        .filter(|outcome| warn_mode_would_deny(&outcome.decision))
        .count();
    if warned > 0 {
        append_stderr_line(
            &mut rendered,
            format!(
                "Warning: deny policy would refuse {warned} access finding(s); this policy is in warn mode."
            ),
        );
    }

    if config.policy.audit_log
        && let Err(error) = append_audit_records(
            &config.policy.audit_path,
            hook_input,
            &outcomes,
            config.policy.audit_inputs,
        )
    {
        append_stderr_line(&mut rendered, format!("Audit logging failed: {error}"));
    }

    Ok(rendered)
}

pub(crate) fn evaluate_for_replay(
    hook_input: &HookInput,
    config: &config::Config,
    registry: &PackRegistry,
) -> Vec<ReplayDecision> {
    let outcomes = if hook_input.tool == ToolKind::Mcp {
        if config.mcp.screens(&hook_input.tool_name) {
            evaluate_mcp(hook_input, config, registry)
        } else {
            Vec::new()
        }
    } else {
        let commands = extract_commands(hook_input);
        evaluate_commands(hook_input, config, registry, &commands)
    };

    outcomes
        .into_iter()
        .map(|outcome| ReplayDecision {
            path: outcome.path,
            rule: outcome.reason_class.as_str(),
            would_deny: would_deny(&outcome.decision),
        })
        .collect()
}

/// What the tool call would read, one entry per simple command. A Read or Grep
/// call is one entry; a Bash command is split into the commands that would run
/// (`sh -c`, `$( )`, `xargs`, `find -exec`, pipelines...), each judged alone.
fn extract_commands(hook_input: &HookInput) -> Vec<CommandExtraction> {
    match hook_input.tool {
        ToolKind::Read | ToolKind::Grep => vec![CommandExtraction::from_path_extraction(
            extract_read_or_grep_paths(hook_input.tool, &hook_input.raw_args, &hook_input.cwd),
        )],
        ToolKind::Bash => command_from_raw_args(&hook_input.raw_args)
            .map(|command| extract_bash_commands(&command, &hook_input.cwd))
            .unwrap_or_default(),
        // an MCP call has no commands: `evaluate_mcp` judges its arguments
        ToolKind::Mcp | ToolKind::Unknown => Vec::new(),
    }
}

/// What an MCP tool call hands over: every string in its arguments that names a
/// path is judged as a word of a command is, for a tool that is not an
/// authorized spine tool (bd-1wa). The reason names the field, as a JSON
/// pointer. Arguments veil did not read to the end are denied, as an argument
/// it cannot resolve is.
fn evaluate_mcp(
    hook_input: &HookInput,
    config: &config::Config,
    registry: &PackRegistry,
) -> Vec<CandidateOutcome> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let scan = mcp::scan_arguments(&hook_input.raw_args, &hook_input.cwd, home.as_deref());
    let matchers = PolicyMatchers::new(config);
    let mut outcomes = Vec::new();

    for found in &scan.paths {
        let input = EvaluationInput::new(
            hook_input.tool,
            found.path.clone(),
            PathExposure::ReadsContents,
        )
        .with_argv_command(&hook_input.tool_name, false);
        let mut decision = evaluate_access_with(&input, config, registry, &matchers);

        // A path that is not protected is the common case; it is neither
        // blocked nor worth a record.
        if decision.action == DecisionAction::Allow && decision.reason.is_none() {
            continue;
        }

        decision.reason = decision
            .reason
            .map(|reason| format!("{reason} (argument `{}`)", found.pointer));
        if decision.remediation.is_some() {
            decision.remediation = Some(MCP_REMEDIATION.to_owned());
        }
        outcomes.push(CandidateOutcome {
            path: found.path.clone(),
            decision,
            sensitivity: sensitivity_pack(registry, &matchers, &found.path),
            origin: Origin::Top,
            reason_class: ReasonClass::McpArgument,
            egress: false,
        });
    }

    if scan.exceeded_limits {
        outcomes.push(CandidateOutcome {
            path: PathBuf::from(UNSCREENED_LABEL),
            decision: evaluator::resolve_policy(
                &config.policy.default,
                None,
                format!(
                    "`{}` was given arguments nested deeper than {} levels or holding more than {} strings, so veil cannot show that none of them names a protected path {}; blocked by policy default",
                    hook_input.tool_name,
                    mcp::MAX_DEPTH,
                    mcp::MAX_STRINGS,
                    InformationLabel::Protected.annotation(),
                ),
                MCP_OVERSIZE_REMEDIATION,
            ),
            sensitivity: None,
            origin: Origin::Top,
            reason_class: ReasonClass::McpArgument,
            egress: false,
        });
    }

    outcomes
}

const UNSCREENED_LABEL: &str = "<arguments veil cannot screen>";

fn command_from_raw_args(raw_args: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw_args)
        .ok()?
        .get("command")?
        .as_str()
        .map(str::to_owned)
}

/// Evaluates every path of every command. An authorized spine tool authorizes
/// only the command that names it, so `shape data/a.csv; cat data/b.csv` still
/// denies the `cat`.
fn evaluate_commands(
    hook_input: &HookInput,
    config: &config::Config,
    registry: &PackRegistry,
    commands: &[CommandExtraction],
) -> Vec<CandidateOutcome> {
    // Built once: a command can name dozens of paths, and building the
    // matchers is linear in the number of configured patterns.
    let matchers = PolicyMatchers::new(config);
    let context = ProtectedContext::new(&hook_input.cwd, registry, &matchers);
    let mut outcomes = Vec::new();

    for command in commands {
        let mut command_config = config.clone();
        if command.egress {
            command_config.policy.default = config.policy.egress_mode().clone();
        }

        // A script that is itself a protected path is denied where it was named
        // (`python3 data/x.csv`); what is in it is not read into another reason.
        if let Some(source) = &command.script
            && script_is_protected(source, registry, &matchers)
        {
            continue;
        }

        let first_outcome = outcomes.len();
        let spine_invocation = detect_spine(hook_input, config, command);
        let mut candidates = command.candidates.clone();

        if candidates.is_empty()
            && command.argv_paths.is_empty()
            && let Some(invocation) = spine_invocation.as_ref()
        {
            candidates.push(invocation.target_path.clone());
        }

        for path in &candidates {
            let mut evaluation_input =
                EvaluationInput::new(hook_input.tool, path.clone(), command.exposure);

            if let Some(invocation) = spine_invocation.clone() {
                evaluation_input = evaluation_input.with_spine_invocation(invocation);
            }

            let (decision, egress) = classify_egress(
                command,
                evaluate_access_with(&evaluation_input, &command_config, registry, &matchers),
            );
            outcomes.push(CandidateOutcome {
                path: path.clone(),
                decision,
                sensitivity: sensitivity_pack(registry, &matchers, path),
                origin: command.origin,
                reason_class: ReasonClass::DirectRead,
                egress,
            });
        }

        let program = command.argv.first().map(|word| command_basename(word));

        for argv in &command.argv_paths {
            // Past the filesystem budget a word is only text, so it is judged
            // only if the text already matches a protected pattern.
            if !argv.resolved && !matchers.is_protected(&argv.path) {
                continue;
            }

            let mut evaluation_input =
                EvaluationInput::new(hook_input.tool, argv.path.clone(), command.argv_exposure)
                    .with_argv_command(program.unwrap_or(""), command.argv_scans_directories);
            if argv.resolved {
                evaluation_input = evaluation_input.with_canonical_path();
            }

            // An authorized spine tool is authorized for every path it names.
            if let Some(invocation) = spine_invocation.as_ref() {
                evaluation_input =
                    evaluation_input.with_spine_invocation(invocation.for_path(argv.path.clone()));
            }

            let decision =
                evaluate_access_with(&evaluation_input, &command_config, registry, &matchers);

            // A word that is not protected is the common case (`git commit -m
            // a/b`, `sed s/a/b/`); it is neither blocked nor worth a record.
            if decision.action == DecisionAction::Allow && decision.reason.is_none() {
                continue;
            }

            let (decision, egress) = classify_egress(command, decision);
            outcomes.push(CandidateOutcome {
                path: argv.path.clone(),
                decision,
                sensitivity: sensitivity_pack(registry, &matchers, &argv.path),
                origin: command.origin,
                reason_class: ReasonClass::ArgvPath,
                egress,
            });
        }

        // A path that was already denied needs no second reason. An authorized
        // spine tool takes a protected path and prints metadata, so an
        // argument it is given needs no resolving either.
        let already_denied = outcomes[first_outcome..]
            .iter()
            .any(|outcome| would_deny(&outcome.decision));
        if command.has_dynamic_args()
            && !already_denied
            && spine_invocation.is_none()
            && let Some(mut outcome) = dynamic_outcome(&command_config, command, &context)
        {
            outcome.egress = command.egress && would_deny(&outcome.decision);
            outcomes.push(outcome);
        }

        // What came out of a script says which script it was, and that reading
        // scripts is best effort.
        if let Some(source) = &command.script {
            annotate_script_outcomes(&mut outcomes[first_outcome..], source);

            if let Some(why) = &source.unread {
                outcomes.push(unread_script_outcome(
                    hook_input,
                    &command_config,
                    registry,
                    &matchers,
                    command,
                    source,
                    why,
                ));
            }
        }
    }

    outcomes
}

/// The script is a path the policy protects, or sits in a directory it protects.
fn script_is_protected(
    source: &ScriptSource,
    registry: &PackRegistry,
    matchers: &PolicyMatchers,
) -> bool {
    matchers.is_protected(&source.path)
        || registry.classify(&source.path, false).is_some()
        || source
            .path
            .parent()
            .is_some_and(|directory| matchers.covers_directory(directory))
}

fn annotate_script_outcomes(outcomes: &mut [CandidateOutcome], source: &ScriptSource) {
    for outcome in outcomes {
        let Some(reason) = outcome.decision.reason.take() else {
            continue;
        };

        outcome.decision.reason = Some(format!(
            "{reason} (found in script `{}`)",
            readable(&source.name)
        ));
        if let Some(remediation) = outcome.decision.remediation.as_mut() {
            remediation.push_str(SCRIPT_REMEDIATION);
        }
    }
}

/// The outcome for a script veil was asked to run and did not read: it is larger
/// than the limit, or is one script too many. It is judged by what its directory
/// holds, the look a recursive copy of that directory would get: a protected
/// path within reach denies it; with none, it is allowed and recorded.
fn unread_script_outcome(
    hook_input: &HookInput,
    config: &config::Config,
    registry: &PackRegistry,
    matchers: &PolicyMatchers,
    command: &CommandExtraction,
    source: &ScriptSource,
    why: &str,
) -> CandidateOutcome {
    let program = command
        .argv
        .first()
        .map(|word| readable(command_basename(word)))
        .unwrap_or_default();
    let name = readable(&source.name);
    let reach = evaluate_access_with(
        &EvaluationInput::new(
            hook_input.tool,
            source.run_in.clone(),
            PathExposure::ReadsContents,
        )
        .with_argv_command(&program, true),
        config,
        registry,
        matchers,
    );
    let decision = if reach.reason.is_some() {
        evaluator::resolve_policy(
            &config.policy.default,
            None,
            format!(
                "`{program}` runs `{name}`, which {why}, so veil cannot read it to show that it reads nothing protected, and the directory it runs in holds a protected path {}; blocked by policy default",
                InformationLabel::Protected.annotation(),
            ),
            SCRIPT_UNREAD_REMEDIATION,
        )
    } else {
        Decision {
            action: DecisionAction::Allow,
            label: InformationLabel::Public,
            clearance: types::Clearance::Derived,
            reason: Some(format!(
                "`{program}` runs `{name}`, which {why}; nothing protected is within reach of the directory it runs in, so it is allowed"
            )),
            severity: None,
            confidence: None,
            remediation: None,
        }
    };

    CandidateOutcome {
        path: source.path.clone(),
        decision,
        sensitivity: None,
        origin: Origin::Script,
        reason_class: ReasonClass::ScriptTooLarge,
        egress: false,
    }
}

/// Whether the commands of one Bash call run where a protected path is in play
/// (bd-2mi): in a protected directory, or in a string that sets a variable to a
/// protected path. Asked only for a command that carries an argument veil
/// cannot resolve and is not one that reads or ships files anyway.
struct ProtectedContext<'a> {
    cwd: &'a Path,
    registry: &'a PackRegistry,
    matchers: &'a PolicyMatchers,
    directory: OnceCell<bool>,
}

impl<'a> ProtectedContext<'a> {
    fn new(cwd: &'a Path, registry: &'a PackRegistry, matchers: &'a PolicyMatchers) -> Self {
        Self {
            cwd,
            registry,
            matchers,
            directory: OnceCell::new(),
        }
    }

    /// The working directory is inside a `[sensitivity] protected` root or one
    /// a sensitivity pack recognises (`~/.ssh`, a credentials directory...).
    fn in_protected_directory(&self) -> bool {
        *self.directory.get_or_init(|| {
            let covered = self.matchers.covers_directory(self.cwd);
            covered
                || self
                    .registry
                    .classify(self.cwd.join(DIRECTORY_PROBE), false)
                    .is_some()
        })
    }

    /// Some value the command string assigns to a variable is a protected
    /// path, or sits in a protected directory.
    fn assigns_protected_path(&self, assigned: &[PathBuf]) -> bool {
        assigned.iter().any(|path| {
            let covered = self.matchers.is_protected(path);
            covered
                || self.registry.classify(path, false).is_some()
                || self.matchers.covers_directory(path)
                || self
                    .registry
                    .classify(path.join(DIRECTORY_PROBE), false)
                    .is_some()
        })
    }
}

/// The outcome for a command with an argument veil cannot resolve to a path:
/// `None` when the stance has nothing to say about it. A reader, a filter, a
/// bulk transfer or an unresolved program is judged wherever it runs; any
/// other command only where a protected path is in play.
fn dynamic_outcome(
    config: &config::Config,
    command: &CommandExtraction,
    context: &ProtectedContext<'_>,
) -> Option<CandidateOutcome> {
    let why = if command.opaque {
        DynamicReason::Unanalysable
    } else if command.dynamic_strict {
        DynamicReason::Strict
    } else if context.in_protected_directory() {
        DynamicReason::ProtectedDirectory
    } else if context.assigns_protected_path(&command.assigned_paths) {
        DynamicReason::ProtectedValue
    } else {
        return None;
    };

    let program = command
        .argv
        .first()
        .map(|word| readable(command_basename(word)))
        .unwrap_or_default();
    let (label, what) = match command.unresolved.first() {
        _ if command.opaque => (UNANALYSABLE_LABEL.to_owned(), String::new()),
        Some(word) if word.as_str().eq(STDIN_ARGUMENTS) => (
            "<arguments read from standard input>".to_owned(),
            "the names it reads from standard input".to_owned(),
        ),
        Some(word) => {
            let label = readable(word);
            let what = format!("`{label}`");
            (label, what)
        }
        // The program itself is the unresolved word.
        None => (program.clone(), format!("`{program}` as its program")),
    };

    Some(CandidateOutcome {
        path: PathBuf::from(label),
        decision: dynamic_args_decision(config, &program, &what, why)?,
        sensitivity: None,
        origin: command.origin,
        reason_class: ReasonClass::DynamicPath,
        // An argument veil cannot resolve is not an attempt to send a
        // protected path, so it stays out of the egress class.
        egress: false,
    })
}

const UNANALYSABLE_LABEL: &str = "<command veil cannot analyse>";

/// How many characters of an unresolved word a reason or an audit record shows.
const READABLE_WORD_LIMIT: usize = 80;

/// A word as the person wrote it: the markers veil leaves for a `$( )` result
/// spelled out, and cut short if it is long.
fn readable(word: &str) -> String {
    let text = word.replace(SUBSTITUTION, "$(...)");
    match text.char_indices().nth(READABLE_WORD_LIMIT) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text,
    }
}

fn sensitivity_pack(
    registry: &PackRegistry,
    matchers: &PolicyMatchers,
    path: &Path,
) -> Option<String> {
    registry
        .classify(path, matchers.is_protected(path))
        .map(|result| result.pack)
}

fn command_basename(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

fn detect_spine(
    hook_input: &HookInput,
    config: &config::Config,
    command: &CommandExtraction,
) -> Option<spine::SpineInvocation> {
    if hook_input.tool != ToolKind::Bash {
        return None;
    }

    detect_spine_argv(
        &command.argv,
        &config.spine.authorized_tools,
        &config.spine.denied_flags,
        &hook_input.cwd,
    )
}

fn select_decision(outcomes: &[CandidateOutcome]) -> Decision {
    if let Some(outcome) = outcomes
        .iter()
        .find(|outcome| outcome.decision.action == DecisionAction::Deny)
    {
        return outcome.decision.clone();
    }

    outcomes
        .iter()
        .find(|outcome| outcome.decision.reason.is_some())
        .map(|outcome| outcome.decision.clone())
        .unwrap_or_else(allow_silent_decision)
}

fn allow_silent_decision() -> Decision {
    Decision {
        action: DecisionAction::Allow,
        label: InformationLabel::Public,
        clearance: types::Clearance::Derived,
        reason: None,
        severity: None,
        confidence: None,
        remediation: None,
    }
}

fn append_audit_records(
    audit_path: &Path,
    hook_input: &HookInput,
    outcomes: &[CandidateOutcome],
    audit_inputs: bool,
) -> io::Result<()> {
    if outcomes.is_empty() {
        return Ok(());
    }

    let timestamp = audit_timestamp();
    let tool_input = (audit_inputs && hook_input.raw_args.len() <= MAX_AUDIT_TOOL_INPUT_BYTES)
        .then(|| audit_tool_input(hook_input));

    for outcome in outcomes {
        append_audit_record(
            audit_path,
            &AuditRecord {
                ts: timestamp.clone(),
                tool: audit_tool_name(hook_input),
                path: if audit_inputs {
                    outcome.path.to_string_lossy().into_owned()
                } else {
                    boundary_detectors::hash_match(outcome.path.to_string_lossy().as_bytes())
                },
                decision: decision_name(&outcome.decision.action).to_owned(),
                reason: outcome.decision.reason.clone(),
                sensitivity: outcome.sensitivity.clone(),
                confidence: outcome.decision.confidence,
                session_id: hook_input.session_id.clone(),
                origin: Some(outcome.origin.as_str().to_owned()),
                reason_class: Some(outcome.reason_class.as_str().to_owned()),
                class: outcome.egress.then(|| "egress".to_owned()),
                would_deny: would_deny(&outcome.decision),
                path_is_hash: !audit_inputs,
                tool_input: tool_input.clone(),
            },
        )?;
    }

    Ok(())
}

fn audit_tool_input(hook_input: &HookInput) -> Value {
    json!({
        "protocol": match hook_input.protocol {
            HookProtocol::ClaudeCode => "claude_code",
            HookProtocol::GeminiCli => "gemini_cli",
            HookProtocol::GitHubCopilot => "github_copilot",
            HookProtocol::Grok => "grok",
            HookProtocol::Unknown => "unknown",
        },
        "tool_kind": match hook_input.tool {
            ToolKind::Read => "read",
            ToolKind::Grep => "grep",
            ToolKind::Bash => "bash",
            ToolKind::Mcp => "mcp",
            ToolKind::Unknown => "unknown",
        },
        "tool_name": hook_input.tool_name,
        "cwd": hook_input.cwd.to_string_lossy(),
        "session_id": hook_input.session_id,
        "raw_args": hook_input.raw_args,
    })
}

fn audit_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "0".to_owned(),
    }
}

/// The tool as the audit log names it. An MCP call is recorded under its own
/// name (`mcp__mail__send_email`): `Mcp` would be every server's every tool.
fn audit_tool_name(hook_input: &HookInput) -> String {
    match hook_input.tool {
        ToolKind::Read => "Read".to_owned(),
        ToolKind::Grep => "Grep".to_owned(),
        ToolKind::Bash => "Bash".to_owned(),
        ToolKind::Mcp => hook_input.tool_name.clone(),
        ToolKind::Unknown => "Unknown".to_owned(),
    }
}

fn decision_name(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "allow",
        DecisionAction::Deny => "deny",
    }
}

fn append_stderr_line(rendered: &mut RenderedDecision, line: String) {
    match rendered.stderr.as_mut() {
        Some(stderr) if !stderr.is_empty() => {
            stderr.push('\n');
            stderr.push_str(&line);
        }
        Some(stderr) => stderr.push_str(&line),
        None => rendered.stderr = Some(line),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::BufRead;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("veil-{name}-{nanos}"))
    }

    fn configure_repo(repo_root: &Path, protected_patterns: &[&str]) -> PathBuf {
        fs::create_dir_all(repo_root).expect("repo root should be created");

        let audit_path = repo_root.join("state").join("audit.jsonl");
        let protected = protected_patterns
            .iter()
            .map(|pattern| format!("\"{pattern}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "[sensitivity]\nprotected = [{protected}]\n\n[policy]\ndefault = \"deny\"\naudit_log = true\naudit_path = \"{}\"\n",
            audit_path.to_string_lossy().replace('\\', "\\\\")
        );

        fs::write(repo_root.join(".veil.toml"), config).expect("config should be written");
        audit_path
    }

    fn read_audit_records(path: &Path) -> Vec<Value> {
        let file = fs::File::open(path).expect("audit file should exist");
        io::BufReader::new(file)
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(&line.expect("audit line should be readable"))
                    .expect("audit line should parse")
            })
            .collect()
    }

    #[test]
    fn terminal_stdin_is_rejected_with_discovery_guidance_and_pipes_are_not() {
        let error = reject_terminal_stdin(true).expect_err("a terminal stdin must be rejected");
        let message = error.to_string();
        for hint in ["--robot-triage", "capabilities --json", "veil --help"] {
            assert!(message.contains(hint), "guidance should mention {hint}");
        }

        assert!(reject_terminal_stdin(false).is_ok());
    }

    #[test]
    fn run_with_io_allows_authorized_spine_command_and_audits_it() {
        let repo_root = unique_temp_dir("hook-allow");
        let audit_path = configure_repo(&repo_root, &["protected/**"]);
        fs::create_dir_all(repo_root.join("protected")).expect("protected dir should exist");
        fs::write(repo_root.join("protected").join("secret.bin"), "top secret")
            .expect("fixture file should be written");

        let input = format!(
            r#"{{
                "session_id":"gemini-session",
                "cwd":"{}",
                "hook_event_name":"BeforeTool",
                "tool_name":"run_shell_command",
                "tool_input":{{"command":"shape protected/secret.bin","description":"Summarize metadata only"}}
            }}"#,
            repo_root.display()
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_with_io(input.as_bytes(), &mut stdout, &mut stderr)
            .expect("hook pipeline should succeed");

        assert_eq!(
            String::from_utf8(stdout).expect("stdout should be UTF-8"),
            "{\"decision\":\"allow\"}\n"
        );
        assert!(stderr.is_empty());

        let records = read_audit_records(&audit_path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tool"], "Bash");
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["session_id"], "gemini-session");
        let recorded_path = Path::new(
            records[0]["path"]
                .as_str()
                .expect("audit path should be recorded as a string"),
        );
        assert!(recorded_path.ends_with(Path::new("protected").join("secret.bin")));
    }

    #[test]
    fn run_with_io_denies_spine_raw_value_flags_and_audits_the_denial() {
        let repo_root = unique_temp_dir("hook-raw-flag");
        let audit_path = configure_repo(&repo_root, &["protected/**"]);
        fs::create_dir_all(repo_root.join("protected")).expect("protected dir should exist");
        fs::write(repo_root.join("protected").join("secret.bin"), "top secret")
            .expect("fixture file should be written");

        for command in [
            "shape --explicit protected/secret.bin",
            "profile protected/secret.bin --explicit",
            "shape --dump=all protected/secret.bin",
        ] {
            let input = format!(
                r#"{{
                    "session_id":"raw-flag-session",
                    "cwd":"{}",
                    "hook_event_name":"PreToolUse",
                    "tool_name":"Bash",
                    "tool_input":{{"command":"{command}"}}
                }}"#,
                repo_root.display()
            );
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            run_with_io(input.as_bytes(), &mut stdout, &mut stderr)
                .expect("hook pipeline should succeed");

            let stdout = String::from_utf8(stdout).expect("stdout should be UTF-8");
            assert!(
                stdout.contains("\"permissionDecision\":\"deny\""),
                "`{command}` must be denied, got {stdout}"
            );
            assert!(
                stdout.contains("escalates its output from metadata to protected content"),
                "`{command}`: {stdout}"
            );
            let stderr = String::from_utf8(stderr).expect("stderr should be UTF-8");
            assert!(stderr.contains("Raw-value flag blocked"), "{stderr}");
            assert!(!stderr.to_lowercase().contains("script"), "{stderr}");
        }

        let records = read_audit_records(&audit_path);
        assert_eq!(records.len(), 3);
        for record in &records {
            assert_eq!(record["tool"], "Bash");
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["session_id"], "raw-flag-session");
            assert!(
                record["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("raw-value flag")),
                "audit reason should name the raw-value flag: {record}"
            );
        }
    }

    #[test]
    fn run_with_io_denies_direct_read_after_path_hardening_and_audits_it() {
        let repo_root = unique_temp_dir("hook-deny");
        let audit_path = configure_repo(&repo_root, &["protected/**"]);
        fs::create_dir_all(repo_root.join("protected").join("nested"))
            .expect("nested dir should exist");
        fs::write(repo_root.join("protected").join("secret.bin"), "classified")
            .expect("fixture file should be written");

        let input = format!(
            r#"{{
                "session_id":"claude-session",
                "cwd":"{}",
                "hook_event_name":"PreToolUse",
                "tool_name":"Read",
                "tool_input":{{"file_path":"protected/nested/../secret.bin"}}
            }}"#,
            repo_root.display()
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_with_io(input.as_bytes(), &mut stdout, &mut stderr)
            .expect("hook pipeline should succeed");

        assert_eq!(
            String::from_utf8(stdout).expect("stdout should be UTF-8"),
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"direct read inside a protected directory is blocked by policy default\"}}\n"
        );
        let stderr = String::from_utf8(stderr).expect("stderr should be UTF-8");
        assert!(stderr.contains("Sensitive file access blocked"));
        assert!(!stderr.contains("nested/.."));
        assert!(stderr.contains("Run `veil operator`"));
        assert!(stderr.contains("discover the authorized spine tools"));
        assert!(stderr.contains("choose the right metadata-safe path for this file"));

        let records = read_audit_records(&audit_path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tool"], "Read");
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["session_id"], "claude-session");
        let recorded_path = Path::new(
            records[0]["path"]
                .as_str()
                .expect("audit path should be recorded as a string"),
        );
        assert!(recorded_path.ends_with(Path::new("protected").join("secret.bin")));
    }

    #[test]
    fn run_with_io_rejects_invalid_hook_payloads() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"unexpected":true}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("invalid hook payload should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_io_rejects_empty_hook_payload_with_operator_guidance() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io("".as_bytes(), &mut stdout, &mut stderr)
            .expect_err("empty hook payload should fail");

        let message = error.to_string();
        assert!(message.contains("no hook payload received"));
        assert!(message.contains("veil --robot-triage"));
        assert!(message.contains("veil capabilities --json"));
        assert!(message.contains("For help with veil"));
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_io_rejects_malformed_copilot_tool_args() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"cwd":"/tmp","toolName":"view","toolArgs":"not-json"}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("malformed Copilot toolArgs should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_io_rejects_malformed_snake_case_tool_input() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_with_io(
            br#"{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":"not-json"}"#.as_slice(),
            &mut stdout,
            &mut stderr,
        )
        .expect_err("malformed snake-case tool_input should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    /// Extract, evaluate and select for one Bash command, the work the hook does
    /// after it has read the payload and the config.
    fn judge(command: &str, repo_root: &Path, config: &config::Config) -> (Decision, usize) {
        let hook_input = HookInput {
            protocol: types::HookProtocol::ClaudeCode,
            tool: ToolKind::Bash,
            tool_name: "Bash".to_owned(),
            cwd: repo_root.to_path_buf(),
            session_id: None,
            raw_args: serde_json::json!({ "command": command }).to_string(),
        };
        let registry = PackRegistry::with_built_ins();
        let commands = extract_commands(&hook_input);
        let outcomes = evaluate_commands(&hook_input, config, &registry, &commands);

        (select_decision(&outcomes), outcomes.len())
    }

    #[test]
    fn a_command_that_names_sixty_four_files_is_judged_in_about_a_millisecond() {
        let repo_root = unique_temp_dir("hook-64-words");
        configure_repo(&repo_root, &["data/**"]);
        fs::create_dir_all(repo_root.join("data")).expect("data dir");
        fs::create_dir_all(repo_root.join("src")).expect("src dir");
        let mut words = Vec::new();
        for index in 0..63 {
            let name = format!("src/file{index}.rs");
            fs::write(repo_root.join(&name), "fn f() {}\n").expect("source file");
            words.push(name);
        }
        let repo_root = fs::canonicalize(&repo_root).expect("canonical root");
        let config = load_config(&repo_root).expect("config should load");
        let clean = format!("awk 1 {}", words.join(" "));
        let dirty = format!("{clean} data/clients.csv");

        let mut best = std::time::Duration::MAX;
        for _ in 0..50 {
            let start = std::time::Instant::now();
            let (decision, _) = judge(&clean, &repo_root, &config);
            best = best.min(start.elapsed());
            assert_eq!(decision.action, DecisionAction::Allow);
        }
        let (decision, records) = judge(&dirty, &repo_root, &config);

        // Where the time goes, best of 50 for each stage.
        let hook_input = HookInput {
            protocol: types::HookProtocol::ClaudeCode,
            tool: ToolKind::Bash,
            tool_name: "Bash".to_owned(),
            cwd: repo_root.clone(),
            session_id: None,
            raw_args: serde_json::json!({ "command": clean }).to_string(),
        };
        let stage = |work: &mut dyn FnMut()| {
            (0..50)
                .map(|_| {
                    let start = std::time::Instant::now();
                    work();
                    start.elapsed()
                })
                .min()
                .expect("fifty runs")
        };
        let registry_time = stage(&mut || drop(PackRegistry::with_built_ins()));
        let registry = PackRegistry::with_built_ins();
        let extract_time = stage(&mut || drop(extract_commands(&hook_input)));
        let commands = extract_commands(&hook_input);
        let evaluate_time = stage(&mut || {
            drop(evaluate_commands(
                &hook_input,
                &config,
                &registry,
                &commands,
            ))
        });
        // The same hook work for a command that names two files.
        let few = format!("awk 1 {} {}", words[0], words[1]);
        let mut few_best = std::time::Duration::MAX;
        for _ in 0..50 {
            let start = std::time::Instant::now();
            let (decision, _) = judge(&few, &repo_root, &config);
            few_best = few_best.min(start.elapsed());
            assert_eq!(decision.action, DecisionAction::Allow);
        }
        eprintln!(
            "64 words, 1 pattern: whole {best:?} = registry {registry_time:?} + extract {extract_time:?} + evaluate {evaluate_time:?}; 2 words: {few_best:?}"
        );
        assert_eq!(decision.action, DecisionAction::Deny);
        assert_eq!(records, 1, "only the protected word is worth a record");
        // About 1 ms in a release build for the most words one command gets
        // resolved. The bound is a guard against a regression, loose enough for
        // a debug build on a busy machine; the measurement is in the line above.
        let bound = if cfg!(debug_assertions) { 20 } else { 3 };
        assert!(
            best < std::time::Duration::from_millis(bound),
            "judging 63 clean words took {best:?}"
        );
    }

    #[test]
    fn ten_thousand_protected_patterns_do_not_slow_a_command_by_the_number_of_patterns() {
        // A repo of 63 ordinary files whose config protects `count` patterns, and
        // the words that name the files.
        let repo_with = |label: &str, count: usize| {
            let repo_root = unique_temp_dir(label);
            fs::create_dir_all(repo_root.join("src")).expect("src dir");
            let audit_path = repo_root.join("state").join("audit.jsonl");
            let patterns = (0..count)
                .map(|index| format!("\"zone{index}/**\""))
                .collect::<Vec<_>>()
                .join(", ");
            fs::write(
                repo_root.join(".veil.toml"),
                format!(
                    "[sensitivity]\nprotected = [{patterns}]\n\n[policy]\ndefault = \"deny\"\naudit_log = true\naudit_path = \"{}\"\n",
                    audit_path.to_string_lossy().replace('\\', "\\\\")
                ),
            )
            .expect("config should be written");
            let mut words = Vec::new();
            for index in 0..63 {
                let name = format!("src/file{index}.rs");
                fs::write(repo_root.join(&name), "fn f() {}\n").expect("source file");
                words.push(name);
            }
            let repo_root = fs::canonicalize(&repo_root).expect("canonical root");
            let config = load_config(&repo_root).expect("config should load");

            (repo_root, config, words)
        };
        let (small_root, small, words) = repo_with("hook-10", 10);
        let (big_root, big, _) = repo_with("hook-10k", 10_000);
        // the config adds a few built-in patterns to the 10,000 above
        assert!(big.sensitivity.protected.len() >= 10_000);
        assert!(small.sensitivity.protected.len() < 1_000);

        let clean = format!("awk 1 {}", words.join(" "));
        let few = format!("awk 1 {} {}", words[0], words[1]);
        let dirty = format!("{clean} zone9999/x.csv");

        // Four measurements of one command each, taken in turn so that load on the
        // machine lands on all of them alike, each the best of 20: 63 words and 2
        // words, against 10 patterns and against 10,000.
        let measure = |command: &str, root: &Path, config: &config::Config| {
            let start = std::time::Instant::now();
            let (decision, _) = judge(command, root, config);
            assert_eq!(decision.action, DecisionAction::Allow);
            start.elapsed()
        };
        let mut calibration = std::time::Duration::MAX;
        let mut few_small = std::time::Duration::MAX;
        let mut many = std::time::Duration::MAX;
        let mut few_many = std::time::Duration::MAX;
        for _ in 0..20 {
            calibration = calibration.min(measure(&clean, &small_root, &small));
            few_small = few_small.min(measure(&few, &small_root, &small));
            many = many.min(measure(&clean, &big_root, &big));
            few_many = few_many.min(measure(&few, &big_root, &big));
        }
        let (decision, _) = judge(&dirty, &big_root, &big);
        assert_eq!(decision.action, DecisionAction::Deny);

        // The matchers are built once per command: that build, not a lookup per
        // word, is what the patterns cost. So what 61 more words cost must not
        // depend on the number of patterns, and the build is a fixed price.
        //
        // None of the bounds is a clock time, because a clock time fails on a
        // busy machine without a regression (the old bound was 100 ms; at a load
        // of 5 the build alone is 115 ms in a debug build). Each is relative to
        // measurements made here, in this test, under the same load. Measured at
        // load 5: debug 10 patterns 5.2 ms, 10k patterns 120 ms; release 0.9 ms
        // and 25 ms; the cost of 61 more words is the same at both counts.
        eprintln!(
            "10 patterns: 63 words {calibration:?}, 2 words {few_small:?}; \
             10k patterns: 63 words {many:?}, 2 words {few_many:?}"
        );

        // 1. 61 more words cost about what they cost against 10 patterns. The
        // patterns are 1,000 times as many: a lookup that scans them, or a
        // matcher built for each word, would make this a ratio in the hundreds.
        // The slack is a tenth of the build, the noise of timing it twice.
        let per_word_small = calibration.saturating_sub(few_small);
        let per_word_many = many.saturating_sub(few_many);
        assert!(
            per_word_many <= per_word_small * 5 + few_many / 10,
            "61 more words cost {per_word_many:?} against 10,000 patterns and {per_word_small:?} \
             against 10 (63 words {many:?} and {calibration:?}, 2 words {few_many:?} and {few_small:?})"
        );

        // 2. The build is a fixed price for the command: 63 words against 10,000
        // patterns cost at most a hundred times what they cost against 10. They
        // cost 23 to 29 times as much, debug or release.
        assert!(
            many < calibration * 100,
            "63 words against 10,000 patterns took {many:?}, more than 100 times the {calibration:?} \
             they take against 10 patterns"
        );

        // 3. A backstop for a calibration that is itself wrong: two seconds is
        // seventeen times what a debug build takes at a load of 5.
        assert!(
            many < std::time::Duration::from_secs(2),
            "judging 63 clean words against 10,000 patterns took {many:?}"
        );
    }
}
