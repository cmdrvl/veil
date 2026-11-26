//! Session-scoped broker and `veil exec` client.
//!
//! The broker accepts one typed JSON request per Unix socket connection. It
//! never invokes a shell, and it withholds stdout and stderr until both have
//! passed the shared boundary detector.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};

use crate::audit::{AuditRecord, append_audit_record_with_enforcement};
use crate::broker_output::{BrokerOutputScanner, MAX_BROKER_OUTPUT_BYTES};
use crate::config::{self, Config};
use crate::sandbox::seatbelt;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_FRAME_BYTES: usize = 64 * 1024;
const OUTPUT_CHUNK_BYTES: usize = 8 * 1024;
const MAX_SESSION_CALLS: usize = 64;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
pub(crate) const BROKER_SOCKET_ENV: &str = "VEIL_BROKER_SOCKET";
const BROKER_SESSION_ENV: &str = "VEIL_BROKER_SESSION";
const DERIVED_TOOLS: &[&str] = &[
    "shape",
    "rvl",
    "vacuum",
    "hashbytes",
    "fingerprint",
    "profile",
    "canon",
    "lock",
    "pack",
    "verify",
    "assess",
    "benchmark",
    "airlock",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequest {
    tool: String,
    argv: Vec<String>,
    /// Where the client stands; relative arguments are read from there. It must
    /// be inside the directory the broker was started in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct BrokerContext {
    config: Config,
    cwd: PathBuf,
    session: String,
    executables: BTreeMap<String, PathBuf>,
    scanner: BrokerOutputScanner,
    derived_path: PathBuf,
}

#[derive(Debug)]
struct ToolResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
    error: Option<FrameError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct FrameError {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<Vec<Value>>,
}

#[derive(Debug)]
enum BoundedRead {
    Complete(Vec<u8>),
    TooLarge,
}

#[derive(Debug)]
enum NamedRead {
    Stdout(BoundedRead),
    Stderr(BoundedRead),
}

impl BrokerContext {
    fn load(session: String) -> io::Result<Self> {
        let cwd = env::current_dir()?;
        let config = config::load_config(&cwd)?;
        let path = env::var_os("PATH").unwrap_or_default();
        let executables = resolve_authorized_tools(&config, &path);
        let home = env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME is required for broker state")
        })?;
        let state_dir = home.join(".cmdrvl/state/veil");
        ensure_private_directory(&state_dir)?;

        Ok(Self {
            config,
            cwd,
            session,
            executables,
            scanner: BrokerOutputScanner::new(),
            derived_path: state_dir.join("derived.jsonl"),
        })
    }

    fn process(&self, request: BrokerRequest, enforcement: &str, origin: &str) -> ToolResult {
        let input_bytes = serde_json::to_vec(&request).unwrap_or_default();
        let input_hash = boundary_detectors::hash_match(&input_bytes);
        let empty_hash = boundary_detectors::hash_match(&[]);

        let executable = match self.authorize(&request) {
            Ok(executable) => executable,
            Err(code) => {
                if self
                    .audit(
                        &request.tool,
                        &input_hash,
                        &empty_hash,
                        0,
                        "deny",
                        Some(code),
                        "protected",
                        enforcement,
                        origin,
                    )
                    .is_err()
                {
                    return ToolResult::denied("broker_audit_failed");
                }
                return ToolResult::denied(code);
            }
        };

        let ran = self.working_directory(&request).and_then(|cwd| {
            run_bounded(tool_command(executable, enforcement), &request.argv, &cwd)
        });
        let (stdout, stderr, exit_code) = match ran {
            Ok(result) => result,
            Err(code) => {
                if self
                    .audit(
                        &request.tool,
                        &input_hash,
                        &empty_hash,
                        0,
                        "deny",
                        Some(code),
                        "protected",
                        enforcement,
                        origin,
                    )
                    .is_err()
                {
                    return ToolResult::denied("broker_audit_failed");
                }
                return ToolResult::denied(code);
            }
        };

        let output_bytes = stdout.len().saturating_add(stderr.len());
        if output_bytes > MAX_BROKER_OUTPUT_BYTES {
            let output_hash = hash_streams(&stdout, &stderr);
            if self
                .audit(
                    &request.tool,
                    &input_hash,
                    &output_hash,
                    output_bytes,
                    "deny",
                    Some("broker_output_too_large"),
                    "protected",
                    enforcement,
                    origin,
                )
                .is_err()
            {
                return ToolResult::denied("broker_audit_failed");
            }
            return ToolResult::denied("broker_output_too_large");
        }

        let findings = match self.scanner.scan_streams(&stdout, &stderr) {
            Ok(findings) => findings,
            Err(_) => {
                let output_hash = hash_streams(&stdout, &stderr);
                if self
                    .audit(
                        &request.tool,
                        &input_hash,
                        &output_hash,
                        output_bytes,
                        "deny",
                        Some("broker_output_too_large"),
                        "protected",
                        enforcement,
                        origin,
                    )
                    .is_err()
                {
                    return ToolResult::denied("broker_audit_failed");
                }
                return ToolResult::denied("broker_output_too_large");
            }
        };

        let output_hash = hash_streams(&stdout, &stderr);
        if !findings.is_empty() {
            let details = findings
                .iter()
                .map(|finding| {
                    json!({
                        "pack": format!("{:?}", finding.pack).to_ascii_lowercase(),
                        "rule_id": finding.rule_id,
                        "byte_span": finding.byte_span,
                        "match_hash": finding.match_hash,
                    })
                })
                .collect::<Vec<_>>();
            let reason = findings
                .iter()
                .map(|finding| format!("{}:{}", finding.rule_id, finding.match_hash))
                .collect::<Vec<_>>()
                .join(",");
            if self
                .audit(
                    &request.tool,
                    &input_hash,
                    &output_hash,
                    output_bytes,
                    "deny",
                    Some(&reason),
                    "protected",
                    enforcement,
                    origin,
                )
                .is_err()
            {
                return ToolResult::denied("broker_audit_failed");
            }
            return ToolResult {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 126,
                error: Some(FrameError {
                    code: "broker_output_denied".to_owned(),
                    findings: Some(details),
                }),
            };
        }

        let argv_hash = input_hash.clone();
        if append_derived(
            &self.derived_path,
            &output_hash,
            &request.tool,
            &argv_hash,
            &self.session,
        )
        .is_err()
        {
            if self
                .audit(
                    &request.tool,
                    &input_hash,
                    &output_hash,
                    output_bytes,
                    "deny",
                    Some("broker_derived_registry_failed"),
                    "protected",
                    enforcement,
                    origin,
                )
                .is_err()
            {
                return ToolResult::denied("broker_audit_failed");
            }
            return ToolResult::denied("broker_derived_registry_failed");
        }

        if self
            .audit(
                &request.tool,
                &input_hash,
                &output_hash,
                output_bytes,
                "allow",
                None,
                "derived",
                enforcement,
                origin,
            )
            .is_err()
        {
            return ToolResult::denied("broker_audit_failed");
        }

        ToolResult {
            stdout,
            stderr,
            exit_code,
            error: None,
        }
    }

    /// The directory the tool runs in, with symlinks resolved before it is
    /// compared with the project directory.
    fn working_directory(&self, request: &BrokerRequest) -> Result<PathBuf, &'static str> {
        let Some(requested) = &request.cwd else {
            return Ok(self.cwd.clone());
        };
        let outside = "broker_cwd_outside_project";
        if !requested.is_absolute() {
            return Err(outside);
        }
        let resolved = fs::canonicalize(requested).map_err(|_| outside)?;
        let root = fs::canonicalize(&self.cwd).map_err(|_| outside)?;
        if !resolved.is_dir() || !resolved.starts_with(root) {
            return Err(outside);
        }
        Ok(resolved)
    }

    fn authorize(&self, request: &BrokerRequest) -> Result<&Path, &'static str> {
        if !valid_tool_name(&request.tool) || !DERIVED_TOOLS.contains(&request.tool.as_str()) {
            return Err("broker_tool_unauthorized");
        }
        if request.argv.len() > MAX_ARGUMENTS
            || request.argv.iter().any(|argument| {
                argument.len() > MAX_ARGUMENT_BYTES || argument.chars().any(char::is_control)
            })
        {
            return Err("broker_request_invalid");
        }
        if request
            .argv
            .iter()
            .any(|argument| has_shell_metacharacter(argument))
        {
            return Err("broker_shell_metacharacter");
        }

        let configured = self.config.spine.authorized_tools.iter().any(|name| {
            Path::new(name).file_name().and_then(|name| name.to_str())
                == Some(request.tool.as_str())
        });
        if !configured {
            return Err("broker_tool_unauthorized");
        }
        if self
            .config
            .spine
            .denied_flags
            .find(&request.tool, &request.argv)
            .is_some()
        {
            return Err("broker_flag_forbidden");
        }

        self.executables
            .get(&request.tool)
            .map(PathBuf::as_path)
            .ok_or("broker_tool_unavailable")
    }

    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        tool: &str,
        input_hash: &str,
        output_hash: &str,
        output_bytes: usize,
        decision: &str,
        reason: Option<&str>,
        sensitivity: &str,
        enforcement: &str,
        origin: &str,
    ) -> io::Result<()> {
        let record = AuditRecord {
            ts: timestamp(),
            tool: tool.to_owned(),
            path: output_hash.to_owned(),
            decision: decision.to_owned(),
            reason: reason.map(str::to_owned),
            sensitivity: Some(sensitivity.to_owned()),
            confidence: None,
            session_id: Some(self.session.clone()),
            origin: Some(origin.to_owned()),
            reason_class: None,
            class: None,
            would_deny: decision == "deny",
            path_is_hash: true,
            tool_input: Some(json!({
                "input_hash": input_hash,
                "output_hash": output_hash,
                "output_bytes": output_bytes,
            })),
        };
        append_audit_record_with_enforcement(&self.config.policy.audit_path, &record, enforcement)
    }
}

impl ToolResult {
    fn denied(code: &'static str) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 126,
            error: Some(FrameError {
                code: code.to_owned(),
                findings: None,
            }),
        }
    }
}

/// Run the hidden `--broker` mode used by `veil sandbox`.
pub fn run_broker_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var_os(BROKER_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or("broker socket path is missing")?;
    let session = env::var(BROKER_SESSION_ENV).map_err(|_| "broker session id is missing")?;
    serve(&socket, BrokerContext::load(session)?)?;
    Ok(())
}

fn serve(socket: &Path, context: BrokerContext) -> io::Result<()> {
    let parent = socket.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker socket has no parent directory",
        )
    })?;
    ensure_private_directory(parent)?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    exit_with_launcher(socket.to_path_buf());

    let mut call_number = 0usize;
    loop {
        let (stream, _) = listener.accept()?;
        handle_connection(stream, &context, call_number >= MAX_SESSION_CALLS);
        call_number = call_number.saturating_add(1);
    }
}

/// The launcher holds the other end of the broker's standard input and writes
/// nothing to it. It closes when the launcher goes, however it goes, and then
/// the broker removes its socket and exits.
fn exit_with_launcher(socket: PathBuf) {
    thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
        let _ = fs::remove_file(socket);
        std::process::exit(0);
    });
}

/// What the confined process must not change while the broker is running: the
/// executables the broker will run, as the paths found on `path` and as the
/// files they resolve to, and the broker's own state.
pub fn sandbox_write_denials(
    config: &Config,
    path: &std::ffi::OsStr,
    state_dir: &Path,
) -> io::Result<String> {
    let mut files = Vec::new();
    for (name, executable) in resolve_authorized_tools(config, path) {
        refuse_second_names(&executable)?;
        files.push(executable);
        let found = env::split_paths(path)
            .map(|directory| directory.join(&name))
            .find(|candidate| candidate.is_file());
        if let Some(found) = found
            && let (Some(parent), Some(file)) = (found.parent(), found.file_name())
        {
            files.push(fs::canonicalize(parent)?.join(file));
        }
    }

    seatbelt::write_denials(&files, &[fs::canonicalize(state_dir)?])
}

/// The write denials name paths, and a hard link made before the session is
/// one more path to the same file: through it the confined process could
/// rewrite what the broker runs (bd-wwh). The profile denies new links, so
/// counting them before confinement covers the whole session.
fn refuse_second_names(executable: &Path) -> io::Result<()> {
    let links = fs::metadata(executable)?.nlink();
    if links > 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "authorized tool {} has {links} hard links, so the sandbox cannot stop the confined command from rewriting it through another of its names; replace it with a copy of its own and start the sandbox again",
                executable.display()
            ),
        ));
    }
    Ok(())
}

fn tool_command(executable: &Path, enforcement: &str) -> Command {
    if enforcement == "sandbox" && cfg!(target_os = "macos") {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(seatbelt::NO_FILE_WRITES_PROFILE)
            .arg(executable);
        return command;
    }
    Command::new(executable)
}

fn handle_connection(mut stream: UnixStream, context: &BrokerContext, limit_reached: bool) {
    let cloned = match stream.try_clone() {
        Ok(cloned) => cloned,
        Err(_) => {
            let _ = write_final(&mut stream, &ToolResult::denied("broker_connection_failed"));
            return;
        }
    };
    let result = read_request(&mut BufReader::new(cloned));
    let request_bytes = match result {
        Ok(bytes) => bytes,
        Err(code) => {
            let hash = boundary_detectors::hash_match(code.as_bytes());
            let empty = boundary_detectors::hash_match(&[]);
            let result = result_after_audit(
                context.audit(
                    "broker",
                    &hash,
                    &empty,
                    0,
                    "deny",
                    Some(code),
                    "protected",
                    "sandbox",
                    "broker",
                ),
                code,
            );
            let _ = write_final(&mut stream, &result);
            return;
        }
    };

    if limit_reached {
        let input_hash = boundary_detectors::hash_match(&request_bytes);
        let empty_hash = boundary_detectors::hash_match(&[]);
        let result = result_after_audit(
            context.audit(
                "broker",
                &input_hash,
                &empty_hash,
                0,
                "deny",
                Some("broker_call_limit_reached"),
                "protected",
                "sandbox",
                "broker",
            ),
            "broker_call_limit_reached",
        );
        let _ = write_final(&mut stream, &result);
        return;
    }

    let request = match serde_json::from_slice::<BrokerRequest>(&request_bytes) {
        Ok(request) => request,
        Err(_) => {
            let input_hash = boundary_detectors::hash_match(&request_bytes);
            let empty_hash = boundary_detectors::hash_match(&[]);
            let result = result_after_audit(
                context.audit(
                    "broker",
                    &input_hash,
                    &empty_hash,
                    0,
                    "deny",
                    Some("broker_malformed_request"),
                    "protected",
                    "sandbox",
                    "broker",
                ),
                "broker_malformed_request",
            );
            let _ = write_final(&mut stream, &result);
            return;
        }
    };

    let result = context.process(request, "sandbox", "broker");
    let _ = write_result(&mut stream, result);
}

/// Send a `veil exec` call through the session broker, or use the same
/// authorization/scanning path directly when no sandbox session is active.
pub fn run_exec(tool: String, argv: Vec<String>) -> Result<i32, Box<dyn std::error::Error>> {
    let request = BrokerRequest {
        tool,
        argv,
        cwd: Some(env::current_dir()?),
    };
    // Direct mode confines nothing, so it has no project directory to hold the
    // client to: the context is loaded where the client stands.
    let result = if let Some(socket) = env::var_os(BROKER_SOCKET_ENV) {
        request_over_socket(&PathBuf::from(socket), &request)?
    } else {
        let session = format!("direct-{}", std::process::id());
        let context = BrokerContext::load(session)?;
        context.process(request, "direct", "direct_exec")
    };

    if let Some(error) = result.error {
        eprintln!("veil exec refused: {}", error.code);
        if let Some(findings) = error.findings {
            eprintln!("detector findings: {}", serde_json::to_string(&findings)?);
        }
        return Ok(result.exit_code);
    }

    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;
    Ok(result.exit_code)
}

fn request_over_socket(socket: &Path, request: &BrokerRequest) -> io::Result<ToolResult> {
    let mut stream = UnixStream::connect(socket)?;
    let mut request_bytes = serde_json::to_vec(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    request_bytes.push(b'\n');
    if request_bytes.len() > MAX_REQUEST_BYTES {
        return Ok(ToolResult::denied("broker_request_too_large"));
    }
    stream.write_all(&request_bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    read_result(&mut BufReader::new(stream))
}

fn read_request(reader: &mut BufReader<UnixStream>) -> Result<Vec<u8>, &'static str> {
    let mut request = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| "broker_read_failed")?;
        if available.is_empty() {
            return Err("broker_malformed_request");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if request.len().saturating_add(consumed) > MAX_REQUEST_BYTES {
            return Err("broker_request_too_large");
        }
        request.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            if !reader
                .fill_buf()
                .map_err(|_| "broker_read_failed")?
                .is_empty()
            {
                return Err("broker_malformed_request");
            }
            request.pop();
            return Ok(request);
        }
    }
}

fn write_result(stream: &mut UnixStream, result: ToolResult) -> io::Result<()> {
    if result.error.is_some() {
        return write_final(stream, &result);
    }

    let exit_code = result.exit_code;
    let stdout = result.stdout;
    let stderr = result.stderr;
    for (name, output) in [("stdout", stdout), ("stderr", stderr)] {
        for chunk in output.chunks(OUTPUT_CHUNK_BYTES) {
            serde_json::to_writer(&mut *stream, &json!({"stream": name, "chunk": chunk}))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            stream.write_all(b"\n")?;
        }
    }

    write_final_code(stream, exit_code, None)
}

fn write_final(stream: &mut UnixStream, result: &ToolResult) -> io::Result<()> {
    write_final_code(stream, result.exit_code, result.error.as_ref())
}

fn write_final_code(
    stream: &mut UnixStream,
    exit_code: i32,
    error: Option<&FrameError>,
) -> io::Result<()> {
    let mut frame = json!({"exit_code": exit_code});
    if let Some(error) = error {
        frame["error"] = serde_json::to_value(error)
            .map_err(|failure| io::Error::new(io::ErrorKind::InvalidData, failure))?;
    }
    serde_json::to_writer(&mut *stream, &frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    stream.write_all(b"\n")
}

fn read_result(reader: &mut BufReader<UnixStream>) -> io::Result<ToolResult> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader
            .take((MAX_RESPONSE_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker closed before the final frame",
            ));
        }
        if line.len() > MAX_RESPONSE_FRAME_BYTES || line.last() != Some(&b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broker frame exceeds its size limit",
            ));
        }
        line.pop();
        let frame: Value = serde_json::from_slice(&line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if let Some(stream) = frame.get("stream").and_then(Value::as_str) {
            let bytes: Vec<u8> = serde_json::from_value(
                frame
                    .get("chunk")
                    .cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing chunk"))?,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            match stream {
                "stdout" => stdout.extend(bytes),
                "stderr" => stderr.extend(bytes),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown broker stream",
                    ));
                }
            }
            continue;
        }

        let exit_code = frame
            .get("exit_code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing exit code"))?;
        let error = frame
            .get("error")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|failure| io::Error::new(io::ErrorKind::InvalidData, failure))?;
        return Ok(ToolResult {
            stdout,
            stderr,
            exit_code,
            error,
        });
    }
}

fn resolve_authorized_tools(config: &Config, path: &std::ffi::OsStr) -> BTreeMap<String, PathBuf> {
    let mut resolved = BTreeMap::new();
    for configured in &config.spine.authorized_tools {
        let Some(name) = Path::new(configured)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            continue;
        };
        if !valid_tool_name(name) || !DERIVED_TOOLS.contains(&name) {
            continue;
        }
        if let Some(executable) = find_executable(name, path) {
            resolved.insert(name.to_owned(), executable);
        }
    }
    resolved
}

fn find_executable(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    env::split_paths(path).find_map(|directory| {
        let candidate = directory.join(name);
        let metadata = fs::metadata(&candidate).ok()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
        fs::canonicalize(candidate).ok()
    })
}

fn valid_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool != "."
        && tool != ".."
        && tool.len() <= 128
        && tool
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn has_shell_metacharacter(argument: &str) -> bool {
    argument.chars().any(|character| {
        matches!(
            character,
            ';' | '|'
                | '&'
                | '$'
                | '`'
                | '>'
                | '<'
                | '\''
                | '"'
                | '\\'
                | '*'
                | '?'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '~'
        )
    })
}

fn run_bounded(
    mut command: Command,
    argv: &[String],
    cwd: &Path,
) -> Result<(Vec<u8>, Vec<u8>, i32), &'static str> {
    let mut child = command
        .args(argv)
        .current_dir(cwd)
        .env_remove(BROKER_SOCKET_ENV)
        .env_remove(BROKER_SESSION_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "broker_tool_start_failed")?;
    let stdout = child.stdout.take().ok_or("broker_tool_start_failed")?;
    let stderr = child.stderr.take().ok_or("broker_tool_start_failed")?;
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_reader = thread::spawn(move || {
        let _ = stdout_sender.send(NamedRead::Stdout(read_bounded(stdout)));
    });
    let stderr_reader = thread::spawn(move || {
        let _ = sender.send(NamedRead::Stderr(read_bounded(stderr)));
    });

    let mut stdout_bytes = None;
    let mut stderr_bytes = None;
    let mut oversized = false;
    for _ in 0..2 {
        match receiver.recv().map_err(|_| "broker_output_read_failed")? {
            NamedRead::Stdout(BoundedRead::Complete(bytes)) => stdout_bytes = Some(bytes),
            NamedRead::Stderr(BoundedRead::Complete(bytes)) => stderr_bytes = Some(bytes),
            NamedRead::Stdout(BoundedRead::TooLarge) | NamedRead::Stderr(BoundedRead::TooLarge) => {
                oversized = true;
                let _ = child.kill();
            }
        }
    }
    let status = child.wait().map_err(|_| "broker_tool_wait_failed")?;
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();

    if oversized {
        return Err("broker_output_too_large");
    }
    let stdout = stdout_bytes.ok_or("broker_output_read_failed")?;
    let stderr = stderr_bytes.ok_or("broker_output_read_failed")?;
    let total = stdout.len().saturating_add(stderr.len());
    if total > MAX_BROKER_OUTPUT_BYTES {
        return Err("broker_output_too_large");
    }
    Ok((stdout, stderr, status.code().unwrap_or(128)))
}

fn read_bounded(reader: impl Read) -> BoundedRead {
    let mut output = Vec::new();
    if reader
        .take((MAX_BROKER_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .is_err()
        || output.len() > MAX_BROKER_OUTPUT_BYTES
    {
        BoundedRead::TooLarge
    } else {
        BoundedRead::Complete(output)
    }
}

fn hash_streams(stdout: &[u8], stderr: &[u8]) -> String {
    let mut output = Vec::with_capacity(stdout.len() + stderr.len() + 1);
    output.extend_from_slice(stdout);
    output.push(0);
    output.extend_from_slice(stderr);
    boundary_detectors::hash_match(&output)
}

fn append_derived(
    path: &Path,
    output_hash: &str,
    tool: &str,
    argv_hash: &str,
    session: &str,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_directory(parent)?;
    }
    let record = json!({
        "hash": output_hash,
        "tool": tool,
        "argv_hash": argv_hash,
        "session": session,
        "ts": timestamp(),
    });
    let mut line = serde_json::to_vec(&record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&line)?;
    file.flush()
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker state path must be a real directory",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

fn result_after_audit(audit: io::Result<()>, code: &'static str) -> ToolResult {
    if audit.is_ok() {
        ToolResult::denied(code)
    } else {
        ToolResult::denied("broker_audit_failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_protocol_rejects_shell_strings_unknown_fields_and_path_escape() {
        assert!(
            serde_json::from_slice::<BrokerRequest>(br#"{"tool":"shape","argv":["a.csv"]}"#)
                .is_ok()
        );
        assert!(
            serde_json::from_slice::<BrokerRequest>(
                br#"{"tool":"shape","command":"cat x","argv":[]}"#
            )
            .is_err()
        );
        assert!(!valid_tool_name("../shape"));
        assert!(has_shell_metacharacter("protected.txt; cat"));
        assert!(!has_shell_metacharacter("/work/protected data.csv"));
    }

    #[test]
    fn socket_request_reader_refuses_extra_lines_and_oversize_input() {
        let (mut client, server) = UnixStream::pair().expect("local socket pair");
        client
            .write_all(b"{\"tool\":\"shape\",\"argv\":[]}\nextra\n")
            .expect("request write");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("request half-close");
        assert_eq!(
            read_request(&mut BufReader::new(server)),
            Err("broker_malformed_request")
        );

        let (mut client, server) = UnixStream::pair().expect("second local socket pair");
        let writer = thread::spawn(move || {
            client
                .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
                .expect("oversized request write");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("request half-close");
        });
        assert_eq!(
            read_request(&mut BufReader::new(server)),
            Err("broker_request_too_large")
        );
        writer.join().expect("request writer should finish");
    }
}

#[cfg(all(test, feature = "proptest"))]
mod properties {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proptest::prelude::*;

    use super::*;

    /// A broker whose `shape` is `/bin/echo`, so a generated argument is the
    /// tool's output.
    fn echo_broker(case: &Path) -> BrokerContext {
        let mut config = config::load_config(case).expect("default config");
        config.policy.audit_path = case.join("audit.jsonl");
        BrokerContext {
            config,
            cwd: case.to_path_buf(),
            session: "property".to_owned(),
            executables: BTreeMap::from([("shape".to_owned(), PathBuf::from("/bin/echo"))]),
            scanner: BrokerOutputScanner::new(),
            derived_path: case.join("derived.jsonl"),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// An output is registered exactly when the client receives it: whole,
        /// under the registered hash. A refused one is neither.
        #[test]
        fn an_output_is_registered_exactly_when_the_client_receives_it(
            words in "[a-z]{1,12}( [a-z]{1,12}){0,6}",
            secret in any::<bool>(),
        ) {
            static CASE: AtomicUsize = AtomicUsize::new(0);
            let case = env::temp_dir().join(format!(
                "veil-broker-property-{}-{}-{}",
                std::process::id(),
                timestamp(),
                CASE.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir_all(&case).expect("case directory");
            let broker = echo_broker(&case);
            let output = if secret {
                format!("{words} AKIAIOSFODNN7EXAMPLE")
            } else {
                words
            };
            let request = BrokerRequest {
                tool: "shape".to_owned(),
                argv: vec![output.clone()],
                cwd: None,
            };

            // through the socket framing, which is how output enters a sandbox
            let (mut server, client) = UnixStream::pair().expect("socket pair");
            write_result(&mut server, broker.process(request, "direct", "property"))
                .expect("result is framed");
            drop(server);
            let received = read_result(&mut BufReader::new(client)).expect("client reads");
            let registry = fs::read_to_string(&broker.derived_path).unwrap_or_default();

            if secret {
                prop_assert!(received.error.is_some());
                prop_assert!(received.stdout.is_empty() && received.stderr.is_empty());
                prop_assert!(registry.is_empty());
            } else {
                prop_assert!(received.error.is_none());
                let echoed = format!("{output}\n").into_bytes();
                prop_assert_eq!(&received.stdout, &echoed);
                let record: Value = serde_json::from_str(registry.trim()).expect("one record");
                let delivered = hash_streams(&received.stdout, &received.stderr);
                prop_assert_eq!(record["hash"].as_str(), Some(delivered.as_str()));
            }
        }
    }
}
