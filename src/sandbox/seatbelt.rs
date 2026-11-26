//! macOS Seatbelt profile compiler.
//!
//! Seatbelt has path rules rather than a glob rule. Exact paths and whole
//! protected directory roots become literal/subpath denies. Other globs are
//! expanded against the filesystem at compile time under a fixed entry budget;
//! a new file matching one of those patterns needs the profile to be compiled
//! again. Symlink spellings and resolved targets are both denied.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crate::allowlist::SafePathMatcher;
use crate::config::{self, Config};

/// Maximum number of filesystem entries examined while expanding one policy.
pub const MAX_GLOB_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledProfile {
    /// The profile text accepted by `/usr/bin/sandbox-exec`.
    pub profile: String,
    /// Limits callers should show before someone relies on the profile.
    pub warnings: Vec<String>,
    /// Number of distinct path-deny rules emitted (the `file-link` rule is not
    /// included).
    pub path_rules: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuleKind {
    Literal,
    Subpath,
}

impl RuleKind {
    fn filter(&self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Subpath => "subpath",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DenyRule {
    path: PathBuf,
    kind: RuleKind,
}

/// Compile `[sensitivity].protected` from the already-merged configuration.
/// Relative patterns are resolved against `project_root`, matching the
/// workspace a sandbox invocation is about to launch. This deliberately
/// treats a relative pattern as workspace-scoped even though hook matching
/// also recognizes matching suffixes outside the workspace.
pub fn compile(config: &Config, project_root: &Path) -> io::Result<CompiledProfile> {
    let mut compiled = compile_with_limit(config, project_root, MAX_GLOB_ENTRIES)?;
    if let Some(home) = std::env::var_os("HOME") {
        compiled.profile.push_str(&read_own_settings(&absolute_path(
            Path::new(&home),
            Path::new("/"),
        )?)?);
    }
    compiled.profile.push_str(&outside_denials(
        std::env::var_os("TMUX").as_deref(),
        std::env::var_os("TMUX_TMPDIR").as_deref(),
    )?);
    compiled
        .profile
        .push_str(&policy_write_denials(project_root)?);
    Ok(compiled)
}

/// Rules that keep a confined command from changing what a later session takes
/// its policy from. A session reads the `.veil.toml` nearest to where it
/// starts, so no file of that name may be written anywhere, in any case. The
/// user's settings and the project config in force are refused by path too,
/// with whatever they link to, and so is putting something else in the place of
/// a directory or link on the way to them. One of those files with a second
/// hard link is refused outright: the other name would stay writable.
fn policy_write_denials(project_root: &Path) -> io::Result<String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let sources = config::policy_sources(project_root, home.as_deref(), xdg_config_home.as_deref());
    let absolute = |paths: &[PathBuf]| {
        paths
            .iter()
            .map(|path| absolute_path(path, project_root))
            .collect::<io::Result<Vec<_>>>()
    };
    let (files, directories) = (absolute(&sources.files)?, absolute(&sources.directories)?);

    let mut kept_files = Vec::new();
    for file in &files {
        let target = follow_links(file);
        if let Ok(metadata) = fs::metadata(&target)
            && metadata.is_file()
            && metadata.nlink() > 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "veil settings file {} has {} hard links, so the sandbox cannot stop the confined command from rewriting it through another of its names; replace it with a copy of its own and start the sandbox again",
                    target.display(),
                    metadata.nlink()
                ),
            ));
        }
        kept_files.push(target);
    }
    let kept_directories = directories
        .iter()
        .map(|directory| follow_links(directory))
        .collect::<Vec<_>>();

    let mut rules =
        String::from("(deny file-write* (regex #\"/[.][vV][eE][iI][lL][.][tT][oO][mM][lL]$\"))\n");
    rules.push_str(&write_denials(&kept_files, &kept_directories)?);

    let mut lines = BTreeSet::new();
    for path in files.iter().chain(&directories) {
        keep_links(path, &mut lines)?;
        // and nothing may be put where there is nothing yet
        for name in walk_links(path).1 {
            if fs::symlink_metadata(&name).is_err() {
                lines.insert(format!(
                    "(deny file-write-create (literal \"{}\"))\n",
                    seatbelt_string(&name)?
                ));
            }
        }
    }
    rules.extend(lines);

    Ok(rules)
}

/// The profile allows what it does not name, and some of that acts outside the
/// sandbox. These rules close ways found open: signalling a process that is
/// not in it, asking LaunchServices (as `open` does) to start an application,
/// and asking a tmux server to run a command. Apple events are refused as
/// well; no test sends one, because that can raise a permission dialog.
///
/// `tmux` is `$TMUX`, which starts with the socket of the server this session
/// is in, and `tmux_tmpdir` is `$TMUX_TMPDIR`, where tmux makes its sockets
/// instead of in `/tmp`. A server listening anywhere else is not covered.
fn outside_denials(tmux: Option<&OsStr>, tmux_tmpdir: Option<&OsStr>) -> io::Result<String> {
    let mut rules = String::from(
        "(deny signal)\n\
         (allow signal (target same-sandbox))\n\
         (deny lsopen)\n\
         (deny appleevent-send)\n",
    );

    // tmux keeps its sockets in a directory named `tmux-<user number>`
    let mut sockets = vec![String::from(
        r##"(regex #"^/private/tmp/tmux-[0-9]+(/|$)")"##,
    )];
    if let Some(directory) = tmux_tmpdir.and_then(|path| fs::canonicalize(path).ok()) {
        sockets.push(format!(
            "(require-all (subpath \"{}\") (regex #\"/tmux-[0-9]+(/|$)\"))",
            seatbelt_string(&directory)?
        ));
        for above in directory.ancestors().filter(|path| path.parent().is_some()) {
            rules.push_str(&format!(
                "(deny file-write-unlink (literal \"{}\"))\n",
                seatbelt_string(above)?
            ));
        }
    }
    for filter in sockets {
        // a rule names a path, so the socket must also keep its name
        rules.push_str(&format!(
            "(deny network-outbound {filter})\n(deny file-write* {filter})\n"
        ));
    }

    // `path,server process,session`
    if let Some(value) = tmux
        && let Some(socket) = value.as_bytes().rsplitn(3, |byte| *byte == b',').nth(2)
    {
        let socket = Path::new(OsStr::from_bytes(socket));
        if let (Some(parent), Some(name)) = (socket.parent(), socket.file_name())
            && let Ok(parent) = fs::canonicalize(parent)
        {
            let socket = parent.join(name);
            rules.push_str(&format!(
                "(deny network-outbound (literal \"{}\"))\n",
                seatbelt_string(&socket)?
            ));
            rules.push_str(&write_denials(&[socket], &[])?);
        }
    }

    Ok(rules)
}

/// veil's settings are under `~/.cmdrvl/config`, which is protected by default,
/// and the hook inside the sandbox has to read them. These rules, which come
/// after the denials, allow reading that one file.
///
/// A confined session can create any of these names that is missing, and must
/// not be able to make something else readable in the next session. So
/// `config` and `config/veil` must be real directories, and a settings file
/// that is a link is followed only inside `config/veil`.
fn read_own_settings(home: &Path) -> io::Result<String> {
    let cmdrvl = home.join(".cmdrvl");
    let (Ok(root), Ok(directory)) = (
        fs::canonicalize(&cmdrvl),
        fs::canonicalize(cmdrvl.join("config/veil")),
    ) else {
        return Ok(String::new());
    };
    let settings = directory.join("config.toml");
    let Ok(metadata) = fs::symlink_metadata(&settings) else {
        return Ok(String::new());
    };
    if directory != root.join("config/veil") {
        return Ok(String::new());
    }

    let mut readable = vec![settings.clone()];
    if metadata.is_symlink()
        && let Ok(target) = fs::canonicalize(&settings)
        && target.starts_with(&directory)
    {
        readable.push(target);
    }
    let mut rules = String::new();
    for path in readable {
        rules.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            seatbelt_string(&path)?
        ));
    }
    Ok(rules)
}

fn compile_with_limit(
    config: &Config,
    project_root: &Path,
    max_entries: usize,
) -> io::Result<CompiledProfile> {
    let project_root = absolute_path(project_root, Path::new("/"))?;
    let mut rules = BTreeSet::new();
    let mut warnings = vec![
        "(deny file-link) prevents the confined process from creating new hard links; it does not block reads through hard-link aliases created before confinement.".to_owned(),
        "This profile compiles configured [sensitivity].protected paths; hook-only built-in path classifiers are not expanded into Seatbelt rules.".to_owned(),
        "This compiler adds filesystem read denials only; it does not restrict network access or revoke read-capable file descriptors opened before confinement.".to_owned(),
        "sandbox-exec is deprecated; availability and profile behavior must be checked on each supported macOS release.".to_owned(),
        format!(
            "Relative [sensitivity].protected patterns are rooted at the sandbox project directory {}; matching suffixes outside that directory are not covered.",
            project_root.display()
        ),
    ];
    let mut entries = 0usize;

    for raw in &config.sensitivity.protected {
        let pattern = resolve_pattern(raw, &project_root)?;

        if let Some(root) = subpath_pattern_root(&pattern) {
            add_path(&root, true, &mut rules)?;
            continue;
        }

        if !pattern.to_string_lossy().contains('*') {
            add_path(&pattern, false, &mut rules)?;
            continue;
        }

        warnings.push(format!(
            "glob `{raw}` was expanded from its current filesystem matches; newly matching paths are not covered until this profile is recompiled."
        ));
        let matcher_pattern = pattern
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected glob is not valid UTF-8 and cannot be matched",
                )
            })?
            .trim_start_matches('/');
        let matcher = SafePathMatcher::from_patterns([matcher_pattern]);
        expand_glob(
            &matcher,
            &pattern,
            &project_root,
            max_entries,
            &mut entries,
            &mut rules,
        )?;
    }

    let path_rules = rules.len();
    let mut profile = String::from("(version 1)\n(allow default)\n(deny file-link)\n");
    for rule in &rules {
        let path = seatbelt_string(&rule.path)?;
        profile.push_str(&format!(
            "(deny file-read* ({} \"{path}\"))\n",
            rule.kind.filter()
        ));
    }
    profile.push_str(&keep_in_place(&rules)?);

    Ok(CompiledProfile {
        profile,
        warnings,
        path_rules,
    })
}

fn expand_glob(
    matcher: &SafePathMatcher,
    pattern: &Path,
    project_root: &Path,
    max_entries: usize,
    entries_seen: &mut usize,
    rules: &mut BTreeSet<DenyRule>,
) -> io::Result<()> {
    let anchor = glob_anchor(pattern, project_root);
    if !anchor.exists() {
        return Ok(());
    }

    let mut pending = VecDeque::from([anchor]);
    let mut visited = HashSet::new();
    while let Some(directory) = pending.pop_front() {
        let directory = absolute_path(&directory, project_root)?;
        let visit_key = fs::canonicalize(&directory).unwrap_or_else(|_| directory.clone());
        if !visited.insert(visit_key) {
            continue;
        }

        if matcher.covers_directory(&directory) {
            add_path(&directory, true, rules)?;
            continue;
        }

        let contents = fs::read_dir(&directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot expand protected glob beneath {}: {error}",
                    directory.display()
                ),
            )
        })?;

        for entry in contents {
            let entry = entry?;
            *entries_seen = entries_seen.saturating_add(1);
            if *entries_seen > max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "protected glob expansion exceeded the {max_entries}-entry limit; refusing an incomplete Seatbelt profile"
                    ),
                ));
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let target = fs::canonicalize(&path).ok();
            let target_metadata = target
                .as_deref()
                .and_then(|target| fs::metadata(target).ok());

            if matcher.is_safe(&path) {
                add_path(&path, metadata.is_dir(), rules)?;
            }
            if let (Some(target), Some(metadata)) = (target.as_deref(), target_metadata.as_ref())
                && (matcher.is_safe(target)
                    || (metadata.is_dir() && matcher.covers_directory(target)))
            {
                add_path(&path, metadata.is_dir(), rules)?;
                add_path(target, metadata.is_dir(), rules)?;
            }

            if metadata.is_dir() {
                pending.push_back(path);
            } else if metadata.file_type().is_symlink()
                && target_metadata
                    .as_ref()
                    .is_some_and(|target| target.is_dir())
                && let Some(target) = target
            {
                // Keep the alias path while walking so a glob rooted beneath
                // the alias matches its children. Canonical targets are used
                // for cycle detection and are added to the deny rules too.
                if matcher.is_safe(&path)
                    || matcher.covers_directory(&path)
                    || matcher.covers_directory(&target)
                {
                    add_path(&path, true, rules)?;
                    add_path(&target, true, rules)?;
                } else {
                    pending.push_back(path);
                }
            }
        }
    }

    Ok(())
}

fn glob_anchor(pattern: &Path, project_root: &Path) -> PathBuf {
    let mut prefix = PathBuf::new();
    for component in pattern.components() {
        if component.as_os_str().to_string_lossy().contains('*') {
            break;
        }
        prefix.push(component.as_os_str());
    }

    if prefix.as_os_str().is_empty() {
        return project_root.to_path_buf();
    }
    if prefix.is_dir() {
        prefix
    } else {
        prefix
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(project_root)
            .to_path_buf()
    }
}

fn subpath_pattern_root(pattern: &Path) -> Option<PathBuf> {
    let text = pattern.to_str()?;
    let root = text.strip_suffix("/**")?;
    if root.contains('*') {
        return None;
    }
    Some(PathBuf::from(root))
}

pub(super) fn resolve_pattern(pattern: &str, project_root: &Path) -> io::Result<PathBuf> {
    let home_suffix = pattern
        .strip_prefix('~')
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'));
    let expanded = if let Some(suffix) = home_suffix {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot resolve protected pattern `{pattern}` without HOME"),
            ));
        };
        home.join(suffix.strip_prefix('/').unwrap_or(suffix))
    } else {
        PathBuf::from(pattern)
    };
    absolute_path(&expanded, project_root)
}

fn absolute_path(path: &Path, base: &Path) -> io::Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if !normalized.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sandbox path is not absolute: {}", path.display()),
        ));
    }
    Ok(normalized)
}

fn add_path(path: &Path, directory_hint: bool, rules: &mut BTreeSet<DenyRule>) -> io::Result<()> {
    let path = absolute_path(path, Path::new("/"))?;
    let metadata = fs::metadata(&path).ok();
    let kind = if directory_hint || metadata.as_ref().is_some_and(fs::Metadata::is_dir) {
        RuleKind::Subpath
    } else {
        RuleKind::Literal
    };
    add_rule(path.clone(), kind.clone(), rules)?;

    let target = fs::canonicalize(&path).unwrap_or_else(|_| follow_links(&path));
    if target != path {
        let target_kind = match fs::metadata(&target) {
            Ok(metadata) if metadata.is_dir() => RuleKind::Subpath,
            Ok(_) => RuleKind::Literal,
            // nothing there yet: it is what the configured pattern says it is
            Err(_) => kind,
        };
        add_rule(target, target_kind, rules)?;
    }

    Ok(())
}

/// The name Seatbelt will compare for a path that does not exist yet: every
/// symlink on the way is followed, including one whose target is missing, and
/// the parts that do not exist are kept as written. Past 40 links the rest is
/// kept as written, which is what the kernel refuses to resolve too.
fn follow_links(path: &Path) -> PathBuf {
    walk_links(path).0
}

/// [`follow_links`], and every name passed on the way there, each with the
/// links before it already followed.
fn walk_links(path: &Path) -> (PathBuf, Vec<PathBuf>) {
    let mut passed = Vec::new();
    let mut pending = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect::<VecDeque<_>>();
    let mut resolved = PathBuf::new();
    let mut followed = 0;
    while let Some(part) = pending.pop_front() {
        // a target written `./name` must not leave the `.` in the names passed
        if part == "." {
            continue;
        }
        if part == ".." {
            resolved.pop();
            continue;
        }
        // joining "/" starts again from the root, as an absolute target does
        let next = resolved.join(&part);
        if next.parent().is_some() {
            passed.push(next.clone());
        }
        match fs::read_link(&next) {
            Ok(target) if followed < 40 => {
                followed += 1;
                for component in target.components().rev() {
                    pending.push_front(component.as_os_str().to_owned());
                }
            }
            _ => resolved = next,
        }
    }
    (resolved, passed)
}

/// Adds the rules that keep `path` leading where it leads now: no link it
/// passes through may be replaced, and no directory it passes through renamed
/// or removed. A later session follows the same links, so one that is
/// retargeted would hand it another file.
fn keep_links(path: &Path, lines: &mut BTreeSet<String>) -> io::Result<()> {
    for name in walk_links(path).1 {
        let operation = match fs::symlink_metadata(&name) {
            Ok(metadata) if metadata.is_symlink() => "file-write*",
            _ => "file-write-unlink",
        };
        lines.insert(format!(
            "(deny {operation} (literal \"{}\"))\n",
            seatbelt_string(&name)?
        ));
    }
    Ok(())
}

/// Rules, to append to a compiled profile, that keep each of `paths` leading
/// where it leads now. Paths must be absolute. What they lead to is not made
/// unwritable here; [`write_denials`] does that.
pub fn keep_resolution(paths: &[PathBuf]) -> io::Result<String> {
    let mut lines = BTreeSet::new();
    for path in paths {
        keep_links(path, &mut lines)?;
    }
    Ok(lines.into_iter().collect())
}

fn add_rule(path: PathBuf, kind: RuleKind, rules: &mut BTreeSet<DenyRule>) -> io::Result<()> {
    if path.to_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path is not valid UTF-8 and cannot be encoded in a Seatbelt profile",
        ));
    }
    rules.insert(DenyRule { path, kind });
    Ok(())
}

/// A profile under which a process can write no file. The broker runs each tool
/// under it, so no flag or subcommand of a tool (`--output`, a copy into an
/// evidence pack, a sliced CSV) can put unscanned bytes where the confined
/// client reads them.
pub const NO_FILE_WRITES_PROFILE: &str = "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (literal \"/dev/null\"))\n";

/// How every broker socket's file name starts. The profile refuses sockets by
/// name, so this is part of the boundary.
pub const BROKER_SOCKET_PREFIX: &str = "veil-broker-";

/// Rules, to append to a compiled profile, that let the confined process
/// connect to its own session's broker and to no other. Another broker answers
/// with its own session's files and policy, which this session may deny
/// (bd-xa6). `broker_dir` is where this user's brokers listen and `own` is this
/// session's socket, both with symlinked directories resolved.
///
/// A session started under another `HOME` listens elsewhere, so a socket is
/// refused by its name wherever it is, and may not be renamed or removed.
/// `broker_dir` is refused whole as well.
pub fn broker_reach(broker_dir: &Path, own: &Path) -> io::Result<String> {
    let any = format!("(regex #\"/{BROKER_SOCKET_PREFIX}[^/]*[.]sock$\")");
    Ok(format!(
        "(deny network-outbound {any})\n\
         (deny network-outbound (subpath \"{}\"))\n\
         (allow network-outbound (literal \"{}\"))\n\
         (deny file-write* {any})\n",
        seatbelt_string(broker_dir)?,
        seatbelt_string(own)?,
    ))
}

/// A path rule follows a name, not a file. These rules keep protected content
/// from getting a name the read denials do not cover: no protected path, and no
/// directory above one, may be renamed, swapped or removed, and no directory
/// above one may be cloned. macOS checks a `clonefile(2)` of a directory
/// against that directory alone, and the clone carries everything beneath it.
fn keep_in_place(rules: &BTreeSet<DenyRule>) -> io::Result<String> {
    let mut lines = BTreeSet::new();
    for rule in rules {
        // the rules hold each protected path as configured and as resolved,
        // and neither names what lies between the two
        keep_links(&rule.path, &mut lines)?;
        lines.insert(format!(
            "(deny file-write-unlink ({} \"{}\"))\n",
            rule.kind.filter(),
            seatbelt_string(&rule.path)?
        ));
        for ancestor in rule.path.ancestors().skip(1) {
            let ancestor_text = seatbelt_string(ancestor)?;
            lines.insert(format!("(deny file-clone (literal \"{ancestor_text}\"))\n"));
            if ancestor.parent().is_some() {
                lines.insert(format!(
                    "(deny file-write-unlink (literal \"{ancestor_text}\"))\n"
                ));
            }
        }
    }
    Ok(lines.into_iter().collect())
}

/// A rule, to append to a compiled profile, that keeps the confined process from
/// opening the file at `path` for its contents. It is how veil tells that it is
/// confined (see [`super::marker`]). `path` has symlinked directories resolved.
pub fn refuse_opening(path: &Path) -> io::Result<String> {
    Ok(format!(
        "(deny file-read-data (literal \"{}\"))\n",
        seatbelt_string(path)?
    ))
}

/// Rules, to append to a compiled profile, that keep the confined process from
/// changing `files` or anything under `subtrees`. No directory above one of
/// them may be renamed or removed, which would let another take its place.
/// Paths must be absolute with symlinked directories resolved, as Seatbelt
/// compares them.
pub fn write_denials(files: &[PathBuf], subtrees: &[PathBuf]) -> io::Result<String> {
    let mut rules = BTreeSet::new();
    let targets = files
        .iter()
        .map(|path| ("literal", path))
        .chain(subtrees.iter().map(|path| ("subpath", path)));

    for (kind, path) in targets {
        rules.insert(format!(
            "(deny file-write* ({kind} \"{}\"))\n",
            seatbelt_string(path)?
        ));
        for ancestor in path.ancestors().skip(1) {
            if ancestor.parent().is_some() {
                rules.insert(format!(
                    "(deny file-write-unlink (literal \"{}\"))\n",
                    seatbelt_string(ancestor)?
                ));
            }
        }
    }

    Ok(rules.into_iter().collect())
}

fn seatbelt_string(path: &Path) -> io::Result<String> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path is not valid UTF-8 and cannot be encoded in a Seatbelt profile",
        )
    })?;
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "protected path contains a control character: {}",
                path.display()
            ),
        ));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AllowlistConfig, Config, DynamicArgsMode, McpConfig, PolicyConfig, PolicyMode,
        SensitivityConfig, SpineConfig,
    };
    use crate::protected_corpus::CorpusLimits;
    use crate::spine::DeniedFlags;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "veil-seatbelt-profile-{}-{time}-{count}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture root");
        path
    }

    fn config(protected: Vec<PathBuf>) -> Config {
        Config {
            sensitivity: SensitivityConfig {
                protected: protected
                    .into_iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
            },
            allowlist: AllowlistConfig {
                safe_patterns: Vec::new(),
            },
            spine: SpineConfig {
                authorized_tools: Vec::new(),
                denied_flags: DeniedFlags::default(),
            },
            policy: PolicyConfig {
                default: PolicyMode::Deny,
                egress: Some(PolicyMode::Warn),
                audit_log: false,
                audit_path: PathBuf::from("/tmp/veil-seatbelt-test-audit.jsonl"),
                audit_inputs: false,
                require_dcg: false,
                dynamic_args: DynamicArgsMode::Deny,
            },
            protected_corpus: CorpusLimits::default(),
            mcp: McpConfig::default(),
        }
    }

    #[test]
    fn exact_files_and_directory_roots_become_different_deny_rules() {
        let root = temp_dir();
        let directory = root.join("data");
        fs::create_dir_all(&directory).expect("protected directory");
        let file = root.join("one.csv");
        fs::write(&file, "secret\n").expect("protected file");

        let profile =
            compile(&config(vec![directory.join("**"), file.clone()]), &root).expect("profile");

        assert!(profile.profile.contains(&format!(
            "(deny file-read* (subpath \"{}\"))",
            directory.display()
        )));
        assert!(profile.profile.contains(&format!(
            "(deny file-read* (literal \"{}\"))",
            file.display()
        )));
        assert!(profile.profile.contains("(deny file-link)"));
        assert!(profile.path_rules >= 2);
    }

    #[test]
    fn a_symlink_to_a_protected_file_and_its_target_are_both_denied() {
        let root = temp_dir();
        let protected = root.join("data/secret.csv");
        fs::create_dir_all(protected.parent().expect("parent")).expect("protected dir");
        fs::write(&protected, "sensitive\n").expect("protected file");
        let alias = root.join("outside-link.csv");
        std::os::unix::fs::symlink(&protected, &alias).expect("symlink alias");

        let profile = compile(&config(vec![alias.clone()]), &root).expect("profile");

        let resolved = fs::canonicalize(&protected).expect("resolved protected target");
        for path in [&resolved, &alias] {
            assert!(profile.profile.contains(&format!(
                "(deny file-read* (literal \"{}\"))",
                path.display()
            )));
        }
    }

    #[test]
    fn a_glob_is_expanded_and_warns_that_new_matches_need_recompilation() {
        let root = temp_dir();
        let directory = root.join("reports");
        fs::create_dir_all(&directory).expect("report directory");
        let protected = directory.join("secret.csv");
        fs::write(&protected, "sensitive\n").expect("protected file");
        let pattern = PathBuf::from("**/secret.csv");

        let profile = compile(&config(vec![pattern]), &root).expect("profile");

        assert!(profile.profile.contains(&format!(
            "(deny file-read* (literal \"{}\"))",
            protected.display()
        )));
        assert!(
            profile
                .warnings
                .iter()
                .any(|warning| warning.contains("newly matching paths"))
        );
    }

    #[test]
    fn an_incomplete_glob_expansion_fails_closed() {
        let root = temp_dir();
        fs::write(root.join("one.csv"), "sensitive\n").expect("protected file");

        let error = compile_with_limit(&config(vec![root.join("*.csv")]), &root, 0)
            .expect_err("a zero-entry budget cannot prove a complete profile");

        assert!(error.to_string().contains("refusing an incomplete"));
    }
}
