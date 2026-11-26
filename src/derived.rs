#![forbid(unsafe_code)]

//! Derived outputs (bd-3qw): content veil itself saw a spine tool produce.
//!
//! `~/.cmdrvl/state/veil/derived.jsonl` turns a deny into an allow: a Read or
//! Grep of a file veil would refuse is allowed when the file's bytes are
//! registered. So an entry has to be hard to forge and hard to earn.
//!
//! - **Forging.** Every record carries a MAC under `derived.key`, so a line
//!   anyone else writes unlocks nothing. No tool call veil sees may read or
//!   write the key or the registry ([`VeilState`]), whatever the policy mode.
//!   A key or registry that is a symlink, or has a second name made by a hard
//!   link (bd-oao), is refused by every reader and writer.
//! - **Earning.** Only the broker writes records. It registers content only if
//!   the detectors pass it and it repeats nothing from a file veil would refuse
//!   to show ([`Sources`]). A file written under `--out` is registered only if
//!   its path did not exist before the run.
//!
//! # The copy check
//!
//! Both sides are compared with ASCII letters lowercased and every run of white
//! space made one space. Content of 64 bytes or more is refused when it repeats
//! 95 bytes in a row of a source (a shorter run is caught only if it lines up
//! with a window). Content of 24 to 63 bytes is refused when any 24 bytes of it
//! are in a source. Content identical to a source is refused at any length. A
//! tool that drops or reorders columns, re-encodes or paraphrases is not seen
//! as copying: the registry is no stronger than this check and the detectors.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::allowlist::SafePathMatcher;
use crate::audit::{ROTATE_BYTES, ROTATED_FILES, lock_in_time, rotate_if_full, rotated_path};
use crate::broker_output::{BrokerOutputScanner, MAX_BROKER_OUTPUT_BYTES};
use crate::config::{Config, PolicyMode, is_cmdrvl_config_protection_pattern, project_directory};
use crate::evaluator::{EvaluationInput, PolicyMatchers, evaluate_access_with};
use crate::extract::PathExposure;
use crate::packs::PackRegistry;
use crate::protected_corpus::absolute_pattern_roots;
use crate::types::{DecisionAction, ToolKind};

/// The largest file a Read or Grep checks against the registry.
pub const MAX_VERIFY_BYTES: u64 = 64 * 1024 * 1024;

/// Where veil keeps the registry and its key, beneath the home directory.
const STATE_RELATIVE: &str = ".cmdrvl/state/veil";
pub const REGISTRY_FILE: &str = "derived.jsonl";
pub const KEY_FILE: &str = "derived.key";
/// Every file of the registry's: the key, the registry, its rotated files, its
/// lock files and the key while it is being made.
const STATE_PREFIX: &str = "derived.";

const KEY_BYTES: usize = 32;
const MAC_CONTEXT: &[u8] = b"veil.derived.v1\n";
/// A registry file past this size was not left by veil, which rotates at
/// [`ROTATE_BYTES`] before it appends.
const MAX_REGISTRY_FILE_BYTES: u64 = 4 * ROTATE_BYTES;

/// How much of the files veil would not show one `veil exec` call compares with.
const MAX_SOURCE_FILES: usize = 10_000;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_WALK_ENTRIES: usize = 100_000;
/// How much of a directory written under `--out` one call registers from.
const MAX_OUTPUT_FILES: usize = 256;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The copy check's windows, in bytes of normalized text.
const WINDOW: usize = 64;
const SHORT_WINDOW: usize = 24;
const STRIDE: usize = 32;

const VCS_DIRECTORIES: [&str; 3] = [".git", ".hg", ".svn"];

/// The registry and key of one home directory, as paths a tool call might name.
#[derive(Clone, Debug)]
pub struct VeilState {
    /// The state directory as spelled and with its symlinks followed.
    directories: Vec<PathBuf>,
}

impl VeilState {
    pub fn at(directory: &Path) -> Self {
        let mut directories = vec![directory.to_path_buf()];
        let resolved = resolve_links(directory);
        if resolved != directory {
            directories.push(resolved);
        }
        Self { directories }
    }

    pub fn from_env() -> Option<Self> {
        home_directory().map(|home| Self::at(&home.join(STATE_RELATIVE)))
    }

    /// `path` is the key, the registry, one of their rotated, lock or temporary
    /// files, or the directory that holds them, by any name: through symlinks
    /// (a dangling one too), in another letter case, or as a hard link.
    pub fn holds(&self, path: &Path) -> bool {
        let resolved = resolve_links(path);
        let named = [path, resolved.as_path()].into_iter().any(|candidate| {
            self.directories.iter().any(|directory| {
                same_name(candidate, directory)
                    || (candidate
                        .parent()
                        .is_some_and(|parent| same_name(parent, directory))
                        && candidate.file_name().is_some_and(is_state_file_name))
            })
        });
        named || self.glob_reaches(path) || self.is_another_name(path)
    }

    /// Whether a shell could expand the glob `path` to the state directory, to
    /// one of the two directories above it or to a file of veil's in it:
    /// `cat ~/.cmdrvl/state/veil/*` reads the key.
    fn glob_reaches(&self, path: &Path) -> bool {
        let is_glob = path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|byte| matches!(byte, b'*' | b'?' | b'['));
        if !is_glob {
            return false;
        }

        let parts: Vec<&[u8]> = path
            .components()
            .map(|part| part.as_os_str().as_encoded_bytes())
            .collect();
        self.directories.iter().any(|directory| {
            let wanted: Vec<&[u8]> = directory
                .components()
                .map(|part| part.as_os_str().as_encoded_bytes())
                .collect();
            if parts.len() + 2 < wanted.len() || parts.len() > wanted.len() + 1 {
                return false;
            }
            let directories_match = parts
                .iter()
                .zip(&wanted)
                .all(|(part, name)| could_expand_to(part, name));
            // one part more than the directory has: a file in it
            let file_matches = parts.get(wanted.len()).is_none_or(|part| {
                part.get(..STATE_PREFIX.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(STATE_PREFIX.as_bytes()))
                    || [KEY_FILE, REGISTRY_FILE]
                        .iter()
                        .any(|file| could_expand_to(part, file.as_bytes()))
            });
            directories_match && file_matches
        })
    }

    /// `path` is `~/.cmdrvl` or `~/.cmdrvl/state`: moving, replacing or
    /// linking one takes the key with it.
    pub fn is_container(&self, path: &Path) -> bool {
        let resolved = resolve_links(path);
        self.directories.iter().any(|directory| {
            directory
                .ancestors()
                .skip(1)
                .take(2)
                .any(|container| same_name(path, container) || same_name(&resolved, container))
        })
    }

    /// The state directory is `path` or somewhere beneath it, so a tool handed
    /// `path` as a tree reaches the key.
    pub fn is_beneath(&self, path: &Path) -> bool {
        let resolved = resolve_links(path);
        self.directories
            .iter()
            .any(|directory| within(directory, path) || within(directory, &resolved))
    }

    /// Some word of `argv`, or the value of some `--flag=value`, reaches the
    /// key or registry. The broker refuses such a call: a tool told to write
    /// there could put a key of the caller's choosing in place.
    pub fn is_reached_by(&self, cwd: &Path, argv: &[String]) -> bool {
        argv_values(argv).any(|value| {
            let path = cwd.join(value);
            self.holds(&path) || self.is_container(&path) || self.is_beneath(&path)
        })
    }

    /// The same file as one of veil's under another name: a hard link, or a
    /// spelling the filesystem takes for the same one.
    fn is_another_name(&self, path: &Path) -> bool {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        // a file with one name has no hard link, and every path pays for this
        if metadata.is_file() && metadata.nlink() < 2 {
            return false;
        }
        let same =
            |other: &Metadata| (other.dev(), other.ino()) == (metadata.dev(), metadata.ino());

        self.directories.iter().any(|directory| {
            if metadata.is_dir() {
                return fs::metadata(directory).is_ok_and(|other| same(&other));
            }
            fs::read_dir(directory).is_ok_and(|entries| {
                entries.flatten().any(|entry| {
                    is_state_file_name(&entry.file_name())
                        && entry.metadata().is_ok_and(|other| same(&other))
                })
            })
        })
    }
}

/// Whether the shell word `pattern`, one path component, can stand for `name`:
/// `*` is any run, `?` and a `[...]` set are any one byte, and neither stands
/// for the dot of a hidden name. Letter case is ignored. A set matches more here
/// than in a shell, which only refuses more.
pub(crate) fn could_expand_to(pattern: &[u8], name: &[u8]) -> bool {
    if name.starts_with(b".") && !pattern.starts_with(b".") {
        return false;
    }

    let (mut at, mut taken) = (0, 0);
    // where the last `*` is and how much of `name` it has been given
    let mut star: Option<(usize, usize)> = None;
    while taken < name.len() {
        let step = match pattern.get(at) {
            Some(b'*') => {
                star = Some((at, taken));
                at += 1;
                continue;
            }
            Some(b'?') => Some(at + 1),
            Some(byte) => {
                // a `[` that nothing closes is an ordinary character
                let set = if *byte == b'[' {
                    set_end(pattern, at)
                } else {
                    None
                };
                match set {
                    Some(end) => Some(end + 1),
                    None => byte.eq_ignore_ascii_case(&name[taken]).then_some(at + 1),
                }
            }
            None => None,
        };
        if let Some(next) = step {
            at = next;
            taken += 1;
            continue;
        }
        let Some((star_at, given)) = star else {
            return false;
        };
        star = Some((star_at, given + 1));
        at = star_at + 1;
        taken = given + 1;
    }
    pattern[at..].iter().all(|byte| *byte == b'*')
}

/// The index of the `]` that closes the set opened at `open`. A `]` right after
/// the `[` belongs to the set.
fn set_end(pattern: &[u8], open: usize) -> Option<usize> {
    let rest = pattern.get(open + 2..)?;
    rest.iter()
        .position(|byte| *byte == b']')
        .map(|found| open + 2 + found)
}

fn is_state_file_name(name: &std::ffi::OsStr) -> bool {
    name.as_encoded_bytes()
        .get(..STATE_PREFIX.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(STATE_PREFIX.as_bytes()))
}

/// Paths compared as a filesystem that ignores letter case compares them. On
/// one that does not, this refuses a few names that are other files.
fn same_name(one: &Path, other: &Path) -> bool {
    let mut one = one.components();
    let mut other = other.components();
    loop {
        match (one.next(), other.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if same_component(a, b) => {}
            _ => return false,
        }
    }
}

/// Whether `path` is `ancestor` or beneath it.
fn within(path: &Path, ancestor: &Path) -> bool {
    let mut components = path.components();
    ancestor
        .components()
        .all(|wanted| components.next().is_some_and(|c| same_component(c, wanted)))
}

fn same_component(one: Component<'_>, other: Component<'_>) -> bool {
    one.as_os_str()
        .as_encoded_bytes()
        .eq_ignore_ascii_case(other.as_os_str().as_encoded_bytes())
}

/// `path` with `.` and `..` applied and every symlink on the way followed,
/// including one whose target does not exist. Past 40 links the rest is kept
/// as written.
pub(crate) fn resolve_links(path: &Path) -> PathBuf {
    let mut pending: VecDeque<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::new();
    let mut followed = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        if part == "." {
            continue;
        }
        let next = resolved.join(&part);
        match fs::read_link(&next) {
            Ok(target) if followed < 40 => {
                followed += 1;
                // an absolute target starts again from the root
                for component in target.components().rev() {
                    pending.push_front(component.as_os_str().to_owned());
                }
            }
            _ => resolved = next,
        }
    }
    resolved
}

fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Each word of a tool's arguments, and what follows the first `=` of one that
/// has it (`--out=path`).
fn argv_values(argv: &[String]) -> impl Iterator<Item = &str> {
    argv.iter().flat_map(|word| {
        let value = word.split_once('=').map(|(_, value)| value);
        [Some(word.as_str()), value]
            .into_iter()
            .flatten()
            .filter(|text| !text.is_empty())
    })
}

/// One registered call. `mac` signs every other field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Of the whole call: stdout, a NUL byte, stderr. It never matches a file.
    pub hash: String,
    /// Of each content a Read may be allowed for: stdout alone, as a shell
    /// redirect saves it, and each file written under `--out`.
    pub files: Vec<String>,
    pub tool: String,
    pub argv_hash: String,
    /// The harness session the call was made in.
    pub session: String,
    /// The entry outlives its session (`veil exec --persist`).
    pub persist: bool,
    pub ts: String,
    #[serde(default)]
    pub mac: String,
}

/// What the registry says about one file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lookup {
    NotRegistered,
    /// Registered, for this session or persisted.
    Derived(Box<Record>),
    /// Registered by a session that is not this one.
    OtherSession,
    TooLarge,
    /// The key or the registry is not as veil leaves it, so none of it counts.
    Refused(String),
}

#[derive(Clone, Debug)]
pub struct Registry {
    path: PathBuf,
}

type Key = [u8; KEY_BYTES];

impl Registry {
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn from_home(home: &Path) -> Self {
        Self::at(home.join(STATE_RELATIVE).join(REGISTRY_FILE))
    }

    pub fn from_env() -> Option<Self> {
        home_directory().map(|home| Self::from_home(&home))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn key_path(&self) -> PathBuf {
        self.path.with_file_name(KEY_FILE)
    }

    fn directory(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }

    /// The current file, then the rotated ones from newest to oldest.
    fn files(&self) -> impl Iterator<Item = PathBuf> + '_ {
        std::iter::once(self.path.clone())
            .chain((1..=ROTATED_FILES).map(|index| rotated_path(&self.path, index)))
    }

    /// Refuses a state directory, key or registry file that is not as veil
    /// leaves it.
    pub fn check(&self) -> Result<(), String> {
        match fs::symlink_metadata(self.directory()) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "{} is not a real directory",
                    self.directory().display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("{}: {error}", self.directory().display())),
        }
        self.key()?;
        for path in self.files() {
            open_plain(&path)?;
        }
        Ok(())
    }

    /// Makes the key if there is none and checks what is there. A sandbox does
    /// this before it confines anything, so no key is made while it runs.
    pub fn prepare(&self) -> Result<(), String> {
        fs::create_dir_all(self.directory())
            .map_err(|error| format!("{}: {error}", self.directory().display()))?;
        self.check()?;
        self.key_or_create().map(|_| ())
    }

    fn key(&self) -> Result<Option<Key>, String> {
        let path = self.key_path();
        let Some((mut file, metadata)) = open_plain(&path)? else {
            return Ok(None);
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} can be read or written by other users (mode {mode:o})",
                path.display()
            ));
        }
        let mut key = [0u8; KEY_BYTES];
        if metadata.len() != KEY_BYTES as u64 || file.read_exact(&mut key).is_err() {
            return Err(format!("{} is not a {KEY_BYTES}-byte key", path.display()));
        }
        Ok(Some(key))
    }

    fn key_or_create(&self) -> Result<Key, String> {
        if let Some(key) = self.key()? {
            return Ok(key);
        }
        let path = self.key_path();
        self.create_key(&path)
            .map_err(|error| format!("could not make {}: {error}", path.display()))?;
        self.key()?
            .ok_or_else(|| format!("{} vanished", path.display()))
    }

    /// Writes 32 random bytes to `path` unless another veil got there first.
    fn create_key(&self, path: &Path) -> io::Result<()> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.directory().join("derived.key.lock"))?;
        // released when `lock` is dropped
        lock_in_time(&lock)?;
        if fs::symlink_metadata(path).is_ok() {
            return Ok(());
        }

        let mut key = [0u8; KEY_BYTES];
        File::open("/dev/urandom")?.read_exact(&mut key)?;
        let temporary = self.directory().join(format!(
            "derived.key.{}-{}.tmp",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&key)?;
        file.sync_all()?;
        // the key appears whole or not at all
        fs::rename(&temporary, path)
    }

    /// Signs `record` and appends it, rotating the registry as the audit log is.
    pub fn append(&self, mut record: Record) -> Result<(), String> {
        self.check()?;
        let key = self.key_or_create()?;
        record.mac = mac(&key, &record).to_hex().to_string();
        let mut line = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
        line.push(b'\n');

        let failed = |error: io::Error| format!("{}: {error}", self.path.display());
        rotate_if_full(&self.path, ROTATE_BYTES, ROTATED_FILES).map_err(failed)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(failed)?;
        file.write_all(&line).map_err(failed)
    }

    /// The contents of every registry file that exists, newest first.
    fn contents(&self) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
        let mut contents = Vec::new();
        for path in self.files() {
            let Some((file, _)) = open_plain(&path)? else {
                continue;
            };
            let mut bytes = Vec::new();
            file.take(MAX_REGISTRY_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if bytes.len() as u64 > MAX_REGISTRY_FILE_BYTES {
                return Err(format!(
                    "{} is larger than veil lets it grow",
                    path.display()
                ));
            }
            contents.push((path, bytes));
        }
        Ok(contents)
    }

    /// Every content hash some authentic record registers, whatever its
    /// session. None when the registry is not to be trusted.
    fn registered_digests(&self) -> HashSet<String> {
        let (Ok(()), Ok(Some(key))) = (self.check(), self.key()) else {
            return HashSet::new();
        };
        let Ok(contents) = self.contents() else {
            return HashSet::new();
        };
        contents
            .iter()
            .flat_map(|(_, bytes)| {
                String::from_utf8_lossy(bytes)
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Record>(line).ok())
                    .filter(|record| authentic(&key, record))
                    .flat_map(|record| record.files)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The records with a valid MAC that register the content hash `digest`.
    fn matching(&self, digest: &str) -> Result<Vec<Record>, String> {
        self.check()?;
        let Some(key) = self.key()? else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for (_, bytes) in self.contents()? {
            for line in String::from_utf8_lossy(&bytes).lines() {
                // most lines are about other content: look before parsing
                if !line.contains(digest) {
                    continue;
                }
                let Ok(record) = serde_json::from_str::<Record>(line) else {
                    continue;
                };
                if authentic(&key, &record) && record.files.iter().any(|file| file == digest) {
                    found.push(record);
                }
            }
        }
        Ok(found)
    }

    /// Whether a Read of `path` in the harness session `session` is a read of
    /// registered content. This hashes the file as it is now.
    pub fn lookup(&self, path: &Path, session: Option<&str>) -> Lookup {
        // a machine that never ran `veil exec` pays for nothing
        if !self.files().any(|file| fs::symlink_metadata(file).is_ok()) {
            return Lookup::NotRegistered;
        }
        let digest = match digest_file(path) {
            Ok(Some(digest)) => digest,
            Ok(None) => return Lookup::TooLarge,
            Err(_) => return Lookup::NotRegistered,
        };
        let records = match self.matching(&digest) {
            Ok(records) => records,
            Err(why) => return Lookup::Refused(why),
        };
        if records.is_empty() {
            return Lookup::NotRegistered;
        }
        records
            .into_iter()
            .find(|record| record.persist || session == Some(record.session.as_str()))
            .map_or(Lookup::OtherSession, |record| {
                Lookup::Derived(Box::new(record))
            })
    }
}

/// Opens one of veil's own files: a regular file, under this name only.
/// `None` when there is none.
fn open_plain(path: &Path) -> Result<Option<(File, Metadata)>, String> {
    let failed = |error: io::Error| format!("{}: {error}", path.display());
    let named = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(failed(error)),
    };
    if named.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    if !named.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if named.nlink() != 1 {
        return Err(format!(
            "{} has {} names: a hard link was made to it",
            path.display(),
            named.nlink()
        ));
    }
    let file = File::open(path).map_err(failed)?;
    let opened = file.metadata().map_err(failed)?;
    if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
        return Err(format!("{} changed while it was opened", path.display()));
    }
    Ok(Some((file, opened)))
}

/// The content hash of the regular file at `path`, as a Read would see it.
/// `None` when it is larger than [`MAX_VERIFY_BYTES`].
fn digest_file(path: &Path) -> io::Result<Option<String>> {
    // asked first: opening a FIFO would wait for a writer
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > MAX_VERIFY_BYTES {
        return Ok(None);
    }
    let mut reader = File::open(path)?.take(MAX_VERIFY_BYTES + 1);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((total <= MAX_VERIFY_BYTES).then(|| format!("blake3:{}", hasher.finalize().to_hex())))
}

fn mac(key: &Key, record: &Record) -> blake3::Hash {
    // an array of the fields in a fixed order: no two records share a spelling
    let signed = json!([
        record.hash,
        record.files,
        record.tool,
        record.argv_hash,
        record.session,
        record.persist,
        record.ts,
    ]);
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(MAC_CONTEXT);
    hasher.update(signed.to_string().as_bytes());
    hasher.finalize()
}

fn authentic(key: &Key, record: &Record) -> bool {
    // `blake3::Hash` compares in constant time
    blake3::Hash::from_hex(&record.mac).is_ok_and(|claimed| claimed == mac(key, record))
}

/// The harness session `veil exec` runs in, when the harness says so in the
/// environment. Claude Code puts the id its hooks receive in
/// `CLAUDE_CODE_SESSION_ID`.
pub fn harness_session() -> Option<String> {
    std::env::var("CLAUDE_CODE_SESSION_ID")
        .ok()
        .filter(|session| !session.is_empty())
}

/// A file as it was before a tool ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
}

impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Collected {
    files: Vec<(PathBuf, Stamp)>,
    bytes: u64,
    /// Why not every file is here.
    gap: Option<String>,
}

impl Collected {
    fn add(&mut self, path: PathBuf, metadata: &Metadata) {
        self.bytes = self.bytes.saturating_add(metadata.len());
        if self.files.len() >= MAX_SOURCE_FILES || self.bytes > MAX_SOURCE_BYTES {
            self.gap.get_or_insert_with(|| {
                format!(
                    "there are more than {MAX_SOURCE_FILES} files or {} MiB to compare",
                    MAX_SOURCE_BYTES / (1024 * 1024)
                )
            });
            return;
        }
        self.files.push((path, Stamp::of(metadata)));
    }
}

/// The files veil would refuse to show that a `veil exec` call could have
/// copied. They are read before the tool runs and compared after it.
#[derive(Clone, Debug, Default)]
pub struct Sources {
    /// Named on the command line, or beneath a directory named there.
    named: Collected,
    /// Covered by the configured protected patterns, named or not: a tool can
    /// reach a file through a list. veil's built-in `~/.cmdrvl` patterns are
    /// left out, so a file there is compared only when it is named.
    protected: Collected,
    /// The hash of what each file held before the tool started, by device and
    /// inode. Whatever rewrites a file can put its stamp back, so a comparison
    /// counts only where it reads these same bytes again (bd-5ks).
    contents: BTreeMap<(u64, u64), blake3::Hash>,
}

impl Sources {
    /// `loaded_in` is where `config` was loaded from, which says what the
    /// project is. The tool runs in `cwd`. Call this before the tool starts.
    pub fn before(config: &Config, loaded_in: &Path, cwd: &Path, argv: &[String]) -> Self {
        let mut sources = Self::find(config, loaded_in, cwd, argv);
        sources.read_contents();
        sources
    }

    fn find(config: &Config, loaded_in: &Path, cwd: &Path, argv: &[String]) -> Self {
        let mut sources = Self::default();

        // "would veil refuse to show it" is what the hook says to a Read of it,
        // under the deny policy whatever the configured mode
        let mut strict = config.clone();
        strict.policy.default = PolicyMode::Deny;
        let packs = PackRegistry::with_built_ins();
        let matchers = PolicyMatchers::new(&strict);
        let mut entries = 0;
        for value in argv_values(argv) {
            let path = cwd.join(value);
            if fs::metadata(&path).is_err() {
                continue;
            }
            let named = &mut sources.named;
            let walked = walk(&path, &mut entries, |file, metadata| {
                let read = EvaluationInput::new(ToolKind::Read, &file, PathExposure::ReadsContents);
                let decision = evaluate_access_with(&read, &strict, &packs, &matchers);
                if decision.action == DecisionAction::Deny {
                    named.add(file, metadata);
                }
            });
            if let Err(why) = walked {
                named.gap.get_or_insert(why);
            }
        }

        let patterns: Vec<String> = config
            .sensitivity
            .protected
            .iter()
            .filter(|pattern| !is_cmdrvl_config_protection_pattern(pattern))
            .cloned()
            .collect();
        if patterns.is_empty() {
            return sources;
        }
        let matcher = SafePathMatcher::from_patterns(patterns.iter());
        let mut roots = absolute_pattern_roots(&patterns);
        // a name or a name pattern can match anywhere in the project, wherever
        // in it the tool runs
        if patterns.iter().any(|pattern| !pattern.starts_with('/')) {
            let project = match project_directory(loaded_in) {
                Ok(project) => project.unwrap_or_else(|| loaded_in.to_path_buf()),
                Err(error) => {
                    sources
                        .protected
                        .gap
                        .get_or_insert_with(|| format!("{}: {error}", loaded_in.display()));
                    loaded_in.to_path_buf()
                }
            };
            for directory in [project.as_path(), cwd] {
                if !roots.iter().any(|root| directory.starts_with(root)) {
                    roots.retain(|root| !root.starts_with(directory));
                    roots.push(directory.to_path_buf());
                }
            }
        }
        let mut entries = 0;
        for root in roots {
            let protected = &mut sources.protected;
            let walked = walk(&root, &mut entries, |file, metadata| {
                if matcher.is_safe(&file) {
                    protected.add(file, metadata);
                }
            });
            if let Err(why) = walked {
                protected.gap.get_or_insert(why);
            }
        }
        sources
    }

    /// Where a file is already missing from the comparison nothing will be
    /// registered, so there is nothing to read.
    fn read_contents(&mut self) {
        if self.named.gap.is_some() || self.protected.gap.is_some() {
            return;
        }
        for collected in [&mut self.named, &mut self.protected] {
            for (path, stamp) in &collected.files {
                let Entry::Vacant(content) = self.contents.entry((stamp.device, stamp.inode))
                else {
                    continue;
                };
                match read_source(path, |_| {}) {
                    Ok(hash) => {
                        content.insert(hash);
                    }
                    Err(why) => {
                        collected.gap = Some(why);
                        return;
                    }
                }
            }
        }
    }

    /// For each candidate, the content hash to register or why veil will not.
    ///
    /// stdout gets the same comparison as a file under `--out`: a tool can
    /// print a file it reached through a list, and registering that would let
    /// the protected original be read. A source whose content the registry
    /// already holds passed this comparison itself, so repeating it refuses
    /// nothing.
    pub fn judge(
        &self,
        scanner: &BrokerOutputScanner,
        registry: &Registry,
        candidates: &[&[u8]],
    ) -> Vec<Result<String, String>> {
        let mut verdicts: Vec<Result<String, String>> = candidates
            .iter()
            .map(|candidate| self.screen(scanner, candidate))
            .collect();

        let needles = Needles::new(
            candidates
                .iter()
                .zip(&verdicts)
                .map(|(candidate, verdict)| verdict.is_ok().then(|| normalized(candidate)))
                .collect(),
        );
        let mut compared = HashSet::new();
        let mut derived = None;
        for (path, stamp) in self.named.files.iter().chain(&self.protected.files) {
            if verdicts.iter().all(Result::is_err) {
                break;
            }
            let file = (stamp.device, stamp.inode);
            if !compared.insert(file) {
                continue;
            }
            match needles.search(path, *stamp, self.contents.get(&file)) {
                Ok((digest, repeated)) => {
                    let takes =
                        |index: usize, own: &String| *own == digest || repeated.contains(&index);
                    let taken: Vec<usize> = verdicts
                        .iter()
                        .enumerate()
                        .filter(|(index, verdict)| {
                            verdict.as_ref().is_ok_and(|own| takes(*index, own))
                        })
                        .map(|(index, _)| index)
                        .collect();
                    if taken.is_empty()
                        || derived
                            .get_or_insert_with(|| registry.registered_digests())
                            .contains(&digest)
                    {
                        continue;
                    }
                    for index in taken {
                        verdicts[index] = Err(format!(
                            "it copies or repeats text of {}, which veil would not show",
                            path.display()
                        ));
                    }
                }
                Err(why) => {
                    for verdict in &mut verdicts {
                        if verdict.is_ok() {
                            *verdict = Err(why.clone());
                        }
                    }
                }
            }
        }
        verdicts
    }

    /// What can be said before any source is opened.
    fn screen(&self, scanner: &BrokerOutputScanner, bytes: &[u8]) -> Result<String, String> {
        if bytes.is_empty() {
            return Err("it is empty".to_owned());
        }
        if bytes.len() > MAX_BROKER_OUTPUT_BYTES {
            return Err("it is larger than the detectors read".to_owned());
        }
        if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
            return Err("it is not text".to_owned());
        }
        if !scanner
            .scan(bytes)
            .is_ok_and(|findings| findings.is_empty())
        {
            return Err("a detector flagged it".to_owned());
        }
        if let Some(gap) = &self.named.gap {
            return Err(format!(
                "veil cannot compare it with every file named on the command line: {gap}"
            ));
        }
        if let Some(gap) = &self.protected.gap {
            return Err(format!(
                "veil cannot compare it with every protected file: {gap}"
            ));
        }
        Ok(boundary_detectors::hash_match(bytes))
    }
}

/// Calls `visit` for every file at or beneath `start`, following symlinks once
/// into each directory and leaving version-control directories out. `Err` says
/// why not every file was reached.
fn walk(
    start: &Path,
    entries: &mut usize,
    mut visit: impl FnMut(PathBuf, &Metadata),
) -> Result<(), String> {
    let mut stack = vec![start.to_path_buf()];
    let mut entered = HashSet::new();
    while let Some(path) = stack.pop() {
        *entries += 1;
        if *entries > MAX_WALK_ENTRIES {
            return Err(format!(
                "there are more than {MAX_WALK_ENTRIES} directory entries to look through"
            ));
        }
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            // nothing there: a dangling link, or a pattern root not yet made
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if metadata.is_file() {
            visit(path, &metadata);
            continue;
        }
        let skipped = path != start
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| VCS_DIRECTORIES.contains(&name));
        if !metadata.is_dir() || skipped || !entered.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        let children = fs::read_dir(&path)
            .and_then(|children| {
                children
                    .map(|child| child.map(|child| child.path()))
                    .collect::<io::Result<Vec<_>>>()
            })
            .map_err(|error| format!("{}: {error}", path.display()))?;
        stack.extend(children);
    }
    Ok(())
}

/// Lowercases ASCII and makes each run of white space one space, with none at
/// either end, a byte at a time.
#[derive(Default)]
struct Normalizer {
    started: bool,
    space: bool,
}

impl Normalizer {
    fn push(&mut self, byte: u8, mut emit: impl FnMut(u8)) {
        if byte.is_ascii_whitespace() {
            self.space = self.started;
            return;
        }
        if self.space {
            self.space = false;
            emit(b' ');
        }
        self.started = true;
        emit(byte.to_ascii_lowercase());
    }
}

fn normalized(bytes: &[u8]) -> Vec<u8> {
    let mut normalizer = Normalizer::default();
    let mut text = Vec::with_capacity(bytes.len());
    for byte in bytes {
        normalizer.push(*byte, |byte| text.push(byte));
    }
    text
}

/// A polynomial hash over the last `width` bytes pushed.
struct Rolling {
    ring: Vec<u8>,
    next: usize,
    filled: usize,
    hash: u64,
    /// `BASE^(width - 1)`: what the oldest byte was multiplied by.
    top: u64,
}

const BASE: u64 = 0x0000_0100_0000_01b3;

impl Rolling {
    fn new(width: usize) -> Self {
        Self {
            ring: vec![0; width],
            next: 0,
            filled: 0,
            hash: 0,
            top: (1..width).fold(1u64, |power, _| power.wrapping_mul(BASE)),
        }
    }

    fn of(window: &[u8]) -> u64 {
        window.iter().fold(0u64, |hash, byte| {
            hash.wrapping_mul(BASE).wrapping_add(u64::from(*byte))
        })
    }

    /// The hash of the window ending at `byte`, once a whole one has been seen.
    fn push(&mut self, byte: u8) -> Option<u64> {
        let width = self.ring.len();
        if self.filled == width {
            let oldest = u64::from(self.ring[self.next]);
            self.hash = self.hash.wrapping_sub(oldest.wrapping_mul(self.top));
        } else {
            self.filled += 1;
        }
        self.hash = self.hash.wrapping_mul(BASE).wrapping_add(u64::from(byte));
        self.ring[self.next] = byte;
        self.next = (self.next + 1) % width;
        (self.filled == width).then_some(self.hash)
    }

    fn window_is(&self, wanted: &[u8]) -> bool {
        let (newer, older) = self.ring.split_at(self.next);
        wanted.len() == self.ring.len()
            && wanted[..older.len()] == *older
            && wanted[older.len()..] == *newer
    }
}

/// The windows of one width taken from the candidates.
struct Windows {
    width: usize,
    /// Which candidate and where in it, by the window's hash.
    by_hash: BTreeMap<u64, Vec<(usize, usize)>>,
    /// A bit for each leading 16 bits of a hash in `by_hash`: nearly every
    /// byte of a source is dismissed without a map lookup.
    seen: Vec<u64>,
}

impl Windows {
    fn new(width: usize) -> Self {
        Self {
            width,
            by_hash: BTreeMap::new(),
            seen: vec![0; 1024],
        }
    }

    fn add(&mut self, candidate: usize, text: &[u8], offset: usize) {
        let hash = Rolling::of(&text[offset..offset + self.width]);
        let bit = (hash >> 48) as usize;
        self.seen[bit / 64] |= 1 << (bit % 64);
        self.by_hash
            .entry(hash)
            .or_default()
            .push((candidate, offset));
    }

    fn matches(
        &self,
        hash: u64,
        rolling: &Rolling,
        texts: &[Option<Vec<u8>>],
        found: &mut HashSet<usize>,
    ) {
        let bit = (hash >> 48) as usize;
        if self.seen[bit / 64] & (1 << (bit % 64)) == 0 {
            return;
        }
        for (candidate, offset) in self.by_hash.get(&hash).into_iter().flatten() {
            if !found.contains(candidate)
                && let Some(text) = &texts[*candidate]
                && rolling.window_is(&text[*offset..offset + self.width])
            {
                found.insert(*candidate);
            }
        }
    }
}

struct Needles {
    /// Normalized candidate text; `None` for one already refused.
    texts: Vec<Option<Vec<u8>>>,
    long: Windows,
    short: Windows,
}

impl Needles {
    fn new(texts: Vec<Option<Vec<u8>>>) -> Self {
        let mut long = Windows::new(WINDOW);
        let mut short = Windows::new(SHORT_WINDOW);
        for (candidate, text) in texts.iter().enumerate() {
            let Some(text) = text else { continue };
            if text.len() >= WINDOW {
                let last = text.len() - WINDOW;
                for offset in (0..last).step_by(STRIDE).chain([last]) {
                    long.add(candidate, text, offset);
                }
            } else if text.len() >= SHORT_WINDOW {
                for offset in 0..=text.len() - SHORT_WINDOW {
                    short.add(candidate, text, offset);
                }
            }
        }
        Self { texts, long, short }
    }

    /// The content hash of the source at `path` and which candidates repeat
    /// text of it. `Err` unless it is still the file it was before the tool ran
    /// and the bytes searched are the ones it held then, `content`.
    fn search(
        &self,
        path: &Path,
        before: Stamp,
        content: Option<&blake3::Hash>,
    ) -> Result<(String, HashSet<usize>), String> {
        let changed = || {
            format!(
                "{} changed while the tool ran, so veil cannot compare with it",
                path.display()
            )
        };
        let still = || fs::metadata(path).is_ok_and(|metadata| Stamp::of(&metadata) == before);
        if !still() {
            return Err(changed());
        }

        let mut scan = Scan::new(self);
        let searched = read_source(path, |bytes| scan.feed(bytes))?;
        if !still() || content != Some(&searched) {
            return Err(changed());
        }
        Ok((format!("blake3:{}", searched.to_hex()), scan.found))
    }
}

/// Reads a file through once, handing each piece to `each`, and returns the
/// hash of exactly what it handed over.
fn read_source(path: &Path, mut each: impl FnMut(&[u8])) -> Result<blake3::Hash, String> {
    let failed = |error: io::Error| format!("{}: {error}", path.display());
    let mut file = File::open(path).map_err(failed)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(failed)?;
        if read == 0 {
            return Ok(hasher.finalize());
        }
        hasher.update(&buffer[..read]);
        each(&buffer[..read]);
    }
}

/// One source on its way past the windows, in pieces of any size.
struct Scan<'a> {
    needles: &'a Needles,
    normalizer: Normalizer,
    long: Rolling,
    short: Rolling,
    /// The candidates that repeat some of it.
    found: HashSet<usize>,
}

impl<'a> Scan<'a> {
    fn new(needles: &'a Needles) -> Self {
        Self {
            needles,
            normalizer: Normalizer::default(),
            long: Rolling::new(WINDOW),
            short: Rolling::new(SHORT_WINDOW),
            found: HashSet::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        let Self {
            needles,
            normalizer,
            long,
            short,
            found,
        } = self;
        for byte in bytes {
            normalizer.push(*byte, |byte| {
                if let Some(hash) = long.push(byte) {
                    needles.long.matches(hash, long, &needles.texts, found);
                }
                if let Some(hash) = short.push(byte) {
                    needles.short.matches(hash, short, &needles.texts, found);
                }
            });
        }
    }
}

/// The `--out` and `--output` paths of a call, noted before the tool runs.
#[derive(Debug, Default)]
pub struct OutTargets {
    /// Paths where nothing was: what is there afterwards was made during the
    /// run.
    new: Vec<PathBuf>,
    pub notes: Vec<String>,
}

impl OutTargets {
    pub fn before(cwd: &Path, argv: &[String]) -> Self {
        let mut targets = Self::default();
        let mut words = argv.iter();
        while let Some(word) = words.next() {
            let value = if word == "--out" || word == "--output" {
                words.next().map(String::as_str)
            } else {
                word.strip_prefix("--out=")
                    .or_else(|| word.strip_prefix("--output="))
            };
            // `-` is standard output
            let Some(value) = value.filter(|value| !value.is_empty() && *value != "-") else {
                continue;
            };
            let path = cwd.join(value);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !targets.new.contains(&path) {
                        targets.new.push(path);
                    }
                }
                _ => targets.notes.push(not_registered(
                    &path,
                    "it existed before the run, so veil cannot tell what the tool wrote",
                )),
            }
        }
        targets
    }

    /// The files the tool made at the new paths, each read once: what is
    /// checked is what is hashed.
    pub fn written(&self) -> Written {
        let mut written = Written::default();
        for target in &self.new {
            written.take(target);
        }
        written
    }
}

#[derive(Debug, Default)]
pub struct Written {
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub notes: Vec<String>,
    bytes: u64,
}

impl Written {
    fn take(&mut self, target: &Path) {
        let mut stack = vec![target.to_path_buf()];
        while let Some(path) = stack.pop() {
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    self.notes.push(not_registered(&path, &error.to_string()));
                    continue;
                }
            };
            if metadata.is_dir() {
                match fs::read_dir(&path) {
                    Ok(children) => {
                        let mut children: Vec<PathBuf> =
                            children.flatten().map(|child| child.path()).collect();
                        children.sort_by(|a, b| b.cmp(a));
                        stack.extend(children);
                    }
                    Err(error) => self.notes.push(not_registered(&path, &error.to_string())),
                }
                continue;
            }
            self.bytes = self.bytes.saturating_add(metadata.len());
            if self.files.len() >= MAX_OUTPUT_FILES || self.bytes > MAX_OUTPUT_BYTES {
                self.notes.push(not_registered(
                    target,
                    "veil registers at most 256 files and 64 MiB from one call; the rest are not",
                ));
                return;
            }
            match read_output(&path) {
                Ok(bytes) => self.files.push((path, bytes)),
                Err(why) => self.notes.push(not_registered(&path, &why)),
            }
        }
    }
}

/// A file a tool wrote, when it is a file of its own: not a symlink and not a
/// second name of some other file.
fn read_output(path: &Path) -> Result<Vec<u8>, String> {
    let Some((file, metadata)) = open_plain(path)? else {
        return Err("it vanished".to_owned());
    };
    if metadata.len() > MAX_BROKER_OUTPUT_BYTES as u64 {
        return Err("it is larger than the detectors read".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BROKER_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

/// What `veil exec` says about content it did not register.
pub fn not_registered(what: &Path, why: &str) -> String {
    format!("not registered as derived: {}: {why}", what.display())
}

/// `veil derived list`: every record in the registry and whether its MAC holds.
pub fn render_list(registry: &Registry, as_json: bool) -> Result<String, String> {
    registry.check()?;
    let key = registry.key()?;
    let mut entries = Vec::new();
    for (path, bytes) in registry.contents()? {
        let source = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Ok(record) = serde_json::from_str::<Record>(line) else {
                continue;
            };
            let valid = key.is_some_and(|key| authentic(&key, &record));
            entries.push((source.clone(), valid, record));
        }
    }

    if as_json {
        let entries: Vec<_> = entries
            .iter()
            .map(|(source, valid, record)| {
                json!({
                    "file": source,
                    "valid": valid,
                    "ts": record.ts,
                    "tool": record.tool,
                    "session": record.session,
                    "persist": record.persist,
                    "files": record.files,
                })
            })
            .collect();
        return Ok(json!({
            "schema_version": "veil.derived.v1",
            "registry": registry.path(),
            "entries": entries,
        })
        .to_string());
    }

    let mut text = format!(
        "{}: {} record(s)\n",
        registry.path().display(),
        entries.len()
    );
    for (source, valid, record) in &entries {
        let _ = writeln!(
            text,
            "{} {} session={} persist={} contents={} mac={} ({source})",
            record.ts,
            record.tool,
            record.session,
            record.persist,
            record.files.len(),
            if *valid { "valid" } else { "INVALID" },
        );
    }
    Ok(text.trim_end().to_owned())
}

/// `veil derived verify <path>`: whether the file's bytes are registered, and
/// for which sessions. The second value is true when they are.
pub fn render_verify(
    registry: &Registry,
    path: &Path,
    as_json: bool,
) -> Result<(String, bool), String> {
    let digest = digest_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (status, detail, records) = match &digest {
        None => ("too_large_to_verify", None, Vec::new()),
        Some(digest) => match registry.matching(digest) {
            Ok(records) if records.is_empty() => ("not_registered", None, records),
            Ok(records) => ("registered", None, records),
            Err(why) => ("registry_refused", Some(why), Vec::new()),
        },
    };
    let registered = status == "registered";

    if as_json {
        let entries: Vec<_> = records
            .iter()
            .map(|record| {
                json!({
                    "ts": record.ts,
                    "tool": record.tool,
                    "session": record.session,
                    "persist": record.persist,
                })
            })
            .collect();
        let document = json!({
            "schema_version": "veil.derived.v1",
            "path": path,
            "hash": digest,
            "status": status,
            "detail": detail,
            "entries": entries,
        });
        return Ok((document.to_string(), registered));
    }

    let mut text = format!("{}: {status}", path.display());
    if let Some(detail) = detail {
        let _ = write!(text, ": {detail}");
    }
    for record in &records {
        let lasts = if record.persist {
            "any session (persisted)".to_owned()
        } else {
            format!("session {} only", record.session)
        };
        let _ = write!(
            text,
            "\n  {} at {}, readable in {lasts}",
            record.tool, record.ts
        );
    }
    Ok((text, registered))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source goes past in small pieces, so that windows cross them.
    fn repeats(candidate: &[u8], source: &[u8]) -> bool {
        let needles = Needles::new(vec![Some(normalized(candidate))]);
        let mut scan = Scan::new(&needles);
        for piece in source.chunks(7) {
            scan.feed(piece);
        }
        !scan.found.is_empty()
    }

    #[test]
    fn making_the_key_gives_up_on_a_lock_that_is_never_let_go() {
        let directory = std::env::temp_dir().join(format!(
            "veil-derived-key-lock-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("state directory");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("derived.key.lock"))
            .expect("lock file");
        lock.lock().expect("held by this test");

        let registry = Registry::at(directory.join(REGISTRY_FILE));
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(registry.prepare()));
        let made = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("an answer, with the lock still held");
        let why = made.expect_err("no key can be made without the lock");
        assert!(why.contains("another process holds the lock"), "{why}");
        assert!(!directory.join(KEY_FILE).exists());
        drop(lock);
    }

    #[test]
    fn the_rolling_hash_of_a_window_is_the_hash_of_its_bytes() {
        let text = b"the quick brown fox jumps over the lazy dog, twice over";
        for width in [1, 2, 24, text.len()] {
            let mut rolling = Rolling::new(width);
            for (end, byte) in text.iter().enumerate() {
                let hash = rolling.push(*byte);
                if end + 1 < width {
                    assert_eq!(hash, None);
                    continue;
                }
                let window = &text[end + 1 - width..=end];
                assert_eq!(hash, Some(Rolling::of(window)), "width {width} at {end}");
                assert!(rolling.window_is(window), "width {width} at {end}");
            }
        }
    }

    #[test]
    fn white_space_and_ascii_case_do_not_hide_a_copy() {
        assert_eq!(normalized(b"  One\n\n  TWO\tthree  "), b"one two three");
        let source = b"alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima";
        let shouted = b"CHARLIE\nDELTA\n\nECHO   FOXTROT\tGOLF HOTEL";
        assert!(repeats(shouted, source));
        assert!(!repeats(
            b"nothing in this line is in the source at all, none of it",
            source
        ));
    }

    #[test]
    fn short_content_is_a_copy_from_24_shared_bytes() {
        let source = b"alpha bravo charlie delta echo foxtrot golf hotel india juliett";
        // `#` is nowhere in the source, so each shared run ends where it looks to
        let run = |shared: &str| format!("##########{shared}##########");
        let one_short = run("charlie delta echo foxt");
        let enough = run("charlie delta echo foxtr");
        assert_eq!(one_short.len(), 20 + SHORT_WINDOW - 1);
        assert!(!repeats(one_short.as_bytes(), source));
        assert!(repeats(enough.as_bytes(), source));
        // below 24 bytes only identical content is refused, which is not this check
        assert!(!repeats(b"charlie delta echo", source));
    }
}

#[cfg(all(test, feature = "proptest"))]
mod properties {
    use proptest::prelude::*;

    use super::*;

    fn found(candidate: &[u8], source: &[u8]) -> bool {
        let needles = Needles::new(vec![Some(normalized(candidate))]);
        let mut scan = Scan::new(&needles);
        scan.feed(source);
        !scan.found.is_empty()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// 95 bytes in a row of a source, anywhere in a candidate of any
        /// length, are always seen.
        #[test]
        fn a_run_of_95_source_bytes_is_always_found(
            source in "[a-z0-9,]{200,600}",
            start in 0usize..100,
            run in (WINDOW + STRIDE - 1)..100usize,
            before in "[A-Z!]{0,90}",
            after in "[A-Z!]{0,90}",
        ) {
            let copied = &source[start..start + run];
            let candidate = format!("{before}{copied}{after}");
            prop_assert!(found(candidate.as_bytes(), source.as_bytes()));
        }

        /// Text drawn from letters the source never uses shares nothing.
        #[test]
        fn text_that_shares_nothing_is_not_found(
            source in "[a-m]{100,300}",
            candidate in "[n-z]{24,300}",
        ) {
            prop_assert!(!found(candidate.as_bytes(), source.as_bytes()));
        }
    }
}
