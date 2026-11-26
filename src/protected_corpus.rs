#![forbid(unsafe_code)]

//! One-way protected-corpus filter, built by veil outside the sandbox.
//!
//! `veil sandbox --egress airlock` knows which files `[sensitivity] protected`
//! covers. Before the harness starts it calls [`build_protected_corpus`] to turn
//! those files into a [`ShingleBloom`] (salted shingle hashes in a fixed-size
//! bit array, no text, no per-file index) and [`write_filter`] to put the
//! serialized filter in a private directory for `airlock gate --protected-bloom`.
//! The file format is `ShingleBloom::to_bytes()` (`BDBL` v1) and nothing else;
//! see the `boundary-detectors` crate, which veil and airlock pin to the same
//! revision.
//!
//! What gets filtered is exactly what the hook protects: the walk starts at the
//! repo root and at the literal root of each absolute protected pattern, and a
//! file is taken only when [`SafePathMatcher`] (the matcher the hook uses)
//! matches its absolute path.
//!
//! Bounded and honest: a corpus larger than [`CorpusLimits`] is cut down by a
//! deterministic order, never by directory order, and every file or directory the
//! filter does not cover is counted in the [`CorpusReport`]. Nothing is dropped
//! silently; [`CorpusReport::is_complete`] says whether any limit or I/O error
//! left protected content out.
//!
//! This module does not decide where the filter file lives. The launcher must
//! put it where the sandboxed agent cannot read it: the filter is one-way, but
//! anyone who already holds a candidate passage can test it against the filter.
//!
//! # What the pinned filter does and does not catch
//!
//! Measured against `boundary-detectors` rev `0d4dd36`, on small samples:
//!
//! - Text with whitespace is matched at any offset: a 100-byte excerpt of
//!   protected prose yields 3 to 9 shingle hits, 150 bytes 8 to 18, 200 bytes 14
//!   to 27. A 60-byte excerpt yields at most 3.
//! - Compact data with no whitespace (one long hex or base64 token, minified
//!   rows) is covered only by 64-byte windows taken every 16 bytes from the start
//!   of the file, so an excerpt is found only when it starts at the same offset
//!   modulo 16. A 1000-byte excerpt of a 4000-byte hex token was found at 2 of 32
//!   start offsets. A whole file copied from the start is found.
//! - The crate has no boilerplate filter. Code shares idioms and library docs
//!   share text, so a protected corpus of source code produces matches in
//!   unrelated code: veil's 15 source files had 0 to 4 hits each against 4.4 MB
//!   of four unrelated crates. The match threshold (`shingle_min_hits`, default
//!   2) is airlock's setting and has to sit above that noise.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};

use crate::allowlist::SafePathMatcher;

/// Name of the serialized filter inside the directory given to [`write_filter`].
pub const FILTER_FILE_NAME: &str = "protected-corpus.bdbl";

/// Per-shingle false positive rate the filter is sized for. This is the lowest
/// rate `ShingleBloom` sizes for (it clamps lower requests to this value). A
/// match needs several shingle hits and a long payload tests tens of thousands
/// of shingles, so the sizing is deliberately conservative: see
/// [`PLANNED_SHINGLES_PER_BYTE`].
pub const DEFAULT_TARGET_FPR: f64 = 1e-6;

/// Lowest and highest per-shingle rate `ShingleBloom::new` sizes for.
pub const MIN_TARGET_FPR: f64 = 1e-6;
pub const MAX_TARGET_FPR: f64 = 0.25;

/// Shingles inserted per input byte, as an upper bound for valid UTF-8 text.
///
/// A word shingle is 8 words that join to at least 24 bytes, so at best one per
/// 3.125 bytes (0.32 per byte); the crate adds one 64-byte window per 16 bytes
/// (0.0625 per byte). Ordinary text and code land near 0.2 per byte, so a
/// filter sized for 0.4 runs well under its target rate. Input that is not
/// valid UTF-8 is decoded lossily and can exceed the bound; the report's
/// `estimated_fpr` is computed from what was actually inserted.
const PLANNED_SHINGLES_PER_BYTE: f64 = 0.4;

const BINARY_SNIFF_BYTES: u64 = 8192;
const VCS_DIRS: [&str; 3] = [".git", ".hg", ".svn"];

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// How much a filter build may read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorpusLimits {
    /// Most files taken into the filter.
    pub max_files: usize,
    /// Most bytes read across all files.
    pub max_bytes: u64,
    /// Most bytes read from one file; the rest of a longer file is left out.
    pub max_file_bytes: u64,
    /// Most directory entries the walk inspects, so a huge tree cannot stall
    /// session launch.
    pub max_walk_entries: usize,
}

impl Default for CorpusLimits {
    fn default() -> Self {
        Self {
            max_files: 2_000,
            max_bytes: 64 * 1024 * 1024,
            max_file_bytes: 4 * 1024 * 1024,
            max_walk_entries: 500_000,
        }
    }
}

impl CorpusLimits {
    /// Rejects a zero limit, which would silently produce no filter.
    pub fn validate(&self) -> Result<(), String> {
        for (name, zero) in [
            ("max_files", self.max_files == 0),
            ("max_bytes", self.max_bytes == 0),
            ("max_file_bytes", self.max_file_bytes == 0),
            ("max_walk_entries", self.max_walk_entries == 0),
        ] {
            if zero {
                return Err(format!("{name} must be greater than zero"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CorpusOptions {
    pub limits: CorpusLimits,
    /// Per-shingle false positive rate to size the filter for, within
    /// [`MIN_TARGET_FPR`]..=[`MAX_TARGET_FPR`]. A value outside that range is
    /// refused rather than silently clamped.
    pub target_fpr: f64,
    /// Mixed into every hash and stored in the filter header (not a secret).
    pub salt: [u8; 16],
}

impl Default for CorpusOptions {
    fn default() -> Self {
        Self {
            limits: CorpusLimits::default(),
            target_fpr: DEFAULT_TARGET_FPR,
            salt: BloomConfig::default().salt,
        }
    }
}

/// What a build covered and what it left out.
///
/// `files_matched == files_included + files_sampled_out + files_binary +
/// files_unreadable`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CorpusReport {
    /// Non-empty regular files the protected patterns match.
    pub files_matched: usize,
    /// Files whose text is in the filter.
    pub files_included: usize,
    /// Bytes read from the included files.
    pub bytes_included: u64,
    /// Shingles inserted (a count; the shingles themselves are gone).
    pub shingles: u64,
    /// Matched files left out because `max_files` or `max_bytes` was reached.
    pub files_sampled_out: usize,
    /// Included files cut short at `max_file_bytes`.
    pub files_truncated: usize,
    /// Matched files left out because they hold NUL bytes. A text filter cannot
    /// cover them.
    pub files_binary: usize,
    /// Matched files that could not be opened or read.
    pub files_unreadable: usize,
    /// Entries or directories the walk could not inspect or list.
    pub entries_unreadable: usize,
    /// Matched symlinks, which are never followed.
    pub symlinks_skipped: usize,
    /// The walk stopped at `max_walk_entries`.
    pub walk_truncated: bool,
    /// Expected per-shingle false positive rate of the finished filter, from
    /// the shingles actually inserted (duplicates count, so this errs high).
    /// Above the target when the corpus outgrew the largest filter (64 MiB).
    pub estimated_fpr: f64,
}

impl CorpusReport {
    /// `true` when no limit and no I/O error left protected text out of the
    /// filter. Binary files and symlinks are reported separately: a text filter
    /// cannot cover them by design.
    pub fn is_complete(&self) -> bool {
        self.files_sampled_out == 0
            && self.files_truncated == 0
            && self.files_unreadable == 0
            && self.entries_unreadable == 0
            && !self.walk_truncated
    }
}

/// The result of [`build_protected_corpus`].
#[derive(Clone, Debug)]
pub struct ProtectedCorpus {
    /// `None` when there was nothing to protect (no matching text files, or only
    /// text too short to make a shingle). The launcher then omits
    /// `--protected-bloom` and never passes an empty filter.
    pub filter: Option<ShingleBloom>,
    pub report: CorpusReport,
}

struct Candidate {
    path: PathBuf,
    len: u64,
}

/// Builds the one-way filter over the files `protected` covers under `root`.
///
/// `protected` is `config.sensitivity.protected`. Fails only when `root` is not a
/// directory or the options are invalid; everything else that goes wrong is
/// counted in the report.
pub fn build_protected_corpus(
    root: &Path,
    protected: &[String],
    options: &CorpusOptions,
) -> io::Result<ProtectedCorpus> {
    options
        .limits
        .validate()
        .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;
    if !(MIN_TARGET_FPR..=MAX_TARGET_FPR).contains(&options.target_fpr) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("target_fpr must be within {MIN_TARGET_FPR}..={MAX_TARGET_FPR}"),
        ));
    }

    let root = std::path::absolute(root)?;
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a directory", root.display()),
        ));
    }

    let matcher = SafePathMatcher::from_patterns(protected.iter());
    let mut walker = Walker {
        matcher: &matcher,
        max_walk_entries: options.limits.max_walk_entries,
        entries: 0,
        seen: BTreeSet::new(),
        candidates: Vec::new(),
        report: CorpusReport::default(),
    };

    walker.walk(&root);
    for extra in absolute_pattern_roots(protected) {
        if !extra.starts_with(&root) {
            walker.walk(&extra);
        }
    }

    let Walker {
        candidates,
        mut report,
        ..
    } = walker;

    let selected = select(candidates, &root, options, &mut report);
    if selected.is_empty() {
        return Ok(ProtectedCorpus {
            filter: None,
            report,
        });
    }

    let planned: u64 = selected
        .iter()
        .map(|candidate| candidate.len.min(options.limits.max_file_bytes))
        .sum();
    let config = BloomConfig {
        expected_shingles: planned_shingles(planned),
        false_positive_rate: options.target_fpr,
        salt: options.salt,
        ..BloomConfig::default()
    };
    let mut filter = ShingleBloom::new(config.clone());

    let mut buffer = Vec::new();
    for candidate in &selected {
        buffer.clear();
        let read = File::open(&candidate.path).and_then(|file| {
            file.take(options.limits.max_file_bytes)
                .read_to_end(&mut buffer)
        });
        match read {
            Ok(bytes) => {
                report.bytes_included += bytes as u64;
                filter.insert_text(&String::from_utf8_lossy(&buffer));
            }
            Err(_) => {
                report.files_included -= 1;
                report.files_unreadable += 1;
            }
        }
    }

    let inserted = filter.inserted_shingles();
    report.shingles = inserted;
    report.estimated_fpr = estimated_fpr(&config, &filter);

    Ok(ProtectedCorpus {
        filter: (inserted > 0).then_some(filter),
        report,
    })
}

/// Shingle count to size the filter for, given the bytes the build plans to read.
fn planned_shingles(planned_bytes: u64) -> usize {
    let shingles = (planned_bytes as f64 * PLANNED_SHINGLES_PER_BYTE).ceil() as u64 + 2;
    usize::try_from(shingles).unwrap_or(usize::MAX)
}

/// Hash functions `ShingleBloom::new` picks for a filter of `m_bits` sized for
/// `expected_shingles`. Mirrors the crate at the pinned revision; a unit test
/// compares it with the `k_hashes` byte of a real serialized filter.
fn hash_count(m_bits: u64, expected_shingles: usize) -> u8 {
    let n = expected_shingles.max(64) as f64;
    ((m_bits as f64 / n) * std::f64::consts::LN_2)
        .round()
        .clamp(2.0, 16.0) as u8
}

/// Standard Bloom estimate `(1 - e^(-k n / m))^k` for the filter as built.
fn estimated_fpr(config: &BloomConfig, filter: &ShingleBloom) -> f64 {
    let m = filter.bit_len() as f64;
    let k = f64::from(hash_count(filter.bit_len(), config.expected_shingles));
    let n = filter.inserted_shingles() as f64;
    (1.0 - (-k * n / m).exp()).powf(k)
}

/// Writes `filter` to `dir/protected-corpus.bdbl` and returns that path.
///
/// `dir` must be a real directory (not a symlink) that group and others cannot
/// access. The file is created with mode 0600 and `create_new`, so an existing
/// file or a planted symlink is an error rather than something followed or
/// overwritten. Where `dir` lives relative to the sandbox is the launcher's job.
pub fn write_filter(dir: &Path, filter: &ShingleBloom) -> io::Result<PathBuf> {
    require_private_dir(dir)?;
    let path = dir.join(FILTER_FILE_NAME);
    let mut file = create_private_file(&path)?;
    file.write_all(&filter.to_bytes())?;
    file.sync_all()?;
    Ok(path)
}

#[cfg(unix)]
fn require_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a directory (symlinks are refused)",
                dir.display()
            ),
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} has mode {:o}; the filter directory must not be accessible to group or others",
                dir.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_dir(_dir: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cannot verify directory privacy on this platform",
    ))
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

struct Walker<'a> {
    matcher: &'a SafePathMatcher,
    max_walk_entries: usize,
    entries: usize,
    seen: BTreeSet<PathBuf>,
    candidates: Vec<Candidate>,
    report: CorpusReport,
}

impl Walker<'_> {
    /// Depth-first walk in name order, so a walk cut off by `max_walk_entries`
    /// stops at the same place every time.
    fn walk(&mut self, start: &Path) {
        let mut stack = vec![start.to_path_buf()];
        let mut first = true;

        while let Some(path) = stack.pop() {
            if self.entries >= self.max_walk_entries {
                self.report.walk_truncated = true;
                return;
            }
            self.entries += 1;

            // The start itself may be reached through a symlink (a linked repo
            // root); everything below it is inspected without following links.
            let metadata = if first {
                fs::metadata(&path)
            } else {
                fs::symlink_metadata(&path)
            };
            let is_start = first;
            first = false;

            let metadata = match metadata {
                Ok(metadata) => metadata,
                // A pattern root that does not exist (the default
                // `~/.cmdrvl/...` profile on a fresh machine) or an entry that
                // vanished mid-walk left no protected content uncovered.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    self.report.entries_unreadable += 1;
                    continue;
                }
            };
            let file_type = metadata.file_type();

            if file_type.is_symlink() {
                if self.matcher.is_safe(&path) {
                    self.report.symlinks_skipped += 1;
                }
            } else if file_type.is_dir() {
                if !is_start && is_vcs_dir(&path) {
                    continue;
                }
                match sorted_children(&path) {
                    Ok(children) => stack.extend(children.into_iter().rev()),
                    Err(_) => self.report.entries_unreadable += 1,
                }
            } else if file_type.is_file() {
                self.consider_file(path, metadata.len());
            }
        }
    }

    fn consider_file(&mut self, path: PathBuf, len: u64) {
        if len == 0 || !self.matcher.is_safe(&path) || !self.seen.insert(path.clone()) {
            return;
        }

        self.report.files_matched += 1;
        match is_text(&path) {
            Ok(true) => self.candidates.push(Candidate { path, len }),
            Ok(false) => self.report.files_binary += 1,
            Err(_) => self.report.files_unreadable += 1,
        }
    }
}

fn is_vcs_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| VCS_DIRS.contains(&name))
}

fn sorted_children(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut children = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    children.sort();
    Ok(children)
}

/// A file with a NUL byte in its first block is treated as binary.
fn is_text(path: &Path) -> io::Result<bool> {
    let mut head = Vec::new();
    File::open(path)?
        .take(BINARY_SNIFF_BYTES)
        .read_to_end(&mut head)?;
    Ok(!head.contains(&0))
}

/// Takes files in ascending salted hash of their root-relative path until a
/// limit is reached. The order depends only on the path text and the salt, so
/// the same files are chosen wherever the repo is checked out and in whatever
/// order the directory lists them.
fn select(
    candidates: Vec<Candidate>,
    root: &Path,
    options: &CorpusOptions,
    report: &mut CorpusReport,
) -> Vec<Candidate> {
    let limits = &options.limits;
    let mut ordered: Vec<(u64, PathBuf, Candidate)> = candidates
        .into_iter()
        .map(|candidate| {
            let key = candidate
                .path
                .strip_prefix(root)
                .unwrap_or(&candidate.path)
                .to_path_buf();
            (priority(&options.salt, &key), key, candidate)
        })
        .collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let mut selected = Vec::new();
    let mut planned_bytes = 0u64;
    for (_, _, candidate) in ordered {
        let take = candidate.len.min(limits.max_file_bytes);
        if selected.len() >= limits.max_files
            || planned_bytes.saturating_add(take) > limits.max_bytes
        {
            report.files_sampled_out += 1;
            continue;
        }
        planned_bytes += take;
        if candidate.len > limits.max_file_bytes {
            report.files_truncated += 1;
        }
        selected.push(candidate);
    }

    report.files_included = selected.len();
    selected
}

fn priority(salt: &[u8; 16], key: &Path) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in salt {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    for component in key.components() {
        if let Component::Normal(part) = component {
            for byte in part.to_string_lossy().bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
            }
            hash = (hash ^ u64::from(b'/')).wrapping_mul(FNV_PRIME);
        }
    }

    // FNV leaves the high bits of short inputs poorly mixed.
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

/// The literal directory (or file) each absolute pattern starts from, so a
/// protected tree outside the repo root is walked too. Never the filesystem
/// root: a pattern like `/*.pem` is not walked from `/`.
pub(crate) fn absolute_pattern_roots(patterns: &[String]) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for pattern in patterns {
        let pattern = pattern.replace('\\', "/");
        if !pattern.starts_with('/') {
            continue;
        }

        let mut root = PathBuf::from("/");
        for part in pattern.split('/').filter(|part| !part.is_empty()) {
            if part.contains(['*', '?', '[']) {
                break;
            }
            root.push(part);
        }
        if root != Path::new("/") {
            roots.insert(root);
        }
    }

    // Sorted order puts a directory before its children, so one pass drops every
    // root that an earlier root already covers.
    let mut kept: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !kept.iter().any(|ancestor| root.starts_with(ancestor)) {
            kept.push(root);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_depends_only_on_path_text_and_salt() {
        let path = Path::new("deals/memo.txt");
        let (zero, one) = ([0u8; 16], [1u8; 16]);
        assert_eq!(
            priority(&zero, path),
            priority(&zero, Path::new("deals/memo.txt"))
        );
        assert_ne!(priority(&zero, path), priority(&one, path));
        assert_ne!(
            priority(&zero, path),
            priority(&zero, Path::new("deals/memo2.txt"))
        );
        // The separator is part of the hash: "a/bc" and "ab/c" differ.
        assert_ne!(
            priority(&zero, Path::new("a/bc")),
            priority(&zero, Path::new("ab/c"))
        );
    }

    #[test]
    fn absolute_pattern_roots_stop_at_the_first_glob_and_never_use_slash() {
        let patterns = [
            "/home/u/.cmdrvl/config/**".to_owned(),
            "/home/u/.cmdrvl/config/secrets/**".to_owned(),
            "/srv/data/*.csv".to_owned(),
            "/*.pem".to_owned(),
            "/**".to_owned(),
            "protected/**".to_owned(),
            "/etc/exact.key".to_owned(),
        ];

        assert_eq!(
            absolute_pattern_roots(&patterns),
            vec![
                PathBuf::from("/etc/exact.key"),
                PathBuf::from("/home/u/.cmdrvl/config"),
                PathBuf::from("/srv/data"),
            ]
        );
    }

    /// `hash_count` re-derives what `ShingleBloom::new` chose, because the crate
    /// does not expose it. Check it against the `k_hashes` byte (offset 5) of a
    /// real serialized `BDBL` v1 header, including the size-capped geometry, so a
    /// crate bump that changes the sizing fails here instead of skewing the report.
    #[test]
    fn hash_count_matches_the_k_hashes_byte_of_a_real_filter() {
        for expected_shingles in [0usize, 64, 1_000, 50_000, 3_000_000, 100_000_000] {
            for false_positive_rate in [MIN_TARGET_FPR, 1e-3, MAX_TARGET_FPR] {
                let filter = ShingleBloom::new(BloomConfig {
                    expected_shingles,
                    false_positive_rate,
                    ..BloomConfig::default()
                });
                let bytes = filter.to_bytes();
                assert_eq!(&bytes[..5], b"BDBL\x01");
                assert_eq!(
                    bytes[5],
                    hash_count(filter.bit_len(), expected_shingles),
                    "expected_shingles {expected_shingles}, rate {false_positive_rate}"
                );
            }
        }
    }

    #[test]
    fn planned_shingles_covers_the_densest_valid_text() {
        // 8 one-or-ten-byte words per 25 bytes is the densest text that still
        // makes a word shingle for every window.
        let densest = "a a a a a a a abcdefghij ".repeat(40_000);
        let mut filter = ShingleBloom::new(BloomConfig::default());
        filter.insert_text(&densest);
        let planned = planned_shingles(densest.len() as u64);
        assert!(
            filter.inserted_shingles() <= planned as u64,
            "inserted {} > planned {planned}",
            filter.inserted_shingles()
        );
        // The bound is tight for that text (within 2x), not an arbitrary big number.
        assert!(planned as u64 <= filter.inserted_shingles() * 2);
    }

    #[test]
    fn limits_reject_zero() {
        assert!(CorpusLimits::default().validate().is_ok());
        for broken in [
            CorpusLimits {
                max_files: 0,
                ..CorpusLimits::default()
            },
            CorpusLimits {
                max_bytes: 0,
                ..CorpusLimits::default()
            },
            CorpusLimits {
                max_file_bytes: 0,
                ..CorpusLimits::default()
            },
            CorpusLimits {
                max_walk_entries: 0,
                ..CorpusLimits::default()
            },
        ] {
            assert!(broken.validate().is_err());
        }
    }
}
