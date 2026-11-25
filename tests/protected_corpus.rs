//! The veil side of the protected-corpus handoff to `airlock gate
//! --protected-bloom`: building the one-way filter from `[sensitivity]
//! protected` files and writing it where only the launching user can read it.
//!
//! These tests run the real builder on real files and match with the shared
//! `boundary-detectors` `Scanner`, the same code airlock links. They do NOT prove
//! the end-to-end behavior bd-d97 asks for (a live `airlock gate` answering 403):
//! that gate is airlock's.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use boundary_detectors::shingle_bloom::ShingleBloom;
use boundary_detectors::{Pack, ScanConfig, Scanner};
use veil::protected_corpus::{
    CorpusLimits, CorpusOptions, CorpusReport, DEFAULT_TARGET_FPR, FILTER_FILE_NAME,
    ProtectedCorpus, build_protected_corpus, write_filter,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "veil-corpus-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn put(root: &Path, relative: &str, content: impl AsRef<[u8]>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("file has a parent")).expect("parent dir");
    fs::write(path, content).expect("file should be written");
}

/// Deterministic pseudo-random lowercase "prose": every paragraph for a seed is
/// unique, so any match against another seed's filter would be a false positive.
fn prose(seed: u64, bytes: usize) -> String {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut out = String::with_capacity(bytes + 16);
    while out.len() < bytes {
        let length = 4 + (next() % 7) as usize;
        for _ in 0..length {
            out.push(char::from(b'a' + (next() % 26) as u8));
        }
        out.push(if next().is_multiple_of(14) { '\n' } else { ' ' });
    }
    out.truncate(bytes);
    out
}

fn protected() -> Vec<String> {
    vec!["protected/**".to_owned()]
}

fn build(root: &Path, patterns: &[String], options: &CorpusOptions) -> ProtectedCorpus {
    build_protected_corpus(root, patterns, options).expect("build should succeed")
}

fn limits(max_files: usize, max_bytes: u64, max_file_bytes: u64) -> CorpusOptions {
    CorpusOptions {
        limits: CorpusLimits {
            max_files,
            max_bytes,
            max_file_bytes,
            ..CorpusLimits::default()
        },
        ..CorpusOptions::default()
    }
}

/// The decode depth of the shallowest protected-corpus finding in `payload`, or
/// `None` when the shared scanner finds none. Uses the crate's default
/// `shingle_min_hits`, the loosest setting airlock could pick.
fn protected_hit(filter: &ShingleBloom, payload: &[u8]) -> Option<u8> {
    let config = ScanConfig::with_packs(vec![Pack::ProtectedCorpus]);
    Scanner::with_bloom(config, filter.clone())
        .scan_bytes(payload)
        .iter()
        .filter(|finding| {
            finding.pack == Pack::ProtectedCorpus && finding.rule_id == "PROTECTED_CORPUS_MATCH"
        })
        .map(|finding| finding.depth)
        .min()
}

/// Lowercased with whitespace runs collapsed: what the crate hashes, so the
/// one-way check below also covers the normalized form of the text.
fn normalized(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn assert_accounting(report: &CorpusReport) {
    assert_eq!(
        report.files_matched,
        report.files_included
            + report.files_sampled_out
            + report.files_binary
            + report.files_unreadable,
        "every matched file is included, sampled out, binary or unreadable: {report:?}"
    );
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | u32::from(*byte) << (16 - 8 * index)
        });
        for position in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[(value >> (18 - 6 * position)) as usize & 63],
            ));
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn one_file_filter(label: &str, paragraph: &str) -> ShingleBloom {
    let root = unique_dir(label);
    put(&root, "protected/memo.txt", paragraph);
    build(&root, &protected(), &CorpusOptions::default())
        .filter
        .expect("a 3 KB text file should produce a filter")
}

#[test]
fn filter_holds_no_protected_text_and_its_size_depends_only_on_params() {
    let first_text = prose(1, 6000);
    let second_text = prose(2, 6000);
    let first = one_file_filter("oneway-a", &first_text);
    let second = one_file_filter("oneway-b", &second_text);

    let first_bytes = first.to_bytes();
    let second_bytes = second.to_bytes();
    assert_eq!(first_bytes.len(), second_bytes.len());
    assert_eq!(
        first_bytes.len(),
        40 + usize::try_from(first.bit_len() / 8).expect("bit array fits in memory"),
        "length is the 40-byte header plus the bit array and nothing else"
    );

    // No 8-byte window of the protected text, as written or normalized, may
    // appear anywhere in the serialized filter.
    let filter_windows: HashSet<&[u8]> = first_bytes.windows(8).collect();
    let normalized_text = normalized(&first_text);
    for source in [first_text.as_bytes(), normalized_text.as_bytes()] {
        for window in source.windows(8) {
            assert!(
                !filter_windows.contains(window),
                "protected text leaked into the filter: {:?}",
                String::from_utf8_lossy(window)
            );
        }
    }
}

#[test]
fn copied_paragraph_is_found_after_rewrap_case_light_edits_and_encoding() {
    let paragraph = prose(7, 3000);
    let filter = one_file_filter("detect", &paragraph);

    assert_eq!(
        protected_hit(&filter, paragraph.as_bytes()),
        Some(0),
        "verbatim copy"
    );

    let rewrapped: String = paragraph
        .to_uppercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .chunks(9)
        .map(|words| words.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        protected_hit(&filter, rewrapped.as_bytes()),
        Some(0),
        "upper-cased and re-wrapped"
    );

    let mut edited = paragraph.clone().into_bytes();
    for position in [700, 1900, 2600] {
        edited[position] = b'#';
    }
    assert_eq!(
        protected_hit(&filter, &edited),
        Some(0),
        "three characters changed"
    );

    let prompt = |body: String| format!("Please summarize this attachment:\n{body}\nThanks.");
    let as_base64 = prompt(base64(paragraph.as_bytes()));
    let depth = protected_hit(&filter, as_base64.as_bytes());
    assert!(
        matches!(depth, Some(depth) if depth >= 1),
        "base64 copy must be found after decoding, got {depth:?}"
    );

    let as_hex = prompt(hex(paragraph.as_bytes()));
    let depth = protected_hit(&filter, as_hex.as_bytes());
    assert!(
        matches!(depth, Some(depth) if depth >= 1),
        "hex copy must be found after decoding, got {depth:?}"
    );
}

#[test]
fn normal_code_prompts_and_unrelated_prose_do_not_match() {
    let filter = one_file_filter("clean", &prose(11, 3000));

    let own_source = include_str!("../src/lib.rs");
    let own_readme = include_str!("../README.md");
    let unrelated = prose(12, 3000);
    let clean_prompt = format!("Please refactor this function.\n{own_source}\n{unrelated}");

    for (name, payload) in [
        ("veil source and prose", clean_prompt.as_bytes()),
        ("readme", own_readme.as_bytes()),
    ] {
        assert_eq!(protected_hit(&filter, payload), None, "{name}");
    }

    let encoded = base64(own_source.as_bytes());
    assert_eq!(
        protected_hit(&filter, encoded.as_bytes()),
        None,
        "decoded clean code must not match either"
    );
}

#[test]
fn only_protected_files_are_in_the_filter() {
    let root = unique_dir("scope");
    let secret = prose(21, 3000);
    let public = prose(22, 3000);
    put(&root, "protected/deals/memo.txt", &secret);
    put(&root, "notes/public.txt", &public);
    put(
        &root,
        "src/main.rs",
        "fn main() { println!(\"hello world again\"); }\n",
    );

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    let filter = corpus.filter.expect("filter");

    assert_eq!(corpus.report.files_matched, 1);
    assert_eq!(corpus.report.files_included, 1);
    assert!(corpus.report.is_complete(), "{:?}", corpus.report);
    assert_eq!(protected_hit(&filter, secret.as_bytes()), Some(0));
    assert_eq!(
        protected_hit(&filter, public.as_bytes()),
        None,
        "a file the hook does not protect must not be in the filter"
    );
}

#[test]
fn nested_directories_match_the_way_the_hook_matches() {
    let root = unique_dir("nested");
    let deep = prose(31, 3000);
    put(&root, "services/a/protected/deep/clients.txt", &deep);

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    let filter = corpus.filter.expect("filter");
    assert_eq!(protected_hit(&filter, deep.as_bytes()), Some(0));
}

#[test]
fn over_budget_selection_ignores_directory_order_and_checkout_location() {
    let files: Vec<(String, String)> = (0..40)
        .map(|index| {
            (
                format!("protected/f{index:02}.txt"),
                prose(100 + index, 3000),
            )
        })
        .collect();

    let ascending = unique_dir("order-asc");
    for (name, text) in &files {
        put(&ascending, name, text);
    }
    let descending = unique_dir("order-desc");
    for (name, text) in files.iter().rev() {
        put(&descending, name, text);
    }

    let options = limits(12, u64::MAX, 4 * 1024 * 1024);
    let first = build(&ascending, &protected(), &options);
    let second = build(&descending, &protected(), &options);

    assert_eq!(first.report, second.report);
    assert_eq!(first.report.files_matched, 40);
    assert_eq!(first.report.files_included, 12);
    assert_eq!(first.report.files_sampled_out, 28);
    assert!(!first.report.is_complete());
    assert_accounting(&first.report);

    let first_filter = first.filter.expect("filter");
    let second_filter = second.filter.expect("filter");
    assert_eq!(
        first_filter.to_bytes(),
        second_filter.to_bytes(),
        "same files, different order and location, byte-identical filter"
    );

    let covered: BTreeSet<&str> = files
        .iter()
        .filter(|(_, text)| protected_hit(&first_filter, text.as_bytes()).is_some())
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(covered.len(), 12, "exactly the 12 selected files match");

    let first_twelve_by_name: BTreeSet<&str> = files
        .iter()
        .take(12)
        .map(|(name, _)| name.as_str())
        .collect();
    assert_ne!(
        covered, first_twelve_by_name,
        "selection follows the salted path hash, not name order"
    );
}

#[test]
fn byte_budget_limits_the_corpus_and_is_reported() {
    let root = unique_dir("bytes");
    for index in 0..6 {
        put(
            &root,
            &format!("protected/f{index}.txt"),
            prose(200 + index, 3000),
        );
    }

    let corpus = build(&root, &protected(), &limits(100, 10_000, 4 * 1024 * 1024));
    assert_eq!(corpus.report.files_included, 3);
    assert_eq!(corpus.report.bytes_included, 9000);
    assert_eq!(corpus.report.files_sampled_out, 3);
    assert!(!corpus.report.is_complete());
    assert_accounting(&corpus.report);
}

#[test]
fn per_file_cap_truncates_and_reports_it() {
    let root = unique_dir("cap");
    let long = prose(41, 20_000);
    put(&root, "protected/long.txt", &long);

    let corpus = build(&root, &protected(), &limits(10, u64::MAX, 5_000));
    assert_eq!(corpus.report.files_truncated, 1);
    assert_eq!(corpus.report.bytes_included, 5_000);
    assert!(!corpus.report.is_complete());

    let filter = corpus.filter.expect("filter");
    assert_eq!(protected_hit(&filter, &long.as_bytes()[..4_000]), Some(0));
    assert_eq!(
        protected_hit(&filter, &long.as_bytes()[12_000..16_000]),
        None,
        "text past the cap is not covered, and the report said so"
    );
}

#[test]
fn binary_empty_and_vcs_files_are_left_out_and_counted_honestly() {
    let root = unique_dir("binary");
    let text = prose(51, 3000);
    put(&root, "protected/memo.txt", &text);
    let mut blob = prose(52, 3000).into_bytes();
    blob[100] = 0;
    put(&root, "protected/scan.bin", &blob);
    put(&root, "protected/empty.txt", "");
    put(&root, ".git/protected/hidden.txt", prose(53, 3000));

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    let filter = corpus.filter.expect("filter");

    assert_eq!(corpus.report.files_matched, 2, "empty file is not a file");
    assert_eq!(corpus.report.files_included, 1);
    assert_eq!(corpus.report.files_binary, 1);
    assert!(
        corpus.report.is_complete(),
        "binary files are reported, not an incompleteness: {:?}",
        corpus.report
    );
    assert_accounting(&corpus.report);
    assert_eq!(protected_hit(&filter, text.as_bytes()), Some(0));
    assert_eq!(protected_hit(&filter, &blob), None);
}

#[test]
fn walk_budget_stops_the_walk_and_says_so() {
    let root = unique_dir("walk");
    for index in 0..30 {
        put(
            &root,
            &format!("protected/f{index:02}.txt"),
            prose(300 + index, 500),
        );
    }

    let options = CorpusOptions {
        limits: CorpusLimits {
            max_walk_entries: 5,
            ..CorpusLimits::default()
        },
        ..CorpusOptions::default()
    };
    let corpus = build(&root, &protected(), &options);
    assert!(corpus.report.walk_truncated);
    assert!(!corpus.report.is_complete());
    assert!(corpus.report.files_matched < 30);
}

#[test]
fn nothing_to_protect_yields_no_filter_and_never_an_empty_one() {
    let root = unique_dir("empty");
    put(&root, "src/main.rs", "fn main() {}\n");
    let none = build(&root, &protected(), &CorpusOptions::default());
    assert!(none.filter.is_none());
    assert_eq!(none.report.files_matched, 0);

    put(&root, "protected/tiny.txt", "too short\n");
    let tiny = build(&root, &protected(), &CorpusOptions::default());
    assert!(tiny.filter.is_none(), "too short to make one shingle");
    assert_eq!(tiny.report.files_included, 1);
    assert_eq!(tiny.report.shingles, 0);
}

#[test]
fn absolute_pattern_roots_outside_the_repo_are_walked_and_missing_ones_are_not_an_error() {
    let repo = unique_dir("abs-repo");
    let outside = unique_dir("abs-outside");
    let secret = prose(61, 3000);
    put(&outside, "tokens/notes.txt", &secret);

    let patterns = vec![
        format!("{}/**", outside.display()),
        "/definitely/not/a/real/veil/root/**".to_owned(),
    ];
    let corpus = build(&repo, &patterns, &CorpusOptions::default());
    let filter = corpus.filter.expect("filter");

    assert_eq!(corpus.report.files_included, 1);
    assert!(
        corpus.report.is_complete(),
        "a pattern root that does not exist leaves nothing uncovered: {:?}",
        corpus.report
    );
    assert_eq!(protected_hit(&filter, secret.as_bytes()), Some(0));
}

#[test]
fn invalid_options_and_roots_are_refused() {
    let root = unique_dir("invalid");
    let zero = CorpusOptions {
        limits: CorpusLimits {
            max_files: 0,
            ..CorpusLimits::default()
        },
        ..CorpusOptions::default()
    };
    assert!(build_protected_corpus(&root, &protected(), &zero).is_err());

    // ShingleBloom sizes only for 1e-6..=0.25; anything else is refused rather
    // than silently clamped to a rate the caller did not ask for.
    for target_fpr in [0.0, 1e-9, 0.3, f64::NAN] {
        let bad_fpr = CorpusOptions {
            target_fpr,
            ..CorpusOptions::default()
        };
        let result = build_protected_corpus(&root, &protected(), &bad_fpr);
        let error = result.expect_err("a rate outside what the filter sizes for is refused");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "target_fpr {target_fpr}"
        );
    }

    let missing = root.join("nope");
    assert!(build_protected_corpus(&missing, &protected(), &CorpusOptions::default()).is_err());
}

#[test]
fn realistic_corpus_gets_a_filter_near_the_target_false_positive_rate() {
    let root = unique_dir("fpr");
    for index in 0..20 {
        put(
            &root,
            &format!("protected/doc{index}.txt"),
            prose(400 + index, 8_000),
        );
    }

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    assert!(corpus.filter.is_some());
    assert!(corpus.report.shingles > 20_000, "{:?}", corpus.report);
    assert!(
        corpus.report.estimated_fpr <= DEFAULT_TARGET_FPR,
        "estimated per-shingle false positive rate {} is above the target {DEFAULT_TARGET_FPR}",
        corpus.report.estimated_fpr
    );
}

#[test]
fn excerpts_of_a_few_lines_are_found_at_any_offset() {
    // Whitespace-bearing text makes word shingles at every offset, so a pasted
    // excerpt does not have to start where a corpus window starts. Measured with
    // the pinned crate: a 200-byte excerpt yields at least 14 shingle hits.
    let text = prose(501, 12_000);
    let filter = one_file_filter("excerpts", &text);

    for index in 0..40usize {
        let start = 53 + index * 271;
        let excerpt = &text.as_bytes()[start..start + 200];
        assert_eq!(
            protected_hit(&filter, excerpt),
            Some(0),
            "a 200-byte excerpt at offset {start} was not found"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed_and_a_symlinked_repo_root_still_works() {
    use std::os::unix::fs::symlink;

    let root = unique_dir("symlink");
    let outside = unique_dir("symlink-outside");
    let leaked = prose(71, 3000);
    put(&outside, "secret.txt", &leaked);
    let inside = prose(72, 3000);
    put(&root, "protected/real.txt", &inside);
    fs::create_dir_all(root.join("protected")).expect("dir");
    symlink(outside.join("secret.txt"), root.join("protected/link.txt")).expect("symlink");

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    let filter = corpus.filter.expect("filter");
    assert_eq!(corpus.report.symlinks_skipped, 1);
    assert_eq!(protected_hit(&filter, inside.as_bytes()), Some(0));
    assert_eq!(protected_hit(&filter, leaked.as_bytes()), None);

    let link_root = unique_dir("symlink-root").join("repo-link");
    symlink(&root, &link_root).expect("root symlink");
    let linked = build(&link_root, &protected(), &CorpusOptions::default());
    assert_eq!(linked.report.files_included, 1);
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_counted_not_swallowed() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_dir("unreadable");
    put(&root, "protected/ok.txt", prose(81, 3000));
    put(&root, "protected/locked.txt", prose(82, 3000));
    let locked = root.join("protected/locked.txt");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

    if fs::File::open(&locked).is_ok() {
        // Running with privileges that ignore file modes (root): nothing to test.
        return;
    }

    let corpus = build(&root, &protected(), &CorpusOptions::default());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).expect("restore mode");

    assert_eq!(corpus.report.files_unreadable, 1);
    assert_eq!(corpus.report.files_included, 1);
    assert!(!corpus.report.is_complete());
    assert_accounting(&corpus.report);
}

#[cfg(unix)]
fn private_dir(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = unique_dir(label);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 700");
    dir
}

#[cfg(unix)]
#[test]
fn written_filter_is_private_and_loads_with_the_calls_airlock_will_use() {
    use std::os::unix::fs::PermissionsExt;

    let paragraph = prose(91, 3000);
    let filter = one_file_filter("write", &paragraph);

    let dir = private_dir("write-dir");
    let path = write_filter(&dir, &filter).expect("write into a private directory");

    assert_eq!(path, dir.join(FILTER_FILE_NAME));
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // What the gate does at startup: read to EOF, parse with the shared crate.
    let bytes = fs::read(&path).expect("read back");
    assert_eq!(bytes, filter.to_bytes());
    let loaded = ShingleBloom::from_bytes(&bytes).expect("airlock-side parse");
    assert_eq!(loaded, filter);
    assert_eq!(protected_hit(&loaded, paragraph.as_bytes()), Some(0));
}

#[cfg(unix)]
#[test]
fn write_refuses_open_directories_overwrites_and_planted_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let filter = one_file_filter("refuse", &prose(92, 3000));

    let open_dir = unique_dir("refuse-open");
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).expect("chmod 755");
    let error = write_filter(&open_dir, &filter).expect_err("group/other-accessible dir");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!open_dir.join(FILTER_FILE_NAME).exists());

    let dir = private_dir("refuse-twice");
    write_filter(&dir, &filter).expect("first write");
    let error = write_filter(&dir, &filter).expect_err("second write must not overwrite");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

    let victim_dir = private_dir("refuse-victim");
    let victim = victim_dir.join("victim.txt");
    fs::write(&victim, b"").expect("victim");
    let trap = private_dir("refuse-trap");
    symlink(&victim, trap.join(FILTER_FILE_NAME)).expect("planted symlink");
    write_filter(&trap, &filter).expect_err("a planted symlink is an error, not followed");
    assert_eq!(fs::metadata(&victim).expect("victim").len(), 0);

    let real = private_dir("refuse-real");
    let link_dir = unique_dir("refuse-linkdir").join("link");
    symlink(&real, &link_dir).expect("dir symlink");
    write_filter(&link_dir, &filter).expect_err("a symlinked directory is refused");
    assert!(!real.join(FILTER_FILE_NAME).exists());
}
