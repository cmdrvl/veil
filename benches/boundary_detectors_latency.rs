//! The shared scanner's latency contract as consumed by veil.
//!
//! Run with `cargo bench -p veil --bench boundary_detectors_latency`. The
//! clean inputs exercise all scan packs, magic-byte sniffing, bounded blob
//! inspection and a populated protected-corpus Bloom filter.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};
use boundary_detectors::{Pack, ScanConfig, Scanner};

const SNIFF_BYTES: usize = 4 * 1024;
const PAYLOAD_BYTES: usize = 256 * 1024;
const SNIFF_BUDGET: Duration = Duration::from_millis(1);
const PAYLOAD_BUDGET: Duration = Duration::from_millis(5);
const ITERATIONS: usize = 101;

fn clean_payload(bytes: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "steady", "quiet", "review", "window", "signal", "record", "answer", "change", "branch",
        "sample", "memory", "reader", "writer", "result", "method", "normal", "useful", "direct",
        "simple", "clear", "source", "future", "current", "report",
    ];

    let mut output = Vec::with_capacity(bytes);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let word_count = u64::try_from(WORDS.len()).unwrap_or(u64::MAX);
    while output.len() < bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let word_index = usize::try_from(state % word_count).unwrap_or_default();
        let word = WORDS.get(word_index).copied().unwrap_or("steady");
        output.extend_from_slice(word.as_bytes());
        output.push(b' ');
    }
    output.truncate(bytes);
    output
}

fn scanner() -> Scanner {
    let mut bloom = ShingleBloom::new(BloomConfig {
        expected_shingles: 20_000,
        false_positive_rate: 0.000001,
        ..BloomConfig::default()
    });
    bloom.insert_text(
        "confidential memorandum account portfolio exposure settlement allocation "
            .repeat(1_000)
            .as_str(),
    );

    let mut config = ScanConfig::default();
    config.packs.push(Pack::ProtectedCorpus);
    Scanner::with_bloom(config, bloom)
}

fn measure(scanner: &Scanner, label: &str, input: &[u8], budget: Duration) -> bool {
    for _ in 0..5 {
        std::hint::black_box(boundary_detectors::magic::sniff(input));
        if !scanner.scan_bytes(input).is_empty() {
            eprintln!("{label}: warmup input produced findings");
            return false;
        }
    }

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        std::hint::black_box(boundary_detectors::magic::sniff(input));
        let findings = scanner.scan_bytes(input);
        let elapsed = started.elapsed();
        if !findings.is_empty() {
            eprintln!("{label}: benchmark input produced findings");
            return false;
        }
        samples.push(elapsed);
    }
    samples.sort_unstable();

    let min = samples.first().copied().unwrap_or_default();
    let median = samples.get(samples.len() / 2).copied().unwrap_or_default();
    let p95 = samples
        .get(samples.len() * 95 / 100)
        .copied()
        .unwrap_or_default();
    let max = samples.last().copied().unwrap_or_default();
    let within_budget = median < budget;
    println!(
        "{label}: {} bytes, min {min:?}, median {median:?}, p95 {p95:?}, max {max:?}, budget {budget:?} -> {}",
        input.len(),
        if within_budget { "ok" } else { "OVER BUDGET" }
    );
    within_budget
}

fn main() -> ExitCode {
    let scanner = scanner();
    let sniff_ok = measure(
        &scanner,
        "4 KiB veil sniff",
        &clean_payload(SNIFF_BYTES),
        SNIFF_BUDGET,
    );
    let payload_ok = measure(
        &scanner,
        "256 KiB broker/airlock payload",
        &clean_payload(PAYLOAD_BYTES),
        PAYLOAD_BUDGET,
    );

    if sniff_ok && payload_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
