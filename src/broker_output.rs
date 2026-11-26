//! Bounded consume-side wrapper for the shared detector used on broker output.
//!
//! Construct one scanner per broker session and reuse it for each tool result.
//! Findings contain detector IDs, spans, and hashes only; callers must withhold
//! the original output whenever findings are present.

use std::fmt;

use boundary_detectors::shingle_bloom::ShingleBloom;
use boundary_detectors::{Finding, Pack, ScanConfig, Scanner};

/// The broker output cap and the largest buffer this scanner will inspect.
pub const MAX_BROKER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

const OUTPUT_PACKS: [Pack; 4] = [Pack::Secrets, Pack::Pii, Pack::Tabular, Pack::Blobs];

/// Reusable scanner for public/derived tool output before it crosses into the
/// sandboxed agent. Path strings are omitted because ordinary derived output
/// can legitimately name its input file; the broker's path policy handles that
/// separately.
#[derive(Debug, Clone)]
pub struct BrokerOutputScanner {
    scanner: Scanner,
}

impl BrokerOutputScanner {
    /// Create a scanner for secrets, PII, tabular dumps, and encoded blobs.
    pub fn new() -> Self {
        let config = output_config(false);
        Self {
            scanner: Scanner::new(config),
        }
    }

    /// Also screen output for text copied from this session's protected corpus.
    pub fn with_protected_corpus(bloom: ShingleBloom) -> Self {
        let config = output_config(true);
        Self {
            scanner: Scanner::with_bloom(config, bloom),
        }
    }

    /// Scan the complete output buffer, refusing oversized input rather than
    /// silently scanning only a prefix. An empty findings vector means the
    /// enabled packs found no match within the byte and decode budgets.
    pub fn scan(&self, output: &[u8]) -> Result<Vec<Finding>, OutputTooLarge> {
        if output.len() > MAX_BROKER_OUTPUT_BYTES {
            return Err(OutputTooLarge {
                actual_bytes: output.len(),
            });
        }

        Ok(self.scanner.scan_bytes(output))
    }

    /// Scan both streams of one tool call. The client receives both and can put
    /// them back together (bd-ds7), so each is scanned alone and then the two
    /// as one buffer in either order: once exactly, and once without the
    /// whitespace where they meet, which line-by-line printing leaves there.
    /// Findings from a joined buffer have spans in that buffer. A value broken
    /// up any other way is not matched.
    pub fn scan_streams(
        &self,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<Vec<Finding>, OutputTooLarge> {
        let mut findings = self.scan(stdout)?;
        findings.extend(self.scan(stderr)?);
        if !findings.is_empty() || stdout.is_empty() || stderr.is_empty() {
            return Ok(findings);
        }
        for (first, second) in [(stdout, stderr), (stderr, stdout)] {
            for joined in [
                [first, second].concat(),
                [first.trim_ascii_end(), second.trim_ascii_start()].concat(),
            ] {
                let found = self.scan(&joined)?;
                if !found.is_empty() {
                    return Ok(found);
                }
            }
        }
        Ok(findings)
    }
}

impl Default for BrokerOutputScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Output above the broker's fixed cap is never scanned or returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputTooLarge {
    pub actual_bytes: usize,
}

impl fmt::Display for OutputTooLarge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "broker output is {} bytes; the limit is {MAX_BROKER_OUTPUT_BYTES} bytes",
            self.actual_bytes
        )
    }
}

impl std::error::Error for OutputTooLarge {}

fn output_config(include_protected_corpus: bool) -> ScanConfig {
    let mut packs = OUTPUT_PACKS.to_vec();
    if include_protected_corpus {
        packs.push(Pack::ProtectedCorpus);
    }

    let mut config = ScanConfig::with_packs(packs);
    config.max_input_bytes = MAX_BROKER_OUTPUT_BYTES;
    config
}
