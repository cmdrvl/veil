use boundary_detectors::Pack;
use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};
use veil::broker_output::{BrokerOutputScanner, MAX_BROKER_OUTPUT_BYTES};

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const ENCODED_SSN_CSV: &str = "bG9hbl9pZCxib3Jyb3dlcl9zc24sdXBiCkwtMTAwMSwxMjMtNDUtNjc4OSw1MDAwMDAwCkwtMTAwMiwyMzQtNTYtNzg5MCw2MjAwMDAwCkwtMTAwMywzNDUtNjctODkwMSw3MTAwMDAwCkwtMTAwNCw0NTYtNzgtOTAxMiw4MzAwMDAwCg==";
const BASE64_AWS_KEY_WITH_BOUNDARY: &str = "QUtJQUlPU0ZPRE5ON0VYQU1QTEUgICAg";

#[test]
fn a_planted_secret_is_found_without_returning_its_raw_value() {
    let findings = BrokerOutputScanner::new()
        .scan(AWS_KEY.as_bytes())
        .expect("small output should be scanned");

    assert!(findings.iter().any(|finding| {
        finding.pack == Pack::Secrets && finding.rule_id == "SECRET_AWS_ACCESS_KEY"
    }));
    let serialized = serde_json::to_string(&findings).expect("findings should serialize");
    assert!(serialized.contains("blake3:"));
    assert!(!serialized.contains(AWS_KEY));
}

#[test]
fn a_planted_pii_csv_is_found_after_base64_decode_without_raw_values() {
    let findings = BrokerOutputScanner::new()
        .scan(ENCODED_SSN_CSV.as_bytes())
        .expect("encoded CSV should fit the output cap");

    assert!(findings.iter().any(|finding| {
        finding.pack == Pack::Pii && finding.rule_id == "PII_US_SSN" && finding.depth == 1
    }));
    assert!(findings.iter().any(|finding| {
        finding.pack == Pack::Tabular
            && finding.rule_id == "TABULAR_CSV_BLOCK"
            && finding.depth == 1
    }));
    let serialized = serde_json::to_string(&findings).expect("findings should serialize");
    assert!(!serialized.contains("123-45-6789"));
    assert!(!serialized.contains("L-1001"));
}

#[test]
fn a_planted_secret_is_found_after_base64_and_hex_encoding() {
    let scanner = BrokerOutputScanner::new();
    let encoded_base64 = BASE64_AWS_KEY_WITH_BOUNDARY.repeat(17);
    let base64_findings = scanner
        .scan(encoded_base64.as_bytes())
        .expect("base64 output should fit the output cap");
    assert!(base64_findings.iter().any(|finding| {
        finding.pack == Pack::Secrets
            && finding.rule_id == "SECRET_AWS_ACCESS_KEY"
            && finding.depth == 1
    }));

    let encoded_hex = hex_encode(format!("{AWS_KEY}    ").as_bytes());
    let hex_findings = scanner
        .scan(encoded_hex.as_bytes())
        .expect("hex output should fit the output cap");
    assert!(hex_findings.iter().any(|finding| {
        finding.pack == Pack::Secrets
            && finding.rule_id == "SECRET_AWS_ACCESS_KEY"
            && finding.depth == 1
    }));
}

#[test]
fn ordinary_derived_metadata_with_a_path_is_a_clean_negative() {
    let metadata = br#"{"table":"customers","rows":42,"columns":6,"source":"/srv/cairn/exports/customers.csv"}"#;
    let findings = BrokerOutputScanner::new()
        .scan(metadata)
        .expect("ordinary metadata should fit the output cap");

    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn protected_corpus_filter_is_consumed_by_the_broker_output_scanner() {
    let protected = "Confidential credit committee memorandum regarding Meridian Plaza senior bridge loan extension and covenant waiver schedule";
    let mut bloom = ShingleBloom::new(BloomConfig::default());
    bloom.insert_text(protected);

    let findings = BrokerOutputScanner::with_protected_corpus(bloom)
        .scan(protected.as_bytes())
        .expect("protected corpus text should fit the output cap");

    assert!(findings.iter().any(|finding| {
        finding.pack == Pack::ProtectedCorpus && finding.rule_id == "PROTECTED_CORPUS_MATCH"
    }));
}

#[test]
fn output_over_the_cap_is_refused_without_silent_prefix_scanning() {
    let oversized = vec![b'x'; MAX_BROKER_OUTPUT_BYTES + 1];
    let error = BrokerOutputScanner::new()
        .scan(&oversized)
        .expect_err("oversized output must not be partially scanned");

    assert_eq!(error.actual_bytes, MAX_BROKER_OUTPUT_BYTES + 1);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
