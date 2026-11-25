//! spine-rules family contract for veil.
//!
//! veil is a hook with no verdict domain and no witness ledger, so the
//! fixture-driven R-001 / R-008 / R-017 / R-021 tests are not opted into:
//! veil's decisions are not `version`-stamped verdict JSON, it does not accept
//! `--no-witness`, and it never emits CSV. See the bd-bf2 comment.

use spine_rules::golden_rules_suite;

golden_rules_suite! {
    binary: env!("CARGO_BIN_EXE_veil"),
    operator_json: include_str!("../operator.json"),
    source_files: &["src/lib.rs", "src/operator.rs", "src/hooks.rs"],
}
