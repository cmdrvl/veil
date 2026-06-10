# Regression Alerts

No regressions were detected in pass 1.

Verification completed in this pass:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- Intent corpus replay: 0 silent failures, 0 useless errors
- Five audit regression scripts under `audit/regression_tests/`
