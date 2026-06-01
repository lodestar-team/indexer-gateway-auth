#![no_main]
//! Fuzz target for the GraphQL operation classifier.
//!
//! The classifier is the only component that parses attacker-controlled input,
//! and a panic here would be a denial-of-service. This target asserts that
//! `classify` never panics for arbitrary bytes — it must always return `Ok` or a
//! `ClassifyError`.
//!
//! Run with: `cargo +nightly fuzz run classify` (requires `cargo install cargo-fuzz`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = iga::classify::classify(data);
});
