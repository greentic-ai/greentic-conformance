//! Lightweight stub for the unreleased `greentic-oauth` crate.
//!
//! This placeholder exists so that `greentic-conformance` can build and run
//! its test suites without depending on a private registry. The real crate
//! should be provided via a `[patch]` override when available.

/// Marker type that indicates the real `greentic-oauth` dependency is missing.
#[derive(Debug, Clone, Copy)]
pub struct MissingGreenticOauth;

impl MissingGreenticOauth {
    /// Returns an error explaining that the stub is in use.
    pub fn missing() -> &'static str {
        "greentic-oauth stub: replace via [patch] with the real crate"
    }
}
