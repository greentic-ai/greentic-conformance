//! Lightweight stub for the unreleased `greentic-pack` crate.
//!
//! The real crate should be supplied via a `[patch]` override when available.

/// Marker type indicating the stub implementation was linked.
#[derive(Debug, Clone, Copy)]
pub struct MissingGreenticPack;

impl MissingGreenticPack {
    /// Returns an explanatory message.
    pub fn missing() -> &'static str {
        "greentic-pack stub: replace via [patch] with the real crate"
    }
}
