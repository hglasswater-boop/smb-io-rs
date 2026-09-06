#![forbid(unsafe_code)]

//! Test fixtures, mock transports, interoperability helpers, and fuzz support.

/// Identifies a protocol fixture by a stable human-readable name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureName(pub &'static str);
