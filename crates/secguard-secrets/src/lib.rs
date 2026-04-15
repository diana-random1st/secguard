//! Secret and credential detection.
//!
//! Scans text for API keys, tokens, connection strings, and other credentials.

pub mod redactor;
pub mod rules;
pub mod scanner;

pub use redactor::{redact, redact_value};
pub use scanner::{Finding, Scanner};
