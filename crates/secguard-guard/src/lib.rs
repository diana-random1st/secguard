//! Destructive command detection.
//!
//! Three-phase classification: policy allowlist -> heuristic rules -> ML brain.

pub mod config;
pub mod heuristic;
pub mod policy;

#[cfg(feature = "ml")]
mod brain;

pub use config::GuardConfig;

/// Result of guard classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Command is safe to execute.
    Safe,
    /// Command is destructive — includes human-readable reason.
    Destructive(String),
}

/// Classify a shell command through all enabled phases.
pub fn check(cmd: &str) -> Verdict {
    check_with_config(cmd, &GuardConfig::default())
}

/// Classify with custom configuration.
pub fn check_with_config(cmd: &str, config: &GuardConfig) -> Verdict {
    if policy::is_safe_by_policy(cmd) {
        return Verdict::Safe;
    }

    if let Some(reason) = heuristic::check_destructive(cmd, config) {
        return Verdict::Destructive(reason);
    }

    #[cfg(feature = "ml")]
    if let Some(reason) = brain::check_destructive(cmd) {
        return Verdict::Destructive(reason);
    }

    Verdict::Safe
}
