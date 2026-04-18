//! ML-based destructive command classification.

use secguard_brain::{BrainConfig, MicroBrain};
use std::sync::OnceLock;

const GUARD_SYSTEM_PROMPT: &str = "You are a safety classifier for shell commands.\n\
Classify whether the command is safe or destructive.\n\
Respond with ONLY the label. No explanation.\n\
\n\
Labels:\n\
- safe: read-only, builds, tests, linting, formatting, git status/log/diff, package install\n\
- destructive: deletes user data/files, force-overwrites files, drops databases, \
rewrites git history, remote code execution, bypasses safety checks, \
deletes data on external services (API DELETE calls, SaaS CLI delete/remove/destroy commands)";

const GUARD_LABELS: &[&str] = &["safe", "destructive"];
const CONFIDENCE_THRESHOLD: f32 = 0.85;

static GUARD_BRAIN: OnceLock<&'static Option<MicroBrain>> = OnceLock::new();

fn get_guard_brain() -> &'static Option<MicroBrain> {
    GUARD_BRAIN.get_or_init(|| {
        let config = BrainConfig::new(GUARD_SYSTEM_PROMPT, GUARD_LABELS).with_max_tokens(5);
        let brain = MicroBrain::load_default("secguard-guard", config);
        Box::leak(Box::new(brain))
    })
}

pub fn check_destructive(cmd: &str) -> Option<String> {
    check_destructive_detailed(cmd).map(|(reason, _)| reason)
}

pub fn check_destructive_detailed(cmd: &str) -> Option<(String, f32)> {
    let brain = get_guard_brain().as_ref()?;
    let (label, confidence) = brain.classify_with_confidence(cmd)?;
    if label == "destructive" && confidence >= CONFIDENCE_THRESHOLD {
        Some((
            format!("brain: destructive ({:.0}% confidence)", confidence * 100.0),
            confidence,
        ))
    } else {
        log::debug!(
            "[guard-brain] label={label} confidence={:.1}% (threshold={:.0}%) — pass",
            confidence * 100.0,
            CONFIDENCE_THRESHOLD * 100.0
        );
        None
    }
}
