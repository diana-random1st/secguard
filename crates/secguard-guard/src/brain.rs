//! ML-based destructive command classification.

use secguard_brain::{BrainConfig, MicroBrain};
use std::sync::OnceLock;

const GUARD_SYSTEM_PROMPT: &str = "You are a safety classifier for shell commands. \
Classify whether the command is safe or destructive. \
Respond with ONLY the label.\n\n\
Labels:\n\
- safe: read-only, builds, tests, linting, formatting, git status/log/diff, package install\n\
- destructive: deletes data/files, force-overwrites, drops databases, \
rewrites git history, remote code execution, bypasses safety checks, \
deletes data on external services";

const GUARD_LABELS: &[&str] = &["safe", "destructive"];
const CONFIDENCE_THRESHOLD: f32 = 0.85;

static GUARD_BRAIN: OnceLock<&'static Option<MicroBrain>> = OnceLock::new();

fn get_guard_brain() -> &'static Option<MicroBrain> {
    GUARD_BRAIN.get_or_init(|| {
        // max_tokens=20 to accommodate Qwen3 `<think>...</think>` preamble + label
        let config = BrainConfig::new(GUARD_SYSTEM_PROMPT, GUARD_LABELS).with_max_tokens(20);
        let brain = MicroBrain::load_default("secguard-guard", config);
        Box::leak(Box::new(brain))
    })
}

/// Rich outcome of ML-based classification.
#[derive(Debug, Clone)]
pub enum BrainOutcome {
    /// Model file missing or init failed.
    NotLoaded,
    /// Model loaded but produced a token not in {"safe","destructive"}.
    MalformedOutput,
    /// Label was "safe" with given confidence.
    Safe { confidence: f32 },
    /// Label was "destructive" but confidence below threshold — not enforced.
    LowConfidence { confidence: f32 },
    /// Label was "destructive" with confidence >= threshold.
    Destructive { reason: String, confidence: f32 },
}

pub fn classify(cmd: &str) -> BrainOutcome {
    let Some(brain) = get_guard_brain().as_ref() else {
        return BrainOutcome::NotLoaded;
    };
    let Some((label, confidence)) = brain.classify_with_confidence(cmd) else {
        return BrainOutcome::MalformedOutput;
    };
    match label.as_str() {
        "destructive" if confidence >= CONFIDENCE_THRESHOLD => BrainOutcome::Destructive {
            reason: format!("brain: destructive ({:.0}% confidence)", confidence * 100.0),
            confidence,
        },
        "destructive" => {
            log::debug!(
                "[guard-brain] destructive but below threshold: {:.1}% < {:.0}%",
                confidence * 100.0,
                CONFIDENCE_THRESHOLD * 100.0
            );
            BrainOutcome::LowConfidence { confidence }
        }
        _ => BrainOutcome::Safe { confidence },
    }
}
