//! Structured telemetry for secguard hook invocations.
//!
//! Appends JSONL events to `~/.secguard/telemetry.jsonl`.
//! Disabled with `SECGUARD_TELEMETRY=off`. Never blocks the hook.

use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct GuardEvent {
    pub ts: String,
    pub mode: &'static str,
    pub tool_name: String,
    pub command: String,
    pub verdict: &'static str,
    pub verdict_source: String,
    pub reason: Option<String>,
    pub confidence: Option<f32>,
    pub latency_us: u128,
    pub target: String,
}

#[derive(Debug, Serialize)]
pub struct SecretsEvent {
    pub ts: String,
    pub mode: &'static str,
    pub findings_count: usize,
    pub rule_ids: Vec<String>,
    pub latency_us: u128,
    pub target: String,
}

fn is_enabled() -> bool {
    std::env::var("SECGUARD_TELEMETRY")
        .map(|v| v != "off" && v != "false" && v != "0")
        .unwrap_or(true)
}

fn telemetry_path() -> Option<std::path::PathBuf> {
    let dir = dirs::home_dir()?.join(".secguard");
    Some(dir.join("telemetry.jsonl"))
}

pub fn now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    // Simple UTC timestamp — no chrono dependency
    format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        1970 + secs / 31_557_600,              // approximate year
        ((secs % 31_557_600) / 2_629_800) + 1, // approximate month
        ((secs % 2_629_800) / 86_400) + 1,     // approximate day
        h,
        m,
        s
    )
}

pub fn emit_guard(event: &GuardEvent) {
    if !is_enabled() {
        return;
    }
    emit_json(event);
}

pub fn emit_secrets(event: &SecretsEvent) {
    if !is_enabled() {
        return;
    }
    emit_json(event);
}

fn emit_json<T: Serialize>(event: &T) {
    let Some(path) = telemetry_path() else {
        return;
    };
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(e) => {
            log::debug!("[telemetry] serialize error: {e}");
            return;
        }
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(e) => {
            log::debug!("[telemetry] write error: {e}");
        }
    }
}
