//! Hook protocol handler for Claude Code, Gemini CLI, and Codex CLI.

use std::io::Read;

use crate::cmd_update;
use crate::telemetry;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum HookMode {
    /// Scan tool input for secrets and redact them
    SecretsScan,
    /// Check if command is destructive
    Guard,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum HookTarget {
    /// Claude Code (uses "ask" + hookSpecificOutput)
    Claude,
    /// Codex CLI (uses "deny" + systemMessage; "ask" fails open)
    Codex,
    /// Gemini CLI (BeforeTool events)
    Gemini,
}

impl std::fmt::Display for HookTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookTarget::Claude => write!(f, "claude"),
            HookTarget::Codex => write!(f, "codex"),
            HookTarget::Gemini => write!(f, "gemini"),
        }
    }
}

pub fn run(mode: HookMode, target: HookTarget) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let v: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));

    // Cheap update surface: emit one-line notice if a marker is present,
    // then maybe fork a detached background check (throttled 7d).
    cmd_update::notify_if_available();
    cmd_update::maybe_background_check();

    match mode {
        HookMode::SecretsScan => run_secrets_scan(&v, target),
        HookMode::Guard => run_guard(&v, target),
    }
}

fn run_secrets_scan(v: &serde_json::Value, target: HookTarget) -> anyhow::Result<()> {
    let scanner = secguard_secrets::Scanner::new();
    let mut input_clone = v
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let start = std::time::Instant::now();
    let findings = secguard_secrets::redact_value(&mut input_clone, &scanner);
    let latency_us = start.elapsed().as_micros();

    let rule_ids: Vec<String> = findings.iter().map(|f| f.rule_id.clone()).collect();
    telemetry::emit_secrets(&telemetry::SecretsEvent {
        ts: telemetry::now_iso(),
        mode: "secrets-scan",
        findings_count: findings.len(),
        rule_ids,
        latency_us,
        target: target.to_string(),
    });

    if !findings.is_empty() {
        let types: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        let unique_types: std::collections::BTreeSet<&str> = types.into_iter().collect();
        let context = format!(
            "[secguard] Redacted {} credential(s). Types: {}",
            findings.len(),
            unique_types.into_iter().collect::<Vec<_>>().join(", ")
        );
        eprintln!("{context}");

        let hook_event_name = incoming_hook_event_name(v);
        let json = allow_response(target, hook_event_name, Some(input_clone), Some(context));
        println!("{}", serde_json::to_string(&json)?);
    } else if matches!(target, HookTarget::Codex) {
        let json = allow_response(target, incoming_hook_event_name(v), None, None);
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
}

fn run_guard(v: &serde_json::Value, target: HookTarget) -> anyhow::Result<()> {
    let tool_name = v.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let Some(text_to_check) = text_to_check(tool_name, v) else {
        if matches!(target, HookTarget::Codex) {
            println!("{}", serde_json::to_string(&serde_json::json!({}))?);
        }
        return Ok(());
    };

    if text_to_check.is_empty() {
        if matches!(target, HookTarget::Codex) {
            let json = allow_response(target, incoming_hook_event_name(v), None, None);
            println!("{}", serde_json::to_string(&json)?);
        }
        return Ok(());
    }

    let start = std::time::Instant::now();
    let detail =
        secguard_guard::check_detailed(&text_to_check, &secguard_guard::GuardConfig::default());
    let latency_us = start.elapsed().as_micros();

    let (verdict_str, reason) = match &detail.verdict {
        secguard_guard::Verdict::Safe => ("safe", None),
        secguard_guard::Verdict::Destructive(r) => ("destructive", Some(r.clone())),
    };

    telemetry::emit_guard(&telemetry::GuardEvent {
        ts: telemetry::now_iso(),
        mode: "guard",
        tool_name: tool_name.to_string(),
        command: truncate_chars(&redact_command(&text_to_check), 500),
        verdict: verdict_str,
        verdict_source: serde_json::to_string(&detail.source)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string(),
        reason: reason.clone(),
        confidence: detail.confidence,
        latency_us,
        target: target.to_string(),
    });

    if let secguard_guard::Verdict::Destructive(reason) = detail.verdict {
        let display = truncate_chars(&redact_command(&text_to_check), 200);

        let reason_text = format!("\u{26a0}\u{fe0f} Destructive: {reason}\nCommand: {display}");
        eprintln!("[secguard] {reason_text}");

        let hook_event_name = incoming_hook_event_name(v);
        let json = deny_response(target, hook_event_name, reason_text);
        println!("{}", serde_json::to_string(&json)?);
    } else if matches!(target, HookTarget::Codex) {
        let json = allow_response(target, incoming_hook_event_name(v), None, None);
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
}

fn redact_command(command: &str) -> String {
    let scanner = secguard_secrets::Scanner::new();
    let findings = scanner.scan(command);
    secguard_secrets::redact(command, &findings)
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let mut truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        truncated.push_str("...");
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_handles_utf8_boundaries() {
        let text = "ж".repeat(201);
        let truncated = truncate_chars(&text, 200);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.trim_end_matches("...").chars().count(), 200);
    }

    #[test]
    fn redact_command_removes_detected_secrets() {
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let redacted = redact_command(&format!("echo {key}"));
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(!redacted.contains(&key));
    }
}

fn allow_response(
    target: HookTarget,
    hook_event_name: String,
    updated_input: Option<serde_json::Value>,
    context: Option<String>,
) -> serde_json::Value {
    if matches!(target, HookTarget::Codex) && updated_input.is_none() && context.is_none() {
        return serde_json::json!({});
    }

    let mut hook_specific_output = serde_json::json!({
        "hookEventName": hook_event_name,
    });

    if !matches!(target, HookTarget::Codex) {
        hook_specific_output["permissionDecision"] = serde_json::Value::String("allow".into());
    }

    if let Some(context) = context {
        if !matches!(target, HookTarget::Codex) {
            hook_specific_output["permissionDecisionReason"] =
                serde_json::Value::String(context.clone());
        }
        hook_specific_output["additionalContext"] = serde_json::Value::String(context);
    }

    if let Some(updated_input) = updated_input {
        hook_specific_output["updatedInput"] = updated_input;
    }

    match target {
        HookTarget::Codex => serde_json::json!({
            "hookSpecificOutput": hook_specific_output
        }),
        _ => {
            let mut json = serde_json::json!({
                "hookSpecificOutput": hook_specific_output
            });
            json["decision"] = serde_json::Value::String("allow".into());
            json
        }
    }
}

fn deny_response(target: HookTarget, hook_event_name: String, reason: String) -> serde_json::Value {
    let permission_decision = match target {
        HookTarget::Codex => "deny",
        _ => "ask",
    };

    let hook_specific_output = serde_json::json!({
        "hookEventName": hook_event_name,
        "permissionDecision": permission_decision,
        "permissionDecisionReason": &reason
    });

    match target {
        HookTarget::Codex => serde_json::json!({
            "hookSpecificOutput": hook_specific_output,
            "systemMessage": reason
        }),
        _ => serde_json::json!({
            "decision": "ask",
            "hookSpecificOutput": hook_specific_output
        }),
    }
}

fn incoming_hook_event_name(v: &serde_json::Value) -> String {
    v.get("hook_event_name")
        .or_else(|| v.get("hookEventName"))
        .and_then(|value| value.as_str())
        .unwrap_or("PreToolUse")
        .to_string()
}

fn text_to_check(tool_name: &str, value: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" => extract_command(value),
        "run_shell_command" | "shell" => extract_command(value),
        name if name.starts_with("mcp__") => {
            let tool_input = value
                .get("tool_input")
                .map(|value| serde_json::to_string(value).unwrap_or_default())
                .unwrap_or_default();
            Some(format!("{name} {tool_input}"))
        }
        other if other.to_ascii_lowercase().contains("shell") => extract_command(value),
        _ => None,
    }
}

fn extract_command(value: &serde_json::Value) -> Option<String> {
    value
        .get("tool_input")
        .and_then(|value| value.get("command").or_else(|| value.get("cmd")))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}
