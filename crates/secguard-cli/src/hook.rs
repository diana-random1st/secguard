//! Hook protocol handler for Claude Code, Gemini CLI, and Codex CLI.

use std::io::Read;

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

pub fn run(mode: HookMode, target: HookTarget) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let v: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));

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

    let findings = secguard_secrets::redact_value(&mut input_clone, &scanner);

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
        let json = match target {
            HookTarget::Codex => serde_json::json!({
                "decision": "allow",
                "reason": &context,
                "systemMessage": &context,
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "permissionDecision": "allow",
                    "permissionDecisionReason": &context,
                    "updatedInput": input_clone,
                    "additionalContext": &context
                }
            }),
            _ => serde_json::json!({
                "decision": "allow",
                "reason": &context,
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "permissionDecision": "allow",
                    "permissionDecisionReason": &context,
                    "updatedInput": input_clone,
                    "additionalContext": &context
                }
            }),
        };
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
}

fn run_guard(v: &serde_json::Value, target: HookTarget) -> anyhow::Result<()> {
    let tool_name = v.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let Some(text_to_check) = text_to_check(tool_name, v) else {
        return Ok(());
    };

    if text_to_check.is_empty() {
        return Ok(());
    }

    let verdict = secguard_guard::check(&text_to_check);

    if let secguard_guard::Verdict::Destructive(reason) = verdict {
        let display = if text_to_check.len() > 200 {
            format!("{}...", &text_to_check[..197])
        } else {
            text_to_check.clone()
        };

        let reason_text = format!("\u{26a0}\u{fe0f} Destructive: {reason}\nCommand: {display}");
        eprintln!("[secguard] {reason_text}");

        let hook_event_name = incoming_hook_event_name(v);
        let json = match target {
            HookTarget::Codex => serde_json::json!({
                "decision": "deny",
                "reason": &reason_text,
                "systemMessage": &reason_text,
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": &reason_text
                }
            }),
            _ => serde_json::json!({
                "decision": "ask",
                "reason": &reason_text,
                "hookSpecificOutput": {
                    "hookEventName": hook_event_name,
                    "permissionDecision": "ask",
                    "permissionDecisionReason": &reason_text
                }
            }),
        };
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
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
