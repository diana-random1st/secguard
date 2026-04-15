//! Claude Code PreToolUse hook protocol handler.

use std::io::Read;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum HookMode {
    /// Scan tool input for secrets and redact them
    SecretsScan,
    /// Check if command is destructive
    Guard,
}

pub fn run(mode: HookMode) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let v: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));

    match mode {
        HookMode::SecretsScan => run_secrets_scan(&v),
        HookMode::Guard => run_guard(&v),
    }
}

fn run_secrets_scan(v: &serde_json::Value) -> anyhow::Result<()> {
    let scanner = secguard_secrets::Scanner::new();
    let mut input_clone = v
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let findings = secguard_secrets::redact_value(&mut input_clone, &scanner);

    if !findings.is_empty() {
        let types: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        let unique_types: std::collections::HashSet<&str> = types.into_iter().collect();
        let context = format!(
            "[secguard] Redacted {} credential(s). Types: {}",
            findings.len(),
            unique_types.into_iter().collect::<Vec<_>>().join(", ")
        );
        eprintln!("{context}");

        let json = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": input_clone,
                "additionalContext": context
            }
        });
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
}

fn run_guard(v: &serde_json::Value) -> anyhow::Result<()> {
    let tool_name = v.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");

    let text_to_check = match tool_name {
        "Bash" => v
            .get("tool_input")
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name if name.starts_with("mcp__") => {
            let tool_input = v
                .get("tool_input")
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default();
            format!("{name} {tool_input}")
        }
        _ => return Ok(()),
    };

    if text_to_check.is_empty() {
        return Ok(());
    }

    let verdict = secguard_guard::check(&text_to_check);

    if let secguard_guard::Verdict::Destructive(reason) = verdict {
        let display = if text_to_check.len() > 200 {
            format!("{}...", &text_to_check[..197])
        } else {
            text_to_check
        };

        let reason_text = format!("\u{26a0}\u{fe0f} Destructive: {reason}\nCommand: {display}");
        eprintln!("[secguard] {reason_text}");

        let json = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason_text
            }
        });
        println!("{}", serde_json::to_string(&json)?);
    }

    Ok(())
}
