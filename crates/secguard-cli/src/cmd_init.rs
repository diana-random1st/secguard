use std::fs;
use std::path::PathBuf;

pub fn run(global: bool) -> anyhow::Result<()> {
    let settings_path = if global {
        dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home directory"))?
            .join(".claude")
            .join("settings.json")
    } else {
        PathBuf::from(".claude").join("settings.json")
    };

    let scope = if global { "global" } else { "project" };

    // Find the secguard binary path
    let secguard_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("secguard"));
    let bin = secguard_bin.to_string_lossy();

    // Define hooks to inject
    let guard_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook guard")
    });
    let secrets_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook secrets-scan")
    });

    // Load or create settings
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        serde_json::json!({})
    };

    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.json is not an object"))?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks is not an object"))?;

    // PreToolUse hooks
    let pre = hooks
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("PreToolUse is not an array"))?;

    let secguard_marker = "secguard hook";

    // Check if already installed
    let already_installed = pre.iter().any(|entry| {
        if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
            hooks_arr.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains(secguard_marker))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    });

    if already_installed {
        eprintln!("secguard hooks already installed in {scope} settings");
        return Ok(());
    }

    // Add guard hook on Bash
    pre.push(serde_json::json!({
        "matcher": "Bash",
        "hooks": [guard_hook]
    }));

    // Add secrets-scan hook on Bash|Edit|Write|Agent|mcp__*
    pre.push(serde_json::json!({
        "matcher": "Bash|Edit|Write|Agent|mcp__*",
        "hooks": [secrets_hook]
    }));

    // Write back
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let formatted = serde_json::to_string_pretty(&settings)?;
    fs::write(&settings_path, formatted)?;

    eprintln!("Installed secguard hooks to {}", settings_path.display());
    eprintln!("  - guard: Bash commands checked for destructive ops");
    eprintln!("  - secrets-scan: credentials redacted from tool input");

    // Offer to download ML model if not present
    let model_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".secguard")
        .join("models")
        .join("secguard-guard.gguf");
    if !model_path.exists() {
        eprintln!();
        eprintln!("ML model not found. Download secguard-guard.gguf (~774MB)?");
        eprintln!("This enables L3 (ML) destructive command detection.");
        eprint!("Download now? [Y/n] ");
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_ok() {
            let answer = answer.trim().to_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                crate::cmd_model::run(None)?;
            } else {
                eprintln!("Skipped. Run `secguard model` later to download.");
            }
        }
    }

    Ok(())
}
