use serde::{Deserialize, Serialize};

/// Guard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub safe_kill_targets: Vec<String>,
    #[serde(default)]
    pub safe_rm_patterns: Vec<String>,
    /// User-defined command prefixes that are always safe.
    /// Built-in allowlist rules (gws, diana, psql, terraform plan, brew, package managers)
    /// are not listed here — they are hard-coded in policy.rs.
    #[serde(default)]
    pub safe_command_prefixes: Vec<String>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            safe_kill_targets: vec!["node".into(), "python".into(), "ruby".into()],
            safe_rm_patterns: vec![
                "build".into(),
                "dist".into(),
                "node_modules".into(),
                "__pycache__".into(),
                "target/debug".into(),
                ".build".into(),
                "/tmp/".into(),
            ],
            safe_command_prefixes: vec![],
        }
    }
}

/// Load `GuardConfig` from disk.
///
/// Resolution order:
/// 1. `$SECGUARD_CONFIG` env var — if set and the path exists, parse it.
/// 2. `~/.config/secguard/config.toml`.
/// 3. `GuardConfig::default()`.
///
/// On parse error, logs to stderr and falls back to default. Never panics.
pub fn load() -> GuardConfig {
    if let Ok(path) = std::env::var("SECGUARD_CONFIG") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            return load_from_path(p);
        }
        // env var set but path doesn't exist — fall through to default path
        eprintln!("[secguard] SECGUARD_CONFIG={path} not found, falling back to default path");
    }

    if let Some(config_dir) = dirs::config_dir() {
        let p = config_dir.join("secguard").join("config.toml");
        if p.exists() {
            return load_from_path(&p);
        }
    }

    GuardConfig::default()
}

fn load_from_path(path: &std::path::Path) -> GuardConfig {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str::<GuardConfig>(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "[secguard] config parse error: {} — using defaults",
                    e
                );
                GuardConfig::default()
            }
        },
        Err(e) => {
            eprintln!(
                "[secguard] config read error: {} — using defaults",
                e
            );
            GuardConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_empty_safe_command_prefixes() {
        let cfg = GuardConfig::default();
        assert!(cfg.safe_command_prefixes.is_empty());
    }

    #[test]
    fn parse_sample_config_with_safe_command_prefixes() {
        let toml_text = r#"
safe_kill_targets = ["node", "python", "postgres"]
safe_command_prefixes = ["gws", "rclone copy", "tailscale status"]
"#;
        let cfg: GuardConfig = toml::from_str(toml_text).expect("parse failed");
        assert!(cfg.safe_kill_targets.contains(&"postgres".to_string()));
        assert!(cfg.safe_command_prefixes.contains(&"rclone copy".to_string()));
        assert_eq!(cfg.safe_command_prefixes.len(), 3);
    }

    #[test]
    fn load_from_temp_file_lets_rclone_through() {
        use std::io::Write;

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            r#"safe_command_prefixes = ["rclone copy", "tailscale status"]"#
        )
        .unwrap();

        let cfg = load_from_path(tmp.path());
        assert!(
            cfg.safe_command_prefixes
                .iter()
                .any(|p| p == "rclone copy"),
            "rclone copy should be in safe_command_prefixes"
        );

        // Verify it integrates with policy: rclone copy should pass
        use crate::policy::is_safe_by_policy;
        assert!(is_safe_by_policy("rclone copy src dst", &cfg));
        // rm -rf / must still fire
        assert!(!is_safe_by_policy("rm -rf /", &cfg));
    }
}
