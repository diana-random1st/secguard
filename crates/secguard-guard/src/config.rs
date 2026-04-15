use serde::{Deserialize, Serialize};

/// Guard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub safe_kill_targets: Vec<String>,
    #[serde(default)]
    pub safe_rm_patterns: Vec<String>,
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
        }
    }
}
