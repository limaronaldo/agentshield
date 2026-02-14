use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::rules::policy::Policy;

/// Top-level configuration from `.agentshield.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policy: Policy,
}

impl Config {
    /// Load config from a TOML file. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Generate a starter config file.
    pub fn starter_toml() -> &'static str {
        r#"# AgentShield configuration
# See https://github.com/limaronaldo/agentshield for documentation.

[policy]
# Minimum severity to fail the scan (info, low, medium, high, critical).
fail_on = "high"

# Rule IDs to ignore entirely.
# ignore_rules = ["SHIELD-008"]

# Per-rule severity overrides.
# [policy.overrides]
# "SHIELD-012" = "info"
"#
    }
}
