pub mod console;
pub mod json;
pub mod sarif;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::rules::policy::PolicyVerdict;
use crate::rules::Finding;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Console,
    Json,
    Sarif,
}

impl OutputFormat {
    pub fn from_str_lenient(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "console" | "text" => Some(Self::Console),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }
}

/// Render findings into the specified format.
pub fn render(
    findings: &[Finding],
    verdict: &PolicyVerdict,
    format: OutputFormat,
    target_name: &str,
) -> Result<String> {
    match format {
        OutputFormat::Console => Ok(console::render(findings, verdict)),
        OutputFormat::Json => json::render(findings, verdict),
        OutputFormat::Sarif => sarif::render(findings, target_name),
    }
}
