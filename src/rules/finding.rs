use serde::{Deserialize, Serialize};

use crate::ir::{data_surface::TaintPath, SourceLocation};

/// A security finding produced by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique rule identifier (e.g., "SHIELD-001").
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Severity level.
    pub severity: Severity,
    /// Confidence level (how certain we are this is a real issue).
    pub confidence: Confidence,
    /// MITRE ATT&CK-style category.
    pub attack_category: AttackCategory,
    /// Human-readable description of the finding.
    pub message: String,
    /// Primary source location.
    pub location: Option<SourceLocation>,
    /// Evidence supporting the finding.
    pub evidence: Vec<Evidence>,
    /// Taint path (if applicable).
    pub taint_path: Option<TaintPath>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// CWE identifier (if applicable).
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str_lenient(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    CommandInjection,
    CodeInjection,
    CredentialExfiltration,
    Ssrf,
    ArbitraryFileAccess,
    SupplyChain,
    SelfModification,
    PromptInjectionSurface,
    ExcessivePermissions,
    DataExfiltration,
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandInjection => write!(f, "Command Injection"),
            Self::CodeInjection => write!(f, "Code Injection"),
            Self::CredentialExfiltration => write!(f, "Credential Exfiltration"),
            Self::Ssrf => write!(f, "SSRF"),
            Self::ArbitraryFileAccess => write!(f, "Arbitrary File Access"),
            Self::SupplyChain => write!(f, "Supply Chain"),
            Self::SelfModification => write!(f, "Self-Modification"),
            Self::PromptInjectionSurface => write!(f, "Prompt Injection Surface"),
            Self::ExcessivePermissions => write!(f, "Excessive Permissions"),
            Self::DataExfiltration => write!(f, "Data Exfiltration"),
        }
    }
}

/// Evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub location: Option<SourceLocation>,
    pub snippet: Option<String>,
}

/// Metadata about a detector rule, used for `list-rules` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_severity: Severity,
    pub attack_category: AttackCategory,
    pub cwe_id: Option<String>,
}
