//! AgentShield — Security scanner for AI agent extensions.
//!
//! Offline-first, multi-framework, SARIF output. Scans MCP servers,
//! OpenClaw skills, and other agent extension formats for security issues.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::path::Path;
//! use agentshield::{scan, ScanOptions};
//!
//! let options = ScanOptions::default();
//! let report = scan(Path::new("./my-mcp-server"), &options).unwrap();
//! println!("Pass: {}, Findings: {}", report.verdict.pass, report.findings.len());
//! ```

pub mod adapter;
pub mod analysis;
pub mod config;
pub mod error;
pub mod ir;
pub mod output;
pub mod parser;
pub mod rules;

use std::path::Path;

use config::Config;
use error::Result;
use output::OutputFormat;
use rules::policy::PolicyVerdict;
use rules::{Finding, RuleEngine};

/// Options for a scan invocation.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Path to config file (defaults to `.agentshield.toml` in scan dir).
    pub config_path: Option<std::path::PathBuf>,
    /// Output format.
    pub format: OutputFormat,
    /// CLI override for fail_on threshold.
    pub fail_on_override: Option<rules::Severity>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            config_path: None,
            format: OutputFormat::Console,
            fail_on_override: None,
        }
    }
}

/// Complete scan report.
#[derive(Debug)]
pub struct ScanReport {
    pub target_name: String,
    pub findings: Vec<Finding>,
    pub verdict: PolicyVerdict,
}

/// Run a complete scan: detect framework, parse, analyze, evaluate policy.
pub fn scan(path: &Path, options: &ScanOptions) -> Result<ScanReport> {
    // Load config
    let config_path = options
        .config_path
        .clone()
        .unwrap_or_else(|| path.join(".agentshield.toml"));
    let mut config = Config::load(&config_path)?;

    // Apply CLI override
    if let Some(fail_on) = options.fail_on_override {
        config.policy.fail_on = fail_on;
    }

    // Auto-detect framework and load IR
    let targets = adapter::auto_detect_and_load(path)?;

    // Run detectors on all targets
    let engine = RuleEngine::new();
    let mut all_findings: Vec<Finding> = Vec::new();

    let target_name = if let Some(first) = targets.first() {
        first.name.clone()
    } else {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into())
    };

    for target in &targets {
        let findings = engine.run(target);
        all_findings.extend(findings);
    }

    // Apply policy (ignore rules, overrides)
    let effective_findings = config.policy.apply(&all_findings);
    let verdict = config.policy.evaluate(&all_findings);

    Ok(ScanReport {
        target_name,
        findings: effective_findings,
        verdict,
    })
}

/// Render a scan report in the specified format.
pub fn render_report(report: &ScanReport, format: OutputFormat) -> Result<String> {
    output::render(
        &report.findings,
        &report.verdict,
        format,
        &report.target_name,
    )
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn safe_calculator_zero_findings() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/safe_calculator"),
            &opts,
        )
        .unwrap();
        assert!(report.findings.is_empty());
        assert!(report.verdict.pass);
    }

    #[test]
    fn vuln_cmd_inject_detected() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject"),
            &opts,
        )
        .unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-001"));
        assert!(!report.verdict.pass);
    }

    #[test]
    fn vuln_ssrf_detected() {
        let opts = ScanOptions::default();
        let report = scan(Path::new("tests/fixtures/mcp_servers/vuln_ssrf"), &opts).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-003"));
        assert!(!report.verdict.pass);
    }

    #[test]
    fn vuln_cred_exfil_detected() {
        let opts = ScanOptions::default();
        let report = scan(
            Path::new("tests/fixtures/mcp_servers/vuln_cred_exfil"),
            &opts,
        )
        .unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "SHIELD-002"));
        assert!(!report.verdict.pass);
    }
}
