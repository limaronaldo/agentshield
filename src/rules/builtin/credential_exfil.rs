use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-002: Credential Exfiltration
///
/// Flags co-occurrence of secret/sensitive env var access and outbound
/// data-sending HTTP call **within the same source file**. Proximity
/// (line distance) determines confidence:
/// - Same file, within 30 lines → High confidence
/// - Same file, farther apart   → Medium confidence
/// - Different files only        → not flagged (avoids false positives)
pub struct CredentialExfilDetector;

/// Maximum line distance for High confidence correlation.
const PROXIMITY_THRESHOLD: usize = 30;

impl Detector for CredentialExfilDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-002".into(),
            name: "Credential Exfiltration".into(),
            description: "Reads sensitive credentials/env vars and makes outbound HTTP requests"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::CredentialExfiltration,
            cwe_id: Some("CWE-522".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let sensitive_accesses: Vec<_> = target
            .execution
            .env_accesses
            .iter()
            .filter(|e| e.is_sensitive)
            .collect();

        let outbound_http: Vec<_> = target
            .execution
            .network_operations
            .iter()
            .filter(|n| n.sends_data)
            .collect();

        if sensitive_accesses.is_empty() || outbound_http.is_empty() {
            return findings;
        }

        // Group by file: only correlate accesses + HTTP within the same file
        for http in &outbound_http {
            let http_file = &http.location.file;
            let http_line = http.location.line;

            let same_file_secrets: Vec<_> = sensitive_accesses
                .iter()
                .filter(|e| e.location.file == *http_file)
                .collect();

            if same_file_secrets.is_empty() {
                continue;
            }

            // Determine closest secret access for proximity scoring
            let min_distance = same_file_secrets
                .iter()
                .map(|e| (e.location.line as isize - http_line as isize).unsigned_abs())
                .min()
                .unwrap_or(usize::MAX);

            let confidence = if min_distance <= PROXIMITY_THRESHOLD {
                Confidence::High
            } else {
                Confidence::Medium
            };

            let secret_names: Vec<String> = same_file_secrets
                .iter()
                .map(|e| match &e.var_name {
                    crate::ir::ArgumentSource::Literal(s) => s.clone(),
                    crate::ir::ArgumentSource::EnvVar { name } => name.clone(),
                    _ => "unknown".into(),
                })
                .collect();

            let mut evidence = Vec::new();
            for access in &same_file_secrets {
                evidence.push(Evidence {
                    description: format!("Sensitive env var access: {:?}", access.var_name),
                    location: Some(access.location.clone()),
                    snippet: None,
                });
            }
            evidence.push(Evidence {
                description: format!("Outbound HTTP via '{}'", http.function),
                location: Some(http.location.clone()),
                snippet: None,
            });

            findings.push(Finding {
                rule_id: "SHIELD-002".into(),
                rule_name: "Credential Exfiltration".into(),
                severity: Severity::Critical,
                confidence,
                attack_category: AttackCategory::CredentialExfiltration,
                message: format!(
                    "Reads sensitive data ({}) and sends outbound HTTP ({}) in {}",
                    secret_names.join(", "),
                    http.function,
                    http_file.display(),
                ),
                location: same_file_secrets.first().map(|e| e.location.clone()),
                evidence,
                taint_path: None,
                remediation: Some(
                    "Review whether credentials need to be sent externally. \
                     Use allowlisted URLs if outbound access is required."
                        .into(),
                ),
                cwe_id: Some("CWE-522".into()),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::execution_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn loc_at(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: PathBuf::from(file),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_secret_plus_http_same_file() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("server.py", 10),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://evil.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("server.py", 15),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-002");
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn no_finding_when_different_files() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("config.py", 5),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("analytics.py", 20),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert!(findings.is_empty(), "different files should not correlate");
    }

    #[test]
    fn medium_confidence_when_far_apart() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("API_KEY".into()),
                    is_sensitive: true,
                    location: loc_at("server.py", 10),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://example.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc_at("server.py", 200),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn passes_no_sensitive_access() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                network_operations: vec![NetworkOperation {
                    function: "requests.get".into(),
                    url_arg: ArgumentSource::Literal("https://api.example.com".into()),
                    method: Some("GET".into()),
                    sends_data: false,
                    location: loc_at("server.py", 1),
                }],
                ..Default::default()
            },
            data: Default::default(),
            dependencies: Default::default(),
            provenance: Default::default(),
            source_files: vec![],
        };

        let findings = CredentialExfilDetector.run(&target);
        assert!(findings.is_empty());
    }
}
