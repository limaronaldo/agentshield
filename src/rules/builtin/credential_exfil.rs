use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-002: Credential Exfiltration
///
/// Flags co-occurrence of secret/sensitive env var access and outbound HTTP
/// call in the same scan target. This is the classic pattern of reading
/// ~/.ssh, .env, AWS_* and then making an HTTP POST.
pub struct CredentialExfilDetector;

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

        if !sensitive_accesses.is_empty() && !outbound_http.is_empty() {
            let secret_names: Vec<String> = sensitive_accesses
                .iter()
                .map(|e| match &e.var_name {
                    crate::ir::ArgumentSource::Literal(s) => s.clone(),
                    crate::ir::ArgumentSource::EnvVar { name } => name.clone(),
                    _ => "unknown".into(),
                })
                .collect();

            let http_targets: Vec<String> =
                outbound_http.iter().map(|n| n.function.clone()).collect();

            let mut evidence = Vec::new();
            for access in &sensitive_accesses {
                evidence.push(Evidence {
                    description: format!("Sensitive env var access: {:?}", access.var_name),
                    location: Some(access.location.clone()),
                    snippet: None,
                });
            }
            for http in &outbound_http {
                evidence.push(Evidence {
                    description: format!("Outbound HTTP via '{}'", http.function),
                    location: Some(http.location.clone()),
                    snippet: None,
                });
            }

            findings.push(Finding {
                rule_id: "SHIELD-002".into(),
                rule_name: "Credential Exfiltration".into(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                attack_category: AttackCategory::CredentialExfiltration,
                message: format!(
                    "Reads sensitive data ({}) and sends outbound HTTP ({})",
                    secret_names.join(", "),
                    http_targets.join(", ")
                ),
                location: sensitive_accesses.first().map(|e| e.location.clone()),
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

    fn loc() -> SourceLocation {
        SourceLocation {
            file: PathBuf::from("test.py"),
            line: 1,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    #[test]
    fn flags_secret_plus_http() {
        let target = ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: ExecutionSurface {
                env_accesses: vec![EnvAccess {
                    var_name: ArgumentSource::Literal("AWS_SECRET_ACCESS_KEY".into()),
                    is_sensitive: true,
                    location: loc(),
                }],
                network_operations: vec![NetworkOperation {
                    function: "requests.post".into(),
                    url_arg: ArgumentSource::Literal("https://evil.com".into()),
                    method: Some("POST".into()),
                    sends_data: true,
                    location: loc(),
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
                    location: loc(),
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
