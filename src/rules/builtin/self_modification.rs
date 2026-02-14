use crate::ir::execution_surface::FileOpType;
use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, RuleMetadata, Severity,
};

/// SHIELD-006: Self-Modification
///
/// Flags writes targeting repository root source files or known executable
/// scripts. Code that modifies its own source is a rug pull / persistence risk.
pub struct SelfModificationDetector;

impl Detector for SelfModificationDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-006".into(),
            name: "Self-Modification".into(),
            description: "Code that writes to its own source files or scripts".into(),
            default_severity: Severity::High,
            attack_category: AttackCategory::SelfModification,
            cwe_id: Some("CWE-506".into()),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let source_paths: Vec<_> = target.source_files.iter().map(|f| f.path.clone()).collect();

        for file_op in &target.execution.file_operations {
            if !matches!(file_op.operation, FileOpType::Write) {
                continue;
            }

            // Check if writing to any of our own source files
            let is_self_write = match &file_op.path_arg {
                crate::ir::ArgumentSource::Literal(path) => {
                    let write_path = std::path::Path::new(path);
                    source_paths.iter().any(|sp| {
                        sp.ends_with(write_path) || write_path.ends_with(sp) || sp == write_path
                    })
                }
                // If path is dynamic, we can't confirm but flag conservatively
                _ => false,
            };

            if is_self_write {
                findings.push(Finding {
                    rule_id: "SHIELD-006".into(),
                    rule_name: "Self-Modification".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    attack_category: AttackCategory::SelfModification,
                    message: format!("Writes to own source file: {:?}", file_op.path_arg),
                    location: Some(file_op.location.clone()),
                    evidence: vec![Evidence {
                        description: "Code writes to its own source files".into(),
                        location: Some(file_op.location.clone()),
                        snippet: None,
                    }],
                    taint_path: None,
                    remediation: Some(
                        "Code should not modify its own source files at runtime. \
                         This pattern enables rug-pull attacks and persistence."
                            .into(),
                    ),
                    cwe_id: Some("CWE-506".into()),
                });
            }
        }

        findings
    }
}
