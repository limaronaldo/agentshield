use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::{Finding, Severity};

/// Policy verdict — the final pass/fail decision after applying
/// ignore list and severity overrides to raw findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub pass: bool,
    pub total_findings: usize,
    pub effective_findings: usize,
    pub highest_severity: Option<Severity>,
    pub fail_threshold: Severity,
}

/// Policy configuration loaded from `.agentshield.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Minimum severity to fail the scan.
    #[serde(default = "default_fail_on")]
    pub fail_on: Severity,
    /// Rule IDs to ignore entirely.
    #[serde(default)]
    pub ignore_rules: HashSet<String>,
    /// Per-rule severity overrides.
    #[serde(default)]
    pub overrides: HashMap<String, Severity>,
}

fn default_fail_on() -> Severity {
    Severity::High
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            ignore_rules: HashSet::new(),
            overrides: HashMap::new(),
        }
    }
}

impl Policy {
    /// Evaluate findings against this policy and produce a verdict.
    pub fn evaluate(&self, findings: &[Finding]) -> PolicyVerdict {
        let effective: Vec<Severity> = findings
            .iter()
            .filter(|f| !self.ignore_rules.contains(&f.rule_id))
            .map(|f| {
                self.overrides
                    .get(&f.rule_id)
                    .copied()
                    .unwrap_or(f.severity)
            })
            .collect();

        let highest = effective.iter().copied().max();
        let failed = effective.iter().any(|&sev| sev >= self.fail_on);

        PolicyVerdict {
            pass: !failed,
            total_findings: findings.len(),
            effective_findings: effective.len(),
            highest_severity: highest,
            fail_threshold: self.fail_on,
        }
    }

    /// Filter findings: remove ignored rules, apply overrides.
    pub fn apply(&self, findings: &[Finding]) -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| !self.ignore_rules.contains(&f.rule_id))
            .map(|f| {
                let mut f = f.clone();
                if let Some(&override_sev) = self.overrides.get(&f.rule_id) {
                    f.severity = override_sev;
                }
                f
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{AttackCategory, Confidence};

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            rule_name: "Test".into(),
            severity,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "test".into(),
            location: None,
            evidence: vec![],
            taint_path: None,
            remediation: None,
            cwe_id: None,
        }
    }

    #[test]
    fn default_policy_fails_on_high() {
        let policy = Policy::default();
        let findings = vec![make_finding("SHIELD-001", Severity::High)];
        let verdict = policy.evaluate(&findings);
        assert!(!verdict.pass);
    }

    #[test]
    fn default_policy_passes_on_medium() {
        let policy = Policy::default();
        let findings = vec![make_finding("SHIELD-009", Severity::Medium)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
    }

    #[test]
    fn ignore_rule_removes_finding() {
        let mut policy = Policy::default();
        policy.ignore_rules.insert("SHIELD-001".into());
        let findings = vec![make_finding("SHIELD-001", Severity::Critical)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
        assert_eq!(verdict.effective_findings, 0);
    }

    #[test]
    fn override_downgrades_severity() {
        let mut policy = Policy::default();
        policy.overrides.insert("SHIELD-001".into(), Severity::Info);
        let findings = vec![make_finding("SHIELD-001", Severity::Critical)];
        let verdict = policy.evaluate(&findings);
        assert!(verdict.pass);
    }
}
