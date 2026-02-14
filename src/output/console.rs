use crate::rules::policy::PolicyVerdict;
use crate::rules::{Finding, Severity};

/// Render findings as colored console output, grouped by severity then file path.
pub fn render(findings: &[Finding], verdict: &PolicyVerdict) -> String {
    let mut output = String::new();

    if findings.is_empty() {
        output.push_str("\n  No security findings detected.\n\n");
        return output;
    }

    // Sort by severity (critical first), then by file path
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then_with(|| {
            let a_file = a.location.as_ref().map(|l| &l.file);
            let b_file = b.location.as_ref().map(|l| &l.file);
            a_file.cmp(&b_file)
        })
    });

    output.push_str(&format!("\n  {} finding(s) detected:\n\n", findings.len()));

    for finding in &sorted {
        let severity_tag = match finding.severity {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]    ",
            Severity::Medium => "[MEDIUM]  ",
            Severity::Low => "[LOW]     ",
            Severity::Info => "[INFO]    ",
        };

        let location = finding
            .location
            .as_ref()
            .map(|l| format!("{}:{}", l.file.display(), l.line))
            .unwrap_or_else(|| "-".into());

        output.push_str(&format!(
            "  {} {} {}\n",
            severity_tag, finding.rule_id, finding.message
        ));
        output.push_str(&format!("           at {}\n", location));
        if let Some(remediation) = &finding.remediation {
            output.push_str(&format!("           fix: {}\n", remediation));
        }
        output.push('\n');
    }

    // Verdict
    let status = if verdict.pass { "PASS" } else { "FAIL" };
    output.push_str(&format!(
        "  Result: {} (threshold: {}, highest: {})\n\n",
        status,
        verdict.fail_threshold,
        verdict
            .highest_severity
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into()),
    ));

    output
}
