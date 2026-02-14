use crate::error::Result;
use crate::rules::policy::PolicyVerdict;
use crate::rules::Finding;

use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    findings: &'a [Finding],
    verdict: &'a PolicyVerdict,
}

/// Render findings as a JSON report.
pub fn render(findings: &[Finding], verdict: &PolicyVerdict) -> Result<String> {
    let report = JsonReport { findings, verdict };
    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}
