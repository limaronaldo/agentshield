//! Capability escalation heuristics.
//!
//! Analyzes whether an extension requests more capabilities than it uses,
//! or combines capabilities in dangerous ways.

use crate::ir::ScanTarget;

/// Compute a capability escalation score (0.0–1.0).
///
/// Higher values indicate more suspicious capability combinations.
/// Currently a stub — full implementation in a future release.
pub fn escalation_score(target: &ScanTarget) -> f64 {
    let has_network = !target.execution.network_operations.is_empty();
    let has_exec =
        !target.execution.commands.is_empty() || !target.execution.dynamic_exec.is_empty();
    let has_file = !target.execution.file_operations.is_empty();
    let has_env = !target.execution.env_accesses.is_empty();

    let capabilities = [has_network, has_exec, has_file, has_env];
    let count = capabilities.iter().filter(|&&c| c).count();

    match count {
        0 | 1 => 0.0,
        2 => 0.3,
        3 => 0.6,
        _ => 0.9,
    }
}
