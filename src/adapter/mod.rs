pub mod mcp;
pub mod openclaw;

use std::path::Path;

use crate::error::{Result, ShieldError};
use crate::ir::{Framework, ScanTarget};

/// An adapter detects a specific agent framework and loads its artifacts
/// into the unified IR.
pub trait Adapter: Send + Sync {
    /// The framework this adapter handles.
    fn framework(&self) -> Framework;

    /// Check if this adapter can handle the given directory.
    fn detect(&self, root: &Path) -> bool;

    /// Load artifacts from the directory into scan targets.
    fn load(&self, root: &Path) -> Result<Vec<ScanTarget>>;
}

/// All registered adapters.
pub fn all_adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(mcp::McpAdapter),
        Box::new(openclaw::OpenClawAdapter),
    ]
}

/// Auto-detect the framework and load scan targets.
pub fn auto_detect_and_load(root: &Path) -> Result<Vec<ScanTarget>> {
    let adapters = all_adapters();

    for adapter in &adapters {
        if adapter.detect(root) {
            return adapter.load(root);
        }
    }

    Err(ShieldError::NoAdapter(root.display().to_string()))
}
