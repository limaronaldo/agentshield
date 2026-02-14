use serde::{Deserialize, Serialize};

/// Provenance metadata — who wrote this, where it came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceSurface {
    /// Author information (from package.json, pyproject.toml, etc.)
    pub author: Option<String>,
    /// Repository URL.
    pub repository: Option<String>,
    /// License.
    pub license: Option<String>,
    /// Whether the package is signed.
    pub signed: bool,
    /// Checksum of the distribution (if from registry).
    pub checksum: Option<String>,
}
