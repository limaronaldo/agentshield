use serde::{Deserialize, Serialize};

use super::SourceLocation;

/// A declared tool/function exposed by the extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSurface {
    pub name: String,
    pub description: Option<String>,
    /// JSON Schema of the tool's input parameters.
    pub input_schema: Option<serde_json::Value>,
    /// JSON Schema of the tool's output.
    pub output_schema: Option<serde_json::Value>,
    /// Permissions declared by the tool (if any).
    pub declared_permissions: Vec<DeclaredPermission>,
    /// Source location where the tool is defined.
    pub defined_at: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredPermission {
    pub permission_type: PermissionType,
    /// e.g., "filesystem:/tmp/*"
    pub target: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionType {
    FileRead,
    FileWrite,
    NetworkAccess,
    ProcessExec,
    EnvAccess,
    DatabaseAccess,
    Unknown,
}
