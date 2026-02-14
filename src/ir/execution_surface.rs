use serde::{Deserialize, Serialize};

use super::{ArgumentSource, SourceLocation};

/// Execution capabilities discovered through static analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionSurface {
    /// Commands/subprocesses invoked.
    pub commands: Vec<CommandInvocation>,
    /// File I/O operations.
    pub file_operations: Vec<FileOperation>,
    /// Network I/O operations.
    pub network_operations: Vec<NetworkOperation>,
    /// Environment variable accesses.
    pub env_accesses: Vec<EnvAccess>,
    /// Dynamic code execution (eval, exec, etc.).
    pub dynamic_exec: Vec<DynamicExec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInvocation {
    /// e.g., "subprocess.run", "os.system"
    pub function: String,
    pub command_arg: ArgumentSource,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation: FileOpType,
    pub path_arg: ArgumentSource,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOpType {
    Read,
    Write,
    Delete,
    List,
    Chmod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperation {
    /// e.g., "requests.get", "fetch"
    pub function: String,
    pub url_arg: ArgumentSource,
    /// GET, POST, etc.
    pub method: Option<String>,
    /// Does it send body/params?
    pub sends_data: bool,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAccess {
    pub var_name: ArgumentSource,
    /// Whether the variable name looks sensitive (AWS_*, SECRET_*, API_KEY, etc.)
    pub is_sensitive: bool,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicExec {
    /// eval, exec, compile, __import__
    pub function: String,
    pub code_arg: ArgumentSource,
    pub location: SourceLocation,
}
