use serde::{Deserialize, Serialize};

use super::SourceLocation;

/// Data flow surfaces — what data enters and exits the extension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataSurface {
    /// Taint sources (where untrusted data enters).
    pub sources: Vec<TaintSource>,
    /// Taint sinks (where data exits or has impact).
    pub sinks: Vec<TaintSink>,
    /// Detected taint paths (source -> sink connections).
    pub taint_paths: Vec<TaintPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub source_type: TaintSourceType,
    pub description: String,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceType {
    /// User/LLM-provided tool input.
    ToolArgument,
    /// Prompt text (prompt injection vector).
    PromptContent,
    /// Environment variable read.
    EnvVariable,
    /// Credential/secret access.
    SecretStore,
    /// Data from HTTP response.
    HttpResponse,
    /// Data read from files.
    FileContent,
    /// Data from DB queries.
    DatabaseQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub sink_type: TaintSinkType,
    pub description: String,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSinkType {
    /// subprocess, os.system, exec
    ProcessExec,
    /// eval(), exec(), compile()
    DynamicEval,
    /// Outbound HTTP (exfiltration).
    HttpRequest,
    /// Write to filesystem.
    FileWrite,
    /// print, logging (info leak).
    LogOutput,
    /// SQL injection potential.
    DatabaseWrite,
    /// Data returned to the LLM.
    ResponseToLlm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: TaintSource,
    pub sink: TaintSink,
    /// Intermediate nodes in the taint propagation.
    pub through: Vec<SourceLocation>,
    /// Confidence that this path is exploitable (0.0-1.0).
    pub confidence: f32,
}
