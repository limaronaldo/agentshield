use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::SourceLocation;

/// Dependency information extracted from lockfiles and manifests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencySurface {
    /// Parsed dependencies.
    pub dependencies: Vec<Dependency>,
    /// Lockfile information.
    pub lockfile: Option<LockfileInfo>,
    /// Issues found in dependency analysis.
    pub issues: Vec<DependencyIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version_constraint: Option<String>,
    pub locked_version: Option<String>,
    pub locked_hash: Option<String>,
    /// "pypi", "npm", etc.
    pub registry: String,
    pub is_dev: bool,
    pub location: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileInfo {
    pub path: PathBuf,
    pub format: LockfileFormat,
    pub all_pinned: bool,
    pub all_hashed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockfileFormat {
    PipRequirements,
    PipenvLock,
    PoetryLock,
    UvLock,
    NpmLock,
    PnpmLock,
    YarnLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyIssue {
    pub issue_type: DependencyIssueType,
    pub package_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyIssueType {
    Unpinned,
    NoHash,
    PossibleTyposquat,
    NoLockfile,
}
