# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-20

### Added

- **TypeScript tree-sitter parser** — AST-based parsing replaces regex for TypeScript/JavaScript
  - Multi-line call expression detection (regex parser missed calls spanning multiple lines)
  - Accurate line/column source locations from AST node positions
  - Proper scope-aware parameter tracking across nested callbacks and closures
  - Destructured parameter support (`{ url }` patterns now tracked for taint analysis)
  - TSX/JSX file support via `LANGUAGE_TSX` grammar
  - Feature-gated: `typescript` feature (enabled by default)
  - Regex fallback preserved when feature is disabled (`--no-default-features`)

### Changed

- Default features now include `typescript` alongside `python`
- `full` feature includes both `python` and `typescript`
- Version bump: 0.1.0 → 0.2.0

## [0.1.0] - 2026-02-13

### Added

- **12 built-in security detectors**
  - SHIELD-001: Command Injection (Critical, CWE-78)
  - SHIELD-002: Credential Exfiltration (Critical, CWE-522)
  - SHIELD-003: SSRF (High, CWE-918)
  - SHIELD-004: Arbitrary File Access (High, CWE-22)
  - SHIELD-005: Runtime Package Install (High, CWE-829)
  - SHIELD-006: Self-Modification (High, CWE-506)
  - SHIELD-007: Prompt Injection Surface (Medium)
  - SHIELD-008: Excessive Permissions (Medium, CWE-250)
  - SHIELD-009: Unpinned Dependencies (Medium, CWE-1104)
  - SHIELD-010: Typosquat Detection (Medium, CWE-506)
  - SHIELD-011: Dynamic Code Execution (Critical, CWE-95)
  - SHIELD-012: No Lockfile (Low)

- **Framework adapters**
  - MCP (Model Context Protocol) server auto-detection
  - OpenClaw SKILL.md adapter

- **Language parsers**
  - Python (tree-sitter AST + regex source/sink detection)
  - Shell (regex-based command extraction)
  - JSON Schema (MCP tool input parsing)

- **Output formats**
  - Console (plain text with severity badges)
  - JSON (structured findings + verdict)
  - SARIF 2.1.0 (GitHub Code Scanning compatible)
  - HTML (self-contained dark-themed report)

- **Policy system**
  - `.agentshield.toml` configuration
  - Configurable fail-on severity threshold
  - Rule ignore list and severity overrides

- **CLI**
  - `agentshield scan` — scan with format/threshold/output options
  - `agentshield list-rules` — display all rules (table or JSON)
  - `agentshield init` — generate starter config

- **CI/CD**
  - GitHub Action (`action.yml`) with SARIF upload
  - CI workflow (test, clippy, fmt, smoke test on 3 OS)
  - Release workflow (5-platform binary builds with SHA256 checksums)

- **Supply chain analysis**
  - Lockfile detection (pip, poetry, uv, npm, yarn, pnpm)
  - Typosquat detection via Levenshtein distance against popular packages
  - Unpinned dependency version detection

[0.2.0]: https://github.com/limaronaldo/agentshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/limaronaldo/agentshield/releases/tag/v0.1.0
