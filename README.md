# AgentShield

**Security scanner for AI agent extensions — offline-first, multi-framework, SARIF output.**

[![CI](https://github.com/limaronaldo/agentshield/actions/workflows/ci.yml/badge.svg)](https://github.com/limaronaldo/agentshield/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Crates.io](https://img.shields.io/crates/v/agent-shield.svg)](https://crates.io/crates/agent-shield)
[![docs.rs](https://img.shields.io/docsrs/agent-shield)](https://docs.rs/agent-shield)

AgentShield scans MCP servers, OpenClaw skills, and other AI agent extensions for security vulnerabilities **before they reach production**. Single Rust binary, zero data sharing, runs entirely on your machine.

---

## Why AgentShield?

AI agents are being given tools that can execute commands, read files, make HTTP requests, and install packages. A single malicious or poorly-written extension can:

- **Exfiltrate credentials** — read env vars and POST them to an external server
- **Execute arbitrary commands** — pass user input straight to `subprocess.run(shell=True)`
- **Install backdoors at runtime** — `pip install` inside a tool handler
- **Serve as SSRF proxies** — fetch attacker-controlled URLs from tool parameters

AgentShield catches these patterns with 12 built-in detectors and cross-file validation tracking that eliminates false positives, producing SARIF reports that integrate directly with GitHub Code Scanning.

### How it compares

| Feature | AgentShield | mcp-scan | Invariant Labs |
|---------|:-----------:|:--------:|:--------------:|
| Rust single binary | Yes | No (Python) | No (Cloud) |
| Offline / local-first | Yes | Partial | No |
| Multi-framework | MCP, OpenClaw | MCP only | MCP only |
| Cross-file analysis | Yes | No | No |
| SARIF output | Yes | No | No |
| GitHub Action | Yes | No | No |
| Static analysis (AST) | tree-sitter | Regex | Runtime |

---

## Quick Start

### GitHub Action (recommended)

Add to `.github/workflows/security.yml`:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: limaronaldo/agentshield@v1
        with:
          path: '.'
          fail-on: 'high'
          upload-sarif: true
```

Findings appear as PR annotations and in the repository's **Security > Code scanning** tab.

### CLI

```bash
# Install from crates.io
cargo install agent-shield

# Scan current directory
agentshield scan .

# Scan with specific format and threshold
agentshield scan ./my-mcp-server --format sarif --fail-on medium --output results.sarif

# Generate HTML report
agentshield scan ./my-mcp-server --format html --output report.html

# List all rules
agentshield list-rules

# Create starter config
agentshield init
```

### Pre-built binaries

Download from the [latest release](https://github.com/limaronaldo/agentshield/releases/latest) — available for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64).

### From source

```bash
git clone https://github.com/limaronaldo/agentshield.git
cd agentshield
cargo build --release
./target/release/agentshield scan /path/to/mcp-server
```

---

## Detection Rules

| ID | Name | Severity | What it detects |
|----|------|----------|-----------------|
| SHIELD-001 | Command Injection | Critical | `subprocess`/`os.system` with non-literal args |
| SHIELD-002 | Credential Exfiltration | Critical | Reads secrets + makes HTTP requests in same file |
| SHIELD-003 | SSRF | High | Fetches URLs from tool parameters |
| SHIELD-004 | Arbitrary File Access | High | File read/write with parameter-derived paths |
| SHIELD-005 | Runtime Package Install | High | `pip install`/`npm install` at runtime |
| SHIELD-006 | Self-Modification | High | Writes to own source files |
| SHIELD-007 | Prompt Injection Surface | Medium | Returns unescaped external content to LLM |
| SHIELD-008 | Excessive Permissions | Medium | Declares more capabilities than used |
| SHIELD-009 | Unpinned Dependencies | Medium | No version pinning (`>=`, `~=`, `^`, `*`) |
| SHIELD-010 | Typosquat Detection | Medium | Package name similar to popular packages |
| SHIELD-011 | Dynamic Code Execution | Critical | `eval`/`exec` with non-literal args |
| SHIELD-012 | No Lockfile | Low | Dependencies declared without lockfile |

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Console | `--format console` | Local development (default) |
| JSON | `--format json` | Programmatic consumption |
| SARIF | `--format sarif` | GitHub Code Scanning, VS Code |
| HTML | `--format html` | Shareable standalone reports |

### Console output

```
  4 finding(s) detected:

  [CRITICAL] SHIELD-001 'subprocess.run' receives parameter 'command' as command argument
           at server.py:13
           fix: Validate and sanitize the input, or use an allowlist of permitted commands.

  [HIGH]     SHIELD-003 HTTP request to URL from parameter 'url'
           at server.py:8
           fix: Validate URLs against an allowlist of permitted domains.

  Result: FAIL (threshold: high, highest: critical)
```

---

## Configuration

Create `.agentshield.toml` in your project root (or run `agentshield init`):

```toml
[policy]
# Minimum severity to fail the scan (info, low, medium, high, critical)
fail_on = "high"

# Rules to skip entirely
ignore_rules = ["SHIELD-008"]

# Downgrade specific rules
[policy.overrides]
"SHIELD-012" = "info"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan passed (no findings above threshold) |
| 1 | Scan failed (findings above threshold) |
| 2 | Scan error (invalid config, no adapter found, etc.) |

---

## Supported Frameworks

| Framework | Status | Adapter |
|-----------|--------|---------|
| MCP (Model Context Protocol) | Supported | Auto-detects `package.json` with MCP SDK + Python source |
| OpenClaw | Supported | Auto-detects `SKILL.md` files |
| LangChain | Planned | — |
| CrewAI | Planned | — |

---

## Language Support

| Language | Parser | Feature Flag |
|----------|--------|-------------|
| Python | tree-sitter AST | `python` (default) |
| TypeScript/TSX | tree-sitter AST | `typescript` (default) |
| JavaScript/JSX | tree-sitter AST | `typescript` (default) |
| Shell (bash/zsh) | Regex | always on |
| JSON Schema | MCP tool input parser | always on |

Both tree-sitter parsers are feature-gated. Build without them for a smaller binary:

```bash
cargo build --no-default-features   # regex fallback for all languages
cargo build --features python        # only Python AST
cargo build --features full          # all parsers
```

---

## Architecture

```
CLI / GitHub Action
       │
┌──────▼──────┐
│  Scan Engine │ ── scan() → ScanReport
└──────┬──────┘
       │
  ┌────┼────────────┐
  ▼    ▼            ▼
Adapters  Parsers    Supply Chain
MCP,      Python,    Analysis
OpenClaw  TypeScript,
          Shell,
          JSON Schema
  └────┬────────────┘
       ▼
  Cross-File Analysis
  (sanitizer tracking)
       ▼
  Unified IR (ScanTarget)
       │
  ┌────▼────┐
  │  Rules  │ ── 12 detectors
  │  Engine │
  └────┬────┘
       ▼
    Output
  SARIF, JSON,
  HTML, Console
```

Adapters translate framework-specific files into a **unified intermediate representation** (`ScanTarget`). Cross-file analysis eliminates false positives from helper functions that receive already-validated input. Detectors only read the IR, so adding a new framework never requires changing any detector.

---

## Development

```bash
# Run tests
cargo test

# Run with strict lints
cargo clippy -- -D warnings

# Check formatting
cargo fmt --check

# Build release binary
cargo build --release
```

---

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
