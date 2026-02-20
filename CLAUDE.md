# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**AgentShield** is a Rust-based, offline-first security scanner for AI agent extensions
(MCP servers, OpenClaw skills, LangChain tools). It produces SARIF output compatible
with GitHub Code Scanning.

## Repository Structure

```
agentshield/
├── src/
│   ├── lib.rs                    # Public API: scan(), render_report()
│   ├── error.rs                  # ShieldError (thiserror)
│   ├── bin/cli.rs                # Clap CLI: scan, list-rules, init
│   ├── ir/                       # Intermediate Representation (ScanTarget)
│   │   ├── mod.rs                # ScanTarget, Framework, SourceFile, ArgumentSource
│   │   ├── tool_surface.rs       # Tool definitions, permissions
│   │   ├── execution_surface.rs  # Commands, file IO, network IO
│   │   ├── data_surface.rs       # Sources, sinks, taint paths
│   │   ├── dependency_surface.rs # Dependencies, lockfiles
│   │   └── provenance_surface.rs # Author, repo, license
│   ├── adapter/                  # Framework → IR (3-phase pipeline)
│   │   ├── mod.rs                # Adapter trait, auto_detect_and_load()
│   │   ├── mcp.rs                # MCP server adapter
│   │   └── openclaw.rs           # OpenClaw SKILL.md adapter
│   ├── parser/                   # Language parsers
│   │   ├── mod.rs                # Parser trait, ParsedFile, FunctionDef, CallSite
│   │   ├── python.rs             # tree-sitter Python + regex patterns
│   │   ├── typescript.rs         # tree-sitter TypeScript/TSX + regex fallback
│   │   ├── shell.rs              # Regex-based shell parser
│   │   └── json_schema.rs        # JSON Schema → ToolSurface
│   ├── analysis/                 # Static analysis
│   │   ├── mod.rs                # Module exports
│   │   ├── capability.rs         # Capability escalation scoring
│   │   ├── cross_file.rs         # Cross-file sanitizer-aware validation (v0.2.2)
│   │   └── supply_chain.rs       # Typosquat detection
│   ├── rules/                    # Detection engine
│   │   ├── mod.rs                # RuleEngine, Detector trait
│   │   ├── finding.rs            # Finding, Severity, Evidence structs
│   │   ├── registry.rs           # Rule metadata registry
│   │   ├── policy.rs             # Policy evaluation (.agentshield.toml)
│   │   └── builtin/              # 12 built-in detectors (SHIELD-001..012)
│   ├── output/                   # Report formatters
│   │   ├── mod.rs                # OutputFormat enum, render()
│   │   ├── console.rs            # Plain text
│   │   ├── json.rs               # JSON
│   │   ├── sarif.rs              # SARIF 2.1.0
│   │   └── html.rs               # Self-contained HTML
│   └── config/                   # .agentshield.toml parsing
├── tests/fixtures/               # Test MCP servers (safe + vulnerable)
│   └── mcp_servers/
│       ├── safe_calculator/      # Zero-finding baseline
│       ├── safe_filesystem/      # Cross-file validation test (v0.2.2)
│       ├── vuln_cmd_inject/      # SHIELD-001 true positive
│       ├── vuln_ssrf/            # SHIELD-003 true positive
│       └── vuln_cred_exfil/      # SHIELD-002 true positive
├── .github/workflows/
│   ├── ci.yml                    # Test + clippy + fmt + smoke
│   └── release.yml               # 5-platform binary builds
└── action.yml                    # GitHub Action (composite)
```

## Common Commands

```bash
# Build
cargo build --release

# Test (83 tests)
cargo test

# Lint
cargo clippy -- -D warnings
cargo fmt --check

# Run CLI
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- list-rules
cargo run -- scan . --format html --output report.html
```

## Architecture Principles

1. **Adapters produce IR, detectors consume IR.** Adding a new framework never changes any detector.
2. **All adapters run.** `auto_detect_and_load()` runs every matching adapter, not just the first.
3. **ArgumentSource is the taint abstraction.** Detectors check `is_tainted()` — no full dataflow needed.
4. **Policy is separate from detection.** Detectors always run; policy decides what to report and whether to fail.
5. **Cross-file analysis runs between parsing and detection.** Downgrades taint for functions that only receive sanitized input.

## Key Types

- `ScanTarget` — unified IR with 5 surfaces (tool, execution, data, dependency, provenance)
- `Finding` — detector output with severity, confidence, location, evidence, remediation
- `ArgumentSource` — `Literal` (safe), `Parameter` (tainted), `EnvVar`, `Interpolated`, `Unknown`, `Sanitized` (safe, v0.2.2)
- `Detector` trait — `metadata() -> RuleMetadata`, `run(&ScanTarget) -> Vec<Finding>`
- `PolicyVerdict` — pass/fail with threshold and highest severity
- `ParsedFile` — parser output with `commands`, `file_operations`, `network_operations`, `function_defs`, `call_sites`, `sanitized_vars`
- `FunctionDef` — extracted function definition with name, params, `is_exported`
- `CallSite` — function call with callee name, classified arguments, caller context

## Adapter Pipeline (3-phase, v0.2.2)

Adapters use a 3-phase pipeline:

```
Phase 1: Parse     — each source file → ParsedFile (with FunctionDef, CallSite, sanitized_vars)
Phase 2: Analyze   — apply_cross_file_sanitization() downgrades tainted params to Sanitized
Phase 3: Merge     — combine all ParsedFiles into ScanTarget surfaces
```

This eliminates false positives from internal helpers that receive already-validated input:

```typescript
// index.ts — handler validates input
const validPath = await validatePath(args.path);  // sanitizer detected
const content = await readFileContent(validPath);  // CallSite with Sanitized arg

// operations.ts — helper uses validated input
export async function readFileContent(filePath: string) {
    return fs.readFile(filePath, 'utf-8');  // Parameter downgraded → no SHIELD-004
}
```

## Cross-File Analysis (`src/analysis/cross_file.rs`)

The `apply_cross_file_sanitization()` function:

1. **Phase 1:** Builds function def map (`name → file_index, params, is_exported`)
2. **Phase 2:** Builds call-site map (`callee → Vec<argument_sources>`)
3. **Phase 3:** For each function, checks if ALL call sites pass safe args (Literal or Sanitized) per parameter
4. **Phase 4:** If all-safe, downgrades matching `ArgumentSource::Parameter` to `Sanitized` in the callee's operations

**Conservative rules:**
- Exported functions with zero discovered call sites stay tainted
- If ANY call site passes a tainted argument, the parameter stays tainted
- Only one level deep (caller → callee, not recursive)

**Sanitizer registry** (`is_sanitizer()`): recognizes `validatePath`, `path.resolve`, `os.path.realpath`, `parseInt`, `URL.parse`, and pattern-based matches like `validate*Path`, `sanitize*`.

## Adding a New Detector

1. Create `src/rules/builtin/your_detector.rs`
2. Implement `Detector` trait (`metadata()` + `run()`)
3. Register in `src/rules/builtin/mod.rs` → `all_detectors()`
4. Add tests in the same file
5. Add fixture in `tests/fixtures/` if applicable
6. Run `cargo test && cargo clippy -- -D warnings`

## Adding a New Adapter

1. Create `src/adapter/your_framework.rs`
2. Implement `Adapter` trait (`name()`, `detect()`, `load()`)
3. Register in `src/adapter/mod.rs` → `all_adapters()`
4. `detect()` checks for framework-specific files
5. `load()` uses parsers to populate `ScanTarget`

## Conventions

- `thiserror` for error types, `?` operator everywhere
- No `unwrap()` in production paths
- tree-sitter for AST parsing, regex for pattern matching and fallback
- Tests use real fixture files under `tests/fixtures/`
- Conventional Commits for git messages
- Parsers extract `FunctionDef`, `CallSite`, and `sanitized_vars` for cross-file analysis
- `ArgumentSource::Sanitized` is the safe variant for cross-file validated params — `is_tainted()` returns `false`

## Version History

| Version | Tests | Key Feature |
|---------|-------|-------------|
| 0.1.0 | 46 | 12 detectors, Python parser, MCP/OpenClaw adapters |
| 0.2.0 | 69 | TypeScript tree-sitter parser, Homebrew, GitHub Action |
| 0.2.1 | 69 | Async HTTP detection, GitPython, typosquat allowlist, Marketplace |
| 0.2.2 | 83 | Cross-file validation tracking (IBVI-482) |
