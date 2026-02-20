# Next Steps — Post v0.1.0

Status: v0.2.2 shipped Feb 20, 2026. TypeScript tree-sitter parser, crates.io, Homebrew, GitHub Action e2e, real-world validation, cross-file validation tracking — all done.

---

## ~~1. Real-World Validation~~ — Done

Completed Feb 20, 2026. Scanned 7 Anthropic reference MCP servers. See `docs/VALIDATION_REPORT.md` for full results.

### Results Summary

- **170 total findings** across 7 servers (everything, fetch, filesystem, git, memory, sequentialthinking, time)
- **0 false negatives** remaining (2 critical P1 issues found and fixed)
- **~53% false positives** (mostly test files — need `--ignore-tests` flag)
- **1 parser panic** found and fixed (single-char string literals)

### Bugs Found and Fixed

1. **P0: Parser panic** on single-char strings (`typescript.rs`) — fixed with length guard
2. **P1: Async HTTP client detection** — `httpx.AsyncClient`/`aiohttp.ClientSession` context manager method calls now detected via `HTTP_CLIENT_CTX_RE` + `HTTP_CLIENT_METHODS` + `PARTIAL_CALL_RE` (multi-line support)
3. **P1: GitPython command detection** — `repo.git.*` dynamic dispatchers now detected via `GITPYTHON_RE`
4. **P2: vitest typosquat FP** — added `KNOWN_SAFE` allowlist to typosquat detector

### Remaining Improvements

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| **P2** | Test file exclusion (`--ignore-tests`) | Medium — reduces noise ~60% | Low |
| ~~**P3**~~ | ~~Cross-file validation tracking~~ | ~~Done v0.2.2 (IBVI-482)~~ | ~~Done~~ |

---

## ~~2. Test GitHub Action End-to-End~~ — Done

Tested Feb 20, 2026. Test repo: [`limaronaldo/agentshield-test`](https://github.com/limaronaldo/agentshield-test)

### Results

- [x] Action downloads correct binary for ubuntu-latest (x86_64-unknown-linux-gnu)
- [x] Scan finds SHIELD-001, SHIELD-002, SHIELD-003, SHIELD-004, SHIELD-007 (7 total findings)
- [x] SARIF uploads to Code Scanning tab (5 alerts with source locations)
- [x] Action fails with exit code 1 (findings above `high` threshold)
- [ ] Creating a PR shows annotations inline (not yet tested)

### SARIF bugs found and fixed

Three SARIF validation issues were discovered during e2e testing and fixed:

1. **`startColumn` must be >= 1** — parser emits 0-based columns, SARIF 2.1.0 requires 1-based. Fixed with `.max(1)`.
2. **`fixes[]` requires `artifactChanges`** — removed invalid `fixes` array, moved remediation text to `result.properties.remediation`.
3. **Location-less results rejected** — supply-chain findings (SHIELD-009, SHIELD-012) have no source location; GitHub Code Scanning requires at least one. Fixed by filtering them from SARIF output (still appear in console/JSON/HTML).

---

## 3. ~~Publish to crates.io~~ — Done

Published as [`agent-shield`](https://crates.io/crates/agent-shield) v0.2.0 on Feb 20, 2026.
(`agentshield` name was taken by an unrelated crate; binary name remains `agentshield`.)

### Pre-publish checklist

- [x] Cargo.toml has: name, version, description, license, repository, readme
- [x] README.md exists
- [x] LICENSE exists
- [x] `cargo publish --dry-run` succeeds
- [x] No private/internal dependencies
- [x] Published to crates.io as `agent-shield`

---

## 4. v0.2.0 Roadmap

Features deferred from v0.1.0:

| Feature | Linear | Effort | Impact |
|---------|--------|--------|--------|
| ~~TypeScript parser (tree-sitter)~~ | ~~RML-1078~~ | ~~Done v0.2.0~~ | ~~High~~ |
| ~~Homebrew formula~~ | — | ~~Done v0.2.0~~ | ~~Medium~~ |
| ~~GitHub Action e2e test~~ | ~~IBVI-488~~ | ~~Done v0.2.0~~ | ~~High~~ |
| ~~Real-world validation~~ | ~~[IBVI-481](https://linear.app/mbras/issue/IBVI-481)~~ | ~~Done v0.2.0~~ | ~~High — 170 findings, 4 bugs fixed~~ |
| ~~Cross-file taint analysis~~ | ~~[IBVI-482](https://linear.app/mbras/issue/IBVI-482)~~ | ~~Done v0.2.2~~ | ~~Done — eliminates filesystem FPs~~ |
| ~~GitHub Marketplace submission~~ | ~~[IBVI-483](https://linear.app/mbras/issue/IBVI-483)~~ | ~~Done v0.2.1~~ | ~~High — [listed](https://github.com/marketplace/actions/agentshield-security-scanner)~~ |
| Blog post / announcement | [IBVI-484](https://linear.app/mbras/issue/IBVI-484) | Medium | High — launch content |
| VS Code extension | [IBVI-485](https://linear.app/mbras/issue/IBVI-485) | Medium | Medium — inline findings |
| LangChain adapter | [IBVI-486](https://linear.app/mbras/issue/IBVI-486) | Medium | Medium — new framework |
| CrewAI adapter | [IBVI-487](https://linear.app/mbras/issue/IBVI-487) | Low | Low — new framework |
| PR annotation test | [IBVI-488](https://linear.app/mbras/issue/IBVI-488) | Low | Low — verify inline annotations |

---

## 5. v0.2.2 — Cross-File Validation Tracking — Done

Completed Feb 20, 2026. See [IBVI-482](https://linear.app/mbras/issue/IBVI-482).

### What it does

Post-parsing analysis phase that recognizes sanitizer function calls (`validatePath`, `path.resolve`, etc.), tracks which variables hold sanitized results, and when a function is only called with sanitized arguments, downgrades its parameters from tainted to `Sanitized`. Detectors already check `is_tainted()` — `Sanitized` returns `false` — so **zero detector changes were needed**.

### Implementation

- `ArgumentSource::Sanitized { sanitizer }` variant in `src/ir/mod.rs`
- `FunctionDef`, `CallSite`, `sanitized_vars` in `src/parser/mod.rs`
- TypeScript + Python parsers extract these structures
- `apply_cross_file_sanitization()` in `src/analysis/cross_file.rs`
- 3-phase adapter pipeline (parse → cross-file analysis → merge) in MCP and OpenClaw adapters
- `safe_filesystem` test fixture (3 TypeScript files mimicking Anthropic's filesystem MCP server)
- 14 new tests (83 total, up from 69)

### Impact

Eliminates false positives from internal helper functions that receive already-validated input — the primary source of noise in the filesystem MCP server scan (54 SHIELD-004 + 33 SHIELD-006 findings were all false positives).

### Post-v0.2.2 Roadmap

| Feature | Linear | Effort | Impact |
|---------|--------|--------|--------|
| Test file exclusion (`--ignore-tests`) | — | Low | Medium — reduces remaining noise |
| Re-scan 7 Anthropic servers with v0.2.2 | — | Low | Medium — measure FP reduction |
| Blog post / announcement | [IBVI-484](https://linear.app/mbras/issue/IBVI-484) | Medium | High — launch content |
| VS Code extension | [IBVI-485](https://linear.app/mbras/issue/IBVI-485) | Medium | Medium — inline findings |
| LangChain adapter | [IBVI-486](https://linear.app/mbras/issue/IBVI-486) | Medium | Medium — new framework |
| CrewAI adapter | [IBVI-487](https://linear.app/mbras/issue/IBVI-487) | Low | Low — new framework |

---

## 6. Launch / Promotion

### Blog post outline: "We scanned N MCP servers — here's what we found"

1. Intro: AI agents are getting powerful tools, but who's checking the tools?
2. Methodology: scanned X open-source MCP servers with AgentShield
3. Findings breakdown: N command injections, N SSRF, N credential leaks
4. Case studies: 2-3 interesting real findings with code snippets
5. How to protect yourself: add AgentShield to your CI
6. CTA: GitHub Action link, star the repo

### Distribution channels

- Hacker News (Show HN)
- Reddit r/MachineLearning, r/rust
- Twitter/X (AI security community)
- MCP Discord / community channels
- Dev.to / Hashnode blog post

---

## Linear Project Reference

- Project: AgentShield - Security Scanner for AI Agent Extensions
- Project ID: bafa5ae7-f48a-4a45-8ec8-14f49fcac779 (IBVI org)
- Team: IBVI (e792ad0a-a7d5-4927-b7ef-4fe22dde0fd4)
- Repo: https://github.com/limaronaldo/agentshield
- v0.1.0 issues: Done (RML-1062..1091, migrated from MBRAS IBVI-311..340)
- v0.2.0 issues: IBVI-481..488 (created Feb 20, 2026)
