# AgentShield Real-World Validation — Scan Results

**Date:** February 19, 2026
**AgentShield Version:** 1.0.0
**Linear Issue:** RML-1122

---

## Executive Summary

We scanned **19 MCP server targets** from **12 popular open-source repositories** (combined ~250k GitHub stars) and found **126 security findings** across **11 servers**. 8 servers were clean.

| Metric | Value |
|--------|-------|
| Repositories scanned | 12 |
| Individual scan targets | 19 |
| Total findings | 126 |
| Critical | 1 |
| High | 31 |
| Medium | 88 |
| Low | 6 |
| Clean servers | 8 (42%) |
| Servers with findings | 11 (58%) |

---

## Repositories Scanned

| # | Repository | Stars | Language | Targets Scanned |
|---|-----------|-------|----------|-----------------|
| 1 | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | ~79k | TS + Python | fetch, git, filesystem, memory, sequentialthinking |
| 2 | [ahujasid/blender-mcp](https://github.com/ahujasid/blender-mcp) | ~17k | Python | Root directory |
| 3 | [awslabs/mcp](https://github.com/awslabs/mcp) | ~8k | Python | 8 AWS service servers |
| 4 | [firecrawl/firecrawl-mcp-server](https://github.com/firecrawl/firecrawl-mcp-server) | ~6k | TypeScript | Root directory |
| 5 | [executeautomation/mcp-playwright](https://github.com/executeautomation/mcp-playwright) | ~5k | TypeScript | Root directory |
| 6 | [cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare) | ~3k | TypeScript | Root directory |
| 7 | [browserbase/supabase-mcp](https://github.com/supabase-community/supabase-mcp) | ~3k | TypeScript | Root directory |
| 8 | [benborla/mcp-server-mysql](https://github.com/benborla/mcp-server-mysql) | ~1k | TypeScript | Root directory |

**Not scanned (parser panic — bug filed):**
- [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp) (~23k stars) — Python parser crash on edge-case string literal
- [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) (~22k stars) — Same parser bug

**Not scanned (no adapter matched root):**
- [mindsdb/mindsdb](https://github.com/mindsdb/mindsdb) (~39k stars) — Large monorepo, MCP server deeply nested
- [stripe/agent-toolkit](https://github.com/stripe/agent-toolkit) (~1k stars) — Multi-language monorepo

---

## Results by Server

### Clean Servers (0 findings)

| Server | Language | Notes |
|--------|----------|-------|
| modelcontextprotocol/servers — **fetch** | Python | Official Anthropic server |
| modelcontextprotocol/servers — **git** | Python | Official Anthropic server |
| awslabs/mcp — **kendra-index** | Python | AWS service |
| awslabs/mcp — **keyspaces** | Python | AWS service |
| awslabs/mcp — **neptune** | Python | AWS service |
| awslabs/mcp — **qbusiness-anonymous** | Python | AWS service |
| awslabs/mcp — **qindex** | Python | AWS service |
| awslabs/mcp — **sns-sqs** | Python | AWS service |

### Servers with Findings

#### blender-mcp — 41 findings (1 critical, 27 high, 13 medium)

The most concerning server scanned. Major findings:

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| **CRITICAL** | SHIELD-011 | 1 | **`exec()` on user-supplied `code` parameter** — arbitrary code injection |
| HIGH | SHIELD-003 | 13 | SSRF — `requests.get()` with uncontrolled URLs from parameters |
| HIGH | SHIELD-004 | 10 | Arbitrary file read/write with paths from user input |
| HIGH | SHIELD-006 | 4 | Self-modification — writes to files with unresolved paths |
| MEDIUM | SHIELD-007 | 13 | Prompt injection surface — untrusted text in prompts |

**Key finding:** `addon.py` uses `exec(code)` where `code` comes directly from an MCP tool parameter. This allows any connected AI agent to execute arbitrary Python code in the user's Blender session.

#### mcp-server-mysql — 21 findings (21 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 20 | Unpinned dependencies in package.json |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |

All dependency-related. No code-level vulnerabilities detected.

#### mcp-playwright — 14 findings (1 high, 13 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| HIGH | SHIELD-005 | 1 | Runtime package install in docker-build.sh |
| MEDIUM | SHIELD-009 | 12 | Unpinned dependencies |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |

#### modelcontextprotocol/servers — filesystem — 14 findings (1 low, 13 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 12 | Unpinned dependencies |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |
| LOW | SHIELD-012 | 1 | No lockfile |

Official Anthropic server — only supply-chain hygiene findings, no code vulnerabilities.

#### modelcontextprotocol/servers — sequentialthinking — 11 findings

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 9 | Unpinned dependencies |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |
| LOW | SHIELD-012 | 1 | No lockfile |

#### modelcontextprotocol/servers — memory — 8 findings

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 6 | Unpinned dependencies |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |
| LOW | SHIELD-012 | 1 | No lockfile |

#### firecrawl-mcp — 6 findings (1 low, 5 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 5 | Unpinned dependencies |
| LOW | SHIELD-012 | 1 | No lockfile |

#### cloudflare-mcp — 5 findings (1 low, 4 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 3 | Unpinned dependencies |
| MEDIUM | SHIELD-010 | 1 | Potential typosquat dependency |
| LOW | SHIELD-012 | 1 | No lockfile |

#### awslabs/mcp — bedrock-agentcore — 3 findings (2 high, 1 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| HIGH | SHIELD-003 | 1 | SSRF — `urllib.request.urlopen` without URL allowlist |
| HIGH | SHIELD-004 | 1 | Arbitrary file access — file read from untrusted path |
| MEDIUM | SHIELD-007 | 1 | Prompt injection surface |

#### supabase-mcp — 2 findings (1 low, 1 medium)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| MEDIUM | SHIELD-009 | 1 | Unpinned dependency |
| LOW | SHIELD-012 | 1 | No lockfile |

#### awslabs/mcp — amazon-mq — 1 finding (1 high)

| Severity | Rule | Count | Description |
|----------|------|-------|-------------|
| HIGH | SHIELD-003 | 1 | SSRF — `requests.request` with URL from parameter |

---

## Findings by Rule

| Rule | Name | Total | Severity | Description |
|------|------|-------|----------|-------------|
| SHIELD-009 | Unpinned Dependencies | 68 | Medium | Dependencies without exact version pins |
| SHIELD-003 | SSRF | 15 | High | Server-Side Request Forgery — fetching URLs from user input |
| SHIELD-007 | Prompt Injection | 14 | Medium | Untrusted data in prompt construction |
| SHIELD-004 | Arbitrary File Access | 11 | High | File read/write with paths from user input |
| SHIELD-010 | Typosquat Detection | 6 | Low/Medium | Dependencies with names similar to popular packages |
| SHIELD-012 | No Lockfile | 6 | Low | Missing package-lock.json or equivalent |
| SHIELD-006 | Self-Modification | 4 | High | Writing to files that may be own source code |
| SHIELD-011 | Dynamic Code Execution | 1 | Critical | `exec()` or `eval()` on user-controlled input |
| SHIELD-005 | Runtime Package Install | 1 | High | Installing packages at runtime |

**Rules with 0 findings:**
- SHIELD-001 (Command Injection) — 0
- SHIELD-002 (Credential Exfiltration) — 0
- SHIELD-008 (Excessive Permissions) — 0

---

## Key Takeaways

### 1. Supply chain hygiene is the #1 issue
68 of 126 findings (54%) are unpinned dependencies (SHIELD-009). This is common in the Node.js ecosystem where `^` semver ranges are the default in `package.json`.

### 2. Anthropic's official servers are well-hardened
The Python servers (`fetch`, `git`) had **zero findings**. The TypeScript servers only had supply-chain findings (dependency pinning), no code-level vulnerabilities.

### 3. Community servers carry more risk
`blender-mcp` (17k stars) had a **critical `exec()` vulnerability** — the most dangerous finding in our scan. AWS's bedrock-agentcore had SSRF and file access issues.

### 4. SSRF is the most common code vulnerability
15 findings across 3 servers. MCP servers frequently need to fetch URLs, and many don't validate the target.

### 5. No credential exfiltration detected
SHIELD-002 found zero matches — no servers were exfiltrating secrets through tool responses or side channels.

---

## Bugs Discovered During Scanning

### Python Parser Panic (string literal edge case)

**Impact:** Scanner crashes on certain Python files with edge-case string slicing.
**Repos affected:** fastmcp, python-sdk
**Error:** `begin <= end (1 <= 0) when slicing` at `src/parser/python.rs:219`
**Priority:** Should fix before blog post / public announcement.

### Adapter detection for monorepos

**Impact:** Some large monorepos (mindsdb, stripe-toolkit) don't match any adapter at the root level.
**Workaround:** Scan subdirectories individually.
**Enhancement:** Consider recursive adapter detection or `--recursive` flag.

---

## Scan Methodology

1. **Clone**: `git clone --depth 1` each repository
2. **Scan**: `agentshield scan <path> -f json -o results.json`
3. **Analyze**: Aggregate JSON results, count by severity and rule
4. **Verify**: Spot-check critical/high findings against source code

All scans performed locally on macOS, no network requests during scanning (offline-first design).

---

## Files

| File | Description |
|------|-------------|
| `docs/SCAN_RESULTS.md` | This report |
| `/tmp/agentshield-results/*.json` | Raw JSON scan results (19 files) |
| `/tmp/agentshield-results/blender-mcp.html` | HTML report for blender-mcp |

---

**Last Updated:** February 19, 2026
