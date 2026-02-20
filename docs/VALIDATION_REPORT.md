# Real-World Validation Report

**Date:** February 20, 2026
**Scanner:** AgentShield v0.2.0 (commit `59b7ad6`, post-panic-fix)
**Target:** [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) — Anthropic's official MCP reference servers
**Linear:** [IBVI-481](https://linear.app/mbras/issue/IBVI-481)

---

## Summary

| Server | Language | Findings | Critical Issues |
|--------|----------|----------|----------------|
| **everything** | TypeScript | 20 | 4 high (SHIELD-003, -004) |
| **fetch** | Python | 0 | **False negative** — SSRF not detected |
| **filesystem** | TypeScript | 101 | **Noisy** — 87 high but all post-validation |
| **git** | Python | 0 | **False negative** — command exec not detected |
| **memory** | TypeScript | 25 | 17 high (mostly test files) |
| **sequentialthinking** | TypeScript | 11 | Supply-chain only |
| **time** | TypeScript | 0 | Correct — no dangerous patterns |

**Total findings across 7 servers:** 157

---

## Bugs Found

### P0: Parser panic on single-char string literals

**Fixed in:** commit `59b7ad6`

`classify_argument_text` in `typescript.rs:694` panicked with `begin <= end (1 <= 0)` when tree-sitter produced a node containing just `"` or `'`. Crashed on `everything` and `filesystem` servers.

**Root cause:** `&first_arg[1..first_arg.len() - 1]` underflows when `first_arg.len() == 1`.

**Fix:** Added `first_arg.len() >= 2` guard before slicing.

---

## False Negatives (Critical)

### FN-1: `fetch` server — SSRF not detected (SHIELD-003)

**Expected:** SHIELD-003 (SSRF) + SHIELD-007 (Prompt Injection Surface)

**Actual:** 0 findings

**Root cause:** The fetch server uses `httpx.AsyncClient` context manager pattern:

```python
async with AsyncClient(proxies=proxy_url) as client:
    response = await client.get(url, ...)  # user-controlled URL
```

The Python parser's `NETWORK_PATTERNS` includes `httpx.get` but not `client.get` — it can't follow the variable binding from `AsyncClient()` to `client.get()`.

**Fix needed:** Either:
- Add async context manager tracking to the Python parser (cross-statement taint)
- Add `client.get`, `client.post` etc. as network sink patterns
- Or use tree-sitter AST to follow variable assignments

### FN-2: `git` server — command execution not detected (SHIELD-001)

**Expected:** SHIELD-001 (Command Injection)

**Actual:** 0 findings

**Root cause:** The git server uses `GitPython` library:

```python
repo.git.log(*args)      # user timestamps in args
repo.git.add("--", *files)  # user file list
repo.git.branch(name)    # user branch name
```

The Python parser's `EXEC_PATTERNS` includes `subprocess.run`, `os.system`, etc. but not GitPython's `repo.git.*` methods, which are dynamic method dispatchers that execute shell commands.

**Fix needed:**
- Add GitPython patterns: `repo.git.`, `.git.execute`, `.git.log`, `.git.add`
- Consider a "library command abstraction" category for libraries that wrap shell execution

---

## False Positives

### FP-1: `filesystem` server — 54 SHIELD-004 findings, all post-validation

All 54 "Arbitrary File Access" findings are on functions that are called **after** `validatePath()` validates the input:

```typescript
// index.ts (public endpoints)
const validPath = await validatePath(args.path);  // always first
const content = await readFileContent(validPath);   // then operate

// lib.ts (internal, flagged by scanner)
export async function readFileContent(filePath: string) {
    return fs.readFile(filePath, 'utf-8');  // ← flagged as SHIELD-004
}
```

The scanner can't see the call-site validation because it's in a different file (single-file analysis).

**Distribution:** 8 in production code (all post-validation), 46 in test files.

**Fix options:**
- Cross-file taint analysis (IBVI-482) would resolve this
- `--ignore-tests` flag to skip test directories
- `validatePath()` could be recognized as a sanitizer pattern

### FP-2: `filesystem` server — 33 SHIELD-006 findings

All "Self-Modification" findings are on file writes that cannot reach the server's own source:
- Production writes use `validatePath()` restricted to user-configured `allowedDirectories`
- Test writes go to `os.tmpdir()` temp directories
- The server code is never in `allowedDirectories`

### FP-3: `memory` server — 17 high findings, mostly test files

12 SHIELD-004 and 5 SHIELD-006 findings, all in test files (`knowledge-graph.test.ts`, `file-path.test.ts`). Tests intentionally read/write to temp paths.

### FP-4: `vitest` flagged as typosquat of `pytest` (SHIELD-010)

`vitest` (JavaScript test runner) is flagged as similar to `pytest` (Python test runner). These are both well-known, legitimate packages. The Levenshtein distance is 2 (vi→py), which triggers the threshold.

**Fix needed:** Add `vitest` to the allowlist of known-good packages.

---

## True Positives

### TP-1: `everything` server — SHIELD-003 (SSRF) + SHIELD-004 (File Access)

The "everything" demo server intentionally exposes dangerous operations as examples:
- 1 SSRF finding (network fetch with user URL)
- 3 file access findings (file read/write with user paths)

These are correct detections on an intentionally vulnerable demo server.

### TP-2: All servers — SHIELD-009 (Unpinned Dependencies)

All servers use `^` ranges in `package.json` (e.g., `"@modelcontextprotocol/sdk": "^1.26.0"`). This is standard npm practice but does present supply-chain risk. Correct detection.

### TP-3: All servers — SHIELD-012 (No Lockfile)

The reference servers don't commit lockfiles (they use a monorepo root lockfile). Correct detection at the per-server level.

---

## Improvement Priorities

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| **P0** | ~~Parser panic on single-char strings~~ | **Fixed** | Done |
| **P1** | Async HTTP client detection (FN-1) | High — misses modern Python SSRF | Medium |
| **P1** | Library command abstractions — GitPython (FN-2) | High — misses real cmd injection | Low |
| **P2** | Test file exclusion flag | Medium — reduces noise by ~60% | Low |
| **P2** | `vitest` allowlist (FP-4) | Low — cosmetic | Trivial |
| **P3** | Cross-file validation tracking (FP-1) | High — but very complex | High |

---

## Metrics

| Metric | Value |
|--------|-------|
| Servers scanned | 7 |
| Total findings | 157 |
| True positives | ~35 (22%) |
| False positives | ~90 (57%) — mostly test files |
| False negatives | 2 critical (fetch SSRF, git cmd injection) |
| Parser crashes | 1 (fixed) |
| Supply-chain (expected) | ~32 (20%) |
