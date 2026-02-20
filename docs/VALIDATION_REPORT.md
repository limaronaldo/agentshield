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
| **fetch** | Python | 4 | ~~0 (FN)~~ → 2 SSRF + 2 Prompt Injection (**fixed**) |
| **filesystem** | TypeScript | 101 | **Noisy** — 87 high but all post-validation |
| **git** | Python | 9 | ~~0 (FN)~~ → 9 cmd injection via GitPython (**fixed**) |
| **memory** | TypeScript | 25 | 17 high (mostly test files) |
| **sequentialthinking** | TypeScript | 11 | Supply-chain only |
| **time** | TypeScript | 0 | Correct — no dangerous patterns |

**Total findings across 7 servers:** 170 (was 157 before P1 fixes)

---

## Bugs Found

### P0: Parser panic on single-char string literals

**Fixed in:** commit `59b7ad6`

`classify_argument_text` in `typescript.rs:694` panicked with `begin <= end (1 <= 0)` when tree-sitter produced a node containing just `"` or `'`. Crashed on `everything` and `filesystem` servers.

**Root cause:** `&first_arg[1..first_arg.len() - 1]` underflows when `first_arg.len() == 1`.

**Fix:** Added `first_arg.len() >= 2` guard before slicing.

---

## False Negatives (Critical) — All Fixed

### FN-1: `fetch` server — SSRF not detected (SHIELD-003) — FIXED

**Expected:** SHIELD-003 (SSRF) + SHIELD-007 (Prompt Injection Surface)

**Actual (before fix):** 0 findings | **After fix:** 4 findings (2× SHIELD-003, 2× SHIELD-007)

**Root cause:** The fetch server uses `httpx.AsyncClient` context manager pattern:

```python
async with AsyncClient(proxies=proxy_url) as client:
    response = await client.get(url, ...)  # user-controlled URL
```

The Python parser's `NETWORK_PATTERNS` includes `httpx.get` but not `client.get` — it can't follow the variable binding from `AsyncClient()` to `client.get()`.

**Fix applied:** Added `HTTP_CLIENT_CTX_RE` regex to track async context manager bindings (`async with AsyncClient() as client:`), `HTTP_CLIENT_METHODS` list for variable method matching, and `PARTIAL_CALL_RE` for multi-line function call detection.

### FN-2: `git` server — command execution not detected (SHIELD-001) — FIXED

**Expected:** SHIELD-001 (Command Injection)

**Actual (before fix):** 0 findings | **After fix:** 9 findings (all SHIELD-001)

**Root cause:** The git server uses `GitPython` library:

```python
repo.git.log(*args)      # user timestamps in args
repo.git.add("--", *files)  # user file list
repo.git.branch(name)    # user branch name
```

The Python parser's `EXEC_PATTERNS` includes `subprocess.run`, `os.system`, etc. but not GitPython's `repo.git.*` methods, which are dynamic method dispatchers that execute shell commands.

**Fix applied:** Added `GITPYTHON_RE` regex matching `<var>.git.<method>(...)` patterns as command invocations.

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

### FP-4: `vitest` flagged as typosquat of `pytest` (SHIELD-010) — FIXED

`vitest` (JavaScript test runner) was flagged as similar to `pytest` (Python test runner). These are both well-known, legitimate packages. The Levenshtein distance is 2 (vi→py), which triggers the threshold.

**Fix applied:** Added `KNOWN_SAFE` allowlist (`vitest`, `nuxt`, `vite`, etc.) that skips Levenshtein comparison for known-good packages.

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
| **P1** | ~~Async HTTP client detection (FN-1)~~ | **Fixed** — fetch server: 4 findings | Done |
| **P1** | ~~Library command abstractions — GitPython (FN-2)~~ | **Fixed** — git server: 9 findings | Done |
| **P2** | Test file exclusion flag | Medium — reduces noise by ~60% | Low |
| **P2** | ~~`vitest` allowlist (FP-4)~~ | **Fixed** — known-safe packages allowlist | Done |
| **P3** | Cross-file validation tracking (FP-1) | High — but very complex | High |

---

## Post-Fix Re-Scan (Feb 20, 2026)

After implementing the P1 fixes, re-scanning the two previously-missed servers:

| Server | Before | After | Key Findings |
|--------|--------|-------|-------------|
| **fetch** | 0 | **4** | 2× SHIELD-003 (SSRF), 2× SHIELD-007 (Prompt Injection) |
| **git** | 0 | **9** | 9× SHIELD-001 (Command Injection via `repo.git.*`) |

**Fixes applied:**
1. Async HTTP context manager tracking (`AsyncClient`/`ClientSession` → variable method calls)
2. Multi-line function call detection (partial call regex + next-line lookahead)
3. GitPython `repo.git.*` command pattern matching
4. Typosquat allowlist for `vitest`, `nuxt`, and other known-safe packages

**Updated total:** 157 → **170** findings across 7 servers.

---

## Metrics (v0.2.0)

| Metric | Value |
|--------|-------|
| Servers scanned | 7 |
| Total findings | 170 (was 157 before P1 fixes) |
| True positives | ~48 (28%) |
| False positives | ~90 (53%) — mostly test files |
| False negatives | ~~2 critical~~ → **0** (both fixed) |
| Parser crashes | 1 (fixed) |
| Supply-chain (expected) | ~32 (19%) |

---

## v0.2.2 Update: Cross-File Validation Tracking

**Date:** February 20, 2026
**Scanner:** AgentShield v0.2.2 (commit `25a7757`)
**Linear:** [IBVI-482](https://linear.app/mbras/issue/IBVI-482)

### What Changed

v0.2.2 adds cross-file sanitizer-aware validation tracking. When a helper function is only ever called with sanitized arguments (e.g., after `validatePath()`), its parameters are downgraded from tainted to `Sanitized`, eliminating false positives.

### Validated with Test Fixture

The `safe_filesystem` fixture (`tests/fixtures/mcp_servers/safe_filesystem/`) mimics Anthropic's filesystem MCP server pattern:

```
index.ts      — public handler: validatePath(args.path) → readFileContent(validPath)
operations.ts — internal helper: fs.readFile(filePath, 'utf-8')
utils.ts      — sanitizer: validatePath() with allowlist check
```

**Result:** 0 SHIELD-004 findings (previously would have produced false positives on every `fs.readFile`/`fs.writeFile`/`fs.readdir` in operations.ts).

### Expected Impact on Real Filesystem Server

The v0.2.0 scan of Anthropic's filesystem server produced:
- 54 SHIELD-004 (Arbitrary File Access) — all post-validation, all false positives
- 33 SHIELD-006 (Self-Modification) — all writes to validated paths, all false positives

With v0.2.2 cross-file analysis, the production code findings (8 SHIELD-004 + SHIELD-006 in non-test files) should be eliminated because all call sites pass through `validatePath()`.

Test file findings (~79) remain — these need the `--ignore-tests` feature (not yet implemented).

### Updated Improvement Priorities

| Priority | Issue | Impact | Status |
|----------|-------|--------|--------|
| **P0** | ~~Parser panic on single-char strings~~ | Fixed v0.2.0 | Done |
| **P1** | ~~Async HTTP client detection~~ | Fixed v0.2.1 | Done |
| **P1** | ~~GitPython command detection~~ | Fixed v0.2.1 | Done |
| **P2** | ~~Typosquat allowlist~~ | Fixed v0.2.1 | Done |
| **P3** | ~~Cross-file validation tracking~~ | Fixed v0.2.2 | Done |
| **P2** | Test file exclusion (`--ignore-tests`) | Reduces noise ~60% | Pending |
