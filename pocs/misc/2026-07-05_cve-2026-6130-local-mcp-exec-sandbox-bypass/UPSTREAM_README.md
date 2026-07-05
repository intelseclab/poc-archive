# local-mcp

![Version](https://img.shields.io/badge/version-1.1.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen)
![Tests](https://img.shields.io/badge/tests-81%2F81-passing)
![Dependencies](https://img.shields.io/badge/dependencies-0-success)

**Zero-dependency MCP server for local file operations.** 13 filesystem tools + 3 meta-tools for progressive discovery — no SDKs, no frameworks, no `npm install` needed.

> **MCP Protocol:** 2024-11-05 · **Transport:** stdio + Streamable HTTP · **Runtime:** Node.js ≥ 22.0.0

---

## Architecture

```
local-mcp.mjs       — 595 lines, 13 tools, entry point
lib/mcp-core.mjs    — 229 lines, stdio + HTTP transport, 9 MCP methods
lib/config.mjs      —  31 lines, MCP_WORKSPACE/DATA env config with validation
```

**Total: ~855 lines, zero runtime dependencies.**

---

## Tools

### Filesystem Tools (13)

| Tool | Description | Annotation |
|------|-------------|------------|
| `read` | Read file with line numbers, optional `head`/`tail` truncation | `readOnlyHint` |
| `search` | File search by name (glob) then content (grep) | `readOnlyHint` |
| `ls` | Compact directory listing with lazy stat | `readOnlyHint` |
| `exec` | Streaming command execution with stdin support and timeout | `destructiveHint` |
| `diff` | Diff two files or text strings (Myers O(ND)) | `readOnlyHint` |
| `copy` | Copy file or directory | `destructiveHint` |
| `move` | Move or rename file/directory | `destructiveHint` |
| `batch` | Run multiple ops sequentially; atomic rollback, `$prev` refs | `destructiveHint` |
| `file` | Unified: read, write, edit, append, delete, info, mkdir, move | — |
| `block` | Read/replace/insert/delete code blocks by range or function name | — |
| `bookmark` | Persistent path aliases (add/get/list/delete) | — |
| `grep` | Compact `file:line:content` format with adaptive concurrency | `readOnlyHint` |
| `watch` | Watch file/directory for changes; max 20 concurrent watchers | — |

### Meta-Tools (3) — Progressive Discovery

| Tool | Description |
|------|-------------|
| `search_tools` | Search available tools by keyword — saves ~90% tokens vs listing all |
| `describe_tool` | Get full input schema for a specific tool (loaded on demand) |
| `call_tool` | Execute any tool by name with arguments |

Instead of sending all 13 tool schemas (~3,000 tokens) in every request, progressive discovery with these 3 meta-tools reduces it to ~50 tokens — **~90% token savings**.

---

## Performance Optimizations (v1.1.1)

| # | Optimization | Impact |
|---|-------------|--------|
| **A** | **Stream head/tail read** | `streamHead()` avoids reading entire files. 500MB logs: 3s → 5ms, memory: 500MB → few KB |
| **B** | **Lazy stat in ls** | Only calls `statSync` when `sort=size`. 1000-file dir: 50ms → 2ms |
| **C** | **Adaptive grep concurrency** | `os.availableParallelism()` (max 16, min 4) instead of hardcoded 16 workers |
| **D** | **LRU cache eviction** | Map insertion-order LRU — hot small files no longer evicted by cold large files |
| **E** | **Grep byte protection** | `MAX_GREP_TOTAL_MB=100` + `MAX_GREP_FILES=1000` guards prevent OOM |
| **F** | **Progress notification** | `_meta.progressToken` passthrough for MCP 2025 spec (TODO: events for long exec) |

### Additional Optimizations

| Area | Detail |
|------|--------|
| **Read cache** | Size-aware eviction (max 50 items, 10 MB) + 5s TTL |
| **Myers diff** | O(ND) algorithm, used by `edit`, `block`, and `diff` |
| **Search scoring** | Name-match first (no I/O), then stat only top 50 candidates |
| **Output format** | `grep`: `file:line:content`, `ls`: compact columns, `read`: line numbers + truncation hint |
| **Protocol** | O(1) Map dispatch, sync handler short-circuit |

---

## Getting Started

```bash
# Zero install — no dependencies
node local-mcp.mjs

# With configuration
MCP_WORKSPACE=D:/projects node local-mcp.mjs
```

### stdio mode (default)

```json
{
  "mcpServers": {
    "local-mcp": {
      "command": "node",
      "args": ["D:/path/to/local-mcp.mjs"],
      "env": {
        "MCP_WORKSPACE": "D:/projects"
      }
    }
  }
}
```

### HTTP mode

```bash
node local-mcp.mjs --http
node local-mcp.mjs --http --port 3456
```

Supports JSON-RPC 2.0 POST, SSE streaming (`Accept: text/event-stream`), CORS, and `GET /tools`.

### CLI flags

```bash
node local-mcp.mjs --help          # Show usage + env vars
node local-mcp.mjs --list-tools    # Print available tools and exit
node local-mcp.mjs --http          # Start HTTP mode
node local-mcp.mjs --http --port 3456
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WORKSPACE` | `process.cwd()` | Working directory root (security boundary) |
| `MCP_DATA` | `{WORKSPACE}/.mcp-data` | Data directory (bookmarks, temp files) |
| `MCP_DIR` | `{WORKSPACE}` | Default directory for tree/ls commands |
| `MCP_PORT` | `3100` | HTTP server port (when using `--http`) |
| `MCP_READONLY` | `false` | Set to `true` to block all write operations |
| `MCP_EXCLUDE` | — | Comma-separated extra dirs to exclude from search |

---

## Security

- All file operations restricted to `MCP_WORKSPACE` and subdirectories
- Prototype-safe bookmark keys (blocks `__proto__`/`constructor`/`prototype` injection)
- Atomic writes (temp + rename) prevent partial file writes
- Binary file detection prevents reading non-text files
- `.gitignore` and common exclude dirs (`node_modules`, `.git`, etc.) respected

---

## Dependencies

**Zero runtime dependencies.** Uses only Node.js built-ins:

| Module | Purpose |
|--------|---------|
| `fs` | File system + `glob` (Node 22) |
| `child_process` | Streaming shell execution |
| `http` | HTTP transport (no Express needed) |
| `path` | Path resolution |
| `os` | `availableParallelism()` for adaptive concurrency |
| `readline` | Streaming line-by-line processing |

---

## Changelog

### v1.1.1 — Performance Optimizations

- **A.** Stream head/tail read: 500MB logs 3s → 5ms
- **B.** Lazy stat in ls: 1000-file dir 50ms → 2ms
- **C.** Adaptive grep concurrency with `availableParallelism()`
- **D.** LRU cache eviction via Map insertion order
- **E.** Grep byte protection (100MB / 1000 files)
- **F.** Progress notification passthrough for MCP 2025 spec
- **Fix:** `streamHead` scope bug — `done` defined outside Promise callback

### v1.1.0

- 13 filesystem tools + 3 meta-tools for progressive discovery
- stdio + Streamable HTTP transport
- Myers diff engine, read cache, streaming exec
- Environment-based configuration with validation

---

## Development

```bash
# Run tests
node --test test/*.test.mjs

# Adding a tool
# 1. Define schema + handler in local-mcp.mjs
# 2. Register with server.tool()
# 3. Add tests
```

### Contributing

1. Maintain zero-dependency constraint
2. Add tests for new functionality
3. Update the Optimizations table for performance changes

---

## License

MIT
