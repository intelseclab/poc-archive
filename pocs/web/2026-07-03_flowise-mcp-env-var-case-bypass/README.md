# Flowise Custom MCP Environment Variable Case Bypass

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-07 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | flowise, mcp, model-context-protocol, windows, environment-variable, case-insensitivity, node-options, rce |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Flowise / `flowise-components` |
| **Versions Affected** | 3.1.2 |
| **Language / Platform** | Node.js/TypeScript, Windows deployments (Custom MCP stdio transport) |
| **Authentication Required** | Yes (authenticated Flowise session or API-key context) |
| **Network Access Required** | Yes |

---

## Summary

Flowise's Custom MCP stdio node validates configured environment variables against a denylist (`PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `NODE_OPTIONS`) using exact, case-sensitive string comparison. Windows, however, treats environment variable names case-insensitively, so a casing variant such as `node_options` sails through Flowise's validation while still being honored by a spawned Node.js child process as `NODE_OPTIONS`. When the configured MCP command starts a Node.js process, this lets an authenticated user preload attacker-chosen JavaScript via Node's startup option handling, achieving code execution in the Flowise worker/server context on Windows. The included PoC models Flowise's validator, confirms the exact-case denylist blocks `NODE_OPTIONS` but not `node_options`, and launches a real Node.js child process to prove the lowercase variant is honored. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`packages/components/nodes/tools/MCP/core.ts`'s `validateEnvironmentVariables` denies dangerous environment variable names by exact-case string comparison (`dangerousEnvVars.includes(key)`), which is not platform-aware. On Windows, environment variable name matching is case-insensitive at the OS/process level, so a differently-cased key bypasses the check but is still applied by the child process.

### Attack Vector

1. Attacker obtains an authenticated Flowise session or API-key context that can configure or load a Custom MCP stdio node.
2. Attacker sets an environment variable named `node_options` (lowercase) instead of `NODE_OPTIONS` on the MCP server config, with a value like `--require <malicious-loader>`.
3. Flowise's exact-case validator does not match `node_options` against its denylist and allows the configuration.
4. `MCPToolkit.createClient` passes the environment map to the MCP SDK's `StdioClientTransport`, which spawns the configured command (a Node.js process) with that environment.
5. On Windows, Node.js resolves `node_options` to the same slot as `NODE_OPTIONS` and honors the injected startup flag, executing attacker-supplied code at process start.

### Impact

Code execution in the Flowise worker/server process on Windows deployments where Custom MCP stdio configuration is reachable by an authenticated user, potentially enabling privilege escalation within the Flowise environment or lateral movement from the compromised worker.

---

## Environment / Lab Setup

```
Target:   Flowise / flowise-components 3.1.2 on Windows
Attacker: Python 3.10+, Node.js available in PATH for the canary execution step
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python poc.py
python poc.py --marker C:\Temp\flowise_marker.txt
```

The script replicates Flowise's exact-case denylist check to show `NODE_OPTIONS` is blocked while `node_options` is accepted, then spawns a local Node.js process with the lowercase variant to confirm the environment variable is honored and a marker file is created — proving the case bypass and its code-execution consequence.

---

## Detection & Indicators of Compromise

```
# Custom MCP stdio configurations containing environment variable keys that are
# case-variant matches of PATH / LD_LIBRARY_PATH / DYLD_LIBRARY_PATH / NODE_OPTIONS
# (e.g., node_options, Node_Options, PaTh)
```

**Signs of compromise:**
- Unexpected Node.js `--require`/startup flags observed in spawned MCP child processes
- Custom MCP node configurations with unusual-casing environment variable names
- Anomalous file writes or network activity originating from Flowise worker processes shortly after MCP tool configuration changes

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Normalize environment variable names before denylist comparison on every platform, or switch to an allowlist of safe MCP stdio environment variables |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/flowise-mcp-env-case-bypass-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `flowise-mcp-env-case-bypass-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
