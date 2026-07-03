# Ladybird Browser WebAssembly ESM Host-Function Use-After-Free RCE

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-07 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | Weaponized |
| **Tags** | ladybird, browser, webassembly, wasm-gc, use-after-free, memory-corruption, rce, javascript-engine, sandbox-escape |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Ladybird web browser (WebContent process, LibWeb / LibWasm) |
| **Versions Affected** | Upstream commit `31bb4d872d802c78ce23d2f273a300f36e8ef6a0` and likely surrounding history |
| **Language / Platform** | HTML/JavaScript PoC page; targets a native C++ browser engine on Linux |
| **Authentication Required** | No |
| **Network Access Required** | No (victim loads a local/remote HTML page in the browser) |

---

## Summary

The PoC targets a lifetime bug in Ladybird's WebAssembly ESM import path: `WebAssemblyModule.cpp` builds a `Wasm::FunctionType` as a stack-local value and passes it by reference into `create_host_function()`, so the resulting long-lived JS host callback retains a dangling reference to that type after the caller returns. Because the WebAssembly bytecode interpreter does not validate a host function's returned result arity against the statically declared call-site type, a host callback made to return zero values while the call site expects one leaves a stale, attacker-influenced value sitting in a destination register. That stale register is later consumed by a WebAssembly GC `array.set` operation as a raw pointer-shaped abstract reference, giving the attacker a write primitive through a fake `ArrayInstance`. The PoC pairs this with a separate `ImageData`/WebGL memory64 leak (a moved backing store still referenced by a stale bitmap pointer) to defeat ASLR, then pivots through a `DataView` retarget and a crafted `setcontext` frame to reach arbitrary native code execution inside the WebContent renderer process. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`create_host_function()` in `Libraries/LibWeb/WebAssembly/WebAssembly.cpp` captures `Wasm::FunctionType const& type` by reference for use inside a long-lived JS host callback, but the WASM ESM import path in `WebAssemblyModule.cpp` only supplies a stack-local `FunctionType`, producing a dangling reference. The bytecode interpreter (`BytecodeInterpreter.cpp`) then trusts a host callback's dynamically returned result vector without checking it against the statically declared result arity, leaving a stale register value that WASM GC `array.set` later dereferences after only a null check.

### Attack Vector

1. Import a JavaScript function into a WebAssembly ESM module declaring a static result type of `arrayref`.
2. Trigger the dangling `FunctionType` reference inside the generated host callback.
3. Make the host callback dynamically return zero WASM values, leaving the destination register stale with an attacker-shaped abstract GC reference.
4. Use WASM GC `array.set` to write through a fake `ArrayInstance` built from that stale reference.
5. Leak heap/library base addresses via an `ImageData` + WebGL `texImage2D`/`readPixels` primitive against a moved memory64 backing store.
6. Retarget a `DataView` for arbitrary native read/write and construct a fake virtual-dispatch target plus a `setcontext` frame.
7. Trigger a WebGL virtual call to redirect execution and run an attacker command in the WebContent process.

### Impact

Native code execution inside Ladybird's WebContent (renderer) process triggered purely by loading an attacker-controlled HTML page, with no user interaction beyond page load.

---

## Environment / Lab Setup

```
Target:   Ladybird browser built from commit 31bb4d872d802c78ce23d2f273a300f36e8ef6a0 (Linux)
Attacker: Locally hosted poc.html, no special tooling beyond a browser build
```

---

## Proof of Concept

### PoC Script

> See `poc.html` in this folder.

```bash
Build/gui-sanitizers/bin/ladybird --headless=screenshot --screenshot-delay=20 --screenshot-path=/tmp/ladybird-wasm-esm.png file:///absolute/path/to/poc.html
```

Loading the page drives the WASM type-confusion write primitive, leaks pointers via the ImageData/WebGL memory64 bug, and finally hijacks a virtual call to execute a native marker command (`touch /tmp/ladybird_wasm_esm_rce`), proving arbitrary code execution in the renderer process.

---

## Detection & Indicators of Compromise

```
# WebContent process crashing or exiting shortly after a page finishes loading WASM content
# Unexpected native process spawned as a child of the WebContent/Ladybird process
```

**Signs of compromise:**
- Ladybird WebContent process terminating unexpectedly right after evaluating WebAssembly with ESM host-function imports
- Unexplained file writes or child processes originating from the browser renderer sandbox
- Crash reports referencing `Wasm::ArrayInstance`, `array.set`, or `DataView` backing-store handling

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Disable WebAssembly execution for untrusted origins where feasible, or avoid pre-release/dev Ladybird builds for browsing untrusted content until a fix lands |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/ladybird-wasm-esm-host-function-rce-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `ladybird-wasm-esm-host-function-rce-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
