# Ghidra 12.1.2 Conditional Swift Demangler ACE (plus TraceRMI RCE and SevenZipJBinding Reachability)

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-07 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | binary |
| **Severity** | Medium |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | Incomplete PoC |
| **Tags** | ghidra, reverse-engineering, arbitrary-code-execution, tracermi, sevenzipjbinding, native-parser, conditional-exploit, calc-poc |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Ghidra (NSA reverse-engineering suite) |
| **Versions Affected** | 12.1.2 |
| **Language / Platform** | Java, Python 3 PoC harnesses |
| **Authentication Required** | Local-only (requires a configured/restored Swift tool directory, or an exposed TraceRMI debugger-agent channel) |
| **Network Access Required** | No (Swift demangler path is local); TraceRMI variant requires an untrusted peer reaching an already-established debugger-agent channel |

---

## Summary

This entry packages three conditional, defensively-scoped findings against Ghidra 12.1.2 rather than a single unconditional exploit. First, the Swift demangler analyzer builds and launches a `swift-demangle` executable from a program/analyzer-controlled tool directory, which is local arbitrary code execution if that directory can be redirected to an attacker-controlled binary. Second, TraceRMI debugger-agent implementations (GDB/LLDB) expose command/eval sinks (`execute(cmd)`, `pyeval(expr)`) that grant code execution to any untrusted peer able to drive an already-created TraceRMI channel. Third, Ghidra bundles an older SevenZipJBinding native archive parser and routes recognized archive bytes into it in-process, a plausible native-parser attack surface given reverse engineers routinely open untrusted archives/firmware images. The author is explicit that these are conditional, calc-only demonstrations (simulated sinks and source-reachability checks) rather than full unauthenticated exploit chains against a stock Ghidra install. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

The Swift demangler analyzer resolves and launches a `swift-demangle` binary from a configurable tool directory without restricting that directory to a trusted, non-writable location. The TraceRMI debugger-agent implementations expose raw command/eval methods (`gdb.execute`, LLDB command interpreter, Python `eval`) directly on the RMI channel without a trust boundary for the connecting peer. SevenZipJBinding's bundled native archive-parsing code is reachable from Ghidra's archive-recognition logic on attacker-supplied byte streams.

### Attack Vector

1. **Swift demangler**: an attacker who can influence the configured/restored Swift tool directory (e.g., via a shared project or imported configuration) plants a malicious `swift-demangle`; when Ghidra's Swift analyzer runs, it launches that binary, achieving local code execution.
2. **TraceRMI**: an untrusted peer that can reach an already-established TraceRMI debugger-agent channel sends a crafted `execute`/`pyeval` command, which the agent runs directly (shell command or Python `eval`).
3. **SevenZipJBinding**: a user opens an attacker-supplied archive/firmware container; Ghidra routes the recognized bytes into the native SevenZipJBinding parser in-process, exposing any native parser bugs.

### Impact

Where preconditions are met, arbitrary local code execution in the Ghidra process (Swift demangler, TraceRMI) or a native memory-corruption attack surface reachable via untrusted archive files (SevenZipJBinding). All three require specific configuration or interaction preconditions rather than being reachable from a default, unconfigured Ghidra session.

---

## Environment / Lab Setup

```
Target:   Ghidra 12.1.2 source checkout (for TraceRMI/SevenZip reachability checks) and/or installed Ghidra (for Swift demangler simulation)
Attacker: Python 3 (stdlib only); optional local calculator (calc.exe / xcalc / gnome-calculator / Calculator.app) as a benign proof marker
```

---

## Proof of Concept

### PoC Script

> See `ace_swift_demangler_calc_poc.py`, `rce_tracermi_conditional_calc_poc.py`, `sevenzip_jbinding_reachability.py`, `calc_helper.py`, and `SevenZipReachabilityProbe.java` in this folder.

```bash
python3 ace_swift_demangler_calc_poc.py --run
python3 rce_tracermi_conditional_calc_poc.py --ghidra-source /path/to/ghidra-12.1.2
python3 sevenzip_jbinding_reachability.py --ghidra-source /path/to/ghidra-12.1.2
```

The Swift demangler script creates a fake `swift-demangle` tool and simulates the process-launch sink, optionally launching the local calculator as a benign marker. The TraceRMI script scans a Ghidra source checkout for execution-capable agent methods and emits calc-only command shapes for those sinks. The SevenZipJBinding script performs benign source-reachability and harmless archive-sample checks rather than triggering an actual memory-corruption bug.

---

## Detection & Indicators of Compromise

```
# Unexpected child-process launches of swift-demangle from non-standard tool directories
# TraceRMI debugger-agent connections from unexpected/untrusted peers issuing execute/pyeval commands
# Ghidra processes loading SevenZipJBinding native code against attacker-supplied archive files
```

**Signs of compromise:**
- Ghidra spawning unexpected child processes during Swift symbol demangling
- TraceRMI channel activity from peers outside the expected debugger-host relationship
- Crashes or anomalous behavior in Ghidra's native archive-parsing path when opening untrusted files

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Restrict the Swift tool directory to a trusted, non-writable path; require authentication/trust verification before exposing TraceRMI debugger-agent channels to any peer; treat archive files opened for analysis as untrusted and consider sandboxing native archive-parsing components such as SevenZipJBinding |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/ghidra-12.1.2-rce-ace-calc-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `ghidra-12.1.2-rce-ace-calc-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The source README explicitly frames all three findings as conditional (precondition-gated) rather than unconditional, default-reachable exploits, and the included scripts are calc-only/reachability demonstrations rather than full weaponized exploit chains.
