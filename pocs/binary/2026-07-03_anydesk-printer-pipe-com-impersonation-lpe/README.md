# AnyDesk Printer Pipe COM Impersonation Local Privilege Escalation

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | anydesk, windows, privilege-escalation, com-impersonation, named-pipe, local-service, lpe, ipc |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | AnyDesk for Windows 9.7.6 |
| **Versions Affected** | 9.7.6 (release observed 2026-06-15); other nearby versions unconfirmed |
| **Language / Platform** | Python 3.10+ with `pywin32` (PoC), targets Windows x86 service process |
| **Authentication Required** | Local-only (requires a low-privileged local Windows account) |
| **Network Access Required** | No |

---

## Summary

AnyDesk's local printer IPC worker creates a named pipe (`\\.\pipe\adprinterpipe`) with an ACL that grants access to `Everyone`, then accepts a message containing attacker-controlled COM marshaling bytes, unmarshals it into an `IUnknown`, queries for `IStream`, and invokes `IStream::Read` on it. Because the AnyDesk process initializes COM security with impersonation level `RPC_C_IMP_LEVEL_IMPERSONATE`, the attacker-supplied COM object's callback can impersonate the calling AnyDesk process during that invocation. When AnyDesk is installed as a Windows service (the default, since `CreateServiceW` is called with a null service account and thus runs as LocalSystem), a low-privileged local user who can connect to the pipe can escalate to the AnyDesk service identity — in the default configuration, `NT AUTHORITY\SYSTEM`. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

The printer pipe IPC boundary accepts marshaled COM interface data from any local client (the pipe DACL grants `GENERIC_ALL` to `S-1-1-0`/Everyone) and unmarshals it via `CoUnmarshalInterface`, creating a proxy to an attacker-controlled local COM server. Because the process configures `CoInitializeSecurity` with impersonation level 3 (`RPC_C_IMP_LEVEL_IMPERSONATE`), any method invoked on that proxy (e.g., `IStream::Read`) lets the attacker's COM server impersonate the AnyDesk caller's token during the callback.

### Attack Vector

1. Low-privileged local attacker connects to `\\.\pipe\adprinterpipe`, which is reachable due to a permissive `Everyone`-accessible ACL.
2. Attacker sends a pipe message containing marshaled COM object bytes; AnyDesk's `FUN_0100e6e0` copies these into an `HGLOBAL`, wraps it via `CreateStreamOnHGlobal`, and calls `CoUnmarshalInterface`.
3. AnyDesk queries the unmarshaled object for `IID_IStream` and calls `IStream::Read` on it, crossing back into attacker-controlled code.
4. Because COM impersonation is enabled, the attacker's `IStream::Read` implementation captures the impersonated AnyDesk caller identity.
5. If AnyDesk is running as an installed service (default: LocalSystem), the attacker's callback impersonates `NT AUTHORITY\SYSTEM`, enabling privilege escalation from that context.

### Impact

Local privilege escalation from a low-privileged local user to the AnyDesk service identity, which by default is `NT AUTHORITY\SYSTEM` when AnyDesk is installed as a Windows service.

---

## Environment / Lab Setup

```
Target:   Windows host with AnyDesk for Windows 9.7.6 installed as a service
Attacker: Python 3.10+, pywin32 (pip install -r requirements.txt)
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python poc.py selftest
```

Runs a local two-process harness that reproduces the vulnerable COM flow (pipe message, `CoUnmarshalInterface`, `QueryInterface(IStream)`, `IStream::Read`) and prints the identity impersonated during the attacker-controlled callback, without touching the real AnyDesk binary. A separate `python poc.py analyze <path-to-AnyDesk-runtime.exe>` mode performs static marker analysis against an actual AnyDesk runtime PE to confirm the vulnerable code paths are present.

---

## Detection & Indicators of Compromise

```
# Unexpected client connections to \\.\pipe\adprinterpipe from low-privileged processes
# AnyDesk service process issuing CoUnmarshalInterface calls on pipe-supplied data
# Token impersonation events originating from the AnyDesk service process shortly after pipe I/O
```

**Signs of compromise:**
- Non-AnyDesk processes opening handles to `\\.\pipe\adprinterpipe`
- AnyDesk service process spawning or impersonating tokens outside of normal printer-redirection activity
- Unexpected SYSTEM-level actions correlated with local user sessions running AnyDesk client processes

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory from AnyDesk |
| **Interim mitigation** | Restrict the `adprinterpipe` DACL to trusted SIDs only; where feasible, disable or restrict AnyDesk's printer-redirection feature on multi-user or shared hosts until patched |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/anydesk-printer-com-impersonation-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `anydesk-printer-com-impersonation-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The source README notes that a live installed-service VM should be used for final vendor-grade confirmation of the SYSTEM identity in the real service context, indicating validation is not yet fully end-to-end on a production install.
