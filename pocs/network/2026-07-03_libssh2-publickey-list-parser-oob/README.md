# libssh2 Publickey Subsystem List Parser Heap Corruption to Code Execution

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | network |
| **Severity** | Critical |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | Weaponized |
| **Tags** | libssh2, ssh, publickey-subsystem, heap-overflow, use-after-free, integer-overflow, windows, rce, memory-corruption |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | libssh2, publickey subsystem list parser (`src/publickey.c`) |
| **Versions Affected** | libssh2/libssh2 `master` at commit `e75b4bae3c68a9bde71de1fb6b0fba5b0c716020` (2026-06-24) |
| **Language / Platform** | C (Win32/Win64 PoC harnesses), Python (Paramiko-based live SSH server) — targets Windows libssh2 clients |
| **Authentication Required** | No (triggered by a malicious/compromised SSH server against a connecting libssh2 client using the publickey subsystem) |
| **Network Access Required** | Yes (delivered over an SSH connection, including a live end-to-end transport proof) |

---

## Summary

`libssh2_publickey_list_fetch()` parses a stream of publickey-subsystem response packets and grows an array of `libssh2_publickey_list` entries as responses arrive, but the parser has two distinct memory-safety defects depending on target architecture. On 32-bit Windows builds, `num_attrs * sizeof(libssh2_publickey_attribute)` can integer-overflow (e.g. `0x0ccccccd * 20 = 0x100000004`, truncating to a 4-byte allocation on 32-bit `size_t`), after which the attribute-parsing loop writes multiple attacker-controlled fields past the undersized buffer, letting an attacker groom an adjacent callback pointer and redirect execution. On 64-bit builds the same tiny-allocation path is not reachable, but a use-after-free exists instead: an unexpected "recognized" version response frees an attacker-shaped response buffer while a subsequent malformed publickey response grows the list allocation into that freed slot, so list cleanup later walks attacker-shaped entries and frees attacker-chosen `attrs` pointers, which can be reclaimed and used to hijack a callback. The PoC package includes both a Win32 heap-groom chain and a Win64 free/reclaim chain, plus a live end-to-end proof that drives the Win64 chain over a real localhost SSH session using a Paramiko server and a target-shaped libssh2 client. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`src/publickey.c` computes the publickey attribute array allocation as `num_attrs * sizeof(libssh2_publickey_attribute)` without checking for multiplication overflow (Win32 impact), and `libssh2_publickey_list_free()` trusts `packet`/`attrs` pointers in newly grown-but-not-yet-initialized list entries until a sentinel is reached, allowing an out-of-order or malformed response sequence to trigger a free of, and later reclaim into, an attacker-influenced entry (Win64 impact).

### Attack Vector

1. Attacker controls or compromises an SSH server that a libssh2-based client connects to and opens the `publickey` subsystem against.
2. **Win32 path:** server sends a `publickey` response with a small key name/blob but a huge `num_attrs` value that overflows the 32-bit attrs allocation to 4 bytes; the parser's attribute loop then writes name/value pointers and lengths past that tiny buffer, overwriting an adjacent callback slot that the harness later invokes to launch code.
3. **Win64 path:** server first sends an unexpected-but-recognized version response sized to match a future list allocation, causing libssh2 to free an attacker-shaped buffer; server then sends a malformed publickey response that forces the error path before the new list entry and sentinel are initialized.
4. List cleanup (`libssh2_publickey_list_free()`) walks the still-uninitialized entry and frees the attacker-controlled `attrs` pointer left over from the freed victim object.
5. A same-size allocation reclaims the freed slot and installs a controlled callback, which the harness invokes to demonstrate code execution; the live-transport variant performs the same chain over a real SSH connection using public libssh2 APIs.

### Impact

Attacker-controlled SSH servers can corrupt heap memory in connecting libssh2 clients that use the publickey subsystem, with a demonstrated path to arbitrary code execution (calc.exe launch) on both 32-bit and 64-bit Windows builds.

---

## Environment / Lab Setup

```
Target:   Windows libssh2 client (Win32 and Win64 builds) linking publickey.c from the tested commit
Attacker: MinGW-w64 cross-compiler, Python 3 with Paramiko (live transport proof), Wine (for non-Windows replay)
```

---

## Proof of Concept

### PoC Script

> See `publickey_win32_heap_groom_calc_repro.c`, `publickey_win64_arbitrary_free_calc_repro.c`, `live_publickey_server.py`, `live_publickey_client_win64.c`, and `replay-calc-poc.py` in this folder.

```bash
python3 replay-calc-poc.py

# Live SSH transport proof:
python3 live_publickey_server.py --host 127.0.0.1 --port 2228 --victim 0x0000013370000000 --offset 27
wine ./live_publickey_client_win64.exe 127.0.0.1 2228 calc
```

`replay-calc-poc.py` builds vulnerable and hardened ("checked") Win32/Win64 harnesses locally and drives both the allocation-wrap and free/reclaim chains, popping `calc.exe` on the vulnerable builds while confirming the checked builds are unaffected. `live_publickey_server.py` and `live_publickey_client_win64.c` demonstrate the Win64 free/reclaim chain end-to-end over a real SSH session using the public libssh2 client API.

---

## Detection & Indicators of Compromise

```
# libssh2 client processes crashing or spawning unexpected child processes after opening the publickey subsystem
# SSH publickey-subsystem response sequences containing out-of-order or unexpected "recognized" version responses
```

**Signs of compromise:**
- SSH clients using the publickey subsystem crashing or exhibiting heap corruption shortly after connecting to a given server
- Unexpected process creation immediately following publickey subsystem list-fetch operations
- Anomalous publickey response sequences (oversized `num_attrs`, out-of-order version responses) observed in SSH session captures

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory; upstream fix shape per the source is to zero newly grown list entries immediately and reject `num_attrs` values that would overflow the attrs allocation multiplication |
| **Interim mitigation** | Only use the publickey subsystem against trusted, verified SSH servers; pin host keys and avoid untrusted SSH endpoints until patched |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/libssh2-publickey-list-calc-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `libssh2-publickey-list-calc-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
