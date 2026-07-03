# Nmap IPv6 Extension-Header Length Wrap

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | network |
| **Severity** | Low |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | Incomplete PoC |
| **Tags** | nmap, ipv6, integer-wraparound, packet-parsing, libnetutil, extension-headers, denial-of-service, research-in-progress |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Nmap — shared packet parsing code (`libnetutil/netutil.cc`, `tcpip.cc`) |
| **Versions Affected** | Current Nmap source tree at time of research (specific release not pinned by source) |
| **Language / Platform** | C++17 standalone parser-behavior harness (`ipv6_extlen_wrap_probe.cpp`) |
| **Authentication Required** | No |
| **Network Access Required** | No (PoC is a standalone local arithmetic/parser-behavior harness, not a live network exploit) |

---

## Summary

The Nmap IPv6 extension-header parser in `libnetutil/netutil.cc` advances a payload pointer by an attacker-declared extension-header length without first checking that the advanced pointer stays within the bounds of the captured packet. When a crafted, truncated IPv6 packet declares an extension-header length that pushes the pointer beyond the actual captured data, the subsequent remaining-payload-length calculation — stored in an unsigned integer — wraps around to a very large value. The researcher's standalone harness reproduces this arithmetic locally, showing a 48-byte captured packet being represented internally as carrying billions of bytes of "remaining" UDP payload. The researcher explicitly marks this work as ongoing, noting it is the strongest fresh parser candidate from a broader review pass but that further work is needed to determine whether this primitive can be escalated beyond parser-state corruption and out-of-bounds reads. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

The IPv6 extension-header walking logic advances a payload pointer using `p += (extension_length + 1) * 8` without a post-advance bounds/containment check against the captured packet length, before computing the remaining payload length into an `unsigned int`, which wraps when the pointer has already moved past the end of the buffer.

### Attack Vector

1. Attacker crafts a 48-byte IPv6 packet whose IPv6 header declares a Hop-by-Hop Options extension header.
2. The extension header's own "next header" field is set to UDP, and its length field is set such that the parser advances the payload pointer past the actual captured packet (to offset 56 in a 48-byte capture).
3. The parser computes the "remaining payload length" as an unsigned subtraction that wraps to a huge value (`4294967288` in the researcher's harness).
4. Downstream Nmap consumers (raw scan engine, packet validators) that trust this computed length may then treat the truncated packet as containing a large, well-formed upper-layer payload beyond the actual buffer.

### Impact

Parser-state corruption and out-of-bounds read exposure in Nmap's packet-length accounting when scanning/parsing crafted IPv6 traffic; potential for scan-result confusion, over-reads, or crashes in downstream consumers. The researcher notes this is not yet demonstrated as a stronger memory-corruption primitive.

---

## Environment / Lab Setup

```
Target:   Nmap shared packet-parsing code path (libnetutil/netutil.cc, tcpip.cc) — modeled, not live Nmap binary
Attacker: g++ (C++17), any Linux/macOS/WSL/MinGW toolchain
```

---

## Proof of Concept

### PoC Script

> See `ipv6_extlen_wrap_probe.cpp` in this folder.

```bash
g++ -std=c++17 -O0 -g -Wall -Wextra -o ipv6_extlen_wrap_probe ipv6_extlen_wrap_probe.cpp
./ipv6_extlen_wrap_probe
```

The standalone harness models the IPv6 extension-header parsing and length-adjustment logic from Nmap's `libnetutil/netutil.cc` and `tcpip.cc`, feeds it a crafted 48-byte packet shape, and prints the resulting wrapped payload-length value to demonstrate the unsigned-integer wraparound condition.

---

## Detection & Indicators of Compromise

```
# Not directly applicable — this is a local parser-behavior harness, not a
# live network exploit against a running Nmap process
# Anomalous truncated IPv6 packets with Hop-by-Hop extension headers whose
# declared length exceeds the remaining captured packet size
```

**Signs of compromise:**
- Not directly observable in production; this PoC targets Nmap's own parsing code as a research/regression artifact rather than a network-facing service
- Crash reports or malformed-length warnings from Nmap when scanning networks carrying crafted, truncated IPv6 extension-header traffic

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Add a post-advance bounds/containment check in the IPv6 extension-header walking logic before computing remaining payload length; treat truncated extension headers as parse failures rather than continuing with wrapped-length arithmetic |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/nmap-ipv6-extlen-wrap-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `nmap-ipv6-extlen-wrap-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The source author explicitly marks this research as "ongoing" / incomplete: exploitability beyond the demonstrated integer-wraparound arithmetic (e.g., whether it can be escalated to a stronger memory-corruption primitive) had not been established at time of mirroring.
