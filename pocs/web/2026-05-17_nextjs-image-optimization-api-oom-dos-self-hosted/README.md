# Next.js Image Optimization API OOM DoS (Self-Hosted) (CVE-2026-44577)

<!-- 
  File: 2026-05-17_nextjs-image-optimization-api-oom-dos-self-hosted.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44577 |
| **Category** | web |
| **Severity** | Medium |
| **CVSS Score** | 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H) |
| **Status** | Weaponized |
| **Tags** | DoS, OOM, image-optimizer, Next.js, self-hosted, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js Image Optimization API (`/_next/image`) on self-hosted deployments |
| **Versions Affected** | >=15.0.0, <15.5.16 and >=16.0.0, <16.2.5 |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44577 is a denial-of-service issue in Next.js Image Optimization on self-hosted deployments. In vulnerable builds, `/_next/image` can fetch very large local assets into memory without an effective size cap and then perform expensive image decode/transform work. By repeatedly requesting oversized local files that match `images.localPatterns`, an unauthenticated attacker can drive high memory usage and trigger process out-of-memory conditions. Public reporting for this issue states Vercel-hosted deployments are not affected.

---

## Vulnerability Details

### Root Cause

The image optimizer request path accepted attacker-controlled `url` values pointing to local assets and read upstream image bodies into memory before sufficient size/pixel limit enforcement in vulnerable versions. This enabled excessive memory consumption during fetch and decode in the image processing pipeline.

### Attack Vector

An attacker sends repeated requests such as `/_next/image?url=/large.bin&w=16&q=1` (or similar local paths) against a self-hosted Next.js application where local image patterns permit the target path. The endpoint fetches and processes oversized local content, amplifying memory pressure.

### Impact

Successful exploitation can cause severe memory exhaustion, request failures, and application downtime. The practical outcome is unauthenticated denial-of-service against vulnerable self-hosted instances.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows
Target:      Self-hosted Next.js app in affected range (e.g. 16.2.4)
Attacker:    Any host with network reachability to target
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44577_GHSA-h64f-5h5j-jqjh

# Run PoCs against vulnerable target
python3 exploit.py
# or
bash exploit.sh
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Run a vulnerable self-hosted Next.js target** with image optimization enabled.
   ```bash
   npm install next@16.2.4
   npm run start
   ```

2. **Execute the Python PoC** against the target (or local mock harness if no target is passed).
   ```bash
   python3 exploit.py http://127.0.0.1:3000
   ```

3. **Execute the shell PoC** and observe latency/errors under oversized local image processing.
   ```bash
   IMAGES_PATH=/large.bin SIZE_MB=200 bash exploit.sh http://127.0.0.1:3000
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
from exploit import main
import sys

sys.exit(main())
```

### Expected Output

```
[+] VULNERABLE -- optimizer fully decoded oversized asset
# or
[+] VULNERABLE -- optimizer crashed / OOM-killed
```

---

## Screenshots / Evidence

- `screenshots/` — add memory/latency/error evidence from a controlled vulnerable environment

---

## Detection & Indicators of Compromise

```
# Suspicious pattern:
# - Repeated requests to /_next/image with local oversized asset paths
# - Elevated 5xx/timeouts and memory spikes in Next.js process
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Next.js image optimizer OOM DoS attempt";
  content:"/_next/image?url="; http_uri;
  pcre:"/w=\d+&q=\d+/";
  sid:900044577; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16+ or 16.2.5+ |
| **Workaround** | Disable built-in optimizer (`images.unoptimized=true`) or block oversized local image optimization requests at edge/proxy |
| **Config Hardening** | Restrict `images.localPatterns`, enforce request rate/body limits, and monitor process memory thresholds |

---

## References

- [CVE-2026-44577 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44577)
- [Next.js Security Advisory — GHSA-h64f-5h5j-jqjh](https://github.com/vercel/next.js/security/advisories/GHSA-h64f-5h5j-jqjh)
- [Next.js v16.2.5 Release](https://github.com/vercel/next.js/releases/tag/v16.2.5)
- [Source Repository — dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

Issue notes report no known active exploitation at publication time.
