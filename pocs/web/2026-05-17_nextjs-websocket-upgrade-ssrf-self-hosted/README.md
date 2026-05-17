# Next.js WebSocket Upgrade SSRF (Self-Hosted) (CVE-2026-44578)

<!-- 
  File: 2026-05-17_nextjs-websocket-upgrade-ssrf-self-hosted.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44578 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) |
| **Status** | Weaponized |
| **Tags** | SSRF, WebSocket, upgrade-request, Next.js, self-hosted, unauthenticated, metadata-service |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js standalone router server (`next start`) |
| **Versions Affected** | >=13.0.0, <15.5.16 and >=16.0.0, <16.2.5 in self-hosted mode |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44578 is a server-side request forgery (SSRF) vulnerability in self-hosted Next.js WebSocket upgrade handling. A crafted HTTP request with `Upgrade: websocket` can coerce vulnerable versions into proxying to attacker-chosen internal targets on port 80 (or attacker-selected ports), including cloud metadata endpoints and internal admin services. The attacker can read the proxied response over the same socket, making this a high-impact unauthenticated primitive. Public reporting indicates active in-the-wild exploitation for internal service enumeration and secret retrieval.

---

## Vulnerability Details

### Root Cause

In vulnerable builds, router-server upgrade handling could forward requests when the parsed URL contained a protocol, without requiring the route-resolution flow to explicitly mark the request as a safe, finished proxy target. This allowed attacker-controlled absolute-URL request lines (and in some deployments, host-header influenced routing) to reach the internal proxy path.

### Attack Vector

An unauthenticated attacker sends a raw HTTP/1.1 request to the public Next.js server with WebSocket upgrade headers and a crafted target (for example, `http://169.254.169.254/latest/meta-data/...`) in the request line. The vulnerable server opens an outbound connection to that internal host and relays response bytes back to the attacker.

### Impact

Successful exploitation can expose cloud instance metadata and credentials, allow reconnaissance or interaction with internal-only services, and bypass perimeter assumptions by turning the Next.js host into an internal network proxy.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows
Target:      Self-hosted Next.js app running vulnerable version (e.g. 16.2.4)
Attacker:    Any reachable host able to open raw TCP/HTTP requests
Tools:       python3, bash, netcat (nc)
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44578_GHSA-c4j6-fc7j-m34r

# Run PoCs against vulnerable target
python3 exploit.py
# or
bash exploit.sh
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Start a mock internal service** to confirm SSRF relay behavior.
   ```bash
   python3 -m http.server 9999 --bind 127.0.0.1
   ```

2. **Run the Python PoC** against a vulnerable Next.js server.
   ```bash
   python3 exploit.py --next 127.0.0.1:3000 --target 127.0.0.1:9999 --path /
   ```

3. **Run the shell PoC** with absolute-URL and host-header variants.
   ```bash
   NEXT_HOST=127.0.0.1 NEXT_PORT=3000 TARGET_HOST=127.0.0.1 TARGET_PORT=9999 bash exploit.sh
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
[+] SSRF CONFIRMED
[+] VULNERABLE — internal target was reached via WS upgrade SSRF
```

---

## Screenshots / Evidence

- `screenshots/` — add request/response traces from a controlled vulnerable environment

---

## Detection & Indicators of Compromise

```
# Suspicious patterns to monitor:
# - Upgrade: websocket on endpoints that normally do not perform WS upgrades
# - Absolute URL in request-line to public Next.js entrypoints
# - Requests targeting metadata/internal IP ranges through Next.js host
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Next.js WS-upgrade SSRF attempt";
  content:"Upgrade|3a 20|websocket"; http_header;
  pcre:"/GET\s+https?:\/\//i";
  sid:900044578; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16+ or 16.2.5+ |
| **Workaround** | Block absolute-URL request-lines and unexpected `Upgrade` traffic at reverse proxy / WAF |
| **Config Hardening** | Restrict egress from app hosts to metadata and internal network ranges; monitor SSRF-like upgrade traffic |

---

## References

- [Next.js Security Advisory — GHSA-c4j6-fc7j-m34r](https://github.com/vercel/next.js/security/advisories/GHSA-c4j6-fc7j-m34r)
- [Next.js Patch Commit 5b194ee2d4](https://github.com/vercel/next.js/commit/5b194ee2d4)
- [Next.js v16.2.5 Release](https://github.com/vercel/next.js/releases/tag/v16.2.5)
- [Source Repository — dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.
