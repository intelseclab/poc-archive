# Next.js Cache Components Connection Exhaustion DoS (CVE-2026-44579)

<!-- 
  File: 2026-05-17_nextjs-cache-components-connection-exhaustion-dos.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | dwisiswant0 |
| **CVE / Advisory** | CVE-2026-44579 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | 7.5 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | DoS, connection-exhaustion, next-resume, Next.js, cache-components, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js applications using Cache Components / Partial Prerendering (PPR) |
| **Versions Affected** | 15.0.0–15.5.15 and 16.0.0–16.2.4 (fixed in 15.5.16 / 16.2.5) |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-44579 is a denial-of-service issue in Next.js Cache Components (PPR) request handling. Before the fix, a crafted client request could force the server into the `next-resume` flow and trigger expensive request-body processing and resume rendering work. Repeated crafted POST requests can leave connections occupied long enough to exhaust worker/file-descriptor capacity and degrade or deny service. The issue is rated High (CVSS 7.5) and fixed in 15.5.16 / 16.2.5.

---

## Vulnerability Details

### Root Cause

The internal `next-resume` header was not consistently filtered at the trust boundary in vulnerable builds. That allowed direct client traffic to enter a resume-specific processing path intended for trusted internal flow, causing request bodies to be consumed and resume logic to run under attacker control. Under concurrency, this creates a resource-amplification condition (connection slots, CPU, and memory).

### Attack Vector

An attacker sends repeated unauthenticated POST requests to a vulnerable PPR page with `next-resume` and crafted request bodies (often large postponed-state payloads). Each request pushes the server through expensive resume/body parsing behavior. Sustained concurrency can starve available connections and file descriptors.

### Impact

Successful exploitation can cause partial or complete service unavailability due to connection exhaustion and backend resource pressure. In affected environments this can manifest as high latency, request failures, worker starvation, and eventual outage.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows
Target:      Next.js app in affected version range with Cache Components/PPR path
Attacker:    Any host with network reachability to target
Tools:       python3, bash, curl
```

### Setup Steps

```bash
# Clone source PoC collection
git clone https://github.com/dwisiswant0/next-16.2.4-pocs.git
cd next-16.2.4-pocs/poc/CVE-2026-44579_GHSA-mg66-mrh9-m8jx

# Run PoCs against vulnerable target
python3 exploit.py
# or
bash exploit.sh
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Run a vulnerable target** with an affected Next.js version and a PPR page.
   ```bash
   npm install next@16.2.4
   npm run start
   ```

2. **Execute the Python PoC** to trigger `next-resume` request-path abuse.
   ```bash
   python3 exploit.py http://127.0.0.1:3000/some-ppr-page
   ```

3. **Run the shell PoC with parallel requests** to amplify exhaustion behavior.
   ```bash
   CONCURRENCY=20 SIZE_MB=15 bash exploit.sh http://127.0.0.1:3000/some-ppr-page
   ```

### Exploit Code

> See `exploit.py` and `exploit.sh` in this folder.

```python
from exploit import main

exit_code = main(["exploit.py", "http://127.0.0.1:3000/some-ppr-page", "15", "10"])
print(exit_code)
```

### Expected Output

```
[+] VULNERABLE — server processed resume request (slow wall time and/or 413/500)
total wall-time for parallel resume requests significantly exceeds baseline
```

---

## Screenshots / Evidence

- `screenshots/` — add timing and error-rate evidence from vulnerable environment if captured

---

## Detection & Indicators of Compromise

```
# Suspicious headers and request patterns for this issue:
next-resume: 1
x-next-resume-state-length: 1

# Repeated large POST bodies to PPR routes, often followed by
# elevated 413/500 rates, timeout spikes, and worker saturation.
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
  msg:"Possible Next.js next-resume connection exhaustion attempt";
  content:"next-resume|3a 20|1"; http_header;
  flow:to_server,established;
  sid:900044579; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to 15.5.16+ or 16.2.5+ |
| **Workaround** | Strip `next-resume` at edge/proxy and rate-limit large POSTs to PPR routes |
| **Config Hardening** | Enforce strict header allowlists and low request-body limits on public routes |

---

## References

- [CVE-2026-44579 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44579)
- [Next.js Security Advisory — GHSA-mg66-mrh9-m8jx](https://github.com/vercel/next.js/security/advisories/GHSA-mg66-mrh9-m8jx)
- [Next.js Patch Commit 9d50c0b719](https://github.com/vercel/next.js/commit/9d50c0b7190f59c470308578e12882788819f14c)
- [Source Repository — dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

## Notes

Auto-ingested from https://github.com/dwisiswant0/next-16.2.4-pocs on 2026-05-17.

Issue notes report no known active exploitation at publication time.
