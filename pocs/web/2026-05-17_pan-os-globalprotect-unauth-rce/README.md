# Palo Alto PAN-OS GlobalProtect Unauthenticated RCE (CVE-2024-3400)

<!-- 
  File: 2026-05-17_pan-os-globalprotect-unauth-rce.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Author / Researcher** | h4x0r-dz |
| **CVE / Advisory** | CVE-2024-3400 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | 10.0 (CVSSv3.1) |
| **Status** | Weaponized |
| **Tags** | RCE, command-injection, path-traversal, PAN-OS, GlobalProtect, unauthenticated, zero-day |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Palo Alto Networks PAN-OS GlobalProtect gateway |
| **Versions Affected** | PAN-OS 10.2, 11.0, and 11.1 branches before vendor fixes (GlobalProtect enabled) |
| **Language / Platform** | PAN-OS appliance / VM management plane (HTTP/HTTPS) |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2024-3400 is an unauthenticated command injection vulnerability in PAN-OS GlobalProtect that can be reached over the network when specific features are enabled. Public reporting showed chained abuse via arbitrary file creation and command execution as root. The issue was exploited as a zero-day before patch release and later saw broad mass scanning and exploitation activity.

---

## Vulnerability Details

### Root Cause

Input from attacker-controlled request components is insufficiently constrained in vulnerable request handling paths tied to GlobalProtect and device telemetry workflows. Attackers can influence file creation paths and inject shell metacharacters, enabling command execution.

### Attack Vector

An unauthenticated attacker sends crafted HTTP `POST` requests to `/ssl-vpn/hipreport.esp` with a malicious `SESSID` cookie value. The request can force arbitrary file creation and, in exploit chains, command injection in telemetry-related paths.

### Impact

Successful exploitation can lead to remote code execution as root on affected firewalls. This can enable full device compromise, credential theft, traffic interception, and persistent access.

---

## Environment / Lab Setup

```
OS:          Linux/macOS/Windows attacker host
Target:      Vulnerable PAN-OS GlobalProtect gateway (authorized lab only)
Attacker:    Security testing workstation
Tools:       Python 3, curl (optional)
```

### Setup Steps

```bash
# Clone this archive repo and move to this PoC folder
cd pocs/web/2026-05-17_pan-os-globalprotect-unauth-rce

# Run the included PoC against an authorized target
python3 exploit.py --target https://<target-host>
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Confirm authorized scope** and identify a potentially vulnerable PAN-OS target.
2. **Send crafted unauthenticated request** to `/ssl-vpn/hipreport.esp` with traversal-style `SESSID` cookie.
3. **Verify indicator response** by requesting the marker file path and checking for `403` (commonly used signal in public PoCs).

### Exploit Code

> See `exploit.py` in this folder.

```python
python3 exploit.py --target https://<target-host>
```

### Expected Output

```
[+] POST /ssl-vpn/hipreport.esp -> HTTP 200
[+] GET /global-protect/portal/images/hellome1337.txt -> HTTP 403
[!] Possible vulnerability indicator observed (403 on marker file).
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized captures of crafted requests and responses

---

## Detection & Indicators of Compromise

```
# Potential indicators:
# - POST requests to /ssl-vpn/hipreport.esp with suspicious SESSID traversal payloads
# - Unexpected files under /var/appweb/sslvpndocs/global-protect/portal/images/
# - Telemetry path abuse under /opt/panlogs/tmp/device_telemetry/
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $HOME_NET any (
  msg:"Possible PAN-OS CVE-2024-3400 exploitation attempt";
  content:"/ssl-vpn/hipreport.esp"; http_uri;
  content:"SESSID="; http_header;
  sid:952403400; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade to fixed PAN-OS releases from Palo Alto advisory guidance for CVE-2024-3400 |
| **Workaround** | Restrict exposure of GlobalProtect and management interfaces to trusted networks only |
| **Config Hardening** | Apply Threat Prevention signatures and monitor for traversal/command-injection patterns in VPN logs |

---

## References

- [CVE-2024-3400 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)
- [Palo Alto Networks Security Advisory — CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [Unit 42: Threat Brief on CVE-2024-3400](https://unit42.paloaltonetworks.com/cve-2024-3400/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Rapid7 AttackerKB Analysis](https://attackerkb.com/topics/SSTk336Tmf/cve-2024-3400/rapid7-analysis)
- [watchTowr Labs Research](https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/)
- [Source Repository — h4x0r-dz/CVE-2024-3400](https://github.com/h4x0r-dz/CVE-2024-3400)

---

## Notes

Auto-ingested from https://github.com/h4x0r-dz/CVE-2024-3400 on 2026-05-17.
