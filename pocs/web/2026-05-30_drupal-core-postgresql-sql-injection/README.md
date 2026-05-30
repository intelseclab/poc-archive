# Drupal Core PostgreSQL SQL Injection (CVE-2026-9082)

<!-- 
  File: 2026-05-30_drupal-core-postgresql-sql-injection.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-30 |
| **Last Updated** | 2026-05-21 |
| **Author / Researcher** | 7h30th3r0n3 (discoverer credited by advisory: michaelmaturi) |
| **CVE / Advisory** | CVE-2026-9082 / SA-CORE-2026-004 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | N/A |
| **Status** | Patched |
| **Tags** | SQLi, Drupal, PostgreSQL, JSON:API, unauthenticated, data-exfiltration |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Drupal Core |
| **Versions Affected** | 8.0.0 through 11.3.9 (PostgreSQL-backed sites) |
| **Language / Platform** | PHP / Drupal with PostgreSQL backend |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2026-9082 is an unauthenticated SQL injection in Drupal Core's PostgreSQL entity-query handling for JSON:API filters. User-controlled array keys are used to build SQL placeholder names without proper sanitization, enabling injection into generated SQL. On vulnerable targets, attackers can retrieve database metadata and potentially extract sensitive records.

---

## Vulnerability Details

### Root Cause

In Drupal's PostgreSQL entity query condition translation flow, user-controlled keys from `filter[...][condition][value][KEY]` can influence placeholder construction. Malformed keys can terminate expected SQL structure and append attacker-controlled SQL.

### Attack Vector

An unauthenticated attacker sends crafted requests to JSON:API endpoints using malicious `filter` parameters. Because JSON:API is commonly enabled, this can be reachable without login on exposed sites.

### Impact

Blind SQL injection can permit data extraction (DB version, users, table names) and downstream compromise depending on database permissions and deployment hardening.

---

## Environment / Lab Setup

```
OS:          Linux/macOS attacker workstation
Target:      Drupal 8.0.0-11.3.9 with PostgreSQL + JSON:API reachable
Attacker:    Authorized security tester
Tools:       Python 3, requests, rich
```

### Setup Steps

```bash
cd pocs/web/2026-05-30_drupal-core-postgresql-sql-injection
pip install requests rich
python3 exploit.py -u https://target.example --check
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. Confirm a reachable Drupal JSON:API endpoint.
   ```bash
   curl -i https://target.example/jsonapi
   ```

2. Run vulnerability check mode.
   ```bash
   python3 exploit.py -u https://target.example --check
   ```

3. Optionally run extraction actions against authorized lab targets.
   ```bash
   python3 exploit.py -u https://target.example --version
   python3 exploit.py -u https://target.example --dbinfo
   python3 exploit.py -u https://target.example --tables
   ```

### Exploit Code

> See `exploit.py` in this folder.

```python
# Core usage examples
python3 exploit.py -u https://target.example --check
python3 exploit.py -u https://target.example --query "SELECT current_user"
```

### Expected Output

```
✔ JSON:API endpoint found and active
✔ VULNERABLE — boolean-based confirmed
✔ Done.
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized lab captures of vulnerable checks or extraction output.

---

## Detection & Indicators of Compromise

```
# Watch for suspicious JSON:API requests containing nested filter condition arrays
# with unusual encoded keys and SQL fragments in query parameters.
```

**SIEM / IDS Rule (example):**
```
alert http any any -> any any (
  msg:"Possible Drupal CVE-2026-9082 JSON:API SQLi probe";
  content:"/jsonapi/"; http_uri;
  content:"filter%5B"; http_uri;
  content:"condition%5D%5Bvalue%5D%5B"; http_uri;
  sid:95269082; rev:1;
)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Drupal Core to fixed releases (11.3.10, 11.2.12, 10.6.9, 10.5.10 or later) |
| **Workaround** | Restrict JSON:API exposure and apply strict access controls where feasible |
| **Config Hardening** | Review database least privilege, monitor anomalous JSON:API queries, and keep core/modules updated |

---

## References

- [Drupal Advisory SA-CORE-2026-004](https://www.drupal.org/sa-core-2026-004)
- [Source Repository — 7h30th3r0n3/CVE-2026-9082-Drupal-PoC](https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC)
- [Patch Commit (Drupal)](https://git.drupalcode.org/project/drupal/-/commit/ea9524d9)

---

## Notes

Auto-ingested from https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC on 2026-05-30.
