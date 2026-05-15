# Exchange Health Checker Outbound Rule Blind Spot (CVE-2026-42897)

<!-- 
  File: 2026-05-15_exchange-health-checker-outbound-rule-blind-spot.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-15 |
| **Author / Researcher** | atiilla |
| **CVE / Advisory** | CVE-2026-42897 |
| **Category** | web |
| **Severity** | Medium |
| **CVSS Score** | 5.3 (CVSSv3) |
| **Status** | Researched |
| **Tags** | Exchange, HealthChecker, IIS, URL-Rewrite, outbound-rules, EOMT, CSP, detection-gap |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Microsoft CSS-Exchange Health Checker (`HealthChecker.ps1`) |
| **Versions Affected** | Versions where `Get-URLRewriteRule.ps1` only parses `rewrite.rules` and not `rewrite.outboundRules` |
| **Language / Platform** | PowerShell / Exchange on Windows Server with IIS |
| **Authentication Required** | Yes (administrator/operator running diagnostics) |
| **Network Access Required** | No |

---

## Summary

CVE-2026-42897 describes a diagnostic blind spot in Exchange Health Checker. The analyzer only enumerates inbound IIS URL Rewrite rules and ignores outbound rules. The EOMT mitigation for this CVE installs an outbound Content-Security-Policy rewrite rule (`EOMT OWA CSP - outbound`), so Health Checker reports omit this mitigation and can produce false-negative mitigation verification results.

---

## Vulnerability Details

### Root Cause

`Get-URLRewriteRule.ps1` reads only `.rewrite.rules` across all three parsing paths (web.config, applicationHost per-location, and applicationHost global). It does not read `.rewrite.outboundRules`. `Invoke-AnalyzerIISInformation.ps1` then displays only names from the inbound `.rule` collection.

### Attack Vector

This is an audit/visibility weakness rather than direct code execution. An administrator applies EOMT mitigations and relies on Health Checker output for validation. Because outbound rules are excluded from parsing, the applied mitigation rule remains invisible in the report.

### Impact

- False negatives when verifying EOMT mitigation deployment.
- Reduced confidence in Health Checker as a sole mitigation-audit source.
- Incident-response and compliance workflows may miss mitigation evidence unless IIS configs are checked manually.

---

## Environment / Lab Setup

```
OS:          Windows Server with Exchange/IIS context (or PowerShell lab)
Target:      Health Checker parsing logic for IIS rewrite configuration
Attacker:    N/A (diagnostic blind spot PoC)
Tools:       PowerShell 7+, mock IIS XML in PoC script
```

### Setup Steps

```bash
# 1. Use an authorized lab host with PowerShell available
# 2. Execute the PoC script
pwsh ./poc_cve_2026_42897.ps1
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. Run `poc_cve_2026_42897.ps1` to generate mock IIS configs containing both inbound and outbound rules.
2. Observe vulnerable-mode output: only inbound rules are surfaced.
3. Observe patched-mode output: inbound and outbound rules are both surfaced, including `EOMT OWA CSP - outbound`.
4. Compare JSON excerpts printed by the script to confirm mitigation visibility gap.

### Exploit Code

> See `poc_cve_2026_42897.ps1` in this folder.

```powershell
# Vulnerable behavior example (inbound-only)
$rules = $content.configuration.'system.webServer'.rewrite.rules
$displayRewriteRules = ($rules.rule | Where-Object { $_.enabled -ne "false" }).name
```

### Expected Output

```
[*] Vulnerable path (inbound only):
    Rules found: Redirect to HTTPS
    MISSING: EOMT OWA CSP - outbound

[*] Patched path (inbound + outbound):
    Rules found: Redirect to HTTPS, EOMT OWA CSP - outbound
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized lab captures of vulnerable vs patched script output

---

## Detection & Indicators of Compromise

```
# Detection clue in operations pipelines:
# Health Checker output does not include outbound rewrite rules,
# while IIS config contains <outboundRules> entries such as
# "EOMT OWA CSP - outbound".
```

**SIEM / IDS Rule (example):**
```
Flag Exchange health-audit results where EOMT mitigation is marked missing,
then cross-check IIS rewrite outbound rules from applicationHost.config/web.config.
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Update Health Checker logic to parse both `rewrite.rules` and `rewrite.outboundRules` at all config paths |
| **Workaround** | Validate EOMT outbound rule presence directly in IIS config and/or IIS Manager instead of relying solely on Health Checker |
| **Config Hardening** | Add secondary validation checks in operational runbooks to compare Health Checker output against IIS rewrite configuration |

---

## References

- [CVE-2026-42897](https://nvd.nist.gov/vuln/detail/CVE-2026-42897)
- [Source Repository — atiilla/CVE-2026-42897](https://github.com/atiilla/CVE-2026-42897)
- [CSS-Exchange: Get-URLRewriteRule.ps1](https://github.com/microsoft/CSS-Exchange/blob/main/Diagnostics/HealthChecker/Analyzer/Get-URLRewriteRule.ps1)
- [CSS-Exchange: Invoke-AnalyzerIISInformation.ps1](https://github.com/microsoft/CSS-Exchange/blob/main/Diagnostics/HealthChecker/Analyzer/Invoke-AnalyzerIISInformation.ps1)
- [CSS-Exchange: EOMT CVE-2026-42897 Mitigation Script](https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/EOMT/Mitigations/CVE-2026-42897.ps1)

---

## Notes

Auto-ingested from https://github.com/atiilla/CVE-2026-42897 on 2026-05-15.
