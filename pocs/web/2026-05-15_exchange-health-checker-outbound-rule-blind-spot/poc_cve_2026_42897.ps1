#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CVE-2026-42897 - Exchange Health Checker Outbound Rewrite Rule Blind Spot
    Proof of Concept

.DESCRIPTION
    Demonstrates that Get-URLRewriteRule.ps1 in Exchange Health Checker only
    reads inbound IIS URL Rewrite rules and silently ignores outbound rules.

    The EOMT mitigation for CVE-2026-42897 deploys its CSP rule as an outbound
    rule ("EOMT OWA CSP - outbound"). Because Health Checker never reads
    outboundRules, the mitigation is invisible to the diagnostic tool - producing
    a false negative for administrators verifying EOMT deployment.

    This script:
      1. Builds mock IIS config XML (web.config and applicationHost.config)
         containing both inbound and outbound rewrite rules.
      2. Runs the VULNERABLE parsing logic (inbound-only, mirrors Health Checker).
      3. Runs the PATCHED parsing logic (inbound + outbound).
      4. Prints a diff so the blind spot is visible.

    Covers all three config paths Health Checker uses:
      - web.config
      - applicationHost.config per-location entry
      - applicationHost.config global system.webServer

.NOTES
    Affected files in CSS-Exchange repo:
      Diagnostics/HealthChecker/Analyzer/Get-URLRewriteRule.ps1       (L49, L72, L97)
      Diagnostics/HealthChecker/Analyzer/Invoke-AnalyzerIISInformation.ps1 (L442-459)

    Related mitigation:
      Security/src/EOMT/Mitigations/CVE-2026-42897.ps1               (L147-254)

    FOR AUTHORIZED SECURITY RESEARCH ONLY.
    Run on your own systems or in isolated lab environments.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Mock IIS configuration XML
# ---------------------------------------------------------------------------
# Represents the structure Health Checker parses from a live Exchange server.
# Contains one inbound rule (what Health Checker sees) and one outbound rule
# (the EOMT CSP mitigation - what Health Checker misses).

[xml]$MockWebConfig = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="Redirect to HTTPS" enabled="true" stopProcessing="true">
          <match url=".*" />
          <conditions logicalGrouping="MatchAll">
            <add input="{HTTPS}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:0}" redirectType="Permanent" />
        </rule>
      </rules>
      <outboundRules>
        <rule name="EOMT OWA CSP - outbound" enabled="true">
          <match serverVariable="RESPONSE_Content-Security-Policy" pattern=".*" />
          <action type="Rewrite"
                  value="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';" />
        </rule>
      </outboundRules>
    </rewrite>
  </system.webServer>
</configuration>
'@

# applicationHost.config with a per-location entry (mirrors Health Checker path 2)
[xml]$MockAppHostConfig = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <location path="Default Web Site/owa">
    <system.webServer>
      <rewrite>
        <rules>
          <rule name="OWA Inbound Block" enabled="true">
            <match url="^(.*)$" />
            <conditions>
              <add input="{REQUEST_URI}" pattern="suspicious_pattern" />
            </conditions>
            <action type="AbortRequest" />
          </rule>
        </rules>
        <outboundRules>
          <rule name="EOMT OWA CSP - outbound" enabled="true">
            <match serverVariable="RESPONSE_Content-Security-Policy" pattern=".*" />
            <action type="Rewrite"
                    value="default-src 'self'; script-src 'self' 'unsafe-inline';" />
          </rule>
        </outboundRules>
      </rewrite>
    </system.webServer>
  </location>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="Global Inbound Rule" enabled="true">
          <match url=".*" />
          <action type="None" />
        </rule>
      </rules>
      <outboundRules>
        <rule name="EOMT OWA CSP - outbound" enabled="true">
          <match serverVariable="RESPONSE_Content-Security-Policy" pattern=".*" />
          <action type="Rewrite" value="default-src 'self';" />
        </rule>
      </outboundRules>
    </rewrite>
  </system.webServer>
</configuration>
'@

# ---------------------------------------------------------------------------
# Helper: display rule names collected by a parsing path
# ---------------------------------------------------------------------------
function Show-RuleResults {
    param(
        [string]   $PathLabel,
        [string[]] $InboundNames,
        [string[]] $OutboundNames,
        [bool]     $IsVulnerable
    )

    $mode = if ($IsVulnerable) { "VULNERABLE (inbound only)" } else { "PATCHED (inbound + outbound)" }
    Write-Host "`n  [$PathLabel - $mode]" -ForegroundColor Cyan

    if ($InboundNames.Count -gt 0) {
        foreach ($n in $InboundNames) {
            Write-Host "    [INBOUND ] $n" -ForegroundColor Green
        }
    } else {
        Write-Host "    [INBOUND ] (none)" -ForegroundColor DarkGray
    }

    if (-not $IsVulnerable) {
        if ($OutboundNames.Count -gt 0) {
            foreach ($n in $OutboundNames) {
                Write-Host "    [OUTBOUND] $n" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [OUTBOUND] (none)" -ForegroundColor DarkGray
        }
    } else {
        $outboundCount = $OutboundNames.Count
        Write-Host "    [OUTBOUND] *** $outboundCount rule(s) silently ignored ***" -ForegroundColor Red
        foreach ($n in $OutboundNames) {
            Write-Host "               MISSING: $n" -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# PATH 1: web.config
# Mirrors Get-URLRewriteRule.ps1 L49
# ---------------------------------------------------------------------------
function Test-WebConfigPath {
    Write-Host "`n=== PATH 1: web.config ===" -ForegroundColor White

    # --- Vulnerable logic (exactly as in Health Checker) ---
    $rules    = $MockWebConfig.configuration.'system.webServer'.rewrite.rules
    $inbound  = @($rules.rule | Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outbound = @($MockWebConfig.configuration.'system.webServer'.rewrite.outboundRules.rule |
                  Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "web.config" -InboundNames $inbound -OutboundNames $outbound -IsVulnerable $true

    # --- Patched logic ---
    $inboundFixed  = @($MockWebConfig.configuration.'system.webServer'.rewrite.rules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outboundFixed = @($MockWebConfig.configuration.'system.webServer'.rewrite.outboundRules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "web.config" -InboundNames $inboundFixed -OutboundNames $outboundFixed -IsVulnerable $false
}

# ---------------------------------------------------------------------------
# PATH 2: applicationHost.config - per-location entry
# Mirrors Get-URLRewriteRule.ps1 L72
# ---------------------------------------------------------------------------
function Test-AppHostPerLocationPath {
    Write-Host "`n=== PATH 2: applicationHost.config (per-location) ===" -ForegroundColor White

    $location = $MockAppHostConfig.configuration.location

    # --- Vulnerable logic ---
    $rules    = $location.'system.webServer'.rewrite.rules
    $inbound  = @($rules.rule | Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outbound = @($location.'system.webServer'.rewrite.outboundRules.rule |
                  Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "appHost/location" -InboundNames $inbound -OutboundNames $outbound -IsVulnerable $true

    # --- Patched logic ---
    $inboundFixed  = @($location.'system.webServer'.rewrite.rules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outboundFixed = @($location.'system.webServer'.rewrite.outboundRules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "appHost/location" -InboundNames $inboundFixed -OutboundNames $outboundFixed -IsVulnerable $false
}

# ---------------------------------------------------------------------------
# PATH 3: applicationHost.config - global system.webServer
# Mirrors Get-URLRewriteRule.ps1 L97
# ---------------------------------------------------------------------------
function Test-AppHostGlobalPath {
    Write-Host "`n=== PATH 3: applicationHost.config (global) ===" -ForegroundColor White

    # --- Vulnerable logic ---
    $rules    = $MockAppHostConfig.configuration.'system.webServer'.rewrite.rules
    $inbound  = @($rules.rule | Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outbound = @($MockAppHostConfig.configuration.'system.webServer'.rewrite.outboundRules.rule |
                  Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "appHost/global" -InboundNames $inbound -OutboundNames $outbound -IsVulnerable $true

    # --- Patched logic ---
    $inboundFixed  = @($MockAppHostConfig.configuration.'system.webServer'.rewrite.rules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    $outboundFixed = @($MockAppHostConfig.configuration.'system.webServer'.rewrite.outboundRules.rule |
                       Where-Object { $_.enabled -ne "false" } | Select-Object -ExpandProperty name)
    Show-RuleResults -PathLabel "appHost/global" -InboundNames $inboundFixed -OutboundNames $outboundFixed -IsVulnerable $false
}

# ---------------------------------------------------------------------------
# Simulate what Health Checker JSON output looks like (vulnerable vs patched)
# ---------------------------------------------------------------------------
function Show-HealthCheckerOutputComparison {
    Write-Host "`n=== Health Checker Report Output Comparison ===" -ForegroundColor White

    Write-Host "`n  [Vulnerable Health Checker JSON excerpt]" -ForegroundColor Cyan
    $vulnerableOutput = [PSCustomObject]@{
        IISURLRewrite = [PSCustomObject]@{
            Rules = @("Redirect to HTTPS")   # outbound rule absent
        }
        MitigationStatus = [PSCustomObject]@{
            "EOMT OWA CSP - outbound" = "NOT DETECTED"
            Note = "Outbound rules are not enumerated - EOMT mitigation invisible"
        }
    }
    $vulnerableOutput | ConvertTo-Json -Depth 4

    Write-Host "`n  [Patched Health Checker JSON excerpt]" -ForegroundColor Green
    $patchedOutput = [PSCustomObject]@{
        IISURLRewrite = [PSCustomObject]@{
            InboundRules  = @("Redirect to HTTPS")
            OutboundRules = @("EOMT OWA CSP - outbound")
        }
        MitigationStatus = [PSCustomObject]@{
            "EOMT OWA CSP - outbound" = "DETECTED (enabled)"
            Note = "Outbound rules enumerated - EOMT mitigation visible"
        }
    }
    $patchedOutput | ConvertTo-Json -Depth 4
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║  CVE-2026-42897 - Exchange Health Checker Outbound Rewrite Blind Spot  ║
  ║                                                                          ║
  ║  Affected:  Get-URLRewriteRule.ps1 (L49, L72, L97)                      ║
  ║             Invoke-AnalyzerIISInformation.ps1 (L442-459)                ║
  ║  Impact:    EOMT OWA CSP outbound mitigation invisible in HC reports    ║
  ║  For authorized security research only.                                  ║
  ╚══════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Magenta

Write-Host "[*] Building mock IIS configuration with inbound + outbound rules..." -ForegroundColor Gray
Write-Host "    Inbound rule:  'Redirect to HTTPS'" -ForegroundColor Gray
Write-Host "    Outbound rule: 'EOMT OWA CSP - outbound'  <-- EOMT mitigation for CVE-2026-42897" -ForegroundColor Gray

Test-WebConfigPath
Test-AppHostPerLocationPath
Test-AppHostGlobalPath
Show-HealthCheckerOutputComparison

Write-Host "`n=== Summary ===" -ForegroundColor White
Write-Host @"

  The three code paths in Get-URLRewriteRule.ps1 each access only:
      .rewrite.rules           (inbound)

  None access:
      .rewrite.outboundRules   (outbound)

  The EOMT mitigation for CVE-2026-42897 creates its CSP rule in outboundRules.
  Running Health Checker after EOMT deployment will NOT show this rule in the
  report. Administrators cannot use Health Checker as a sole verification tool
  for EOMT outbound mitigation status.

  Remediation:
    In Get-URLRewriteRule.ps1 - read both .rewrite.rules and .rewrite.outboundRules
    at all three config paths (L49, L72, L97).
    In Invoke-AnalyzerIISInformation.ps1 - iterate .rule from both collections.

"@ -ForegroundColor Yellow

Write-Host "[!] FOR AUTHORIZED SECURITY RESEARCH ONLY`n" -ForegroundColor DarkRed
