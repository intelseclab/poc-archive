#Requires -RunAsAdministrator
# =============================================
# YellowKey Mitigation Script (CVE-2026-45585)
# Combines WinRE fix + TPM+PIN enforcement
# Author : Ashraf Zaryouh / @0xBlackash
# =============================================

param(
    [string]$Drive = "",          # Optional: e.g. "C:"
    [switch]$SkipWinRE = $false,  # Use if you only want TPM+PIN
    [switch]$SkipTPMPIN = $false  # Use if you only want WinRE fix
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "YellowKey Mitigation Tool"

Write-Host "YellowKey Mitigation Tool (CVE-2026-45585)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# --- Windows Version Check ---
$build = [System.Environment]::OSVersion.Version.Build
if ($build -lt 22000) {
    Write-Host "Windows 10 detected — not affected by YellowKey." -ForegroundColor Green
    exit 0
}

# ======================
# 1. WinRE Mitigation (Primary Fix)
# ======================
if (-not $SkipWinRE) {
    Write-Host "`n[1/2] Applying WinRE Mitigation (remove autofstx.exe)..." -ForegroundColor Yellow

    $MountPath = "C:\WinRE_Mount"
    $WinREPath = "$MountPath\Windows\System32\Recovery\WinRE.wim"

    try {
        # Create mount directory if needed
        if (-not (Test-Path $MountPath)) {
            New-Item -Path $MountPath -ItemType Directory -Force | Out-Null
        }

        # Disable and re-enable WinRE to get clean state
        reagentc /disable | Out-Null
        reagentc /enable | Out-Null

        # Mount WinRE
        Write-Host "Mounting WinRE image..." -ForegroundColor Gray
        reagentc /mountre /path $MountPath /target $env:SystemDrive | Out-Null

        # Load offline SYSTEM hive
        $HivePath = "$MountPath\Windows\System32\config\SYSTEM"
        reg load HKLM\WinRE_Hive $HivePath | Out-Null

        # Modify BootExecute
        $keyPath = "HKLM:\WinRE_Hive\ControlSet001\Control\Session Manager"
        $value = Get-ItemProperty -Path $keyPath -Name "BootExecute" -ErrorAction SilentlyContinue

        if ($value) {
            $bootExecute = $value.BootExecute
            $newBootExecute = $bootExecute | Where-Object { $_ -notlike "*autofstx.exe*" }

            if ($newBootExecute.Count -ne $bootExecute.Count) {
                Set-ItemProperty -Path $keyPath -Name "BootExecute" -Value $newBootExecute -Type MultiString -Force
                Write-Host "Successfully removed autofstx.exe from BootExecute" -ForegroundColor Green
            } else {
                Write-Host "autofstx.exe was not present — already mitigated" -ForegroundColor Green
            }
        }

        # Unload hive
        [GC]::Collect()
        reg unload HKLM\WinRE_Hive | Out-Null

        # Commit changes
        reagentc /unmountre /commit | Out-Null
        Write-Host "WinRE mitigation applied successfully." -ForegroundColor Green

    } catch {
        Write-Host "WinRE mitigation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "You may need to run this manually or check WinRE status." -ForegroundColor Yellow
    }
}

# ======================
# 2. TPM + PIN Mitigation
# ======================
if (-not $SkipTPMPIN) {
    Write-Host "`n[2/2] Applying TPM+PIN BitLocker Protection..." -ForegroundColor Yellow

    # Set Group Policy keys
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    if (-not (Test-Path $fvePath)) { New-Item -Path $fvePath -Force | Out-Null }

    Set-ItemProperty -Path $fvePath -Name "UseAdvancedStartup" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $fvePath -Name "UseTPMPIN" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $fvePath -Name "UseTPM" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $fvePath -Name "UseEnhancedPin" -Value 1 -Type DWord -Force

    gpupdate /force | Out-Null

    # Process drives
    if ($Drive) {
        $volumes = Get-BitLockerVolume -MountPoint $Drive.TrimEnd(':') -ErrorAction SilentlyContinue
    } else {
        $volumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" }
    }

    foreach ($vol in $volumes) {
        $mp = $vol.MountPoint
        Write-Host "`nProcessing drive: $mp" -ForegroundColor White

        $hasTPM = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -match "Tpm" }
        if (-not $hasTPM) {
            Write-Host "  No TPM protector found. Skipping." -ForegroundColor Yellow
            continue
        }

        $hasTPMPIN = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "TpmPin" }
        if ($hasTPMPIN) {
            Write-Host "  Already has TPM+PIN protector." -ForegroundColor Green
            continue
        }

        Write-Host "  Adding TPM+PIN protector..." -ForegroundColor Cyan
        try {
            manage-bde -protectors -add $mp -TPMAndPIN
            Write-Host "  TPM+PIN added successfully!" -ForegroundColor Green

            # Optional: Remove old TPM-only
            $tpmOnly = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "Tpm" }
            if ($tpmOnly) {
                $confirm = Read-Host "  Remove old TPM-only protector? (y/N)"
                if ($confirm -eq 'y') {
                    manage-bde -protectors -delete $mp -id $tpmOnly.KeyProtectorId
                    Write-Host "  TPM-only protector removed." -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "  Failed to add TPM+PIN: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`nMitigation process completed!" -ForegroundColor Green
Write-Host "Recommended: Reboot and test BitLocker + Recovery Environment." -ForegroundColor Gray
