# Windows Defender — ShieldBreak: RoguePlanet (CVE-2026-50656) Patch Bypass via Cloud Files Rehydration + Object Manager Symlinks

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-08-11 |
| **Last Updated** | 2026-08-11 |
| **Author / Researcher** | MSNightmare (INFINITE NIGHTMARE / Project Nightcrawler) |
| **CVE / Advisory** | Bypass of CVE-2026-50656 (RoguePlanet); no CVE assigned to ShieldBreak as of 2026-08-11 |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | 7.8 (estimated CVSSv3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| **Status** | Unpatched |
| **Tags** | windows, windows-defender, lpe, privilege-escalation, 0day, patch-bypass, cloud-files, cfapi, object-manager, symlink, wer, dll-sideload, CWE-59, CWE-426, microsoft, rogueplanet, shieldbreak |
| **Related** | pocs/binary/2026-06-10_rogueplanet-defender-lpe/ (original RoguePlanet, same author), pocs/binary/2026-06-26_cve-2026-50656-rogueplanet-checker/ (RoguePlanet checker), pocs/binary/2026-05-15_bluehammer-defender-lpe/ (different Defender LPE) |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Microsoft Windows Defender (Antimalware Service Executable / MsMpEng.exe), threat remediation subsystem |
| **Versions Affected** | Windows 11 25H2 (including Canary channel) and Windows Server 2025 with the latest Defender definitions. Windows 10 and respective Server editions are also vulnerable but not currently supported by this PoC. |
| **Language / Platform** | C++ (Visual Studio 2022, .NET Framework 4.6.2 for Rubeus dependency). Targets x64 Windows with Defender enabled. |
| **Authentication Required** | Yes — requires local user-level access on the target machine (standard user, no admin) |
| **Network Access Required** | Local — the exploit runs on the target machine; uses loopback UNC path (`\\127.0.0.1\C$`) for the symlink target |

---

## Summary

ShieldBreak is a 0-day local privilege escalation exploit that bypasses the patch for CVE-2026-50656 (RoguePlanet), achieving SYSTEM-level code execution from an unprivileged user on fully patched Windows 11 and Server 2025 systems. The exploit was released by the same researcher (MSNightmare) who discovered the original RoguePlanet vulnerability.

The exploit chains three Windows subsystems: the Cloud Files API (CfApi), the NT Object Manager, and Windows Error Reporting (WER). It registers a malicious cloud sync provider that serves different content on successive hydration requests, uses object manager symlinks to redirect Defender threat remediation to write an attacker-controlled DLL to `C:\Windows\System32`, and then triggers the WER scheduled task to load the planted DLL as SYSTEM.

The PoC has a reported 100% success rate on supported platforms.

---

## Vulnerability Details

### Root Cause

Microsoft patched CVE-2026-50656 (RoguePlanet) by adding validation to the Defender cleanup path. ShieldBreak bypasses this patch by using a different file delivery mechanism (Cloud Files rehydration instead of direct file placement) and a different symlink chain (object manager directories with shadow directories instead of NTFS junctions).

The fundamental issue remains: Windows Defender threat remediation runs as SYSTEM and follows symlinks during cleanup operations without adequate validation of the final destination path. The patch for CVE-2026-50656 hardened specific paths but did not address the underlying symlink-following behavior in the cleanup subsystem.

### Attack Flow

1. **Setup**: Create a work directory (`C:\ShieldBreak_<GUID>`) and register a Cloud Files sync provider via `CfRegisterSyncRoot`.

2. **Placeholder creation**: Create a Cloud Files placeholder file ("BERLIN") backed by the sync provider. The initial file size matches the EICAR bait ZIP.

3. **Object Manager symlink chain**: Create two object manager directories with a shadow relationship and two symlinks:
   - `WD_SHADOW_<GUID>\WD_SCAN` -> work directory (for the scan path)
   - `WD_TARGET_<GUID>\WD_SCAN` -> `\CLFS\??\<workdir>` (for the CLFS log redirect)

4. **Trigger Defender scan**: Scan the placeholder through the object manager symlink path. The Cloud Files callback serves the bait ZIP (containing a DLL Defender detects as malware) on the first hydration.

5. **Race the cleanup**: When Defender detects the threat and begins remediation, it creates a CLFS (Common Log File System) log in the work directory. The exploit monitors for this file creation event.

6. **Symlink pivot**: Delete the first scan symlink and replace it with an object directory containing a symlink to `\\127.0.0.1\C$\Windows\System32\phoneinfo.dll`. Lock the CLFS log file to control timing.

7. **Rehydration swap**: Call `CfRestartHydration` to restart the placeholder hydration. This time the Cloud Files callback serves `Warden.dll` (the payload DLL) instead of the bait ZIP. Defender writes the payload to the redirected destination: `C:\Windows\System32\phoneinfo.dll`.

8. **DLL loading via WER**: Create a crafted crash report in `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` and trigger the WER `QueueReporting` scheduled task. The task runs as SYSTEM and loads `phoneinfo.dll` from System32.

9. **SYSTEM shell**: The planted DLL executes as SYSTEM, connecting back to a named pipe (`\\.\pipe\SHIELDBREAK`) to deliver the elevated context.

### Impact

Local privilege escalation from standard user to SYSTEM on fully patched Windows 11 and Server 2025. An attacker with local access can achieve complete system compromise, bypassing all Defender protections in the process — since the exploit abuses Defender itself to write the payload.

---

## Environment / Lab Setup

```
# Requirements:
# - Windows 11 25H2 or Windows Server 2025 (latest updates)
# - Windows Defender enabled with current definitions
# - Visual Studio 2022 with C++ workload (to compile)
# - Standard (non-admin) user account
# - phoneinfo.dll must NOT already exist in System32
#   (the exploit checks for this and exits if present)
```

### Setup Steps

```
# 1. Clone the repository
git clone https://github.com/MSNightmare/ShieldBreak.git

# 2. Open ShieldBreak.slnx in Visual Studio 2022

# 3. Build the solution (Release, x64)

# 4. Run as a standard (non-admin) user:
ShieldBreak.exe
```

---

## Proof of Concept

> See `ShieldBreak.cpp` (1,410 lines, C++) and supporting files in this folder — mirrored from [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak). The upstream README is preserved as `upstream-README.md`.

### Step-by-Step Reproduction

1. **Compile** ShieldBreak.slnx in Visual Studio 2022 (Release, x64).
2. **Verify** that `C:\Windows\System32\phoneinfo.dll` does not exist.
3. **Run** `ShieldBreak.exe` as a standard user.
4. **Observe** the exploit output — it should report success and spawn a SYSTEM shell via the named pipe.

### Exploit Code

The Cloud Files callback — serves different content on successive hydrations (bait ZIP first, payload DLL second):

```cpp
void CALLBACK CLBK(
    _In_ CONST CF_CALLBACK_INFO* CallbackInfo,
    _In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {
    DWORD* RNA = (DWORD*)CallbackInfo->CallbackContext;
    if (*RNA == 1) {
        opParams.TransferData.Buffer = pResourceData_zip;   // bait
        opParams.TransferData.Length.QuadPart = dwSize_zip;
        *RNA = 2;
    } else {
        opParams.TransferData.Buffer = pResourceData_dll;   // payload
        opParams.TransferData.Length.QuadPart = dwSize_dll;
    }
    // ...
}
```

The symlink pivot — redirect Defender cleanup to System32:

```cpp
ObjectSymlinkMgr* lsymlink = new ObjectSymlinkMgr(
    _lsymlinkname,
    (wchar_t*)L"\\??\\UNC\\127.0.0.1\\C$\\Windows\\System32\\phoneinfo.dll",
    foodir->GetHandle());
```

The WER trigger — scheduled task runs as SYSTEM and loads the planted DLL:

```cpp
taskfolder->GetTask((BSTR)L"QueueReporting", &taskex);
taskex->Run(_variant_t(), &runningtask);
```

### Expected Output

```
[+] \??\C:\ShieldBreak_{GUID} was created.
[+] Cloud provider has been registered.
[+] Attached cloud provider to C:\ShieldBreak_{GUID}
[+] Placeholder created.
[+] \BaseNamedObjects\Restricted\WD_TARGET_{GUID} object manager directory created
[+] \BaseNamedObjects\Restricted\WD_SHADOW_{GUID} object manager directory created
[+] WD_SCAN <=> \??\C:\ShieldBreak_{GUID} object link created
[+] WD_SCAN <=> \CLFS\??\C:\ShieldBreak_{GUID} object link created
[*] Scan initiated for \\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_{GUID}\WD_SCAN\BERLIN
[*] Please wait...
[+] Cloud provider callback success.
[+] Cloud provider callback success.
[+] Link deleted.
[+] CLFS log locked.
[+] Cloud provider callback success.
[+] Cloud provider callback success.
[+] \??\C:\Windows\System32\phoneinfo.dll:stream file locked.
[*] Attempting to spawn shell...
[+] Exploit succeeded.
```

---

## Detection and Indicators of Compromise

```
# Process signals:
# - Non-admin process loading MpClient.dll and calling MpScanStart/MpCleanOpen
# - CfRegisterSyncRoot from a non-standard (non-OneDrive/non-known) provider
# - CfCreatePlaceholders followed by CfRestartHydration in quick succession
# - Creation of object manager directories under \BaseNamedObjects\Restricted\
#   with "WD_TARGET" or "WD_SHADOW" prefixes

# Filesystem signals:
# - phoneinfo.dll appearing in C:\Windows\System32 (this file does not normally exist)
# - Directories matching C:\ShieldBreak_* (hidden attribute)
# - Crafted WER reports in C:\ProgramData\Microsoft\Windows\WER\ReportQueue\
#   referencing "AngryPeopleBug.exe"

# Scheduled task signals:
# - WER QueueReporting task triggered by a non-system process
# - Event ID 4688 (process creation) showing WerFault loading phoneinfo.dll

# Named pipe:
# - \\.\pipe\SHIELDBREAK created by non-admin process
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | No patch available as of 2026-08-11 — this is a 0-day bypass of the CVE-2026-50656 fix. Monitor MSRC for an updated advisory. |
| **Workaround** | Deploy an ASR (Attack Surface Reduction) rule to block untrusted Cloud Files sync provider registrations. Monitor for `phoneinfo.dll` creation in System32. Block the WER QueueReporting scheduled task from loading unsigned DLLs. Consider deploying application control (WDAC) policies that prevent unsigned DLLs in System32. |
| **Verification** | Check that `C:\Windows\System32\phoneinfo.dll` does not exist. Monitor Sysmon or ETW for CfRegisterSyncRoot calls from non-standard processes. |

---

## References

- [MSNightmare/ShieldBreak (upstream PoC)](https://github.com/MSNightmare/ShieldBreak)
- [MSNightmare/RoguePlanet (original vulnerability)](https://github.com/MSNightmare/RoguePlanet)
- [CVE-2026-50656 — RoguePlanet (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-50656)
- [Project Nightcrawler Blog](https://blog.projectnightcrawler.dev/)
- [Related — RoguePlanet Defender LPE (in this archive)](../2026-06-10_rogueplanet-defender-lpe/)
- [Related — CVE-2026-50656 RoguePlanet Checker (in this archive)](../2026-06-26_cve-2026-50656-rogueplanet-checker/)
- [Cloud Files API (CfApi) Documentation](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/)

---

## Notes

Verified this session by reading the full PoC source (`ShieldBreak.cpp`, 1,410 lines). The exploit is a sophisticated single-file C++ application that chains Cloud Files API (CfApi) placeholder hydration, NT Object Manager symlink manipulation, Windows Defender MpClient.dll RPC-based scan/clean invocation, and WER scheduled task DLL sideloading into a seamless privilege escalation from standard user to SYSTEM. The code is well-structured with clear phase separation: setup, cloud provider registration, placeholder creation, symlink chain, scan trigger, race/pivot, rehydration swap, DLL plant, and WER trigger.

The exploit embeds three resources: a bait ZIP (`eicar_com.zip`, containing `ShellDll.dll` — a DLL Defender detects as malware, used to trigger the cleanup flow), a payload DLL (`Warden.dll`, planted to System32 as `phoneinfo.dll`), and a crafted WER crash report (`Report.wer`, referencing a fake app "AngryPeopleBug.exe"). The WER report triggers the QueueReporting scheduled task which loads the planted DLL as SYSTEM.

**Committed binary caveat**: The repository includes two pre-compiled binaries (`eicar_com.zip` containing `ShellDll.dll`, and `Warden.dll`) whose contents cannot be verified from source code. The C++ exploit source is fully readable and clearly legitimate, and the author (MSNightmare) is the same researcher behind RoguePlanet (1,586 stars, CVE-2026-50656, already in this archive). Users should exercise caution with pre-compiled binaries and consider building their own test DLLs if reproducing the exploit in a lab.

Author track record: MSNightmare (INFINITE NIGHTMARE / Project Nightcrawler) is a prolific Windows security researcher with 2,511 GitHub followers. Their prior disclosures — RoguePlanet (Defender LPE, CVE-2026-50656, 1,586 stars), LegacyHive (Windows ProfSvc 0-day, 298 stars), GreatXML (BitLocker bypass, 621 stars), and BrokenArrow (80 stars) — demonstrate deep expertise in Windows internals and privilege escalation. The ShieldBreak repo was created August 11, 2026, and accumulated 341 stars and 112 forks within a day, consistent with the high-impact nature of the disclosure.

The exploit requires `phoneinfo.dll` to NOT exist in System32 as a precondition (the code checks and exits if present). This is a reasonable constraint — `phoneinfo.dll` is not a standard Windows system DLL. The cleanup step removes the work directory, WER report, and temporary files but deliberately leaves `phoneinfo.dll` in System32 (as it demonstrates the persistent payload plant).
