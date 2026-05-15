# BlueHammer Defender Local Privilege Escalation (CVE-2026-33825)

<!-- 
  File: 2026-05-15_bluehammer-defender-lpe.md
  Location: pocs/binary/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-15 |
| **Author / Researcher** | Nightmare-Eclipse |
| **CVE / Advisory** | CVE-2026-33825 |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | 7.8 (estimated, CVSSv3) |
| **Status** | Weaponized |
| **Tags** | LPE, Windows Defender, VSS, SAM-hive-leak, RPC, local-user |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Microsoft Defender Antivirus update/scan workflow on Windows |
| **Versions Affected** | N/A (exact vulnerable build range not specified in source repository) |
| **Language / Platform** | C++ / Windows |
| **Authentication Required** | Yes (local code execution) |
| **Network Access Required** | Local only |

---

## Summary

BlueHammer is a Windows local privilege-escalation PoC targeting Defender-associated update and scanning behavior. The exploit orchestrates object-manager symbolic links, directory change notifications, oplocks, RPC-triggered Defender activity, and transactional file access to obtain high-value data (`SAM`) through a privileged path. The leaked credential material is then used to manipulate local user authentication state and launch elevated execution flow, culminating in SYSTEM-level shell access.

---

## Vulnerability Details

### Root Cause

The PoC indicates a privileged logic/path-handling weakness in Defender-related update processing. By controlling timing and namespace/object links around Defender definition-update activity, an unprivileged local process can redirect privileged file interactions and read protected targets via VSS-backed paths.

### Attack Vector

A local attacker runs the PoC binary on a Defender-enabled host. The exploit waits for Defender signature-update activity, stages crafted update files in a controlled directory, races the update workflow with oplocks and object-manager links, and maps `mpasbase.vdm` access to sensitive VSS-backed files (notably `\Windows\System32\Config\SAM`). It then uses the leaked data to perform account/password-token abuse and spawn elevated processes.

### Impact

Local privilege escalation to administrative/SYSTEM execution, enabling full host compromise from a local user context.

---

## Environment / Lab Setup

```
OS:          Windows (Defender enabled)
Target:      Host where vulnerable Defender behavior is present
Attacker:    Local non-admin user with execution rights
Tools:       Visual Studio (v143 toolset), Windows SDK APIs, RPC runtime
```

### Setup Steps

```bash
# 1. Clone source repository
git clone --depth=1 https://github.com/Nightmare-Eclipse/BlueHammer /tmp/bluehammer-source

# 2. Build the Visual Studio project on an authorized Windows lab host
#    (FunnyApp.sln / FunnyApp.vcxproj)

# 3. Run the compiled executable as a local user in a controlled test lab
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Build and execute BlueHammer** — compile `FunnyApp.cpp` and run the produced executable as a local user.
   ```bash
   FunnyApp.exe
   ```

2. **Trigger Defender update workflow** — the PoC polls for signature updates, downloads update payload components, and waits for Defender to create a new definition-update directory.

3. **Redirect privileged access and leak SAM** — the exploit races Defender file operations with NT object links/oplocks and opens a redirected `mpasbase.vdm` path to obtain sensitive hive data.

4. **Escalate privileges** — credential abuse and service creation paths are used to obtain SYSTEM shell execution.

### Exploit Code

> See `FunnyApp.cpp` in this folder.

```cpp
// Minimal concept snippet — full exploit in FunnyApp.cpp
printf("Checking for windows defender signature updates...\n");
while (!CheckForWDUpdates(updtitle, &criterr)) {
    Sleep(30000);
}

// ... after update-path/object-link race and file redirection
printf("Exploit succeeded.\n");
DoSpawnShellAsAllUsers(hleakedfile);
```

### Expected Output

```
Checking for windows defender signature updates...
Found Update :
...
Exploit succeeded.
    SYSTEMShell : OK.
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized lab evidence of successful SYSTEM shell escalation

---

## Detection & Indicators of Compromise

```
# Potential host indicators
# - Suspicious activity under C:\ProgramData\Microsoft\Windows Defender\Definition Updates
# - Rapid object-manager symbolic-link and reparse operations from user context
# - Unusual access attempts to VSS-backed \Windows\System32\Config\SAM paths
# - Service-creation events following Defender update activity
```

**SIEM / IDS Rule (example):**
```
Detect sequence: unprivileged process -> Defender update event ->
object-link/reparse manipulation -> sensitive hive access -> service creation/SYSTEM token use
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Apply Microsoft updates addressing CVE-2026-33825 for Defender/Windows components |
| **Workaround** | Restrict local untrusted code execution and monitor/block suspicious link/reparse abuse in user-writable paths |
| **Config Hardening** | Enforce application allowlisting, Defender tamper protection, and high-fidelity auditing for privileged file-access/service-creation chains |

---

## References

- [CVE-2026-33825](https://nvd.nist.gov/vuln/detail/CVE-2026-33825)
- [Source Repository — Nightmare-Eclipse/BlueHammer](https://github.com/Nightmare-Eclipse/BlueHammer)
- [MIT License — Source repository](https://github.com/Nightmare-Eclipse/BlueHammer/blob/main/LICENSE)

---

## Notes

Auto-ingested from https://github.com/Nightmare-Eclipse/BlueHammer on 2026-05-15.

The upstream repository README notes that there may be bugs in the published PoC; reproduce only in controlled, authorized environments.
