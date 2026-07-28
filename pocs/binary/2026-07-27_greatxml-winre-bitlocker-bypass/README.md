# GreatXML — WinRE / Defender Offline-Scan Trust-Boundary Abuse → BitLocker Bypass (No CVE)

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-27 |
| **Last Updated** | 2026-06-11 |
| **Author / Researcher** | Nightmare-Eclipse (GitHub: MSNightmare) |
| **CVE / Advisory** | N/A (no CVE assigned, no Microsoft advisory as of 2026-07-27) |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | N/A (unofficial; no CVSS assigned) |
| **Status** | Unpatched |
| **Tags** | windows, bitlocker, winre, defender, offline-scan, trust-boundary-bypass, zero-day, unpatched, physical-access, local |
| **Related** | pocs/binary/2026-07-27_legacyhive-windows-hive-load-lpe/ (same researcher, same disclosure wave) |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Windows Recovery Environment (WinRE) — Microsoft Defender Offline Scan launch path (`ReAgent.xml` scheduled operation) |
| **Versions Affected** | Windows builds using the `26100.1.amd64fre.ge_release.240331-1435` WinRE image family (Windows 11 24H2-era) and likely later builds sharing the same offline-scan launch mechanism; no fix confirmed as of 2026-07-27 |
| **Language / Platform** | Windows unattend/setup XML (`unattend.xml`, `ReAgent.xml`), WinRE (Windows PE) |
| **Authentication Required** | No — if Defender Offline Scan has ever run on the machine, no login is required at all |
| **Network Access Required** | Local only — requires physical access to reboot the target into WinRE |

---

## Summary

GreatXML abuses the trust boundary around Microsoft Defender's Offline Scan feature, which reboots a Windows machine into WinRE (Windows PE) and runs `OfflineScannerShell.exe` with elevated, pre-BitLocker-unlock trust. The `ReAgent.xml` recovery-configuration file specifies exactly which `OperationParam` command WinRE will execute during this offline-scan operation — and an attacker with physical access (and a mountable recovery/EFI partition, or the ability to have Defender Offline Scan already initiated on the box) can overwrite this file along with a companion `unattend.xml` that provisions blank-password local Admin/User accounts with autologon and runs attacker-controlled PowerShell during Windows setup/specialize passes. If Defender Offline Scan has ever been triggered on the victim machine, the attacker does not even need to log in first — simply replacing these files and rebooting to WinRE (Shift+Click "Restart") is sufficient to spawn a shell with unrestricted access to the BitLocker-protected volume, bypassing the disk encryption's intended protection against offline/physical tampering. No CVE has been assigned and no Microsoft patch exists as of this writing.

---

## Vulnerability Details

### Root Cause

`ReAgent.xml` under `\Recovery\WindowsRE\` governs WinRE's recovery behavior, including a `ScheduledOperation` state and an `OperationParam` string that WinRE executes on the next boot into the recovery environment — legitimately used to launch `OfflineScannerShell.exe -Threshold -AutoScan -Inbox -UpdateSigs -ConsoleUi` for Defender's offline malware scan. This scan runs *before* the OS volume is unlocked from BitLocker in the normal boot sequence, meaning WinRE (and whatever `ReAgent.xml` tells it to launch) operates with a level of trust and pre-unlock access that the OS proper does not extend to arbitrary local processes. Because `ReAgent.xml` and the accompanying `unattend.xml`/`Recovery` directory contents are writable by anyone with access to the recovery/EFI partition (physical access, or any existing local session capable of reaching that partition), an attacker can substitute their own `OperationParam` and provisioning scripts. Windows Setup's `unattend.xml` "specialize" and "oobeSystem" passes are designed to run trusted, unattended configuration (create accounts, run scripts) precisely because they occur before any interactive login gate exists — repurposing that same trusted pipeline via the WinRE offline-scan path turns it into an attacker-controlled code-execution and account-provisioning primitive with pre-BitLocker-unlock privilege.

### Attack Vector

1. **If Defender Offline Scan was ever previously initiated** on the victim machine, the machine is already vulnerable with no login required at all.
2. Copy the malicious `unattend.xml` and `Recovery` directory (containing the crafted `ReAgent.xml`) to the root of the recovery partition.
3. Reboot into WinRE via Shift+Click on the Restart button (no credentials needed for this step on a machine that has never been logged into, if offline scan was previously triggered by any means, e.g. a scheduled scan).
4. WinRE reads the substituted `ReAgent.xml`'s `OperationParam`/`ScheduledOperation` and launches the attacker-controlled path instead of (or via) the legitimate offline-scanner invocation; the accompanying `unattend.xml` provisions a blank-password local Administrator account with autologon and runs attacker-supplied PowerShell (`Specialize.ps1`/`FirstLogon.ps1`) during Windows Setup passes.
5. Result: a shell with unrestricted access to the BitLocker-protected volume, obtained without ever supplying the BitLocker recovery key or valid Windows credentials.
6. **If Defender Offline Scan was never previously initiated**, the attacker must first either log in and initiate a scan themselves, or find another way to boot into WinRE in the offline-scan state without logging in (the upstream author states this is likely possible but does not fully demonstrate it in the public PoC).

### Impact

Complete bypass of BitLocker's physical-tampering protection model: an attacker with physical access to a locked, BitLocker-encrypted Windows machine (and, in the common case where offline scan has run before, no credentials at all) can obtain unrestricted SYSTEM-level access to the encrypted volume's contents, entirely defeating the purpose of disk encryption against device theft/loss scenarios. This is a physical-access attack, not a remote one, but it directly undermines a security control (BitLocker) whose entire threat model is physical/offline access.

---

## Environment / Lab Setup

```
OS:          Windows 11 24H2-era build using WinRE image 26100.1.amd64fre.ge_release.240331-1435
             (or later builds sharing the same offline-scan launch mechanism)
Target:      A BitLocker-encrypted Windows machine with a writable/mountable recovery
             or EFI partition, where Defender Offline Scan has previously run at least once
Attacker:    Physical access to the target machine; a way to write to the recovery
             partition (e.g. booting external media, or an existing local session)
Tools:       unattend.xml + Recovery/WindowsRE/ReAgent.xml (this folder)
```

### Setup Steps

```bash
# 1. Obtain write access to the target's recovery partition (physical access /
#    external boot media, or an existing local session that can reach it).
# 2. Copy this folder's unattend.xml to the root of the recovery partition.
# 3. Copy this folder's Recovery/WindowsRE/ReAgent.xml to \Recovery\WindowsRE\
#    on the recovery partition, overwriting the existing file.
# 4. Reboot the target: Shift+Click the Restart button to boot directly into WinRE.
```

---

## Proof of Concept

> See `unattend.xml`, `Recovery/WindowsRE/ReAgent.xml`, and `upstream-README.md`/`LICENSE` in this folder — mirrored from [MSNightmare/GreatXML](https://github.com/MSNightmare/GreatXML) (MIT-licensed, 596–611 stars / 240 forks). Verified before ingestion: fetched and read both XML files directly. `Recovery/WindowsRE/ReAgent.xml` is a legitimate-structured WinRE config whose `OperationParam` references the real, correctly-flagged Defender Offline Scan binary (`\ProgramData\Microsoft\Windows Defender\Offline Scanner\OfflineScannerShell.exe -Threshold -AutoScan -Inbox -UpdateSigs -ConsoleUi`) and a non-default `ScheduledOperation state="15"` — matching the "abuse the offline-scan trust boundary" mechanism described in third-party coverage (ThreatLocker, The Hacker News, SecurityWeek). `unattend.xml` is a real, well-formed Windows unattend-answer file (generated via the well-known [schneegans.de unattend generator](https://schneegans.de/windows/unattend-generator/), commit hash embedded in the file) that creates local Admin/User accounts with blank passwords, autologon, and runs embedded PowerShell scripts (`Specialize.ps1`, `FirstLogon.ps1`) during the Setup specialize/oobeSystem passes — standard unattended-Windows-install tooling repurposed as the payload delivery stage, not a generic obfuscated dropper. No external C2/callback URLs are embedded in either XML file. Same researcher/track record as the `legacyhive-windows-hive-load-lpe` entry in this archive.

### Step-by-Step Reproduction

1. **Precondition check** — confirm Defender Offline Scan has run at least once on the target (common in default-configured environments with periodic Defender scans), or initiate it manually if you have login access.
2. **Stage the files** — copy `unattend.xml` to the recovery partition root, and `Recovery/WindowsRE/ReAgent.xml` to `\Recovery\WindowsRE\`, overwriting the original.
3. **Reboot to WinRE** — Shift+Click Restart from the lock screen or login screen (no credentials required if the precondition in step 1 holds).
4. **Observe shell** — per upstream author's documented result, a shell with unrestricted access to the BitLocker volume spawns.

### Exploit Code

> This entry's "exploit" is entirely configuration data, not executable code — see `unattend.xml` and `Recovery/WindowsRE/ReAgent.xml` in this folder for the complete, unmodified content.

```xml
<!-- ReAgent.xml — the key trust-boundary-abusing field -->
<OperationParam path="\ProgramData\Microsoft\Windows Defender\Offline Scanner\OfflineScannerShell.exe &lt;-Threshold -AutoScan -Inbox -UpdateSigs -ConsoleUi  &gt;"/>
<ScheduledOperation state="15"/>
```

```xml
<!-- unattend.xml — blank-password autologon Admin + attacker PowerShell during Setup -->
<LocalAccount wcm:action="add">
  <Name>Admin</Name>
  <Group>Administrators</Group>
  <Password><Value></Value><PlainText>true</PlainText></Password>
</LocalAccount>
<AutoLogon><Username>Admin</Username><Enabled>true</Enabled><LogonCount>1</LogonCount></AutoLogon>
```

### Expected Output

```
(Per upstream author's documented result — screenshots showed a WinRE-launched shell
with unrestricted access to the BitLocker-protected volume contents; the two screenshot
assets referenced in the upstream README are hosted on GitHub user-attachments and are
not repository files, so they are not mirrored in this archive entry.)
```

---

## Screenshots / Evidence

- Not included in this archive entry. Upstream author's README embeds two screenshots (`screenshot1.png`, `screenshot2.png`) demonstrating a successful run; these ARE present as files in the upstream repository and could be mirrored on request, but were omitted here to keep this entry text/config-only.

---

## Detection & Indicators of Compromise

```
# Unexpected modification timestamps on \Recovery\WindowsRE\ReAgent.xml or a root-level
# unattend.xml on the recovery/EFI partition, especially outside of a legitimate
# Windows Setup/upgrade window

# ReAgent.xml OperationParam or ScheduledOperation values that differ from the
# vendor-default offline-scanner invocation, or reference paths outside
# \ProgramData\Microsoft\Windows Defender\Offline Scanner\

# Presence of an unattend.xml on the recovery partition provisioning blank-password
# local Administrator accounts with AutoLogon enabled — never a legitimate
# post-deployment state

# Physical-security controls: any unauthorized physical access to a BitLocker-
# encrypted machine, followed by a Shift+Click restart into WinRE, should be treated
# as a potential BitLocker-bypass attempt pending this class of vulnerability
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | None available. No CVE assigned, no Microsoft advisory or fix as of 2026-07-27 — monitor MSRC for a future update addressing WinRE/offline-scan trust-boundary handling. |
| **Workaround** | Enable BitLocker protection for the recovery/EFI partition contents where supported, or use TPM+PIN/startup-key BitLocker configurations that require pre-boot authentication before WinRE can be reached at all; restrict physical access to devices as the primary mitigating control given no software fix exists. |
| **Config Hardening** | Disable or tightly control Defender Offline Scan scheduling where BitLocker physical-tamper resistance is a hard requirement; audit recovery-partition file integrity (`ReAgent.xml`, `unattend.xml`) periodically; enforce Secure Boot and pre-boot authentication to reduce the WinRE attack surface. |

---

## References

- [Public PoC — MSNightmare/GreatXML](https://github.com/MSNightmare/GreatXML)
- [SecurityWeek — GreatXML Zero-Day Exploit Bypasses BitLocker](https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/)
- [The Register — Nightmare Eclipse Drops Claimed BitLocker Bypass for Microsoft Windows](https://www.theregister.com/security/2026/06/11/nightmare-eclipse-drops-claimed-bitlocker-bypass-for-microsoft-windows/5254371)
- [Cyderes — GreatXML Windows Zero-Day](https://www.cyderes.com/howler-cell/greatxml-windows-zero-day)

---

## Notes

**No CVE / unpatched:** Public 0-day, no CVE assignment, no Microsoft patch as of ingestion (2026-07-27). Released by the same researcher/account ("Nightmare-Eclipse" / MSNightmare) as `legacyhive-windows-hive-load-lpe` (also in this archive), amid the same ongoing public dispute with MSRC.

**Physical-access precondition:** This is not a remote or even fully local-unauthenticated attack in the general case — it requires physical access to the target device to reboot into WinRE and (in the harder case) write access to the recovery partition. The "no login required" scenario specifically depends on Defender Offline Scan having been triggered at least once previously on that machine, which the researcher notes is common but not universal.

**Verification:** Both files in this folder (`unattend.xml`, `Recovery/WindowsRE/ReAgent.xml`) are byte-for-byte identical to the upstream repository (verified via `diff` against a fresh clone) — no paraphrasing or rewriting was performed. No obfuscated code, no external C2/callback URLs embedded in either XML file, no malware/scam signals found in the repository.
