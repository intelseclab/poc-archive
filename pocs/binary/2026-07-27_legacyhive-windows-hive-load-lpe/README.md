# LegacyHive — Windows User Profile Service Arbitrary Registry Hive Load LPE (No CVE)

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-27 |
| **Last Updated** | 2026-07-24 |
| **Author / Researcher** | Nightmare-Eclipse (GitHub: MSNightmare) |
| **CVE / Advisory** | N/A (no CVE assigned, no Microsoft advisory as of 2026-07-27) |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | N/A (unofficial; no CVSS assigned) |
| **Status** | Unpatched |
| **Tags** | windows, lpe, privilege-escalation, registry-hive, user-profile-service, toctou, oplock, zero-day, unpatched, local |
| **Related** | pocs/binary/2026-07-27_greatxml-winre-bitlocker-bypass/ (same researcher, same disclosure wave) |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Windows User Profile Service (profsvc) — registry hive-loading path |
| **Versions Affected** | All currently supported desktop and server Windows builds as of the July 2026 patch level (per upstream author, no fix has been shipped) |
| **Language / Platform** | C++ / Win32, native NT registry and object-manager APIs |
| **Authentication Required** | Yes — requires a second standard (non-admin) user's credentials in addition to the local attacker's own session |
| **Network Access Required** | Local only |

---

## Summary

LegacyHive abuses the Windows User Profile Service's registry hive-loading logic to mount an arbitrary user's registry hive under the current user's `HKEY_CLASSES_ROOT`. The published PoC exploits a race between hive-load validation and hive-open operations (an oplock-backed TOCTOU window) combined with an object-manager symbolic-link redirection, allowing a local standard user — who additionally supplies a second standard user's credentials — to load that second user's `UsrClass.dat` hive into their own session. The researcher (Nightmare-Eclipse) states the public release is deliberately "stripped down": the original, unpublished version required no second credential and was not limited to `UsrClass.dat` — any hive could reportedly be loaded via the same underlying primitive. No CVE has been assigned and no Microsoft patch exists as of this writing; this is a public, unpatched 0-day.

---

## Vulnerability Details

### Root Cause

The User Profile Service loads a target user's classes-root hive (`UsrClass.dat`) via the legacy Offline Registry (`OR*`) API family (`OROpenHiveByHandle`, `OROpenKey`, `ORSetValue`, `ORSaveHive`) in conjunction with `RegOpenUserClassesRoot`. The PoC wins a TOCTOU race in this path by requesting an oplock (`FSCTL_REQUEST_BATCH_OPLOCK`) on the target hive file and using the oplock break as a synchronization signal: while the profile-loading code has resolved (but not yet finished operating on) the target hive path, the PoC substitutes the path using an object-manager symbolic link crafted via `NtCreateDirectoryObjectEx`/`NtCreateSymbolicLinkObject` (resolved dynamically via `GetProcAddress` against `ntdll.dll`, since these are undocumented/native APIs) inside a directory created with a permissive DACL (`CreateDirectoryWithPermissiveDACL()`). Combined with a thread-hijacking primitive (`RaiseExceptionInThread()`/`ThrowFunc()`, which suspends a target thread via `SuspendThread`, captures/mutates its context via `GetThreadContext`/`SetThreadContext`, then resumes it) to drive the profile-loading code down the desired path at the right moment, the hive belonging to a second, attacker-known user account ends up loaded and mounted under the *attacker's own* `HKEY_CLASSES_ROOT` (`HiveLoaderThread()`), rather than the intended user's session.

### Attack Vector

1. As a local standard user, obtain the credentials of a second standard user account on the same machine (the public PoC requires this; the researcher states the original internal version did not).
2. Use `LogonUser`/`ImpersonateLoggedOnUser`/`CreateProcessWithLogonW` to establish the second user's security context transiently, sufficient to reference their profile hive path.
3. Create a permissive-DACL directory and object-manager symbolic link chain positioned to intercept the User Profile Service's hive-open sequence.
4. Trigger hive loading for the second user (`RegOpenUserClassesRoot`-driven path), racing the oplock-backed TOCTOU window: when the service resolves the target hive path but has not yet completed its open/validate step, redirect it via the crafted symlink so the operation completes against the attacker's intended target instead.
5. On success, the second user's `UsrClass.dat` hive is mounted into the attacker's own `HKEY_CLASSES_ROOT`, exposing that user's classes-root registry contents (COM registrations, file associations, and other per-user hive data) to the attacker's session.

### Impact

An unprivileged local standard user can force the Windows User Profile Service to load another user's registry hive into their own session context. In the public (deliberately limited) PoC this is scoped to `UsrClass.dat` and requires the victim's own credentials, which constrains real-world impact primarily to information disclosure / hive-content exposure between two known standard accounts. The researcher's own claims — that the underlying primitive, unstripped, generalizes to loading arbitrary hives without needing a second credential — imply a substantially more severe privilege-escalation path exists but is not publicly demonstrated. Treat the underlying class of bug as high-severity pending further public research or an official patch.

---

## Environment / Lab Setup

```
OS:          Windows 10 / 11 / Windows Server, fully patched to July 2026 per upstream author
Attacker:    Local standard (non-admin) user account
Victim:      A second standard user account on the same host, whose credentials the
             attacker must also possess for this stripped public PoC to function
Tools:       LegacyHive.cpp (this folder) — Visual Studio / MSVC, Windows SDK
             (native NT APIs resolved dynamically via GetProcAddress)
```

### Setup Steps

```bash
# Build in Visual Studio (or with cl.exe) against the Windows SDK.
# No third-party dependencies — only ntdll.dll/advapi32.dll native APIs.
cl.exe /EHsc LegacyHive.cpp /link ntdll.lib advapi32.lib
```

---

## Proof of Concept

> See `LegacyHive.cpp` (full, unmodified) and `upstream-README.md` / `LICENSE` in this folder — mirrored from [MSNightmare/LegacyHive](https://github.com/MSNightmare/LegacyHive) (MIT-licensed). Verified before ingestion: read the complete 474-line source. It genuinely implements the documented mechanism — `GenGUID()`, `CreateDirectoryWithPermissiveDACL()`, a thread-hijack primitive (`RaiseExceptionInThread()`/`ThrowFunc()` via `SuspendThread`/`GetThreadContext`/`SetThreadContext`), and `HiveLoaderThread()` orchestrated from `wmain()`, calling the real, correctly-paired Windows registry-hive-loader APIs (`OROpenHiveByHandle`, `OROpenKey`, `ORSetValue`, `ORSaveHive`, `RegOpenUserClassesRoot`), object-manager APIs resolved via `GetProcAddress` (`NtCreateDirectoryObjectEx`, `NtCreateSymbolicLinkObject`), an oplock-based TOCTOU race (`FSCTL_REQUEST_BATCH_OPLOCK`), and impersonation/logon APIs (`LogonUser`, `ImpersonateLoggedOnUser`, `CreateProcessWithLogonW`) — not a stub or template. This matches the technical description in independent third-party coverage (LevelBLUE SpiderLabs, cybersecuritynews.com) exactly. The upstream author (MSNightmare / "Nightmare-Eclipse", 2.3k GitHub followers) has a track record of prior similar releases (RoguePlanet — 1.6k stars, already covered elsewhere in this archive as `rogueplanet-defender-lpe`). No obfuscated code, no external downloader stage, no calls to suspicious network endpoints observed in the reviewed source.

### Step-by-Step Reproduction

1. **Build** — compile `LegacyHive.cpp` as above on a Windows lab host at July 2026 patch level.
2. **Run as the attacker's standard-user session**, supplying the second standard user's credentials when prompted/via command-line arguments (see upstream `README.md` for exact invocation, mirrored as `upstream-README.md`).
3. **Observe hive mount** — on success, the second user's `UsrClass.dat` is mounted under the running session's `HKEY_CLASSES_ROOT`; inspect via `regedit` or `reg query HKCR` to confirm keys belonging to the second user are now visible.

### Exploit Code

> See `LegacyHive.cpp` in this folder for the complete implementation.

```cpp
// LegacyHive.cpp — conceptual orchestration (see wmain() / HiveLoaderThread() for the real sequence)
CreateDirectoryWithPermissiveDACL(stagingDir);
// ... construct object-manager symlink via NtCreateDirectoryObjectEx / NtCreateSymbolicLinkObject ...
// ... request oplock (FSCTL_REQUEST_BATCH_OPLOCK) on target hive, wait for break as race signal ...
RaiseExceptionInThread(targetThread);   // SuspendThread/GetThreadContext/SetThreadContext hijack
HiveLoaderThread(secondUserCreds);      // OROpenHiveByHandle / OROpenKey / ORSetValue / ORSaveHive
```

### Expected Output

```
[*] Impersonating secondary user...
[*] Staging permissive-DACL directory + object-manager symlink...
[*] Requesting oplock on target hive, racing TOCTOU window...
[*] Hive mounted: HKEY_CLASSES_ROOT now contains target user's UsrClass.dat contents
```

---

## Screenshots / Evidence

- Not included in this archive entry. Upstream author's README embeds a screenshot (`Screenshot 2026-07-14 102705`, hosted on GitHub user-attachments) demonstrating a successful run; not mirrored here as it is a hosted image asset rather than a repository file.

---

## Detection & Indicators of Compromise

```
# Unexpected object-manager symbolic-link creation events (NtCreateSymbolicLinkObject)
# originating from a non-privileged process, especially directed at paths under
# a directory with a recently-applied permissive DACL

# Oplock request/break patterns (FSCTL_REQUEST_BATCH_OPLOCK) against user profile
# hive files (UsrClass.dat / NTUSER.DAT) from processes other than the profile
# service itself

# SuspendThread/SetThreadContext calls targeting threads belonging to
# profsvc.dll-hosted services (svchost.exe instances running the Profile Service)

# Unexpected registry keys appearing under a user's HKEY_CLASSES_ROOT that do not
# correspond to that user's own installed software/COM registrations
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | None available. No CVE assigned, no Microsoft advisory or fix as of 2026-07-27 — monitor MSRC for a future update addressing this researcher's disclosed User Profile Service hive-load behavior. |
| **Workaround** | Restrict local interactive logon to only trusted accounts where feasible; monitor for the object-manager symlink / oplock detection patterns above; treat any host where an untrusted local user can authenticate as a second standard account as at-risk. |
| **Config Hardening** | Apply general local-privilege-escalation hardening (LSA protection, restrict token impersonation rights, Credential Guard) as defense-in-depth; none of these directly close this specific hive-load path, since no patch exists. |

---

## References

- [Public PoC — MSNightmare/LegacyHive](https://github.com/MSNightmare/LegacyHive)
- [The Hacker News — Researcher Drops New Windows Zero-Day](https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html)
- [SecurityWeek — Nightmare Eclipse Drops LegacyHive Windows Zero-Day](https://www.securityweek.com/nightmare-eclipse-drops-legacyhive-windows-zero-day/)
- [LevelBlue SpiderLabs — LegacyHive: Nightmare Eclipse's Latest Zero-Day Drop, With a Stripped PoC](https://www.levelblue.com/blogs/spiderlabs-blog/legacyhive-nightmare-eclipses-latest-zero-day-drop-with-a-stripped-poc)
- [ExpertInsights — Nightmare Eclipse Releases LegacyHive Windows Zero-Day](https://expertinsights.com/news/nightmare-eclipse-releases-legacyhive-windows-zero-day)

---

## Notes

**No CVE / unpatched:** This is a public 0-day with no CVE assignment and no Microsoft patch as of ingestion (2026-07-27). It was released by the same researcher/account ("Nightmare-Eclipse" / MSNightmare) responsible for several other entries already in this archive (`bluehammer-defender-lpe`, `redsun-privileged-file-write`, `rogueplanet-defender-lpe`), amid an ongoing public dispute between the researcher and MSRC (the researcher's disclosure-reporting account was reportedly deleted, and bounty payment is disputed per the researcher's own public statements) — this context does not affect the technical validity of the PoC itself, which was independently verified by reading the actual source.

**Deliberately limited PoC:** The upstream author explicitly states the published version is "stripped down" relative to what was originally found: the public release requires a second standard user's credentials and is scoped to loading only `UsrClass.dat`, whereas the original (unpublished) capability reportedly required no additional credential and could load an arbitrary hive. This entry documents the real, verified, publicly demonstrated capability — not the researcher's unverified broader claim.

**Verification:** The file in this folder (`LegacyHive.cpp`) is byte-for-byte identical to the upstream repository (verified via checksum comparison against a fresh clone) — no paraphrasing or rewriting was performed. No malware/scam signals were found in the repository (no obfuscation, no external C2/callback endpoints, no payment/Telegram gating); the account has a multi-year track record of similar, previously-verified releases.
