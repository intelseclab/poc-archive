# Lunar Client Modrinth Explore Raw-HTML to Local Launcher Execution Chain

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | binary |
| **Severity** | Critical |
| **CVSS Score** | Not yet scored (source estimates tentative CVSS v3.1 9.6, no CVE/CVSS formally assigned) |
| **Status** | Incomplete PoC |
| **Tags** | lunar-client, electron, minecraft, modrinth, raw-html-injection, ipc, rce, sandbox-escape, launcher-abuse |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Lunar Client (Electron desktop application), Modrinth Explore integration |
| **Versions Affected** | Lunar Client build reviewed via extracted source maps, June 2026 |
| **Language / Platform** | JavaScript/Node.js (calc-pop demonstration), Electron/TypeScript renderer+main process chain |
| **Authentication Required** | No (victim only needs to view/click an attacker-controlled Modrinth project in Lunar Explore) |
| **Network Access Required** | Yes (attacker-controlled content must be fetched from Modrinth by the victim's Lunar Client) |

---

## Summary

The chain begins with Lunar Client's Explore feature rendering attacker-controlled Modrinth project Markdown (project body and version changelog) through `ReactMarkdown` with the `rehypeRaw` plugin and no observed HTML sanitizer, allowing raw HTML/script-capable content to execute inside the privileged Explore renderer. That renderer has access to exposed preload APIs and an unrestricted Redux state-sync IPC bridge into the Electron main process, which the researcher shows can be abused to forge or install a malicious Modrinth "profile" whose `overrides.gameDirectory` points at an attacker-chosen writable directory. When main installs that forged profile, it extracts root-level `overrides/*` entries from the `.mrpack` into the chosen directory — a path that the existing unverified-modpack-file warning scanner does not cover, since it only inspects `mods/`, `resourcepacks/`, and `shaderpacks/`. The renderer then calls an external-link API with a `file://` URL pointing at the dropped launcher file using a non-restricted initiator, and main's `openExternalLink` handler reaches `shell.openExternal()`, causing the OS to execute the dropped local launcher (e.g., a `.lnk` on Windows) and achieve code execution as the desktop user. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed, and the researcher explicitly states this is a "high-confidence critical candidate, not yet a fully packaged public Modrinth-to-Lunar end-to-end exploit."

---

## Vulnerability Details

### Root Cause

Multiple individually weak controls compound into a full chain: unsanitized raw-HTML rendering of untrusted Modrinth Markdown in the Explore renderer (`markdown.tsx` using `ReactMarkdown` + `rehypeRaw`), an unrestricted Redux/IPC state-sync bridge granting the renderer influence over main-process profile state, an unauthenticated profile installer that trusts a renderer-forged `overrides.gameDirectory`, a modpack-extraction routine that writes root-level `overrides/*` archive entries without restriction, an unverified-file warning scanner that only covers three specific subdirectories, and an `openExternalLink` handler that permits `file://` URLs to reach `shell.openExternal()` for non-restricted call sites.

### Attack Vector

1. Attacker publishes a Modrinth project whose description/changelog contains raw HTML capable of executing script inside Lunar Client's Explore renderer via `rehypeRaw`.
2. Victim views the malicious project in Lunar Explore, and the embedded HTML executes renderer JavaScript.
3. Renderer JavaScript uses exposed preload APIs and the Redux state-sync IPC bridge to forge/install a Modrinth provider profile with an attacker-chosen `overrides.gameDirectory`.
4. Main process downloads the `.mrpack` and extracts root-level `overrides/*` entries (including a launcher file) into the attacker-chosen directory, bypassing the unverified-file warning scanner which only checks `mods/`, `resourcepacks/`, and `shaderpacks/`.
5. Renderer calls the external-link API with a `file:///.../<launcher>` URL from a non-restricted initiator.
6. Main's `openExternalLink` handler reaches `shell.openExternal(url)`, and the OS dispatches the dropped local launcher file, executing attacker code as the desktop user — without needing Minecraft to be launched or a JRE/account to be configured.

### Impact

Arbitrary code execution as the victim's desktop user triggered by viewing or clicking a malicious Modrinth project inside Lunar Client, if the live Modrinth-delivery leg is confirmed end-to-end through production infrastructure.

---

## Environment / Lab Setup

```
Target:   Lunar Client Electron application (Windows/macOS/Linux), Modrinth Explore integration
Attacker: Node.js (for the included calc-pop primitive demonstration only)
```

---

## Proof of Concept

### PoC Script

> See `calc-pop.js` and `renderer-chain-skeleton.md` in this folder.

```bash
npm run poc
```

`calc-pop.js` validates only the final "drop a local launcher file and have the OS shell open it" execution primitive in isolation, on a local test machine — it does not contact Modrinth or Lunar Client. It writes a marker file, creates a platform-appropriate launcher (`.lnk` on Windows, `.command` on macOS, `.desktop` on Linux), asks the OS shell to open it, and pops a local Calculator app to prove that shell-dispatched local launcher files execute code. `renderer-chain-skeleton.md` is a non-executable outline of the renderer-side chain (raw HTML → IPC/Redux forgery → profile install) and is not a weaponized payload.

---

## Detection & Indicators of Compromise

```
# Lunar Client (or other Electron apps) writing unexpected .lnk/.command/.desktop files to modpack/override directories
# shell.openExternal invocations targeting file:// URLs sourced from renderer/IPC state rather than direct user file dialogs
```

**Signs of compromise:**
- Unexpected launcher/shortcut files appearing in Lunar Client profile or override directories after browsing Modrinth content
- Modrinth projects containing raw HTML/script payloads in their description or changelog fields
- Endpoint telemetry showing Lunar Client's main process invoking `shell.openExternal` on local file paths shortly after Explore page interaction

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory |
| **Interim mitigation** | Sanitize or disable raw HTML rendering in Modrinth Markdown, restrict the IPC/Redux bridge to an explicit action allowlist, validate profile objects at every IPC boundary, extend the unverified-file scanner to cover root-level overrides, and block non-HTTP protocols (`file:`, `ms-*`) in `openExternalLink` |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/lunar-modrinth-chain-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `lunar-modrinth-chain-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The source explicitly describes this as research status "high-confidence critical candidate, not yet a fully packaged public Modrinth-to-Lunar end-to-end exploit" and states the repository intentionally omits a live malicious Modrinth project, a weaponized renderer payload, and a malicious `.mrpack` — only the final local-execution primitive is demonstrated end-to-end.
