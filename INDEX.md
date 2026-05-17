# POC Archive — Index

> Last updated: 2026-05-17 14:17:55

---

## 2026

| Date | Name | Category | CVE | Severity | Tags | Status |
|---|---|---|---|---|---|---|
| 2026-05-14 | [linux-xfrm-fragnesia-lpe](./pocs/binary/2026-05-14_linux-xfrm-fragnesia-lpe/) | `binary` | CVE-2026-46300 | High | LPE, privilege-escalation, kernel, XFRM, ESP-in-TCP, page-cache, write-primitive, unprivileged | Weaponized |
| 2026-05-14 | [linux-xfrm-rxrpc-lpe](./pocs/binary/2026-05-14_linux-xfrm-rxrpc-lpe/) | `binary` | CVE-2026-43500, CVE-2026-43284 | Critical | LPE, Linux kernel, page-cache, xfrm, RxRPC, local, unauthenticated, Dirty Pipe variant | Weaponized |
| 2026-05-15 | [bluehammer-defender-lpe](./pocs/binary/2026-05-15_bluehammer-defender-lpe/) | `binary` | CVE-2026-33825 | High | LPE, Windows Defender, VSS, SAM-hive-leak, RPC, local-user | Weaponized |
| 2026-05-15 | [cve-2024-21338-admin-to-kernel](./pocs/binary/2026-05-15_cve-2024-21338-admin-to-kernel/) | `binary` | CVE-2024-21338 | High | LPE, Windows, AppLocker, token-impersonation, HVCI, admin-to-kernel, local-user | Weaponized |
| 2026-05-15 | [miniplasma-cve-2020-17103](./pocs/binary/2026-05-15_miniplasma-cve-2020-17103/) | `binary` | CVE-2020-17103 | High | LPE, Windows, cldflt.sys, Cloud Files API, registry-symlink, race-condition, WER-hijack, SYSTEM-shell, local-user | Weaponized |
| 2026-05-15 | [redsun-privileged-file-write](./pocs/binary/2026-05-15_redsun-privileged-file-write/) | `binary` | CVE-2026-33825 | High | LPE, privileged-file-write, Windows Defender, Cloud Files API, TOCTOU, file-reparse-point | Weaponized |
| 2026-05-16 | [adobe-acrobat-prototype-pollution-sandbox-escape](./pocs/binary/2026-05-16_adobe-acrobat-prototype-pollution-sandbox-escape/) | `binary` | CVE-2026-34621 | Critical | prototype-pollution, sandbox-escape, Adobe-Acrobat, Adobe-Reader, PDF, RCE, Windows, macOS, user-interaction | Weaponized |
| 2026-05-16 | [cve-2025-21298-outlook-rtf-rce](./pocs/binary/2026-05-16_cve-2025-21298-outlook-rtf-rce/) | `binary` | CVE-2025-21298 | Critical | RCE, zero-click, Outlook, RTF, OLE, ole32, Windows, memory-corruption, unauthenticated | Researched |
| 2026-05-16 | [qemutiny-memory-corruption](./pocs/binary/2026-05-16_qemutiny-memory-corruption/) | `binary` | N/A | Critical | QEMU, CXL, memory-corruption, OOB-read, OOB-write, guest-to-host-escape, local, root-in-guest | Weaponized |
| 2026-05-15 | [winrar-path-traversal-cve-2025-6218](./pocs/misc/2026-05-15_winrar-path-traversal-cve-2025-6218/) | `misc` | CVE-2025-6218 | High | path-traversal, arbitrary-file-write, startup-folder, WinRAR, Windows, user-interaction | Weaponized |
| 2026-05-16 | [apache-parquet-unsafe-deserialization-rce](./pocs/misc/2026-05-16_apache-parquet-unsafe-deserialization-rce/) | `misc` | CVE-2025-30065 | Critical | RCE, unsafe-deserialization, parquet-avro, avro-schema, Java, JVM, SSRF, data-pipeline | Weaponized |
| 2026-05-15 | [blueducky-cve-2023-45866](./pocs/network/2026-05-15_blueducky-cve-2023-45866/) | `network` | CVE-2023-45866 | High | Bluetooth, HID, keystroke-injection, unauthenticated, Android, Linux | Weaponized |
| 2026-05-15 | [cve-2021-31166-http-sys-uaf](./pocs/network/2026-05-15_cve-2021-31166-http-sys-uaf/) | `network` | CVE-2021-31166 | Critical | HTTP.sys, use-after-free, RCE, Windows, kernel, unauthenticated | Weaponized |
| 2026-05-15 | [ldap-nightmare-cve-2024-49113](./pocs/network/2026-05-15_ldap-nightmare-cve-2024-49113/) | `network` | CVE-2024-49113 | Critical | LDAP, NRPC, Windows Server, unauthenticated, DoS, potential-RCE | Weaponized |
| 2026-05-16 | [openssh-regresshion-signal-handler-race](./pocs/network/2026-05-16_openssh-regresshion-signal-handler-race/) | `network` | CVE-2024-6387 | High | RCE, OpenSSH, sshd, glibc, race-condition, SIGALRM, unauthenticated | Weaponized |
| 2026-05-16 | [vmware-esxi-ad-auth-bypass](./pocs/network/2026-05-16_vmware-esxi-ad-auth-bypass/) | `network` | CVE-2024-37085 | Medium | auth-bypass, Active Directory, ESXi, vCenter, ransomware, unauthenticated-esxi | Weaponized |
| 2026-05-16 | [vmware-vcenter-dcerpc-heap-overflow-rce](./pocs/network/2026-05-16_vmware-vcenter-dcerpc-heap-overflow-rce/) | `network` | CVE-2024-37079 | Critical | RCE, heap-overflow, DCE/RPC, vCenter, unauthenticated, KEV | Weaponized |
| 2026-05-17 | [fortimanager-fortijump-rce-cve-2024-47575](./pocs/network/2026-05-17_fortimanager-fortijump-rce-cve-2024-47575/) | `network` | CVE-2024-47575 | Critical | RCE, unauthenticated, FortiManager, fgfmd, zero-day, KEV | Weaponized |
| 2026-05-14 | [nginx-rift-cve-2026-42945](./pocs/web/2026-05-14_nginx-rift-cve-2026-42945/) | `web` | CVE-2026-42945 | Critical | RCE, unauthenticated, nginx, heap-overflow, buffer-overflow, rewrite | Weaponized |
| 2026-05-15 | [exchange-health-checker-outbound-rule-blind-spot](./pocs/web/2026-05-15_exchange-health-checker-outbound-rule-blind-spot/) | `web` | CVE-2026-42897 | Medium | Exchange, HealthChecker, IIS, URL-Rewrite, outbound-rules, EOMT, CSP, detection-gap | Researched |
| 2026-05-15 | [nextjs-middleware-bypass-cve-2025-29927](./pocs/web/2026-05-15_nextjs-middleware-bypass-cve-2025-29927/) | `web` | CVE-2025-29927 | Critical | auth-bypass, middleware-bypass, Next.js, unauthenticated, header-injection | Weaponized |
| 2026-05-16 | [chrome-cssfontfeaturevaluesmap-use-after-free](./pocs/web/2026-05-16_chrome-cssfontfeaturevaluesmap-use-after-free/) | `web` | CVE-2026-2441 | High | use-after-free, Chrome, Blink, CSSOM, renderer-rce, unauthenticated, drive-by | Weaponized |
| 2026-05-16 | [citrixbleed-2-session-token-disclosure](./pocs/web/2026-05-16_citrixbleed-2-session-token-disclosure/) | `web` | CVE-2025-5777 | Critical | citrixbleed2, memory-disclosure, session-hijack, NetScaler, Gateway, unauthenticated | Weaponized |
| 2026-05-16 | [cpanel-whm-auth-bypass-crlf-session-injection](./pocs/web/2026-05-16_cpanel-whm-auth-bypass-crlf-session-injection/) | `web` | CVE-2026-41940 | Critical | auth-bypass, CRLF-injection, session-poisoning, cPanel, WHM, unauthenticated | Weaponized |
| 2026-05-16 | [fortios-fortiproxy-auth-bypass-cve-2024-55591](./pocs/web/2026-05-16_fortios-fortiproxy-auth-bypass-cve-2024-55591/) | `web` | CVE-2024-55591 | Critical | auth-bypass, websocket, race-condition, FortiOS, FortiProxy, unauthenticated, super-admin | Weaponized |
| 2026-05-16 | [fortios-sslvpn-rce-cve-2024-21762](./pocs/web/2026-05-16_fortios-sslvpn-rce-cve-2024-21762/) | `web` | CVE-2024-21762 | Critical | RCE, out-of-bounds-write, SSL-VPN, FortiOS, edge-appliance, unauthenticated, KEV | Weaponized |
| 2026-05-16 | [pan-os-management-auth-bypass](./pocs/web/2026-05-16_pan-os-management-auth-bypass/) | `web` | CVE-2025-0108 | Critical | auth-bypass, path-traversal, PAN-OS, Palo Alto, management-interface, unauthenticated | Weaponized |
| 2026-05-17 | [jenkins-cli-arbitrary-file-read-rce](./pocs/web/2026-05-17_jenkins-cli-arbitrary-file-read-rce/) | `web` | CVE-2024-23897 | Critical | arbitrary-file-read, Jenkins, CLI, credential-theft, RCE, unauthenticated, KEV | Weaponized |
| 2026-05-17 | [nextjs-beforeinteractive-script-xss](./pocs/web/2026-05-17_nextjs-beforeinteractive-script-xss/) | `web` | CVE-2026-44580 | Medium | XSS, next/script, beforeInteractive, Next.js, App-Router, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-cache-components-connection-exhaustion-dos](./pocs/web/2026-05-17_nextjs-cache-components-connection-exhaustion-dos/) | `web` | CVE-2026-44579 | High | DoS, connection-exhaustion, next-resume, Next.js, cache-components, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-csp-nonce-cache-poisoned-xss](./pocs/web/2026-05-17_nextjs-csp-nonce-cache-poisoned-xss/) | `web` | CVE-2026-44581 | Medium | XSS, cache-poisoning, CSP-nonce, Next.js, App-Router, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-image-optimization-api-oom-dos-self-hosted](./pocs/web/2026-05-17_nextjs-image-optimization-api-oom-dos-self-hosted/) | `web` | CVE-2026-44577 | Medium | DoS, OOM, image-optimizer, Next.js, self-hosted, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-rsc-cache-busting-weak-hash-collision](./pocs/web/2026-05-17_nextjs-rsc-cache-busting-weak-hash-collision/) | `web` | CVE-2026-44582 | Low | cache-poisoning, RSC, weak-hash, Next.js, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-rsc-response-cache-poisoning](./pocs/web/2026-05-17_nextjs-rsc-response-cache-poisoning/) | `web` | CVE-2026-44576 | Medium | cache-poisoning, RSC, response-confusion, Next.js, shared-cache, unauthenticated | Weaponized |
| 2026-05-17 | [nextjs-websocket-upgrade-ssrf-self-hosted](./pocs/web/2026-05-17_nextjs-websocket-upgrade-ssrf-self-hosted/) | `web` | CVE-2026-44578 | High | SSRF, WebSocket, upgrade-request, Next.js, self-hosted, unauthenticated, metadata-service | Weaponized |
| 2026-05-17 | [pan-os-globalprotect-unauth-rce](./pocs/web/2026-05-17_pan-os-globalprotect-unauth-rce/) | `web` | CVE-2024-3400 | Critical | RCE, command-injection, path-traversal, PAN-OS, GlobalProtect, unauthenticated, zero-day | Weaponized |

---

*Total POCs: 36*

## By Category

- **`binary`** — 9 entries
- **`cloud`** — 0 entries
- **`crypto`** — 0 entries
- **`hardware`** — 0 entries
- **`misc`** — 2 entries
- **`network`** — 7 entries
- **`social-engineering`** — 0 entries
- **`web`** — 18 entries

## Archives

- [2025](./archive/2025.md) — 0 entries
- [2024](./archive/2024.md) — 0 entries
- [2023](./archive/2023.md) — 0 entries
- [2021](./archive/2021.md) — 0 entries
- [2020](./archive/2020.md) — 0 entries

