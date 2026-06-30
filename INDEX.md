# POC Archive — Index

> Last updated: 2026-06-30 22:06:06

---

## 2026

| Date Added | Last Updated | Name | Category | CVE | Severity | Tags | Status |
|---|---|---|---|---|---|---|---|
| 2026-05-14 | — | [linux-xfrm-fragnesia-lpe](./pocs/binary/2026-05-14_linux-xfrm-fragnesia-lpe/) | `binary` | CVE-2026-46300 | High | LPE, privilege-escalation, kernel, XFRM, ESP-in-TCP, page-cache, write-primitive, unprivileged | Weaponized |
| 2026-05-14 | — | [linux-xfrm-rxrpc-lpe](./pocs/binary/2026-05-14_linux-xfrm-rxrpc-lpe/) | `binary` | CVE-2026-43500, CVE-2026-43284 | Critical | LPE, Linux kernel, page-cache, xfrm, RxRPC, local, unauthenticated, Dirty Pipe variant | Weaponized |
| 2026-05-15 | — | [bluehammer-defender-lpe](./pocs/binary/2026-05-15_bluehammer-defender-lpe/) | `binary` | CVE-2026-33825 | High | LPE, Windows Defender, VSS, SAM-hive-leak, RPC, local-user | Weaponized |
| 2026-05-15 | — | [redsun-privileged-file-write](./pocs/binary/2026-05-15_redsun-privileged-file-write/) | `binary` | CVE-2026-33825 | High | LPE, privileged-file-write, Windows Defender, Cloud Files API, TOCTOU, file-reparse-point | Weaponized |
| 2026-05-16 | — | [adobe-acrobat-prototype-pollution-sandbox-escape](./pocs/binary/2026-05-16_adobe-acrobat-prototype-pollution-sandbox-escape/) | `binary` | CVE-2026-34621 | Critical | prototype-pollution, sandbox-escape, Adobe-Acrobat, Adobe-Reader, PDF, RCE, Windows, macOS, user-interaction | Weaponized |
| 2026-05-16 | — | [qemutiny-memory-corruption](./pocs/binary/2026-05-16_qemutiny-memory-corruption/) | `binary` | N/A | Critical | QEMU, CXL, memory-corruption, OOB-read, OOB-write, guest-to-host-escape, local, root-in-guest | Weaponized |
| 2026-05-17 | 2026-04-29 | [copy-fail-cve-2026-31431](./pocs/binary/2026-05-17_copy-fail-cve-2026-31431/) | `binary` | CVE-2026-31431 | High | LPE, Linux kernel, AF_ALG, authenc, splice, local, Python | Weaponized |
| 2026-05-18 | N/A | [dirtydecrypt](./pocs/binary/2026-05-18_dirtydecrypt/) | `binary` | N/A (reported as duplicate by kernel maintainers; patched on mainline) | High | LPE, Linux kernel, page-cache, rxgk, RxRPC, COW, write-primitive, unprivileged, Dirty-Pipe-variant, splice, MSG_SPLICE_PAGES | Weaponized |
| 2026-05-20 | 2026-05-19 | [pintheft-rds-double-free](./pocs/binary/2026-05-20_pintheft-rds-double-free/) | `binary` | N/A | High | LPE, double-free, use-after-free, Linux kernel, RDS, io_uring, page-cache-overwrite, x86_64, local | Weaponized |
| 2026-05-28 | N/A | [notepad-plus-plus-8-9-6-multi-cve](./pocs/binary/2026-05-28_notepad-plus-plus-8-9-6-multi-cve/) | `binary` | CVE-2026-48770, CVE-2026-48778, CVE-2026-48800 | High | Notepad++, Windows, OOB-read, DoS, command-injection, config.xml, shortcuts.xml, local | Patched |
| 2026-06-05 | N/A | [ssh-keysign-pwn](./pocs/binary/2026-06-05_ssh-keysign-pwn/) | `binary` | CVE-2026-46333 | High | LPE, Linux kernel, pidfd_getfd, ptrace, ssh-keysign, chage, fd-theft | Patched |
| 2026-06-10 | 2026-06-09 | [rogueplanet-defender-lpe](./pocs/binary/2026-06-10_rogueplanet-defender-lpe/) | `binary` | CVE-2026-50656 | High | LPE, Windows Defender, race-condition, TOCTOU, ISO-mount, VirtualDisk, Task-Scheduler, WER, EICAR, SYSTEM-shell, Windows-10, Windows-11, local | Weaponized |
| 2026-06-26 | 2026-06-18 | [cve-2026-50656-rogueplanet-checker](./pocs/binary/2026-06-26_cve-2026-50656-rogueplanet-checker/) | `binary` | CVE-2026-50656 | High | LPE, Windows Defender, TOCTOU, symlink, reparse-point, junction, CWE-59, checker, detection, non-destructive, MsMpEng | Researched |
| 2026-06-28 | 2026-05-12 | [cve-2026-45586-ctfmon-greenplasma-lpe](./pocs/binary/2026-06-28_cve-2026-45586-ctfmon-greenplasma-lpe/) | `binary` | CVE-2026-45586 | High | LPE, EoP, Windows, CTFMON, section-object, object-directory, link-following, zero-day, CTF-challenge, Windows-11, Windows-2022, Windows-2026, incomplete-poc | PoC |
| 2026-06-28 | 2026-06-28 | [dirtyclone-cve-2026-43503-lpe](./pocs/binary/2026-06-28_dirtyclone-cve-2026-43503-lpe/) | `binary` | CVE-2026-43503 | High | LPE, Linux kernel, netfilter, TEE, IPsec, XFRM, page-cache, file-backed memory, DirtyFrag, skb, privilege escalation, C, in-the-wild | Weaponized |
| 2026-06-30 | 2026-06-30 | [cve-2026-46331-linux-act-pedit-lpe](./pocs/binary/2026-06-30_cve-2026-46331-linux-act-pedit-lpe/) | `binary` | CVE-2026-46331 | High | LPE, Linux kernel, COW, page-cache, act_pedit, tc, netlink, traffic-control, privilege-escalation, userns, C, DirtyFrag | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-7574-claude-desktop-cowork-vm-bypass](./pocs/binary/2026-06-30_cve-2026-7574-claude-desktop-cowork-vm-bypass/) | `binary` | CVE-2026-7574 | High | LPE, persistence, VM-integrity, rootfs, Claude, AI-application, macOS, ext4, integrity-bypass, Shell | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-8461-ffmpeg-magicyuv-oob-rce](./pocs/binary/2026-06-30_cve-2026-8461-ffmpeg-magicyuv-oob-rce/) | `binary` | CVE-2026-8461 | High | RCE, OOB-write, heap-corruption, FFmpeg, MagicYUV, media, video, PixelSmash, libavcodec, Python, High | PoC |
| 2026-06-26 | 2026-05-31 | [yellowkey-bitlocker-bypass](./pocs/misc/2026-06-26_yellowkey-bitlocker-bypass/) | `misc` | CVE-2026-45585 | Medium | BitLocker, bypass, physical-access, WinRE, TPM, autofstx, NTFS-transactions, FsTx, Windows-11, Windows-Server-2022, zero-day, full-disk-access | Researched |
| 2026-05-18 | N/A | [tossup-terramaster-redis-rce](./pocs/network/2026-05-18_tossup-terramaster-redis-rce/) | `network` | N/A (vendor confirmed TOS4 is EOL; no fix planned) | Critical | RCE, unauthenticated, Redis, TerraMaster, NAS, AArch64, root, module-loading, replication-abuse, NFS, no_root_squash, LPE, network | Weaponized |
| 2026-06-04 | 2026-06-04 | [netlogon-cldap-stack-buffer-overflow](./pocs/network/2026-06-04_netlogon-cldap-stack-buffer-overflow/) | `network` | CVE-2026-41089 | Critical | Netlogon, CLDAP, Windows Server, stack-overflow, unauthenticated, DoS, potential-RCE | Weaponized |
| 2026-06-28 | 2026-06-09 | [cve-2026-10520-ivanti-sentry-rce](./pocs/network/2026-06-28_cve-2026-10520-ivanti-sentry-rce/) | `network` | CVE-2026-10520, CVE-2026-10523 | Critical | pre-auth, RCE, OS-command-injection, Ivanti, Sentry, MICS-API, auth-bypass, admin-creation, CISA-KEV | PoC |
| 2026-06-28 | 2026-06-14 | [cve-2026-20245-cisco-sdwan-priv-esc](./pocs/network/2026-06-28_cve-2026-20245-cisco-sdwan-priv-esc/) | `network` | CVE-2026-20245 | High | privilege-escalation, Cisco, SD-WAN, vManage, file-upload, command-injection, root, CISA-KEV, no-patch, Mandiant, nation-state | PoC |
| 2026-06-28 | 2026-06-05 | [cve-2026-34908-unifi-os-rce-chain](./pocs/network/2026-06-28_cve-2026-34908-unifi-os-rce-chain/) | `network` | CVE-2026-34908, CVE-2026-34909, CVE-2026-34910 | Critical | unauth-rce, nginx-bypass, path-traversal, command-injection, CISA-KEV, Mirai, Gaafgyt, chain, UniFi, Ubiquiti, network | PoC |
| 2026-06-28 | 2026-06-10 | [cve-2026-50751-checkpoint-ikev1-bypass](./pocs/network/2026-06-28_cve-2026-50751-checkpoint-ikev1-bypass/) | `network` | CVE-2026-50751 | Critical | auth-bypass, VPN, IKEv1, Check-Point, Remote-Access, certificate-bypass, Qilin, ransomware, CISA-KEV, unauthenticated | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-12485-geovision-dvrsearch-rce](./pocs/network/2026-06-30_cve-2026-12485-geovision-dvrsearch-rce/) | `network` | CVE-2026-12485 | Critical | RCE, unauthenticated, stack-overflow, buffer-overflow, IoT, GeoVision, DVR, embedded, UDP, network, Python, CVSS-10 | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-24061-gnu-telnetd-rce](./pocs/network/2026-06-30_cve-2026-24061-gnu-telnetd-rce/) | `network` | CVE-2026-24061 | Critical | RCE, unauthenticated, authentication-bypass, telnetd, GNU-Inetutils, NEW-ENVIRON, legacy, OT, CISA-KEV, active-exploitation, Python | Weaponized |
| 2026-06-30 | 2026-06-30 | [cve-2026-55200-libssh2-oob-rce](./pocs/network/2026-06-30_cve-2026-55200-libssh2-oob-rce/) | `network` | CVE-2026-55200 | Critical | RCE, OOB-write, heap-corruption, libssh2, SSH, integer-overflow, unauthenticated, C, network | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-8932-libcurl-mtls-auth-bypass](./pocs/network/2026-06-30_cve-2026-8932-libcurl-mtls-auth-bypass/) | `network` | CVE-2026-8932 | Low | authentication-bypass, mTLS, TLS, libcurl, connection-reuse, client-certificate, C, Low | PoC |
| 2026-05-14 | — | [nginx-rift-cve-2026-42945](./pocs/web/2026-05-14_nginx-rift-cve-2026-42945/) | `web` | CVE-2026-42945 | Critical | RCE, unauthenticated, nginx, heap-overflow, buffer-overflow, rewrite | Weaponized |
| 2026-05-15 | — | [exchange-health-checker-outbound-rule-blind-spot](./pocs/web/2026-05-15_exchange-health-checker-outbound-rule-blind-spot/) | `web` | CVE-2026-42897 | Medium | Exchange, HealthChecker, IIS, URL-Rewrite, outbound-rules, EOMT, CSP, detection-gap | Researched |
| 2026-05-16 | — | [chrome-cssfontfeaturevaluesmap-use-after-free](./pocs/web/2026-05-16_chrome-cssfontfeaturevaluesmap-use-after-free/) | `web` | CVE-2026-2441 | High | use-after-free, Chrome, Blink, CSSOM, renderer-rce, unauthenticated, drive-by | Weaponized |
| 2026-05-16 | — | [cpanel-whm-auth-bypass-crlf-session-injection](./pocs/web/2026-05-16_cpanel-whm-auth-bypass-crlf-session-injection/) | `web` | CVE-2026-41940 | Critical | auth-bypass, CRLF-injection, session-poisoning, cPanel, WHM, unauthenticated | Weaponized |
| 2026-05-17 | 2026-05-11 | [apache-httpd-mod-http2-double-free](./pocs/web/2026-05-17_apache-httpd-mod-http2-double-free/) | `web` | CVE-2026-23918 | Critical | RCE, pre-auth, unauthenticated, double-free, heap-corruption, Apache, httpd, mod_http2, HTTP/2, TLS | Weaponized |
| 2026-05-17 | — | [nextjs-beforeinteractive-script-xss](./pocs/web/2026-05-17_nextjs-beforeinteractive-script-xss/) | `web` | CVE-2026-44580 | Medium | XSS, next/script, beforeInteractive, Next.js, App-Router, unauthenticated | Weaponized |
| 2026-05-17 | — | [nextjs-cache-components-connection-exhaustion-dos](./pocs/web/2026-05-17_nextjs-cache-components-connection-exhaustion-dos/) | `web` | CVE-2026-44579 | High | DoS, connection-exhaustion, next-resume, Next.js, cache-components, unauthenticated | Weaponized |
| 2026-05-17 | — | [nextjs-csp-nonce-cache-poisoned-xss](./pocs/web/2026-05-17_nextjs-csp-nonce-cache-poisoned-xss/) | `web` | CVE-2026-44581 | Medium | XSS, cache-poisoning, CSP-nonce, Next.js, App-Router, unauthenticated | Weaponized |
| 2026-05-17 | 2026-05-08 | [nextjs-dynamic-route-injection-auth-bypass](./pocs/web/2026-05-17_nextjs-dynamic-route-injection-auth-bypass/) | `web` | CVE-2026-44574 | High | auth-bypass, dynamic-route, nxtP-injection, middleware-bypass, param-smuggling, Next.js, App-Router, unauthenticated | Weaponized |
| 2026-05-17 | 2026-05-08 | [nextjs-i18n-middleware-bypass](./pocs/web/2026-05-17_nextjs-i18n-middleware-bypass/) | `web` | CVE-2026-44573 | High | middleware-bypass, i18n, _next/data, Pages-Router, authorization-bypass, information-disclosure, Next.js, unauthenticated | Weaponized |
| 2026-05-17 | — | [nextjs-image-optimization-api-oom-dos-self-hosted](./pocs/web/2026-05-17_nextjs-image-optimization-api-oom-dos-self-hosted/) | `web` | CVE-2026-44577 | Medium | DoS, OOM, image-optimizer, Next.js, self-hosted, unauthenticated | Weaponized |
| 2026-05-17 | — | [nextjs-rsc-cache-busting-weak-hash-collision](./pocs/web/2026-05-17_nextjs-rsc-cache-busting-weak-hash-collision/) | `web` | CVE-2026-44582 | Low | cache-poisoning, RSC, weak-hash, Next.js, unauthenticated | Weaponized |
| 2026-05-17 | 2026-05-08 | [nextjs-rsc-dos-flight-deserialization](./pocs/web/2026-05-17_nextjs-rsc-dos-flight-deserialization/) | `web` | CVE-2026-23870 | High | DoS, RSC, React-Flight, deserialization, cyclic-payload, Next.js, App-Router, unauthenticated, pre-auth | Weaponized |
| 2026-05-17 | — | [nextjs-rsc-response-cache-poisoning](./pocs/web/2026-05-17_nextjs-rsc-response-cache-poisoning/) | `web` | CVE-2026-44576 | Medium | cache-poisoning, RSC, response-confusion, Next.js, shared-cache, unauthenticated | Weaponized |
| 2026-05-17 | 2026-05-09 | [nextjs-segment-prefetch-middleware-bypass](./pocs/web/2026-05-17_nextjs-segment-prefetch-middleware-bypass/) | `web` | CVE-2026-44575 | High | authorization-bypass, middleware-bypass, App-Router, segment-prefetch, RSC, Next.js, unauthenticated | Weaponized |
| 2026-05-17 | — | [nextjs-websocket-upgrade-ssrf-self-hosted](./pocs/web/2026-05-17_nextjs-websocket-upgrade-ssrf-self-hosted/) | `web` | CVE-2026-44578 | High | SSRF, WebSocket, upgrade-request, Next.js, self-hosted, unauthenticated, metadata-service | Weaponized |
| 2026-05-17 | 2026-05-08 | [nextjs-x-nextjs-data-cache-poisoning](./pocs/web/2026-05-17_nextjs-x-nextjs-data-cache-poisoning/) | `web` | CVE-2026-44572 | Low | cache-poisoning, x-nextjs-data, redirect, CDN, header-smuggling, Next.js, Pages-Router, unauthenticated | Researched |
| 2026-05-18 | 2026-04-02 | [chrome-webgpu-use-after-free](./pocs/web/2026-05-18_chrome-webgpu-use-after-free/) | `web` | CVE-2026-5281 | High | use-after-free, WebGPU, Chrome, Dawn, GPU, browser, unauthenticated | Weaponized |
| 2026-05-30 | 2026-05-21 | [drupal-core-postgresql-sql-injection](./pocs/web/2026-05-30_drupal-core-postgresql-sql-injection/) | `web` | CVE-2026-9082 / SA-CORE-2026-004 | Critical | SQLi, Drupal, PostgreSQL, JSON:API, unauthenticated, data-exfiltration | Patched |
| 2026-05-30 | 2026-04-30 | [litespeed-user-end-cpanel-plugin-privesc](./pocs/web/2026-05-30_litespeed-user-end-cpanel-plugin-privesc/) | `web` | CVE-2026-48172 | High | local-privilege-escalation, cPanel, LiteSpeed, symlink, archive-extraction | Patched |
| 2026-06-08 | 2026-06-08 | [firefox-focus-ios-uxss-redirect-scheme-race-condition](./pocs/web/2026-06-08_firefox-focus-ios-uxss-redirect-scheme-race-condition/) | `web` | N/A | Critical | UXSS, XSS, race-condition, TOCTOU, redirect-validation, javascript-scheme, iOS, Firefox Focus | Unpatched |
| 2026-06-28 | 2026-06-12 | [cve-2026-20253-splunk-preauth-rce](./pocs/web/2026-06-28_cve-2026-20253-splunk-preauth-rce/) | `web` | CVE-2026-20253 | Critical | pre-auth, RCE, PostgreSQL, Splunk, CISA-KEV, lo-export, sidecar, unauthenticated, file-write | PoC |
| 2026-06-30 | 2026-06-30 | [cve-2026-48908-sp-page-builder-joomla-rce](./pocs/web/2026-06-30_cve-2026-48908-sp-page-builder-joomla-rce/) | `web` | CVE-2026-48908 | Critical | RCE, unauthenticated, file-upload, PHP-webshell, Joomla, CMS, access-control, Python, CVSS-10 | PoC |

---

*Total POCs: 85*

## By Category

- **`binary`** — 27 entries
- **`cloud`** — 2 entries
- **`crypto`** — 0 entries
- **`hardware`** — 0 entries
- **`misc`** — 3 entries
- **`network`** — 20 entries
- **`social-engineering`** — 0 entries
- **`web`** — 34 entries

## Archives

- [2025](./archive/2025.md) — 17 entries
- [2024](./archive/2024.md) — 12 entries
- [2023](./archive/2023.md) — 2 entries
- [2021](./archive/2021.md) — 1 entries
- [2020](./archive/2020.md) — 1 entries

