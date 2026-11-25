# PHP2Shell — PHP Core Pre-Auth RCE via OOM longjmp and Stale Request State (CVE-2026-109618 / CVE-2026-109619)

<!--
  File: 2026-11-25_php2shell-php-core-preauth-rce.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-11-25 |
| **Last Updated** | 2026-10-24 |
| **Author / Researcher** | 9bie (PoC); PHP Security Team (advisory) |
| **CVE / Advisory** | CVE-2026-109618, CVE-2026-109619 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | 9.8 (CVE-2026-109618), 9.2 (CVE-2026-109619) |
| **Status** | Weaponized |
| **Tags** | RCE, unauthenticated, PHP, memory-corruption, longjmp, OOM, stale-state, Apache, mod_php, PHP-FPM, heap-grooming, ASLR-bypass |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | PHP (Apache `mod_php` and PHP-FPM SAPIs) |
| **Versions Affected** | PHP 7.3.0–8.2.35, 8.3.0–8.3.36, 8.4.0–8.4.27, 8.5.0–8.5.12 (NVD ranges) |
| **Language / Platform** | C; Linux x86_64 / aarch64; Apache prefork / PHP-FPM |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

PHP2Shell is a pair of PHP-core memory-corruption bugs that turn request parsing into unauthenticated remote code execution. When a request exhausts the PHP memory limit during multipart/upload parsing, PHP's longjmp-based OOM bailout can leave request memory uninitialized (CVE-2026-109618), and a related bug can leave global state pointing into freed request memory across requests on the same worker (CVE-2026-109619). The public PoC reaches RCE against the stock php:8.4.26-apache image with a 128M memory limit and display errors off, using only HTTP: it pins an Apache worker, leaks the heap and libphp bases through an oversized Set-Cookie OOB read, then forges a hash-table destructor that calls the zif system function.

---

## Vulnerability Details

### Root Cause

PHP allocates request memory from the Zend memory manager and frees it at request shutdown. On an out-of-memory condition during request parsing, PHP uses `longjmp()` to abort the current context. Some parsing contexts do not account for this bailout and leave parts of request memory uninitialized before the next allocation; the cleanup path can then read or branch on that memory. A second bug leaves global state temporarily pointing into request memory and can preserve those stale pointers after the memory is freed, so a later request handled by the same worker can observe stale state. Both bugs are in the request-parsing / shutdown path, before any application script runs.

### Attack Vector

An unauthenticated attacker sends crafted HTTP requests to any PHP endpoint — the PoC target page is only `<?php echo "OK\n"; ?>`. The chain uses chunked multipart bodies (no `Content-Length`) to bypass the `post_max_size` check, thousands of nested file fields and a `PHP_SESSION_UPLOAD_PROGRESS` part to force an OOM inside `php_url_encode()` during END cleanup, and a large `Set-Cookie` to read out of bounds and leak the chunk and `libphp` bases. A second OOM points the session state at a forged structure; a final request writes a fake `zend_array` whose `pDestructor` is `zif_system`, which is invoked during `zend_hash_destroy()`.

### Impact

Remote code execution as the PHP worker user (`www-data` in the reference lab). The PoC demonstrates command execution with `id` and supports arbitrary commands; a compromised web tier gives access to application secrets, databases, and any files readable by the web user.

---

## Environment / Lab Setup

```
OS:          Linux x86_64 (Docker)
Target:      php:8.4.26-apache (official image, official php.ini-production,
             128M memory_limit, display_errors=Off, Apache prefork
             MaxRequestWorkers=150)
Attacker:    Python 3.10+ (stdlib only), same host or LAN
Tools:       Docker, Python 3, curl
```

### Setup Steps

```bash
# From this entry's directory. Starts a disposable target on 127.0.0.1:18110.
./pure/run_pure.sh

# The exploit sends the four-request chain and writes the proof command output.
python3 exploit.py --port 18110

# Optional: restart the target for a fresh ASLR layout, or run an arbitrary command.
python3 exploit.py --port 18110 --restart p2s-pure-18110
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Start the stock target** — `./pure/run_pure.sh` starts `php:8.4.26-apache` with the official ini and prefork configuration; the target page is a one-line `<?php echo "OK\n"; ?>`.
2. **Pin one worker** — with `MaxRequestWorkers=150`, the exploit holds 149 children with incomplete POST bodies so the four chain requests are served by the same child.
3. **A1 / B1** — trigger the END-cleanup OOM, then leak the chunk base and `libphp` base through the oversized `Set-Cookie` OOB read (`zval_ptr_dtor` pointers in the leak window).
4. **A2 / B2** — trigger the cheap OOM, write the fake reference and fake `zend_array`, and let `zend_hash_destroy()` call `system()` during request shutdown.
5. **Verify** — the proof file contains `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

### Exploit Code

> See [`exploit.py`](./exploit.py) and the chain primitives in [pure/](https://github.com/9bie/php2shell-bypass-aslr-exp/tree/main/pure). The upstream English write-up is in [`upstream-readme-en.md`](./upstream-readme-en.md).

The chain shape is:

```text
A1  END-cleanup send_cookie OOM
B1  stale-id OOB read -> chunk base + libphp base
A2  cheap-OOM -> dangling PS(http_session_vars)
B2  fake reference + fake zend_array -> pDestructor = zif_system
```

### Expected Output

```text
[try 1] A1: END-cleanup send_cookie OOM
[try 1] B1: stale-id OOB read (chunk base + libphp)
      arch=x86_64 decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
[try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
[4/4] RCE OK; proof .../out/p1:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Detection & Indicators of Compromise

- PHP / Apache logs showing `Allowed memory size of ... exhausted` during multipart parsing, followed by worker restarts or 500/502 responses.
- Repeated chunked multipart requests larger than `post_max_size`, with very large header counts, nested file fields, or `PHP_SESSION_UPLOAD_PROGRESS` activity.
- `Set-Cookie` responses with unusually large encoded values, or anomalous `PHPSESSID` growth.
- Worker crashes / segmentation faults in the PHP process, especially clustered with OOM entries.
- The upstream response kit (`orbitron-ai/php2shell-response-kit`) provides Sigma, Splunk, QRadar, CrowdStrike, SentinelOne, Wazuh, YARA and ModSecurity content; treat it as detection guidance, not part of this PoC.

**SIEM / IDS rule (example):**

```text
alert http any any -> any any (msg:"PHP2Shell oversized multipart / OOM pattern"; \
  content:"PHP_SESSION_UPLOAD_PROGRESS"; http_client_body; \
  content:"Content-Type|3a| multipart/form-data"; http_header; sid:9002610;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or later) and restart every PHP worker; opcache/APCu alone does not replace the restart. |
| **Workaround** | The upstream advisory's mitigations reduce risk but do not fully fix: set `memory_limit = -1` with a cgroup/container memory limit, `post_max_size = 8M` (32M with uploads), `session.upload_progress.enabled = 0`, and `fatal_error_backtraces = 0` on PHP 8.5. |
| **Config Hardening** | Put a WAF/reverse proxy in front of PHP, cap request body size and header counts, isolate web workers, and monitor for OOM-driven worker restarts. |

---

## References

- [CVE-2026-109618 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
- [CVE-2026-109619 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- [PHP advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Arctic Wolf — PHP2Shell write-up](https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/)
- [Metasploit module PR #22139](https://github.com/rapid7/metasploit-framework/pull/22139)
- [9bie/php2shell-bypass-aslr-exp — source PoC](https://github.com/9bie/php2shell-bypass-aslr-exp)
- [dinosn/php-cve-2026-10961x-lab-poc — independent lab](https://github.com/dinosn/php-cve-2026-10961x-lab-poc)
- [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Notes

Auto-ingested from https://github.com/9bie/php2shell-bypass-aslr-exp on 2026-11-25. The upstream repository has no explicit license file; the exploit files are archived with attribution for authorized research only. The `pure/` directory contains the chain primitives required by `exploit.py`; the upstream `archive/legacy-8m` tree and `logs/` were not copied.

Review of candidates: `9bie/php2shell-bypass-aslr-exp` is the selected full RCE PoC. `dinosn/php-cve-2026-10961x-lab-poc` is an independent self-contained lab and was kept as an alternate. `jf0x3f/php2shell-pocs` is a lab wrapper around the 9bie PoC. `AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619` is a defensive fleet audit (explicitly does not exploit) and `orbitron-ai/php2shell-response-kit` is a detection/response kit; both were excluded as detectors.

The PoC was verified against the stock official image in the upstream lab (10/10 on the 150-worker configuration, 20/20 single-worker). It requires the target to be reachable and the Apache prefork worker count to be known or default; the chain is ASLR-dependent and re-leaks/retries on failure. Run only against systems you own or have written authorization to test.
