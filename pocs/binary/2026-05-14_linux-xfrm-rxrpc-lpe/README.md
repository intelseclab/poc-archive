# Dirty Frag: Linux XFRM/RxRPC Page Cache Write Chain LPE

<!-- 
  File: 2026-05-14_linux-xfrm-rxrpc-lpe.md
  Location: pocs/binary/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-14 |
| **Author / Researcher** | Hyunwoo Kim (@v4bel) |
| **CVE / Advisory** | CVE-2026-43500, CVE-2026-43284 |
| **Category** | binary |
| **Severity** | Critical |
| **CVSS Score** | 7.8 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | LPE, Linux kernel, page-cache, xfrm, RxRPC, local, unauthenticated, Dirty Pipe variant |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Linux kernel |
| **Versions Affected** | CVE-2026-43284: cac2661c53f3 (2017-01-17) – f4c50a4034e6 (2026-05-05); CVE-2026-43500: 2dc334f1a63a (2023-06-08) – aa54b1d27fe0 (2026-05-10) |
| **Language / Platform** | C, Linux x86_64 |
| **Authentication Required** | No |
| **Network Access Required** | No (local only) |

---

## Summary

Dirty Frag is a universal Linux Local Privilege Escalation (LPE) vulnerability class discovered by Hyunwoo Kim (@v4bel) that chains two Page Cache Write primitives: the xfrm-ESP Page-Cache Write (CVE-2026-43284) and the RxRPC Page-Cache Write (CVE-2026-43500). By exploiting these bugs, an unprivileged local user can overwrite arbitrary read-only pages in the kernel page cache — including SUID binaries such as `/usr/bin/su` — and obtain root privileges on all major Linux distributions. The exploit is deterministic, requires no race condition, and has a very high success rate.

---

## Vulnerability Details

### Root Cause

Both vulnerabilities are instances of the Dirty Pipe / Copy Fail bug class, which allow data to be written into arbitrary page-cache pages via the `splice()` / `sendmsg()` kernel path without the write permission check being enforced. Specifically:

- **CVE-2026-43284** (xfrm-ESP Page-Cache Write): The `xfrm` ESP-over-UDP code path incorrectly sets the `PIPE_BUF_FLAG_CAN_MERGE` flag on pipe buffers that point to a victim page-cache page. A subsequent `write()` to the pipe merges attacker data directly into that read-only page.
- **CVE-2026-43500** (RxRPC Page-Cache Write): The `rxrpc` kernel AFS transport similarly leaves `PIPE_BUF_FLAG_CAN_MERGE` set on a victim page-cache reference, allowing the same write-merge primitive without requiring the privilege to create a network namespace.

### Attack Vector

1. The attacker opens a target SUID binary (e.g., `/usr/bin/su`) for reading to pull its pages into the page cache.
2. The attacker creates a pipe and splices the target page into it (establishing the pipe buffer / page-cache mapping).
3. Using either the xfrm-ESP or RxRPC socket sendmsg path, the attacker triggers the flag corruption to enable merging on that page-cache buffer.
4. The attacker writes a minimal root-shell ELF payload into the pipe; the kernel merges this data directly into the read-only page-cache page for `/usr/bin/su`.
5. The attacker executes the (now-replaced) SUID binary, which runs the embedded shell ELF as root.

On Ubuntu (where unprivileged user namespace creation is blocked by AppArmor), the exploit falls back to the RxRPC path (rxrpc.ko is loaded by default). On other distributions where rxrpc.ko is absent, the xfrm path is used. The two variants cover each other's blind spots.

### Impact

Full Local Privilege Escalation to root (`uid=0`) on all major Linux distributions, including Ubuntu 24.04, RHEL 10, Fedora 44, openSUSE Tumbleweed, AlmaLinux 10, and CentOS Stream 10. Scope of impact spans roughly 9 years of kernel versions.

---

## Environment / Lab Setup

```
OS:          Ubuntu 24.04 LTS (kernel 6.17.0-23-generic) or equivalent major distro
Target:      /usr/bin/su (any setuid binary in page cache)
Attacker:    Local unprivileged user shell
Tools:       gcc, standard libc (no external dependencies)
```

### Setup Steps

```bash
# Clone the exploit repository
git clone --depth=1 https://github.com/V4bel/dirtyfrag.git /tmp/dirtyfrag
cd /tmp/dirtyfrag

# Compile the exploit
gcc -O0 -Wall -o exp exp.c -lutil

# Run (as unprivileged user)
./exp
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Compile** — Build `exp.c` with gcc (no special flags required).
   ```bash
   gcc -O0 -Wall -o exp exp.c -lutil
   ```

2. **Execute** — Run the binary as an unprivileged local user.
   ```bash
   ./exp
   ```

3. **Cleanup** — Drop the polluted page cache to restore system stability.
   ```bash
   echo 3 > /proc/sys/vm/drop_caches
   # or reboot
   ```

### Exploit Code

> See `exp.c` in this folder.

```c
/* Minimal conceptual flow (see exp.c for full implementation):
 *
 * 1. Open target SUID binary and splice its first page into a pipe.
 * 2. Trigger xfrm-ESP or RxRPC sendmsg to set PIPE_BUF_FLAG_CAN_MERGE.
 * 3. Write root-shell ELF payload into the pipe (merges into page cache).
 * 4. Execute the contaminated SUID binary → root shell.
 */
```

### Expected Output

```
[*] Trying xfrm-ESP path (CVE-2026-43284) ...
[+] Page cache write successful
[+] Spawning root shell via /usr/bin/su
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Screenshots / Evidence

<!-- Add screenshots once available -->
- `screenshots/` — Reserved for demo evidence

---

## Detection & Indicators of Compromise

```
# Kernel audit log entries indicating splice + pipe write to read-only page:
audit: type=SYSCALL ... syscall=splice ...
audit: type=SYSCALL ... syscall=sendmsg ... comm="exp"

# Unexpected modification timestamp on SUID binaries (before patch):
stat /usr/bin/su   # mtime unchanged but page-cache contents differ

# Suspicious process spawning root shell from non-root UID:
audit: type=EXECVE ... a0="/usr/bin/su" ... uid=1000 euid=0
```

**SIEM / IDS Rule (example):**
```
alert process any -> any (msg:"Possible DirtyFrag LPE: unprivileged splice to SUID binary page cache"; process.name:"exp"; user.id != "0"; process.parent.euid:"0"; sid:9000010;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Apply kernel commits f4c50a4034e6 (CVE-2026-43284) and aa54b1d27fe0 (CVE-2026-43500); update to a patched distribution kernel |
| **Workaround** | Blacklist and unload vulnerable modules: `printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf && rmmod esp4 esp6 rxrpc 2>/dev/null && echo 3 > /proc/sys/vm/drop_caches` |
| **Config Hardening** | Where applicable, restrict unprivileged user namespace creation (e.g., `kernel.unprivileged_userns_clone=0`) to limit the xfrm path; note this does not block the RxRPC path on Ubuntu |

---

## References

- [CVE-2026-43500 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-43500)
- [CVE-2026-43284 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- [Source Repository — V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
- [Kernel patch: CVE-2026-43284 (f4c50a4034e6)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)
- [Kernel patch: CVE-2026-43500 (aa54b1d27fe0)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71)
- [Dirty Pipe (CVE-2022-0847)](https://dirtypipe.cm4all.com/)
- [Copy Fail vulnerability](https://copy.fail/)

---

## Notes

Auto-ingested from https://github.com/V4bel/dirtyfrag on 2026-05-14.

Dirty Frag chains two distinct Page Cache Write primitives to cover each other's blind spots across distributions:
- xfrm-ESP path (CVE-2026-43284) requires unprivileged namespace creation; blocked on Ubuntu by default AppArmor policy.
- RxRPC path (CVE-2026-43500) does not require namespace privileges; rxrpc.ko is loaded by default on Ubuntu.

The exploit contaminates the page cache for `/usr/bin/su`; run `echo 3 > /proc/sys/vm/drop_caches` or reboot after testing to restore a clean state.

Human review is required before treating this entry as authoritative — verify metadata, affected version ranges, and CVSS score against official advisories once published.
