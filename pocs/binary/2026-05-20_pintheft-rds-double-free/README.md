# PinTheft: RDS Double-Free → LPE

<!-- 
  File: 2026-05-20_pintheft-rds-double-free.md
  Location: pocs/binary/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-20 |
| **Last Updated** | 2026-05-19 |
| **Author / Researcher** | Aaron Esau (stong) — V12 Security Team |
| **CVE / Advisory** | N/A |
| **Category** | binary |
| **Severity** | High |
| **CVSS Score** | N/A |
| **Status** | Weaponized |
| **Tags** | LPE, double-free, use-after-free, Linux kernel, RDS, io_uring, page-cache-overwrite, x86_64, local |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Linux kernel (RDS subsystem + io_uring) |
| **Versions Affected** | Kernels with CONFIG_RDS, CONFIG_RDS_TCP, and CONFIG_IO_URING enabled |
| **Language / Platform** | C, Linux x86_64 |
| **Authentication Required** | No |
| **Network Access Required** | No (local only) |

---

## Summary

PinTheft is a Linux local privilege escalation exploit targeting a double-free in the RDS zerocopy send path (`rds_message_zcopy_from_user()`). When a multi-page zerocopy send faults on a later page, the error path drops already-pinned pages, but RDS message cleanup later drops them again because the scatterlist state is not cleared. The exploit abuses `io_uring` fixed buffers to accumulate `FOLL_PIN` references, drains them via repeated failing RDS sends, frees the target page, reclaims it as page cache for a SUID-root binary, then uses the dangling `io_uring` fixed-buffer page pointer to overwrite that page cache with a root-shell ELF payload. Confirmed default exposure is limited to distributions shipping the RDS module (notably Arch Linux).

---

## Vulnerability Details

### Root Cause

`rds_message_zcopy_from_user()` pins user pages one at a time via GUP (`FOLL_GET`). If a later page faults, the error path calls `put_page()` on already-pinned pages. However, `rds_message_purge()` is later called and drops those pages a second time because `op_mmp_znotifier` was NULLed while `op_nents` and the scatterlist entries were left intact. When the page still has other live references, the second `__free_page` silently decrements the refcount — a double-drop that amounts to a reference count underflow on the stolen page.

### Attack Vector

A local, unprivileged user without any special capabilities:

1. Registers an anonymous page as an `io_uring` fixed buffer (adds `GUP_PIN_COUNTING_BIAS` = 1024 pin references).
2. Clones the fixed buffer into a second `io_uring` ring and holds it open via a daemon child to prevent premature unpin.
3. Performs 1024 failing two-page RDS TCP zerocopy sends where the second page is mapped `PROT_NONE`. Each send steals one `FOLL_PIN` reference from the first page via the double-drop.
4. After all 1024 pin references are stolen, the page refcount drops to ~1 (PTE mapping only). `munmap` then frees the page cleanly through the normal `__folio_put` path (clearing `memcg_data`, no `bad_page` check).
5. A `pread` on the SUID binary causes page cache to reallocate the just-freed frame. The stale `io_uring` bvec `struct page *` now points at live page cache.
6. `IORING_OP_READ_FIXED` writes the embedded shell ELF payload into the dangling fixed buffer, which lands in the SUID binary's page cache.
7. Executing the SUID binary runs the payload and drops a root shell.

### Impact

Full local privilege escalation to root (`uid=0`). The exploit modifies the in-memory page cache of a chosen SUID-root binary without requiring any capabilities.

---

## Environment / Lab Setup

```
OS:       Arch Linux (default RDS module present) or any Linux with CONFIG_RDS+CONFIG_RDS_TCP+CONFIG_IO_URING
Kernel:   Any version with io_uring_disabled=0 and autoload allowed for rds_tcp
Attacker: Local unprivileged user shell
Tools:    gcc (to compile poc.c)
```

### Requirements

- `CONFIG_RDS` and `CONFIG_RDS_TCP` kernel options enabled
- `CONFIG_IO_URING` with `io_uring_disabled=0`
- At least one readable SUID-root binary (`/usr/bin/su`, `/usr/bin/mount`, `/usr/bin/passwd`, `/usr/bin/pkexec`, etc.)
- x86_64 architecture (embedded payload is x86_64; technique is arch-independent)

### Setup Steps

```bash
# Compile on the target (no cross-compile needed)
gcc -o exp poc.c
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Compile** — Build the exploit on the target machine.
   ```bash
   gcc -o exp poc.c
   ```

2. **Run** — Execute as an unprivileged user.
   ```bash
   ./exp
   ```

3. **Root shell** — The exploit selects a SUID binary, backs it up, overwrites its page cache, and executes it to obtain a root shell.

### Exploit Code

> See `poc.c` in this folder.

```c
// Chain: register(+1024) -> clone(refs=2) -> daemon holds clone ->
// steal 1024 refs -> evict target page cache -> drain PCP ->
// munmap(free) -> pread target(reclaim) -> READ_FIXED(overwrite) ->
// verify -> exec -> root
```

### Expected Output

```
[*] Targeting /usr/bin/su (backup: /tmp/.backup_su_<pid>)
[*] Restore command: sudo cp /tmp/.backup_su_<pid> /usr/bin/su && sudo chmod u+s /usr/bin/su
[*] Registering fixed buffer and cloning to daemon ring...
[*] Stealing 1024 FOLL_PIN references via failing RDS zcopy sends...
[*] Freeing page and reclaiming as page cache...
[*] Writing payload via READ_FIXED...
[*] Payload verified in page cache. Executing target...
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Screenshots / Evidence

<!-- Add paths to screenshots or embed them -->
- `screenshots/` — (see source repo for demo video)

---

## Detection & Indicators of Compromise

```
# Suspicious patterns to watch for:
# 1. Unexpected RDS socket creation by unprivileged processes
# 2. io_uring REGISTER_BUFFERS + REGISTER_CLONE_BUFFERS in rapid succession by non-root
# 3. Rapid repeated sendmsg(SOCK_RDS) failures from the same process
# 4. A SUID binary's page cache modified without a corresponding write to disk
```

**Kernel audit / eBPF rule (example):**
```
# Watch for rds socket + io_uring combination from unprivileged users
# Audit: -a always,exit -F arch=b64 -S socket -F a0=21 (AF_RDS=21)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Apply upstream fix: https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/ |
| **Workaround** | Unload and blacklist RDS modules: `rmmod rds_tcp rds` + `printf 'install rds /bin/false\ninstall rds_tcp /bin/false\n' > /etc/modprobe.d/pintheft.conf` |
| **Config Hardening** | Disable io_uring if not needed: `sysctl -w kernel.io_uring_disabled=1` |

---

## References

- [Upstream patch (lore.kernel.org)](https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/)
- [Source Repository — v12-security/pocs (pintheft)](https://github.com/v12-security/pocs/tree/main/pintheft)
- [V12 Security](https://v12.sh)

---

## Notes

Auto-ingested from https://github.com/v12-security/pocs/tree/main/pintheft on 2026-05-20.

The RDS module (`CONFIG_RDS`, `CONFIG_RDS_TCP`) is required and is only loaded by default on Arch Linux among common distributions. Most Debian/Ubuntu/RHEL/Fedora systems are not exposed by default. The `poc.c` file includes a demo video link and a cleanup warning — if run on a non-disposable machine, restore the SUID binary from the printed backup command before rebooting.
