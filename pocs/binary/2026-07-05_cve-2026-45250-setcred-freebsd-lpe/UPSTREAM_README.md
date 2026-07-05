# FreeBSD setcred(2) — research artifacts

This subdirectory collects the write-up and working exploits for the
`setcred(2)` stack buffer overflow in FreeBSD 14.x kernel.

The vulnerability itself is fully documented in `setcred.txt`. The short
version: `kern_setcred_copyin_supp_groups()` uses `sizeof(*groups)` where
`groups` is `gid_t **`, producing an 8-byte stride instead of 4 for a
`copyin()` into a fixed-size kernel-stack array. The overflow is reachable
before any privilege check, by any unprivileged user.

This repository captures two working exploit paths:

  * **no-SMAP / no-SMEP** — `exp2_lpe_no_smap.c`.  A single
    `setcred(2)` syscall flips the calling thread to uid=0 by
    redirecting the chain primitive at `amd64_syscall+0x155` to
    user-space shellcode through a fake `struct sysentvec`.

  * **SMAP / SMEP enabled** — `exp_setcred_smap_zfs.c`.  Hijacks to
    `ZSTD_initCStream_advanced` in `zfs.ko` whose body writes
    `td_ucred = rcx+1`.  With `rcx = K1 = parent_pargs - 1` (a
    qword planted in a child's pargs slab), the calling thread's
    credential pointer lands inside the parent's pargs slab where
    we have planted a fake `struct ucred` with `cr_uid=0`.  Works
    on any FreeBSD 14.4 GENERIC system with `zfs.ko` loaded
    (typical server configuration) and requires no kernel
    info-leak primitive.

## Layout

```
setcred/
+- setcred.txt          Primary write-up: vulnerability, both LPE
|                       techniques, PoC pointers, FIX STATUS, timeline.
|                       Pure ASCII.
+- exploits/            Curated exploit drop.
    +- poc_dos.c                    Minimal DoS PoC -- any user
    |                               panics kernel.
    +- exp2_lpe_no_smap.c           Full LPE on no-SMAP/SMEP kernel.
    +- exp_setcred_smap_zfs.c       SMAP/SMEP-safe LPE via zfs.ko
    |                               ZSTD gadget.  No info-leak.
    +- wrapper.c                    Tiny setuid-root → /bin/sh
    |                               launcher installed at /tmp/rsh
    |                               by exp_setcred_smap_zfs.
    +- Makefile.setcred_smap_zfs    Guest-side build pipeline for
    |                               the SMAP/SMEP path
    |                               (all, install, clean).
    +- README_setcred_smap_zfs.md   End-user write-up for the
                                    SMAP/SMEP path.
```

## Status

  * DoS (any user panics the kernel) and full LPE without SMAP/SMEP
    are reproducible by the corresponding programs in `exploits/`.

  * Full LPE with SMAP/SMEP enabled is reproducible via
    `exp_setcred_smap_zfs.c` on any FreeBSD 14.4 GENERIC system with
    `zfs.ko` loaded.  See `setcred.txt` for the technique.

  * 14.4-RELEASE / stable/14 remain vulnerable as of report date.
    The fix landed in main on 2025-11-27 (commit 000d5b5) as a side
    effect of an unrelated refactoring and was not backported.
