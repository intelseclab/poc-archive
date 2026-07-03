# Docker cp Copy-Out Destination Escape via Symlink Race

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | cloud |
| **Severity** | Medium |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | docker, container-escape, toctou, symlink-race, docker-cp, path-traversal, archive-extraction, host-file-write |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Docker Engine / CLI |
| **Versions Affected** | Validated on Docker Client/Server 29.6.0, API 1.55 (2026-06-23) |
| **Language / Platform** | Bash PoC driver; underlying bug spans Docker CLI (`cli/command/container/cp.go`) and daemon (`daemon/archive_unix.go`, vendored `go-archive`) in Go |
| **Authentication Required** | Local-only (attacker needs code execution inside a running container; a host user must separately run `docker cp` from that container) |
| **Network Access Required** | No |

---

## Summary

`docker cp` copy-out operations are vulnerable to a time-of-check/time-of-use race: the daemon walks the container's source path with `filepath.WalkDir` and builds a tar stream, but if a container process changes a directory entry (e.g., swaps it for a symlink) after the walk observes it but before the entry is added to the tar stream, the resulting archive can contain a symlink whose target escapes the intended destination. On the client side, `archive.CopyTo`/`Untar` checks the resolved symlink target with a raw `strings.HasPrefix(targetPath, extractDir)` string check rather than a proper path-boundary check, so a symlink target like `dst2` passes the prefix check against `dst` even though it is a sibling directory outside the requested extraction root. Entries that follow the symlink in the tar stream are then written through it into the sibling path. The researcher validated this against Docker 29.6.0 by racing many padding files before the target path and reliably (in ~0.2s of skew) getting a marker file written outside the requested destination. This is a host-operator-initiated escape, not an unattended container breakout — it requires a host user to run `docker cp` against an attacker-controlled container. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`Untar`'s symlink extraction constructs the target path with `filepath.Join(filepath.Dir(path), hdr.Linkname)` and validates containment using `strings.HasPrefix(targetPath, extractDir)` (`vendor/github.com/moby/go-archive/archive.go:480-490`), a raw string-prefix check that a sibling directory sharing a name prefix (e.g., `dst` vs. `dst2`) can pass despite being outside the extraction root, combined with a TOCTOU window during tar-stream creation on the daemon side that lets a container process substitute a symlink for a previously-observed directory entry.

### Attack Vector

1. Attacker gains code execution inside a running Linux container and prepares to race a directory entry under a path that will later be copied out (e.g., `/tmp/src`).
2. Attacker creates a host destination naming scenario where a sibling path (`dst2`) shares a raw string prefix with the intended destination (`dst`).
3. A host user (operator) runs `docker cp <container>:/tmp/src <host-destination>/dst`.
4. During the daemon's archive creation, the attacker's in-container process swaps a directory entry for a symlink pointing at `../../../dst2` after the tar walker has observed the entry but before it is added/recursed.
5. On the client side, `archive.CopyTo`'s `Untar` follows the symlink; the raw prefix check on `targetPath` incorrectly treats `dst2` as inside `dst`, so subsequent regular-file entries in the tar stream are written through the symlink into the sibling host directory.

### Impact

A container-controlled file write to a host path outside the requested `docker cp` destination directory, when a host operator copies data out of an attacker-controlled container into a destination with an exploitable sibling path name.

---

## Environment / Lab Setup

```
Target:   Host with Docker Engine 29.6.0 (or similar), Linux container under attacker control
Attacker: Bash, Docker CLI access to run the container and (as a separate host-operator step) docker cp
```

---

## Proof of Concept

### PoC Script

> See `poc.sh` in this folder.

```bash
chmod +x poc.sh
HOST_BASE=/tmp/docker-cp-copyout-repro ./poc.sh
```

The script starts a disposable container, races padding files against the copy-out path, invokes `docker cp <container>:/tmp/src $HOST_BASE/dst` from the host side, and reports whether a marker file was written into the sibling `$HOST_BASE/dst2` directory outside the requested destination — the researcher's validated run showed the race succeeding at a ~0.2s timing offset.

---

## Detection & Indicators of Compromise

```
# Host filesystem writes appearing outside the directory explicitly passed to `docker cp`
# Symlinks with traversal targets (e.g., ../../../<sibling>) appearing in docker cp
# extraction output where none were expected
```

**Signs of compromise:**
- New/unexpected files in directories adjacent to a `docker cp` destination shortly after a copy-out operation
- `docker cp` extraction directories containing symlinks pointing outside the requested destination path
- Host automation that runs `docker cp` against containers with untrusted or attacker-influenced content

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor Docker Engine release notes; proper fix requires descriptor-rooted extraction that resolves paths relative to a trusted directory file descriptor rather than raw string-prefix checks |
| **Interim mitigation** | Avoid running `docker cp` copy-out against containers whose contents are controlled by an untrusted party; prefer copying from stopped containers or immutable snapshots; avoid destination directory names that share a prefix with sibling paths |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/docker-cp-copyout-destination-escape)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `docker-cp-copyout-destination-escape`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The source README explicitly states this is not an unattended/no-interaction container escape and not a Docker socket exposure — it requires a host operator to run `docker cp` against an attacker-controlled container with an exploitable destination naming pattern.
