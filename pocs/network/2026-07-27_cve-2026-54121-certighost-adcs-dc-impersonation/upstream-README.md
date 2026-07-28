# CVE-2026-54121 (Certighost)

This is a proof-of-concept tool to demonstrace CVE-2026-54121 a.k.a _Certighost_. Read here https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26 for the detailed analysis.

## Usage

Run as root because the rogue LDAP and SMB services listen on high privileged ports 389 and 445.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Successful execution writes the target certificate (`.pfx`) and Kerberos cache (`.ccache`) to the current directory.

## What this script does
1. Create a new computer account (e.g. `GHOSTABCDEFGH$`) or reuse one passed via `--computer-name`.
2. Start two rogue listeners: an SMB/LSA server on port 445 and an LDAP server on port 389.
3. Send a certificate request as that computer account, embedding a custom `cdc` attribute pointing to a controlled IP (via `--listener`; optional, auto-detected if omitted) plus an `rmd` attribute carrying the target DC's DNS name.
4. The CA connects back to the rogue LSA/LDAP listeners. They authenticate as the created account (validated through the real DC over Netlogon) and answer the CA's lookups with the target DC's identity (sAMAccountName, SID, dNSHostName) instead.
5. The CA issues a valid certificate belonging to the DC.
6. The scripts also performs PKINIT with the DC's pfx to request .ccache and NT hash 

## References
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121
- https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26
- https://github.com/ly4k/Certipy
