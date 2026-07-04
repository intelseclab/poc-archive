# PostgreSQL Referential-Integrity Owner-Switched Implicit Cast RCE

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-04 |
| **Last Updated** | 2026-07-04 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-04 |
| **Category** | network |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE assigned) |
| **Status** | PoC |
| **Tags** | postgresql, privilege-escalation, referential-integrity, implicit-cast, command-execution, database, uncoordinated-disclosure |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | PostgreSQL (server) |
| **Versions Affected** | Tested against `PostgreSQL 20devel` at commit `e0ff7fd9aa2e6f77c38825e71200ced742220d55`; root cause is in long-standing RI-trigger owner-switch logic, so likely affects released versions too — not independently verified against a stable release by this archive |
| **Language / Platform** | Python (PoC driver) against a stock PostgreSQL server via `psql` |
| **Authentication Required** | Yes — attacker needs a role with column-level `REFERENCES` grant on the target primary-key column, plus the ability to create types/functions/casts/tables (i.e., a low-privilege application DB role, not superuser) |
| **Network Access Required** | Yes (PostgreSQL wire protocol / `psql`) |

---

## Summary

This PoC demonstrates that PostgreSQL's referential-integrity (RI) enforcement for foreign keys switches its effective role to the *referenced* table's owner before invoking any implicit cast needed to compare the foreign-key value against the primary-key type. An attacker who can create a data type, a `SECURITY INVOKER` SQL function, an implicit cast from that type to the primary key's type, and a table with a foreign key referencing the victim's table can smuggle attacker-authored SQL into the cast function. When a row is inserted that triggers the RI check, PostgreSQL runs the attacker's cast function under the *referenced table owner's* privileges rather than the attacker's own — and if that owner is a member of `pg_execute_server_program`, the attacker's function can reach `COPY ... TO PROGRAM` for server-side command execution, despite direct calls to the same function being blocked by the normal privilege check. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed, has no CVE, and has not been independently verified by this archive against a released (non-devel) PostgreSQL build.

---

## Vulnerability Details

### Root Cause

`ri_PerformCheck()` / `ri_FastPathCheck()` in `src/backend/utils/adt/ri_triggers.c` switch the active user ID to the owner of the table being queried for RI enforcement before probing the primary-key index. If the foreign-key value requires an implicit cast to match the primary key's operator-class input type, `build_index_scankeys()` invokes the cached cast function while still running as that owner-switched role — not as the inserting user. An attacker-owned implicit cast function is therefore executed with the referenced table owner's privileges.

### Attack Vector

1. Obtain a role with column-level `REFERENCES` grant on a target table's primary-key column (a common, low-privilege grant in multi-tenant schemas).
2. Create an attacker-owned composite type, a `SECURITY INVOKER` SQL function, and an implicit `CAST ... AS IMPLICIT` from that type to the primary key's column type.
3. Create a table with a foreign key referencing the victim's primary key, typed so the FK-to-PK comparison requires the attacker's implicit cast.
4. Insert a row that forces PostgreSQL's RI check to invoke the cast — this runs under the *referenced table owner's* effective role, not the attacker's.
5. If that owner belongs to `pg_execute_server_program`, have the cast function issue `COPY ... TO PROGRAM` to execute an OS command on the database host, even though the attacker could not call `COPY ... TO PROGRAM` directly under their own role.

### Impact

Privilege escalation from a low-privileged database role (holding only a `REFERENCES` grant) to arbitrary server-side command execution as the referenced table's owner, if that owner has `pg_execute_server_program` membership — potentially full OS command execution on the database host.

---

## Environment / Lab Setup

```
Target:   PostgreSQL 20devel (commit e0ff7fd9aa2e6f77c38825e71200ced742220d55), Linux x86-64
Attacker: Python 3 + psql client; a DB role with REFERENCES grant on the victim table
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python3 poc.py \
  --psql /path/to/psql \
  --host 127.0.0.1 \
  --port 5432 \
  --admin-user postgres \
  --admin-db postgres \
  --marker /tmp/postgres_ri_cast_marker.txt
```

The script bootstraps two roles (`ri_owner_probe`, granted `pg_execute_server_program`, and `ri_attacker_probe`), creates the referenced/referencing tables, the attacker-owned implicit cast, and an FK insert that triggers the RI check. It first confirms a *direct* call to the cast function is blocked by the normal `COPY TO PROGRAM` privilege check, then shows the same function executing successfully once invoked indirectly through the RI owner-switch path — writing a marker file containing `current_user`/`session_user`/`is_superuser` to prove the effective-role switch.

---

## Detection & Indicators of Compromise

```
# PostgreSQL logs: CREATE CAST / CREATE FUNCTION / CREATE TYPE statements from
#   non-admin roles, followed shortly by INSERT statements on foreign-key
#   tables that reference a table owned by a role with pg_execute_server_program
# Unexpected COPY ... TO PROGRAM invocations correlated with ordinary FK inserts
```

**Signs of compromise:**
- Non-admin roles creating implicit casts (`CREATE CAST ... AS IMPLICIT`) targeting primary-key column types of tables they don't own
- Unexpected child processes spawned by the PostgreSQL server process shortly after INSERT activity
- Marker/side-effect files appearing on the database host with no corresponding legitimate admin action

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-04 — monitor `pgsql-hackers`/PostgreSQL security advisories |
| **Interim mitigation** | Audit and restrict which roles hold `pg_execute_server_program`; restrict column-level `REFERENCES` grants to trusted roles; review `pg_cast` for unexpected implicit casts created by non-admin roles |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/postgres-ri-owner-switched-cast-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `postgres-ri-owner-switched-cast-poc`) on 2026-07-04. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The PoC was tested by its author only against a PostgreSQL development build (`20devel`) at a specific commit, not a released version — applicability to stable PostgreSQL releases is plausible given the root cause is in long-standing RI-trigger code, but has not been independently confirmed by this archive.
