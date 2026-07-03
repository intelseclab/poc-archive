# PHP 8.5.7 StreamBucket-to-SOAP Numeric Cookie Remote Code Execution

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | php, type-confusion, streambucket, soap, hashtable-overwrite, memory-corruption, rce, zend-engine |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | PHP CLI (Zend Engine) — `ArrayIterator`, `StreamBucket`, `SoapClient` internals |
| **Versions Affected** | PHP `8.5.7` (build-specific symbol offsets used; other builds require recomputed offsets) |
| **Language / Platform** | Single-file PHP RPoC (`rpoc.php`) targeting a local PHP 8.5.7 CLI build on Linux/WSL |
| **Authentication Required** | No (proof runs in-process against a local PHP binary; real-world reachability depends on whether attacker-controlled SOAP responses can be driven in the target deployment) |
| **Network Access Required** | No for the local replay (uses a loopback SOAP server); Yes in a realistic deployment where an attacker-influenced SOAP response delivers the numeric cookie |

---

## Summary

This PoC demonstrates a full memory-corruption-to-RCE chain in PHP 8.5.7 built from three engine/extension behaviors chained together: `ArrayIterator` can mutate normally-protected internal object properties (bypassing typed-property/visibility/readonly invariants) to corrupt a `StreamBucket`'s `data` property into a raw pointer; `php_stream_bucket_attach()` validates the `bucket` resource but later trusts `data` as a string without a type check, yielding a controlled heap-pointer disclosure and overread; and `SoapClient`'s cookie storage uses `zend_symtable_update()`, which treats numeric cookie names as integer hash-table keys, providing the pivot needed to write a canonical (non-tagged) pointer value. By spraying fake `HashTable` structures in heap string storage and steering a numeric `Set-Cookie` name equal to the decimal address of `zif_system`, the chain overwrites `zend_execute_internal` with `zif_system`, so that any subsequent dynamic internal function call (e.g., `$fn = 'md5'; $fn($cmd);`) actually executes `system($cmd)`. The researcher validated this locally with both a marker-file check and a debugger (GDB) transcript confirming the exact overwrite and `zif_system` hit. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`ArrayIterator` offset assignment can write to internal-object properties (such as `StreamBucket::$data` and `SoapClient::$_cookies`) while bypassing the type/visibility/readonly invariants those properties are supposed to have; downstream, `php_stream_bucket_attach()` trusts `StreamBucket::$data` as a string without re-validating its type, and `SoapClient`'s cookie handling stores response cookies via `zend_symtable_update()`, which treats numeric-looking cookie names as raw integer hash keys rather than hashed string keys — avoiding the high-bit tagging PHP normally applies to string-key hashes and enabling a canonical function-pointer overwrite.

### Attack Vector

1. Use `ArrayIterator` property mutation to corrupt a `StreamBucket` object's `data` property into an attacker-chosen integer (pointer) value while keeping its `bucket` property a valid resource.
2. Exploit `php_stream_bucket_attach()`'s missing type check on `data` to obtain a controlled heap-pointer disclosure and overread via chained user stream filters.
3. Spray heap string storage with fake `HashTable` structures whose `arData` field points to `zend_execute_internal - 16`, and locate the sprayed marker via the leaked pointer/overread.
4. Use `ArrayIterator` again to replace `SoapClient::$_cookies` (normally a real array) with the address of the fake `HashTable`.
5. Start a loopback SOAP server and trigger `SoapClient->__soapCall()`, delivering a `Set-Cookie` response whose cookie name is the decimal address of `zif_system`.
6. `zend_symtable_update()` routes the numeric cookie name to `zend_hash_index_update()`, writing the canonical `zif_system` address into the fake table's steered `Bucket.h` slot, overwriting `zend_execute_internal`.
7. Invoke a dynamic internal function call (`$fn = 'md5'; $fn($cmd);`); the VM's internal-call handler now dispatches through the overwritten `zend_execute_internal`, landing in `zif_system($cmd)` and executing the attacker's command.

### Impact

Full native code execution in the PHP process via `system()`, achieved from PHP-userland-reachable engine/extension behaviors (`ArrayIterator`, `StreamBucket`, `SoapClient`) without requiring memory-unsafe extensions — a critical remote-code-execution primitive in any application context where these classes/behaviors are reachable with attacker influence.

---

## Environment / Lab Setup

```
Target:   PHP 8.5.7 CLI build (soap, SPL, standard, stream-filter support) on Linux/WSL with /proc/self/maps and /proc/self/mem access
Attacker: The rpoc.php script itself (self-contained); validate.sh replay wrapper
```

---

## Proof of Concept

### PoC Script

> See `rpoc.php` and `validate.sh` in this folder.

```bash
bash validate.sh /path/to/php-8.5.7/sapi/cli/php
```

`rpoc.php` reads its own PIE base from `/proc/self/maps`, computes `zend_execute_internal`/`zif_system` addresses from known build offsets, sprays and locates a fake `HashTable` via the `StreamBucket` type-confusion overread, replaces `SoapClient::$_cookies` with the fake table's address, drives a loopback SOAP call with a numeric `Set-Cookie` equal to `zif_system`'s decimal address, and finally makes a dynamic internal call that executes `system()`, writing a marker file (`/tmp/php857_rce_<pid>.txt` containing `PHP857_RCE`) to prove command execution.

---

## Detection & Indicators of Compromise

```
# Marker file: /tmp/php857_rce_<pid>.txt containing "PHP857_RCE"
# Unexpected child processes spawned from a PHP-FPM/CLI worker with no
# corresponding legitimate shell_exec/system/passthru call in application code
# PHP crash/segfault logs correlating with SOAP requests carrying unusually
# large numeric Set-Cookie names
```

**Signs of compromise:**
- Unexplained `system()`-spawned child processes from PHP worker processes
- SOAP request/response traffic containing `Set-Cookie` values that are large decimal integers rather than typical session tokens
- Application logs showing `ArrayIterator` usage against `SoapClient` or stream-filter internal objects from untrusted input paths

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor php-src for a fix restricting `ArrayIterator` property mutation on internal objects, and for hardening in `php_stream_bucket_attach()` and SOAP cookie handling |
| **Interim mitigation** | Avoid exposing `ArrayIterator` offset-assignment on internal engine objects (`StreamBucket`, `SoapClient`, etc.) to untrusted input paths; validate `StreamBucket::$data` type before use; verify `SoapClient::$_cookies` is a genuine array before use; disable `system()`/exec-family functions via `disable_functions` where not required |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/php857-streambucket-soap-rce-rpoc)
- [PHP source repository](https://github.com/php/php-src)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `php857-streambucket-soap-rce-rpoc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation. The chain is build-specific (uses hardcoded symbol offsets for the tested PHP 8.5.7 binary) and would require recomputed offsets and possible heap-shaping adjustments against other builds.
