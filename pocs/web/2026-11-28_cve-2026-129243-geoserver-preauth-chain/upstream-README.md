# GeoServer Unauthenticated RCE PoC

Proof-of-concept exploit for the unauthenticated remote command execution chain in the [GeoServer pre-auth RCE writeup](https://cryptocat.me/blog/research/analysis/geoserver_preauth_rce/). I found the chain and reported it to GeoServer on August 2, 2026. GeoServer fixed it in 3.0.2, 2.28.6 and 2.27.7, and published it as five advisories on November 23, 2026.

| Step | CVE | Advisory | Severity |
| --- | --- | --- | --- |
| Data-directory path in WFS exception | [CVE-2026-129244](https://nvd.nist.gov/vuln/detail/CVE-2026-129244) | [GHSA-4v26-c537-jvxc](https://github.com/geoserver/geoserver/security/advisories/GHSA-4v26-c537-jvxc) | 6.9 (medium) |
| `service=x/WFS` operation-security bypass | [CVE-2026-129243](https://nvd.nist.gov/vuln/detail/CVE-2026-129243) | [GHSA-rv5g-g2r9-58rj](https://github.com/geoserver/geoserver/security/advisories/GHSA-rv5g-g2r9-58rj) | 8.8 (high) |
| Stored-query XInclude local file read | [CVE-2026-120705](https://nvd.nist.gov/vuln/detail/CVE-2026-120705) | [GHSA-39mw-5chv-jh47](https://github.com/geoserver/geoserver/security/advisories/GHSA-39mw-5chv-jh47) | 8.6 (high, CVSS 3.1) |
| Predictable remember-me key permits administrator-session forgery | [CVE-2026-129245](https://nvd.nist.gov/vuln/detail/CVE-2026-129245) | [GHSA-hgm3-wq4h-8vvq](https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq) | 9.2 (critical) |
| JDBC user-service deserialisation | [CVE-2026-129242](https://nvd.nist.gov/vuln/detail/CVE-2026-129242) | [GHSA-9wf2-fcgq-vxhq](https://github.com/geoserver/geoserver/security/advisories/GHSA-9wf2-fcgq-vxhq) | 8.6 (high) |

Severities are GeoServer's CVSS 4.0 scores unless noted.

## Usage

`geoserver_preauth_rce.py` runs the whole chain from an anonymous WFS request to command output. Run only against systems you are authorised to test.

```console
python3 geoserver_preauth_rce.py -u http://127.0.0.1:18080/geoserver -c id
```

```text
 [*] Probing anonymous WFS stored-query errors for the data-directory path
 [+] data directory: /opt/geoserver_data
 [*] Persisting an anonymous x/WFS stored query with deferred XInclude
 [+] DescribeStoredQueries disclosed the remember-me key and admin password digest
 [*] Forging a remember-me cookie and exchanging it for a session
 [+] administrator JSESSIONID accepted by the REST API
 [*] Uploading the HSQLDB payload database and request via REST
 [+] registered JDBC user-group service 'jdbc_geoserver_poc'
 [*] Triggering deserialisation through a user-property lookup
 [+] command executed (exit code 0)
 [+] output of: id
  ------------------------------------------------------------
uid=0(root) gid=0(root) groups=0(root)
 [*] Cleaning up
 [+] removed the staging directory and temporary JDBC service
```

That run is against the official `docker.osgeo.org/geoserver:3.0.0` image, which runs GeoServer as root. Progress goes to stderr and only the command output goes to stdout, so `> out.txt` keeps just the result. `--help` lists every option.

The payload runs `/bin/sh -c`, so the target must be Linux. The command can be up to 512 printable ASCII bytes. The chain targets the enabled `admin` user in GeoServer's `default` file user service. Don't run two copies against the same target at once, because the temporary JDBC service name is fixed.

## How It Works

1. An overlong `storedQuery_id` makes the WFS exception leak the absolute data-directory path.
2. `service=x/WFS` misses the `wfs.CreateStoredQuery` rule, so an anonymous stored query can carry escaped `xi:include` elements. `DescribeStoredQueries` returns `security/config.xml` and `users.xml` through them.
3. The remember-me key and the admin password digest sign a forged remember-me cookie, which GeoServer exchanges for an administrator session.
4. As admin, the REST API uploads an HSQLDB database and registers it as a JDBC user-group service. Looking up a user deserialises an `OTHER` column, and a `BeanComparator`/`TemplatesImpl` gadget loads a translet that runs the command.

The client removes its stored query, JDBC service and staging directory afterwards. If it can't prove the database was closed, it leaves the staging directory and prints its location so you can remove it after restarting GeoServer.

## Files

- `geoserver_preauth_rce.py`: the exploit client.
- `payload.properties` and `payload.script`: an HSQLDB file database (HSQLDB stores one as this pair), holding the serialised gadget graph and the compiled translet. The command isn't baked in, because the client uploads it separately at run time, so these files never change. Keep them beside the client.
- `payload-src/`: the Java source for the translet and the generator that builds the database, with rebuild steps, so the hex in `payload.script` isn't an unexplained blob.

Affected: GeoServer 2.27.6 and earlier, 2.28.0 to 2.28.5, and 3.0.0 to 3.0.1. Fixed in 2.27.7, 2.28.6 and 3.0.2.
