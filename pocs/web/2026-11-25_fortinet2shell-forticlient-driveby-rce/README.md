# Fortinet2Shell — FortiClient Local API Origin Validation Error to SYSTEM RCE (CVE-2026-121529)

<!--
  File: 2026-11-25_fortinet2shell-forticlient-driveby-rce.md
  Location: pocs/web/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-11-25 |
| **Last Updated** | 2026-11-19 |
| **Author / Researcher** | googlesky (PoC); Fortinet PSIRT (advisory) |
| **CVE / Advisory** | CVE-2026-121529 |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | 9.6 (NVD CVSSv3.1); vendor advisory: 9.1 |
| **Status** | Weaponized (lab model; real FortiClient required for live use) |
| **Tags** | RCE, FortiClient, FortiPAM, CORS, origin-validation, local-API, browser, drive-by, Windows, macOS, SYSTEM |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Fortinet FortiClient, FortiClient Windows PAM, FortiClient Mac |
| **Versions Affected** | Windows and Windows PAM 7.4.0–7.4.7, Windows 7.2.0–7.2.14; Mac 7.4.0–7.4.7. Fixed in 7.4.8 / 7.2.15 |
| **Language / Platform** | Windows / macOS endpoint software; browser-driven local HTTP/WebSocket API on `127.0.0.1:9191` |
| **Authentication Required** | No (victim must visit an attacker-controlled page) |
| **Network Access Required** | Yes — the victim's browser reaches the loopback API from a web page |

---

## Summary

Fortinet2Shell is a drive-by RCE against FortiClient's local API. The privileged endpoint on 127.0.0.1:9191 does not validate the caller's Origin, and it reflects the attacker's origin while allowing credentials. Any web page the victim visits can therefore make the victim's own browser call the privileged-session endpoint and execute a command with the service's privileges — SYSTEM on Windows. The vulnerability requires victim interaction (a page visit) but no credentials and no prior local access. The included PoC runs a real headless Chromium inside the endpoint's network namespace against a faithful local API model, demonstrates command execution and data exfiltration, and includes a differential against three remediation shapes plus a 0-day sweep against the patched model.

---

## Vulnerability Details

### Root Cause

The FortiClient local API listens on loopback and offers a privileged-session operation that runs a command with the service account's privileges. Its CORS/origin-validation layer reflects the request's `Origin` in `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`, so a cross-origin page can both drive the API and read the response. The same design is exposed over a WebSocket surface, which no CORS policy governs. An origin check that accepts requests without an `Origin` header is bypassed by a cross-origin `<img>`; a DNS-rebinding style page can make the page origin equal the API origin.

### Attack Vector

1. The attacker hosts a page on any origin.
2. The victim visits it; JavaScript issues `fetch('http://127.0.0.1:9191/api/v1/privileged/session')` (or opens the WebSocket variant).
3. The local API reflects the origin and executes the privileged operation.
4. The page reads the response (CORS reflection) or uses blind side channels such as an image load; the PoC exfiltrates the command output and a proof image to the attacker server.

### Impact

Unauthenticated remote code execution as the FortiClient service account (`SYSTEM` on Windows) on the victim's endpoint. The lab proves command execution and exfiltration; a real deployment also exposes the endpoint's privileged session handling and any data the service can reach.

---

## Environment / Lab Setup

```
OS:          Linux x86_64 (Podman; Docker can be substituted)
Target:      Local FortiClient API model (vulnerable + three remediation shapes)
Attacker:    Attacker web site container + headless Chromium (Playwright) in a
             PoC container sharing the endpoint's network namespace
Tools:       Podman, Python 3, Playwright/Chromium (inside the PoC image)
```

The real FortiClient code and binaries are not redistributed; the lab models the documented behaviour (loopback listener, privileged-session operation, origin reflection, WebSocket surface). It is a faithful reproduction of the security-relevant semantics, not the proprietary product.

### Setup Steps

```bash
# The upstream Makefile uses Podman. Targets and the run-lab.sh wrapper are equivalent.
make prepare          # build the endpoint and PoC images
make up               # start four endpoint models + attacker site
make check-vuln       # vulnerable model (exit 1 = vulnerable)
make check-fixed      # strict model (exit 0 = safe)
make exploit-vuln     # full chain: command output + exfiltrated data
make differential     # vulnerable vs the three remediation shapes
make down             # tear down

# Or:
./run-lab.sh up && ./run-lab.sh exploit
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Build and start the lab** — `make prepare && make up`.
2. **Classify the vulnerable model** — `make check-vuln` returns exit code 1 because the page can drive the API and read the answer.
3. **Run the full chain** — `make exploit-vuln` runs the PoC container in the endpoint's network namespace, loads the attacker page in headless Chromium, and drives the privileged-session endpoint.
4. **Verify execution** — the lab writes the command output and the exfiltrated data to the shared `results/` volume; the PoC prints a proof path and the data.
5. **Compare remediations** — `make differential` shows the CORS-header-only fix does not stop the WebSocket path, and the origin-only fix is bypassed by a missing-`Origin` request.

### Exploit Code

> The site viewer shows [`exploit.py`](./exploit.py); the canonical driver is [poc/poc.py](https://github.com/googlesky/CVE-2026-121529/blob/main/poc/poc.py), the standalone chain is [exploit/exploit.py](https://github.com/googlesky/CVE-2026-121529/blob/main/exploit/exploit.py), and the local API/attacker models are in [lab/](https://github.com/googlesky/CVE-2026-121529/tree/main/lab).

The PoC is browser-driven, not a cURL one-liner: a real Chromium must enforce (or fail to enforce) the CORS decision. The `poc` container shares the endpoint container's network namespace so `http://127.0.0.1:9191` is the victim's real loopback.

### Expected Output

```text
[*] endpoint: vulnerable model
[*] page -> http://127.0.0.1:9191/api/v1/privileged/session
[*] command executed; proof written to /results/proof.png
[*] exfiltrated data: <command output>
[*] verdict: VULNERABLE (exit 1)
```

`make check-fixed` should print `SAFE (exit 0)` for the strict model.

---

## Detection & Indicators of Compromise

- Browser or endpoint telemetry showing a page issuing requests to `http://127.0.0.1:9191/api/v1/privileged/session` or opening the local WebSocket.
- FortiClient local API logs with hostile or missing `Origin` headers, or responses reflecting an external origin with `Access-Control-Allow-Credentials: true`.
- Outbound requests from the endpoint to an unusual attacker domain immediately after a page visit (the PoC's exfiltration path).
- FortiClient version in the affected range and the privileged-session feature enabled.
- Browser console/CORS errors followed by successful local-API responses are a strong signal of the reflection behavior.

**SIEM / IDS rule (example):**

```text
alert http any any -> any any (msg:"FortiClient local API privileged session from browser"; \
  content:"/api/v1/privileged/session"; http_uri; \
  content:"Origin|3a|"; http_header; sid:9002613;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade FortiClient to 7.4.8 or 7.2.15 (or later) on Windows, Windows PAM and Mac; restart the FortiClient service. |
| **Workaround** | Restrict the local API to expected origins, validate the `Origin` header including its absence, and enforce origin checks on the WebSocket handshake (a CORS-header-only fix is insufficient). Disable the privileged-session feature where it is not required. |
| **Config Hardening** | Isolate privileged browsing, monitor loopback API calls from browsers, and treat endpoint local APIs as an attack surface in EDR/browser policy. |

---

## References

- [CVE-2026-121529 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121529)
- [Fortinet advisory FG-IR-26-194](https://fortiguard.fortinet.com/psirt/FG-IR-26-194)
- [googlesky/CVE-2026-121529 — source PoC](https://github.com/googlesky/CVE-2026-121529)
- [tc4dy/CVE-2026-121529-Toolkit — independent toolkit](https://github.com/tc4dy/CVE-2026-121529-Toolkit)
- [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Notes

Auto-ingested from https://github.com/googlesky/CVE-2026-121529 on 2026-11-25 (MIT). The PoC is a **model-based** reproduction: FortiClient is proprietary, so the lab implements the documented local API semantics and uses a real browser to exercise the origin-validation flaw. It proves the bug class and the browser-side chain; a live test requires the real FortiClient build on Windows/macOS.

Review of candidates: `googlesky/CVE-2026-121529` was selected because it is licensed, includes a real-browser lab, three remediation differentials, and recorded evidence. `tc4dy/CVE-2026-121529-Toolkit` (licensed) is a credible independent PoC/toolkit and is referenced as an alternate. `ashrafzaryouh/CVE-2026-121529` is a near-identical copy of the googlesky PoC with no license and was not ingested. `Ghost-Bx1/cve-2026-121529-forticlient-cors-rce` was not reachable at ingest time.

The vulnerability requires victim interaction and is browser-enforced; a scripted HTTP client cannot demonstrate the CORS flaw, which is why the PoC uses Chromium. The NVD CVSS is 9.6; the vendor advisory scores it 9.1 — both are included above. Run only against endpoints you own or have written authorization to test.
