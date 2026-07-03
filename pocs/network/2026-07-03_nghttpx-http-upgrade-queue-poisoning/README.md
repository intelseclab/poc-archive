# nghttpx HTTP/1.1 Upgrade Request Body Response Queue Poisoning

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | network |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | nghttp2, nghttpx, reverse-proxy, request-smuggling, response-queue-poisoning, http-desync, upgrade-request, cache-poisoning |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | nghttp2's `nghttpx` reverse proxy |
| **Versions Affected** | `v1.69.0` (fixed by upstream commit `ab28105c4a0197da24f8bfc414bc116055249e1e`) |
| **Language / Platform** | C++ target (`nghttpx`); Python 3 stdlib-only PoC driver |
| **Authentication Required** | No |
| **Network Access Required** | Yes (attacker connects to the `nghttpx` HTTP/1.1 frontend; requires an Upgrade-aware HTTP/1.1 backend behind it) |

---

## Summary

`nghttpx`, the reverse proxy shipped with nghttp2, incorrectly accepts an HTTP/1.1 `Upgrade` request that also carries a `Content-Length` header, then forwards both the Upgrade headers and the body bytes unmodified to a keep-alive HTTP/1.1 backend connection. If the backend treats the Upgrade request as a protocol switch and parses the trailing body bytes as an entirely separate, smuggled HTTP request, that smuggled request's response gets queued on the shared backend connection. When `nghttpx` subsequently reuses the same backend connection for an unrelated victim client's request, the victim receives the attacker's queued/smuggled response instead of their own. The researcher verified this locally end-to-end against a real `nghttpx` v1.69.0 binary, including a fixed-control run against the patched upstream commit. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`nghttpx`'s HTTP/1.1 frontend parser accepts Upgrade requests that also carry `Content-Length` instead of rejecting them, and `HttpDownstreamConnection` forwards both the original Upgrade/Content-Length headers and the buffered request body to the backend on a reusable keep-alive connection, allowing an Upgrade-aware backend to desynchronize and treat the trailing body bytes as a second, smuggled HTTP request.

### Attack Vector

1. Attacker connects to the `nghttpx` cleartext HTTP/1.1 frontend and sends a `GET /upgrade` request with `Connection: Upgrade`, `Upgrade: websocket`, and a `Content-Length` body containing a fully-formed smuggled request (`GET /poisoned HTTP/1.1`).
2. `nghttpx` forwards the Upgrade request headers and body verbatim to a keep-alive HTTP/1.1 backend.
3. The backend treats the Upgrade header terminator as a message boundary and parses the trailing body bytes as a second request (`/poisoned`), delaying its response.
4. The backend replies to the original Upgrade request (e.g., `UPGRADE-REJECT`), and the attacker's frontend connection closes.
5. A victim client sends an unrelated request (e.g., `GET /victim`) that `nghttpx` routes onto the same now-reused backend connection.
6. The backend's previously delayed response to the smuggled `/poisoned` request is delivered as the victim's response, poisoning the victim's request with attacker-controlled content.

### Impact

An unauthenticated attacker can cause an arbitrary victim client sharing a backend connection through `nghttpx` to receive an attacker-chosen response body, enabling cross-client response injection/cache poisoning and potential further abuse depending on what content the proxied application allows to be smuggled.

---

## Environment / Lab Setup

```
Target:   nghttp2 nghttpx v1.69.0 reverse proxy, fronting a keep-alive HTTP/1.1 backend
Attacker: Python 3 (stdlib only) — poc.py
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python3 poc.py --nghttpx ./build/src/nghttpx --cwd ./nghttp2-v1.69.0
```

The script starts a real `nghttpx` v1.69.0 process fronting a small Python backend that implements the Upgrade-desync behavior, sends the crafted attacker Upgrade request with a smuggled body request, then sends a subsequent victim request over the reused backend connection, and prints a JSON result showing whether the victim received the smuggled response instead of its own.

---

## Detection & Indicators of Compromise

```
# nghttpx access logs showing Upgrade requests carrying Content-Length
# Backend connection logs showing more requests parsed per connection than
# frontend requests forwarded (evidence of a smuggled second request)
```

**Signs of compromise:**
- Clients reporting responses unrelated to the request they sent when proxied through `nghttpx`
- Backend logs showing multiple HTTP requests parsed from a single forwarded connection where only one was expected
- Unusual `Upgrade` requests combined with `Content-Length` in frontend access logs

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | Upgrade to a build containing upstream commit `ab28105c4a0197da24f8bfc414bc116055249e1e` ("nghttpx: Tighten up CONNECT and HTTP Upgrade handling"), first present after `v1.69.0` |
| **Interim mitigation** | Reject or strip `Content-Length`/`Transfer-Encoding` on `CONNECT` or `Upgrade` requests at an edge layer in front of `nghttpx`; disable backend connection reuse for Upgrade-capable routes if not required |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/nghttp2-nghttpx-upgrade-queue-poison-poc)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `nghttp2-nghttpx-upgrade-queue-poison-poc`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
