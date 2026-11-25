#!/usr/bin/env python3
"""
Model of the FortiClient local API  --  CVE-2026-121529 (Fortinet PSIRT FG-IR-26-194).

WHAT THIS IS
------------
FortiClient (Windows / Windows PAM / Mac) ships a local HTTP API that listens on the
loopback interface and is used by the FortiPAM "Privileged Access Agent" components on
the same machine (public write-ups name TCP 127.0.0.1:9191 and the FortiVRS.exe /
FortiPAM privileged-access-agent processes).

Fortinet PSIRT FG-IR-26-194 (published 2026-11-10) describes the flaw as:

    "An origin validation error vulnerability [CWE-346] in FortiClient Mac,
     FortiClient Windows, and FortiClient Windows PAM may allow an unauthorized remote
     attacker to execute unauthorized code or commands. Successful exploitation requires
     interaction with the victim."

i.e. the local API trusts the `Origin` header of a browser request, so a page on any
web site can drive the privileged local API through the victim's browser.

FortiClient is proprietary and cannot be redistributed/obtained here, so this file is an
explicitly documented MODEL of that local API.  It reproduces the security-relevant
behaviour that the CVE is about:

  * an HTTP listener on 127.0.0.1:9191 with a small privileged-session API,
  * a CORS/origin-validation layer, whose three behaviours are modelled here,
  * command execution with the privileges of the service (root in this lab, SYSTEM on a
    real Windows endpoint).

The three behaviours (FCT_MODE):

  vuln         FortiClient 7.4.7 model.  THE VULNERABLE BUILD.
               No server-side origin validation at all.  Every response reflects the
               request `Origin` into `Access-Control-Allow-Origin` and sets
               `Access-Control-Allow-Credentials: true`.  A preflight is answered
               permissively for any origin.  -> The browser lets the attacker's script
               READ the response: full cross-origin RCE + data exfiltration.

  fixed-cors   A *hypothetical* CORS-header-only remediation (what a patch that only
               tightens the CORS headers would produce).  The untrusted origin is no
               longer echoed, so the browser blocks the attacker's script from reading
               the response -- but the server STILL EXECUTES THE COMMAND.
               -> CORS protects the response, not the request.  The RCE survives.

  fixed-strict A *hypothetical* proper remediation: the origin is validated server-side
               and untrusted origins are rejected with 403 BEFORE anything is executed,
               and privileged calls additionally require a non-simple shared secret
               header that a cross-origin browser request cannot set without a
               preflight.  -> No execution, no response.

Nothing in this file is a real FortiClient implementation; see README.md.
"""

import base64
import hashlib
import json
import os
import shlex
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --------------------------------------------------------------------------- config

MODE = os.environ.get("FCT_MODE", "vuln")
PORT = int(os.environ.get("FCT_PORT", "9191"))
BIND = os.environ.get("FCT_BIND", "127.0.0.1")
RESULTS = os.environ.get("FCT_RESULTS", "/results")
TOKEN = os.environ.get("FCT_TOKEN", "fct-local-agent-shared-secret")
TOKEN_HEADER = "x-fortipam-client"
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "FCT_ALLOWED_ORIGINS",
        "https://fortipam.fortinet.com,chrome-extension://klbibpmmopcnogkgdclkbjoepgphcnak",
    ).split(",")
    if o.strip()
]
VERSION = {
    "vuln": "7.4.7",
    "fixed-cors": "7.4.8",
    "fixed-origin-only": "7.4.8",
    "fixed-strict": "7.4.8",
}[MODE]
PRODUCT = "FortiClient"

_lock = threading.Lock()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def _results_dir(sub="poc"):
    d = os.path.join(RESULTS, sub)
    os.makedirs(d, exist_ok=True)
    return d


def _append_jsonl(path, obj):
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) + "\n")


# --------------------------------------------------------------------- CORS policy


def cors_allowed(origin):
    """Is `origin` allowed to *read* responses?

    This models only the CORS header layer.  It is deliberately kept separate from
    `action_allowed()` because that separation is the whole point of the residual
    finding: a CORS-header-only fix leaves the execution untouched, and it does not
    reach the WebSocket surface at all -- no CORS policy governs a WebSocket.
    """
    if MODE == "vuln":
        # 7.4.7 model: the service trusts whatever origin asks.
        return True
    if origin is None:
        return False
    return origin in ALLOWED_ORIGINS


def action_allowed(headers):
    """Is the request allowed to make the local API *do* something?

    vuln              -> always (no server-side validation; this is the CVE).
    fixed-cors        -> always (CORS-header-only remediation: the request is still
                         processed even though the browser hides the response).
    fixed-origin-only -> the origin is validated server-side, but a request that carries
                         *no* Origin header is still accepted, because the native local
                         agent does not send one.  This is the shape a plausible patch
                         takes, and it is the shape the <img> bypass defeats.
    fixed-strict      -> the origin must be trusted AND the privileged call must carry
                         the shared secret header that a cross-origin browser request
                         cannot set without a preflight.
    """
    if MODE in ("vuln", "fixed-cors"):
        return True
    origin = headers.get("Origin")
    token = headers.get(TOKEN_HEADER)
    if MODE == "fixed-origin-only":
        if origin is None:
            # Treated as a trusted local component.
            return True
        return origin in ALLOWED_ORIGINS
    # fixed-strict
    if token != TOKEN:
        return False
    if origin is None:
        # Local agent / native client: no Origin header, but the secret is present.
        return True
    return origin in ALLOWED_ORIGINS


# --------------------------------------------------------------- WebSocket bits

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def _ws_read_frame(rfile):
    hdr = rfile.read(2)
    if len(hdr) < 2:
        return None, None
    b1, b2 = hdr
    opcode = b1 & 0x0F
    masked = b2 & 0x80
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", rfile.read(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", rfile.read(8))[0]
    mask = rfile.read(4) if masked else None
    payload = rfile.read(length) if length else b""
    if mask:
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return opcode, payload


def _ws_write_frame(wfile, payload, opcode=0x1):
    frame = bytearray()
    frame.append(0x80 | opcode)
    n = len(payload)
    if n < 126:
        frame.append(n)
    elif n < 65536:
        frame.append(126)
        frame += struct.pack(">H", n)
    else:
        frame.append(127)
        frame += struct.pack(">Q", n)
    frame += payload
    wfile.write(bytes(frame))
    wfile.flush()


# ------------------------------------------------------------------------ handler


class FortiClientLocalAPI(BaseHTTPRequestHandler):
    server_version = "FortiClient/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ utilities

    def log_message(self, fmt, *args):  # keep stdout tidy, we log JSONL instead
        pass

    def _log(self, entry):
        entry = dict(entry)
        entry["ts"] = _now()
        entry["mode"] = MODE
        entry["version"] = VERSION
        entry["peer"] = "%s:%s" % self.client_address[:2]
        _append_jsonl(os.path.join(RESULTS, "api-%s.jsonl" % MODE), entry)
        return entry

    def _send(self, code, payload=None, cors_origin=None, extra_headers=None, no_cors=False):
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")

        origin = cors_origin if cors_origin is not None else self.headers.get("Origin")
        if not no_cors and cors_allowed(origin) and origin:
            # The vulnerable build echoes ANY origin and allows credentials.
            # The patched builds only echo a trusted origin.
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Expose-Headers", "X-FortiClient-Version")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -------------------------------------------------------------- preflight

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        allowed = cors_allowed(origin)
        entry = self._log(
            {
                "event": "preflight",
                "method": "OPTIONS",
                "path": self.path,
                "origin": origin,
                "requested_method": self.headers.get("Access-Control-Request-Method"),
                "requested_headers": self.headers.get("Access-Control-Request-Headers"),
                "cors_allowed": allowed,
                "executed": False,
                "status": 200 if allowed else 403,
            }
        )
        if not allowed:
            # The patched build rejects the preflight outright.
            self._send(403, {"error": "origin not allowed", "origin": origin})
            return
        extra = {
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            # Reflects whatever the browser asked for -- a second permissive element.
            "Access-Control-Allow-Headers": self.headers.get(
                "Access-Control-Request-Headers", "Content-Type, Authorization"
            ),
            "Access-Control-Max-Age": "86400",
        }
        self._send(200, None, cors_origin=origin, extra_headers=extra)

    # ------------------------------------------------------------------- GET

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        origin = self.headers.get("Origin")

        # ---- WebSocket upgrade: the browser applies NO CORS policy to a WebSocket
        # ---- handshake, so an origin-validation scheme built on CORS never applies
        # ---- to this surface at all.
        if u.path == "/ws" and (self.headers.get("Upgrade") or "").lower() == "websocket":
            return self._websocket(origin)

        if u.path in ("/", "/api", "/api/v1"):
            return self._send(
                200,
                {
                    "product": PRODUCT,
                    "version": VERSION,
                    "mode": MODE,
                    "endpoints": [
                        "GET  /api/v1/ping",
                        "GET  /api/v1/system/info",
                        "GET  /api/v1/files/<name>",
                        "POST /api/v1/privileged/session",
                        "GET  /api/v1/privileged/session?command=...",
                        "POST /api/v1/privileged/session/legacy",
                        "WS   /ws",
                    ],
                },
                cors_origin=origin,
            )

        if u.path == "/api/v1/ping":
            self._log({"event": "ping", "origin": origin, "executed": False, "status": 200})
            return self._send(200, {"status": "ok"}, cors_origin=origin)

        if u.path == "/api/v1/system/info":
            self._log({"event": "system/info", "origin": origin, "executed": False, "status": 200})
            return self._send(
                200,
                {
                    "product": PRODUCT,
                    "version": VERSION,
                    "os": "Windows 11 Pro",
                    "build": "0643",
                    "privileges": "LocalSystem",
                },
                cors_origin=origin,
            )

        # ---- state changing, reachable with a *simple* GET (no preflight, no Origin
        # ---- header from the browser): this is the CSRF-shaped sibling endpoint.
        if u.path == "/api/v1/privileged/session":
            cmd = (q.get("command") or [None])[0]
            if cmd is None:
                return self._send(405, {"error": "command required"}, cors_origin=origin)
            return self._privileged(cmd, origin, "GET", "query")

        # ---- diagnostics artefact store.  A privileged session can drop a file here
        # ---- and a browser can then load it as an image: that turns a blind RCE into
        # ---- a *confirmed* one, because the image decodes only if the command ran.
        if u.path.startswith("/api/v1/files/"):
            name = os.path.basename(u.path[len("/api/v1/files/") :])
            if not name or not action_allowed(self.headers):
                return self._send(403, {"error": "not allowed"}, cors_origin=origin)
            path = os.path.join(_results_dir("marker"), name)
            if not os.path.isfile(path):
                return self._send(404, {"error": "not found"}, cors_origin=origin)
            with open(path, "rb") as fh:
                data = fh.read()
            ctype = "image/png" if name.endswith(".png") else "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            if cors_allowed(origin) and origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(data)
            self._log(
                {"event": "file", "path": u.path, "origin": origin, "executed": False, "status": 200}
            )
            return

        self._send(404, {"error": "not found"}, cors_origin=origin)

    # ------------------------------------------------------------------ POST

    def do_POST(self):
        u = urlparse(self.path)
        origin = self.headers.get("Origin")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except Exception:
            body = {"_raw": raw.decode("utf-8", "replace")}
        if not isinstance(body, dict):
            body = {"_raw": body}

        if u.path in ("/api/v1/privileged/session", "/api/v1/privileged/session/launch"):
            cmd = body.get("command") or body.get("cmd") or body.get("args")
            if isinstance(cmd, list):
                cmd = " ".join(shlex.quote(str(x)) for x in cmd)
            if not cmd:
                return self._send(400, {"error": "command required"}, cors_origin=origin)
            return self._privileged(cmd, origin, "POST", "json")

        # Endpoint that never sends CORS headers at all: not readable cross-origin,
        # but still perfectly CSRF-able if the server does not validate the origin.
        if u.path == "/api/v1/privileged/session/legacy":
            cmd = body.get("command") or body.get("cmd")
            if not cmd:
                return self._send(400, {"error": "command required"}, cors_origin=origin)
            # This endpoint never sends CORS headers.  A browser therefore cannot read
            # its response cross-origin, but the request is still delivered and still
            # acted upon -- a CORS-shaped endpoint that is only protected by CSRF.
            return self._privileged(cmd, origin, "POST", "legacy-no-cors", no_cors=True)

        self._send(404, {"error": "not found"}, cors_origin=origin)

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self._send(405, {"error": "method not allowed"}, cors_origin=self.headers.get("Origin"))

    # ------------------------------------------------------------- the RCE sink

    def _run_command(self, command, origin, verb, channel):
        """Run `command` with the privileges of the service and record the proof."""
        try:
            proc = subprocess.run(
                ["/bin/sh", "-c", command],
                capture_output=True,
                text=True,
                timeout=20,
            )
            out, err, rc = proc.stdout, proc.stderr, proc.returncode
        except Exception as exc:  # pragma: no cover
            out, err, rc = "", "exec failed: %r" % (exc,), -1

        proof = {
            "ts": _now(),
            "mode": MODE,
            "version": VERSION,
            "command": command,
            "origin": origin,
            "verb": verb,
            "channel": channel,
            "exit_code": rc,
            "stdout": out,
            "stderr": err,
            "uid": os.getuid(),
            "euid": os.geteuid(),
        }
        proof_id = "pwn-%s-%d" % (MODE, int(time.time() * 1000))
        proof["proof_id"] = proof_id
        pdir = _results_dir("poc")
        with open(os.path.join(pdir, proof_id + ".json"), "w", encoding="utf-8") as fh:
            json.dump(proof, fh)

        self._log(
            {
                "event": "privileged",
                "verb": verb,
                "channel": channel,
                "origin": origin,
                "command": command,
                "executed": True,
                "exit_code": rc,
                "proof_id": proof_id,
                "status": 200,
            }
        )
        return {
            "ok": True,
            "session": "priv-1",
            "proof_id": proof_id,
            "stdout": out,
            "stderr": err,
            "exit_code": rc,
            "privileges": "LocalSystem (uid=%d)" % os.geteuid(),
        }

    def _privileged(self, command, origin, verb, channel, no_cors=False):
        """The privileged action: run `command` with the privileges of the service."""
        allowed = action_allowed(self.headers)
        if not allowed:
            self._log(
                {
                    "event": "privileged",
                    "verb": verb,
                    "channel": channel,
                    "origin": origin,
                    "command": command,
                    "executed": False,
                    "status": 403,
                }
            )
            return self._send(
                403,
                {"error": "origin not allowed", "origin": origin},
                cors_origin=origin,
            )

        result = self._run_command(command, origin, verb, channel)

        return self._send(
            200,
            result,
            cors_origin=origin,
            no_cors=no_cors,
        )

    # -------------------------------------------------------------- WebSocket

    def _websocket(self, origin):
        """The privileged session over a WebSocket.

        A browser applies **no** CORS policy to a WebSocket handshake: there is no
        preflight, and the frames exchanged afterwards are not subject to the
        `Access-Control-*` machinery at all.  Any origin-validation scheme that is
        built on CORS therefore does not reach this surface, and the answer is read
        back by the page in full.
        """
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return self._send(400, {"error": "bad websocket handshake"}, cors_origin=origin)

        allowed = action_allowed(self.headers)
        if not allowed:
            self._log(
                {
                    "event": "websocket",
                    "origin": origin,
                    "executed": False,
                    "status": 403,
                }
            )
            return self._send(
                403,
                {"error": "origin not allowed", "origin": origin},
                cors_origin=origin,
            )

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", _ws_accept(key))
        self.end_headers()
        self.wfile.flush()
        self._log({"event": "websocket", "origin": origin, "executed": False, "status": 101})

        try:
            while True:
                opcode, payload = _ws_read_frame(self.rfile)
                if opcode is None or opcode == 0x8:
                    break
                if opcode != 0x1:
                    continue
                try:
                    msg = json.loads(payload.decode("utf-8", "replace"))
                except Exception:
                    msg = {}
                cmd = msg.get("command") or msg.get("cmd")
                if cmd:
                    result = self._run_command(cmd, origin, "WS", "websocket")
                else:
                    result = {"ok": False, "error": "command required"}
                _ws_write_frame(self.wfile, json.dumps(result).encode())
        except Exception:
            pass
        return


def main():
    os.makedirs(RESULTS, exist_ok=True)
    srv = ThreadingHTTPServer((BIND, PORT), FortiClientLocalAPI)
    srv.daemon_threads = True
    print(
        "[forticlient-api] mode=%s version=%s listening on http://%s:%d/ (results=%s)"
        % (MODE, VERSION, BIND, PORT, RESULTS),
        flush=True,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
