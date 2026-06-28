#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# cve_2026_34908_check.py
#
# Safe detector for the UniFi OS Server <= 5.0.6 unauthenticated RCE chain
# (Ubiquiti Security Advisory Bulletin 064):
#
#   * CVE-2026-34908 / CVE-2026-34909 — auth-gateway bypass (improper access
#     control / path traversal). The auth subrequest treats any request whose
#     RAW URI starts with "/api/auth/validate-sso/" as public, but nginx routes
#     by the NORMALIZED URI (it decodes %2f -> "/" and collapses "../"). Encoding
#     a traversal makes those diverge, granting unauthenticated access to internal
#     "/proxy/<service>/" backends.
#   * CVE-2026-34910 — unauthenticated command injection reached via the bypass.
#     CVE-2026-33000 is the same sink reached with a valid token instead of bypass.
#
# Fixed in UniFi OS Server 5.0.8.
#
# Produced by Bishop Fox Team X and released for defensive use. Use only against
# systems you are authorized to test.

"""
Detection methodology — non-destructive behavioral probing (no command is ever run).

Per target the detector sends up to three plain GETs: a baseline control, the
auth-bypass probe, and (only when the result is otherwise unclassifiable) a
root-page UniFi OS fingerprint. The core check exercises the auth-bypass primitive
against the vulnerable endpoint. On a vulnerable host, that request:
    - passes nginx auth (the RAW URI is treated as the public
      "/api/auth/validate-sso/" prefix), and
    - is routed to the internal package-update handler (the NORMALIZED path
      collapses onto "/proxy/users/api/v2/ucs/update/latest_package"),
which then rejects the missing parameter ("query param pkg_name required").
We therefore confirm both the auth bypass and that the vulnerable handler is
reachable without sending a command injection payload.

Response classification:
    HTTP 200 + handler error markers -> VULNERABLE   (bypass reached the sink handler)
    HTTP 400                          -> PATCHED      (5.0.8 nginx rejects the divergence)
    HTTP 401, UniFi OS fingerprint    -> INCONCLUSIVE (bypass blocked / auth enforced)
    HTTP 401, no fingerprint          -> UNAFFECTED   (not a UniFi OS Server)
    anything else, no fingerprint     -> UNAFFECTED   (not a UniFi OS Server)
    anything else, UniFi OS present   -> INCONCLUSIVE (UniFi OS, but unexpected response)

INCONCLUSIVE covers two confirmed-UniFi-OS cases that the verdict's detail string
distinguishes: (1) the bypass was blocked / auth enforced (HTTP 401) — not confirmed
vulnerable, verify the version manually; and (2) the probe returned an unexpected
response that fits no known pattern. Both warrant human review.

A baseline request to the same endpoint WITHOUT the bypass is also sent and must
return 401; this guards against false positives on open/misconfigured instances.
Whenever the probe does not positively confirm vulnerable or patched, the detector
fingerprints the root page (the same surface the nuclei UOS templates match) before
reporting a not-vulnerable verdict: only hosts that carry the UniFi OS portal markers
are reported INCONCLUSIVE; hosts without the markers are reported UNAFFECTED (not a
UniFi OS Server at all).

The probe tests the vulnerable behavior directly: a positive verdict means the auth
bypass actually reached the sink on the live target.

Exit status: 1 if any target is VULNERABLE, else 0 (argparse usage errors exit 2).
"""

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlsplit

DEFAULT_PORT = 11443

# --- non-exploit probes ------------------------------------------------------
# Auth-bypass primitive. NOTE: contains NO `pkg_name`, NO `by_cmd`, and NO shell
# metacharacters -> the vulnerable handler errors on the missing parameter before
# any command string is constructed. Reaching it proves the bug without running it.
BYPASS_PROBE = (
    "/api/auth/validate-sso/..%2f..%2f..%2f"
    "proxy/users/api/v2/ucs/update/latest_package"
)

# The same endpoint WITHOUT the bypass. Must be 401 on a sane host (false-positive guard).
BASELINE = "/proxy/users/api/v2/ucs/update/latest_package"

# Markers that identify the vulnerable handler's own "missing parameter" response,
# i.e. proof we landed on the package-update handler (not the SPA or another route).
VULN_HANDLER_MARKERS = ("pkg_name", "CODE_SYSTEM_ERROR", "parameters are invalid")

# Root-page markers that positively identify the UniFi OS management portal. Used
# only to tell "not a UniFi OS Server at all" (UNAFFECTED) apart from "UniFi OS
# present but unclassifiable".
UOS_FINGERPRINT_MARKERS = (
    "<title>UniFi OS</title>",
    "window.UNIFI_OS_MANIFEST",
    'id="portal-root"',
    'id="site-manager_portal-container"',
)


# --- terminal colour ---------------------------------------------------------
class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"


# verdict -> (marker, ansi-style)
VERDICT_STYLE = {
    "VULNERABLE": ("[!]", Ansi.BOLD + Ansi.RED),
    "PATCHED": ("[+]", Ansi.GREEN),
    "UNAFFECTED": ("[-]", Ansi.DIM),
    "INCONCLUSIVE": ("[?]", Ansi.YELLOW),
    "ERROR": ("[x]", Ansi.MAGENTA),
}


def want_color(flag_no_color: bool) -> bool:
    """Honour --no-color, the NO_COLOR convention, and non-TTY output."""
    if flag_no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def paint(text: str, style: str, enabled: bool) -> str:
    return f"{style}{text}{Ansi.RESET}" if enabled else text


# --- HTTP --------------------------------------------------------------------
def fetch(host, port, target, timeout, max_bytes=4096):
    """Issue one GET with an UN-normalized request-target.

    `http.client` sends the path verbatim, which is required so the literal
    "..%2f" survives to the server (libraries like `requests` would re-normalize
    or re-encode it). TLS verification is disabled because these appliances ship
    self-signed certificates. Returns (status, content_type, body_text).
    """
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.request(
            "GET",
            target,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
            },
        )
        resp = conn.getresponse()
        body = resp.read(max_bytes).decode("utf-8", "replace")
        return resp.status, (resp.getheader("Content-Type") or ""), body
    finally:
        conn.close()


def is_unifi_os(host, port, timeout):
    """Confirm the host serves the UniFi OS management portal via the root-page
    fingerprint (same surface the nuclei UOS templates match). Used only to make
    the 'not a UniFi OS Server' verdict conclusive rather than merely inconclusive.
    Reads more of the body than the probe path because the manifest/container
    markers sit further down the document than the <title>.
    """
    try:
        _, _, body = fetch(host, port, "/", timeout, max_bytes=65536)
    except Exception:
        return False
    return any(m in body for m in UOS_FINGERPRINT_MARKERS)


def check_bypass(host, port, timeout):
    """Run the behavioral probe + baseline control. Returns {state, detail}."""
    base_status = None
    try:
        base_status, _, _ = fetch(host, port, BASELINE, timeout)
    except Exception:
        pass  # baseline is only a corroborating control; tolerate its failure

    status, ctype, body = fetch(host, port, BYPASS_PROBE, timeout)
    reached_handler = any(m in body for m in VULN_HANDLER_MARKERS)

    if status == 200 and reached_handler:
        if base_status == 401:
            return {
                "state": "vulnerable",
                "detail": "auth bypass reached the vulnerable handler "
                "(no command executed); baseline correctly 401",
            }
        # Reached the handler but the control wasn't 401 -> still vulnerable, but
        # the host may also be open/misconfigured; flag it for human review.
        return {
            "state": "vulnerable",
            "detail": f"auth bypass reached the vulnerable handler; "
            f"baseline status={base_status} (expected 401) — review",
        }
    if status == 400:
        return {
            "state": "patched",
            "detail": "nginx rejected the normalized-path divergence "
            "(HTTP 400) — 5.0.8+ behavior",
        }
    if status == 401:
        # An auth layer rejected the bypass. On a confirmed UniFi OS box the bypass
        # was blocked but we can't tell patched-vs-mitigated-vs-other, so it's
        # inconclusive; a non-UniFi proxy that 401s everything is simply not affected.
        # Fingerprint the root page to tell the two apart.
        if is_unifi_os(host, port, timeout):
            return {
                "state": "inconclusive",
                "detail": "bypass blocked / auth enforced (HTTP 401) on a "
                "confirmed UniFi OS host — not confirmed vulnerable",
            }
        return {
            "state": "not_unifi",
            "detail": "HTTP 401 but no UniFi OS web fingerprint on / "
            "— target is not a UniFi OS Server",
        }
    # Ambiguous probe response (not the vuln handler, the 5.0.8 nginx guard, or the
    # auth gateway). Use the root-page fingerprint to decide whether this is even a
    # UniFi OS Server: absent -> conclusively not affected; present -> the second
    # inconclusive flavor (UOS, but an unexpected probe response, vs. the auth-enforced
    # 401 above) — leave it for human review. The detail string says which case it is.
    if not is_unifi_os(host, port, timeout):
        return {
            "state": "not_unifi",
            "detail": f"no UniFi OS web fingerprint on / "
            f"(probe HTTP {status}) — target is not a UniFi OS Server",
        }
    return {
        "state": "inconclusive",
        "detail": f"UniFi OS detected, but probe returned an "
        f"unexpected response: HTTP {status} {ctype}".strip(),
    }


def assess(host, port, timeout):
    """Probe one target and return the full result dict."""
    result = {"target": f"{host}:{port}"}
    try:
        result["bypass"] = check_bypass(host, port, timeout)
    except (socket.timeout, TimeoutError):
        return {**result, "verdict": "ERROR", "error": "timeout"}
    except (socket.gaierror, ConnectionError, OSError) as e:
        return {**result, "verdict": "ERROR", "error": str(e)}
    except Exception as e:
        # noqa: BLE001 - report anything unexpected, don't crash a scan
        return {**result, "verdict": "ERROR", "error": str(e)}

    result["verdict"] = {
        "vulnerable": "VULNERABLE",
        "patched": "PATCHED",
        "not_unifi": "UNAFFECTED",
        "inconclusive": "INCONCLUSIVE",
    }.get(result["bypass"]["state"], "INCONCLUSIVE")
    return result


# --- output ------------------------------------------------------------------
def print_human(r, color):
    verdict = r["verdict"]
    marker, style = VERDICT_STYLE.get(verdict, ("[?]", Ansi.YELLOW))
    print(
        f"{paint(marker, style, color)} {paint(r['target'], Ansi.BOLD, color)}: "
        f"{paint(verdict, style, color)}"
    )
    if "error" in r:
        print(f"      error: {r['error']}")
        return
    print(f"      {paint(r['bypass']['detail'], Ansi.DIM, color)}")


def print_brief(r, color):
    """One aligned line per target — convenient for scanning many hosts."""
    verdict = r["verdict"]
    _, style = VERDICT_STYLE.get(verdict, ("[?]", Ansi.YELLOW))
    status = paint(f"{verdict:<13}", style, color)
    note = r["error"] if "error" in r else ""
    note = f"  {paint(note, Ansi.DIM, color)}" if note else ""
    print(f"{status} {r['target']}{note}")


# --- CLI ---------------------------------------------------------------------
def parse_target(raw):
    if "://" in raw:
        u = urlsplit(raw)
        return u.hostname, (u.port or DEFAULT_PORT)
    if ":" in raw:
        host, _, port = raw.rpartition(":")
        return host, int(port)
    return raw, DEFAULT_PORT


def build_parser():
    p = argparse.ArgumentParser(
        prog="cve_2026_34908_check.py",
        description="Safe detector for UniFi OS Server <=5.0.6 "
        "unauthenticated RCE — SA Bulletin 064 "
        "(CVE-2026-34908/34909 + CVE-2026-34910).",
        epilog="examples:\n"
        "  cve_2026_34908_check.py 192.168.1.10\n"
        "  cve_2026_34908_check.py host-a:11443 https://host-b\n"
        "  cve_2026_34908_check.py -f targets.txt --brief\n"
        "  cve_2026_34908_check.py -f targets.txt --json > results.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="host, host:port, or https://host:port")
    p.add_argument(
        "-f",
        "--targets-file",
        metavar="FILE",
        help="file with one target per line ('#' comments allowed)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="per-request timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--brief",
        action="store_true",
        help="single-line output per target (for scanning many hosts)",
    )
    p.add_argument("--json", action="store_true", help="emit JSON results")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p


def main():
    args = build_parser().parse_args()

    targets = list(args.targets)
    if args.targets_file:
        try:
            with open(args.targets_file) as fh:
                targets += [
                    ln.strip()
                    for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
        except OSError as e:
            print(f"error: cannot read targets file: {e}", file=sys.stderr)
            return 2
    if not targets:
        build_parser().error("no targets given (positional or --targets-file)")

    color = want_color(args.no_color)
    results = []
    for raw in targets:
        host, port = parse_target(raw)
        r = assess(host, port, args.timeout)
        results.append(r)
        if args.json:
            continue
        print_brief(r, color) if args.brief else print_human(r, color)

    if args.json:
        print(json.dumps(results, indent=2))

    return 1 if any(r.get("verdict") == "VULNERABLE" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
