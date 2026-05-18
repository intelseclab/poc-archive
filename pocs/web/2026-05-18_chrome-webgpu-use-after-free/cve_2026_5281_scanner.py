# DISCLAIMER: For authorized security research and defensive testing only.
#!/usr/bin/env python3
"""
CVE-2026-5281 Vulnerability Scanner
A simple, consolidated Python script to audit Chrome versions locally and via inventory files,
as well as triage crash logs, to detect potential vulnerability to CVE-2026-5281 (WebGPU Use-After-Free).

Patched Version: 146.0.7680.178
"""

import argparse
import csv
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

try:
    import winreg
except ImportError:  # Non-Windows platforms
    winreg = None

PATCHED_VERSION = "146.0.7680.178"

FATAL_LOG_PATTERNS = [
    re.compile(r"gpu device lost", re.IGNORECASE),
    re.compile(r"crash detected", re.IGNORECASE),
    re.compile(r"vulnerability confirmed", re.IGNORECASE),
    re.compile(r"uncaught gpu error.*(device lost|gpu hang|context lost|out of memory|internal error|removed)", re.IGNORECASE),
]

NON_FATAL_LOG_PATTERNS = [
    re.compile(r"max attempts reached without crash", re.IGNORECASE),
    re.compile(r"no exploit signatures detected", re.IGNORECASE),
]

# --- Version Utilities ---

def parse_chrome_version(version: str):
    if not version:
        return None
    parts = version.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        parsed = tuple(int(p) for p in parts)
    except ValueError:
        return None
    if any(p < 0 for p in parsed):
        return None
    return parsed

def compare_versions(left: str, right: str):
    l = parse_chrome_version(left)
    r = parse_chrome_version(right)
    if l is None or r is None:
        return None
    if l < r:
        return -1
    if l > r:
        return 1
    return 0

def is_vulnerable(version: str):
    cmp_result = compare_versions(version, PATCHED_VERSION)
    if cmp_result is None:
        return None, "Invalid version format"
    if cmp_result < 0:
        return True, f"Version is below patched release {PATCHED_VERSION}"
    return False, f"Version is at or above patched release {PATCHED_VERSION}"


# --- Local Audit ---

def get_registry_versions():
    records = []
    if platform.system() != "Windows" or winreg is None:
        return records
    
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome\BLBeacon"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Google\Chrome\BLBeacon")
    ]
    
    for hkey, subkey in paths:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                version, _ = winreg.QueryValueEx(key, "version")
                vuln, reason = is_vulnerable(version)
                records.append({
                    "source": "registry",
                    "path": f"HKEY_...\\{subkey}",
                    "version": version,
                    "vulnerable": vuln,
                    "reason": reason
                })
        except OSError:
            pass
    return records

def get_binary_versions():
    records = []
    if platform.system() != "Windows":
        return records
        
    common_paths = [
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    ]
    
    for p in common_paths:
        if p.exists():
            try:
                cmd = f'(Get-Item "{p}").VersionInfo.ProductVersion'
                output = subprocess.check_output(["powershell", "-c", cmd], text=True).strip()
                version = output.split()[0] if output else None
                if version:
                    vuln, reason = is_vulnerable(version)
                    records.append({
                        "source": "binary",
                        "path": str(p),
                        "version": version,
                        "vulnerable": vuln,
                        "reason": reason
                    })
            except Exception:
                pass
    return records

def run_local_audit(json_output=False):
    results = get_registry_versions() + get_binary_versions()
    if json_output:
        print(json.dumps(results, indent=2))
        return
        
    print(f"\n[+] Local System Audit for CVE-2026-5281")
    if not results:
        print("  [-] No Chrome installations found.")
        return
        
    for r in results:
        status = "VULNERABLE" if r["vulnerable"] else "SAFE" if r["vulnerable"] is False else "UNKNOWN"
        print(f"  [{status}] {r['path']} -> v{r['version']}")


# --- Fleet Audit ---

def run_fleet_audit(csv_path: str, json_output=False):
    results = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                version = row.get("version", "").strip()
                vuln, reason = is_vulnerable(version)
                results.append({
                    "host": row.get("host", "unknown"),
                    "product": row.get("product", "unknown"),
                    "version": version,
                    "vulnerable": vuln,
                    "reason": reason
                })
    except Exception as e:
        print(f"Error reading {csv_path}: {e}")
        return

    if json_output:
        print(json.dumps(results, indent=2))
        return
        
    print(f"\n[+] Fleet Audit for CVE-2026-5281 ({len(results)} hosts)")
    for r in results:
        status = "VULNERABLE" if r["vulnerable"] else "SAFE" if r["vulnerable"] is False else "UNKNOWN"
        print(f"  [{status}] Host: {r['host']} | Product: {r['product']} | Version: {r['version']}")


# --- Log Triage ---

def run_log_triage(log_path: str):
    p = Path(log_path)
    if not p.exists():
        print(f"Log path does not exist: {log_path}")
        return
    
    signatures = [
        re.compile(r"use-after-free", re.IGNORECASE),
        re.compile(r"webgpu", re.IGNORECASE),
        re.compile(r"commandbuffer", re.IGNORECASE),
        re.compile(r"dawn::", re.IGNORECASE)
    ]
    
    print(f"\n[+] Triaging logs in {p} for CVE-2026-5281 signatures...")
    
    files_to_check = [p] if p.is_file() else p.rglob("*.log")
    found_any = False
    
    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for num, line in enumerate(f, 1):
                    # Check if line indicates a UAF in WebGPU
                    if "use-after-free" in line.lower() and ("webgpu" in line.lower() or "dawn" in line.lower() or "commandbuffer" in line.lower()):
                        print(f"  [!] SUSPICIOUS LINE in {fpath.name} (Line {num}):")
                        print(f"      {line.strip()}")
                        found_any = True
        except Exception:
            pass
            
    if not found_any:
        print("  [-] No exploit signatures detected in provided logs.")


# --- Claim Readiness Assessment ---

def load_text(path: str):
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return p.read_text(encoding="utf-8", errors="ignore")


def analyze_log_markers(content: str):
    fatal_hits = []
    safe_hits = []

    for pattern in FATAL_LOG_PATTERNS:
        if pattern.search(content):
            fatal_hits.append(pattern.pattern)

    for pattern in NON_FATAL_LOG_PATTERNS:
        if pattern.search(content):
            safe_hits.append(pattern.pattern)

    return {
        "fatal_hits": fatal_hits,
        "safe_hits": safe_hits,
        "has_fatal": len(fatal_hits) > 0,
        "has_safe": len(safe_hits) > 0,
    }


def run_claim_assessment(vuln_log: str, patched_log: str, vuln_version: str = None, patched_version: str = None, json_output: bool = False):
    vuln_content = load_text(vuln_log)
    patched_content = load_text(patched_log)

    vuln_markers = analyze_log_markers(vuln_content)
    patched_markers = analyze_log_markers(patched_content)

    checks = []

    checks.append({
        "name": "vulnerable_run_shows_fatal_gpu_behavior",
        "pass": vuln_markers["has_fatal"],
        "details": vuln_markers["fatal_hits"],
    })

    checks.append({
        "name": "patched_run_does_not_show_fatal_gpu_behavior",
        "pass": not patched_markers["has_fatal"],
        "details": patched_markers["fatal_hits"],
    })

    if vuln_version:
        is_vuln, reason = is_vulnerable(vuln_version)
        checks.append({
            "name": "vulnerable_version_is_below_fixed_threshold",
            "pass": is_vuln is True,
            "details": reason,
        })

    if patched_version:
        is_vuln, reason = is_vulnerable(patched_version)
        checks.append({
            "name": "patched_version_is_at_or_above_fixed_threshold",
            "pass": is_vuln is False,
            "details": reason,
        })

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    verdict = "READY"
    if passed < total:
        verdict = "PARTIAL"
    if passed <= max(1, total // 2):
        verdict = "INSUFFICIENT"

    output = {
        "patched_version_threshold": PATCHED_VERSION,
        "verdict": verdict,
        "score": {
            "passed": passed,
            "total": total,
        },
        "checks": checks,
        "evidence": {
            "vulnerable_log": vuln_log,
            "patched_log": patched_log,
            "vulnerable_log_markers": vuln_markers,
            "patched_log_markers": patched_markers,
        },
    }

    if json_output:
        print(json.dumps(output, indent=2))
        return

    print("\n[+] Claim Readiness Assessment for CVE-2026-5281")
    print(f"  Verdict: {verdict}")
    print(f"  Score: {passed}/{total}")
    for c in checks:
        state = "PASS" if c["pass"] else "FAIL"
        print(f"  [{state}] {c['name']}")
        if c["details"]:
            print(f"       {c['details']}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="CVE-2026-5281 Universal Scanner & Audit Tool")
    parser.add_argument("--local", action="store_true", help="Run a local Chrome installation audit")
    parser.add_argument("--fleet", metavar="CSV_FILE", help="Run a fleet audit against a CSV inventory file (needs host, product, version columns)")
    parser.add_argument("--triage", metavar="LOG_DIR_OR_FILE", help="Triage crash logs for WebGPU/Dawn Use-After-Free signatures")
    parser.add_argument("--assess-claim", action="store_true", help="Assess claim readiness using vulnerable and patched run logs")
    parser.add_argument("--vuln-log", metavar="LOG_FILE", help="Path to vulnerable test run log")
    parser.add_argument("--patched-log", metavar="LOG_FILE", help="Path to patched test run log")
    parser.add_argument("--vuln-version", metavar="VERSION", help="Browser version used for vulnerable run")
    parser.add_argument("--patched-version", metavar="VERSION", help="Browser version used for patched run")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format (applies to --local and --fleet)")
    
    args = parser.parse_args()
    
    if not any([args.local, args.fleet, args.triage, args.assess_claim]):
        parser.print_help()
        return
        
    if args.local:
        run_local_audit(args.json)
        
    if args.fleet:
        run_fleet_audit(args.fleet, args.json)
        
    if args.triage:
        run_log_triage(args.triage)

    if args.assess_claim:
        if not args.vuln_log or not args.patched_log:
            print("Error: --assess-claim requires --vuln-log and --patched-log")
            sys.exit(2)
        run_claim_assessment(
            vuln_log=args.vuln_log,
            patched_log=args.patched_log,
            vuln_version=args.vuln_version,
            patched_version=args.patched_version,
            json_output=args.json,
        )

if __name__ == "__main__":
    main()
