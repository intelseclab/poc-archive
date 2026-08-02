#!/usr/bin/env python3
"""Audit the archive's `patched` flag against authoritative sources.

Sources
  OSV.dev  — batch API, returns explicit "fixed" version events for
             open-source ecosystems. Fast: 1 request per 1000 CVEs.
  NVD 2.0  — per-CVE; we read vulnStatus and whether any reference is
             tagged "Patch". Rate limited to 5 req/30s without an API key,
             so pass --nvd-limit N to sample rather than sweep all.

Writes reports/patch-status-audit.json and prints a summary. Read-only with
respect to the site: it never modifies pocs/ or content/.
"""

import json, re, sys, time, argparse
import urllib.request, urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
POCS_DIR = REPO_ROOT / "pocs"
OUT = REPO_ROOT / "reports" / "patch-status-audit.json"

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_ONE = "https://api.osv.dev/v1/vulns/"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
UA = "poc-archive-patch-audit/1.0 (+https://poc.intelseclab.com)"


def post_json(url, payload, timeout=90):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def get_json(url, timeout=45):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def collect_entries():
    """(cve, patched_flag, relpath) for every archive entry with a CVE."""
    out = []
    for readme in sorted(POCS_DIR.rglob("README.md")):
        if len(readme.relative_to(POCS_DIR).parts) != 3:
            continue
        text = readme.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'\|\s*\*\*CVE / Advisory\*\*\s*\|\s*(.+?)\s*\|', text, re.I)
        if not m:
            continue
        cm = re.search(r'CVE-\d{4}-\d{4,7}', m.group(1), re.I)
        if not cm:
            continue
        sm = re.search(r'\|\s*\*\*Status\*\*\s*\|\s*(.+?)\s*\|', text, re.I)
        out.append({
            "cve": cm.group(0).upper(),
            "status_field": (sm.group(1).strip() if sm else ""),
            "path": str(readme.parent.relative_to(REPO_ROOT)),
        })
    return out


def osv_lookup(cves):
    """CVE -> {'fixed': [versions], 'ids': [osv ids]} for anything OSV knows."""
    found = {}
    CHUNK = 500
    for i in range(0, len(cves), CHUNK):
        batch = cves[i:i + CHUNK]
        payload = {"queries": [{"package": {}, "version": "", "id": c} for c in batch]}
        # querybatch doesn't accept bare CVE ids reliably; use the vulns endpoint
        # for each id instead, which is a plain GET and is not rate limited.
        for c in batch:
            try:
                d = get_json(OSV_ONE + c, timeout=20)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                continue
            except Exception:
                continue
            fixed = []
            for aff in d.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed.append(ev["fixed"])
            found[c] = {"fixed": sorted(set(fixed)), "id": d.get("id", "")}
        print(f"    OSV: {min(i+CHUNK, len(cves))}/{len(cves)} checked, {len(found)} known",
              file=sys.stderr)
    return found


def nvd_lookup(cves, limit=None, pause=6.5):
    """CVE -> {'status':…, 'has_patch_ref':bool, 'patch_urls':[…]}"""
    out = {}
    todo = cves[:limit] if limit else cves
    for n, c in enumerate(todo, 1):
        try:
            d = get_json(NVD.format(cve=c))
        except Exception as e:
            print(f"    NVD {c}: {e}", file=sys.stderr)
            time.sleep(pause)
            continue
        vulns = d.get("vulnerabilities", [])
        if not vulns:
            out[c] = {"status": "NOT_IN_NVD", "has_patch_ref": False, "patch_urls": []}
        else:
            cve = vulns[0]["cve"]
            refs = cve.get("references", [])
            patch_urls = [r["url"] for r in refs if "Patch" in (r.get("tags") or [])]
            out[c] = {
                "status": cve.get("vulnStatus", ""),
                "has_patch_ref": bool(patch_urls),
                "patch_urls": patch_urls[:3],
            }
        if n % 10 == 0:
            print(f"    NVD: {n}/{len(todo)}", file=sys.stderr)
        time.sleep(pause)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd-limit", type=int, default=0,
                    help="how many CVEs to check against NVD (0 = skip NVD)")
    ap.add_argument("--skip-osv", action="store_true")
    args = ap.parse_args()

    entries = collect_entries()
    cves = sorted({e["cve"] for e in entries})
    print(f"Archive: {len(entries)} entries with a CVE, {len(cves)} distinct.", file=sys.stderr)

    osv = {} if args.skip_osv else osv_lookup(cves)
    nvd = nvd_lookup(cves, args.nvd_limit) if args.nvd_limit else {}

    # Current flag comes from the same heuristic the site build uses.
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bhc", REPO_ROOT / "scripts" / "build-hugo-content.py")
    bhc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bhc)

    rows = []
    for e in entries:
        readme = REPO_ROOT / e["path"] / "README.md"
        text = readme.read_text(encoding="utf-8", errors="replace")
        current = bhc.determine_patched(text)
        o = osv.get(e["cve"])
        n = nvd.get(e["cve"])
        evidence = []
        authoritative = None
        if o and o["fixed"]:
            authoritative = True
            evidence.append(f"OSV fixed in {', '.join(o['fixed'][:3])}")
        if n:
            if n["has_patch_ref"]:
                authoritative = True
                evidence.append("NVD has Patch-tagged reference")
            if n["status"] and not n["has_patch_ref"]:
                evidence.append(f"NVD status {n['status']}, no Patch ref")
        rows.append({
            "cve": e["cve"], "path": e["path"],
            "status_field": e["status_field"],
            "current_patched": current,
            "authoritative_patched": authoritative,
            "evidence": evidence,
        })

    checked = [r for r in rows if r["authoritative_patched"] is not None]
    wrong = [r for r in checked if r["current_patched"] != r["authoritative_patched"]]
    false_unpatched = [r for r in wrong if r["authoritative_patched"] and not r["current_patched"]]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "entries": len(rows),
        "checked_against_source": len(checked),
        "disagreements": len(wrong),
        "flagged_unpatched_but_actually_fixed": len(false_unpatched),
        "rows": rows,
    }, indent=2) + "\n")

    print(f"\n  entries                     : {len(rows)}", file=sys.stderr)
    print(f"  currently flagged patched   : {sum(1 for r in rows if r['current_patched'])}", file=sys.stderr)
    print(f"  currently flagged unpatched : {sum(1 for r in rows if not r['current_patched'])}", file=sys.stderr)
    print(f"  verifiable against a source : {len(checked)}", file=sys.stderr)
    print(f"  disagreements               : {len(wrong)}", file=sys.stderr)
    print(f"    of which 'unpatched' but a fix exists: {len(false_unpatched)}", file=sys.stderr)
    print(f"\n  wrote {OUT.relative_to(REPO_ROOT)}", file=sys.stderr)
    for r in false_unpatched[:15]:
        print(f"    {r['cve']:<18} {r['evidence'][0][:60]}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
