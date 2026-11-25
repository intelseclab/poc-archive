#!/usr/bin/env python3
"""Provision vulnerable GitLab lab: create public project + upload PoC payload. Stdlib only. Run INSIDE container."""
import json, sys, urllib.request, urllib.parse, urllib.error, time
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv)>1 else "http://172.20.0.1:8929"
TOKEN = sys.argv[2] if len(sys.argv)>2 else ""
HDRS = {"PRIVATE-TOKEN": TOKEN, "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
POC = Path(__file__).resolve().parents[1] / "poc.py"

def api(method, path, data=None):
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=HDRS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: b = e.read().decode()[:500]
        except: b = ""
        return e.code, {"error": b}
    except Exception as e:
        return None, {"error": str(e)[:200]}

if not TOKEN:
    print("usage: provision_lab.py <base> <root_PAT>"); sys.exit(2)
# 1. version
st, j = api("GET", "/api/v4/version")
print(f"[*] version: {st} {j}")
# 2. create public project victim/pub (namespace victim may need creation; use user namespace root)
st, j = api("POST", "/api/v4/projects", {"name": "pub", "path": "pub", "visibility": "public", "initialize_with_readme": True})
print(f"[*] create pub: {st} id={j.get(chr(105)+chr(100), j)}")
pid = j.get("id")
if not pid:
    # try list
    st, j = api("GET", "/api/v4/projects?search=pub")
    print(f"[*] search: {st} {str(j)[:300]}")
    sys.exit(1)
# 3. upload payloads via repository files API (create p0.org + README control already exists)
for fname, repeats in [("p0.org", 35000)]:
    import subprocess
    subprocess.run([sys.executable, str(POC), "payload", "--repeats", str(repeats), "-o", f"/tmp/{fname}"], check=True)
    with open(f"/tmp/{fname}") as f: content = f.read()
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    st, j = api("POST", f"/api/v4/projects/{pid}/repository/files/{urllib.parse.quote(fname, safe='')}",
                {"branch": "master" if False else "main", "content": b64, "encoding": "base64", "commit_message": f"add {fname} PoC"})
    # GitLab default branch may be main or master; retry master on 400
    if st == 400:
        st, j = api("POST", f"/api/v4/projects/{pid}/repository/files/{urllib.parse.quote(fname, safe='')}",
                    {"branch": "master", "content": b64, "encoding": "base64", "commit_message": f"add {fname} PoC"})
    print(f"[*] upload {fname}: {st} {str(j)[:300]}")
print(f"[*] done pid={pid}")
