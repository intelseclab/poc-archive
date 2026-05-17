#!/usr/bin/env python3
import os, re, base64, gzip

INPUT = "cURL"
OUTDIR = "out"
os.makedirs(OUTDIR, exist_ok=True)

# Read whole curl text (as pasted)
data = open(INPUT, "rb").read()

# 1) Extract URL-encoded base64 between CompressedDataTable%3d%22 ... %22
m = re.search(rb"CompressedDataTable%3d%22([A-Za-z0-9+/=%]+)%22", data, re.DOTALL)
if not m: raise SystemExit("CompressedDataTable not found")
raw = m.group(1).decode("ascii", "ignore")

# 2) Minimal URL-decode to real base64
b64 = (raw.replace("%2b","+").replace("%2B","+")
           .replace("%2f","/").replace("%2F","/")
           .replace("%3d","=").replace("%3D","="))

# 3) Decode outer: base64 -> gunzip -> bytes
outer = gzip.decompress(base64.b64decode(b64))

# 4) Save outer strings
def strings(b, n=3):
    out=[]; buf=[]
    for ch in b:
        if 32 <= ch <= 126 or ch in (9,10,13):
            buf.append(chr(ch))
        else:
            if len(buf)>=n: out.append("".join(buf))
            buf=[]
    if len(buf)>=n: out.append("".join(buf))
    return "\n".join(out)

open(os.path.join(OUTDIR,"analyse_outer.txt"),"w",encoding="utf-8",errors="ignore").write(strings(outer))

# 5) Pull inner LosFormatter base64 inside <anyType ...>...</anyType>
m2 = re.search(rb"<anyType\b[^>]*>(.*?)</anyType>", outer, re.DOTALL|re.IGNORECASE)
if not m2: raise SystemExit("anyType inner payload not found")
inner_b64 = m2.group(1).strip()
open(os.path.join(OUTDIR,"inner_b64.txt"),"wb").write(inner_b64)

# 6) Decode inner LosFormatter (not gzipped), dump strings
inner = base64.b64decode(inner_b64)
open(os.path.join(OUTDIR,"analyse_inner.txt"),"w",encoding="utf-8",errors="ignore").write(strings(inner))

print("Wrote: out/analyse_outer.txt, out/inner_b64.txt, out/analyse_inner.txt")
