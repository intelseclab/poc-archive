#!/usr/bin/env python3
"""Minimal B builder with slot-shaping fields (for fs4-head experiments)."""
from __future__ import annotations

import argparse

B = b"C" * 10


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--sid", default="a")
    ap.add_argument("--progress-len", type=int, default=35)
    ap.add_argument("--pre", type=int, default=0, help="consumer fields before PHPSESSID")
    ap.add_argument("--mid", type=int, default=0, help="consumer fields between PHPSESSID and PROGRESS")
    ap.add_argument("--name-len", type=int, default=8)
    ap.add_argument("--value-len", type=int, default=1)
    args = ap.parse_args()

    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    def cons(prefix: bytes, i: int) -> None:
        n = (prefix + (b"%04d" % i)).ljust(args.name_len, b"x")[:args.name_len]
        part(n, b"v" * args.value_len)

    for i in range(args.pre):
        cons(b"p", i)
    part(b"PHPSESSID", args.sid.encode())
    for i in range(args.mid):
        cons(b"m", i)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.progress_len)
    out.extend(b"--" + B + b"--\r\n")
    with open(args.out, "wb") as fh:
        fh.write(bytes(out))
    print("body=%d pre=%d mid=%d" % (len(out), args.pre, args.mid))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
