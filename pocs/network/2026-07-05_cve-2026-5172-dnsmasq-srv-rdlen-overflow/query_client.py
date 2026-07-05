#!/usr/bin/env python3
"""Standalone DNS query client that sends a UDP DNS query to dnsmasq.

Usage:
  python3 query_client.py --dnsmasq-host 127.0.0.1 --dnsmasq-port 5352 --qname _sip._tcp.example.com --qtype SRV

This client constructs a minimal DNS query packet and sends it to the
configured dnsmasq instance. It prints basic info about the reply.
"""

import argparse
import random
import socket
import struct
import sys
import time


QTYPE_MAP = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'PTR': 12,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,
    'SRV': 33,
    'ANY': 255,
}


def encode_qname(name: str) -> bytes:
    if name == '.' or name == '':
        return b'\x00'
    parts = name.rstrip('.').split('.')
    out = bytearray()
    for p in parts:
        out.append(len(p))
        out.extend(p.encode('utf-8'))
    out.append(0)
    return bytes(out)


def build_query(qname: str, qtype_name: str) -> bytes:
    qtype = QTYPE_MAP.get(qtype_name.upper(), 1)
    qid = random.getrandbits(16)
    flags = 0x0100  # standard recursive query
    qdcount = 1
    header = struct.pack('>HHHHHH', qid, flags, qdcount, 0, 0, 0)

    qname_raw = encode_qname(qname)
    question = qname_raw + struct.pack('>HH', qtype, 1)
    return header + question


def hexdump(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)


def main() -> int:
    ap = argparse.ArgumentParser(description='Send raw DNS query to dnsmasq')
    ap.add_argument('--dnsmasq-host', default='127.0.0.1')
    ap.add_argument('--dnsmasq-port', type=int, default=5352)
    ap.add_argument('--qname', default='_sip._tcp.example.com')
    ap.add_argument('--qtype', default='SRV')
    ap.add_argument('--count', type=int, default=1)
    ap.add_argument('--delay', type=float, default=0.2)
    ap.add_argument('--timeout', type=float, default=2.0)
    args = ap.parse_args()

    server = (args.dnsmasq_host, args.dnsmasq_port)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(args.timeout)

    for i in range(args.count):
        pkt = build_query(args.qname, args.qtype)
        try:
            s.sendto(pkt, server)
            print(f"[>] Sent {len(pkt)} bytes to {server}")
        except OSError as e:
            print(f"[!] send failed: {e}")
            return 2

        try:
            data, addr = s.recvfrom(8192)
        except socket.timeout:
            print('[!] no reply (timeout)')
            time.sleep(args.delay)
            continue

        print(f"[<] Received {len(data)} bytes from {addr}")
        # Basic parse: show header and rcode
        if len(data) >= 12:
            id, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', data[:12])
            rcode = flags & 0x000F
            print(f"    id=0x{id:04x} flags=0x{flags:04x} qd={qd} an={an} ns={ns} ar={ar} rcode={rcode}")
        print('    hexdump:', hexdump(data[:200]))
        time.sleep(args.delay)

    s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
