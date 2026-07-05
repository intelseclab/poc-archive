#!/usr/bin/env python3
import socket
import argparse

def probe_http3(target_ip, target_port):
    print(f"[*] Probing {target_ip}:{target_port} for HTTP/3 QUIC support...")
    # Send a dummy QUIC initial packet
    dummy_quic = bytes.fromhex("c30000000108000000000000000000000000")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(dummy_quic, (target_ip, target_port))
        data, addr = sock.recvfrom(1024)
        if data:
            print("[+] Target responded! QUIC protocol is likely supported.")
            print(f"[>] Received {len(data)} bytes from target.")
            return True
    except socket.timeout:
        print("[-] Request timed out. Target might not be running QUIC.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP/3 Recon Tool")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", type=int, help="Target UDP port (usually 443)")
    args = parser.parse_args()
    
    probe_http3(args.ip, args.port)
