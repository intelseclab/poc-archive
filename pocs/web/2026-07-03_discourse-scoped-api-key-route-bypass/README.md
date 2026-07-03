# Discourse Scoped API Key Pre-Route Authorization Bypass

---

## Metadata

| Field | Value |
|---|---|
| **Date Added** | 2026-07-03 |
| **Last Updated** | 2026-06 |
| **Author / Researcher** | bikini (@ashdfrkl) — original discovery; mirrored via exploitarium |
| **CVE / Advisory** | None assigned as of 2026-07-03 |
| **Category** | web |
| **Severity** | High |
| **CVSS Score** | Not yet scored (no CVE/CVSS assigned) |
| **Status** | PoC |
| **Tags** | discourse, authorization-bypass, api-key-scope, rails, middleware, privilege-escalation, route-confusion |
| **Related** | N/A |

---

## Affected Target

| Field | Value |
|---|---|
| **Software / System** | Discourse (forum platform) |
| **Versions Affected** | Commit `3dfcc8f884313da69711ed5f26f3749fb6516ef2` (verified against `docker.io/discourse/discourse_dev:20260609-1222`) |
| **Language / Platform** | Ruby on Rails (target), Python 3.10+ (PoC driver using stdlib HTTP only) |
| **Authentication Required** | Yes (attacker needs a valid granular all-users API key scoped only to `topics:read`) |
| **Network Access Required** | Yes (HTTP access to the Discourse instance) |

---

## Summary

Discourse's overload-protection middleware authenticates API requests before Rails routing has resolved the actual HTTP verb, and its scoped API key matcher (`lib/route_matcher.rb`) calls `Rails.application.routes.recognize_path(request.path_info)` without passing the real request method. By sending a caller-controlled `X-Request-Start` header that makes the request appear queued long enough to trigger the overload-protection authentication path, an attacker holding a read-only scoped API key (`topics:read`) can have that key's permission check resolve against the GET route for a topic path even though the actual request is a `PUT /t/:topic_id.json`. The middleware then caches the authenticated API user in the Rack environment, and the later `TopicsController#update` action executes using that cached user, effectively turning a read-scoped API key into a write-capable request. In the researcher's validated run, a control `PUT` without the header was correctly rejected (403) while the same request with `X-Request-Start: t=0` succeeded (200) and changed the topic title. This PoC was published by a pseudonymous independent researcher (bikini/ashdfrkl) as part of the uncoordinated "exploitarium" vulnerability dump; it has not been vendor-confirmed.

---

## Vulnerability Details

### Root Cause

`lib/route_matcher.rb`'s pre-route scope check resolves the request path via `recognize_path` without the actual HTTP method, so a `PUT` request can be matched against a `GET`-only route (`topics#show`) for scope-permission purposes; combined with the overload-protection middleware caching the resulting authenticated user in the Rack environment, this pre-route authorization decision is later reused by the real controller action regardless of the request's true verb.

### Attack Vector

1. Attacker obtains or is issued a granular all-users Discourse API key scoped only to `topics:read`, plus a privileged API username able to edit the target topic.
2. Attacker sends `PUT /t/:topic_id.json` with the scoped API key and an attacker-controlled `X-Request-Start` header set to a value that makes `OverloadProtections` treat the request as queued/overloaded.
3. The overload middleware invokes the current-user provider, which calls `api_key.request_allowed?` → `ApiKeyScope#permits?` → `RouteMatcher#path_params_from_request`, resolving the path as `topics#show` (a `topics:read`-permitted route) without checking the real `PUT` verb.
4. The middleware caches the resolved API user into `_DISCOURSE_CURRENT_USER` in the Rack environment.
5. Rails then routes the request normally to `TopicsController#update`, which reads `current_user` from the same Rack environment (the cached API user) and performs the update, including `guardian.ensure_can_edit!`, which passes because the cached user has edit rights.

### Impact

A read-scoped (`topics:read`) API key can be used to perform write operations (topic updates) as the API key's associated username, effectively bypassing granular API key scope restrictions for any writable route whose path shape overlaps a read-permitted route.

---

## Environment / Lab Setup

```
Target:   Discourse @ 3dfcc8f884313da69711ed5f26f3749fb6516ef2 (docker.io/discourse/discourse_dev:20260609-1222)
Attacker: Python 3.10+ (stdlib only), a topics:read-scoped all-users API key, one visible target topic
```

---

## Proof of Concept

### PoC Script

> See `poc.py` in this folder.

```bash
python poc.py \
  --base-url http://127.0.0.1:3000 \
  --api-key '<topics-read-api-key>' \
  --api-username admin \
  --topic-id 8 \
  --new-title 'Scope bypass direct proof title' \
  --output proof.json
```

The script reads the target topic's current title, sends a control `PUT /t/:topic_id.json` without `X-Request-Start` and confirms it is rejected (403) and the title unchanged, then sends the same request with `X-Request-Start: t=0` and confirms it succeeds (200) and the title is changed — writing a JSON proof object with both results.

---

## Detection & Indicators of Compromise

```
# Discourse access logs showing PUT/POST requests from API keys with narrow read-only scopes
# succeeding (2xx) rather than being rejected (403)
# Requests carrying an attacker-supplied X-Request-Start header from clients outside the
# trusted reverse-proxy boundary
```

**Signs of compromise:**
- Topic or other resource updates attributed to API usernames whose associated key is scoped read-only
- Inbound requests with client-supplied `X-Request-Start` headers not stripped/overwritten by the reverse proxy
- Audit log entries for writes performed via API keys that should be incapable of writes per their granular scope

---

## Remediation

| Action | Detail |
|---|---|
| **Primary fix** | No vendor patch confirmed as of 2026-07-03 — monitor for advisory from Discourse |
| **Interim mitigation** | Ensure the reverse proxy strips/overwrites any client-supplied `X-Request-Start` header before it reaches Discourse; resolve routes with the real HTTP method during pre-route scope checks; avoid caching an authenticated user during overload handling for later reuse by unrelated controller actions |

---

## References

- [Source repository (bikini/exploitarium)](https://github.com/bikini/exploitarium/tree/main/discourse-scoped-api-key-preauth-bypass)

---

## Notes

Mirrored from https://github.com/bikini/exploitarium (folder: `discourse-scoped-api-key-preauth-bypass`) on 2026-07-03. No CVE has been assigned as of ingestion — this is an uncoordinated disclosure by a pseudonymous researcher; treat with appropriate caution pending vendor confirmation.
