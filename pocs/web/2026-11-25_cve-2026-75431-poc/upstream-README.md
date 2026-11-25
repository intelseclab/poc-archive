# PowerJob JWT Signing Key Predictable (Key Derived from Default JDBC URL) → Token Forgery

## 1. Summary

The PowerJob Server's JWT (HS256) signing key is derived by BASE64-decoding a **hardcoded constant concatenated with the MD5 of the default JDBC URL** (`DefaultSecretProvider` / `JwtServiceImpl`). The JDBC URL is public in the default deployment (docker-compose / `application-daily.properties`), so an attacker can **derive the key fully offline** and forge a valid JWT for any user (including the admin); the OpenAPI App Token can likewise be forged to bypass OpenAPI authentication.

## 2. Affected Product

- **Product:** PowerJob Server (web console 7700 + OpenAPI)
- **Affected versions:** 5.1.2
- **Default deployment:** `application-daily.properties` exposes `jdbc:mysql://powerjob-mysql:3306/powerjob-daily?...` in plaintext

## 3. Vulnerability Location

- `powerjob-server-auth/.../jwt/impl/DefaultSecretProvider.java:31-45`: `return md5(environment.getProperty("spring.datasource.core.jdbc-url"));`
- `powerjob-server-auth/.../jwt/impl/JwtServiceImpl.java:44-102`: hardcoded `BASE_SECURITY` constant; `genSecretKey(secret) = Decoders.BASE64.decode(BASE_SECURITY.concat(secret))` → `Keys.hmacShaKeyFor`
- The key shares the repository/database with business data; the JDBC URL is plaintext in config/docker-compose.

## 4. Root Cause

- A **predictable / derivable** key is used instead of a random, persisted one: the key depends only on a public constant + the MD5 of the public default URL.
- The JWT payload (`username`/`encryptedToken`) has a secondary check for PWJB accounts (`DigestUtils.rePassword(password, username)`), but:
  - under the default password this value is computable offline → full admin takeover;
  - the OpenAPI App Token (claims `appId/password/encryptType`) can be forged directly to bypass authentication (`OpenApiSecurityServiceImpl:87-105`);
  - other third-party login accounts may have no secondary check.

## 5. Reproduction (verified — complete end-to-end)

Environment: local PowerJob server (`127.0.0.1:7700`, JDBC URL `jdbc:mysql://127.0.0.1:3307/powerjob_daily?useUnicode=true&characterEncoding=UTF-8&serverTimezone=Asia/Shanghai&allowMultiQueries=true`). The attacker derives everything **offline from public information only**:

```python
# ① Derive encryptedToken (= rePassword(password, username)); computable with the default password
rePassword("powerjob_admin", "ADMIN")
   = ADMIN_b82a450701f6a71723fb99931fe35e18_b      # byte-for-byte equal to DB user_info.token_login_verify_info ✅

# ② Derive the HS256 signing key = BASE64(BASE_SECURITY + MD5(JDBC_URL))
secret = BASE_SECURITY + md5(jdbc_url)             # 101-byte key

# ③ Forge an ADMIN web JWT (claims: username=PWJB_ADMIN, encryptedToken=result of ①, sub=PowerJob)
```

**Actual result (forged token passes authentication):**
```
[*] /namespace/list no token :
{"success":false,"data":null,"message":"PowerJobAuthException: UserNotLoggedIn","code":"-100"}

[*] /namespace/list forged JWT :
{"success":true,"data":{"index":0,"pageSize":10,"totalPages":1,"totalItems":1,"data":[{"id":1,"code":"default_namespace","name":"default_namespace","dept":null,"tags":null,"extra":null,"status":1,"statusStr":"ENABLE","gmtCreate":"2026-08-07T13:07:32.000+00:00","gmtCreateStr":"2026-08-07 21:07:32","gmtModified":"2026-08-07T13:07:32.000+00:00","gmtModifiedStr":"2026-08-07 21:07:32","showName":"default_namespace(default_namespace)","token":"14e4ebff-9a79-4845-ac66-8b20c4dff2ee","componentUserRoleInfo":{"observer":[],"qa":[],"developer":[],"admin":[]},"creatorShowName":null,"modifierShowName":null}]},"message":null}
```
→ the forged token authenticates as admin and returns real data (baseline is rejected with `UserNotLoggedIn`).

**Key points:**
- The offline-derived `encryptedToken` matches the DB-stored value **byte-for-byte** (`ADMIN_b82a450701f6a71723fb99931fe35e18_b`).
- The key is determined entirely by the **public constant `BASE_SECURITY` + MD5 of the public default JDBC URL** → derivable offline with no credentials.
- The PWJB `encryptedToken` is recomputable offline with the default password (`powerjob_admin`, finding PJ-02) → **full admin takeover**.
- If the admin changed the password, forging a web token is blocked by the `encryptedToken` mismatch, but the **OpenAPI App Token** path (claims `appId/password/encryptType`, `OpenApiSecurityServiceImpl:87-105`) can still be forged independently to bypass OpenAPI authentication.

**Even if the default password is changed, the vulnerability persists through other attack vectors:**
- An attacker who obtains **any valid user's `encryptedToken`** via other means (e.g., SQL injection, database backup exposure, log leakage, or information disclosure from other endpoints) can combine that token with the predictable signing key to forge a JWT for that specific user.
- This bypasses the `encryptedToken` mismatch issue entirely, because the forged token now contains a legitimate `encryptedToken` derived from the actual database record.
- As a result, the attacker does not need to know the user's plaintext password at all, and the forged JWT remains valid even after the user changes their password (until the token expires).

**PoC:** `powerjob_jwt_key.py 192.168.49.128:7700`

<img width="883" height="330" alt="image" src="https://github.com/user-attachments/assets/edce9f4e-0ff2-4410-8a45-0c8b51fb00f3" />

<img width="1234" height="381" alt="image" src="https://github.com/user-attachments/assets/54663ad5-40f1-420c-9756-77724a502d5f" />


## 6. Impact

- Authentication bypass / arbitrary-user token forgery → web console / OpenAPI administration surfaces.

## 7. Suggested Fix

- Generate the key randomly and persist it (file/environment), never derive it from the JDBC URL or a constant.
- Use a separate key for OpenAPI App Tokens vs. web JWTs.
- Enforce the `encryptedToken` secondary check for all accounts.

## 8. CWE / CVSS

- CWE: **CWE-321** (Use of Hard-coded Cryptographic Key) / **CWE-798**
- CVSS: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 Critical** (combined with the default password / OpenAPI)
