# TC-AUTH-01: Authentication enforcement

| Field | Value |
|---|---|
| Requirement | PPS-F-021 (authentication) |
| Story | #54 |
| Branch | `feature/PPS-F-021-auth-audit-evidence` |
| Date | 2026-10-30 |
| Tester | Chinmayi Hebbar A M |
| Environment | Windows, Python 3.12.6, Flask dashboard on `http://127.0.0.1:5000` |

## Objective
Show that protected API routes reject unauthenticated or invalid requests, that a wrong password is refused, and that a correct password grants access.

## Checks

### 1. Protected route without a token
```
curl.exe -i http://127.0.0.1:5000/api/packets
```
Response: `HTTP/1.1 401 UNAUTHORIZED`, body `{"errorCode":"UNAUTHORIZED","message":"Authentication required"}`.
Security headers were also present (`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Content-Security-Policy`, `Cache-Control: no-store`).

**Result: PASS.**

### 2. Protected route with an invalid token
```
curl.exe -i -H "Authorization: Bearer abc" http://127.0.0.1:5000/api/packets
```
Response: `HTTP/1.1 401 UNAUTHORIZED`, same JSON body.

**Result: PASS.**
Evidence (checks 1 and 2): `auth01-401.png`

### 3. Wrong password
Signing in with an incorrect password is rejected and the sign-in page shows an error. No token is issued.
Evidence: `auth01-wrong-password.png`

**Result: PASS.**

### 4. Correct password
Signing in with the correct password loads the dashboard and the protected data endpoints respond.
Evidence: `auth01-login-ok.png`

**Result: PASS.**

### 5. Regression
`python -m pytest`: 47 passed, 1 skipped (POSIX-only test).

## Conclusion
Every `/api` route except config, auth state, setup, login and the single-use download link requires a valid JWT. Missing and malformed tokens return 401, and wrong credentials are rejected.
