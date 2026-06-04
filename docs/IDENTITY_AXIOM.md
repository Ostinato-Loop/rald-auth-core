# RALD Identity Axiom — Architectural Record

**Owner:** LILCKY STUDIO LIMITED  
**Authority:** RALD Platform Engineering  
**Status:** ACTIVE — binding for all RALD products

---

## The Rule

> **Products do not own identity. Profiles owns identity. Products consume identity.**

A user authenticates once at `profiles.rald.cloud`. That authentication is valid across the entire RALD ecosystem.

A user sees a second login screen **only when:**
1. They explicitly log out
2. Their session expires (24 h JWT TTL)
3. A security intervention is required (suspension, device revocation)

---

## Silent SSO Flow

```
User navigates to loop.rald.cloud
          │
          ▼
SDK: initSession("loop")
          │
          ├─ ?rald_token= in URL?
          │     └─ POST /sso/exchange → store token → strip URL → ✅ enter app
          │
          ├─ localStorage token valid? → GET /session
          │     └─ ✅ enter app silently
          │
          ├─ rald_session cookie present? → worker reads Cookie header
          │     └─ ✅ enter app silently (no JS required)
          │
          └─ No session → redirect →
                profiles.rald.cloud/login?app_id=loop&redirect_to=https://loop.rald.cloud
                          │
                          ▼ (user logs in ONCE)
                POST /sso/exchange → redirect back with ?rald_token=
                          │
                          ▼ (loop.rald.cloud picks up token)
                         ✅
```

---

## Cookie Specification

```
Set-Cookie: rald_session=<JWT>
  Domain=.rald.cloud   ← browser sends to all *.rald.cloud subdomains automatically
  Path=/
  HttpOnly             ← JS cannot read — XSS protection
  Secure               ← HTTPS only
  SameSite=Lax         ← top-level navigations include cookie
  Max-Age=86400        ← 24 h — matches JWT TTL
```

**Why cookies, not localStorage:**  
localStorage is origin-scoped. `loop.rald.cloud` cannot read `profiles.rald.cloud` storage.  
`Domain=.rald.cloud` cookies are sent by the browser to every subdomain automatically.

---

## Token Types

| Token | Endpoint | Audience | TTL | Use |
|-------|----------|----------|-----|-----|
| Master JWT | /auth/login | any RALD service | 24 h | Ecosystem session |
| App JWT | /sso/exchange | specific app | 1 h | Product API calls |
| Handoff | /sso/handoff | redirect flow | 5 min | Browser hand-off |

---

## Product Compliance

| Product | Auth Ownership | Status |
|---------|---------------|--------|
| Profiles | Authority ✅ | Compliant |
| Loop | None — redirects to profiles | ✅ Fixed this sprint |
| Messenger | None — redirects to profiles | ✅ Fixed this sprint |
| PayRald | None — must redirect | Required |
| GitRald | None — must redirect | Required |

---

## Migration: Pre → Post Sprint

**Before (broken):**
- Loop owned OTP (Termii) + issued `LOOP_JWT_SECRET` tokens
- Messenger owned OTP independently
- Cross-app "SSO" = fragile `rald_master_token` in localStorage passed via URL
- No ecosystem cookie — every product had isolated sessions

**After (correct):**
- Loop auth removed entirely; worker accepts RALD JWT via `RALD_JWT_SECRET`
- Messenger OTP removed; RALD token accepted directly
- `auth.rald.cloud` sets `rald_session` cookie on every login
- Silent auth: product workers read `Cookie: rald_session` from request
- `GET /sso/silent` — server-side cookie validation without redirect

---

*Maintained in `rald-auth-core/docs/IDENTITY_AXIOM.md`*
