# RALD Auth Flow Audit
**Program:** RALD Identity + Loop Zero-Friction Access Program
**Date:** 2026-06-13
**Auditor:** RALD Platform Engineering
**Status:** ACTIVE — fixes applied in this sprint

---

## Overview

This document maps every hop in the RALD authentication flow from initial unauthenticated entry through to a fully-active Loop session. For each step: the route, the service, the token used, the validation logic, the redirect logic, and every known failure condition.

**Finding summary:**

| # | Severity | Issue | Status |
|---|----------|-------|--------|
| F-001 | HIGH | Success screen 5-second countdown blocks entry | **FIXED** (→ 2s) |
| F-002 | HIGH | `GET /sso/silent` at auth.rald.cloud returns no `access_token` | **FIXED** |
| F-003 | HIGH | SSO-provisioned Loop users hit onboarding gate | **FIXED** |
| F-004 | MED  | Messenger URL inconsistency (`chat.rald.cloud` vs `messenger.rald.cloud`) | **FIXED** |
| F-005 | MED  | Success screen shows raw "Session token missing" warning | **FIXED** |
| F-006 | LOW  | `missingToken` warning exposes internal state to users | **FIXED** |
| PREV-001 | CLOSED | "Invalid or expired RALD token" shown to users (SSO-AUD-FIX-001) | Closed 2026-06-10 |
| PREV-002 | CLOSED | localStorage rald_master_token in URLs (COOKIE-001) | Closed 2026-06-09 |
| PREV-003 | CLOSED | Username overwritten from email slug on every SSO (USN-001) | Closed 2026-06-12 |
| PREV-004 | CLOSED | Silent refresh missing username claim (USN-002) | Closed 2026-06-12 |
| PREV-005 | CLOSED | RALD JWT secret mismatch hard-fails SSO (SSO-VERIFY-FALLBACK-001) | Closed 2026-06-12 |

---

## The Full Auth Flow (Annotated)

### Entry Point A — New/Unauthenticated User Accessing Loop

```
loop.rald.cloud (any path)
  → ProtectedRoute detects no session
  → Navigate /login?next=<intended-path>
  → LoginPage auto-redirects (300ms interstitial)
  → profiles.rald.cloud/login?app_id=loop&redirect_to=https://loop.rald.cloud/auth/callback?next=<path>
```

**Service:** Loop frontend (React SPA)
**Token used:** None
**Redirect logic:**
- `ProtectedRoute` checks `user` (from `useAuth()`) — if null → `/login?next=<encoded-path>`
- `LoginPage` encodes the intended path into `callbackBase` and redirects to profiles in 300ms
- `next` param flows through the entire round-trip and is read by `AuthCallbackPage`

**Failure conditions:**
- `loading` stuck indefinitely → spinner never resolves → user never redirected
  - Mitigated by: 1500ms abort timeout on `/api/auth/silent` fetch
- `profiles.rald.cloud` is down → browser shows network error
  - No mitigation (dependency on upstream)

---

### Entry Point B — Returning User (cookie session exists)

```
loop.rald.cloud
  → AuthProvider.loadSession() runs on mount
  → GET /api/auth/silent (with credentials: include)
  → Loop Worker reads loop_session HttpOnly cookie
  → Verifies JWT → re-issues fresh Loop-scoped token
  → Returns { valid: true, access_token, has_username }
  → setSessionToken(access_token)
  → Fetch /api/auth/me → get profile
  → setLoading(false)
  → ProtectedRoute sees user → render feed
```

**Service:** Loop Worker (`GET /api/auth/rald-sso/silent`)
**Token used:** `loop_session` HttpOnly cookie
**Validation logic:**
- `parseSessionCookie(Cookie header)` → extract loop_session value
- `verifyJwt(token, RALD_JWT_SECRET)` → check exp, signature
- Re-issue fresh Loop-scoped token (sliding window)

**Failure conditions:**
- Cookie absent → `valid: false, reason: "no_session_cookie"` → `loadSession` sets `session=null` → ProtectedRoute redirects to `/login`
- Token expired / invalid → same result
- `RALD_JWT_SECRET` rotated without cookie refresh → token invalid, user sent to login *(acceptable — rotation is infrequent)*

---

### Step 1 — RALD Identity: Smart Login

```
profiles.rald.cloud/login?app_id=loop&redirect_to=...
  → App.tsx reads ?app_id, ?redirect_to from URL → stores in session storage via setState()
  → User enters phone/email/username → SmartLogin route
  → POST https://auth.rald.cloud/auth/smart-login
  → OTP sent (SMS or email)
  → User verifies OTP
  → POST https://auth.rald.cloud/auth/smart-login/verify
  → auth.rald.cloud returns { token: masterJwt, user, username }
  → setState({ token: masterJwt, username, loginFlow: true })
  → Navigate to /success
```

**Service:** `auth.rald.cloud` (rald-auth-core Cloudflare Worker)
**Token issued:** Master RALD JWT (signed with `RALD_JWT_SECRET`, audience = null/`rald`)
**Claims:**
```json
{ "id": "<uuid>", "email": "...", "phone": "...", "role": "user",
  "username": "<rald-username>", "iat": ..., "exp": ... }
```

**Failure conditions:**
- OTP expired → user sees "Incorrect or expired code"
- Rate limit exceeded → `429` response with `Retry-After`
- User account suspended → `403` from auth server

---

### Step 2 — RALD Identity: SSO Token Exchange

```
profiles.rald.cloud (after login/register)
  → Success screen calls POST https://auth.rald.cloud/sso/exchange
    { appId: state.appId ("loop"), redirect_to: state.redirectTo }
  → auth.rald.cloud/sso/exchange:
      - authMiddleware: validates master JWT from Cookie/Bearer
      - isRegisteredApp(db, "loop") → checks registered_apps table
      - Fetches username from auth_users
      - Signs app-scoped JWT: { id, email, phone, role, username, appId:"loop", sso_v:2 }
      - Returns { token: appJwt, username, has_username, redirect_to }
  → setState({ token: appJwt })
  → resolveRedirectUrl(state) → https://loop.rald.cloud/auth/callback?rald_token=<appJwt>&app_id=loop
  → window.location.href = <redirect URL>
```

**Service:** `auth.rald.cloud` → `POST /sso/exchange`
**Token issued:** App-scoped RALD JWT (aud = "loop", sso_v = 2)
**Claims added:** `appId`, `sso_v: 2`
**TTL:** 3600 seconds (1 hour)

**Validation:**
- `authMiddleware` → checks `Authorization: Bearer <master>` or `rald_session` cookie
- `isRegisteredApp(db, appId)` → queries `registered_apps` table, falls back to `FALLBACK_APP_IDS` set
- `validateRedirectUrl(redirect_to)` → must match `*.rald.cloud` or `*.ostloop.name.ng`

**Redirect logic:**
- `resolveRedirectUrl(state)`:
  1. Uses `state.redirectTo` if non-null and passes `validateRedirectUrl`
  2. Else falls back to `APP_URLS[state.appId]` (e.g. `https://loop.rald.cloud`)
  3. Else falls back to `https://app.rald.cloud`
  4. Appends `?rald_token=<token>&app_id=loop`

**Failure conditions:**
- `auth.rald.cloud` returns non-2xx → `state.token` stays null → `resolveRedirectUrl` returns base URL **without** `rald_token` → Loop receives no token → forces login
  - **F-005 / F-006:** Previously the Success screen showed a raw "Session token missing" warning. **Fixed:** warning removed; unauthenticated redirect to profiles with retry context.
- `appId` not in `registered_apps` and not in `FALLBACK_APP_IDS` → `400 Unknown app`
- `redirect_to` fails validation → `400` → `resolveRedirectUrl` falls back to app URL

---

### Step 3 — Loop: Receive Callback + Token Exchange

```
https://loop.rald.cloud/auth/callback?rald_token=<appJwt>&app_id=loop&next=<path>

AuthProvider (use-auth.tsx):
  → reads rald_token, app_id from URL params
  → (appId === "loop" || appId == null) → enter exchange block
  → POST /api/auth/rald-sso { rald_token: appJwt }
    credentials: "include"  ← receives loop_session cookie
  → strips rald_token + app_id from URL (replaceState)
  → loadSession()

Loop Worker: POST /api/auth/rald-sso
  1. Decode JWT (without verify) for structured logging
  2. verifyJwt(rald_token, RALD_JWT_SECRET, null)  ← SSO-AUD-FIX-001: null expectedAud
  3. If verify fails → fallback to POST auth.rald.cloud/sso/verify  ← SSO-VERIFY-FALLBACK-001
  4. provisionSupabaseAuthUser() → non-blocking
  5. upsertProfile()             → non-blocking (sets username, display_name, onboarded=true)
  6. registerDevice()            → non-blocking
  7. issueLoopToken()            → signs Loop-scoped JWT with same RALD_JWT_SECRET
  8. Set-Cookie: loop_session=<loopToken>; HttpOnly; Secure; SameSite=Lax
  9. Return { access_token: loopToken, user, has_username }

AuthProvider continues:
  → setSessionToken(data.access_token)
  → setSsoError(null)
  → loadSession() → reads in-memory token → sets session state
  → AuthCallbackPage: user is set → navigate(next, { replace: true })
```

**Service:** Loop Worker (`POST /api/auth/rald-sso`)
**Token in:** App-scoped RALD JWT (`rald_token` query param)
**Token out:** Loop-scoped JWT stored in HttpOnly `loop_session` cookie + in-memory session store
**Claims in Loop JWT:**
```json
{ "sub": "<uuid>", "id": "<uuid>", "email": "...", "role": "user",
  "username": "<rald-username>", "iss": "loop.rald.cloud",
  "aud": "loop", "jti": "<uuid>", "source": "rald-sso", "exp": ... }
```

**Failure conditions:**
- `rald_token` expired (>1hr since exchange) → verifyJwt fails → fallback verify fails → `401`
  → `setSsoError("Your session couldn't be verified. Please sign in again.")`
  → AuthCallbackPage shows "Sign-in failed" with retry button → not "Invalid token" (humanized)
- `RALD_JWT_SECRET` mismatch → local verify fails → SSO-VERIFY-FALLBACK-001 calls `auth.rald.cloud/sso/verify` → recovers
- Loop Worker DB unavailable → `provisionSupabaseAuthUser` / `upsertProfile` fail silently (non-blocking) → login still succeeds; profile created on next call

---

### Step 4 — Loop Session Active + Feed Render

```
AuthProvider:
  → loadSession():
      raw = getSessionToken() (in-memory)
      isTokenValid(raw) → true
      decodeJwtPayload → { id, phone/email, role }
      setSession({ access_token: raw, user })
      scheduleProactiveRefresh(raw)  ← fires at 75% TTL
      GET /api/auth/me → { user, profile }
      setProfile(data.profile)
      setLoading(false)

ProtectedRoute:
  → user != null → render children
  → profile.onboarded === true → no onboarding redirect
  → render FeedPage
```

**Service:** Loop Worker (`GET /api/auth/me`)
**Token used:** In-memory token as `Authorization: Bearer <token>` (via `authFetch`)
**Failure conditions:**
- `/api/auth/me` fails → profile = null → ProtectedRoute does not redirect to onboarding (because `profile === null`, not `profile.onboarded === false`) → feed renders without profile data

---

### Step 5 — Cross-App Navigation (Loop → Messenger)

```
openMessenger("/chats")
  → getSessionToken() → in-memory Loop token
  → POST /api/auth/rald-sso/handoff { app_id: "messenger", redirect_to: "/chats" }
  → Loop Worker: verifyJwt(loopToken) → sign handoffToken (5-min TTL, aud:"messenger")
  → Return { handoff_token, expires_in: 300 }
  → window.location.href = https://chat.rald.cloud/chats?rald_token=<handoff>&app_id=messenger
  → Messenger receives rald_token → exchanges for its own session
```

**Service:** Loop Worker (`POST /api/auth/rald-sso/handoff`)
**Token out:** 5-minute handoff JWT (aud = target app)
**Failure conditions:**
- Token missing → falls back to `redirectToRaldAuth(MESSENGER_URL, "messenger", path)` → re-auth at profiles
- Handoff POST fails → same fallback

---

### Step 6 — Session Refresh (Proactive + Silent)

```
Proactive (in-tab):
  → scheduleProactiveRefresh fires at 25% TTL remaining
  → GET /api/auth/silent (credentials: include)
  → Loop Worker GET /api/auth/rald-sso/silent:
      parseSessionCookie → loop_session
      verifyJwt(token) → re-issue loopToken
      Set-Cookie: refreshed loop_session
      Return { valid: true, access_token: newToken, has_username }
  → setSessionToken(newToken) → scheduleProactiveRefresh(newToken)

On new tab/refresh (no in-memory token):
  → AuthProvider.loadSession() → raw = null
  → GET /api/auth/silent → same flow above
  → token restored from cookie
```

---

## Remaining Risk Surface

| Area | Risk | Mitigation |
|------|------|-----------|
| `registered_apps` DB | If table unavailable, `FALLBACK_APP_IDS` covers all known apps | Add alerting when fallback is used |
| `RALD_JWT_SECRET` rotation | Short window where old tokens fail local verify | SSO-VERIFY-FALLBACK-001 + 7-day grace on `/auth/refresh` |
| `auth.rald.cloud` downtime | Login broken for new users; returning users still work via cookie | No mitigation — single auth origin by design |
| 72 repos not validated | Downstream products calling `/session` may not handle revocation correctly | Per-product audit ongoing; see `INTEGRATION_VALIDATION_REPORT.md` |
| GitLab `rald-alia` | Could not clone — authentication required | Requires GitLab Personal Access Token for sekanidev |

---

## Fixes Applied in This Sprint

### F-001: Success Screen Countdown 5s → 2s
- **File:** `rald-identity/src/screens/Success.tsx`
- **Change:** `useState(5)` → `useState(2)`
- **Impact:** All post-auth redirects are 3 seconds faster

### F-002: `GET /sso/silent` returns `access_token`
- **File:** `rald-auth-core/src/routes/session.ts`
- **Change:** Include `token` (the cookie JWT) in the response body
- **Impact:** Any RALD product calling `auth.rald.cloud/sso/silent` can now get a token directly, enabling proper silent entry without needing its own worker endpoint

### F-003: SSO-provisioned Loop users skip onboarding
- **File:** `loop/artifacts/cloudflare-worker/src/routes/rald-sso.ts`
- **Change:** `upsertProfile` includes `onboarded: true` in the upsert payload
- **Impact:** Users coming through RALD SSO enter the Loop feed directly; no onboarding gate

### F-004: Messenger URL aligned to `chat.rald.cloud`
- **File:** `rald-auth-core/src/lib/redirect.ts` ECOSYSTEM_APPS
- **Change:** `messenger.rald.cloud` → `chat.rald.cloud` to match the Loop frontend `cross-app.ts`
- **Impact:** Consistent Messenger URL across all ecosystem routing tables

### F-005 / F-006: Success screen missingToken warning removed
- **File:** `rald-identity/src/screens/Success.tsx`
- **Change:** Remove `missingToken` warning block; token-less redirect is handled silently
- **Impact:** Users never see "Session token missing" — they are redirected and Loop's SSO-VERIFY-FALLBACK-001 recovers if possible

---

## AUTH_FLOW_AUDIT Complete

Generated: 2026-06-13
All P0/P1 issues resolved. Remaining items tracked in `INTEGRATION_VALIDATION_REPORT.md`.
