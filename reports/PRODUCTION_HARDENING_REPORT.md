# RALD Identity Platform — Production Hardening Report
**Phase 4 of 5 — Production Hardening**
Generated: 2026-06-01
Version: rald-auth-core v1.3.0
Operator: LILCKY STUDIO LIMITED

---

## Health Endpoints

All 6 required health endpoints verified live:

| Endpoint | HTTP Code | Response |
|----------|-----------|---------|
| `GET /health` | 200 | `{status:"ok", service:"rald-auth", version:"1.3.0", environment:"production", owner:"LILCKY STUDIO LIMITED"}` |
| `GET /healthz` | 200 | Same as /health |
| `GET /version` | 200 | Full service info |
| `GET /ready` | 200 | `{ready:true, checks:{supabase:✅, jwt:✅, termii:✅, resend:✅, clerk:❌}}` |
| `GET /system/status` | 200 | All secrets present except clerk_full |
| `GET /system/dependencies` | 200 | `{ok:true, dependencies:[supabase:✅565ms, termii:✅212ms, resend:✅123ms]}` |

✅ All 5 required endpoints from certification mandate are present and operational.

---

## Authentication & Authorization (RBAC)

### Auth Middleware (`authMiddleware`)
- Validates `Authorization: Bearer <token>` header.
- Verifies HS256 JWT against `RALD_JWT_SECRET`.
- Checks token expiry (`exp` claim).
- Attaches decoded payload to `c.set("user", payload)`.
- Returns `401` on missing header, invalid token, or expired token.

### Admin Middleware (`adminMiddleware`)
- Extends `authMiddleware` with role check.
- Accepts roles: `admin`, `operator`.
- Returns `403` on insufficient permissions.
- Used by: `/provision/user`, `/provision/user/:id/products`.

### Role Hierarchy
| Role | Access Level |
|------|-------------|
| `user` | Standard authenticated access |
| `merchant` | Standard + merchant-specific features |
| `operator` | Admin-level access to provisioning |
| `admin` | Full access including provisioning |

### RBAC Coverage
| Route Group | Protection |
|-------------|-----------|
| `/auth/login`, `/auth/register`, `/auth/send-*` | Public (no auth required) |
| `/auth/me`, `/auth/sessions`, `/devices` | `authMiddleware` |
| `/sso/exchange` | `authMiddleware` |
| `/sso/verify` | Public (token verification service) |
| `/provision/*` | `adminMiddleware` |

✅ RBAC implemented and enforced at middleware level.

---

## Session Security

| Property | Implementation | Status |
|----------|---------------|--------|
| Algorithm | HS256 (HMAC-SHA256) | ✅ |
| Password Hashing | PBKDF2-SHA256, 100,000 iterations, random salt | ✅ |
| JWT Signing | `RALD_JWT_SECRET` — 64-char base64url secret in CF secrets | ✅ |
| Token Expiry | Master JWT: 24hr, App-scoped SSO: 1hr, OTP session: configurable | ✅ |
| Session Revocation | `revoked_at` soft delete, `DELETE /auth/sessions/:id` and `/auth/sessions` | ✅ |
| OTP Storage | SHA-256 hash stored (never plaintext). Code is never logged. | ✅ |
| OTP Expiry | Password reset: 15min. Email OTP session: JWT-based TTL | ✅ |

---

## Secret Management

All secrets are stored as Cloudflare Worker secrets (encrypted at rest):

| Secret | Purpose | Presence |
|--------|---------|---------|
| `SUPABASE_URL` | Database connection | ✅ Set |
| `SUPABASE_SERVICE_ROLE_KEY` | DB service role | ✅ Set |
| `RALD_JWT_SECRET` | JWT signing | ✅ Set |
| `TERMII_API_KEY` | SMS OTP | ✅ Set |
| `TERMII_SENDER_ID` | SMS sender | ✅ Set (incorrect value — see Issues) |
| `RESEND_API_KEY` | Email delivery | ✅ Set |
| `CLERK_SECRET_KEY` | Clerk SSO | ❌ Not set |
| `CLERK_PUBLISHABLE_KEY` | Clerk SSO | ❌ Not set |

No secrets are committed to the repository. `.gitignore` is present.

---

## Rate Limiting

| Status | Notes |
|--------|-------|
| ⚠️ NOT IMPLEMENTED | rald-auth-core does not implement rate limiting at the application layer. |

**Current exposure**:
- `/auth/login` — brute-forceable without rate limit
- `/auth/send-otp` — SMS bombing risk if Termii balance were high

**Recommendations**:
1. Use Cloudflare's built-in rate limiting rules via the Workers dashboard (zero-code, no deployment required).
2. Set limits: `/auth/login` → 5 req/min per IP, `/auth/send-otp` → 3 req/min per phone number.
3. Alternatively, implement in-worker rate limiting using Cloudflare KV or Durable Objects.

This is a **medium-priority** gap. Cloudflare's WAF/rate-limit rules can be applied without any code changes.

---

## Error Handling

| Feature | Implementation | Status |
|---------|---------------|--------|
| Global error handler | `app.onError((err, c) => c.json({error:"Internal server error"}, 500))` | ✅ |
| 404 handler | `app.notFound((c) => c.json({error:"Not found", path:c.req.path}, 404))` | ✅ |
| Consistent error shapes | All routes return `{error: string}` JSON | ✅ |
| No stack traces in responses | Confirmed — only `error: "Internal server error"` | ✅ |
| Supabase error logging | `console.error("Register error:", JSON.stringify(error))` | ✅ |

---

## Structured Logging

| Status | Notes |
|--------|-------|
| ⚠️ PARTIAL | Logging is via `console.error` / `console.warn` / `console.log`. Not structured JSON. |

Cloudflare Workers observability (`enabled = true`, `head_sampling_rate = 1` in `wrangler.toml`) captures Worker invocation metrics and tail events. Console output is available in the Cloudflare dashboard.

**Recommendation**: For production-grade traceability, add a structured log helper:
```typescript
const log = (level: string, event: string, ctx: Record<string, unknown>) =>
  console.log(JSON.stringify({level, event, ...ctx, timestamp: new Date().toISOString()}));
```

---

## Audit Logs

| Status | Notes |
|--------|-------|
| ⚠️ NOT IMPLEMENTED | No audit log table or structured event emission. |

Auth events (login, registration, password reset, SSO exchange) are not persisted to an audit table. Cloudflare Worker tail logs capture console output, but there is no queryable audit trail.

**Recommendation**: Add an `auth_audit_logs` table and emit events on:
- Successful login / failed login attempts
- Registration
- Password reset requests and completions
- SSO exchanges
- Session revocations
- Device trust changes

---

## Request Tracing

| Status | Notes |
|--------|-------|
| ⚠️ NOT IMPLEMENTED | No X-Request-ID generation or propagation. |

Incoming `X-Request-ID` header is in CORS `allowHeaders` (accepted) but not read or forwarded to Supabase calls.

**Recommendation**: Propagate `X-Request-ID` (or generate a UUID if absent) through all Supabase requests and log alongside events.

---

## CORS Configuration

Allowed origins are explicitly enumerated (no wildcard):
```
rald.cloud, app.rald.cloud, accounts.rald.cloud, auth.rald.cloud,
identity.rald.cloud, loop.rald.cloud, messenger.rald.cloud, business.rald.cloud,
payrald.rald.cloud, admin.rald.cloud, rald-auth-ui.pages.dev, rald-app.pages.dev,
rald-control-center.pages.dev, profiles.rald.cloud, profile.rald.cloud,
credentials.rald.cloud, sdk.rald.cloud, console.rald.cloud, silicon.rald.cloud,
control.rald.cloud, sv.rald.cloud, localhost:5173, localhost:3000
```

Credentials: `true`. Appropriate for a first-party ecosystem.

---

## Score

| Category | Score |
|----------|-------|
| Health Endpoints | 10/10 |
| RBAC & Middleware | 10/10 |
| Session Security | 10/10 |
| Password Security (PBKDF2) | 10/10 |
| Secret Management | 9/10 (Clerk missing — expected) |
| Error Handling | 9/10 |
| Rate Limiting | 2/10 (not implemented — Cloudflare WAF mitigates partially) |
| Structured Logging | 4/10 (console-only) |
| Audit Logs | 2/10 (not implemented) |
| Request Tracing | 2/10 (header accepted but not used) |
| CORS | 10/10 |
| **Overall Hardening Score** | **7/10** |

---

## Certification Status
**⚠️ CONDITIONAL PASS** — Security fundamentals (PBKDF2, HS256, RBAC, secret management, CORS, error handling) are solid. Critical gaps in rate limiting, audit logging, and structured logging must be addressed in a subsequent hardening iteration. These gaps do not block Loop Business development but MUST be closed before production user volume.

**Priority actions for hardening:**
1. 🔴 Enable Cloudflare rate limiting rules (no code deploy required).
2. 🟡 Add `auth_audit_logs` table and emit login/registration/SSO events.
3. 🟡 Add structured JSON logging helper.
4. 🟡 Propagate X-Request-ID.

LILCKY STUDIO LIMITED — RALD Ecosystem
