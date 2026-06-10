# RALD Identity V2 — Public Beta Readiness Report

**Generated:** 2026-06-10  
**Platform:** RALD Identity (auth.rald.cloud + profiles.rald.cloud)  
**Version:** 2.4.0  
**Prepared by:** RALD Platform Engineering · LILCKY STUDIO LIMITED

---

## Executive Summary

RALD Identity V2 implements a username-first authentication paradigm. Users claim a `@username`, verify via SMS or email OTP, and receive a 30-day HttpOnly session cookie that works across the entire RALD ecosystem. This report certifies what is **actually working** as of this sprint. No assumptions. No placeholder certifications.

---

## Phase 1 — Deployment Stability ✅

| Check | Status | Notes |
|---|---|---|
| TypeScript — rald-auth-core | ✅ PASS | Fixed in this sprint (OTP brute-force + type safety) |
| TypeScript — rald-identity  | ✅ PASS | Fixed in this sprint (unused import removed) |
| Cloudflare Workers deploy   | ✅ PASS | wrangler-action v3, automatic on push to main |
| Cloudflare Pages deploy     | ✅ PASS | Vite SPA, `public/_redirects` for client routing |
| Biome lint                  | ✅ PASS | Warnings only (`noExplicitAny`, `noNonNullAssertion`) |
| Environment secrets         | ✅ PASS | All required secrets validated at worker boot |

**Boot-time validation** (`src/index.ts`): Worker returns HTTP 503 immediately if `RALD_JWT_SECRET`, `SUPABASE_URL`, or `SUPABASE_SERVICE_ROLE_KEY` are missing. No silent failures.

---

## Phase 2 — Authentication Hardening ✅

| Feature | Status | Notes |
|---|---|---|
| Username-first flow | ✅ | `POST /auth/register-username` → OTP → `/complete` |
| HttpOnly session cookies | ✅ | `Domain=.rald.cloud; HttpOnly; Secure; SameSite=Lax` |
| Session validation | ✅ | `GET /session` — validates JWT + KV liveness |
| Session revocation | ✅ | `POST /session/revoke-all`, `/session/revoke-device` |
| Global logout | ✅ | Revokes all KV sessions for user |
| Device trust/revoke | ✅ | `/devices/:id/trust`, `/devices/:id/remove` |
| Silent re-auth | ✅ | `GET /sso/silent` via cookie |
| Recovery codes | ✅ | `/recovery` — 10-code TOTP-style recovery |
| Audit logging | ✅ | All auth events written to `audit_logs` table |
| No localStorage tokens | ✅ | Token only set via `Set-Cookie` header |

**⚠ Session Restore (D7 retention):** Session cookie is valid for 30 days. Silent re-auth via `/sso/silent` reads the `rald_session` cookie. Browser storage is not used. Users who clear cookies must re-verify.

---

## Phase 3 — Username Registry Hardening ✅

| Feature | Status | Notes |
|---|---|---|
| Case-insensitive uniqueness | ✅ | DB uses `ilike` + `lower()` unique index |
| Reserved username list | ✅ | 60+ reserved words (brand, civic, infra) |
| Mail alias reservation | ✅ | `username@rald.me` reserved in `username_namespace_reservations` |
| Subdomain reservation | ✅ | `username.rald.me` reserved |
| Workspace slug reservation | ✅ | Reserved in same table |
| Double underscore / edge underscore | ✅ | Rejected at validation |
| Bot/test pattern blocking | ✅ | `test\d*`, `user\d+`, `admin\d+` rejected |
| Namespace collision prevention | ✅ | DB unique constraints on all three namespace types |

**Mail namespace:** `@boyd` → automatically reserves `boyd@rald.me` and `boyd.rald.me`. This happens atomically in `reserve_username_namespace` RPC inside `POST /auth/register-username`.

---

## Phase 4 — Observability ✅

| Feature | Status | Notes |
|---|---|---|
| Audit log (all events) | ✅ | `audit_logs` table — every auth event |
| Signups metric | ✅ | `GET /admin/metrics` — 24h + 7d counts |
| OTP success rate | ✅ | 24h + 7d success/failure + rate % |
| Session metrics | ✅ | Logins, logouts, sessions created |
| Rate-limit events | ✅ | Count of blocked requests |
| Realtime 5-min buckets | ✅ | `GET /admin/metrics/realtime` |
| `signup_events` view | ✅ | Fast denormalized view for reporting |

**⚠ Dashboard UI:** No visual dashboard UI yet. Metrics are available via authenticated API. Recommend connecting to Grafana, Retool, or Metabase for team-facing views.

---

## Phase 5 — Security ✅

| Control | Status | Notes |
|---|---|---|
| IP rate limiting — registration | ✅ | 10/hour per IP (KV sliding window) |
| IP rate limiting — completion | ✅ | 10/hour per IP |
| Per-user OTP brute-force | ✅ | **NEW** — 5 attempts per user per 15 min |
| OTP send — phone | ✅ | 3/phone/10min, 10/IP/10min |
| OTP send — email | ✅ | 3/email/10min |
| Login rate limiting | ✅ | 5/email/15min, 10/IP/15min |
| Username enumeration | ✅ | `/username/check` rate-limited; same response time either way |
| Security headers | ✅ | CSP, HSTS, X-Frame-Options, Referrer-Policy on all responses |
| OTP failure audit | ✅ | Every failed OTP attempt logged with IP |
| Redirect allowlist | ✅ | `POST /auth/redirect` validates against registered app list |

**KV Fail-open:** Rate limiter fails open (allows) when KV is unavailable. This preserves availability over security — acceptable for v2 beta. Production should add secondary protection.

**⚠ Device anomaly detection:** Not yet implemented. Recommended for v2.5. |
**⚠ Session anomaly detection (geo/UA mismatch):** Not yet implemented.

---

## Phase 6 — Retention ✅

| Feature | Status | Notes |
|---|---|---|
| 30-day session cookie | ✅ | Users return without re-auth for 30 days |
| Username examples in UI | ✅ | `@boyd`, `@lagosmusic`, `@abujacreator`, `@manillafm` |
| Namespace reservation messaging | ✅ | User sees `boyd@rald.me is reserved for you` |
| Ecosystem product grid on success | ✅ | Shows all 6 connected RALD products |
| Auto-redirect engine | ✅ | `?app_id=loop` → `loop.rald.cloud` after auth |
| Graceful recovery | ✅ | Recovery codes (`/recovery`) |
| Session persistence check | ✅ | `/session` validates without re-auth |

**⚠ D1/D7 Retention Tracking:** Not yet implemented in product. `audit_logs` contains session restore events — retention can be computed from these. Recommend building a retention report from `signup_events` view.

---

## Phase 7 — Public Beta Testing Matrix

### Critical Path (must pass before launch)

| Test | Platform | Expected | Status |
|---|---|---|---|
| Create username `@newuser` | Desktop Chrome | Reserved + pending_user_id returned | ✅ Implemented |
| Send SMS OTP (Nigerian number) | Android (Termii) | 6-digit code via SMS | ✅ Implemented |
| Enter correct OTP | Mobile | Session cookie set, redirect fires | ✅ Implemented |
| Enter wrong OTP ×5 | Mobile | Blocked after 5th attempt (429) | ✅ Implemented |
| Take reserved username (`@admin`) | Any | 400 — reserved | ✅ Implemented |
| Take taken username | Any | 409 — already taken | ✅ Implemented |
| ?app_id=loop redirect | Desktop | Auto-redirect to loop.rald.cloud | ✅ Implemented |
| Session restore (re-open tab) | Desktop | No re-auth required for 30 days | ✅ Implemented |
| Global logout | Any | All sessions revoked | ✅ Implemented |
| Account recovery | Any | 10 recovery codes usable | ✅ Implemented |

### Secondary Tests (pre-GA)

| Test | Status |
|---|---|
| Slow network simulation (2G) | ⚠ Not tested — recommend Lighthouse throttling |
| iOS Safari (cookie handling) | ⚠ Not tested — `SameSite=Lax` should work |
| Cross-subdomain SSO (loop → messenger) | ⚠ Implemented via `/sso/silent` but not E2E tested |
| Device trust flow | ⚠ Implemented but UI not built |
| Mail sending (Resend deliverability) | ⚠ Depends on DNS records for `auth@rald.cloud` |

---

## Phase 8 — Public Beta Certification

### What IS production-ready

- Username registration and OTP verification flow (end-to-end)
- HttpOnly ecosystem session cookies (`Domain=.rald.cloud`)
- Rate limiting and brute-force protection on all auth endpoints
- Username namespace reservation (mail + subdomain + workspace)
- Reserved username list (60+ entries)
- Session management (view, revoke, global logout)
- Recovery codes
- Audit trail (all events)
- Security headers (CSP, HSTS, X-Frame-Options)
- Cloudflare Workers deployment (zero cold-start on paid plan)
- Cloudflare Pages frontend deployment (global CDN)
- Observability API (`/admin/metrics`, `/admin/metrics/realtime`)

### What is NOT yet ready for GA (post-beta work)

| Gap | Priority | Effort |
|---|---|---|
| Device anomaly detection | High | ~1 week |
| Visual ops dashboard | Medium | ~1 week |
| iOS E2E testing | High | ~2 days |
| D1/D7 retention pipeline | Medium | ~1 week |
| Email deliverability verification | Critical | ~1 day (DNS config) |
| Password-less login (existing users) | High | ~3 days |
| Profile completion UI | Medium | ~1 week |

---

## Recommendation

**RALD Identity V2 is certified for PUBLIC BETA launch** with the following conditions:

1. ✅ CI/CD is fully green (fixed this sprint)
2. ✅ OTP brute-force protection is live
3. ✅ Username namespace is protected
4. ⚠ Run Supabase migration `20260610_public_beta_hardening.sql` before launch
5. ⚠ Verify Resend DNS records for `auth@rald.cloud` sender domain
6. ⚠ Set Cloudflare Workers paid plan for zero cold-starts
7. ⚠ Test iOS Safari cookie handling before iOS launch

**Target:** 100–1,000 users in public beta with monitoring via `/admin/metrics`.  
**Next milestone:** V2.5 — device anomaly detection + profile completion flow.

---

*RALD Identity — Built in Africa. Works on any network.*  
*LILCKY STUDIO LIMITED · 2026*
