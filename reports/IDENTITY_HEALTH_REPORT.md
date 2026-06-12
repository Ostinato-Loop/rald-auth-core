# RALD IDENTITY HEALTH REPORT
## Phase 2: Identity Stability Audit

**Generated:** 2026-06-12  
**Service:** RALD Auth Core v2.8.0 + RALD Identity UI  
**Domain:** auth.rald.cloud | profiles.rald.cloud  
**Prepared by:** RALD Platform Engineering · LILCKY STUDIO LIMITED

---

## Executive Summary

RALD Identity V2 implements a username-first, phone/email OTP authentication paradigm with 30-day HttpOnly session cookies scoped to `Domain=.rald.cloud`. This report verifies the health of every identity subsystem and identifies gaps requiring remediation before public beta.

---

## 1. Authentication Flow Verification

| Flow | Endpoint | Status | Notes |
|---|---|---|---|
| Username availability check | `GET /username/check` | ✅ | Rate-limited; same timing for taken/free |
| Username registration | `POST /auth/register-username` | ✅ | Reserves namespace atomically |
| OTP send (SMS) | `POST /auth/request-otp` | ✅ | Termii; 3/phone/10min |
| OTP send (Email) | `POST /auth/request-otp` | ✅ | Resend; 3/email/10min |
| OTP verify | `POST /auth/complete` | ✅ | 5 attempts; blocks after 5th (429) |
| Login (existing user) | `POST /auth/login-username` | ✅ | Smart login with OTP |
| Smart login | `POST /auth/smart-login` | ✅ | Detects existing vs new |
| Loop claim (one-step) | `POST /auth/loop-claim` | ✅ | v2.8.0 — Loop identity integration |
| SSO silent auth | `GET /sso/silent` | ✅ | Cookie-based; no page reload |
| Session validation | `GET /session` | ✅ | JWT + KV liveness check |
| Global logout | `POST /session/revoke-all` | ✅ | Revokes all KV sessions |
| Device revocation | `POST /session/revoke-device` | ✅ | Per-device revocation |
| QR login | `POST /qr/*` | ✅ | QR code generation + approval |
| WebAuthn/Passkeys | `POST /webauthn/*` | ✅ | @simplewebauthn/server v13 |
| Recovery codes | `POST /recovery/*` | ✅ | 10-code system |
| Account recovery | `POST /auth/recovery` | ✅ | Phone/email re-verification |
| Session refresh | `POST /auth/refresh` | ❌ MISSING | No sliding window renewal |
| Cross-product SSO | Via `/sso/silent` + cookie | ✅ | Works for all `.rald.cloud` subdomains |

---

## 2. Duplicate Identity Prevention

| Check | Mechanism | Status |
|---|---|---|
| Duplicate usernames | DB unique index on `lower(username)` | ✅ |
| Duplicate phone numbers | DB unique constraint on `phone_number` | ✅ |
| Duplicate email addresses | DB unique constraint on `email` | ✅ |
| Duplicate onboarding | `completed_onboarding` flag in identity_capabilities | ✅ |
| Duplicate mail namespace | Atomic reservation in `username_namespace_reservations` | ✅ |
| Duplicate subdomain reservation | Same table, separate namespace type | ✅ |
| Cross-product duplicate signup | Same `user_id` across all RALD services (Supabase UUID) | ✅ |

**Finding:** No duplicate identity records are possible at the database level. The username uniqueness is enforced case-insensitively. However:

⚠ **Loop Guest Users:** Before v2.8.0 (`/auth/loop-claim`), Loop users could exist as `guest_xxx@loop.guest` in the auth_users table. The `loop-claim` endpoint was built to convert these. Verify all guest users have been migrated.

---

## 3. Username System Health

| Feature | Status | Notes |
|---|---|---|
| Username Registry | ✅ | `username_registry` table + unique index |
| Username Reservation | ✅ | `username_namespace_reservations` table |
| Username Recovery | ✅ | `/recovery` endpoint |
| Username Transfer | ✅ | `/admin/username/transfer` (admin-only) |
| Username Release | ✅ | `/admin/username/release` (admin-only) |
| Admin Controls | ✅ | `admin-username.ts` route file |
| Reserved Word List | ✅ | 60+ reserved words |
| Bot/Test Pattern Blocking | ✅ | `test\d*`, `user\d+`, `admin\d+` rejected |
| Double underscore blocking | ✅ | Validation rejects `__` |
| Edge underscore blocking | ✅ | Cannot start/end with `_` |
| Mail alias reservation | ✅ | `username@rald.me` reserved atomically |
| Subdomain reservation | ✅ | `username.rald.me` reserved |
| Workspace slug reservation | ✅ | Reserved in same namespace table |

### ⚠ Future Readiness
The `username_namespace_reservations` table structure supports:
- Premium username marketplace (status column)
- Business usernames (type column)
- Mail usernames (namespace_type = 'mail')
- Transfer between users (admin RPC)

---

## 4. Identity Intelligence Layer (Phase 3)

**Status: ✅ MIGRATION DEPLOYED** (`20260612000000_identity_intelligence_layer.sql`)

| Table | Status | Purpose |
|---|---|---|
| `identity_capabilities` | ✅ Created + seeded | What RALD knows about each user |
| `identity_memory` | ✅ Created | Per-user history, dismissed prompts, preferences |
| Back-fill from `auth_users` | ✅ Done | Username, email, phone, country, trust_level, mail_reserved |
| `updated_at` triggers | ✅ Active | Auto-updates on any change |
| RLS policies | ✅ Active | Users read own row; service role has full write |

### Identity Intelligence API Routes (Required)

The database layer exists. The API routes for products to query identity capabilities must be implemented:

| Endpoint | Status | Priority |
|---|---|---|
| `GET /identity/capabilities` | ⚠ EXISTS — verify implementation | P0 |
| `POST /identity/capabilities/update` | ⚠ Verify | P0 |
| `GET /identity/memory` | ⚠ Verify | P1 |
| `POST /identity/memory/update` | ⚠ Verify | P1 |
| `POST /identity/capabilities/sync` | ❓ Not verified | P1 |

Products must call `GET /identity/capabilities` before requesting any information from users.

---

## 5. Session Hardening Status

| Feature | Status | Notes |
|---|---|---|
| HttpOnly cookies | ✅ | `Domain=.rald.cloud; HttpOnly; Secure; SameSite=Lax` |
| Cookie security headers | ✅ | CSP, HSTS, X-Frame-Options on all responses |
| 30-day session validity | ✅ | KV TTL = 30 days |
| Session KV liveness check | ✅ | `GET /session` validates both JWT and KV entry |
| Global logout | ✅ | Revokes all KV sessions |
| Device-level revocation | ✅ | Per-device KV key invalidation |
| Silent re-auth | ✅ | `GET /sso/silent` reads cookie |
| Session sliding window (refresh) | ❌ MISSING | `POST /auth/refresh` not implemented |
| Cross-device session sync | ⚠ PARTIAL | Events emitted but no push notification to other devices |
| Token revocation on compromise | ✅ | Immediate KV delete |

### ⚠ Critical Gap: POST /auth/refresh
Without a refresh endpoint:
- Users with 30-day sessions that expire must re-authenticate from scratch
- There is no way for products to silently extend a valid session
- Recommendation: Implement sliding window — refresh if session is valid AND was last used within 7 days

---

## 6. SSO & Cross-Product Login

| Check | Status | Notes |
|---|---|---|
| Loop → rald-auth SSO | ✅ | `/auth/rald-sso` in loop worker |
| Messenger → rald-auth SSO | ✅ | `/auth` route in messenger worker |
| Cookie shared across subdomains | ✅ | `Domain=.rald.cloud` covers all products |
| `app_id` redirect after auth | ✅ | `?app_id=loop` → loop.rald.cloud |
| Registered app allowlist | ✅ | `registered_apps` table validates redirects |
| Cross-device session awareness | ⚠ | Not yet — no real-time session event push |

---

## 7. Trust System

| Feature | Status | Location |
|---|---|---|
| Trust levels (none/basic/verified) | ✅ | `auth_users.trust_level` column |
| Trust level in identity_capabilities | ✅ | Synced via back-fill migration |
| Creator verification flag | ✅ | `identity_capabilities.creator_verified` |
| Business verification flag | ✅ | `identity_capabilities.business_verified` |
| Civic verification flag | ✅ | `identity_capabilities.civic_verified` |
| Trust score computation | ❌ NOT BUILT | Planned in Operator Sprint Phase 5 |
| Centralized trust engine | ❌ NOT BUILT | Currently per-column in Supabase |

---

## 8. Verification Engine

| Verification Type | Endpoint | Status |
|---|---|---|
| Email verification | `POST /verification-engine/email` | ✅ |
| Phone verification | `POST /verification-engine/phone` | ✅ |
| Identity verification (KYC) | `POST /verification-engine/identity` | ✅ |
| Creator verification | `POST /verification-engine/creator` | ✅ |
| Business verification | `POST /verification-engine/business` | ✅ |

---

## 9. Developer Platform (Phase 8)

**Status: ✅ MIGRATION DEPLOYED** (`20260612100000_developer_platform.sql`)

| Table | Status |
|---|---|
| `developer_profiles` | ✅ Created |
| `developer_api_keys` | ✅ Created |
| `developer_registered_apps` | ✅ Created |
| Developer API routes | ✅ `src/routes/developer.ts` exists |
| Webhook registry | ⚠ Not in migration — add separately |
| API registry | ⚠ Not in migration — add separately |

---

## 10. Identity Health Recommendations

### P0 — Before Public Beta
1. **Implement `POST /auth/refresh`** — sliding session window (30d → extend on use)
2. **Verify `/identity/capabilities` endpoint** — confirm products can query what RALD knows
3. **Migrate all Loop guest users** — verify `loop-claim` has been run for all `guest_xxx@loop.guest` accounts
4. **Test iOS Safari cookie handling** — `SameSite=Lax` behavior differs on Safari

### P1 — Week 1 of Beta
5. **Build device anomaly detection** — geo/UA mismatch alerting
6. **D1/D7 retention pipeline** — compute from `audit_logs`
7. **Session event push to devices** — real-time session revocation notification
8. **Webhook registry table** — complete developer platform schema

### P2 — Pre-GA
9. **Centralized Trust Engine** — replace per-column trust with computed score
10. **Country-aware identity restrictions** — integrate with country_registry

---

## 11. Certification

| System | Status | Conditions |
|---|---|---|
| Authentication (OTP + Username) | ✅ CERTIFIED | — |
| Session Management | ⚠ CONDITIONAL | Implement /auth/refresh first |
| Username Registry | ✅ CERTIFIED | — |
| Cross-Product SSO | ✅ CERTIFIED | — |
| Verification Engine | ✅ CERTIFIED | — |
| Identity Intelligence Layer | ✅ DB READY | API routes need verification |
| Developer Platform | ✅ DB READY | Routes exist; E2E not verified |
| Trust System | ⚠ PARTIAL | Score computation not built |
| Device Management | ✅ CERTIFIED | — |
| Recovery System | ✅ CERTIFIED | — |

---

*RALD Identity — One identity. Every product.*  
*LILCKY STUDIO LIMITED · 2026*
