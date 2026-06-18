# WIZMAC — rald-auth-core
> RALD Auth Core — Universal Identity + Verification Engine
> Last updated: 2026-06-17 — LILCKY STUDIO LIMITED

---

## 1. Product Overview
**rald-auth-core** is the identity backbone of the entire RALD ecosystem. Every login, signup, session, username, verification, trust score, and SSO token flows through this service.

| Field | Value |
|-------|-------|
| Live URL | `https://auth.rald.cloud` |
| Repo | `Ostinato-Loop/rald-auth-core` |
| Stack | Cloudflare Worker (Hono) + Supabase |
| Database | Supabase `onxdcikfttdmnhofsuwo.supabase.co` |
| Version | 3.x (40+ migrations applied) |

---

## 2. Architecture
| Layer | Stack | Deployment |
|-------|-------|------------|
| API Worker | Cloudflare Worker (Hono) | `auth.rald.cloud` |
| Database | Supabase PostgreSQL | `onxdcikfttdmnhofsuwo.supabase.co` |
| SSO Tokens | RALD JWT (HS256) | Shared `RALD_JWT_SECRET` |
| Cron Jobs | Cloudflare Cron | Username expiry cleanup (every 5min) |
| WebAuthn | Cloudflare Worker | Passkey support |

---

## 3. Auth Flow
```
1. User submits email + password (or WebAuthn)
2. auth-core validates credentials against auth_users
3. Checks identity_state (must be ACTIVE, not SUSPENDED/DELETED)
4. Creates auth_sessions record
5. Issues RALD JWT: { sub, rald_id, email, role, iat, exp:7d }
6. If new signup: publishes identity.created event → rald-event-bus
7. All downstream services validate JWT using shared RALD_JWT_SECRET
```

---

## 4. Key Database Tables
| Table | Purpose |
|-------|---------|
| `auth_users` | Core user records (email, password_hash, rald_id, identity_state) |
| `auth_sessions` | Active sessions (user_agent, ip, expires_at) |
| `auth_devices` | Trusted devices per user |
| `auth_product_access` | Which products each user can access |
| `rald_usernames` | Username registry + reservation system |
| `rald_users` | Universal identity record (created migration 20260617) |
| `auth_verifications` | KYC/ID verification submissions |
| `auth_trust_scores` | Trust score history |
| `auth_machine_identities` | Machine-to-machine JWT issuers |
| `auth_webhooks` | Registered webhook endpoints |
| `auth_organizations` | Organisation/workspace records |
| `auth_permissions` | Role-based permissions |
| `auth_audit_log` | Full audit stream |
| `auth_webauthn_credentials` | WebAuthn/passkey credentials |

---

## 5. Key Environment Variables
| Variable | Required | Set In |
|----------|----------|--------|
| `RALD_JWT_SECRET` | ✅ | Cloudflare secret |
| `SUPABASE_URL` | ✅ | Cloudflare secret |
| `SUPABASE_SERVICE_ROLE_KEY` | ✅ ⚠️ ROTATE | Cloudflare secret |
| `RALD_INTERNAL_SECRET` | ✅ | Cloudflare secret |
| `MACHINE_IDENTITY_SECRET` | ✅ | Cloudflare secret |
| `RESEND_API_KEY` | ✅ | Cloudflare secret (email verification) |
| `ENVIRONMENT` | ✅ | `production` |

---

## 6. Live Endpoints
| Method | Path | Auth | Status |
|--------|------|------|--------|
| GET | `/health` | None | ✅ |
| POST | `/auth/register` | None | ✅ |
| POST | `/auth/login` | None | ✅ |
| POST | `/auth/logout` | JWT | ✅ |
| POST | `/auth/verify-email` | None | ✅ |
| POST | `/auth/refresh` | None | ✅ |
| POST | `/auth/sso` | None | ✅ |
| GET | `/auth/me` | JWT | ✅ |
| POST | `/identity/provision` | JWT | ✅ |
| GET | `/users/:id/profile` | JWT | ✅ |
| POST | `/auth/webauthn/register` | JWT | ✅ |
| POST | `/auth/webauthn/authenticate` | None | ✅ |
| GET | `/admin/users` | Admin JWT | ✅ |
| POST | `/machine/token` | Machine secret | ✅ |

---

## 7. CI Pipelines
| Workflow | Trigger | Status |
|----------|---------|--------|
| CI | Push/PR to main | ✅ Green |
| Deploy Worker | Push to main | ✅ Green |
| Apply Migrations | Manual / workflow_dispatch | ⚠️ Requires DB password |

---

## 8. Incidents
| # | Date | Description | Status |
|---|------|-------------|--------|
| A-001 | 2026-06 | identity_state machine column missing from auth_users | ✅ Fixed (migration applied) |
| A-002 | 2026-06-17 | rald_users universal identity table created (migration 20260617) | ✅ Applied |
