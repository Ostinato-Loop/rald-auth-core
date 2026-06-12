# RALD Ecosystem — Service Identity Logic Audit
**Sprint: Public Beta Hardening · 2026-06-14**  
**Auditor: Automated sprint hardening**

## Scope

Every RALD service was audited for inline identity logic that should instead be
delegated to `rald-identity-brain` (alias: `auth.rald.cloud/identity`).

---

## rald-auth-core (auth.rald.cloud)

**Status: CANONICAL AUTHORITY — no delegation needed**

This service IS the identity brain. All identity operations originate here.

| Domain | Implementation | Notes |
|--------|---------------|-------|
| Username governance | `routes/username.ts` | ✅ Canonical |
| Trust scoring | `routes/trust.ts` | ✅ Canonical |
| Permission eval | `routes/permissions.ts` | ✅ Canonical |
| Country activation | `routes/country.ts` | ✅ Canonical |
| Machine identity | `routes/machine.ts` | ✅ Canonical |
| Developer keys | `routes/developer.ts` | ✅ Canonical |
| Identity intelligence | `routes/identity.ts` | ✅ Canonical |

---

## rald-search (search.rald.cloud)

**Status: ACCEPTABLE — local JWT verify, no inline identity data fetching**

`src/lib/auth.ts` implements `verifyJwt()` locally (HMAC-SHA256 against `RALD_JWT_SECRET`).  
This is the **correct pattern** for a stateless JWT consumer — it avoids an extra network hop to auth.rald.cloud on every search request.

**Finding**: The `authMiddleware` does not fetch user records from Supabase. It only decodes the
JWT and sets `c.var.user`. Search results are filtered by the privacy flag `search_discoverable`
in the DB query itself, not by the middleware.

**Action Required**: None. The pattern is correct and performant.

---

## rald-event-bus (events.rald.cloud)

**Status: CORRECT — machine JWT auth, no inline identity logic**

The event bus does not resolve user identities. Events carry `user_id` / `actor_id` as opaque
UUIDs. Subscribers are responsible for resolving user details via rald-auth-core if needed.

**Finding**: `RALD_INTERNAL_SECRET` (deprecated shared secret) is still declared in `Bindings` for
backward-compat fallback in `machine-auth.ts`. The fallback logs a deprecation warning.

**Action Required**: Once all callers have migrated to machine JWTs, remove `RALD_INTERNAL_SECRET`
from the event bus `Bindings` and `wrangler.toml` secrets list.

---

## rald-config (config.rald.cloud)

**Status: CORRECT — machine JWT auth, no inline identity logic**

Config reads/writes are protected by `requireMachineRead()` / `requireMachineWrite()`. No user
identity resolution is performed. Admin mutations additionally require a user admin JWT (`isAdmin`).

**Finding**: `RALD_ADMIN_SECRET` (deprecated shared secret) is still in `Bindings` as backward-compat
fallback. Same pattern as rald-event-bus.

**Action Required**: Same — remove `RALD_ADMIN_SECRET` fallback once all callers use machine JWTs.

---

## rald-api-core (loop-api.rald.cloud + CF worker)

**Status: DIFFERENT AUTH DOMAIN — Replit OIDC, not RALD JWT**

`rald-api-core` is an infrastructure management API, not a RALD user-facing product API. It uses
Replit OpenID Connect (PKCE) for authentication — `ISSUER_URL = "https://replit.com/oidc"`.

**Finding**: This is intentional. The rald-api-core manages Replit deployments, secrets, and repos on
behalf of the Ostinato-Loop engineering team. It has no RALD end-users.

**Action Required**: None. Separate auth domain is correct.

---

## rald-trust (trust.rald.cloud)

**Status: STATIC FRONTEND — no identity logic**

`rald-trust` contains only a `vite.config.ts`. It is a frontend-only artifact with no auth logic.

**Action Required**: None.

---

## Summary Table

| Service | Auth Pattern | Inline Identity Logic | Action |
|---------|-------------|----------------------|--------|
| rald-auth-core | N/A (is the authority) | Canonical | None |
| rald-search | Local JWT verify | None | None |
| rald-event-bus | Machine JWT + deprecated fallback | None | Remove RALD_INTERNAL_SECRET when migration complete |
| rald-config | Machine JWT + deprecated fallback | None | Remove RALD_ADMIN_SECRET when migration complete |
| rald-api-core | Replit OIDC | None (different domain) | None |
| rald-trust | None (frontend) | None | None |

**Conclusion**: No service in the RALD ecosystem contains problematic inline identity logic.
All user-facing services delegate to `rald-auth-core`. Machine-to-machine auth has been
migrated from shared secrets to machine JWTs (backward-compat fallbacks remain during transition).
