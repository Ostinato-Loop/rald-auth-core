# RALD DISASTER RECOVERY RUNBOOK
## Operator Platform Sprint — Phase 10

**Version:** 1.0 · **Date:** 2026-06-12  
**Owner:** RALD Platform Engineering · LILCKY STUDIO LIMITED  
**SLO:** RTO < 4 hours · RPO < 1 hour for P0 incidents

---

## Incident Classification

| Severity | Definition | Response Time | Examples |
|---|---|---|---|
| P0 | Full service outage — users cannot authenticate | < 15 min | Supabase down, CF zone down, credential compromise |
| P1 | Partial outage — core features degraded | < 1 hour | Auth slow, Loop rooms failing, SMS not delivering |
| P2 | Non-critical degradation | < 4 hours | Search down, inbox delayed, minor feature broken |
| P3 | Cosmetic / minor | < 24 hours | UI glitch, slow analytics |

---

## Runbook 1: Cloudflare Outage

**Scenario:** Cloudflare Workers / CF zone experiencing outage  
**Impact:** All RALD services (all backend is CF Workers)

**Steps:**
1. Monitor: https://www.cloudflarestatus.com/
2. Kill switch via Supabase direct (not via rald-config): UPDATE kill_switches SET is_active = true WHERE name = 'disable_all'
3. Post status update on status.rald.cloud
4. Wait for CF recovery — no action possible (no alternative infra for CF Workers)
5. Once CF recovers: verify all Workers deployed and responding on all domains

**Prevention:** Cloudflare has 99.99% SLA. No mitigation beyond monitoring.

---

## Runbook 2: Supabase Outage

**Scenario:** Supabase project down or unreachable  
**Impact:** Auth failures, no new logins possible; existing KV sessions still work

**Steps:**
1. KV sessions continue to work for up to 30 days — existing users stay logged in
2. Disable new registrations via kill switch (prevents confusing failed signups): `POST /admin/kill-switches` `{ "name": "disable_registration", "is_active": true }`
3. Disable OTP endpoints (OTP writes to Supabase): activate `disable_otp` kill switch
4. Monitor: https://status.supabase.com/
5. On recovery: verify migrations are current, run `SELECT COUNT(*) FROM auth_users` to confirm DB state
6. Re-enable kill switches

**Supabase Backup:** Supabase Pro includes daily PITR (Point In Time Recovery). Restore from PITR if data loss occurs.

---

## Runbook 3: Credential Compromise

**Scenario:** RALD_JWT_SECRET, RALD_INTERNAL_SECRET, or SUPABASE_SERVICE_ROLE_KEY compromised

**RALD_JWT_SECRET compromised:**
1. **IMMEDIATE:** Rotate the secret in Cloudflare Workers dashboard for ALL workers
2. This invalidates ALL existing sessions — all users will be logged out
3. Post incident notice: "We've updated our security. Please log in again."
4. Rotate in order: rald-auth-core → rald-notify → rald-realtime → rald-inbox → rald-search → rald-event-bus → loop-api → messenger
5. Verify auth flow works before marking incident resolved

**SUPABASE_SERVICE_ROLE_KEY compromised:**
1. Rotate key in Supabase Dashboard → Settings → API
2. Update all CF Workers with new key (same order as above)
3. Monitor Supabase audit log for any unauthorized operations during the window

**RALD_INTERNAL_SECRET compromised:**
1. Rotate in all Workers
2. Machine Identity rollout is the permanent fix (removes shared secret entirely)

---

## Runbook 4: Region Outage (Nigeria-specific)

**Scenario:** Connectivity issues in Nigeria (Termii SMS failures, latency spikes)

**Steps:**
1. Switch SMS provider to Africa's Talking: update `sms_primary_provider` in rald-config country config for NG
2. Activate extended OTP window: 10 minutes instead of 5 (update config flag)
3. Enable email OTP fallback for Nigeria users
4. Monitor Termii status: https://status.termii.com/

---

## Runbook 5: Mass Abuse Event

**Scenario:** Coordinated account creation, spam, or abuse attack

**Steps:**
1. Activate `disable_registration` kill switch immediately
2. Review auth_users created in last 24h: filter by country + creation timestamp
3. Activate trust-gating: require phone verification before room creation
4. Ban identified IP ranges via Cloudflare WAF
5. Use `machine_identity_audit_log` to check for unusual service-to-service patterns
6. Re-enable registration after mitigation with CAPTCHA or invite-only mode

---

## Runbook 6: Loop D1 Database Corruption

**Scenario:** Loop D1 database has corrupted records or bad migration

**Steps:**
1. Cloudflare D1 has point-in-time restore via: `wrangler d1 restore <database-id> --time <ISO8601>`
2. Loop API is stateless — no data loss from Worker restarts
3. Identify affected records: check `cleanup_schedule.status = 'failed'` entries
4. Run repair migration if schema affected

---

## Backup Registry

| Data Store | Backup Method | Frequency | Retention | RTO |
|---|---|---|---|---|
| Supabase (PostgreSQL) | Supabase PITR | Continuous | 7 days | < 1 hour |
| Cloudflare KV | No backup (ephemeral session cache) | — | N/A | Instant (KV self-heals) |
| Cloudflare D1 (Loop) | D1 time-travel restore | Continuous | 30 days | < 30 min |
| Cloudflare R2 (Loop media) | R2 versioning | On write | 30 days | < 15 min |

---

## Service Recovery Checklist

After any P0 incident:

- [ ] Verify auth flow: signup → OTP → login → session → refresh
- [ ] Verify SSO: loop.rald.cloud → profiles.rald.cloud cross-domain
- [ ] Verify kill switches: test enable/disable cycle
- [ ] Verify event bus: POST /events/publish → check event_log
- [ ] Verify notifications: send test OTP
- [ ] Verify feature flags: GET /flags returns expected state
- [ ] Run `SELECT COUNT(*) FROM auth_users` — compare to pre-incident baseline
- [ ] Post incident report within 24 hours

---

*RALD Disaster Recovery — Prepared for what we hope never happens.*  
*LILCKY STUDIO LIMITED · 2026*
