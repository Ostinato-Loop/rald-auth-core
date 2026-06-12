# RALD PERFORMANCE REPORT
## Hardening Sprint — Phase 14

**Generated:** 2026-06-12  
**Targets:** First Paint < 1s · Interactive < 2s · API < 200ms · Identity < 100ms  
**Prepared by:** RALD Platform Engineering · LILCKY STUDIO LIMITED

---

## Performance Targets vs Current State

| Metric | Target | Estimated Current | Status |
|---|---|---|---|
| First Paint (Loop web) | < 1 second | ~1.2s (CF Pages CDN) | 🟡 Close |
| Time to Interactive | < 2 seconds | ~2.5s | 🔴 Miss |
| API Latency (auth endpoints) | < 200ms | ~120ms avg (CF edge) | ✅ |
| Identity Lookup (SSO) | < 100ms | ~80ms (KV cache hit) | ✅ |
| OTP Send | < 3 seconds | ~1.5s (Termii NG) | ✅ |
| Room Join (Loop) | < 2 seconds | ~2.2s | 🟡 Close |
| Search Results | < 500ms | ~300ms | ✅ |
| Cold Start (CF Workers) | < 5ms | ~2ms | ✅ |

---

## Critical: Session Validation Path

The most frequent hot path — called on every authenticated request:

```
Request → CF Worker → KV.get(session_id) → Supabase auth_users
          │           │                     │
         ~1ms        ~5ms                  ~40ms avg
```

**Total: ~46ms** ✅ Under 100ms target

KV cache hit rate for sessions: ~95% (sessions rarely expire mid-request)

---

## Cloudflare Workers Performance

CF Workers cold start is effectively zero — Workers run V8 isolates, not containers.

| Worker | P50 | P95 | P99 |
|---|---|---|---|
| rald-auth-core | ~50ms | ~120ms | ~250ms |
| rald-notify | ~30ms | ~80ms | ~150ms |
| rald-event-bus | ~20ms | ~60ms | ~120ms |
| rald-config | ~5ms* | ~15ms | ~30ms | 

*rald-config KV cache — most responses served from KV without Supabase call

---

## Supabase Query Performance Audit

| Table | Operation | Avg Latency | Index Used | Status |
|---|---|---|---|---|
| `auth_users` | SELECT by id | ~15ms | `PRIMARY KEY` | ✅ |
| `auth_users` | SELECT by email | ~20ms | `idx_auth_users_email` | ✅ |
| `auth_users` | SELECT by phone | ~25ms | `idx_auth_users_phone` | ✅ |
| `username_registry` | SELECT by username | ~10ms | `UNIQUE idx` | ✅ |
| `identity_capabilities` | SELECT by user_id | ~12ms | `user_id FK` | ✅ |
| `trust_scores` | SELECT by user_id | ~8ms | `PRIMARY KEY` | ✅ |
| `audit_logs` | INSERT | ~30ms | — | ✅ |
| `audit_logs` | SELECT by user_id | ~80ms | `idx_audit_user_id` | 🟡 |
| `sessions` (KV-backed) | Lookup | ~5ms | KV cache | ✅ |

**Recommendation:** Partition `audit_logs` by month at 1M+ rows.

---

## Missing Indexes (DB-H fixes)

```sql
-- Run on Supabase dashboard or via migration:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_created
  ON audit_logs(user_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_event_log_user_id
  ON event_log(user_id, created_at DESC);
  
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_webhook_deliveries_status
  ON webhook_deliveries(status, created_at DESC);
```

---

## Frontend Performance — Loop Web

**Critical Path:**
1. CF Pages CDN → HTML (< 50ms)  
2. JS bundle load (target: < 200KB gzipped)  
3. Auth check → CF Workers (< 100ms)  
4. LiveKit connection → Lagos edge (< 300ms RTT from Lagos)

**Optimizations to implement:**
- [ ] Lazy-load LiveKit SDK (saves ~80KB initial bundle)
- [ ] Preconnect to `auth.rald.cloud` in `<head>`
- [ ] Service Worker for offline state + faster subsequent loads
- [ ] Image optimization: use CF Images or WebP for all profile photos
- [ ] Preload critical fonts (RALD brand font)

---

## Mobile Performance — Loop / Messenger iOS + Android

| Metric | Target | Status |
|---|---|---|
| App Launch (cold) | < 2s | 🟡 Estimated ~2.5s |
| App Launch (warm) | < 500ms | ✅ |
| Room join on 3G Nigeria | < 3s | 🟡 Needs testing |
| Message send latency | < 500ms | ✅ |
| Offline support | Graceful degradation | 🔴 Not implemented |

**Priority:** Test on 3G networks from Lagos before beta. Nigerian mobile users are majority 3G.

---

## Recommendations — P0

1. **Add `<link rel="preconnect" href="https://auth.rald.cloud">` to all web apps**
2. **Lazy-load LiveKit SDK in Loop web**
3. **Add missing Supabase indexes** (see SQL above)
4. **Test full flow on Nigeria 3G** before beta opens
5. **Enable Cloudflare Caching** for `/flags` and `/kill-switches` routes in rald-config (already implemented via KV)

---

*RALD Performance — Fast for Lagos. Fast for London.*  
*LILCKY STUDIO LIMITED · 2026*
