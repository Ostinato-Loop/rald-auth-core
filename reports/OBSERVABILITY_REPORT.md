# RALD OBSERVABILITY REPORT
## Phase 8: Observability Audit

**Generated:** 2026-06-12  
**Scope:** All active RALD services  
**Prepared by:** RALD Platform Engineering · LILCKY STUDIO LIMITED

---

## Executive Summary

RALD services run on Cloudflare Workers with built-in observability (`[observability] enabled = true`) and a Supabase audit log for identity events. This report assesses the current observability coverage, identifies gaps, and defines the target state for production-grade monitoring.

---

## 1. Current Observability Coverage

### Cloudflare Workers — Built-in Observability

All active Cloudflare Workers have observability enabled:

| Service | Workers Observability | Log Retention | Head Sampling |
|---|---|---|---|
| rald-auth-core | ✅ enabled | Cloudflare default | 100% |
| rald-notify | ✅ enabled | Cloudflare default | 100% |
| rald-realtime | ✅ enabled | Cloudflare default | 100% |
| rald-inbox | ✅ enabled | Cloudflare default | 100% |
| rald-search | ✅ enabled | Cloudflare default | 100% |
| rald-event-bus | ✅ enabled (new) | Cloudflare default | 100% |
| rald-config | ✅ enabled (new) | Cloudflare default | 100% |
| loop-api | ✅ enabled | Cloudflare default | 100% (default) |

**Cloudflare Workers Observability provides:**
- Real-time request logs (URL, method, status, duration, CPU time)
- Exception tracking
- Tail workers integration
- R2 log export (configurable)
- Dashboard at dash.cloudflare.com → Workers & Pages → {Worker} → Logs

### Supabase Audit Logs (Identity)

rald-auth-core writes structured audit logs to the `audit_logs` table for all identity events:

| Event Category | Events Logged | Retention |
|---|---|---|
| Authentication | login, register, OTP send/verify | DB (no TTL) |
| Sessions | create, revoke, revoke-all, logout | DB (no TTL) |
| Username | claimed, changed, released, transferred | DB (no TTL) |
| Devices | added, trusted, removed | DB (no TTL) |
| Admin actions | suspend, unsuspend, force-logout | DB (no TTL) |
| Security events | rate_limit_hit, brute_force_detected | DB (no TTL) |

### Service-Specific Audit Logs

| Service | Has Audit Logging | Table/Mechanism |
|---|---|---|
| rald-auth-core | ✅ | `audit_logs` table in Supabase |
| rald-notify | ✅ | `notification_audit_logs` |
| rald-inbox | ✅ | `inbox_audit_logs` |
| rald-search | ✅ | `search_audit_logs` |
| rald-event-bus | ✅ (new) | `event_bus_audit_logs` |
| rald-config | ✅ (new) | `config_audit_logs` |
| loop-api | ⚠ Partial | D1 analytics table — no structured audit |
| messenger | ⚠ Partial | No dedicated audit table found |

---

## 2. OpenObserve Integration

rald-notify has optional OpenObserve integration (structured log shipping):

```toml
# Already in rald-notify wrangler.toml comments:
# OPEN_OBSERVE_API_KEY  (optional)
# OPEN_OBSERVE_ENDPOINT (optional)
```

**Status:** Configured but not yet shipping logs (secrets not set).  
**Action:** Set `OPEN_OBSERVE_API_KEY` and `OPEN_OBSERVE_ENDPOINT` on all services to enable structured log shipping to OpenObserve.

---

## 3. Identified Observability Gaps

### 🔴 CRITICAL

**OBS-C-001: No real-time alerting on authentication anomalies**  
- OTP brute-force attempts are rate-limited but not alerted on in real-time
- Unusual login patterns (geo jumps, device changes) are not monitored
- **Action:** Add Cloudflare Tail Worker to ship auth anomaly events to a webhook (Slack/PagerDuty)

**OBS-C-002: No centralized log aggregation**  
- Each service logs independently — no way to trace a request across services
- A user complaint cannot be traced from auth → loop → notify in one query
- **Action:** Ship all service logs to OpenObserve with `trace_id` correlation header

### 🟡 HIGH

**OBS-H-001: No uptime/SLA monitoring**  
- status.rald.cloud exists but no automated health checks feed it
- No external monitoring (UptimeRobot/Better Uptime) configured
- **Action:** Configure external health check monitors for all `*.rald.cloud` domains

**OBS-H-002: No D1 query performance monitoring**  
- Loop API uses D1 — no slow query logging
- No index usage tracking for D1
- **Action:** Log D1 query durations; alert on queries > 100ms

**OBS-H-003: Cron health not monitored**  
- Loop's cleanup cron is disabled (cron quota exhausted — C-004)
- No cron run history or alerting when cron fails to execute
- **Action:** Re-enable crons after quota freed; add Cloudflare cron execution logs

**OBS-H-004: No business metrics dashboard**  
- No real-time visibility into: DAU, MAU, registrations/day, rooms created/day
- rald-auth-core `/metrics/*` admin endpoints exist but no dashboard UI
- **Action:** Build metrics dashboard in rald-control-center consuming auth metrics API

### 🟢 LOW

**OBS-L-001: No Supabase query performance monitoring**  
- Supabase has built-in query performance tools but they haven't been configured
- **Action:** Enable Supabase Performance Dashboard; set up slow query alerts (> 500ms)

**OBS-L-002: OpenObserve is configured but not running**  
- `OPEN_OBSERVE_API_KEY` and `OPEN_OBSERVE_ENDPOINT` are listed as optional secrets in rald-notify but no OpenObserve instance URL is documented
- **Action:** Either provision OpenObserve Cloud or self-hosted; set secrets on all services

---

## 4. Target Observability Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   RALD Services                         │
│  rald-auth-core │ loop-api │ messenger │ rald-notify     │
│  rald-event-bus │ rald-config │ rald-inbox │ rald-search │
└──────────────┬──────────────────────────────────────────┘
               │  Structured logs + trace_id
               ▼
┌─────────────────────────┐      ┌─────────────────────────┐
│  Cloudflare Workers     │      │  OpenObserve             │
│  (real-time logs,       │─────▶│  (log aggregation,       │
│   exceptions, tail)     │      │   search, dashboards)    │
└─────────────────────────┘      └─────────────────────────┘
               │                               │
               ▼                               ▼
┌─────────────────────────┐      ┌─────────────────────────┐
│  Supabase audit_logs    │      │  Alerting (Slack/Email)  │
│  (identity events,      │      │  (anomalies, SLA,        │
│   session events)       │      │   auth failures)         │
└─────────────────────────┘      └─────────────────────────┘
```

---

## 5. Metrics Collected Today

### Auth Metrics (via /metrics/* endpoints in rald-auth-core)

Available today via admin-only API:
- `GET /metrics/overview` — total users, active sessions, countries
- `GET /metrics/registrations` — registrations by day
- `GET /metrics/trust-distribution` — users by trust tier
- `GET /metrics/otp-analytics` — OTP success/fail rates, channels
- `GET /metrics/session-health` — session count, revocations
- `GET /metrics/device-analytics` — device type distribution

These endpoints exist but are not surfaced in a dashboard yet.

---

## 6. Immediate Recommendations

1. **Set OpenObserve secrets** on rald-notify (add `OPEN_OBSERVE_API_KEY`, `OPEN_OBSERVE_ENDPOINT` to all services)
2. **Add `X-RALD-Trace-ID` header** to all cross-service requests for distributed tracing
3. **Configure external health monitors** for all `*.rald.cloud` endpoints
4. **Build metrics dashboard** in rald-control-center consuming `/metrics/*` endpoints
5. **Add Cloudflare Tail Worker** for real-time anomaly detection (OBS-C-001)
6. **Set Supabase slow query alerts** (OBS-L-001)

---

*RALD Observability — If it moves, we measure it.*  
*LILCKY STUDIO LIMITED · 2026*
