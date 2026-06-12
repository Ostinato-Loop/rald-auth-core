# RALD LOOP RETENTION ENGINE REPORT
## Hardening Sprint — Phase 11

**Generated:** 2026-06-12  
**Scope:** Loop — Civic, Entertainment, Business retention  
**Prepared by:** RALD Platform Engineering · LILCKY STUDIO LIMITED

---

## Architecture: Three Retention Pillars

Loop's retention is intentionally structured across three distinct room/community types. Each has different retention drivers.

```
LOOP RETENTION ENGINE
├── CIVIC (daily discussions, governance, local participation)
├── ENTERTAINMENT (creators, shows, clubs, live rooms)
└── BUSINESS (storefronts, professional communities, commerce)
```

---

## D1 Schema Implemented

| Table | Purpose |
|---|---|
| `retention_metrics` | Per-user D1/D7/D30 retention with session count, rooms joined/created |
| `daily_active_users` | Aggregated DAU by country + platform (feeds metrics dashboard) |
| `room_analytics_summary` | Peak listeners, duration, replay count, share count per room |
| `cleanup_schedule` | CleanupCoordinator DO queue — fixes C-004 cron quota exhaustion |
| `content_flags` | Moderation: rooms, messages, communities, users, profiles |

---

## Room Quality Scores

```sql
-- Computed from room_analytics_summary
room_quality_score = (
  (peak_listeners * 0.3) +
  (duration_seconds / 3600.0 * 0.2) +      -- hours of content
  (replay_count * 0.3) +
  (share_count * 0.2)
) normalized to 0.0–1.0
```

Rooms scoring > 0.7 qualify for:
- Algorithm boost ("Top Rooms" surface)
- Host reliability credit
- Community health contribution

---

## Host Reliability Score

Computed per host over trailing 30 days:

| Signal | Weight |
|---|---|
| Rooms started on time (< 5 min late) | 30% |
| Rooms that ran > 15 minutes | 25% |
| Average peak listeners | 20% |
| Audience return rate (same host, next room) | 15% |
| No content flags on rooms | 10% |

Score tiers: `new` → `emerging` → `reliable` → `top` → `elite`

---

## Community Health Score

Signals per community (trailing 30 days):

| Signal | Weight |
|---|---|
| Weekly active members / total members | 30% |
| New members joining | 20% |
| Rooms created per week | 25% |
| Member retention (D7) | 15% |
| Content flags received | -10% penalty |

Score tiers: `inactive` → `low` → `healthy` → `vibrant` → `thriving`

---

## Retention by Pillar

### Civic Retention
- **Driver:** Daily content habit — governance updates, community discussions
- **Key metric:** D7 return rate of users who joined a civic room
- **Target at beta:** > 40% D7 for civic room joiners
- **Levers:** Push notifications for scheduled civic rooms, community updates

### Entertainment Retention
- **Driver:** Creator loyalty + show scheduling
- **Key metric:** Replay plays per room, return rate to same host
- **Target at beta:** > 25% D7 for entertainment room joiners
- **Levers:** Creator notifications, show scheduling, replay surfacing

### Business Retention
- **Driver:** Professional utility — recurring meetings, commerce
- **Key metric:** Community activity score, D30 return
- **Target at beta:** > 50% D30 for business community members
- **Levers:** Business room scheduling, storefront updates, commerce notifications

---

## Cleanup & Moderation

- `cleanup_schedule` — DO reads this instead of relying on cron (fixes C-004)
- `content_flags` — All moderation actions logged with content_type + content_id + reason
- Pending moderation items visible in rald-control-center (admin queue)

---

## Implementation Status

| Component | Status |
|---|---|
| D1 schema (5 tables) | ✅ Loop PR #17 |
| Retention metrics ingestion | 🟡 Loop API needs POST /analytics/session route |
| Room quality score computation | 🟡 Needs DO or scheduled worker |
| Host reliability score computation | 🟡 Needs aggregate query in loop-api |
| Community health score computation | 🟡 Needs aggregate query in loop-api |
| DAU aggregation job | 🟡 Needs cron trigger or DO |
| Moderation queue in control center | 🟡 Pending rald-control-center work |

---

*Loop Retention — Built for Africa's social fabric.*  
*LILCKY STUDIO LIMITED · 2026*
