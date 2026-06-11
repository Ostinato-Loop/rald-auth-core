// RALD Auth Core — Internal Observability Metrics
// GET  /admin/metrics          — key operational counters (last 24h / 7d)
// GET  /admin/metrics/retention — D1 / D7 / D30 cohort retention
// Phase 6 Hardening Sprint (2026-06-11): Added retention cohort endpoint
// GET  /admin/metrics/realtime — live: last 60 min, 5-min buckets
//
// Protected by admin JWT. Never exposed publicly.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";

const metrics = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /admin/metrics ────────────────────────────────────────────────────────
metrics.get("/", adminMiddleware, async (c) => {
  const db = c.get("db");
  const now = new Date();
  const h24 = new Date(now.getTime() - 24 * 3600 * 1000).toISOString();
  const d7  = new Date(now.getTime() - 7 * 86400 * 1000).toISOString();

  const auditCount = (action: string, since: string) =>
    db.from("audit_logs")
      .select("id", { count: "exact", head: true })
      .eq("action", action)
      .gte("created_at", since);

  const [
    signups24h,  signups7d,
    otpOk24h,    otpOk7d,
    otpFail24h,  otpFail7d,
    logins24h,   logins7d,
    logouts24h,
    sessions24h,
    rateLimited24h,
  ] = await Promise.all([
    auditCount("username_claimed", h24),
    auditCount("username_claimed", d7),
    auditCount("otp_verified",     h24),
    auditCount("otp_verified",     d7),
    auditCount("otp_failed",       h24),
    auditCount("otp_failed",       d7),
    auditCount("login",            h24),
    auditCount("login",            d7),
    auditCount("logout",           h24),
    auditCount("session_created",  h24),
    auditCount("rate_limited",     h24),
  ]);

  const n = (r: Awaited<ReturnType<typeof auditCount>>) => r.count ?? 0;
  const otpSuccessRate = (ok: number, fail: number) =>
    ok + fail > 0 ? Math.round((ok / (ok + fail)) * 100) : null;

  const ok24h = n(otpOk24h);
  const ok7d  = n(otpOk7d);
  const f24h  = n(otpFail24h);
  const f7d   = n(otpFail7d);

  return c.json({
    generated_at: now.toISOString(),
    window: { h24, d7 },
    signups: {
      last_24h: n(signups24h),
      last_7d:  n(signups7d),
    },
    otp: {
      success_24h:      ok24h,
      success_7d:       ok7d,
      failure_24h:      f24h,
      failure_7d:       f7d,
      success_rate_24h: otpSuccessRate(ok24h, f24h),
      success_rate_7d:  otpSuccessRate(ok7d,  f7d),
    },
    sessions: {
      logins_24h:   n(logins24h),
      logins_7d:    n(logins7d),
      logouts_24h:  n(logouts24h),
      created_24h:  n(sessions24h),
    },
    security: {
      rate_limited_24h: n(rateLimited24h),
    },
  });
});

// ── GET /admin/metrics/realtime — 5-min buckets, last 60 min ─────────────────
metrics.get("/realtime", adminMiddleware, async (c) => {
  const db  = c.get("db");
  const since = new Date(Date.now() - 3600 * 1000).toISOString();

  const actions = ["username_claimed", "otp_verified", "otp_failed", "login", "logout"] as const;
  const results = await Promise.all(
    actions.map(action =>
      db.from("audit_logs")
        .select("created_at")
        .eq("action", action)
        .gte("created_at", since)
        .order("created_at", { ascending: true })
        .then(r => ({ action, rows: r.data ?? [] }))
    )
  );

  // Group into 5-minute buckets
  const bucket = (iso: string) => {
    const d = new Date(iso);
    d.setSeconds(0, 0);
    d.setMinutes(Math.floor(d.getMinutes() / 5) * 5);
    return d.toISOString();
  };

  const buckets: Record<string, Record<string, number>> = {};
  for (const { action, rows } of results) {
    for (const row of rows) {
      const b = bucket(row.created_at as string);
      if (!buckets[b]) buckets[b] = {};
      buckets[b][action] = (buckets[b][action] ?? 0) + 1;
    }
  }

  const timeline = Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, counts]) => ({ time, ...counts }));

  return c.json({
    generated_at: new Date().toISOString(),
    since,
    interval_minutes: 5,
    timeline,
  });
});



// ── GET /admin/metrics/retention — D1 / D7 / D30 cohort retention ─────────────
// Phase 6 — Public Beta Hardening Sprint
// Computes cohort retention using audit_logs (login actions as "active" signal).
// D1 cohort: users who registered 1–2 days ago; retained = had login action in last 24h.
// D7 cohort: users who registered 7–14 days ago; retained = had login in last 7 days.
// D30 cohort: users who registered 30–60 days ago; retained = had login in last 30 days.
// LILCKY STUDIO LIMITED
metrics.get("/retention", adminMiddleware, async (c) => {
  const db  = c.get("db");
  const now = new Date();

  const ts = (daysAgo: number) => new Date(now.getTime() - daysAgo * 86_400_000).toISOString();

  // Cohort windows
  const d1_start  = ts(2);  const d1_end  = ts(1);
  const d7_start  = ts(14); const d7_end  = ts(7);
  const d30_start = ts(60); const d30_end = ts(30);

  // Activity windows
  const active_d1  = ts(1);
  const active_d7  = ts(7);
  const active_d30 = ts(30);

  // Fetch cohort sizes and retained counts in parallel
  const [
    d1_cohort, d7_cohort, d30_cohort,
    d1_active, d7_active, d30_active,
    total_users, new_7d, new_30d,
  ] = await Promise.all([
    // Cohort sizes: users who registered in each window
    db.from("audit_logs").select("user_id", { count: "exact", head: true })
      .eq("action", "register").gte("created_at", d1_start).lt("created_at", d1_end),
    db.from("audit_logs").select("user_id", { count: "exact", head: true })
      .eq("action", "register").gte("created_at", d7_start).lt("created_at", d7_end),
    db.from("audit_logs").select("user_id", { count: "exact", head: true })
      .eq("action", "register").gte("created_at", d30_start).lt("created_at", d30_end),
    // Retained: users from each cohort who had ANY login in the activity window
    // We approximate by counting distinct user_ids with login actions in the window
    // (Supabase doesn't do subqueries; we do two-step in memory for exact numbers)
    db.from("audit_logs").select("user_id").eq("action", "login")
      .gte("created_at", active_d1).gte("created_at", d1_start),
    db.from("audit_logs").select("user_id").eq("action", "login")
      .gte("created_at", active_d7).gte("created_at", d7_start),
    db.from("audit_logs").select("user_id").eq("action", "login")
      .gte("created_at", active_d30).gte("created_at", d30_start),
    // Total users and recent new users
    db.from("auth_users").select("id", { count: "exact", head: true }),
    db.from("auth_users").select("id", { count: "exact", head: true }).gte("created_at", ts(7)),
    db.from("auth_users").select("id", { count: "exact", head: true }).gte("created_at", ts(30)),
  ]);

  // Deduplicate retained user IDs in memory
  const uniq = (rows: { user_id: string }[] | null) =>
    new Set((rows ?? []).map(r => r.user_id)).size;

  const d1_cohort_n  = d1_cohort.count  ?? 0;
  const d7_cohort_n  = d7_cohort.count  ?? 0;
  const d30_cohort_n = d30_cohort.count ?? 0;

  const d1_ret_n  = uniq(d1_active.data  as { user_id: string }[] | null);
  const d7_ret_n  = uniq(d7_active.data  as { user_id: string }[] | null);
  const d30_ret_n = uniq(d30_active.data as { user_id: string }[] | null);

  const pct = (retained: number, cohort: number) =>
    cohort > 0 ? Math.round((retained / cohort) * 100) : null;

  return c.json({
    generated_at:   now.toISOString(),
    total_users:    total_users.count ?? 0,
    new_users_7d:   new_7d.count ?? 0,
    new_users_30d:  new_30d.count ?? 0,
    d1: {
      cohort_size:   d1_cohort_n,
      retained:      d1_ret_n,
      retention_pct: pct(d1_ret_n, d1_cohort_n),
    },
    d7: {
      cohort_size:   d7_cohort_n,
      retained:      d7_ret_n,
      retention_pct: pct(d7_ret_n, d7_cohort_n),
    },
    d30: {
      cohort_size:   d30_cohort_n,
      retained:      d30_ret_n,
      retention_pct: pct(d30_ret_n, d30_cohort_n),
    },
  });
});

export default metrics;
