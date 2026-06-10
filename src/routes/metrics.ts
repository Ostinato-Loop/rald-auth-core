// RALD Auth Core — Internal Observability Metrics
// GET  /admin/metrics          — key operational counters (last 24h / 7d)
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

export default metrics;
