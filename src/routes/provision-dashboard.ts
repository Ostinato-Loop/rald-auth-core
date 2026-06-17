// RALD Phase 1 — Provisioning Dashboard API
// Admin-only endpoints providing live visibility into the identity
// provisioning pipeline: stats, per-user status, failed items, audit trails.
// Consumed by rald-control-center admin UI.
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";
import { processRetryQueue } from "../lib/identity-provisioner";

const dashboard = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /admin/provision/dashboard — headline stats ────────────────────────────
dashboard.get("/dashboard", adminMiddleware, async (c) => {
  const db = c.get("db");

  const [statsRes, retryStatsRes, recentRes, failedRes] = await Promise.all([
    db.from("provision_dashboard_stats").select("*").maybeSingle(),
    db.from("retry_queue_stats").select("*"),
    db.from("rald_users")
      .select("id,username,rald_email,provision_status,activated_products,created_at")
      .order("created_at", { ascending: false })
      .limit(10),
    db.from("provision_retry_queue")
      .select("rald_id,service,status,attempt_count,max_attempts,last_error,next_retry_at,created_at")
      .in("status", ["pending","retrying","exhausted"])
      .order("created_at", { ascending: false })
      .limit(20),
  ]);

  const serviceHealth = ["wallet","alia","mail","messenger"].map(svc => {
    const successCount = (retryStatsRes.data ?? []).find(
      (r: any) => r.service === svc && r.status === "success"
    )?.count ?? 0;
    const failedCount = (retryStatsRes.data ?? []).find(
      (r: any) => r.service === svc && r.status === "exhausted"
    )?.count ?? 0;
    const pendingCount = (retryStatsRes.data ?? [])
      .filter((r: any) => r.service === svc && ["pending","retrying"].includes(r.status))
      .reduce((acc: number, r: any) => acc + (r.count ?? 0), 0);
    return { service: svc, succeeded: successCount, pending: pendingCount, exhausted: failedCount };
  });

  return c.json({
    stats:           statsRes.data ?? {},
    service_health:  serviceHealth,
    retry_queue:     retryStatsRes.data ?? [],
    recent_signups:  recentRes.data ?? [],
    stuck_items:     failedRes.data ?? [],
    generated_at:    new Date().toISOString(),
  });
});

// ── GET /admin/provision/users — paginated user list ──────────────────────────
dashboard.get("/users", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const page   = Math.max(1, Number(c.req.query("page") ?? "1"));
  const limit  = Math.min(100, Number(c.req.query("limit") ?? "50"));
  const status = c.req.query("status");
  const search = c.req.query("q");

  let query = db
    .from("rald_users")
    .select("id,username,rald_email,alia_handle,wallet_id,provision_status,trust_score,kyc_tier,activated_products,created_at")
    .order("created_at", { ascending: false })
    .range((page - 1) * limit, page * limit - 1);

  if (status) query = query.eq("provision_status", status);
  if (search) query = query.or(`username.ilike.%${search}%,rald_email.ilike.%${search}%`);

  const { data, count } = await query;

  return c.json({
    users:      data ?? [],
    total:      count ?? 0,
    page,
    limit,
    has_more:   (data?.length ?? 0) === limit,
  });
});

// ── GET /admin/provision/failed — stuck / exhausted items ─────────────────────
dashboard.get("/failed", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data } = await db
    .from("provision_retry_queue")
    .select(`
      id,rald_id,service,status,attempt_count,max_attempts,
      last_error,next_retry_at,created_at,
      rald_users(username,rald_email,provision_status)
    `)
    .in("status", ["exhausted","pending","retrying"])
    .order("created_at", { ascending: false })
    .limit(100);

  return c.json({ failed: data ?? [], count: data?.length ?? 0 });
});

// ── GET /admin/provision/audit/:rald_id — full audit trail ────────────────────
dashboard.get("/audit/:rald_id", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const [identityRes, auditRes, retryRes] = await Promise.all([
    db.from("rald_users").select("*").eq("id", raldId).maybeSingle(),
    db.from("provision_audit_log")
      .select("*")
      .eq("rald_id", raldId)
      .order("created_at", { ascending: true }),
    db.from("provision_retry_queue")
      .select("*")
      .eq("rald_id", raldId)
      .order("created_at", { ascending: true }),
  ]);

  if (!identityRes.data) return c.json({ error: "Identity not found" }, 404);

  // Build timeline: merge audit events and retry events
  const timeline = [
    ...(auditRes.data ?? []).map((e: any) => ({
      ...e,
      _kind: "audit",
    })),
    ...(retryRes.data ?? []).map((e: any) => ({
      ...e,
      _kind: "retry",
    })),
  ].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

  return c.json({
    identity:  identityRes.data,
    timeline,
    audit:     auditRes.data ?? [],
    retries:   retryRes.data ?? [],
  });
});

// ── POST /admin/provision/retry-all — drain the retry queue now ───────────────
dashboard.post("/retry-all", adminMiddleware, async (c) => {
  const db = c.get("db");
  const stats = await processRetryQueue(db);
  return c.json({
    ok: true,
    message: "Retry queue drained",
    ...stats,
  });
});

// ── POST /admin/provision/reprovision/:rald_id — force re-run all steps ────────
dashboard.post("/reprovision/:rald_id", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  // Reset provision_status so finalize can set it back correctly
  await Promise.resolve(
    db.from("rald_users")
      .update({ provision_status: "provisioning", updated_at: new Date().toISOString() })
      .eq("id", raldId)
  ).then(undefined, () => null);

  // Reset exhausted retries to pending
  await Promise.resolve(
    db.from("provision_retry_queue")
      .update({ status: "pending", next_retry_at: new Date().toISOString() })
      .eq("rald_id", raldId)
      .eq("status", "exhausted")
  ).then(undefined, () => null);

  const stats = await processRetryQueue(db);
  return c.json({ ok: true, rald_id: raldId, ...stats });
});

export default dashboard;
