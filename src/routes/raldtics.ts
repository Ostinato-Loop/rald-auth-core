// RALD OS Phase 6 — RALDTICS Observability
// Executive dashboard API: signups, wallets, aliases, payments, messages.
// Track every product metric from one endpoint.
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";

const raldtics = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /raldtics/dashboard — executive overview ───────────────────────────────
raldtics.get("/dashboard", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data } = await db.from("raldtics_executive_dashboard").select("*").maybeSingle();
  return c.json({ dashboard: data ?? {}, generated_at: new Date().toISOString() });
});

// ── GET /raldtics/signups — signup funnel ─────────────────────────────────────
raldtics.get("/signups", adminMiddleware, async (c) => {
  const db = c.get("db");

  const [h1, h24, d7, d30, allTime] = await Promise.all([
    db.from("rald_users").select("id", { count: "exact", head: true }).gte("created_at", new Date(Date.now() - 3_600_000).toISOString()),
    db.from("rald_users").select("id", { count: "exact", head: true }).gte("created_at", new Date(Date.now() - 86_400_000).toISOString()),
    db.from("rald_users").select("id", { count: "exact", head: true }).gte("created_at", new Date(Date.now() - 604_800_000).toISOString()),
    db.from("rald_users").select("id", { count: "exact", head: true }).gte("created_at", new Date(Date.now() - 2_592_000_000).toISOString()),
    db.from("rald_users").select("id", { count: "exact", head: true }),
  ]);

  const byStatus = await db
    .from("rald_users")
    .select("provision_status")
    .then(({ data }) => {
      const counts: Record<string, number> = {};
      (data ?? []).forEach((r: any) => { counts[r.provision_status] = (counts[r.provision_status] ?? 0) + 1; });
      return counts;
    });

  return c.json({
    signups: {
      last_1h:  h1.count ?? 0,
      last_24h: h24.count ?? 0,
      last_7d:  d7.count ?? 0,
      last_30d: d30.count ?? 0,
      all_time: allTime.count ?? 0,
    },
    by_provision_status: byStatus,
  });
});

// ── GET /raldtics/products — per-product user counts ──────────────────────────
raldtics.get("/products", adminMiddleware, async (c) => {
  const db = c.get("db");

  const [products, wallets, aliases, mailboxes, messengers] = await Promise.all([
    db.from("rald_products").select("slug,name,status"),
    db.from("payrald_wallets").select("status", { count: "exact", head: true }).eq("status", "active"),
    db.from("alia_handles").select("status", { count: "exact", head: true }).eq("status", "active"),
    db.from("mail_accounts").select("status", { count: "exact", head: true }).eq("status", "active"),
    db.from("messenger_accounts").select("status", { count: "exact", head: true }).eq("status", "active"),
  ]);

  return c.json({
    products:    products.data ?? [],
    active_wallets:    wallets.count ?? 0,
    active_aliases:    aliases.count ?? 0,
    active_mailboxes:  mailboxes.count ?? 0,
    active_messengers: messengers.count ?? 0,
    generated_at: new Date().toISOString(),
  });
});

// ── GET /raldtics/trust — trust tier distribution ─────────────────────────────
raldtics.get("/trust", adminMiddleware, async (c) => {
  const db = c.get("db");

  const { data } = await db
    .from("rald_trust_profiles")
    .select("trust_tier,kyc_tier,is_merchant,is_creator,is_school,fraud_flagged,sanctions_flagged");

  const byTier: Record<string, number> = {};
  let merchants = 0, creators = 0, schools = 0, fraud = 0, sanctions = 0;

  (data ?? []).forEach((r: any) => {
    byTier[r.trust_tier] = (byTier[r.trust_tier] ?? 0) + 1;
    if (r.is_merchant) merchants++;
    if (r.is_creator)  creators++;
    if (r.is_school)   schools++;
    if (r.fraud_flagged)    fraud++;
    if (r.sanctions_flagged) sanctions++;
  });

  return c.json({
    total_profiles: data?.length ?? 0,
    by_tier:        byTier,
    merchants,
    creators,
    schools,
    fraud_flagged:      fraud,
    sanctions_flagged:  sanctions,
    generated_at: new Date().toISOString(),
  });
});

// ── GET /raldtics/retry-queue — provisioning pipeline health ──────────────────
raldtics.get("/retry-queue", adminMiddleware, async (c) => {
  const db = c.get("db");

  const { data } = await db.from("retry_queue_stats").select("*");
  const { data: exhausted } = await db
    .from("provision_retry_queue")
    .select("service,rald_id,last_error,created_at")
    .eq("status", "exhausted")
    .order("created_at", { ascending: false })
    .limit(10);

  return c.json({
    queue_stats:    data ?? [],
    stuck_samples:  exhausted ?? [],
    generated_at:   new Date().toISOString(),
  });
});

// ── POST /raldtics/snapshot — admin: force a metrics snapshot ─────────────────
raldtics.post("/snapshot", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const period = (c.req.query("period") as "1h" | "24h" | "7d" | "30d") ?? "24h";

  const dashboard = await db.from("raldtics_executive_dashboard").select("*").maybeSingle();
  const d = dashboard.data ?? {};

  const { data, error } = await db.from("raldtics_snapshots").insert({
    period,
    total_users:      d.total_identities ?? 0,
    signups:          period === "24h" ? (d.signups_24h ?? 0) : period === "7d" ? (d.signups_7d ?? 0) : (d.signups_30d ?? 0),
    active_users:     d.total_identities ?? 0,
    wallets:          d.active_wallets ?? 0,
    active_wallets:   d.active_wallets ?? 0,
    aliases:          d.active_aliases ?? 0,
    schools:          d.schools ?? 0,
    merchants:        d.merchants ?? 0,
  }).select().single();

  if (error) return c.json({ error: error.message }, 500);
  return c.json({ ok: true, snapshot: data });
});

export default raldtics;
