// RALD Auth Core — Expansion Management (Admin)
// Country Activation Pipeline: admin-only transition control.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const expansion = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Valid pipeline transitions (forward only unless restricting)
const PIPELINE: Record<string, string[]> = {
  WAITLIST:               ["REGULATORY_REVIEW"],
  REGULATORY_REVIEW:      ["INFRASTRUCTURE_REVIEW", "WAITLIST"],
  INFRASTRUCTURE_REVIEW:  ["MODERATION_REVIEW",     "REGULATORY_REVIEW"],
  MODERATION_REVIEW:      ["PREVIEW",               "INFRASTRUCTURE_REVIEW"],
  PREVIEW:                ["PRIVATE_BETA",           "MODERATION_REVIEW"],
  PRIVATE_BETA:           ["PUBLIC_BETA",            "PREVIEW"],
  PUBLIC_BETA:            ["ACTIVE",                 "PRIVATE_BETA"],
  ACTIVE:                 ["RESTRICTED"],
  RESTRICTED:             ["ACTIVE", "PUBLIC_BETA", "PRIVATE_BETA", "PREVIEW"],
};

// ── GET /admin/expansion — list all countries with full scorecard ─────────────
expansion.get("/", adminMiddleware, async (c) => {
  const db = c.get("db");

  const { data, error } = await db
    .from("country_registry")
    .select(`
      id, country_code, country_name, status,
      demand_score, legal_score, compliance_score, moderation_score, infrastructure_score, support_score,
      payrald_status, launch_date, activated_at, approved_by, approved_at,
      legal_notes, compliance_notes, moderation_notes, infrastructure_notes,
      created_at, updated_at
    `)
    .order("demand_score", { ascending: false });

  if (error) {
    return c.json({ error: "Failed to fetch expansion data" }, 500);
  }

  // Attach waitlist counts
  const counts: Record<string, number> = {};
  const { data: wl } = await db
    .from("country_waitlist")
    .select("country_code");
  for (const row of wl ?? []) {
    if (!row) continue;
    counts[row.country_code] = (counts[row.country_code] ?? 0) + 1;
  }

  const countries = (data ?? []).map(row => ({
    ...row,
    waitlist_count:   counts[row!.country_code] ?? 0,
    next_transitions: PIPELINE[row!.status] ?? [],
    readiness_score:  row ? Math.round(
      (row.legal_score + row.compliance_score + row.moderation_score + row.infrastructure_score + row.support_score) / 5
    ) : 0,
  }));

  return c.json({ ok: true, countries, total: countries.length });
});

// ── GET /admin/expansion/:code — single country detail ───────────────────────
expansion.get("/:code", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const code = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);

  const { data, error } = await db
    .from("country_registry")
    .select("*")
    .eq("country_code", code)
    .limit(1)
    .single();

  if (error || !data) return c.json({ error: "Country not found" }, 404);

  const { count: waitlistCount } = await db
    .from("country_waitlist")
    .select("id", { count: "exact", head: true })
    .eq("country_code", code);

  const { data: log } = await db
    .from("country_activation_log")
    .select("from_status, to_status, reason, created_at, changed_by")
    .eq("country_code", code)
    .order("created_at", { ascending: false })
    .limit(20);

  return c.json({
    ok: true,
    country: {
      ...data,
      waitlist_count:   waitlistCount ?? 0,
      next_transitions: PIPELINE[data.status] ?? [],
      readiness_score:  Math.round(
        (data.legal_score + data.compliance_score + data.moderation_score + data.infrastructure_score + data.support_score) / 5
      ),
    },
    activation_log: log ?? [],
  });
});

// ── POST /admin/expansion — add a new country to registry ────────────────────
expansion.post("/", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    country_code:  string;
    country_name:  string;
    status?:       string;
    demand_score?: number;
  }>().catch(() => null);

  if (!body?.country_code || !body?.country_name) {
    return c.json({ error: "country_code and country_name are required" }, 400);
  }

  const code   = body.country_code.toUpperCase().slice(0, 2);
  const status = body.status ?? "WAITLIST";

  const { data, error } = await db
    .from("country_registry")
    .insert({ country_code: code, country_name: body.country_name, status, demand_score: body.demand_score ?? 0 })
    .select("country_code, country_name, status")
    .limit(1)
    .single();

  if (error) {
    if (error.code === "23505") return c.json({ error: "Country already exists" }, 409);
    return c.json({ error: "Failed to add country" }, 500);
  }

  await writeAuditLog(db, {
    action: "country_added", ip, status: "success",
    metadata: { country_code: code, country_name: body.country_name, admin: user.id },
  });

  return c.json({ ok: true, country: data }, 201);
});

// ── PATCH /admin/expansion/:code/scorecard — update regulatory scores ─────────
expansion.patch("/:code/scorecard", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const code = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);

  const body = await c.req.json<{
    legal_score?:          number;
    compliance_score?:     number;
    moderation_score?:     number;
    infrastructure_score?: number;
    support_score?:        number;
    demand_score?:         number;
    legal_notes?:          string;
    compliance_notes?:     string;
    moderation_notes?:     string;
    infrastructure_notes?: string;
  }>().catch(() => null);

  if (!body) return c.json({ error: "Request body required" }, 400);

  const update: Record<string, unknown> = {};
  const allowed = [
    "legal_score","compliance_score","moderation_score","infrastructure_score","support_score","demand_score",
    "legal_notes","compliance_notes","moderation_notes","infrastructure_notes",
  ];
  const bodyRec = body as Record<string, unknown>;
  for (const key of allowed) {
    if (bodyRec[key] !== undefined) update[key] = bodyRec[key];
  }

  const { data, error } = await db
    .from("country_registry")
    .update(update)
    .eq("country_code", code)
    .select("country_code, country_name, status, legal_score, compliance_score, moderation_score, infrastructure_score, support_score, demand_score")
    .limit(1)
    .single();

  if (error || !data) return c.json({ error: "Country not found" }, 404);

  return c.json({ ok: true, country: data });
});

// ── POST /admin/expansion/:code/transition — move through pipeline ────────────
expansion.post("/:code/transition", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const code = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);

  const body = await c.req.json<{
    to_status: string;
    reason?:   string;
  }>().catch(() => null);

  if (!body?.to_status) return c.json({ error: "to_status is required" }, 400);
  const toStatus = body.to_status.toUpperCase();

  const { data: reg, error: fetchErr } = await db
    .from("country_registry")
    .select("country_code, country_name, status")
    .eq("country_code", code)
    .limit(1)
    .single();

  if (fetchErr || !reg) return c.json({ error: "Country not found" }, 404);

  const fromStatus  = reg.status as string;
  const allowed     = PIPELINE[fromStatus] ?? [];

  if (!allowed.includes(toStatus)) {
    return c.json({
      error:            `Cannot transition ${fromStatus} → ${toStatus}`,
      allowed_transitions: allowed,
    }, 422);
  }

  const updatePayload: Record<string, unknown> = { status: toStatus };
  if (toStatus === "ACTIVE") {
    updatePayload.activated_at  = new Date().toISOString();
    updatePayload.approved_by   = user.id;
    updatePayload.approved_at   = new Date().toISOString();
  }

  const { data: updated, error: updateErr } = await db
    .from("country_registry")
    .update(updatePayload)
    .eq("country_code", code)
    .select("country_code, country_name, status, activated_at")
    .limit(1)
    .single();

  if (updateErr || !updated) return c.json({ error: "Failed to update country status" }, 500);

  await db.from("country_activation_log").insert({
    country_code: code,
    from_status:  fromStatus,
    to_status:    toStatus,
    changed_by:   user.id,
    reason:       body.reason ?? null,
  });

  await writeAuditLog(db, {
    action: "country_status_changed", ip, status: "success",
    metadata: { country_code: code, from: fromStatus, to: toStatus, admin: user.id, reason: body.reason },
  });

  return c.json({
    ok:          true,
    country:     updated,
    transition:  { from: fromStatus, to: toStatus },
    message:     `${reg.country_name} moved from ${fromStatus} → ${toStatus}`,
  });
});

// ── POST /admin/expansion/:code/restrict — emergency kill switch ──────────────
// Must execute in under 60 seconds. Stops new onboarding while preserving existing users.
expansion.post("/:code/restrict", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const code = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);

  const body = await c.req.json<{ reason?: string }>().catch(() => ({}));

  const { data: reg } = await db
    .from("country_registry")
    .select("country_name, status")
    .eq("country_code", code)
    .limit(1)
    .single();

  if (!reg) return c.json({ error: "Country not found" }, 404);

  const fromStatus = reg.status as string;

  const { error } = await db
    .from("country_registry")
    .update({ status: "RESTRICTED" })
    .eq("country_code", code);

  if (error) return c.json({ error: "Emergency restrict failed" }, 500);

  await db.from("country_activation_log").insert({
    country_code: code,
    from_status:  fromStatus,
    to_status:    "RESTRICTED",
    changed_by:   user.id,
    reason:       body.reason ?? "Emergency restriction applied",
  });

  await writeAuditLog(db, {
    action: "country_restricted", ip, status: "success",
    metadata: { country_code: code, from: fromStatus, admin: user.id, reason: body.reason },
  });

  return c.json({
    ok:          true,
    country_code: code,
    country_name: reg.country_name,
    status:      "RESTRICTED",
    effective_immediately: true,
    effects: [
      "new registrations stopped",
      "new business workspaces blocked",
      "new civic rooms blocked",
      "financial services stopped",
      "existing users retain access",
    ],
    message: `${reg.country_name} has been restricted. Existing users are unaffected.`,
  });
});

// ── PATCH /admin/expansion/:code/payrald — manage PayRald gate separately ─────
expansion.patch("/:code/payrald", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const code = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);

  const body = await c.req.json<{ status: string; reason?: string }>().catch(() => null);
  if (!body?.status) return c.json({ error: "status is required" }, 400);

  const { data, error } = await db
    .from("country_registry")
    .update({ payrald_status: body.status, payrald_approved_at: new Date().toISOString() })
    .eq("country_code", code)
    .select("country_code, country_name, payrald_status")
    .limit(1)
    .single();

  if (error || !data) return c.json({ error: "Country not found" }, 404);

  await writeAuditLog(db, {
    action: "payrald_gate_updated", ip, status: "success",
    metadata: { country_code: code, payrald_status: body.status, admin: user.id },
  });

  return c.json({ ok: true, country: data, message: `PayRald status for ${data.country_name} set to ${body.status}` });
});

// ── GET /admin/expansion/:code/waitlist — paginated waitlist ──────────────────
expansion.get("/:code/waitlist", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const code   = (c.req.param("code") ?? "").toUpperCase().slice(0, 2);
  const limit  = Math.min(Number(c.req.query("limit") ?? 50), 200);
  const offset = Number(c.req.query("offset") ?? 0);

  const { data, count, error } = await db
    .from("country_waitlist")
    .select("id, state, city, email, username, created_at", { count: "exact" })
    .eq("country_code", code)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) return c.json({ error: "Failed to fetch waitlist" }, 500);

  return c.json({ ok: true, country_code: code, total: count ?? 0, offset, limit, entries: data ?? [] });
});

export default expansion;
