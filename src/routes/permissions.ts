// RALD Auth Core — Permission Engine Routes
// Sprint: Operator Platform Phase 6 · 2026-06-12
// RBAC permission checks for all RALD products.
// Products call POST /permissions/check before gating features.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { getClientIp } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const permissions = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /permissions — list all permission definitions ────────────────────────
permissions.get("/permissions", async (c) => {
  const db = c.get("db");
  const scope = c.req.query("scope");
  let q = db.from("permission_definitions").select("*").order("scope,name");
  if (scope) q = q.eq("scope", scope);
  const { data, error } = await q;
  if (error) return c.json({ error: "Failed to fetch permissions" }, 500);
  return c.json({ permissions: data ?? [], count: data?.length ?? 0 });
});

// ── POST /permissions/check — check if a user has permission ──────────────────
// This is the primary API that products call.
// Returns { granted: bool, reason: string } in < 50ms (no external calls).
permissions.post("/permissions/check", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const body = await c.req.json<{
    scope:      string;
    permission: string;
    country?:   string;
  }>().catch(() => null);
  if (!body?.scope || !body.permission) {
    return c.json({ error: "scope and permission are required" }, 400);
  }

  // 1. Check for explicit override (overrides trump everything)
  const { data: override } = await db.from("user_permission_overrides")
    .select("granted,reason,expires_at")
    .eq("user_id", user.id).eq("scope", body.scope).eq("permission", body.permission)
    .single();
  if (override) {
    if (override.expires_at && new Date(override.expires_at) < new Date()) {
      // Override expired — fall through to standard check
    } else {
      return c.json({ granted: override.granted, reason: override.reason ?? (override.granted ? "explicit_grant" : "explicit_deny"), source: "override" });
    }
  }

  // 2. Fetch permission definition
  const { data: permDef } = await db.from("permission_definitions")
    .select("tier_required,country_restrictions")
    .eq("scope", body.scope).eq("name", body.permission).single();
  if (!permDef) {
    return c.json({ granted: false, reason: "permission_not_found", source: "registry" });
  }

  // 3. Check country restrictions
  if (body.country && permDef.country_restrictions?.length > 0) {
    if (permDef.country_restrictions.includes(body.country)) {
      return c.json({ granted: false, reason: "country_restricted", source: "regulatory", country: body.country });
    }
  }

  // 4. Check trust tier requirement
  const { data: trust } = await db.from("trust_scores").select("tier,score").eq("user_id", user.id).single();
  const tier = trust?.tier ?? "none";

  const tierOrder = ["none", "basic", "standard", "verified", "creator", "civic", "premium"];
  const userTierIdx    = tierOrder.indexOf(tier);
  const requiredTierIdx = tierOrder.indexOf(permDef.tier_required);

  if (userTierIdx < requiredTierIdx) {
    return c.json({
      granted: false,
      reason:  "insufficient_trust_tier",
      source:  "trust_engine",
      required_tier: permDef.tier_required,
      current_tier:  tier,
    });
  }

  return c.json({ granted: true, reason: "trust_tier_met", source: "trust_engine", current_tier: tier });
});

// ── GET /permissions/user/:userId — all overrides for a user (admin) ──────────
permissions.get("/permissions/user/:userId", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data, error } = await db.from("user_permission_overrides")
    .select("*").eq("user_id", c.req.param("userId")).order("created_at", { ascending: false });
  if (error) return c.json({ error: "Failed to fetch overrides" }, 500);
  return c.json({ overrides: data ?? [] });
});

// ── POST /permissions/override — grant or deny a specific permission (admin) ──
permissions.post("/permissions/override", adminMiddleware, async (c) => {
  const db = c.get("db");
  const admin = c.get("user")!;
  const ip = getClientIp(c.req.raw);
  const body = await c.req.json<{
    user_id: string; scope: string; permission: string;
    granted: boolean; reason?: string; expires_at?: string;
  }>().catch(() => null);
  if (!body?.user_id || !body.scope || !body.permission) {
    return c.json({ error: "user_id, scope, permission required" }, 400);
  }
  const { data, error } = await db.from("user_permission_overrides").upsert({
    user_id: body.user_id, scope: body.scope, permission: body.permission,
    granted: body.granted, reason: body.reason ?? null, granted_by: admin.id, expires_at: body.expires_at ?? null,
  }, { onConflict: "user_id,scope,permission" }).select().single();
  if (error) return c.json({ error: "Failed to set override" }, 500);
  await writeAuditLog(db, { userId: admin.id, action: "permission.override", ip, status: "success",
    metadata: { target_user: body.user_id, scope: body.scope, permission: body.permission, granted: body.granted } });
  return c.json(data, 201);
});

// ── GET /permissions/regulatory/:country — regulatory profile ─────────────────
permissions.get("/permissions/regulatory/:country", async (c) => {
  const db = c.get("db");
  const country = c.req.param("country").toUpperCase();
  const { data } = await db.from("regulatory_profiles").select("*").eq("country_code", country).single();
  if (!data) return c.json({ error: "Country not found in regulatory registry" }, 404);
  return c.json(data);
});

export default permissions;
