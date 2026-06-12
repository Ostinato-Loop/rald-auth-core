/**
 * RALD Auth Core — Developer Portal Routes
 * /developer/* — API key management, app registry, webhooks, audit logs
 *
 * Routes:
 *   POST  /developer/onboard          — create developer profile
 *   GET   /developer/profile          — get developer profile
 *   GET   /developer/stats            — dashboard stats
 *   GET   /developer/keys             — list API keys
 *   POST  /developer/keys             — create API key
 *   POST  /developer/keys/:id/rotate  — rotate a key
 *   POST  /developer/keys/:id/revoke  — revoke a key
 *   POST  /developer/keys/:id/suspend — suspend a key
 *   GET   /developer/apps             — list registered applications
 *   POST  /developer/apps             — register new application
 *   PATCH /developer/apps/:id         — update application
 *   GET   /developer/webhooks         — list webhooks
 *   POST  /developer/webhooks         — create webhook
 *   DELETE /developer/webhooks/:id    — delete webhook
 *   GET   /developer/audit            — get audit logs
 *   GET   /developer/usage            — get API usage stats
 *
 * LILCKY STUDIO LIMITED · 2026-06-12
 */

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { getClientIp } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const developer = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Helpers ──────────────────────────────────────────────────────────────────

function generateDevId(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "dev_rald_";
  for (let i = 0; i < 8; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

function generateApiKey(type: string): { prefix: string; full: string; hash: string } {
  const prefixMap: Record<string, string> = {
    MASTER:    "rk_live",
    PRODUCT:   "rp_live",
    WORKSPACE: "rw_live",
    SERVICE:   "rs_live",
  };
  const prefix = prefixMap[type] ?? "rk_live";
  const chars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let secret   = "";
  for (let i = 0; i < 32; i++) secret += chars[Math.floor(Math.random() * chars.length)];
  const full = `${prefix}_${secret}`;
  const hash = btoa(full).slice(0, 32);
  return { prefix: `${prefix}_${secret.slice(0, 6)}`, full, hash };
}

// ── POST /developer/onboard ───────────────────────────────────────────────────

developer.post("/onboard", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    developer_name?: string;
    organization?: string;
    website?: string;
    country?: string;
  }>().catch(() => null);

  if (!body?.developer_name?.trim()) {
    return c.json({ error: "developer_name is required" }, 400);
  }

  const existing = await db
    .from("developer_profiles")
    .select("dev_id")
    .eq("user_id", user.id)
    .maybeSingle();

  if (existing.data) {
    return c.json({ error: "Developer profile already exists" }, 409);
  }

  const devId = generateDevId();
  const now   = new Date().toISOString();

  const { data, error } = await db
    .from("developer_profiles")
    .insert({
      user_id:             user.id,
      dev_id:              devId,
      developer_name:      body.developer_name.trim(),
      organization:        body.organization?.trim() ?? null,
      website:             body.website?.trim() ?? null,
      country:             body.country?.trim() ?? null,
      verification_status: "unverified",
      trust_level:         1,
      api_usage_tier:      "Starter",
      created_at:          now,
    })
    .select()
    .single();

  if (error) {
    console.error("[developer/onboard]", error);
    return c.json({ error: "Failed to create developer profile" }, 500);
  }

  const masterKey = generateApiKey("MASTER");
  await db.from("developer_api_keys").insert({
    user_id:    user.id,
    type:       "MASTER",
    name:       "Master Key",
    prefix:     masterKey.prefix,
    key_hash:   masterKey.hash,
    scopes:     ["identity:read", "identity:write", "keys:create"],
    status:     "active",
    created_at: now,
  });

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "developer.onboarded",
    resourceType: "developer_profile",
    resourceId:   devId,
    ip,
    metadata:     { dev_id: devId, has_master_key: true },
  });

  return c.json({ ...data, master_key: masterKey.full }, 201);
});

// ── GET /developer/profile ────────────────────────────────────────────────────

developer.get("/profile", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .from("developer_profiles")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  if (error) return c.json({ error: "Failed to fetch profile" }, 500);
  if (!data)  return c.json({ error: "Developer profile not found. Complete onboarding first." }, 404);
  return c.json(data);
});

// ── GET /developer/stats ──────────────────────────────────────────────────────

developer.get("/stats", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [keysRes, appsRes, webhooksRes] = await Promise.all([
    db.from("developer_api_keys").select("id,status").eq("user_id", user.id),
    db.from("developer_registered_apps").select("id,status").eq("user_id", user.id),
    db.from("developer_webhooks").select("id").eq("user_id", user.id),
  ]);

  const keys  = keysRes.data  ?? [];
  const apps  = appsRes.data  ?? [];
  const hooks = webhooksRes.data ?? [];

  return c.json({
    total_keys:     keys.length,
    active_keys:    keys.filter((k) => (k as { status: string }).status === "active").length,
    total_apps:     apps.length,
    active_apps:    apps.filter((a) => (a as { status: string }).status !== "suspended").length,
    total_webhooks: hooks.length,
    usage: {
      total_calls:          0,
      calls_today:          0,
      calls_this_month:     0,
      rate_limit:           1000,
      rate_limit_remaining: 1000,
      top_endpoints:        [],
    },
  });
});

// ── GET /developer/keys ───────────────────────────────────────────────────────

developer.get("/keys", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .from("developer_api_keys")
    .select("id,type,name,prefix,product,workspace_id,scopes,status,created_at,last_used_at,revoked_at")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return c.json({ error: "Failed to fetch keys" }, 500);
  return c.json({ keys: data ?? [] });
});

// ── POST /developer/keys ──────────────────────────────────────────────────────

developer.post("/keys", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    type?: string;
    name?: string;
    product?: string;
    workspace_id?: string;
    scopes?: string[];
  }>().catch(() => null);

  const VALID_TYPES = ["MASTER", "PRODUCT", "WORKSPACE", "SERVICE"];
  if (!body?.type || !VALID_TYPES.includes(body.type)) {
    return c.json({ error: `type must be one of: ${VALID_TYPES.join(", ")}` }, 400);
  }
  if (!body.name?.trim()) return c.json({ error: "name is required" }, 400);

  if (body.type === "MASTER") {
    const existing = await db
      .from("developer_api_keys")
      .select("id")
      .eq("user_id", user.id)
      .eq("type", "MASTER")
      .eq("status", "active")
      .maybeSingle();
    if (existing.data) {
      return c.json({ error: "You already have an active Master Key. Rotate it instead." }, 409);
    }
  }

  const k   = generateApiKey(body.type);
  const now = new Date().toISOString();

  const { data, error } = await db
    .from("developer_api_keys")
    .insert({
      user_id:      user.id,
      type:         body.type,
      name:         body.name.trim(),
      prefix:       k.prefix,
      key_hash:     k.hash,
      product:      body.product ?? null,
      workspace_id: body.workspace_id ?? null,
      scopes:       body.scopes ?? [],
      status:       "active",
      created_at:   now,
    })
    .select("id,type,name,prefix,product,workspace_id,scopes,status,created_at")
    .single();

  if (error) return c.json({ error: "Failed to create key" }, 500);

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "api_key.created",
    resourceType: "api_key",
    resourceId:   data.id as string,
    ip,
    metadata:     { type: body.type, name: body.name },
  });

  return c.json({ key: { ...data, display_key: k.full } }, 201);
});

// ── POST /developer/keys/:id/rotate ──────────────────────────────────────────

developer.post("/keys/:id/rotate", authMiddleware, async (c) => {
  const user    = c.get("user")!;
  const db      = c.get("db");
  const ip      = getClientIp(c.req.raw);
  const { id }  = c.req.param();

  const { data: existing } = await db
    .from("developer_api_keys")
    .select("id,type,name")
    .eq("id", id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!existing) return c.json({ error: "Key not found" }, 404);

  const k = generateApiKey((existing as { type: string }).type);

  const { data, error } = await db
    .from("developer_api_keys")
    .update({ prefix: k.prefix, key_hash: k.hash, last_used_at: null })
    .eq("id", id)
    .eq("user_id", user.id)
    .select("id,type,name,prefix,product,workspace_id,scopes,status,created_at")
    .single();

  if (error) return c.json({ error: "Failed to rotate key" }, 500);

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "api_key.rotated",
    resourceType: "api_key",
    resourceId:   id,
    ip,
    metadata:     { name: (existing as { name: string }).name },
  });

  return c.json({ key: { ...data, display_key: k.full } });
});

// ── POST /developer/keys/:id/revoke ──────────────────────────────────────────

developer.post("/keys/:id/revoke", authMiddleware, async (c) => {
  const user   = c.get("user")!;
  const db     = c.get("db");
  const ip     = getClientIp(c.req.raw);
  const { id } = c.req.param();

  const { error } = await db
    .from("developer_api_keys")
    .update({ status: "revoked", revoked_at: new Date().toISOString() })
    .eq("id", id)
    .eq("user_id", user.id);

  if (error) return c.json({ error: "Failed to revoke key" }, 500);

  await writeAuditLog(db, {
    userId: user.id, action: "api_key.revoked",
    resourceType: "api_key", resourceId: id, ip,
  });
  return c.json({ ok: true });
});

// ── POST /developer/keys/:id/suspend ─────────────────────────────────────────

developer.post("/keys/:id/suspend", authMiddleware, async (c) => {
  const user   = c.get("user")!;
  const db     = c.get("db");
  const { id } = c.req.param();

  const { error } = await db
    .from("developer_api_keys")
    .update({ status: "suspended" })
    .eq("id", id)
    .eq("user_id", user.id);

  if (error) return c.json({ error: "Failed to suspend key" }, 500);
  return c.json({ ok: true });
});

// ── GET /developer/apps ───────────────────────────────────────────────────────

developer.get("/apps", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .from("developer_registered_apps")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return c.json({ error: "Failed to fetch apps" }, 500);
  return c.json({ apps: data ?? [] });
});

// ── POST /developer/apps ──────────────────────────────────────────────────────

developer.post("/apps", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    name?: string;
    description?: string;
    website?: string;
    country?: string;
    callback_urls?: string[];
    environment?: string;
  }>().catch(() => null);

  if (!body?.name?.trim()) return c.json({ error: "name is required" }, 400);

  const appId = `app_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const { data, error } = await db
    .from("developer_registered_apps")
    .insert({
      user_id:       user.id,
      app_id:        appId,
      name:          body.name.trim(),
      description:   body.description?.trim() ?? null,
      website:       body.website?.trim() ?? null,
      country:       body.country?.trim() ?? null,
      callback_urls: body.callback_urls ?? [],
      environment:   body.environment ?? "development",
      status:        "development",
      created_at:    new Date().toISOString(),
    })
    .select()
    .single();

  if (error) return c.json({ error: "Failed to register app" }, 500);

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "app.created",
    resourceType: "registered_app",
    resourceId:   appId,
    ip,
    metadata:     { name: body.name, environment: body.environment },
  });

  return c.json({ app: data }, 201);
});

// ── PATCH /developer/apps/:id ─────────────────────────────────────────────────

developer.patch("/apps/:id", authMiddleware, async (c) => {
  const user   = c.get("user")!;
  const db     = c.get("db");
  const { id } = c.req.param();

  const body = await c.req.json<Record<string, unknown>>().catch(() => null);
  if (!body) return c.json({ error: "Invalid request body" }, 400);

  const allowed  = ["name", "description", "website", "callback_urls", "environment", "status"];
  const patch: Record<string, unknown> = {};
  for (const k of allowed) {
    if (k in body) patch[k] = body[k];
  }

  if (Object.keys(patch).length === 0) return c.json({ error: "No valid fields to update" }, 400);

  const { data, error } = await db
    .from("developer_registered_apps")
    .update(patch)
    .eq("id", id)
    .eq("user_id", user.id)
    .select()
    .single();

  if (error) return c.json({ error: "Failed to update app" }, 500);
  return c.json({ app: data });
});

// ── GET /developer/webhooks ───────────────────────────────────────────────────

developer.get("/webhooks", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .from("developer_webhooks")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return c.json({ error: "Failed to fetch webhooks" }, 500);
  return c.json({ webhooks: data ?? [] });
});

// ── POST /developer/webhooks ──────────────────────────────────────────────────

developer.post("/webhooks", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    url?: string;
    events?: string[];
    secret?: string;
  }>().catch(() => null);

  if (!body?.url?.trim())  return c.json({ error: "url is required" }, 400);
  if (!Array.isArray(body.events) || body.events.length === 0) {
    return c.json({ error: "events must be a non-empty array" }, 400);
  }

  const { data, error } = await db
    .from("developer_webhooks")
    .insert({
      user_id:    user.id,
      url:        body.url.trim(),
      events:     body.events,
      secret:     body.secret ?? null,
      active:     true,
      created_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (error) return c.json({ error: "Failed to create webhook" }, 500);

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "webhook.created",
    resourceType: "webhook",
    resourceId:   (data as { id: string }).id,
    ip,
    metadata:     { url: body.url, event_count: body.events.length },
  });

  return c.json({ webhook: data }, 201);
});

// ── DELETE /developer/webhooks/:id ────────────────────────────────────────────

developer.delete("/webhooks/:id", authMiddleware, async (c) => {
  const user   = c.get("user")!;
  const db     = c.get("db");
  const ip     = getClientIp(c.req.raw);
  const { id } = c.req.param();

  const { error } = await db
    .from("developer_webhooks")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id);

  if (error) return c.json({ error: "Failed to delete webhook" }, 500);

  await writeAuditLog(db, {
    userId: user.id, action: "webhook.deleted",
    resourceType: "webhook", resourceId: id, ip,
  });
  return c.json({ ok: true });
});

// ── GET /developer/audit ──────────────────────────────────────────────────────

developer.get("/audit", authMiddleware, async (c) => {
  const user   = c.get("user")!;
  const db     = c.get("db");
  const page   = Math.max(1, Number(c.req.query("page") ?? "1"));
  const limit  = Math.min(100, Math.max(1, Number(c.req.query("limit") ?? "50")));
  const offset = (page - 1) * limit;

  const { data, error, count } = await db
    .from("audit_logs")
    .select("id,action,resource_type,resource_id,ip,user_agent,metadata,created_at", { count: "exact" })
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) return c.json({ error: "Failed to fetch audit logs" }, 500);
  return c.json({ logs: data ?? [], total: count ?? 0, page });
});

// ── GET /developer/usage ──────────────────────────────────────────────────────

developer.get("/usage", authMiddleware, async (c) => {
  const user  = c.get("user")!;
  const db    = c.get("db");
  const today = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);

  const [total, todayLogs, monthLogs] = await Promise.all([
    db.from("audit_logs").select("id", { count: "exact", head: true }).eq("user_id", user.id),
    db.from("audit_logs").select("id", { count: "exact", head: true }).eq("user_id", user.id).gte("created_at", `${today}T00:00:00Z`),
    db.from("audit_logs").select("id", { count: "exact", head: true }).eq("user_id", user.id).gte("created_at", `${month}-01T00:00:00Z`),
  ]);

  return c.json({
    total_calls:          total.count ?? 0,
    calls_today:          todayLogs.count ?? 0,
    calls_this_month:     monthLogs.count ?? 0,
    rate_limit:           1000,
    rate_limit_remaining: 1000,
    top_endpoints:        [],
  });
});

export default developer;
