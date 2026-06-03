// RALD Auth Core — Universal Profile Hub
// Serves profiles.rald.cloud — canonical user identity + app launcher + connected apps
// Phase: RALD Identity Platform V2
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { ECOSYSTEM_APPS } from "../lib/redirect";

const profiles = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /profiles/me — full profile card ─────────────────────────────────────
profiles.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const [userRes, profileRes, appsRes] = await Promise.all([
    db.from("auth_users")
      .select("id,email,name,role,metadata,created_at")
      .eq("id", user.id).limit(1),
    db.from("auth_user_profiles")
      .select("*")
      .eq("user_id", user.id).maybeSingle(),
    db.from("auth_product_access")
      .select("product,role,granted_at")
      .eq("user_id", user.id),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const meta = (u.metadata as Record<string, string> | null) ?? {};
  const profile = profileRes.data;

  return c.json({
    id:            u.id,
    rald_id:       `RALD-${u.id.split("-")[0].toUpperCase()}`,
    email:         u.email,
    name:          profile?.display_name ?? u.name ?? null,
    avatar_url:    profile?.avatar_url ?? null,
    bio:           profile?.bio ?? null,
    phone:         meta.phone ?? null,
    role:          u.role,
    preferences:   profile?.preferences ?? {},
    provisioned_apps: profile?.provisioned_apps ?? [],
    active_products: (appsRes.data ?? []).map((a: { product: string }) => a.product),
    created_at:    u.created_at,
    identity_hub:  "profiles.rald.cloud",
    version:       "v2",
  });
});

// ── PATCH /profiles/me — update profile ──────────────────────────────────────
profiles.patch("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const body = await c.req.json<{
    display_name?: string;
    avatar_url?: string;
    bio?: string;
    preferences?: Record<string, unknown>;
  }>().catch(() => null);
  if (!body) return c.json({ error: "Invalid JSON body" }, 400);

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (body.display_name !== undefined) updates.display_name = body.display_name.trim().slice(0, 80);
  if (body.avatar_url !== undefined) updates.avatar_url = body.avatar_url.trim().slice(0, 500);
  if (body.bio !== undefined) updates.bio = body.bio.trim().slice(0, 300);
  if (body.preferences !== undefined) updates.preferences = body.preferences;

  await db.from("auth_user_profiles").upsert(
    { user_id: user.id, ...updates },
    { onConflict: "user_id" }
  );

  return c.json({ ok: true, updated: Object.keys(updates).filter(k => k !== "updated_at") });
});

// ── GET /profiles/apps — Universal App Launcher ───────────────────────────────
profiles.get("/apps", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  // Get user's provisioned apps
  const { data: access } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", user.id);

  const provisioned = new Set((access ?? []).map((a: { product: string }) => a.product));

  const launcher = ECOSYSTEM_APPS.map(app => ({
    ...app,
    provisioned: provisioned.has(app.id),
    role:        access?.find((a: { product: string; role: string }) => a.product === app.id)?.role ?? null,
  }));

  return c.json({
    apps: launcher,
    total: launcher.length,
    provisioned_count: launcher.filter(a => a.provisioned).length,
    identity_hub: "profiles.rald.cloud",
  });
});

// ── GET /profiles/sessions — Active sessions (Connected Apps Dashboard) ───────
profiles.get("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  try {
    const { data } = await db
      .from("auth_sessions")
      .select("id,user_agent,ip_address,last_seen_at,created_at,expires_at")
      .eq("user_id", user.id)
      .is("revoked_at", null)
      .gte("expires_at", new Date().toISOString())
      .order("last_seen_at", { ascending: false });
    return c.json({ sessions: data ?? [], count: data?.length ?? 0 });
  } catch {
    return c.json({ sessions: [], count: 0 });
  }
});

// ── DELETE /profiles/sessions/:sessionId — revoke session ────────────────────
profiles.delete("/sessions/:sessionId", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  await db.from("auth_sessions")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", c.req.param("sessionId"))
    .eq("user_id", user.id);
  return c.json({ ok: true });
});

// ── DELETE /profiles/sessions — revoke all sessions ──────────────────────────
profiles.delete("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  await db.from("auth_sessions")
    .update({ revoked_at: new Date().toISOString() })
    .eq("user_id", user.id)
    .is("revoked_at", null);
  return c.json({ ok: true, message: "All sessions revoked" });
});

// ── GET /profiles/activity — login history ────────────────────────────────────
profiles.get("/activity", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const { limit = "50" } = c.req.query();
  const l = Math.min(200, parseInt(limit));

  try {
    const { data } = await db
      .from("auth_login_history")
      .select("id,app_id,ip_address,user_agent,country,success,created_at")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(l);
    return c.json({ activity: data ?? [], count: data?.length ?? 0 });
  } catch {
    return c.json({ activity: [], count: 0 });
  }
});

// ── GET /profiles/connected-apps — apps with session activity ─────────────────
profiles.get("/connected-apps", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const { data: access } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", user.id)
    .order("granted_at", { ascending: false });

  const apps = (access ?? []).map((a: { product: string; role: string; granted_at: string }) => ({
    app_id:     a.product,
    role:       a.role,
    connected:  a.granted_at,
    meta: ECOSYSTEM_APPS.find(ea => ea.id === a.product) ?? null,
  }));

  return c.json({ connected_apps: apps, count: apps.length });
});

// ── GET /profiles/devices — device history ─────────────────────────────────
profiles.get("/devices", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  try {
    const { data } = await db
      .from("auth_devices")
      .select("id,device_name,device_type,last_seen_at,created_at,trusted")
      .eq("user_id", user.id)
      .order("last_seen_at", { ascending: false });
    return c.json({ devices: data ?? [], count: data?.length ?? 0 });
  } catch {
    return c.json({ devices: [], count: 0 });
  }
});

export default profiles;
