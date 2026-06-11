// RALD Auth Core — Universal Profile Hub
// Serves profiles.rald.cloud — canonical user identity + app launcher + connected apps
// Phase: RALD Foundation Hardening — Organizations + Audit Logs + Verification
// P1 fix (2026-06-11): PATCH /profiles/me now accepts country, region, region_state
// P6 fix (2026-06-11): Smart ecosystem profiles — never ask again for existing data
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { ECOSYSTEM_APPS } from "../lib/redirect";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const profiles = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /profiles/me — full profile card ─────────────────────────────────────
profiles.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const [userRes, profileRes, appsRes, trustRes] = await Promise.all([
    db.from("auth_users")
      .select("id,email,name,role,metadata,created_at,username,rald_internal_id,rald_id,reserved_email_address,trust_level,trust_score,phone_number,email_verified,phone_verified")
      .eq("id", user.id).limit(1),
    db.from("auth_user_profiles")
      .select("*")
      .eq("user_id", user.id).maybeSingle(),
    db.from("auth_product_access")
      .select("product,role,granted_at")
      .eq("user_id", user.id),
    db.from("auth_trust_profiles")
      .select("*")
      .eq("user_id", user.id).maybeSingle(),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const meta    = (u.metadata as Record<string, unknown> | null) ?? {};
  const profile = profileRes.data;
  const trust   = trustRes.data;

  return c.json({
    id:            u.id,
    rald_id:       u.rald_id ?? `RALD-${u.id.split("-")[0].toUpperCase()}`,
    rald_internal_id: u.rald_internal_id ?? null,
    username:      u.username ?? null,
    email:         u.email,
    name:          profile?.display_name ?? u.name ?? null,
    avatar_url:    profile?.avatar_url ?? null,
    bio:           profile?.bio ?? null,
    phone:         u.phone_number ?? (meta.phone as string | null) ?? null,
    role:          u.role,
    email_verified:  u.email_verified === true || meta.email_verified === "true",
    phone_verified:  u.phone_verified === true || meta.phone_verified === "true",
    // P3: reserved email address
    reserved_email_address: u.reserved_email_address ?? (u.username ? `${u.username}@rald.me` : null),
    reserved_domain:        u.username ? `${u.username}.rald.me` : null,
    // Regional data
    country:      profile?.country ?? null,
    region:       profile?.region ?? null,
    region_state: profile?.region_state ?? null,
    // Trust profile
    trust_level:  u.trust_level ?? trust?.trust_level ?? "none",
    trust_score:  u.trust_score ?? trust?.trust_score ?? 0,
    trust_profile: trust ? {
      has_username:       trust.has_username,
      has_verified_phone: trust.has_verified_phone,
      has_verified_email: trust.has_verified_email,
      has_reserved_mail:  trust.has_reserved_mail,
      has_profile:        trust.has_profile,
      identity_complete:  trust.identity_complete,
    } : null,
    // Ecosystem state
    preferences:      profile?.preferences ?? {},
    provisioned_apps: profile?.provisioned_apps ?? [],
    active_products:  (appsRes.data ?? []).map((a: { product: string }) => a.product),
    // P4: needs_username flag for migration flow
    needs_username: !u.username,
    created_at:    u.created_at,
    identity_hub:  "profiles.rald.cloud",
    version:       "v2",
  });
});

// ── PATCH /profiles/me — update profile ──────────────────────────────────────
// P1 fix: now accepts country, region, region_state
// P6 fix: never overwrites existing non-null values unless explicitly sent
profiles.patch("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    display_name?: string;
    avatar_url?:   string;
    bio?:          string;
    preferences?:  Record<string, unknown>;
    // P1 fix: regional fields now accepted
    country?:      string;
    region?:       string;
    region_state?: string;
    // P6: allow phone update (non-verified — verification separate)
    phone?:        string;
  }>().catch(() => null);
  if (!body) return c.json({ error: "Invalid JSON body" }, 400);

  const now = new Date().toISOString();

  // ── Profile table updates ───────────────────────────────────────────────────
  const profileUpdates: Record<string, unknown> = { updated_at: now };
  if (body.display_name !== undefined) profileUpdates.display_name = body.display_name.trim().slice(0, 80);
  if (body.avatar_url   !== undefined) profileUpdates.avatar_url   = body.avatar_url.trim().slice(0, 500);
  if (body.bio          !== undefined) profileUpdates.bio          = body.bio.trim().slice(0, 300);
  if (body.preferences  !== undefined) profileUpdates.preferences  = body.preferences;
  // P1 fix: regional fields
  if (body.country      !== undefined) profileUpdates.country      = body.country.trim().slice(0, 10);
  if (body.region       !== undefined) profileUpdates.region       = body.region.trim().slice(0, 80);
  if (body.region_state !== undefined) profileUpdates.region_state = body.region_state.trim().slice(0, 80);

  await db.from("auth_user_profiles").upsert(
    { user_id: user.id, ...profileUpdates },
    { onConflict: "user_id" }
  );

  // ── User table updates (phone only — other fields managed separately) ──────
  const userUpdates: Record<string, unknown> = {};
  if (body.phone !== undefined) {
    const cleanPhone = body.phone.replace(/\s+/g, "");
    userUpdates.phone_number = cleanPhone;
  }
  if (Object.keys(userUpdates).length > 0) {
    await db.from("auth_users").update(userUpdates).eq("id", user.id)
      .then(() => null, () => null);
  }

  // ── P5 fix: Sync trust profile with latest state ──────────────────────────
  await db.rpc("repair_identity_records", { p_user_id: user.id })
    .then(() => null, () => null);

  await writeAuditLog(db, {
    userId: user.id,
    action: "profile_updated",
    ip,
    status: "success",
    metadata: { updated_fields: Object.keys(profileUpdates).filter(k => k !== "updated_at") },
  });

  const updatedFields = [
    ...Object.keys(profileUpdates).filter(k => k !== "updated_at"),
    ...Object.keys(userUpdates),
  ];

  return c.json({ ok: true, updated: updatedFields });
});

// ── GET /profiles/apps — Universal App Launcher ───────────────────────────────
profiles.get("/apps", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

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

// ── GET /profiles/sessions — Active sessions ───────────────────────────────────
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

// ── DELETE /profiles/sessions/:sessionId — revoke session ─────────────────────
profiles.delete("/sessions/:sessionId", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  await db.from("auth_sessions")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", c.req.param("sessionId"))
    .eq("user_id", user.id);
  return c.json({ ok: true });
});

// ── DELETE /profiles/sessions — revoke all sessions ───────────────────────────
profiles.delete("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  await db.from("auth_sessions")
    .update({ revoked_at: new Date().toISOString() })
    .eq("user_id", user.id)
    .is("revoked_at", null);
  return c.json({ ok: true, message: "All sessions revoked" });
});

// ── GET /profiles/activity — login history ─────────────────────────────────────
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
    granted_at: a.granted_at,
  }));

  return c.json({ apps, count: apps.length });
});

// ── GET /profiles/identity — full identity card (P5: identity registry) ───────
profiles.get("/identity", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const { data, error } = await db
    .from("identity_registry")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  if (error || !data) {
    // Auto-repair and retry
    await db.rpc("repair_identity_records", { p_user_id: user.id })
      .then(() => null, () => null);
    const { data: repaired } = await db
      .from("identity_registry")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle();
    if (!repaired) return c.json({ error: "Identity record not found" }, 404);
    return c.json(repaired);
  }

  return c.json(data);
});

export default profiles;
