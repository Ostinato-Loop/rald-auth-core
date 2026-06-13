// RALD Auth Core — SSO Token Exchange Routes
// Phase G.12: Dynamic App Registry — replaces hardcoded TRUSTED_APP_IDS
// All app validation goes through the registered_apps table.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { signJwt, verifyJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import { validateRedirectUrl, safeRedirect, ECOSYSTEM_APPS } from "../lib/redirect";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const sso = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * FALLBACK_APP_IDS — emergency fallback only if registered_apps DB is unavailable.
 * @deprecated — all apps must be registered in the registered_apps table.
 * Remove this once registered_apps is confirmed stable in production.
 */
const FALLBACK_APP_IDS = new Set([
  // Core platform
  "rald-app", "loop-business", "rald-control-center", "dispatch", "voice",
  // Identity hub
  "profiles", "identity", "rald-identity", "loop-identity", "credentials",
  // Ecosystem apps
  "loop", "loop-app", "loop-core", "loop-messenger", "messenger",
  "payrald", "dunarald", "gitrald", "rald-inbox", "raldtics", "raldtics-app",
  "gitrald-app", "pay", "duna",
  // Manilla — music platform
  "manilla",
]);

/**
 * Checks whether an appId is registered and active in the ecosystem app registry.
 * Falls back to the hardcoded set if the DB query fails (prevents auth outage).
 */
async function isRegisteredApp(db: SupabaseClient, appId: string): Promise<boolean> {
  try {
    const { data, error } = await db
      .from("registered_apps")
      .select("app_id")
      .eq("app_id", appId)
      .eq("status", "active")
      .limit(1);
    if (error) {
      console.error("[rald-auth] registered_apps lookup error:", error.message, "— using fallback");
      return FALLBACK_APP_IDS.has(appId);
    }
    return !!(data && data.length > 0);
  } catch (e) {
    console.error("[rald-auth] registered_apps lookup threw:", String(e), "— using fallback");
    return FALLBACK_APP_IDS.has(appId);
  }
}

// ── GET /sso/apps — list trusted app IDs (DB-driven) ─────────────────────────
sso.get("/apps", async (c) => {
  const db = c.get("db");
  const { data, error } = await db
    .from("registered_apps")
    .select("app_id, name, domain, status")
    .eq("status", "active")
    .order("name");

  if (error) {
    console.error("[rald-auth] /sso/apps DB error, using fallback:", error.message);
    return c.json({
      apps: [...FALLBACK_APP_IDS],
      count: FALLBACK_APP_IDS.size,
      ecosystem: ECOSYSTEM_APPS,
      identity_hub: "profiles.rald.cloud",
      source: "fallback",
      note: "registered_apps table unavailable — using emergency fallback list",
    });
  }

  return c.json({
    apps: (data || []).map((r) => r.app_id),
    registry: data || [],
    count: (data || []).length,
    ecosystem: ECOSYSTEM_APPS,
    identity_hub: "profiles.rald.cloud",
    source: "database",
    note: "Apps are dynamically registered via the ecosystem app registry.",
  });
});

// ── GET /sso/registry — full app registry details ────────────────────────────
sso.get("/registry", async (c) => {
  const db = c.get("db");
  const { data, error } = await db
    .from("registered_apps")
    .select("app_id, name, domain, callback_url, logout_url, icon, status, created_at")
    .order("name");

  if (error) return c.json({ error: "Registry unavailable", detail: error.message }, 503);
  return c.json({ apps: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
});

// ── POST /sso/registry — register a new app (admin only) ─────────────────────
sso.post("/registry", adminMiddleware, async (c) => {
  const db = c.get("db");
  const body = await c.req.json<{
    app_id: string;
    name: string;
    domain: string;
    callback_url: string;
    logout_url?: string;
    icon?: string;
  }>().catch(() => null);

  if (!body?.app_id || !body?.name || !body?.domain || !body?.callback_url)
    return c.json({ error: "app_id, name, domain, callback_url are required" }, 400);

  if (!validateRedirectUrl(body.callback_url))
    return c.json({ error: "callback_url must be a valid *.rald.cloud or *.ostloop.name.ng URL" }, 400);

  const { data, error } = await db
    .from("registered_apps")
    .upsert({ ...body, status: "active", updated_at: new Date().toISOString() }, { onConflict: "app_id" })
    .select()
    .limit(1);

  if (error) return c.json({ error: "Registration failed", detail: error.message }, 500);

  const ip = getClientIp(c.req.raw);
  await writeAuditLog(db, {
    userId: c.get("user")!.id,
    action: "app_registered" as Parameters<typeof writeAuditLog>[1]["action"],
    ip,
    status: "success",
    metadata: { app_id: body.app_id, domain: body.domain },
  });

  return c.json({ registered: data?.[0], message: "App registered in ecosystem registry" }, 201);
});

// ── POST /sso/exchange — exchange master JWT for an app-scoped token ──────────
sso.post("/exchange", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{ appId?: string; redirect_to?: string }>().catch(() => null);
  if (!body?.appId) return c.json({ error: "appId required" }, 400);

  if (!(await isRegisteredApp(db, body.appId)))
    return c.json({ error: "Unknown app — not registered in the RALD ecosystem", appId: body.appId }, 400);

  const redirect_to = safeRedirect(body.redirect_to, undefined);
  if (body.redirect_to && !validateRedirectUrl(body.redirect_to)) {
    return c.json({
      error: "Invalid redirect_to — only *.rald.cloud and *.ostloop.name.ng are allowed",
      rejected: body.redirect_to,
    }, 400);
  }

  // USN-001 + Phase 1: Fetch username, identity_state, and trust claims for SSO token
  const { data: userRow } = await db
    .from("auth_users")
    .select("username,identity_state,trust_score,trust_level")
    .eq("id", user.id)
    .limit(1);
  const raldUsername: string | null = (userRow?.[0]?.username as string | null) ?? null;
  const userRowData = (userRow?.[0] as Record<string, unknown> | undefined) ?? {};

  // Identity state guard — SUSPENDED/DELETED accounts cannot receive app-scoped tokens
  const ssoIdentityState = userRowData.identity_state as string | undefined;
  if (ssoIdentityState === "SUSPENDED") {
    await writeAuditLog(db, { userId: user.id, action: "sso_blocked", ip, status: "blocked", metadata: { appId: body.appId, reason: "SUSPENDED" } });
    return c.json({ error: "Your account is temporarily unavailable. Contact support." }, 403);
  }
  if (ssoIdentityState === "DELETED") {
    await writeAuditLog(db, { userId: user.id, action: "sso_blocked", ip, status: "blocked", metadata: { appId: body.appId, reason: "DELETED" } });
    return c.json({ error: "Account not found." }, 403);
  }

  const appToken = await signJwt(
    {
      id:          user.id,
      email:       user.email,
      phone:       (user as unknown as Record<string, unknown>).phone ?? null,
      role:        user.role,
      username:    raldUsername,
      trust_score: (userRowData.trust_score ?? 0) as number,
      trust_level: (userRowData.trust_level ?? "none") as string,
      appId:       body.appId,
      source:      "rald-auth",
      sso_v:       2,
    },
    c.env.RALD_JWT_SECRET,
    3600
  );

  c.executionCtx.waitUntil(
    Promise.resolve(
      db.from("auth_login_history").insert({
        user_id: user.id, app_id: body.appId, ip_address: ip, success: true,
        created_at: new Date().toISOString(),
      })
    ).then(undefined, () => null)
  );

  await writeAuditLog(db, {
    userId: user.id, action: "sso_exchange", ip, status: "success",
    metadata: { appId: body.appId, redirect_to: redirect_to ?? null },
  });

  c.header("Set-Cookie", buildSessionCookie(appToken, 3600));
  return c.json({
    token:        appToken,
    appId:        body.appId,
    expiresIn:    3600,
    username:     raldUsername,
    has_username: !!raldUsername,
    trust_score:  (userRowData.trust_score ?? 0) as number,
    trust_level:  (userRowData.trust_level ?? "none") as string,
    redirect_to:  redirect_to ?? null,
    sso_version:  2,
  });
});

// ── POST /sso/verify — verify a RALD token (for other services) ───────────────
sso.post("/verify", async (c) => {
  const body = await c.req.json<{ token?: string }>().catch(() => null);
  if (!body?.token) return c.json({ error: "token required" }, 400);

  const payload = await verifyJwt(body.token, c.env.RALD_JWT_SECRET);
  if (!payload) return c.json({ valid: false, error: "Invalid or expired token" }, 401);

  return c.json({ valid: true, user: payload });
});

// ── POST /sso/handoff — redirect-based SSO (browser handoff) ─────────────────
sso.post("/handoff", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{ appId?: string; redirect_to?: string }>().catch(() => null);
  if (!body?.appId) return c.json({ error: "appId required" }, 400);

  if (!(await isRegisteredApp(db, body.appId)))
    return c.json({ error: "Unknown app — not registered in the RALD ecosystem", appId: body.appId }, 400);

  if (!validateRedirectUrl(body.redirect_to)) {
    return c.json({
      error: "redirect_to is required and must be a valid *.rald.cloud or *.ostloop.name.ng URL",
    }, 400);
  }

  // USN-001 + Phase 1: Fetch username and identity_state for handoff token
  const { data: handoffUserRow } = await db
    .from("auth_users")
    .select("username,identity_state")
    .eq("id", user.id)
    .limit(1);
  const handoffUsername: string | null = (handoffUserRow?.[0]?.username as string | null) ?? null;
  const handoffIdentityState = (handoffUserRow?.[0] as Record<string, unknown> | undefined)?.identity_state as string | undefined;

  if (handoffIdentityState === "SUSPENDED") {
    await writeAuditLog(db, { userId: user.id, action: "sso_blocked", ip, status: "blocked", metadata: { appId: body.appId, reason: "SUSPENDED", flow: "handoff" } });
    return c.json({ error: "Your account is temporarily unavailable. Contact support." }, 403);
  }
  if (handoffIdentityState === "DELETED") {
    await writeAuditLog(db, { userId: user.id, action: "sso_blocked", ip, status: "blocked", metadata: { appId: body.appId, reason: "DELETED", flow: "handoff" } });
    return c.json({ error: "Account not found." }, 403);
  }

  const handoffToken = await signJwt(
    { id: user.id, email: user.email, role: user.role, username: handoffUsername, appId: body.appId, purpose: "sso-handoff" },
    c.env.RALD_JWT_SECRET,
    300
  );

  await writeAuditLog(db, {
    userId: user.id, action: "sso_handoff_issued", ip, status: "success",
    metadata: { appId: body.appId, redirect_to: body.redirect_to },
  });

  return c.json({
    handoff_token: handoffToken, redirect_to: body.redirect_to, expires_in: 300,
    note: "Append ?rald_token=<handoff_token> to redirect_to and navigate there",
  });
});

// ── GET /sso/validate-redirect ────────────────────────────────────────────────
sso.get("/validate-redirect", (c) => {
  const url = c.req.query("url");
  const valid = validateRedirectUrl(url);
  return c.json({
    url, valid,
    allowed_patterns: ["*.rald.cloud", "*.ostloop.name.ng"],
    reason: valid ? "URL is within the RALD ecosystem" : "URL is not an allowed RALD ecosystem domain",
  });
});

export default sso;