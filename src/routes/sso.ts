// RALD Auth Core — SSO Token Exchange Routes
// Phase: RALD Identity Platform V2 — Universal SSO
// Flow: User authenticated once → RALD master token → any app → silent provisioning → enter
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { signJwt, verifyJwt } from "../lib/auth";
import { validateRedirectUrl, safeRedirect, ECOSYSTEM_APPS } from "../lib/redirect";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const sso = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * TRUSTED_APP_IDS — all apps that may receive SSO tokens.
 * Every RALD ecosystem app must be listed here.
 */
const TRUSTED_APP_IDS = new Set([
  // ── Core platform ──────────────────────────────────────────────────────────
  "rald-app",
  "loop-business",
  "rald-control-center",
  "dispatch",
  "voice",
  // ── Identity hub (V2) ──────────────────────────────────────────────────────
  "profiles",
  "identity",
  "rald-identity",
  "loop-identity",
  "credentials",
  // ── Ecosystem apps ─────────────────────────────────────────────────────────
  "loop",
  "loop-app",
  "loop-core",
  "loop-messenger",
  "messenger",
  "payrald",
  "dunarald",
  "gitrald",
  "rald-inbox",
  "raldtics",
  "raldtics-app",
  // ── Future / upcoming ──────────────────────────────────────────────────────
  "gitrald-app",
  "pay",
  "duna",
]);

// ── GET /sso/apps — list of trusted app IDs ───────────────────────────────────
sso.get("/apps", (c) =>
  c.json({
    apps: [...TRUSTED_APP_IDS],
    count: TRUSTED_APP_IDS.size,
    ecosystem: ECOSYSTEM_APPS,
    identity_hub: "profiles.rald.cloud",
    note: "Only apps in this list may receive SSO tokens from /sso/exchange",
  })
);

// ── POST /sso/exchange — exchange master JWT for an app-scoped token ──────────
// Body: { appId: string, redirect_to?: string }
// redirect_to is validated — only *.rald.cloud and *.ostloop.name.ng are accepted.
sso.post("/exchange", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    appId?: string;
    redirect_to?: string;
  }>().catch(() => null);
  if (!body?.appId) return c.json({ error: "appId required" }, 400);
  if (!TRUSTED_APP_IDS.has(body.appId))
    return c.json({ error: "Unknown app", appId: body.appId }, 400);

  // Validate redirect_to — reject anything not in the RALD ecosystem
  const redirect_to = safeRedirect(body.redirect_to, undefined);
  if (body.redirect_to && !validateRedirectUrl(body.redirect_to)) {
    return c.json({
      error: "Invalid redirect_to — only *.rald.cloud and *.ostloop.name.ng are allowed",
      rejected: body.redirect_to,
    }, 400);
  }

  const appToken = await signJwt(
    {
      id:        user.id,
      email:     user.email,
      phone:     (user as unknown as Record<string, unknown>).phone ?? null,
      role:      user.role,
      appId:     body.appId,
      source:    "rald-auth",
      sso_v:     2,
    },
    c.env.RALD_JWT_SECRET,
    3600
  );

  // Non-blocking: log SSO exchange to login history
  c.executionCtx.waitUntil(
    db.from("auth_login_history").insert({
      user_id:    user.id,
      app_id:     body.appId,
      ip_address: ip,
      success:    true,
      created_at: new Date().toISOString(),
    }).catch(() => null)
  );

  await writeAuditLog(db, {
    userId: user.id,
    action: "sso_exchange",
    ip,
    status: "success",
    metadata: { appId: body.appId, redirect_to: redirect_to ?? null },
  });

  return c.json({
    token:       appToken,
    appId:       body.appId,
    expiresIn:   3600,
    redirect_to: redirect_to ?? null,
    sso_version: 2,
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
// Used when a direct API call is not possible (pure browser navigation).
// Returns a short-lived handoff token + validated redirect_to URL.
sso.post("/handoff", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    appId?: string;
    redirect_to?: string;
  }>().catch(() => null);
  if (!body?.appId) return c.json({ error: "appId required" }, 400);
  if (!TRUSTED_APP_IDS.has(body.appId))
    return c.json({ error: "Unknown app", appId: body.appId }, 400);

  // Strict redirect validation for browser handoff
  if (!validateRedirectUrl(body.redirect_to)) {
    return c.json({
      error: "redirect_to is required and must be a valid *.rald.cloud or *.ostloop.name.ng URL",
    }, 400);
  }

  // Short-lived handoff token (5 min)
  const handoffToken = await signJwt(
    { id: user.id, email: user.email, role: user.role, appId: body.appId, purpose: "sso-handoff" },
    c.env.RALD_JWT_SECRET,
    300
  );

  await writeAuditLog(db, {
    userId: user.id, action: "sso_handoff_issued", ip, status: "success",
    metadata: { appId: body.appId, redirect_to: body.redirect_to },
  });

  return c.json({
    handoff_token: handoffToken,
    redirect_to:   body.redirect_to,
    expires_in:    300,
    note:          "Append ?rald_token=<handoff_token> to redirect_to and navigate there",
  });
});

// ── GET /sso/validate-redirect — validate a redirect_to URL ──────────────────
sso.get("/validate-redirect", (c) => {
  const url = c.req.query("url");
  const valid = validateRedirectUrl(url);
  return c.json({
    url,
    valid,
    allowed_patterns: ["*.rald.cloud", "*.ostloop.name.ng"],
    reason: valid ? "URL is within the RALD ecosystem" : "URL is not an allowed RALD ecosystem domain",
  });
});

export default sso;
