// RALD Auth Core — SSO Token Exchange Routes
// Allows trusted RALD apps to exchange a master JWT for an app-scoped token
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { signJwt, verifyJwt } from "../lib/auth";

const sso = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * TRUSTED_APP_IDS — only these app identifiers may receive SSO tokens.
 * Every RALD ecosystem app that uses cross-app SSO must be listed here.
 *
 * ⚠ IMPORTANT: "loop" was missing before G.12. Its absence caused
 *   rald-auth-ui to receive a 400 on ssoExchange("loop"), breaking all
 *   Loop ↔ Messenger cross-app navigation (WS1-F2 / WS3-F1). Fixed.
 */
const TRUSTED_APP_IDS = new Set([
  // ── Core apps (previously listed) ──────────────────────────────────────
  "rald-app",
  "loop-business",
  "rald-control-center",
  "payrald",
  "messenger",
  "dispatch",
  "voice",
  "raldtics",
  // ── G.12 additions — unlocks cross-app SSO for these apps ──────────────
  "loop",               // Loop social app (loop.rald.cloud)
  "loop-app",           // Loop app alternate ID (loop-app.pages.dev)
  "loop-core",          // Loop core services
  "loop-messenger",     // Messenger CF worker app ID
  "profiles",           // profiles.rald.cloud
  "identity",           // identity.rald.cloud
  "loop-identity",      // alternate identity app ID
  "rald-identity",      // rald-identity Pages app
  // ── Planned / upcoming ─────────────────────────────────────────────────
  "dunarald",           // dunarald.rald.cloud
  "gitrald",            // gitrald.rald.cloud
  "rald-inbox",         // inbox.rald.cloud
  "raldtics-app",       // raldtics.rald.cloud
]);

// ── GET /sso/apps — list of trusted app IDs (for operators) ─────────────────
sso.get("/apps", (c) =>
  c.json({
    apps: [...TRUSTED_APP_IDS],
    count: TRUSTED_APP_IDS.size,
    note: "Only apps in this list may receive SSO tokens from /sso/exchange",
  })
);

// ── POST /sso/exchange — exchange master JWT for an app-scoped token ────────
sso.post("/exchange", authMiddleware, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { appId?: string } | null;
  if (!body?.appId) return c.json({ error: "appId required" }, 400);
  if (!TRUSTED_APP_IDS.has(body.appId))
    return c.json({ error: "Unknown app", appId: body.appId }, 400);

  const user = c.get("user")!;
  const appToken = await signJwt(
    {
      id:     user.id,
      email:  user.email,
      phone:  user.phone ?? null,
      role:   user.role,
      appId:  body.appId,
      source: "rald-auth",
    },
    c.env.RALD_JWT_SECRET,
    3600
  );

  return c.json({ token: appToken, appId: body.appId, expiresIn: 3600 });
});

// ── POST /sso/verify — verify a RALD token (for other services) ─────────────
sso.post("/verify", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { token?: string } | null;
  if (!body?.token) return c.json({ error: "token required" }, 400);

  const payload = await verifyJwt(body.token, c.env.RALD_JWT_SECRET);
  if (!payload) return c.json({ valid: false, error: "Invalid or expired token" }, 401);

  return c.json({ valid: true, user: payload });
});

export default sso;
