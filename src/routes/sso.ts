// RALD Auth Core — SSO Token Exchange Routes
// Allows trusted RALD apps to exchange a master JWT for an app-scoped token
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { signJwt, verifyJwt } from "../lib/auth";

const sso = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const TRUSTED_APP_IDS = new Set([
  "rald-app",
  "loop-business",
  "rald-control-center",
  "payrald",
  "messenger",
  "dispatch",
  "voice",
  "raldtics",
]);

// Exchange a master RALD JWT for an app-scoped token
sso.post("/exchange", authMiddleware, async (c) => {
  const body = (await c.req.json().catch(() => null)) as { appId?: string } | null;
  if (!body?.appId) return c.json({ error: "appId required" }, 400);
  if (!TRUSTED_APP_IDS.has(body.appId))
    return c.json({ error: "Unknown app" }, 400);

  const user = c.get("user")!;
  const appToken = await signJwt(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      appId: body.appId,
      source: "rald-auth",
    },
    c.env.RALD_JWT_SECRET,
    3600
  );

  return c.json({ token: appToken, appId: body.appId, expiresIn: 3600 });
});

// Verify a RALD token (for other services to call)
sso.post("/verify", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { token?: string } | null;
  if (!body?.token) return c.json({ error: "token required" }, 400);

  const payload = await verifyJwt(body.token, c.env.RALD_JWT_SECRET);
  if (!payload) return c.json({ valid: false, error: "Invalid or expired token" }, 401);

  return c.json({ valid: true, user: payload });
});

export default sso;
