// RALD Auth Core — Cloudflare Worker
// Standalone identity engine for the RALD ecosystem
// Deployed at: auth.rald.cloud
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { JwtPayload } from "./lib/auth";
import authRoutes from "./routes/auth";
import devicesRoutes from "./routes/devices";
import ssoRoutes from "./routes/sso";
import provisionRoutes from "./routes/provision";

export type Bindings = {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET: string;
  TERMII_API_KEY: string;
  TERMII_SENDER_ID: string;
  RESEND_API_KEY: string;
  ENVIRONMENT: string;
};

export type Variables = {
  db: SupabaseClient;
  user?: JwtPayload;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use(
  "*",
  cors({
    origin: [
      "https://rald.cloud",
      "https://app.rald.cloud",
      "https://admin.rald.cloud",
      "https://auth.rald.cloud",
      "https://loop.rald.cloud",
      "https://messenger.rald.cloud",
      "https://business.rald.cloud",
      "https://payrald.rald.cloud",
      "https://rald-auth-ui.pages.dev",
      "https://rald-app.pages.dev",
      "https://rald-control-center.pages.dev",
      "http://localhost:5173",
      "http://localhost:3000",
    ],
    allowHeaders: ["Authorization", "Content-Type", "X-Request-ID", "X-App-ID"],
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
  })
);

// ── Supabase client per request ───────────────────────────────────────────────
app.use("*", async (c, next) => {
  c.set("db", createClient(c.env.SUPABASE_URL, c.env.SUPABASE_SERVICE_ROLE_KEY));
  await next();
});

// ── Health ────────────────────────────────────────────────────────────────────
const serviceInfo = (c: { env: Bindings }) => ({
  service: "rald-auth",
  version: "1.0.0",
  environment: c.env.ENVIRONMENT ?? "production",
  owner: "LILCKY STUDIO LIMITED",
  timestamp: new Date().toISOString(),
});

app.get("/health", (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/healthz", (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/ready", (c) =>
  c.json({
    ready: true,
    checks: {
      supabase: !!c.env.SUPABASE_URL,
      termii: !!c.env.TERMII_API_KEY,
      resend: !!c.env.RESEND_API_KEY,
    },
    ...serviceInfo(c),
  })
);
app.get("/version", (c) => c.json(serviceInfo(c)));

// ── Routes ────────────────────────────────────────────────────────────────────
app.route("/auth", authRoutes);
app.route("/devices", devicesRoutes);
app.route("/sso", ssoRoutes);
app.route("/provision", provisionRoutes);

// ── Root ──────────────────────────────────────────────────────────────────────
app.get("/", (c) =>
  c.json({
    service: "RALD Auth",
    version: "1.0.0",
    docs: "https://auth.rald.cloud/health",
    ...serviceInfo(c),
  })
);

app.notFound((c) => c.json({ error: "Not found", path: c.req.path }, 404));
app.onError((err, c) => {
  console.error("[RALD Auth Error]", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default app;
