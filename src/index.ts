// RALD Auth Core — Cloudflare Worker
// Deployed at: auth.rald.cloud | Version: 1.4.0
// G.9 Remediation: Added RATE_LIMIT_KV binding for per-endpoint rate limiting
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { JwtPayload } from "./lib/auth";
import type { KVNamespace } from "./lib/rate-limit";
import authRoutes      from "./routes/auth";
import devicesRoutes   from "./routes/devices";
import ssoRoutes       from "./routes/sso";
import clerkRoutes     from "./routes/clerk";
import provisionRoutes from "./routes/provision";

export type Bindings = {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET: string;
  TERMII_API_KEY: string;
  TERMII_SENDER_ID: string;
  RESEND_API_KEY: string;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  ENVIRONMENT: string;
  RATE_LIMIT_KV: KVNamespace;
};

export type Variables = {
  db: SupabaseClient;
  user?: JwtPayload;
};

const VERSION = "1.4.0";

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use("*", cors({
  origin: [
    "https://rald.cloud", "https://app.rald.cloud", "https://accounts.rald.cloud",
    "https://auth.rald.cloud", "https://identity.rald.cloud", "https://loop.rald.cloud",
    "https://messenger.rald.cloud", "https://business.rald.cloud", "https://payrald.rald.cloud",
    "https://admin.rald.cloud", "https://rald-auth-ui.pages.dev", "https://rald-app.pages.dev",
    "https://rald-control-center.pages.dev", "https://profiles.rald.cloud",
    "https://profile.rald.cloud", "https://credentials.rald.cloud", "https://sdk.rald.cloud",
    "https://console.rald.cloud", "https://silicon.rald.cloud", "https://control.rald.cloud",
    "https://sv.rald.cloud", "http://localhost:5173", "http://localhost:3000",
  ],
  allowHeaders: ["Authorization", "Content-Type", "X-Request-ID", "X-App-ID"],
  allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  credentials: true,
}));

// ── Supabase client per request ───────────────────────────────────────────────
app.use("*", async (c, next) => {
  c.set("db", createClient(c.env.SUPABASE_URL, c.env.SUPABASE_SERVICE_ROLE_KEY));
  await next();
});

// ── Service info helper ───────────────────────────────────────────────────────
const serviceInfo = (c: { env: Bindings }) => ({
  service: "rald-auth",
  version: VERSION,
  environment: c.env.ENVIRONMENT ?? "production",
  owner: "LILCKY STUDIO LIMITED",
  timestamp: new Date().toISOString(),
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health",  (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/healthz", (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/version", (c) => c.json(serviceInfo(c)));

app.get("/ready", (c) =>
  c.json({
    ready: !!(c.env.SUPABASE_URL && c.env.RALD_JWT_SECRET && c.env.RESEND_API_KEY),
    checks: {
      supabase:      !!c.env.SUPABASE_URL && !!c.env.SUPABASE_SERVICE_ROLE_KEY,
      jwt:           !!c.env.RALD_JWT_SECRET,
      termii:        !!c.env.TERMII_API_KEY,
      resend:        !!c.env.RESEND_API_KEY,
      clerk:         !!c.env.CLERK_SECRET_KEY && !!c.env.CLERK_PUBLISHABLE_KEY,
      rate_limiting: !!(c.env.RATE_LIMIT_KV),
    },
    ...serviceInfo(c),
  })
);

// ── System Status ─────────────────────────────────────────────────────────────
app.get("/system/status", (c) =>
  c.json({
    status:      "operational",
    version:     VERSION,
    environment: c.env.ENVIRONMENT ?? "production",
    secrets: {
      supabase:      !!c.env.SUPABASE_URL && !!c.env.SUPABASE_SERVICE_ROLE_KEY,
      jwt:           !!c.env.RALD_JWT_SECRET,
      termii:        !!c.env.TERMII_API_KEY,
      resend:        !!c.env.RESEND_API_KEY,
      clerk_full:    !!c.env.CLERK_SECRET_KEY && !!c.env.CLERK_PUBLISHABLE_KEY,
      rate_limiting: !!(c.env.RATE_LIMIT_KV),
    },
    timestamp: new Date().toISOString(),
  })
);

// ── System Dependencies (live ping) ──────────────────────────────────────────
app.get("/system/dependencies", async (c) => {
  const checks = await Promise.allSettled([
    (async () => {
      const t0 = Date.now();
      const r  = await fetch(`${c.env.SUPABASE_URL}/rest/v1/`, {
        headers: { apikey: c.env.SUPABASE_SERVICE_ROLE_KEY },
        signal: AbortSignal.timeout(5000),
      });
      return { name: "supabase", ok: r.ok, latency: Date.now() - t0, note: "auth_users table namespace" };
    })(),
    (async () => {
      const t0 = Date.now();
      const r  = await fetch(
        `https://api.ng.termii.com/api/get-balance?api_key=${c.env.TERMII_API_KEY}`,
        { signal: AbortSignal.timeout(5000) }
      );
      const d  = await r.json() as { balance?: number; currency?: string };
      return { name: "termii", ok: r.ok, latency: Date.now() - t0, balance: d.balance, currency: d.currency };
    })(),
    (async () => {
      const t0 = Date.now();
      const r  = await fetch("https://api.resend.com/domains", {
        headers: { Authorization: `Bearer ${c.env.RESEND_API_KEY}` },
        signal: AbortSignal.timeout(5000),
      });
      return { name: "resend", ok: r.ok, latency: Date.now() - t0 };
    })(),
  ]);

  const results = checks.map((c) =>
    c.status === "fulfilled"
      ? c.value
      : { name: "unknown", ok: false, latency: -1, error: String((c as PromiseRejectedResult).reason) }
  );

  const allOk = results.every((r) => r.ok);
  return c.json({ ok: allOk, dependencies: results, timestamp: new Date().toISOString() },
    allOk ? 200 : 503
  );
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.route("/auth",      authRoutes);
app.route("/devices",   devicesRoutes);
app.route("/sso",       ssoRoutes);
app.route("/sso",       clerkRoutes);
app.route("/provision", provisionRoutes);

// ── Root ──────────────────────────────────────────────────────────────────────
app.get("/", (c) => c.json({ docs: "https://auth.rald.cloud/health", ...serviceInfo(c) }));
app.notFound((c) => c.json({ error: "Not found", path: c.req.path }, 404));
app.onError((err, c) => {
  console.error("[RALD Auth Error]", err.message ?? err);
  return c.json({ error: "Internal server error" }, 500);
});

export default app;
