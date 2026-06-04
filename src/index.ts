// RALD Auth Core — Cloudflare Worker
// Deployed at: auth.rald.cloud | Version: 2.1.0
// Phase G.10: KV Session Authority (rald-session), /session broker, /me shortcut, /logout
// Changelog v2.1.0: RALD_SESSION_KV binding, session route, expanded audit types
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { JwtPayload } from "./lib/auth";
import type { KVNamespace } from "./lib/rate-limit";
import type { KvSessionStore } from "./lib/session";
import authRoutes      from "./routes/auth";
import devicesRoutes   from "./routes/devices";
import ssoRoutes       from "./routes/sso";
import clerkRoutes     from "./routes/clerk";
import provisionRoutes from "./routes/provision";
import profilesRoutes  from "./routes/profiles";
import sessionRoutes   from "./routes/session";

export type Bindings = {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET: string;           // Required — 64-char base64url — NO fallback
  TERMII_API_KEY: string;
  TERMII_SENDER_ID: string;
  RESEND_API_KEY: string;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  ENVIRONMENT: string;
  RATE_LIMIT_KV: KVNamespace;        // rald-auth-rate-limit namespace
  RALD_SESSION_KV: KvSessionStore;   // rald-session namespace (Phase G.10)
};

export type Variables = {
  db: SupabaseClient;
  user?: JwtPayload;
};

const VERSION = "2.1.0";

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── CORS — full RALD ecosystem ────────────────────────────────────────────────
// profiles.rald.cloud is the canonical identity hub
// accounts.rald.cloud: REMOVED (Phase V2)
app.use("*", cors({
  origin: [
    // ── Identity hub ──────────────────────────────────────────────────────────
    "https://profiles.rald.cloud",
    "https://credentials.rald.cloud",
    // ── Core platform ─────────────────────────────────────────────────────────
    "https://rald.cloud",
    "https://auth.rald.cloud",
    "https://admin.rald.cloud",
    "https://control.rald.cloud",
    "https://console.rald.cloud",
    "https://sdk.rald.cloud",
    "https://sv.rald.cloud",
    "https://silicon.rald.cloud",
    // ── Ecosystem apps ────────────────────────────────────────────────────────
    "https://loop.rald.cloud",
    "https://messenger.rald.cloud",
    "https://inbox.rald.cloud",
    "https://pay.rald.cloud",
    "https://payrald.rald.cloud",
    "https://duna.rald.cloud",
    "https://git.rald.cloud",
    "https://analytics.rald.cloud",
    "https://business.rald.cloud",
    // ── ostloop.name.ng ───────────────────────────────────────────────────────
    "https://ostloop.name.ng",
    // ── CF Pages previews ─────────────────────────────────────────────────────
    "https://rald-auth-ui.pages.dev",
    "https://rald-app.pages.dev",
    "https://rald-control-center.pages.dev",
    // ── Local dev ─────────────────────────────────────────────────────────────
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:4173",
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

const serviceInfo = (c: { env: Bindings }) => ({
  service:      "rald-auth",
  version:      VERSION,
  identity_hub: "profiles.rald.cloud",
  environment:  c.env.ENVIRONMENT ?? "production",
  owner:        "LILCKY STUDIO LIMITED",
  timestamp:    new Date().toISOString(),
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
      rate_limit_kv: !!(c.env.RATE_LIMIT_KV),
      session_kv:    !!(c.env.RALD_SESSION_KV),
    },
    ...serviceInfo(c),
  })
);

app.get("/system/status", (c) =>
  c.json({
    status:       "operational",
    version:      VERSION,
    identity_hub: "profiles.rald.cloud",
    environment:  c.env.ENVIRONMENT ?? "production",
    secrets: {
      supabase:      !!c.env.SUPABASE_URL && !!c.env.SUPABASE_SERVICE_ROLE_KEY,
      jwt:           !!c.env.RALD_JWT_SECRET,
      termii:        !!c.env.TERMII_API_KEY,
      resend:        !!c.env.RESEND_API_KEY,
      clerk_full:    !!c.env.CLERK_SECRET_KEY && !!c.env.CLERK_PUBLISHABLE_KEY,
      rate_limit_kv: !!(c.env.RATE_LIMIT_KV),
      session_kv:    !!(c.env.RALD_SESSION_KV),
    },
    timestamp: new Date().toISOString(),
  })
);

app.get("/system/dependencies", async (c) => {
  const checks = await Promise.allSettled([
    (async () => {
      const t0 = Date.now();
      const r  = await fetch(`${c.env.SUPABASE_URL}/rest/v1/`, {
        headers: { apikey: c.env.SUPABASE_SERVICE_ROLE_KEY },
        signal: AbortSignal.timeout(5000),
      });
      return { name: "supabase", ok: r.ok, latency: Date.now() - t0 };
    })(),
    (async () => {
      const t0 = Date.now();
      const r  = await fetch(
        `https://api.ng.termii.com/api/get-balance?api_key=${c.env.TERMII_API_KEY}`,
        { signal: AbortSignal.timeout(5000) }
      );
      const d = await r.json() as { balance?: number; currency?: string };
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
    (async () => {
      const kv = c.env.RALD_SESSION_KV as unknown as { get: (k: string) => Promise<string | null> } | null;
      if (!kv) return { name: "session_kv", ok: false, latency: 0, note: "not bound" };
      const t0 = Date.now();
      await kv.get("__health__").catch(() => null);
      return { name: "session_kv", ok: true, latency: Date.now() - t0 };
    })(),
  ]);

  const results = checks.map((c) =>
    c.status === "fulfilled"
      ? c.value
      : { name: "unknown", ok: false, latency: -1, error: String((c as PromiseRejectedResult).reason) }
  );
  const allOk = results.every((r) => r.ok);
  return c.json({ ok: allOk, dependencies: results, timestamp: new Date().toISOString() }, allOk ? 200 : 503);
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.route("/auth",      authRoutes);
app.route("/devices",   devicesRoutes);
app.route("/sso",       ssoRoutes);
app.route("/sso",       clerkRoutes);
app.route("/provision", provisionRoutes);
app.route("/profiles",  profilesRoutes);
app.route("/",          sessionRoutes);   // GET /session · GET /me · POST /logout etc.

// ── Root ──────────────────────────────────────────────────────────────────────
app.get("/", (c) => c.json({ docs: "https://auth.rald.cloud/health", ...serviceInfo(c) }));
app.notFound((c) => c.json({ error: "Not found", path: c.req.path }, 404));
app.onError((err, c) => {
  console.error("[RALD Auth Error]", err.message ?? err);
  return c.json({ error: "Internal server error" }, 500);
});

export default {
  async fetch(req: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
    // ── FAIL FAST — service must not start with missing secrets ──────────
    const missing: string[] = [];
    if (!env.RALD_JWT_SECRET)           missing.push('RALD_JWT_SECRET');
    if (!env.SUPABASE_URL)              missing.push('SUPABASE_URL');
    if (!env.SUPABASE_SERVICE_ROLE_KEY) missing.push('SUPABASE_SERVICE_ROLE_KEY');
    if (missing.length) {
      console.error(`[FATAL] rald-auth: missing required secrets: ${missing.join(', ')}`);
      return new Response(JSON.stringify({ error: 'Service misconfigured', missing, service: 'rald-auth' }), {
        status: 503, headers: { 'Content-Type': 'application/json' },
      });
    }
    return app.fetch(req, env, ctx);
  },
};
