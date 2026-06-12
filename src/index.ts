// RALD Auth Core — Cloudflare Worker
// Deployed at: auth.rald.cloud | Version: 2.9.0
// Changelog v2.9.0: Phase 1 — Public Beta Blockers
//   - /identity-brain/* namespace alias for /identity/* (Rule #4 spec compliance)
//   - Scheduled cleanup handler: OTP, sessions, devices, rotation alerts, health snapshot
//   - MACHINE_IDENTITY_SECRET + ADMIN_USER_ID bindings for automated alerting
// Changelog v2.8.0: Loop Identity Integration
//   - POST /auth/loop-claim: one-step username claim for Loop — issues JWT immediately
//     Loop users are now first-class RALD identities from day one (no more guest_xxx@loop.guest)
// Changelog v2.7.0: Identity Audit & Username Ownership Sprint (P1–P6)
// Changelog v2.6.0: QR Code Login + WebAuthn/Face Auth end-to-end
// Changelog v2.5.0: V2 Username-First Identity — /username, /auth/register-username, /recovery
// Changelog v2.3.0: Phase H.2 — Privacy Center, Verification Engine, Role Engine, Ecosystem Events
// Phase 8: Security Hardening — CSP, HSTS, Referrer-Policy headers on all responses
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { JwtPayload } from "./lib/auth";
import type { KVNamespace } from "./lib/rate-limit";
import type { KvSessionStore } from "./lib/session";
import authRoutes               from "./routes/auth";
import devicesRoutes            from "./routes/devices";
import ssoRoutes                from "./routes/sso";
import clerkRoutes              from "./routes/clerk";
import provisionRoutes          from "./routes/provision";
import profilesRoutes           from "./routes/profiles";
import sessionRoutes            from "./routes/session";
import searchRoutes             from "./routes/search";
import graphRoutes              from "./routes/graph";
import privacyRoutes            from "./routes/privacy";
import verificationEngineRoutes from "./routes/verification-engine";
import rolesRoutes              from "./routes/roles";
import usernameRoutes           from "./routes/username";
import registerUsernameRoute    from "./routes/register-username";
import recoveryRoutes           from "./routes/recovery";
import qrRoutes                 from "./routes/qr";
import webauthnRoutes           from "./routes/webauthn";
import metricsRoutes            from "./routes/metrics";
import loginUsernameRoute       from "./routes/login-username";
import migrationRoutes          from "./routes/migration";
import loopAuthRoutes           from "./routes/loop-auth";
import countryRoutes            from "./routes/country";
import expansionRoutes          from "./routes/expansion";
import smartLoginRoute           from "./routes/smart-login";
import adminUsernameRoutes       from "./routes/admin-username";
import identityRoutes            from "./routes/identity";
import identityBrainRoutes        from "./routes/identity-brain";
import developerRoutes          from "./routes/developer";
import machineRoutes            from "./routes/machine";
import trustRoutes              from "./routes/trust";
import permissionsRoutes        from "./routes/permissions";
import { requestLogger }         from "./lib/logger";
import { runHourlyCleanup, runDailyCleanup, runHealthSnapshot } from "./jobs/cleanup";

export type Bindings = {
  SUPABASE_URL:              string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET:           string;
  TERMII_API_KEY:            string;
  TERMII_SENDER_ID:          string;
  RESEND_API_KEY:            string;
  CLERK_SECRET_KEY:          string;
  CLERK_PUBLISHABLE_KEY:     string;
  ENVIRONMENT:               string;
  RATE_LIMIT_KV:             KVNamespace;
  RALD_SESSION_KV:           KvSessionStore;
  OPEN_OBSERVE_API_KEY?:     string;  // OpenObserve ingest key (C-CERT-004)
  OPEN_OBSERVE_ENDPOINT?:    string;  // e.g. https://observe.rald.cloud/api/rald/rald-auth-core/_json
  MACHINE_IDENTITY_SECRET?:  string;  // Phase 1: auth service machine token for calling notify
  ADMIN_USER_ID?:            string;  // Phase 1: admin user UUID for alerting
};

export type Variables = {
  db:    SupabaseClient;
  user?: JwtPayload;
};

const VERSION = "2.9.0";

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── CORS — full RALD ecosystem ────────────────────────────────────────────────
const STATIC_ORIGINS = new Set([
  "https://profiles.rald.cloud",
  "https://credentials.rald.cloud",
  "https://app.rald.cloud",
  "https://learn.rald.cloud",
  "https://rald.cloud",
  "https://auth.rald.cloud",
  "https://admin.rald.cloud",
  "https://control.rald.cloud",
  "https://console.rald.cloud",
  "https://sdk.rald.cloud",
  "https://sv.rald.cloud",
  "https://silicon.rald.cloud",
  "https://loop.rald.cloud",
  "https://messenger.rald.cloud",
  "https://chat.rald.cloud",
  "https://inbox.rald.cloud",
  "https://pay.rald.cloud",
  "https://payrald.rald.cloud",
  "https://duna.rald.cloud",
  "https://git.rald.cloud",
  "https://analytics.rald.cloud",
  "https://business.rald.cloud",
  "https://ostloop.name.ng",
  "https://identity.rald.cloud",
  "https://rald-identity.pages.dev",
  "https://rald-auth-ui.pages.dev",
  "https://rald-app.pages.dev",
  "https://rald-control-center.pages.dev",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173",
]);

function isAllowedOrigin(origin: string): boolean {
  if (STATIC_ORIGINS.has(origin)) return true;
  if (/^https:\/\/[a-z0-9-]+\.replit\.(app|dev)$/.test(origin)) return true;
  return false;
}

// ── Request logger — OpenObserve log shipping ────────────────────────────────
app.use("*", requestLogger("rald-auth-core"));

app.use("*", cors({
  origin: (origin) => (isAllowedOrigin(origin) ? origin : null),
  allowHeaders: ["Authorization", "Content-Type", "X-Request-ID", "X-App-ID"],
  allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  credentials: true,
}));

// ── Phase 8: Security headers on every response ───────────────────────────────
app.use("*", async (c, next) => {
  await next();
  const res = c.res;
  res.headers.set("X-Content-Type-Options",    "nosniff");
  res.headers.set("X-Frame-Options",            "DENY");
  res.headers.set("X-XSS-Protection",           "1; mode=block");
  res.headers.set("Referrer-Policy",            "strict-origin-when-cross-origin");
  res.headers.set("Permissions-Policy",         "camera=(), microphone=(), geolocation=()");
  res.headers.set("Strict-Transport-Security",  "max-age=31536000; includeSubDomains; preload");
  res.headers.set("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.rald.cloud https://*.supabase.co; frame-ancestors 'none'; upgrade-insecure-requests");
  res.headers.set("X-RALD-Version",    VERSION);
  res.headers.set("X-RALD-Service",    "auth");
  res.headers.set("X-RALD-Owner",      "LILCKY STUDIO LIMITED");
});

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
      observability: !!(c.env.OPEN_OBSERVE_API_KEY && c.env.OPEN_OBSERVE_ENDPOINT),
      machine_auth:  !!(c.env.MACHINE_IDENTITY_SECRET),
    },
    phase: "V2.9 — Phase 1 Public Beta Blockers",
    ...serviceInfo(c),
  })
);

app.get("/system/status", (c) =>
  c.json({
    status:       "operational",
    version:      VERSION,
    identity_hub: "profiles.rald.cloud",
    environment:  c.env.ENVIRONMENT ?? "production",
    features: {
      auth:               "✓ login, register, OTP (email+SMS), password reset",
      loop_identity:      "✓ /auth/loop-claim — username-first, JWT issued immediately, no OTP required",
      username:           "✓ check, claim, change (30-day policy), migration flow",
      sessions:           "✓ create, revoke, revoke-all, device revoke",
      devices:            "✓ list, remove, trust",
      sso:                "✓ exchange, clerk-exchange, silent SSO",
      profiles:           "✓ me, update (incl. region/country), apps, identity, sessions, activity",
      privacy:            "✓ me, export, permissions, delete-request, cancel-deletion",
      verification:       "✓ status, apply, withdraw, badge",
      roles:              "✓ all, me, request, capabilities",
      search:             "✓ users, related",
      graph:              "✓ identity graph, mutual connections, suggestions",
      migration:          "✓ identity-status, claim-username, repair, registry-check (admin)",
      country_activation: "✓ /country/:code status, /country/waitlist join, /country/:code/access gates",
      expansion_admin:    "✓ /admin/expansion list, transition pipeline, emergency restrict, PayRald gate, scorecard",
      security_headers:   "✓ HSTS, CSP, X-Frame-Options, Referrer-Policy",
      identity_brain:     "✓ /identity-brain/* — canonical namespace (aliases /identity/*)",
      scheduled_cleanup:  "✓ OTP, sessions, devices, rotation alerts, health snapshot",
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
app.route("/auth",                   authRoutes);
app.route("/auth",                   loopAuthRoutes);   // POST /auth/loop-claim
app.route("/devices",                devicesRoutes);
app.route("/sso",                    ssoRoutes);
app.route("/sso",                    clerkRoutes);
app.route("/provision",              provisionRoutes);
app.route("/profiles",               profilesRoutes);
app.route("/search",                 searchRoutes);
app.route("/graph",                  graphRoutes);
app.route("/privacy",                privacyRoutes);
app.route("/verify",                 verificationEngineRoutes);
app.route("/roles",                  rolesRoutes);
app.route("/username",               usernameRoutes);
app.route("/auth/register-username", registerUsernameRoute);
app.route("/auth/login-username",    loginUsernameRoute);
app.route("/recovery",               recoveryRoutes);
app.route("/auth/qr",                qrRoutes);
app.route("/auth/webauthn",          webauthnRoutes);
app.route("/auth/smart-login",        smartLoginRoute);
app.route("/admin/usernames",         adminUsernameRoutes);
app.route("/admin/metrics",          metricsRoutes);
app.route("/admin/expansion",        expansionRoutes);
app.route("/migration",              migrationRoutes);
app.route("/country",                countryRoutes);
app.route("/identity",               identityRoutes);
app.route("/identity-brain",         identityBrainRoutes); // manifest + capabilities at /identity-brain/ and /identity-brain/health
app.route("/identity-brain",         identityRoutes);   // Phase 1: canonical Identity Brain namespace (aliases /identity/*)
app.route("/developer",              developerRoutes);
app.route("/machine",                machineRoutes);
app.route("/trust",                  trustRoutes);
app.route("/permissions",            permissionsRoutes);
app.route("/",                       sessionRoutes);

// ── Root ──────────────────────────────────────────────────────────────────────
app.get("/", (c) => c.json({
  docs:           "https://learn.rald.cloud/developers",
  auth:           "https://auth.rald.cloud/health",
  identity_brain: "https://auth.rald.cloud/identity-brain/intelligence",
  learn:          "https://learn.rald.cloud",
  ...serviceInfo(c),
}));
app.notFound((c) => c.json({ error: "Not found", path: c.req.path }, 404));
app.onError((err, c) => {
  console.error("[RALD Auth Error]", err.message ?? err);
  return c.json({ error: "Internal server error" }, 500);
});

export default {
  // ── HTTP handler ────────────────────────────────────────────────────────────
  async fetch(req: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
    const pathname = new URL(req.url).pathname;
    // Health bypass — liveness probes must always get a 200
    if (pathname === "/health" || pathname === "/healthz" || pathname === "/healthcheck" || pathname === "/readyz") {
      return app.fetch(req, env, ctx);
    }

    const missing: string[] = [];
    if (!env.RALD_JWT_SECRET)           missing.push("RALD_JWT_SECRET");
    if (!env.SUPABASE_URL)              missing.push("SUPABASE_URL");
    if (!env.SUPABASE_SERVICE_ROLE_KEY) missing.push("SUPABASE_SERVICE_ROLE_KEY");
    if (missing.length) {
      console.error(`[FATAL] rald-auth: missing required secrets: ${missing.join(", ")}`);
      return new Response(JSON.stringify({ error: "Service misconfigured", missing, service: "rald-auth" }), {
        status: 503, headers: { "Content-Type": "application/json" },
      });
    }
    return app.fetch(req, env, ctx);
  },

  // ── Scheduled handler — Phase 1 Self-Healing Ops ───────────────────────────
  // Cron schedule (defined in wrangler.toml [triggers]):
  //   "0 * * * *"  — hourly: OTP cleanup + expired session deletion
  //   "0 0 * * *"  — daily:  device cleanup + rotation alerts + health snapshot
  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        console.log(`[rald-auth-scheduled] cron fired: ${event.cron} at ${new Date().toISOString()}`);

        // Both crons run hourly cleanup
        const hourlyStats = await runHourlyCleanup(env);
        console.log("[rald-auth-scheduled] hourly cleanup:", JSON.stringify(hourlyStats));

        // Daily jobs (midnight UTC only)
        if (event.cron === "0 0 * * *") {
          const dailyStats = await runDailyCleanup(env);
          console.log("[rald-auth-scheduled] daily cleanup:", JSON.stringify(dailyStats));

          await runHealthSnapshot(env);
        }
      })()
    );
  },
};
