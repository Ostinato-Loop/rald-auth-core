// RALD Auth Core — Cloudflare Worker
// Deployed at: auth.rald.cloud | Version: 3.1.0
// Changelog v3.1.0: RALD OS Phases 2, 3, 4, 6
//   Phase 2: POST /provision/webhook — async identity.created receiver
//   Phase 3: GET/PATCH /trust/* — Trust Engine (single trust source)
//   Phase 4: GET/POST /products/* — Product Registry
//   Phase 6: GET /raldtics/* — RALDTICS Observability dashboard
//   Scheduled: POST /raldtics/snapshot taken every hour
// Changelog v3.0.0: Phase 1 — Universal Identity Layer
//   POST /signup, /signup/status, /signup/retry
//   GET/POST /admin/provision/*
//   retry queue drained hourly, events.rald.cloud wired
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
import smartLoginRoute          from "./routes/smart-login";
import adminUsernameRoutes      from "./routes/admin-username";
import identityRoutes           from "./routes/identity";
import identityBrainRoutes      from "./routes/identity-brain";
import developerRoutes          from "./routes/developer";
import machineRoutes            from "./routes/machine";
import trustRoutes              from "./routes/trust";
import permissionsRoutes        from "./routes/permissions";
// RALD OS Phase 1: Universal Identity Layer
import universalSignupRoutes    from "./routes/universal-signup";
import provisionDashboardRoutes from "./routes/provision-dashboard";
// RALD OS Phase 2: Async Provisioning Webhook
import provisionWebhookRoutes   from "./routes/provision-webhook";
// RALD OS Phase 3: Trust Engine
import trustEngineRoutes        from "./routes/trust-engine";
// RALD OS Phase 4: Product Registry
import productRegistryRoutes    from "./routes/product-registry";
// RALD OS Phase 6: RALDTICS Observability
import raldticsRoutes           from "./routes/raldtics";
import { requestLogger }        from "./lib/logger";
import { runHourlyCleanup, runDailyCleanup, runHealthSnapshot } from "./jobs/cleanup";
import { processRetryQueue }    from "./lib/identity-provisioner";

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
  OPEN_OBSERVE_API_KEY?:     string;
  OPEN_OBSERVE_ENDPOINT?:    string;
  MACHINE_IDENTITY_SECRET?:  string;
  ADMIN_USER_ID?:            string;
  // RALD OS: Event bus + machine identity
  EVENTS_BUS_URL?:           string;
  RALD_INTERNAL_SECRET?:     string;
  MACHINE_KEY_ID?:           string;
  MACHINE_KEY_SECRET?:       string;
};

export type Variables = {
  db:      SupabaseClient;
  user?:   JwtPayload;
  logger?: { info: (m: string | Record<string,unknown>, msg?: string) => void; warn: (m: string | Record<string,unknown>, msg?: string) => void; error: (m: string | Record<string,unknown>, msg?: string) => void };
  machine?: { sub: string; aud: string; permissions: string[]; machine: boolean; iat: number; exp: number };
};

const VERSION = "3.1.0";

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── CORS ─────────────────────────────────────────────────────────────────────
const STATIC_ORIGINS = new Set([
  "https://profiles.rald.cloud","https://credentials.rald.cloud",
  "https://app.rald.cloud","https://learn.rald.cloud","https://rald.cloud",
  "https://auth.rald.cloud","https://admin.rald.cloud","https://control.rald.cloud",
  "https://console.rald.cloud","https://sdk.rald.cloud","https://sv.rald.cloud",
  "https://silicon.rald.cloud","https://loop.rald.cloud","https://messenger.rald.cloud",
  "https://chat.rald.cloud","https://inbox.rald.cloud","https://pay.rald.cloud",
  "https://payrald.rald.cloud","https://duna.rald.cloud","https://git.rald.cloud",
  "https://analytics.rald.cloud","https://business.rald.cloud","https://ostloop.name.ng",
  "https://identity.rald.cloud","https://provision.rald.cloud","https://api.rald.cloud",
  "https://rald-identity.pages.dev","https://rald-auth-ui.pages.dev",
  "https://rald-app.pages.dev","https://rald-control-center.pages.dev",
  "http://localhost:5173","http://localhost:3000","http://localhost:4173",
]);

function isAllowedOrigin(origin: string): boolean {
  if (STATIC_ORIGINS.has(origin)) return true;
  if (/^https:\/\/[a-z0-9-]+\.replit\.(app|dev)$/.test(origin)) return true;
  return false;
}

app.use("*", requestLogger("rald-auth-core"));

app.use("*", cors({
  origin: (origin) => (isAllowedOrigin(origin) ? origin : null),
  allowHeaders: ["Authorization","Content-Type","X-Request-ID","X-App-ID","X-RALD-Internal-Key","X-RALD-Signature"],
  allowMethods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  credentials: true,
}));

app.use("*", async (c, next) => {
  await next();
  const r = c.res;
  r.headers.set("X-Content-Type-Options",   "nosniff");
  r.headers.set("X-Frame-Options",          "DENY");
  r.headers.set("X-XSS-Protection",         "1; mode=block");
  r.headers.set("Referrer-Policy",          "strict-origin-when-cross-origin");
  r.headers.set("Permissions-Policy",       "camera=(), microphone=(), geolocation=()");
  r.headers.set("Strict-Transport-Security","max-age=31536000; includeSubDomains; preload");
  r.headers.set("Content-Security-Policy",  "default-src 'self'; frame-ancestors 'none'");
  r.headers.set("X-RALD-Version",   VERSION);
  r.headers.set("X-RALD-Service",   "auth");
  r.headers.set("X-RALD-Owner",     "LILCKY STUDIO LIMITED");
});

app.use("*", async (c, next) => {
  c.set("db", createClient(c.env.SUPABASE_URL, c.env.SUPABASE_SERVICE_ROLE_KEY));
  await next();
});

const serviceInfo = (c: { env: Bindings }) => ({
  service:     "rald-auth",
  version:     VERSION,
  os_phase:    "3.1.0 — Trust + Products + RALDTICS + Async Provision",
  environment: c.env.ENVIRONMENT ?? "production",
  owner:       "LILCKY STUDIO LIMITED",
  timestamp:   new Date().toISOString(),
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health",  (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/healthz", (c) => c.json({ status: "ok", ...serviceInfo(c) }));
app.get("/version", (c) => c.json(serviceInfo(c)));

app.get("/ready", (c) =>
  c.json({
    ready: !!(c.env.SUPABASE_URL && c.env.RALD_JWT_SECRET && c.env.RESEND_API_KEY),
    checks: {
      supabase:            !!c.env.SUPABASE_URL && !!c.env.SUPABASE_SERVICE_ROLE_KEY,
      jwt:                 !!c.env.RALD_JWT_SECRET,
      termii:              !!c.env.TERMII_API_KEY,
      resend:              !!c.env.RESEND_API_KEY,
      clerk:               !!c.env.CLERK_SECRET_KEY && !!c.env.CLERK_PUBLISHABLE_KEY,
      rate_limit_kv:       !!(c.env.RATE_LIMIT_KV),
      session_kv:          !!(c.env.RALD_SESSION_KV),
      event_bus:           !!(c.env.RALD_INTERNAL_SECRET),
      machine_auth:        !!(c.env.MACHINE_KEY_ID && c.env.MACHINE_KEY_SECRET),
    },
    os_phases: { p1_identity:"✓", p2_async_provision:"✓", p3_trust:"✓", p4_products:"✓", p6_raldtics:"✓" },
    ...serviceInfo(c),
  })
);

app.get("/system/status", (c) =>
  c.json({
    status: "operational",
    version: VERSION,
    features: {
      // Original auth features
      auth:"✓ login, register, OTP, password reset",
      loop_identity:"✓ /auth/loop-claim",
      sessions:"✓ create, revoke, revoke-all",
      devices:"✓ list, remove, trust",
      sso:"✓ exchange, clerk, silent",
      profiles:"✓ me, update, apps, identity, sessions",
      privacy:"✓ me, export, permissions, delete",
      verification:"✓ status, apply, withdraw, badge",
      roles:"✓ all, me, request, capabilities",
      search:"✓ users, related",
      identity_brain:"✓ /identity-brain/* canonical",
      // RALD OS Phases
      p1_universal_signup:"✓ POST /signup — full chain in <10s",
      p1_provision_status:"✓ GET /signup/status/:rald_id",
      p1_provision_dashboard:"✓ GET /admin/provision/dashboard",
      p2_async_webhook:"✓ POST /provision/webhook — identity.created fan-out",
      p3_trust_engine:"✓ GET /trust-engine/:rald_id, PATCH, recompute, leaderboard",
      p4_product_registry:"✓ GET/POST /products, /products/ecosystem/health",
      p6_raldtics:"✓ GET /raldtics/dashboard|signups|products|trust|retry-queue",
      event_bus:"✓ identity.created → events.rald.cloud",
      retry_queue:"✓ exponential backoff, 10 attempts, drained hourly",
    },
    timestamp: new Date().toISOString(),
    ...serviceInfo(c),
  })
);

// ── Routes ────────────────────────────────────────────────────────────────────
app.route("/auth",                   authRoutes);
app.route("/auth",                   loopAuthRoutes);
app.route("/devices",                devicesRoutes);
app.route("/sso",                    ssoRoutes);
app.route("/sso",                    clerkRoutes);
app.route("/provision",              provisionRoutes);
app.route("/provision",              provisionWebhookRoutes);   // Phase 2
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
app.route("/auth/smart-login",       smartLoginRoute);
app.route("/admin/usernames",        adminUsernameRoutes);
app.route("/admin/metrics",          metricsRoutes);
app.route("/admin/expansion",        expansionRoutes);
app.route("/admin/provision",        provisionDashboardRoutes); // Phase 1
app.route("/migration",              migrationRoutes);
app.route("/country",                countryRoutes);
app.route("/identity",               identityRoutes);
app.route("/identity-brain",         identityBrainRoutes);
app.route("/identity-brain",         identityRoutes);
app.route("/developer",              developerRoutes);
app.route("/machine",                machineRoutes);
app.route("/trust",                  trustRoutes);
app.route("/trust-engine",           trustEngineRoutes);        // Phase 3
app.route("/permissions",            permissionsRoutes);
app.route("/products",               productRegistryRoutes);    // Phase 4
app.route("/signup",                 universalSignupRoutes);    // Phase 1
app.route("/raldtics",               raldticsRoutes);           // Phase 6
app.route("/",                       sessionRoutes);

// ── Root ──────────────────────────────────────────────────────────────────────
app.get("/", (c) => c.json({
  docs:          "https://learn.rald.cloud/developers",
  api_gateway:   "https://api.rald.cloud",
  signup:        "POST /signup",
  identity:      "GET /identity-brain/intelligence",
  trust:         "GET /trust-engine/:rald_id",
  products:      "GET /products",
  dashboard:     "GET /admin/provision/dashboard",
  raldtics:      "GET /raldtics/dashboard",
  ecosystem:     "GET https://api.rald.cloud/ecosystem/health",
  ...serviceInfo(c),
}));
app.notFound((c) => c.json({ error: "Not found", path: c.req.path }, 404));
app.onError((err, c) => {
  console.error("[RALD Auth Error]", err.message ?? err);
  return c.json({ error: "Internal server error" }, 500);
});

export default {
  async fetch(req: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
    const pathname = new URL(req.url).pathname;
    if (["/health","/healthz","/healthcheck","/readyz"].includes(pathname)) {
      return app.fetch(req, env, ctx);
    }
    const missing: string[] = [];
    if (!env.RALD_JWT_SECRET)           missing.push("RALD_JWT_SECRET");
    if (!env.SUPABASE_URL)              missing.push("SUPABASE_URL");
    if (!env.SUPABASE_SERVICE_ROLE_KEY) missing.push("SUPABASE_SERVICE_ROLE_KEY");
    if (missing.length) {
      return new Response(JSON.stringify({ error: "Service misconfigured", missing }), {
        status: 503, headers: { "Content-Type": "application/json" },
      });
    }
    return app.fetch(req, env, ctx);
  },

  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        console.log(`[rald-auth-scheduled] cron: ${event.cron} at ${new Date().toISOString()}`);
        const db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);

        // Hourly: OTP + session cleanup + retry queue drain
        const [hourlyStats, retryStats] = await Promise.all([
          runHourlyCleanup(env),
          processRetryQueue(db),
        ]);
        console.log("[scheduled] hourly:", JSON.stringify(hourlyStats));
        console.log("[scheduled] retry:",  JSON.stringify(retryStats));

        // Hourly: RALDTICS snapshot
        const dashboard = await db.from("raldtics_executive_dashboard").select("*").maybeSingle();
        const d = dashboard.data ?? {} as any;
        await db.from("raldtics_snapshots").insert({
          period: "1h", total_users: d.total_identities ?? 0,
          signups: d.signups_24h ?? 0, active_users: d.total_identities ?? 0,
          wallets: d.active_wallets ?? 0, active_wallets: d.active_wallets ?? 0,
          aliases: d.active_aliases ?? 0, schools: d.schools ?? 0, merchants: d.merchants ?? 0,
        }).then(undefined, (e: unknown) => console.warn("[scheduled] snapshot failed:", String(e)));

        // Daily (midnight UTC): device cleanup + rotation alerts + health snapshot
        if (event.cron === "0 0 * * *") {
          const [dailyStats] = await Promise.all([
            runDailyCleanup(env),
            runHealthSnapshot(env),
          ]);
          console.log("[scheduled] daily:", JSON.stringify(dailyStats));
          // Daily 24h snapshot
          await db.from("raldtics_snapshots").insert({
            period: "24h", total_users: d.total_identities ?? 0,
            signups: d.signups_24h ?? 0, active_users: d.total_identities ?? 0,
            wallets: d.active_wallets ?? 0, active_wallets: d.active_wallets ?? 0,
            aliases: d.active_aliases ?? 0, schools: d.schools ?? 0, merchants: d.merchants ?? 0,
          }).then(undefined, (e: unknown) => console.warn("[scheduled] daily snapshot failed:", String(e)));
        }
      })()
    );
  },
};
