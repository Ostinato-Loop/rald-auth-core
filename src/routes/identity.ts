/**
 * RALD Identity Intelligence Layer — /identity/* routes
 *
 * Single source of truth for what RALD already knows about a user.
 * Products call GET /identity/intelligence before showing any onboarding
 * step so they never ask for information RALD already has.
 *
 * Routes
 *   GET  /identity/canonical-redirect   → tells products where to send users for identity edits
 *   GET  /identity/capabilities         → user's unlocked product capabilities
 *   GET  /identity/intelligence         → full capability snapshot (auth required)
 *   POST /identity/intelligence         → update a single capability field (auth required)
 *   GET  /identity/memory               → onboarding + dismissal history (auth required)
 *   POST /identity/memory/dismiss       → mark a prompt as dismissed (auth required)
 *   POST /identity/memory/step          → record current onboarding step (auth required)
 *
 * ONE RALD — Identity Consolidation & Account Authority Program
 * LILCKY STUDIO LIMITED · 2026-06-12
 */

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";

const identity = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /identity/canonical-redirect ─────────────────────────────────────────
//
// Products use this whenever the user attempts any identity-related action:
//   Edit Profile · Change Username · Security Settings · Session Management
//   Device Management · Verification · Recovery · Developer Portal
//
// Response is intentionally unauthenticated so products can call it pre-login.
// The canonical URL is always profiles.rald.cloud — the ONE RALD Account Portal.
//
// Action IDs that products should pass as ?action=<id>:
//   profile          → /account
//   username         → /account
//   security         → /security
//   sessions         → /security
//   devices          → /security
//   verification     → /account
//   recovery         → /login
//   developer        → /developer  (future)
//   privacy          → /privacy
//   country          → /account
//   workspace        → /account
//   delete           → /privacy

const CANONICAL_BASE = "https://profiles.rald.cloud";

const ACTION_PATHS: Record<string, string> = {
  profile:       "/account",
  username:      "/account",
  security:      "/security",
  sessions:      "/security",
  devices:       "/security",
  verification:  "/account",
  recovery:      "/login",
  developer:     "/developer",
  privacy:       "/privacy",
  country:       "/account",
  workspace:     "/account",
  delete:        "/privacy",
};

identity.get("/canonical-redirect", async (c) => {
  const action  = c.req.query("action")  ?? null;
  const appId   = c.req.query("app_id")  ?? null;
  const returnTo = c.req.query("return_to") ?? null;

  const path   = (action && ACTION_PATHS[action]) ?? "/account";
  let canonical = `${CANONICAL_BASE}${path}`;

  // Preserve the calling product's context so the portal can redirect back after edit
  const params = new URLSearchParams();
  if (appId)    params.set("app_id",    appId);
  if (returnTo) params.set("return_to", returnTo);
  if (action)   params.set("intent",    action);
  const qs = params.toString();
  if (qs) canonical += `?${qs}`;

  return c.json({
    canonical,
    base:   CANONICAL_BASE,
    path,
    reason: "identity-management",
    // Human-readable note for product developers
    note: "Users must edit their identity only at profiles.rald.cloud. Products are consumers of RALD Identity, not owners.",
  });
});

// ── GET /identity/capabilities ────────────────────────────────────────────────
//
// Returns the authenticated user's unlocked product capabilities.
// Products self-configure based on this instead of guessing or hard-coding.
// Capabilities are derived from trust level, verification status, and provisioned apps.

identity.get("/capabilities", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [capRes, userRes] = await Promise.all([
    db.from("identity_capabilities")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle(),
    db.from("auth_users")
      .select("trust_level, username, reserved_email_address")
      .eq("id", user.id)
      .limit(1),
  ]);

  const cap = capRes.data;
  const u   = userRes.data?.[0];

  const trustLevel: string = cap?.trust_level ?? u?.trust_level ?? "none";
  const hasUsername         = !!(cap?.username ?? u?.username);
  const hasMail             = !!(cap?.mail_reserved ?? u?.reserved_email_address);
  const creatorVerified     = cap?.creator_verified  ?? false;
  const businessVerified    = cap?.business_verified ?? false;

  return c.json({
    // Core identity capabilities — available to all registered users
    mail:          hasMail,
    developer:     hasUsername,
    workspace:     hasUsername,

    // Trust-gated capabilities
    payments:      ["basic", "full", "elite"].includes(trustLevel),
    business:      businessVerified || ["full", "elite"].includes(trustLevel),
    creator:       creatorVerified,

    // Product access
    loop:          true,
    messenger:     true,
    gitrald:       hasUsername,
    dispatch:      ["full", "elite"].includes(trustLevel),
    voice:         ["full", "elite"].includes(trustLevel),

    // Trust metadata
    trust_level:   trustLevel,

    // Identity completeness flag
    identity_ready: hasUsername && hasMail,
  });
});

// ── GET /identity/intelligence ───────────────────────────────────────────────
identity.get("/intelligence", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [capRes, userRes, profileRes] = await Promise.all([
    db.from("identity_capabilities")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle(),
    db.from("auth_users")
      .select("id,username,email,email_verified,phone_number,phone_verified,trust_level,reserved_email_address")
      .eq("id", user.id)
      .limit(1),
    db.from("auth_user_profiles")
      .select("avatar_url,country,region,bio,display_name,onboarding_complete")
      .eq("user_id", user.id)
      .maybeSingle(),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const cap = capRes.data;
  const p   = profileRes.data;

  const username     = cap?.username     ?? u.username     ?? null;
  const email        = cap?.email        ?? u.email        ?? null;
  const phone        = cap?.phone        ?? u.phone_number ?? null;
  const profilePhoto = cap?.profile_photo ?? p?.avatar_url ?? null;
  const country      = cap?.country      ?? p?.country     ?? null;
  const mailAddress  = cap?.mail_reserved
    ?? u.reserved_email_address
    ?? (username ? `${username}@rald.me` : null);

  return c.json({
    // Boolean flags — true = RALD already has this, products must not ask again
    username:              !!username,
    username_verified:     cap?.username_verified ?? !!username,
    email:                 !!email,
    email_verified:        cap?.email_verified ?? u.email_verified ?? false,
    phone:                 !!phone,
    phone_verified:        cap?.phone_verified ?? u.phone_verified ?? false,
    profile_photo:         !!profilePhoto,
    country:               !!country,
    state:                 !!(cap?.state),
    city:                  !!(cap?.city),
    language:              !!(cap?.language),
    // Trust & verification tiers
    trust_level:           cap?.trust_level ?? u.trust_level ?? "none",
    creator_verified:      cap?.creator_verified  ?? false,
    business_verified:     cap?.business_verified ?? false,
    civic_verified:        cap?.civic_verified    ?? false,
    // RALD Mail
    mail_reserved:         !!mailAddress,
    mail_address:          mailAddress,
    // Onboarding
    completed_onboarding:  cap?.completed_onboarding ?? p?.onboarding_complete ?? false,
    // Pre-fill values — safe for the authenticated user to receive
    _values: {
      username,
      email,
      phone,
      profile_photo: profilePhoto,
      country,
      display_name:  p?.display_name ?? null,
      bio:           p?.bio          ?? null,
    },
  });
});

// ── POST /identity/intelligence ──────────────────────────────────────────────
identity.post("/intelligence", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const body = await c.req.json<{ field: string; value: unknown }>().catch(() => null);
  if (!body?.field) return c.json({ error: "field is required" }, 400);

  const ALLOWED = new Set([
    "profile_photo", "country", "state", "city", "language", "timezone",
    "completed_onboarding", "creator_verified", "business_verified", "civic_verified",
    "mail_reserved",
  ]);
  if (!ALLOWED.has(body.field)) {
    return c.json({ error: `field '${body.field}' cannot be updated via this endpoint` }, 400);
  }

  const { error } = await db.from("identity_capabilities").upsert(
    { user_id: user.id, [body.field]: body.value, updated_at: new Date().toISOString() },
    { onConflict: "user_id" },
  );

  if (error) {
    c.get("logger")?.error({ err: error.message }, "[identity] update error");
    return c.json({ error: "Update failed" }, 500);
  }
  return c.json({ ok: true, field: body.field });
});

// ── GET /identity/memory ─────────────────────────────────────────────────────
identity.get("/memory", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data } = await db.from("identity_memory")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  return c.json({
    last_onboarding_step: data?.last_onboarding_step ?? null,
    dismissed_prompts:    data?.dismissed_prompts    ?? [],
    verification_history: data?.verification_history ?? [],
    product_history:      data?.product_history      ?? [],
    preferences:          data?.preferences          ?? {},
  });
});

// ── POST /identity/memory/dismiss ────────────────────────────────────────────
identity.post("/memory/dismiss", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const body = await c.req.json<{ prompt: string }>().catch(() => null);
  if (!body?.prompt) return c.json({ error: "prompt is required" }, 400);

  const { data: existing } = await db.from("identity_memory")
    .select("dismissed_prompts")
    .eq("user_id", user.id)
    .maybeSingle();

  const current: string[] = (existing?.dismissed_prompts as string[] | null) ?? [];
  if (!current.includes(body.prompt)) current.push(body.prompt);

  await db.from("identity_memory").upsert(
    { user_id: user.id, dismissed_prompts: current, updated_at: new Date().toISOString() },
    { onConflict: "user_id" },
  );

  return c.json({ ok: true, dismissed: current });
});

// ── POST /identity/memory/step ───────────────────────────────────────────────
identity.post("/memory/step", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const body = await c.req.json<{ step: string; product?: string }>().catch(() => null);
  if (!body?.step) return c.json({ error: "step is required" }, 400);

  const { data: existing } = await db.from("identity_memory")
    .select("product_history")
    .eq("user_id", user.id)
    .maybeSingle();

  const history = (existing?.product_history as Array<{ product: string; step: string; ts: string }> | null) ?? [];
  history.push({ product: body.product ?? "unknown", step: body.step, ts: new Date().toISOString() });
  // Keep last 100 history entries
  const trimmed = history.slice(-100);

  await db.from("identity_memory").upsert(
    {
      user_id:              user.id,
      last_onboarding_step: body.step,
      product_history:      trimmed,
      updated_at:           new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );

  return c.json({ ok: true, step: body.step });
});

export default identity;
