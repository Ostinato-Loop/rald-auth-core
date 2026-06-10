// RALD Auth Core — Username Routes (V2 Identity)
// GET  /username/check/:username  — live availability check (no auth required)
// POST /username/claim             — claim a username (authenticated)
// GET  /username/me                — get caller's username (authenticated)
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { checkRateLimit, RATE_LIMITS, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const username = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Reserved words — cannot be claimed as usernames
const RESERVED_WORDS = new Set([
  "admin", "administrator", "support", "help", "security", "abuse",
  "rald", "loop", "messenger", "payrald", "gitrald", "raldtics",
  "mail", "voice", "dispatch", "ai", "inbox", "billing",
  "root", "system", "bot", "api", "auth", "sso", "oauth",
  "null", "undefined", "true", "false", "test", "demo", "example",
  "official", "staff", "team", "mod", "moderator", "operator",
]);

/** Validate username format: 2–20 chars, lowercase letters/numbers/underscores only */
function validateUsernameFormat(u: string): { valid: boolean; reason?: string } {
  const lower = u.toLowerCase();
  if (lower.length < 2)  return { valid: false, reason: "Username must be at least 2 characters" };
  if (lower.length > 20) return { valid: false, reason: "Username must be 20 characters or fewer" };
  if (!/^[a-z0-9_]+$/.test(lower)) return { valid: false, reason: "Username can only contain letters, numbers, and underscores" };
  if (lower.startsWith("_") || lower.endsWith("_")) return { valid: false, reason: "Username cannot start or end with an underscore" };
  if (/_{2,}/.test(lower)) return { valid: false, reason: "Username cannot contain consecutive underscores" };
  if (RESERVED_WORDS.has(lower)) return { valid: false, reason: "This username is reserved" };
  return { valid: true };
}

// ── GET /username/check/:username — live availability (no auth) ───────────────
username.get("/check/:username", async (c) => {
  const raw = c.req.param("username");
  const lower = raw.toLowerCase();

  const { valid, reason } = validateUsernameFormat(lower);
  if (!valid) {
    return c.json({ available: false, username: lower, reason });
  }

  const db = c.get("db");
  const { data, error } = await db
    .from("usernames")
    .select("username")
    .eq("username", lower)
    .eq("active", true)
    .limit(1);

  if (error) {
    console.error("[username/check] db error:", error.message);
    return c.json({ available: false, username: lower, reason: "Availability check failed, please try again" }, 500);
  }

  const taken = !!(data && data.length > 0);
  return c.json({
    available: !taken,
    username:  lower,
    reason:    taken ? "Username is already taken" : null,
  });
});

// ── POST /username/claim — claim a username (authenticated user) ───────────────
username.post("/claim", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const db   = c.get("db");
  const kv   = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  // Rate limit: 5 claims per user per hour (prevents churn/squatting)
  const rlCheck = await checkRateLimit(kv, {
    key: `username:claim:${user.id}`,
    limit: 5,
    windowSeconds: 3600,
  });
  if (!rlCheck.allowed) return rateLimitResponse(rlCheck.resetAt);

  const body = await c.req.json<{ username?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim();
  const { valid, reason } = validateUsernameFormat(lower);
  if (!valid) return c.json({ error: reason }, 400);

  // Check if user already has a username
  const { data: existing } = await db
    .from("auth_users")
    .select("username")
    .eq("id", user.id)
    .limit(1);

  const currentUsername = existing?.[0]?.username ?? null;
  if (currentUsername) {
    return c.json({
      error: `You already have the username @${currentUsername}. Contact support to change it.`,
      current_username: currentUsername,
    }, 409);
  }

  // Atomically check + insert into usernames table
  const { error: insertError } = await db.from("usernames").insert({
    username:   lower,
    user_id:    user.id,
    claimed_at: new Date().toISOString(),
    active:     true,
  });

  if (insertError) {
    if (insertError.code === "23505") {
      // Unique violation — someone else just claimed it
      return c.json({ error: "Username just became unavailable. Please choose another." }, 409);
    }
    console.error("[username/claim] insert error:", insertError.message);
    return c.json({ error: "Failed to claim username" }, 500);
  }

  // Update auth_users with username
  await db.from("auth_users").update({
    username:        lower,
    username_set_at: new Date().toISOString(),
  }).eq("id", user.id);

  // Write username history
  await db.from("username_history").insert({
    user_id:  user.id,
    username: lower,
    action:   "claimed",
  });

  // Reserve namespace: username@rald.me, username.rald.me, workspace slug
  await db.rpc("reserve_username_namespace", {
    p_user_id:  user.id,
    p_username: lower,
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "username_claimed",
    ip,
    status:   "success",
    metadata: { username: lower },
  });

  return c.json({
    ok:                  true,
    username:            lower,
    reserved_mail:       `${lower}@rald.me`,
    reserved_domain:     `${lower}.rald.me`,
    reserved_workspace:  lower,
    message:             `@${lower} is yours. Your RALD mail address ${lower}@rald.me has been reserved.`,
  });
});

// ── GET /username/me — get current user's username ────────────────────────────
username.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data } = await db
    .from("auth_users")
    .select("username, username_set_at, rald_internal_id")
    .eq("id", user.id)
    .limit(1);

  const row = data?.[0];
  return c.json({
    user_id:         user.id,
    username:        row?.username ?? null,
    username_set_at: row?.username_set_at ?? null,
    has_username:    !!row?.username,
  });
});

export default username;
