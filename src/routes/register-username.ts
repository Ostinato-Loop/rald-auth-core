// RALD Auth Core — Username-First Registration (V2)
// POST /auth/register-username
//
// Flow:
//   1. User submits desired @username (no email, no password)
//   2. Server validates + reserves username
//   3. Creates auth_users row with rald_internal_id (Layer 1)
//   4. Creates usernames row (Layer 2)
//   5. Reserves mail + workspace namespace
//   6. Returns pending_user_id — next step is OTP verification
//
// After this endpoint, the caller must hit:
//   POST /auth/send-phone-otp  or  POST /auth/send-email-otp
// with { pending_user_id } to receive and verify a code.
// Session is only issued after OTP is verified.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const registerUsername = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const RESERVED_WORDS = new Set([
  "admin", "administrator", "support", "help", "security", "abuse",
  "rald", "loop", "messenger", "payrald", "gitrald", "raldtics",
  "mail", "voice", "dispatch", "ai", "inbox", "billing",
  "root", "system", "bot", "api", "auth", "sso", "oauth",
  "null", "undefined", "true", "false", "test", "demo", "example",
  "official", "staff", "team", "mod", "moderator", "operator",
]);

function validateUsername(u: string): { valid: boolean; reason?: string } {
  if (u.length < 2)  return { valid: false, reason: "Username must be at least 2 characters" };
  if (u.length > 20) return { valid: false, reason: "Username must be 20 characters or fewer" };
  if (!/^[a-z0-9_]+$/.test(u)) return { valid: false, reason: "Username can only contain letters, numbers, and underscores" };
  if (u.startsWith("_") || u.endsWith("_")) return { valid: false, reason: "Username cannot start or end with an underscore" };
  if (/_{2,}/.test(u)) return { valid: false, reason: "Username cannot contain consecutive underscores" };
  if (RESERVED_WORDS.has(u)) return { valid: false, reason: "This username is reserved" };
  return { valid: true };
}

/** Generate a permanent internal RALD ID: rald_XXXXXXXX (8 uppercase alphanumeric chars) */
function generateRaldInternalId(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return "rald_" + Array.from(buf).map(b => chars[b % chars.length]).join("");
}

// ── POST /auth/register-username ──────────────────────────────────────────────
registerUsername.post("/", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  // Rate limit: 10 attempts per IP per hour
  const rlCheck = await checkRateLimit(kv, {
    key:           `register-username:ip:${ip}`,
    limit:         10,
    windowSeconds: 3600,
  });
  if (!rlCheck.allowed) return rateLimitResponse(rlCheck.resetAt);

  const body = await c.req.json<{
    username?:    string;
    app_id?:      string;
    redirect_to?: string;
    country?:     string;
  }>().catch(() => null);

  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim();
  const { valid, reason } = validateUsername(lower);
  if (!valid) return c.json({ error: reason }, 400);

  // Check availability
  const { data: existing, error: checkErr } = await db
    .from("usernames")
    .select("username")
    .eq("username", lower)
    .eq("active", true)
    .limit(1);

  if (checkErr) {
    console.error("[register-username] availability check failed:", checkErr.message);
    return c.json({ error: "Could not check username availability" }, 500);
  }

  if (existing && existing.length > 0) {
    return c.json({ error: "Username is already taken", available: false }, 409);
  }

  // Generate permanent internal ID (Layer 1)
  const raldInternalId = generateRaldInternalId();

  // Create auth_users row — no email, no password (V2 username-first)
  // email column is NOT NULL in current schema, so we use a placeholder
  // that is identifiable but never used for auth. Will be updated when
  // user adds a recovery email via /profile/add-email.
  const placeholderEmail = `${lower}.pending@rald.identity`;

  const { data: newUsers, error: createErr } = await db
    .from("auth_users")
    .insert({
      email:            placeholderEmail,
      name:             lower,    // display name defaults to username, updateable later
      username:         lower,
      username_set_at:  new Date().toISOString(),
      rald_internal_id: raldInternalId,
      rald_id:          raldInternalId, // keep legacy rald_id in sync
      role:             "user",
      email_verified:   false,
      phone_verified:   false,
    })
    .select("id")
    .limit(1);

  if (createErr || !newUsers || newUsers.length === 0) {
    console.error("[register-username] user create error:", createErr?.message);
    if (createErr?.code === "23505") {
      return c.json({ error: "Username is already taken", available: false }, 409);
    }
    return c.json({ error: "Failed to create identity" }, 500);
  }

  const userId = newUsers[0]!.id as string;

  // Insert into usernames table (canonical registry)
  await db.from("usernames").insert({
    username:   lower,
    user_id:    userId,
    claimed_at: new Date().toISOString(),
    active:     true,
  }).then(() => null, () => null);

  // Reserve namespace: username@rald.me, username.rald.me, workspace
  await db.rpc("reserve_username_namespace", {
    p_user_id:  userId,
    p_username: lower,
  }).then(() => null, () => null);

  // Username history
  await db.from("username_history").insert({
    user_id:  userId,
    username: lower,
    action:   "claimed",
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId:   userId,
    action:   "username_claimed",
    ip,
    status:   "success",
    metadata: {
      username:         lower,
      rald_internal_id: raldInternalId,
      app_id:           body.app_id ?? null,
      country:          body.country ?? null,
    },
  });

  return c.json({
    ok:               true,
    pending_user_id:  userId,
    username:         lower,
    rald_internal_id: raldInternalId,
    reserved_mail:    `${lower}@rald.me`,
    next_step:        "verification",
    message:          `@${lower} is reserved. Verify your identity to complete setup.`,
    verification_options: ["sms", "email"],
  }, 201);
});

export default registerUsername;
