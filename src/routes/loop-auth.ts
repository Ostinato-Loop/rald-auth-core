// RALD Auth Core — Loop Identity Claim
// POST /auth/loop-claim
//
// Loop-specific one-step identity creation.
// Reserves @username → issues JWT immediately → no OTP required to enter Loop.
// The user IS a first-class RALD identity from day one:
//   - Real username in auth_users + usernames table
//   - username@rald.me reserved
//   - auth_user_profiles + auth_trust_profiles created
//   - username_migration_queue NOT seeded (they have a username)
//
// Identity is "soft" until verified (needs_verification: true in response).
// Verification is prompted async inside Loop — never blocks room entry.
//
// Rate limiting: 5 claims per IP per hour (prevents squatting on loop launch)
//
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { signJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const loopAuth = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Reserved namespace (mirrors register-username.ts) ─────────────────────────
const RESERVED_WORDS = new Set([
  "rald", "raldcloud", "raldme", "raldinc", "raldstudio", "raldteam",
  "lilcky", "lilckystudio", "lilckystudios", "ostinato", "ostinatoloop",
  "loop", "messenger", "payrald", "gitrald", "raldtics", "raldai",
  "mail", "raldmail", "voice", "raldvoice", "dispatch", "raldispatch",
  "silicon", "sv", "duna", "manilla", "manillafm",
  "admin", "administrator", "superadmin", "sysadmin",
  "support", "help", "helpdesk", "billing", "payments",
  "security", "abuse", "noreply", "no-reply", "donotreply",
  "root", "system", "bot", "bots", "daemon",
  "api", "auth", "sso", "oauth", "openid", "saml",
  "null", "undefined", "true", "false",
  "test", "demo", "example", "sample", "dummy", "placeholder",
  "official", "staff", "team", "crew", "mod", "moderator", "operator",
  "inbox", "postmaster", "webmaster", "hostmaster",
  "president", "governor", "minister", "senator", "government",
  "police", "army", "military", "cbn", "firs", "efcc",
]);

function validateUsername(raw: string): { valid: boolean; reason?: string } {
  const u = raw.toLowerCase().trim();
  if (u.length < 2)  return { valid: false, reason: "Username must be at least 2 characters" };
  if (u.length > 20) return { valid: false, reason: "Username must be 20 characters or fewer" };
  if (!/^[a-z0-9_]+$/.test(u)) return { valid: false, reason: "Only letters, numbers, and underscores are allowed" };
  if (u.startsWith("_") || u.endsWith("_")) return { valid: false, reason: "Username cannot start or end with an underscore" };
  if (/_{2,}/.test(u)) return { valid: false, reason: "Username cannot contain consecutive underscores" };
  if (RESERVED_WORDS.has(u)) return { valid: false, reason: "This username is reserved" };
  if (/^test\d*$/.test(u) || /^user\d+$/.test(u) || /^admin\d+$/.test(u)) {
    return { valid: false, reason: "This username is reserved" };
  }
  return { valid: true };
}

function generateRaldInternalId(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return "rald_" + Array.from(buf, b => chars[b % chars.length]).join("");
}

// ── POST /auth/loop-claim ─────────────────────────────────────────────────────
loopAuth.post("/loop-claim", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const rl = await checkRateLimit(kv, {
    key: `loop-claim:ip:${ip}`, limit: 5, windowSeconds: 3600,
  });
  if (!rl.allowed) return rateLimitResponse(rl.resetAt);

  const body = await c.req.json<{
    username?:     string;
    display_name?: string;
    region?:       string;
    country?:      string;
  }>().catch(() => null);

  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower       = body.username.toLowerCase().trim();
  const displayName = (body.display_name ?? lower).trim().slice(0, 40);

  const { valid, reason } = validateUsername(lower);
  if (!valid) return c.json({ error: reason }, 400);

  // Availability check (case-insensitive, both tables)
  const [usernamesCheck, authUsersCheck] = await Promise.all([
    db.from("usernames").select("username").eq("username", lower).eq("active", true).limit(1),
    db.from("auth_users").select("id").ilike("username", lower).limit(1),
  ]);

  if ((usernamesCheck.data?.length ?? 0) > 0 || (authUsersCheck.data?.length ?? 0) > 0) {
    return c.json({ error: "Username is already taken", available: false }, 409);
  }

  const raldInternalId       = generateRaldInternalId();
  const reservedEmailAddress = `${lower}@rald.me`;
  // Placeholder email: not a real address — user completes identity with phone/email later
  const placeholderEmail     = `${lower}.loop@rald.identity`;
  const now                  = new Date().toISOString();

  // Create the user — this is a real first-class RALD identity
  // Try V2 extended columns first; fall back to base schema if migration not yet applied (42703 = column does not exist)
  let loopInsertResult = await db
    .from("auth_users")
    .insert({
      email:                  placeholderEmail,
      name:                   displayName,
      username:               lower,
      username_set_at:        now,
      rald_internal_id:       raldInternalId,
      rald_id:                raldInternalId,
      role:                   "user",
      email_verified:         false,
      phone_verified:         false,
      reserved_email_address: reservedEmailAddress,
      trust_level:            "basic",
      trust_score:            30,
    })
    .select("id")
    .limit(1);

  if (loopInsertResult.error?.code === "42703" || loopInsertResult.error?.message?.includes("does not exist")) {
    console.warn("[loop-claim] V2 schema pending — retrying with base columns (apply migration to fix)");
    loopInsertResult = await db
      .from("auth_users")
      .insert({
        email:          placeholderEmail,
        name:           displayName,
        role:           "user",
        email_verified: false,
        phone_verified: false,
      })
      .select("id")
      .limit(1);
  }

  const { data: newUsers, error: createErr } = loopInsertResult;

  if (createErr || !newUsers?.length) {
    if (createErr?.code === "23505") {
      return c.json({ error: "Username is already taken", available: false }, 409);
    }
    console.error("[loop-claim] user create error:", createErr?.message);
    return c.json({ error: "Failed to create identity" }, 500);
  }

  const userId = newUsers[0]!.id as string;

  // Register in usernames table (canonical username ownership)
  await db.from("usernames").insert({
    username: lower, user_id: userId, claimed_at: now, active: true,
  }).then(() => null, () => null);

  // Reserve namespace: username@rald.me, username.rald.me, workspace
  await db.rpc("reserve_username_namespace", {
    p_user_id: userId, p_username: lower,
  }).then(() => null, () => null);

  // Username history
  await db.from("username_history").insert({
    user_id: userId, username: lower, action: "claimed",
  }).then(() => null, () => null);

  // Auto-create auth_user_profiles (P1 fix: always exists from day one)
  const profileData: Record<string, unknown> = {
    user_id:      userId,
    display_name: displayName,
    updated_at:   now,
  };
  if (body.country) profileData.country = body.country;
  if (body.region)  profileData.region  = body.region;
  await db.from("auth_user_profiles")
    .upsert(profileData, { onConflict: "user_id" })
    .then(() => null, () => null);

  // Auto-create trust profile (P5 fix)
  await db.from("auth_trust_profiles").upsert({
    user_id:            userId,
    trust_level:        "basic",
    trust_score:        30,
    has_username:       true,
    has_verified_phone: false,
    has_verified_email: false,
    has_reserved_mail:  true,
    has_profile:        true,
    updated_at:         now,
  }, { onConflict: "user_id" }).then(() => null, () => null);

  // Provision Loop product access
  await db.from("auth_product_access").upsert(
    { user_id: userId, product: "loop", role: "user", granted_at: now },
    { onConflict: "user_id,product" }
  ).then(() => null, () => null);

  // Issue 30-day JWT — real session, same as any other RALD auth flow
  const token = await signJwt(
    {
      id:       userId,
      email:    placeholderEmail,
      role:     "user",
      username: lower,
      via:      "loop-claim",
      iss:      "rald.cloud",
    },
    c.env.RALD_JWT_SECRET,
    30 * 86400,
  );

  await db.from("auth_sessions").insert({
    user_id:    userId,
    expires_at: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId,
    action:   "register",
    ip,
    status:   "success",
    metadata: {
      username:         lower,
      rald_internal_id: raldInternalId,
      via:              "loop-claim",
      region:           body.region ?? null,
    },
  });

  c.header("Set-Cookie", buildSessionCookie(token));

  return c.json({
    ok:    true,
    token,
    user: {
      id:                     userId,
      username:               lower,
      display_name:           displayName,
      name:                   displayName,
      role:                   "user",
      rald_internal_id:       raldInternalId,
      reserved_email_address: reservedEmailAddress,
      trust_level:            "basic",
      // Loop-specific identity flag — prompts async verification banner inside Loop
      needs_verification:     true,
      verification_url:       "https://profiles.rald.cloud/verify",
    },
  }, 201);
});

export default loopAuth;
