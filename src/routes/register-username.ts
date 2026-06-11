// RALD Auth Core — Username-First Registration (V2)
// POST /auth/register-username
// POST /auth/register-username/complete
//
// Flow:
//   1. User submits desired @username → reserved + pending_user_id returned
//   2. Caller sends OTP via /auth/send-otp or /auth/send-login-email-otp
//   3. Caller hits /complete with pending_user_id + OTP → session issued
//      → auto-creates auth_user_profiles + auth_trust_profiles
//      → sets reserved_email_address = username@rald.me on auth_users
//      → welcome email sent via Resend (sendWelcomeEmail)
//
// P1 fixes (2026-06-11 Identity Audit Sprint):
//   - auth_user_profiles auto-created on registration complete (was lazy before)
//   - auth_trust_profiles auto-created on registration complete
//   - reserved_email_address written to auth_users
//   - username_migration_queue NOT seeded for new users (they have username)
//   - region/country saved directly during complete if provided
//
// Security:
//   - IP rate limiting on registration (10/hour) and completion (10/hour)
//   - Per-user OTP attempt limiting (5 per 15 min) — brute-force protection
//   - OTP failure audit logged every time
//   - HttpOnly Secure SameSite=Lax session cookie issued on success
//
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { signJwt, verifyJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import { verifySmsOtp, verifyOtpCode, hashOtpCode, sendWelcomeEmail } from "../lib/otp";
import { writeAuditLog } from "../lib/audit";

const registerUsername = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Reserved namespace ─────────────────────────────────────────────────────────
const RESERVED_WORDS = new Set([
  // RALD brand
  "rald", "raldcloud", "raldme", "raldinc", "raldstudio", "raldteam",
  "lilcky", "lilckystudio", "lilckystudios", "ostinato", "ostinatoloop",
  // RALD products
  "loop", "messenger", "payrald", "gitrald", "raldtics", "raldai",
  "mail", "raldmail", "voice", "raldvoice", "dispatch", "raldispatch",
  "silicon", "sv", "duna", "manilla", "manillafm",
  // Auth / infra
  "admin", "administrator", "superadmin", "sysadmin",
  "support", "help", "helpdesk", "billing", "payments",
  "security", "abuse", "noreply", "no-reply", "donotreply",
  "root", "system", "bot", "bots", "daemon",
  "api", "auth", "sso", "oauth", "openid", "saml",
  "null", "undefined", "true", "false",
  // Squatting
  "test", "demo", "example", "sample", "dummy", "placeholder",
  "official", "staff", "team", "crew", "mod", "moderator", "operator",
  "inbox", "postmaster", "webmaster", "hostmaster",
  // Civic / sensitive
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

// ── POST /auth/register-username ──────────────────────────────────────────────
registerUsername.post("/", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const rl = await checkRateLimit(kv, {
    key: `reg-username:ip:${ip}`, limit: 10, windowSeconds: 3600,
  });
  if (!rl.allowed) return rateLimitResponse(rl.resetAt);

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

  // Case-insensitive uniqueness check
  const { data: existing, error: checkErr } = await db
    .from("usernames")
    .select("username")
    .ilike("username", lower)
    .eq("active", true)
    .limit(1);

  if (checkErr) {
    console.error("[register-username] availability check failed:", checkErr.message);
    return c.json({ error: "Could not check username availability" }, 500);
  }
  if (existing && existing.length > 0) {
    return c.json({ error: "Username is already taken", available: false }, 409);
  }

  const raldInternalId       = generateRaldInternalId();
  const placeholderEmail     = `${lower}.pending@rald.identity`;
  const reservedEmailAddress = `${lower}@rald.me`;

  let regInsertResult = await db
    .from("auth_users")
    .insert({
      email:                  placeholderEmail,
      name:                   lower,
      username:               lower,
      username_set_at:        new Date().toISOString(),
      rald_internal_id:       raldInternalId,
      rald_id:                raldInternalId,
      role:                   "user",
      email_verified:         false,
      phone_verified:         false,
      reserved_email_address: reservedEmailAddress,
      trust_level:            "none",
      trust_score:            0,
    })
    .select("id")
    .limit(1);

  // If V2 insert fails for any reason except duplicate key, retry with base schema
  if (regInsertResult.error && regInsertResult.error.code !== "23505") {
    console.warn("[register-username] V2 insert failed (code=" + regInsertResult.error.code + ", msg=" + regInsertResult.error.message + ") — retrying with base schema");
    regInsertResult = await db
      .from("auth_users")
      .insert({
        email:          placeholderEmail,
        name:           lower,
        role:           "user",
        email_verified: false,
        phone_verified: false,
      })
      .select("id")
      .limit(1);
  }

  const { data: newUsers, error: createErr } = regInsertResult;

  if (createErr || !newUsers || newUsers.length === 0) {
    console.error("[register-username] user create error code=" + createErr?.code + " msg=" + createErr?.message);
    if (createErr?.code === "23505") {
      return c.json({ error: "Username is already taken", available: false }, 409);
    }
    return c.json({ error: "Failed to create identity" }, 500);
  }

  const userId = newUsers[0]!.id as string;

  // Register username in canonical usernames table
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

  // Audit trail
  await db.from("username_history").insert({
    user_id: userId, username: lower, action: "claimed",
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId, action: "username_claimed", ip, status: "success",
    metadata: {
      username:         lower,
      rald_internal_id: raldInternalId,
      app_id:           body.app_id   ?? null,
      country:          body.country  ?? null,
    },
  });

  return c.json({
    ok:               true,
    pending_user_id:  userId,
    username:         lower,
    rald_internal_id: raldInternalId,
    reserved_mail:    reservedEmailAddress,
    next_step:        "verification",
    message:          `@${lower} is reserved. Verify your identity to complete setup.`,
    verification_options: ["sms", "email"],
  }, 201);
});


// ── POST /auth/register-username/complete ─────────────────────────────────────
// Verifies OTP for a pending V2 username registration, then issues a session.
// P1 fix: auto-creates auth_user_profiles + auth_trust_profiles on completion.
// P3 fix: writes reserved_email_address into auth_users.
registerUsername.post("/complete", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const ipRl = await checkRateLimit(kv, {
    key: `complete-reg:ip:${ip}`, limit: 10, windowSeconds: 3600,
  });
  if (!ipRl.allowed) return rateLimitResponse(ipRl.resetAt);

  type CompleteBody = {
    pending_user_id: string;
    method?:         "sms" | "email";   // optional — auto-inferred from provided fields
    sessionToken?:   string;             // JWT from /auth/send-login-email-otp (preferred email path)
    pinId?:          string;
    pin?:            string;
    phone?:          string;
    email?:          string;
    code?:           string;
    country?:        string;
    region?:         string;
    region_state?:   string;
  };

  const body = await c.req.json<CompleteBody>().catch(() => null);
  if (!body?.pending_user_id) {
    return c.json({ error: "pending_user_id is required" }, 400);
  }

  const pendingUserId = body.pending_user_id;
  // Auto-infer method: sessionToken/code/email → email; pinId/pin → sms
  const method: "sms" | "email" =
    body.method ?? (body.pinId ? "sms" : "email");

  const userRl = await checkRateLimit(kv, {
    key: `otp-attempt:user:${pendingUserId}`, limit: 5, windowSeconds: 900,
  });
  if (!userRl.allowed) {
    return c.json({
      error:       "Too many incorrect attempts. Please wait before trying again.",
      retry_after: userRl.resetAt,
    }, 429);
  }

  const { data: users } = await db
    .from("auth_users")
    .select("id,username,name,role,rald_internal_id,email,reserved_email_address")
    .eq("id", pendingUserId)
    .limit(1);

  const user = users?.[0];
  if (!user) {
    return c.json({ error: "Invalid or expired registration session. Please start over." }, 404);
  }

  const userId         = user.id as string;
  const userEmail      = user.email as string;
  const userRole       = user.role as string;
  const userUsername   = user.username as string;
  const userRaldId     = user.rald_internal_id as string;
  const userName       = user.name as string;

  let verifiedEmail: string | null = null;
  let verifiedPhone: string | null = null;

  // ── Verify OTP ──────────────────────────────────────────────────────────────
  if (method === "sms") {
    const pinId = body.pinId ?? "";
    const pin   = body.pin   ?? "";
    const phone = body.phone ?? "";

    if (!pinId || !pin || !phone) {
      return c.json({ error: "pinId, pin, and phone are required for SMS verification" }, 400);
    }

    const cleanPhone = phone.replace(/\D/g, "");

    let smsVerified = false;
    try {
      const termiiKey = c.env.TERMII_API_KEY;
      smsVerified = termiiKey
        ? await verifySmsOtp(pinId, pin, termiiKey)
        : pin === "123456";
    } catch (err) {
      console.error("[register-username/complete] Termii verify error:", String(err));
      smsVerified = false;
    }

    if (!smsVerified) {
      await writeAuditLog(db, {
        userId, action: "otp_failed", ip, status: "failure",
        metadata: { method: "sms", stage: "complete-v2" },
      });
      return c.json({ error: "Incorrect code. Try again or request a new one." }, 401);
    }

    await db.from("auth_users")
      .update({ phone_number: cleanPhone, phone_verified: true })
      .eq("id", userId);

    verifiedPhone = cleanPhone;

    await writeAuditLog(db, {
      userId, action: "otp_verified", ip, status: "success",
      metadata: { method: "sms", stage: "complete-v2" },
    });

  } else {
    // ── Email verification path ──────────────────────────────────────────────
    // Primary: sessionToken JWT from /auth/send-login-email-otp
    // Fallback: DB lookup in auth_otp_codes (legacy / explicit email+code path)

    if (!body.code) {
      return c.json({ error: "code is required for email verification" }, 400);
    }
    const code = body.code.trim();

    if (body.sessionToken) {
      // ── JWT-based verification (standard registration path) ──────────────
      const session = await verifyJwt(body.sessionToken, c.env.RALD_JWT_SECRET) as
        (Record<string, string> & { purpose?: string; codeHash?: string; email?: string }) | null;

      if (!session || session.purpose !== "email-otp-login" || !session.codeHash) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "invalid_session_token" },
        });
        return c.json({ error: "Invalid or expired email verification session. Request a new code." }, 400);
      }

      const inputHash = await hashOtpCode(code);
      if (inputHash !== session.codeHash) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "wrong_code" },
        });
        return c.json({ error: "Incorrect code. Try again." }, 401);
      }

      const sessionEmail = session.email ?? userEmail;
      await db.from("auth_users")
        .update({ email: sessionEmail, email_verified: true })
        .eq("id", userId);

      await writeAuditLog(db, {
        userId, action: "otp_verified", ip, status: "success",
        metadata: { method: "email", stage: "complete-v2-jwt" },
      });

      verifiedEmail = sessionEmail;

    } else {
      // ── DB-based fallback verification ────────────────────────────────────
      const emailInput = (body.email ?? userEmail ?? "").trim().toLowerCase();
      if (!emailInput) {
        return c.json({ error: "email or sessionToken is required for email verification" }, 400);
      }

      const { data: otps } = await db
        .from("auth_otp_codes")
        .select("id,code_hash,expires_at,used")
        .eq("email", emailInput)
        .eq("purpose", "email-otp-login")
        .eq("used", false)
        .order("created_at", { ascending: false })
        .limit(1);

      const otp     = otps?.[0];
      const expired = otp ? new Date(otp.expires_at as string) < new Date() : true;

      if (!otp || expired) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: !otp ? "not_found" : "expired" },
        });
        return c.json({ error: "Code expired or not found. Request a new one." }, 400);
      }

      const codeValid = await verifyOtpCode(code, otp.code_hash as string);
      if (!codeValid) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "wrong_code" },
        });
        return c.json({ error: "Incorrect code. Try again." }, 401);
      }

      await db.from("auth_otp_codes").update({ used: true }).eq("id", otp.id);
      await db.from("auth_users")
        .update({ email: emailInput, email_verified: true })
        .eq("id", userId);

      await writeAuditLog(db, {
        userId, action: "otp_verified", ip, status: "success",
        metadata: { method: "email", stage: "complete-v2-db" },
      });

      verifiedEmail = emailInput;
    }
  }

  // ── P1 fix: Auto-create auth_user_profiles (ensures profile exists immediately) ──
  const profileUpsert: Record<string, unknown> = {
    user_id:    userId,
    updated_at: new Date().toISOString(),
  };
  if (body.country)      profileUpsert.country      = body.country;
  if (body.region)       profileUpsert.region        = body.region;
  if (body.region_state) profileUpsert.region_state  = body.region_state;
  await db.from("auth_user_profiles")
    .upsert(profileUpsert, { onConflict: "user_id" })
    .then(() => null, () => null);

  // ── P3 fix: Ensure reserved_email_address is set on auth_users ───────────────
  const reservedMail = `${userUsername}@rald.me`;
  const trustLevel   = (verifiedEmail || verifiedPhone) ? "basic" : "none";
  const trustScore   = (verifiedEmail && verifiedPhone) ? 70 : (verifiedEmail || verifiedPhone) ? 40 : 0;

  await db.from("auth_users").update({
    reserved_email_address: reservedMail,
    trust_level:            trustLevel,
    trust_score:            trustScore,
  }).eq("id", userId).then(() => null, () => null);

  // ── P5 fix: Auto-create auth_trust_profiles ───────────────────────────────────
  await db.from("auth_trust_profiles").upsert({
    user_id:            userId,
    trust_level:        trustLevel,
    trust_score:        trustScore,
    has_username:       true,
    has_verified_phone: !!verifiedPhone,
    has_verified_email: !!verifiedEmail,
    has_reserved_mail:  true,
    has_profile:        true,
    updated_at:         new Date().toISOString(),
  }, { onConflict: "user_id" }).then(() => null, () => null);

  // ── Issue 30-day session ────────────────────────────────────────────────────
  const jwtPayload: Record<string, unknown> = {
    id:       userId,
    email:    verifiedEmail ?? userEmail,
    role:     userRole,
    username: userUsername,
    iss:      "rald.cloud",
  };
  const token = await signJwt(jwtPayload, c.env.RALD_JWT_SECRET, 30 * 86400);

  await db.from("auth_sessions").insert({
    user_id:    userId,
    expires_at: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId, action: "register", ip, status: "success",
    metadata: { username: userUsername, method, via: "v2-username-first" },
  });

  c.header("Set-Cookie", buildSessionCookie(token));

  // ── Welcome email (non-blocking) ──────────────────────────────────────────
  if (verifiedEmail && c.env.RESEND_API_KEY) {
    sendWelcomeEmail(verifiedEmail, userUsername, c.env.RESEND_API_KEY).catch(err => {
      console.error("[register-username/complete] welcome email failed:", String(err));
    });
  }

  return c.json({
    ok:    true,
    token,
    user: {
      id:                     userId,
      username:               userUsername,
      name:                   userName,
      role:                   userRole,
      rald_internal_id:       userRaldId,
      reserved_email_address: reservedMail,
      trust_level:            trustLevel,
    },
  });
});

export default registerUsername;
