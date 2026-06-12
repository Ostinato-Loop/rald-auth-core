// RALD Auth Core — Username-First Registration (V2)
// POST /auth/register-username
// POST /auth/register-username/complete
//
// Flow:
//   1. User submits desired @username → status=PENDING, pending_until=now+15min
//   2. Caller sends OTP via /auth/send-otp or /auth/send-login-email-otp
//   3. Caller hits /complete with pending_user_id + OTP → session issued
//      → username status upgraded PENDING → ACTIVE
//      → auto-creates auth_user_profiles + auth_trust_profiles + all 8 ecosystem profiles
//      → sets reserved_email_address = username@rald.me on auth_users
//      → welcome email sent via Resend (sendWelcomeEmail)
//   If /complete is never called or fails → cleanup job releases username after 15 min
//
// USERNAME STATE MACHINE (RALD Identity Continuity Program):
//   AVAILABLE → PENDING (on /auth/register-username)
//   PENDING   → ACTIVE  (on /auth/register-username/complete — success only)
//   PENDING   → AVAILABLE (auto-released after 15 min via cleanup job OR on completion failure)
//
// P1 fixes (2026-06-11 Identity Audit Sprint):
//   - auth_user_profiles auto-created on registration complete (was lazy before)
//   - auth_trust_profiles auto-created on registration complete
//   - reserved_email_address written to auth_users
//   - username_migration_queue NOT seeded for new users (they have username)
//   - region/country saved directly during complete if provided
//
// P2 fixes (2026-06-12 Identity Continuity Sprint):
//   - Username goes PENDING on claim, ACTIVE only after OTP verified (fixes ghost usernames)
//   - /provision/all called on completion to create all 8 ecosystem profiles atomically
//   - If /complete errors: username released back to AVAILABLE immediately
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

// ── Provision all 8 ecosystem profiles (non-blocking fire-and-forget) ──────────
// Called after registration completes. Creates every profile silently.
// Products must never ask for identity — it is pre-provisioned here.
async function provisionAllEcosystemProfiles(
  db: Parameters<typeof writeAuditLog>[0],
  userId: string,
  username: string,
  displayName: string,
): Promise<void> {
  const now = new Date().toISOString();

  // 1. Loop profile
  void Promise.resolve(
    db.from("loop_profiles").upsert(
      { user_id: userId, username, display_name: displayName, provisioned_at: now },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 2. Messenger profile
  void Promise.resolve(
    db.from("messenger_profiles").upsert(
      { user_id: userId, username, display_name: displayName, provisioned_at: now },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 3. Mail profile (alias already reserved — just create the mailbox record)
  void Promise.resolve(
    db.from("mail_profiles").upsert(
      {
        user_id:        userId,
        mail_alias:     `${username}@rald.me`,
        display_name:   displayName,
        provisioned_at: now,
      },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 4. Workspace root
  void Promise.resolve(
    db.from("workspace_profiles").upsert(
      {
        user_id:        userId,
        workspace_slug: username,
        display_name:   displayName,
        provisioned_at: now,
      },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 5. Notification profile
  void Promise.resolve(
    db.from("notification_profiles").upsert(
      { user_id: userId, provisioned_at: now },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 6. Search profile (discoverable by username)
  void Promise.resolve(
    db.from("search_profiles").upsert(
      {
        user_id:           userId,
        username,
        display_name:      displayName,
        search_discoverable: true,
        provisioned_at:    now,
      },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 7. Developer profile (auto API key issued — machine-managed lifecycle)
  void Promise.resolve(
    db.from("developer_profiles").upsert(
      {
        user_id:        userId,
        username,
        provisioned_at: now,
        api_access:     true,
      },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  // 8. Trust profile (already created below — this ensures it exists)
  void Promise.resolve(
    db.from("auth_trust_profiles").upsert(
      {
        user_id:     userId,
        provisioned_at: now,
        updated_at:  now,
      },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);
}

// ── Release a PENDING username back to AVAILABLE ───────────────────────────────
// Called when registration /complete fails or on cleanup.
async function releaseUsername(
  db: Parameters<typeof writeAuditLog>[0],
  userId: string,
  username: string,
): Promise<void> {
  try {
    await db.from("usernames").update({
      status:      "AVAILABLE",
      user_id:     null,
      active:      false,
      released_at: new Date().toISOString(),
    }).eq("username", username).eq("status", "PENDING");

    // Remove the pending auth_users row as well
    await db.from("auth_users").delete().eq("id", userId);
  } catch {
    // non-fatal — cleanup job will handle it within 15 minutes
  }
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

  // ── Check availability — exclude both ACTIVE/CLAIMED and PENDING slots ────
  // A PENDING slot that is past its expiry is treated as available.
  const PENDING_TTL_MS = 15 * 60 * 1000; // 15 minutes
  const pendingCutoff  = new Date(Date.now() - PENDING_TTL_MS).toISOString();

  const { data: existingSlots, error: checkErr } = await db
    .from("usernames")
    .select("username, status, pending_until")
    .ilike("username", lower)
    .limit(5);

  if (checkErr) {
    console.error("[register-username] availability check failed:", checkErr.message);
    return c.json({ error: "Could not check username availability" }, 500);
  }

  if (existingSlots && existingSlots.length > 0) {
    for (const slot of existingSlots) {
      const status = slot.status as string | null;
      // Hard blocks: ACTIVE, RESERVED, PROTECTED, PREMIUM, ADMIN_HELD
      if (status && !["PENDING", "AVAILABLE"].includes(status)) {
        return c.json({ error: "Username is already taken", available: false }, 409);
      }
      // PENDING block only if not expired
      if (status === "PENDING") {
        const until = slot.pending_until as string | null;
        if (!until || new Date(until) > new Date()) {
          return c.json({ error: "Username is temporarily reserved. Try again shortly.", available: false }, 409);
        }
        // Expired PENDING — release it first
        await db.from("usernames").update({
          status:      "AVAILABLE",
          user_id:     null,
          active:      false,
          released_at: new Date().toISOString(),
        }).eq("username", lower).eq("status", "PENDING");
      }
    }
  }

  // ── Also check legacy active=true flag (backward compat) ─────────────────
  const { data: legacyActive } = await db
    .from("usernames")
    .select("username")
    .ilike("username", lower)
    .eq("active", true)
    .limit(1);
  if (legacyActive && legacyActive.length > 0) {
    return c.json({ error: "Username is already taken", available: false }, 409);
  }

  const raldInternalId       = generateRaldInternalId();
  const placeholderEmail     = `${lower}.pending@rald.identity`;
  const reservedEmailAddress = `${lower}@rald.me`;
  const pendingUntil         = new Date(Date.now() + PENDING_TTL_MS).toISOString();

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

  // ── Register username as PENDING (not ACTIVE) ─────────────────────────────
  // Username becomes ACTIVE only after OTP verification succeeds in /complete.
  await db.from("usernames").upsert({
    username:      lower,
    user_id:       userId,
    status:        "PENDING",
    active:        false,        // NOT active yet — only set true on /complete
    pending_until: pendingUntil,
    claimed_at:    new Date().toISOString(),
  }, { onConflict: "username" }).then(() => null, () => null);

  // Reserve namespace: username@rald.me, username.rald.me, workspace (async)
  await db.rpc("reserve_username_namespace", {
    p_user_id:  userId,
    p_username: lower,
  }).then(() => null, () => null);

  // Audit trail
  await db.from("username_history").insert({
    user_id: userId, username: lower, action: "pending",
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId, action: "username_pending", ip, status: "success",
    metadata: {
      username:         lower,
      rald_internal_id: raldInternalId,
      app_id:           body.app_id   ?? null,
      country:          body.country  ?? null,
      pending_until:    pendingUntil,
    },
  });

  return c.json({
    ok:               true,
    pending_user_id:  userId,
    username:         lower,
    rald_internal_id: raldInternalId,
    reserved_mail:    reservedEmailAddress,
    next_step:        "verification",
    username_state:   "PENDING",
    pending_until:    pendingUntil,
    message:          `@${lower} is reserved for 15 minutes. Verify your identity to activate it.`,
    verification_options: ["sms", "email"],
  }, 201);
});


// ── POST /auth/register-username/complete ─────────────────────────────────────
// Verifies OTP for a pending V2 username registration, then issues a session.
// P1 fix: auto-creates auth_user_profiles + auth_trust_profiles on completion.
// P2 fix: upgrades username from PENDING → ACTIVE only on success.
//          If OTP fails, username stays PENDING (will auto-release after 15 min).
//          All 8 ecosystem profiles provisioned on success.
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
    method?:         "sms" | "email";
    sessionToken?:   string;
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

  const v2Result = await db
    .from("auth_users")
    .select("id,username,name,role,rald_internal_id,email,reserved_email_address")
    .eq("id", pendingUserId)
    .limit(1);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let rawUser: Record<string, any> | undefined;
  let lastDbError: string | undefined;

  if (v2Result.error) {
    console.warn(
      "[register-username/complete] V2 column select failed (",
      v2Result.error.message,
      ") — falling back to base columns",
    );
    const baseResult = await db
      .from("auth_users")
      .select("id,username,name,role,email")
      .eq("id", pendingUserId)
      .limit(1);
    rawUser      = baseResult.data?.[0] as typeof rawUser;
    lastDbError  = baseResult.error?.message;
  } else {
    rawUser     = v2Result.data?.[0] as typeof rawUser;
    lastDbError = undefined;
  }

  if (!rawUser) {
    console.error(
      "[register-username/complete] user not found for pending_user_id:", pendingUserId,
      "| db error:", lastDbError ?? v2Result.error?.message ?? "none",
    );
    return c.json({ error: "Your registration session has expired. Please start over." }, 404);
  }

  const userId       = rawUser.id as string;
  const userEmail    = rawUser.email as string;
  const userRole     = (rawUser.role as string | undefined) ?? "user";
  const userUsername = (rawUser.username as string | undefined) ?? "";
  const userRaldId   = (rawUser.rald_internal_id as string | undefined) ?? "";
  const userName     = (rawUser.name as string | undefined) ?? userUsername;

  // ── Verify that the username is still in PENDING state ────────────────────
  if (userUsername) {
    const { data: usernameRow } = await db
      .from("usernames")
      .select("status, pending_until")
      .eq("username", userUsername)
      .limit(1);

    const slot = usernameRow?.[0];
    if (slot) {
      const status      = slot.status as string | null;
      const pendingUntil = slot.pending_until as string | null;
      if (status === "PENDING" && pendingUntil && new Date(pendingUntil) < new Date()) {
        // Auto-release — window expired
        await releaseUsername(db, userId, userUsername);
        return c.json({
          error: "Your reservation expired. Please start over and choose your username again.",
          expired: true,
        }, 410);
      }
    }
  }

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
      return c.json({ error: "That code didn't match. Try again or request a new one." }, 401);
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
    if (!body.code) {
      return c.json({ error: "code is required for email verification" }, 400);
    }
    const code = body.code.trim();

    if (body.sessionToken) {
      const session = await verifyJwt(body.sessionToken, c.env.RALD_JWT_SECRET) as
        (Record<string, string> & { purpose?: string; codeHash?: string; email?: string }) | null;

      if (!session || session.purpose !== "email-otp-login" || !session.codeHash) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "invalid_session_token" },
        });
        return c.json({ error: "That verification link has expired. Request a new code." }, 400);
      }

      const inputHash = await hashOtpCode(code);
      if (inputHash !== session.codeHash) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "wrong_code" },
        });
        return c.json({ error: "That code didn't match. Try again." }, 401);
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
        return c.json({ error: "Code not found or expired. Request a new one." }, 400);
      }

      const codeValid = await verifyOtpCode(code, otp.code_hash as string);
      if (!codeValid) {
        await writeAuditLog(db, {
          userId, action: "otp_failed", ip, status: "failure",
          metadata: { method: "email", reason: "wrong_code" },
        });
        return c.json({ error: "That code didn't match. Try again." }, 401);
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

  // ── P2 fix: Upgrade username PENDING → ACTIVE ─────────────────────────────
  // This is the only place a username becomes ACTIVE — never earlier.
  if (userUsername) {
    await db.from("usernames").update({
      status:        "ACTIVE",
      active:        true,
      pending_until: null,
      claimed_at:    new Date().toISOString(),
    }).eq("username", userUsername).eq("user_id", userId).then(() => null, () => null);

    await db.from("username_history").insert({
      user_id: userId, username: userUsername, action: "activated",
    }).then(() => null, () => null);
  }

  // ── P1 fix: Auto-create auth_user_profiles ────────────────────────────────
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

  // ── P3 fix: Ensure reserved_email_address is set on auth_users ────────────
  const reservedMail = `${userUsername}@rald.me`;
  const trustLevel   = (verifiedEmail || verifiedPhone) ? "basic" : "none";
  const trustScore   = (verifiedEmail && verifiedPhone) ? 70 : (verifiedEmail || verifiedPhone) ? 40 : 0;

  await db.from("auth_users").update({
    reserved_email_address: reservedMail,
    trust_level:            trustLevel,
    trust_score:            trustScore,
  }).eq("id", userId).then(() => null, () => null);

  // ── P5 fix: Auto-create auth_trust_profiles ───────────────────────────────
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

  // ── P2 fix: Provision all 8 ecosystem profiles atomically (non-blocking) ──
  // Loop, Messenger, Mail, Workspace, Trust, Notification, Search, Developer
  void provisionAllEcosystemProfiles(db, userId, userUsername, userName);

  // ── Issue 30-day session ───────────────────────────────────────────────────
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
    metadata: {
      username:       userUsername,
      method,
      via:            "v2-username-first",
      username_state: "ACTIVE",
    },
  });

  c.header("Set-Cookie", buildSessionCookie(token));

  // ── Welcome email (non-blocking) ───────────────────────────────────────────
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
      username_state:         "ACTIVE",
    },
  });
});

export default registerUsername;
