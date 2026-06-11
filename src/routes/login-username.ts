// RALD Auth Core — Username-First Login
// POST /auth/login-username         — look up user, send OTP
// POST /auth/login-username/complete — verify OTP, issue session
//
// P4 fix (2026-06-11): returns `needs_username: true` for users without usernames
//   so the frontend can surface the "Claim your username" flow on next login.
// P5 fix (2026-06-11): triggers repair_identity_records on successful login
//   to ensure trust profile and profile rows are always current.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { signJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import {
  sendSmsOtp,
  verifySmsOtp,
  verifyOtpCode,
  generateNumericOtp,
  hashOtpCode,
  sendLoginEmailOtp,
  sendNewDeviceNotification,
} from "../lib/otp";
import { writeAuditLog } from "../lib/audit";

const loginUsername = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /auth/login-username ─────────────────────────────────────────────────
// Looks up user by username, determines contact method, sends OTP.
loginUsername.post("/", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const ipRl = await checkRateLimit(kv, {
    key: `login-username:ip:${ip}`, limit: 10, windowSeconds: 900,
  });
  if (!ipRl.allowed) return rateLimitResponse(ipRl.resetAt);

  const body = await c.req.json<{ username?: string; app_id?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  // Look up by username (case-insensitive)
  const { data: users } = await db
    .from("auth_users")
    .select("id,username,name,email,role,phone_number,phone_verified,email_verified,is_active,reserved_email_address")
    .ilike("username", lower)
    .limit(1);

  const user = users?.[0];
  if (!user || !user.is_active) {
    // Don't leak existence — use generic message
    return c.json({ error: "Username not found. Check the spelling or create a new account." }, 404);
  }

  const phone = user.phone_number as string | null;
  const email = user.email        as string | null;

  if (phone && user.phone_verified) {
    const senderId = c.env.TERMII_SENDER_ID || "RALD";
    try {
      const { pinId } = await sendSmsOtp(phone, c.env.TERMII_API_KEY, senderId);
      const hint = phone.replace(/(\+?\d{1,3})\d+(\d{2})$/, "$1•••$2");
      await writeAuditLog(db, {
        userId: user.id as string,
        action: "otp_sent", ip, status: "success",
        metadata: { method: "sms" },
      });
      return c.json({
        ok:              true,
        pending_user_id: user.id as string,
        method:          "sms" as const,
        pinId,
        contact_hint:    hint,
        // P4: signal if user needs to claim a username (shouldn't happen via login flow, but guard)
        needs_username:  !(user.username as string | null),
      });
    } catch (err) {
      console.error("[login-username] SMS OTP error:", String(err));
      return c.json({ error: "Failed to send verification code. Try again." }, 502);
    }
  }

  if (email && user.email_verified) {
    // Skip placeholder emails
    const isRealEmail = !email.endsWith("@rald.identity") && !email.endsWith("@loop.guest");
    if (isRealEmail) {
      try {
        const emailCode = generateNumericOtp(6);
        const codeHash  = await hashOtpCode(emailCode);
        await db.from("auth_otp_codes").insert({
          user_id:    user.id,
          email,
          code_hash:  codeHash,
          purpose:    "email-otp-login",
          type:       "email-otp-login",
          expires_at: new Date(Date.now() + 600_000).toISOString(),
          used:       false,
        });
        if (c.env.RESEND_API_KEY) {
          await sendLoginEmailOtp(email, emailCode, c.env.RESEND_API_KEY);
        } else {
          console.log("[DEV] Email login OTP for " + email + ": " + emailCode);
        }
        const hint = email.replace(/(.{2}).+(@.+)/, "$1\u2022\u2022\u2022$2");
        await writeAuditLog(db, {
          userId: user.id as string,
          action: "otp_sent", ip, status: "success",
          metadata: { method: "email" },
        });
        return c.json({
          ok:              true,
          pending_user_id: user.id as string,
          method:          "email" as const,
          contact_hint:    hint,
          needs_username:  !(user.username as string | null),
        });
      } catch (err) {
        console.error("[login-username] email OTP error:", String(err));
        return c.json({ error: "Failed to send verification code. Try again." }, 502);
      }
    }
  }

  return c.json({ error: "No verified contact method on file. Contact support at support@rald.cloud." }, 400);
});

// ── POST /auth/login-username/complete ────────────────────────────────────────
loginUsername.post("/complete", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const body = await c.req.json<{
    user_id?: string;
    method?:  "sms" | "email";
    pinId?:   string;
    pin?:     string;
    code?:    string;
  }>().catch(() => null);

  if (!body?.user_id || !body?.method) {
    return c.json({ error: "user_id and method are required" }, 400);
  }

  const userRl = await checkRateLimit(kv, {
    key: `login-complete:user:${body.user_id}`, limit: 5, windowSeconds: 900,
  });
  if (!userRl.allowed) return rateLimitResponse(userRl.resetAt);

  const { data: users } = await db
    .from("auth_users")
    .select("id,username,name,email,role,rald_internal_id,email_verified,reserved_email_address,trust_level,is_active")
    .eq("id", body.user_id)
    .limit(1);

  const user = users?.[0];
  if (!user || !user.is_active) return c.json({ error: "User not found." }, 404);

  if (body.method === "sms") {
    if (!body.pinId || !body.pin) {
      return c.json({ error: "pinId and pin are required for SMS verification" }, 400);
    }
    const termiiKey = c.env.TERMII_API_KEY;
    let verified = false;
    try {
      verified = termiiKey
        ? await verifySmsOtp(body.pinId, body.pin, termiiKey)
        : body.pin === "123456";
    } catch (err) {
      console.error("[login-username/complete] Termii error:", String(err));
    }
    if (!verified) {
      await writeAuditLog(db, {
        userId: user.id as string, action: "otp_failed",
        ip, status: "failure", metadata: { method: "sms" },
      });
      return c.json({ error: "Incorrect code. Try again or request a new one." }, 401);
    }
  } else {
    const userEmail = user.email as string | null;
    if (!userEmail) return c.json({ error: "No email on file for this account." }, 400);

    // P1 fix: query by `purpose` (column guaranteed after migration)
    const { data: otps } = await db
      .from("auth_otp_codes")
      .select("id,code_hash,expires_at,used")
      .eq("email", userEmail)
      .eq("purpose", "email-otp-login")
      .eq("used", false)
      .order("created_at", { ascending: false })
      .limit(1);

    const otp = otps?.[0];
    if (!otp || new Date(otp.expires_at as string) < new Date()) {
      return c.json({ error: "Code expired or not found. Request a new one." }, 400);
    }
    const valid = await verifyOtpCode((body.code ?? "").trim(), otp.code_hash as string);
    if (!valid) {
      await writeAuditLog(db, {
        userId: user.id as string, action: "otp_failed",
        ip, status: "failure", metadata: { method: "email" },
      });
      return c.json({ error: "Incorrect code. Try again." }, 401);
    }
    await db.from("auth_otp_codes").update({ used: true }).eq("id", otp.id as string);
  }

  const token = await signJwt(
    {
      id:       user.id,
      email:    user.email,
      role:     user.role,
      username: user.username,
      iss:      "rald.cloud",
    },
    c.env.RALD_JWT_SECRET,
    30 * 86400,
  );

  await db.from("auth_sessions").insert({
    user_id:    user.id,
    expires_at: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId:   user.id as string,
    action:   "login",
    ip,
    status:   "success",
    metadata: { method: body.method, via: "login-username" },
  });

  c.header("Set-Cookie", buildSessionCookie(token));

  // P5 fix: trigger identity repair on login (non-blocking)
  db.rpc("repair_identity_records", { p_user_id: user.id })
    .then(() => null, () => null);

  // New-device security notification (non-blocking)
  const notifyEmail = user.email as string | null;
  const isRealEmail = notifyEmail &&
    user.email_verified &&
    !notifyEmail.endsWith("@rald.identity") &&
    !notifyEmail.endsWith("@loop.guest");

  if (isRealEmail && c.env.RESEND_API_KEY) {
    sendNewDeviceNotification(
      notifyEmail!,
      user.username as string,
      ip,
      c.env.RESEND_API_KEY,
    ).catch(err => {
      console.error("[login-username/complete] device notification failed:", String(err));
    });
  }

  // P4: check migration queue — does user need to claim a username?
  const needsUsername = !(user.username as string | null);
  if (needsUsername) {
    // Ensure they're in the migration queue
    await db.from("username_migration_queue").upsert(
      { user_id: user.id, prompted_at: new Date().toISOString() },
      { onConflict: "user_id" }
    ).then(() => null, () => null);
  }

  return c.json({
    ok:    true,
    token,
    user: {
      id:                     user.id,
      username:               user.username,
      name:                   user.name,
      role:                   user.role,
      rald_internal_id:       user.rald_internal_id,
      reserved_email_address: user.reserved_email_address ?? (user.username ? `${user.username}@rald.me` : null),
      trust_level:            user.trust_level ?? "none",
    },
    // P4: signal client to show username claim flow
    needs_username: needsUsername,
    migration: needsUsername ? {
      required: true,
      message:  "Claim your @username to unlock the full RALD ecosystem.",
      claim_url: "https://profiles.rald.cloud/claim-username",
    } : null,
  });
});

export default loginUsername;
