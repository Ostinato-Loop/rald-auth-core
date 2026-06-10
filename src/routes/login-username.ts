// RALD Auth Core — Username Login (Return-User Path)
// POST /auth/login-username          — find existing user, send OTP
// POST /auth/login-username/complete — verify OTP, issue 30-day session JWT
//
// New users use /auth/register-username.
// The /complete endpoint looks up the verified contact from DB — the frontend
// never handles the raw phone/email, preventing any privacy leakage.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { signJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import { verifySmsOtp, sendSmsOtp, sendLoginEmailOtp, verifyOtpCode, generateNumericOtp, hashOtpCode } from "../lib/otp";
import { writeAuditLog } from "../lib/audit";

const loginUsername = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /auth/login-username ─────────────────────────────────────────────────
loginUsername.post("/", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const body = await c.req.json<{ username?: string; app_id?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim();

  const ipRl = await checkRateLimit(kv, {
    key: `login-username:ip:${ip}`, limit: 10, windowSeconds: 3600,
  });
  if (!ipRl.allowed) return rateLimitResponse(ipRl.resetAt);

  const { data: users } = await db
    .from("auth_users")
    .select("id, username, phone_number, email, phone_verified, email_verified")
    .ilike("username", lower)
    .limit(1);

  const user = users?.[0];
  if (!user) return c.json({ error: "No account found with that username." }, 404);

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
      });
    } catch (err) {
      console.error("[login-username] SMS OTP error:", String(err));
      return c.json({ error: "Failed to send verification code. Try again." }, 502);
    }
  }

  if (email && user.email_verified) {
    try {
      const emailCode = generateNumericOtp(6);
      const codeHash  = await hashOtpCode(emailCode);
      await db.from("auth_otp_codes").insert({
        user_id:    user.id,
        email,
        code_hash:  codeHash,
        purpose:    "email-otp-login",
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
      });
    } catch (err) {
      console.error("[login-username] email OTP error:", String(err));
      return c.json({ error: "Failed to send verification code. Try again." }, 502);
    }
  }

  return c.json({ error: "No verified contact method on file. Contact support." }, 400);
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
    .select("id, username, name, email, role, rald_internal_id")
    .eq("id", body.user_id)
    .limit(1);

  const user = users?.[0];
  if (!user) return c.json({ error: "User not found." }, 404);

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

    const { data: otps } = await db
      .from("auth_otp_codes")
      .select("id, code_hash, expires_at, used")
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

  return c.json({
    ok:    true,
    token,
    user: {
      id:               user.id,
      username:         user.username,
      name:             user.name,
      role:             user.role,
      rald_internal_id: user.rald_internal_id,
    },
  });
});

export default loginUsername;
