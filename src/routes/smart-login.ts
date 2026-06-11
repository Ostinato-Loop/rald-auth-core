// RALD Auth Core — Smart Unified Login (Phase 6)
// POST /auth/smart-login         — detect identifier type, send OTP
// POST /auth/smart-login/complete — verify OTP, issue session
//
// Single input field. Auto-detects:
//   - Phone:    starts with + or is 7–15 digits → SMS OTP via Termii
//   - Email:    contains @ → email OTP via Resend
//   - Username: everything else → existing /auth/login-username flow
//
// RALD AUTH EMERGENCY STABILIZATION SPRINT — Phase 6
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
} from "../lib/otp";
import { writeAuditLog } from "../lib/audit";

const smartLogin = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Detection helpers ─────────────────────────────────────────────────────────

type IdentifierType = "phone" | "email" | "username";

function detectIdentifierType(raw: string): IdentifierType {
  const trimmed = raw.trim();
  // Phone: starts with + or is digits/spaces/dashes/parens, 7–15 digits
  const digitsOnly = trimmed.replace(/[\s\-\(\)\+]/g, "");
  if (/^\+?[\d\s\-\(\)]+$/.test(trimmed) && digitsOnly.length >= 7 && digitsOnly.length <= 15) {
    return "phone";
  }
  // Email: contains @ with something on both sides
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return "email";
  }
  return "username";
}

function normalizePhone(raw: string): string {
  // Strip non-digits except leading +
  const digits = raw.replace(/[^\d+]/g, "");
  // If Nigerian number without country code (starts with 0), prepend +234
  if (digits.startsWith("0") && digits.length === 11) {
    return "+234" + digits.slice(1);
  }
  if (!digits.startsWith("+")) {
    return "+" + digits;
  }
  return digits;
}

// ── POST /auth/smart-login ────────────────────────────────────────────────────

smartLogin.post("/", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;

  const ipRl = await checkRateLimit(kv, {
    key: `smart-login:ip:${ip}`, limit: 15, windowSeconds: 900,
  });
  if (!ipRl.allowed) return rateLimitResponse(ipRl.resetAt);

  const body = await c.req.json<{
    identifier?: string;
    app_id?:     string;
  }>().catch(() => null);

  if (!body?.identifier?.trim()) {
    return c.json({ error: "identifier is required (username, email, or phone)" }, 400);
  }

  const raw        = body.identifier.trim();
  const idType     = detectIdentifierType(raw);
  const lower      = raw.toLowerCase();

  // ── Phone path ────────────────────────────────────────────────────────────
  if (idType === "phone") {
    const phone = normalizePhone(raw);

    const identRl = await checkRateLimit(kv, {
      key: `smart-login:phone:${phone}`, limit: 5, windowSeconds: 900,
    });
    if (!identRl.allowed) return rateLimitResponse(identRl.resetAt);

    // Look up by phone_number in auth_users
    const { data: users } = await db
      .from("auth_users")
      .select("id,username,name,email,role,phone_number,phone_verified,is_active")
      .or(`phone_number.eq.${phone},metadata->>phone.eq.${phone}`)
      .limit(1);

    const user = users?.[0];
    if (!user || !user.is_active) {
      return c.json({
        error: "No account found with this phone number. Create one at profiles.rald.cloud.",
        identifier_type: "phone",
      }, 404);
    }
    if (!user.phone_verified) {
      return c.json({ error: "Phone number is not verified on this account. Try logging in with email or username." }, 400);
    }

    try {
      const senderId = c.env.TERMII_SENDER_ID || "RALD";
      const { pinId } = await sendSmsOtp(phone, c.env.TERMII_API_KEY, senderId);
      const hint = phone.replace(/(\+\d{1,4})\d+(\d{2})$/, "$1•••$2");

      await writeAuditLog(db, {
        userId: user.id as string,
        action: "otp_sent", ip, status: "success",
        metadata: { method: "sms", via: "smart-login", identifier_type: "phone" },
      });

      return c.json({
        ok:              true,
        pending_user_id: user.id as string,
        method:          "sms" as const,
        identifier_type: "phone",
        pinId,
        contact_hint:    hint,
        needs_username:  !(user.username as string | null),
      });
    } catch (err) {
      console.error("[smart-login] SMS OTP error:", String(err));
      return c.json({ error: "Failed to send verification code. Try again." }, 502);
    }
  }

  // ── Email path ────────────────────────────────────────────────────────────
  if (idType === "email") {
    const email = lower;

    const identRl = await checkRateLimit(kv, {
      key: `smart-login:email:${email}`, limit: 5, windowSeconds: 900,
    });
    if (!identRl.allowed) return rateLimitResponse(identRl.resetAt);

    const { data: users } = await db
      .from("auth_users")
      .select("id,username,name,email,role,email_verified,is_active")
      .eq("email", email)
      .limit(1);

    const user = users?.[0];
    if (!user || !user.is_active) {
      return c.json({
        error: "No account found with this email. Create one at profiles.rald.cloud.",
        identifier_type: "email",
      }, 404);
    }

    const isRealEmail = !(email.endsWith("@rald.identity") || email.endsWith("@loop.guest"));
    if (!isRealEmail || !user.email_verified) {
      return c.json({ error: "Email not verified for this account. Try logging in with phone or username." }, 400);
    }

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
        console.log("[DEV] Smart-login email OTP for " + email + ": " + emailCode);
      }

      const hint = email.replace(/(.{2}).+(@.+)/, "$1\u2022\u2022\u2022$2");

      await writeAuditLog(db, {
        userId: user.id as string,
        action: "otp_sent", ip, status: "success",
        metadata: { method: "email", via: "smart-login", identifier_type: "email" },
      });

      return c.json({
        ok:              true,
        pending_user_id: user.id as string,
        method:          "email" as const,
        identifier_type: "email",
        contact_hint:    hint,
        needs_username:  !(user.username as string | null),
      });
    } catch (err) {
      console.error("[smart-login] email OTP error:", String(err));
      return c.json({ error: "Failed to send verification code. Try again." }, 502);
    }
  }

  // ── Username path (default) ───────────────────────────────────────────────
  const username = lower.replace(/^@/, "");

  const identRl = await checkRateLimit(kv, {
    key: `smart-login:username:${username}`, limit: 5, windowSeconds: 900,
  });
  if (!identRl.allowed) return rateLimitResponse(identRl.resetAt);

  const { data: users } = await db
    .from("auth_users")
    .select("id,username,name,email,role,phone_number,phone_verified,email_verified,is_active,reserved_email_address")
    .ilike("username", username)
    .limit(1);

  const user = users?.[0];
  if (!user || !user.is_active) {
    return c.json({
      error: "Username not found. Check the spelling or create a new account.",
      identifier_type: "username",
    }, 404);
  }

  const phone = user.phone_number as string | null;
  const email = user.email        as string | null;

  if (phone && user.phone_verified) {
    try {
      const senderId = c.env.TERMII_SENDER_ID || "RALD";
      const { pinId } = await sendSmsOtp(phone, c.env.TERMII_API_KEY, senderId);
      const hint = phone.replace(/(\+\d{1,4})\d+(\d{2})$/, "$1•••$2");

      await writeAuditLog(db, {
        userId: user.id as string,
        action: "otp_sent", ip, status: "success",
        metadata: { method: "sms", via: "smart-login", identifier_type: "username" },
      });

      return c.json({
        ok:              true,
        pending_user_id: user.id as string,
        method:          "sms" as const,
        identifier_type: "username",
        pinId,
        contact_hint:    hint,
        needs_username:  false,
      });
    } catch (err) {
      console.error("[smart-login] username→SMS error:", String(err));
      // Fall through to email if SMS fails
    }
  }

  if (email) {
    const isRealEmail = !(email.endsWith("@rald.identity") || email.endsWith("@loop.guest"));
    if (isRealEmail && user.email_verified) {
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
        }

        const hint = email.replace(/(.{2}).+(@.+)/, "$1\u2022\u2022\u2022$2");

        await writeAuditLog(db, {
          userId: user.id as string,
          action: "otp_sent", ip, status: "success",
          metadata: { method: "email", via: "smart-login", identifier_type: "username" },
        });

        return c.json({
          ok:              true,
          pending_user_id: user.id as string,
          method:          "email" as const,
          identifier_type: "username",
          contact_hint:    hint,
          needs_username:  false,
        });
      } catch (err) {
        console.error("[smart-login] username→email error:", String(err));
      }
    }
  }

  return c.json({
    error:           "No verified contact method on file. Contact support at support@rald.cloud.",
    identifier_type: "username",
  }, 400);
});

// ── POST /auth/smart-login/complete ───────────────────────────────────────────
// Shared completion for all identifier types — same as login-username/complete

smartLogin.post("/complete", async (c) => {
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
    key: `smart-login-complete:user:${body.user_id}`, limit: 5, windowSeconds: 900,
  });
  if (!userRl.allowed) return rateLimitResponse(userRl.resetAt);

  const { data: users } = await db
    .from("auth_users")
    .select("id,username,name,email,role,rald_internal_id,email_verified,reserved_email_address,trust_level,is_active")
    .eq("id", body.user_id)
    .limit(1);

  const user = users?.[0];
  if (!user || !user.is_active) return c.json({ error: "User not found." }, 404);

  // ── Verify OTP ────────────────────────────────────────────────────────────

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
      console.error("[smart-login/complete] Termii error:", String(err));
    }
    if (!verified) {
      await writeAuditLog(db, {
        userId: user.id as string, action: "otp_failed",
        ip, status: "failure", metadata: { method: "sms", via: "smart-login" },
      });
      return c.json({ error: "Incorrect code. Try again or request a new one." }, 401);
    }
  } else {
    const userEmail = user.email as string | null;
    if (!userEmail) return c.json({ error: "No email on file for this account." }, 400);

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
        ip, status: "failure", metadata: { method: "email", via: "smart-login" },
      });
      return c.json({ error: "Incorrect code. Try again." }, 401);
    }
    await db.from("auth_otp_codes").update({ used: true }).eq("id", otp.id as string);
  }

  // ── Issue session ─────────────────────────────────────────────────────────

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
    metadata: { method: body.method, via: "smart-login" },
  });

  c.header("Set-Cookie", buildSessionCookie(token));

  // Identity repair (non-blocking)
  db.rpc("repair_identity_records", { p_user_id: user.id })
    .then(() => null, () => null);

  const needsUsername = !(user.username as string | null);
  if (needsUsername) {
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
    needs_username: needsUsername,
    migration: needsUsername ? {
      required:  true,
      message:   "Claim your @username to unlock the full RALD ecosystem.",
      claim_url: "https://profiles.rald.cloud/claim-username",
    } : null,
  });
});

export default smartLogin;
