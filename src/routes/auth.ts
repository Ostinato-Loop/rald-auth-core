// RALD Auth Core — Auth Routes
// Password, SMS OTP, Email OTP, Sessions, Password Reset
// G.9 Remediation: Rate limiting + audit logging on all auth endpoints
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { buildSessionCookie } from "../lib/cookie";
import type { Bindings, Variables } from "../index";
import { signJwt, verifyJwt, verifyPassword, hashPassword } from "../lib/auth";
import { authMiddleware } from "../lib/middleware";
import {
  sendSmsOtp,
  verifySmsOtp,
  generateNumericOtp,
  sendEmailOtp,
  sendLoginEmailOtp,
  sendWelcomeEmail,
  hashOtpCode,
  verifyOtpCode,
} from "../lib/otp";
import {
  checkRateLimit,
  RATE_LIMITS,
  getClientIp,
  rateLimitResponse,
} from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";
import { isSessionActive, isUserSuspended } from "../lib/session";
import type { KvSessionStore } from "../lib/session";

const auth = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * Identity State Guard — Phase 1 / RALD Ecosystem Finalization
 * Blocks SUSPENDED and DELETED identities at every JWT issuance point.
 * Returns a typed error object; caller responds with c.json(guard.error, guard.status).
 */
function checkIdentityState(state: string | null | undefined): { error: string; status: 403 } | null {
  if (state === "SUSPENDED") return { error: "Your account is temporarily unavailable. Contact support.", status: 403 };
  if (state === "DELETED")   return { error: "Account not found.", status: 403 };
  return null;
}

type UserRow = {
  id: string;
  email: string;
  name: string | null;
  role: string;
  created_at: string;
};

const userShape = (u: UserRow) => ({
  id: u.id,
  email: u.email,
  name: u.name,
  role: u.role,
  createdAt: u.created_at,
});

// ── Password Auth ─────────────────────────────────────────────────────────────

auth.post("/login", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    email?: string;
    password?: string;
  } | null;
  if (!body?.email || !body?.password)
    return c.json({ error: "Email and password required" }, 400);

  const email = body.email.trim().toLowerCase();

  // ── Rate limiting: IP + email ───────────────────────────────────────────────
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  const ipCheck = await checkRateLimit(kv, RATE_LIMITS.loginIp(ip));
  if (!ipCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "login_ip", email } });
    return rateLimitResponse(ipCheck.resetAt);
  }

  const emailCheck = await checkRateLimit(kv, RATE_LIMITS.loginEmail(email));
  if (!emailCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "login_email", email } });
    return rateLimitResponse(emailCheck.resetAt);
  }

  const { data: users } = await db
    .from("auth_users")
    .select("id,email,name,role,password_hash,created_at,identity_state,trust_score,trust_level")
    .eq("email", email)
    .limit(1);

  const user = users?.[0];
  if (!user || !user.password_hash || !(await verifyPassword(body.password, user.password_hash))) {
    await writeAuditLog(db, { action: "login_failed", ip, status: "failure", metadata: { email } });
    return c.json({ error: "Invalid email or password" }, 401);
  }

  const stateGuard = checkIdentityState((user as unknown as Record<string, unknown>).identity_state as string);
  if (stateGuard) {
    await writeAuditLog(db, { userId: user.id, action: "login_blocked", ip, status: "blocked", metadata: { email, reason: (user as unknown as Record<string, unknown>).identity_state } });
    return c.json({ error: stateGuard.error }, stateGuard.status);
  }

  const token = await signJwt(
    {
      id:          user.id,
      email:       user.email,
      role:        user.role,
      trust_score: ((user as unknown as Record<string, unknown>).trust_score ?? 0) as number,
      trust_level: ((user as unknown as Record<string, unknown>).trust_level ?? "none") as string,
      iss:         "rald.cloud",
    },
    c.env.RALD_JWT_SECRET
  );
  try {
    await db.from("auth_sessions").insert({
      user_id:    user.id,
      expires_at: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
    });
  } catch (e) {
    console.error("[rald-auth] session insert failed:", String(e));
  }

  await writeAuditLog(db, { userId: user.id, action: "login", ip, status: "success", metadata: { email } });
  c.header("Set-Cookie", buildSessionCookie(token));

  return c.json({ token, user: userShape(user) });
});

auth.post("/register", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    email?: string;
    password?: string;
    name?: string;
    role?: string;
    phone?: string;
    businessName?: string;
  } | null;

  if (!body?.email || !body?.password || !body?.name)
    return c.json({ error: "Name, email, and password are required" }, 400);

  // ── Rate limiting: IP ───────────────────────────────────────────────────────
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];
  const ipCheck = await checkRateLimit(kv, RATE_LIMITS.registerIp(ip));
  if (!ipCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "register_ip" } });
    return rateLimitResponse(ipCheck.resetAt);
  }

  const email = body.email.trim().toLowerCase();
  const name = body.name.trim();
  const role = body.role === "merchant" ? "merchant" : "user";

  if (body.password.length < 8)
    return c.json({ error: "Password must be at least 8 characters" }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return c.json({ error: "Invalid email address" }, 400);

  const { data: existing } = await db.from("auth_users").select("id").eq("email", email).limit(1);
  if (existing?.length) return c.json({ error: "An account with this email already exists" }, 409);

  const password_hash = await hashPassword(body.password);
  const meta: Record<string, string> = {};
  if (body.phone?.trim()) meta.phone = body.phone.trim().replace(/\D/g, "");
  if (role === "merchant" && body.businessName) meta.business_name = body.businessName.trim();

  const insertData: Record<string, unknown> = { email, password_hash, name, role, identity_state: "ACTIVE" };
  if (Object.keys(meta).length) insertData.metadata = meta;

  const { data: newUsers, error } = await db
    .from("auth_users")
    .insert(insertData)
    .select("id,email,name,role,created_at")
    .limit(1);

  if (error || !newUsers?.length) {
    console.error("Register error:", JSON.stringify(error));
    return c.json({ error: "Failed to create account. Please try again." }, 500);
  }

  const newUser = newUsers[0]!;

  // Phase 1 fix: generate temp username (user_xxxxx) for legacy email/password registrations
  // Users who signed up without the V2 username-first flow must still have a username
  const tempUsername = await (async () => {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (let attempt = 0; attempt < 10; attempt++) {
      const buf = new Uint8Array(5);
      crypto.getRandomValues(buf);
      const suffix = Array.from(buf, b => chars[b % chars.length]).join("");
      const candidate = `user_${suffix}`;
      const { data: existing } = await db
        .from("usernames").select("username").eq("username", candidate).limit(1);
      if (!existing?.length) return candidate;
    }
    return `user_${Date.now().toString(36)}`; // fallback: epoch-based
  })();

  // Set username on the auth_users row and register in usernames table (non-blocking)
  db.from("auth_users")
    .update({ username: tempUsername, username_set_at: new Date().toISOString() })
    .eq("id", newUser.id)
    .then(() => {}, () => {});
  db.from("usernames")
    .insert({ username: tempUsername, user_id: newUser.id, claimed_at: new Date().toISOString(), active: true })
    .then(() => {}, () => {});

  const token = await signJwt(
    { id: newUser.id, email: newUser.email, role: newUser.role, username: tempUsername, iss: "rald.cloud" },
    c.env.RALD_JWT_SECRET
  );

  db.from("auth_user_profiles").insert({
    user_id:      newUser.id,
    display_name: name,
    search_discoverable: true,
  }).then(() => {}, (e: unknown) => console.error("[rald-auth] profile insert failed:", String(e)));

  if (c.env.RESEND_API_KEY)
    sendWelcomeEmail(newUser.email, newUser.name ?? name, c.env.RESEND_API_KEY).catch(console.error);

  await writeAuditLog(db, { userId: newUser.id, action: "register", ip, status: "success", metadata: { email, role, temp_username: tempUsername } });
  c.header("Set-Cookie", buildSessionCookie(token));

  return c.json({ token, user: { ...userShape(newUser), username: tempUsername } }, 201);
});

// ── SMS OTP Auth ──────────────────────────────────────────────────────────────

auth.post("/send-otp", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as { phone?: string } | null;
  if (!body?.phone) return c.json({ error: "Phone number required" }, 400);

  const phone = body.phone.replace(/\D/g, "");
  if (phone.length < 10) return c.json({ error: "Invalid phone number" }, 400);

  // ── Rate limiting: per-phone + per-IP ──────────────────────────────────────
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  const phoneCheck = await checkRateLimit(kv, RATE_LIMITS.otpSendPhone(phone));
  if (!phoneCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "otp_phone", phone } });
    return rateLimitResponse(phoneCheck.resetAt);
  }

  const ipCheck = await checkRateLimit(kv, RATE_LIMITS.otpSendIp(ip));
  if (!ipCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "otp_ip" } });
    return rateLimitResponse(ipCheck.resetAt);
  }

  // ── Dev mode: only when ENVIRONMENT is not production AND no real key ───────
  const isProduction = c.env.ENVIRONMENT === "production";
  if (!c.env.TERMII_API_KEY && !isProduction) {
    console.log(`[DEV] SMS OTP for ${phone}: 123456`);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "success", metadata: { phone, channel: "dev" } });
    return c.json({ pinId: "dev-mode-pin-id", message: "Verification code sent" });
  }

  if (!c.env.TERMII_API_KEY) {
    console.error("[rald-auth] TERMII_API_KEY not configured in production");
    return c.json({ error: "Verification service not available. Please try again later." }, 503);
  }

  try {
    const senderId = c.env.TERMII_SENDER_ID || "N-Alert";
    const { pinId } = await sendSmsOtp(phone, c.env.TERMII_API_KEY, senderId);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "success", metadata: { phone, channel: "termii" } });
    return c.json({ pinId, message: "Verification code sent" });
  } catch (err: unknown) {
    const isUnavailable = err instanceof Error && err.message === "SMS_UNAVAILABLE";
    console.error("SMS OTP error:", err);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "failure", metadata: { phone, error: String(err) } });
    return c.json(
      {
        error: isUnavailable
          ? "SMS is temporarily unavailable. Please choose email verification instead."
          : "Could not send verification code. Please try again or use email.",
        sms_unavailable: true,
      },
      503,
    );
  }
});

auth.post("/verify-otp", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    pinId?: string;
    pin?: string;
    phone?: string;
  } | null;
  if (!body?.pinId || !body?.pin || !body?.phone)
    return c.json({ error: "pinId, pin, and phone are required" }, 400);

  let verified = false;
  const isProduction = c.env.ENVIRONMENT === "production";

  // SEC-OTP-002: Brute-force guard on verify attempts.
  // A 6-digit OTP has 1 000 000 combinations. Without per-pinId throttling an
  // attacker who observed a pinId (or reused a stolen one) could exhaust the
  // full space in seconds. 5 attempts/pinId + 20 attempts/IP per 10-min window.
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];
  const pinAttemptCheck = await checkRateLimit(kv, {
    key: `otp:verify:pin:${body.pinId}`,
    limit: 5,
    windowSeconds: 600,
  });
  if (!pinAttemptCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "otp_verify_pin", phone: body.phone } });
    return rateLimitResponse(pinAttemptCheck.resetAt);
  }
  const verifyIpCheck = await checkRateLimit(kv, {
    key: `otp:verify:ip:${ip}`,
    limit: 20,
    windowSeconds: 600,
  });
  if (!verifyIpCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "otp_verify_ip", phone: body.phone } });
    return rateLimitResponse(verifyIpCheck.resetAt);
  }

  // SEC-OTP-001: dev-mode bypass MUST be inside !isProduction guard.
  // Vulnerable: (!TERMII_KEY && !isProd) || pinId==="dev-mode-pin-id"
  // JS operator precedence: right-hand OR branch has no production guard —
  // any caller could POST pinId:"dev-mode-pin-id" + pin:"123456" in production
  // to bypass OTP for any phone number without ever receiving a code.
  if (!isProduction && (!c.env.TERMII_API_KEY || body.pinId === "dev-mode-pin-id")) {
    verified = body.pin === "123456";
  } else if (c.env.TERMII_API_KEY) {
    try {
      verified = await verifySmsOtp(body.pinId, body.pin, c.env.TERMII_API_KEY);
    } catch (err) {
      console.error("SMS verify error:", err);
      return c.json({ error: "Verification error. Try again." }, 502);
    }
  } else {
    return c.json({ error: "Verification service not available." }, 503);
  }

  if (!verified) {
    await writeAuditLog(db, { action: "otp_failed", ip, status: "failure", metadata: { phone: body.phone } });
    return c.json({ error: "Invalid or expired code. Try again." }, 401);
  }

  const phone = body.phone.replace(/\D/g, "");
  let existingUser: UserRow | undefined;
  try {
    const { data } = await db
      .from("auth_users")
      .select("id,email,name,role,created_at,identity_state")
      .filter("metadata->>phone", "eq", phone)
      .limit(1);
    existingUser = data?.[0];
  } catch {}

  if (existingUser) {
    const stateGuard = checkIdentityState((existingUser as unknown as Record<string, unknown>).identity_state as string);
    if (stateGuard) {
      await writeAuditLog(db, { userId: existingUser.id, action: "login_blocked", ip, status: "blocked", metadata: { phone, reason: (existingUser as unknown as Record<string, unknown>).identity_state } });
      return c.json({ error: stateGuard.error }, stateGuard.status);
    }
    const token = await signJwt(
      { id: existingUser.id, email: existingUser.email, role: existingUser.role },
      c.env.RALD_JWT_SECRET
    );
    await writeAuditLog(db, { userId: existingUser.id, action: "otp_verified", ip, status: "success", metadata: { phone } });
    return c.json({ token, user: userShape(existingUser) });
  }

  const otpToken = await signJwt(
    { phone, purpose: "phone-verified" },
    c.env.RALD_JWT_SECRET,
    300
  );
  await writeAuditLog(db, { action: "otp_verified", ip, status: "success", metadata: { phone, newUser: true } });
  return c.json({ newUser: true, phone, otpToken });
});

auth.post("/register-from-otp", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    otpToken?: string;
    name?: string;
    email?: string;
    role?: string;
    businessName?: string;
  } | null;

  if (!body?.otpToken || !body?.name || !body?.email)
    return c.json({ error: "otpToken, name, and email are required" }, 400);

  const payload = await verifyJwt(body.otpToken, c.env.RALD_JWT_SECRET);
  if (!payload || (payload as unknown as Record<string, unknown>).purpose !== "phone-verified")
    return c.json({ error: "Invalid or expired phone verification token" }, 401);

  const phone = (payload as unknown as Record<string, string>).phone;
  if (!phone) return c.json({ error: "Phone missing from token" }, 400);

  const email = body.email.trim().toLowerCase();
  const name = body.name.trim();
  const role = body.role === "merchant" ? "merchant" : "user";

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return c.json({ error: "Invalid email address" }, 400);

  const { data: existing } = await db.from("auth_users").select("id").eq("email", email).limit(1);
  if (existing?.length) return c.json({ error: "An account with this email already exists" }, 409);

  const meta: Record<string, string> = { phone };
  if (role === "merchant" && body.businessName) meta.business_name = body.businessName.trim();

  const { data: newUsers, error } = await db
    .from("auth_users")
    .insert({ email, name, role, password_hash: "", metadata: meta, identity_state: "ACTIVE" })
    .select("id,email,name,role,created_at")
    .limit(1);

  if (error || !newUsers?.length) {
    console.error("register-from-otp error:", JSON.stringify(error));
    return c.json({ error: "Failed to create account. Please try again." }, 500);
  }

  const newUser = newUsers[0]!;
  const token = await signJwt(
    { id: newUser.id, email: newUser.email, role: newUser.role },
    c.env.RALD_JWT_SECRET
  );
  if (c.env.RESEND_API_KEY)
    sendWelcomeEmail(newUser.email, newUser.name ?? name, c.env.RESEND_API_KEY).catch(console.error);

  await writeAuditLog(db, { userId: newUser.id, action: "register", ip, status: "success", metadata: { email, role, via: "otp" } });
  c.header("Set-Cookie", buildSessionCookie(token));

  return c.json({ token, user: userShape(newUser) }, 201);
});

// ── Email OTP Auth ────────────────────────────────────────────────────────────

auth.post("/send-login-email-otp", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as { email?: string } | null;
  if (!body?.email) return c.json({ error: "Email required" }, 400);

  const email = body.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return c.json({ error: "Invalid email address" }, 400);

  // ── Rate limiting: per-email ────────────────────────────────────────────────
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];
  const emailCheck = await checkRateLimit(kv, RATE_LIMITS.otpSendEmail(email));
  if (!emailCheck.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "otp_email", email } });
    return rateLimitResponse(emailCheck.resetAt);
  }

  const code = generateNumericOtp(6);
  const codeHash = await hashOtpCode(code);
  const sessionToken = await signJwt(
    { email, codeHash, purpose: "email-otp-login" },
    c.env.RALD_JWT_SECRET,
    600
  );

  if (!c.env.RESEND_API_KEY) {
    console.log(`[DEV] Email login OTP for ${email}: ${code}`);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "success", metadata: { email, channel: "dev" } });
    return c.json({ sessionToken, message: "Verification code sent to your email" });
  }

  try {
    await sendLoginEmailOtp(email, code, c.env.RESEND_API_KEY);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "success", metadata: { email, channel: "resend" } });
    return c.json({ sessionToken, message: "Verification code sent to your email" });
  } catch (err: unknown) {
    console.error("Login email OTP error:", err);
    await writeAuditLog(db, { action: "otp_sent", ip, status: "failure", metadata: { email, error: String(err) } });
    return c.json({ error: "Failed to send verification email. Try again." }, 502);
  }
});

auth.post("/verify-login-email-otp", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    sessionToken?: string;
    code?: string;
  } | null;
  if (!body?.sessionToken || !body?.code)
    return c.json({ error: "sessionToken and code are required" }, 400);

  const payload = await verifyJwt(body.sessionToken, c.env.RALD_JWT_SECRET);
  if (!payload || (payload as unknown as Record<string, unknown>).purpose !== "email-otp-login")
    return c.json({ error: "Invalid or expired session. Request a new code." }, 401);

  const { email, codeHash } = payload as unknown as Record<string, string>;
  if (!email || !codeHash) return c.json({ error: "Invalid session data" }, 400);

  const inputHash = await hashOtpCode(body.code.trim());
  if (inputHash !== codeHash) {
    await writeAuditLog(db, { action: "otp_failed", ip, status: "failure", metadata: { email } });
    return c.json({ error: "Invalid or expired code. Try again." }, 401);
  }

  const { data: users } = await db
    .from("auth_users")
    .select("id,email,name,role,created_at,identity_state")
    .eq("email", email)
    .limit(1);

  const existingUser = users?.[0];
  if (existingUser) {
    const stateGuard = checkIdentityState((existingUser as unknown as Record<string, unknown>).identity_state as string);
    if (stateGuard) {
      await writeAuditLog(db, { userId: existingUser.id, action: "login_blocked", ip, status: "blocked", metadata: { email, reason: (existingUser as unknown as Record<string, unknown>).identity_state } });
      return c.json({ error: stateGuard.error }, stateGuard.status);
    }
    const token = await signJwt(
      { id: existingUser.id, email: existingUser.email, role: existingUser.role },
      c.env.RALD_JWT_SECRET
    );
    await writeAuditLog(db, { userId: existingUser.id, action: "otp_verified", ip, status: "success", metadata: { email } });
    return c.json({ token, user: userShape(existingUser) });
  }

  const emailToken = await signJwt(
    { email, purpose: "email-verified" },
    c.env.RALD_JWT_SECRET,
    300
  );
  await writeAuditLog(db, { action: "otp_verified", ip, status: "success", metadata: { email, newUser: true } });
  return c.json({ newUser: true, email, emailToken });
});

// ── Password Reset ────────────────────────────────────────────────────────────

auth.post("/request-password-reset", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as { email?: string } | null;
  if (!body?.email) return c.json({ error: "Email required" }, 400);

  const email = body.email.trim().toLowerCase();

  // ── Rate limiting: per-email ────────────────────────────────────────────────
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];
  const rl = await checkRateLimit(kv, RATE_LIMITS.passwordReset(email));
  if (!rl.allowed) {
    await writeAuditLog(db, { action: "rate_limited", ip, status: "blocked", metadata: { reason: "password_reset", email } });
    return rateLimitResponse(rl.resetAt);
  }

  const { data: users } = await db.from("auth_users").select("id").eq("email", email).limit(1);
  const okMsg = { message: "If an account exists with this email, a reset code has been sent." };
  if (!users?.length) return c.json(okMsg);

  const code = generateNumericOtp(6);
  const codeHash = await hashOtpCode(code);

  try {
    await db.from("auth_otp_codes").insert({
      email,
      code_hash: codeHash,
      type: "password_reset",
      expires_at: new Date(Date.now() + 900000).toISOString(),
    });
  } catch {
    console.warn("otps table unavailable");
  }

  if (c.env.RESEND_API_KEY)
    sendEmailOtp(email, code, c.env.RESEND_API_KEY).catch((e) =>
      console.error("Reset email error:", e)
    );
  else console.log(`[DEV] Password reset for ${email}: ${code}`);

  await writeAuditLog(db, { action: "password_reset_requested", ip, status: "success", metadata: { email } });
  return c.json(okMsg);
});

auth.post("/reset-password", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");

  const body = (await c.req.json().catch(() => null)) as {
    email?: string;
    code?: string;
    newPassword?: string;
  } | null;
  if (!body?.email || !body?.code || !body?.newPassword)
    return c.json({ error: "Email, code, and new password are required" }, 400);
  if (body.newPassword.length < 8)
    return c.json({ error: "Password must be at least 8 characters" }, 400);

  const email = body.email.trim().toLowerCase();

  let otp: { id: string; code_hash: string } | undefined;
  try {
    const { data: otps } = await db
      .from("auth_otp_codes")
      .select("id,code_hash")
      .eq("email", email)
      .eq("type", "password_reset")
      .eq("used", false)
      .gte("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1);
    otp = otps?.[0];
  } catch {
    return c.json({ error: "Password reset not available. Contact support@rald.cloud." }, 503);
  }

  if (!otp) return c.json({ error: "No valid reset code. Request a new one." }, 400);
  if (!(await verifyOtpCode(body.code, otp.code_hash)))
    return c.json({ error: "Incorrect reset code." }, 401);

  await db.from("auth_otp_codes").update({ used: true }).eq("id", otp.id);
  const password_hash = await hashPassword(body.newPassword);
  await db.from("auth_users").update({ password_hash }).eq("email", email);

  await writeAuditLog(db, { action: "password_reset_completed", ip, status: "success", metadata: { email } });
  return c.json({ message: "Password updated. You can now sign in." });
});

// ── User / Sessions ───────────────────────────────────────────────────────────

auth.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const { data: users } = await db
    .from("auth_users")
    .select("id,email,name,role,metadata,created_at")
    .eq("id", user.id)
    .limit(1);

  const u = users?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const meta = u.metadata as Record<string, string> | null;
  return c.json({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    phone: meta?.phone ?? null,
    createdAt: u.created_at,
  });
});

auth.get("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  try {
    const { data } = await db
      .from("auth_sessions")
      .select("id,user_agent,ip_address,last_seen_at,created_at")
      .eq("user_id", user.id)
      .is("revoked_at", null)
      .gte("expires_at", new Date().toISOString())
      .order("last_seen_at", { ascending: false });
    return c.json(data ?? []);
  } catch {
    return c.json([]);
  }
});

auth.delete("/sessions/:id", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);
  try {
    await db
      .from("auth_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", c.req.param("id"))
      .eq("user_id", user.id);
  } catch {}
  await writeAuditLog(db, { userId: user.id, action: "session_revoked", ip, status: "success" });
  return c.json({ message: "Session revoked" });
});

auth.delete("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);
  try {
    await db
      .from("auth_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .is("revoked_at", null);
  } catch {}
  await writeAuditLog(db, { userId: user.id, action: "all_sessions_revoked", ip, status: "success" });
  return c.json({ message: "All sessions revoked" });
});



export default auth;
