// RALD Auth Core — Auth Routes
// Password, SMS OTP, Email OTP, Sessions, Password Reset
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
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

const auth = new Hono<{ Bindings: Bindings; Variables: Variables }>();

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
  const body = (await c.req.json().catch(() => null)) as {
    email?: string;
    password?: string;
  } | null;
  if (!body?.email || !body?.password)
    return c.json({ error: "Email and password required" }, 400);

  const db = c.get("db");
  const { data: users } = await db
    .from("users")
    .select("id,email,name,role,password_hash,created_at")
    .eq("email", body.email.trim().toLowerCase())
    .limit(1);

  const user = users?.[0];
  if (!user || !user.password_hash || !(await verifyPassword(body.password, user.password_hash)))
    return c.json({ error: "Invalid email or password" }, 401);

  const token = await signJwt(
    { id: user.id, email: user.email, role: user.role, iss: "rald.cloud" },
    c.env.RALD_JWT_SECRET
  );
  // Write session record (fire-and-forget)
  db.from("sessions").insert({
    user_id: user.id,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 86400 * 1000).toISOString(),
    ip_address: c.req.header("CF-Connecting-IP") ?? null,
    user_agent: c.req.header("User-Agent") ?? null,
  }).then(() => {}).catch((e: unknown) => console.error("Session write:", e));

  return c.json({ token, user: userShape(user) });
});

auth.post("/register", async (c) => {
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

  const email = body.email.trim().toLowerCase();
  const name = body.name.trim();
  const role = body.role === "merchant" ? "merchant" : "user";

  if (body.password.length < 8)
    return c.json({ error: "Password must be at least 8 characters" }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return c.json({ error: "Invalid email address" }, 400);

  const db = c.get("db");
  const { data: existing } = await db.from("users").select("id").eq("email", email).limit(1);
  if (existing?.length) return c.json({ error: "An account with this email already exists" }, 409);

  const password_hash = await hashPassword(body.password);
  const meta: Record<string, string> = {};
  if (body.phone?.trim()) meta.phone = body.phone.trim().replace(/\D/g, "");
  if (role === "merchant" && body.businessName) meta.business_name = body.businessName.trim();

  const insertData: Record<string, unknown> = { email, password_hash, name, role };
  if (Object.keys(meta).length) insertData.metadata = meta;

  const { data: newUsers, error } = await db
    .from("users")
    .insert(insertData)
    .select("id,email,name,role,created_at")
    .limit(1);

  if (error || !newUsers?.length) {
    console.error("Register error:", JSON.stringify(error));
    return c.json({ error: "Failed to create account. Please try again." }, 500);
  }

  const newUser = newUsers[0]!;
  const token = await signJwt(
    { id: newUser.id, email: newUser.email, role: newUser.role },
    c.env.RALD_JWT_SECRET
  );
  if (c.env.RESEND_API_KEY)
    sendWelcomeEmail(newUser.email, newUser.name ?? name, c.env.RESEND_API_KEY).catch(console.error);

  return c.json({ token, user: userShape(newUser) }, 201);
});

// ── SMS OTP Auth ──────────────────────────────────────────────────────────────

auth.post("/send-otp", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { phone?: string } | null;
  if (!body?.phone) return c.json({ error: "Phone number required" }, 400);

  const phone = body.phone.replace(/\D/g, "");
  if (phone.length < 10) return c.json({ error: "Invalid phone number" }, 400);

  if (!c.env.TERMII_API_KEY) {
    console.log(`[DEV] SMS OTP for ${phone}: 123456`);
    return c.json({ pinId: "dev-mode-pin-id", message: "Verification code sent" });
  }

  try {
    const { pinId } = await sendSmsOtp(phone, c.env.TERMII_API_KEY);
    return c.json({ pinId, message: "Verification code sent" });
  } catch (err: unknown) {
    console.error("SMS OTP error:", err);
    return c.json(
      { error: err instanceof Error ? err.message : "Failed to send code. Try again." },
      502
    );
  }
});

auth.post("/verify-otp", async (c) => {
  const body = (await c.req.json().catch(() => null)) as {
    pinId?: string;
    pin?: string;
    phone?: string;
  } | null;
  if (!body?.pinId || !body?.pin || !body?.phone)
    return c.json({ error: "pinId, pin, and phone are required" }, 400);

  let verified = false;
  if (!c.env.TERMII_API_KEY || body.pinId === "dev-mode-pin-id") {
    verified = body.pin === "123456";
  } else {
    try {
      verified = await verifySmsOtp(body.pinId, body.pin, c.env.TERMII_API_KEY);
    } catch (err) {
      console.error("SMS verify error:", err);
      return c.json({ error: "Verification error. Try again." }, 502);
    }
  }

  if (!verified) return c.json({ error: "Invalid or expired code. Try again." }, 401);

  const db = c.get("db");
  const phone = body.phone.replace(/\D/g, "");
  let existingUser: UserRow | undefined;
  try {
    const { data } = await db
      .from("users")
      .select("id,email,name,role,created_at")
      .filter("metadata->>phone", "eq", phone)
      .limit(1);
    existingUser = data?.[0];
  } catch {}

  if (existingUser) {
    const token = await signJwt(
      { id: existingUser.id, email: existingUser.email, role: existingUser.role },
      c.env.RALD_JWT_SECRET
    );
    return c.json({ token, user: userShape(existingUser) });
  }

  const otpToken = await signJwt(
    { phone, purpose: "phone-verified" },
    c.env.RALD_JWT_SECRET,
    300
  );
  return c.json({ newUser: true, phone, otpToken });
});

auth.post("/register-from-otp", async (c) => {
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

  const db = c.get("db");
  const { data: existing } = await db.from("users").select("id").eq("email", email).limit(1);
  if (existing?.length) return c.json({ error: "An account with this email already exists" }, 409);

  const meta: Record<string, string> = { phone };
  if (role === "merchant" && body.businessName) meta.business_name = body.businessName.trim();

  const { data: newUsers, error } = await db
    .from("users")
    .insert({ email, name, role, password_hash: "", metadata: meta })
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

  return c.json({ token, user: userShape(newUser) }, 201);
});

// ── Email OTP Auth ────────────────────────────────────────────────────────────

auth.post("/send-login-email-otp", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { email?: string } | null;
  if (!body?.email) return c.json({ error: "Email required" }, 400);

  const email = body.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return c.json({ error: "Invalid email address" }, 400);

  const code = generateNumericOtp(6);
  const codeHash = await hashOtpCode(code);
  const sessionToken = await signJwt(
    { email, codeHash, purpose: "email-otp-login" },
    c.env.RALD_JWT_SECRET,
    600
  );

  if (!c.env.RESEND_API_KEY) {
    console.log(`[DEV] Email login OTP for ${email}: ${code}`);
    return c.json({ sessionToken, message: "Verification code sent to your email" });
  }

  try {
    await sendLoginEmailOtp(email, code, c.env.RESEND_API_KEY);
    return c.json({ sessionToken, message: "Verification code sent to your email" });
  } catch (err: unknown) {
    console.error("Login email OTP error:", err);
    return c.json({ error: "Failed to send verification email. Try again." }, 502);
  }
});

auth.post("/verify-login-email-otp", async (c) => {
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
  if (inputHash !== codeHash) return c.json({ error: "Invalid or expired code. Try again." }, 401);

  const db = c.get("db");
  const { data: users } = await db
    .from("users")
    .select("id,email,name,role,created_at")
    .eq("email", email)
    .limit(1);

  const existingUser = users?.[0];
  if (existingUser) {
    const token = await signJwt(
      { id: existingUser.id, email: existingUser.email, role: existingUser.role },
      c.env.RALD_JWT_SECRET
    );
    return c.json({ token, user: userShape(existingUser) });
  }

  const emailToken = await signJwt(
    { email, purpose: "email-verified" },
    c.env.RALD_JWT_SECRET,
    300
  );
  return c.json({ newUser: true, email, emailToken });
});

// ── Password Reset ────────────────────────────────────────────────────────────

auth.post("/request-password-reset", async (c) => {
  const body = (await c.req.json().catch(() => null)) as { email?: string } | null;
  if (!body?.email) return c.json({ error: "Email required" }, 400);

  const email = body.email.trim().toLowerCase();
  const db = c.get("db");
  const { data: users } = await db.from("users").select("id").eq("email", email).limit(1);

  const okMsg = { message: "If an account exists with this email, a reset code has been sent." };
  if (!users?.length) return c.json(okMsg);

  const code = generateNumericOtp(6);
  const codeHash = await hashOtpCode(code);

  try {
    await db.from("otps").insert({
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

  return c.json(okMsg);
});

auth.post("/reset-password", async (c) => {
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
  const db = c.get("db");

  let otp: { id: string; code_hash: string } | undefined;
  try {
    const { data: otps } = await db
      .from("otps")
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

  await db.from("otps").update({ used: true }).eq("id", otp.id);
  const password_hash = await hashPassword(body.newPassword);
  await db.from("users").update({ password_hash }).eq("email", email);

  return c.json({ message: "Password updated. You can now sign in." });
});

// ── User / Sessions ───────────────────────────────────────────────────────────

auth.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const { data: users } = await db
    .from("users")
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
      .from("sessions")
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
  try {
    await db
      .from("sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", c.req.param("id"))
      .eq("user_id", user.id);
  } catch {}
  return c.json({ message: "Session revoked" });
});

auth.delete("/sessions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  try {
    await db
      .from("sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .is("revoked_at", null);
  } catch {}
  return c.json({ message: "All sessions revoked" });
});

export default auth;
