// RALD Auth Core — Recovery Codes (V2)
// POST /recovery/generate  — generate a fresh set of 8 one-time codes (authenticated)
// POST /recovery/verify    — verify a recovery code + issue session (no other auth needed)
// GET  /recovery/status    — how many unused codes remain
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { signJwt } from "../lib/auth";
import { buildSessionCookie } from "../lib/cookie";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const recovery = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const CODES_PER_SET = 8;
const CODE_BYTES    = 10; // 10 random bytes → 20-char hex string

function generateRecoveryCode(): string {
  const buf = new Uint8Array(CODE_BYTES);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── POST /recovery/generate — issue fresh set of codes ───────────────────────
recovery.post("/generate", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  // Revoke all existing unused codes first
  await db.from("recovery_codes")
    .update({ used: true, used_at: new Date().toISOString() })
    .eq("user_id", user.id)
    .eq("used", false);

  // Generate new codes
  const plainCodes: string[] = [];
  const rows: { user_id: string; code_hash: string }[] = [];

  for (let i = 0; i < CODES_PER_SET; i++) {
    const plain = generateRecoveryCode();
    plainCodes.push(plain);
    rows.push({ user_id: user.id, code_hash: await sha256hex(plain) });
  }

  const { error } = await db.from("recovery_codes").insert(rows);
  if (error) {
    console.error("[recovery/generate] db error:", error.message);
    return c.json({ error: "Failed to generate recovery codes" }, 500);
  }

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "recovery_codes_generated",
    ip:       getClientIp(c.req.raw),
    status:   "success",
    metadata: { count: CODES_PER_SET },
  });

  return c.json({
    ok:      true,
    codes:   plainCodes,
    count:   CODES_PER_SET,
    warning: "Save these codes somewhere safe. Each code can only be used once. They will not be shown again.",
  });
});

// ── POST /recovery/verify — use a recovery code to authenticate ───────────────
recovery.post("/verify", async (c) => {
  const ip = getClientIp(c.req.raw);
  const db = c.get("db");
  const kv = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  // Rate limit: 5 attempts per IP per 15 minutes (prevent brute force)
  const rlCheck = await checkRateLimit(kv, {
    key: `recovery:ip:${ip}`,
    limit: 5,
    windowSeconds: 900,
  });
  if (!rlCheck.allowed) return rateLimitResponse(rlCheck.resetAt);

  const body = await c.req.json<{ user_id?: string; code?: string }>().catch(() => null);
  if (!body?.user_id || !body?.code) {
    return c.json({ error: "user_id and code are required" }, 400);
  }

  const codeHash = await sha256hex(body.code.toLowerCase().trim());

  // Find the matching unused code
  const { data: codes, error } = await db
    .from("recovery_codes")
    .select("id, user_id, code_hash, used")
    .eq("user_id", body.user_id)
    .eq("code_hash", codeHash)
    .eq("used", false)
    .limit(1);

  if (error || !codes || codes.length === 0) {
    await writeAuditLog(db, {
      userId:   body.user_id,
      action:   "recovery_code_failed",
      ip,
      status:   "failure",
      metadata: { reason: "invalid_or_used" },
    });
    return c.json({ error: "Invalid or already-used recovery code" }, 401);
  }

  const codeRow = codes[0]!;

  // Mark code as used
  await db.from("recovery_codes")
    .update({ used: true, used_at: new Date().toISOString() })
    .eq("id", codeRow.id);

  // Fetch user
  const { data: users } = await db
    .from("auth_users")
    .select("id, email, username, role")
    .eq("id", body.user_id)
    .limit(1);

  const user = users?.[0];
  if (!user) return c.json({ error: "User not found" }, 404);

  // Issue session
  const token = await signJwt(
    { id: user.id, email: user.email ?? null, username: user.username ?? null, role: user.role, iss: "rald.cloud" },
    c.env.RALD_JWT_SECRET
  );

  await db.from("auth_sessions").insert({
    user_id:    user.id,
    ip_address: ip,
    expires_at: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
  });

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "recovery_code_used",
    ip,
    status:   "success",
    metadata: { code_id: codeRow.id },
  });

  const [, setSession] = await Promise.all([
    null,
    (async () => { c.header("Set-Cookie", (await import("../lib/cookie")).buildSessionCookie(token)); })(),
  ]);
  void setSession;

  return c.json({
    ok:    true,
    token,
    user:  { id: user.id, username: user.username ?? null, email: user.email ?? null, role: user.role },
    warning: "You used a recovery code. Please generate a new set of codes to stay protected.",
  });
});

// ── GET /recovery/status — how many unused codes remain ───────────────────────
recovery.get("/status", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { count } = await db
    .from("recovery_codes")
    .select("*", { count: "exact", head: true })
    .eq("user_id", user.id)
    .eq("used", false);

  return c.json({
    unused_count:    count ?? 0,
    needs_refresh:   (count ?? 0) < 3,
    recommendation:  (count ?? 0) < 3
      ? "You have fewer than 3 recovery codes left. Generate a fresh set."
      : null,
  });
});

export default recovery;
