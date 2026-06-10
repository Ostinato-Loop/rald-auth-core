// RALD Auth Core — QR Code Login
// POST /auth/qr/generate    → { qr_token, qr_url, expires_in, poll_url }
// GET  /auth/qr/status/:t   → { status, scanned_by?, session_token? }
// POST /auth/qr/scan/:t     → marks token as scanned (mobile, requires auth)
// POST /auth/qr/approve/:t  → approves login (mobile, requires auth) → issues JWT
// POST /auth/qr/reject/:t   → rejects login (mobile, requires auth)
// POST /auth/qr/activate    → desktop finalises: validates JWT → Set-Cookie
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import { authMiddleware } from "../lib/middleware";
import type { Bindings, Variables } from "../index";
import { buildSessionCookie } from "../lib/cookie";
import { signJwt, verifyJwt } from "../lib/auth";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const QR_TTL_SECONDS = 120;

interface QrSession {
  status: "waiting" | "scanned" | "approved" | "rejected";
  created_at: number;
  expires_at: number;
  desktop_ip: string;
  desktop_ua: string;
  mobile_user_id?: string;
  mobile_username?: string;
  session_jwt?: string;
}

const qr = new Hono<{ Bindings: Bindings; Variables: Variables }>();

function generateToken(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Generate ──────────────────────────────────────────────────────────────────
qr.post("/generate", async (c) => {
  const kv = c.env.RATE_LIMIT_KV;
  const ip = getClientIp(c.req.raw);
  const ua = c.req.header("user-agent") ?? "";

  const token = generateToken();
  const now = Date.now();
  const session: QrSession = {
    status: "waiting",
    created_at: now,
    expires_at: now + QR_TTL_SECONDS * 1000,
    desktop_ip: ip,
    desktop_ua: ua,
  };

  await kv.put(`qr:session:${token}`, JSON.stringify(session), {
    expirationTtl: QR_TTL_SECONDS,
  });

  return c.json({
    qr_token: token,
    qr_url: `https://profiles.rald.cloud/qr-approve?token=${token}`,
    expires_in: QR_TTL_SECONDS,
    poll_url: `/auth/qr/status/${token}`,
  });
});

// ── Poll status ───────────────────────────────────────────────────────────────
qr.get("/status/:token", async (c) => {
  const token = c.req.param("token") ?? "";
  const kv = c.env.RATE_LIMIT_KV;

  const raw = await kv.get(`qr:session:${token}`);
  if (!raw) return c.json({ status: "expired" });

  const session = JSON.parse(raw) as QrSession;
  if (Date.now() > session.expires_at) {
    await kv.delete(`qr:session:${token}`);
    return c.json({ status: "expired" });
  }

  const res: Record<string, unknown> = { status: session.status };
  if (session.status === "scanned" && session.mobile_username) {
    res.scanned_by = session.mobile_username;
  }
  if (session.status === "approved" && session.session_jwt) {
    res.session_token = session.session_jwt;
    await kv.delete(`qr:session:${token}`);
  }
  return c.json(res);
});

// ── Scan (mobile marks scanned) ───────────────────────────────────────────────
qr.post("/scan/:token", authMiddleware, async (c) => {
  const token = c.req.param("token") ?? "";
  const user = c.get("user")!;
  const kv = c.env.RATE_LIMIT_KV;

  const raw = await kv.get(`qr:session:${token}`);
  if (!raw) return c.json({ error: "QR code expired" }, 400);

  const session = JSON.parse(raw) as QrSession;
  if (session.status !== "waiting") return c.json({ error: "QR already used" }, 400);
  if (Date.now() > session.expires_at) return c.json({ error: "QR code expired" }, 400);

  session.status = "scanned";
  session.mobile_user_id = user.id;
  session.mobile_username = (user.username as string | undefined) ?? (user.email as string | undefined) ?? user.id;

  const remaining = Math.max(
    Math.floor((session.expires_at - Date.now()) / 1000),
    1,
  );
  await kv.put(`qr:session:${token}`, JSON.stringify(session), {
    expirationTtl: remaining,
  });

  return c.json({ ok: true, desktop_ip: session.desktop_ip });
});

// ── Approve ───────────────────────────────────────────────────────────────────
qr.post("/approve/:token", authMiddleware, async (c) => {
  const token = c.req.param("token") ?? "";
  const user = c.get("user")!;
  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;
  const ip = getClientIp(c.req.raw);

  const raw = await kv.get(`qr:session:${token}`);
  if (!raw) return c.json({ error: "QR code expired" }, 400);

  const session = JSON.parse(raw) as QrSession;
  if (
    session.status !== "waiting" &&
    session.status !== "scanned"
  ) {
    return c.json({ error: "QR already finalised" }, 400);
  }
  if (Date.now() > session.expires_at) return c.json({ error: "QR code expired" }, 400);

  const jwt = await signJwt(
    {
      id:       user.id,
      username: user.username,
      email:    user.email,
      role:     user.role,
      iss:      "rald.cloud",
      via:      "qr",
    },
    c.env.RALD_JWT_SECRET,
  );

  const tokenHash = await sha256Hex(jwt);

  await db.from("auth_sessions").insert({
    user_id:      user.id,
    token_hash:   tokenHash,
    expires_at:   new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    ip_address:   session.desktop_ip,
    user_agent:   session.desktop_ua,
    login_method: "qr",
  });

  session.status          = "approved";
  session.mobile_user_id  = user.id;
  session.mobile_username = (user.username as string | undefined) ?? (user.email as string | undefined) ?? user.id;
  session.session_jwt     = jwt;

  const remaining = Math.max(
    Math.floor((session.expires_at - Date.now()) / 1000),
    1,
  );
  await kv.put(`qr:session:${token}`, JSON.stringify(session), {
    expirationTtl: remaining,
  });

  await writeAuditLog(db, {
    user_id:  user.id,
    action:   "qr_login_approved",
    status:   "success",
    ip,
    metadata: {
      desktop_ip: session.desktop_ip,
      token_prefix: token.substring(0, 8),
    },
  });

  return c.json({ ok: true });
});

// ── Reject ────────────────────────────────────────────────────────────────────
qr.post("/reject/:token", authMiddleware, async (c) => {
  const token = c.req.param("token") ?? "";
  const user = c.get("user")!;
  const kv = c.env.RATE_LIMIT_KV;

  const raw = await kv.get(`qr:session:${token}`);
  if (!raw) return c.json({ ok: true });

  const session = JSON.parse(raw) as QrSession;
  session.status = "rejected";
  session.mobile_user_id = user.id;

  const remaining = Math.max(
    Math.floor((session.expires_at - Date.now()) / 1000),
    1,
  );
  await kv.put(`qr:session:${token}`, JSON.stringify(session), {
    expirationTtl: remaining,
  });

  return c.json({ ok: true });
});

// ── Activate (desktop sets cookie from the JWT returned by poll) ──────────────
// Desktop sends the session_token it received from the approved poll response.
// We re-validate the JWT and respond with Set-Cookie so the browser receives
// the HttpOnly session cookie without exposing the raw JWT to JavaScript.
qr.post("/activate", async (c) => {
  const body = await c.req.json<{ session_token: string }>().catch(() => null);
  if (!body?.session_token) return c.json({ error: "session_token required" }, 400);

  const payload = await verifyJwt(body.session_token, c.env.RALD_JWT_SECRET);
  if (!payload) {
    return c.json({ error: "Invalid or expired session token" }, 401);
  }

  if (payload.via !== "qr") {
    return c.json({ error: "Token is not a QR session token" }, 400);
  }

  return c.json(
    {
      ok: true,
      user: {
        id:       payload.id,
        username: payload.username,
        email:    payload.email,
        role:     payload.role,
      },
    },
    200,
    { "Set-Cookie": buildSessionCookie(body.session_token) },
  );
});

export default qr;
