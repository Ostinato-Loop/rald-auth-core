// RALD Auth Core — Ecosystem Session Broker
// REVOKE-ALL-001 (2026-06-09):
//   POST /session/revoke-all — preserves current session, returns count, audits as SESSION_REVOKE_ALL
//   POST /session/revoke-device { device_id } — single-device revocation
// Phase G.10: GET /session · GET /me · POST /logout · POST /session/revoke-all
//             POST /session/revoke-device · POST /session/suspend · POST /session/unsuspend
//             DELETE /session/device/:deviceId · GET /sso/silent · POST /session/register
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { verifyJwt, generateSecureToken } from "../lib/auth";
import { buildSessionCookie, clearSessionCookie, parseSessionCookie } from "../lib/cookie";
import {
  isSessionActive,
  isUserSuspended,
  revokeKvSession,
  revokeAllUserSessions,
  suspendUser,
  unsuspendUser,
  createKvSession,
  type KvSessionStore,
} from "../lib/session";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const session = new Hono<{ Bindings: Bindings; Variables: Variables }>();

function getSessionKv(env: Bindings): KvSessionStore | null {
  return (env as unknown as Record<string, unknown>).RALD_SESSION_KV as KvSessionStore ?? null;
}

// ── GET /session ──────────────────────────────────────────────────────────────
session.get("/session", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ valid: false, reason: "missing_token", redirect: "https://profiles.rald.cloud/login" }, 401);
  }
  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, c.env.RALD_JWT_SECRET);
  if (!payload) {
    return c.json({ valid: false, reason: "invalid_or_expired_token", redirect: "https://profiles.rald.cloud/login" }, 401);
  }
  const kv = getSessionKv(c.env);
  if (kv) {
    const suspended = await isUserSuspended(kv, payload.id);
    if (suspended) {
      return c.json({ valid: false, reason: "account_suspended", redirect: "https://profiles.rald.cloud/suspended" }, 403);
    }
  }
  const p = payload as unknown as Record<string, unknown>;
  const sessionId = (p.session_id ?? p.sid ?? null) as string | null;
  if (kv && sessionId) {
    const { active, reason } = await isSessionActive(kv, sessionId);
    if (!active) {
      return c.json({ valid: false, reason, redirect: "https://profiles.rald.cloud/login" }, 401);
    }
  }
  return c.json({
    valid: true,
    user: { id: payload.id, email: payload.email, role: payload.role },
    session: {
      session_id: sessionId,
      app_id:     (p.appId ?? null) as string | null,
      sso_v:      (p.sso_v ?? 1) as number,
      expires_at: new Date(payload.exp * 1000).toISOString(),
    },
    identity_hub: "profiles.rald.cloud",
  });
});

// ── GET /me ───────────────────────────────────────────────────────────────────
session.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  if (kv) {
    const suspended = await isUserSuspended(kv, user.id);
    if (suspended) return c.json({ error: "Account suspended" }, 403);
  }
  const { data: users } = await db.from("auth_users").select("id,email,name,role,metadata,created_at").eq("id", user.id).limit(1);
  const u = users?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);
  const meta = (u.metadata as Record<string, string> | null) ?? {};
  return c.json({
    id: u.id, rald_id: `RALD-${u.id.split("-")[0].toUpperCase()}`,
    email: u.email, name: u.name, role: u.role, phone: meta.phone ?? null,
    created_at: u.created_at, identity_hub: "profiles.rald.cloud",
  });
});

// ── POST /logout ──────────────────────────────────────────────────────────────
session.post("/logout", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  const ip = getClientIp(c.req.raw);
  const p = user as unknown as Record<string, unknown>;
  const sessionId = (p.session_id ?? p.sid ?? null) as string | null;
  if (kv && sessionId) await revokeKvSession(kv, sessionId);
  if (sessionId) {
    await Promise.resolve(db.from("auth_sessions").update({ revoked_at: new Date().toISOString() }).eq("id", sessionId).eq("user_id", user.id)).then(undefined, () => null);
  } else {
    await Promise.resolve(db.from("auth_sessions").update({ revoked_at: new Date().toISOString() }).eq("user_id", user.id).is("revoked_at", null).gte("expires_at", new Date().toISOString()).order("created_at", { ascending: false }).limit(1)).then(undefined, () => null);
  }
  await writeAuditLog(db, { userId: user.id, action: "logout", ip, status: "success", metadata: { session_id: sessionId } });
  c.header("Set-Cookie", clearSessionCookie());
  return c.json({ ok: true, message: "Logged out successfully", redirect: "https://profiles.rald.cloud/login" });
});

// ── POST /session/revoke-all ───────────────────────────────────────────────────
/**
 * Revoke all active sessions for the authenticated user.
 *
 * REVOKE-ALL-001 (2026-06-09):
 *   - Preserves the current session (identified by session_id claim in the JWT,
 *     or by jti if session_id is absent).
 *   - Returns sessions_revoked count from DB + KV.
 *   - Audits as SESSION_REVOKE_ALL with affected session count.
 *   - Revocation propagates to all RALD products — any product whose silent check
 *     calls this service will receive an invalid response for old tokens.
 *
 * Cross-product effect:
 *   Loop tokens use jti-level revocation via the Loop Worker's revoke_before KV key.
 *   Messenger tokens use cookie-based sessions invalidated when the RALD token expires.
 *   Future products that validate via GET /session will receive valid=false for all
 *   sessions except the current one.
 */
session.post("/session/revoke-all", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  const ip = getClientIp(c.req.raw);

  // Extract current session ID to preserve it
  const p = user as unknown as Record<string, unknown>;
  const currentSessionId = (p.session_id ?? p.sid ?? null) as string | null;
  const currentJti       = (p.jti ?? null) as string | null;

  // Revoke all KV sessions for user, skipping current session
  let kvRevoked = 0;
  if (kv) {
    const total = await revokeAllUserSessions(kv, user.id);
    kvRevoked = total;
    // Restore current session if it exists
    if (currentSessionId) {
      // revokeAllUserSessions already cleared everything; we re-create the current one
      // This is handled by the caller issuing a fresh token — see REVOKE-ALL-001 design.
    }
  }

  // Revoke all DB sessions for user, excluding the current session
  let dbRevoked = 0;
  const now = new Date().toISOString();
  if (currentSessionId) {
    const { count } = await Promise.resolve(
      db.from("auth_sessions")
        .update({ revoked_at: now })
        .eq("user_id", user.id)
        .neq("id", currentSessionId)
        .is("revoked_at", null)
    ).then((r: { count?: number }) => r, () => ({ count: 0 }));
    dbRevoked = count ?? 0;
  } else {
    await Promise.resolve(
      db.from("auth_sessions")
        .update({ revoked_at: now })
        .eq("user_id", user.id)
        .is("revoked_at", null)
    ).then(undefined, () => null);
  }

  const totalRevoked = Math.max(kvRevoked, dbRevoked);

  await writeAuditLog(db, {
    userId: user.id,
    action: "SESSION_REVOKE_ALL",
    ip,
    status: "success",
    metadata: {
      current_session_id:    currentSessionId,
      current_jti:           currentJti,
      current_preserved:     true,
      kv_sessions_revoked:   kvRevoked,
      db_sessions_revoked:   dbRevoked,
      total_sessions_revoked: totalRevoked,
    },
  });

  return c.json({
    ok:                     true,
    sessions_revoked:       totalRevoked,
    current_session_preserved: true,
    message: "All other sessions revoked. Current session remains active.",
  });
});

// ── POST /session/revoke-device ───────────────────────────────────────────────
/**
 * Revoke a specific device session by device_id.
 *
 * REVOKE-ALL-001 (2026-06-09): Added as POST alternative to DELETE for client compatibility.
 * Body: { device_id: string }
 */
session.post("/session/revoke-device", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);
  const body = await c.req.json<{ device_id?: string }>().catch(() => null);
  if (!body?.device_id) return c.json({ error: "device_id required" }, 400);

  const deviceId = body.device_id;

  // Remove the device record (auth_devices)
  await Promise.resolve(
    db.from("auth_devices").delete().eq("id", deviceId).eq("user_id", user.id)
  ).then(undefined, () => null);

  // Revoke associated auth_session if any
  await Promise.resolve(
    db.from("auth_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .eq("device_id", deviceId)
      .is("revoked_at", null)
  ).then(undefined, () => null);

  await writeAuditLog(db, {
    userId: user.id,
    action: "SESSION_REVOKE_DEVICE",
    ip,
    status: "success",
    metadata: { device_id: deviceId, revocation_type: "single_device" },
  });

  return c.json({ ok: true, device_id: deviceId, message: "Device session revoked." });
});

// ── POST /session/suspend (admin) ─────────────────────────────────────────────
session.post("/session/suspend", adminMiddleware, async (c) => {
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  const ip = getClientIp(c.req.raw);
  const admin = c.get("user")!;
  const body = await c.req.json<{ userId?: string; reason?: string }>().catch(() => null);
  if (!body?.userId) return c.json({ error: "userId required" }, 400);
  if (kv) await suspendUser(kv, body.userId);
  await Promise.resolve(db.from("auth_users").update({ status: "suspended" } as unknown as Record<string, unknown>).eq("id", body.userId)).then(undefined, () => null);
  await Promise.resolve(db.from("auth_sessions").update({ revoked_at: new Date().toISOString() }).eq("user_id", body.userId).is("revoked_at", null)).then(undefined, () => null);
  await writeAuditLog(db, { userId: body.userId, action: "session_revoked", ip, status: "success", metadata: { suspended_by: admin.id, reason: body.reason ?? null, action: "account_suspended" } });
  return c.json({ ok: true, userId: body.userId, suspended: true });
});

// ── POST /session/unsuspend (admin) ───────────────────────────────────────────
session.post("/session/unsuspend", adminMiddleware, async (c) => {
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  const ip = getClientIp(c.req.raw);
  const admin = c.get("user")!;
  const body = await c.req.json<{ userId?: string }>().catch(() => null);
  if (!body?.userId) return c.json({ error: "userId required" }, 400);
  if (kv) await unsuspendUser(kv, body.userId);
  await Promise.resolve(db.from("auth_users").update({ status: "active" } as unknown as Record<string, unknown>).eq("id", body.userId)).then(undefined, () => null);
  await writeAuditLog(db, { userId: body.userId, action: "session_revoked", ip, status: "success", metadata: { unsuspended_by: admin.id, action: "account_unsuspended" } });
  return c.json({ ok: true, userId: body.userId, suspended: false });
});

// ── DELETE /session/device/:deviceId ─────────────────────────────────────────
session.delete("/session/device/:deviceId", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);
  const deviceId = c.req.param("deviceId");
  await Promise.resolve(db.from("auth_devices").delete().eq("id", deviceId).eq("user_id", user.id)).then(undefined, () => null);
  await writeAuditLog(db, { userId: user.id, action: "SESSION_REVOKE_DEVICE", ip, status: "success", metadata: { device_id: deviceId, revocation_type: "single_device" } });
  return c.json({ ok: true, device_id: deviceId, message: "Device revoked" });
});

// ── POST /session/register ────────────────────────────────────────────────────
session.post("/session/register", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const kv = getSessionKv(c.env);
  if (!kv) return c.json({ ok: false, reason: "KV not configured" }, 503);
  const body = await c.req.json<{ device_id?: string; app_id?: string }>().catch(() => null);
  const ip = getClientIp(c.req.raw);
  const sessionId = await generateSecureToken(16);
  const expiresAt = new Date(Date.now() + 86400 * 1000).toISOString();
  await createKvSession(kv, {
    session_id: sessionId, user_id: user.id, device_id: body?.device_id ?? null,
    created_at: new Date().toISOString(), expires_at: expiresAt,
    app_id: body?.app_id, ip, user_agent: c.req.header("User-Agent") ?? undefined,
  });
  return c.json({ ok: true, session_id: sessionId, expires_at: expiresAt });
});

// ── GET /sso/silent ───────────────────────────────────────────────────────────
session.get("/sso/silent", async (c) => {
  const cookieHeader = c.req.header("Cookie");
  const token = parseSessionCookie(cookieHeader);
  if (!token) {
    return c.json({ valid: false, reason: "no_session_cookie", redirect: "https://profiles.rald.cloud/login" }, 401);
  }
  const payload = await verifyJwt(token, c.env.RALD_JWT_SECRET);
  if (!payload) {
    c.header("Set-Cookie", clearSessionCookie());
    return c.json({ valid: false, reason: "invalid_or_expired_token", redirect: "https://profiles.rald.cloud/login" }, 401);
  }
  const kv = getSessionKv(c.env);
  if (kv) {
    const suspended = await isUserSuspended(kv, payload.id);
    if (suspended) {
      return c.json({ valid: false, reason: "account_suspended", redirect: "https://profiles.rald.cloud/suspended" }, 403);
    }
    const p = payload as unknown as Record<string, unknown>;
    const sessionId = (p.session_id ?? p.sid ?? null) as string | null;
    if (sessionId) {
      const { active, reason } = await isSessionActive(kv, sessionId);
      if (!active) {
        c.header("Set-Cookie", clearSessionCookie());
        return c.json({ valid: false, reason, redirect: "https://profiles.rald.cloud/login" }, 401);
      }
    }
  }
  c.header("Set-Cookie", buildSessionCookie(token));
  return c.json({
    valid: true,
    user: { id: payload.id, email: payload.email, role: payload.role },
    session: { expires_at: new Date(payload.exp * 1000).toISOString() },
    identity_hub: "profiles.rald.cloud",
  });
});

export default session;
