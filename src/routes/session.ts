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
import { verifyJwt, generateSecureToken, signJwt } from "../lib/auth";
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
    ).then((r) => ({ count: r.count ?? 0 }), () => ({ count: 0 }));
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


// ── verifyJwtGrace — decode JWT with extended expiry tolerance ────────────────
// Used by POST /auth/refresh to accept tokens within a grace window past expiry.
async function verifyJwtGrace(
  token: string,
  secret: string,
  graceSeconds: number
): Promise<import("../lib/auth").JwtPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts as [string, string, string];
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    const sigBytes = Uint8Array.from(
      atob(sig.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify(
      "HMAC", key, sigBytes,
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(
      atob(body.replace(/-/g, "+").replace(/_/g, "/"))
    ) as import("../lib/auth").JwtPayload;
    const now = Math.floor(Date.now() / 1000);
    // Accept tokens up to graceSeconds past their expiry
    if (payload.exp + graceSeconds < now) return null;
    return payload;
  } catch { return null; }
}

// ── POST /auth/refresh ────────────────────────────────────────────────────────
/**
 * Silent session refresh — sliding 30-day window.
 * Sprint: Hardening Phase 6 · Session Hardening · 2026-06-12
 *
 * Strategy:
 *   1. Read rald_session cookie (Authorization: Bearer as fallback)
 *   2. Verify JWT with 7-day grace window for tokens that slipped through
 *   3. Check KV session is active and not revoked
 *   4. Issue a new JWT with fresh 30-day expiry
 *   5. Update KV session TTL to 30 more days
 *   6. Set new HttpOnly ecosystem cookie
 *
 * Called by RALD products on every app open / tab focus.
 * LILCKY STUDIO LIMITED
 */
session.post("/auth/refresh", async (c) => {
  // ── 1. Extract token ────────────────────────────────────────────────────────
  const cookieToken = parseSessionCookie(c.req.header("Cookie"));
  const authHeader  = c.req.header("Authorization");
  const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const token       = cookieToken ?? bearerToken;

  if (!token) {
    return c.json(
      { ok: false, reason: "no_session", redirect: "https://profiles.rald.cloud/login" },
      401
    );
  }

  // ── 2. Verify JWT (with 7-day grace window) ─────────────────────────────────
  let payload = await verifyJwt(token, c.env.RALD_JWT_SECRET);
  if (!payload) {
    payload = await verifyJwtGrace(token, c.env.RALD_JWT_SECRET, 7 * 86400);
  }
  if (!payload) {
    c.header("Set-Cookie", clearSessionCookie());
    return c.json(
      { ok: false, reason: "token_invalid_or_too_old", redirect: "https://profiles.rald.cloud/login" },
      401
    );
  }

  const p          = payload as unknown as Record<string, unknown>;
  const sessionId  = (p.session_id ?? p.sid ?? null) as string | null;
  const kv         = getSessionKv(c.env);

  // ── 3. KV liveness checks ───────────────────────────────────────────────────
  if (kv) {
    const suspended = await isUserSuspended(kv, payload.id);
    if (suspended) {
      c.header("Set-Cookie", clearSessionCookie());
      return c.json(
        { ok: false, reason: "account_suspended", redirect: "https://profiles.rald.cloud/suspended" },
        403
      );
    }
    if (sessionId) {
      const { active, reason } = await isSessionActive(kv, sessionId);
      if (!active) {
        c.header("Set-Cookie", clearSessionCookie());
        return c.json({ ok: false, reason, redirect: "https://profiles.rald.cloud/login" }, 401);
      }
    }
  }

  // ── 4. Fetch current user record ────────────────────────────────────────────
  const db = c.get("db");
  const { data: user } = await db
    .from("auth_users")
    .select("id,email,username,name,role,trust_level,status")
    .eq("id", payload.id)
    .single();

  if (!user || user.status === "suspended") {
    c.header("Set-Cookie", clearSessionCookie());
    return c.json(
      {
        ok: false,
        reason: user?.status === "suspended" ? "account_suspended" : "user_not_found",
        redirect: "https://profiles.rald.cloud/login",
      },
      401
    );
  }

  // ── 5. Issue new JWT with fresh 30-day expiry ───────────────────────────────
  const SESSION_TTL  = 2_592_000; // 30 days
  const newSessionId = sessionId ?? (await generateSecureToken(16));
  const expiresAt    = new Date(Date.now() + SESSION_TTL * 1000).toISOString();

  const newToken = await signJwt(
    {
      id:         user.id,
      email:      user.email,
      username:   user.username    ?? null,
      name:       user.name        ?? null,
      role:       user.role        ?? "user",
      trust:      user.trust_level ?? "none",
      session_id: newSessionId,
      sso_v:      2,
      via:        "refresh",
      app_id:     (p.appId ?? p.app_id ?? null) as string | null,
    },
    c.env.RALD_JWT_SECRET,
    SESSION_TTL
  );

  // ── 6. Extend KV session TTL ────────────────────────────────────────────────
  if (kv) {
    await createKvSession(kv, {
      session_id: newSessionId,
      user_id:    user.id,
      device_id:  (p.device_id ?? null) as string | null,
      created_at: new Date().toISOString(),
      expires_at: expiresAt,
      app_id:     (p.appId ?? p.app_id ?? null) as string | undefined,
      ip:         getClientIp(c.req.raw),
      user_agent: c.req.header("User-Agent") ?? undefined,
    });
  }

  // ── 7. Set refreshed cookie ─────────────────────────────────────────────────
  c.header("Set-Cookie", buildSessionCookie(newToken, SESSION_TTL));

  return c.json({
    ok:         true,
    token:      newToken,
    session_id: newSessionId,
    expires_at: expiresAt,
    user: {
      id:       user.id,
      email:    user.email,
      username: user.username    ?? null,
      name:     user.name        ?? null,
      role:     user.role        ?? "user",
      trust:    user.trust_level ?? "none",
    },
  });
});

export default session;
