// RALD Auth Core — Ecosystem Session Broker
// Phase G.10: GET /session · GET /me · POST /logout · POST /session/revoke-all · POST /session/suspend
// Fix: PostgrestFilterBuilder is PromiseLike (not Promise) — use Promise.resolve().then(undefined, fn) not .catch()
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { verifyJwt, generateSecureToken } from "../lib/auth";
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

// ── GET /session — ECOSYSTEM SESSION VALIDATOR ────────────────────────────────
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
  return c.json({ ok: true, message: "Logged out successfully", redirect: "https://profiles.rald.cloud/login" });
});

// ── POST /session/revoke-all ───────────────────────────────────────────────────
session.post("/session/revoke-all", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const kv = getSessionKv(c.env);
  const ip = getClientIp(c.req.raw);
  const kvCount = kv ? await revokeAllUserSessions(kv, user.id) : 0;
  await Promise.resolve(db.from("auth_sessions").update({ revoked_at: new Date().toISOString() }).eq("user_id", user.id).is("revoked_at", null)).then(undefined, () => null);
  await writeAuditLog(db, { userId: user.id, action: "all_sessions_revoked", ip, status: "success", metadata: { kv_sessions_revoked: kvCount } });
  return c.json({ ok: true, message: "All sessions revoked across all devices and applications", kv_sessions_revoked: kvCount });
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
  await writeAuditLog(db, { userId: user.id, action: "session_revoked", ip, status: "success", metadata: { device_id: deviceId, action: "device_revoked" } });
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

export default session;
