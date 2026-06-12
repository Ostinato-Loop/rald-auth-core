// RALD Auth Core — Machine Identity Routes
// Sprint: Hardening Phase 5 + Operator Platform Phase 9 · 2026-06-12
// Admin-provisioned machine identities for each RALD service.
// Enables service-to-service auth without sharing RALD_JWT_SECRET.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";
import { signJwt } from "../lib/auth";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const machine = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const PREFIX = "mid_";
const KEY_TTL = 86400 * 90; // 90 days default rotation window

async function generateMachineKey(): Promise<{ keyId: string; secret: string; keyHash: string; keySalt: string }> {
  const keyId = `${PREFIX}${generateId(8)}`;
  const secret = generateId(32);
  const salt = generateId(16);
  const keyHash = await sha256(`${secret}:${salt}`);
  return { keyId, secret, keyHash, keySalt: salt };
}

function generateId(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── GET /machine/identities — list all (admin only) ───────────────────────────
machine.get("/machine/identities", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data, error } = await db
    .from("machine_identities")
    .select("id,service_name,display_name,status,scopes,allowed_services,last_rotated_at,rotation_due_at,created_at")
    .order("service_name");
  if (error) return c.json({ error: "Failed to fetch machine identities" }, 500);
  return c.json({ identities: data ?? [], count: data?.length ?? 0 });
});

// ── GET /machine/identities/rotation-alerts — services due for rotation ────────
machine.get("/machine/identities/rotation-alerts", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data, error } = await db.from("machine_identity_rotation_alerts").select("*");
  if (error) return c.json({ error: "Failed to fetch rotation alerts" }, 500);
  return c.json({ alerts: data ?? [] });
});

// ── POST /machine/identities — provision a new machine identity ───────────────
machine.post("/machine/identities", adminMiddleware, async (c) => {
  const db = c.get("db");
  const admin = c.get("user")!;
  const ip = getClientIp(c.req.raw);
  const body = await c.req.json<{
    service_name:    string;
    display_name:    string;
    description?:    string;
    scopes?:         string[];
    allowed_services?: string[];
    environment?:    string;
  }>().catch(() => null);
  if (!body?.service_name || !body.display_name) {
    return c.json({ error: "service_name and display_name are required" }, 400);
  }
  const { keyId, secret, keyHash, keySalt } = await generateMachineKey();
  const rotationDue = new Date(Date.now() + KEY_TTL * 1000).toISOString();
  const { data, error } = await db.from("machine_identities").upsert({
    service_name:    body.service_name,
    display_name:    body.display_name,
    description:     body.description ?? "",
    environment:     body.environment ?? "production",
    key_id:          keyId,
    key_hash:        keyHash,
    key_salt:        keySalt,
    scopes:          body.scopes ?? [],
    allowed_services: body.allowed_services ?? [],
    status:          "active",
    created_by:      admin.id,
    last_rotated_at: new Date().toISOString(),
    rotation_due_at: rotationDue,
  }, { onConflict: "service_name" }).select("id,service_name,display_name,status,scopes,rotation_due_at,created_at").single();
  if (error) return c.json({ error: "Failed to provision machine identity" }, 500);
  await writeAuditLog(db, {
    userId: admin.id, action: "machine_identity.provisioned", ip, status: "success",
    metadata: { service_name: body.service_name, key_id: keyId, rotation_due: rotationDue },
  });
  // Return the secret ONCE — it is never stored in plaintext
  return c.json({ ...data, key_id: keyId, secret: `${keyId}:${secret}`, rotation_due_at: rotationDue,
    _warning: "Store this secret securely. It will not be shown again." }, 201);
});

// ── POST /machine/identities/:id/rotate — rotate machine identity key ─────────
machine.post("/machine/identities/:id/rotate", adminMiddleware, async (c) => {
  const db = c.get("db");
  const admin = c.get("user")!;
  const ip = getClientIp(c.req.raw);
  const id = c.req.param("id");
  const { keyId, secret, keyHash, keySalt } = await generateMachineKey();
  const rotationDue = new Date(Date.now() + KEY_TTL * 1000).toISOString();
  const { data, error } = await db.from("machine_identities")
    .update({ key_id: keyId, key_hash: keyHash, key_salt: keySalt, last_rotated_at: new Date().toISOString(), rotation_due_at: rotationDue })
    .eq("id", id).select("service_name").single();
  if (error || !data) return c.json({ error: "Machine identity not found" }, 404);
  await db.from("machine_identity_audit_log").insert({ identity_id: id, action: "rotated", ip, metadata: { rotated_by: admin.id, new_key_id: keyId } });
  await writeAuditLog(db, { userId: admin.id, action: "machine_identity.rotated", ip, status: "success", metadata: { service_name: data.service_name, new_key_id: keyId } });
  return c.json({ ok: true, service_name: data.service_name, key_id: keyId, secret: `${keyId}:${secret}`, rotation_due_at: rotationDue,
    _warning: "Store this secret securely. It will not be shown again." });
});

// ── POST /machine/auth — authenticate using machine identity ──────────────────
// Used by services to exchange their machine key for a scoped JWT
machine.post("/machine/auth", async (c) => {
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);
  const body = await c.req.json<{ key_id?: string; secret?: string }>().catch(() => null);
  if (!body?.key_id || !body.secret) return c.json({ error: "key_id and secret are required" }, 400);
  // Extract service from key_id:secret format
  const fullSecret = body.secret.includes(":") ? body.secret.split(":").slice(1).join(":") : body.secret;
  const { data: identity } = await db.from("machine_identities")
    .select("*").eq("key_id", body.key_id).eq("status", "active").single();
  if (!identity) {
    await db.from("machine_identity_audit_log").insert({ identity_id: "00000000-0000-0000-0000-000000000000", action: "auth_failed", ip, metadata: { key_id: body.key_id, reason: "not_found" } });
    return c.json({ error: "Invalid credentials" }, 401);
  }
  // Verify hash
  const expectedHash = await sha256(`${fullSecret}:${identity.key_salt}`);
  if (expectedHash !== identity.key_hash) {
    await db.from("machine_identity_audit_log").insert({ identity_id: identity.id, action: "auth_failed", ip, metadata: { reason: "invalid_secret" } });
    return c.json({ error: "Invalid credentials" }, 401);
  }
  // Issue scoped machine JWT (1 hour TTL — short-lived for machine tokens)
  const token = await signJwt(
    { sub: identity.service_name, service: identity.service_name, type: "machine", scopes: identity.scopes, allowed_services: identity.allowed_services },
    c.env.RALD_JWT_SECRET,
    3600
  );
  await db.from("machine_identity_audit_log").insert({ identity_id: identity.id, action: "auth_success", ip, metadata: { service: identity.service_name } });
  return c.json({ ok: true, token, service: identity.service_name, scopes: identity.scopes, expires_in: 3600 });
});

// ── DELETE /machine/identities/:id — revoke ────────────────────────────────────
machine.delete("/machine/identities/:id", adminMiddleware, async (c) => {
  const db = c.get("db");
  const admin = c.get("user")!;
  const ip = getClientIp(c.req.raw);
  const id = c.req.param("id");
  const { data } = await db.from("machine_identities").update({ status: "revoked", revoked_at: new Date().toISOString() }).eq("id", id).select("service_name").single();
  await writeAuditLog(db, { userId: admin.id, action: "machine_identity.revoked", ip, status: "success", metadata: { identity_id: id, service_name: data?.service_name } });
  return c.json({ ok: true, id, revoked: true });
});

export default machine;
