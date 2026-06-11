// RALD Auth Core — Admin Username Console (Phase 4)
// GET  /admin/usernames              — search/list usernames by status
// POST /admin/usernames/reserve      — reserve a username (RESERVED status)
// POST /admin/usernames/release      — release back to AVAILABLE
// POST /admin/usernames/transfer     — transfer username to another user
// POST /admin/usernames/protect      — mark PROTECTED (blocks all claims)
// POST /admin/usernames/premium      — mark PREMIUM (future marketplace)
// POST /admin/usernames/recover      — pull into ADMIN_HELD
// POST /admin/usernames/bulk-reserve — reserve a list of usernames
//
// All routes require admin role.
// RALD AUTH EMERGENCY STABILIZATION SPRINT — Phase 4
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const adminUsername = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// All routes require admin auth
adminUsername.use("*", adminMiddleware);

type UsernameStatus =
  | "AVAILABLE"
  | "RESERVED"
  | "CLAIMED"
  | "PROTECTED"
  | "PREMIUM"
  | "ADMIN_HELD";

// ── GET /admin/usernames — search & list ──────────────────────────────────────
adminUsername.get("/", async (c) => {
  const db     = c.get("db");
  const q      = c.req.query("q");
  const status = c.req.query("status") as UsernameStatus | undefined;
  const limit  = Math.min(Number.parseInt(c.req.query("limit") ?? "50", 10), 200);
  const offset = Number.parseInt(c.req.query("offset") ?? "0", 10);

  let query = db
    .from("usernames")
    .select("username, status, user_id, reserved_by, reserved_until, released_at, claimed_at, created_at, active")
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (status) query = query.eq("status", status);
  if (q)      query = query.ilike("username", `%${q}%`);

  const { data, error, count } = await query;
  if (error) return c.json({ error: "Failed to query usernames", detail: error.message }, 500);

  return c.json({ usernames: data ?? [], count, offset, limit });
});

// ── POST /admin/usernames/reserve ─────────────────────────────────────────────
adminUsername.post("/reserve", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{
    username:         string;
    reason?:          string;
    reserved_until?:  string; // ISO8601 — null = indefinite
  }>().catch(() => null);

  if (!body?.username) return c.json({ error: "username is required" }, 400);
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  // Check current state
  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];

  if (row?.status === "CLAIMED") {
    return c.json({ error: `@${lower} is currently CLAIMED. Use /transfer or /recover instead.` }, 409);
  }

  const now = new Date().toISOString();

  if (row) {
    await db.from("usernames").update({
      status:         "RESERVED",
      reserved_by:    admin.id,
      reserved_until: body.reserved_until ?? null,
      active:         false,
    }).eq("username", lower);
  } else {
    await db.from("usernames").insert({
      username:       lower,
      status:         "RESERVED",
      reserved_by:    admin.id,
      reserved_until: body.reserved_until ?? null,
      active:         false,
      created_at:     now,
      claimed_at:     null,
    });
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_reserve",
    ip,
    status:   "success",
    metadata: { username: lower, reason: body.reason ?? null, reserved_until: body.reserved_until ?? null },
  });

  return c.json({
    ok:       true,
    username: lower,
    status:   "RESERVED",
    reserved_by:    admin.id,
    reserved_until: body.reserved_until ?? null,
    message:  `@${lower} is now RESERVED.`,
  });
});

// ── POST /admin/usernames/release ─────────────────────────────────────────────
adminUsername.post("/release", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{ username: string; reason?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];
  if (!row) return c.json({ error: `@${lower} not found in registry.` }, 404);

  if (row.status === "CLAIMED") {
    return c.json({ error: `@${lower} is CLAIMED by a user. Recover it first.` }, 409);
  }

  await db.from("usernames").update({
    status:         "AVAILABLE",
    user_id:        null,
    reserved_by:    null,
    reserved_until: null,
    released_at:    new Date().toISOString(),
    active:         false,
  }).eq("username", lower);

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_release",
    ip,
    status:   "success",
    metadata: { username: lower, previous_status: row.status, reason: body.reason ?? null },
  });

  return c.json({
    ok:      true,
    username: lower,
    status:  "AVAILABLE",
    message: `@${lower} is now AVAILABLE for anyone to claim.`,
  });
});

// ── POST /admin/usernames/transfer ────────────────────────────────────────────
adminUsername.post("/transfer", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{
    username:        string;
    to_user_id:      string;
    reason?:         string;
  }>().catch(() => null);

  if (!body?.username || !body?.to_user_id) {
    return c.json({ error: "username and to_user_id are required" }, 400);
  }
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  // Verify target user exists
  const { data: targetUsers } = await db
    .from("auth_users")
    .select("id, username, name")
    .eq("id", body.to_user_id)
    .limit(1);

  const target = targetUsers?.[0];
  if (!target) return c.json({ error: "Target user not found." }, 404);

  // Get current username row
  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];
  const oldUserId = row?.user_id ?? null;

  // Release old owner's claim (if any)
  if (oldUserId && oldUserId !== body.to_user_id) {
    await db.from("auth_users")
      .update({ username: null, username_set_at: null })
      .eq("id", oldUserId)
      .eq("username", lower)
      .then(() => null, () => null);
  }

  // Transfer
  await db.from("usernames").upsert({
    username:   lower,
    user_id:    body.to_user_id,
    status:     "CLAIMED",
    active:     true,
    claimed_at: new Date().toISOString(),
  }, { onConflict: "username" });

  await db.from("auth_users").update({
    username:        lower,
    username_set_at: new Date().toISOString(),
  }).eq("id", body.to_user_id);

  // History
  if (oldUserId) {
    await db.from("username_history").insert([
      { user_id: oldUserId,       username: lower, action: "admin_revoked" },
      { user_id: body.to_user_id, username: lower, action: "admin_transferred" },
    ]).then(() => null, () => null);
  } else {
    await db.from("username_history").insert({
      user_id: body.to_user_id, username: lower, action: "admin_transferred",
    }).then(() => null, () => null);
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_transfer",
    ip,
    status:   "success",
    metadata: {
      username:     lower,
      from_user_id: oldUserId,
      to_user_id:   body.to_user_id,
      reason:       body.reason ?? null,
    },
  });

  return c.json({
    ok:          true,
    username:    lower,
    status:      "CLAIMED",
    transferred_to: body.to_user_id,
    transferred_from: oldUserId ?? null,
    message:     `@${lower} transferred to user ${body.to_user_id}.`,
  });
});

// ── POST /admin/usernames/protect ─────────────────────────────────────────────
adminUsername.post("/protect", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{ username: string; reason?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];

  if (row) {
    await db.from("usernames").update({ status: "PROTECTED", active: false }).eq("username", lower);
  } else {
    await db.from("usernames").insert({
      username: lower, status: "PROTECTED", active: false, created_at: new Date().toISOString(),
    });
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_protect",
    ip,
    status:   "success",
    metadata: { username: lower, reason: body.reason ?? null },
  });

  return c.json({
    ok:      true,
    username: lower,
    status:  "PROTECTED",
    message: `@${lower} is now PROTECTED. It cannot be claimed by any user.`,
  });
});

// ── POST /admin/usernames/premium ─────────────────────────────────────────────
// Architecture-only: marks username PREMIUM (future marketplace).
// Does NOT build marketplace. Only creates the status record.
adminUsername.post("/premium", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{
    username:            string;
    reason?:             string;
    estimated_price_usd?: number;
  }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  const { data: existing } = await db
    .from("usernames")
    .select("username, status")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];
  if (row?.status === "CLAIMED") {
    return c.json({ error: `@${lower} is currently CLAIMED. Recover it first.` }, 409);
  }

  if (row) {
    await db.from("usernames").update({ status: "PREMIUM", active: false }).eq("username", lower);
  } else {
    await db.from("usernames").insert({
      username: lower, status: "PREMIUM", active: false, created_at: new Date().toISOString(),
    });
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_premium",
    ip,
    status:   "success",
    metadata: {
      username:             lower,
      reason:               body.reason ?? null,
      estimated_price_usd:  body.estimated_price_usd ?? null,
      note:                 "Marketplace not yet built — architecture only.",
    },
  });

  return c.json({
    ok:       true,
    username: lower,
    status:   "PREMIUM",
    message:  `@${lower} is now PREMIUM. Marketplace architecture registered.`,
    marketplace: "not_yet_built",
  });
});

// ── POST /admin/usernames/recover ─────────────────────────────────────────────
// Pull a claimed username back into ADMIN_HELD (revokes from user).
adminUsername.post("/recover", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{ username: string; reason: string }>().catch(() => null);
  if (!body?.username || !body?.reason) {
    return c.json({ error: "username and reason are required for recovery" }, 400);
  }
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];
  const previousOwner = row?.user_id ?? null;

  // Revoke from current owner in auth_users
  if (previousOwner) {
    await db.from("auth_users")
      .update({ username: null, username_set_at: null })
      .eq("id", previousOwner)
      .eq("username", lower)
      .then(() => null, () => null);

    await db.from("username_history").insert({
      user_id: previousOwner, username: lower, action: "admin_recovered",
    }).then(() => null, () => null);
  }

  if (row) {
    await db.from("usernames").update({
      status:      "ADMIN_HELD",
      user_id:     null,
      active:      false,
      released_at: new Date().toISOString(),
    }).eq("username", lower);
  } else {
    await db.from("usernames").insert({
      username: lower, status: "ADMIN_HELD", active: false, created_at: new Date().toISOString(),
    });
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_recover",
    ip,
    status:   "success",
    metadata: { username: lower, previous_owner: previousOwner, reason: body.reason },
  });

  return c.json({
    ok:             true,
    username:       lower,
    status:         "ADMIN_HELD",
    previous_owner: previousOwner,
    message:        `@${lower} recovered. Previous owner's claim revoked. Reason: ${body.reason}`,
  });
});

// ── POST /admin/usernames/bulk-reserve ────────────────────────────────────────
adminUsername.post("/bulk-reserve", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{
    usernames: string[];
    reason?:   string;
  }>().catch(() => null);

  if (!body?.usernames?.length) {
    return c.json({ error: "usernames array is required" }, 400);
  }
  if (body.usernames.length > 100) {
    return c.json({ error: "Maximum 100 usernames per bulk operation" }, 400);
  }

  const normalized = body.usernames.map(u => u.toLowerCase().trim().replace(/^@/, ""));
  const now = new Date().toISOString();

  const rows = normalized.map(username => ({
    username,
    status:      "RESERVED",
    reserved_by: admin.id,
    active:      false,
    created_at:  now,
  }));

  const { data, error } = await db
    .from("usernames")
    .upsert(rows, { onConflict: "username", ignoreDuplicates: false });

  if (error) {
    console.error("[admin-username] bulk-reserve error:", error.message);
    return c.json({ error: "Bulk reserve partially failed", detail: error.message }, 500);
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "admin_username_bulk_reserve",
    ip,
    status:   "success",
    metadata: { count: normalized.length, usernames: normalized, reason: body.reason ?? null },
  });

  return c.json({
    ok:       true,
    reserved: normalized,
    count:    normalized.length,
    status:   "RESERVED",
    message:  `${normalized.length} username(s) reserved.`,
  });
});

export default adminUsername;
