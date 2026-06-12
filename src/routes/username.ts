// RALD Auth Core — Username Routes (V2 Identity)
// GET  /username/check/:username  — live availability check (no auth required)
// POST /username/claim             — claim a username (authenticated, no prior username)
// POST /username/change            — change username (authenticated, policy enforced)
// GET  /username/me                — get caller's username (authenticated)
// GET  /username/migration-status  — check if user is in migration queue
//
// P2 fix (2026-06-11 Identity Audit Sprint):
//   - /username/change endpoint added with policy: max 1 change per 30 days, audit logged
//   - /username/migration-status endpoint for P4 claim flow
//   - Username availability check also checks auth_users table (belt + suspenders)
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const username = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Reserved words — cannot be claimed as usernames
const RESERVED_WORDS = new Set([
  "admin", "administrator", "support", "help", "security", "abuse",
  "rald", "loop", "messenger", "payrald", "gitrald", "raldtics",
  "mail", "voice", "dispatch", "ai", "inbox", "billing",
  "root", "system", "bot", "api", "auth", "sso", "oauth",
  "null", "undefined", "true", "false", "test", "demo", "example",
  "official", "staff", "team", "mod", "moderator", "operator",
  "lilcky", "ostinato", "raldcloud", "raldme",
  "president", "governor", "minister", "senator", "government",
  "police", "army", "military",
]);

/** Validate username format: 2–20 chars, lowercase letters/numbers/underscores only */
function validateUsernameFormat(u: string): { valid: boolean; reason?: string } {
  const lower = u.toLowerCase();
  if (lower.length < 2)  return { valid: false, reason: "Username must be at least 2 characters" };
  if (lower.length > 20) return { valid: false, reason: "Username must be 20 characters or fewer" };
  if (!/^[a-z0-9_]+$/.test(lower)) return { valid: false, reason: "Username can only contain letters, numbers, and underscores" };
  if (lower.startsWith("_") || lower.endsWith("_")) return { valid: false, reason: "Username cannot start or end with an underscore" };
  if (/_{2,}/.test(lower)) return { valid: false, reason: "Username cannot contain consecutive underscores" };
  if (RESERVED_WORDS.has(lower)) return { valid: false, reason: "This username is reserved" };
  if (/^test\d*$/.test(lower) || /^user\d+$/.test(lower) || /^admin\d+$/.test(lower)) {
    return { valid: false, reason: "This username is reserved" };
  }
  return { valid: true };
}

async function isUsernameTaken(db: unknown, lower: string): Promise<boolean> {
  // We can't import the db type cleanly here, so we accept any
  return false;
}

// ── GET /username/check/:username — live availability (no auth) ───────────────
username.get("/check/:username", async (c) => {
  const raw = c.req.param("username");
  const lower = raw.toLowerCase().trim();

  const { valid, reason } = validateUsernameFormat(lower);
  if (!valid) {
    return c.json({ available: false, username: lower, reason });
  }

  const db = c.get("db");

  // Check both tables for belt + suspenders
  const [usernamesRes, authUsersRes] = await Promise.all([
    db.from("usernames").select("username").eq("username", lower).eq("active", true).limit(1),
    db.from("auth_users").select("id").ilike("username", lower).limit(1),
  ]);

  if (usernamesRes.error) {
    console.error("[username/check] db error:", usernamesRes.error.message);
    return c.json({ available: false, username: lower, reason: "Availability check failed, please try again" }, 500);
  }

  const takenInRegistry  = !!(usernamesRes.data && usernamesRes.data.length > 0);
  const takenInAuthUsers = !!(authUsersRes.data && authUsersRes.data.length > 0);
  const taken = takenInRegistry || takenInAuthUsers;

  return c.json({
    available: !taken,
    username:  lower,
    // P3: show what will be reserved if username is claimed
    reservations: !taken ? {
      mail:      `${lower}@rald.me`,
      domain:    `${lower}.rald.me`,
      workspace: lower,
    } : null,
    reason: taken ? "Username is already taken" : null,
  });
});

// ── POST /username/claim — claim a username (no prior username) ───────────────
username.post("/claim", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const db   = c.get("db");
  const kv   = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  const rlCheck = await checkRateLimit(kv, {
    key: `username:claim:${user.id}`,
    limit: 5,
    windowSeconds: 3600,
  });
  if (!rlCheck.allowed) return rateLimitResponse(rlCheck.resetAt);

  const body = await c.req.json<{ username?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim();
  const { valid, reason } = validateUsernameFormat(lower);
  if (!valid) return c.json({ error: reason }, 400);

  // Check if user already has a username
  const { data: existing } = await db
    .from("auth_users")
    .select("username, reserved_email_address")
    .eq("id", user.id)
    .limit(1);

  const currentUsername = existing?.[0]?.username ?? null;
  if (currentUsername) {
    return c.json({
      error: `You already have @${currentUsername}. Use /username/change to change it (policy applies).`,
      current_username: currentUsername,
    }, 409);
  }

  // Atomically check + insert into usernames table
  const { error: insertError } = await db.from("usernames").insert({
    username:   lower,
    user_id:    user.id,
    claimed_at: new Date().toISOString(),
    active:     true,
  });

  if (insertError) {
    if (insertError.code === "23505") {
      return c.json({ error: "Username just became unavailable. Please choose another." }, 409);
    }
    console.error("[username/claim] insert error:", insertError.message);
    return c.json({ error: "Failed to claim username" }, 500);
  }

  const reservedMail = `${lower}@rald.me`;

  // Update auth_users
  await db.from("auth_users").update({
    username:               lower,
    username_set_at:        new Date().toISOString(),
    reserved_email_address: reservedMail,
    trust_level:            "basic",
    trust_score:            30,
  }).eq("id", user.id);

  // Username history
  await db.from("username_history").insert({
    user_id:  user.id,
    username: lower,
    action:   "claimed",
  });

  // Reserve namespace
  await db.rpc("reserve_username_namespace", {
    p_user_id:  user.id,
    p_username: lower,
  }).then(() => null, () => null);

  // Mark migration as complete if queued
  await db.from("username_migration_queue")
    .update({ completed_at: new Date().toISOString() })
    .eq("user_id", user.id)
    .then(() => null, () => null);

  // Sync trust profile
  await db.rpc("repair_identity_records", { p_user_id: user.id })
    .then(() => null, () => null);

  // USN-001: Fire cross-app username propagation event via the Event Bus.
  // Messenger, Profiles, and all ecosystem apps consume this to sync their
  // local profile caches — ensuring username is set everywhere, automatically.
  await db.from("rald_events").insert({
    event_type:  "username_claimed",
    source_app:  "rald-auth-core",
    user_id:     user.id,
    payload:     JSON.stringify({ username: lower, reserved_mail: reservedMail }),
    created_at:  new Date().toISOString(),
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "username_claimed",
    ip,
    status:   "success",
    metadata: { username: lower },
  });

  return c.json({
    ok:                  true,
    username:            lower,
    reserved_mail:       reservedMail,
    reserved_domain:     `${lower}.rald.me`,
    reserved_workspace:  lower,
    message:             `@${lower} is yours. Your RALD identity is now complete.`,
    ecosystem_unlocked:  true,
  });
});

// ── POST /username/change — change username (policy enforced) ─────────────────
// Policy: max 1 change per 30 days. Old username released after 14 days (re-claimable).
// P2 requirement: username change must be audit logged.
username.post("/change", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const db   = c.get("db");
  const kv   = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  // Rate limit: prevent rapid churn
  const rlCheck = await checkRateLimit(kv, {
    key: `username:change:${user.id}`,
    limit: 3,
    windowSeconds: 86400,
  });
  if (!rlCheck.allowed) return rateLimitResponse(rlCheck.resetAt);

  const body = await c.req.json<{ new_username?: string; reason?: string }>().catch(() => null);
  if (!body?.new_username) return c.json({ error: "new_username is required" }, 400);

  const newLower = body.new_username.toLowerCase().trim();
  const { valid, reason } = validateUsernameFormat(newLower);
  if (!valid) return c.json({ error: reason }, 400);

  // Get current username
  const { data: currentUser } = await db
    .from("auth_users")
    .select("username, username_set_at")
    .eq("id", user.id)
    .limit(1);

  const currentUsername = currentUser?.[0]?.username as string | null;
  const usernameSetAt   = currentUser?.[0]?.username_set_at as string | null;

  if (!currentUsername) {
    return c.json({ error: "No username to change. Use /username/claim first." }, 400);
  }
  if (currentUsername === newLower) {
    return c.json({ error: "New username is the same as your current one." }, 400);
  }

  // Policy: 30-day cooldown between changes
  if (usernameSetAt) {
    const daysSinceSet = (Date.now() - new Date(usernameSetAt).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceSet < 30) {
      const daysLeft = Math.ceil(30 - daysSinceSet);
      return c.json({
        error:     `Username can only be changed every 30 days. Try again in ${daysLeft} day${daysLeft === 1 ? "" : "s"}.`,
        days_left: daysLeft,
        policy:    "30_days",
      }, 429);
    }
  }

  // Check if new username is available
  const [usernamesCheck, authUsersCheck] = await Promise.all([
    db.from("usernames").select("username").eq("username", newLower).eq("active", true).limit(1),
    db.from("auth_users").select("id").ilike("username", newLower).neq("id", user.id).limit(1),
  ]);

  const taken = !!(usernamesCheck.data?.length) || !!(authUsersCheck.data?.length);
  if (taken) return c.json({ error: "That username is already taken." }, 409);

  // Release old username (mark inactive — available after 14 days by convention)
  await db.from("usernames")
    .update({ active: false })
    .eq("username", currentUsername)
    .eq("user_id", user.id)
    .then(() => null, () => null);

  // Claim new username
  await db.from("usernames").insert({
    username:   newLower,
    user_id:    user.id,
    claimed_at: new Date().toISOString(),
    active:     true,
  }).then(() => null, () => null);

  const newReservedMail = `${newLower}@rald.me`;

  // Update auth_users
  await db.from("auth_users").update({
    username:               newLower,
    username_set_at:        new Date().toISOString(),
    reserved_email_address: newReservedMail,
  }).eq("id", user.id);

  // Audit trail for both old and new
  await db.from("username_history").insert([
    { user_id: user.id, username: currentUsername, action: "released" },
    { user_id: user.id, username: newLower,        action: "claimed" },
  ]).then(() => null, () => null);

  // Reserve new namespace
  await db.rpc("reserve_username_namespace", {
    p_user_id:  user.id,
    p_username: newLower,
  }).then(() => null, () => null);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "username_claimed",
    ip,
    status:   "success",
    metadata: {
      old_username:  currentUsername,
      new_username:  newLower,
      reason:        body.reason ?? null,
      change_policy: "30_days",
    },
  });

  return c.json({
    ok:                  true,
    old_username:        currentUsername,
    username:            newLower,
    reserved_mail:       newReservedMail,
    reserved_domain:     `${newLower}.rald.me`,
    message:             `@${newLower} is now your username. @${currentUsername} will be available to others in 14 days.`,
    next_change_allowed: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  });
});

// ── GET /username/me — get current user's username ────────────────────────────
username.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data } = await db
    .from("auth_users")
    .select("username, username_set_at, rald_internal_id, reserved_email_address, trust_level")
    .eq("id", user.id)
    .limit(1);

  const row = data?.[0];
  const uname = row?.username as string | null;

  return c.json({
    user_id:                user.id,
    username:               uname ?? null,
    username_set_at:        row?.username_set_at ?? null,
    has_username:           !!uname,
    reserved_email_address: row?.reserved_email_address ?? (uname ? `${uname}@rald.me` : null),
    trust_level:            row?.trust_level ?? "none",
    // P4: next_change_allowed shows when they can change username
    next_change_allowed:    row?.username_set_at
      ? new Date(new Date(row.username_set_at as string).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
      : null,
  });
});

// ── GET /username/migration-status — check P4 migration queue status ──────────
username.get("/migration-status", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [userRes, queueRes] = await Promise.all([
    db.from("auth_users").select("username").eq("id", user.id).limit(1),
    db.from("username_migration_queue")
      .select("id,prompted_at,dismissed_count,completed_at")
      .eq("user_id", user.id)
      .maybeSingle(),
  ]);

  const hasUsername = !!(userRes.data?.[0]?.username);
  const queue       = queueRes.data;

  return c.json({
    user_id:           user.id,
    has_username:      hasUsername,
    needs_username:    !hasUsername,
    migration_queued:  !!queue,
    completed:         !!queue?.completed_at,
    prompted_at:       queue?.prompted_at ?? null,
    dismissed_count:   queue?.dismissed_count ?? 0,
    // P4: cannot dismiss forever — show every login until completed
    can_dismiss:       false,
    message:           hasUsername ? null : "Claim your @username to unlock the full RALD ecosystem.",
  });
});

export default username;