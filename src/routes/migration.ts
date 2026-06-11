// RALD Auth Core — Identity Migration Routes
// P4: Existing User Migration — username claim flow for users without usernames
// P5: Identity Registry — verify and repair all identity records
//
// Routes:
//   GET  /migration/identity-status     — check user's identity completeness
//   POST /migration/claim-username      — claim username (for auth'd users without one)
//   POST /migration/repair              — trigger identity repair for authenticated user
//   GET  /migration/registry-check (admin) — audit identity registry for gaps
//
// LILCKY STUDIO LIMITED — 2026-06-11

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { checkRateLimit, getClientIp, rateLimitResponse } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const migration = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /migration/identity-status — full identity completeness check ─────────
// P4: Called after login to determine what the user still needs to complete.
migration.get("/identity-status", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [userRes, profileRes, trustRes, queueRes] = await Promise.all([
    db.from("auth_users")
      .select("id,username,email,email_verified,phone_number,phone_verified,reserved_email_address,trust_level,trust_score,rald_internal_id,created_at")
      .eq("id", user.id).limit(1),
    db.from("auth_user_profiles")
      .select("display_name,country,region,region_state")
      .eq("user_id", user.id).maybeSingle(),
    db.from("auth_trust_profiles")
      .select("*")
      .eq("user_id", user.id).maybeSingle(),
    db.from("username_migration_queue")
      .select("prompted_at,dismissed_count,completed_at")
      .eq("user_id", user.id).maybeSingle(),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const hasUsername      = !!(u.username as string | null);
  const hasVerifiedPhone = u.phone_verified === true;
  const hasVerifiedEmail = u.email_verified === true &&
    !(u.email as string).endsWith("@rald.identity") &&
    !(u.email as string).endsWith("@loop.guest");
  const hasRegion        = !!(profileRes.data?.country || profileRes.data?.region);
  const hasReservedMail  = !!(u.reserved_email_address as string | null);

  const identityComplete = hasUsername && (hasVerifiedPhone || hasVerifiedEmail);

  // Build list of required actions the user still needs to take
  const requiredActions: Array<{ action: string; priority: number; label: string; url: string }> = [];

  if (!hasUsername) {
    requiredActions.push({
      action:   "claim_username",
      priority: 1,
      label:    "Claim your @username",
      url:      "https://profiles.rald.cloud/claim-username",
    });
  }
  if (!hasVerifiedPhone && !hasVerifiedEmail) {
    requiredActions.push({
      action:   "verify_contact",
      priority: 2,
      label:    "Verify your phone or email",
      url:      "https://profiles.rald.cloud/verify",
    });
  }
  if (!hasRegion) {
    requiredActions.push({
      action:   "set_region",
      priority: 3,
      label:    "Set your region",
      url:      "https://profiles.rald.cloud/region",
    });
  }

  return c.json({
    user_id:         u.id,
    username:        u.username ?? null,
    rald_internal_id: u.rald_internal_id ?? null,
    reserved_email_address: u.reserved_email_address ?? null,
    trust_level:     u.trust_level ?? "none",
    trust_score:     u.trust_score ?? 0,
    identity_complete: identityComplete,
    completeness: {
      has_username:       hasUsername,
      has_verified_phone: hasVerifiedPhone,
      has_verified_email: hasVerifiedEmail,
      has_region:         hasRegion,
      has_reserved_mail:  hasReservedMail,
      has_profile:        !!profileRes.data,
      has_trust_profile:  !!trustRes.data,
    },
    // P4: migration state
    migration: {
      in_queue:        !!queueRes.data,
      completed:       !!queueRes.data?.completed_at,
      prompted_at:     queueRes.data?.prompted_at ?? null,
      dismissed_count: queueRes.data?.dismissed_count ?? 0,
    },
    // P4: what needs to be done next (sorted by priority)
    required_actions: requiredActions.sort((a, b) => a.priority - b.priority),
    // P6: smart fill — prefill data from existing records
    smart_fill: {
      country:      profileRes.data?.country ?? null,
      region:       profileRes.data?.region ?? null,
      region_state: profileRes.data?.region_state ?? null,
      display_name: profileRes.data?.display_name ?? (u.username as string | null) ?? null,
    },
  });
});

// ── POST /migration/claim-username — authenticated username claim ──────────────
// P4: For users who registered via the old guest/email flow and need a username.
migration.post("/claim-username", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const ip   = getClientIp(c.req.raw);
  const db   = c.get("db");
  const kv   = (c.env as unknown as Record<string, unknown>).RATE_LIMIT_KV as Parameters<typeof checkRateLimit>[0];

  const rl = await checkRateLimit(kv, {
    key: `migration:claim:${user.id}`, limit: 10, windowSeconds: 3600,
  });
  if (!rl.allowed) return rateLimitResponse(rl.resetAt);

  const body = await c.req.json<{ username?: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username is required" }, 400);

  const lower = body.username.toLowerCase().trim();

  // Validate format
  if (lower.length < 2 || lower.length > 20) {
    return c.json({ error: "Username must be 2–20 characters" }, 400);
  }
  if (!/^[a-z0-9_]+$/.test(lower)) {
    return c.json({ error: "Only letters, numbers, and underscores are allowed" }, 400);
  }
  if (lower.startsWith("_") || lower.endsWith("_")) {
    return c.json({ error: "Username cannot start or end with an underscore" }, 400);
  }

  // Check if already has username
  const { data: currentUser } = await db
    .from("auth_users")
    .select("username, reserved_email_address")
    .eq("id", user.id)
    .limit(1);

  if (currentUser?.[0]?.username) {
    return c.json({
      error: `You already have @${currentUser[0].username}.`,
      username: currentUser[0].username,
      already_complete: true,
    }, 409);
  }

  // Check availability
  const [usernamesRes, authUsersRes] = await Promise.all([
    db.from("usernames").select("username").eq("username", lower).eq("active", true).limit(1),
    db.from("auth_users").select("id").ilike("username", lower).neq("id", user.id).limit(1),
  ]);

  const taken = !!(usernamesRes.data?.length) || !!(authUsersRes.data?.length);
  if (taken) return c.json({ error: "That username is already taken. Try another.", available: false }, 409);

  const reservedMail = `${lower}@rald.me`;

  // Claim username
  await db.from("usernames").insert({
    username: lower, user_id: user.id,
    claimed_at: new Date().toISOString(), active: true,
  }).then(() => null, (e: unknown) => { throw e; });

  await db.from("auth_users").update({
    username:               lower,
    username_set_at:        new Date().toISOString(),
    reserved_email_address: reservedMail,
    trust_level:            "basic",
    trust_score:            30,
  }).eq("id", user.id);

  await db.from("username_history").insert({ user_id: user.id, username: lower, action: "claimed" })
    .then(() => null, () => null);

  await db.rpc("reserve_username_namespace", { p_user_id: user.id, p_username: lower })
    .then(() => null, () => null);

  // Mark migration complete
  await db.from("username_migration_queue")
    .upsert({ user_id: user.id, completed_at: new Date().toISOString() }, { onConflict: "user_id" })
    .then(() => null, () => null);

  // Sync trust profile
  await db.rpc("repair_identity_records", { p_user_id: user.id })
    .then(() => null, () => null);

  await writeAuditLog(db, {
    userId: user.id, action: "username_claimed", ip, status: "success",
    metadata: { username: lower, via: "migration_claim" },
  });

  return c.json({
    ok:                     true,
    username:               lower,
    reserved_email_address: reservedMail,
    reserved_domain:        `${lower}.rald.me`,
    message:                `@${lower} is yours. Welcome to the full RALD ecosystem.`,
    ecosystem_unlocked:     true,
    identity_complete:      true,
  }, 201);
});

// ── POST /migration/repair — trigger identity repair for current user ──────────
// P5: Ensures auth_user_profiles, auth_trust_profiles, reserved_email_address exist.
migration.post("/repair", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .rpc("repair_identity_records", { p_user_id: user.id });

  if (error) {
    console.error("[migration/repair] error:", error.message);
    return c.json({ ok: false, error: "Repair failed" }, 500);
  }

  return c.json({
    ok:      true,
    user_id: user.id,
    repaired: data?.[0] ?? null,
    message: "Identity records verified and repaired.",
  });
});

// ── GET /migration/registry-check — admin: audit identity registry ─────────────
// P5: Returns stats on how many users are missing required identity fields.
migration.get("/registry-check", adminMiddleware, async (c) => {
  const db = c.get("db");

  const [totalRes, noUsernameRes, noProfileRes, noTrustRes, noReservedMailRes] = await Promise.all([
    db.from("auth_users").select("id", { count: "exact", head: true }).eq("is_active", true),
    db.from("auth_users").select("id", { count: "exact", head: true }).is("username", null).eq("is_active", true),
    db.from("auth_users")
      .select("id", { count: "exact", head: true })
      .eq("is_active", true)
      .not("id", "in",
        db.from("auth_user_profiles").select("user_id")
      ),
    db.from("auth_users")
      .select("id", { count: "exact", head: true })
      .eq("is_active", true)
      .not("id", "in",
        db.from("auth_trust_profiles").select("user_id")
      ),
    db.from("auth_users")
      .select("id", { count: "exact", head: true })
      .is("reserved_email_address", null)
      .not("username", "is", null)
      .eq("is_active", true),
  ]);

  const total        = totalRes.count ?? 0;
  const noUsername   = noUsernameRes.count ?? 0;
  const noProfile    = noProfileRes.count ?? 0;
  const noTrust      = noTrustRes.count ?? 0;
  const noReserved   = noReservedMailRes.count ?? 0;

  return c.json({
    total_active_users: total,
    gaps: {
      missing_username:               noUsername,
      missing_profile_row:            noProfile,
      missing_trust_profile:          noTrust,
      missing_reserved_email_despite_username: noReserved,
    },
    health_score: total > 0
      ? Math.round(((total - noUsername) / total) * 100)
      : 100,
    recommendations: [
      noUsername > 0 && `${noUsername} users need to claim a username (P4 migration)`,
      noProfile  > 0 && `${noProfile} users missing profile row — run repair_identity_records()`,
      noTrust    > 0 && `${noTrust} users missing trust profile — run repair_identity_records()`,
      noReserved > 0 && `${noReserved} users have username but missing reserved_email_address — run repair_identity_records()`,
    ].filter(Boolean),
    checked_at: new Date().toISOString(),
  });
});

export default migration;
