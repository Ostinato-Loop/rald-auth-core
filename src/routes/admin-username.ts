// RALD Auth Core — Admin Username Console (Phase 4 + Identity Continuity Sprint)
// GET  /admin/usernames              — search/list usernames by status
// POST /admin/usernames/reserve      — reserve a username (RESERVED status)
// POST /admin/usernames/release      — release back to AVAILABLE
// POST /admin/usernames/transfer     — transfer username to another user
// POST /admin/usernames/protect      — mark PROTECTED (blocks all claims)
// POST /admin/usernames/premium      — mark PREMIUM (future marketplace)
// POST /admin/usernames/recover      — pull into ADMIN_HELD
// POST /admin/usernames/bulk-reserve — reserve a list of usernames
// GET  /admin/usernames/ghost-audit  — scan for ghost/orphaned usernames (RALD Identity Continuity)
// POST /admin/usernames/ghost-repair — auto-release ghost usernames found in audit
//
// USERNAME STATES (RALD Identity Continuity Program):
//   AVAILABLE   — free to claim
//   PENDING     — reserved during registration (auto-expires in 15 min if /complete never called)
//   ACTIVE      — claimed by a verified user (replaces legacy active=true/CLAIMED)
//   UNDER_REVIEW — flagged for manual review (ghost candidates)
//   PROTECTED   — blocked from any claim (brand / civic names)
//   RESERVED    — held by admin
//
// Ghost username criteria (Document 2 — Audit Area 2):
//   - user_id IS NULL with active=true or status=ACTIVE/CLAIMED
//   - status=PENDING AND pending_until < now (expired)
//   - status=ACTIVE/CLAIMED but no matching auth_users row
//   - status=ACTIVE/CLAIMED but email_verified=false AND phone_verified=false
//
// All routes require admin role.
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
  | "PENDING"
  | "ACTIVE"
  | "RESERVED"
  | "CLAIMED"        // legacy alias for ACTIVE
  | "PROTECTED"
  | "PREMIUM"
  | "UNDER_REVIEW"
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
    .select("username, status, user_id, reserved_by, reserved_until, pending_until, released_at, claimed_at, created_at, active")
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (status) query = query.eq("status", status);
  if (q)      query = query.ilike("username", `%${q}%`);

  const { data, error, count } = await query;
  if (error) return c.json({ error: "Failed to query usernames", detail: error.message }, 500);

  return c.json({ usernames: data ?? [], count, offset, limit });
});

// ── GET /admin/usernames/ghost-audit — scan for orphaned/ghost usernames ──────
// RALD Identity Continuity Program — Ghost Username Audit
// Scans for all username states that indicate a ghost condition.
// Returns a full report with counts, examples, and recommended actions.
adminUsername.get("/ghost-audit", async (c) => {
  const db  = c.get("db");
  const now = new Date().toISOString();

  const [
    expiredPendingRes,
    nullUserIdRes,
    noAuthUserRowRes,
    unverifiedActiveRes,
    pendingCountRes,
  ] = await Promise.allSettled([

    // 1. PENDING usernames whose pending_until has expired (registration abandoned)
    db.from("usernames")
      .select("username, user_id, pending_until, created_at")
      .eq("status", "PENDING")
      .lt("pending_until", now)
      .order("pending_until", { ascending: true })
      .limit(100),

    // 2. Active/claimed usernames with no user_id (orphaned)
    db.from("usernames")
      .select("username, status, created_at")
      .is("user_id", null)
      .in("status", ["ACTIVE", "CLAIMED"])
      .limit(100),

    // 3. Active/claimed usernames whose auth_users row is missing
    // (join check — approximate via left anti-join via RPC if available, else sampled)
    db.rpc("audit_ghost_usernames_no_user_row", {}).catch(() => ({ data: null, error: null })),

    // 4. Active/claimed usernames where neither email nor phone is verified
    db.from("usernames")
      .select("username, user_id, status, claimed_at")
      .in("status", ["ACTIVE", "CLAIMED"])
      .not("user_id", "is", null)
      .limit(200),

    // 5. Current PENDING count (in-flight registrations)
    db.from("usernames")
      .select("username", { count: "exact", head: true })
      .eq("status", "PENDING")
      .gte("pending_until", now),
  ]);

  const expiredPending = expiredPendingRes.status === "fulfilled"
    ? (expiredPendingRes.value.data ?? []) : [];
  const nullUserId = nullUserIdRes.status === "fulfilled"
    ? (nullUserIdRes.value.data ?? []) : [];
  const noUserRow = noAuthUserRowRes.status === "fulfilled" && noAuthUserRowRes.value.data
    ? (noAuthUserRowRes.value.data as unknown[]) : [];
  const activePending = pendingCountRes.status === "fulfilled"
    ? (pendingCountRes.value.count ?? 0) : 0;

  // Cross-reference unverified active usernames with auth_users
  let unverifiedActive: Array<{ username: string; user_id: string }> = [];
  if (unverifiedActiveRes.status === "fulfilled" && unverifiedActiveRes.value.data?.length) {
    const userIds = (unverifiedActiveRes.value.data as Array<{ user_id: string; username: string }>)
      .map(r => r.user_id)
      .filter(Boolean);

    if (userIds.length > 0) {
      const { data: unverifiedUsers } = await db
        .from("auth_users")
        .select("id, email_verified, phone_verified")
        .in("id", userIds)
        .eq("email_verified", false)
        .eq("phone_verified", false);

      const unverifiedSet = new Set((unverifiedUsers ?? []).map((u: { id: string }) => u.id));

      unverifiedActive = (unverifiedActiveRes.value.data as Array<{ user_id: string; username: string }>)
        .filter(r => unverifiedSet.has(r.user_id))
        .map(r => ({ username: r.username, user_id: r.user_id }));
    }
  }

  const totalGhosts =
    expiredPending.length +
    nullUserId.length +
    noUserRow.length +
    unverifiedActive.length;

  const report = {
    generated_at:         now,
    summary: {
      total_ghost_candidates: totalGhosts,
      expired_pending:        expiredPending.length,
      null_user_id:           nullUserId.length,
      no_auth_user_row:       noUserRow.length,
      unverified_active:      unverifiedActive.length,
      active_pending_registrations: activePending,
    },
    categories: {
      expired_pending: {
        description:  "PENDING usernames whose 15-min reservation window expired (registration abandoned)",
        action:       "auto-release to AVAILABLE",
        count:        expiredPending.length,
        examples:     expiredPending.slice(0, 10),
      },
      null_user_id: {
        description:  "ACTIVE/CLAIMED usernames with no user_id (orphaned at DB level)",
        action:       "move to UNDER_REVIEW then release",
        count:        nullUserId.length,
        examples:     nullUserId.slice(0, 10),
      },
      no_auth_user_row: {
        description:  "ACTIVE/CLAIMED usernames whose auth_users record no longer exists",
        action:       "move to UNDER_REVIEW then release",
        count:        noUserRow.length,
        examples:     (noUserRow as Array<{ username: string }>).slice(0, 10),
      },
      unverified_active: {
        description:  "ACTIVE usernames where user has neither verified email nor phone",
        action:       "move to UNDER_REVIEW — user must verify or username released",
        count:        unverifiedActive.length,
        examples:     unverifiedActive.slice(0, 10),
      },
    },
    recommendations: [
      expiredPending.length > 0
        ? `Run POST /admin/usernames/ghost-repair to release ${expiredPending.length} expired-PENDING usernames`
        : null,
      nullUserId.length > 0
        ? `${nullUserId.length} usernames have null user_id — run ghost-repair to move to UNDER_REVIEW`
        : null,
      noUserRow.length > 0
        ? `${noUserRow.length} usernames point to deleted auth_users rows — run ghost-repair`
        : null,
      unverifiedActive.length > 0
        ? `${unverifiedActive.length} active usernames have no verified contact — review and optionally release`
        : null,
    ].filter(Boolean),
    overall_health: totalGhosts === 0 ? "CLEAN" : totalGhosts < 10 ? "MINOR_ISSUES" : "NEEDS_REPAIR",
  };

  return c.json(report);
});

// ── POST /admin/usernames/ghost-repair — auto-release ghost usernames ──────────
// RALD Identity Continuity Program — Ghost Username Repair
// Automatically releases ghost usernames found in the audit.
// Safe: only releases PENDING/expired or null-user_id orphans.
// UNDER_REVIEW usernames are moved for manual intervention only.
adminUsername.post("/ghost-repair", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");
  const now   = new Date().toISOString();

  const body = await c.req.json<{
    dry_run?:              boolean;
    release_expired_pending?: boolean;
    release_null_userid?:  boolean;
    move_unverified_to_review?: boolean;
  }>().catch(() => null);

  const dryRun                  = body?.dry_run ?? false;
  const releaseExpiredPending   = body?.release_expired_pending ?? true;
  const releaseNullUserId       = body?.release_null_userid ?? true;
  const moveUnverifiedToReview  = body?.move_unverified_to_review ?? true;

  const results: {
    expired_pending_released:     number;
    null_userid_moved:            number;
    unverified_moved_to_review:   number;
    errors:                       string[];
  } = {
    expired_pending_released:   0,
    null_userid_moved:          0,
    unverified_moved_to_review: 0,
    errors:                     [],
  };

  // ── 1. Release expired PENDING usernames ───────────────────────────────────
  if (releaseExpiredPending) {
    try {
      if (!dryRun) {
        const { data: expired } = await db
          .from("usernames")
          .select("username, user_id")
          .eq("status", "PENDING")
          .lt("pending_until", now);

        if (expired?.length) {
          // Release all expired PENDING
          const { count } = await db
            .from("usernames")
            .update({
              status:        "AVAILABLE",
              user_id:       null,
              active:        false,
              released_at:   now,
              pending_until: null,
            })
            .eq("status", "PENDING")
            .lt("pending_until", now)
            .select("username", { count: "exact", head: true });

          // Also clean up the dangling auth_users rows created during pending registration
          const pendingEmails = expired.map((u: { username: string }) => `${u.username}.pending@rald.identity`);
          if (pendingEmails.length > 0) {
            await db.from("auth_users")
              .delete()
              .in("email", pendingEmails)
              .then(() => null, () => null);
          }

          results.expired_pending_released = count ?? expired.length;
        }
      } else {
        // Dry run — just count
        const { count } = await db
          .from("usernames")
          .select("username", { count: "exact", head: true })
          .eq("status", "PENDING")
          .lt("pending_until", now);
        results.expired_pending_released = count ?? 0;
      }
    } catch (err) {
      results.errors.push(`expired_pending: ${String(err)}`);
    }
  }

  // ── 2. Move null-user_id active/claimed to UNDER_REVIEW ───────────────────
  if (releaseNullUserId) {
    try {
      if (!dryRun) {
        const { count } = await db
          .from("usernames")
          .update({ status: "UNDER_REVIEW", active: false, released_at: now })
          .is("user_id", null)
          .in("status", ["ACTIVE", "CLAIMED"])
          .select("username", { count: "exact", head: true });
        results.null_userid_moved = count ?? 0;
      } else {
        const { count } = await db
          .from("usernames")
          .select("username", { count: "exact", head: true })
          .is("user_id", null)
          .in("status", ["ACTIVE", "CLAIMED"]);
        results.null_userid_moved = count ?? 0;
      }
    } catch (err) {
      results.errors.push(`null_userid: ${String(err)}`);
    }
  }

  // ── 3. Move unverified-active to UNDER_REVIEW (non-destructive) ───────────
  if (moveUnverifiedToReview) {
    try {
      const { data: activeClaimed } = await db
        .from("usernames")
        .select("username, user_id")
        .in("status", ["ACTIVE", "CLAIMED"])
        .not("user_id", "is", null)
        .limit(500);

      if (activeClaimed?.length) {
        const userIds = (activeClaimed as Array<{ user_id: string }>).map(r => r.user_id);
        const { data: unverified } = await db
          .from("auth_users")
          .select("id")
          .in("id", userIds)
          .eq("email_verified", false)
          .eq("phone_verified", false);

        if (unverified?.length && !dryRun) {
          const unverifiedIds = new Set((unverified as Array<{ id: string }>).map(u => u.id));
          const toReview = (activeClaimed as Array<{ username: string; user_id: string }>)
            .filter(r => unverifiedIds.has(r.user_id))
            .map(r => r.username);

          for (const uname of toReview) {
            await db.from("usernames")
              .update({ status: "UNDER_REVIEW" })
              .eq("username", uname)
              .then(() => null, () => null);
          }
          results.unverified_moved_to_review = toReview.length;
        } else {
          results.unverified_moved_to_review = unverified?.length ?? 0;
        }
      }
    } catch (err) {
      results.errors.push(`unverified_review: ${String(err)}`);
    }
  }

  await writeAuditLog(db, {
    userId:   admin.id,
    action:   "ghost_username_repair",
    ip,
    status:   "success",
    metadata: { dry_run: dryRun, ...results },
  });

  return c.json({
    ok:      !dryRun,
    dry_run: dryRun,
    repaired_at: now,
    results,
    message: dryRun
      ? `Dry run complete. ${results.expired_pending_released} expired-PENDING, ${results.null_userid_moved} null-user_id, ${results.unverified_moved_to_review} unverified-active found.`
      : `Repair complete. ${results.expired_pending_released} usernames released, ${results.null_userid_moved + results.unverified_moved_to_review} moved to UNDER_REVIEW.`,
  });
});

// ── POST /admin/usernames/reserve ─────────────────────────────────────────────
adminUsername.post("/reserve", async (c) => {
  const admin = c.get("user")!;
  const ip    = getClientIp(c.req.raw);
  const db    = c.get("db");

  const body = await c.req.json<{
    username:         string;
    reason?:          string;
    reserved_until?:  string;
  }>().catch(() => null);

  if (!body?.username) return c.json({ error: "username is required" }, 400);
  const lower = body.username.toLowerCase().trim().replace(/^@/, "");

  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];

  if (row?.status === "ACTIVE" || row?.status === "CLAIMED") {
    return c.json({ error: `@${lower} is currently active. Use /transfer or /recover instead.` }, 409);
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

  if (row.status === "ACTIVE" || row.status === "CLAIMED") {
    return c.json({ error: `@${lower} is active. Recover it first.` }, 409);
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

  const { data: targetUsers } = await db
    .from("auth_users")
    .select("id, username, name")
    .eq("id", body.to_user_id)
    .limit(1);

  const target = targetUsers?.[0];
  if (!target) return c.json({ error: "Target user not found." }, 404);

  const { data: existing } = await db
    .from("usernames")
    .select("username, status, user_id")
    .eq("username", lower)
    .limit(1);

  const row = existing?.[0];
  const oldUserId = row?.user_id ?? null;

  if (oldUserId && oldUserId !== body.to_user_id) {
    await db.from("auth_users")
      .update({ username: null, username_set_at: null })
      .eq("id", oldUserId)
      .eq("username", lower)
      .then(() => null, () => null);
  }

  await db.from("usernames").upsert({
    username:   lower,
    user_id:    body.to_user_id,
    status:     "ACTIVE",
    active:     true,
    claimed_at: new Date().toISOString(),
  }, { onConflict: "username" });

  await db.from("auth_users").update({
    username:        lower,
    username_set_at: new Date().toISOString(),
  }).eq("id", body.to_user_id);

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
    status:      "ACTIVE",
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
  if (row?.status === "ACTIVE" || row?.status === "CLAIMED") {
    return c.json({ error: `@${lower} is currently active. Recover it first.` }, 409);
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
