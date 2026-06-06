// RALD Auth Core — Privacy Center Routes
// Phase 3: Privacy Center — Download My Data, Export Activity, Delete Account, Permission Controls
// Profiles.RALD.Cloud Hardening Program — LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const privacy = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /privacy/me — privacy overview ────────────────────────────────────────
privacy.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const [userRes, profileRes, appsRes, sessionsRes] = await Promise.all([
    db.from("auth_users").select("id,email,name,role,metadata,created_at").eq("id", user.id).limit(1),
    db.from("auth_user_profiles").select("*").eq("user_id", user.id).maybeSingle(),
    db.from("auth_product_access").select("product,role,granted_at").eq("user_id", user.id),
    db.from("auth_sessions").select("id,created_at").eq("user_id", user.id),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const meta = (u.metadata as Record<string, unknown>) ?? {};
  return c.json({
    data_collected: {
      email:      u.email,
      name:       u.name,
      phone:      meta.phone ?? null,
      created_at: u.created_at,
      avatar_url: profileRes.data?.avatar_url ?? null,
      bio:        profileRes.data?.bio ?? null,
    },
    connected_apps:  (appsRes.data ?? []).map((a: { product: string }) => a.product),
    active_sessions: sessionsRes.data?.length ?? 0,
    permissions: {
      profile_visible:   meta.profile_visible !== false,
      activity_tracking: meta.activity_tracking !== false,
      marketing_emails:  meta.marketing_emails !== false,
    },
    data_residency:   "Nigeria (af-south-1)",
    retention_policy: "Account data retained for 90 days after deletion request.",
    last_updated:     new Date().toISOString(),
  });
});

// ── GET /privacy/export — export all user data (GDPR-style) ──────────────────
privacy.get("/export", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  // Fetch all user data in parallel
  // Table names verified against live schema:
  //   audit_logs (not auth_audit_logs) — from lib/audit.ts
  //   auth_login_history (not auth_login_activity) — from routes/profiles.ts
  const [userRes, profileRes, appsRes, sessionsRes, devicesRes, auditRes, activityRes] = await Promise.all([
    db.from("auth_users").select("*").eq("id", user.id).limit(1),
    db.from("auth_user_profiles").select("*").eq("user_id", user.id).maybeSingle(),
    db.from("auth_product_access").select("*").eq("user_id", user.id),
    db.from("auth_sessions")
      .select("id,user_agent,ip_address,created_at,expires_at,last_seen_at")
      .eq("user_id", user.id),
    db.from("auth_devices")
      .select("id,device_name,device_type,last_seen_at,created_at")
      .eq("user_id", user.id),
    db.from("audit_logs")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(500),
    db.from("auth_login_history")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(500),
  ]);

  const u = userRes.data?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "data_export_requested",
    ip,
    status:   "success",
    metadata: { format: "json" },
  });

  const exportData = {
    _meta: {
      export_requested_at: new Date().toISOString(),
      export_version:      "1.0",
      data_controller:     "LILCKY STUDIO LIMITED",
      contact:             "privacy@rald.cloud",
    },
    identity: {
      id:         u.id as string,
      rald_id:    `RALD-${(u.id as string).split("-")[0]?.toUpperCase() ?? ""}`,
      email:      u.email as string,
      name:       u.name as string | null,
      role:       u.role as string,
      created_at: u.created_at as string,
    },
    profile: {
      display_name: profileRes.data?.display_name ?? null,
      bio:          profileRes.data?.bio ?? null,
      avatar_url:   profileRes.data?.avatar_url ?? null,
      preferences:  (profileRes.data?.preferences ?? {}) as Record<string, unknown>,
    },
    connected_apps:  appsRes.data ?? [],
    sessions:        sessionsRes.data ?? [],
    devices:         devicesRes.data ?? [],
    audit_log:       auditRes.data ?? [],
    login_history:   activityRes.data ?? [],
  };

  return new Response(JSON.stringify(exportData, null, 2), {
    headers: {
      "Content-Type":        "application/json",
      "Content-Disposition": `attachment; filename="rald-data-export-${new Date().toISOString().split("T")[0]}.json"`,
    },
  });
});

// ── PATCH /privacy/permissions — update privacy preferences ───────────────────
privacy.patch("/permissions", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    profile_visible?:   boolean;
    activity_tracking?: boolean;
    marketing_emails?:  boolean;
  }>().catch(() => null);
  if (!body) return c.json({ error: "Invalid JSON body" }, 400);

  const { data: userRow } = await db
    .from("auth_users")
    .select("metadata")
    .eq("id", user.id)
    .limit(1)
    .single();

  const meta: Record<string, unknown> = (userRow?.metadata as Record<string, unknown>) ?? {};

  if (body.profile_visible   !== undefined) meta.profile_visible   = body.profile_visible;
  if (body.activity_tracking !== undefined) meta.activity_tracking = body.activity_tracking;
  if (body.marketing_emails  !== undefined) meta.marketing_emails  = body.marketing_emails;

  const { error } = await db.from("auth_users").update({ metadata: meta }).eq("id", user.id);
  if (error) return c.json({ error: "Failed to update preferences" }, 500);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "privacy_permissions_updated",
    ip,
    status:   "success",
    metadata: { changes: body as Record<string, unknown> },
  });

  return c.json({ ok: true, permissions: body });
});

// ── POST /privacy/delete-request — initiate account deletion ─────────────────
privacy.post("/delete-request", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{ reason?: string; confirm?: boolean }>().catch(() => null);
  if (!body?.confirm) {
    return c.json({
      error:   "Confirmation required",
      message: "Send { confirm: true } to initiate account deletion. Your account will be scheduled for deletion in 30 days.",
    }, 400);
  }

  const scheduledAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const { data: userRow } = await db
    .from("auth_users")
    .select("metadata")
    .eq("id", user.id)
    .limit(1)
    .single();

  const meta: Record<string, unknown> = (userRow?.metadata as Record<string, unknown>) ?? {};
  meta.deletion_requested_at = new Date().toISOString();
  meta.deletion_scheduled_at = scheduledAt;
  meta.deletion_reason       = body.reason ?? "User request";
  meta.status                = "pending_deletion";

  await db.from("auth_users").update({ metadata: meta }).eq("id", user.id);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "account_deletion_requested",
    ip,
    status:   "success",
    metadata: { scheduled_at: scheduledAt, reason: body.reason ?? "User request" },
  });

  return c.json({
    ok:           true,
    message:      "Account deletion scheduled. Your account and all associated data will be permanently deleted in 30 days.",
    scheduled_at: scheduledAt,
    cancellable:  true,
    cancel_url:   "https://profiles.rald.cloud/privacy/cancel-deletion",
  });
});

// ── POST /privacy/cancel-deletion — cancel pending deletion ───────────────────
privacy.post("/cancel-deletion", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const { data: userRow } = await db
    .from("auth_users")
    .select("metadata")
    .eq("id", user.id)
    .limit(1)
    .single();

  const meta: Record<string, unknown> = (userRow?.metadata as Record<string, unknown>) ?? {};

  if (!meta.deletion_requested_at) {
    return c.json({ error: "No pending deletion request found" }, 404);
  }

  delete meta.deletion_requested_at;
  delete meta.deletion_scheduled_at;
  delete meta.deletion_reason;
  delete meta.status;

  await db.from("auth_users").update({ metadata: meta }).eq("id", user.id);

  await writeAuditLog(db, {
    userId:   user.id,
    action:   "account_deletion_cancelled",
    ip,
    status:   "success",
    metadata: {},
  });

  return c.json({ ok: true, message: "Account deletion cancelled. Your account is safe." });
});

export default privacy;
