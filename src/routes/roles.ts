// RALD Auth Core — Role Engine Routes
// Phase 5: Role Engine — User, Artist, Label, Manager, Radio, Advertiser, Contributor
// Profiles owns all roles — applications consume them
// Profiles.RALD.Cloud Hardening Program — LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const roles = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// All valid roles in the RALD ecosystem
export const RALD_ROLES = [
  "user",
  "artist",
  "label",
  "manager",
  "radio",
  "advertiser",
  "contributor",
  "operator",
  "admin",
] as const;

export type RaldRole = (typeof RALD_ROLES)[number];

type RoleInfo = {
  label:                  string;
  description:            string;
  capabilities:           string[];
  requires_verification:  boolean;
};

// Role capabilities matrix — keyed by RaldRole string
const ROLE_CAPABILITIES: Record<RaldRole, RoleInfo> = {
  user: {
    label:       "User",
    description: "Standard RALD ecosystem account. Access to all consumer apps.",
    capabilities: ["access_consumer_apps", "create_profile", "join_rooms", "send_messages", "purchase"],
    requires_verification: false,
  },
  artist: {
    label:       "Artist",
    description: "Verified music artist. Unlocks Manilla artist tools, Loop artist rooms, and verified badge.",
    capabilities: ["access_consumer_apps", "create_artist_profile", "upload_music", "monetize_streams", "loop_artist_rooms", "verified_badge"],
    requires_verification: true,
  },
  label: {
    label:       "Label",
    description: "Record label. Manage artists, distribute music, and access label analytics.",
    capabilities: ["manage_artists", "distribute_music", "label_analytics", "batch_upload", "verified_badge"],
    requires_verification: true,
  },
  manager: {
    label:       "Manager",
    description: "Artist manager. Act on behalf of artists and labels.",
    capabilities: ["manage_artists", "booking_access", "financial_reports", "campaign_management"],
    requires_verification: false,
  },
  radio: {
    label:       "Radio",
    description: "Radio station operator. Broadcast live streams and manage station pages.",
    capabilities: ["broadcast_audio", "manage_station", "show_scheduling", "dj_rooms", "verified_badge"],
    requires_verification: true,
  },
  advertiser: {
    label:       "Advertiser",
    description: "Brand or agency running ad campaigns across the RALD ecosystem.",
    capabilities: ["run_campaigns", "audience_targeting", "campaign_analytics", "loop_ads", "messenger_ads"],
    requires_verification: true,
  },
  contributor: {
    label:       "Contributor",
    description: "Content contributor to RALD products. Articles, curated playlists, community rooms.",
    capabilities: ["create_content", "curate_playlists", "host_rooms", "contributor_badge"],
    requires_verification: false,
  },
  operator: {
    label:       "Operator",
    description: "RALD platform operator. Administrative access to specific products.",
    capabilities: ["admin_panel", "moderate_content", "manage_users", "view_analytics"],
    requires_verification: false,
  },
  admin: {
    label:       "Admin",
    description: "Full RALD platform admin. Restricted to LILCKY STUDIO LIMITED staff.",
    capabilities: ["full_access", "manage_operators", "audit_all", "configure_system"],
    requires_verification: false,
  },
};

// ── GET /roles/all — public list of all roles ─────────────────────────────────
roles.get("/all", (c) => {
  return c.json({
    roles: (Object.entries(ROLE_CAPABILITIES) as [RaldRole, RoleInfo][]).map(
      ([key, val]) => ({ role: key, ...val }),
    ),
    total: RALD_ROLES.length,
  });
});

// ── GET /roles/me — current user's role + capabilities ────────────────────────
roles.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data: userRow } = await db
    .from("auth_users")
    .select("id,role,metadata")
    .eq("id", user.id)
    .limit(1)
    .single();

  if (!userRow) return c.json({ error: "User not found" }, 404);

  const meta     = (userRow.metadata as Record<string, unknown>) ?? {};
  const roleStr  = userRow.role as string;
  // Narrow to RaldRole — fall back to "user" if unknown
  const role: RaldRole = (RALD_ROLES as readonly string[]).includes(roleStr)
    ? (roleStr as RaldRole)
    : "user";

  const info: RoleInfo = ROLE_CAPABILITIES[role];

  const { data: productRoles } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", user.id);

  return c.json({
    primary_role:     role,
    role_info:        info,
    product_roles:    productRoles ?? [],
    additional_roles: (meta.additional_roles as string[]) ?? [],
    verified_as:      (meta.verified_types as string[]) ?? [],
    can_request_roles: RALD_ROLES.filter(
      (r) => !["admin", "operator"].includes(r) && r !== role,
    ),
  });
});

// ── POST /roles/request — request a role upgrade ─────────────────────────────
roles.post("/request", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    requested_role: string;
    reason?:        string;
  }>().catch(() => null);

  if (!body?.requested_role) return c.json({ error: "requested_role is required" }, 400);

  // Validate role is a known RaldRole
  if (!(RALD_ROLES as readonly string[]).includes(body.requested_role)) {
    return c.json({
      error: `Invalid role. Must be one of: ${RALD_ROLES.join(", ")}`,
    }, 400);
  }

  const requestedRole = body.requested_role as RaldRole;

  if (requestedRole === "admin" || requestedRole === "operator") {
    return c.json({ error: "Admin and Operator roles cannot be self-requested" }, 403);
  }

  // Now safely access ROLE_CAPABILITIES — key is validated RaldRole
  const roleInfo: RoleInfo = ROLE_CAPABILITIES[requestedRole];

  if (!roleInfo.requires_verification) {
    const { data: userRow } = await db
      .from("auth_users")
      .select("metadata")
      .eq("id", user.id)
      .limit(1)
      .single();

    const meta: Record<string, unknown> = (userRow?.metadata as Record<string, unknown>) ?? {};
    const additionalRoles = (meta.additional_roles as string[]) ?? [];

    if (!additionalRoles.includes(requestedRole)) {
      additionalRoles.push(requestedRole);
      meta.additional_roles = additionalRoles;
      await db.from("auth_users").update({ metadata: meta }).eq("id", user.id);
    }

    await writeAuditLog(db, {
      userId:       user.id,
      action:       "role_granted",
      resourceType: "role",
      resourceId:   requestedRole,
      ip,
      status:       "success",
      metadata:     { role: requestedRole, auto_granted: true },
    });

    return c.json({
      ok:           true,
      granted:      true,
      role:         requestedRole,
      message:      `${roleInfo.label} role granted immediately.`,
      capabilities: roleInfo.capabilities,
    });
  }

  // Verification-required roles go to pending
  await writeAuditLog(db, {
    userId:       user.id,
    action:       "role_requested",
    resourceType: "role",
    resourceId:   requestedRole,
    ip,
    status:       "success",
    metadata:     { role: requestedRole, reason: body.reason ?? null },
  });

  return c.json({
    ok:      true,
    granted: false,
    role:    requestedRole,
    message: `${roleInfo.label} role requires verification. Submit a verification application at /verify/apply.`,
    next_steps: [
      "Complete your profile at profiles.rald.cloud",
      `Apply for ${roleInfo.label} verification at /verify/apply with type: "${requestedRole}"`,
      "Our team reviews applications within 5–10 business days",
    ],
  });
});

// ── GET /roles/capabilities/:role — public capabilities for a role ─────────────
roles.get("/capabilities/:role", (c) => {
  const roleParam = c.req.param("role");
  if (!(RALD_ROLES as readonly string[]).includes(roleParam)) {
    return c.json({ error: "Unknown role" }, 404);
  }
  const role = roleParam as RaldRole;
  const info: RoleInfo = ROLE_CAPABILITIES[role];
  return c.json({ role, ...info });
});

export default roles;
