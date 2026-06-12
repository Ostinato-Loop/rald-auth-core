// RALD Auth Core — Universal App Provisioning Service
// Phase: RALD Identity Platform V2 + Identity Continuity Sprint
// Rule: Authenticated users are NEVER redirected to onboarding — apps are provisioned silently.
// Fix: PostgrestFilterBuilder is PromiseLike — use Promise.resolve().then(undefined, fn) not .catch()
//
// Routes:
//   POST /provision/app      — self-service: provision one app for authenticated user
//   POST /provision/all      — self-service: provision ALL 8 ecosystem profiles (RALD Identity Continuity)
//   GET  /provision/status   — self-service: check provisioning status across all apps
//   POST /provision/user     — admin: provision another user into a product
//   GET  /provision/user/:userId/products — admin: list user's products
//
// POST /provision/all (Identity Continuity Program):
//   Creates all 8 ecosystem profiles in one atomic call:
//   Loop, Messenger, Mail, Workspace, Trust, Notification, Search, Developer
//   Non-blocking for individual failures — partial success is returned.
//   Products must never ask for identity information RALD already holds.
//
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { ECOSYSTEM_APPS, type EcosystemAppId } from "../lib/redirect";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const provision = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /provision/app — self-service app provisioning ───────────────────────
provision.post("/app", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    app_id: string;
    workspace_id?: string;
    metadata?: Record<string, unknown>;
  }>().catch(() => null);
  if (!body?.app_id) return c.json({ error: "app_id is required" }, 400);

  const validAppIds = ECOSYSTEM_APPS.map(a => a.id) as readonly string[];
  if (!validAppIds.includes(body.app_id))
    return c.json({ error: `Unknown app_id: ${body.app_id}` }, 400);

  const now = new Date().toISOString();

  const { error: accessError } = await db.from("auth_product_access").upsert(
    {
      user_id:    user.id,
      product:    body.app_id,
      role:       "user",
      granted_at: now,
    },
    { onConflict: "user_id,product" }
  );
  if (accessError) {
    console.error("[provision] auth_product_access upsert error:", accessError.message);
    return c.json({ error: "Provisioning failed" }, 500);
  }

  await Promise.resolve(
    db.from("auth_user_profiles").upsert(
      { user_id: user.id, updated_at: now },
      { onConflict: "user_id" }
    )
  ).then(undefined, () => null);

  await Promise.resolve(
    db.rpc("provision_app_append", {
      p_user_id: user.id,
      p_app_id:  body.app_id,
    })
  ).then(undefined, () => null);

  const appMeta = ECOSYSTEM_APPS.find(a => a.id === body.app_id as EcosystemAppId);
  void Promise.resolve(
    db.from("auth_login_history").insert({
      user_id:    user.id,
      app_id:     body.app_id,
      ip_address: ip,
      success:    true,
      created_at: now,
    })
  ).then(undefined, () => null);

  await writeAuditLog(db, {
    userId: user.id,
    action: "app_provisioned",
    ip,
    status: "success",
    metadata: { app_id: body.app_id, workspace_id: body.workspace_id ?? null },
  });

  return c.json({
    ok:           true,
    provisioned:  true,
    app_id:       body.app_id,
    app_name:     appMeta?.name ?? body.app_id,
    app_url:      appMeta?.url ?? null,
    user_id:      user.id,
    role:         "user",
    message:      "App provisioned silently — no onboarding required",
  });
});

// ── POST /provision/all — atomically provision ALL 8 ecosystem profiles ────────
// RALD Identity Continuity Program
// Called automatically after registration and optionally by any app when
// it detects a user is missing one or more profiles.
// Products must NEVER ask for identity info RALD already has — this ensures
// all profiles exist so products can always pull from identity-intelligence.
//
// Profiles provisioned:
//   1. Loop profile          (loop_profiles)
//   2. Messenger profile     (messenger_profiles)
//   3. Mail profile          (mail_profiles — alias = username@rald.me)
//   4. Workspace             (workspace_profiles — slug = username)
//   5. Trust profile         (auth_trust_profiles)
//   6. Notification profile  (notification_profiles)
//   7. Search profile        (search_profiles — discoverable by default)
//   8. Developer profile     (developer_profiles — API access enabled)
provision.post("/all", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);
  const now  = new Date().toISOString();

  // Fetch the user's current identity to seed profiles correctly
  const { data: userRows } = await db
    .from("auth_users")
    .select("id,username,name,email,email_verified,phone_number,phone_verified,reserved_email_address,trust_level,trust_score")
    .eq("id", user.id)
    .limit(1);

  const u = userRows?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  const username    = (u.username as string | null) ?? "";
  const displayName = (u.name as string | null) ?? username;
  const mailAlias   = (u.reserved_email_address as string | null) ?? (username ? `${username}@rald.me` : null);

  // Track which profiles succeeded and which failed (non-blocking partial success)
  const provisioned: string[] = [];
  const failed:      Array<{ profile: string; error: string }> = [];

  async function tryProvision(name: string, fn: () => Promise<unknown>) {
    try {
      await fn();
      provisioned.push(name);
    } catch (err) {
      failed.push({ profile: name, error: String(err) });
      console.error(`[provision/all] ${name} failed:`, String(err));
    }
  }

  // ── 1. auth_user_profiles (base profile) ─────────────────────────────────
  await tryProvision("base_profile", () =>
    Promise.resolve(
      db.from("auth_user_profiles").upsert(
        { user_id: user.id, updated_at: now },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 2. Loop profile ───────────────────────────────────────────────────────
  await tryProvision("loop", () =>
    Promise.resolve(
      db.from("loop_profiles").upsert(
        { user_id: user.id, username, display_name: displayName, provisioned_at: now },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 3. Messenger profile ──────────────────────────────────────────────────
  await tryProvision("messenger", () =>
    Promise.resolve(
      db.from("messenger_profiles").upsert(
        { user_id: user.id, username, display_name: displayName, provisioned_at: now },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 4. Mail profile ───────────────────────────────────────────────────────
  if (mailAlias) {
    await tryProvision("mail", () =>
      Promise.resolve(
        db.from("mail_profiles").upsert(
          { user_id: user.id, mail_alias: mailAlias, display_name: displayName, provisioned_at: now },
          { onConflict: "user_id" }
        )
      )
    );
  } else {
    failed.push({ profile: "mail", error: "No username — mail alias cannot be assigned yet" });
  }

  // ── 5. Workspace profile ──────────────────────────────────────────────────
  if (username) {
    await tryProvision("workspace", () =>
      Promise.resolve(
        db.from("workspace_profiles").upsert(
          { user_id: user.id, workspace_slug: username, display_name: displayName, provisioned_at: now },
          { onConflict: "user_id" }
        )
      )
    );
  } else {
    failed.push({ profile: "workspace", error: "No username — workspace slug cannot be assigned yet" });
  }

  // ── 6. Trust profile ──────────────────────────────────────────────────────
  await tryProvision("trust", () =>
    Promise.resolve(
      db.from("auth_trust_profiles").upsert(
        {
          user_id:            user.id,
          trust_level:        (u.trust_level as string | null) ?? "none",
          trust_score:        (u.trust_score as number | null) ?? 0,
          has_username:       !!username,
          has_verified_phone: u.phone_verified === true,
          has_verified_email: u.email_verified === true,
          has_reserved_mail:  !!mailAlias,
          has_profile:        true,
          updated_at:         now,
        },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 7. Notification profile ───────────────────────────────────────────────
  await tryProvision("notification", () =>
    Promise.resolve(
      db.from("notification_profiles").upsert(
        { user_id: user.id, provisioned_at: now },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 8. Search profile (discoverable by default) ───────────────────────────
  await tryProvision("search", () =>
    Promise.resolve(
      db.from("search_profiles").upsert(
        {
          user_id:             user.id,
          username,
          display_name:        displayName,
          search_discoverable: true,
          provisioned_at:      now,
        },
        { onConflict: "user_id" }
      )
    )
  );

  // ── 9. Developer profile (API access) ─────────────────────────────────────
  await tryProvision("developer", () =>
    Promise.resolve(
      db.from("developer_profiles").upsert(
        { user_id: user.id, username, api_access: true, provisioned_at: now },
        { onConflict: "user_id" }
      )
    )
  );

  // ── Append all app IDs to product_access ──────────────────────────────────
  const APP_IDS = ["loop", "messenger", "mail", "workspace", "voice", "pay"] as const;
  for (const appId of APP_IDS) {
    await Promise.resolve(
      db.from("auth_product_access").upsert(
        { user_id: user.id, product: appId, role: "user", granted_at: now },
        { onConflict: "user_id,product" }
      )
    ).then(undefined, () => null);
  }

  await writeAuditLog(db, {
    userId: user.id,
    action: "provision_all",
    ip,
    status: failed.length === 0 ? "success" : "partial",
    metadata: {
      provisioned_count: provisioned.length,
      failed_count:      failed.length,
      provisioned,
      failed:            failed.map(f => f.profile),
    },
  });

  return c.json({
    ok:                true,
    user_id:           user.id,
    username:          username || null,
    provisioned_count: provisioned.length,
    failed_count:      failed.length,
    provisioned,
    failed,
    message: failed.length === 0
      ? "All ecosystem profiles provisioned. You're fully set up across RALD."
      : `${provisioned.length} profiles provisioned. ${failed.length} deferred (usually no username yet).`,
    fully_provisioned: failed.length === 0,
  });
});

// ── GET /provision/status — check provisioning status across all apps ──────────
provision.get("/status", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");

  const { data: access } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", user.id);

  const provisioned = new Set((access ?? []).map((a: { product: string }) => a.product));

  const status = ECOSYSTEM_APPS.map(app => ({
    app_id:      app.id,
    app_name:    app.name,
    provisioned: provisioned.has(app.id),
    role:        access?.find((a: { product: string; role: string }) => a.product === app.id)?.role ?? null,
    granted_at:  access?.find((a: { product: string; granted_at: string }) => a.product === app.id)?.granted_at ?? null,
  }));

  return c.json({
    user_id:           user.id,
    apps:              status,
    provisioned_count: status.filter(a => a.provisioned).length,
    total_apps:        status.length,
  });
});

// ── POST /provision/user — admin: provision another user into a product ────────
provision.post("/user", adminMiddleware, async (c) => {
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    userId?: string;
    product?: string;
    role?: string;
  }>().catch(() => null);
  if (!body?.userId || !body?.product)
    return c.json({ error: "userId and product required" }, 400);

  const { data: user } = await db
    .from("auth_users").select("id,email,name,role").eq("id", body.userId).limit(1);
  if (!user?.length) return c.json({ error: "User not found" }, 404);

  const { error } = await db.from("auth_product_access").upsert(
    { user_id: body.userId, product: body.product, role: body.role ?? "user", granted_at: new Date().toISOString() },
    { onConflict: "user_id,product" }
  );
  if (error) return c.json({ error: "Provisioning failed" }, 500);

  await writeAuditLog(db, {
    userId: body.userId, action: "app_provisioned_by_admin", ip, status: "success",
    metadata: { product: body.product, role: body.role ?? "user" },
  });

  return c.json({ ok: true, userId: body.userId, product: body.product });
});

// ── GET /provision/user/:userId/products — admin: list user's products ─────────
provision.get("/user/:userId/products", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", c.req.param("userId"));
  return c.json({ products: data ?? [], count: data?.length ?? 0 });
});

export default provision;
