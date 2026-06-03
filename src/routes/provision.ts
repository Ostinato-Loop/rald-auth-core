// RALD Auth Core — Universal App Provisioning Service
// Phase: RALD Identity Platform V2
// Rule: Authenticated users are NEVER redirected to onboarding — apps are provisioned silently.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { ECOSYSTEM_APPS, type EcosystemAppId } from "../lib/redirect";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const provision = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /provision/app — self-service app provisioning (authenticated user) ──
// Called by any RALD app when an authenticated user arrives without a local profile.
// Creates the app access record, links to customer graph, generates default preferences.
// Returns immediately — user is never blocked or redirected to onboarding.
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

  // 1. Upsert into auth_product_access
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

  // 2. Ensure auth_user_profiles row exists (creates default preferences)
  await db.from("auth_user_profiles").upsert(
    {
      user_id:          user.id,
      updated_at:       now,
      provisioned_apps: db.rpc("array_append_unique", { arr: [], val: body.app_id }) as unknown as string[],
    },
    { onConflict: "user_id" }
  ).then(() => {
    // Append app_id to provisioned_apps array
    return db.rpc("provision_app_append", {
      p_user_id: user.id,
      p_app_id:  body.app_id,
    }).catch(() => null); // graceful — array function may not exist yet
  }).catch(() => null);

  // 3. Non-blocking: link to CRM if app has customer context
  const appMeta = ECOSYSTEM_APPS.find(a => a.id === body.app_id as EcosystemAppId);
  c.executionCtx.waitUntil((async () => {
    // Write login history
    await db.from("auth_login_history").insert({
      user_id:    user.id,
      app_id:     body.app_id,
      ip_address: ip,
      success:    true,
      created_at: now,
    }).catch(() => null);

    // Audit log
    await writeAuditLog(db, {
      userId: user.id,
      action: "app_provisioned",
      ip,
      status: "success",
      metadata: { app_id: body.app_id, workspace_id: body.workspace_id ?? null },
    });
  })());

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

// ── GET /provision/status — check user's provisioning status across all apps ──
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
    user_id:          user.id,
    apps:             status,
    provisioned_count: status.filter(a => a.provisioned).length,
    total_apps:       status.length,
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
