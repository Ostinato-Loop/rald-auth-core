// RALD Auth Core — User Provisioning Routes
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";

const provision = new Hono<{ Bindings: Bindings; Variables: Variables }>();

provision.post("/user", adminMiddleware, async (c) => {
  const body = (await c.req.json().catch(() => null)) as {
    userId?: string;
    product?: string;
    role?: string;
  } | null;
  if (!body?.userId || !body?.product)
    return c.json({ error: "userId and product required" }, 400);

  const db = c.get("db");
  const { data: user } = await db
    .from("auth_users")
    .select("id,email,name,role")
    .eq("id", body.userId)
    .limit(1);

  if (!user?.length) return c.json({ error: "User not found" }, 404);

  const { error } = await db.from("auth_product_access").upsert(
    {
      user_id: body.userId,
      product: body.product,
      role: body.role ?? "user",
      granted_at: new Date().toISOString(),
    },
    { onConflict: "user_id,product" }
  );

  if (error) {
    console.error("Provision error:", JSON.stringify(error));
    return c.json({ error: "Provisioning failed" }, 500);
  }

  return c.json({ ok: true, userId: body.userId, product: body.product });
});

provision.get("/user/:userId/products", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data } = await db
    .from("auth_product_access")
    .select("product,role,granted_at")
    .eq("user_id", c.req.param("userId"));
  return c.json(data ?? []);
});

export default provision;
