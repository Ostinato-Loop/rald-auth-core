// RALD Auth Core — Device Management Routes
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";

const devices = new Hono<{ Bindings: Bindings; Variables: Variables }>();

devices.get("/", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  try {
    const { data } = await db
      .from("auth_devices")
      .select("id,device_name,device_type,os,browser,ip_address,last_seen_at,is_trusted,created_at")
      .eq("user_id", user.id)
      .order("last_seen_at", { ascending: false });
    return c.json(data ?? []);
  } catch {
    return c.json([]);
  }
});

devices.post("/:id/trust", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  try {
    await db
      .from("auth_devices")
      .update({ is_trusted: true })
      .eq("id", c.req.param("id"))
      .eq("user_id", user.id);
    return c.json({ message: "Device trusted" });
  } catch {
    return c.json({ error: "Device not found" }, 404);
  }
});

devices.delete("/:id", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  try {
    await db
      .from("auth_devices")
      .delete()
      .eq("id", c.req.param("id"))
      .eq("user_id", user.id);
    return c.json({ message: "Device removed" });
  } catch {
    return c.json({ error: "Device not found" }, 404);
  }
});

export default devices;
