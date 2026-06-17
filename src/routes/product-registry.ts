// RALD OS Phase 4 — Product Registry
// Every RALD product is registered here. New products auto-recognize existing users.
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { adminMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const products = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /products — list all active products (public) ─────────────────────────
products.get("/", async (c) => {
  const db     = c.get("db");
  const status = c.req.query("status") ?? "active";

  const { data, error } = await db
    .from("rald_products")
    .select("slug,name,description,status,base_url,api_endpoint,icon_url,billing_model,auto_provision,permissions,created_at")
    .eq("status", status)
    .order("created_at", { ascending: true });

  if (error) return c.json({ error: "Failed to list products" }, 500);
  return c.json({ products: data ?? [], count: data?.length ?? 0 });
});

// ── GET /products/:slug — get one product ─────────────────────────────────────
products.get("/:slug", async (c) => {
  const db   = c.get("db");
  const slug = c.req.param("slug");

  const { data } = await db
    .from("rald_products")
    .select("*")
    .eq("slug", slug)
    .maybeSingle();

  if (!data) return c.json({ error: "Product not found" }, 404);
  return c.json(data);
});

// ── POST /products — admin: register a new product ────────────────────────────
products.post("/", adminMiddleware, async (c) => {
  const db = c.get("db");
  const ip = getClientIp(c.req.raw);

  const body = await c.req.json<{
    slug:           string;
    name:           string;
    description?:   string;
    owner?:         string;
    status?:        string;
    base_url?:      string;
    api_endpoint?:  string;
    health_url?:    string;
    icon_url?:      string;
    billing_model?: string;
    permissions?:   string[];
    auto_provision?:boolean;
    metadata?:      Record<string, unknown>;
  }>().catch(() => null);

  if (!body?.slug || !body?.name) {
    return c.json({ error: "slug and name are required" }, 400);
  }
  if (!/^[a-z0-9-]+$/.test(body.slug)) {
    return c.json({ error: "slug must be lowercase alphanumeric with hyphens only" }, 400);
  }

  const { data, error } = await db.from("rald_products").insert({
    slug:           body.slug,
    name:           body.name,
    description:    body.description ?? null,
    owner:          body.owner ?? "LILCKY STUDIO LIMITED",
    status:         body.status ?? "beta",
    base_url:       body.base_url ?? null,
    api_endpoint:   body.api_endpoint ?? null,
    health_url:     body.health_url ?? null,
    icon_url:       body.icon_url ?? null,
    billing_model:  body.billing_model ?? "free",
    permissions:    body.permissions ?? [],
    auto_provision: body.auto_provision ?? false,
    metadata:       body.metadata ?? {},
  }).select().single();

  if (error) {
    if (error.code === "23505") return c.json({ error: `Product '${body.slug}' already exists` }, 409);
    return c.json({ error: error.message }, 500);
  }

  await writeAuditLog(db, {
    action: "app_provisioned" as any,
    ip,
    status: "success",
    metadata: { slug: body.slug, name: body.name },
  });

  return c.json({ ok: true, product: data }, 201);
});

// ── PATCH /products/:slug — admin: update product ─────────────────────────────
products.patch("/:slug", adminMiddleware, async (c) => {
  const db   = c.get("db");
  const slug = c.req.param("slug");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<Record<string, unknown>>().catch(() => null);
  if (!body) return c.json({ error: "Invalid body" }, 400);

  const ALLOWED = new Set(["name","description","status","base_url","api_endpoint","health_url","icon_url","billing_model","permissions","auto_provision","metadata","owner"]);
  const update: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const [k, v] of Object.entries(body)) {
    if (ALLOWED.has(k)) update[k] = v;
  }

  const { data, error } = await db.from("rald_products")
    .update(update).eq("slug", slug).select().single();

  if (error) return c.json({ error: error.message }, 500);
  await writeAuditLog(db, { action: "app_provisioned" as any, ip, status: "success", metadata: { slug, updated: Object.keys(update) } });
  return c.json({ ok: true, product: data });
});

// ── GET /products/:slug/health — check health of a product ────────────────────
products.get("/:slug/health", async (c) => {
  const db   = c.get("db");
  const slug = c.req.param("slug");

  const { data } = await db.from("rald_products").select("health_url,name,status").eq("slug", slug).maybeSingle();
  if (!data) return c.json({ error: "Product not found" }, 404);
  if (!data.health_url) return c.json({ slug, name: data.name, health: "unknown", reason: "No health_url configured" });

  const t0 = Date.now();
  try {
    const res = await fetch(data.health_url as string, { signal: AbortSignal.timeout(5000) });
    return c.json({
      slug,
      name:       data.name,
      health:     res.ok ? "ok" : "degraded",
      status_code: res.status,
      latency_ms:  Date.now() - t0,
    });
  } catch {
    return c.json({ slug, name: data.name, health: "down", latency_ms: Date.now() - t0 });
  }
});

// ── GET /products/ecosystem/health — aggregate health of all products ──────────
products.get("/ecosystem/health", async (c) => {
  const db = c.get("db");
  const { data: prods } = await db
    .from("rald_products")
    .select("slug,name,health_url,status")
    .eq("status", "active");

  const checks = await Promise.allSettled(
    (prods ?? []).map(async (p: any) => {
      if (!p.health_url) return { slug: p.slug, name: p.name, health: "unknown" };
      const t0 = Date.now();
      try {
        const res = await fetch(p.health_url, { signal: AbortSignal.timeout(4000) });
        return { slug: p.slug, name: p.name, health: res.ok ? "ok" : "degraded", latency_ms: Date.now() - t0 };
      } catch {
        return { slug: p.slug, name: p.name, health: "down", latency_ms: Date.now() - t0 };
      }
    })
  );

  const results = checks.map(r => r.status === "fulfilled" ? r.value : { health: "error" });
  const allOk   = results.every(r => r.health === "ok" || r.health === "unknown");

  return c.json({
    ecosystem_health: allOk ? "ok" : "degraded",
    products: results,
    generated_at: new Date().toISOString(),
  }, allOk ? 200 : 207);
});

export default products;
