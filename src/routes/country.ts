// RALD Auth Core — Country Activation Framework
// Public endpoints: status check, access gate, waitlist join
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { getClientIp } from "../lib/rate-limit";

const country = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Statuses that allow full access
const FULL_ACCESS_STATUSES  = new Set(["ACTIVE", "PUBLIC_BETA"]);
// Statuses that allow limited onboarding (username reserve, profile create)
const PREVIEW_STATUSES      = new Set(["PREVIEW", "PRIVATE_BETA", "PUBLIC_BETA", "ACTIVE"]);
// Statuses completely blocked
const BLOCKED_STATUSES      = new Set(["WAITLIST", "REGULATORY_REVIEW", "INFRASTRUCTURE_REVIEW", "MODERATION_REVIEW"]);

function statusMessage(status: string, countryName: string): string {
  switch (status) {
    case "ACTIVE":               return `RALD is live in ${countryName}.`;
    case "PUBLIC_BETA":          return `RALD is in public beta in ${countryName}.`;
    case "PRIVATE_BETA":         return `RALD is in invite-only beta in ${countryName}. You need an invite code.`;
    case "PREVIEW":              return `RALD is coming soon to ${countryName}. You can reserve your username now.`;
    case "MODERATION_REVIEW":    return `RALD is preparing moderation infrastructure for ${countryName}.`;
    case "INFRASTRUCTURE_REVIEW":return `RALD is reviewing infrastructure for ${countryName}.`;
    case "REGULATORY_REVIEW":    return `RALD is completing legal and regulatory review for ${countryName}.`;
    case "WAITLIST":             return `RALD is not active in ${countryName} yet. Join the waitlist and help bring RALD to your region.`;
    case "RESTRICTED":           return `RALD is temporarily unavailable in ${countryName}.`;
    default:                     return `RALD is not available in ${countryName} yet.`;
  }
}

// ── GET /country/:code — public country status ────────────────────────────────
country.get("/:code", async (c) => {
  const db   = c.get("db");
  const code = c.req.param("code").toUpperCase().slice(0, 2);

  const { data, error } = await db
    .from("country_registry")
    .select("country_code, country_name, status, demand_score, launch_date, payrald_status")
    .eq("country_code", code)
    .limit(1)
    .single();

  if (error || !data) {
    return c.json({
      country_code: code,
      status:       "WAITLIST",
      available:    false,
      message:      `RALD is not active in your country yet. Join the waitlist and help bring RALD to your region.`,
    });
  }

  const status    = data.status as string;
  const available = FULL_ACCESS_STATUSES.has(status);
  const preview   = PREVIEW_STATUSES.has(status) && !available;

  return c.json({
    country_code:   data.country_code,
    country_name:   data.country_name,
    status,
    available,
    preview_access: preview,
    payrald_status: data.payrald_status,
    launch_date:    data.launch_date ?? null,
    message:        statusMessage(status, data.country_name),
    ...(BLOCKED_STATUSES.has(status) && {
      waitlist_available: true,
      cta: "Join the waitlist — be first when RALD launches near you.",
    }),
  });
});

// ── GET /country/:code/access — structured access gates ──────────────────────
// Used by Loop, Civic Engine, Business Workspace to check feature access per country.
country.get("/:code/access", async (c) => {
  const db   = c.get("db");
  const code = c.req.param("code").toUpperCase().slice(0, 2);

  const { data } = await db
    .from("country_registry")
    .select("country_code, country_name, status, payrald_status")
    .eq("country_code", code)
    .limit(1)
    .single();

  const status         = (data?.status ?? "WAITLIST") as string;
  const payraldStatus  = (data?.payrald_status ?? "WAITLIST") as string;
  const countryName    = data?.country_name ?? code;

  const active         = FULL_ACCESS_STATUSES.has(status);
  const previewAccess  = PREVIEW_STATUSES.has(status);
  const restricted     = status === "RESTRICTED";

  return c.json({
    country_code: code,
    country_name: countryName,
    status,
    gates: {
      loop_rooms:         active,
      loop_feed:          active,
      civic_rooms:        active,
      messenger:          previewAccess,
      username_reserve:   previewAccess || BLOCKED_STATUSES.has(status) === false,
      profile_create:     previewAccess,
      business_workspace: active,
      payrald:            FULL_ACCESS_STATUSES.has(payraldStatus),
      creator_rankings:   active,
      regional_feed:      previewAccess,
    },
    restricted,
    message: statusMessage(status, countryName),
  });
});

// ── POST /country/waitlist — join country waitlist ────────────────────────────
country.post("/waitlist", async (c) => {
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);
  const body = await c.req.json<{
    country_code: string;
    state?:       string;
    city?:        string;
    email?:       string;
    username?:    string;
  }>().catch(() => null);

  if (!body?.country_code) return c.json({ error: "country_code is required" }, 400);
  const code = body.country_code.toUpperCase().slice(0, 2);

  // Check if country is in WAITLIST (only waitlisted countries accept new entries)
  const { data: reg } = await db
    .from("country_registry")
    .select("country_name, status")
    .eq("country_code", code)
    .limit(1)
    .single();

  const status      = (reg?.status ?? "WAITLIST") as string;
  const countryName = reg?.country_name ?? code;

  if (FULL_ACCESS_STATUSES.has(status)) {
    return c.json({
      message:  `RALD is already live in ${countryName} — no waitlist needed!`,
      status,
      action:   "create_account",
    });
  }

  // Hash IP for privacy
  const ipBytes  = new TextEncoder().encode(ip + code);
  const hashBuf  = await crypto.subtle.digest("SHA-256", ipBytes);
  const ipHash   = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);

  // Insert waitlist entry (ignore duplicate ip_hash per country)
  const { error } = await db
    .from("country_waitlist")
    .insert({
      country_code: code,
      state:    body.state    ?? null,
      city:     body.city     ?? null,
      email:    body.email    ?? null,
      username: body.username ?? null,
      ip_hash:  ipHash,
    });

  if (error) {
    console.warn("[country-waitlist] insert error:", error.message);
  }

  // Update demand score: count distinct waitlist entries
  const { count } = await db
    .from("country_waitlist")
    .select("id", { count: "exact", head: true })
    .eq("country_code", code);

  const demandScore = Math.min(99, Math.round(Math.log10(Math.max(1, count ?? 0) + 1) * 33));
  await db
    .from("country_registry")
    .upsert({ country_code: code, country_name: countryName, status, demand_score: demandScore }, { onConflict: "country_code" });

  return c.json({
    ok:           true,
    country_code: code,
    country_name: countryName,
    status,
    message:      `You're on the waitlist for ${countryName}. We'll notify you when RALD launches near you.`,
    demand_score: demandScore,
  });
});

// ── GET /country — list all publicly visible countries ────────────────────────
country.get("/", async (c) => {
  const db = c.get("db");
  const { data } = await db
    .from("country_registry")
    .select("country_code, country_name, status, demand_score, launch_date")
    .order("status", { ascending: false })
    .order("demand_score", { ascending: false });

  const grouped: Record<string, typeof data> = {
    active:       [],
    beta:         [],
    coming_soon:  [],
    waitlist:     [],
  };

  for (const row of data ?? []) {
    if (!row) continue;
    if (row.status === "ACTIVE")                      grouped["active"]!.push(row);
    else if (["PUBLIC_BETA","PRIVATE_BETA"].includes(row.status)) grouped["beta"]!.push(row);
    else if (["PREVIEW"].includes(row.status))        grouped["coming_soon"]!.push(row);
    else                                              grouped["waitlist"]!.push(row);
  }

  return c.json({ ok: true, countries: grouped, total: (data ?? []).length });
});

export default country;
