// RALD Auth Core — Verification Engine Routes
// Phase 6: Verification Engine — Artist, Label, Radio, Advertiser
// Statuses: pending | under_review | approved | rejected
// Profiles.RALD.Cloud Hardening Program — LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const verificationEngine = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type VerificationType =
  | "artist"
  | "label"
  | "radio"
  | "advertiser"
  | "media_house"
  | "community";

const VERIFICATION_TYPES: VerificationType[] = [
  "artist", "label", "radio", "advertiser", "media_house", "community",
];

// ── GET /verify/status — current verification status ─────────────────────────
verificationEngine.get("/status", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data, error } = await db
    .from("auth_verifications")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error && error.code !== "PGRST116") {
    console.error("[verify/status] db error:", error.message);
    return c.json({ verifications: [], count: 0, has_approved: false, approved_types: [] });
  }

  const rows = data ?? [];
  return c.json({
    verifications:  rows,
    count:          rows.length,
    has_approved:   rows.some((v: { status: string }) => v.status === "approved"),
    approved_types: rows
      .filter((v: { status: string }) => v.status === "approved")
      .map((v: { verification_type: string }) => v.verification_type),
  });
});

// ── POST /verify/apply — submit verification application ─────────────────────
verificationEngine.post("/apply", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{
    type:          VerificationType;
    name:          string;
    description?:  string;
    website?:      string;
    social_links?: Record<string, string>;
    documents?:    string[];
    metadata?:     Record<string, unknown>;
  }>().catch(() => null);

  if (!body?.type || !body?.name) {
    return c.json({ error: "type and name are required" }, 400);
  }
  if (!VERIFICATION_TYPES.includes(body.type)) {
    return c.json({
      error: `Invalid verification type. Must be one of: ${VERIFICATION_TYPES.join(", ")}`,
    }, 400);
  }

  // Check for existing pending/under_review application for same type
  const { data: existing } = await db
    .from("auth_verifications")
    .select("id,status")
    .eq("user_id", user.id)
    .eq("verification_type", body.type)
    .in("status", ["pending", "under_review"])
    .limit(1);

  // noUncheckedIndexedAccess: existing[0] is T | undefined — must guard
  if (existing && existing.length > 0) {
    const first = existing[0];
    if (first) {
      return c.json({
        error:  "Application already in progress",
        status: (first as { status: string }).status,
        id:     (first as { id: string }).id,
      }, 409);
    }
  }

  const { data: newApp, error } = await db
    .from("auth_verifications")
    .insert({
      user_id:           user.id,
      verification_type: body.type,
      status:            "pending",
      name:              body.name.trim().slice(0, 120),
      description:       body.description?.trim().slice(0, 500) ?? null,
      website:           body.website?.trim().slice(0, 300) ?? null,
      social_links:      body.social_links ?? {},
      documents:         body.documents ?? [],
      metadata:          body.metadata ?? {},
      submitted_at:      new Date().toISOString(),
    })
    .select("*")
    .single();

  if (error) {
    console.error("[verify/apply] insert error:", error.message);
    // Table not yet migrated
    if (error.code === "42P01") {
      return c.json({
        ok:      false,
        message: "Verification table is being set up. Please try again shortly.",
        queued:  true,
      });
    }
    return c.json({ error: "Failed to submit application" }, 500);
  }

  if (!newApp) {
    return c.json({ error: "Failed to retrieve created application" }, 500);
  }

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "verification_applied",
    resourceType: "verification",
    resourceId:   (newApp as { id: string }).id,
    ip,
    status:       "success",
    metadata:     { type: body.type, name: body.name },
  });

  return c.json(
    {
      ok:          true,
      application: newApp,
      message:     "Application submitted. We review applications within 5–10 business days.",
      next_steps: [
        "You will receive an email when your review begins.",
        "Check your status at profiles.rald.cloud.",
        "We may contact you for additional documentation.",
      ],
    },
    201,
  );
});

// ── GET /verify/:id — get specific verification ────────────────────────────────
verificationEngine.get("/:id", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const id   = c.req.param("id");

  const { data, error } = await db
    .from("auth_verifications")
    .select("*")
    .eq("id", id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (error ?? !data) return c.json({ error: "Verification not found" }, 404);
  return c.json(data);
});

// ── DELETE /verify/:id — withdraw application ─────────────────────────────────
verificationEngine.delete("/:id", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const ip   = getClientIp(c.req.raw);
  const id   = c.req.param("id");

  const { data: existing } = await db
    .from("auth_verifications")
    .select("id,status,verification_type")
    .eq("id", id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!existing) return c.json({ error: "Verification not found" }, 404);

  const row = existing as { id: string; status: string; verification_type: string };
  if (row.status === "approved") {
    return c.json({ error: "Cannot withdraw an approved verification" }, 409);
  }

  await db.from("auth_verifications").delete().eq("id", id);

  await writeAuditLog(db, {
    userId:       user.id,
    action:       "verification_withdrawn",
    resourceType: "verification",
    resourceId:   id,
    ip,
    status:       "success",
    metadata:     { type: row.verification_type },
  });

  return c.json({ ok: true, message: "Verification application withdrawn." });
});

// ── POST /verify/badge/:type — request public verification badge ───────────────
verificationEngine.post("/badge/:type", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const type = c.req.param("type") as VerificationType;

  if (!VERIFICATION_TYPES.includes(type)) {
    return c.json({ error: "Invalid verification type" }, 400);
  }

  const { data } = await db
    .from("auth_verifications")
    .select("id,status")
    .eq("user_id", user.id)
    .eq("verification_type", type)
    .eq("status", "approved")
    .maybeSingle();

  if (!data) {
    return c.json({ error: "No approved verification found for this type. Apply first." }, 403);
  }

  const badgeIcons: Record<VerificationType, string> = {
    artist:      "🎵",
    label:       "🏷️",
    radio:       "📻",
    advertiser:  "📢",
    media_house: "📡",
    community:   "🏘️",
  };

  return c.json({
    verified:  true,
    type,
    badge:     badgeIcons[type],
    issued_at: new Date().toISOString(),
    badge_url: `https://profiles.rald.cloud/badges/${type}`,
  });
});

export default verificationEngine;
