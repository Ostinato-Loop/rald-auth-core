// RALD OS Phase 3 — Trust Engine
// Single trust source for every product. PayRald reads tier before allowing
// transfers. ALIA reads merchant_score before routing. Elimu reads school_score.
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

const trust = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /trust/me — own trust profile ─────────────────────────────────────────
trust.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data: raldUser } = await db
    .from("rald_users").select("id").eq("user_id", user.id).maybeSingle();

  const { data } = await db
    .from("rald_trust_profiles")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  if (!data) {
    return c.json({
      user_id:          user.id,
      rald_id:          raldUser?.id ?? null,
      trust_tier:       "none",
      trust_score:      0,
      kyc_tier:         0,
      phone_verified:   false,
      email_verified:   false,
      is_merchant:      false,
      is_creator:       false,
      is_school:        false,
      message:          "Trust profile not yet created — sign up via POST /signup",
    });
  }

  return c.json(data);
});

// ── GET /trust/:rald_id — trust profile by RALD ID (service-to-service) ───────
trust.get("/:rald_id", authMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data } = await db
    .from("rald_trust_profiles")
    .select("rald_id,user_id,trust_score,trust_tier,kyc_tier,fraud_score,reputation_score,merchant_score,school_score,phone_verified,email_verified,bvn_verified,nin_verified,is_merchant,is_creator,is_school,sanctions_flagged,fraud_flagged,last_computed_at")
    .eq("rald_id", raldId)
    .maybeSingle();

  if (!data) return c.json({ error: "Trust profile not found" }, 404);
  return c.json(data);
});

// ── POST /trust/:rald_id/provision — create trust profile on signup ────────────
trust.post("/:rald_id/provision", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");
  const ip     = getClientIp(c.req.raw);

  const { data: raldUser } = await db
    .from("rald_users")
    .select("id,user_id,username")
    .eq("id", raldId)
    .maybeSingle();
  if (!raldUser) return c.json({ error: "rald_users record not found" }, 404);

  const { data, error } = await db.from("rald_trust_profiles").upsert({
    rald_id:     raldId,
    user_id:     raldUser.user_id,
    trust_score: 50,   // 50 points on signup — has RALD identity
    kyc_tier:    0,
    trust_tier:  "none",
  }, { onConflict: "rald_id" }).select().single();

  if (error) return c.json({ error: error.message }, 500);

  await writeAuditLog(db, {
    userId: raldUser.user_id as string,
    action: "trust.recomputed" as any,
    ip,
    status: "success",
    metadata: { rald_id: raldId, trust_score: 50 },
  });

  return c.json({ ok: true, trust: data }, 201);
});

// ── POST /trust/:rald_id/recompute — admin: recompute trust score ──────────────
trust.post("/:rald_id/recompute", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");
  const ip     = getClientIp(c.req.raw);

  const { data: profile } = await db
    .from("rald_trust_profiles").select("*").eq("rald_id", raldId).maybeSingle();
  if (!profile) return c.json({ error: "Trust profile not found" }, 404);

  // Score computation: additive model
  let score = 0;
  if (profile.phone_verified)   score += 100;
  if (profile.email_verified)   score += 80;
  if (profile.bvn_verified)     score += 200;
  if (profile.nin_verified)     score += 150;
  if (profile.address_verified) score += 50;
  if (profile.kyc_tier >= 1)    score += 50;
  if (profile.kyc_tier >= 2)    score += 100;
  if (profile.kyc_tier >= 3)    score += 150;
  score = Math.max(0, Math.min(1000, score));

  const { data, error } = await db.from("rald_trust_profiles")
    .update({ trust_score: score, last_computed_at: new Date().toISOString() })
    .eq("rald_id", raldId)
    .select().single();

  if (error) return c.json({ error: error.message }, 500);

  await writeAuditLog(db, {
    action: "trust.recomputed" as any,
    ip,
    status: "success",
    metadata: { rald_id: raldId, old_score: profile.trust_score, new_score: score },
  });

  return c.json({ ok: true, rald_id: raldId, trust_score: score, trust_tier: data.trust_tier });
});

// ── PATCH /trust/:rald_id — admin: update specific trust fields ────────────────
trust.patch("/:rald_id", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");
  const ip     = getClientIp(c.req.raw);

  const body = await c.req.json<Partial<{
    kyc_tier:         number;
    phone_verified:   boolean;
    email_verified:   boolean;
    bvn_verified:     boolean;
    nin_verified:     boolean;
    address_verified: boolean;
    fraud_flagged:    boolean;
    sanctions_flagged:boolean;
    is_merchant:      boolean;
    is_creator:       boolean;
    is_school:        boolean;
    fraud_score:      number;
    merchant_score:   number;
    school_score:     number;
    review_note:      string;
    manually_reviewed:boolean;
  }>>().catch(() => null);
  if (!body) return c.json({ error: "Invalid JSON body" }, 400);

  const ALLOWED = new Set([
    "kyc_tier","phone_verified","email_verified","bvn_verified","nin_verified",
    "address_verified","fraud_flagged","sanctions_flagged","is_merchant","is_creator",
    "is_school","fraud_score","merchant_score","school_score","review_note","manually_reviewed",
  ]);
  const update: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const [k, v] of Object.entries(body)) {
    if (ALLOWED.has(k)) update[k] = v;
  }

  const { data, error } = await db.from("rald_trust_profiles")
    .update(update).eq("rald_id", raldId).select().single();

  if (error) return c.json({ error: error.message }, 500);

  await writeAuditLog(db, {
    action: "trust.recomputed" as any,
    ip,
    status: "success",
    metadata: { rald_id: raldId, updated_fields: Object.keys(update) },
  });

  return c.json({ ok: true, trust: data });
});

// ── GET /trust/leaderboard — top trust scores (public) ────────────────────────
trust.get("/leaderboard", async (c) => {
  const db    = c.get("db");
  const limit = Math.min(100, Number(c.req.query("limit") ?? "20"));

  const { data } = await db
    .from("rald_trust_profiles")
    .select("rald_id,trust_score,trust_tier,is_merchant,is_creator,is_school,last_computed_at")
    .gte("trust_score", 200)
    .eq("fraud_flagged", false)
    .eq("sanctions_flagged", false)
    .order("trust_score", { ascending: false })
    .limit(limit);

  return c.json({ leaderboard: data ?? [], count: data?.length ?? 0 });
});

export default trust;
