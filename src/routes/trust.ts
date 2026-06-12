// RALD Auth Core — Trust Engine Routes
// Sprint: Operator Platform Phase 5 · 2026-06-12
// Compute, query, and manage trust scores for users.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { getClientIp } from "../lib/rate-limit";
import { writeAuditLog } from "../lib/audit";

const trust = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Shape returned by the compute_trust_score Supabase RPC
interface TrustScoreResult {
  score: number;
  tier: string;
}

// ── GET /trust/score — get own trust score ────────────────────────────────────
trust.get("/trust/score", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const { data } = await db.from("trust_scores").select("*").eq("user_id", user.id).single();
  if (!data) {
    const { data: computedRaw } = await db.rpc("compute_trust_score", { p_user_id: user.id }).single();
    const computed = computedRaw as TrustScoreResult | null;
    return c.json({ user_id: user.id, score: computed?.score ?? 0, tier: computed?.tier ?? "none", computed_now: true });
  }
  return c.json(data);
});

// ── POST /trust/compute — (re)compute trust score for calling user ─────────────
trust.post("/trust/compute", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db = c.get("db");
  const { data: computedRaw, error } = await db.rpc("compute_trust_score", { p_user_id: user.id }).single();
  if (error) return c.json({ error: "Failed to compute trust score" }, 500);
  const computed = computedRaw as TrustScoreResult | null;
  return c.json({ user_id: user.id, score: computed?.score ?? 0, tier: computed?.tier ?? "none" });
});

// ── GET /trust/score/:userId — get user trust (admin or internal) ─────────────
trust.get("/trust/score/:userId", adminMiddleware, async (c) => {
  const db = c.get("db");
  const userId = c.req.param("userId");
  const { data } = await db.from("trust_scores").select("*").eq("user_id", userId).single();
  if (!data) {
    const { data: computedRaw } = await db.rpc("compute_trust_score", { p_user_id: userId }).single();
    const computed = computedRaw as TrustScoreResult | null;
    return c.json({ user_id: userId, score: computed?.score ?? 0, tier: computed?.tier ?? "none", computed_now: true });
  }
  return c.json(data);
});

// ── POST /trust/compute/:userId — force recompute (admin only) ────────────────
trust.post("/trust/compute/:userId", adminMiddleware, async (c) => {
  const db = c.get("db");
  const admin = c.get("user")!;
  const ip = getClientIp(c.req.raw);
  const userId = c.req.param("userId");
  const { data: computedRaw, error } = await db.rpc("compute_trust_score", { p_user_id: userId }).single();
  if (error) return c.json({ error: "Failed to compute trust score" }, 500);
  const computed = computedRaw as TrustScoreResult | null;
  await writeAuditLog(db, {
    userId: admin.id, action: "trust.recomputed", ip, status: "success",
    metadata: { target_user_id: userId, score: computed?.score, tier: computed?.tier },
  });
  return c.json({ user_id: userId, score: computed?.score ?? 0, tier: computed?.tier ?? "none" });
});

// ── GET /trust/distribution — trust tier distribution (admin) ─────────────────
trust.get("/trust/distribution", adminMiddleware, async (c) => {
  const db = c.get("db");
  const { data, error } = await db.from("trust_scores")
    .select("tier")
    .then(async (r) => {
      if (r.error) return r;
      const distribution: Record<string, number> = {};
      for (const row of r.data ?? []) {
        distribution[row.tier] = (distribution[row.tier] ?? 0) + 1;
      }
      return { data: distribution, error: null };
    });
  if (error) return c.json({ error: "Failed to fetch distribution" }, 500);
  return c.json({ distribution: data });
});

export default trust;
