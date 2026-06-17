// RALD Phase 1 — Universal Signup Route
// POST /signup       → create rald_users + wallet + ALIA + mail + messenger + emit event
// GET  /signup/status/:rald_id  → provisioning status for a given rald_id
// POST /signup/retry/:rald_id   → admin: force retry all failed steps
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import { createClient } from "@supabase/supabase-js";
import type { Bindings, Variables } from "../index";
import { authMiddleware, adminMiddleware } from "../lib/middleware";
import { writeAuditLog } from "../lib/audit";
import { verifyJwt } from "../lib/auth";
import { checkRateLimit, getClientIp } from "../lib/rate-limit";
import {
  IdentityProvisioner,
  generateRaldId,
  processRetryQueue,
} from "../lib/identity-provisioner";

const signup = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /signup ───────────────────────────────────────────────────────────────
// Full identity provisioning chain.
// Accepts an existing authenticated session OR service-key request.
// Idempotent: calling for an already-provisioned user returns the existing record.
signup.post("/", authMiddleware, async (c) => {
  const t0  = Date.now();
  const db  = c.get("db");
  const user = c.get("user")!;
  const ip  = getClientIp(c.req.raw);

  // Rate-limit: 5 signup attempts per user per hour
  const { allowed } = await checkRateLimit(
    c.env.RATE_LIMIT_KV,
    `signup:${user.id}`,
    5,
    3600
  );
  if (!allowed) return c.json({ error: "Too many signup requests" }, 429);

  // ── Idempotency check: if rald_users record already exists, return it ────
  const { data: existing } = await db
    .from("rald_users")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  if (existing && existing.provision_status === "complete") {
    return c.json({
      ok:                true,
      idempotent:        true,
      rald_id:           existing.id,
      username:          existing.username,
      rald_email:        existing.rald_email,
      alia_handle:       existing.alia_handle,
      wallet_id:         existing.wallet_id,
      messenger_id:      existing.messenger_id,
      activated_products: existing.activated_products,
      provision_status:  existing.provision_status,
      message:           "Identity already fully provisioned",
    });
  }

  // ── Fetch auth_users record for this user ─────────────────────────────────
  const { data: userRows } = await db
    .from("auth_users")
    .select("id,username,email,email_verified,phone_number,phone_verified,name")
    .eq("id", user.id)
    .limit(1);

  const u = userRows?.[0];
  if (!u) return c.json({ error: "User record not found" }, 404);

  const username = (u.username as string | null) ?? null;
  if (!username) {
    return c.json({
      error:   "Username required",
      message: "Claim a username first via POST /auth/register-username before provisioning",
      code:    "USERNAME_REQUIRED",
    }, 422);
  }

  // ── Generate or reuse rald_id ─────────────────────────────────────────────
  const raldId = existing?.id ?? generateRaldId();

  // ── Run full provisioning chain ───────────────────────────────────────────
  const provisioner = new IdentityProvisioner(db);
  const report = await provisioner.provisionAll({
    raldId,
    userId:      u.id as string,
    username,
    email:       u.email as string | null,
    displayName: (u.name as string | null) ?? username,
  });

  // ── Emit identity.created event to events.rald.cloud ─────────────────────
  c.executionCtx?.waitUntil(
    emitIdentityEvent(c.env, {
      rald_id:      raldId,
      user_id:      u.id as string,
      username,
      rald_email:   `${username}@rald.cloud`,
      alia_handle:  `@${username}`,
      wallet_id:    report.wallet_id,
      messenger_id: report.messenger_id,
      provisioned:  report.provisioned,
    })
  );

  // ── Audit ─────────────────────────────────────────────────────────────────
  await writeAuditLog(db, {
    userId: u.id as string,
    action: "identity.provisioned" as any,
    ip,
    status: report.fully_provisioned ? "success" : "partial",
    metadata: {
      rald_id:           raldId,
      provisioned_count: report.provisioned.length,
      failed_count:      report.failed.length,
      duration_ms:       report.duration_ms,
    },
  });

  return c.json({
    ok:                true,
    rald_id:           report.rald_id,
    username,
    rald_email:        report.rald_email,
    alia_handle:       report.alia_handle,
    wallet_id:         report.wallet_id,
    messenger_id:      report.messenger_id,
    mail_id:           report.mail_id,
    provisioned:       report.provisioned,
    failed:            report.failed,
    queued_for_retry:  report.queued_for_retry,
    fully_provisioned: report.fully_provisioned,
    duration_ms:       report.duration_ms,
    message: report.fully_provisioned
      ? `@${username} is fully provisioned across all RALD services`
      : `@${username} provisioned with ${report.failed.length} step(s) queued for retry`,
  }, report.fully_provisioned ? 201 : 207);
});

// ── GET /signup/status/:rald_id ────────────────────────────────────────────────
signup.get("/status/:rald_id", authMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data: identity } = await db
    .from("rald_users")
    .select("*")
    .eq("id", raldId)
    .maybeSingle();

  if (!identity) return c.json({ error: "Identity not found" }, 404);

  // Ensure the requesting user owns this identity
  const user = c.get("user")!;
  if (identity.user_id !== user.id && user.role !== "admin" && user.role !== "operator") {
    return c.json({ error: "Forbidden" }, 403);
  }

  // Fetch audit trail for this identity
  const { data: auditItems } = await db
    .from("provision_audit_log")
    .select("service,event_type,status,error,duration_ms,created_at")
    .eq("rald_id", raldId)
    .order("created_at", { ascending: false })
    .limit(50);

  // Fetch pending retries
  const { data: retries } = await db
    .from("provision_retry_queue")
    .select("service,status,attempt_count,max_attempts,next_retry_at,last_error")
    .eq("rald_id", raldId)
    .in("status", ["pending", "retrying"]);

  const services = ["wallet", "alia", "mail", "messenger"];
  const serviceStatus = services.map(svc => {
    const lastAudit = auditItems?.find(a => a.service === svc);
    const retry     = retries?.find(r => r.service === svc);
    return {
      service:         svc,
      provisioned:     lastAudit?.status === "success",
      status:          lastAudit?.status ?? "not_started",
      pending_retry:   !!retry,
      retry_attempts:  retry?.attempt_count ?? 0,
      next_retry_at:   retry?.next_retry_at ?? null,
      last_error:      lastAudit?.error ?? retry?.last_error ?? null,
    };
  });

  return c.json({
    rald_id:           identity.id,
    username:          identity.username,
    rald_email:        identity.rald_email,
    alia_handle:       identity.alia_handle,
    wallet_id:         identity.wallet_id,
    messenger_id:      identity.messenger_id,
    mail_id:           identity.mail_id,
    trust_score:       identity.trust_score,
    kyc_tier:          identity.kyc_tier,
    activated_products: identity.activated_products,
    provision_status:  identity.provision_status,
    created_at:        identity.created_at,
    services:          serviceStatus,
    audit_trail:       auditItems ?? [],
  });
});

// ── POST /signup/retry/:rald_id — force retry all pending steps ───────────────
signup.post("/retry/:rald_id", adminMiddleware, async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data: identity } = await db
    .from("rald_users")
    .select("id,user_id,username,email,rald_email")
    .eq("id", raldId)
    .maybeSingle();

  if (!identity) return c.json({ error: "Identity not found" }, 404);

  const provisioner = new IdentityProvisioner(db);
  const input = {
    raldId:      identity.id as string,
    userId:      identity.user_id as string,
    username:    identity.username as string,
    email:       identity.email as string | null,
    displayName: identity.username as string,
  };

  // Run all steps — idempotent, skips already-provisioned ones
  const report = await provisioner.provisionAll(input);
  await provisioner.finalizeIdentity(raldId);

  return c.json({
    ok:                true,
    rald_id:           raldId,
    provisioned:       report.provisioned,
    failed:            report.failed,
    fully_provisioned: report.fully_provisioned,
    duration_ms:       report.duration_ms,
  });
});

// ── Event emission to events.rald.cloud ───────────────────────────────────────
async function emitIdentityEvent(env: Bindings, payload: Record<string, unknown>): Promise<void> {
  const eventsUrl = env.EVENTS_BUS_URL ?? "https://events.rald.cloud";
  const secret    = env.RALD_INTERNAL_SECRET;
  if (!secret) {
    console.log("[signup] RALD_INTERNAL_SECRET not set — logging event:", JSON.stringify(payload));
    return;
  }
  try {
    const res = await fetch(`${eventsUrl}/events`, {
      method:  "POST",
      headers: {
        "Content-Type":        "application/json",
        "X-Source-Service":    "rald-auth-core",
        "X-RALD-Internal-Key": secret,
      },
      body: JSON.stringify({
        event_type: "identity.created",
        source:     "rald-auth-core",
        user_id:    payload.user_id,
        actor_id:   payload.user_id,
        payload,
      }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) {
      console.warn("[signup] event emission failed:", res.status, await res.text());
    }
  } catch (err) {
    console.warn("[signup] event emission error:", String(err));
  }
}

export default signup;
