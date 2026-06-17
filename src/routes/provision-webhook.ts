// RALD OS Phase 2 — Async Provisioning Webhook
// Receives identity.created events from events.rald.cloud.
// Triggers the full provisioning chain asynchronously.
// This makes provisioning truly decoupled from the signup HTTP request.
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import { createClient } from "@supabase/supabase-js";
import type { Bindings, Variables } from "../index";
import { IdentityProvisioner, generateRaldId } from "../lib/identity-provisioner";

const webhook = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── POST /provision/webhook — receive identity.created from event bus ──────────
// Verifies HMAC signature from events.rald.cloud before processing.
webhook.post("/webhook", async (c) => {
  const body   = await c.req.text();
  const sigHex = c.req.header("X-RALD-Signature") ?? "";
  const secret = c.env.RALD_INTERNAL_SECRET;

  if (!secret) {
    // If no secret configured, accept from trusted internal origins only
    const source = c.req.header("X-Source-Service");
    if (source !== "rald-auth-core" && source !== "rald-event-bus") {
      return c.json({ error: "Forbidden" }, 403);
    }
  } else {
    // Verify HMAC-SHA256 signature
    const valid = await verifyHmac(body, sigHex, secret);
    if (!valid) return c.json({ error: "Invalid signature" }, 401);
  }

  let event: Record<string, unknown>;
  try { event = JSON.parse(body); } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (event.event_type !== "identity.created") {
    return c.json({ ok: true, skipped: true, reason: `event_type '${event.event_type}' not handled here` });
  }

  const payload = event.payload as Record<string, unknown>;
  const raldId  = payload.rald_id as string | undefined;
  const userId  = payload.user_id as string | undefined;
  const username = payload.username as string | undefined;

  if (!raldId || !userId || !username) {
    return c.json({ error: "Missing rald_id, user_id, or username in payload" }, 400);
  }

  // Fire-and-forget via waitUntil — respond immediately, process async
  c.executionCtx?.waitUntil(
    runAsyncProvisioning(c.env, { raldId, userId, username, email: payload.email as string | null })
  );

  return c.json({
    ok:         true,
    accepted:   true,
    rald_id:    raldId,
    event_type: event.event_type,
    message:    "Provisioning chain triggered asynchronously",
  });
});

// ── Async provisioning chain ───────────────────────────────────────────────────
async function runAsyncProvisioning(
  env: Bindings,
  input: { raldId: string; userId: string; username: string; email?: string | null }
): Promise<void> {
  const db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);

  // Check if already fully provisioned (idempotency)
  const { data: existing } = await db
    .from("rald_users")
    .select("provision_status")
    .eq("id", input.raldId)
    .maybeSingle();

  if (existing?.provision_status === "complete") {
    console.log(`[provision-webhook] ${input.raldId} already complete — skipping`);
    return;
  }

  const provisioner = new IdentityProvisioner(db);
  const report = await provisioner.provisionAll({
    raldId:   input.raldId,
    userId:   input.userId,
    username: input.username,
    email:    input.email ?? null,
  });

  // Also provision trust profile
  await db.from("rald_trust_profiles").upsert({
    rald_id:     input.raldId,
    user_id:     input.userId,
    trust_score: 50,
    kyc_tier:    0,
    trust_tier:  "none",
  }, { onConflict: "rald_id" });

  console.log(JSON.stringify({
    level:             "info",
    msg:               "async-provisioning-complete",
    rald_id:           input.raldId,
    provisioned:       report.provisioned,
    failed:            report.failed.length,
    fully_provisioned: report.fully_provisioned,
    duration_ms:       report.duration_ms,
  }));
}

// ── HMAC-SHA256 verification ───────────────────────────────────────────────────
async function verifyHmac(body: string, sigHex: string, secret: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
    const computed = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
    return computed === sigHex;
  } catch { return false; }
}

export default webhook;
