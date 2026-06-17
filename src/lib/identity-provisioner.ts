// RALD Phase 1 — Identity Provisioner
// Orchestrates creation of every core service record for a new RALD user.
// Idempotent: safe to call multiple times — uses upsert everywhere.
// Adds failed steps to provision_retry_queue automatically.
// LILCKY STUDIO LIMITED · 2026-06-17

import type { SupabaseClient } from "@supabase/supabase-js";

// ── ID generators ──────────────────────────────────────────────────────────────
const CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";

export function generateRaldId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let suffix = "";
  for (const b of bytes) suffix += CHARSET[b % CHARSET.length];
  return `rld_${suffix}`;
}

export function walletId(raldId: string): string    { return `wallet_${raldId}`; }
export function messengerId(raldId: string): string  { return `msg_${raldId}`; }
export function mailId(raldId: string): string       { return `mail_${raldId}`; }
export function aliaId(raldId: string): string       { return `alia_${raldId}`; }

// ── Types ──────────────────────────────────────────────────────────────────────
export interface ProvisionInput {
  raldId:      string;
  userId:      string;    // auth_users.id (UUID)
  username:    string;
  email?:      string | null;
  displayName?: string | null;
}

export interface StepResult {
  ok:    boolean;
  error?: string;
}

export interface ProvisionReport {
  rald_id:           string;
  wallet_id:         string;
  messenger_id:      string;
  mail_id:           string;
  alia_id:           string;
  rald_email:        string;
  alia_handle:       string;
  provisioned:       string[];
  failed:            Array<{ service: string; error: string }>;
  queued_for_retry:  string[];
  fully_provisioned: boolean;
  duration_ms:       number;
}

// ── IdentityProvisioner class ──────────────────────────────────────────────────
export class IdentityProvisioner {
  private provisioned:      string[]                              = [];
  private failed:           Array<{ service: string; error: string }> = [];
  private queued_for_retry: string[]                              = [];

  constructor(private db: SupabaseClient) {}

  // ── Audit log helper (best-effort, never throws) ──────────────────────────
  private async audit(
    raldId:    string,
    service:   string,
    eventType: string,
    status:    "success" | "failed" | "skipped",
    payload:   Record<string, unknown> = {},
    error?:    string,
    durationMs?: number
  ): Promise<void> {
    await Promise.resolve(
      this.db.from("provision_audit_log").insert({
        rald_id:     raldId,
        event_type:  eventType,
        service,
        status,
        payload,
        error:       error ?? null,
        duration_ms: durationMs ?? null,
      })
    ).then(undefined, (e: unknown) => console.warn("[provision-audit] write failed:", String(e)));
  }

  // ── Retry queue (best-effort, never throws) ───────────────────────────────
  private async enqueueRetry(
    raldId:  string,
    service: string,
    payload: Record<string, unknown>,
    error:   string
  ): Promise<void> {
    this.queued_for_retry.push(service);
    const nextRetryAt = new Date(Date.now() + 30_000).toISOString(); // retry in 30s
    await Promise.resolve(
      this.db.from("provision_retry_queue").insert({
        rald_id:       raldId,
        service,
        payload,
        last_error:    error,
        next_retry_at: nextRetryAt,
        status:        "pending",
      })
    ).then(undefined, (e: unknown) => console.warn("[provision-retry] enqueue failed:", String(e)));
  }

  // ── Step runner helper ────────────────────────────────────────────────────
  private async step(
    raldId:    string,
    service:   string,
    eventType: string,
    payload:   Record<string, unknown>,
    fn:        () => Promise<void>
  ): Promise<StepResult> {
    const t0 = Date.now();
    try {
      await fn();
      this.provisioned.push(service);
      await this.audit(raldId, service, eventType, "success", payload, undefined, Date.now() - t0);
      return { ok: true };
    } catch (err) {
      const msg = String(err);
      this.failed.push({ service, error: msg });
      await this.audit(raldId, service, eventType, "failed", payload, msg, Date.now() - t0);
      await this.enqueueRetry(raldId, service, payload, msg);
      return { ok: false, error: msg };
    }
  }

  // ── 1. Create rald_users record ───────────────────────────────────────────
  async createIdentityRecord(input: ProvisionInput): Promise<StepResult> {
    const { raldId, userId, username, email, displayName } = input;
    return this.step(raldId, "identity", "identity.created", { rald_id: raldId, username }, async () => {
      const { error } = await this.db.from("rald_users").upsert({
        id:               raldId,
        user_id:          userId,
        username,
        email:            email ?? null,
        rald_email:       `${username}@rald.cloud`,
        alia_handle:      `@${username}`,
        wallet_id:        walletId(raldId),
        messenger_id:     messengerId(raldId),
        mail_id:          mailId(raldId),
        trust_score:      0,
        kyc_tier:         0,
        activated_products: ["auth"],
        provision_status: "provisioning",
      }, { onConflict: "user_id" });
      if (error) throw new Error(error.message);
    });
  }

  // ── 2. Create wallet ───────────────────────────────────────────────────────
  async createWallet(input: ProvisionInput): Promise<StepResult> {
    const { raldId, userId, username } = input;
    const wId = walletId(raldId);
    return this.step(raldId, "wallet", "wallet.created", { wallet_id: wId }, async () => {
      const { error } = await this.db.from("payrald_wallets").upsert({
        id:          wId,
        rald_id:     raldId,
        user_id:     userId,
        balance_ngn: 0,
        currency:    "NGN",
        status:      "active",
      }, { onConflict: "rald_id" });
      if (error) throw new Error(error.message);
    });
  }

  // ── 3. Create ALIA handle ─────────────────────────────────────────────────
  async createAliaHandle(input: ProvisionInput): Promise<StepResult> {
    const { raldId, userId, username } = input;
    const aId    = aliaId(raldId);
    const handle = `@${username}`;
    return this.step(raldId, "alia", "alias.created", { alia_id: aId, handle }, async () => {
      const { error } = await this.db.from("alia_handles").upsert({
        id:      aId,
        rald_id: raldId,
        user_id: userId,
        handle,
        status:  "active",
      }, { onConflict: "rald_id" });
      if (error) throw new Error(error.message);
    });
  }

  // ── 4. Create mailbox ─────────────────────────────────────────────────────
  async createMailAccount(input: ProvisionInput): Promise<StepResult> {
    const { raldId, userId, username, displayName } = input;
    const mId    = mailId(raldId);
    const address = `${username}@rald.cloud`;
    return this.step(raldId, "mail", "mailbox.created", { mail_id: mId, address }, async () => {
      const { error } = await this.db.from("mail_accounts").upsert({
        id:           mId,
        rald_id:      raldId,
        user_id:      userId,
        address,
        display_name: displayName ?? username,
        status:       "active",
      }, { onConflict: "rald_id" });
      if (error) throw new Error(error.message);
    });
  }

  // ── 5. Create messenger account ───────────────────────────────────────────
  async createMessengerAccount(input: ProvisionInput): Promise<StepResult> {
    const { raldId, userId, username, displayName } = input;
    const msgId = messengerId(raldId);
    return this.step(raldId, "messenger", "messenger.created", { messenger_id: msgId }, async () => {
      const { error } = await this.db.from("messenger_accounts").upsert({
        id:           msgId,
        rald_id:      raldId,
        user_id:      userId,
        username,
        display_name: displayName ?? username,
        status:       "active",
      }, { onConflict: "rald_id" });
      if (error) throw new Error(error.message);
    });
  }

  // ── 6. Mark provision complete and update activated_products ─────────────
  async finalizeIdentity(raldId: string): Promise<void> {
    const services = this.provisioned.filter(s =>
      ["wallet","alia","mail","messenger"].includes(s)
    );
    const allComplete = this.failed.length === 0;
    await Promise.resolve(
      this.db.from("rald_users").update({
        activated_products: ["auth", ...services],
        provision_status:   allComplete ? "complete" : "partial",
        updated_at:         new Date().toISOString(),
      }).eq("id", raldId)
    ).then(undefined, (e: unknown) => console.warn("[provision] finalize failed:", String(e)));
  }

  // ── Main orchestrator: run all steps ───────────────────────────────────────
  async provisionAll(input: ProvisionInput): Promise<ProvisionReport> {
    const t0 = Date.now();

    // Run all steps in sequence (identity must be first; rest are parallel-safe)
    await this.createIdentityRecord(input);
    await Promise.all([
      this.createWallet(input),
      this.createAliaHandle(input),
      this.createMailAccount(input),
      this.createMessengerAccount(input),
    ]);

    await this.finalizeIdentity(input.raldId);

    return {
      rald_id:           input.raldId,
      wallet_id:         walletId(input.raldId),
      messenger_id:      messengerId(input.raldId),
      mail_id:           mailId(input.raldId),
      alia_id:           aliaId(input.raldId),
      rald_email:        `${input.username}@rald.cloud`,
      alia_handle:       `@${input.username}`,
      provisioned:       this.provisioned,
      failed:            this.failed,
      queued_for_retry:  this.queued_for_retry,
      fully_provisioned: this.failed.length === 0,
      duration_ms:       Date.now() - t0,
    };
  }
}

// ── Retry processor: called by scheduled job ───────────────────────────────────
// Picks up to 50 pending retries, attempts each, marks success or re-queues.
export async function processRetryQueue(db: SupabaseClient): Promise<{
  processed: number;
  succeeded: number;
  failed: number;
  exhausted: number;
}> {
  const stats = { processed: 0, succeeded: 0, failed: 0, exhausted: 0 };
  const now   = new Date().toISOString();

  const { data: items } = await db
    .from("provision_retry_queue")
    .select("*")
    .in("status", ["pending", "retrying"])
    .lte("next_retry_at", now)
    .order("next_retry_at", { ascending: true })
    .limit(50);

  if (!items?.length) return stats;

  for (const item of items) {
    stats.processed++;
    const attempt = (item.attempt_count as number) + 1;
    const raldId  = item.rald_id as string;
    const service = item.service as string;
    const payload = item.payload as Record<string, unknown>;

    // Mark as retrying
    await Promise.resolve(
      db.from("provision_retry_queue").update({
        status:        "retrying",
        attempt_count: attempt,
        updated_at:    new Date().toISOString(),
      }).eq("id", item.id)
    ).then(undefined, () => null);

    let ok = false;
    let lastErr = "";

    try {
      // Re-fetch rald_users to get current state
      const { data: raldUser } = await db
        .from("rald_users")
        .select("id,user_id,username,email,rald_email")
        .eq("id", raldId)
        .single();

      if (!raldUser) throw new Error("rald_users record not found");

      const provisioner = new IdentityProvisioner(db);
      const input: ProvisionInput = {
        raldId:   raldUser.id as string,
        userId:   raldUser.user_id as string,
        username: raldUser.username as string,
        email:    raldUser.email as string | null,
      };

      let result: StepResult;
      switch (service) {
        case "wallet":    result = await provisioner.createWallet(input);         break;
        case "alia":      result = await provisioner.createAliaHandle(input);     break;
        case "mail":      result = await provisioner.createMailAccount(input);    break;
        case "messenger": result = await provisioner.createMessengerAccount(input); break;
        default:
          result = { ok: false, error: `Unknown service: ${service}` };
      }

      ok      = result.ok;
      lastErr = result.error ?? "";

      if (ok) {
        // If this step succeeded, check if all steps are now done
        await provisioner.finalizeIdentity(raldId);
      }
    } catch (err) {
      lastErr = String(err);
    }

    if (ok) {
      stats.succeeded++;
      await Promise.resolve(
        db.from("provision_retry_queue").update({
          status:     "success",
          updated_at: new Date().toISOString(),
        }).eq("id", item.id)
      ).then(undefined, () => null);
    } else {
      const maxAttempts = item.max_attempts as number;
      if (attempt >= maxAttempts) {
        stats.exhausted++;
        await Promise.resolve(
          db.from("provision_retry_queue").update({
            status:        "exhausted",
            last_error:    lastErr,
            attempt_count: attempt,
            updated_at:    new Date().toISOString(),
          }).eq("id", item.id)
        ).then(undefined, () => null);
      } else {
        stats.failed++;
        // Exponential backoff: 30s × 2^attempt, capped at 1 hour
        const backoffMs  = Math.min(30_000 * Math.pow(2, attempt - 1), 3_600_000);
        const nextRetry  = new Date(Date.now() + backoffMs).toISOString();
        await Promise.resolve(
          db.from("provision_retry_queue").update({
            status:        "pending",
            last_error:    lastErr,
            attempt_count: attempt,
            next_retry_at: nextRetry,
            updated_at:    new Date().toISOString(),
          }).eq("id", item.id)
        ).then(undefined, () => null);
      }
    }
  }

  return stats;
}
