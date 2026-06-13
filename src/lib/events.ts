// RALD Ecosystem Finalization Program — Phase 5: Event Bus
// Event publishing stubs — replace with Cloudflare Queues once provisioned

import type { Env } from "../types";

export type RaldEventType =
  | "user.created"
  | "user.verified"
  | "user.deleted"
  | "username.claimed"
  | "identity.updated"
  | "trust.updated"
  | "session.suspended"
  | "session.unsuspended"
  | "consent.granted"
  | "consent.revoked"
  | "developer.enabled"
  | "organization.created";

export interface RaldEvent<T = unknown> {
  type:        RaldEventType;
  version:     number;
  id:          string;
  occurred_at: string;
  producer:    "auth.rald.cloud";
  payload:     T;
  metadata?: {
    correlation_id?: string;
    ip?:             string;
  };
}

/**
 * Publish an event to the RALD event bus.
 *
 * Phase 5 stub: logs event as structured JSON.
 * TODO: Replace with Cloudflare Queue publish once queue is provisioned:
 *   await env.EVENT_QUEUE.send(event);
 */
export async function publishEvent<T>(
  type: RaldEventType,
  payload: T,
  env: Env,
  metadata?: { correlation_id?: string; ip?: string }
): Promise<void> {
  const event: RaldEvent<T> = {
    type,
    version:     1,
    id:          crypto.randomUUID(),
    occurred_at: new Date().toISOString(),
    producer:    "auth.rald.cloud",
    payload,
    metadata,
  };

  // Phase 5: Queue integration
  // When Cloudflare Queue is provisioned, uncomment:
  // if (env.EVENT_QUEUE) {
  //   await env.EVENT_QUEUE.send(event);
  //   return;
  // }

  // Fallback: structured log (consumed by log-based event bridge)
  console.log(JSON.stringify({
    level:      "info",
    msg:        "event.published",
    event_type: event.type,
    event_id:   event.id,
    event,
  }));
}

// Convenience helpers
export const Events = {
  userCreated: (payload: { user_id: string; username: string | null; phone: string; country: string; created_via: string }, env: Env, ip?: string) =>
    publishEvent("user.created", payload, env, { ip }),

  userDeleted: (payload: { user_id: string; deletion_type: "soft" | "hard" }, env: Env) =>
    publishEvent("user.deleted", payload, env),

  usernameClaimed: (payload: { user_id: string; username: string; previous_username: string | null }, env: Env) =>
    publishEvent("username.claimed", payload, env),

  identityUpdated: (payload: { user_id: string; changed_fields: string[]; trust_score?: number }, env: Env) =>
    publishEvent("identity.updated", payload, env),

  sessionSuspended: (payload: { user_id: string; reason: string; suspended_by: "admin" | "system" }, env: Env) =>
    publishEvent("session.suspended", payload, env),

  sessionUnsuspended: (payload: { user_id: string }, env: Env) =>
    publishEvent("session.unsuspended", payload, env),

  trustUpdated: (payload: { user_id: string; old_score: number; new_score: number; trigger: string }, env: Env) =>
    publishEvent("trust.updated", payload, env),
};
