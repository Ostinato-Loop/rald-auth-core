// RALD Ecosystem — Event Bus Integration
// Publishes events to events.rald.cloud when EVENTS_BUS_URL + RALD_INTERNAL_SECRET are set.
// Falls back to structured console log (consumed by log-based event bridge) if not configured.
// Phase 1 update: wired to live events.rald.cloud HTTP endpoint.
// LILCKY STUDIO LIMITED · 2026-06-17

import type { Env } from "../types";

export type RaldEventType =
  | "user.created"
  | "user.verified"
  | "user.deleted"
  | "username.claimed"
  | "identity.created"
  | "identity.updated"
  | "identity.provisioned"
  | "wallet.created"
  | "alias.created"
  | "mailbox.created"
  | "messenger.created"
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
 * When EVENTS_BUS_URL + RALD_INTERNAL_SECRET are configured, POSTs to events.rald.cloud.
 * Falls back to structured console log for log-based bridging.
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

  // Live HTTP emission to events.rald.cloud
  const eventsUrl = env.EVENTS_BUS_URL ?? "https://events.rald.cloud";
  const secret    = env.RALD_INTERNAL_SECRET;

  if (secret) {
    try {
      const res = await fetch(`${eventsUrl}/events`, {
        method: "POST",
        headers: {
          "Content-Type":        "application/json",
          "X-Source-Service":    "rald-auth-core",
          "X-RALD-Internal-Key": secret,
        },
        body: JSON.stringify({
          event_type: event.type,
          source:     event.producer,
          user_id:    (payload as any)?.user_id   ?? null,
          actor_id:   (payload as any)?.user_id   ?? null,
          payload:    event.payload,
          metadata:   event.metadata ?? {},
        }),
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        console.log(JSON.stringify({
          level: "info",
          msg:   "event.emitted",
          event_type: event.type,
          event_id:   event.id,
          destination: eventsUrl,
        }));
        return;
      }
      console.warn(`[events] HTTP ${res.status} from event bus — falling back to log`);
    } catch (err) {
      console.warn(`[events] fetch error: ${String(err)} — falling back to log`);
    }
  }

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
  userCreated: (payload: {
    user_id:      string;
    username:     string | null;
    phone:        string;
    country:      string;
    created_via:  string;
  }, env: Env, ip?: string) =>
    publishEvent("user.created", payload, env, { ip }),

  identityCreated: (payload: {
    rald_id:      string;
    user_id:      string;
    username:     string;
    rald_email:   string;
    alia_handle:  string;
    wallet_id:    string;
    messenger_id: string;
    provisioned:  string[];
  }, env: Env) =>
    publishEvent("identity.created", payload, env),

  userDeleted: (payload: {
    user_id:       string;
    deletion_type: "soft" | "hard";
  }, env: Env) =>
    publishEvent("user.deleted", payload, env),

  usernameClaimed: (payload: {
    user_id:           string;
    username:          string;
    previous_username: string | null;
  }, env: Env) =>
    publishEvent("username.claimed", payload, env),

  identityUpdated: (payload: {
    user_id:        string;
    changed_fields: string[];
    trust_score?:   number;
  }, env: Env) =>
    publishEvent("identity.updated", payload, env),

  sessionSuspended: (payload: {
    user_id:      string;
    reason:       string;
    suspended_by: "admin" | "system";
  }, env: Env) =>
    publishEvent("session.suspended", payload, env),

  sessionUnsuspended: (payload: { user_id: string }, env: Env) =>
    publishEvent("session.unsuspended", payload, env),

  trustUpdated: (payload: {
    user_id:    string;
    old_score:  number;
    new_score:  number;
    trigger:    string;
  }, env: Env) =>
    publishEvent("trust.updated", payload, env),
};
