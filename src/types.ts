// RALD Auth Core — Shared Type Exports
// Phase 11 (2026-06-13): Created to satisfy imports from
//   src/cron/cleanup.ts, src/lib/events.ts, src/middleware/machine.ts
//   which all require `Env` (= the Cloudflare Worker Bindings interface).
// Phase 1 (2026-06-17): Added EVENTS_BUS_URL, RALD_INTERNAL_SECRET,
//   MACHINE_KEY_ID, MACHINE_KEY_SECRET for event bus and machine identity.
// LILCKY STUDIO LIMITED

import type { KVNamespace }   from "./lib/rate-limit";
import type { KvSessionStore } from "./lib/session";

/**
 * Env = the Cloudflare Worker Bindings object.
 * Mirrors the `Bindings` export in src/index.ts.
 * Kept as a re-export here so it can be imported with `../types`
 * from files in subdirectories without a circular dependency.
 */
export type Env = {
  SUPABASE_URL:              string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET:           string;
  TERMII_API_KEY:            string;
  TERMII_SENDER_ID:          string;
  RESEND_API_KEY:            string;
  CLERK_SECRET_KEY:          string;
  CLERK_PUBLISHABLE_KEY:     string;
  ENVIRONMENT:               string;
  RATE_LIMIT_KV:             KVNamespace;
  RALD_SESSION_KV:           KvSessionStore;
  // Observability
  OPEN_OBSERVE_API_KEY?:     string;
  OPEN_OBSERVE_ENDPOINT?:    string;
  // Machine identity (deprecated path — prefer MACHINE_KEY_ID/SECRET)
  MACHINE_IDENTITY_SECRET?:  string;
  ADMIN_USER_ID?:            string;
  INTERNAL_SECRET?:          string;
  // Phase 1: Event bus integration
  EVENTS_BUS_URL?:           string;  // defaults to https://events.rald.cloud
  RALD_INTERNAL_SECRET?:     string;  // shared secret for event bus auth (X-RALD-Internal-Key)
  // Phase 1: Machine identity (new pattern)
  MACHINE_KEY_ID?:           string;  // provisioned via POST /machine/auth
  MACHINE_KEY_SECRET?:       string;  // provisioned during machine identity onboarding
  // Add a supabase client instance (populated by middleware)
  supabase?: any;
};
