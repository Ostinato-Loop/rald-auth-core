// RALD Auth Core — Shared Type Exports
// Phase 11 (2026-06-13): Created to satisfy imports from
//   src/cron/cleanup.ts, src/lib/events.ts, src/middleware/machine.ts
//   which all require `Env` (= the Cloudflare Worker Bindings interface).
// LILCKY STUDIO LIMITED

import type { KVNamespace }  from "./lib/rate-limit";
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
  OPEN_OBSERVE_API_KEY?:     string;
  OPEN_OBSERVE_ENDPOINT?:    string;
  MACHINE_IDENTITY_SECRET?:  string;
  ADMIN_USER_ID?:            string;
  INTERNAL_SECRET?:          string;
  // Add a supabase client instance (populated by middleware)
  supabase?: any;
};
