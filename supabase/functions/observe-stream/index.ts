// RALD — Supabase Edge Function: observe-stream
// Sprint: Hardening C-CERT-004 · 2026-06-12
// Receives pg_net HTTP POST payloads from Postgres audit triggers.
// Forwards structured audit events to OpenObserve in real time.
// Deployed at: https://onxdcikfttdmnhofsuwo.supabase.co/functions/v1/observe-stream
//
// Required Edge Function secrets (set via Supabase Dashboard → Functions → Secrets):
//   OPEN_OBSERVE_API_KEY  — base64(email:password) or raw API key
//   OPEN_OBSERVE_ENDPOINT — https://observe.rald.cloud/api/rald/rald-audit/_json
//   OBSERVE_STREAM_SECRET — shared secret set in app.observe_stream_secret GUC
//
// LILCKY STUDIO LIMITED

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

interface TriggerPayload {
  table:     string;
  schema:    string;
  event:     "INSERT" | "UPDATE" | "DELETE";
  service:   string;
  timestamp: string;
  data:      Record<string, unknown>;
}

interface ObserveEntry {
  _timestamp:   string;
  level:        "info" | "warn" | "error";
  service:      string;
  source:       "database";
  table:        string;
  event:        string;
  action?:      string;
  user_id?:     string;
  ip?:          string;
  status?:      string;
  metadata?:    unknown;
  [key: string]: unknown;
}

function tableToService(table: string): string {
  const map: Record<string, string> = {
    audit_logs:                   "rald-auth-core",
    event_bus_audit_logs:         "rald-event-bus",
    config_audit_logs:            "rald-config",
    notification_audit_log:       "rald-notify",
    machine_identity_audit_log:   "rald-auth-core",
  };
  return map[table] ?? "rald-unknown";
}

function rowToObserveEntry(payload: TriggerPayload): ObserveEntry {
  const d = payload.data;
  const action = (d.action ?? d.event_type ?? "") as string;
  const status = (d.status ?? "success") as string;
  const level: ObserveEntry["level"] =
    status === "failure" || status === "failed" || action.includes("failed") ? "warn"
    : action.includes("error") || action.includes("revoked") ? "warn"
    : "info";

  return {
    _timestamp:  (d.created_at as string) ?? payload.timestamp,
    level,
    service:     tableToService(payload.table),
    source:      "database",
    table:       payload.table,
    event:       payload.event,
    action:      action || undefined,
    user_id:     (d.user_id ?? d.admin_id ?? d.identity_id) as string | undefined,
    ip:          (d.ip ?? d.ip_address) as string | undefined,
    status:      status || undefined,
    metadata:    d.metadata ?? undefined,
  };
}

serve(async (req: Request): Promise<Response> => {
  // ── Auth: verify shared secret ──────────────────────────────────────────────
  const streamSecret = Deno.env.get("OBSERVE_STREAM_SECRET");
  if (streamSecret) {
    const auth = req.headers.get("Authorization") ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (token !== streamSecret) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json" },
      });
    }
  }

  // ── Parse payload ──────────────────────────────────────────────────────────
  let payload: TriggerPayload;
  try {
    payload = await req.json() as TriggerPayload;
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  // ── Transform → OpenObserve entry ─────────────────────────────────────────
  const entry = rowToObserveEntry(payload);

  // ── Ship to OpenObserve ───────────────────────────────────────────────────
  const apiKey   = Deno.env.get("OPEN_OBSERVE_API_KEY");
  const endpoint = Deno.env.get("OPEN_OBSERVE_ENDPOINT");

  if (!apiKey || !endpoint) {
    // Secrets not yet set — acknowledge receipt, skip shipping
    return new Response(JSON.stringify({ ok: true, shipped: false, reason: "secrets_not_set" }), {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const res = await fetch(endpoint, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Basic ${apiKey}`,
      },
      body: JSON.stringify([entry]),
    });

    return new Response(JSON.stringify({ ok: res.ok, shipped: true, status: res.status }), {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    // Never let observability failure cascade — return 200 so pg_net doesn't retry endlessly
    console.error("[observe-stream] ship failed:", err);
    return new Response(JSON.stringify({ ok: false, shipped: false, error: String(err) }), {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  }
});
