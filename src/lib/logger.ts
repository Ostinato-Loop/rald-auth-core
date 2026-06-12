// RALD — OpenObserve Log Shipping Middleware
// Sprint: Hardening C-CERT-004 · 2026-06-12
// Forwards structured request logs to OpenObserve via HTTP ingest API.
// No-ops gracefully when OPEN_OBSERVE_API_KEY / OPEN_OBSERVE_ENDPOINT are unset.
// Ships logs using ctx.waitUntil() — zero latency impact on responses.
// LILCKY STUDIO LIMITED

import type { Context, Next } from "hono";

export interface LogEntry {
  _timestamp:   string;   // ISO 8601
  level:        "info" | "warn" | "error";
  service:      string;
  environment:  string;
  method?:      string;
  path?:        string;
  status?:      number;
  duration_ms?: number;
  country?:     string;
  user_agent?:  string;
  request_id?:  string;
  message?:     string;
  [key: string]: unknown;
}

interface ObserveEnv {
  OPEN_OBSERVE_API_KEY?: string;
  OPEN_OBSERVE_ENDPOINT?: string;
  ENVIRONMENT?: string;
  SERVICE_NAME?: string;
}

// ── Ship a batch of log entries to OpenObserve ────────────────────────────────
// OpenObserve ingest: POST <OPEN_OBSERVE_ENDPOINT> with body = JSON array
// OPEN_OBSERVE_ENDPOINT example: https://observe.rald.cloud/api/rald/rald-logs/_json
// OPEN_OBSERVE_API_KEY: base64(email:password) or raw API key
export async function shipLogs(
  env: ObserveEnv,
  entries: LogEntry[]
): Promise<void> {
  if (!env.OPEN_OBSERVE_API_KEY || !env.OPEN_OBSERVE_ENDPOINT) return;
  if (!entries.length) return;
  try {
    await fetch(env.OPEN_OBSERVE_ENDPOINT, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Basic ${env.OPEN_OBSERVE_API_KEY}`,
      },
      body: JSON.stringify(entries),
    });
  } catch {
    // Silently drop — log shipping must never break the primary request path
  }
}

// ── requestLogger — Hono middleware ──────────────────────────────────────────
// Logs every request: method, path, status, duration, CF country, user-agent.
// Usage: app.use("*", requestLogger("rald-auth-core"));
export function requestLogger(serviceName: string) {
  return async (c: Context<{ Bindings: ObserveEnv }>, next: Next) => {
    const start      = Date.now();
    const method     = c.req.method;
    const path       = new URL(c.req.url).pathname;
    const requestId  = c.req.header("X-Request-ID") ?? crypto.randomUUID();
    const userAgent  = c.req.header("User-Agent") ?? "";
    // Cloudflare adds cf-ipcountry header on incoming requests
    const country    = c.req.header("cf-ipcountry") ?? "";

    await next();

    const status     = c.res.status;
    const duration   = Date.now() - start;
    const env        = c.env;
    const level: LogEntry["level"] = status >= 500 ? "error" : status >= 400 ? "warn" : "info";

    const entry: LogEntry = {
      _timestamp:  new Date().toISOString(),
      level,
      service:     serviceName,
      environment: env.ENVIRONMENT ?? "production",
      method,
      path,
      status,
      duration_ms: duration,
      country,
      user_agent:  userAgent.slice(0, 120),
      request_id:  requestId,
    };

    // Fire and forget — never awaited on the hot path
    c.executionCtx?.waitUntil(shipLogs(env, [entry]));
  };
}

// ── logEvent — one-shot structured event (non-request) ───────────────────────
// Usage: await logEvent(c.env, c.executionCtx, { level:"warn", message:"..." });
export function logEvent(
  env: ObserveEnv,
  ctx: { waitUntil(p: Promise<unknown>): void } | null,
  extra: Partial<LogEntry> & { level: LogEntry["level"]; message: string },
  serviceName: string,
): void {
  const entry: LogEntry = {
    _timestamp:  new Date().toISOString(),
    service:     serviceName,
    environment: env.ENVIRONMENT ?? "production",
    ...extra,
  };
  ctx?.waitUntil(shipLogs(env, [entry]));
}
