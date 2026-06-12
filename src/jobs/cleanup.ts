// RALD Auth Core — Scheduled Cleanup Job
// Phase 1 — Public Beta Blockers — Session/OTP Cleanup Automation
// Runs hourly (OTP + session) and daily (devices + audit summary + rotation alerts)
// LILCKY STUDIO LIMITED

import { createClient } from "@supabase/supabase-js";
import type { Bindings } from "../index";

const LOG_TAG = "[rald-auth-cleanup]";

// ── Machine token cache ────────────────────────────────────────────────────
// rald-auth-core calls POST /machine/auth to get a scoped JWT for service-to-service calls.
// Token is cached in-memory per isolate lifetime (cold start = re-issue).
let _machineTokenCache: { token: string; expiresAt: number } | null = null;

async function getMachineToken(env: Bindings): Promise<string | null> {
  const keyId     = (env as Record<string, unknown>).MACHINE_KEY_ID     as string | undefined;
  const keySecret = (env as Record<string, unknown>).MACHINE_KEY_SECRET as string | undefined;
  if (!keyId || !keySecret) {
    console.warn(\`\${LOG_TAG} MACHINE_KEY_ID / MACHINE_KEY_SECRET not configured — cannot send notifications\`);
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (_machineTokenCache && _machineTokenCache.expiresAt > now + 60) {
    return _machineTokenCache.token;
  }
  try {
    const resp = await fetch("https://auth.rald.cloud/machine/auth", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ key_id: keyId, secret: keySecret }),
      signal:  AbortSignal.timeout(10_000),
    });
    if (!resp.ok) {
      console.warn(\`\${LOG_TAG} Machine auth exchange failed: HTTP \${resp.status}\`);
      return null;
    }
    const data = await resp.json() as { token?: string; expires_in?: number };
    if (!data.token) return null;
    _machineTokenCache = { token: data.token, expiresAt: now + (data.expires_in ?? 3600) };
    return data.token;
  } catch (e) {
    console.warn(\`\${LOG_TAG} Machine auth exchange error:\`, String(e));
    return null;
  }
}

interface CleanupStats {
  expired_sessions_deleted: number;
  expired_otps_deleted: number;
  inactive_devices_marked: number;
  stale_invites_deleted: number;
  rotation_alerts: number;
  errors: string[];
}

// ── Hourly: delete expired OTPs + stale sessions ───────────────────────────
export async function runHourlyCleanup(env: Bindings): Promise<Partial<CleanupStats>> {
  const db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
  const stats: Partial<CleanupStats> = { errors: [] };

  // 1. Delete expired OTP codes (older than 15 minutes past expiry)
  try {
    const cutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { count, error } = await db
      .from("auth_otp_codes")
      .delete({ count: "exact" })
      .lt("expires_at", cutoff);
    if (error) {
      // Table may not exist yet — non-fatal
      console.warn(`${LOG_TAG} OTP cleanup error (may need migration):`, error.message);
      stats.errors!.push(`otp_cleanup: ${error.message}`);
    } else {
      stats.expired_otps_deleted = count ?? 0;
      console.log(`${LOG_TAG} OTP cleanup: deleted ${count ?? 0} expired codes`);
    }
  } catch (e) {
    stats.errors!.push(`otp_cleanup_fatal: ${String(e)}`);
  }

  // 2. Delete sessions expired more than 30 days ago
  try {
    const cutoff30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const { count, error } = await db
      .from("auth_sessions")
      .delete({ count: "exact" })
      .lt("expires_at", cutoff30d);
    if (error) {
      console.warn(`${LOG_TAG} Session cleanup error:`, error.message);
      stats.errors!.push(`session_cleanup: ${error.message}`);
    } else {
      stats.expired_sessions_deleted = count ?? 0;
      console.log(`${LOG_TAG} Session cleanup: deleted ${count ?? 0} expired sessions`);
    }
  } catch (e) {
    stats.errors!.push(`session_cleanup_fatal: ${String(e)}`);
  }

  return stats;
}

// ── Daily: mark inactive devices + check rotation alerts + delete stale invites ──
export async function runDailyCleanup(env: Bindings): Promise<Partial<CleanupStats>> {
  const db = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
  const stats: Partial<CleanupStats> = { errors: [] };

  // 1. Mark devices inactive after 90 days of no activity
  try {
    const cutoff90d = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
    const { count, error } = await db
      .from("auth_devices")
      .update({ status: "inactive" }, { count: "exact" })
      .lt("last_seen_at", cutoff90d)
      .eq("status", "active");
    if (error) {
      console.warn(`${LOG_TAG} Device cleanup error:`, error.message);
      stats.errors!.push(`device_cleanup: ${error.message}`);
    } else {
      stats.inactive_devices_marked = count ?? 0;
      console.log(`${LOG_TAG} Device cleanup: marked ${count ?? 0} devices inactive`);
    }
  } catch (e) {
    stats.errors!.push(`device_cleanup_fatal: ${String(e)}`);
  }

  // 2. Delete stale pending invites (older than 7 days)
  try {
    const cutoff7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { count, error } = await db
      .from("auth_invites")
      .delete({ count: "exact" })
      .eq("status", "pending")
      .lt("created_at", cutoff7d);
    if (error) {
      // Table may not exist — non-fatal
      stats.errors!.push(`invite_cleanup: ${error.message}`);
    } else {
      stats.stale_invites_deleted = count ?? 0;
      console.log(`${LOG_TAG} Invite cleanup: deleted ${count ?? 0} stale invites`);
    }
  } catch (e) {
    stats.errors!.push(`invite_cleanup_fatal: ${String(e)}`);
  }

  // 3. Check machine identity rotation alerts — alert admin via notify if any are due
  try {
    const { data: alerts, error } = await db
      .from("machine_identity_rotation_alerts")
      .select("service_name, rotation_due_at, days_until_rotation");
    if (error) {
      stats.errors!.push(`rotation_alerts: ${error.message}`);
    } else {
      stats.rotation_alerts = alerts?.length ?? 0;
      if (alerts && alerts.length > 0) {
        console.warn(`${LOG_TAG} ROTATION ALERT: ${alerts.length} machine identity token(s) due for rotation:`);
        for (const alert of alerts) {
          console.warn(`  ${alert.service_name}: due ${alert.rotation_due_at} (${alert.days_until_rotation} days)`);
        }
        // Fire alert to admin via rald-notify (non-fatal if notify unavailable)
        await sendRotationAlert(env, alerts);
      } else {
        console.log(`${LOG_TAG} Rotation alerts: none due`);
      }
    }
  } catch (e) {
    stats.errors!.push(`rotation_alerts_fatal: ${String(e)}`);
  }

  return stats;
}

// ── Send rotation alert to admin via rald-notify ───────────────────────────
async function sendRotationAlert(
  env: Bindings,
  alerts: Array<{ service_name: string; rotation_due_at: string; days_until_rotation: number }>
): Promise<void> {
  const machineToken = await getMachineToken(env);
  if (!machineToken) return; // getMachineToken already logs the reason

  const adminUserId = (env as Record<string, unknown>).ADMIN_USER_ID as string | undefined;
  if (!adminUserId) {
    console.warn(`${LOG_TAG} ADMIN_USER_ID not set — logging rotation alert only`);
    return;
  }

  const bodyText = alerts
    .map(a => `• ${a.service_name}: ${a.days_until_rotation} days until rotation due`)
    .join("\n");

  try {
    await fetch("https://notification.rald.cloud/api/notifications", {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer \${machineToken}`,
      },
      body: JSON.stringify({
        user_id:  adminUserId,
        type:     "machine_token_rotation",
        title:    `⚠️ \${alerts.length} machine token(s) due for rotation`,
        body:     bodyText,
        channel:  "email",
        metadata: { alerts },
      }),
      signal: AbortSignal.timeout(10_000),
    });
    console.log(`${LOG_TAG} Rotation alert sent to admin`);
  } catch (e) {
    console.warn(`${LOG_TAG} Failed to send rotation alert via notify:`, String(e));
  }
}

// ── Health check snapshot — record to HEALTH_KV if available ──────────────
export async function runHealthSnapshot(env: Bindings): Promise<void> {
  const services = [
    { name: "loop-api",   url: "https://loop-api.rald.cloud/health" },
    { name: "messenger",  url: "https://messenger.rald.cloud/health" },
    { name: "notify",     url: "https://notification.rald.cloud/health" },
    { name: "search",     url: "https://search.rald.cloud/health" },
    { name: "realtime",   url: "https://realtime.rald.cloud/health" },
  ];

  const results = await Promise.allSettled(
    services.map(async (svc) => {
      const t0 = Date.now();
      try {
        const resp = await fetch(svc.url, { signal: AbortSignal.timeout(8_000) });
        return { name: svc.name, ok: resp.ok, status: resp.status, latency: Date.now() - t0 };
      } catch {
        return { name: svc.name, ok: false, status: 0, latency: Date.now() - t0 };
      }
    })
  );

  const snapshot = results.map((r) =>
    r.status === "fulfilled" ? r.value : { name: "unknown", ok: false, status: 0, latency: -1 }
  );
  const unhealthy = snapshot.filter((s) => !s.ok);

  console.log(
    `${LOG_TAG} Health snapshot: ${snapshot.filter((s) => s.ok).length}/${snapshot.length} healthy`
  );

  if (unhealthy.length > 0) {
    console.error(`${LOG_TAG} UNHEALTHY SERVICES:`, unhealthy.map((s) => s.name).join(", "));
    // Alert admin if machine token available (non-fatal)
    const machineToken = await getMachineToken(env);
    const adminUserId = (env as Record<string, unknown>).ADMIN_USER_ID as string | undefined;
    if (machineToken && adminUserId) {
      await fetch("https://notification.rald.cloud/api/notifications", {
        method: "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer \${machineToken}`,
        },
        body: JSON.stringify({
          user_id:  adminUserId,
          type:     "service_health_alert",
          title:    `🔴 \${unhealthy.length} service(s) unhealthy`,
          body:     unhealthy.map((s) => `• \${s.name}: HTTP \${s.status}`).join("\n"),
          channel:  "push",
        }),
        signal: AbortSignal.timeout(10_000),
      }).catch(() => {});
    }
  }
}
