// RALD Ecosystem Finalization Program — Phase 1: Identity State Machine
// Cleanup cron: expire stale username reservations and incomplete registrations

import type { Env } from "../types";

/**
 * Called by Cloudflare Cron Trigger every 5 minutes.
 * Releases expired username reservations and stale partial registrations.
 */
export async function runIdentityCleanup(env: Env): Promise<void> {
  const now = new Date().toISOString();

  // 1. Expire USERNAME_RESERVED that passed their reservation window
  const { data: expiredReservations, error: err1 } = await env.supabase
    .from("auth_users")
    .update({ identity_state: "DELETED", username_reservation_expires_at: null })
    .eq("identity_state", "USERNAME_RESERVED")
    .lt("username_reservation_expires_at", now)
    .select("id, username");

  if (err1) {
    console.error(JSON.stringify({ level: "error", msg: "cleanup: reservation expiry failed", error: err1.message }));
  } else if (expiredReservations && expiredReservations.length > 0) {
    console.log(JSON.stringify({
      level: "info",
      msg:   "cleanup: expired username reservations",
      count: expiredReservations.length,
    }));
  }

  // 2. Expire PENDING_VERIFICATION that passed their OTP window
  const { data: expiredOTP, error: err2 } = await env.supabase
    .from("auth_users")
    .update({ identity_state: "AVAILABLE" })
    .eq("identity_state", "PENDING_VERIFICATION")
    .lt("otp_expires_at", now)
    .select("id");

  if (err2) {
    console.error(JSON.stringify({ level: "error", msg: "cleanup: OTP expiry failed", error: err2.message }));
  } else if (expiredOTP && expiredOTP.length > 0) {
    console.log(JSON.stringify({
      level: "info",
      msg:   "cleanup: expired pending verifications",
      count: expiredOTP.length,
    }));
  }

  // 3. Expire OTP_VERIFIED / PROFILE_COMPLETED older than 24 hours
  const cutoff24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const { data: expiredPartial, error: err3 } = await env.supabase
    .from("auth_users")
    .update({ identity_state: "DELETED" })
    .in("identity_state", ["OTP_VERIFIED", "PROFILE_COMPLETED"])
    .lt("updated_at", cutoff24h)
    .select("id");

  if (err3) {
    console.error(JSON.stringify({ level: "error", msg: "cleanup: partial profile expiry failed", error: err3.message }));
  } else if (expiredPartial && expiredPartial.length > 0) {
    console.log(JSON.stringify({
      level: "info",
      msg:   "cleanup: expired partial profiles",
      count: expiredPartial.length,
    }));
  }
}
