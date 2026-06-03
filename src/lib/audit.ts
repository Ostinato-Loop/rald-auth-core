// RALD Auth Core — Audit Logging
// Writes to audit_logs table (best-effort — never throws, never blocks main flow).
// Phase G.10: Expanded AuditAction types for session management
// LILCKY STUDIO LIMITED

import { SupabaseClient } from "@supabase/supabase-js";

export type AuditAction =
  // Auth
  | "login"
  | "login_failed"
  | "logout"
  | "register"
  | "otp_sent"
  | "otp_verified"
  | "otp_failed"
  | "password_reset_requested"
  | "password_reset_completed"
  // Sessions
  | "session_created"
  | "session_revoked"
  | "all_sessions_revoked"
  | "forced_logout"
  // Devices
  | "device_trusted"
  | "device_revoked"
  // SSO & Provisioning
  | "sso_exchange"
  | "sso_handoff_issued"
  | "token_verified"
  | "app_provisioned"
  | "app_provisioned_by_admin"
  // Account
  | "account_suspended"
  | "account_unsuspended"
  | "account_deleted"
  // Security
  | "rate_limited"
  | "redirect_rejected";

export interface AuditEntry {
  userId?: string | null;
  action: AuditAction;
  resourceType?: string;
  resourceId?: string;
  ip?: string;
  userAgent?: string;
  status?: "success" | "failure" | "blocked";
  metadata?: Record<string, unknown>;
}

export async function writeAuditLog(db: SupabaseClient, entry: AuditEntry): Promise<void> {
  try {
    await db.from("audit_logs").insert({
      user_id:       entry.userId ?? null,
      action:        entry.action,
      resource_type: entry.resourceType ?? null,
      resource_id:   entry.resourceId ?? null,
      ip_address:    entry.ip ?? null,
      user_agent:    entry.userAgent ?? null,
      status:        entry.status ?? "success",
      metadata:      entry.metadata ?? null,
    });
  } catch (err) {
    console.warn("[audit] write failed:", String(err));
  }
}
