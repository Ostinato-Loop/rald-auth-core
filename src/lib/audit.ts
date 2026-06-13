// RALD Auth Core — Audit Logging
// Writes to audit_logs table (best-effort — never throws, never blocks main flow).
// Phase G.10: Expanded AuditAction types for session management
// Phase H.2: Added privacy, verification, role, ecosystem action types
// Phase V2.1: Added QR login and WebAuthn audit actions
// Phase 4 (Emergency Stabilization Sprint): Added admin username console actions
// Sprint 2026-06-14: Added machine identity, permission, trust action types
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
  | "SESSION_REVOKE_ALL"
  | "SESSION_REVOKE_DEVICE"
  | "all_sessions_revoked"
  | "forced_logout"
  // Devices
  | "device_trusted"
  | "device_revoked"
  // Token lifecycle
  | "token_refreshed"
  // Profile
  | "profile_updated"
  | "profile_viewed"
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
  | "redirect_rejected"
  // Privacy — Phase H.2
  | "data_export_requested"
  | "privacy_permissions_updated"
  | "account_deletion_requested"
  | "account_deletion_cancelled"
  // Verification — Phase H.2
  | "verification_applied"
  | "verification_withdrawn"
  | "verification_approved"
  | "verification_rejected"
  // Roles — Phase H.2
  | "role_granted"
  | "role_requested"
  | "role_revoked"
  // V2 Username Identity — Phase V2
  | "username_claimed"
  | "username_released"
  | "username_admin_change"
  // Admin Username Console — Phase 4 (Emergency Stabilization Sprint)
  | "admin_username_reserve"
  | "admin_username_release"
  | "admin_username_transfer"
  | "admin_username_protect"
  | "admin_username_premium"
  | "admin_username_recover"
  | "admin_username_bulk_reserve"
  // Recovery Codes — Phase V2
  | "recovery_codes_generated"
  | "recovery_code_used"
  | "recovery_code_failed"
  // QR Login — Phase V2.1
  | "qr_login_approved"
  // WebAuthn / Biometric — Phase V2.1
  | "webauthn_credential_registered"
  | "webauthn_login_failed"
  | "webauthn_login_success"
  // Workspaces — Phase V2
  | "workspace_created"
  | "workspace_deleted"
  | "workspace_member_added"
  | "workspace_member_removed"
  // Organizations — Phase H
  | "organization_created"
  | "organization_left"
  | "organization_deleted"
  // Country Activation Framework
  | "country_activated"
  | "country_restricted"
  | "country_status_changed"
  | "country_added"
  | "payrald_gate_updated"
  // Developer Platform — 2026-06-12
  | "developer.onboarded"
  | "api_key.created"
  | "api_key.rotated"
  | "api_key.revoked"
  | "app.created"
  | "app.updated"
  | "webhook.created"
  | "webhook.deleted"
  // Machine Identity — Sprint 2026-06-14
  | "machine_identity.provisioned"
  | "machine_identity.rotated"
  | "machine_identity.revoked"
  // Permissions — Sprint 2026-06-14
  | "permission.override"
  // Trust — Sprint 2026-06-14
  | "trust.recomputed"
  // Phase 11 additions (2026-06-13)
  | "login_blocked"
  | "sso_blocked"
  | "provision_all"
  | "username_pending"
  | "ghost_username_repair";

export interface AuditEntry {
  userId?: string | null;
  user_id?: string | null;
  action: AuditAction;
  resourceType?: string;
  resourceId?: string;
  ip?: string;
  userAgent?: string;
  status?: "success" | "failure" | "blocked" | "partial";
  metadata?: Record<string, unknown>;
}

export async function writeAuditLog(db: SupabaseClient, entry: AuditEntry): Promise<void> {
  try {
    const userId = entry.userId ?? entry.user_id ?? null;
    await db.from("audit_logs").insert({
      user_id:       userId,
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
