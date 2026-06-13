-- RALD Ecosystem Finalization Program — Phase 1: Identity State Machine
-- Migration: add identity_state to auth_users

-- Add identity_state column
ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS identity_state TEXT NOT NULL DEFAULT 'ACTIVE'
    CONSTRAINT chk_identity_state CHECK (identity_state IN (
      'USERNAME_RESERVED',
      'PENDING_VERIFICATION',
      'OTP_VERIFIED',
      'PROFILE_COMPLETED',
      'ACTIVE',
      'SUSPENDED',
      'DELETED'
    )),
  ADD COLUMN IF NOT EXISTS username_reservation_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS otp_expires_at TIMESTAMPTZ;

-- Backfill existing users to ACTIVE
UPDATE auth_users
  SET identity_state = 'ACTIVE'
  WHERE identity_state IS NULL OR identity_state = '';

-- Index for expiry cleanup cron (runs every 5 minutes)
CREATE INDEX IF NOT EXISTS idx_auth_users_state_expiry
  ON auth_users (identity_state, username_reservation_expires_at)
  WHERE identity_state IN ('USERNAME_RESERVED', 'PENDING_VERIFICATION');

-- Index for suspended/deleted guards on login
CREATE INDEX IF NOT EXISTS idx_auth_users_state
  ON auth_users (identity_state)
  WHERE identity_state IN ('SUSPENDED', 'DELETED');
