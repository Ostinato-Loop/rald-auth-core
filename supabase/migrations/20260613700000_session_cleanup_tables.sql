-- RALD Auth Core — Session, OTP, and Device Schema Hardening
-- Adds missing columns to existing auth_* tables (cleanup job support).
-- Also creates machine_identity_rotation_alerts view + auth_invites table.
-- Safe: IF NOT EXISTS + ADD COLUMN IF NOT EXISTS throughout.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: HARDEN auth_otp_codes (already exists — add columns)
-- ═══════════════════════════════════════════════════════════════

-- Add user_id FK if missing (original had only email)
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth_users(id) ON DELETE CASCADE;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'email'
  CHECK (channel IN ('sms','email','push','whatsapp'));
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'login';
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS is_used BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS max_attempts INT NOT NULL DEFAULT 3;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS sent_to TEXT;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS device_id TEXT;

-- Backfill user_id from email join (best effort)
UPDATE auth_otp_codes otp
SET user_id = u.id
FROM auth_users u
WHERE u.email = otp.email
  AND otp.user_id IS NULL;

CREATE INDEX IF NOT EXISTS auth_otp_user_idx       ON auth_otp_codes(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS auth_otp_expires_idx    ON auth_otp_codes(expires_at) WHERE is_used = false;

COMMENT ON TABLE auth_otp_codes IS
  'One-time passwords. Cleanup job deletes expired codes hourly (15min past expires_at).';

-- ═══════════════════════════════════════════════════════════════
-- PART B: HARDEN auth_sessions (already exists — add columns)
-- ═══════════════════════════════════════════════════════════════

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS token_hash TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS session_type TEXT NOT NULL DEFAULT 'jwt';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS device_id UUID;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS country_code VARCHAR(2);
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS app_id TEXT;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS revoke_reason TEXT;

-- Unique token_hash index (only for rows that have it set)
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_token_hash_idx ON auth_sessions(token_hash)
  WHERE token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS auth_sessions_active_idx  ON auth_sessions(user_id, last_used_at DESC)
  WHERE revoked_at IS NULL AND expires_at > now();

COMMENT ON TABLE auth_sessions IS
  'JWT/refresh session registry. Cleanup job deletes sessions expired >30 days.';

-- ═══════════════════════════════════════════════════════════════
-- PART C: HARDEN auth_devices (already exists — add columns)
-- ═══════════════════════════════════════════════════════════════

ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
  CHECK (status IN ('active','inactive','revoked','blocked'));
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS platform TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS os_version TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS app_version TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS push_token TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS push_platform TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS trust_level TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS last_country VARCHAR(2);
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS revoke_reason TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS fingerprint_hash TEXT;
ALTER TABLE auth_devices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Backfill status from is_trusted (existing column)
UPDATE auth_devices SET status = 'active' WHERE status = 'active';

CREATE INDEX IF NOT EXISTS auth_devices_status_idx      ON auth_devices(status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS auth_devices_push_token_idx  ON auth_devices(push_token) WHERE push_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS auth_devices_fingerprint_idx ON auth_devices(fingerprint_hash) WHERE fingerprint_hash IS NOT NULL;

COMMENT ON TABLE auth_devices IS
  'Registered user devices. Cleanup job marks devices inactive after 90 days of no activity.';

-- ═══════════════════════════════════════════════════════════════
-- PART D: MACHINE IDENTITY ROTATION ALERTS VIEW
-- Referenced by src/jobs/cleanup.ts daily cleanup job
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW machine_identity_rotation_alerts AS
SELECT
  mi.id,
  mi.service_name,
  mi.display_name,
  mi.rotation_due_at,
  mi.last_rotated_at,
  EXTRACT(DAYS FROM (mi.rotation_due_at - now()))::INT AS days_until_rotation,
  mi.status,
  mi.key_id
FROM machine_identities mi
WHERE mi.status = 'active'
  AND mi.rotation_due_at <= (now() + INTERVAL '14 days')
ORDER BY mi.rotation_due_at ASC;

COMMENT ON VIEW machine_identity_rotation_alerts IS
  'Machine identities due for rotation in the next 14 days. Checked daily by cleanup.ts.';

-- ═══════════════════════════════════════════════════════════════
-- PART E: AUTH INVITES (new table — referenced by cleanup.ts)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS auth_invites (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  inviter_id      UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  invitee_email   TEXT,
  invitee_phone   TEXT,
  invite_code     TEXT NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(16), 'hex'),
  invite_type     TEXT NOT NULL DEFAULT 'general'
                    CHECK (invite_type IN ('general','workspace','community','beta_access')),
  workspace_id    UUID,                      -- soft FK to workspaces (may not exist yet)
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','accepted','expired','cancelled')),
  accepted_by     UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  accepted_at     TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days'),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_invites_inviter_idx  ON auth_invites(inviter_id);
CREATE INDEX IF NOT EXISTS auth_invites_code_idx     ON auth_invites(invite_code);
CREATE INDEX IF NOT EXISTS auth_invites_expires_idx  ON auth_invites(expires_at) WHERE status = 'pending';

COMMENT ON TABLE auth_invites IS
  'User invite codes. Cleanup job deletes stale pending invites older than 7 days.';

-- ═══════════════════════════════════════════════════════════════
-- PART F: ACTIVE SESSIONS VIEW
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW active_sessions AS
SELECT
  s.id,
  s.user_id,
  s.session_type,
  s.device_id,
  s.ip_address,
  s.country_code,
  s.app_id,
  s.last_used_at,
  s.expires_at,
  s.created_at
FROM auth_sessions s
WHERE s.revoked_at IS NULL
  AND s.expires_at > now()
ORDER BY s.last_used_at DESC;

COMMENT ON VIEW active_sessions IS
  'Currently active (non-revoked, non-expired) user sessions.';
