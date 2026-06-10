-- RALD Auth Core — Public Beta Hardening Migration
-- 2026-06-10
--
-- Changes:
--   1. otp_attempt_log table — persistent OTP failure tracking
--   2. signup_events view — fast signup reporting without full audit_logs scan
--   3. username_namespace_reservations index (idempotent)
--   4. Ensure reserve_username_namespace RPC exists (create if missing)
--   5. auth_users: add columns that V2 flow writes (idempotent)
-- LILCKY STUDIO LIMITED

-- ── 1. OTP attempt tracking (persistent, complements KV rate limiting) ────────
CREATE TABLE IF NOT EXISTS otp_attempt_log (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        REFERENCES auth_users(id) ON DELETE CASCADE,
  method        text        NOT NULL CHECK (method IN ('sms','email')),
  success       boolean     NOT NULL,
  ip_address    inet,
  stage         text        NOT NULL DEFAULT 'verify',
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_otp_attempt_user_created
  ON otp_attempt_log(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_otp_attempt_ip_created
  ON otp_attempt_log(ip_address, created_at DESC);

-- ── 2. Signup events materialized view for fast metrics ────────────────────────
CREATE OR REPLACE VIEW public.signup_events AS
SELECT
  al.id,
  al.user_id,
  al.created_at,
  al.ip_address,
  al.metadata->>'username'         AS username,
  al.metadata->>'rald_internal_id' AS rald_internal_id,
  al.metadata->>'app_id'           AS app_id,
  al.metadata->>'country'          AS country,
  au.phone_verified,
  au.email_verified
FROM audit_logs al
LEFT JOIN auth_users au ON au.id = al.user_id
WHERE al.action = 'username_claimed';

-- ── 3. Ensure auth_users has V2 columns ──────────────────────────────────────
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS username         text;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS username_set_at  timestamptz;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS phone_number     text;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS phone_verified   boolean NOT NULL DEFAULT false;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS rald_internal_id text;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS rald_id          text;

-- Case-insensitive unique index on username (V2 namespace protection)
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_username_ci
  ON auth_users(lower(username))
  WHERE username IS NOT NULL;

-- ── 4. reserve_username_namespace RPC (idempotent) ────────────────────────────
CREATE TABLE IF NOT EXISTS username_namespace_reservations (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        REFERENCES auth_users(id) ON DELETE CASCADE,
  username       text        NOT NULL,
  mail_alias     text        NOT NULL,  -- username@rald.me
  subdomain      text        NOT NULL,  -- username.rald.me
  workspace_slug text        NOT NULL,  -- workspace slug
  reserved_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE(mail_alias),
  UNIQUE(subdomain),
  UNIQUE(workspace_slug)
);

CREATE OR REPLACE FUNCTION reserve_username_namespace(
  p_user_id  uuid,
  p_username text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO username_namespace_reservations
    (user_id, username, mail_alias, subdomain, workspace_slug)
  VALUES
    (p_user_id, p_username,
     p_username || '@rald.me',
     p_username || '.rald.me',
     p_username)
  ON CONFLICT DO NOTHING;
END;
$$;

-- ── 5. Fast lookup indexes ────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created
  ON audit_logs(action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action
  ON audit_logs(user_id, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_email_purpose
  ON auth_otp_codes(email, purpose, used, created_at DESC);

-- ── Done ──────────────────────────────────────────────────────────────────────
COMMENT ON TABLE otp_attempt_log IS
  'Persistent OTP attempt tracking for audit and abuse detection. KV rate limits are the primary enforcement mechanism; this table enables after-the-fact analysis.';

COMMENT ON VIEW signup_events IS
  'Fast, denormalized view of V2 username registrations for operational metrics.';

COMMENT ON TABLE username_namespace_reservations IS
  'Permanent record of reserved mail aliases, subdomains, and workspace slugs for each RALD username.';
