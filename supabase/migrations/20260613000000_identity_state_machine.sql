-- ============================================================
-- RALD Auth Core — Identity State Machine
-- Migration: 20260613000000_identity_state_machine
-- Phase 1 of RALD Ecosystem Finalization Program
--
-- Adds identity lifecycle state tracking to auth_users:
--   identity_state                    — canonical FSM state
--   username_reservation_expires_at   — TTL for username holds
--   otp_expires_at                    — TTL for pending verification
--
-- Adds consent grants table for Phase 8 (ALIA Consent Engine).
-- Adds trust signal events table for Phase 7 (ALIA Trust Engine).
--
-- Safe: all ADD COLUMN / CREATE TABLE use IF NOT EXISTS.
-- No data loss. Backfills existing rows to 'ACTIVE'.
-- LILCKY STUDIO LIMITED · 2026-06-13
-- ============================================================

-- ─── 1. identity_state column ────────────────────────────────────────────────

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS identity_state TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (identity_state IN (
      'USERNAME_RESERVED',
      'PENDING_VERIFICATION',
      'OTP_VERIFIED',
      'PROFILE_COMPLETED',
      'ACTIVE',
      'SUSPENDED',
      'DELETED'
    ));

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS username_reservation_expires_at TIMESTAMPTZ;

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS otp_expires_at TIMESTAMPTZ;

-- Backfill: all existing users → ACTIVE
UPDATE auth_users
SET identity_state = 'ACTIVE'
WHERE identity_state IS NULL OR identity_state = '';

-- ─── 2. Indexes for cleanup cron (runs every 5 min) ──────────────────────────

CREATE INDEX IF NOT EXISTS idx_auth_users_state_reservation
  ON auth_users (identity_state, username_reservation_expires_at)
  WHERE identity_state IN ('USERNAME_RESERVED', 'PENDING_VERIFICATION');

CREATE INDEX IF NOT EXISTS idx_auth_users_state
  ON auth_users (identity_state)
  WHERE identity_state IN ('SUSPENDED', 'DELETED');

-- ─── 3. trust_score / trust_level on auth_users (Phase 7 — Trust Engine) ─────
-- Add to auth_users directly for fast JWT issuance (no join needed)

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS trust_score  INTEGER NOT NULL DEFAULT 0
    CHECK (trust_score BETWEEN 0 AND 100);

ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS trust_level  TEXT NOT NULL DEFAULT 'none'
    CHECK (trust_level IN ('none','member','active','contributor','verified','leader','institutional'));

-- Backfill trust_level from trust_score
UPDATE auth_users SET trust_level = CASE
  WHEN trust_score >= 90 THEN 'institutional'
  WHEN trust_score >= 75 THEN 'leader'
  WHEN trust_score >= 60 THEN 'verified'
  WHEN trust_score >= 40 THEN 'contributor'
  WHEN trust_score >= 25 THEN 'active'
  WHEN trust_score >= 10 THEN 'member'
  ELSE 'none'
END
WHERE trust_level = 'none' AND trust_score > 0;

-- Bootstrap: verified phone = at least member level (score 10)
UPDATE auth_users
SET trust_score = GREATEST(trust_score, 10),
    trust_level = CASE WHEN trust_level = 'none' THEN 'member' ELSE trust_level END
WHERE phone_verified = true;

-- ─── 4. Trust signal events log (Phase 7) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS auth_trust_signals (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  signal       TEXT        NOT NULL,
  category     TEXT        NOT NULL CHECK (category IN ('identity','social','commerce','institutional','behavioral')),
  weight       INTEGER     NOT NULL DEFAULT 0,
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  granted_by   TEXT        NOT NULL DEFAULT 'system',
  metadata     JSONB       DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_trust_signals_user_id    ON auth_trust_signals(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_signals_signal     ON auth_trust_signals(user_id, signal);
CREATE INDEX IF NOT EXISTS idx_trust_signals_active     ON auth_trust_signals(user_id)
  WHERE revoked_at IS NULL;

ALTER TABLE auth_trust_signals ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'auth_trust_signals' AND policyname = 'trust_signals_service_role'
  ) THEN
    EXECUTE 'CREATE POLICY "trust_signals_service_role" ON auth_trust_signals
             FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- Seed: phone_verified signal for existing verified users
INSERT INTO auth_trust_signals (user_id, signal, category, weight, granted_by)
SELECT id, 'phone_verified', 'identity', 10, 'migration'
FROM auth_users
WHERE phone_verified = true
ON CONFLICT DO NOTHING;

-- ─── 5. Consent grants table (Phase 8 — ALIA Consent Engine) ─────────────────

CREATE TABLE IF NOT EXISTS auth_consent_grants (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  app_id       TEXT        NOT NULL,
  scopes       TEXT[]      NOT NULL DEFAULT '{}',
  purpose      TEXT,
  granted_by   TEXT        NOT NULL DEFAULT 'user'
               CHECK (granted_by IN ('user','admin','implicit')),
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  metadata     JSONB       DEFAULT '{}'::jsonb
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_consent_grants_user_app
  ON auth_consent_grants (user_id, app_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_id ON auth_consent_grants(user_id);

ALTER TABLE auth_consent_grants ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'auth_consent_grants' AND policyname = 'consent_service_role'
  ) THEN
    EXECUTE 'CREATE POLICY "consent_service_role" ON auth_consent_grants
             FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- Seed implicit consent for first-party RALD products (all existing users)
INSERT INTO auth_consent_grants (user_id, app_id, scopes, purpose, granted_by)
SELECT
  id,
  app_id,
  scopes,
  purpose,
  'implicit'
FROM auth_users,
  (VALUES
    ('loop',      ARRAY['rald:identity:read','loop:read','loop:write','loop:notifications'], 'First-party RALD product — implicit consent'),
    ('messenger', ARRAY['rald:identity:read','messenger:read','messenger:write'],            'First-party RALD product — implicit consent'),
    ('payrald',   ARRAY['rald:identity:read','payrald:balance'],                            'First-party RALD product — implicit consent'),
    ('alia',      ARRAY['rald:identity:read','alia:chat','alia:context:profile'],           'First-party RALD product — implicit consent')
  ) AS apps(app_id, scopes, purpose)
ON CONFLICT DO NOTHING;

-- ─── 6. Machine identity registry (Phase 11) ─────────────────────────────────

CREATE TABLE IF NOT EXISTS machine_identities (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  service_id    TEXT        NOT NULL UNIQUE,   -- e.g. "svc:loop-worker"
  display_name  TEXT        NOT NULL,
  service       TEXT        NOT NULL,
  environment   TEXT        NOT NULL DEFAULT 'production'
                CHECK (environment IN ('production','staging','sandbox')),
  permissions   TEXT[]      NOT NULL DEFAULT '{}',
  public_key    TEXT,                          -- ES256 public key (PEM), NULL during migration
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active        BOOLEAN     NOT NULL DEFAULT true
);

ALTER TABLE machine_identities ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'machine_identities' AND policyname = 'machine_identities_service_role'
  ) THEN
    EXECUTE 'CREATE POLICY "machine_identities_service_role" ON machine_identities
             FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- Seed machine identity registry
INSERT INTO machine_identities (service_id, display_name, service, permissions) VALUES
  ('svc:auth-core',       'Auth Core',             'auth.rald.cloud',   ARRAY['*']),
  ('svc:loop-worker',     'Loop Worker',            'loop',              ARRAY['session.read','profile.read','profile.write','sso.exchange']),
  ('svc:messenger-worker','Messenger Worker',       'messenger',         ARRAY['session.read','profile.read','sso.exchange']),
  ('svc:payrald-worker',  'PayRald Worker',         'payrald',           ARRAY['session.read','profile.read','trust.read','sso.exchange']),
  ('svc:rald-routing',    'ALIA Routing Engine',    'rald-routing',      ARRAY['session.read','trust.read','consent.read','identity.read']),
  ('svc:identity-worker', 'Identity Worker',        'rald-identity',     ARRAY['session.read','profile.read','profile.write'])
ON CONFLICT (service_id) DO NOTHING;

-- ─── 7. update_updated_at trigger for new tables ─────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at_generic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

-- ─── 8. Verify ───────────────────────────────────────────────────────────────
-- SELECT column_name FROM information_schema.columns
-- WHERE table_name = 'auth_users' AND column_name IN
--   ('identity_state','username_reservation_expires_at','otp_expires_at','trust_score','trust_level');
-- Expected: 5 rows
--
-- SELECT tablename FROM pg_tables WHERE tablename IN
--   ('auth_trust_signals','auth_consent_grants','machine_identities');
-- Expected: 3 rows
