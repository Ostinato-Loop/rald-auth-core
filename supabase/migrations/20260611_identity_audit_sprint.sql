-- RALD Auth Core — Identity Audit & Username Ownership Sprint
-- Priority fixes:
--   1. auth_otp_codes: add `purpose` + `user_id` columns (email OTP was broken)
--   2. auth_users: add `reserved_email_address`, `trust_level`, `trust_score`
--   3. auth_user_profiles: add `country`, `region`, `region_state`
--   4. auth_trust_profiles: canonical trust profile table
--   5. identity_registry view: single source of truth query
--   6. repair_identity_records(): auto-repair missing profile/trust rows
--   7. username_namespace_reservations: already created in prior migration (idempotent)
-- Safe: IF NOT EXISTS / IF NOT EXISTS column guards throughout.
-- LILCKY STUDIO LIMITED — 2026-06-11

-- ─── 1. Fix auth_otp_codes — add missing `purpose` and `user_id` columns ──────
-- The routes query by `purpose` but the original table only had `type`.
-- This was the root cause of email OTP verification failures.
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS user_id   UUID REFERENCES auth_users(id) ON DELETE CASCADE;
ALTER TABLE auth_otp_codes ADD COLUMN IF NOT EXISTS purpose   TEXT NOT NULL DEFAULT 'email-otp-login';

-- Back-fill: map existing `type` → `purpose` for continuity
UPDATE auth_otp_codes SET purpose = type WHERE purpose = 'email-otp-login' AND type IS NOT NULL AND type <> '';

-- Indexes for the query pattern used in the routes
CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_email_purpose
  ON auth_otp_codes(email, purpose, used, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_user_id
  ON auth_otp_codes(user_id, purpose, used, created_at DESC);

COMMENT ON COLUMN auth_otp_codes.purpose IS
  'Identifies the OTP flow: email-otp-login | registration | password-reset. Replaces legacy `type` column.';

-- ─── 2. auth_users — identity-first columns ───────────────────────────────────
-- reserved_email_address: username@rald.me — stored at claim time
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS reserved_email_address TEXT UNIQUE;

-- trust_level: none | basic | verified | trusted | premium
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS trust_level TEXT NOT NULL DEFAULT 'none'
  CHECK (trust_level IN ('none', 'basic', 'verified', 'trusted', 'premium'));

-- trust_score: 0–100 numeric score
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS trust_score INTEGER NOT NULL DEFAULT 0
  CHECK (trust_score BETWEEN 0 AND 100);

-- phone_number column (idempotent — may already exist from prior migration)
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS phone_number TEXT;

-- Backfill reserved_email_address for users who already have usernames
UPDATE auth_users
SET reserved_email_address = username || '@rald.me'
WHERE username IS NOT NULL
  AND reserved_email_address IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_users_trust_level ON auth_users(trust_level);
CREATE INDEX IF NOT EXISTS idx_auth_users_reserved_email ON auth_users(reserved_email_address)
  WHERE reserved_email_address IS NOT NULL;

-- ─── 3. auth_user_profiles — regional fields ─────────────────────────────────
ALTER TABLE auth_user_profiles ADD COLUMN IF NOT EXISTS country      TEXT;
ALTER TABLE auth_user_profiles ADD COLUMN IF NOT EXISTS region       TEXT;
ALTER TABLE auth_user_profiles ADD COLUMN IF NOT EXISTS region_state TEXT;

COMMENT ON COLUMN auth_user_profiles.country IS 'ISO 3166-1 alpha-2 country code, e.g. NG';
COMMENT ON COLUMN auth_user_profiles.region  IS 'Broad regional grouping, e.g. West Africa';

-- ─── 4. auth_trust_profiles — canonical trust record per user ─────────────────
CREATE TABLE IF NOT EXISTS auth_trust_profiles (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID        NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
  trust_level         TEXT        NOT NULL DEFAULT 'none'
                                  CHECK (trust_level IN ('none', 'basic', 'verified', 'trusted', 'premium')),
  trust_score         INTEGER     NOT NULL DEFAULT 0 CHECK (trust_score BETWEEN 0 AND 100),
  has_username        BOOLEAN     NOT NULL DEFAULT false,
  has_verified_phone  BOOLEAN     NOT NULL DEFAULT false,
  has_verified_email  BOOLEAN     NOT NULL DEFAULT false,
  has_reserved_mail   BOOLEAN     NOT NULL DEFAULT false,
  has_profile         BOOLEAN     NOT NULL DEFAULT false,
  identity_complete   BOOLEAN     NOT NULL GENERATED ALWAYS AS (
    has_username AND (has_verified_phone OR has_verified_email)
  ) STORED,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_trust_profiles_user_id ON auth_trust_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_trust_profiles_complete ON auth_trust_profiles(identity_complete);

COMMENT ON TABLE auth_trust_profiles IS
  'Canonical trust profile for every RALD identity. Single source of truth for ecosystem access gates.';

-- ─── 5. identity_registry view — P5 single-source-of-truth ───────────────────
CREATE OR REPLACE VIEW identity_registry AS
SELECT
  u.id                      AS user_id,
  u.username,
  COALESCE(p.display_name, u.name, u.username)  AS display_name,
  u.reserved_email_address  AS future_email_reserved,
  u.rald_internal_id,
  u.rald_id,
  u.email_verified,
  u.phone_verified,
  u.trust_level,
  u.trust_score,
  p.country,
  p.region,
  p.region_state,
  t.identity_complete,
  t.has_username,
  t.has_verified_phone,
  t.has_verified_email,
  t.has_reserved_mail,
  u.created_at
FROM auth_users u
LEFT JOIN auth_user_profiles p  ON p.user_id = u.id
LEFT JOIN auth_trust_profiles t ON t.user_id = u.id;

COMMENT ON VIEW identity_registry IS
  'P5: Central identity registry. Every RALD account visible here. Required fields: user_id, username, display_name, future_email_reserved, trust_profile, created_at.';

-- ─── 6. repair_identity_records() — auto-repair missing rows ─────────────────
-- Called from application code and can be scheduled as a cron.
CREATE OR REPLACE FUNCTION repair_identity_records(p_user_id UUID DEFAULT NULL)
RETURNS TABLE(user_id UUID, repaired_profile BOOLEAN, repaired_trust BOOLEAN, repaired_reserved_mail BOOLEAN)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  rec RECORD;
  did_profile       BOOLEAN;
  did_trust         BOOLEAN;
  did_reserved_mail BOOLEAN;
BEGIN
  FOR rec IN
    SELECT
      u.id,
      u.username,
      u.email_verified,
      u.phone_verified,
      u.reserved_email_address
    FROM auth_users u
    WHERE (p_user_id IS NULL OR u.id = p_user_id)
      AND u.is_active = true
  LOOP
    did_profile       := false;
    did_trust         := false;
    did_reserved_mail := false;

    -- Repair auth_user_profiles
    INSERT INTO auth_user_profiles (user_id, created_at, updated_at)
    VALUES (rec.id, now(), now())
    ON CONFLICT (user_id) DO NOTHING;
    GET DIAGNOSTICS did_profile = ROW_COUNT;
    did_profile := did_profile::integer > 0;

    -- Repair auth_trust_profiles
    INSERT INTO auth_trust_profiles (
      user_id, has_username, has_verified_phone, has_verified_email, has_reserved_mail, has_profile,
      trust_level, trust_score
    ) VALUES (
      rec.id,
      rec.username IS NOT NULL,
      rec.phone_verified,
      rec.email_verified,
      rec.reserved_email_address IS NOT NULL,
      true,
      CASE
        WHEN rec.username IS NOT NULL AND (rec.email_verified OR rec.phone_verified) AND rec.reserved_email_address IS NOT NULL THEN 'verified'
        WHEN rec.username IS NOT NULL OR rec.email_verified OR rec.phone_verified THEN 'basic'
        ELSE 'none'
      END,
      CASE
        WHEN rec.username IS NOT NULL AND rec.email_verified AND rec.phone_verified THEN 80
        WHEN rec.username IS NOT NULL AND (rec.email_verified OR rec.phone_verified) THEN 60
        WHEN rec.username IS NOT NULL THEN 30
        ELSE 0
      END
    )
    ON CONFLICT (user_id) DO UPDATE SET
      has_username       = EXCLUDED.has_username,
      has_verified_phone = EXCLUDED.has_verified_phone,
      has_verified_email = EXCLUDED.has_verified_email,
      has_reserved_mail  = EXCLUDED.has_reserved_mail,
      has_profile        = true,
      updated_at         = now();
    GET DIAGNOSTICS did_trust = ROW_COUNT;
    did_trust := did_trust::integer > 0;

    -- Repair reserved_email_address
    IF rec.username IS NOT NULL AND rec.reserved_email_address IS NULL THEN
      UPDATE auth_users
      SET reserved_email_address = rec.username || '@rald.me'
      WHERE id = rec.id;
      did_reserved_mail := true;
    END IF;

    user_id              := rec.id;
    repaired_profile     := did_profile;
    repaired_trust       := did_trust;
    repaired_reserved_mail := did_reserved_mail;
    RETURN NEXT;
  END LOOP;
END;
$$;

COMMENT ON FUNCTION repair_identity_records IS
  'P5: Auto-repair missing auth_user_profiles, auth_trust_profiles, and reserved_email_address for all or a single user.';

-- ─── 7. Backfill trust profiles for all existing users ────────────────────────
SELECT repair_identity_records();

-- ─── 8. username_migration_queue — P4 track users needing username claim ──────
CREATE TABLE IF NOT EXISTS username_migration_queue (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID        NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
  prompted_at     TIMESTAMPTZ,
  dismissed_count INTEGER     NOT NULL DEFAULT 0,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_username_migration_queue_user   ON username_migration_queue(user_id);
CREATE INDEX IF NOT EXISTS idx_username_migration_queue_pending ON username_migration_queue(completed_at)
  WHERE completed_at IS NULL;

-- Seed queue: all existing users without usernames
INSERT INTO username_migration_queue (user_id)
SELECT id FROM auth_users
WHERE username IS NULL AND is_active = true
ON CONFLICT (user_id) DO NOTHING;

COMMENT ON TABLE username_migration_queue IS
  'P4: Tracks users who need to claim a username. Shown on next login, cannot be permanently dismissed.';

-- ─── Done ────────────────────────────────────────────────────────────────────
COMMENT ON VIEW identity_registry IS
  'P5: Central RALD identity registry. Fields: user_id, username, display_name, future_email_reserved, region, trust_profile, created_at.';
