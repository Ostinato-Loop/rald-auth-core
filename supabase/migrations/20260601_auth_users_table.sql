-- ============================================================
-- RALD Auth Core — AUTH NAMESPACE MIGRATION
-- Reason: Shared Supabase DB contains a `users` table owned by
--   a different product (creator/music platform). rald-auth-core
--   needs its own isolated table namespace to avoid schema collision.
-- All rald-auth tables now use the `auth_` prefix.
-- Safe: IF NOT EXISTS throughout — zero data loss risk.
-- Run at: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new
-- LILCKY STUDIO LIMITED — 2026-06-01
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── auth_users ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_users (
  id              UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  email           TEXT          UNIQUE NOT NULL,
  name            TEXT          NOT NULL DEFAULT '',
  password_hash   TEXT,
  role            TEXT          NOT NULL DEFAULT 'user'
                                CHECK (role IN ('user', 'admin', 'operator', 'merchant')),
  rald_id         TEXT          UNIQUE,
  metadata        JSONB         DEFAULT '{}'::jsonb,
  avatar_url      TEXT,
  last_login      TIMESTAMPTZ,
  is_active       BOOLEAN       NOT NULL DEFAULT true,
  email_verified  BOOLEAN       NOT NULL DEFAULT false,
  phone_verified  BOOLEAN       NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_users_email      ON auth_users(email);
CREATE INDEX IF NOT EXISTS idx_auth_users_rald_id    ON auth_users(rald_id);
CREATE INDEX IF NOT EXISTS idx_auth_users_role       ON auth_users(role);
CREATE INDEX IF NOT EXISTS idx_auth_users_created_at ON auth_users(created_at DESC);

-- ─── auth_sessions ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_sessions (
  id            UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id       UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  user_agent    TEXT,
  ip_address    TEXT,
  last_seen_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ   NOT NULL,
  revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id    ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at);

-- ─── auth_devices ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_devices (
  id            UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id       UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  device_name   TEXT,
  device_type   TEXT,
  os            TEXT,
  browser       TEXT,
  ip_address    TEXT,
  last_seen_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  is_trusted    BOOLEAN       NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_devices_user_id ON auth_devices(user_id);

-- ─── auth_product_access ────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_product_access (
  id            UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id       UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  product       TEXT          NOT NULL,
  role          TEXT          NOT NULL DEFAULT 'user',
  granted_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  granted_by    UUID,
  expires_at    TIMESTAMPTZ,
  UNIQUE(user_id, product)
);

CREATE INDEX IF NOT EXISTS idx_auth_product_access_user_id ON auth_product_access(user_id);

-- ─── auth_otp_codes ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_otp_codes (
  id          UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  email       TEXT          NOT NULL,
  code_hash   TEXT          NOT NULL,
  type        TEXT          NOT NULL,
  used        BOOLEAN       NOT NULL DEFAULT false,
  expires_at  TIMESTAMPTZ   NOT NULL,
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_email      ON auth_otp_codes(email);
CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_expires_at ON auth_otp_codes(expires_at);

-- ─── RALD-ID trigger ────────────────────────────────────────
CREATE OR REPLACE FUNCTION generate_rald_id()
RETURNS TRIGGER AS $$
DECLARE
  chars  TEXT    := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  result TEXT    := 'RALD-';
  i      INTEGER;
BEGIN
  FOR i IN 1..6 LOOP
    result := result || substr(chars, floor(random() * length(chars) + 1)::int, 1);
  END LOOP;
  NEW.rald_id := result;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_generate_rald_id ON auth_users;
CREATE TRIGGER trigger_generate_rald_id
  BEFORE INSERT ON auth_users
  FOR EACH ROW WHEN (NEW.rald_id IS NULL)
  EXECUTE FUNCTION generate_rald_id();

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at := NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_auth_users_updated_at ON auth_users;
CREATE TRIGGER trigger_auth_users_updated_at
  BEFORE UPDATE ON auth_users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Seed admin account ─────────────────────────────────────
-- Placeholder hash — update via Supabase dashboard after applying migration
INSERT INTO auth_users (email, name, role, email_verified, is_active)
VALUES ('admin@rald.cloud', 'RALD Admin', 'admin', true, true)
ON CONFLICT (email) DO NOTHING;

-- ─── Row Level Security ──────────────────────────────────────
ALTER TABLE auth_users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_devices        ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_product_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_otp_codes      ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='auth_users'          AND policyname='auth_service_role') THEN EXECUTE 'CREATE POLICY "auth_service_role" ON auth_users          FOR ALL USING (auth.role() = ''service_role'')'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='auth_sessions'       AND policyname='auth_service_role') THEN EXECUTE 'CREATE POLICY "auth_service_role" ON auth_sessions       FOR ALL USING (auth.role() = ''service_role'')'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='auth_devices'        AND policyname='auth_service_role') THEN EXECUTE 'CREATE POLICY "auth_service_role" ON auth_devices        FOR ALL USING (auth.role() = ''service_role'')'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='auth_product_access' AND policyname='auth_service_role') THEN EXECUTE 'CREATE POLICY "auth_service_role" ON auth_product_access FOR ALL USING (auth.role() = ''service_role'')'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='auth_otp_codes'      AND policyname='auth_service_role') THEN EXECUTE 'CREATE POLICY "auth_service_role" ON auth_otp_codes      FOR ALL USING (auth.role() = ''service_role'')'; END IF;
END $$;

-- ─── Verify ──────────────────────────────────────────────────
-- SELECT table_name FROM information_schema.tables
-- WHERE table_schema='public' AND table_name LIKE 'auth_%';
-- Expected: auth_users, auth_sessions, auth_devices, auth_product_access, auth_otp_codes
