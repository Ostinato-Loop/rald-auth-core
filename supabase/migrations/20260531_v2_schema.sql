-- RALD Auth Core — Production Schema Migration V2
-- Apply in Supabase SQL Editor or via supabase CLI
-- Date: 2026-05-31 | LILCKY STUDIO LIMITED

-- ─── EXTENSION ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── USERS TABLE (already exists — safe to skip if present) ─────────────────
CREATE TABLE IF NOT EXISTS users (
  id              UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
  email           TEXT        UNIQUE NOT NULL,
  name            TEXT,
  role            TEXT        NOT NULL DEFAULT 'user',
  password_hash   TEXT,
  rald_id         TEXT        UNIQUE,
  metadata        JSONB       DEFAULT '{}'::jsonb,
  is_active       BOOLEAN     NOT NULL DEFAULT true,
  email_verified  BOOLEAN     NOT NULL DEFAULT false,
  phone_verified  BOOLEAN     NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── SESSIONS TABLE (already exists — safe to skip if present) ──────────────
CREATE TABLE IF NOT EXISTS sessions (
  id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
  ip_address  TEXT,
  user_agent  TEXT,
  revoked_at  TIMESTAMPTZ,
  device_id   UUID
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

-- ─── USER DEVICES TABLE (MISSING — required by devices.ts routes) ────────────
CREATE TABLE IF NOT EXISTS user_devices (
  id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name    TEXT,
  device_type    TEXT,
  os             TEXT,
  browser        TEXT,
  ip_address     TEXT,
  user_agent     TEXT,
  fingerprint    TEXT,
  is_trusted     BOOLEAN     NOT NULL DEFAULT false,
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS user_devices_user_id_idx ON user_devices(user_id);

-- ─── PRODUCT ACCESS TABLE (MISSING — required by provision.ts routes) ────────
CREATE TABLE IF NOT EXISTS product_access (
  id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product     TEXT        NOT NULL,
  role        TEXT        NOT NULL DEFAULT 'user',
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at  TIMESTAMPTZ,
  metadata    JSONB       DEFAULT '{}'::jsonb,
  UNIQUE (user_id, product)
);
CREATE INDEX IF NOT EXISTS product_access_user_id_idx ON product_access(user_id);
CREATE INDEX IF NOT EXISTS product_access_product_idx ON product_access(product);

-- ─── OTP CODES TABLE (for future server-side email OTP storage) ─────────────
-- Note: current email OTP uses JWT-based storage, SMS OTP uses Termii server-side.
-- This table is pre-created for future rate limiting and replay protection.
CREATE TABLE IF NOT EXISTS otp_codes (
  id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
  identifier  TEXT        NOT NULL,
  code_hash   TEXT        NOT NULL,
  purpose     TEXT        NOT NULL DEFAULT 'login',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes'),
  used_at     TIMESTAMPTZ,
  ip_address  TEXT
);
CREATE INDEX IF NOT EXISTS otp_codes_identifier_idx ON otp_codes(identifier);
CREATE INDEX IF NOT EXISTS otp_codes_expires_at_idx ON otp_codes(expires_at);

-- ─── RALD ID GENERATION ──────────────────────────────────────────────────────
-- Auto-generate RALD-XXXXXX ID for new users
CREATE OR REPLACE FUNCTION generate_rald_id()
RETURNS TRIGGER AS $$
DECLARE
  chars TEXT := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  result TEXT := 'RALD-';
  i INTEGER;
BEGIN
  FOR i IN 1..6 LOOP
    result := result || substr(chars, floor(random() * length(chars) + 1)::int, 1);
  END LOOP;
  NEW.rald_id := result;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_generate_rald_id ON users;
CREATE TRIGGER trigger_generate_rald_id
  BEFORE INSERT ON users
  FOR EACH ROW
  WHEN (NEW.rald_id IS NULL)
  EXECUTE FUNCTION generate_rald_id();

-- ─── ROW LEVEL SECURITY ──────────────────────────────────────────────────────
-- Enable RLS on all tables (Workers use service role, bypasses RLS)
ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_devices  ENABLE ROW LEVEL SECURITY;
ALTER TABLE product_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE otp_codes     ENABLE ROW LEVEL SECURITY;

-- Service role bypass (Cloudflare Worker uses service role key)
CREATE POLICY IF NOT EXISTS "service_role_all" ON users         FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY IF NOT EXISTS "service_role_all" ON sessions      FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY IF NOT EXISTS "service_role_all" ON user_devices  FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY IF NOT EXISTS "service_role_all" ON product_access FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY IF NOT EXISTS "service_role_all" ON otp_codes     FOR ALL USING (auth.role() = 'service_role');

-- ─── CLEANUP ─────────────────────────────────────────────────────────────────
-- Remove expired OTP codes and sessions (run periodically via cron or pg_cron)
-- DELETE FROM otp_codes WHERE expires_at < NOW();
-- DELETE FROM sessions WHERE expires_at < NOW() AND revoked_at IS NULL;
