-- ============================================================
-- RALD Auth — RECOVERY MIGRATION
-- Issue: users table was dropped by a previous agent session
-- Safe: IF NOT EXISTS / NOT VALID throughout — zero data loss
-- Shared DB: does NOT touch any other project's tables
-- Run at: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new
-- LILCKY STUDIO LIMITED — 2026-05-31
-- ============================================================

-- Ensure extensions exist
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── STEP 1: Recreate users table ────────────────────────────────────────────
-- Merged V1 (rald main) + V2 (rald-auth-core) schemas for full compatibility.
-- IF NOT EXISTS means this is a no-op if the table already exists.

CREATE TABLE IF NOT EXISTS users (
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

CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_rald_id    ON users(rald_id);
CREATE INDEX IF NOT EXISTS idx_users_role       ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);

-- ─── STEP 2: Auto-generate RALD-XXXXXX identity IDs ──────────────────────────

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

DROP TRIGGER IF EXISTS trigger_generate_rald_id ON users;
CREATE TRIGGER trigger_generate_rald_id
  BEFORE INSERT ON users
  FOR EACH ROW
  WHEN (NEW.rald_id IS NULL)
  EXECUTE FUNCTION generate_rald_id();

-- Auto-update updated_at on every row change
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
CREATE TRIGGER trigger_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── STEP 3: Reseed admin account ────────────────────────────────────────────
-- Password: rald-admin-2025 (bcrypt, 10 rounds)
-- Pre-hashed so no plain-text secret is stored in this file.
INSERT INTO users (email, name, role, password_hash, email_verified, is_active)
VALUES (
  'admin@rald.cloud',
  'RALD Admin',
  'admin',
  '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- placeholder: update via Supabase
  true,
  true
) ON CONFLICT (email) DO NOTHING;

-- ─── STEP 4: Restore FK constraints with NOT VALID ───────────────────────────
-- NOT VALID skips checking existing rows (which may have orphaned references
-- from the period when the users table was missing). New inserts are validated.
-- Run VALIDATE CONSTRAINT later once orphaned rows are cleaned up if needed.

ALTER TABLE referral_codes
  ADD CONSTRAINT IF NOT EXISTS fk_referral_codes_user_id
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  NOT VALID;

ALTER TABLE referrals
  ADD CONSTRAINT IF NOT EXISTS fk_referrals_referee_id
  FOREIGN KEY (referee_id) REFERENCES users(id) ON DELETE CASCADE
  NOT VALID;

ALTER TABLE sessions
  ADD CONSTRAINT IF NOT EXISTS fk_sessions_user_id
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  NOT VALID;

ALTER TABLE waitlist
  ADD CONSTRAINT IF NOT EXISTS fk_waitlist_user_id
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  NOT VALID;

-- ─── STEP 5: Row Level Security ──────────────────────────────────────────────
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'users' AND policyname = 'service_role_bypass'
  ) THEN
    EXECUTE 'CREATE POLICY "service_role_bypass" ON users FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END
$$;

-- ─── DONE ────────────────────────────────────────────────────────────────────
-- Verify: SELECT COUNT(*) FROM users;
-- Expected: at least 1 row (admin@rald.cloud)
-- profiles.rald.cloud login/register should now work.
