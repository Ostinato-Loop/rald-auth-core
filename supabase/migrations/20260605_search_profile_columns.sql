-- ============================================================
-- RALD Auth Core — Search & Discovery columns for auth_user_profiles
-- Adds: username, search_discoverable, location, interests,
--       is_verified, rald_address
-- Safe: IF NOT EXISTS / DO $$ blocks throughout — zero data loss risk.
-- Run at: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new
-- LILCKY STUDIO LIMITED — 2026-06-05
-- ============================================================

ALTER TABLE auth_user_profiles
  ADD COLUMN IF NOT EXISTS username            TEXT        UNIQUE,
  ADD COLUMN IF NOT EXISTS search_discoverable BOOLEAN     NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS location            TEXT,
  ADD COLUMN IF NOT EXISTS interests           TEXT[]      DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS is_verified         BOOLEAN     NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS rald_address        TEXT        UNIQUE;

CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_username     ON auth_user_profiles(username);
CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_discoverable ON auth_user_profiles(search_discoverable);
CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_rald_address ON auth_user_profiles(rald_address);
CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_location     ON auth_user_profiles(location);

-- Full-text search index on display_name + username + bio
CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_fts ON auth_user_profiles
  USING GIN (
    to_tsvector('english',
      COALESCE(display_name,'') || ' ' ||
      COALESCE(username,'')     || ' ' ||
      COALESCE(bio,'')
    )
  );
