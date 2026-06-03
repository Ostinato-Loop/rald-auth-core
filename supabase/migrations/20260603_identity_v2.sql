-- RALD Identity Platform V2 Migration
-- Creates: auth_user_profiles, auth_login_history
-- Phase: Universal Identity Hardening
-- Owner: LILCKY STUDIO LIMITED
-- Date: 2026-06-03

-- ── auth_user_profiles — extended profile data for profiles.rald.cloud ─────────
CREATE TABLE IF NOT EXISTS auth_user_profiles (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
  display_name     TEXT CHECK (char_length(display_name) <= 80),
  avatar_url       TEXT CHECK (char_length(avatar_url) <= 500),
  bio              TEXT CHECK (char_length(bio) <= 300),
  preferences      JSONB NOT NULL DEFAULT '{}',
  provisioned_apps TEXT[] NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_user_profiles_user ON auth_user_profiles(user_id);

COMMENT ON TABLE auth_user_profiles IS
  'Extended profile data served by profiles.rald.cloud (RALD Identity Platform V2)';

-- ── auth_login_history — per-app login tracking for Connected Apps Dashboard ──
CREATE TABLE IF NOT EXISTS auth_login_history (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL,
  app_id       TEXT NOT NULL,
  ip_address   TEXT,
  user_agent   TEXT,
  country      TEXT,
  success      BOOLEAN NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_login_history_user   ON auth_login_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_login_history_app    ON auth_login_history(app_id, user_id);
CREATE INDEX IF NOT EXISTS idx_auth_login_history_recent ON auth_login_history(created_at DESC);

COMMENT ON TABLE auth_login_history IS
  'Login and SSO exchange events per app — powers Connected Apps Dashboard';

-- ── Upsert helper for provisioned_apps array ─────────────────────────────────
CREATE OR REPLACE FUNCTION provision_app_append(p_user_id UUID, p_app_id TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO auth_user_profiles (user_id, provisioned_apps)
  VALUES (p_user_id, ARRAY[p_app_id])
  ON CONFLICT (user_id) DO UPDATE
    SET provisioned_apps = CASE
      WHEN p_app_id = ANY(auth_user_profiles.provisioned_apps)
        THEN auth_user_profiles.provisioned_apps
      ELSE auth_user_profiles.provisioned_apps || ARRAY[p_app_id]
    END,
    updated_at = now();
END;
$$;

COMMENT ON FUNCTION provision_app_append IS
  'Idempotently appends an app_id to a user profile provisioned_apps array';

-- ── Row-level security ────────────────────────────────────────────────────────
ALTER TABLE auth_user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_login_history ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (used by the Worker with service role key)
-- Client-side access policies can be added later when direct Supabase client access is needed
