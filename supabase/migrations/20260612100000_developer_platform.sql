-- RALD Developer Platform — Database Schema
-- Migration: 20260612100000_developer_platform
-- Creates tables for: developer profiles, API keys, registered apps, webhooks
-- LILCKY STUDIO LIMITED · 2026-06-12

-- ── Developer Profiles ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS developer_profiles (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  dev_id              text NOT NULL UNIQUE,
  developer_name      text NOT NULL,
  organization        text,
  website             text,
  country             text,
  region              text,
  verification_status text NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('unverified','pending','verified')),
  trust_level         integer NOT NULL DEFAULT 1 CHECK (trust_level BETWEEN 1 AND 5),
  api_usage_tier      text NOT NULL DEFAULT 'Starter',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS developer_profiles_user_id_idx ON developer_profiles(user_id);
CREATE INDEX IF NOT EXISTS developer_profiles_dev_id_idx ON developer_profiles(dev_id);

ALTER TABLE developer_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY developer_profiles_own ON developer_profiles
  FOR ALL USING (user_id = auth.uid());

-- ── Developer API Keys ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS developer_api_keys (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  developer_id    uuid REFERENCES developer_profiles(id) ON DELETE CASCADE,
  type            text NOT NULL CHECK (type IN ('MASTER','PRODUCT','WORKSPACE','SERVICE')),
  name            text NOT NULL,
  prefix          text NOT NULL,
  key_hash        text NOT NULL,
  product         text,
  workspace_id    text,
  scopes          text[] NOT NULL DEFAULT '{}',
  status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','suspended')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz,
  revoked_at      timestamptz
);

CREATE INDEX IF NOT EXISTS developer_api_keys_user_id_idx ON developer_api_keys(user_id);
CREATE INDEX IF NOT EXISTS developer_api_keys_status_idx ON developer_api_keys(status);

ALTER TABLE developer_api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY developer_api_keys_own ON developer_api_keys
  FOR ALL USING (user_id = auth.uid());

-- ── Developer Registered Apps ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS developer_registered_apps (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  app_id          text NOT NULL UNIQUE,
  name            text NOT NULL,
  description     text,
  website         text,
  country         text,
  callback_urls   text[] NOT NULL DEFAULT '{}',
  environment     text NOT NULL DEFAULT 'development' CHECK (environment IN ('development','test','production')),
  status          text NOT NULL DEFAULT 'development' CHECK (status IN ('development','closed_beta','production','suspended')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS developer_registered_apps_user_id_idx ON developer_registered_apps(user_id);
CREATE INDEX IF NOT EXISTS developer_registered_apps_app_id_idx ON developer_registered_apps(app_id);

ALTER TABLE developer_registered_apps ENABLE ROW LEVEL SECURITY;
CREATE POLICY developer_registered_apps_own ON developer_registered_apps
  FOR ALL USING (user_id = auth.uid());

-- ── Developer Webhooks ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS developer_webhooks (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  url                 text NOT NULL,
  events              text[] NOT NULL DEFAULT '{}',
  secret              text,
  active              boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_triggered_at   timestamptz
);

CREATE INDEX IF NOT EXISTS developer_webhooks_user_id_idx ON developer_webhooks(user_id);

ALTER TABLE developer_webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY developer_webhooks_own ON developer_webhooks
  FOR ALL USING (user_id = auth.uid());

-- ── Updated_at triggers ───────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

CREATE TRIGGER developer_profiles_updated_at
  BEFORE UPDATE ON developer_profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER developer_registered_apps_updated_at
  BEFORE UPDATE ON developer_registered_apps
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Indexes for SSO app lookup (extends existing registered_apps pattern) ────

COMMENT ON TABLE developer_profiles IS 'RALD Developer Identity — profiles for closed beta developer access';
COMMENT ON TABLE developer_api_keys IS 'RALD API Keys — MASTER, PRODUCT, WORKSPACE, SERVICE key management';
COMMENT ON TABLE developer_registered_apps IS 'RALD Application Registry — OAuth and API app registrations';
COMMENT ON TABLE developer_webhooks IS 'RALD Developer Webhooks — event subscriptions';
