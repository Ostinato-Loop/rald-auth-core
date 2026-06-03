-- RALD Ecosystem App Registry
-- Phase G.12: Replaces hardcoded TRUSTED_APP_IDS in rald-auth-core/src/routes/sso.ts
-- All SSO app validation now goes through this table.
-- Owner: LILCKY STUDIO LIMITED
-- Date: 2026-06-03

CREATE TABLE IF NOT EXISTS registered_apps (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id       TEXT        NOT NULL UNIQUE,
  name         TEXT        NOT NULL,
  domain       TEXT        NOT NULL,
  callback_url TEXT        NOT NULL,
  logout_url   TEXT,
  icon         TEXT,
  status       TEXT        NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'suspended', 'pending')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_registered_apps_app_id ON registered_apps(app_id);
CREATE INDEX IF NOT EXISTS idx_registered_apps_status ON registered_apps(status);

COMMENT ON TABLE registered_apps IS
  'Ecosystem app registry — single source of truth for SSO-trusted applications. '
  'Replaces hardcoded TRUSTED_APP_IDS in rald-auth-core.';

ALTER TABLE registered_apps ENABLE ROW LEVEL SECURITY;
-- Service role (used by rald-auth worker) bypasses RLS.

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION set_registered_apps_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_registered_apps_updated_at ON registered_apps;
CREATE TRIGGER trg_registered_apps_updated_at
  BEFORE UPDATE ON registered_apps
  FOR EACH ROW EXECUTE FUNCTION set_registered_apps_updated_at();

-- ── Seed: all apps previously in TRUSTED_APP_IDS ──────────────────────────────
INSERT INTO registered_apps (app_id, name, domain, callback_url, logout_url, icon, status)
VALUES
  -- Identity hub
  ('profiles',            'RALD Profiles',          'profiles.rald.cloud',     'https://profiles.rald.cloud/auth/callback',    'https://profiles.rald.cloud/logout',    '👤', 'active'),
  ('identity',            'RALD Identity',           'profiles.rald.cloud',     'https://profiles.rald.cloud/auth/callback',    'https://profiles.rald.cloud/logout',    '🔐', 'active'),
  ('rald-identity',       'RALD Identity (UI)',      'profiles.rald.cloud',     'https://profiles.rald.cloud/auth/callback',    'https://profiles.rald.cloud/logout',    '🔐', 'active'),
  ('credentials',         'RALD Credentials',        'credentials.rald.cloud',  'https://credentials.rald.cloud/auth/callback', 'https://credentials.rald.cloud/logout', '🔑', 'active'),
  -- Core platform
  ('rald-app',            'RALD',                    'rald.cloud',              'https://rald.cloud/auth/callback',             'https://rald.cloud/logout',             '🌍', 'active'),
  ('rald-control-center', 'RALD Control Center',     'control.rald.cloud',      'https://control.rald.cloud/auth/callback',     'https://control.rald.cloud/logout',     '⚙️',  'active'),
  ('loop-business',       'Loop Business',           'business.rald.cloud',     'https://business.rald.cloud/auth/callback',    'https://business.rald.cloud/logout',    '🏢', 'active'),
  ('dispatch',            'Loop Dispatch',           'dispatch.rald.cloud',     'https://dispatch.rald.cloud/auth/callback',    'https://dispatch.rald.cloud/logout',    '🚚', 'active'),
  ('voice',               'Loop Voice',              'voice.rald.cloud',        'https://voice.rald.cloud/auth/callback',       'https://voice.rald.cloud/logout',       '🎙️',  'active'),
  -- Ecosystem apps
  ('loop',                'Loop',                    'loop.rald.cloud',         'https://loop.rald.cloud/auth/callback',        'https://loop.rald.cloud/logout',        '🎵', 'active'),
  ('loop-app',            'Loop App',                'loop.rald.cloud',         'https://loop.rald.cloud/auth/callback',        'https://loop.rald.cloud/logout',        '🎵', 'active'),
  ('loop-core',           'Loop Core',               'loop.rald.cloud',         'https://loop.rald.cloud/auth/callback',        'https://loop.rald.cloud/logout',        '🎵', 'active'),
  ('loop-identity',       'Loop Identity',           'loop.rald.cloud',         'https://loop.rald.cloud/auth/callback',        'https://loop.rald.cloud/logout',        '🎵', 'active'),
  ('messenger',           'Loop Messenger',          'messenger.rald.cloud',    'https://messenger.rald.cloud/auth/callback',   'https://messenger.rald.cloud/logout',   '💬', 'active'),
  ('loop-messenger',      'Loop Messenger (alt)',    'messenger.rald.cloud',    'https://messenger.rald.cloud/auth/callback',   'https://messenger.rald.cloud/logout',   '💬', 'active'),
  ('rald-inbox',          'RALD Inbox',              'inbox.rald.cloud',        'https://inbox.rald.cloud/auth/callback',       'https://inbox.rald.cloud/logout',       '📥', 'active'),
  ('payrald',             'PayRald',                 'pay.rald.cloud',          'https://pay.rald.cloud/auth/callback',         'https://pay.rald.cloud/logout',         '💳', 'active'),
  ('pay',                 'PayRald (alt)',            'pay.rald.cloud',          'https://pay.rald.cloud/auth/callback',         'https://pay.rald.cloud/logout',         '💳', 'active'),
  ('dunarald',            'DunaRald',                'duna.rald.cloud',         'https://duna.rald.cloud/auth/callback',        'https://duna.rald.cloud/logout',        '🛒', 'active'),
  ('duna',                'DunaRald (alt)',           'duna.rald.cloud',         'https://duna.rald.cloud/auth/callback',        'https://duna.rald.cloud/logout',        '🛒', 'active'),
  ('gitrald',             'GitRald',                 'git.rald.cloud',          'https://git.rald.cloud/auth/callback',         'https://git.rald.cloud/logout',         '⚙️',  'active'),
  ('gitrald-app',         'GitRald App',             'git.rald.cloud',          'https://git.rald.cloud/auth/callback',         'https://git.rald.cloud/logout',         '⚙️',  'active'),
  ('raldtics',            'Raldtics',                'analytics.rald.cloud',    'https://analytics.rald.cloud/auth/callback',   'https://analytics.rald.cloud/logout',   '📊', 'active'),
  ('raldtics-app',        'Raldtics App',            'analytics.rald.cloud',    'https://analytics.rald.cloud/auth/callback',   'https://analytics.rald.cloud/logout',   '📊', 'active')
ON CONFLICT (app_id) DO NOTHING;
