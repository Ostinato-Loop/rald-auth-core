-- RALD Auth V2 — Username-First Identity System
-- Layer 1: rald_internal_id (permanent, never changes, users never see)
-- Layer 2: username (@boyd, @amara — primary login + public identity)
-- Layer 3: recovery methods (phone, email — optional, not identity)
--
-- Migration safety: IF NOT EXISTS throughout — safe to run on existing DB.
-- Supabase URL: https://onxdcikfttdmnhofsuwo.supabase.co
-- LILCKY STUDIO LIMITED — 2026-06-10

-- ── Add V2 identity columns to auth_users ─────────────────────────────────────
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS username         TEXT UNIQUE;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS username_set_at  TIMESTAMPTZ;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS rald_internal_id TEXT UNIQUE;

-- Backfill rald_internal_id for existing users who already have rald_id
UPDATE auth_users
SET rald_internal_id = rald_id
WHERE rald_id IS NOT NULL AND rald_internal_id IS NULL;

-- Username must be lowercase 2–20 chars: letters, numbers, underscores only
ALTER TABLE auth_users DROP CONSTRAINT IF EXISTS auth_users_username_format;
ALTER TABLE auth_users ADD CONSTRAINT auth_users_username_format
  CHECK (username IS NULL OR (
    length(username) BETWEEN 2 AND 20
    AND username ~ '^[a-z0-9_]+$'
    AND username NOT LIKE '\_%'
    AND username NOT LIKE '%\_'
  ));

CREATE INDEX IF NOT EXISTS idx_auth_users_username ON auth_users(username) WHERE username IS NOT NULL;

-- ── usernames — canonical username registry ───────────────────────────────────
-- Every claimed username has one row. This is the source of truth for availability.
CREATE TABLE IF NOT EXISTS usernames (
  username        TEXT          PRIMARY KEY,
  user_id         UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  claimed_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
  active          BOOLEAN       NOT NULL DEFAULT true,
  CONSTRAINT usernames_format CHECK (
    length(username) BETWEEN 2 AND 20
    AND username ~ '^[a-z0-9_]+$'
  )
);

CREATE INDEX IF NOT EXISTS idx_usernames_user_id ON usernames(user_id);
CREATE INDEX IF NOT EXISTS idx_usernames_active   ON usernames(active);

-- ── reserved_usernames — namespace reservation ────────────────────────────────
-- Claimed usernames auto-reserve mail + workspace namespace even before launch.
CREATE TABLE IF NOT EXISTS reserved_usernames (
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  username          TEXT          NOT NULL,
  user_id           UUID          REFERENCES auth_users(id) ON DELETE SET NULL,
  reservation_type  TEXT          NOT NULL CHECK (reservation_type IN ('mail', 'workspace', 'domain', 'system')),
  reserved_value    TEXT          NOT NULL,   -- e.g. "boyd@rald.me" or "boyd.rald.me"
  reserved_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
  UNIQUE (username, reservation_type)
);

CREATE INDEX IF NOT EXISTS idx_reserved_usernames_user_id  ON reserved_usernames(user_id);
CREATE INDEX IF NOT EXISTS idx_reserved_usernames_username  ON reserved_usernames(username);

-- ── username_history — audit trail of username changes ────────────────────────
CREATE TABLE IF NOT EXISTS username_history (
  id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  username    TEXT          NOT NULL,
  action      TEXT          NOT NULL CHECK (action IN ('claimed', 'released', 'admin_change')),
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_username_history_user_id  ON username_history(user_id);
CREATE INDEX IF NOT EXISTS idx_username_history_username ON username_history(username);

-- ── workspaces ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workspaces (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  name          TEXT          NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  slug          TEXT          NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 40 AND slug ~ '^[a-z0-9-]+$'),
  workspace_type TEXT         NOT NULL DEFAULT 'personal' CHECK (workspace_type IN ('personal', 'business', 'organization')),
  avatar_url    TEXT,
  description   TEXT          CHECK (length(description) <= 300),
  is_active     BOOLEAN       NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_workspaces_owner_id ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_slug      ON workspaces(slug);

-- ── workspace_members ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workspace_members (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  UUID          NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id       UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  role          TEXT          NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  joined_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace ON workspace_members(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user      ON workspace_members(user_id);

-- ── recovery_codes ────────────────────────────────────────────────────────────
-- One-time recovery codes for account access without phone/email
CREATE TABLE IF NOT EXISTS recovery_codes (
  id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  code_hash   TEXT          NOT NULL,        -- SHA-256 of the plaintext code
  used        BOOLEAN       NOT NULL DEFAULT false,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id) WHERE used = false;

-- ── Stored function: reserve_username_namespace ───────────────────────────────
-- Called after username is claimed. Auto-reserves mail + workspace namespace.
CREATE OR REPLACE FUNCTION reserve_username_namespace(p_user_id UUID, p_username TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  -- Reserve username@rald.me (mail)
  INSERT INTO reserved_usernames (username, user_id, reservation_type, reserved_value)
  VALUES (p_username, p_user_id, 'mail', p_username || '@rald.me')
  ON CONFLICT (username, reservation_type) DO NOTHING;

  -- Reserve username.rald.me (domain/workspace)
  INSERT INTO reserved_usernames (username, user_id, reservation_type, reserved_value)
  VALUES (p_username, p_user_id, 'domain', p_username || '.rald.me')
  ON CONFLICT (username, reservation_type) DO NOTHING;

  -- Reserve workspace namespace
  INSERT INTO reserved_usernames (username, user_id, reservation_type, reserved_value)
  VALUES (p_username, p_user_id, 'workspace', p_username)
  ON CONFLICT (username, reservation_type) DO NOTHING;
END;
$$;

COMMENT ON FUNCTION reserve_username_namespace IS
  'Auto-reserves mail alias, domain, and workspace namespace on username claim';

-- ── Stored function: check_username_available ─────────────────────────────────
CREATE OR REPLACE FUNCTION check_username_available(p_username TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM usernames
  WHERE username = lower(p_username) AND active = true;
  RETURN v_count = 0;
END;
$$;

-- ── Row-level security ────────────────────────────────────────────────────────
ALTER TABLE usernames          ENABLE ROW LEVEL SECURITY;
ALTER TABLE reserved_usernames ENABLE ROW LEVEL SECURITY;
ALTER TABLE username_history   ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces         ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_members  ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes     ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS — Worker uses service role key
-- Client-side RLS policies to be added when direct Supabase client access is needed
