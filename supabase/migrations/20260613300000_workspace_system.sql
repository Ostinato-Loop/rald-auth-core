-- RALD Workspace System
-- Phase 4 of Final Hardening Plan
-- One account. Multiple workspaces. Identity Brain manages all workspace relationships.
-- Hierarchy: Personal | Creator | Business | Organization | Government
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: WORKSPACE TYPES
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workspace_definitions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type_key        TEXT NOT NULL UNIQUE,       -- 'personal', 'creator', 'business', etc.
  display_name    TEXT NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  max_members     INT,                        -- NULL = unlimited
  requires_verification BOOLEAN NOT NULL DEFAULT false,
  country_restrictions TEXT[] NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO workspace_definitions (type_key, display_name, description, max_members, requires_verification)
VALUES
  ('personal',     'Personal',     'Default workspace for every RALD user. Auto-created at signup.',     1,    false),
  ('creator',      'Creator',      'Content creator workspace with Loop and community tools.',          10,    false),
  ('business',     'Business',     'Business workspace with multi-member teams and admin tools.',      100,    true),
  ('organization', 'Organization', 'Non-profit or civic organization workspace.',                      500,    true),
  ('government',   'Government',   'Government or regulatory body workspace with strict compliance.', 1000,    true)
ON CONFLICT (type_key) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- PART B: WORKSPACES
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workspaces (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
  workspace_type   TEXT NOT NULL REFERENCES workspace_definitions(type_key),

  -- Identity
  name             TEXT NOT NULL,
  handle           TEXT UNIQUE,              -- @handle for the workspace (optional)
  description      TEXT NOT NULL DEFAULT '',
  avatar_url       TEXT,
  banner_url       TEXT,

  -- Workspace config
  country_code     VARCHAR(2),              -- primary country of operation
  industry         TEXT,                    -- for business/org
  website_url      TEXT,
  contact_email    TEXT,

  -- Verification
  verification_status TEXT NOT NULL DEFAULT 'unverified'
                        CHECK (verification_status IN ('unverified','pending','verified','rejected')),
  verified_at      TIMESTAMPTZ,
  verified_by      UUID REFERENCES auth_users(id) ON DELETE SET NULL,

  -- Lifecycle
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','suspended','archived','deleted')),
  suspended_reason TEXT,
  suspended_at     TIMESTAMPTZ,

  -- PayRald gate (separate approval for financial features)
  payrald_enabled  BOOLEAN NOT NULL DEFAULT false,
  payrald_approved_at TIMESTAMPTZ,

  -- Kill switch overrides
  kill_switch_flags TEXT[] NOT NULL DEFAULT '{}', -- active kill switches affecting this workspace

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS workspaces_owner_idx  ON workspaces(owner_id);
CREATE INDEX IF NOT EXISTS workspaces_type_idx   ON workspaces(workspace_type);
CREATE INDEX IF NOT EXISTS workspaces_handle_idx ON workspaces(handle) WHERE handle IS NOT NULL;
CREATE INDEX IF NOT EXISTS workspaces_country_idx ON workspaces(country_code) WHERE country_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS workspaces_status_idx ON workspaces(status);

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
CREATE POLICY "workspaces: owner full access" ON workspaces
  FOR ALL USING (owner_id = auth.uid());
CREATE POLICY "workspaces: public read active" ON workspaces
  FOR SELECT USING (status = 'active');
CREATE POLICY "workspaces: service write" ON workspaces
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE workspaces IS
  'RALD Workspace System — one user, multiple workspaces. Identity Brain manages relationships.';

-- ═══════════════════════════════════════════════════════════════
-- PART C: WORKSPACE MEMBERS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workspace_members (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  role            TEXT NOT NULL DEFAULT 'member'
                    CHECK (role IN ('owner','admin','moderator','member','viewer','guest')),
  invited_by      UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','suspended','removed')),
  UNIQUE (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS workspace_members_user_idx      ON workspace_members(user_id);
CREATE INDEX IF NOT EXISTS workspace_members_workspace_idx ON workspace_members(workspace_id);

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY "workspace_members: member read" ON workspace_members
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "workspace_members: service write" ON workspace_members
  FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════
-- PART D: PERSONAL WORKSPACE AUTO-CREATION TRIGGER
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION create_personal_workspace_on_signup()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _workspace_id UUID;
  _display_name TEXT;
BEGIN
  -- Use username as workspace name, fall back to user_id prefix
  _display_name := COALESCE(NEW.username, 'User ' || substring(NEW.id::text, 1, 8));

  INSERT INTO workspaces (
    owner_id,
    workspace_type,
    name,
    status
  ) VALUES (
    NEW.id,
    'personal',
    _display_name || '''s Space',
    'active'
  )
  RETURNING id INTO _workspace_id;

  -- Add as owner member
  INSERT INTO workspace_members (workspace_id, user_id, role)
  VALUES (_workspace_id, NEW.id, 'owner');

  RETURN NEW;
EXCEPTION
  WHEN OTHERS THEN
    -- Never fail signup over workspace creation
    RAISE WARNING 'workspace auto-create failed for user %: %', NEW.id, SQLERRM;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_create_personal_workspace ON auth_users;
CREATE TRIGGER trg_create_personal_workspace
  AFTER INSERT ON auth_users
  FOR EACH ROW
  EXECUTE FUNCTION create_personal_workspace_on_signup();

-- ═══════════════════════════════════════════════════════════════
-- PART E: WORKSPACE AUDIT LOG
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workspace_audit_log (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  action        TEXT NOT NULL,
  performed_by  UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  metadata      JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS workspace_audit_workspace_idx ON workspace_audit_log(workspace_id, created_at DESC);
