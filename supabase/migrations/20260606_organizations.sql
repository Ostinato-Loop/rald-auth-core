-- RALD Organizations Schema
-- Enables: organization memberships in Profiles dashboard (rald-auth-ui)
-- Types: general, radio, media, business, community, education
-- Phase: RALD Foundation Hardening — Organizations Feature
-- Owner: LILCKY STUDIO LIMITED
-- Date: 2026-06-06

-- ── Organizations ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rald_organizations (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  handle      TEXT NOT NULL UNIQUE CHECK (handle ~ '^[a-z0-9\-_]{3,40}$'),
  type        TEXT NOT NULL DEFAULT 'general'
              CHECK (type IN ('general', 'radio', 'media', 'business', 'community', 'education')),
  description TEXT CHECK (char_length(description) <= 300),
  avatar_url  TEXT CHECK (char_length(avatar_url) <= 500),
  created_by  UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rald_organizations_handle ON rald_organizations(handle);
CREATE INDEX IF NOT EXISTS idx_rald_organizations_type   ON rald_organizations(type);
CREATE INDEX IF NOT EXISTS idx_rald_organizations_creator ON rald_organizations(created_by);

COMMENT ON TABLE rald_organizations IS
  'RALD organization entities (radio stations, businesses, communities, media houses)';

-- ── Organization Members ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rald_org_members (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id    UUID NOT NULL REFERENCES rald_organizations(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  role      TEXT NOT NULL DEFAULT 'member'
            CHECK (role IN ('owner', 'admin', 'member')),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_rald_org_members_org  ON rald_org_members(org_id);
CREATE INDEX IF NOT EXISTS idx_rald_org_members_user ON rald_org_members(user_id);

COMMENT ON TABLE rald_org_members IS
  'Membership records — links auth_users to rald_organizations with role (owner, admin, member)';

-- ── Row-level security ────────────────────────────────────────────────────────
ALTER TABLE rald_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE rald_org_members   ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS — the Cloudflare Worker uses service role key
