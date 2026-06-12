-- RALD Identity Intelligence Layer
-- Sprint: Identity Intelligence · 2026-06-12
-- Source of truth for what RALD knows about each user across all products.
-- identity_capabilities  → what RALD has on the user (prevents re-asking)
-- identity_memory        → per-product history, dismissed prompts, onboarding state
-- LILCKY STUDIO LIMITED

-- ── identity_capabilities ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_capabilities (
  user_id            UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,

  -- Username / handle
  username           TEXT,
  username_verified  BOOLEAN NOT NULL DEFAULT false,

  -- Email
  email              TEXT,
  email_verified     BOOLEAN NOT NULL DEFAULT false,

  -- Phone
  phone              TEXT,
  phone_verified     BOOLEAN NOT NULL DEFAULT false,

  -- Profile
  profile_photo      TEXT,
  country            TEXT,
  state              TEXT,
  city               TEXT,
  language           TEXT,
  timezone           TEXT,

  -- Trust & verification tiers
  trust_level        TEXT NOT NULL DEFAULT 'none',
  creator_verified   BOOLEAN NOT NULL DEFAULT false,
  business_verified  BOOLEAN NOT NULL DEFAULT false,
  civic_verified     BOOLEAN NOT NULL DEFAULT false,

  -- Reserved RALD mail (username@rald.me)
  mail_reserved      TEXT,

  -- Onboarding
  completed_onboarding BOOLEAN NOT NULL DEFAULT false,

  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS: users can read their own row; service role has full access
ALTER TABLE identity_capabilities ENABLE ROW LEVEL SECURITY;
CREATE POLICY "identity_capabilities: own read"
  ON identity_capabilities FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY "identity_capabilities: service write"
  ON identity_capabilities FOR ALL
  USING (true) WITH CHECK (true);

-- ── identity_memory ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_memory (
  user_id               UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,

  last_onboarding_step  TEXT,
  dismissed_prompts     JSONB NOT NULL DEFAULT '[]',
  verification_history  JSONB NOT NULL DEFAULT '[]',
  product_history       JSONB NOT NULL DEFAULT '[]',
  preferences           JSONB NOT NULL DEFAULT '{}',

  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE identity_memory ENABLE ROW LEVEL SECURITY;
CREATE POLICY "identity_memory: own read"
  ON identity_memory FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY "identity_memory: service write"
  ON identity_memory FOR ALL
  USING (true) WITH CHECK (true);

-- ── Back-fill from existing auth_users + auth_user_profiles ─────────────────
INSERT INTO identity_capabilities (
  user_id,
  username, username_verified,
  email, email_verified,
  phone, phone_verified,
  country, trust_level,
  mail_reserved,
  completed_onboarding
)
SELECT
  u.id,
  u.username,
  COALESCE(u.username_verified, u.username IS NOT NULL),
  u.email,
  COALESCE(u.email_verified, false),
  u.phone_number,
  COALESCE(u.phone_verified, false),
  p.country,
  COALESCE(u.trust_level, 'none'),
  CASE WHEN u.username IS NOT NULL
       THEN u.username || '@rald.me'
       ELSE NULL END,
  COALESCE(p.onboarding_complete, false)
FROM auth_users u
LEFT JOIN auth_user_profiles p ON p.user_id = u.id
ON CONFLICT (user_id) DO UPDATE SET
  username           = EXCLUDED.username,
  username_verified  = EXCLUDED.username_verified,
  email              = EXCLUDED.email,
  email_verified     = EXCLUDED.email_verified,
  phone              = EXCLUDED.phone,
  phone_verified     = EXCLUDED.phone_verified,
  country            = EXCLUDED.country,
  trust_level        = EXCLUDED.trust_level,
  mail_reserved      = EXCLUDED.mail_reserved,
  completed_onboarding = EXCLUDED.completed_onboarding,
  updated_at         = now();

-- ── updated_at trigger ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_identity_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_identity_capabilities_updated_at ON identity_capabilities;
CREATE TRIGGER trg_identity_capabilities_updated_at
  BEFORE UPDATE ON identity_capabilities
  FOR EACH ROW EXECUTE FUNCTION update_identity_updated_at();

DROP TRIGGER IF EXISTS trg_identity_memory_updated_at ON identity_memory;
CREATE TRIGGER trg_identity_memory_updated_at
  BEFORE UPDATE ON identity_memory
  FOR EACH ROW EXECUTE FUNCTION update_identity_updated_at();
