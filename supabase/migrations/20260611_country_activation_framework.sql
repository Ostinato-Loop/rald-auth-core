-- RALD Country Activation Framework
-- Region-first expansion system: countries activate only via explicit admin approval.
-- LILCKY STUDIO LIMITED

-- ── Country status enum ───────────────────────────────────────────────────────
CREATE TYPE country_status AS ENUM (
  'WAITLIST',
  'REGULATORY_REVIEW',
  'INFRASTRUCTURE_REVIEW',
  'MODERATION_REVIEW',
  'PREVIEW',
  'PRIVATE_BETA',
  'PUBLIC_BETA',
  'ACTIVE',
  'RESTRICTED'
);

-- ── Country Registry ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS country_registry (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country_code         VARCHAR(2)     NOT NULL UNIQUE,
  country_name         TEXT           NOT NULL,
  status               country_status NOT NULL DEFAULT 'WAITLIST',

  -- Regulatory scorecard (0–100)
  demand_score         SMALLINT       DEFAULT 0 CHECK (demand_score BETWEEN 0 AND 100),
  legal_score          SMALLINT       DEFAULT 0 CHECK (legal_score BETWEEN 0 AND 100),
  compliance_score     SMALLINT       DEFAULT 0 CHECK (compliance_score BETWEEN 0 AND 100),
  moderation_score     SMALLINT       DEFAULT 0 CHECK (moderation_score BETWEEN 0 AND 100),
  infrastructure_score SMALLINT       DEFAULT 0 CHECK (infrastructure_score BETWEEN 0 AND 100),
  support_score        SMALLINT       DEFAULT 0 CHECK (support_score BETWEEN 0 AND 100),

  -- Approval audit
  approved_by          UUID           REFERENCES auth_users(id) ON DELETE SET NULL,
  approved_at          TIMESTAMPTZ,
  activated_at         TIMESTAMPTZ,
  launch_date          DATE,

  -- Notes
  legal_notes          TEXT,
  compliance_notes     TEXT,
  moderation_notes     TEXT,
  infrastructure_notes TEXT,

  -- PayRald gate (separate from Loop activation)
  payrald_status       country_status DEFAULT 'WAITLIST',
  payrald_approved_at  TIMESTAMPTZ,

  created_at           TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ── Country Waitlist ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS country_waitlist (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country_code VARCHAR(2)  NOT NULL,
  state        TEXT,
  city         TEXT,
  email        TEXT,
  username     TEXT,
  ip_hash      TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_country_waitlist_country ON country_waitlist(country_code);
CREATE INDEX IF NOT EXISTS idx_country_registry_status  ON country_registry(status);

-- ── Country Activation Log ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS country_activation_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country_code VARCHAR(2)     NOT NULL,
  from_status  country_status,
  to_status    country_status NOT NULL,
  changed_by   UUID           REFERENCES auth_users(id) ON DELETE SET NULL,
  reason       TEXT,
  created_at   TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ── Updated_at trigger ────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_country_registry_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;
CREATE TRIGGER trg_country_registry_updated_at
  BEFORE UPDATE ON country_registry
  FOR EACH ROW EXECUTE FUNCTION set_country_registry_updated_at();

-- ── RLS ───────────────────────────────────────────────────────────────────────
ALTER TABLE country_registry       ENABLE ROW LEVEL SECURITY;
ALTER TABLE country_waitlist       ENABLE ROW LEVEL SECURITY;
ALTER TABLE country_activation_log ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS entirely (auth worker uses service role key)
-- Public reads: only activated/beta countries visible to anon
CREATE POLICY "public_read_country_registry" ON country_registry
  FOR SELECT USING (true);

CREATE POLICY "service_role_all_country_registry" ON country_registry
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_all_country_waitlist" ON country_waitlist
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_all_country_activation_log" ON country_activation_log
  FOR ALL USING (auth.role() = 'service_role');

-- ── Initial seed data ─────────────────────────────────────────────────────────

-- Wave 1: Nigeria — ACTIVE
INSERT INTO country_registry (country_code, country_name, status,
  demand_score, legal_score, compliance_score, moderation_score, infrastructure_score, support_score,
  activated_at, launch_date,
  legal_notes, compliance_notes)
VALUES (
  'NG', 'Nigeria', 'ACTIVE',
  100, 90, 85, 90, 95, 90,
  NOW(), '2026-06-11',
  'NITDA guidelines reviewed. NCC compliance confirmed. NDPA data protection in place.',
  'FCCPC compliance confirmed. Identity requirements met. KYC framework active.'
)
ON CONFLICT (country_code) DO NOTHING;

-- Wave 2: Kenya, Tanzania, Ghana — WAITLIST
INSERT INTO country_registry (country_code, country_name, status, demand_score)
VALUES
  ('KE', 'Kenya',    'WAITLIST', 72),
  ('TZ', 'Tanzania', 'WAITLIST', 58),
  ('GH', 'Ghana',    'WAITLIST', 68)
ON CONFLICT (country_code) DO NOTHING;

-- Wave 3: South Africa, India, Indonesia — WAITLIST
INSERT INTO country_registry (country_code, country_name, status, demand_score)
VALUES
  ('ZA', 'South Africa', 'WAITLIST', 65),
  ('IN', 'India',        'WAITLIST', 80),
  ('ID', 'Indonesia',    'WAITLIST', 74)
ON CONFLICT (country_code) DO NOTHING;
