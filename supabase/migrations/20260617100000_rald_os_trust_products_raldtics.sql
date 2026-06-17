-- RALD OS: Phases 3, 4, 6
-- 20260617100000_rald_os_trust_products_raldtics.sql
-- Phase 3: rald_trust_profiles — single trust source for every product
-- Phase 4: rald_products — product registry
-- Phase 6: raldtics_* — RALDTICS observability
-- LILCKY STUDIO LIMITED · 2026-06-17

-- ── PHASE 3: TRUST ENGINE ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rald_trust_profiles (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rald_id           TEXT UNIQUE REFERENCES rald_users(id) ON DELETE CASCADE,
  user_id           UUID UNIQUE,                -- auth_users.id
  kyc_tier          INTEGER DEFAULT 0,          -- 0=none 1=basic 2=verified 3=enhanced
  trust_score       INTEGER DEFAULT 0,          -- 0–1000
  fraud_score       INTEGER DEFAULT 0,          -- 0–1000 (higher = riskier)
  reputation_score  INTEGER DEFAULT 500,        -- 0–1000
  merchant_score    INTEGER DEFAULT 0,          -- 0–1000
  school_score      INTEGER DEFAULT 0,          -- 0–1000 (Elimu)
  -- Verification flags
  phone_verified    BOOLEAN DEFAULT FALSE,
  email_verified    BOOLEAN DEFAULT FALSE,
  bvn_verified      BOOLEAN DEFAULT FALSE,
  nin_verified      BOOLEAN DEFAULT FALSE,
  address_verified  BOOLEAN DEFAULT FALSE,
  -- Sanction / risk flags
  sanctions_flagged BOOLEAN DEFAULT FALSE,
  fraud_flagged     BOOLEAN DEFAULT FALSE,
  manually_reviewed BOOLEAN DEFAULT FALSE,
  review_note       TEXT,
  -- Merchant / creator
  is_merchant       BOOLEAN DEFAULT FALSE,
  is_creator        BOOLEAN DEFAULT FALSE,
  is_school         BOOLEAN DEFAULT FALSE,
  -- Composite tier (computed)
  trust_tier        TEXT DEFAULT 'none'
    CHECK (trust_tier IN ('none','basic','verified','enhanced','elite')),
  -- Timestamps
  last_computed_at  TIMESTAMPTZ DEFAULT NOW(),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_rald_id    ON rald_trust_profiles(rald_id);
CREATE INDEX IF NOT EXISTS idx_trust_user_id    ON rald_trust_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_tier       ON rald_trust_profiles(trust_tier);
CREATE INDEX IF NOT EXISTS idx_trust_score      ON rald_trust_profiles(trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_trust_fraud      ON rald_trust_profiles(fraud_flagged) WHERE fraud_flagged = TRUE;
CREATE INDEX IF NOT EXISTS idx_trust_sanctions  ON rald_trust_profiles(sanctions_flagged) WHERE sanctions_flagged = TRUE;

CREATE OR REPLACE FUNCTION update_trust_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;
DROP TRIGGER IF EXISTS trg_trust_updated_at ON rald_trust_profiles;
CREATE TRIGGER trg_trust_updated_at
  BEFORE UPDATE ON rald_trust_profiles
  FOR EACH ROW EXECUTE FUNCTION update_trust_updated_at();

-- Compute trust_tier from trust_score
CREATE OR REPLACE FUNCTION compute_trust_tier(score INTEGER) RETURNS TEXT AS $$
BEGIN
  IF score >= 800 THEN RETURN 'elite';
  ELSIF score >= 600 THEN RETURN 'enhanced';
  ELSIF score >= 400 THEN RETURN 'verified';
  ELSIF score >= 200 THEN RETURN 'basic';
  ELSE RETURN 'none';
  END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Auto-compute tier on score change
CREATE OR REPLACE FUNCTION sync_trust_tier()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.trust_tier := compute_trust_tier(NEW.trust_score);
  NEW.last_computed_at := NOW();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_sync_trust_tier ON rald_trust_profiles;
CREATE TRIGGER trg_sync_trust_tier
  BEFORE INSERT OR UPDATE OF trust_score ON rald_trust_profiles
  FOR EACH ROW EXECUTE FUNCTION sync_trust_tier();

ALTER TABLE rald_trust_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY trust_service_all ON rald_trust_profiles FOR ALL USING (auth.role() = 'service_role');

-- ── PHASE 4: PRODUCT REGISTRY ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rald_products (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          TEXT UNIQUE NOT NULL,            -- 'payrald', 'messenger', 'mail', 'elimu', 'alia'
  name          TEXT NOT NULL,
  description   TEXT,
  owner         TEXT NOT NULL DEFAULT 'LILCKY STUDIO LIMITED',
  status        TEXT DEFAULT 'active'
    CHECK (status IN ('active','beta','disabled','deprecated')),
  base_url      TEXT,                            -- https://pay.rald.cloud
  api_endpoint  TEXT,                            -- https://api.rald.cloud/pay
  health_url    TEXT,                            -- https://pay.rald.cloud/health
  icon_url      TEXT,
  billing_model TEXT DEFAULT 'free'
    CHECK (billing_model IN ('free','subscription','usage','revenue_share')),
  permissions   TEXT[] DEFAULT '{}',             -- ['wallet:read','wallet:write']
  metadata      JSONB DEFAULT '{}',
  auto_provision BOOLEAN DEFAULT TRUE,           -- provision for every new user?
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_slug   ON rald_products(slug);
CREATE INDEX IF NOT EXISTS idx_products_status ON rald_products(status);

ALTER TABLE rald_products ENABLE ROW LEVEL SECURITY;
CREATE POLICY products_service_all  ON rald_products FOR ALL USING (auth.role() = 'service_role');
-- Products list is public (anon can read active products)
CREATE POLICY products_anon_read    ON rald_products FOR SELECT USING (status = 'active');

-- Seed the 8 canonical RALD products
INSERT INTO rald_products (slug, name, description, status, base_url, api_endpoint, health_url, billing_model, auto_provision, permissions)
VALUES
  ('auth',      'RALD Auth',       'Universal identity & authentication',             'active', 'https://auth.rald.cloud',      'https://api.rald.cloud/identity', 'https://auth.rald.cloud/health',      'free',           TRUE,  ARRAY['identity:read','session:write']),
  ('payrald',   'PayRald',         'Payments, wallets, vouchers & transfers',         'active', 'https://pay.rald.cloud',       'https://api.rald.cloud/wallet',   'https://pay.rald.cloud/health',       'revenue_share',  TRUE,  ARRAY['wallet:read','wallet:write','transfer:write']),
  ('messenger', 'RALD Messenger',  'Encrypted messaging with payment bubbles',        'active', 'https://messenger.rald.cloud', 'https://api.rald.cloud/messenger','https://messenger.rald.cloud/health', 'free',           TRUE,  ARRAY['message:read','message:write']),
  ('mail',      'RALD Mail',       'boyd@rald.cloud — sovereign email for Africa',    'beta',   'https://mail.rald.cloud',      'https://api.rald.cloud/mail',     'https://mail.rald.cloud/health',      'free',           TRUE,  ARRAY['mail:read','mail:write']),
  ('alia',      'ALIA Network',    'Alias resolution & cross-bank payment routing',   'beta',   'https://alia.rald.cloud',      'https://api.rald.cloud/alias',    'https://alia.rald.cloud/health',      'revenue_share',  TRUE,  ARRAY['alias:read','alias:write']),
  ('elimu',     'Elimu',           'School fees & education wallet management',       'beta',   'https://elimu.rald.cloud',     'https://api.rald.cloud/elimu',    'https://elimu.rald.cloud/health',     'revenue_share',  FALSE, ARRAY['wallet:read','school:write']),
  ('loop',      'Loop',            'Live audio rooms, communities & creator economy', 'active', 'https://loop.rald.cloud',      'https://api.rald.cloud/loop',     'https://loop.rald.cloud/health',      'free',           TRUE,  ARRAY['identity:read','room:write']),
  ('control',   'Control Center',  'Operator command plane for the RALD ecosystem',   'active', 'https://admin.rald.cloud',     'https://api.rald.cloud/control',  'https://admin.rald.cloud/health',     'free',           FALSE, ARRAY['admin:read','admin:write'])
ON CONFLICT (slug) DO NOTHING;

-- ── PHASE 6: RALDTICS OBSERVABILITY ───────────────────────────────────────────
-- Raw events for time-series analytics
CREATE TABLE IF NOT EXISTS raldtics_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type  TEXT NOT NULL,       -- 'signup','wallet_created','payment','message','login'
  product     TEXT NOT NULL,       -- which product emitted this
  user_id     UUID,
  rald_id     TEXT,
  metadata    JSONB DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raldtics_event_type  ON raldtics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_raldtics_product     ON raldtics_events(product);
CREATE INDEX IF NOT EXISTS idx_raldtics_created_at  ON raldtics_events(created_at DESC);

ALTER TABLE raldtics_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY raldtics_service_all ON raldtics_events FOR ALL USING (auth.role() = 'service_role');

-- Hourly/daily snapshot table (materialized by scheduled job)
CREATE TABLE IF NOT EXISTS raldtics_snapshots (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  period            TEXT NOT NULL CHECK (period IN ('1h','24h','7d','30d')),
  total_users       INTEGER DEFAULT 0,
  signups           INTEGER DEFAULT 0,
  active_users      INTEGER DEFAULT 0,
  wallets           INTEGER DEFAULT 0,
  active_wallets    INTEGER DEFAULT 0,
  total_volume_ngn  BIGINT DEFAULT 0,
  aliases           INTEGER DEFAULT 0,
  schools           INTEGER DEFAULT 0,
  merchants         INTEGER DEFAULT 0,
  messages          INTEGER DEFAULT 0,
  payments          INTEGER DEFAULT 0,
  events_published  INTEGER DEFAULT 0,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_snapshots_period     ON raldtics_snapshots(period, snapshot_at DESC);

ALTER TABLE raldtics_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY snapshots_service_all ON raldtics_snapshots FOR ALL USING (auth.role() = 'service_role');

-- Executive dashboard view
CREATE OR REPLACE VIEW raldtics_executive_dashboard AS
WITH latest AS (
  SELECT DISTINCT ON (period) *
  FROM raldtics_snapshots
  ORDER BY period, snapshot_at DESC
)
SELECT
  (SELECT COUNT(*) FROM rald_users)                              AS total_identities,
  (SELECT COUNT(*) FROM rald_users WHERE provision_status='complete') AS fully_provisioned,
  (SELECT COUNT(*) FROM payrald_wallets WHERE status='active')   AS active_wallets,
  (SELECT COUNT(*) FROM alia_handles WHERE status='active')      AS active_aliases,
  (SELECT COUNT(*) FROM mail_accounts WHERE status='active')     AS active_mailboxes,
  (SELECT COUNT(*) FROM messenger_accounts WHERE status='active') AS active_messenger,
  (SELECT COUNT(*) FROM rald_trust_profiles WHERE trust_tier != 'none') AS verified_users,
  (SELECT COUNT(*) FROM rald_trust_profiles WHERE is_merchant = TRUE) AS merchants,
  (SELECT COUNT(*) FROM rald_trust_profiles WHERE is_school = TRUE)   AS schools,
  (SELECT COUNT(*) FROM rald_users WHERE created_at > NOW() - INTERVAL '24 hours') AS signups_24h,
  (SELECT COUNT(*) FROM rald_users WHERE created_at > NOW() - INTERVAL '7 days')  AS signups_7d,
  (SELECT COUNT(*) FROM rald_users WHERE created_at > NOW() - INTERVAL '30 days') AS signups_30d,
  (SELECT COUNT(*) FROM provision_retry_queue WHERE status IN ('pending','retrying')) AS retry_queue_depth,
  (SELECT COUNT(*) FROM provision_retry_queue WHERE status = 'exhausted') AS stuck_provisions,
  NOW() AS generated_at;

COMMENT ON TABLE rald_trust_profiles IS 'RALD OS Phase 3: Single trust source for every product';
COMMENT ON TABLE rald_products       IS 'RALD OS Phase 4: Product registry — every RALD service registers here';
COMMENT ON TABLE raldtics_events     IS 'RALD OS Phase 6: Raw telemetry events for RALDTICS observability';
COMMENT ON TABLE raldtics_snapshots  IS 'RALD OS Phase 6: Hourly/daily snapshots for executive dashboard';
