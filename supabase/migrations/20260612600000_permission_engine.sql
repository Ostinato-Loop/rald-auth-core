-- RALD Auth Core — Permission Engine + Regulatory Rules
-- Sprint: Operator Platform Phase 6 + Hardening Phase 10 · 2026-06-12
-- Centralized RBAC permission registry with product-scoped permissions.
-- Regulatory rules define what's required per country.
-- LILCKY STUDIO LIMITED

-- ═══════════════════════════════════════════════════════════════
-- PART A: PERMISSION ENGINE
-- ═══════════════════════════════════════════════════════════════

-- ── permission_definitions — the full permissions registry ────────────────────
CREATE TABLE IF NOT EXISTS permission_definitions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope        TEXT NOT NULL,           -- e.g. "loop", "messenger", "rald_auth"
  name         TEXT NOT NULL,           -- e.g. "room:create"
  description  TEXT NOT NULL DEFAULT '',
  tier_required TEXT NOT NULL DEFAULT 'basic'
                  CHECK (tier_required IN ('none','basic','standard','verified','creator','civic','premium')),
  country_restrictions TEXT[] NOT NULL DEFAULT '{}',  -- ISO codes where permission is restricted
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS permission_definitions_scope_name_idx
  ON permission_definitions(scope, name);

ALTER TABLE permission_definitions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "permission_definitions: public read"
  ON permission_definitions FOR SELECT USING (true);
CREATE POLICY "permission_definitions: service write"
  ON permission_definitions FOR ALL USING (true) WITH CHECK (true);

-- ── Seed: Core RALD Permissions ────────────────────────────────────────────────
INSERT INTO permission_definitions (scope, name, description, tier_required) VALUES
  -- Loop
  ('loop', 'room:join',              'Join public audio rooms', 'basic'),
  ('loop', 'room:create',            'Create audio rooms', 'standard'),
  ('loop', 'room:co_host',           'Co-host a room', 'standard'),
  ('loop', 'room:schedule',          'Schedule rooms', 'verified'),
  ('loop', 'room:civic_create',      'Create civic rooms', 'civic'),
  ('loop', 'community:create',       'Create communities', 'verified'),
  ('loop', 'community:moderate',     'Moderate a community', 'creator'),
  ('loop', 'creator:monetize',       'Enable creator monetization', 'creator'),
  ('loop', 'analytics:view',         'View room analytics', 'creator'),
  -- Messenger
  ('messenger', 'message:send',      'Send direct messages', 'basic'),
  ('messenger', 'call:voice',        'Make voice calls', 'standard'),
  ('messenger', 'call:video',        'Make video calls', 'verified'),
  ('messenger', 'group:create',      'Create group chats', 'standard'),
  -- RALD Identity
  ('rald_auth', 'profile:update',    'Update profile', 'basic'),
  ('rald_auth', 'verification:request','Request identity verification', 'basic'),
  ('rald_auth', 'developer:register','Register as developer', 'verified'),
  ('rald_auth', 'api_key:create',    'Create developer API keys', 'verified'),
  ('rald_auth', 'webhook:register',  'Register webhooks', 'verified'),
  -- PayRald (future)
  ('payrald', 'payment:send',        'Send payments', 'verified'),
  ('payrald', 'payment:receive',     'Receive payments', 'standard'),
  ('payrald', 'wallet:create',       'Create a wallet', 'verified')
ON CONFLICT (scope, name) DO NOTHING;

-- ── user_permission_overrides — per-user permission adjustments ───────────────
CREATE TABLE IF NOT EXISTS user_permission_overrides (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  scope         TEXT NOT NULL,
  permission    TEXT NOT NULL,
  granted       BOOLEAN NOT NULL DEFAULT true,   -- false = explicit deny
  reason        TEXT,
  granted_by    TEXT NOT NULL,  -- admin user_id
  expires_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS user_permission_overrides_user_scope_perm_idx
  ON user_permission_overrides(user_id, scope, permission);

ALTER TABLE user_permission_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY "user_permission_overrides: own read"
  ON user_permission_overrides FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "user_permission_overrides: service write"
  ON user_permission_overrides FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════
-- PART B: REGULATORY RULES ENGINE
-- ═══════════════════════════════════════════════════════════════

-- ── regulatory_profiles — per-country regulatory requirements ─────────────────
CREATE TABLE IF NOT EXISTS regulatory_profiles (
  country_code         TEXT PRIMARY KEY,  -- ISO 3166-1 alpha-2

  -- Identity requirements
  kyc_required         BOOLEAN NOT NULL DEFAULT false,
  phone_required       BOOLEAN NOT NULL DEFAULT false,
  bvn_required         BOOLEAN NOT NULL DEFAULT false,   -- Nigeria BVN
  national_id_required BOOLEAN NOT NULL DEFAULT false,

  -- Content rules
  content_moderation_level TEXT NOT NULL DEFAULT 'standard'
                             CHECK (content_moderation_level IN ('minimal','standard','strict')),
  restricted_content_types  TEXT[] NOT NULL DEFAULT '{}',  -- e.g. ["gambling","adult"]
  age_verification_required BOOLEAN NOT NULL DEFAULT false,

  -- Data rules
  data_residency_required  BOOLEAN NOT NULL DEFAULT false,
  data_residency_region    TEXT,   -- e.g. "africa-west", "eu"

  -- Financial rules
  payment_allowed          BOOLEAN NOT NULL DEFAULT true,
  payment_providers        TEXT[] NOT NULL DEFAULT '{}',   -- e.g. ["flutterwave","paystack"]
  p2p_transfer_allowed     BOOLEAN NOT NULL DEFAULT true,
  max_transaction_usd      NUMERIC(12,2),

  -- Notification rules
  sms_allowed             BOOLEAN NOT NULL DEFAULT true,
  sms_providers           TEXT[] NOT NULL DEFAULT '{}',   -- e.g. ["termii"]
  marketing_opt_in_required BOOLEAN NOT NULL DEFAULT true,  -- GDPR/NG-equivalent

  notes                   TEXT NOT NULL DEFAULT '',
  updated_by              TEXT,
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE regulatory_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "regulatory_profiles: service read"
  ON regulatory_profiles FOR SELECT USING (true);
CREATE POLICY "regulatory_profiles: service write"
  ON regulatory_profiles FOR ALL USING (true) WITH CHECK (true);

-- ── Seed: Africa-first regulatory profiles ────────────────────────────────────
INSERT INTO regulatory_profiles (country_code, phone_required, content_moderation_level, sms_providers, payment_providers, notes) VALUES
  ('NG', true,  'standard', ARRAY['termii'], ARRAY['paystack','flutterwave'], 'Nigeria — primary market. BVN for financial services. Termii for SMS. NDPR compliance.'),
  ('KE', true,  'standard', ARRAY['termii','africas_talking'], ARRAY['mpesa','flutterwave'], 'Kenya — M-Pesa primary. Africa''s Talking for SMS. DPA 2019 compliance.'),
  ('GH', true,  'standard', ARRAY['termii'], ARRAY['flutterwave','paystack'], 'Ghana — Data Protection Act 2012. Termii SMS.'),
  ('ZA', false, 'strict',   ARRAY['termii'], ARRAY['peach_payments','flutterwave'], 'South Africa — POPIA compliance. Strict content rules. Age verification required for certain features.'),
  ('GB', false, 'strict',   ARRAY['twilio'], ARRAY['stripe'], 'United Kingdom — UK GDPR. Age verification required. ICO compliance.'),
  ('US', false, 'standard', ARRAY['twilio'], ARRAY['stripe'], 'United States — CCPA/CAN-SPAM. State-level variations apply.')
ON CONFLICT (country_code) DO NOTHING;

COMMENT ON TABLE regulatory_profiles IS
  'Per-country regulatory requirements. Products must check these before enabling features for a country.';
