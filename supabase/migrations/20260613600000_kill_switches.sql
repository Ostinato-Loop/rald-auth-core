-- RALD Emergency Kill Switches
-- Phase 10 of Final Hardening Plan
-- Admin Control Center: disable products, countries, registration, payments,
-- APIs, room creation — without deployment.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: KILL SWITCH REGISTRY
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS kill_switches (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  switch_key      TEXT NOT NULL UNIQUE,       -- e.g. "disable_registration", "disable_loop_rooms"
  category        TEXT NOT NULL CHECK (category IN (
                    'product',
                    'country',
                    'registration',
                    'payments',
                    'api',
                    'feature',
                    'emergency'
                  )),
  display_name    TEXT NOT NULL,
  description     TEXT NOT NULL DEFAULT '',

  -- State
  is_active       BOOLEAN NOT NULL DEFAULT false,  -- true = kill switch ON (feature DISABLED)
  is_permanent    BOOLEAN NOT NULL DEFAULT false,  -- true = cannot be toggled via API; requires DB change
  requires_2fa    BOOLEAN NOT NULL DEFAULT true,   -- require 2FA before toggling

  -- Scope
  scope_type      TEXT NOT NULL DEFAULT 'global'
                    CHECK (scope_type IN ('global','country','product','user_tier')),
  scope_value     TEXT,                           -- country code, product name, etc.

  -- Audit
  last_toggled_by UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  last_toggled_at TIMESTAMPTZ,
  toggle_reason   TEXT,

  -- Alert config
  notify_on_activate BOOLEAN NOT NULL DEFAULT true,
  alert_channel   TEXT NOT NULL DEFAULT 'admin_email',

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed all kill switches from the spec
INSERT INTO kill_switches (switch_key, category, display_name, description, scope_type) VALUES
  -- Product kill switches
  ('disable_loop',                'product',      'Disable Loop',             'Disable entire Loop audio room product', 'global'),
  ('disable_messenger',           'product',      'Disable Messenger',         'Disable entire Messenger product', 'global'),
  ('disable_payrald',             'product',      'Disable PayRald',           'Disable all PayRald payment features', 'global'),
  ('disable_developer_portal',    'product',      'Disable Developer Portal',  'Disable API key issuance and developer access', 'global'),

  -- Feature kill switches
  ('disable_room_creation',       'feature',      'Disable Room Creation',     'Prevent all new audio rooms from being created', 'global'),
  ('disable_community_creation',  'feature',      'Disable Community Creation','Prevent new communities from being created', 'global'),
  ('disable_username_claiming',   'feature',      'Disable Username Claiming', 'Prevent all new username claims', 'global'),
  ('disable_verification_apps',   'feature',      'Disable Verification Apps', 'Pause all verification badge applications', 'global'),
  ('disable_ai_features',         'feature',      'Disable AI Features',       'Kill all AI/ML-powered features (WIZMAC, etc)', 'global'),

  -- Registration kill switches
  ('disable_registration',        'registration', 'Disable Registration',      'Prevent all new account creation globally', 'global'),
  ('disable_phone_registration',  'registration', 'Disable Phone Signup',      'Disable phone number registration method', 'global'),
  ('disable_email_registration',  'registration', 'Disable Email Signup',      'Disable email registration method', 'global'),

  -- Payment kill switches
  ('disable_payments',            'payments',     'Disable Payments',          'Disable all payment processing globally', 'global'),
  ('disable_paystack',            'payments',     'Disable Paystack',          'Disable Paystack payment gateway', 'global'),
  ('disable_wallet_topup',        'payments',     'Disable Wallet Top-up',     'Disable wallet funding', 'global'),

  -- API kill switches
  ('disable_public_api',          'api',          'Disable Public API',        'Take down all public API endpoints (503)', 'global'),
  ('disable_machine_auth',        'api',          'Disable Machine Auth',      'Disable service-to-service machine identity auth', 'global'),
  ('disable_sso',                 'api',          'Disable SSO',               'Disable all Single Sign-On endpoints', 'global'),

  -- Country-specific kill switches (scope_type = country; scope_value = ISO code)
  ('disable_country_NG',          'country',      'Disable Nigeria',           'Restrict all RALD access from Nigeria', 'country'),
  ('disable_country_KE',          'country',      'Disable Kenya',             'Restrict all RALD access from Kenya', 'country'),
  ('disable_country_GH',          'country',      'Disable Ghana',             'Restrict all RALD access from Ghana', 'country'),

  -- Emergency overrides
  ('emergency_read_only',         'emergency',    'Emergency Read-Only Mode',  'Make entire platform read-only — no writes anywhere', 'global'),
  ('emergency_maintenance',       'emergency',    'Emergency Maintenance Mode', 'Show maintenance page to all users', 'global'),
  ('emergency_disable_all',       'emergency',    'EMERGENCY — Disable All',   'Nuclear option — disable every API endpoint', 'global')
ON CONFLICT (switch_key) DO NOTHING;

ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY;
CREATE POLICY "kill_switches: public read" ON kill_switches
  FOR SELECT USING (true);
CREATE POLICY "kill_switches: service write" ON kill_switches
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE kill_switches IS
  'Emergency kill switches — toggle without deployment. Products check these on every request.';

-- ═══════════════════════════════════════════════════════════════
-- PART B: KILL SWITCH AUDIT LOG (immutable)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS kill_switch_audit_log (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  switch_id     UUID NOT NULL REFERENCES kill_switches(id) ON DELETE RESTRICT,
  switch_key    TEXT NOT NULL,
  action        TEXT NOT NULL CHECK (action IN ('activated','deactivated','updated')),
  previous_state BOOLEAN NOT NULL,
  new_state     BOOLEAN NOT NULL,
  performed_by  UUID NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
  reason        TEXT NOT NULL,
  ip_address    INET,
  metadata      JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS kill_switch_audit_switch_idx   ON kill_switch_audit_log(switch_id, created_at DESC);
CREATE INDEX IF NOT EXISTS kill_switch_audit_performer_idx ON kill_switch_audit_log(performed_by);
CREATE INDEX IF NOT EXISTS kill_switch_audit_created_idx  ON kill_switch_audit_log(created_at DESC);

-- Append-only
ALTER TABLE kill_switch_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "kill_switch_audit: insert only" ON kill_switch_audit_log
  FOR INSERT WITH CHECK (true);
CREATE POLICY "kill_switch_audit: service read" ON kill_switch_audit_log
  FOR SELECT USING (true);

-- ═══════════════════════════════════════════════════════════════
-- PART C: ACTIVE KILL SWITCHES VIEW (used by all workers)
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW active_kill_switches AS
SELECT
  switch_key,
  category,
  display_name,
  scope_type,
  scope_value,
  last_toggled_at,
  last_toggled_by,
  toggle_reason
FROM kill_switches
WHERE is_active = true
ORDER BY category, switch_key;

COMMENT ON VIEW active_kill_switches IS
  'All currently active kill switches. Workers should cache this view (TTL 30s) on startup.';

-- ═══════════════════════════════════════════════════════════════
-- PART D: RPC — CHECK KILL SWITCH (for workers to call)
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION check_kill_switch(p_switch_key TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(
    (SELECT is_active FROM kill_switches WHERE switch_key = p_switch_key),
    false  -- if switch doesn't exist, it's not active
  );
$$;

COMMENT ON FUNCTION check_kill_switch IS
  'Returns true if kill switch is active (feature is DISABLED). Call from workers on critical endpoints.';
