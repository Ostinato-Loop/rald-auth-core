-- RALD Ecosystem — Gap Analysis Completion + Scale Readiness Schema
-- Phase 12 of Final Hardening Plan
-- Creates remaining gap tables: audit stream config, health snapshots,
-- feature flags, scale metrics, and regulatory compliance tracking.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: FEATURE FLAGS (complement to kill switches)
-- Feature flags enable gradual rollout. Kill switches are emergency stops.
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feature_flags (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flag_key        TEXT NOT NULL UNIQUE,
  display_name    TEXT NOT NULL,
  description     TEXT NOT NULL DEFAULT '',

  -- State
  is_enabled      BOOLEAN NOT NULL DEFAULT false,
  rollout_percent INT NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
  enabled_for_user_ids UUID[] NOT NULL DEFAULT '{}',
  enabled_for_tiers TEXT[] NOT NULL DEFAULT '{}',  -- trust tiers
  enabled_for_countries TEXT[] NOT NULL DEFAULT '{}',

  -- Audit
  created_by      UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  updated_by      UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed key feature flags
INSERT INTO feature_flags (flag_key, display_name, description, is_enabled, rollout_percent) VALUES
  ('usn_transfers',           'USN Transfer System',    'Username Settlement Network transfer flow',  false, 0),
  ('mail_routing',            'RALD Mail Routing',      'Active mail routing for @rald.me aliases',  false, 0),
  ('workspace_business',      'Business Workspaces',    'Business workspace tier access',             false, 0),
  ('workspace_government',    'Government Workspaces',  'Government workspace tier access',           false, 0),
  ('data_portability_export', 'Data Export',            'User data export (NDPA compliance)',         true,  100),
  ('abuse_ai_detection',      'AI Abuse Detection',     'WIZMAC-powered abuse signal detection',      false, 0),
  ('payrald_beta',            'PayRald Beta',           'PayRald payment features in beta',           false, 0),
  ('developer_portal',        'Developer Portal',       'API key issuance and developer tools',       true,  100),
  ('loop_civic_rooms',        'Civic Rooms',            'Loop civic room creation',                   true,  100),
  ('username_influence',      'Username Influence',     'Username influence score computation',        false, 0)
ON CONFLICT (flag_key) DO NOTHING;

ALTER TABLE feature_flags ENABLE ROW LEVEL SECURITY;
CREATE POLICY "feature_flags: public read" ON feature_flags FOR SELECT USING (true);
CREATE POLICY "feature_flags: service write" ON feature_flags FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE feature_flags IS
  'Gradual rollout flags. Complement to kill_switches (which are emergency stops).';

-- ═══════════════════════════════════════════════════════════════
-- PART B: ECOSYSTEM HEALTH SNAPSHOTS (written by cleanup.ts daily)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ecosystem_health_snapshots (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  services      JSONB NOT NULL DEFAULT '{}', -- {service_name: {ok, latency, status}}
  healthy_count INT NOT NULL DEFAULT 0,
  total_count   INT NOT NULL DEFAULT 0,
  is_degraded   BOOLEAN NOT NULL DEFAULT false,
  alerts_fired  INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS health_snapshots_at_idx ON ecosystem_health_snapshots(snapshot_at DESC);

COMMENT ON TABLE ecosystem_health_snapshots IS
  'Daily ecosystem health snapshots written by the scheduled cleanup handler in rald-auth-core.';

-- ═══════════════════════════════════════════════════════════════
-- PART C: REGULATORY COMPLIANCE TRACKING
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS regulatory_compliance_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country_code    VARCHAR(2) NOT NULL,
  framework       TEXT NOT NULL,       -- 'NDPA', 'GDPR', 'NITDA', 'NCC', 'FCCPC', etc.
  requirement     TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','compliant','non_compliant','under_review','exempted')),
  evidence_notes  TEXT NOT NULL DEFAULT '',
  reviewed_by     UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  reviewed_at     TIMESTAMPTZ,
  next_review_at  TIMESTAMPTZ DEFAULT (now() + INTERVAL '90 days'),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed Nigeria compliance requirements (public beta live)
INSERT INTO regulatory_compliance_log (country_code, framework, requirement, status, evidence_notes) VALUES
  ('NG', 'NDPA',  'Data Protection Impact Assessment completed',              'compliant',     'RALD collects minimal PII; DPIA documented in architecture'),
  ('NG', 'NDPA',  'Data Portability: users can export all data',             'compliant',     'data_export_requests table + /privacy/export endpoint'),
  ('NG', 'NDPA',  'Right to Erasure: deletion requests processed',           'compliant',     'data_deletion_requests table + 30-day grace period'),
  ('NG', 'NDPA',  'Consent management for data processing',                  'compliant',     'Privacy center at /privacy with consent tracking'),
  ('NG', 'NITDA', 'Data localization: Nigerian user data in Nigeria',        'under_review',  'All data in Supabase (US region) — needs review'),
  ('NG', 'NCC',   'KYC requirements for digital services',                   'compliant',     'Phone verification via Termii, identity via rald-auth-core'),
  ('NG', 'FCCPC', 'Consumer protection disclosures',                         'compliant',     'Terms + Privacy policy published at rald.cloud/legal'),
  ('NG', 'FCCPC', 'Payment processing consumer protection',                  'pending',       'PayRald not yet launched — review when PayRald goes live')
ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS reg_compliance_country_idx ON regulatory_compliance_log(country_code);
CREATE INDEX IF NOT EXISTS reg_compliance_status_idx  ON regulatory_compliance_log(status);

-- ═══════════════════════════════════════════════════════════════
-- PART D: SCALE READINESS METRICS (snapshot per week)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scale_readiness_snapshots (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- User metrics
  total_users     BIGINT NOT NULL DEFAULT 0,
  active_30d      BIGINT NOT NULL DEFAULT 0,
  new_this_week   BIGINT NOT NULL DEFAULT 0,

  -- Auth metrics
  sessions_active BIGINT NOT NULL DEFAULT 0,
  devices_active  BIGINT NOT NULL DEFAULT 0,
  otps_issued_24h BIGINT NOT NULL DEFAULT 0,

  -- Platform metrics
  usernames_claimed BIGINT NOT NULL DEFAULT 0,
  communities_count BIGINT NOT NULL DEFAULT 0,
  rooms_created_24h BIGINT NOT NULL DEFAULT 0,

  -- Infrastructure
  supabase_db_size_mb NUMERIC,
  avg_api_latency_ms  NUMERIC,
  error_rate_pct      NUMERIC,

  -- Bottleneck flags
  flags           JSONB NOT NULL DEFAULT '{}',  -- {db_connections: "warning", etc.}
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scale_snapshots_at_idx ON scale_readiness_snapshots(snapshot_at DESC);

COMMENT ON TABLE scale_readiness_snapshots IS
  'Weekly scale readiness snapshots for capacity planning and bottleneck detection.';

-- ═══════════════════════════════════════════════════════════════
-- PART E: ADMIN CONTROL CENTER — convenience view
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW admin_control_panel AS
SELECT
  'kill_switches' AS section,
  COUNT(*) FILTER (WHERE is_active)::TEXT AS active_count,
  COUNT(*)::TEXT AS total_count,
  MAX(last_toggled_at)::TEXT AS last_activity
FROM kill_switches
UNION ALL
SELECT
  'open_abuse_reports',
  COUNT(*) FILTER (WHERE status IN ('pending','under_review'))::TEXT,
  COUNT(*)::TEXT,
  MAX(created_at)::TEXT
FROM abuse_reports
UNION ALL
SELECT
  'data_export_requests',
  COUNT(*) FILTER (WHERE status IN ('queued','processing'))::TEXT,
  COUNT(*)::TEXT,
  MAX(created_at)::TEXT
FROM data_export_requests
UNION ALL
SELECT
  'username_transfers',
  COUNT(*) FILTER (WHERE status NOT IN ('rejected','cancelled','completed'))::TEXT,
  COUNT(*)::TEXT,
  MAX(created_at)::TEXT
FROM username_transfer_requests
UNION ALL
SELECT
  'machine_identities_due_rotation',
  COUNT(*)::TEXT,
  COUNT(*)::TEXT,
  MIN(rotation_due_at)::TEXT
FROM machine_identity_rotation_alerts;

COMMENT ON VIEW admin_control_panel IS
  'Admin dashboard summary. Used by Control Center to show ecosystem health at a glance.';
