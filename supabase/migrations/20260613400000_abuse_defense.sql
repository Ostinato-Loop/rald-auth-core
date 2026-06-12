-- RALD Abuse Defense System
-- Phase 8 of Final Hardening Plan
-- Detect: spam rooms, fake accounts, room farming, creator abuse,
--         mass registration, bot activity.
-- Uses: Identity Brain, Trust Engine, behavioral signals.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: ABUSE REPORT TYPES
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS abuse_categories (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category    TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  severity    TEXT NOT NULL DEFAULT 'medium'
                CHECK (severity IN ('low','medium','high','critical')),
  auto_action TEXT CHECK (auto_action IN (
                 NULL, 'flag_review','restrict','suspend','ban'
               )),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO abuse_categories (category, description, severity, auto_action) VALUES
  ('spam_room',          'Audio room created for spam or promotional abuse',      'high',     'flag_review'),
  ('fake_account',       'Account suspected to be inauthentic or impersonating',  'high',     'flag_review'),
  ('room_farming',       'Systematic creation of rooms to game metrics',          'medium',   'flag_review'),
  ('creator_abuse',      'Creator-tier abuse of platform privileges',             'high',     'flag_review'),
  ('mass_registration',  'Automated or bulk account creation',                    'critical', 'suspend'),
  ('bot_activity',       'Non-human automated behavior detected',                 'critical', 'flag_review'),
  ('identity_theft',     'Attempting to impersonate another user or brand',       'critical', 'suspend'),
  ('doxxing',            'Sharing private personal information of others',         'critical', 'suspend'),
  ('harassment',         'Targeted harassment of another user',                   'high',     'flag_review'),
  ('csam',               'Child safety violation',                                'critical', 'ban'),
  ('spam_message',       'Bulk unsolicited messages',                             'medium',   'restrict'),
  ('phishing',           'Attempting to steal credentials or payment info',       'critical', 'ban')
ON CONFLICT (category) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- PART B: ABUSE REPORTS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS abuse_reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id     UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  subject_user_id UUID REFERENCES auth_users(id) ON DELETE CASCADE,
  category        TEXT NOT NULL REFERENCES abuse_categories(category),

  -- What was reported
  subject_type    TEXT NOT NULL CHECK (subject_type IN (
                    'user','room','message','community','workspace','username'
                  )),
  subject_id      TEXT,            -- ID of the specific item (room_id, message_id, etc.)
  description     TEXT NOT NULL DEFAULT '',
  evidence_urls   TEXT[] NOT NULL DEFAULT '{}',

  -- Auto-detection source
  source          TEXT NOT NULL DEFAULT 'user_report'
                    CHECK (source IN (
                      'user_report',       -- reported by another user
                      'ai_detection',      -- Identity Brain / WIZMAC detection
                      'trust_engine',      -- trust score drop triggered review
                      'pattern_analysis',  -- behavioral pattern detected
                      'admin_flagged'      -- admin manually flagged
                    )),
  confidence_score NUMERIC(4,3) CHECK (confidence_score BETWEEN 0.0 AND 1.0),

  -- Resolution
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN (
                      'pending',
                      'under_review',
                      'action_taken',
                      'dismissed',
                      'escalated'
                    )),
  resolution_notes TEXT,
  actioned_by     UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  actioned_at     TIMESTAMPTZ,

  -- Audit
  ip_address      INET,
  metadata        JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS abuse_reports_subject_idx    ON abuse_reports(subject_user_id);
CREATE INDEX IF NOT EXISTS abuse_reports_category_idx   ON abuse_reports(category);
CREATE INDEX IF NOT EXISTS abuse_reports_status_idx     ON abuse_reports(status) WHERE status IN ('pending','under_review');
CREATE INDEX IF NOT EXISTS abuse_reports_source_idx     ON abuse_reports(source);
CREATE INDEX IF NOT EXISTS abuse_reports_created_idx    ON abuse_reports(created_at DESC);

ALTER TABLE abuse_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "abuse_reports: reporter read own" ON abuse_reports
  FOR SELECT USING (reporter_id = auth.uid());
CREATE POLICY "abuse_reports: service full access" ON abuse_reports
  FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════
-- PART C: BOT DETECTION SIGNALS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS bot_detection_signals (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  signal_type     TEXT NOT NULL CHECK (signal_type IN (
                    'rapid_registrations_same_ip',
                    'headless_browser_detected',
                    'unusual_typing_speed',
                    'otp_automation_pattern',
                    'device_fingerprint_reuse',
                    'impossible_geo_velocity',
                    'mass_room_creation',
                    'mass_message_send',
                    'scripted_interactions',
                    'credential_stuffing'
                  )),
  severity        TEXT NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('low','medium','high','critical')),
  confidence      NUMERIC(4,3) NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
  signal_data     JSONB NOT NULL DEFAULT '{}',
  ip_address      INET,
  device_id       TEXT,
  reviewed        BOOLEAN NOT NULL DEFAULT false,
  review_outcome  TEXT CHECK (review_outcome IN ('false_positive','confirmed','inconclusive')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bot_signals_user_idx     ON bot_detection_signals(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bot_signals_type_idx     ON bot_detection_signals(signal_type);
CREATE INDEX IF NOT EXISTS bot_signals_severity_idx ON bot_detection_signals(severity) WHERE severity IN ('high','critical');
CREATE INDEX IF NOT EXISTS bot_signals_ip_idx       ON bot_detection_signals(ip_address) WHERE ip_address IS NOT NULL;

-- ═══════════════════════════════════════════════════════════════
-- PART D: MASS REGISTRATION ALERTS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mass_registration_alerts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address      INET NOT NULL,
  registration_count INT NOT NULL,
  time_window_minutes INT NOT NULL,
  threshold_exceeded INT NOT NULL DEFAULT 5,  -- registrations that triggered alert
  user_ids        UUID[] NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','investigating','blocked','dismissed')),
  blocked_at      TIMESTAMPTZ,
  notes           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mass_reg_ip_idx    ON mass_registration_alerts(ip_address);
CREATE INDEX IF NOT EXISTS mass_reg_status_idx ON mass_registration_alerts(status) WHERE status = 'open';

-- ═══════════════════════════════════════════════════════════════
-- PART E: USER RESTRICTIONS (applied by abuse engine)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS user_restrictions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  restriction_type TEXT NOT NULL CHECK (restriction_type IN (
                    'read_only',          -- can view but not post/create
                    'no_rooms',           -- cannot create or join rooms
                    'no_messages',        -- cannot send messages
                    'no_communities',     -- cannot create or manage communities
                    'no_registration',    -- IP-level block
                    'shadow_ban',         -- actions succeed but are invisible
                    'full_suspend'        -- complete account suspension
                  )),
  reason          TEXT NOT NULL,
  applied_by      TEXT NOT NULL,            -- 'system:abuse_engine' or admin user_id
  abuse_report_id UUID REFERENCES abuse_reports(id) ON DELETE SET NULL,
  expires_at      TIMESTAMPTZ,             -- NULL = permanent
  lifted_at       TIMESTAMPTZ,             -- NULL = still active
  lifted_by       TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS user_restrictions_user_idx    ON user_restrictions(user_id) WHERE lifted_at IS NULL;
CREATE INDEX IF NOT EXISTS user_restrictions_type_idx    ON user_restrictions(restriction_type) WHERE lifted_at IS NULL;
CREATE INDEX IF NOT EXISTS user_restrictions_expires_idx ON user_restrictions(expires_at) WHERE expires_at IS NOT NULL AND lifted_at IS NULL;

-- ═══════════════════════════════════════════════════════════════
-- PART F: ACTIVE RESTRICTIONS VIEW
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW active_user_restrictions AS
SELECT
  r.id,
  r.user_id,
  r.restriction_type,
  r.reason,
  r.applied_by,
  r.expires_at,
  r.created_at
FROM user_restrictions r
WHERE r.lifted_at IS NULL
  AND (r.expires_at IS NULL OR r.expires_at > now());

COMMENT ON TABLE abuse_reports IS 'User-submitted and AI-detected abuse reports with resolution tracking';
COMMENT ON TABLE bot_detection_signals IS 'Behavioral signals indicating non-human or automated activity';
COMMENT ON TABLE user_restrictions IS 'Active and historical restrictions applied by abuse engine or admins';
