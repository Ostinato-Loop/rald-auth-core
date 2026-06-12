-- RALD Data Portability
-- Phase 9 of Final Hardening Plan
-- Every user can export: profile, communities, messages, settings, account history.
-- Future regulatory compliance (NDPA, GDPR).
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: EXPORT REQUESTS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS data_export_requests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,

  -- Request scope
  export_scope    TEXT[] NOT NULL DEFAULT '{profile,settings,username_history}',
                    -- options: profile, settings, username_history, sessions,
                    --          devices, communities, messages, audit_log, all

  -- Processing state
  status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN (
                      'queued',
                      'processing',
                      'ready',         -- export file is ready for download
                      'downloaded',    -- user downloaded the file
                      'expired',       -- download link expired
                      'failed'
                    )),

  -- Output
  file_url        TEXT,               -- signed URL to download (populated when ready)
  file_size_bytes BIGINT,
  file_sha256     TEXT,               -- integrity check
  expires_at      TIMESTAMPTZ,        -- download link expiry (72 hours after ready)

  -- Rate limiting: max 1 export per user per 30 days
  requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  processing_started_at TIMESTAMPTZ,
  ready_at        TIMESTAMPTZ,
  downloaded_at   TIMESTAMPTZ,

  -- Error
  error_message   TEXT,
  retry_count     INT NOT NULL DEFAULT 0,

  -- Regulatory
  legal_basis     TEXT NOT NULL DEFAULT 'user_request'
                    CHECK (legal_basis IN (
                      'user_request',      -- user-initiated via privacy center
                      'regulatory_order',  -- government/regulator order
                      'legal_process'      -- court order or legal request
                    )),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS data_export_user_idx    ON data_export_requests(user_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS data_export_status_idx  ON data_export_requests(status) WHERE status IN ('queued','processing');

ALTER TABLE data_export_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY "data_export: user reads own" ON data_export_requests
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "data_export: user inserts own" ON data_export_requests
  FOR INSERT WITH CHECK (user_id = auth.uid());
CREATE POLICY "data_export: service full access" ON data_export_requests
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE data_export_requests IS
  'User data export requests for regulatory compliance (NDPA/GDPR). Max 1 per user per 30 days.';

-- ═══════════════════════════════════════════════════════════════
-- PART B: EXPORT MANIFESTS (what each export contains)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS data_export_manifests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  export_id       UUID NOT NULL REFERENCES data_export_requests(id) ON DELETE CASCADE,
  data_category   TEXT NOT NULL,             -- 'profile', 'messages', etc.
  record_count    INT NOT NULL DEFAULT 0,
  included        BOOLEAN NOT NULL DEFAULT true,
  exclusion_reason TEXT,                     -- why it was excluded (e.g. "not applicable")
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ═══════════════════════════════════════════════════════════════
-- PART C: DELETION REQUESTS (right to erasure)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS data_deletion_requests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE SET NULL,
  user_email      TEXT,                      -- preserve for audit even after user deletion
  user_phone      TEXT,

  -- Scope
  deletion_type   TEXT NOT NULL DEFAULT 'full_account'
                    CHECK (deletion_type IN (
                      'full_account',       -- delete everything
                      'partial',            -- specific data categories
                      'anonymize'           -- keep structure, remove PII
                    )),
  categories_to_delete TEXT[] NOT NULL DEFAULT '{}',

  -- Scheduling
  scheduled_for   TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '30 days'),  -- 30-day grace period
  grace_period_ends_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '30 days'),

  -- State
  status          TEXT NOT NULL DEFAULT 'pending_confirmation'
                    CHECK (status IN (
                      'pending_confirmation', -- waiting for user to confirm via email/OTP
                      'confirmed',           -- user confirmed, awaiting scheduled date
                      'cancelled',           -- user cancelled during grace period
                      'processing',          -- deletion in progress
                      'completed',           -- deletion complete
                      'failed'               -- deletion failed, requires manual action
                    )),

  confirmed_at    TIMESTAMPTZ,
  cancelled_at    TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  completed_by    TEXT,                      -- 'system:auto' or admin user_id

  -- Regulatory
  legal_basis     TEXT NOT NULL DEFAULT 'user_request',
  regulatory_reference TEXT,                -- case number if regulatory order

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS data_deletion_user_idx     ON data_deletion_requests(user_id);
CREATE INDEX IF NOT EXISTS data_deletion_scheduled_idx ON data_deletion_requests(scheduled_for)
  WHERE status = 'confirmed';

ALTER TABLE data_deletion_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY "data_deletion: user reads own" ON data_deletion_requests
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "data_deletion: service full access" ON data_deletion_requests
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE data_deletion_requests IS
  'Right to erasure requests. 30-day grace period before deletion executes. User can cancel during grace period.';
