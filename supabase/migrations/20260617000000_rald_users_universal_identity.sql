-- ============================================================================
-- RALD Phase 1: Universal Identity Layer
-- Migration: 20260617000000_rald_users_universal_identity.sql
-- Creates the unified rald_users table and all cross-product provisioning
-- tables: wallets, alia_handles, mail_accounts, messenger_accounts,
-- plus provision_audit_log and provision_retry_queue for resilience.
-- LILCKY STUDIO LIMITED · 2026-06-17
-- ============================================================================

-- ── rald_users: single source of truth for every RALD identity ───────────────
CREATE TABLE IF NOT EXISTS rald_users (
  id                 TEXT PRIMARY KEY,            -- rld_xxxxxxxx (globally unique)
  user_id            UUID UNIQUE,                 -- auth_users.id linkage
  username           TEXT UNIQUE,                 -- @boyd
  email              TEXT,                        -- external email (optional)
  rald_email         TEXT UNIQUE,                 -- boyd@rald.cloud
  alia_handle        TEXT UNIQUE,                 -- @boyd (ALIA network)
  wallet_id          TEXT UNIQUE,                 -- wallet_rld_xxxxxxxx
  messenger_id       TEXT UNIQUE,                 -- msg_rld_xxxxxxxx
  mail_id            TEXT UNIQUE,                 -- mail_rld_xxxxxxxx
  trust_score        INTEGER DEFAULT 0,
  kyc_tier           INTEGER DEFAULT 0,           -- 0=none 1=basic 2=verified 3=enhanced
  activated_products TEXT[] DEFAULT '{}',         -- ['auth','wallet','messenger','mail','alia']
  provision_status   TEXT DEFAULT 'provisioning'  -- provisioning/complete/partial/failed
    CHECK (provision_status IN ('provisioning','complete','partial','failed')),
  created_at         TIMESTAMPTZ DEFAULT NOW(),
  updated_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rald_users_user_id   ON rald_users(user_id);
CREATE INDEX IF NOT EXISTS idx_rald_users_username  ON rald_users(username);
CREATE INDEX IF NOT EXISTS idx_rald_users_status    ON rald_users(provision_status);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_rald_users_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;
DROP TRIGGER IF EXISTS trg_rald_users_updated_at ON rald_users;
CREATE TRIGGER trg_rald_users_updated_at
  BEFORE UPDATE ON rald_users
  FOR EACH ROW EXECUTE FUNCTION update_rald_users_updated_at();

-- ── payrald_wallets ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payrald_wallets (
  id           TEXT PRIMARY KEY,                  -- wallet_rld_xxxxxxxx
  rald_id      TEXT UNIQUE REFERENCES rald_users(id) ON DELETE CASCADE,
  user_id      UUID,                              -- auth_users.id (legacy link)
  balance_ngn  BIGINT DEFAULT 0,                 -- stored in kobo (1 NGN = 100 kobo)
  currency     TEXT DEFAULT 'NGN',
  status       TEXT DEFAULT 'active'
    CHECK (status IN ('active','suspended','closed')),
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallets_user_id  ON payrald_wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_wallets_rald_id  ON payrald_wallets(rald_id);

-- ── alia_handles ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alia_handles (
  id           TEXT PRIMARY KEY,                  -- alia_rld_xxxxxxxx
  rald_id      TEXT UNIQUE REFERENCES rald_users(id) ON DELETE CASCADE,
  user_id      UUID,
  handle       TEXT UNIQUE NOT NULL,              -- @boyd
  status       TEXT DEFAULT 'active'
    CHECK (status IN ('active','suspended','reserved')),
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alia_handles_user_id ON alia_handles(user_id);
CREATE INDEX IF NOT EXISTS idx_alia_handles_handle  ON alia_handles(handle);

-- ── mail_accounts ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mail_accounts (
  id           TEXT PRIMARY KEY,                  -- mail_rld_xxxxxxxx
  rald_id      TEXT UNIQUE REFERENCES rald_users(id) ON DELETE CASCADE,
  user_id      UUID,
  address      TEXT UNIQUE NOT NULL,              -- boyd@rald.cloud
  display_name TEXT,
  status       TEXT DEFAULT 'active'
    CHECK (status IN ('active','suspended','deleted')),
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_accounts_user_id ON mail_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_mail_accounts_address ON mail_accounts(address);

-- ── messenger_accounts ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messenger_accounts (
  id           TEXT PRIMARY KEY,                  -- msg_rld_xxxxxxxx
  rald_id      TEXT UNIQUE REFERENCES rald_users(id) ON DELETE CASCADE,
  user_id      UUID,
  username     TEXT,
  display_name TEXT,
  status       TEXT DEFAULT 'active'
    CHECK (status IN ('active','suspended','deleted')),
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messenger_accounts_user_id  ON messenger_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_messenger_accounts_username ON messenger_accounts(username);

-- ── provision_audit_log ───────────────────────────────────────────────────────
-- Every provisioning step is logged here (identity.created, wallet.created, etc.)
CREATE TABLE IF NOT EXISTS provision_audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rald_id      TEXT REFERENCES rald_users(id) ON DELETE CASCADE,
  event_type   TEXT NOT NULL,                     -- identity.created / wallet.created / etc.
  service      TEXT NOT NULL,                     -- identity / wallet / alia / mail / messenger
  status       TEXT NOT NULL
    CHECK (status IN ('success','failed','skipped')),
  payload      JSONB DEFAULT '{}',
  error        TEXT,
  duration_ms  INTEGER,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provision_audit_rald_id    ON provision_audit_log(rald_id);
CREATE INDEX IF NOT EXISTS idx_provision_audit_event_type ON provision_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_provision_audit_status     ON provision_audit_log(status);
CREATE INDEX IF NOT EXISTS idx_provision_audit_created_at ON provision_audit_log(created_at DESC);

-- ── provision_retry_queue ─────────────────────────────────────────────────────
-- Failed provisioning steps are queued here and retried by the scheduled job.
CREATE TABLE IF NOT EXISTS provision_retry_queue (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rald_id       TEXT REFERENCES rald_users(id) ON DELETE CASCADE,
  service       TEXT NOT NULL,                    -- wallet / alia / mail / messenger / event
  payload       JSONB DEFAULT '{}',               -- all args needed to retry the step
  attempt_count INTEGER DEFAULT 0,
  max_attempts  INTEGER DEFAULT 10,
  last_error    TEXT,
  next_retry_at TIMESTAMPTZ DEFAULT NOW(),
  status        TEXT DEFAULT 'pending'
    CHECK (status IN ('pending','retrying','success','exhausted')),
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_retry_queue_pending  ON provision_retry_queue(status, next_retry_at)
  WHERE status IN ('pending','retrying');
CREATE INDEX IF NOT EXISTS idx_retry_queue_rald_id  ON provision_retry_queue(rald_id);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_retry_queue_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;
DROP TRIGGER IF EXISTS trg_retry_queue_updated_at ON provision_retry_queue;
CREATE TRIGGER trg_retry_queue_updated_at
  BEFORE UPDATE ON provision_retry_queue
  FOR EACH ROW EXECUTE FUNCTION update_retry_queue_updated_at();

-- ── RLS (Row Level Security) ──────────────────────────────────────────────────
-- Service role bypasses RLS. These policies ensure anon cannot read identity data.
ALTER TABLE rald_users            ENABLE ROW LEVEL SECURITY;
ALTER TABLE payrald_wallets       ENABLE ROW LEVEL SECURITY;
ALTER TABLE alia_handles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_accounts         ENABLE ROW LEVEL SECURITY;
ALTER TABLE messenger_accounts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE provision_audit_log   ENABLE ROW LEVEL SECURITY;
ALTER TABLE provision_retry_queue ENABLE ROW LEVEL SECURITY;

-- Service role can do anything (used by rald-auth-core CF Worker)
CREATE POLICY rald_users_service_all            ON rald_users            FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY payrald_wallets_service_all       ON payrald_wallets       FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY alia_handles_service_all          ON alia_handles          FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY mail_accounts_service_all         ON mail_accounts         FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY messenger_accounts_service_all    ON messenger_accounts    FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY provision_audit_service_all       ON provision_audit_log   FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY provision_retry_service_all       ON provision_retry_queue FOR ALL USING (auth.role() = 'service_role');

-- ── Provision dashboard view ──────────────────────────────────────────────────
CREATE OR REPLACE VIEW provision_dashboard_stats AS
SELECT
  COUNT(*)                                          AS total_identities,
  COUNT(*) FILTER (WHERE provision_status = 'complete')     AS fully_provisioned,
  COUNT(*) FILTER (WHERE provision_status = 'partial')      AS partially_provisioned,
  COUNT(*) FILTER (WHERE provision_status = 'provisioning') AS in_progress,
  COUNT(*) FILTER (WHERE provision_status = 'failed')       AS failed,
  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour')  AS created_last_1h,
  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS created_last_24h,
  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')   AS created_last_7d
FROM rald_users;

-- ── Retry queue stats view ─────────────────────────────────────────────────────
CREATE OR REPLACE VIEW retry_queue_stats AS
SELECT
  service,
  status,
  COUNT(*) AS count,
  MAX(attempt_count) AS max_attempts_seen,
  MIN(next_retry_at) AS earliest_retry
FROM provision_retry_queue
GROUP BY service, status;

COMMENT ON TABLE rald_users IS 'Universal RALD identity — one record per user across all products';
COMMENT ON TABLE provision_audit_log IS 'Immutable audit trail of every provisioning action';
COMMENT ON TABLE provision_retry_queue IS 'Retry queue for failed provisioning steps — processed by scheduled job';
