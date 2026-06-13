-- ============================================================
-- RALD Auth Core — ALIA Routing Audit Log
-- Migration: 20260613900002_alia_routing_log
-- Phase 6 / RALD Ecosystem Finalization Program
--
-- Persists every routing decision made by routing.rald.cloud
-- for observability, abuse detection, and analytics.
--
-- Written by the rald-routing worker (fire-and-forget,
-- non-blocking — routing is unaffected if this table is absent).
--
-- Safe: all CREATE use IF NOT EXISTS. No data loss.
-- LILCKY STUDIO LIMITED · 2026-06-13
-- ============================================================

-- ─── 1. Main log table ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alia_routing_log (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        REFERENCES auth_users(id) ON DELETE SET NULL,
  action       TEXT        NOT NULL DEFAULT 'alia_route',
  instance_id  TEXT,                            -- e.g. "finance-alia", "ng-general"
  input_hash   TEXT,                            -- SHA-256 of user input (never raw input)
  intent       TEXT,                            -- comma-separated matched domains
  reasoning    TEXT[]      NOT NULL DEFAULT '{}',
  fallback     BOOLEAN     NOT NULL DEFAULT false,
  latency_ms   INTEGER,
  ip           TEXT,
  metadata     JSONB       NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── 2. Indexes ───────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_alia_log_user_id    ON alia_routing_log(user_id);
CREATE INDEX IF NOT EXISTS idx_alia_log_instance   ON alia_routing_log(instance_id);
CREATE INDEX IF NOT EXISTS idx_alia_log_created    ON alia_routing_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alia_log_fallback   ON alia_routing_log(fallback)
  WHERE fallback = true;

-- ─── 3. Row-Level Security ────────────────────────────────────────────────────

ALTER TABLE alia_routing_log ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'alia_routing_log'
      AND policyname = 'alia_routing_log_service_role'
  ) THEN
    EXECUTE 'CREATE POLICY "alia_routing_log_service_role" ON alia_routing_log
             FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- ─── 4. Analytics view — routing decisions per instance (last 30 days) ────────

CREATE OR REPLACE VIEW alia_routing_stats AS
SELECT
  instance_id,
  COUNT(*)                                              AS total_routes,
  COUNT(*) FILTER (WHERE fallback = true)               AS fallback_count,
  ROUND(
    COUNT(*) FILTER (WHERE fallback = true)::NUMERIC
    / NULLIF(COUNT(*), 0) * 100, 1
  )                                                     AS fallback_pct,
  ROUND(AVG(latency_ms)::NUMERIC, 1)                    AS avg_latency_ms,
  MAX(latency_ms)                                       AS p100_latency_ms,
  MIN(created_at)                                       AS first_seen,
  MAX(created_at)                                       AS last_seen
FROM alia_routing_log
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY instance_id
ORDER BY total_routes DESC;

-- ─── 5. Verify ────────────────────────────────────────────────────────────────
-- SELECT tablename FROM pg_tables WHERE tablename = 'alia_routing_log';
-- SELECT viewname  FROM pg_views  WHERE viewname  = 'alia_routing_stats';
-- Expected: both present
