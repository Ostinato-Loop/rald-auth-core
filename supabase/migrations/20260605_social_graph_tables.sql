-- ============================================================
-- RALD Auth Core — Social Graph Tables
-- Tables: rald_connections, rald_connection_edges
-- Safe: IF NOT EXISTS throughout — zero data loss risk.
-- Run at: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new
-- LILCKY STUDIO LIMITED — 2026-06-05
-- ============================================================

-- ─── rald_connections ─────────────────────────────────────────────────────────
-- Represents a directional social edge between two users.
-- created by /graph/connect; read by /graph/me and /graph/suggestions
CREATE TABLE IF NOT EXISTS rald_connections (
  id              UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id         UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  connected_to    UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  edge_type       TEXT          NOT NULL DEFAULT 'follow'
                                CHECK (edge_type IN ('follow','friend','blocked','shared_room','suggested')),
  weight          INTEGER       NOT NULL DEFAULT 1,
  connection_score INTEGER      NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, connected_to)
);

CREATE INDEX IF NOT EXISTS idx_rald_connections_user_id     ON rald_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_rald_connections_connected_to ON rald_connections(connected_to);
CREATE INDEX IF NOT EXISTS idx_rald_connections_edge_type   ON rald_connections(edge_type);
CREATE INDEX IF NOT EXISTS idx_rald_connections_score       ON rald_connections(connection_score DESC);

-- ─── rald_connection_edges ────────────────────────────────────────────────────
-- Append-only event log that powers weighted graph scoring.
-- Every interaction (shared room, message, etc.) increments weight.
CREATE TABLE IF NOT EXISTS rald_connection_edges (
  id          UUID          DEFAULT uuid_generate_v4() PRIMARY KEY,
  from_user   UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  to_user     UUID          NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  edge_type   TEXT          NOT NULL,
  weight      INTEGER       NOT NULL DEFAULT 1,
  metadata    JSONB         DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_from   ON rald_connection_edges(from_user);
CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_to     ON rald_connection_edges(to_user);
CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_type   ON rald_connection_edges(edge_type);
CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_created ON rald_connection_edges(created_at DESC);

-- ─── RLS ─────────────────────────────────────────────────────────────────────
ALTER TABLE rald_connections        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rald_connection_edges   ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='rald_connections' AND policyname='auth_service_role') THEN
    EXECUTE 'CREATE POLICY "auth_service_role" ON rald_connections       FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='rald_connection_edges' AND policyname='auth_service_role') THEN
    EXECUTE 'CREATE POLICY "auth_service_role" ON rald_connection_edges  FOR ALL USING (auth.role() = ''service_role'')';
  END IF;
END $$;

-- ─── Trigger: updated_at ──────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS trigger_rald_connections_updated_at ON rald_connections;
CREATE TRIGGER trigger_rald_connections_updated_at
  BEFORE UPDATE ON rald_connections
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
