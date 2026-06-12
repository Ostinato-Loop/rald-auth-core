-- RALD Auth Core — Graph Schema Alignment
-- Sprint: Public Beta Hardening · 2026-06-14
--
-- PROBLEM: The 20260605_social_graph_tables.sql migration created columns
-- with different names than the TypeScript routes in graph.ts expect:
--
--   rald_connections.connected_to  → routes expect: target_user_id
--   rald_connection_edges.from_user → routes expect: user_id
--   rald_connection_edges.to_user   → routes expect: target_user_id
--
-- FIX: Rename columns to match the TypeScript route code.
-- All existing data is preserved — this is a pure schema rename, no data migration.
-- LILCKY STUDIO LIMITED

-- ── rald_connections: rename connected_to → target_user_id ────────────────────
ALTER TABLE rald_connections
  RENAME COLUMN connected_to TO target_user_id;

-- Drop old index referencing connected_to (column gone after rename)
DROP INDEX IF EXISTS idx_rald_connections_connected_to;

-- Recreate index with correct column name
CREATE INDEX IF NOT EXISTS idx_rald_connections_target_user_id
  ON rald_connections(target_user_id);

-- The UNIQUE constraint on (user_id, connected_to) is automatically updated
-- by PostgreSQL to (user_id, target_user_id) when the column is renamed.

-- ── rald_connection_edges: rename from_user → user_id, to_user → target_user_id
ALTER TABLE rald_connection_edges
  RENAME COLUMN from_user TO user_id;

ALTER TABLE rald_connection_edges
  RENAME COLUMN to_user TO target_user_id;

-- Drop old indexes
DROP INDEX IF EXISTS idx_rald_connection_edges_from;
DROP INDEX IF EXISTS idx_rald_connection_edges_to;

-- Recreate with correct column names
CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_user_id
  ON rald_connection_edges(user_id);

CREATE INDEX IF NOT EXISTS idx_rald_connection_edges_target_user_id
  ON rald_connection_edges(target_user_id);

-- ── Also add the 'type' column to rald_connections if missing ─────────────────
-- (graph.ts reads .type but the original migration used .edge_type)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'rald_connections' AND column_name = 'type'
  ) THEN
    ALTER TABLE rald_connections ADD COLUMN type TEXT NOT NULL DEFAULT 'connected'
      CHECK (type IN ('connected', 'follow', 'blocked'));
  END IF;
END $$;

-- Migrate existing edge_type values into new type column
UPDATE rald_connections
  SET type = CASE
    WHEN edge_type = 'follow'   THEN 'follow'
    WHEN edge_type = 'blocked'  THEN 'blocked'
    ELSE 'connected'
  END
WHERE type = 'connected' AND edge_type IS NOT NULL;

COMMENT ON TABLE rald_connections IS
  'Directional connection between two RALD users. Updated 2026-06-14 to align column names with route code.';
COMMENT ON TABLE rald_connection_edges IS
  'Append-only event log powering weighted graph scores. Updated 2026-06-14 to align column names.';
