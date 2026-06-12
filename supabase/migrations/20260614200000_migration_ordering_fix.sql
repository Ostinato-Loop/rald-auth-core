-- RALD Auth Core — Migration Ordering & Normalization Fix
-- Sprint: Public Beta Hardening · 2026-06-14
--
-- PROBLEMS FIXED:
--
-- (A) update_identity_updated_at() referenced in 20260612400000_machine_identity.sql
--     but the base schema defines update_updated_at() (different name).
--     Fix: create update_identity_updated_at() as a compatible alias.
--
-- (B) machine_identity_rotation_alerts VIEW created twice:
--     - 20260612400000_machine_identity.sql: uses days_until_due (INTERVAL)
--     - 20260613700000_session_cleanup_tables.sql PART D: uses days_until_rotation (INT)
--     cleanup.ts queries days_until_rotation → the PART D version is canonical.
--     Fix: normalize to single authoritative view with days_until_rotation (INT).
--
-- (C) Re-apply machine_identities updated_at trigger with correct function name.
-- LILCKY STUDIO LIMITED

-- ── A: Create update_identity_updated_at() if missing ─────────────────────────
CREATE OR REPLACE FUNCTION update_identity_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION update_identity_updated_at IS
  'Trigger function: sets updated_at = NOW() on row update. Canonical for identity tables.';

-- ── B: Normalize machine_identity_rotation_alerts view ────────────────────────
-- Drop both versions (from 400000 and 700000 migrations) and replace with one.
DROP VIEW IF EXISTS machine_identity_rotation_alerts;

CREATE VIEW machine_identity_rotation_alerts AS
SELECT
  id,
  service_name,
  display_name,
  environment,
  status,
  last_rotated_at,
  rotation_due_at,
  EXTRACT(DAY FROM (rotation_due_at - NOW()))::INT AS days_until_rotation,
  CASE
    WHEN rotation_due_at < NOW()                       THEN 'OVERDUE'
    WHEN rotation_due_at < NOW() + INTERVAL '7 days'  THEN 'DUE_SOON'
    ELSE 'OK'
  END AS rotation_status
FROM machine_identities
WHERE status = 'active'
ORDER BY rotation_due_at ASC;

COMMENT ON VIEW machine_identity_rotation_alerts IS
  'Canonical view: machine identities due for key rotation. Uses days_until_rotation (INT). Normalized 2026-06-14.';

-- ── C: Re-apply machine_identities updated_at trigger ─────────────────────────
DROP TRIGGER IF EXISTS trg_machine_identities_updated_at ON machine_identities;
CREATE TRIGGER trg_machine_identities_updated_at
  BEFORE UPDATE ON machine_identities
  FOR EACH ROW EXECUTE FUNCTION update_identity_updated_at();

-- ── D: Ensure update_updated_at() also exists (used by earlier tables) ────────
-- This is a safety guard — the function should already exist from
-- the auth_users_table migration (20260601). No-op if already present.
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION update_updated_at IS
  'Trigger function: sets updated_at = NOW() on row update. Base alias used by non-identity tables.';
