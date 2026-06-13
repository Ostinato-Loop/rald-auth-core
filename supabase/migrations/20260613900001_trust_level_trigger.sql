-- ============================================================
-- RALD Auth Core — Trust Level Auto-Sync Trigger
-- Migration: 20260613900001_trust_level_trigger
-- Phase 7 / RALD Ecosystem Finalization Program
--
-- Adds a BEFORE UPDATE trigger on auth_users that recomputes
-- trust_level automatically whenever trust_score changes.
-- Eliminates any possibility of score/level drift without
-- requiring application-layer logic.
--
-- Thresholds (matches migration 20260613000000 + routes/sso.ts):
--   >= 90  → institutional
--   >= 75  → leader
--   >= 60  → verified
--   >= 40  → contributor
--   >= 25  → active
--   >= 10  → member
--    < 10  → none
--
-- Safe: idempotent (CREATE OR REPLACE + DROP TRIGGER IF EXISTS).
-- LILCKY STUDIO LIMITED · 2026-06-13
-- ============================================================

-- ─── 1. Trigger function ──────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION sync_trust_level()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- Only recompute when trust_score actually changes
  IF NEW.trust_score IS DISTINCT FROM OLD.trust_score THEN
    NEW.trust_level := CASE
      WHEN NEW.trust_score >= 90 THEN 'institutional'
      WHEN NEW.trust_score >= 75 THEN 'leader'
      WHEN NEW.trust_score >= 60 THEN 'verified'
      WHEN NEW.trust_score >= 40 THEN 'contributor'
      WHEN NEW.trust_score >= 25 THEN 'active'
      WHEN NEW.trust_score >= 10 THEN 'member'
      ELSE 'none'
    END;
  END IF;
  RETURN NEW;
END;
$$;

-- ─── 2. Attach trigger to auth_users ─────────────────────────────────────────

DROP TRIGGER IF EXISTS trg_sync_trust_level ON auth_users;

CREATE TRIGGER trg_sync_trust_level
  BEFORE UPDATE OF trust_score ON auth_users
  FOR EACH ROW
  EXECUTE FUNCTION sync_trust_level();

-- ─── 3. One-time full resync ──────────────────────────────────────────────────
-- Recomputes trust_level for every row to fix any existing drift
-- (rows where trust_level doesn't match the current trust_score).

UPDATE auth_users
SET trust_level = CASE
  WHEN trust_score >= 90 THEN 'institutional'
  WHEN trust_score >= 75 THEN 'leader'
  WHEN trust_score >= 60 THEN 'verified'
  WHEN trust_score >= 40 THEN 'contributor'
  WHEN trust_score >= 25 THEN 'active'
  WHEN trust_score >= 10 THEN 'member'
  ELSE 'none'
END
WHERE trust_level <> CASE
  WHEN trust_score >= 90 THEN 'institutional'
  WHEN trust_score >= 75 THEN 'leader'
  WHEN trust_score >= 60 THEN 'verified'
  WHEN trust_score >= 40 THEN 'contributor'
  WHEN trust_score >= 25 THEN 'active'
  WHEN trust_score >= 10 THEN 'member'
  ELSE 'none'
END;

-- ─── 4. Verify ───────────────────────────────────────────────────────────────
-- After this migration, run to confirm:
--   SELECT tgname FROM pg_trigger WHERE tgrelid = 'auth_users'::regclass;
--   -- Expected: includes 'trg_sync_trust_level'
--
--   SELECT trust_score, trust_level, count(*) FROM auth_users
--   GROUP BY trust_score, trust_level ORDER BY trust_score DESC;
--   -- Expected: trust_level always matches trust_score band
