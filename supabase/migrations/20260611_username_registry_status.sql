-- RALD Auth Core — Username Registry Status System (Phase 3)
-- Adds proper status enum to `usernames` table:
--   AVAILABLE | RESERVED | CLAIMED | PROTECTED | PREMIUM | ADMIN_HELD
-- Also adds admin tracking columns: reserved_by, reserved_until, released_at
--
-- RALD AUTH EMERGENCY STABILIZATION SPRINT — Phase 3
-- Safe: IF NOT EXISTS / column guards / backfill throughout.
-- LILCKY STUDIO LIMITED

-- ─── 1. Add status column to usernames ────────────────────────────────────────
ALTER TABLE usernames ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'CLAIMED'
  CHECK (status IN ('AVAILABLE', 'RESERVED', 'CLAIMED', 'PROTECTED', 'PREMIUM', 'ADMIN_HELD'));

ALTER TABLE usernames ADD COLUMN IF NOT EXISTS reserved_by     UUID REFERENCES auth_users(id) ON DELETE SET NULL;
ALTER TABLE usernames ADD COLUMN IF NOT EXISTS reserved_until  TIMESTAMPTZ;
ALTER TABLE usernames ADD COLUMN IF NOT EXISTS released_at     TIMESTAMPTZ;

COMMENT ON COLUMN usernames.status IS
  'AVAILABLE: claimable | RESERVED: admin-held for future use | CLAIMED: owned by a user | PROTECTED: blocked globally | PREMIUM: future marketplace | ADMIN_HELD: recovered by admin';
COMMENT ON COLUMN usernames.reserved_by    IS 'Admin user_id who placed the reservation';
COMMENT ON COLUMN usernames.reserved_until IS 'Timestamp when RESERVED status expires (NULL = indefinite)';
COMMENT ON COLUMN usernames.released_at    IS 'Timestamp when username was last released to AVAILABLE';

-- ─── 2. Backfill status from existing `active` boolean ────────────────────────
-- active = true  → CLAIMED (owned by a user)
-- active = false → AVAILABLE (released/freed)
UPDATE usernames SET status = 'CLAIMED'   WHERE active = true  AND status = 'CLAIMED';
UPDATE usernames SET status = 'AVAILABLE' WHERE active = false AND status = 'CLAIMED';

-- ─── 3. Protect critical RALD-brand usernames ─────────────────────────────────
-- These should never be claimable by any user.
-- Uses INSERT ... ON CONFLICT DO UPDATE to ensure they exist with PROTECTED status.
INSERT INTO usernames (username, status, active, created_at)
VALUES
  ('rald',          'PROTECTED', false, now()),
  ('loop',          'PROTECTED', false, now()),
  ('messenger',     'PROTECTED', false, now()),
  ('payrald',       'PROTECTED', false, now()),
  ('gitrald',       'PROTECTED', false, now()),
  ('raldtics',      'PROTECTED', false, now()),
  ('admin',         'PROTECTED', false, now()),
  ('support',       'PROTECTED', false, now()),
  ('security',      'PROTECTED', false, now()),
  ('abuse',         'PROTECTED', false, now()),
  ('api',           'PROTECTED', false, now()),
  ('auth',          'PROTECTED', false, now()),
  ('sso',           'PROTECTED', false, now()),
  ('system',        'PROTECTED', false, now()),
  ('root',          'PROTECTED', false, now()),
  ('lilcky',        'PROTECTED', false, now()),
  ('ostinato',      'PROTECTED', false, now()),
  ('manilla',       'PROTECTED', false, now()),
  ('duna',          'PROTECTED', false, now())
ON CONFLICT (username) DO UPDATE SET
  status = CASE
    WHEN usernames.status = 'CLAIMED' THEN 'CLAIMED'  -- don't override active claims
    ELSE 'PROTECTED'
  END;

-- ─── 4. Mark premium desirable usernames as PREMIUM ──────────────────────────
-- Future marketplace architecture. No auction/purchase built yet.
INSERT INTO usernames (username, status, active, created_at)
VALUES
  ('music',   'PREMIUM', false, now()),
  ('news',    'PREMIUM', false, now()),
  ('sports',  'PREMIUM', false, now()),
  ('lagos',   'PREMIUM', false, now()),
  ('nigeria', 'PREMIUM', false, now()),
  ('abuja',   'PREMIUM', false, now()),
  ('africa',  'PREMIUM', false, now()),
  ('pay',     'PREMIUM', false, now()),
  ('shop',    'PREMIUM', false, now()),
  ('media',   'PREMIUM', false, now()),
  ('tech',    'PREMIUM', false, now()),
  ('health',  'PREMIUM', false, now()),
  ('finance', 'PREMIUM', false, now()),
  ('edu',     'PREMIUM', false, now()),
  ('news',    'PREMIUM', false, now()),
  ('chat',    'PREMIUM', false, now()),
  ('live',    'PREMIUM', false, now()),
  ('store',   'PREMIUM', false, now())
ON CONFLICT (username) DO UPDATE SET
  status = CASE
    WHEN usernames.status = 'CLAIMED' THEN 'CLAIMED'     -- don't override active claims
    WHEN usernames.status = 'PROTECTED' THEN 'PROTECTED' -- don't downgrade PROTECTED
    ELSE 'PREMIUM'
  END;

-- ─── 5. Indexes for the new status column ─────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_usernames_status         ON usernames(status);
CREATE INDEX IF NOT EXISTS idx_usernames_reserved_by    ON usernames(reserved_by) WHERE reserved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_usernames_reserved_until ON usernames(reserved_until) WHERE reserved_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_usernames_status_active  ON usernames(status, active);

-- ─── 6. Function: auto-expire RESERVED status past reserved_until ─────────────
CREATE OR REPLACE FUNCTION expire_username_reservations()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  _count INTEGER;
BEGIN
  UPDATE usernames
  SET status = 'AVAILABLE', reserved_by = NULL, released_at = now()
  WHERE status = 'RESERVED'
    AND reserved_until IS NOT NULL
    AND reserved_until < now();

  GET DIAGNOSTICS _count = ROW_COUNT;
  RETURN _count;
END;
$$;

COMMENT ON FUNCTION expire_username_reservations IS
  'Phase 3: Call periodically (e.g. via cron) to release RESERVED usernames past their reserved_until timestamp.';

-- ─── Done ──────────────────────────────────────────────────────────────────────
