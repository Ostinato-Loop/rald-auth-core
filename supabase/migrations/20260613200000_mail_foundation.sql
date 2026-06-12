-- RALD Mail Foundation
-- Phase 3 of Final Hardening Plan
-- Every username automatically reserves username@rald.me
-- Mail is NOT active. This is reservation infrastructure only.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: MAIL ALIAS REGISTRY
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mail_alias_registry (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username             TEXT NOT NULL UNIQUE,
  user_id              UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  mail_alias           TEXT NOT NULL UNIQUE,    -- username@rald.me
  domain               TEXT NOT NULL DEFAULT 'rald.me',

  -- Reservation state
  reservation_status   TEXT NOT NULL DEFAULT 'RESERVED'
                         CHECK (reservation_status IN (
                           'RESERVED',          -- created, mail not active
                           'ACTIVE',            -- mail routing enabled
                           'SUSPENDED',         -- suspended due to abuse
                           'RELEASED'           -- username released, alias freed
                         )),

  -- Activation tracking (future)
  activated_at         TIMESTAMPTZ,            -- NULL until mail goes live
  activation_notes     TEXT,

  -- Mail routing (future — populated when mail goes live)
  forward_to_email     TEXT,                   -- external forward address
  inbound_webhook_url  TEXT,                   -- webhook to receive inbound mail
  storage_enabled      BOOLEAN NOT NULL DEFAULT false,  -- store mail in RALD inbox

  -- Abuse
  abuse_flags          INT NOT NULL DEFAULT 0,
  last_abuse_at        TIMESTAMPTZ,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mail_alias_user_idx       ON mail_alias_registry(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS mail_alias_status_idx     ON mail_alias_registry(reservation_status);
CREATE INDEX IF NOT EXISTS mail_alias_domain_idx     ON mail_alias_registry(domain);

ALTER TABLE mail_alias_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY "mail_alias_registry: users read own" ON mail_alias_registry
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "mail_alias_registry: service write" ON mail_alias_registry
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE mail_alias_registry IS
  'RALD Mail alias reservations — username@rald.me reserved at username claim time. Mail is NOT active yet.';
COMMENT ON COLUMN mail_alias_registry.reservation_status IS
  'RESERVED: created at username claim. ACTIVE: mail routing live (future). See activation_notes for timeline.';

-- ═══════════════════════════════════════════════════════════════
-- PART B: TRIGGER — auto-reserve alias when username is claimed
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION reserve_mail_alias_on_username_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Reserve username@rald.me when a username is claimed (status → CLAIMED)
  IF NEW.status = 'CLAIMED' AND (OLD.status IS DISTINCT FROM 'CLAIMED') THEN
    INSERT INTO mail_alias_registry (
      username,
      user_id,
      mail_alias,
      domain,
      reservation_status
    ) VALUES (
      NEW.username,
      NEW.user_id,
      lower(NEW.username) || '@rald.me',
      'rald.me',
      'RESERVED'
    )
    ON CONFLICT (username) DO UPDATE SET
      user_id              = EXCLUDED.user_id,
      reservation_status   = 'RESERVED',
      updated_at           = now();
  END IF;

  -- Release alias when username is released
  IF NEW.status IN ('AVAILABLE','RELEASED') AND OLD.status = 'CLAIMED' THEN
    UPDATE mail_alias_registry
    SET reservation_status = 'RELEASED',
        user_id            = NULL,
        updated_at         = now()
    WHERE username = OLD.username;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_reserve_mail_alias ON usernames;
CREATE TRIGGER trg_reserve_mail_alias
  AFTER INSERT OR UPDATE OF status ON usernames
  FOR EACH ROW
  EXECUTE FUNCTION reserve_mail_alias_on_username_claim();

-- ═══════════════════════════════════════════════════════════════
-- PART C: BACKFILL — reserve aliases for all existing CLAIMED usernames
-- ═══════════════════════════════════════════════════════════════

INSERT INTO mail_alias_registry (username, user_id, mail_alias, domain, reservation_status)
SELECT
  u.username,
  u.user_id,
  lower(u.username) || '@rald.me',
  'rald.me',
  'RESERVED'
FROM usernames u
WHERE u.status = 'CLAIMED'
  AND u.user_id IS NOT NULL
ON CONFLICT (username) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- PART D: PROTECTED SYSTEM ALIASES
-- ═══════════════════════════════════════════════════════════════

INSERT INTO mail_alias_registry (username, user_id, mail_alias, domain, reservation_status)
VALUES
  ('admin',       NULL, 'admin@rald.me',       'rald.me', 'RESERVED'),
  ('support',     NULL, 'support@rald.me',     'rald.me', 'RESERVED'),
  ('security',    NULL, 'security@rald.me',    'rald.me', 'RESERVED'),
  ('noreply',     NULL, 'noreply@rald.me',     'rald.me', 'RESERVED'),
  ('hello',       NULL, 'hello@rald.me',       'rald.me', 'RESERVED'),
  ('team',        NULL, 'team@rald.me',        'rald.me', 'RESERVED'),
  ('abuse',       NULL, 'abuse@rald.me',       'rald.me', 'RESERVED'),
  ('legal',       NULL, 'legal@rald.me',       'rald.me', 'RESERVED'),
  ('privacy',     NULL, 'privacy@rald.me',     'rald.me', 'RESERVED'),
  ('payments',    NULL, 'payments@rald.me',    'rald.me', 'RESERVED'),
  ('developers',  NULL, 'developers@rald.me',  'rald.me', 'RESERVED'),
  ('lilcky',      NULL, 'lilcky@rald.me',      'rald.me', 'RESERVED')
ON CONFLICT (username) DO NOTHING;
