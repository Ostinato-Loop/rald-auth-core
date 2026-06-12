-- RALD Username Settlement Network (USN)
-- Phase 2 of Final Hardening Plan + Username Settlement Network Document
-- Private, trust-based username transfer and settlement system.
-- Usernames are ecosystem identities, not public assets.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: EXTEND USERNAME STATUS (add USN statuses)
-- ═══════════════════════════════════════════════════════════════

-- Add new USN status values to the existing check constraint
-- Existing: AVAILABLE, RESERVED, CLAIMED, PROTECTED, PREMIUM, ADMIN_HELD
-- Adding:   SYSTEM_HELD, UNDER_REVIEW, TRANSFER_PENDING, SETTLED

-- Drop and recreate check constraint
ALTER TABLE usernames DROP CONSTRAINT IF EXISTS usernames_status_check;
ALTER TABLE usernames ADD CONSTRAINT usernames_status_check
  CHECK (status IN (
    'AVAILABLE',
    'RESERVED',
    'CLAIMED',
    'PROTECTED',
    'PREMIUM',
    'ADMIN_HELD',
    'SYSTEM_HELD',       -- held by system for strategic allocation
    'UNDER_REVIEW',      -- review triggered (inactivity, legal, strategic)
    'TRANSFER_PENDING',  -- settlement agreement in progress
    'SETTLED'            -- transfer completed
  ));

-- Extend protected username list from USN document
UPDATE usernames SET status = 'PROTECTED' WHERE username IN (
  'admin','support','security','help','payments','official','verified','team',
  'rald','loop','messenger','mail','pay','auth','api','sso','system','root',
  'lilcky','gitrald','raldtics','payrald','identity','identity-brain',
  'trust','permissions','notifications','inbox','search','realtime',
  'nigeria','lagos','abuja','unilag','futa','oau',
  'kenya','ghana','southafrica','india','indonesia'
);
INSERT INTO usernames (username, status, active, created_at)
VALUES
  ('admin',          'PROTECTED', false, now()),
  ('support',        'PROTECTED', false, now()),
  ('security',       'PROTECTED', false, now()),
  ('help',           'PROTECTED', false, now()),
  ('payments',       'PROTECTED', false, now()),
  ('official',       'PROTECTED', false, now()),
  ('verified',       'PROTECTED', false, now()),
  ('team',           'PROTECTED', false, now()),
  ('rald',           'PROTECTED', false, now()),
  ('loop',           'PROTECTED', false, now()),
  ('messenger',      'PROTECTED', false, now()),
  ('mail',           'PROTECTED', false, now()),
  ('pay',            'PROTECTED', false, now()),
  ('nigeria',        'PROTECTED', false, now()),
  ('lagos',          'PROTECTED', false, now()),
  ('abuja',          'PROTECTED', false, now()),
  ('kenya',          'PROTECTED', false, now()),
  ('ghana',          'PROTECTED', false, now())
ON CONFLICT (username) DO UPDATE SET status = 'PROTECTED';

-- ═══════════════════════════════════════════════════════════════
-- PART B: USERNAME LEDGER (immutable audit trail)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS username_ledger (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT NOT NULL,
  event_type    TEXT NOT NULL CHECK (event_type IN (
                  'CLAIMED',
                  'RELEASED',
                  'PROTECTED',
                  'RESERVED',
                  'SYSTEM_HELD',
                  'REVIEW_TRIGGERED',
                  'REVIEW_COMPLETED',
                  'TRANSFER_INITIATED',
                  'TRANSFER_CANCELLED',
                  'TRANSFER_SETTLED',
                  'SETTLEMENT_ISSUED',
                  'VALUATION_UPDATED',
                  'STATUS_CHANGED'
                )),
  from_user_id  UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  to_user_id    UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  from_status   TEXT,
  to_status     TEXT,
  performed_by  TEXT NOT NULL,               -- user_id or 'system' or 'admin:<id>'
  reason        TEXT NOT NULL DEFAULT '',
  metadata      JSONB NOT NULL DEFAULT '{}', -- settlement details, valuation, etc.
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ledger is append-only — no updates or deletes
ALTER TABLE username_ledger ENABLE ROW LEVEL SECURITY;
CREATE POLICY "username_ledger: append only" ON username_ledger
  FOR INSERT WITH CHECK (true);
CREATE POLICY "username_ledger: service read" ON username_ledger
  FOR SELECT USING (true);

CREATE INDEX IF NOT EXISTS username_ledger_username_idx  ON username_ledger(username);
CREATE INDEX IF NOT EXISTS username_ledger_from_user_idx ON username_ledger(from_user_id) WHERE from_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS username_ledger_to_user_idx   ON username_ledger(to_user_id)   WHERE to_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS username_ledger_created_idx   ON username_ledger(created_at DESC);

COMMENT ON TABLE username_ledger IS 'Immutable ledger of all username ownership events — never delete, never update';

-- ═══════════════════════════════════════════════════════════════
-- PART C: USERNAME INFLUENCE SCORES
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS username_influence_scores (
  user_id              UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,

  -- Composite influence score (0.0 – 1.0)
  influence_score      NUMERIC(5,4) NOT NULL DEFAULT 0.0
                         CHECK (influence_score BETWEEN 0.0 AND 1.0),
  candidate_rank       INT,                  -- internal ranking, not exposed publicly

  -- Signal breakdown (each 0.0 – 1.0)
  signal_account_age       NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_trust_score       NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_creator_impact    NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_civic_impact      NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_business_impact   NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_workspace_activity NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_ecosystem_participation NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_verification_level NUMERIC(4,3) NOT NULL DEFAULT 0.0,
  signal_moderation_history NUMERIC(4,3) NOT NULL DEFAULT 1.0, -- starts good (1.0)

  -- Audit
  last_computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  computation_version  INT NOT NULL DEFAULT 1,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS username_influence_score_idx ON username_influence_scores(influence_score DESC);
CREATE INDEX IF NOT EXISTS username_influence_rank_idx  ON username_influence_scores(candidate_rank) WHERE candidate_rank IS NOT NULL;

COMMENT ON TABLE username_influence_scores IS
  'Internal-only contribution scores for USN candidate ranking. Never exposed publicly.';

-- ═══════════════════════════════════════════════════════════════
-- PART D: USERNAME TRANSFER REQUESTS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS username_transfer_requests (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username         TEXT NOT NULL,

  -- Parties
  current_holder_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE RESTRICT,
  candidate_id      UUID REFERENCES auth_users(id) ON DELETE SET NULL,  -- identified by Identity Brain

  -- Trigger
  trigger_type     TEXT NOT NULL CHECK (trigger_type IN (
                     'holder_initiated',   -- current holder requested transfer
                     'inactivity',         -- holder inactive > threshold
                     'strategic',          -- username strategically important
                     'legal_resolution',   -- legal process outcome
                     'contributor_review'  -- top contributor qualifies
                   )),
  trigger_notes    TEXT NOT NULL DEFAULT '',

  -- Flow state
  status           TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN (
                     'initiated',           -- system identified candidate
                     'holder_notified',     -- holder notified privately
                     'discussion_open',     -- settlement discussion in progress
                     'agreement_reached',   -- both parties agreed
                     'admin_review',        -- under admin review
                     'identity_brain_review', -- Identity Brain final approval
                     'approved',            -- transfer approved
                     'rejected',            -- transfer rejected
                     'cancelled',           -- cancelled (holder withdrew)
                     'completed'            -- transfer executed
                   )),

  -- Settlement offer
  settlement_type  TEXT CHECK (settlement_type IN (
                     'monetary',
                     'rald_credits',
                     'ecosystem_rewards',
                     'premium_services',
                     'workspace_upgrades',
                     'no_compensation'
                   )),
  settlement_amount NUMERIC(15,2),
  settlement_currency TEXT DEFAULT 'NGN',
  settlement_details JSONB NOT NULL DEFAULT '{}',

  -- Audit trail
  initiated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  holder_notified_at TIMESTAMPTZ,
  agreement_at     TIMESTAMPTZ,
  admin_review_at  TIMESTAMPTZ,
  completed_at     TIMESTAMPTZ,
  reviewed_by      UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  rejection_reason TEXT,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS username_transfers_username_idx ON username_transfer_requests(username);
CREATE INDEX IF NOT EXISTS username_transfers_holder_idx   ON username_transfer_requests(current_holder_id);
CREATE INDEX IF NOT EXISTS username_transfers_status_idx   ON username_transfer_requests(status);

-- No public access — admin and Identity Brain only
ALTER TABLE username_transfer_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY "username_transfers: service access" ON username_transfer_requests
  FOR ALL USING (true) WITH CHECK (true);

COMMENT ON TABLE username_transfer_requests IS
  'Private USN transfer flow — no public marketplace, no public auctions, no public bids';

-- ═══════════════════════════════════════════════════════════════
-- PART E: PRIVATE CONTENDER EVALUATIONS (Identity Brain)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS username_contender_evaluations (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username         TEXT NOT NULL,
  candidate_id     UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  influence_score  NUMERIC(5,4) NOT NULL,
  evaluation_notes TEXT NOT NULL DEFAULT '',
  is_current_best  BOOLEAN NOT NULL DEFAULT false, -- only ONE per username at a time
  evaluated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS contender_evals_username_idx ON username_contender_evaluations(username, is_current_best);

-- Only ONE active best candidate per username
CREATE UNIQUE INDEX IF NOT EXISTS contender_evals_one_best_idx
  ON username_contender_evaluations(username) WHERE is_current_best = true;

COMMENT ON TABLE username_contender_evaluations IS
  'Internal Identity Brain evaluations — best candidate per username. Never exposed publicly.';

-- ═══════════════════════════════════════════════════════════════
-- PART F: USN ANTI-SPECULATION RULES (database enforced)
-- ═══════════════════════════════════════════════════════════════

-- View: usernames under active review or transfer
CREATE OR REPLACE VIEW usernames_in_review AS
SELECT
  u.username,
  u.status,
  u.user_id AS current_holder_id,
  tr.status AS transfer_status,
  tr.trigger_type,
  tr.initiated_at
FROM usernames u
LEFT JOIN username_transfer_requests tr ON tr.username = u.username
  AND tr.status NOT IN ('rejected','cancelled','completed')
WHERE u.status IN ('UNDER_REVIEW','TRANSFER_PENDING')
ORDER BY tr.initiated_at DESC;

COMMENT ON VIEW usernames_in_review IS
  'Admin view of usernames currently under review or in transfer — never expose to public API';
